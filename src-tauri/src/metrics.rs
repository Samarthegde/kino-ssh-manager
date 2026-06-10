//! Live system metrics — CPU / memory / network / load / uptime / disk.
//!
//! A background task samples the target once a second and emits a
//! `metrics-<streamId>` event. Remote samples run a single cheap `/proc`-based
//! command over a fresh channel on the existing SSH connection (so they never
//! disturb the live terminal); local samples run the same command via `sh -c`.
//! CPU% and network rates are deltas between successive samples.

use serde::Serialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::{AppHandle, Emitter};
use tokio::io::AsyncReadExt;
use tokio::time::timeout;

use crate::ssh_session::ClientHandler;

type SshHandle = Arc<russh::client::Handle<ClientHandler>>;

/// stream_id → the running sampler task (aborted on stop).
pub type MetricsStreams = Arc<Mutex<HashMap<String, tokio::task::JoinHandle<()>>>>;

/// One cheap command gathers everything from `/proc` + `df`. Each line is
/// prefixed so parsing is unambiguous regardless of locale/format.
const METRICS_CMD: &str = "head -1 /proc/stat; \
     awk '/MemTotal|MemAvailable/{print}' /proc/meminfo; \
     awk 'NR>2{rx+=$2;tx+=$10}END{printf \"NET %d %d\\n\",rx,tx}' /proc/net/dev; \
     printf 'LOAD %s\\n' \"$(cut -d' ' -f1-3 /proc/loadavg)\"; \
     printf 'UP %s\\n' \"$(cut -d' ' -f1 /proc/uptime)\"; \
     df -P / 2>/dev/null | awk 'NR==2{printf \"DISK %d %d %s\\n\",$2,$3,$6}'";

#[derive(Serialize, Clone, Default)]
pub struct DiskInfo {
    pub mount: String,
    pub used_kb: u64,
    pub total_kb: u64,
}

#[derive(Serialize, Clone, Default)]
pub struct MetricsSnapshot {
    pub cpu_percent: f32,
    pub mem_used_kb: u64,
    pub mem_total_kb: u64,
    pub net_rx_bytes_per_sec: u64,
    pub net_tx_bytes_per_sec: u64,
    pub load1: f32,
    pub load5: f32,
    pub load15: f32,
    pub uptime_secs: u64,
    /// Refreshed every ~10 samples (disk changes slowly); `None` between refreshes.
    pub disks: Option<Vec<DiskInfo>>,
}

#[derive(Default)]
struct MetricsState {
    prev_cpu_idle: u64,
    prev_cpu_total: u64,
    prev_net_rx: u64,
    prev_net_tx: u64,
    first: bool,
    disk_tick: u32,
    last_disks: Vec<DiskInfo>,
}

impl MetricsState {
    fn new() -> Self {
        Self {
            first: true,
            ..Default::default()
        }
    }

    fn parse(&mut self, text: &str) -> MetricsSnapshot {
        let mut snap = MetricsSnapshot::default();
        let mut mem_total = 0u64;
        let mut mem_avail = 0u64;

        for line in text.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("cpu ") {
                let parts: Vec<u64> = rest
                    .split_whitespace()
                    .filter_map(|s| s.parse().ok())
                    .collect();
                if parts.len() >= 5 {
                    let idle = parts[3].saturating_add(parts[4]);
                    let total: u64 = parts.iter().sum();
                    let dt = total.saturating_sub(self.prev_cpu_total);
                    let di = idle.saturating_sub(self.prev_cpu_idle);
                    if dt > 0 && !self.first {
                        snap.cpu_percent = ((dt - di) as f32 / dt as f32 * 100.0).clamp(0.0, 100.0);
                    }
                    self.prev_cpu_total = total;
                    self.prev_cpu_idle = idle;
                }
            } else if let Some(rest) = line.strip_prefix("MemTotal:") {
                mem_total = rest
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
            } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
                mem_avail = rest
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
            } else if let Some(rest) = line.strip_prefix("NET ") {
                let parts: Vec<u64> = rest
                    .split_whitespace()
                    .filter_map(|s| s.parse().ok())
                    .collect();
                if parts.len() >= 2 {
                    if !self.first {
                        snap.net_rx_bytes_per_sec = parts[0].saturating_sub(self.prev_net_rx);
                        snap.net_tx_bytes_per_sec = parts[1].saturating_sub(self.prev_net_tx);
                    }
                    self.prev_net_rx = parts[0];
                    self.prev_net_tx = parts[1];
                }
            } else if let Some(rest) = line.strip_prefix("LOAD ") {
                let p: Vec<f32> = rest
                    .split_whitespace()
                    .filter_map(|s| s.parse().ok())
                    .collect();
                snap.load1 = p.first().copied().unwrap_or(0.0);
                snap.load5 = p.get(1).copied().unwrap_or(0.0);
                snap.load15 = p.get(2).copied().unwrap_or(0.0);
            } else if let Some(rest) = line.strip_prefix("UP ") {
                snap.uptime_secs = rest
                    .trim()
                    .split('.')
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
            }
        }

        snap.mem_total_kb = mem_total;
        snap.mem_used_kb = mem_total.saturating_sub(mem_avail);

        // Disk: refresh occasionally, reuse cached value in between.
        self.disk_tick += 1;
        if self.first || self.disk_tick >= 10 {
            self.disk_tick = 0;
            for line in text.lines() {
                if let Some(rest) = line.trim().strip_prefix("DISK ") {
                    let parts: Vec<&str> = rest.split_whitespace().collect();
                    if parts.len() >= 3 {
                        self.last_disks = vec![DiskInfo {
                            total_kb: parts[0].parse().unwrap_or(0),
                            used_kb: parts[1].parse().unwrap_or(0),
                            mount: parts[2].to_string(),
                        }];
                    }
                }
            }
            snap.disks = Some(self.last_disks.clone());
        }

        self.first = false;
        snap
    }
}

/// Sample the target: run `METRICS_CMD` over SSH (remote) or `sh -c` (local).
async fn collect(handle: Option<&SshHandle>) -> Result<String, String> {
    match handle {
        Some(handle) => {
            let channel = handle
                .channel_open_session()
                .await
                .map_err(|e| format!("channel error: {e}"))?;
            channel
                .exec(true, METRICS_CMD)
                .await
                .map_err(|e| format!("exec error: {e}"))?;
            let mut stream = channel.into_stream();
            let mut out = Vec::new();
            let read = timeout(Duration::from_secs(3), async {
                let mut buf = [0u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => out.extend_from_slice(&buf[..n]),
                    }
                }
            })
            .await;
            if read.is_err() {
                return Err("metrics sample timed out".into());
            }
            Ok(String::from_utf8_lossy(&out).to_string())
        }
        None => {
            let output = timeout(
                Duration::from_secs(3),
                tokio::process::Command::new("sh")
                    .arg("-c")
                    .arg(METRICS_CMD)
                    .output(),
            )
            .await
            .map_err(|_| "metrics sample timed out".to_string())?
            .map_err(|e| format!("failed to sample local metrics: {e}"))?;
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        }
    }
}

#[tauri::command]
pub async fn metrics_start(
    app: AppHandle,
    state: tauri::State<'_, crate::AppState>,
    session_id: String,
    local: bool,
) -> Result<String, String> {
    let handle: Option<SshHandle> = if local {
        None
    } else {
        let guard = state.sessions.lock().unwrap();
        let session = guard.get(&session_id).ok_or("SSH session is not open")?;
        Some(Arc::clone(&session.handle))
    };

    let stream_id = uuid::Uuid::new_v4().to_string();
    let event = format!("metrics-{}", stream_id);

    let task = tokio::spawn(async move {
        let mut st = MetricsState::new();
        loop {
            match collect(handle.as_ref()).await {
                Ok(text) => {
                    let snap = st.parse(&text);
                    if app.emit(&event, &snap).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });

    state
        .metrics_streams
        .lock()
        .unwrap()
        .insert(stream_id.clone(), task);
    Ok(stream_id)
}

#[tauri::command]
pub fn metrics_stop(state: tauri::State<'_, crate::AppState>, stream_id: String) {
    if let Some(task) = state.metrics_streams.lock().unwrap().remove(&stream_id) {
        task.abort();
    }
}
