//! Docker management — works over the active SSH connection *or* against the
//! local Docker daemon when invoked from a local-shell tab.
//!
//! Commands are built as argument vectors so the two transports stay clean:
//!   - **Remote**: the args are shell-quoted, joined onto `docker `, and exec'd
//!     on a fresh `channel_open_session()` over the existing multiplexed SSH
//!     `Handle` — so queries never disturb the user's live terminal.
//!   - **Local**: the args are passed straight to `Command::new("docker")`, with
//!     no shell in between (no quoting pitfalls, cross-platform).

use russh::client;
use russh::ChannelMsg;
use serde::Serialize;
use std::collections::HashMap;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::{AppHandle, Emitter};
use tokio::io::AsyncReadExt;
use tokio::time::timeout;

use crate::ssh_session::ClientHandler;

type SshHandle = Arc<client::Handle<ClientHandler>>;

/// stream_id → the running `docker logs --follow` task (aborted on stop).
pub type LogStreams = Arc<Mutex<HashMap<String, tokio::task::JoinHandle<()>>>>;

/// Quick queries (`ps`, `logs`) — fail fast if the host is unresponsive.
const QUERY_TIMEOUT: Duration = Duration::from_secs(15);
/// Lifecycle actions honour Docker's ~10s graceful-stop window, so allow more.
const ACTION_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Serialize, Clone)]
pub struct DockerContainer {
    pub id: String,
    pub name: String,
    pub image: String,
    /// Human-readable status, e.g. "Up 3 hours" or "Exited (0) 2 days ago".
    pub status: String,
    /// Machine state: running | exited | paused | created | restarting | dead.
    pub state: String,
    pub ports: String,
}

#[derive(Serialize, Clone)]
pub struct DockerImage {
    pub id: String,
    pub repo_tag: String,
    pub size: String,
}

#[derive(Serialize, Clone)]
pub struct DockerVolume {
    pub name: String,
    pub driver: String,
}

#[derive(Serialize, Clone)]
pub struct DockerNetwork {
    pub id: String,
    pub name: String,
    pub driver: String,
}

struct ExecOutput {
    stdout: String,
    stderr: String,
    code: Option<u32>,
}

/// Single-quote a value for safe interpolation into a remote shell command.
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Run `docker <args>` either over SSH (when `handle` is `Some`) or as a local
/// subprocess (when `handle` is `None`), collecting stdout/stderr and exit code.
async fn run(
    handle: Option<&SshHandle>,
    args: &[&str],
    limit: Duration,
) -> Result<ExecOutput, String> {
    match handle {
        Some(handle) => exec_ssh(handle, args, limit).await,
        None => exec_local(args, limit).await,
    }
}

async fn exec_ssh(
    handle: &SshHandle,
    args: &[&str],
    limit: Duration,
) -> Result<ExecOutput, String> {
    let cmd = std::iter::once("docker".to_string())
        .chain(args.iter().map(|a| shell_quote(a)))
        .collect::<Vec<_>>()
        .join(" ");

    let mut channel = handle
        .channel_open_session()
        .await
        .map_err(|e| format!("Failed to open channel: {}", e))?;

    channel
        .exec(true, cmd.as_str())
        .await
        .map_err(|e| format!("exec failed: {}", e))?;

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut code: Option<u32> = None;

    let read = timeout(limit, async {
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Data { data }) => stdout.extend_from_slice(&data),
                Some(ChannelMsg::ExtendedData { data, .. }) => stderr.extend_from_slice(&data),
                Some(ChannelMsg::ExitStatus { exit_status }) => code = Some(exit_status),
                // `Eof` arrives before the channel fully closes — and the
                // `ExitStatus` message often comes *after* it, so we must keep
                // reading until `Close`/`None` to capture the real exit code.
                Some(ChannelMsg::Close) | None => break,
                _ => {}
            }
        }
    })
    .await;

    if read.is_err() {
        return Err("Docker command timed out".to_string());
    }

    Ok(ExecOutput {
        stdout: String::from_utf8_lossy(&stdout).to_string(),
        stderr: String::from_utf8_lossy(&stderr).to_string(),
        code,
    })
}

async fn exec_local(args: &[&str], limit: Duration) -> Result<ExecOutput, String> {
    let output = timeout(
        limit,
        tokio::process::Command::new("docker").args(args).output(),
    )
    .await
    .map_err(|_| "Docker command timed out".to_string())?
    .map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            "Docker is not installed or not on PATH".to_string()
        } else {
            format!("Failed to run docker: {}", e)
        }
    })?;

    Ok(ExecOutput {
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        code: output.status.code().map(|c| c as u32),
    })
}

/// Map a raw exec result into a friendly error when the command failed.
fn require_success(out: ExecOutput) -> Result<String, String> {
    // `None` = the server closed the channel without an explicit exit-status
    // message; treat that as success rather than surfacing stdout as an error.
    if matches!(out.code, Some(0) | None) {
        return Ok(out.stdout);
    }
    let msg = out.stderr.trim();
    let msg = if msg.is_empty() {
        out.stdout.trim()
    } else {
        msg
    };
    if msg.contains("command not found") || msg.contains("not found") && msg.contains("docker") {
        return Err("Docker is not installed or not on PATH for this user".to_string());
    }
    if msg.contains("permission denied") || msg.contains("Got permission denied") {
        return Err(
            "Permission denied talking to the Docker daemon (is this user in the `docker` group?)"
                .to_string(),
        );
    }
    Err(if msg.is_empty() {
        "Docker command failed".to_string()
    } else {
        msg.to_string()
    })
}

/// Resolve the transport: `Some(handle)` for a remote SSH session, or `None`
/// for the local daemon when `local` is true.
fn transport(
    state: &crate::AppState,
    session_id: &str,
    local: bool,
) -> Result<Option<SshHandle>, String> {
    if local {
        return Ok(None);
    }
    let guard = state.sessions.lock().unwrap();
    let session = guard.get(session_id).ok_or("SSH session is not open")?;
    Ok(Some(Arc::clone(&session.handle)))
}

#[tauri::command]
pub async fn docker_ps(
    state: tauri::State<'_, crate::AppState>,
    session_id: String,
    local: bool,
    all: bool,
) -> Result<Vec<DockerContainer>, String> {
    let handle = transport(&state, &session_id, local)?;
    let mut args = vec!["ps"];
    if all {
        args.push("-a");
    }
    // `{{json .}}` emits one JSON object per line — robust against tabs/spaces.
    args.extend(["--no-trunc", "--format", "{{json .}}"]);
    let out = require_success(run(handle.as_ref(), &args, QUERY_TIMEOUT).await?)?;

    #[derive(serde::Deserialize)]
    struct Raw {
        #[serde(rename = "ID", default)]
        id: String,
        #[serde(rename = "Names", default)]
        names: String,
        #[serde(rename = "Image", default)]
        image: String,
        #[serde(rename = "Status", default)]
        status: String,
        #[serde(rename = "State", default)]
        state: String,
        #[serde(rename = "Ports", default)]
        ports: String,
    }

    let mut containers = Vec::new();
    for line in out.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(raw) = serde_json::from_str::<Raw>(line) {
            // Docker < 20.10 omits the `State` field; derive it from `Status`
            // so the UI shows the right action buttons regardless of version.
            let state = if !raw.state.is_empty() {
                raw.state
            } else if raw.status.contains("(Paused)") {
                "paused".to_string()
            } else if raw.status.starts_with("Up") {
                "running".to_string()
            } else {
                "exited".to_string()
            };
            containers.push(DockerContainer {
                // Short id is plenty for display; full id still works for actions.
                id: raw.id.chars().take(12).collect(),
                name: raw.names.split(',').next().unwrap_or("").trim().to_string(),
                image: raw.image,
                status: raw.status,
                state,
                ports: raw.ports,
            });
        }
    }
    Ok(containers)
}

#[tauri::command]
pub async fn docker_images(
    state: tauri::State<'_, crate::AppState>,
    session_id: String,
    local: bool,
) -> Result<Vec<DockerImage>, String> {
    let handle = transport(&state, &session_id, local)?;
    let out = require_success(
        run(
            handle.as_ref(),
            &["images", "--format", "{{json .}}"],
            QUERY_TIMEOUT,
        )
        .await?,
    )?;

    #[derive(serde::Deserialize)]
    struct Raw {
        #[serde(rename = "ID", default)]
        id: String,
        #[serde(rename = "Repository", default)]
        repository: String,
        #[serde(rename = "Tag", default)]
        tag: String,
        #[serde(rename = "Size", default)]
        size: String,
    }

    let mut images = Vec::new();
    for line in out.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if let Ok(raw) = serde_json::from_str::<Raw>(line) {
            let repo_tag = if raw.tag.is_empty() || raw.tag == "<none>" {
                raw.repository
            } else {
                format!("{}:{}", raw.repository, raw.tag)
            };
            images.push(DockerImage {
                id: raw.id.chars().take(12).collect(),
                repo_tag,
                size: raw.size,
            });
        }
    }
    Ok(images)
}

#[tauri::command]
pub async fn docker_volumes(
    state: tauri::State<'_, crate::AppState>,
    session_id: String,
    local: bool,
) -> Result<Vec<DockerVolume>, String> {
    let handle = transport(&state, &session_id, local)?;
    let out = require_success(
        run(
            handle.as_ref(),
            &["volume", "ls", "--format", "{{json .}}"],
            QUERY_TIMEOUT,
        )
        .await?,
    )?;

    #[derive(serde::Deserialize)]
    struct Raw {
        #[serde(rename = "Name", default)]
        name: String,
        #[serde(rename = "Driver", default)]
        driver: String,
    }

    let mut volumes = Vec::new();
    for line in out.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if let Ok(raw) = serde_json::from_str::<Raw>(line) {
            volumes.push(DockerVolume {
                name: raw.name,
                driver: raw.driver,
            });
        }
    }
    Ok(volumes)
}

#[tauri::command]
pub async fn docker_networks(
    state: tauri::State<'_, crate::AppState>,
    session_id: String,
    local: bool,
) -> Result<Vec<DockerNetwork>, String> {
    let handle = transport(&state, &session_id, local)?;
    let out = require_success(
        run(
            handle.as_ref(),
            &["network", "ls", "--format", "{{json .}}"],
            QUERY_TIMEOUT,
        )
        .await?,
    )?;

    #[derive(serde::Deserialize)]
    struct Raw {
        #[serde(rename = "ID", default)]
        id: String,
        #[serde(rename = "Name", default)]
        name: String,
        #[serde(rename = "Driver", default)]
        driver: String,
    }

    let mut networks = Vec::new();
    for line in out.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if let Ok(raw) = serde_json::from_str::<Raw>(line) {
            networks.push(DockerNetwork {
                id: raw.id.chars().take(12).collect(),
                name: raw.name,
                driver: raw.driver,
            });
        }
    }
    Ok(networks)
}

#[tauri::command]
pub async fn docker_action(
    state: tauri::State<'_, crate::AppState>,
    session_id: String,
    local: bool,
    container_id: String,
    action: String,
) -> Result<(), String> {
    let handle = transport(&state, &session_id, local)?;
    let args: Vec<&str> = match action.as_str() {
        "start" => vec!["start", &container_id],
        "stop" => vec!["stop", &container_id],
        "restart" => vec!["restart", &container_id],
        "pause" => vec!["pause", &container_id],
        "unpause" => vec!["unpause", &container_id],
        "remove" => vec!["rm", "-f", &container_id],
        other => return Err(format!("Unknown docker action: {}", other)),
    };
    require_success(run(handle.as_ref(), &args, ACTION_TIMEOUT).await?)?;
    Ok(())
}

/// Open an interactive shell inside a container as a new terminal session.
/// Returns the new session id; the frontend opens a terminal tab bound to it.
/// Prefers `bash`, falling back to `sh` for minimal images.
#[tauri::command]
pub async fn docker_shell(
    app_handle: tauri::AppHandle,
    state: tauri::State<'_, crate::AppState>,
    session_id: String,
    local: bool,
    container_id: String,
) -> Result<String, String> {
    let new_id = uuid::Uuid::new_v4().to_string();
    let inner = "command -v bash >/dev/null 2>&1 && exec bash || exec sh";

    if local {
        let mut cmd = portable_pty::CommandBuilder::new("docker");
        cmd.arg("exec");
        cmd.arg("-it");
        cmd.arg(&container_id);
        cmd.arg("sh");
        cmd.arg("-c");
        cmd.arg(inner);
        crate::local_session::connect_command(
            app_handle,
            state.local_sessions.clone(),
            new_id.clone(),
            cmd,
        )?;
    } else {
        let handle = {
            let guard = state.sessions.lock().unwrap();
            let session = guard.get(&session_id).ok_or("SSH session is not open")?;
            Arc::clone(&session.handle)
        };
        // The double-quoted -c argument is one literal token to the host shell;
        // the inner sh interprets the bash/sh fallback.
        let exec = format!(
            "docker exec -it {} sh -c \"{}\"",
            shell_quote(&container_id),
            inner
        );
        crate::ssh_session::open_container_shell(
            app_handle,
            state.sessions.clone(),
            new_id.clone(),
            handle,
            exec,
        )
        .await?;
    }

    Ok(new_id)
}

/// Background task: follow a container's logs and emit each chunk as a
/// `docker-log-<streamId>` event (string payload) until the stream ends or the
/// task is aborted. stderr is merged via `2>&1` so startup errors show too.
async fn stream_logs_task(
    app: AppHandle,
    event: String,
    handle: Option<SshHandle>,
    container_id: String,
    tail: u32,
) {
    let cmd = format!(
        "docker logs --follow --tail {} {} 2>&1",
        tail,
        shell_quote(&container_id)
    );

    match handle {
        Some(handle) => {
            let channel = match handle.channel_open_session().await {
                Ok(c) => c,
                Err(e) => {
                    let _ = app.emit(&event, format!("Error opening channel: {e}\n"));
                    return;
                }
            };
            if channel.exec(true, cmd.as_str()).await.is_err() {
                return;
            }
            let mut stream = channel.into_stream();
            let mut buf = [0u8; 4096];
            while let Ok(n) = stream.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                let _ = app.emit(&event, String::from_utf8_lossy(&buf[..n]).to_string());
            }
        }
        None => {
            let mut child = match tokio::process::Command::new("sh")
                .arg("-c")
                .arg(&cmd)
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()
            {
                Ok(c) => c,
                Err(e) => {
                    let _ = app.emit(&event, format!("Failed to run docker logs: {e}\n"));
                    return;
                }
            };
            if let Some(mut out) = child.stdout.take() {
                let mut buf = [0u8; 4096];
                while let Ok(n) = out.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    let _ = app.emit(&event, String::from_utf8_lossy(&buf[..n]).to_string());
                }
            }
        }
    }

    let _ = app.emit(&format!("{event}-end"), ());
}

#[tauri::command]
pub async fn docker_logs_stream(
    app: AppHandle,
    state: tauri::State<'_, crate::AppState>,
    session_id: String,
    local: bool,
    container_id: String,
    tail: u32,
) -> Result<String, String> {
    let handle = transport(&state, &session_id, local)?;
    let stream_id = uuid::Uuid::new_v4().to_string();
    let event = format!("docker-log-{}", stream_id);
    let task = tokio::spawn(stream_logs_task(app, event, handle, container_id, tail));
    state
        .docker_log_streams
        .lock()
        .unwrap()
        .insert(stream_id.clone(), task);
    Ok(stream_id)
}

#[tauri::command]
pub fn docker_logs_stream_stop(state: tauri::State<'_, crate::AppState>, stream_id: String) {
    if let Some(task) = state.docker_log_streams.lock().unwrap().remove(&stream_id) {
        task.abort();
    }
}

#[tauri::command]
pub async fn docker_logs(
    state: tauri::State<'_, crate::AppState>,
    session_id: String,
    local: bool,
    container_id: String,
    tail: u32,
) -> Result<String, String> {
    let handle = transport(&state, &session_id, local)?;
    let tail = tail.to_string();
    let args = ["logs", "--tail", &tail, &container_id];
    let out = run(handle.as_ref(), &args, QUERY_TIMEOUT).await?;
    if !matches!(out.code, Some(0) | None) {
        return require_success(out);
    }
    // Container logs go to both streams; merge so app output and startup
    // errors both show. stdout first keeps chronological-ish ordering.
    let mut combined = out.stdout;
    if !out.stderr.is_empty() {
        combined.push_str(&out.stderr);
    }
    Ok(combined)
}
