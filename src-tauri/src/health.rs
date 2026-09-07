//! Lightweight reachability probe for the host list.
//!
//! Each probe is a plain TCP connect to the host's SSH endpoint - reusing the
//! same transport path as a real connection, so a configured SOCKS5/HTTP proxy
//! is honored - timed and then dropped immediately. No SSH handshake, no
//! credentials, nothing written to the socket.
//!
//! Hosts that can only be reached by standing up a session (agent/relay mode, or
//! anything behind a jump host) report `unknown` rather than a misleading
//! `down`: probing them would mean opening a relay tunnel or a full bastion SSH
//! connection every cycle, which is far too expensive for a background poll.

use serde::Serialize;
use std::time::{Duration, Instant};

use crate::vault::Host;

/// Long enough for a slow WAN round trip, short enough that a dead host doesn't
/// stall the sweep.
const PROBE_TIMEOUT: Duration = Duration::from_secs(4);

#[derive(Serialize, Clone)]
pub struct HostHealth {
    pub id: String,
    /// "up" | "down" | "unknown"
    pub status: String,
    /// Round-trip of the TCP connect, present only when `status` is "up".
    pub latency_ms: Option<u32>,
    /// Why the host is down, or why it wasn't probed.
    pub detail: Option<String>,
}

fn result(id: &str, status: &str, latency_ms: Option<u32>, detail: Option<String>) -> HostHealth {
    HostHealth {
        id: id.to_string(),
        status: status.to_string(),
        latency_ms,
        detail,
    }
}

async fn probe(host: &Host) -> HostHealth {
    if host.connection_mode.as_deref() == Some("agent") {
        return result(
            &host.id,
            "unknown",
            None,
            Some("Reached through a relay - not probed".into()),
        );
    }
    if host
        .jump_host
        .as_deref()
        .map(str::trim)
        .is_some_and(|s| !s.is_empty())
    {
        return result(
            &host.id,
            "unknown",
            None,
            Some("Reached through a jump host - not probed".into()),
        );
    }

    let started = Instant::now();
    match tokio::time::timeout(PROBE_TIMEOUT, crate::ssh_session::open_target_stream(host)).await {
        // The stream drops here, closing the probe connection right away.
        Ok(Ok(_stream)) => result(
            &host.id,
            "up",
            Some(started.elapsed().as_millis().min(u128::from(u32::MAX)) as u32),
            None,
        ),
        Ok(Err(e)) => result(&host.id, "down", None, Some(e)),
        Err(_) => result(&host.id, "down", None, Some("Timed out".into())),
    }
}

/// Probe every supplied host concurrently and return one result per host.
#[tauri::command]
pub async fn check_hosts_health(hosts: Vec<Host>) -> Vec<HostHealth> {
    futures_util::future::join_all(hosts.iter().map(probe)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(id: &str) -> Host {
        Host {
            id: id.into(),
            name: id.into(),
            hostname: "127.0.0.1".into(),
            port: 1,
            username: "u".into(),
            default_auth: "Password".into(),
            password: None,
            private_key: None,
            public_key: None,
            passphrase: None,
            port_forwards: vec![],
            on_connect_snippets: vec![],
            color: None,
            notes: None,
            group: None,
            os: None,
            connection_mode: None,
            agent_id: None,
            relay_url: None,
            relay_token: None,
            control_url: None,
            proxy_type: None,
            proxy_host: None,
            proxy_port: None,
            proxy_username: None,
            proxy_password: None,
            jump_host: None,
            jump: None,
            key_added_at: None,
            ntfy_topic: None,
            environment: None,
        }
    }

    #[tokio::test]
    async fn agent_hosts_are_reported_unknown_not_down() {
        let mut h = host("a");
        h.connection_mode = Some("agent".into());
        let r = probe(&h).await;
        assert_eq!(r.status, "unknown");
        assert!(r.latency_ms.is_none());
    }

    #[tokio::test]
    async fn jump_host_targets_are_reported_unknown() {
        let mut h = host("b");
        h.jump_host = Some("bastion-id".into());
        assert_eq!(probe(&h).await.status, "unknown");
    }

    #[tokio::test]
    async fn a_closed_port_is_down_with_a_reason() {
        // Port 1 on loopback is not listening in any sane test environment.
        let r = probe(&host("c")).await;
        assert_eq!(r.status, "down");
        assert!(r.detail.is_some());
        assert!(r.latency_ms.is_none());
    }
}
