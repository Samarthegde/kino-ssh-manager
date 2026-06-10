use russh::{
    client,
    keys::{
        ssh_key::{HashAlg, PublicKey},
        PrivateKeyWithHashAlg,
    },
    Channel, ChannelMsg,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::{AppHandle, Emitter};
use tokio::sync::mpsc;

use crate::vault::Host;

pub enum TermCommand {
    Data(Vec<u8>),
    Resize(u32, u32),
    Close,
}

pub struct SshSession {
    pub cmd_tx: mpsc::Sender<TermCommand>,
    pub handle: Arc<client::Handle<ClientHandler>>,
    /// Remote-forward route table for this connection (see `forwarding`).
    pub remote_routes: RemoteRoutes,
}

pub type Sessions = Arc<Mutex<HashMap<String, SshSession>>>;

/// `(bind_host, remote_port)` → `(local_target_host, local_target_port)`.
/// Populated by remote forwards; consulted in `server_channel_open_forwarded_tcpip`.
pub type RemoteRoutes = Arc<Mutex<HashMap<(String, u16), (String, u16)>>>;

pub struct ClientHandler {
    pub host: Host,
    pub remote_routes: RemoteRoutes,
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        let fp = server_public_key.fingerprint(HashAlg::Sha256).to_string();
        if let Err(e) = crate::host_keys::enforce(&self.host, &fp) {
            log::error!("Host key enforcement failed: {}", e);
            return Ok(false);
        }
        Ok(true)
    }

    /// The server opened a connection on a port we requested via `tcpip_forward`
    /// (a remote/reverse forward). Bridge it to the registered local target.
    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<client::Msg>,
        connected_address: &str,
        connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let target = self
            .remote_routes
            .lock()
            .unwrap()
            .get(&(connected_address.to_string(), connected_port as u16))
            .cloned();
        match target {
            Some((host, port)) => {
                tokio::spawn(crate::forwarding::bridge_remote(channel, host, port));
            }
            None => {
                let _ = channel.close().await;
            }
        }
        Ok(())
    }
}

pub async fn connect(
    app_handle: AppHandle,
    sessions: Sessions,
    session_id: String,
    host: Host,
    on_connect: Vec<String>,
) -> Result<(), String> {
    let config = Arc::new(client::Config {
        // Send keepalives so dropped connections surface promptly instead of
        // hanging multiplexed channels (terminal, SFTP, docker, forwards).
        keepalive_interval: Some(Duration::from_secs(15)),
        keepalive_max: 3,
        ..Default::default()
    });

    let remote_routes: RemoteRoutes = Arc::new(Mutex::new(HashMap::new()));
    let handler = ClientHandler {
        host: host.clone(),
        remote_routes: Arc::clone(&remote_routes),
    };

    let mut handle = tokio::time::timeout(
        Duration::from_secs(15),
        client::connect(config, (host.hostname.as_str(), host.port), handler),
    )
    .await
    .map_err(|_| "Connection timed out".to_string())?
    .map_err(|e| format!("Connection failed: {}", e))?;

    // Authentication
    let auth_res = match host.default_auth.as_str() {
        "Password" => {
            let pw = host
                .password
                .as_deref()
                .ok_or("No password stored for this host")?;
            handle.authenticate_password(&host.username, pw).await
        }
        "SshKey" => {
            let key_str = host
                .private_key
                .as_deref()
                .ok_or("No SSH key stored for this host")?;
            let key_pair = russh::keys::decode_secret_key(key_str, host.passphrase.as_deref())
                .map_err(|e| format!("Invalid private key: {}", e))?;
            let key = PrivateKeyWithHashAlg::new(Arc::new(key_pair), Some(HashAlg::Sha256));
            handle.authenticate_publickey(&host.username, key).await
        }
        other => return Err(format!("Unknown auth method: {}", other)),
    };

    let authenticated = auth_res.map_err(|e| format!("Auth error: {}", e))?;
    if !authenticated.success() {
        return Err("Authentication failed".to_string());
    }

    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| format!("Failed to open channel: {}", e))?;

    channel
        .request_pty(false, "xterm-256color", 220, 50, 0, 0, &[])
        .await
        .map_err(|e| format!("PTY request failed: {}", e))?;

    channel
        .request_shell(false)
        .await
        .map_err(|e| format!("Shell request failed: {}", e))?;

    let (cmd_tx, cmd_rx) = mpsc::channel::<TermCommand>(256);

    sessions.lock().unwrap().insert(
        session_id.clone(),
        SshSession {
            cmd_tx,
            handle: Arc::new(handle),
            remote_routes,
        },
    );

    spawn_relay(
        app_handle, sessions, session_id, channel, cmd_rx, on_connect,
    );

    Ok(())
}

/// Open an interactive shell *inside a container* by exec'ing a command over a
/// fresh channel on the existing connection. Stored in the same `sessions` map
/// so ssh_write/ssh_resize/ssh_disconnect drive it like a normal terminal tab.
pub async fn open_container_shell(
    app_handle: AppHandle,
    sessions: Sessions,
    session_id: String,
    handle: Arc<client::Handle<ClientHandler>>,
    exec_command: String,
) -> Result<(), String> {
    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| format!("Failed to open channel: {}", e))?;

    channel
        .request_pty(false, "xterm-256color", 220, 50, 0, 0, &[])
        .await
        .map_err(|e| format!("PTY request failed: {}", e))?;

    channel
        .exec(false, exec_command.as_str())
        .await
        .map_err(|e| format!("Container exec failed: {}", e))?;

    let (cmd_tx, cmd_rx) = mpsc::channel::<TermCommand>(256);
    sessions.lock().unwrap().insert(
        session_id.clone(),
        SshSession {
            cmd_tx,
            handle: Arc::clone(&handle),
            // Container shells don't host remote forwards.
            remote_routes: Arc::new(Mutex::new(HashMap::new())),
        },
    );

    spawn_relay(
        app_handle,
        sessions,
        session_id,
        channel,
        cmd_rx,
        Vec::new(),
    );
    Ok(())
}

/// Drive an interactive PTY channel: pump terminal input from `cmd_rx` into the
/// channel and emit channel output as `ssh-data-<id>` events until it closes.
fn spawn_relay(
    app_handle: AppHandle,
    sessions: Sessions,
    session_id: String,
    mut channel: Channel<client::Msg>,
    mut cmd_rx: mpsc::Receiver<TermCommand>,
    on_connect: Vec<String>,
) {
    tokio::spawn(async move {
        // Auto-run on-connect snippets (empty for container shells).
        if !on_connect.is_empty() {
            tokio::time::sleep(Duration::from_millis(400)).await;
            for snippet in &on_connect {
                let text = snippet.replace("\r\n", "\n");
                let payload = if text.ends_with('\n') {
                    text
                } else {
                    format!("{}\n", text)
                };
                let _ = channel.data(payload.as_bytes()).await;
            }
        }

        loop {
            tokio::select! {
                cmd = cmd_rx.recv() => {
                    match cmd {
                        Some(TermCommand::Data(data)) => {
                            let _ = channel.data(&data[..]).await;
                        }
                        Some(TermCommand::Resize(cols, rows)) => {
                            let _ = channel.window_change(cols, rows, 0, 0).await;
                        }
                        Some(TermCommand::Close) | None => {
                            let _ = channel.close().await;
                            sessions.lock().unwrap().remove(&session_id);
                            app_handle.emit(&format!("ssh-closed-{}", session_id), ()).ok();
                            return;
                        }
                    }
                }
                msg = channel.wait() => {
                    match msg {
                        Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                            app_handle.emit(&format!("ssh-data-{}", session_id), data.as_ref()).ok();
                        }
                        Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => {
                            sessions.lock().unwrap().remove(&session_id);
                            app_handle.emit(&format!("ssh-closed-{}", session_id), ()).ok();
                            return;
                        }
                        _ => {}
                    }
                }
            }
        }
    });
}
