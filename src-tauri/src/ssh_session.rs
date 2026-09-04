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
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub enum NetStream {
    Tcp(tokio::net::TcpStream),
    Duplex(tokio::io::DuplexStream),
    /// A direct-tcpip channel tunneled through a jump/bastion host. The boxed
    /// `JumpStream` keeps the bastion's SSH handle alive for the tunnel's life.
    Jump(Box<JumpStream>),
}

/// The transport for a jump-host connection: an SSH channel from the bastion to
/// the target, plus the bastion handle that must outlive it.
pub struct JumpStream {
    inner: russh::ChannelStream<client::Msg>,
    /// Kept solely so the bastion connection isn't dropped while in use.
    _jump: Arc<client::Handle<ClientHandler>>,
}

impl AsyncRead for NetStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            NetStream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            NetStream::Duplex(s) => Pin::new(s).poll_read(cx, buf),
            NetStream::Jump(s) => Pin::new(&mut s.inner).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for NetStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            NetStream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            NetStream::Duplex(s) => Pin::new(s).poll_write(cx, buf),
            NetStream::Jump(s) => Pin::new(&mut s.inner).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            NetStream::Tcp(s) => Pin::new(s).poll_flush(cx),
            NetStream::Duplex(s) => Pin::new(s).poll_flush(cx),
            NetStream::Jump(s) => Pin::new(&mut s.inner).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            NetStream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            NetStream::Duplex(s) => Pin::new(s).poll_shutdown(cx),
            NetStream::Jump(s) => Pin::new(&mut s.inner).poll_shutdown(cx),
        }
    }
}

/// Turn an established relay WebSocket into a byte stream SSH can run over:
/// binary frames in both directions, bridged onto an in-memory duplex pipe.
fn bridge_agent_ws(
    ws_stream: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> Result<NetStream, String> {
    let (mut ws_tx, mut ws_rx) = futures_util::StreamExt::split(ws_stream);
    let (client_stream, backend_stream) = tokio::io::duplex(65536);
    let (mut backend_rx, mut backend_tx) = tokio::io::split(backend_stream);

    tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        while let Some(msg) = futures_util::StreamExt::next(&mut ws_rx).await {
            if let Ok(tokio_tungstenite::tungstenite::protocol::Message::Binary(data)) = msg {
                if backend_tx.write_all(&data).await.is_err() {
                    break;
                }
            }
        }
    });

    tokio::spawn(async move {
        use futures_util::SinkExt;
        use tokio::io::AsyncReadExt;
        let mut buf = [0u8; 8192];
        loop {
            match backend_rx.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if ws_tx
                        .send(tokio_tungstenite::tungstenite::protocol::Message::Binary(
                            buf[..n].into(),
                        ))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    Ok(NetStream::Duplex(client_stream))
}

pub async fn connect_to_host(host: &Host) -> Result<NetStream, String> {
    if host.connection_mode.as_deref() == Some("agent") {
        let agent_id = host
            .agent_id
            .as_deref()
            .ok_or("Agent ID not provided for Agent connection mode")?;

        // Kino Cloud host: no relay details stored at all - one call to
        // kino-control returns a fresh short-lived manager JWT plus where the
        // agent is parked (with an in-memory fallback cache for outages).
        let is_cloud = host.relay_url.as_deref().unwrap_or("").is_empty()
            && host.control_url.as_deref().unwrap_or("").is_empty()
            && host.relay_token.as_deref().unwrap_or("").is_empty();
        if is_cloud {
            let agent = agent_id.to_string();
            let (token, relay_url) =
                tokio::task::spawn_blocking(move || crate::cloud::connect_info(&agent))
                    .await
                    .map_err(|e| format!("Cloud connect task failed: {}", e))??;
            let ws_url = format!("{}/ws/manager/request?agent_id={}", relay_url, agent_id);
            let mut request =
                tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(
                    &ws_url,
                )
                .map_err(|e| format!("Invalid relay URL: {}", e))?;
            let value = format!("Bearer {}", token)
                .parse()
                .map_err(|e| format!("Invalid connection token: {}", e))?;
            request.headers_mut().insert(
                tokio_tungstenite::tungstenite::http::header::AUTHORIZATION,
                value,
            );
            let (ws_stream, _) = tokio_tungstenite::connect_async(request)
                .await
                .map_err(|e| format!("Failed to connect to relay: {}", e))?;
            return bridge_agent_ws(ws_stream);
        }

        // Which relay to dial: ask kino-control where the agent is parked
        // (discovery mode), falling back to the host's saved relay URL if the
        // lookup fails - so a control outage degrades instead of locking you out.
        let relay_url = match host.control_url.as_deref().filter(|c| !c.is_empty()) {
            Some(control) => {
                let lookup_url = format!(
                    "{}/api/agents/{}/relay",
                    control.trim_end_matches('/'),
                    agent_id
                );
                let bearer = format!("Bearer {}", host.relay_token.as_deref().unwrap_or(""));
                let located = tokio::task::spawn_blocking(move || -> Option<String> {
                    let body: serde_json::Value = ureq::get(&lookup_url)
                        .set("Authorization", &bearer)
                        .timeout(std::time::Duration::from_secs(5))
                        .call()
                        .ok()?
                        .into_json()
                        .ok()?;
                    body["relay_url"].as_str().map(str::to_string)
                })
                .await
                .map_err(|e| format!("Relay lookup task failed: {}", e))?;
                match located {
                    Some(url) => url,
                    None => host
                        .relay_url
                        .clone()
                        .filter(|u| !u.is_empty())
                        .ok_or("kino-control could not locate the agent and this host has no fallback Relay URL")?,
                }
            }
            None => host
                .relay_url
                .clone()
                .filter(|u| !u.is_empty())
                .ok_or("Relay URL not provided for Agent connection mode")?,
        };

        let ws_url = format!("{}/ws/manager/request?agent_id={}", relay_url, agent_id);
        // Token travels as a header, not a query parameter, so it stays out of
        // relay/proxy access logs.
        let mut request =
            tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(&ws_url)
                .map_err(|e| format!("Invalid relay URL: {}", e))?;
        if let Some(token) = host.relay_token.as_deref().filter(|t| !t.is_empty()) {
            let value = format!("Bearer {}", token)
                .parse()
                .map_err(|e| format!("Invalid relay token: {}", e))?;
            request.headers_mut().insert(
                tokio_tungstenite::tungstenite::http::header::AUTHORIZATION,
                value,
            );
        }
        let (ws_stream, _) = tokio_tungstenite::connect_async(request)
            .await
            .map_err(|e| format!("Failed to connect to relay: {}", e))?;

        bridge_agent_ws(ws_stream)
    } else if let Some(jump) = host.jump.as_deref() {
        // Tunnel to the target through a bastion: open an SSH session to the
        // jump host, then a direct-tcpip channel from it out to host:port. Any
        // proxy configured on the *target* is bypassed - the bastion is the path.
        let jump_handle = establish_jump(jump).await?;
        let channel = jump_handle
            .channel_open_direct_tcpip(host.hostname.clone(), host.port as u32, "127.0.0.1", 0)
            .await
            .map_err(|e| {
                format!(
                    "Jump host \"{}\" could not reach {}:{}: {e}",
                    jump.name, host.hostname, host.port
                )
            })?;
        Ok(NetStream::Jump(Box::new(JumpStream {
            inner: channel.into_stream(),
            _jump: jump_handle,
        })))
    } else {
        let stream = open_target_stream(host).await?;
        Ok(NetStream::Tcp(stream))
    }
}

/// Open (and authenticate) an SSH session to a bastion/jump host, returning a
/// live handle. The bastion's own `jump`, proxy, and agent settings are honored,
/// so bastions can chain. The returned handle must stay alive for as long as the
/// tunneled session runs - `NetStream::Jump` holds it for exactly that long.
async fn establish_jump(host: &Host) -> Result<Arc<client::Handle<ClientHandler>>, String> {
    let config = Arc::new(client::Config {
        keepalive_interval: Some(Duration::from_secs(15)),
        keepalive_max: 3,
        ..Default::default()
    });
    let handler = ClientHandler {
        host: host.clone(),
        remote_routes: Arc::new(Mutex::new(HashMap::new())),
    };
    // Boxed because connect_to_host recurses back here for multi-hop chains.
    let stream = Box::pin(connect_to_host(host)).await?;
    let mut handle = tokio::time::timeout(
        Duration::from_secs(15),
        client::connect_stream(config, stream, handler),
    )
    .await
    .map_err(|_| format!("Connection to jump host \"{}\" timed out", host.name))?
    .map_err(|e| format!("Jump host \"{}\" connection failed: {e}", host.name))?;
    authenticate(&mut handle, host).await?;
    Ok(Arc::new(handle))
}

/// Open a TCP stream to the host's SSH endpoint, optionally through a proxy.
/// When a proxy is configured the hostname is resolved *proxy-side* (no DNS leak
/// for SOCKS5), and the target port is the host's SSH port.
pub(crate) async fn open_target_stream(host: &Host) -> Result<tokio::net::TcpStream, String> {
    let ptype = host
        .proxy_type
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty() && *p != "none");
    let proxy_host = host.proxy_host.as_deref().map(str::trim).unwrap_or("");
    match ptype {
        Some(kind) if !proxy_host.is_empty() => {
            let proxy_port = host.proxy_port.ok_or("Proxy port not set for this host")?;
            let user = host.proxy_username.as_deref().filter(|s| !s.is_empty());
            let pass = host.proxy_password.as_deref().filter(|s| !s.is_empty());
            match kind {
                "socks5" | "socks" => {
                    socks5_connect(
                        proxy_host,
                        proxy_port,
                        user,
                        pass,
                        &host.hostname,
                        host.port,
                    )
                    .await
                }
                "http" | "https" | "connect" => {
                    http_connect(
                        proxy_host,
                        proxy_port,
                        user,
                        pass,
                        &host.hostname,
                        host.port,
                    )
                    .await
                }
                other => Err(format!("Unknown proxy type: {other}")),
            }
        }
        _ => tokio::net::TcpStream::connect((host.hostname.as_str(), host.port))
            .await
            .map_err(|e| {
                format!(
                    "Failed to connect to {}:{}: {}",
                    host.hostname, host.port, e
                )
            }),
    }
}

/// Minimal SOCKS5 (RFC 1928) client with optional username/password auth
/// (RFC 1929). The target host is sent as a domain name so the proxy resolves
/// it - the DNS request never leaves the proxy side.
async fn socks5_connect(
    proxy_host: &str,
    proxy_port: u16,
    user: Option<&str>,
    pass: Option<&str>,
    target_host: &str,
    target_port: u16,
) -> Result<tokio::net::TcpStream, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let domain = target_host.as_bytes();
    if domain.len() > 255 {
        return Err("Target hostname too long for SOCKS5".to_string());
    }

    let mut s = tokio::net::TcpStream::connect((proxy_host, proxy_port))
        .await
        .map_err(|e| format!("Failed to reach SOCKS5 proxy {proxy_host}:{proxy_port}: {e}"))?;

    // Greeting: offer no-auth and, if creds present, username/password.
    let methods: &[u8] = if user.is_some() {
        &[0x00, 0x02]
    } else {
        &[0x00]
    };
    let mut greeting = vec![0x05u8, methods.len() as u8];
    greeting.extend_from_slice(methods);
    s.write_all(&greeting)
        .await
        .map_err(|e| format!("SOCKS5 write failed: {e}"))?;

    let mut sel = [0u8; 2];
    s.read_exact(&mut sel)
        .await
        .map_err(|e| format!("SOCKS5 handshake failed: {e}"))?;
    if sel[0] != 0x05 {
        return Err("Proxy is not a SOCKS5 server".to_string());
    }
    match sel[1] {
        0x00 => {} // no auth
        0x02 => {
            let u = user.unwrap_or("").as_bytes();
            let p = pass.unwrap_or("").as_bytes();
            if u.len() > 255 || p.len() > 255 {
                return Err("SOCKS5 username/password too long".to_string());
            }
            let mut auth = vec![0x01u8, u.len() as u8];
            auth.extend_from_slice(u);
            auth.push(p.len() as u8);
            auth.extend_from_slice(p);
            s.write_all(&auth)
                .await
                .map_err(|e| format!("SOCKS5 auth write failed: {e}"))?;
            let mut ar = [0u8; 2];
            s.read_exact(&mut ar)
                .await
                .map_err(|e| format!("SOCKS5 auth failed: {e}"))?;
            if ar[1] != 0x00 {
                return Err("SOCKS5 proxy rejected the username/password".to_string());
            }
        }
        0xFF => return Err("SOCKS5 proxy offered no acceptable auth method".to_string()),
        _ => return Err("SOCKS5 proxy chose an unsupported auth method".to_string()),
    }

    // CONNECT request with ATYP=domain (proxy-side resolution).
    let mut req = vec![0x05u8, 0x01, 0x00, 0x03, domain.len() as u8];
    req.extend_from_slice(domain);
    req.extend_from_slice(&target_port.to_be_bytes());
    s.write_all(&req)
        .await
        .map_err(|e| format!("SOCKS5 connect write failed: {e}"))?;

    let mut head = [0u8; 4];
    s.read_exact(&mut head)
        .await
        .map_err(|e| format!("SOCKS5 connect failed: {e}"))?;
    if head[1] != 0x00 {
        return Err(format!(
            "SOCKS5 proxy refused the connection (code {})",
            head[1]
        ));
    }
    // Consume the bound address so the stream is left at the start of payload.
    match head[3] {
        0x01 => {
            let mut b = [0u8; 4];
            s.read_exact(&mut b).await.map_err(|e| e.to_string())?;
        }
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await.map_err(|e| e.to_string())?;
            let mut b = vec![0u8; l[0] as usize];
            s.read_exact(&mut b).await.map_err(|e| e.to_string())?;
        }
        0x04 => {
            let mut b = [0u8; 16];
            s.read_exact(&mut b).await.map_err(|e| e.to_string())?;
        }
        _ => return Err("SOCKS5 proxy returned an unknown address type".to_string()),
    }
    let mut port = [0u8; 2];
    s.read_exact(&mut port).await.map_err(|e| e.to_string())?;
    Ok(s)
}

/// HTTP CONNECT tunnel with optional Basic proxy auth.
async fn http_connect(
    proxy_host: &str,
    proxy_port: u16,
    user: Option<&str>,
    pass: Option<&str>,
    target_host: &str,
    target_port: u16,
) -> Result<tokio::net::TcpStream, String> {
    use base64::Engine;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut s = tokio::net::TcpStream::connect((proxy_host, proxy_port))
        .await
        .map_err(|e| format!("Failed to reach HTTP proxy {proxy_host}:{proxy_port}: {e}"))?;

    let mut req = format!(
        "CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n"
    );
    if let Some(u) = user {
        let creds = format!("{}:{}", u, pass.unwrap_or(""));
        let encoded = base64::engine::general_purpose::STANDARD.encode(creds.as_bytes());
        req.push_str(&format!("Proxy-Authorization: Basic {encoded}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes())
        .await
        .map_err(|e| format!("HTTP proxy write failed: {e}"))?;

    // Read response headers up to the blank line.
    let mut buf = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        let n = s
            .read(&mut byte)
            .await
            .map_err(|e| format!("HTTP proxy read failed: {e}"))?;
        if n == 0 {
            return Err("HTTP proxy closed the connection during CONNECT".to_string());
        }
        buf.push(byte[0]);
        if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
            break;
        }
        if buf.len() > 16 * 1024 {
            return Err("HTTP proxy sent an oversized response".to_string());
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let status_line = head.lines().next().unwrap_or("");
    let code = status_line.split_whitespace().nth(1).unwrap_or("");
    if code != "200" {
        return Err(format!(
            "HTTP proxy refused CONNECT: {}",
            status_line.trim()
        ));
    }
    Ok(s)
}

pub enum TermCommand {
    Data(Vec<u8>),
    Resize(u32, u32),
    StartRecording(String),
    StopRecording,
    Close,
}

pub struct SshSession {
    pub cmd_tx: mpsc::Sender<TermCommand>,
    pub handle: Arc<client::Handle<ClientHandler>>,
    /// Remote-forward route table for this connection (see `forwarding`).
    pub remote_routes: RemoteRoutes,
}

pub type Sessions = Arc<Mutex<HashMap<String, SshSession>>>;

/// `(bind_host, remote_port)` - `(local_target_host, local_target_port)`.
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

/// Authenticate using an SSH agent. On Windows this tries the OpenSSH agent
/// (named pipe) and then Pageant; on Unix it uses `SSH_AUTH_SOCK`. Each identity
/// held by the agent is offered to the server in turn.
async fn agent_authenticate(
    handle: &mut client::Handle<ClientHandler>,
    username: &str,
) -> Result<bool, String> {
    #[cfg(windows)]
    {
        use russh::keys::agent::client::AgentClient;
        let mut last_err = "No SSH agent found (tried the OpenSSH agent and Pageant)".to_string();
        if let Ok(agent) = AgentClient::connect_named_pipe(r"\\.\pipe\openssh-ssh-agent").await {
            match agent_try(handle, username, agent).await {
                Ok(true) => return Ok(true),
                Ok(false) => last_err = "The SSH agent has no key the server accepted".to_string(),
                Err(e) => last_err = e,
            }
        }
        if let Ok(agent) = AgentClient::connect_pageant().await {
            match agent_try(handle, username, agent).await {
                Ok(true) => return Ok(true),
                Ok(false) => last_err = "The SSH agent has no key the server accepted".to_string(),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }
    #[cfg(unix)]
    {
        use russh::keys::agent::client::AgentClient;
        let agent = AgentClient::connect_env().await.map_err(|e| {
            format!("Could not connect to the SSH agent (is SSH_AUTH_SOCK set?): {e}")
        })?;
        agent_try(handle, username, agent).await
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (handle, username);
        Err("SSH agent authentication is not supported on this platform".to_string())
    }
}

/// Offer every identity the agent holds to the server, signing challenges via
/// the agent. Returns `Ok(true)` on the first accepted key.
async fn agent_try<S>(
    handle: &mut client::Handle<ClientHandler>,
    username: &str,
    mut agent: russh::keys::agent::client::AgentClient<S>,
) -> Result<bool, String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    use russh::keys::ssh_key::Algorithm;
    let identities = agent
        .request_identities()
        .await
        .map_err(|e| format!("Failed to list SSH agent identities: {e}"))?;
    if identities.is_empty() {
        return Err("The SSH agent has no identities loaded".to_string());
    }
    for id in identities {
        let key = id.public_key().into_owned();
        // Only RSA needs rsa-sha2-256 forced; other key types sign natively.
        let hash_alg = match key.algorithm() {
            Algorithm::Rsa { .. } => Some(HashAlg::Sha256),
            _ => None,
        };
        if let Ok(res) = handle
            .authenticate_publickey_with(username, key, hash_alg, &mut agent)
            .await
        {
            if res.success() {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Authenticate an established connection using the host's configured method.
async fn authenticate(
    handle: &mut client::Handle<ClientHandler>,
    host: &Host,
) -> Result<(), String> {
    let authenticated: bool = match host.default_auth.as_str() {
        "Password" => {
            let pw = host
                .password
                .as_deref()
                .ok_or("No password stored for this host")?;
            handle
                .authenticate_password(&host.username, pw)
                .await
                .map_err(|e| format!("Auth error: {}", e))?
                .success()
        }
        "SshKey" => {
            let key_str = host
                .private_key
                .as_deref()
                .ok_or("No SSH key stored for this host")?;
            let key_pair = russh::keys::decode_secret_key(key_str, host.passphrase.as_deref())
                .map_err(|e| format!("Invalid private key: {}", e))?;
            let key = PrivateKeyWithHashAlg::new(Arc::new(key_pair), Some(HashAlg::Sha256));
            handle
                .authenticate_publickey(&host.username, key)
                .await
                .map_err(|e| format!("Auth error: {}", e))?
                .success()
        }
        "Agent" => agent_authenticate(handle, &host.username).await?,
        other => return Err(format!("Unknown auth method: {}", other)),
    };
    if !authenticated {
        return Err("Authentication failed".to_string());
    }
    Ok(())
}

/// stdout, stderr and the exit status of a one-off command.
pub struct OnceOutput {
    pub stdout: String,
    pub stderr: String,
    /// `None` when the server closed the channel without reporting a status.
    pub code: Option<u32>,
}

/// Open a fresh connection, run a single command, and return its stdout.
///
/// A non-zero exit becomes an `Err` carrying stderr - convenient for the
/// callers that only care whether it worked. Use `exec_once_full` when the
/// caller needs to see a failure's output rather than a message about it.
pub async fn exec_once(host: &Host, command: &str) -> Result<String, String> {
    let out = exec_once_full(host, command).await?;
    match out.code {
        Some(0) | None => Ok(out.stdout),
        Some(c) => {
            let msg = out.stderr.trim();
            Err(if msg.is_empty() {
                format!("Command failed with exit code {}", c)
            } else {
                msg.to_string()
            })
        }
    }
}

pub async fn exec_once_full(host: &Host, command: &str) -> Result<OnceOutput, String> {
    let config = Arc::new(client::Config {
        keepalive_interval: Some(Duration::from_secs(15)),
        keepalive_max: 3,
        ..Default::default()
    });
    let handler = ClientHandler {
        host: host.clone(),
        remote_routes: Arc::new(Mutex::new(HashMap::new())),
    };

    let stream = connect_to_host(host).await?;
    let mut handle = tokio::time::timeout(
        Duration::from_secs(15),
        client::connect_stream(config, stream, handler),
    )
    .await
    .map_err(|_| "Connection timed out".to_string())?
    .map_err(|e| format!("Connection failed: {}", e))?;

    authenticate(&mut handle, host).await?;

    let mut channel = handle
        .channel_open_session()
        .await
        .map_err(|e| format!("Failed to open channel: {}", e))?;
    channel
        .exec(true, command)
        .await
        .map_err(|e| format!("exec failed: {}", e))?;

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut code: Option<u32> = None;
    let read = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Data { data }) => stdout.extend_from_slice(&data),
                Some(ChannelMsg::ExtendedData { data, .. }) => stderr.extend_from_slice(&data),
                Some(ChannelMsg::ExitStatus { exit_status }) => code = Some(exit_status),
                // ExitStatus can arrive after Eof, so read until Close/None.
                Some(ChannelMsg::Close) | None => break,
                _ => {}
            }
        }
    })
    .await;
    if read.is_err() {
        return Err("Command timed out".to_string());
    }

    Ok(OnceOutput {
        stdout: String::from_utf8_lossy(&stdout).to_string(),
        stderr: String::from_utf8_lossy(&stderr).to_string(),
        code,
    })
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

    let stream = connect_to_host(&host).await?;

    let mut handle = tokio::time::timeout(
        Duration::from_secs(15),
        client::connect_stream(config, stream, handler),
    )
    .await
    .map_err(|_| "Connection timed out".to_string())?
    .map_err(|e| format!("Connection failed: {}", e))?;

    authenticate(&mut handle, &host).await?;

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

        let mut recorder: Option<crate::recorder::Recorder> = None;

        // Batch output on its way to the webview; see crate::coalesce for why.
        // Event names are built once - they were being reformatted per packet.
        let mut batcher =
            crate::coalesce::Coalescer::new(crate::coalesce::WINDOW, crate::coalesce::MAX_BATCH);
        let data_event = format!("ssh-data-{}", session_id);
        let closed_event = format!("ssh-closed-{}", session_id);

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
                        Some(TermCommand::StartRecording(path)) => {
                            if let Ok(rec) = crate::recorder::Recorder::new(std::path::Path::new(&path), 80, 24) {
                                recorder = Some(rec);
                            }
                        }
                        Some(TermCommand::StopRecording) => {
                            recorder = None;
                        }
                        Some(TermCommand::Close) | None => {
                            let _ = channel.close().await;
                            // Flush first: anything still batched is output the
                            // terminal has never seen.
                            if let Some(tail) = batcher.take() {
                                app_handle.emit(&data_event, tail).ok();
                            }
                            sessions.lock().unwrap().remove(&session_id);
                            app_handle.emit(&closed_event, ()).ok();
                            return;
                        }
                    }
                }
                msg = channel.wait() => {
                    match msg {
                        Some(ChannelMsg::Data { ref data }) | Some(ChannelMsg::ExtendedData { ref data, .. }) => {
                            // Record every packet as it lands, not per batch, so
                            // an asciicast keeps the host's original timing.
                            if let Some(ref mut rec) = recorder {
                                let _ = rec.record_output(data.as_ref());
                            }
                            if let Some(out) = batcher.push(data.as_ref(), std::time::Instant::now()) {
                                app_handle.emit(&data_event, out).ok();
                            }
                        }
                        Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => {
                            if let Some(tail) = batcher.take() {
                                app_handle.emit(&data_event, tail).ok();
                            }
                            sessions.lock().unwrap().remove(&session_id);
                            app_handle.emit(&closed_event, ()).ok();
                            return;
                        }
                        _ => {}
                    }
                }
                // Fires only while a burst is in flight; idle sessions park on
                // `pending()` and cost nothing.
                _ = async {
                    match batcher.deadline() {
                        Some(d) => tokio::time::sleep_until(tokio::time::Instant::from_std(d)).await,
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    if let Some(out) = batcher.on_deadline(std::time::Instant::now()) {
                        app_handle.emit(&data_event, out).ok();
                    }
                }
            }
        }
    });
}
