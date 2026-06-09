use ssh2::Session;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::mpsc;
use std::time::Duration;

use crate::vault::Host;

pub struct ForwardHandle {
    pub stop_tx: mpsc::Sender<()>,
}

pub(crate) fn connect_and_auth(host: &Host) -> Result<Session, String> {
    let addr = format!("{}:{}", host.hostname, host.port);
    let socket_addr = addr
        .to_socket_addrs()
        .map_err(|e| format!("Cannot resolve {}: {}", addr, e))?
        .next()
        .ok_or_else(|| format!("No address found for {}", addr))?;

    let tcp = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(15))
        .map_err(|e| format!("Forward connection failed: {}", e))?;

    let mut session = Session::new().map_err(|e| e.to_string())?;
    session.set_tcp_stream(tcp);
    session.handshake().map_err(|e| e.to_string())?;

    // Verify the server's host key before sending any credentials.
    crate::host_keys::enforce(&session, host)?;

    match host.default_auth.as_str() {
        "SshKey" => {
            let key = host.private_key.as_deref().ok_or("No SSH key stored")?;
            let normalized_key = key.replace("\r\n", "\n");
            let public_key = crate::vault::resolve_public_key(host).map(|pk| pk.replace("\r\n", "\n"));
            session
                .userauth_pubkey_memory(
                    &host.username,
                    public_key.as_deref(),
                    &normalized_key,
                    host.passphrase.as_deref(),
                )
                .map_err(|e| format!("Key auth failed: {}", e))?;
        }
        _ => {
            let pw = host.password.as_deref().ok_or("No password stored")?;
            session
                .userauth_password(&host.username, pw)
                .map_err(|e| format!("Password auth failed: {}", e))?;
        }
    }

    if !session.authenticated() {
        return Err("Authentication failed".to_string());
    }
    Ok(session)
}

// Each accepted local TCP connection gets its own SSH session to avoid
// cross-thread Session sharing. Uses non-blocking I/O with write buffers
// to correctly handle partial writes.
fn proxy_connection(mut local: TcpStream, host: Host, remote_host: String, remote_port: u16) {
    let session = match connect_and_auth(&host) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[fwd] auth: {}", e);
            return;
        }
    };

    let mut channel = match session.channel_direct_tcpip(&remote_host, remote_port, None) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[fwd] channel: {}", e);
            return;
        }
    };

    // Switch to non-blocking for the bidirectional I/O loop.
    // Both session.set_blocking() and channel_direct_tcpip() take &self,
    // so this shared immutable borrow is valid while channel is alive.
    session.set_blocking(false);
    local.set_nonblocking(true).ok();

    let mut buf = [0u8; 65536];
    // Pending write buffers handle partial writes in non-blocking mode.
    let mut to_channel: Vec<u8> = Vec::new();
    let mut to_local: Vec<u8> = Vec::new();

    loop {
        let mut progress = false;

        // Read from local socket into buffer
        match local.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                to_channel.extend_from_slice(&buf[..n]);
                progress = true;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => break,
        }

        // Flush buffered data to SSH channel
        if !to_channel.is_empty() {
            match channel.write(&to_channel) {
                Ok(n) if n > 0 => {
                    to_channel.drain(..n);
                    progress = true;
                }
                // Ok(0) in non-blocking ssh2 means EAGAIN (would block), not closed.
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => break,
            }
        }

        // Read from SSH channel into buffer.
        // Ok(0) in non-blocking ssh2 means no data available, not necessarily EOF.
        match channel.read(&mut buf) {
            Ok(0) => {
                if channel.eof() {
                    break;
                }
            }
            Ok(n) => {
                to_local.extend_from_slice(&buf[..n]);
                progress = true;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => break,
        }

        // Flush buffered data to local socket
        if !to_local.is_empty() {
            match local.write(&to_local) {
                Ok(0) => break,
                Ok(n) => {
                    to_local.drain(..n);
                    progress = true;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => break,
            }
        }

        if channel.eof() {
            break;
        }

        if !progress {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

pub fn start_local_forward(
    host: Host,
    local_port: u16,
    remote_host: String,
    remote_port: u16,
) -> Result<ForwardHandle, String> {
    let (stop_tx, stop_rx) = mpsc::channel::<()>();

    let listener = TcpListener::bind(("127.0.0.1", local_port))
        .map_err(|e| format!("Cannot bind 127.0.0.1:{}: {}", local_port, e))?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;

    std::thread::spawn(move || loop {
        match stop_rx.try_recv() {
            Ok(()) | Err(mpsc::TryRecvError::Disconnected) => break,
            Err(mpsc::TryRecvError::Empty) => {}
        }

        match listener.accept() {
            Ok((stream, _)) => {
                let host = host.clone();
                let rh = remote_host.clone();
                std::thread::spawn(move || proxy_connection(stream, host, rh, remote_port));
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(_) => break,
        }
    });

    Ok(ForwardHandle { stop_tx })
}
