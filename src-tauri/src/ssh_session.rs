use ssh2::Session;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::{AppHandle, Emitter};

use crate::vault::Host;

pub enum TermCommand {
    Data(Vec<u8>),
    Resize(u32, u32),
    Close,
}

pub struct SshSession {
    pub cmd_tx: std::sync::mpsc::Sender<TermCommand>,
}

pub type Sessions = Arc<Mutex<HashMap<String, SshSession>>>;

pub fn connect(
    app_handle: AppHandle,
    sessions: Sessions,
    session_id: String,
    host: Host,
    on_connect: Vec<String>,
) -> Result<(), String> {
    let addr = format!("{}:{}", host.hostname, host.port);
    let socket_addr = addr
        .to_socket_addrs()
        .map_err(|e| format!("Cannot resolve {}: {}", addr, e))?
        .next()
        .ok_or_else(|| format!("No address found for {}", addr))?;

    let tcp = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(15))
        .map_err(|e| format!("Connection failed: {}", e))?;

    let mut session = Session::new().map_err(|e| e.to_string())?;
    session.set_tcp_stream(tcp);
    session
        .handshake()
        .map_err(|e| format!("SSH handshake failed: {}", e))?;

    // Verify the server's host key before sending any credentials.
    crate::host_keys::enforce(&session, &host)?;

    match host.default_auth.as_str() {
        "Password" => {
            let pw = host
                .password
                .as_deref()
                .ok_or("No password stored for this host")?;
            session
                .userauth_password(&host.username, pw)
                .map_err(|e| format!("Password authentication failed: {}", e))?;
        }
        "SshKey" => {
            let key = host
                .private_key
                .as_deref()
                .ok_or("No SSH key stored for this host")?;
            let normalized_key = key.replace("\r\n", "\n");
            // Pass the public key explicitly when we can — libssh2 may fail to
            // derive it from an in-memory OpenSSH key (e.g. ed25519) on some
            // backends, which is what breaks key auth on the Windows build.
            let public_key = crate::vault::resolve_public_key(&host).map(|pk| pk.replace("\r\n", "\n"));
            session
                .userauth_pubkey_memory(
                    &host.username,
                    public_key.as_deref(),
                    &normalized_key,
                    host.passphrase.as_deref(),
                )
                .map_err(|e| format!("Key authentication failed: {}", e))?;
        }
        other => return Err(format!("Unknown auth method: {}", other)),
    }

    if !session.authenticated() {
        return Err("Authentication failed".to_string());
    }

    let mut channel = session.channel_session().map_err(|e| e.to_string())?;
    channel
        .request_pty("xterm-256color", None, Some((220, 50, 0, 0)))
        .map_err(|e| e.to_string())?;
    channel.shell().map_err(|e| e.to_string())?;

    let (cmd_tx, cmd_rx) = std::sync::mpsc::channel::<TermCommand>();
    sessions
        .lock()
        .unwrap()
        .insert(session_id.clone(), SshSession { cmd_tx });

    let sid = session_id.clone();
    let sessions_ref = sessions.clone();

    std::thread::spawn(move || {
        // Auto-run on-connect snippets: give the login shell a moment to settle,
        // then type each snippet into the PTY (newline-terminated so it runs).
        if !on_connect.is_empty() {
            std::thread::sleep(Duration::from_millis(400));
            for snippet in &on_connect {
                let text = snippet.replace("\r\n", "\n");
                let payload = if text.ends_with('\n') {
                    text
                } else {
                    format!("{}\n", text)
                };
                if channel.write_all(payload.as_bytes()).is_err() {
                    break;
                }
            }
            channel.flush().ok();
        }

        session.set_blocking(false);
        let mut buf = [0u8; 65536];

        loop {
            while let Ok(cmd) = cmd_rx.try_recv() {
                session.set_blocking(true);
                match cmd {
                    TermCommand::Data(data) => {
                        channel.write_all(&data).ok();
                    }
                    TermCommand::Resize(cols, rows) => {
                        channel.request_pty_size(cols, rows, None, None).ok();
                    }
                    TermCommand::Close => {
                        channel.close().ok();
                        sessions_ref.lock().unwrap().remove(&sid);
                        app_handle.emit(&format!("ssh-closed-{}", sid), ()).ok();
                        return;
                    }
                }
                session.set_blocking(false);
            }

            match channel.read(&mut buf) {
                Ok(0) => {
                    sessions_ref.lock().unwrap().remove(&sid);
                    app_handle.emit(&format!("ssh-closed-{}", sid), ()).ok();
                    return;
                }
                Ok(n) => {
                    app_handle
                        .emit(&format!("ssh-data-{}", sid), buf[..n].to_vec())
                        .ok();
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if channel.eof() {
                        sessions_ref.lock().unwrap().remove(&sid);
                        app_handle.emit(&format!("ssh-closed-{}", sid), ()).ok();
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => {
                    sessions_ref.lock().unwrap().remove(&sid);
                    app_handle.emit(&format!("ssh-closed-{}", sid), ()).ok();
                    return;
                }
            }
        }
    });

    Ok(())
}
