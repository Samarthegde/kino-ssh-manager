//! Port forwarding over the SSH connection — three flavours, all multiplexed on
//! the existing `russh` handle:
//!   - **local**  (`ssh -L`): bind a local port, tunnel each connection to a
//!     remote `host:port` via `channel_open_direct_tcpip`.
//!   - **dynamic** (`ssh -D`): a local SOCKS5 proxy; each CONNECT opens a
//!     direct-tcpip channel to the negotiated target.
//!   - **remote** (`ssh -R`): ask the server to listen on a port and forward
//!     incoming connections back to a local target. Routes are registered in a
//!     map the client `Handler` consults in `server_channel_open_forwarded_tcpip`.

use russh::{client, Channel, ChannelMsg};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::ssh_session::{ClientHandler, RemoteRoutes};

type SshHandle = Arc<client::Handle<ClientHandler>>;

/// Handle for a running forward. Dropping/stopping releases its resources.
pub enum ForwardHandle {
    /// Local & SOCKS forwards: stop the accept loop.
    Local(mpsc::Sender<()>),
    /// Remote forward: cancel the server-side listener and drop the route.
    Remote {
        handle: SshHandle,
        routes: RemoteRoutes,
        bind_host: String,
        remote_port: u16,
    },
}

impl ForwardHandle {
    pub async fn stop(self) {
        match self {
            ForwardHandle::Local(tx) => {
                let _ = tx.send(()).await;
            }
            ForwardHandle::Remote {
                handle,
                routes,
                bind_host,
                remote_port,
            } => {
                let _ = handle
                    .cancel_tcpip_forward(bind_host.clone(), remote_port as u32)
                    .await;
                routes.lock().unwrap().remove(&(bind_host, remote_port));
            }
        }
    }
}

/// Bidirectional pipe between an SSH channel and a local TCP socket.
async fn pipe(mut channel: Channel<client::Msg>, mut tcp: TcpStream) {
    let mut buf = [0u8; 65536];
    loop {
        tokio::select! {
            res = tcp.read(&mut buf) => {
                match res {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if channel.data(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
            msg = channel.wait() => {
                match msg {
                    Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                        if tcp.write_all(data.as_ref()).await.is_err() {
                            break;
                        }
                    }
                    Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => break,
                    _ => {}
                }
            }
        }
    }
}

// ── Local forward (ssh -L) ──────────────────────────────────────────────────

pub async fn start_local_forward(
    ssh_handle: SshHandle,
    local_port: u16,
    remote_host: String,
    remote_port: u16,
) -> Result<ForwardHandle, String> {
    let (stop_tx, mut stop_rx) = mpsc::channel::<()>(1);
    let listener = TcpListener::bind(("127.0.0.1", local_port))
        .await
        .map_err(|e| format!("Cannot bind 127.0.0.1:{}: {}", local_port, e))?;

    tokio::spawn(async move {
        loop {
            tokio::select! {
                res = listener.accept() => {
                    let Ok((stream, _)) = res else { break };
                    let handle = Arc::clone(&ssh_handle);
                    let host = remote_host.clone();
                    tokio::spawn(async move {
                        match handle
                            .channel_open_direct_tcpip(host, remote_port as u32, "127.0.0.1", 0)
                            .await
                        {
                            Ok(channel) => pipe(channel, stream).await,
                            Err(e) => log::error!("[fwd] direct-tcpip failed: {}", e),
                        }
                    });
                }
                _ = stop_rx.recv() => break,
            }
        }
    });

    Ok(ForwardHandle::Local(stop_tx))
}

// ── Dynamic forward / SOCKS5 proxy (ssh -D) ─────────────────────────────────

pub async fn start_socks_forward(
    ssh_handle: SshHandle,
    local_port: u16,
) -> Result<ForwardHandle, String> {
    let (stop_tx, mut stop_rx) = mpsc::channel::<()>(1);
    let listener = TcpListener::bind(("127.0.0.1", local_port))
        .await
        .map_err(|e| format!("Cannot bind SOCKS on 127.0.0.1:{}: {}", local_port, e))?;

    tokio::spawn(async move {
        loop {
            tokio::select! {
                res = listener.accept() => {
                    let Ok((stream, _)) = res else { break };
                    let handle = Arc::clone(&ssh_handle);
                    tokio::spawn(socks_bridge(handle, stream));
                }
                _ = stop_rx.recv() => break,
            }
        }
    });

    Ok(ForwardHandle::Local(stop_tx))
}

async fn socks_bridge(handle: SshHandle, mut tcp: TcpStream) {
    let (target_host, target_port) = match negotiate_socks5(&mut tcp).await {
        Ok(t) => t,
        Err(_) => return,
    };

    let channel = match handle
        .channel_open_direct_tcpip(target_host, target_port as u32, "127.0.0.1", 0)
        .await
    {
        Ok(c) => c,
        Err(_) => {
            let _ = tcp.write_all(&socks5_reply(0x04)).await; // host unreachable
            return;
        }
    };

    if tcp.write_all(&socks5_reply(0x00)).await.is_err() {
        return;
    }
    pipe(channel, tcp).await;
}

/// Minimal SOCKS5 handshake: no-auth + CONNECT. Returns the requested target.
async fn negotiate_socks5(tcp: &mut TcpStream) -> Result<(String, u16), ()> {
    let mut header = [0u8; 2];
    tcp.read_exact(&mut header).await.map_err(|_| ())?;
    if header[0] != 0x05 {
        return Err(());
    }
    let mut methods = vec![0u8; header[1] as usize];
    tcp.read_exact(&mut methods).await.map_err(|_| ())?;
    if !methods.contains(&0x00) {
        let _ = tcp.write_all(&[0x05, 0xFF]).await;
        return Err(());
    }
    tcp.write_all(&[0x05, 0x00]).await.map_err(|_| ())?;

    let mut req = [0u8; 4];
    tcp.read_exact(&mut req).await.map_err(|_| ())?;
    if req[0] != 0x05 {
        return Err(());
    }
    if req[1] != 0x01 {
        let _ = tcp.write_all(&socks5_reply(0x07)).await; // command not supported
        return Err(());
    }

    let host = match req[3] {
        0x01 => {
            let mut a = [0u8; 4];
            tcp.read_exact(&mut a).await.map_err(|_| ())?;
            format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
        }
        0x03 => {
            let mut len = [0u8; 1];
            tcp.read_exact(&mut len).await.map_err(|_| ())?;
            let mut domain = vec![0u8; len[0] as usize];
            tcp.read_exact(&mut domain).await.map_err(|_| ())?;
            String::from_utf8(domain).map_err(|_| ())?
        }
        0x04 => {
            let mut a = [0u8; 16];
            tcp.read_exact(&mut a).await.map_err(|_| ())?;
            let segs: Vec<String> = a
                .chunks(2)
                .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
                .collect();
            format!("[{}]", segs.join(":"))
        }
        _ => {
            let _ = tcp.write_all(&socks5_reply(0x08)).await; // address type not supported
            return Err(());
        }
    };

    let mut port = [0u8; 2];
    tcp.read_exact(&mut port).await.map_err(|_| ())?;
    Ok((host, u16::from_be_bytes(port)))
}

fn socks5_reply(rep: u8) -> [u8; 10] {
    // VER REP RSV ATYP=IPv4 BND.ADDR(0.0.0.0) BND.PORT(0)
    [0x05, rep, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
}

// ── Remote forward (ssh -R) ─────────────────────────────────────────────────

pub async fn start_remote_forward(
    ssh_handle: SshHandle,
    routes: RemoteRoutes,
    bind_host: String,
    remote_port: u16,
    target_host: String,
    target_port: u16,
) -> Result<ForwardHandle, String> {
    // Register the route before requesting the listener to avoid a race with
    // the first incoming connection.
    routes
        .lock()
        .unwrap()
        .insert((bind_host.clone(), remote_port), (target_host, target_port));

    if let Err(e) = ssh_handle
        .tcpip_forward(bind_host.clone(), remote_port as u32)
        .await
    {
        routes
            .lock()
            .unwrap()
            .remove(&(bind_host.clone(), remote_port));
        return Err(format!("Remote forward request failed: {}", e));
    }

    Ok(ForwardHandle::Remote {
        handle: ssh_handle,
        routes,
        bind_host,
        remote_port,
    })
}

/// Bridge a server-initiated forwarded channel to a local TCP target.
/// Called from the client `Handler` when the server opens a forwarded-tcpip.
pub async fn bridge_remote(channel: Channel<client::Msg>, target_host: String, target_port: u16) {
    match TcpStream::connect((target_host.as_str(), target_port)).await {
        Ok(tcp) => pipe(channel, tcp).await,
        Err(_) => {
            let _ = channel.close().await;
        }
    }
}
