use russh::client;
use russh_sftp::client::SftpSession;
use serde::Serialize;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use tauri::{AppHandle, Emitter};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

#[derive(Serialize, Clone)]
pub struct SftpEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    pub perm: u32,
}

#[derive(Serialize, Clone)]
struct TransferProgress {
    direction: &'static str,
    name: String,
    transferred: u64,
    total: u64,
    done: bool,
}

pub enum SftpRequest {
    List {
        path: String,
        resp: oneshot::Sender<Result<Vec<SftpEntry>, String>>,
    },
    Download {
        remote: String,
        local: String,
        resp: oneshot::Sender<Result<(), String>>,
    },
    Upload {
        local: String,
        remote: String,
        resp: oneshot::Sender<Result<(), String>>,
    },
    Rename {
        from: String,
        to: String,
        resp: oneshot::Sender<Result<(), String>>,
    },
    Delete {
        path: String,
        is_dir: bool,
        resp: oneshot::Sender<Result<(), String>>,
    },
    Mkdir {
        path: String,
        resp: oneshot::Sender<Result<(), String>>,
    },
    Chmod {
        path: String,
        mode: u32,
        resp: oneshot::Sender<Result<(), String>>,
    },
    ReadFile {
        path: String,
        resp: oneshot::Sender<Result<String, String>>,
    },
    WriteFile {
        path: String,
        content: String,
        resp: oneshot::Sender<Result<(), String>>,
    },
    Close,
}

pub struct SftpHandle {
    pub tx: mpsc::Sender<SftpRequest>,
}

pub async fn open(
    app_handle: AppHandle,
    session_id: String,
    ssh_handle: Arc<client::Handle<crate::ssh_session::ClientHandler>>,
) -> Result<(SftpHandle, String), String> {
    let channel = ssh_handle
        .channel_open_session()
        .await
        .map_err(|e| format!("SFTP channel open failed: {}", e))?;

    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| format!("SFTP subsystem request failed: {}", e))?;

    let sftp = SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| format!("SFTP session init failed: {}", e))?;

    // russh-sftp's canonicalize returns the resolved path as a String already.
    let home_path = sftp
        .canonicalize(".")
        .await
        .map_err(|e| format!("Failed to get home dir: {}", e))?;

    let (tx, mut rx) = mpsc::channel::<SftpRequest>(32);
    let handle = SftpHandle { tx };

    tokio::spawn(async move {
        while let Some(req) = rx.recv().await {
            match req {
                SftpRequest::List { path, resp } => {
                    let _ = resp.send(do_list(&sftp, &path).await);
                }
                SftpRequest::Download {
                    remote,
                    local,
                    resp,
                } => {
                    let _ = resp
                        .send(do_download(&sftp, &remote, &local, &app_handle, &session_id).await);
                }
                SftpRequest::Upload {
                    local,
                    remote,
                    resp,
                } => {
                    let _ = resp
                        .send(do_upload(&sftp, &local, &remote, &app_handle, &session_id).await);
                }
                SftpRequest::Rename { from, to, resp } => {
                    let _ = resp.send(do_rename(&sftp, &from, &to).await);
                }
                SftpRequest::Delete { path, is_dir, resp } => {
                    let _ = resp.send(do_delete(&sftp, &path, is_dir).await);
                }
                SftpRequest::Mkdir { path, resp } => {
                    let _ = resp.send(sftp.create_dir(path).await.map_err(|e| e.to_string()));
                }
                SftpRequest::Chmod { path, mode, resp } => {
                    let attrs = russh_sftp::protocol::FileAttributes {
                        permissions: Some(mode),
                        ..Default::default()
                    };
                    let _ = resp.send(
                        sftp.set_metadata(path, attrs)
                            .await
                            .map_err(|e| e.to_string()),
                    );
                }
                SftpRequest::ReadFile { path, resp } => {
                    let _ = resp.send(do_read_file(&sftp, &path).await);
                }
                SftpRequest::WriteFile { path, content, resp } => {
                    let _ = resp.send(do_write_file(&sftp, &path, &content).await);
                }
                SftpRequest::Close => {
                    break;
                }
            }
        }
    });

    Ok((handle, home_path))
}

async fn do_list(sftp: &SftpSession, path: &str) -> Result<Vec<SftpEntry>, String> {
    let entries = sftp
        .read_dir(path)
        .await
        .map_err(|e| format!("Cannot list {}: {}", path, e))?;
    let mut out: Vec<SftpEntry> = entries
        .into_iter()
        .filter_map(|entry| {
            let name = entry.file_name();
            let attrs = entry.metadata();
            if name.is_empty() || name == "." || name == ".." {
                return None;
            }
            Some(SftpEntry {
                path: format!("{}/{}", path.trim_end_matches('/'), name),
                name,
                is_dir: attrs.is_dir(),
                size: attrs.size.unwrap_or(0),
                perm: attrs.permissions.unwrap_or(0),
            })
        })
        .collect();
    out.sort_by(|a, b| match (a.is_dir, b.is_dir) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
    });
    Ok(out)
}

async fn do_download(
    sftp: &SftpSession,
    remote: &str,
    local: &str,
    app: &AppHandle,
    session_id: &str,
) -> Result<(), String> {
    let attrs = sftp.metadata(remote).await.map_err(|e| e.to_string())?;
    let total = attrs.size.unwrap_or(0);

    let mut remote_file = sftp
        .open(remote)
        .await
        .map_err(|e| format!("Cannot open remote: {}", e))?;
    let mut local_file = tokio::fs::File::create(local)
        .await
        .map_err(|e| format!("Cannot create local: {}", e))?;

    let event = format!("sftp-progress-{}", session_id);
    let name = Path::new(remote)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let mut buf = [0u8; 65536];
    let mut transferred: u64 = 0;
    let mut last = std::time::Instant::now();

    let _ = app.emit(
        &event,
        TransferProgress {
            direction: "download",
            name: name.clone(),
            transferred,
            total,
            done: false,
        },
    );

    loop {
        let n = remote_file
            .read(&mut buf)
            .await
            .map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        local_file
            .write_all(&buf[..n])
            .await
            .map_err(|e| e.to_string())?;
        transferred += n as u64;

        if last.elapsed().as_millis() >= 80 {
            let _ = app.emit(
                &event,
                TransferProgress {
                    direction: "download",
                    name: name.clone(),
                    transferred,
                    total,
                    done: false,
                },
            );
            last = std::time::Instant::now();
        }
    }
    let _ = local_file.flush().await;
    let _ = app.emit(
        &event,
        TransferProgress {
            direction: "download",
            name,
            transferred,
            total,
            done: true,
        },
    );
    Ok(())
}

async fn do_upload(
    sftp: &SftpSession,
    local: &str,
    remote: &str,
    app: &AppHandle,
    session_id: &str,
) -> Result<(), String> {
    let mut local_file = tokio::fs::File::open(local)
        .await
        .map_err(|e| format!("Cannot open local: {}", e))?;
    let meta = local_file.metadata().await.map_err(|e| e.to_string())?;
    let total = meta.len();

    use russh_sftp::protocol::OpenFlags;
    let mut remote_file = sftp
        .open_with_flags(
            remote,
            OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE,
        )
        .await
        .map_err(|e| format!("Cannot open remote: {}", e))?;

    let event = format!("sftp-progress-{}", session_id);
    let name = Path::new(local)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let mut buf = [0u8; 65536];
    let mut transferred: u64 = 0;
    let mut last = std::time::Instant::now();

    let _ = app.emit(
        &event,
        TransferProgress {
            direction: "upload",
            name: name.clone(),
            transferred,
            total,
            done: false,
        },
    );

    loop {
        let n = local_file.read(&mut buf).await.map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        remote_file
            .write_all(&buf[..n])
            .await
            .map_err(|e| e.to_string())?;
        transferred += n as u64;

        if last.elapsed().as_millis() >= 80 {
            let _ = app.emit(
                &event,
                TransferProgress {
                    direction: "upload",
                    name: name.clone(),
                    transferred,
                    total,
                    done: false,
                },
            );
            last = std::time::Instant::now();
        }
    }

    let _ = app.emit(
        &event,
        TransferProgress {
            direction: "upload",
            name,
            transferred,
            total,
            done: true,
        },
    );
    Ok(())
}

async fn do_rename(sftp: &SftpSession, from: &str, to: &str) -> Result<(), String> {
    sftp.rename(from, to).await.map_err(|e| e.to_string())
}

async fn do_delete(sftp: &SftpSession, path: &str, is_dir: bool) -> Result<(), String> {
    if is_dir {
        remove_dir_recursive(sftp, path).await
    } else {
        sftp.remove_file(path).await.map_err(|e| e.to_string())
    }
}

fn remove_dir_recursive<'a>(
    sftp: &'a SftpSession,
    path: &'a str,
) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
    Box::pin(async move {
        let entries = match sftp.read_dir(path).await {
            Ok(e) => e,
            Err(_) => return sftp.remove_dir(path).await.map_err(|e| e.to_string()),
        };
        for entry in entries {
            let n = entry.file_name();
            let attrs = entry.metadata();
            if n == "." || n == ".." {
                continue;
            }
            let child = format!("{}/{}", path.trim_end_matches('/'), n);
            if attrs.is_dir() {
                remove_dir_recursive(sftp, &child).await?;
            } else {
                sftp.remove_file(&child).await.map_err(|e| e.to_string())?;
            }
        }
        sftp.remove_dir(path).await.map_err(|e| e.to_string())
    })
}

async fn do_read_file(sftp: &SftpSession, path: &str) -> Result<String, String> {
    let mut file = sftp
        .open(path)
        .await
        .map_err(|e| format!("Cannot open file: {}", e))?;
    
    let mut data = Vec::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf).await.map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n]);
    }
    
    String::from_utf8(data).map_err(|e| format!("File contains invalid UTF-8: {}", e))
}

async fn do_write_file(sftp: &SftpSession, path: &str, content: &str) -> Result<(), String> {
    use russh_sftp::protocol::OpenFlags;
    let mut file = sftp
        .open_with_flags(
            path,
            OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE,
        )
        .await
        .map_err(|e| format!("Cannot open file for writing: {}", e))?;
        
    let bytes = content.as_bytes();
    file.write_all(bytes).await.map_err(|e| format!("Cannot write to file: {}", e))?;
    Ok(())
}
