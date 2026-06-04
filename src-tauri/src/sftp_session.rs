//! SFTP sessions. Each open SFTP browser gets its own SSH connection living in
//! a dedicated thread — `ssh2::Sftp` borrows its `Session` and neither is `Send`,
//! so (like the terminal and port-forward sessions) the connection stays pinned
//! to one thread and we talk to it over a request/response channel.

use serde::Serialize;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::mpsc::{self, Sender};
use std::time::Instant;
use tauri::{AppHandle, Emitter};

use crate::forwarding::connect_and_auth;
use crate::vault::Host;

#[derive(Serialize, Clone)]
pub struct SftpEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    /// Unix permission bits (e.g. 0o644), 0 if the server didn't report them.
    pub perm: u32,
}

#[derive(Serialize, Clone)]
struct TransferProgress {
    direction: &'static str, // "download" | "upload"
    name: String,
    transferred: u64,
    total: u64,
    done: bool,
}

/// Copy in chunks, emitting throttled progress events to `sftp-progress-{session_id}`
/// (at most every ~80ms, plus a final 100% event). `total` of 0 means unknown size.
fn copy_with_progress<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    total: u64,
    direction: &'static str,
    name: &str,
    app: &AppHandle,
    session_id: &str,
) -> Result<(), String> {
    let event = format!("sftp-progress-{}", session_id);
    let emit = |transferred: u64, done: bool| {
        app.emit(
            &event,
            TransferProgress {
                direction,
                name: name.to_string(),
                transferred,
                total,
                done,
            },
        )
        .ok();
    };

    let mut buf = [0u8; 65536];
    let mut transferred: u64 = 0;
    let mut last = Instant::now();
    emit(0, false);

    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| format!("Read failed: {}", e))?;
        if n == 0 {
            break;
        }
        writer
            .write_all(&buf[..n])
            .map_err(|e| format!("Write failed: {}", e))?;
        transferred += n as u64;
        if last.elapsed().as_millis() >= 80 {
            emit(transferred, false);
            last = Instant::now();
        }
    }
    writer.flush().ok();
    emit(transferred, true);
    Ok(())
}

/// A unit of work for the SFTP worker thread. Each request carries a one-shot
/// channel the worker replies on.
pub enum SftpRequest {
    List {
        path: String,
        resp: Sender<Result<Vec<SftpEntry>, String>>,
    },
    Download {
        remote: String,
        local: String,
        resp: Sender<Result<(), String>>,
    },
    Upload {
        local: String,
        remote: String,
        resp: Sender<Result<(), String>>,
    },
    Rename {
        from: String,
        to: String,
        resp: Sender<Result<(), String>>,
    },
    Delete {
        path: String,
        is_dir: bool,
        resp: Sender<Result<(), String>>,
    },
    Mkdir {
        path: String,
        resp: Sender<Result<(), String>>,
    },
    Chmod {
        path: String,
        mode: u32,
        resp: Sender<Result<(), String>>,
    },
    Close,
}

pub struct SftpHandle {
    pub tx: Sender<SftpRequest>,
}

fn to_path_string(p: &Path) -> String {
    p.to_string_lossy().to_string()
}

fn do_list(sftp: &ssh2::Sftp, path: &str) -> Result<Vec<SftpEntry>, String> {
    let entries = sftp
        .readdir(Path::new(path))
        .map_err(|e| format!("Cannot list {}: {}", path, e))?;

    let mut out: Vec<SftpEntry> = entries
        .into_iter()
        .filter_map(|(pathbuf, stat)| {
            let name = pathbuf.file_name()?.to_string_lossy().to_string();
            if name.is_empty() {
                return None;
            }
            Some(SftpEntry {
                name,
                path: to_path_string(&pathbuf),
                is_dir: stat.is_dir(),
                size: stat.size.unwrap_or(0),
                // Keep just the low 12 bits (rwx + setuid/gid/sticky).
                perm: stat.perm.unwrap_or(0) & 0o7777,
            })
        })
        .collect();

    // Directories first, then case-insensitive by name.
    out.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    Ok(out)
}

fn file_name(path: &str) -> String {
    Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| path.to_string())
}

fn do_download(
    sftp: &ssh2::Sftp,
    remote: &str,
    local: &str,
    app: &AppHandle,
    session_id: &str,
) -> Result<(), String> {
    let total = sftp
        .stat(Path::new(remote))
        .ok()
        .and_then(|s| s.size)
        .unwrap_or(0);
    let mut remote_file = sftp
        .open(Path::new(remote))
        .map_err(|e| format!("Cannot open remote {}: {}", remote, e))?;
    let mut local_file =
        std::fs::File::create(local).map_err(|e| format!("Cannot create {}: {}", local, e))?;
    copy_with_progress(
        &mut remote_file,
        &mut local_file,
        total,
        "download",
        &file_name(remote),
        app,
        session_id,
    )
}

fn do_upload(
    sftp: &ssh2::Sftp,
    local: &str,
    remote: &str,
    app: &AppHandle,
    session_id: &str,
) -> Result<(), String> {
    let total = std::fs::metadata(local).map(|m| m.len()).unwrap_or(0);
    let mut local_file =
        std::fs::File::open(local).map_err(|e| format!("Cannot open {}: {}", local, e))?;
    let mut remote_file = sftp
        .create(Path::new(remote))
        .map_err(|e| format!("Cannot create remote {}: {}", remote, e))?;
    copy_with_progress(
        &mut local_file,
        &mut remote_file,
        total,
        "upload",
        &file_name(remote),
        app,
        session_id,
    )
}

fn do_rename(sftp: &ssh2::Sftp, from: &str, to: &str) -> Result<(), String> {
    sftp.rename(Path::new(from), Path::new(to), None)
        .map_err(|e| format!("Rename failed: {}", e))
}

fn do_mkdir(sftp: &ssh2::Sftp, path: &str) -> Result<(), String> {
    sftp.mkdir(Path::new(path), 0o755)
        .map_err(|e| format!("Create folder failed: {}", e))
}

fn do_chmod(sftp: &ssh2::Sftp, path: &str, mode: u32) -> Result<(), String> {
    let stat = ssh2::FileStat {
        size: None,
        uid: None,
        gid: None,
        perm: Some(mode),
        atime: None,
        mtime: None,
    };
    sftp.setstat(Path::new(path), stat)
        .map_err(|e| format!("Change permissions failed: {}", e))
}

/// Recursively remove a directory and its contents (SFTP `rmdir` only removes
/// empty dirs, so we walk children depth-first first).
fn remove_dir_recursive(sftp: &ssh2::Sftp, path: &str) -> Result<(), String> {
    let children = sftp
        .readdir(Path::new(path))
        .map_err(|e| format!("Cannot list {}: {}", path, e))?;
    for (child, stat) in children {
        let name = child
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        if name.is_empty() || name == "." || name == ".." {
            continue;
        }
        if stat.is_dir() {
            remove_dir_recursive(sftp, &to_path_string(&child))?;
        } else {
            sftp.unlink(&child)
                .map_err(|e| format!("Delete failed: {}", e))?;
        }
    }
    sftp.rmdir(Path::new(path))
        .map_err(|e| format!("Delete failed: {}", e))
}

fn do_delete(sftp: &ssh2::Sftp, path: &str, is_dir: bool) -> Result<(), String> {
    if is_dir {
        remove_dir_recursive(sftp, path)
    } else {
        sftp.unlink(Path::new(path))
            .map_err(|e| format!("Delete failed: {}", e))
    }
}

/// Open an SFTP session for `host`. Returns a handle plus the starting directory
/// (the remote home dir). Connection + auth happen on the worker thread; the
/// result is reported back before this returns.
pub fn open(
    app: AppHandle,
    session_id: String,
    host: Host,
) -> Result<(SftpHandle, String), String> {
    let (tx, rx) = mpsc::channel::<SftpRequest>();
    let (ready_tx, ready_rx) = mpsc::channel::<Result<String, String>>();

    std::thread::spawn(move || {
        let session = match connect_and_auth(&host) {
            Ok(s) => s,
            Err(e) => {
                ready_tx.send(Err(e)).ok();
                return;
            }
        };
        let sftp = match session.sftp() {
            Ok(s) => s,
            Err(e) => {
                ready_tx.send(Err(format!("SFTP init failed: {}", e))).ok();
                return;
            }
        };

        let home = sftp
            .realpath(Path::new("."))
            .map(|p| to_path_string(&p))
            .unwrap_or_else(|_| "/".to_string());
        if ready_tx.send(Ok(home)).is_err() {
            return; // caller went away
        }

        while let Ok(req) = rx.recv() {
            match req {
                SftpRequest::Close => break,
                SftpRequest::List { path, resp } => {
                    resp.send(do_list(&sftp, &path)).ok();
                }
                SftpRequest::Download {
                    remote,
                    local,
                    resp,
                } => {
                    resp.send(do_download(&sftp, &remote, &local, &app, &session_id))
                        .ok();
                }
                SftpRequest::Upload {
                    local,
                    remote,
                    resp,
                } => {
                    resp.send(do_upload(&sftp, &local, &remote, &app, &session_id))
                        .ok();
                }
                SftpRequest::Rename { from, to, resp } => {
                    resp.send(do_rename(&sftp, &from, &to)).ok();
                }
                SftpRequest::Delete { path, is_dir, resp } => {
                    resp.send(do_delete(&sftp, &path, is_dir)).ok();
                }
                SftpRequest::Mkdir { path, resp } => {
                    resp.send(do_mkdir(&sftp, &path)).ok();
                }
                SftpRequest::Chmod { path, mode, resp } => {
                    resp.send(do_chmod(&sftp, &path, mode)).ok();
                }
            }
        }
        // session/sftp dropped here, closing the connection.
    });

    let home = ready_rx
        .recv()
        .map_err(|_| "SFTP worker stopped unexpectedly".to_string())??;
    Ok((SftpHandle { tx }, home))
}
