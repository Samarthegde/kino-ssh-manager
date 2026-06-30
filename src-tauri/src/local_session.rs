use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::thread;
use tauri::{AppHandle, Emitter};

pub enum TermCommand {
    Data(Vec<u8>),
    Resize(u16, u16),
    StartRecording(String),
    StopRecording,
    Close,
}

pub struct LocalSession {
    pub cmd_tx: std::sync::mpsc::Sender<TermCommand>,
}

pub type LocalSessions = Arc<Mutex<HashMap<String, LocalSession>>>;

pub fn connect(
    app_handle: AppHandle,
    sessions: LocalSessions,
    session_id: String,
) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    let cmd = CommandBuilder::new("powershell.exe");

    #[cfg(not(target_os = "windows"))]
    let cmd = CommandBuilder::new(std::env::var("SHELL").unwrap_or_else(|_| "bash".to_string()));

    connect_command(app_handle, sessions, session_id, cmd)
}

/// Spawn a local PTY running an arbitrary command. Used both for the default
/// shell and for `docker exec` container shells.
pub fn connect_command(
    app_handle: AppHandle,
    sessions: LocalSessions,
    session_id: String,
    cmd: CommandBuilder,
) -> Result<(), String> {
    let pty_system = native_pty_system();

    let pair = pty_system
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|e| format!("Failed to create PTY: {}", e))?;

    let mut child = pair.slave.spawn_command(cmd).map_err(|e| e.to_string())?;

    let mut reader = pair.master.try_clone_reader().map_err(|e| e.to_string())?;
    let mut writer = pair.master.take_writer().map_err(|e| e.to_string())?;

    let (cmd_tx, cmd_rx) = std::sync::mpsc::channel::<TermCommand>();

    sessions
        .lock()
        .unwrap()
        .insert(session_id.clone(), LocalSession { cmd_tx });

    let sid = session_id.clone();
    let app_handle_read = app_handle.clone();
    let sid_read = session_id.clone();
    let sessions_read = sessions.clone();

    let recorder: Arc<Mutex<Option<crate::recorder::Recorder>>> = Arc::new(Mutex::new(None));
    let recorder_read = recorder.clone();

    // Reader thread
    thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if let Ok(mut lock) = recorder_read.lock() {
                        if let Some(ref mut rec) = *lock {
                            let _ = rec.record_output(&buf[..n]);
                        }
                    }
                    app_handle_read
                        .emit(&format!("local-data-{}", sid_read), buf[..n].to_vec())
                        .ok();
                }
                Err(_) => break,
            }
        }
        sessions_read.lock().unwrap().remove(&sid_read);
        app_handle_read
            .emit(&format!("local-closed-{}", sid_read), ())
            .ok();
    });

    let app_handle_write = app_handle.clone();
    let sessions_write = sessions.clone();

    // Writer thread
    thread::spawn(move || {
        while let Ok(cmd) = cmd_rx.recv() {
            match cmd {
                TermCommand::Data(data) => {
                    writer.write_all(&data).ok();
                }
                TermCommand::Resize(cols, rows) => {
                    pair.master
                        .resize(PtySize {
                            rows,
                            cols,
                            pixel_width: 0,
                            pixel_height: 0,
                        })
                        .ok();
                }
                TermCommand::StartRecording(path) => {
                    if let Ok(rec) =
                        crate::recorder::Recorder::new(std::path::Path::new(&path), 80, 24)
                    {
                        if let Ok(mut lock) = recorder.lock() {
                            *lock = Some(rec);
                        }
                    }
                }
                TermCommand::StopRecording => {
                    if let Ok(mut lock) = recorder.lock() {
                        *lock = None;
                    }
                }
                TermCommand::Close => {
                    child.kill().ok();
                    sessions_write.lock().unwrap().remove(&sid);
                    app_handle_write
                        .emit(&format!("local-closed-{}", sid), ())
                        .ok();
                    return;
                }
            }
        }
    });

    Ok(())
}
