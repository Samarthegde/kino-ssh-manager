use serde_json::json;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::time::Instant;

/// Where casts live: a visible folder the user can open, back up or delete,
/// rather than somewhere under application data they would never find.
pub fn recordings_dir() -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join("Videos").join("Kino Recordings")
}

pub struct Recorder {
    file: File,
    last_event_time: Instant,
}

impl Recorder {
    pub fn new(path: &Path, cols: u32, rows: u32) -> Result<Self, String> {
        Self::with_command(path, cols, rows, None)
    }

    /// A recording that names the command it is of (KR-01-F10).
    ///
    /// Asciicast v3 allows `command` in the header, and players show it. For
    /// an MCP recording it is the whole point: the cast is evidence of one
    /// command, and a cast whose first line is already output leaves the
    /// reader guessing what produced it.
    pub fn with_command(
        path: &Path,
        cols: u32,
        rows: u32,
        command: Option<&str>,
    ) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create recording directory: {}", e))?;
        }

        let mut file = OpenOptions::new()
            .write(true)
            .create(true) // We use create to allow overwrite if needed, or we just append
            .truncate(true) // We truncate to start a fresh cast file
            .open(path)
            .map_err(|e| format!("Failed to create cast file: {}", e))?;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Write Asciicast v3 header. v3 nests the terminal size under `term`
        // (v2 used top-level `width`/`height`); players reject a v3 cast that
        // is missing `term.cols`/`term.rows`.
        let mut header = json!({
            "version": 3,
            "term": {
                "cols": cols,
                "rows": rows,
            },
            "timestamp": timestamp,
        });
        if let Some(command) = command {
            header["command"] = json!(command);
        }

        writeln!(file, "{}", header).map_err(|e| format!("Failed to write header: {}", e))?;

        Ok(Recorder {
            file,
            last_event_time: Instant::now(),
        })
    }

    /// Record what was typed, as an `"i"` event (KR-01-F10).
    ///
    /// Without this a cast holds only output, so the command that caused it is
    /// missing from the replay - and for an MCP recording the command *is* the
    /// thing being recorded.
    pub fn record_input(&mut self, data: &[u8]) -> Result<(), String> {
        self.record_event("i", data)
    }

    pub fn record_output(&mut self, data: &[u8]) -> Result<(), String> {
        self.record_event("o", data)
    }

    fn record_event(&mut self, kind: &str, data: &[u8]) -> Result<(), String> {
        if data.is_empty() {
            return Ok(());
        }
        let now = Instant::now();
        let delta = now.duration_since(self.last_event_time).as_secs_f64();
        self.last_event_time = now;

        let data_str = String::from_utf8_lossy(data);

        let event = json!([delta, kind, data_str]);

        writeln!(self.file, "{}", event).map_err(|e| e.to_string())?;
        Ok(())
    }
}
