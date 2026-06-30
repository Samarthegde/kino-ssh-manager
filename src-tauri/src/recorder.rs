use serde_json::json;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::Instant;

pub struct Recorder {
    file: File,
    last_event_time: Instant,
}

impl Recorder {
    pub fn new(path: &Path, cols: u32, rows: u32) -> Result<Self, String> {
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
        let header = json!({
            "version": 3,
            "term": {
                "cols": cols,
                "rows": rows,
            },
            "timestamp": timestamp,
        });

        writeln!(file, "{}", header).map_err(|e| format!("Failed to write header: {}", e))?;

        Ok(Recorder {
            file,
            last_event_time: Instant::now(),
        })
    }

    pub fn record_output(&mut self, data: &[u8]) -> Result<(), String> {
        if data.is_empty() {
            return Ok(());
        }
        let now = Instant::now();
        let delta = now.duration_since(self.last_event_time).as_secs_f64();
        self.last_event_time = now;

        let data_str = String::from_utf8_lossy(data);

        let event = json!([delta, "o", data_str]);

        writeln!(self.file, "{}", event).map_err(|e| e.to_string())?;
        Ok(())
    }
}
