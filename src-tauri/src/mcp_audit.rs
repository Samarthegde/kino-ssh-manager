//! The record of what an assistant did over MCP (KR-01-F8, KR-01-F9).
//!
//! Until now nothing in Kino could answer "what did the assistant run on prod
//! at 2am?". The policy decides *whether* a call runs; this says what
//! happened, including the calls that were refused - a run of denials is how
//! an assistant probing its limits looks from here.
//!
//! **One sealed record per line.** Each is encrypted on its own, under the MCP
//! key with its own nonce, and appended with `O_APPEND`. Nothing earlier is
//! ever read, decrypted or rewritten to add a record, so a crash mid-write
//! costs the last line rather than the file, several `kino-mcp` processes can
//! append at once, and the writer needs no lock. A single sealed blob would
//! give up all four.
//!
//! The key is the MCP key, not the master key: `kino-mcp` never has the master
//! key, and a log the server cannot write is not a log. The app derives the
//! same key from the MCP password it already stores to read the log back.
//!
//! A line that will not decrypt is kept and reported, never dropped. That is
//! the shape tampering takes, and a viewer that silently skipped such lines
//! would present a doctored log as a clean one.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// One tool call, as it is stored.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct AuditRecord {
    /// Unix milliseconds. No date library here, and the frontend formats it.
    pub ts: u64,
    pub tool: String,
    pub host_id: Option<String>,
    pub host_name: Option<String>,
    /// The command, path or snippet the call was about - verbatim, because a
    /// summarised command is not evidence.
    pub argument: String,
    /// `allow` | `deny`. The approval broker (KR-01-F5) will add `approved`,
    /// `denied_by_user` and `expired`.
    pub decision: String,
    /// Which rule decided, when one did.
    pub rule_id: Option<String>,
    /// The remote command's exit code, where the tool produced one.
    pub exit_code: Option<i32>,
    /// Size of the output handed back, before any truncation.
    pub bytes_out: Option<usize>,
    pub duration_ms: u64,
    pub client_name: String,
    pub client_version: String,
    /// The asciicast of this call, when one was written (KR-01-F10). A name,
    /// not a path: recordings live in one folder, and a path in the log would
    /// go stale the moment that folder moved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recording: Option<String>,
    /// Set when the call was allowed but failed anyway - the host was
    /// unreachable, authentication failed. Allowed-and-broken and
    /// refused-by-policy are different events and must not read alike.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// A line as it sits on disk: a nonce and a sealed record.
#[derive(Serialize, Deserialize)]
struct SealedLine {
    v: u8,
    nonce: String,
    ct: String,
}

/// What a read produced. A line that would not decrypt is an entry too.
#[derive(Serialize, Debug)]
pub struct AuditEntry {
    /// `None` when the line could not be decrypted.
    pub record: Option<AuditRecord>,
    /// 1-based line number, so a report can name the line.
    pub line: usize,
}

pub fn audit_path() -> PathBuf {
    crate::vault::vault_path()
        .parent()
        .unwrap()
        .join("mcp_audit.jsonl.enc")
}

fn seal(key: &[u8; 32], record: &AuditRecord) -> Result<String, String> {
    use aes_gcm::aead::{Aead, KeyInit, OsRng};
    use aes_gcm::{AeadCore, Aes256Gcm, Key};
    use base64::{engine::general_purpose::STANDARD, Engine};

    let plaintext = serde_json::to_vec(record).map_err(|e| e.to_string())?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(&nonce, plaintext.as_slice())
        .map_err(|e| e.to_string())?;

    serde_json::to_string(&SealedLine {
        v: 1,
        nonce: STANDARD.encode(nonce),
        ct: STANDARD.encode(ct),
    })
    .map_err(|e| e.to_string())
}

fn open(key: &[u8; 32], line: &str) -> Option<AuditRecord> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use base64::{engine::general_purpose::STANDARD, Engine};

    let sealed: SealedLine = serde_json::from_str(line).ok()?;
    let nonce = STANDARD.decode(&sealed.nonce).ok()?;
    let ct = STANDARD.decode(&sealed.ct).ok()?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), ct.as_slice())
        .ok()?;
    serde_json::from_slice(&plaintext).ok()
}

/// The writer `kino-mcp` holds for the life of the process.
pub struct AuditLog {
    path: PathBuf,
    key: [u8; 32],
}

impl Drop for AuditLog {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
    }
}

impl AuditLog {
    pub fn new(path: PathBuf, key: [u8; 32]) -> Self {
        AuditLog { path, key }
    }

    /// Append one record.
    ///
    /// Returns the error rather than panicking, and the caller reports it to
    /// stderr: a failure to record must not become a failure to answer a call
    /// the policy already allowed. Whether an unwritable log should instead
    /// stop the server is KR-11's question, where budgets depend on it.
    pub fn append(&self, record: &AuditRecord) -> Result<(), String> {
        use std::io::Write;
        let line = seal(&self.key, record)?;
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| format!("Cannot open the audit log: {e}"))?;
        // One write, one line: O_APPEND makes it atomic against other writers.
        file.write_all(format!("{line}\n").as_bytes())
            .map_err(|e| format!("Cannot write to the audit log: {e}"))
    }
}

/// Read every record. Order is the order they were written.
///
/// A missing file is an empty log - nothing has been recorded yet - and not an
/// error.
pub fn read_all(path: &PathBuf, key: &[u8; 32]) -> Result<Vec<AuditEntry>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(path).map_err(|e| format!("Cannot read the log: {e}"))?;
    Ok(text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .enumerate()
        .map(|(i, line)| AuditEntry {
            record: open(key, line),
            line: i + 1,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn record(tool: &str) -> AuditRecord {
        AuditRecord {
            ts: 1_700_000_000_000,
            tool: tool.into(),
            host_id: Some("h1".into()),
            host_name: Some("web-prod".into()),
            argument: "rm -rf /".into(),
            decision: "deny".into(),
            rule_id: Some("default_deny".into()),
            duration_ms: 3,
            client_name: "claude-desktop".into(),
            client_version: "1.2.3".into(),
            ..Default::default()
        }
    }

    #[test]
    fn a_record_survives_the_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl.enc");
        let log = AuditLog::new(path.clone(), key(7));
        log.append(&record("ssh_exec")).unwrap();

        let entries = read_all(&path, &key(7)).unwrap();
        assert_eq!(entries.len(), 1);
        let got = entries[0].record.as_ref().unwrap();
        assert_eq!(got.tool, "ssh_exec");
        assert_eq!(got.argument, "rm -rf /", "the command is kept verbatim");
        assert_eq!(got.decision, "deny");
        assert_eq!(got.client_name, "claude-desktop");
    }

    #[test]
    fn the_command_is_not_on_disk_in_the_clear() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl.enc");
        AuditLog::new(path.clone(), key(7))
            .append(&record("ssh_exec"))
            .unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("rm -rf"));
        assert!(!raw.contains("web-prod"));
    }

    #[test]
    fn appending_keeps_every_earlier_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl.enc");
        let log = AuditLog::new(path.clone(), key(7));
        for tool in ["list_hosts", "ssh_exec", "sftp_read"] {
            log.append(&record(tool)).unwrap();
        }
        let entries = read_all(&path, &key(7)).unwrap();
        let tools: Vec<_> = entries
            .iter()
            .map(|e| e.record.as_ref().unwrap().tool.as_str())
            .collect();
        assert_eq!(tools, ["list_hosts", "ssh_exec", "sftp_read"]);
    }

    #[test]
    fn a_second_writer_does_not_lose_the_first_ones_records() {
        // Two kino-mcp processes, or one restarted mid-session.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl.enc");
        AuditLog::new(path.clone(), key(7))
            .append(&record("ssh_exec"))
            .unwrap();
        AuditLog::new(path.clone(), key(7))
            .append(&record("sftp_write"))
            .unwrap();
        assert_eq!(read_all(&path, &key(7)).unwrap().len(), 2);
    }

    #[test]
    fn a_tampered_line_is_reported_not_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl.enc");
        let log = AuditLog::new(path.clone(), key(7));
        log.append(&record("ssh_exec")).unwrap();
        log.append(&record("sftp_write")).unwrap();
        log.append(&record("run_snippet")).unwrap();

        // Rewrite the middle line, as someone hiding a call would.
        let mut lines: Vec<String> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        let mut sealed: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
        let ct = sealed["ct"].as_str().unwrap().to_string();
        // Flip one base64 character of the ciphertext - GCM's tag catches it.
        let flipped = format!(
            "{}{}",
            if ct.starts_with('A') { 'B' } else { 'A' },
            &ct[1..]
        );
        sealed["ct"] = serde_json::Value::String(flipped);
        lines[1] = serde_json::to_string(&sealed).unwrap();
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let entries = read_all(&path, &key(7)).unwrap();
        assert_eq!(entries.len(), 3, "the line is kept");
        assert!(entries[0].record.is_some());
        assert!(entries[2].record.is_some(), "later records still read");
        let bad: Vec<usize> = entries
            .iter()
            .filter(|e| e.record.is_none())
            .map(|e| e.line)
            .collect();
        assert_eq!(bad, [2], "and it is reported by line number");
    }

    #[test]
    fn the_wrong_key_reads_nothing_rather_than_erroring() {
        // What the app sees after the MCP password is changed: every record is
        // unreadable, and the viewer must say so rather than show an empty log.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl.enc");
        AuditLog::new(path.clone(), key(7))
            .append(&record("ssh_exec"))
            .unwrap();
        let entries = read_all(&path, &key(9)).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].record.is_none());
    }

    #[test]
    fn a_missing_log_is_empty_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nothing-here.jsonl.enc");
        assert!(read_all(&path, &key(7)).unwrap().is_empty());
    }

    #[test]
    fn every_record_gets_its_own_nonce() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl.enc");
        let log = AuditLog::new(path.clone(), key(7));
        log.append(&record("ssh_exec")).unwrap();
        log.append(&record("ssh_exec")).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_ne!(
            lines[0], lines[1],
            "identical records must not produce identical lines"
        );
    }
}
