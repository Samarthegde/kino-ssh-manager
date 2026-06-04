use crate::vault::{load_encrypted, save_encrypted, vault_path};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HistoryEvent {
    pub id: String,
    pub timestamp: u64,
    pub event_type: String,
    pub message: String,
    pub host_id: Option<String>,
}

pub fn history_path() -> PathBuf {
    vault_path().parent().unwrap().join("history.enc")
}

pub fn save_history(
    events: &[HistoryEvent],
    key: &[u8; 32],
    salt: &[u8; 16],
) -> Result<(), String> {
    save_encrypted(&history_path(), events, key, salt)
}

pub fn load_history(key: &[u8; 32]) -> Result<Vec<HistoryEvent>, String> {
    let path = history_path();
    if !path.exists() {
        return Ok(vec![]);
    }
    load_encrypted(&path, key).or_else(|_| Ok(vec![]))
}
