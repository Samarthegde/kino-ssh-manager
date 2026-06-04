//! Shared library of command snippets. A snippet is a reusable block of shell
//! commands; hosts reference snippets by id (`Host.on_connect_snippets`) to run
//! them automatically right after connecting. Stored encrypted next to the
//! vault (same key/salt) and synced as a sibling blob, mirroring history.

use crate::vault::{load_encrypted, save_encrypted, vault_path};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Snippet {
    pub id: String,
    pub name: String,
    /// Multi-line command text; each line is sent to the shell in order.
    pub commands: String,
}

pub fn snippets_path() -> PathBuf {
    vault_path().parent().unwrap().join("snippets.enc")
}

pub fn save_snippets(snippets: &[Snippet], key: &[u8; 32], salt: &[u8; 16]) -> Result<(), String> {
    save_encrypted(&snippets_path(), snippets, key, salt)
}

pub fn load_snippets(key: &[u8; 32]) -> Result<Vec<Snippet>, String> {
    let path = snippets_path();
    if !path.exists() {
        return Ok(vec![]);
    }
    load_encrypted(&path, key).or_else(|_| Ok(vec![]))
}
