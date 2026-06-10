//! Host key verification (trust-on-first-use) using russh.
//!
//! We store SHA256 fingerprints of accepted host keys in `known_hosts.json`
//! (keyed by `host:port`). Fingerprints aren't secret, so this file is plain
//! JSON, mirroring how OpenSSH's known_hosts is plaintext. On connect we compare
//! the server's presented key against the stored fingerprint:
//!   - match    → proceed
//!   - changed  → refuse (possible MITM) until the user re-trusts
//!   - unknown  → first contact; the UI shows the fingerprint and asks to trust

use russh::keys::ssh_key::{HashAlg, PublicKey};
use serde::Serialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::vault::{vault_path, Host};

fn store_path() -> PathBuf {
    vault_path().parent().unwrap().join("known_hosts.json")
}

pub(crate) fn key_for(host: &Host) -> String {
    format!("{}:{}", host.hostname, host.port)
}

/// Pure decision: compare a presented fingerprint against the stored one.
pub(crate) fn classify(stored: Option<&str>, presented: &str) -> HostKeyVerdict {
    match stored {
        Some(known) if known == presented => HostKeyVerdict::Trusted,
        Some(known) => HostKeyVerdict::Changed {
            fingerprint: presented.to_string(),
            known: known.to_string(),
        },
        None => HostKeyVerdict::New {
            fingerprint: presented.to_string(),
        },
    }
}

fn load_map() -> HashMap<String, String> {
    std::fs::read(store_path())
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn save_map(map: &HashMap<String, String>) -> Result<(), String> {
    let path = store_path();
    std::fs::create_dir_all(path.parent().unwrap()).map_err(|e| e.to_string())?;
    let json = serde_json::to_vec_pretty(map).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| e.to_string())
}

struct FingerprintFetcher {
    fingerprint: Arc<Mutex<Option<String>>>,
}

impl russh::client::Handler for FingerprintFetcher {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        let fp = server_public_key.fingerprint(HashAlg::Sha256).to_string();
        *self.fingerprint.lock().await = Some(fp);
        Ok(false) // Abort connection immediately, we just wanted the key
    }
}

/// Connect just far enough to read the server's fingerprint.
async fn fetch_fingerprint(host: &Host) -> Result<String, String> {
    let config = Arc::new(russh::client::Config::default());
    let fp_store = Arc::new(Mutex::new(None));
    let handler = FingerprintFetcher {
        fingerprint: Arc::clone(&fp_store),
    };

    let _ = russh::client::connect(config, (host.hostname.as_str(), host.port), handler).await;

    let fp = fp_store.lock().await.take();
    fp.ok_or_else(|| "Failed to fetch host key (connection timed out or refused)".to_string())
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum HostKeyVerdict {
    /// Presented key matches the stored fingerprint.
    Trusted,
    /// No fingerprint stored yet — first contact.
    New { fingerprint: String },
    /// Stored fingerprint differs from what the server presented.
    Changed { fingerprint: String, known: String },
}

/// Connect just far enough to read the host key and compare to our store.
pub async fn verify(host: &Host) -> Result<HostKeyVerdict, String> {
    let fp = fetch_fingerprint(host).await?;
    let map = load_map();
    Ok(classify(map.get(&key_for(host)).map(|s| s.as_str()), &fp))
}

/// Record the exact fingerprint the user approved in the UI.
pub fn trust(host: &Host, fingerprint: String) -> Result<(), String> {
    let mut map = load_map();
    map.insert(key_for(host), fingerprint);
    save_map(&map)
}

pub fn forget(host: &Host) -> Result<(), String> {
    let mut map = load_map();
    map.remove(&key_for(host));
    save_map(&map)
}

/// Enforced inside an established session's `check_server_key`.
/// Returns `Ok(())` if it matches, or an error string if it fails.
pub fn enforce(host: &Host, presented_fingerprint: &str) -> Result<(), String> {
    let map = load_map();
    match map.get(&key_for(host)) {
        Some(known) if known == presented_fingerprint => Ok(()),
        Some(_) => Err(format!(
            "HOST KEY MISMATCH for {} — the server's key differs from the trusted one. \
             Possible man-in-the-middle; connection refused.",
            key_for(host)
        )),
        None => Err(format!(
            "Host key for {} has not been verified. Connect from the host list to review and trust it.",
            key_for(host)
        )),
    }
}
