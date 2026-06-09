//! Host key verification (trust-on-first-use).
//!
//! We store SHA256 fingerprints of accepted host keys in `known_hosts.json`
//! (keyed by `host:port`). Fingerprints aren't secret, so this file is plain
//! JSON, mirroring how OpenSSH's known_hosts is plaintext. On connect we compare
//! the server's presented key against the stored fingerprint:
//!   - match    → proceed
//!   - changed  → refuse (possible MITM) until the user re-trusts
//!   - unknown  → first contact; the UI shows the fingerprint and asks to trust

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use serde::Serialize;
use ssh2::Session;
use std::collections::HashMap;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::time::Duration;

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

/// `SHA256:<base64-no-pad>` of the session's host key, matching OpenSSH's format.
fn fingerprint_of(session: &Session) -> Result<String, String> {
    let hash = session
        .host_key_hash(ssh2::HashType::Sha256)
        .ok_or("Server did not present a host key")?;
    Ok(format!("SHA256:{}", STANDARD_NO_PAD.encode(hash)))
}

/// TCP connect + SSH handshake only (no auth), to read the server's fingerprint.
fn fetch_fingerprint(host: &Host) -> Result<String, String> {
    let addr = format!("{}:{}", host.hostname, host.port);
    let socket = addr
        .to_socket_addrs()
        .map_err(|e| format!("Cannot resolve {}: {}", addr, e))?
        .next()
        .ok_or_else(|| format!("No address found for {}", addr))?;
    let tcp = TcpStream::connect_timeout(&socket, Duration::from_secs(15))
        .map_err(|e| format!("Connection failed: {}", e))?;
    let mut session = Session::new().map_err(|e| e.to_string())?;
    session.set_tcp_stream(tcp);
    session
        .handshake()
        .map_err(|e| format!("SSH handshake failed: {}", e))?;
    fingerprint_of(&session)
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
pub fn verify(host: &Host) -> Result<HostKeyVerdict, String> {
    let fp = fetch_fingerprint(host)?;
    let map = load_map();
    Ok(classify(map.get(&key_for(host)).map(|s| s.as_str()), &fp))
}

/// Record the exact fingerprint the user approved in the UI. Storing the
/// approved value (rather than re-fetching) means `enforce` will still catch a
/// key that was swapped after approval.
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

/// Enforced inside an established session (after handshake, before auth). Refuses
/// to proceed unless the live key matches a trusted fingerprint.
pub fn enforce(session: &Session, host: &Host) -> Result<(), String> {
    let fp = fingerprint_of(session)?;
    let map = load_map();
    match map.get(&key_for(host)) {
        Some(known) if known == &fp => Ok(()),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn host(hostname: &str, port: u16) -> Host {
        Host {
            id: "1".into(),
            name: "t".into(),
            hostname: hostname.into(),
            port,
            username: "root".into(),
            default_auth: "Password".into(),
            password: None,
            private_key: None,
            public_key: None,
            passphrase: None,
            port_forwards: vec![],
            on_connect_snippets: vec![],
            color: None,
            notes: None,
            group: None,
        }
    }

    #[test]
    fn key_for_combines_host_and_port() {
        assert_eq!(key_for(&host("example.com", 2222)), "example.com:2222");
    }

    #[test]
    fn classify_first_contact_is_new() {
        assert!(matches!(
            classify(None, "SHA256:abc"),
            HostKeyVerdict::New { .. }
        ));
    }

    #[test]
    fn classify_matching_key_is_trusted() {
        assert!(matches!(
            classify(Some("SHA256:abc"), "SHA256:abc"),
            HostKeyVerdict::Trusted
        ));
    }

    #[test]
    fn classify_different_key_is_changed() {
        match classify(Some("SHA256:old"), "SHA256:new") {
            HostKeyVerdict::Changed { fingerprint, known } => {
                assert_eq!(fingerprint, "SHA256:new");
                assert_eq!(known, "SHA256:old");
            }
            other => panic!("expected Changed, got {:?}", serde_json::to_string(&other)),
        }
    }
}
