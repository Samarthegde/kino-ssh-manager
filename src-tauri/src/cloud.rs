//! Kino Cloud: the pasted account key, and the kino-control API calls made
//! with it (machine list, add machine, one-call connect).
//!
//! The config (control URL + account key) is encrypted at rest under the
//! vault key, like the AI and sync configs. A decrypted copy sits in ACTIVE
//! while the vault is unlocked, so the connect path - which has no access to
//! Tauri state - can read it without threading state through every caller.

use std::collections::HashMap;
use std::sync::{Mutex, RwLock};

use serde::{Deserialize, Serialize};

use crate::vault::{load_encrypted, save_encrypted, vault_path};

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct CloudConfig {
    pub control_url: String,
    pub account_key: String,
}

/// What the UI sees - the key itself is never echoed back.
#[derive(Serialize)]
pub struct CloudConfigView {
    pub control_url: String,
    pub key_set: bool,
}

#[derive(Deserialize)]
pub struct CloudConfigInput {
    pub control_url: String,
    /// Empty means "keep the stored one".
    pub account_key: String,
}

/// Decrypted config for the lifetime of the unlocked vault.
static ACTIVE: RwLock<Option<CloudConfig>> = RwLock::new(None);

/// Last successful connect info per agent id, so a kino-control outage
/// degrades to "reuse where it was" instead of failing outright. Manager
/// JWTs live ~1h; entries past expiry are useless and skipped.
static CONNECT_CACHE: Mutex<Option<HashMap<String, CachedConnect>>> = Mutex::new(None);

#[derive(Clone)]
struct CachedConnect {
    relay_url: String,
    token: String,
    expires_at: u64,
}

fn config_path() -> std::path::PathBuf {
    vault_path().parent().unwrap().join("cloud.enc")
}

/// Write the config under a given key - what a master-password change or a
/// recovery needs, since neither has the vault's own save path to hand.
pub fn save_config_with(
    config: &CloudConfig,
    key: &[u8; 32],
    salt: &[u8; 16],
) -> Result<(), String> {
    save_encrypted(&config_path(), config, key, salt)
}

pub fn load_config(key: &[u8; 32]) -> Option<CloudConfig> {
    let path = config_path();
    if !path.exists() {
        return None;
    }
    load_encrypted::<CloudConfig>(&path, key).ok()
}

/// Called on unlock (and after config changes): make the decrypted config
/// available to the connect path.
pub fn activate(key: &[u8; 32]) {
    *ACTIVE.write().unwrap() = load_config(key);
}

/// Called on lock: drop the decrypted copy alongside the vault key.
pub fn deactivate() {
    *ACTIVE.write().unwrap() = None;
    *CONNECT_CACHE.lock().unwrap() = None;
}

pub fn active() -> Option<CloudConfig> {
    ACTIVE
        .read()
        .unwrap()
        .clone()
        .filter(|c| !c.control_url.is_empty() && !c.account_key.is_empty())
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn get_json(config: &CloudConfig, path: &str) -> Result<serde_json::Value, String> {
    call_json(ureq::get(&url(config, path)), config)
}

fn post_json(config: &CloudConfig, path: &str) -> Result<serde_json::Value, String> {
    call_json(
        ureq::post(&url(config, path)).set("Content-Length", "0"),
        config,
    )
}

fn url(config: &CloudConfig, path: &str) -> String {
    format!("{}{}", config.control_url.trim_end_matches('/'), path)
}

fn call_json(req: ureq::Request, config: &CloudConfig) -> Result<serde_json::Value, String> {
    let response = req
        .set("Authorization", &format!("Bearer {}", config.account_key))
        .timeout(std::time::Duration::from_secs(10))
        .call()
        .map_err(|e| match e {
            ureq::Error::Status(401, _) => {
                "Kino Cloud rejected the account key - check Settings".to_string()
            }
            ureq::Error::Status(status, resp) => format!(
                "Kino Cloud error (HTTP {status}): {}",
                resp.into_string().unwrap_or_default()
            ),
            other => format!("Cannot reach Kino Cloud: {other}"),
        })?;
    response
        .into_json()
        .map_err(|e| format!("Bad response from Kino Cloud: {e}"))
}

/// One-call connect: fresh short-lived manager JWT + where the agent is
/// parked. Falls back to the last successful answer (if its JWT is still
/// alive) when kino-control is unreachable.
pub fn connect_info(agent_id: &str) -> Result<(String, String), String> {
    let config = active()
        .ok_or("This host uses Kino Cloud, but no account key is configured - see Settings")?;
    match post_json(&config, &format!("/api/machines/{agent_id}/connect")) {
        Ok(body) => {
            let token = body["token"]
                .as_str()
                .ok_or("Kino Cloud returned no connection token")?
                .to_string();
            let relay_url = body["relay_url"].as_str().map(str::to_string).ok_or(
                "This machine's agent hasn't reported to any relay yet - is it installed and running?",
            )?;
            let mut cache = CONNECT_CACHE.lock().unwrap();
            cache.get_or_insert_with(HashMap::new).insert(
                agent_id.to_string(),
                CachedConnect {
                    relay_url: relay_url.clone(),
                    token: token.clone(),
                    // Conservative: manager JWTs default to 1h; refresh of the
                    // cache happens on every successful connect anyway.
                    expires_at: body["expires_at"].as_u64().unwrap_or(now() + 3000),
                },
            );
            Ok((token, relay_url))
        }
        Err(err) => {
            let cache = CONNECT_CACHE.lock().unwrap();
            if let Some(hit) = cache.as_ref().and_then(|m| m.get(agent_id)) {
                if hit.expires_at > now() + 60 {
                    return Ok((hit.token.clone(), hit.relay_url.clone()));
                }
            }
            Err(err)
        }
    }
}

// ── Tauri commands ───────────────────────────────────────────────────────────

#[tauri::command]
pub fn cloud_get_config(
    state: tauri::State<'_, crate::AppState>,
) -> Result<Option<CloudConfigView>, String> {
    let key = state.vault_key.lock().unwrap().ok_or("Vault is locked")?;
    Ok(load_config(&key).map(|c| CloudConfigView {
        control_url: c.control_url,
        key_set: !c.account_key.is_empty(),
    }))
}

#[tauri::command]
pub fn cloud_set_config(
    state: tauri::State<'_, crate::AppState>,
    config: CloudConfigInput,
) -> Result<CloudConfigView, String> {
    let key = state.vault_key.lock().unwrap().ok_or("Vault is locked")?;
    let salt = state.vault_salt.lock().unwrap().ok_or("Vault is locked")?;
    let existing = load_config(&key).unwrap_or_default();
    let next = CloudConfig {
        control_url: config.control_url.trim().trim_end_matches('/').to_string(),
        account_key: if config.account_key.is_empty() {
            existing.account_key
        } else {
            config.account_key.trim().to_string()
        },
    };
    save_encrypted(&config_path(), &next, &key, &salt)?;
    activate(&key);
    Ok(CloudConfigView {
        control_url: next.control_url,
        key_set: !next.account_key.is_empty(),
    })
}

#[derive(Serialize)]
pub struct Machine {
    pub agent_id: String,
    pub name: String,
    pub created_at: u64,
    pub relay_url: Option<String>,
    pub last_seen: Option<u64>,
}

#[tauri::command]
pub fn cloud_list_machines() -> Result<Vec<Machine>, String> {
    let config = active().ok_or("Kino Cloud is not configured - see Settings")?;
    let body = get_json(&config, "/api/machines")?;
    Ok(body
        .as_array()
        .map(|rows| {
            rows.iter()
                .map(|m| Machine {
                    agent_id: m["agent_id"].as_str().unwrap_or_default().to_string(),
                    name: m["name"].as_str().unwrap_or_default().to_string(),
                    created_at: m["created_at"].as_u64().unwrap_or(0),
                    relay_url: m["relay_url"].as_str().map(str::to_string),
                    last_seen: m["last_seen"].as_u64(),
                })
                .collect()
        })
        .unwrap_or_default())
}

#[derive(Serialize)]
pub struct AddedMachine {
    pub agent_id: String,
    pub name: String,
    pub install_command: String,
}

#[tauri::command]
pub fn cloud_add_machine(name: String) -> Result<AddedMachine, String> {
    let config = active().ok_or("Kino Cloud is not configured - see Settings")?;
    let body = ureq::post(&url(&config, "/api/machines"))
        .set("Authorization", &format!("Bearer {}", config.account_key))
        .timeout(std::time::Duration::from_secs(10))
        .send_json(serde_json::json!({ "name": name }))
        .map_err(|e| match e {
            ureq::Error::Status(status, resp) => format!(
                "Kino Cloud error (HTTP {status}): {}",
                resp.into_string().unwrap_or_default()
            ),
            other => format!("Cannot reach Kino Cloud: {other}"),
        })?
        .into_json::<serde_json::Value>()
        .map_err(|e| format!("Bad response from Kino Cloud: {e}"))?;
    Ok(AddedMachine {
        agent_id: body["agent_id"].as_str().unwrap_or_default().to_string(),
        name: body["name"].as_str().unwrap_or_default().to_string(),
        install_command: body["install_command"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
    })
}

#[tauri::command]
pub fn cloud_remove_machine(agent_id: String) -> Result<(), String> {
    let config = active().ok_or("Kino Cloud is not configured - see Settings")?;
    ureq::delete(&url(&config, &format!("/api/machines/{agent_id}")))
        .set("Authorization", &format!("Bearer {}", config.account_key))
        .timeout(std::time::Duration::from_secs(10))
        .call()
        .map_err(|e| format!("Kino Cloud error: {e}"))?;
    Ok(())
}
