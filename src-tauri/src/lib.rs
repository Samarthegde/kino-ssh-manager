mod docker;
mod forwarding;
mod history;
mod host_keys;
mod keygen;
mod local_session;
mod metrics;
mod recorder;
mod sftp_session;
mod snippets;
mod ssh_session;
mod sync;
mod update;
mod vault;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tauri::State;
use uuid::Uuid;
use vault::Host;

pub struct AppState {
    pub vault_key: Arc<Mutex<Option<[u8; 32]>>>,
    pub vault_salt: Arc<Mutex<Option<[u8; 16]>>>,
    pub hosts: Arc<Mutex<Vec<Host>>>,
    pub history: Arc<Mutex<Vec<history::HistoryEvent>>>,
    pub snippets: Arc<Mutex<Vec<snippets::Snippet>>>,
    pub sessions: ssh_session::Sessions,
    pub local_sessions: local_session::LocalSessions,
    pub active_forwards: Arc<Mutex<HashMap<String, forwarding::ForwardHandle>>>,
    pub sftp_sessions: Arc<Mutex<HashMap<String, sftp_session::SftpHandle>>>,
    pub metrics_streams: metrics::MetricsStreams,
    pub docker_log_streams: docker::LogStreams,
}

// ── Vault commands ────────────────────────────────────────────────────────────

#[tauri::command]
fn vault_exists() -> bool {
    vault::vault_exists()
}

#[tauri::command]
fn unlock_vault(state: State<'_, AppState>, password: String) -> Result<Vec<Host>, String> {
    if vault::vault_exists() {
        let (hosts, key, salt) = vault::load_vault(&password)?;
        let history = history::load_history(&key).unwrap_or_default();
        let snippets = snippets::load_snippets(&key).unwrap_or_default();
        *state.vault_key.lock().unwrap() = Some(key);
        *state.vault_salt.lock().unwrap() = Some(salt);
        *state.hosts.lock().unwrap() = hosts.clone();
        *state.history.lock().unwrap() = history;
        *state.snippets.lock().unwrap() = snippets;
        Ok(hosts)
    } else {
        use aes_gcm::aead::OsRng;
        use rand_core::RngCore;
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let key = vault::derive_key(&password, &salt)?;
        let hosts: Vec<Host> = vec![];
        let history: Vec<history::HistoryEvent> = vec![];
        let snippets: Vec<snippets::Snippet> = vec![];
        vault::save_vault(&hosts, &key, &salt)?;
        history::save_history(&history, &key, &salt)?;
        snippets::save_snippets(&snippets, &key, &salt)?;
        *state.vault_key.lock().unwrap() = Some(key);
        *state.vault_salt.lock().unwrap() = Some(salt);
        *state.hosts.lock().unwrap() = hosts.clone();
        *state.history.lock().unwrap() = history;
        *state.snippets.lock().unwrap() = snippets;
        Ok(hosts)
    }
}

#[tauri::command]
fn lock_vault(state: State<'_, AppState>) {
    // Wipe the derived key from memory rather than just dropping it.
    if let Some(mut key) = state.vault_key.lock().unwrap().take() {
        use zeroize::Zeroize;
        key.zeroize();
    }
    *state.vault_salt.lock().unwrap() = None;
    state.hosts.lock().unwrap().clear();
    state.history.lock().unwrap().clear();
    state.snippets.lock().unwrap().clear();
}

/// Re-key the vault: verify the current master password, then re-encrypt the
/// vault, history, snippets, and sync config under a key derived from a brand-new
/// password + salt.
#[tauri::command]
fn change_master_password(
    state: State<'_, AppState>,
    current_password: String,
    new_password: String,
) -> Result<(), String> {
    use zeroize::Zeroize;
    if new_password.is_empty() {
        return Err("New password cannot be empty".to_string());
    }

    let (old_key, salt) = {
        let kg = state.vault_key.lock().unwrap();
        let sg = state.vault_salt.lock().unwrap();
        (
            *kg.as_ref().ok_or("Vault is locked")?,
            *sg.as_ref().ok_or("Vault is locked")?,
        )
    };

    // Verify the current password against the live key.
    let mut check = vault::derive_key(&current_password, &salt)?;
    let matches = check == old_key;
    check.zeroize();
    if !matches {
        return Err("Current password is incorrect".to_string());
    }

    // Fresh salt + key, then re-encrypt every store under it.
    use aes_gcm::aead::OsRng;
    use rand_core::RngCore;
    let mut new_salt = [0u8; 16];
    OsRng.fill_bytes(&mut new_salt);
    let new_key = vault::derive_key(&new_password, &new_salt)?;

    vault::save_vault(&state.hosts.lock().unwrap(), &new_key, &new_salt)?;
    history::save_history(&state.history.lock().unwrap(), &new_key, &new_salt)?;
    snippets::save_snippets(&state.snippets.lock().unwrap(), &new_key, &new_salt)?;
    if let Some(cfg) = sync::load_config(&old_key) {
        sync::save_config(&cfg, &new_key, &new_salt)?;
    }

    // Swap into state, wiping the old key.
    if let Some(mut k) = state.vault_key.lock().unwrap().replace(new_key) {
        k.zeroize();
    }
    *state.vault_salt.lock().unwrap() = Some(new_salt);
    Ok(())
}

#[tauri::command]
fn get_hosts(state: State<'_, AppState>) -> Result<Vec<Host>, String> {
    if state.vault_key.lock().unwrap().is_none() {
        return Err("Vault is locked".to_string());
    }
    Ok(state.hosts.lock().unwrap().clone())
}

#[tauri::command]
fn get_history(state: State<'_, AppState>) -> Result<Vec<history::HistoryEvent>, String> {
    if state.vault_key.lock().unwrap().is_none() {
        return Err("Vault is locked".to_string());
    }
    Ok(state.history.lock().unwrap().clone())
}

#[tauri::command]
fn log_history(state: State<'_, AppState>, event: history::HistoryEvent) -> Result<(), String> {
    let key_guard = state.vault_key.lock().unwrap();
    let key = key_guard.as_ref().ok_or("Vault is locked")?;
    let salt_guard = state.vault_salt.lock().unwrap();
    let salt = salt_guard.as_ref().ok_or("Vault is locked")?;

    let mut history = state.history.lock().unwrap();
    history.push(event);
    if history.len() > 100 {
        let remove_count = history.len() - 100;
        history.drain(0..remove_count);
    }
    history::save_history(&history, key, salt)?;
    Ok(())
}

#[tauri::command]
fn save_host(state: State<'_, AppState>, mut host: Host) -> Result<Host, String> {
    let key_guard = state.vault_key.lock().unwrap();
    let key = key_guard.as_ref().ok_or("Vault is locked")?;
    let salt_guard = state.vault_salt.lock().unwrap();
    let salt = salt_guard.as_ref().ok_or("Vault is locked")?;
    if host.id.is_empty() {
        host.id = Uuid::new_v4().to_string();
    }
    let mut hosts = state.hosts.lock().unwrap();
    if let Some(existing) = hosts.iter_mut().find(|h| h.id == host.id) {
        *existing = host.clone();
    } else {
        hosts.push(host.clone());
    }
    vault::save_vault(&hosts, key, salt)?;
    Ok(host)
}

#[tauri::command]
fn delete_host(state: State<'_, AppState>, id: String) -> Result<(), String> {
    let key_guard = state.vault_key.lock().unwrap();
    let key = key_guard.as_ref().ok_or("Vault is locked")?;
    let salt_guard = state.vault_salt.lock().unwrap();
    let salt = salt_guard.as_ref().ok_or("Vault is locked")?;
    let mut hosts = state.hosts.lock().unwrap();
    hosts.retain(|h| h.id != id);
    vault::save_vault(&hosts, key, salt)?;
    Ok(())
}

// ── Snippet library commands ──────────────────────────────────────────────────

#[tauri::command]
fn get_snippets(state: State<'_, AppState>) -> Result<Vec<snippets::Snippet>, String> {
    if state.vault_key.lock().unwrap().is_none() {
        return Err("Vault is locked".to_string());
    }
    Ok(state.snippets.lock().unwrap().clone())
}

#[tauri::command]
fn save_snippet(
    state: State<'_, AppState>,
    mut snippet: snippets::Snippet,
) -> Result<snippets::Snippet, String> {
    let key_guard = state.vault_key.lock().unwrap();
    let key = key_guard.as_ref().ok_or("Vault is locked")?;
    let salt_guard = state.vault_salt.lock().unwrap();
    let salt = salt_guard.as_ref().ok_or("Vault is locked")?;
    if snippet.id.is_empty() {
        snippet.id = Uuid::new_v4().to_string();
    }
    let mut list = state.snippets.lock().unwrap();
    if let Some(existing) = list.iter_mut().find(|s| s.id == snippet.id) {
        *existing = snippet.clone();
    } else {
        list.push(snippet.clone());
    }
    snippets::save_snippets(&list, key, salt)?;
    Ok(snippet)
}

#[tauri::command]
fn delete_snippet(state: State<'_, AppState>, id: String) -> Result<(), String> {
    let key_guard = state.vault_key.lock().unwrap();
    let key = key_guard.as_ref().ok_or("Vault is locked")?;
    let salt_guard = state.vault_salt.lock().unwrap();
    let salt = salt_guard.as_ref().ok_or("Vault is locked")?;
    let mut list = state.snippets.lock().unwrap();
    list.retain(|s| s.id != id);
    snippets::save_snippets(&list, key, salt)?;
    // Drop the now-dangling reference from any host that used this snippet.
    let mut hosts = state.hosts.lock().unwrap();
    let mut hosts_changed = false;
    for h in hosts.iter_mut() {
        let before = h.on_connect_snippets.len();
        h.on_connect_snippets.retain(|sid| sid != &id);
        if h.on_connect_snippets.len() != before {
            hosts_changed = true;
        }
    }
    if hosts_changed {
        vault::save_vault(&hosts, key, salt)?;
    }
    Ok(())
}

// ── Cloud sync commands ─────────────────────────────────────────────────────

/// Read the current sync settings for the UI (token is never returned).
#[tauri::command]
fn sync_get_config(state: State<'_, AppState>) -> Result<Option<sync::SyncConfigView>, String> {
    let key_guard = state.vault_key.lock().unwrap();
    let key = key_guard.as_ref().ok_or("Vault is locked")?;
    Ok(sync::load_config(key).map(|c| c.view()))
}

/// Save sync settings. An empty token keeps the previously stored one.
#[tauri::command]
fn sync_set_config(
    state: State<'_, AppState>,
    config: sync::SyncConfigInput,
) -> Result<sync::SyncConfigView, String> {
    let key_guard = state.vault_key.lock().unwrap();
    let key = key_guard.as_ref().ok_or("Vault is locked")?;
    let salt_guard = state.vault_salt.lock().unwrap();
    let salt = salt_guard.as_ref().ok_or("Vault is locked")?;

    let existing = sync::load_config(key);
    let token = if config.token.trim().is_empty() {
        existing
            .as_ref()
            .map(|c| c.token.clone())
            .unwrap_or_default()
    } else {
        config.token.trim().to_string()
    };

    let merged = sync::SyncConfig {
        provider: "github".to_string(),
        token,
        owner: config.owner.trim().to_string(),
        repo: config.repo.trim().to_string(),
        path: {
            let p = config.path.unwrap_or_default();
            if p.trim().is_empty() {
                "vault.enc".to_string()
            } else {
                p.trim().to_string()
            }
        },
        branch: {
            let b = config.branch.unwrap_or_default();
            if b.trim().is_empty() {
                "main".to_string()
            } else {
                b.trim().to_string()
            }
        },
        // Reconfiguring the target invalidates any stored version tokens.
        last_sha: existing.as_ref().and_then(|c| {
            let same_target = c.owner == config.owner.trim() && c.repo == config.repo.trim();
            if same_target {
                c.last_sha.clone()
            } else {
                None
            }
        }),
        history_sha: existing.as_ref().and_then(|c| {
            let same_target = c.owner == config.owner.trim() && c.repo == config.repo.trim();
            if same_target {
                c.history_sha.clone()
            } else {
                None
            }
        }),
        snippets_sha: existing.as_ref().and_then(|c| {
            let same_target = c.owner == config.owner.trim() && c.repo == config.repo.trim();
            if same_target {
                c.snippets_sha.clone()
            } else {
                None
            }
        }),
        last_synced_at: existing.as_ref().and_then(|c| c.last_synced_at),
    };

    sync::save_config(&merged, key, salt)?;
    Ok(merged.view())
}

/// Verify credentials by attempting a pull. Returns whether a remote vault exists.
#[tauri::command]
fn sync_test(state: State<'_, AppState>) -> Result<bool, String> {
    let key_guard = state.vault_key.lock().unwrap();
    let key = key_guard.as_ref().ok_or("Vault is locked")?;
    let config = sync::load_config(key).ok_or("Cloud sync is not configured")?;
    let backend = sync::backend_for(&config)?;
    Ok(backend.pull()?.is_some())
}

/// Push a sibling blob (history / snippets) to its remote path. These follow the
/// vault: best-effort and auto-resolving — a conflict means overwrite, since the
/// vault we just pushed is the source of truth. Returns the new sha, or `None`
/// when there's no local file to push.
fn push_sibling(
    config: &sync::SyncConfig,
    remote_path: String,
    local_path: &std::path::Path,
    expected: Option<String>,
    force: bool,
) -> Result<Option<String>, String> {
    if !local_path.exists() {
        return Ok(None);
    }
    let data = std::fs::read(local_path).map_err(|e| e.to_string())?;
    let backend = sync::backend_for_path(config, remote_path)?;
    let expected = if force {
        backend.pull()?.map(|b| b.sha)
    } else {
        expected
    };
    match backend.push(&data, expected.as_deref()) {
        Ok(sha) => Ok(Some(sha)),
        Err(e) if sync::is_conflict(&e) => {
            let cur = backend.pull()?.map(|b| b.sha);
            Ok(Some(backend.push(&data, cur.as_deref())?))
        }
        Err(e) => Err(e),
    }
}

/// Pull a sibling blob into `local_path` (backing up any existing copy). Returns
/// its sha if it existed remotely. Best-effort: failures are swallowed.
fn pull_sibling(
    config: &sync::SyncConfig,
    remote_path: String,
    local_path: &std::path::Path,
) -> Option<String> {
    let backend = sync::backend_for_path(config, remote_path).ok()?;
    let blob = backend.pull().ok().flatten()?;
    if local_path.exists() {
        let _ = std::fs::copy(local_path, local_path.with_extension("enc.bak"));
    }
    std::fs::write(local_path, &blob.data)
        .ok()
        .map(|_| blob.sha)
}

/// Upload the local encrypted vault. With `force`, overwrite the remote even if
/// it changed since our last sync.
#[tauri::command]
fn sync_push(state: State<'_, AppState>, force: bool) -> Result<sync::PushOutcome, String> {
    let key_guard = state.vault_key.lock().unwrap();
    let key = key_guard.as_ref().ok_or("Vault is locked")?;
    let salt_guard = state.vault_salt.lock().unwrap();
    let salt = salt_guard.as_ref().ok_or("Vault is locked")?;

    let mut config = sync::load_config(key).ok_or("Cloud sync is not configured")?;
    let backend = sync::backend_for(&config)?;

    // The on-disk vault always reflects the latest saved state.
    let data =
        std::fs::read(vault::vault_path()).map_err(|e| format!("Cannot read vault: {}", e))?;

    let expected = if force {
        backend.pull()?.map(|b| b.sha)
    } else {
        config.last_sha.clone()
    };

    let new_sha = match backend.push(&data, expected.as_deref()) {
        Ok(sha) => sha,
        Err(e) if sync::is_conflict(&e) => return Ok(sync::PushOutcome::Conflict),
        Err(e) => return Err(e),
    };
    config.last_sha = Some(new_sha.clone());

    // The history and snippet libraries follow the vault — they're encrypted with
    // the same key/salt, so they stay consistent with the vault we just pushed.
    config.history_sha = push_sibling(
        &config,
        sync::history_remote_path(&config),
        &history::history_path(),
        config.history_sha.clone(),
        force,
    )?;
    config.snippets_sha = push_sibling(
        &config,
        sync::snippets_remote_path(&config),
        &snippets::snippets_path(),
        config.snippets_sha.clone(),
        force,
    )?;

    let synced_at = sync::now_secs();
    config.last_synced_at = Some(synced_at);
    sync::save_config(&config, key, salt)?;
    Ok(sync::PushOutcome::Pushed {
        sha: new_sha,
        synced_at,
    })
}

/// Download the remote vault and replace the local one. Requires the master
/// password (the remote vault has its own salt, so the in-memory key can't
/// decrypt it). The previous local vault is kept as `vault.enc.bak`.
#[tauri::command]
fn sync_pull(state: State<'_, AppState>, password: String) -> Result<sync::PullOutcome, String> {
    // Load config with the current key before we touch the vault file.
    let config = {
        let key_guard = state.vault_key.lock().unwrap();
        let key = key_guard.as_ref().ok_or("Vault is locked")?;
        sync::load_config(key).ok_or("Cloud sync is not configured")?
    };
    let backend = sync::backend_for(&config)?;

    let blob = match backend.pull()? {
        Some(b) => b,
        None => return Ok(sync::PullOutcome::NoRemote),
    };
    if config.last_sha.as_deref() == Some(blob.sha.as_str()) {
        return Ok(sync::PullOutcome::UpToDate);
    }

    // Back up the current vault, then write the remote blob in its place.
    let path = vault::vault_path();
    if path.exists() {
        std::fs::copy(&path, path.with_extension("enc.bak"))
            .map_err(|e| format!("Backup before pull failed: {}", e))?;
    }
    std::fs::write(&path, &blob.data).map_err(|e| format!("Cannot write vault: {}", e))?;

    // Pull the sibling history + snippet blobs too (best-effort). They were
    // encrypted on the source device with the same key/salt as the vault we just
    // wrote, so once we re-derive the key below they decrypt cleanly.
    let mut config = config;
    if let Some(sha) = pull_sibling(
        &config,
        sync::history_remote_path(&config),
        &history::history_path(),
    ) {
        config.history_sha = Some(sha);
    }
    if let Some(sha) = pull_sibling(
        &config,
        sync::snippets_remote_path(&config),
        &snippets::snippets_path(),
    ) {
        config.snippets_sha = Some(sha);
    }

    // Re-derive the key from the pulled vault's own salt and load it.
    let (hosts, new_key, new_salt) = vault::load_vault(&password).inspect_err(|_| {
        // Restore the backup so a wrong password doesn't strand the user.
        let _ = std::fs::copy(path.with_extension("enc.bak"), &path);
    })?;
    let history = history::load_history(&new_key).unwrap_or_default();
    let snippet_lib = snippets::load_snippets(&new_key).unwrap_or_default();

    let synced_at = sync::now_secs();
    config.last_sha = Some(blob.sha.clone());
    config.last_synced_at = Some(synced_at);

    *state.vault_key.lock().unwrap() = Some(new_key);
    *state.vault_salt.lock().unwrap() = Some(new_salt);
    *state.hosts.lock().unwrap() = hosts.clone();
    *state.history.lock().unwrap() = history;
    *state.snippets.lock().unwrap() = snippet_lib;

    // Re-save config under the new key (the pulled vault may use a new salt).
    sync::save_config(&config, &new_key, &new_salt)?;

    Ok(sync::PullOutcome::Pulled {
        sha: blob.sha,
        synced_at,
        hosts,
    })
}

/// Bootstrap a fresh machine: pull the vault straight from the cloud without an
/// existing local vault or saved sync config. Given repo + token + the master
/// password, it downloads the vault (and history), unlocks it, and persists the
/// sync config — so the new device is fully set up in one step.
#[tauri::command]
fn sync_restore(
    state: State<'_, AppState>,
    config: sync::SyncConfigInput,
    password: String,
) -> Result<Vec<Host>, String> {
    let mut cfg = sync::SyncConfig {
        provider: "github".to_string(),
        token: config.token.trim().to_string(),
        owner: config.owner.trim().to_string(),
        repo: config.repo.trim().to_string(),
        path: {
            let p = config.path.unwrap_or_default();
            if p.trim().is_empty() {
                "vault.enc".to_string()
            } else {
                p.trim().to_string()
            }
        },
        branch: {
            let b = config.branch.unwrap_or_default();
            if b.trim().is_empty() {
                "main".to_string()
            } else {
                b.trim().to_string()
            }
        },
        last_sha: None,
        history_sha: None,
        snippets_sha: None,
        last_synced_at: None,
    };
    if cfg.token.is_empty() || cfg.owner.is_empty() || cfg.repo.is_empty() {
        return Err("Enter the repo owner, name, and a token.".to_string());
    }

    let backend = sync::backend_for(&cfg)?;
    let blob = backend
        .pull()?
        .ok_or("No vault found in that repo — push from your other device first.")?;

    let path = vault::vault_path();
    std::fs::create_dir_all(path.parent().unwrap()).map_err(|e| e.to_string())?;
    // Don't clobber an existing local vault without keeping a copy.
    if path.exists() {
        std::fs::copy(&path, path.with_extension("enc.bak"))
            .map_err(|e| format!("Backup of existing vault failed: {}", e))?;
    }
    std::fs::write(&path, &blob.data).map_err(|e| format!("Cannot write vault: {}", e))?;

    // Fetch the sibling blobs into memory; only commit them once the password checks out.
    let hist_blob = sync::backend_for_path(&cfg, sync::history_remote_path(&cfg))
        .ok()
        .and_then(|b| b.pull().ok().flatten());
    let snip_blob = sync::backend_for_path(&cfg, sync::snippets_remote_path(&cfg))
        .ok()
        .and_then(|b| b.pull().ok().flatten());

    let (hosts, key, salt) = vault::load_vault(&password).map_err(|e| {
        // Wrong password: undo the vault we just wrote.
        let bak = path.with_extension("enc.bak");
        if bak.exists() {
            let _ = std::fs::copy(&bak, &path);
        } else {
            let _ = std::fs::remove_file(&path);
        }
        format!(
            "{} (is this the master password from your other device?)",
            e
        )
    })?;

    if let Some(hb) = hist_blob {
        if std::fs::write(history::history_path(), &hb.data).is_ok() {
            cfg.history_sha = Some(hb.sha);
        }
    }
    if let Some(sb) = snip_blob {
        if std::fs::write(snippets::snippets_path(), &sb.data).is_ok() {
            cfg.snippets_sha = Some(sb.sha);
        }
    }
    let history = history::load_history(&key).unwrap_or_default();
    let snippet_lib = snippets::load_snippets(&key).unwrap_or_default();

    cfg.last_sha = Some(blob.sha);
    cfg.last_synced_at = Some(sync::now_secs());
    sync::save_config(&cfg, &key, &salt)?;

    *state.vault_key.lock().unwrap() = Some(key);
    *state.vault_salt.lock().unwrap() = Some(salt);
    *state.hosts.lock().unwrap() = hosts.clone();
    *state.history.lock().unwrap() = history;
    *state.snippets.lock().unwrap() = snippet_lib;

    Ok(hosts)
}

// ── Export / Import ───────────────────────────────────────────────────────────

#[tauri::command]
fn export_host(host: vault::Host, path: String) -> Result<(), String> {
    let json = serde_json::to_string_pretty(&host).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| e.to_string())
}

#[tauri::command]
fn export_ssh_key(content: String, path: String) -> Result<(), String> {
    std::fs::write(&path, content).map_err(|e| e.to_string())
}

#[tauri::command]
fn read_key_file(path: String) -> Result<String, String> {
    std::fs::read_to_string(&path).map_err(|e| format!("Cannot read key file: {}", e))
}

#[tauri::command]
fn save_session_log(content: String, path: String) -> Result<(), String> {
    std::fs::write(&path, content).map_err(|e| format!("Cannot write log: {}", e))
}

#[tauri::command]
fn import_host(path: String) -> Result<vault::Host, String> {
    let content = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let mut host: vault::Host =
        serde_json::from_str(&content).map_err(|e| format!("Invalid profile file: {}", e))?;
    host.id = String::new(); // will get new ID when saved
    Ok(host)
}

// ── Key generation ────────────────────────────────────────────────────────────

#[tauri::command]
fn generate_ssh_key() -> Result<keygen::SshKeyPair, String> {
    keygen::generate_ed25519()
}

// ── Host key verification ─────────────────────────────────────────────────────

/// Fetch the server's host key fingerprint and compare to the trusted store.
#[tauri::command]
async fn verify_host_key(host: vault::Host) -> Result<host_keys::HostKeyVerdict, String> {
    host_keys::verify(&host).await
}

/// Trust the fingerprint the user approved in the UI.
#[tauri::command]
fn trust_host_key(host: vault::Host, fingerprint: String) -> Result<(), String> {
    host_keys::trust(&host, fingerprint)
}

/// Forget a host's trusted key (e.g. after a legitimate server rebuild).
#[tauri::command]
fn forget_host_key(host: vault::Host) -> Result<(), String> {
    host_keys::forget(&host)
}

// ── SSH terminal commands ─────────────────────────────────────────────────────

#[tauri::command]
async fn ssh_connect(
    app_handle: tauri::AppHandle,
    state: State<'_, AppState>,
    host: Host,
) -> Result<String, String> {
    let session_id = Uuid::new_v4().to_string();
    // Resolve the host's selected snippet ids into command text, preserving order.
    let on_connect: Vec<String> = {
        let library = state.snippets.lock().unwrap();
        host.on_connect_snippets
            .iter()
            .filter_map(|id| library.iter().find(|s| &s.id == id))
            .map(|s| s.commands.clone())
            .collect()
    };
    ssh_session::connect(
        app_handle,
        state.sessions.clone(),
        session_id.clone(),
        host,
        on_connect,
    )
    .await?;
    Ok(session_id)
}

#[tauri::command]
async fn ssh_write(
    state: State<'_, AppState>,
    session_id: String,
    data: Vec<u8>,
) -> Result<(), String> {
    let tx = {
        let sessions = state.sessions.lock().unwrap();
        let session = sessions.get(&session_id).ok_or("Session not found")?;
        session.cmd_tx.clone()
    };
    tx.send(ssh_session::TermCommand::Data(data))
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn ssh_resize(
    state: State<'_, AppState>,
    session_id: String,
    cols: u32,
    rows: u32,
) -> Result<(), String> {
    let tx = {
        let sessions = state.sessions.lock().unwrap();
        let session = sessions.get(&session_id).ok_or("Session not found")?;
        session.cmd_tx.clone()
    };
    tx.send(ssh_session::TermCommand::Resize(cols, rows))
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn ssh_disconnect(state: State<'_, AppState>, session_id: String) -> Result<(), String> {
    let tx = {
        let sessions = state.sessions.lock().unwrap();
        sessions.get(&session_id).map(|s| s.cmd_tx.clone())
    };
    if let Some(tx) = tx {
        tx.send(ssh_session::TermCommand::Close).await.ok();
    }
    // Stop all port forwards belonging to this session
    let prefix = format!("{}:", session_id);
    state
        .active_forwards
        .lock()
        .unwrap()
        .retain(|k, _| !k.starts_with(&prefix));
    // Close the SFTP connection for this session, if any. Drop the lock guard
    // before awaiting so we don't hold a std Mutex across an await point.
    let sftp_handle = state.sftp_sessions.lock().unwrap().remove(&session_id);
    if let Some(handle) = sftp_handle {
        handle.tx.send(sftp_session::SftpRequest::Close).await.ok();
    }
    Ok(())
}

// ── Local Shell commands ──────────────────────────────────────────────────────

#[tauri::command]
fn local_connect(
    app_handle: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let session_id = Uuid::new_v4().to_string();
    local_session::connect(app_handle, state.local_sessions.clone(), session_id.clone())?;
    Ok(session_id)
}

#[tauri::command]
fn local_write(
    state: State<'_, AppState>,
    session_id: String,
    data: Vec<u8>,
) -> Result<(), String> {
    let sessions = state.local_sessions.lock().unwrap();
    let session = sessions.get(&session_id).ok_or("Local session not found")?;
    session
        .cmd_tx
        .send(local_session::TermCommand::Data(data))
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn local_resize(
    state: State<'_, AppState>,
    session_id: String,
    cols: u16,
    rows: u16,
) -> Result<(), String> {
    let sessions = state.local_sessions.lock().unwrap();
    let session = sessions.get(&session_id).ok_or("Local session not found")?;
    session
        .cmd_tx
        .send(local_session::TermCommand::Resize(cols, rows))
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn local_disconnect(state: State<'_, AppState>, session_id: String) -> Result<(), String> {
    let sessions = state.local_sessions.lock().unwrap();
    if let Some(session) = sessions.get(&session_id) {
        session.cmd_tx.send(local_session::TermCommand::Close).ok();
    }
    Ok(())
}

// ── SFTP commands ─────────────────────────────────────────────────────────────

/// Clone the request channel for a session's SFTP worker, releasing the map lock
/// before we block on the worker (downloads/listings can be slow).
fn sftp_tx(
    state: &State<'_, AppState>,
    session_id: &str,
) -> Result<tokio::sync::mpsc::Sender<sftp_session::SftpRequest>, String> {
    let sessions = state.sftp_sessions.lock().unwrap();
    Ok(sessions
        .get(session_id)
        .ok_or("SFTP is not open for this session")?
        .tx
        .clone())
}

/// Open (or re-open) an SFTP session for the host bound to `session_id`.
/// Returns the starting remote directory.
#[tauri::command]
async fn sftp_open(
    app_handle: tauri::AppHandle,
    state: State<'_, AppState>,
    session_id: String,
    _host: vault::Host, // Ignored, we use the active ssh_handle now
) -> Result<String, String> {
    let old_tx = {
        state
            .sftp_sessions
            .lock()
            .unwrap()
            .remove(&session_id)
            .map(|s| s.tx)
    };
    if let Some(tx) = old_tx {
        let _ = tx.send(sftp_session::SftpRequest::Close).await;
    }

    let ssh_handle = {
        let sessions = state.sessions.lock().unwrap();
        let session = sessions.get(&session_id).ok_or("SSH session is not open")?;
        Arc::clone(&session.handle)
    };

    let (handle, home) = sftp_session::open(app_handle, session_id.clone(), ssh_handle).await?;
    state
        .sftp_sessions
        .lock()
        .unwrap()
        .insert(session_id, handle);
    Ok(home)
}

#[tauri::command]
async fn sftp_list(
    state: State<'_, AppState>,
    session_id: String,
    path: String,
) -> Result<Vec<sftp_session::SftpEntry>, String> {
    let tx = sftp_tx(&state, &session_id)?;
    let (resp, rx) = tokio::sync::oneshot::channel();
    tx.send(sftp_session::SftpRequest::List { path, resp })
        .await
        .map_err(|_| "SFTP session closed")?;
    rx.await.map_err(|_| "SFTP worker did not respond")?
}

#[tauri::command]
async fn sftp_download(
    state: State<'_, AppState>,
    session_id: String,
    remote: String,
    local: String,
) -> Result<(), String> {
    let tx = sftp_tx(&state, &session_id)?;
    let (resp, rx) = tokio::sync::oneshot::channel();
    tx.send(sftp_session::SftpRequest::Download {
        remote,
        local,
        resp,
    })
    .await
    .map_err(|_| "SFTP session closed")?;
    rx.await.map_err(|_| "SFTP worker did not respond")?
}

#[tauri::command]
async fn sftp_upload(
    state: State<'_, AppState>,
    session_id: String,
    local: String,
    remote: String,
) -> Result<(), String> {
    let tx = sftp_tx(&state, &session_id)?;
    let (resp, rx) = tokio::sync::oneshot::channel();
    tx.send(sftp_session::SftpRequest::Upload {
        local,
        remote,
        resp,
    })
    .await
    .map_err(|_| "SFTP session closed")?;
    rx.await.map_err(|_| "SFTP worker did not respond")?
}

#[tauri::command]
async fn sftp_rename(
    state: State<'_, AppState>,
    session_id: String,
    from: String,
    to: String,
) -> Result<(), String> {
    let tx = sftp_tx(&state, &session_id)?;
    let (resp, rx) = tokio::sync::oneshot::channel();
    tx.send(sftp_session::SftpRequest::Rename { from, to, resp })
        .await
        .map_err(|_| "SFTP session closed")?;
    rx.await.map_err(|_| "SFTP worker did not respond")?
}

#[tauri::command]
async fn sftp_delete(
    state: State<'_, AppState>,
    session_id: String,
    path: String,
    is_dir: bool,
) -> Result<(), String> {
    let tx = sftp_tx(&state, &session_id)?;
    let (resp, rx) = tokio::sync::oneshot::channel();
    tx.send(sftp_session::SftpRequest::Delete { path, is_dir, resp })
        .await
        .map_err(|_| "SFTP session closed")?;
    rx.await.map_err(|_| "SFTP worker did not respond")?
}

#[tauri::command]
async fn sftp_mkdir(
    state: State<'_, AppState>,
    session_id: String,
    path: String,
) -> Result<(), String> {
    let tx = sftp_tx(&state, &session_id)?;
    let (resp, rx) = tokio::sync::oneshot::channel();
    tx.send(sftp_session::SftpRequest::Mkdir { path, resp })
        .await
        .map_err(|_| "SFTP session closed")?;
    rx.await.map_err(|_| "SFTP worker did not respond")?
}

#[tauri::command]
async fn sftp_chmod(
    state: State<'_, AppState>,
    session_id: String,
    path: String,
    mode: u32,
) -> Result<(), String> {
    let tx = sftp_tx(&state, &session_id)?;
    let (resp, rx) = tokio::sync::oneshot::channel();
    tx.send(sftp_session::SftpRequest::Chmod { path, mode, resp })
        .await
        .map_err(|_| "SFTP session closed")?;
    rx.await.map_err(|_| "SFTP worker did not respond")?
}

#[tauri::command]
async fn sftp_read_file(
    state: State<'_, AppState>,
    session_id: String,
    path: String,
) -> Result<String, String> {
    let tx = sftp_tx(&state, &session_id)?;
    let (resp, rx) = tokio::sync::oneshot::channel();
    tx.send(sftp_session::SftpRequest::ReadFile { path, resp })
        .await
        .map_err(|_| "SFTP session closed")?;
    rx.await.map_err(|_| "SFTP worker did not respond")?
}

#[tauri::command]
async fn sftp_write_file(
    state: State<'_, AppState>,
    session_id: String,
    path: String,
    content: String,
) -> Result<(), String> {
    let tx = sftp_tx(&state, &session_id)?;
    let (resp, rx) = tokio::sync::oneshot::channel();
    tx.send(sftp_session::SftpRequest::WriteFile {
        path,
        content,
        resp,
    })
    .await
    .map_err(|_| "SFTP session closed")?;
    rx.await.map_err(|_| "SFTP worker did not respond")?
}

#[tauri::command]
async fn sftp_close(state: State<'_, AppState>, session_id: String) -> Result<(), String> {
    let tx = state
        .sftp_sessions
        .lock()
        .unwrap()
        .remove(&session_id)
        .map(|h| h.tx);
    if let Some(tx) = tx {
        let _ = tx.send(sftp_session::SftpRequest::Close).await;
    }
    Ok(())
}

// ── Recording commands ─────────────────────────────────────────────────────────

#[tauri::command]
async fn start_recording(
    state: State<'_, AppState>,
    session_id: String,
    filename: String,
) -> Result<(), String> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_string());
    let path = std::path::PathBuf::from(home)
        .join("Videos")
        .join("Kino Recordings")
        .join(filename);

    let path_str = path.to_string_lossy().to_string();

    if let Some(session) = state.local_sessions.lock().unwrap().get(&session_id) {
        let _ = session
            .cmd_tx
            .send(local_session::TermCommand::StartRecording(path_str));
        return Ok(());
    }

    let tx = state
        .sessions
        .lock()
        .unwrap()
        .get(&session_id)
        .map(|s| s.cmd_tx.clone());
    if let Some(tx) = tx {
        let _ = tx
            .send(ssh_session::TermCommand::StartRecording(path_str))
            .await;
        return Ok(());
    }

    Err("Session not found".to_string())
}

#[tauri::command]
async fn stop_recording(state: State<'_, AppState>, session_id: String) -> Result<(), String> {
    if let Some(session) = state.local_sessions.lock().unwrap().get(&session_id) {
        let _ = session
            .cmd_tx
            .send(local_session::TermCommand::StopRecording);
        return Ok(());
    }

    let tx = state
        .sessions
        .lock()
        .unwrap()
        .get(&session_id)
        .map(|s| s.cmd_tx.clone());
    if let Some(tx) = tx {
        let _ = tx.send(ssh_session::TermCommand::StopRecording).await;
        return Ok(());
    }

    Err("Session not found".to_string())
}

use serde::Serialize;
#[derive(Serialize)]
struct RecordingInfo {
    name: String,
    size: u64,
    created: u64,
}

#[tauri::command]
async fn list_recordings() -> Result<Vec<RecordingInfo>, String> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_string());
    let dir = std::path::PathBuf::from(home)
        .join("Videos")
        .join("Kino Recordings");

    if !dir.exists() {
        return Ok(vec![]);
    }

    let mut result = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
                if meta.is_file()
                    && entry.path().extension().and_then(|e| e.to_str()) == Some("cast")
                {
                    let created = meta
                        .created()
                        .or_else(|_| meta.modified())
                        .map(|t| {
                            t.duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs()
                        })
                        .unwrap_or(0);
                    result.push(RecordingInfo {
                        name: entry.file_name().to_string_lossy().to_string(),
                        size: meta.len(),
                        created,
                    });
                }
            }
        }
    }

    result.sort_by_key(|r| std::cmp::Reverse(r.created));
    Ok(result)
}

#[tauri::command]
async fn read_recording(filename: String) -> Result<String, String> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_string());
    let path = std::path::PathBuf::from(home)
        .join("Videos")
        .join("Kino Recordings")
        .join(filename);
    std::fs::read_to_string(path).map_err(|e| format!("Failed to read recording: {}", e))
}

#[tauri::command]
async fn delete_recording(filename: String) -> Result<(), String> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_string());
    let path = std::path::PathBuf::from(home)
        .join("Videos")
        .join("Kino Recordings")
        .join(filename);
    std::fs::remove_file(path).map_err(|e| format!("Failed to delete recording: {}", e))
}

// ── Port forwarding commands ──────────────────────────────────────────────────

#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn start_forward(
    state: State<'_, AppState>,
    session_id: String,
    forward_id: String,
    _host: vault::Host,
    kind: Option<String>,
    local_port: u16,
    remote_host: String,
    remote_port: u16,
    bind_host: Option<String>,
) -> Result<(), String> {
    let key = format!("{}:{}", session_id, forward_id);
    {
        let forwards = state.active_forwards.lock().unwrap();
        if forwards.contains_key(&key) {
            return Ok(());
        }
    }

    let (ssh_handle, routes) = {
        let sessions = state.sessions.lock().unwrap();
        let session = sessions.get(&session_id).ok_or("SSH session is not open")?;
        (
            std::sync::Arc::clone(&session.handle),
            std::sync::Arc::clone(&session.remote_routes),
        )
    };

    // Field meanings per kind (see the frontend):
    //   local : listen on local_port → forward to remote_host:remote_port
    //   socks : SOCKS5 proxy on local_port
    //   remote: server listens on bind_host:remote_port → forward to
    //           remote_host:local_port on the app side
    let handle = match kind.as_deref().unwrap_or("local") {
        "local" => {
            forwarding::start_local_forward(ssh_handle, local_port, remote_host, remote_port)
                .await?
        }
        "socks" => forwarding::start_socks_forward(ssh_handle, local_port).await?,
        "remote" => {
            let bind = bind_host.unwrap_or_else(|| "127.0.0.1".to_string());
            forwarding::start_remote_forward(
                ssh_handle,
                routes,
                bind,
                remote_port,
                remote_host,
                local_port,
            )
            .await?
        }
        other => return Err(format!("Unknown forward kind: {}", other)),
    };
    state.active_forwards.lock().unwrap().insert(key, handle);
    Ok(())
}

#[tauri::command]
async fn stop_forward(
    state: State<'_, AppState>,
    session_id: String,
    forward_id: String,
) -> Result<(), String> {
    let key = format!("{}:{}", session_id, forward_id);
    let handle = state.active_forwards.lock().unwrap().remove(&key);
    if let Some(h) = handle {
        h.stop().await;
    }
    Ok(())
}

#[tauri::command]
fn list_active_forwards(state: State<'_, AppState>) -> Vec<String> {
    state
        .active_forwards
        .lock()
        .unwrap()
        .keys()
        .cloned()
        .collect()
}

// ── App entry ─────────────────────────────────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let state = AppState {
        vault_key: Arc::new(Mutex::new(None)),
        vault_salt: Arc::new(Mutex::new(None)),
        hosts: Arc::new(Mutex::new(vec![])),
        history: Arc::new(Mutex::new(vec![])),
        snippets: Arc::new(Mutex::new(vec![])),
        sessions: Arc::new(Mutex::new(HashMap::new())),
        local_sessions: Arc::new(Mutex::new(HashMap::new())),
        active_forwards: Arc::new(Mutex::new(HashMap::new())),
        sftp_sessions: Arc::new(Mutex::new(HashMap::new())),
        metrics_streams: Arc::new(Mutex::new(HashMap::new())),
        docker_log_streams: Arc::new(Mutex::new(HashMap::new())),
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            vault_exists,
            unlock_vault,
            lock_vault,
            change_master_password,
            get_hosts,
            save_host,
            delete_host,
            generate_ssh_key,
            verify_host_key,
            trust_host_key,
            forget_host_key,
            export_host,
            export_ssh_key,
            read_key_file,
            save_session_log,
            import_host,
            ssh_connect,
            ssh_write,
            ssh_resize,
            ssh_disconnect,
            local_connect,
            local_write,
            local_resize,
            local_disconnect,
            get_history,
            log_history,
            get_snippets,
            save_snippet,
            delete_snippet,
            sync_get_config,
            sync_set_config,
            sync_test,
            sync_push,
            sync_pull,
            sync_restore,
            start_forward,
            stop_forward,
            list_active_forwards,
            sftp_open,
            sftp_list,
            sftp_download,
            sftp_upload,
            sftp_rename,
            sftp_delete,
            sftp_mkdir,
            sftp_chmod,
            sftp_read_file,
            sftp_write_file,
            sftp_close,
            docker::docker_ps,
            docker::docker_images,
            docker::docker_volumes,
            docker::docker_networks,
            docker::docker_action,
            docker::docker_logs,
            docker::docker_logs_stream,
            docker::docker_logs_stream_stop,
            docker::docker_shell,
            metrics::metrics_start,
            metrics::metrics_stop,
            update::check_for_update,
            start_recording,
            stop_recording,
            list_recordings,
            read_recording,
            delete_recording,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
