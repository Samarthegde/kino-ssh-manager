//! Shell history excavation: what has been run on a host, gathered from the
//! history files of the account you connect as.
//!
//! The stored archive lives in `shell_history`, keyed by host id - not on the
//! `Host` record, which is exported to plaintext JSON when a profile is shared.

use crate::{exec, shell_history, AppState};
use tauri::State;

/// Read `~/.bash_history` and `~/.zsh_history` for the connecting user.
///
/// Notes on the pipeline, in order:
///
/// * The `sed` strips zsh's `EXTENDED_HISTORY` prefix (`: 1700000000:0;cmd`).
/// * Trimming is done with `sed` and anchored to the ends. An earlier version
///   used `awk '{$1=$1};1'`, which re-joins fields on single spaces and so
///   rewrote the commands it was meant to preserve - `grep "foo    bar"` came
///   back as `grep "foo bar"`. Copying that out gives you a command that does
///   something different from the one that ran.
/// * The second `grep -v` drops lines that became empty once trimmed.
/// * `sort -u` de-duplicates in the shell so a decade of repeated `ls` doesn't
///   cross the wire; it costs chronological order, which the stored archive
///   doesn't keep either.
/// * `head` bounds the transfer. A long-lived box can hold a six-figure history,
///   and every line here crosses IPC and becomes a row in the panel.
const HISTORY_CMD: &str = "cat ~/.bash_history ~/.zsh_history 2>/dev/null \
     | grep -a -v '^$' \
     | sed -e 's/^: [0-9]*:[0-9]*;//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' \
     | grep -a -v '^$' \
     | sort -u \
     | head -n 5000";

/// Fetch from the host, merge into the stored archive, and return the merged
/// list. The merge happens against what is on disk, never against a copy the
/// UI is holding - that is what stops a re-sync replacing an accumulated
/// archive with whatever the host's (rotated, truncated) history file has left.
#[tauri::command]
pub async fn fetch_shell_history(
    state: State<'_, AppState>,
    session_id: String,
    host_id: String,
) -> Result<Vec<String>, String> {
    if host_id.trim().is_empty() {
        return Err("Archaeology needs a saved host to file the history under".into());
    }
    let handle = exec::transport(&state, &session_id, false)?;
    let output = exec::exec(handle.as_ref(), HISTORY_CMD).await?;

    let fetched: Vec<String> = output
        .stdout
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let key_guard = state.vault_key.lock().unwrap();
    let key = key_guard.as_ref().ok_or("Vault is locked")?;
    let salt_guard = state.vault_salt.lock().unwrap();
    let salt = salt_guard.as_ref().ok_or("Vault is locked")?;

    let mut stored = state.shell_history.lock().unwrap();
    let merged = shell_history::merge(&mut stored, &host_id, fetched);
    shell_history::save(&stored, key, salt)?;
    Ok(merged)
}

/// What's already archived for a host, without contacting it.
#[tauri::command]
pub fn get_shell_history(
    state: State<'_, AppState>,
    host_id: String,
) -> Result<Vec<String>, String> {
    if state.vault_key.lock().unwrap().is_none() {
        return Err("Vault is locked".to_string());
    }
    Ok(state
        .shell_history
        .lock()
        .unwrap()
        .get(&host_id)
        .cloned()
        .unwrap_or_default())
}

/// Forget everything archived for a host.
#[tauri::command]
pub fn clear_shell_history(state: State<'_, AppState>, host_id: String) -> Result<(), String> {
    let key_guard = state.vault_key.lock().unwrap();
    let key = key_guard.as_ref().ok_or("Vault is locked")?;
    let salt_guard = state.vault_salt.lock().unwrap();
    let salt = salt_guard.as_ref().ok_or("Vault is locked")?;
    let mut stored = state.shell_history.lock().unwrap();
    stored.remove(&host_id);
    shell_history::save(&stored, key, salt)
}
