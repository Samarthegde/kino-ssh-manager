//! Shell history harvested from remote hosts, keyed by host id.
//!
//! This lived on `Host` first, which put it inside `vault.enc` - and `Host` is
//! what `export_host` serialises to *plaintext JSON*. Sharing a host profile
//! would have handed over every command ever captured from that machine, and
//! shell history is exactly where passwords typed on a command line, tokens in
//! `curl` calls and `mysql -p…` invocations end up. It lives in its own sibling
//! blob now, next to history and snippets, under the same key and salt.
//!
//! The merge happens here rather than in the UI on purpose: the authoritative
//! copy is the one on disk, and merging against a snapshot the frontend happened
//! to be holding is how an accumulated archive gets silently replaced by a
//! smaller one.

use crate::vault::{load_encrypted, save_encrypted, vault_path};
use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;

/// host id -> the commands seen on it, de-duplicated.
pub type HistoryByHost = HashMap<String, Vec<String>>;

/// Per host. Enough to be useful, bounded so a decade-old `.bash_history`
/// can't bloat the vault directory or the panel that renders it.
const MAX_PER_HOST: usize = 5000;

pub fn shell_history_path() -> PathBuf {
    vault_path().parent().unwrap().join("shell-history.enc")
}

pub fn save(map: &HistoryByHost, key: &[u8; 32], salt: &[u8; 16]) -> Result<(), String> {
    save_encrypted(&shell_history_path(), map, key, salt)
}

pub fn load(key: &[u8; 32]) -> Result<HistoryByHost, String> {
    let path = shell_history_path();
    if !path.exists() {
        return Ok(HashMap::new());
    }
    load_encrypted(&path, key).or_else(|_| Ok(HashMap::new()))
}

/// Fold freshly fetched commands into what's already stored for a host.
///
/// Returns the merged list. A `BTreeSet` both de-duplicates and gives a stable
/// order, so two runs over the same host produce the same result.
pub fn merge(stored: &mut HistoryByHost, host_id: &str, fetched: Vec<String>) -> Vec<String> {
    let entry = stored.entry(host_id.to_string()).or_default();
    let mut set: BTreeSet<String> = entry.drain(..).collect();
    set.extend(fetched.into_iter().filter(|c| !c.trim().is_empty()));

    // Keep the tail if we're over the cap: `BTreeSet` is alphabetical, so there
    // is no "oldest" to drop - truncating is arbitrary either way, and saying so
    // is better than pretending the cut is meaningful.
    let merged: Vec<String> = set.into_iter().take(MAX_PER_HOST).collect();
    *entry = merged.clone();
    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lives_beside_the_vault_not_inside_it() {
        assert_eq!(shell_history_path().parent(), vault_path().parent());
        assert_eq!(
            shell_history_path().file_name().unwrap(),
            "shell-history.enc"
        );
    }

    #[test]
    fn merging_never_loses_what_was_already_stored() {
        // The failure this replaces: a re-sync against a stale, empty snapshot
        // replaced the accumulated archive with just the current remote fetch.
        let mut stored = HistoryByHost::new();
        merge(&mut stored, "h1", vec!["ls -la".into(), "df -h".into()]);
        // The host has since rotated its history file and only has one command.
        let merged = merge(&mut stored, "h1", vec!["uptime".into()]);
        assert_eq!(merged, vec!["df -h", "ls -la", "uptime"]);
    }

    #[test]
    fn merging_de_duplicates_and_ignores_blanks() {
        let mut stored = HistoryByHost::new();
        merge(&mut stored, "h1", vec!["ls".into(), "ls".into()]);
        let merged = merge(
            &mut stored,
            "h1",
            vec!["ls".into(), "   ".into(), "".into()],
        );
        assert_eq!(merged, vec!["ls"]);
    }

    #[test]
    fn hosts_do_not_share_a_history() {
        let mut stored = HistoryByHost::new();
        merge(&mut stored, "h1", vec!["secret-on-h1".into()]);
        let other = merge(&mut stored, "h2", vec!["thing-on-h2".into()]);
        assert_eq!(other, vec!["thing-on-h2"]);
        assert_eq!(stored["h1"], vec!["secret-on-h1"]);
    }

    #[test]
    fn a_host_is_capped() {
        let mut stored = HistoryByHost::new();
        let many: Vec<String> = (0..MAX_PER_HOST + 500)
            .map(|i| format!("cmd{:06}", i))
            .collect();
        let merged = merge(&mut stored, "h1", many);
        assert_eq!(merged.len(), MAX_PER_HOST);
    }

    #[test]
    fn round_trips_through_encryption() {
        use crate::vault::derive_key;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shell-history.enc");
        let salt = [5u8; 16];
        let key = derive_key("master", &salt).unwrap();

        let mut map = HistoryByHost::new();
        map.insert("h1".into(), vec!["ls -la".into()]);
        save_encrypted(&path, &map, &key, &salt).unwrap();
        let loaded: HistoryByHost = load_encrypted(&path, &key).unwrap();
        assert_eq!(loaded["h1"], vec!["ls -la"]);
    }
}
