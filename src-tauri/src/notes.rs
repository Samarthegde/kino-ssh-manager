//! Encrypted free-text notes: recovery codes, licence keys, API tokens - the
//! things that belong with your hosts but aren't a host.
//!
//! Stored in a sibling blob next to the vault under the same key and salt, and
//! synced the same way, exactly like `history` and `snippets`. Deliberately
//! *not* a field on `Host`: the vault is rewritten in full on every host edit,
//! and `Host` is what profile export serialises to plaintext JSON - anything
//! secret living there would leave the machine the moment someone shared a
//! host profile.

use crate::vault::{load_encrypted, save_encrypted, vault_path};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Note {
    pub id: String,
    pub title: String,
    /// Free-form body. Multi-line; no interpretation is applied.
    pub body: String,
    /// Unix seconds, set by the backend on every save so the list can be
    /// ordered by recency without trusting a clock from the UI.
    #[serde(default)]
    pub updated_at: i64,
}

pub fn notes_path() -> PathBuf {
    vault_path().parent().unwrap().join("notes.enc")
}

pub fn save_notes(notes: &[Note], key: &[u8; 32], salt: &[u8; 16]) -> Result<(), String> {
    save_encrypted(&notes_path(), notes, key, salt)
}

pub fn load_notes(key: &[u8; 32]) -> Result<Vec<Note>, String> {
    let path = notes_path();
    if !path.exists() {
        return Ok(vec![]);
    }
    load_encrypted(&path, key).or_else(|_| Ok(vec![]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::derive_key;

    #[test]
    fn notes_live_next_to_the_vault() {
        assert_eq!(notes_path().parent(), vault_path().parent());
        assert_eq!(notes_path().file_name().unwrap(), "notes.enc");
    }

    #[test]
    fn round_trips_through_encryption() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notes.enc");
        let salt = [3u8; 16];
        let key = derive_key("master", &salt).unwrap();

        let notes = vec![Note {
            id: "1".into(),
            title: "Recovery codes".into(),
            body: "aaaa-bbbb\ncccc-dddd".into(),
            updated_at: 1_700_000_000,
        }];
        save_encrypted(&path, &notes, &key, &salt).unwrap();
        let loaded: Vec<Note> = load_encrypted(&path, &key).unwrap();
        assert_eq!(loaded, notes);
    }

    #[test]
    fn the_wrong_key_cannot_read_notes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notes.enc");
        let salt = [3u8; 16];
        let key = derive_key("right", &salt).unwrap();
        let wrong = derive_key("wrong", &salt).unwrap();
        save_encrypted(&path, &Vec::<Note>::new(), &key, &salt).unwrap();
        let res: Result<Vec<Note>, String> = load_encrypted(&path, &wrong);
        assert!(res.is_err());
    }

    #[test]
    fn a_note_written_before_updated_at_existed_still_loads() {
        let json = r#"{"id":"x","title":"t","body":"b"}"#;
        let n: Note = serde_json::from_str(json).unwrap();
        assert_eq!(n.updated_at, 0);
    }
}
