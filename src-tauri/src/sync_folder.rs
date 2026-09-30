//! Syncing through a folder something else already syncs.
//!
//! The vault is an encrypted blob, so anything that can hold a file can hold
//! it. That includes the folder Dropbox, Syncthing, iCloud Drive, OneDrive or
//! a mounted NAS share is already watching - and using one of those means no
//! OAuth client to register, no token to ship in the binary, no API that can
//! change under us, and no third party who needs to be trusted beyond the one
//! the user already chose.
//!
//! It also covers the services we will never write a backend for. Someone
//! syncing with a tool nobody here has heard of is served by this.
//!
//! **The version token is the file's own hash.** GitHub hands us a blob sha
//! and refuses a stale one; a folder hands us nothing, so we hash what is
//! there and refuse to write if it is not what we last saw. That catches the
//! case this is really for - two machines, one folder, edits made days apart -
//! and does not catch two machines writing in the same second. The file-sync
//! tool underneath usually notices that and keeps both copies; what we must
//! not do is claim more than that.
//!
//! **Writes go to a temp file and are renamed.** A sync daemon watching the
//! directory will otherwise happily upload a half-written vault, and a crash
//! mid-write would leave one.

use crate::sync::{RemoteBlob, SyncBackend, CONFLICT};
use std::path::{Path, PathBuf};

pub struct FolderBackend {
    /// The directory the user picked - the one their sync tool watches.
    dir: PathBuf,
    /// File within it, e.g. `vault.enc`. Sibling blobs use the same folder.
    name: String,
}

impl FolderBackend {
    pub fn new(dir: impl Into<PathBuf>, name: String) -> Self {
        FolderBackend {
            dir: dir.into(),
            name,
        }
    }

    fn file(&self) -> PathBuf {
        self.dir.join(&self.name)
    }
}

/// The version token: a hash of the bytes as they are on disk.
pub fn version_of(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(data))
}

/// What is there now, if anything.
fn current(path: &Path) -> Result<Option<Vec<u8>>, String> {
    match std::fs::read(path) {
        Ok(data) => Ok(Some(data)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("Could not read {}: {e}", path.display())),
    }
}

impl SyncBackend for FolderBackend {
    fn pull(&self) -> Result<Option<RemoteBlob>, String> {
        Ok(current(&self.file())?.map(|data| RemoteBlob {
            sha: version_of(&data),
            data,
        }))
    }

    fn push(&self, data: &[u8], expected_sha: Option<&str>) -> Result<String, String> {
        let path = self.file();
        let existing = current(&path)?;

        // Same rule as the GitHub backend: writing over something we have not
        // seen is a conflict, not an overwrite. The difference is only that
        // there the server enforces it and here we do.
        match (&existing, expected_sha) {
            (Some(bytes), Some(expected)) if version_of(bytes) != expected => {
                return Err(CONFLICT.to_string())
            }
            (Some(_), None) => return Err(CONFLICT.to_string()),
            _ => {}
        }

        std::fs::create_dir_all(&self.dir)
            .map_err(|e| format!("Could not create {}: {e}", self.dir.display()))?;

        // Written beside the target and renamed over it: a sync daemon
        // watching this directory would otherwise upload a half-written
        // vault, and there is no version of that which ends well.
        let tmp = self
            .dir
            .join(format!(".{}.{}.tmp", self.name, std::process::id()));
        std::fs::write(&tmp, data)
            .map_err(|e| format!("Could not write {}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, &path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            format!("Could not replace {}: {e}", path.display())
        })?;

        Ok(version_of(data))
    }
}

/// Check a folder is usable before it is saved, so the failure arrives while
/// the user is looking at the setting rather than at their next sync.
pub fn check(dir: &str) -> Result<(), String> {
    let path = PathBuf::from(dir);
    if dir.trim().is_empty() {
        return Err("Pick a folder to sync through.".into());
    }
    if !path.exists() {
        return Err(format!("{dir} does not exist."));
    }
    if !path.is_dir() {
        return Err(format!("{dir} is a file, not a folder."));
    }
    let probe = path.join(".kino-write-test");
    std::fs::write(&probe, b"")
        .map_err(|_| format!("{dir} cannot be written to. Check the folder's permissions."))?;
    let _ = std::fs::remove_file(&probe);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backend(dir: &Path) -> FolderBackend {
        FolderBackend::new(dir, "vault.enc".to_string())
    }

    #[test]
    fn an_empty_folder_has_nothing_to_pull() {
        let dir = tempfile::tempdir().unwrap();
        assert!(backend(dir.path()).pull().unwrap().is_none());
    }

    #[test]
    fn what_is_pushed_comes_back() {
        let dir = tempfile::tempdir().unwrap();
        let b = backend(dir.path());
        let version = b.push(b"ciphertext", None).unwrap();

        let got = b.pull().unwrap().unwrap();
        assert_eq!(got.data, b"ciphertext");
        assert_eq!(got.sha, version, "the version is the file's own hash");
    }

    #[test]
    fn pushing_over_something_we_have_not_seen_is_a_conflict() {
        // The other machine wrote while we were away. Overwriting here is
        // how someone loses a host they added last week.
        let dir = tempfile::tempdir().unwrap();
        let b = backend(dir.path());
        b.push(b"theirs", None).unwrap();
        assert_eq!(b.push(b"ours", None).unwrap_err(), CONFLICT);
    }

    #[test]
    fn pushing_with_a_stale_version_is_a_conflict() {
        let dir = tempfile::tempdir().unwrap();
        let b = backend(dir.path());
        let first = b.push(b"one", None).unwrap();
        b.push(b"two", Some(&first)).unwrap();
        assert_eq!(
            b.push(b"three", Some(&first)).unwrap_err(),
            CONFLICT,
            "the version we last saw is two writes old"
        );
    }

    #[test]
    fn pushing_with_the_current_version_works() {
        let dir = tempfile::tempdir().unwrap();
        let b = backend(dir.path());
        let v1 = b.push(b"one", None).unwrap();
        let v2 = b.push(b"two", Some(&v1)).unwrap();
        assert_eq!(b.pull().unwrap().unwrap().data, b"two");
        assert_ne!(v1, v2);
    }

    #[test]
    fn the_same_bytes_have_the_same_version() {
        // Which means a push that changes nothing does not look like a
        // conflict to the other machine.
        let dir = tempfile::tempdir().unwrap();
        let b = backend(dir.path());
        let v1 = b.push(b"same", None).unwrap();
        let v2 = b.push(b"same", Some(&v1)).unwrap();
        assert_eq!(v1, v2);
    }

    #[test]
    fn nothing_half_written_is_left_behind() {
        // A sync daemon watching this folder must never find a partial vault,
        // so the write lands under a temp name and is renamed into place.
        let dir = tempfile::tempdir().unwrap();
        let b = backend(dir.path());
        b.push(b"ciphertext", None).unwrap();

        let leftovers: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n != "vault.enc")
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[test]
    fn siblings_live_beside_the_vault() {
        let dir = tempfile::tempdir().unwrap();
        backend(dir.path()).push(b"vault", None).unwrap();
        FolderBackend::new(dir.path(), "history.enc".to_string())
            .push(b"history", None)
            .unwrap();
        assert!(dir.path().join("vault.enc").is_file());
        assert!(dir.path().join("history.enc").is_file());
    }

    #[test]
    fn a_folder_that_does_not_exist_is_created_on_first_push() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("Kino");
        FolderBackend::new(&nested, "vault.enc".to_string())
            .push(b"x", None)
            .unwrap();
        assert!(nested.join("vault.enc").is_file());
    }

    #[test]
    fn checking_a_folder_catches_the_obvious_mistakes() {
        let dir = tempfile::tempdir().unwrap();
        assert!(check(&dir.path().to_string_lossy()).is_ok());
        assert!(check("").unwrap_err().contains("Pick a folder"));
        assert!(check("/definitely/not/here")
            .unwrap_err()
            .contains("does not exist"));

        let file = dir.path().join("a-file");
        std::fs::write(&file, b"x").unwrap();
        assert!(check(&file.to_string_lossy())
            .unwrap_err()
            .contains("not a folder"));
    }

    #[test]
    fn checking_leaves_nothing_behind() {
        let dir = tempfile::tempdir().unwrap();
        check(&dir.path().to_string_lossy()).unwrap();
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn a_read_only_folder_is_refused_while_the_user_is_looking_at_it() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let locked = dir.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o500)).unwrap();

        let result = check(&locked.to_string_lossy());

        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
        // Root ignores the permission bits, so only assert where it bites.
        let am_root = std::process::Command::new("id")
            .arg("-u")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
            .unwrap_or(false);
        if !am_root {
            assert!(result.unwrap_err().contains("permissions"));
        }
    }
}
