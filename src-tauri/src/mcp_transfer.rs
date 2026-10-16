//! Moving whole files between a host and one folder on this machine.
//!
//! `sftp_read` and `sftp_write` move *content*, which means through the
//! model's context: fine for a config file, hopeless for a 200 MB tarball,
//! and the base64-in-the-command-line trick behind the old write has a hard
//! ceiling around a couple of megabytes. These two tools move the bytes
//! instead, over real SFTP, in 64 KiB chunks, and **never hand the contents to
//! the assistant**. What comes back is a path, a size and a hash.
//!
//! That is the whole point of the design. An assistant that asks for a file
//! gets told where it was put, not what is in it, so downloading a 500 MB
//! database dump costs nothing in context and leaks nothing into a transcript
//! that gets sent to a model provider.
//!
//! **The folder is the boundary.** Transfers only work once a person has
//! named a folder in Kino - there is no default, because this is the one part
//! of MCP that touches the user's own disk rather than a host they chose to
//! expose. Without that line, an assistant allowed to write to any host could
//! upload `~/.ssh/id_ed25519` to it, and no host policy would have an opinion:
//! none of it is about a host.
//!
//! Inside that folder, a name is a name. No absolute paths, no `..`, no
//! symlink out, no subdirectories: the assistant picks what a file is called,
//! and a person picks where files go.

use crate::vault::Host;
use serde::Serialize;
use std::path::{Path, PathBuf};

/// Biggest single transfer, unless the budget says less. Large enough for a
/// database dump, small enough that a mistake is not a filled disk.
pub const DEFAULT_MAX_BYTES: u64 = 100 * 1024 * 1024;

/// What a finished transfer reports. Deliberately not the contents.
#[derive(Serialize, Debug, PartialEq)]
pub struct Transferred {
    pub bytes: u64,
    /// SHA-256 of what moved, so the other end can be checked independently.
    pub sha256: String,
    /// Where it landed, or where it came from.
    pub local_path: String,
}

/// Turn what the assistant asked for into a file inside `root`.
///
/// The failure this exists to prevent is `../../.ssh/authorized_keys`, and
/// the one after it is a symlink in the folder pointing somewhere else. Both
/// are refused by name rather than by resolving and hoping.
pub fn local_file(root: &Path, name: &str) -> Result<PathBuf, String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("Give the file a name.".into());
    }
    if name.contains('/') || name.contains('\\') {
        return Err(format!(
            "'{name}' looks like a path. Transfers use a plain file name - the folder is set in \
             Kino, not here."
        ));
    }
    if name == "." || name == ".." {
        return Err(format!("'{name}' is not a file name."));
    }
    let path = root.join(name);

    // A name that resolves outside the folder - through a symlink planted
    // earlier, say - is refused even though the name itself looked ordinary.
    if let Ok(resolved) = path.canonicalize() {
        let root_real = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        if !resolved.starts_with(&root_real) {
            return Err(format!(
                "'{name}' leads outside the transfers folder, so it was refused."
            ));
        }
    }
    Ok(path)
}

/// What to call a downloaded file: the remote basename, unless the assistant
/// asked for something else.
pub fn name_for(remote_path: &str, asked: Option<&str>) -> String {
    if let Some(name) = asked.map(str::trim).filter(|n| !n.is_empty()) {
        return name.to_string();
    }
    remote_path
        .rsplit('/')
        .find(|part| !part.is_empty())
        .unwrap_or("download")
        .to_string()
}

/// Open SFTP on a host, the way `exec_once_full` opens a shell.
async fn connect(host: &Host) -> Result<russh_sftp::client::SftpSession, String> {
    let handle = crate::ssh_session::connect_authenticated(host).await?;
    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| format!("SFTP channel open failed: {e}"))?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| format!("SFTP subsystem request failed: {e}"))?;
    russh_sftp::client::SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| format!("SFTP session init failed: {e}"))
}

/// Stream a file off the host into `dest`.
///
/// Written to a `.part` and renamed, so whatever watches that folder - the
/// user, a sync tool, an editor - never sees a half file.
pub async fn download(
    host: &Host,
    remote: &str,
    dest: &Path,
    max_bytes: u64,
) -> Result<Transferred, String> {
    let sftp = connect(host).await?;
    let size = sftp
        .metadata(remote)
        .await
        .map_err(|e| format!("Cannot read {remote} on {}: {e}", host.name))?
        .size
        .unwrap_or(0);
    if size > max_bytes {
        return Err(too_big(size, max_bytes));
    }

    let mut remote_file = sftp
        .open(remote)
        .await
        .map_err(|e| format!("Cannot open {remote} on {}: {e}", host.name))?;

    if let Some(dir) = dest.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("Could not create {}: {e}", dir.display()))?;
    }
    let part = dest.with_extension("part");
    let mut out = tokio::fs::File::create(&part)
        .await
        .map_err(|e| format!("Could not write {}: {e}", part.display()))?;

    // Every way out of the streaming below has to take the .part with it. The
    // one that matters is a full disk 8 GB into a 10 GB download: the failure
    // itself is fine, a dead half-file holding the space afterwards is not.
    let moved = stream_in(&mut remote_file, &mut out, max_bytes).await;
    drop(out);
    let (bytes, digest) = commit(&part, dest, moved)?;

    Ok(Transferred {
        bytes,
        sha256: digest,
        local_path: dest.display().to_string(),
    })
}

/// Put the finished download in place, or clear up after a failed one.
///
/// Every way out of streaming has to take the `.part` with it. The one that
/// matters is a full disk eight gigabytes into a ten gigabyte download: the
/// failure itself is fine, a dead half-file holding the space afterwards is
/// not. Separate from the streaming so that rule can be tested without a host
/// on the other end.
fn commit(
    part: &Path,
    dest: &Path,
    streamed: Result<(u64, String), String>,
) -> Result<(u64, String), String> {
    let done = match streamed {
        Ok(done) => done,
        Err(e) => {
            let _ = std::fs::remove_file(part);
            return Err(e);
        }
    };
    std::fs::rename(part, dest).map_err(|e| {
        let _ = std::fs::remove_file(part);
        format!("Could not finish {}: {e}", dest.display())
    })?;
    Ok(done)
}

/// Read the remote file into the local one, hashing as it goes.
///
/// Separate from its caller so every failure in here lands in one place, and
/// the caller can do the one thing that must happen on all of them: remove
/// the partial file.
async fn stream_in(
    remote_file: &mut russh_sftp::client::fs::File,
    out: &mut tokio::fs::File,
    max_bytes: u64,
) -> Result<(u64, String), String> {
    use sha2::{Digest, Sha256};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 65536];
    let mut bytes: u64 = 0;
    loop {
        let n = remote_file
            .read(&mut buf)
            .await
            .map_err(|e| format!("Transfer failed: {e}"))?;
        if n == 0 {
            break;
        }
        bytes += n as u64;
        // Checked while streaming, not only up front: a file being appended
        // to can outgrow what its metadata promised.
        if bytes > max_bytes {
            return Err(too_big(bytes, max_bytes));
        }
        hasher.update(&buf[..n]);
        out.write_all(&buf[..n])
            .await
            .map_err(|e| format!("Could not write the download: {e}"))?;
    }
    out.flush().await.map_err(|e| e.to_string())?;
    Ok((bytes, format!("{:x}", hasher.finalize())))
}

/// Stream a file from the folder onto the host.
pub async fn upload(
    host: &Host,
    source: &Path,
    remote: &str,
    max_bytes: u64,
) -> Result<Transferred, String> {
    use russh_sftp::protocol::OpenFlags;
    use sha2::{Digest, Sha256};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let meta = std::fs::metadata(source)
        .map_err(|_| format!("{} is not in the transfers folder.", display_name(source)))?;
    if meta.len() > max_bytes {
        return Err(too_big(meta.len(), max_bytes));
    }

    let sftp = connect(host).await?;
    let mut local = tokio::fs::File::open(source)
        .await
        .map_err(|e| format!("Could not read {}: {e}", display_name(source)))?;
    let mut remote_file = sftp
        .open_with_flags(
            remote,
            OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE,
        )
        .await
        .map_err(|e| format!("Cannot write {remote} on {}: {e}", host.name))?;

    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 65536];
    let mut bytes: u64 = 0;
    loop {
        let n = local
            .read(&mut buf)
            .await
            .map_err(|e| format!("Could not read {}: {e}", display_name(source)))?;
        if n == 0 {
            break;
        }
        bytes += n as u64;
        hasher.update(&buf[..n]);
        remote_file
            .write_all(&buf[..n])
            .await
            .map_err(|e| format!("Transfer failed: {e}"))?;
    }
    remote_file
        .flush()
        .await
        .map_err(|e| format!("Transfer failed: {e}"))?;

    Ok(Transferred {
        bytes,
        sha256: format!("{:x}", hasher.finalize()),
        local_path: source.display().to_string(),
    })
}

fn too_big(size: u64, max: u64) -> String {
    format!(
        "That file is {} and the limit for one transfer is {}. Raise it in Kino - Settings - \
         MCP Server, or move it in pieces. Nothing was transferred.",
        human(size),
        human(max)
    )
}

fn display_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

/// Sizes a person reads, not bytes they count.
pub fn human(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{size:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_name_lands_in_the_folder() {
        let dir = tempfile::tempdir().unwrap();
        let path = local_file(dir.path(), "dump.sql").unwrap();
        assert_eq!(path, dir.path().join("dump.sql"));
    }

    #[test]
    fn a_path_is_refused_because_the_folder_is_not_the_assistants_to_choose() {
        let dir = tempfile::tempdir().unwrap();
        for attempt in [
            "../escape.txt",
            "/etc/passwd",
            "sub/dir/file",
            "..\\windows",
            "~/.ssh/authorized_keys",
        ] {
            let err = local_file(dir.path(), attempt).unwrap_err();
            assert!(
                err.contains("path") || err.contains("file name"),
                "{attempt}: {err}"
            );
        }
    }

    #[test]
    fn dots_are_not_a_file_name() {
        let dir = tempfile::tempdir().unwrap();
        assert!(local_file(dir.path(), ".").is_err());
        assert!(local_file(dir.path(), "..").is_err());
        assert!(local_file(dir.path(), "   ").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_out_of_the_folder_is_refused() {
        // The name looks ordinary; where it leads does not. Checking the
        // string alone would miss this.
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("secret");
        std::fs::write(&target, b"x").unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join("innocent.txt")).unwrap();

        let err = local_file(dir.path(), "innocent.txt").unwrap_err();
        assert!(err.contains("outside"), "{err}");
    }

    #[test]
    fn a_hidden_file_is_still_just_a_file() {
        let dir = tempfile::tempdir().unwrap();
        assert!(local_file(dir.path(), ".env").is_ok());
    }

    #[test]
    fn a_downloaded_file_is_named_after_the_remote_one() {
        assert_eq!(name_for("/var/log/app.log", None), "app.log");
        assert_eq!(name_for("/var/log/", None), "log");
        assert_eq!(name_for("app.log", None), "app.log");
        assert_eq!(
            name_for("/var/log/app.log", Some("yesterday.log")),
            "yesterday.log"
        );
        assert_eq!(
            name_for("/var/log/app.log", Some("  ")),
            "app.log",
            "a blank name is no name"
        );
    }

    #[test]
    fn a_failed_download_leaves_nothing_behind() {
        // Disk full, eight gigabytes into ten. The failure is fine; a dead
        // half-file holding the space afterwards is not.
        let dir = tempfile::tempdir().unwrap();
        let part = dir.path().join("big.iso.part");
        let dest = dir.path().join("big.iso");
        std::fs::write(&part, b"half of it").unwrap();

        let err = commit(&part, &dest, Err("No space left on device".into())).unwrap_err();
        assert!(err.contains("No space left"));
        assert!(!part.exists(), "the .part is gone");
        assert!(!dest.exists(), "and nothing was put in its place");
    }

    #[test]
    fn a_finished_download_is_renamed_into_place() {
        let dir = tempfile::tempdir().unwrap();
        let part = dir.path().join("big.iso.part");
        let dest = dir.path().join("big.iso");
        std::fs::write(&part, b"all of it").unwrap();

        let (bytes, hash) = commit(&part, &dest, Ok((9, "abc".into()))).unwrap();
        assert_eq!((bytes, hash.as_str()), (9, "abc"));
        assert!(!part.exists(), "nothing watching the folder sees a .part");
        assert_eq!(std::fs::read(&dest).unwrap(), b"all of it");
    }

    #[test]
    fn a_rename_that_fails_does_not_leave_the_part_either() {
        // dest is a directory, so the rename cannot succeed.
        let dir = tempfile::tempdir().unwrap();
        let part = dir.path().join("big.iso.part");
        let dest = dir.path().join("big.iso");
        std::fs::write(&part, b"x").unwrap();
        std::fs::create_dir(&dest).unwrap();

        assert!(commit(&part, &dest, Ok((1, "abc".into()))).is_err());
        assert!(!part.exists());
    }

    #[test]
    fn sizes_are_written_for_people() {
        assert_eq!(human(512), "512 B");
        assert_eq!(human(2048), "2.0 KB");
        assert_eq!(human(5 * 1024 * 1024), "5.0 MB");
        assert_eq!(human(DEFAULT_MAX_BYTES), "100.0 MB");
    }

    #[test]
    fn the_refusal_says_both_sizes_and_that_nothing_moved() {
        let message = too_big(200 * 1024 * 1024, DEFAULT_MAX_BYTES);
        assert!(message.contains("200.0 MB"), "{message}");
        assert!(message.contains("100.0 MB"), "{message}");
        assert!(message.contains("Nothing was transferred"), "{message}");
    }
}
