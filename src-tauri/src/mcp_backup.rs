//! Keeping the old version of a file an assistant is about to replace
//! (KR-11-F14).
//!
//! A rollout that stops tells you exactly which hosts it changed. That is
//! only useful if there is something to change them back to, and the moment
//! to take a copy is the moment before the write - not afterwards, and not
//! in a snapshot somebody remembered to schedule.
//!
//! **Where.** `~/.kino/backups/<hash of path>/<timestamp>.<mode>`, in the SSH
//! user's own home. **Not `/tmp`**: it is world-readable, it is cleared on
//! reboot, and a fixed name keeps exactly one version - so the second write
//! would destroy the copy taken before the first.
//!
//! The directory is `0700` and each copy `0600`, because a config file's
//! previous version is as sensitive as the file, and quite often that is a
//! password somebody has since rotated.
//!
//! **A file that did not exist gets a marker** rather than no backup at all.
//! "Restore" then means "delete it", which is the correct undo for a file the
//! assistant created, and the only way to tell that from "no backup taken".
//!
//! Five versions per path. Enough to walk back through a bad afternoon,
//! bounded enough that a chatty assistant cannot fill a disk with copies of
//! the file it keeps rewriting.
//!
//! Everything here builds shell, so everything here quotes. The path comes
//! from the assistant, which is reason enough; the timestamp and the mode are
//! ours and are still quoted, because a script that quotes only what it
//! currently distrusts stops being safe the moment somebody adds a field.

use crate::exec::shell_quote;

/// Versions kept per path. The sixth write drops the oldest.
pub const KEEP: usize = 5;

/// Where a path's copies live on the host: a hash, so a directory name can
/// never be mistaken for a path and nothing has to be escaped twice.
pub fn backup_dir(path: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("$HOME/.kino/backups/{:x}", Sha256::digest(path.as_bytes()))
}

/// The same, as a shell word: double-quoted, so `$HOME` expands and a home
/// directory with a space in it still works. Single quotes would stop the
/// expansion; a bare word would break on the space.
fn dir_word(path: &str) -> String {
    format!("\"{}\"", backup_dir(path))
}

/// Take a copy, then write the new contents - in one script, so the copy
/// cannot be skipped by a connection that drops between two calls.
///
/// `content_b64` is base64 for the same reason `sftp_write` uses it: content
/// containing the heredoc marker would otherwise end the quoting and become
/// shell.
pub fn backup_then_write(path: &str, content_b64: &str, stamp: u64) -> String {
    let dir = dir_word(path);
    let q = shell_quote(path);
    format!(
        r#"set -e
dir={dir}
mkdir -p "$dir" && chmod 700 "$dir"
if [ -e {q} ]; then
  mode=$(stat -c '%a' {q} 2>/dev/null || stat -f '%Lp' {q} 2>/dev/null || echo 644)
  cp -p {q} "$dir/{stamp}.$mode"
  chmod 600 "$dir/{stamp}.$mode"
else
  : > "$dir/{stamp}.absent"
  chmod 600 "$dir/{stamp}.absent"
fi
ls -1 "$dir" | sort -r | tail -n +{keep_plus_one} | while read -r old; do rm -f "$dir/$old"; done
printf '%s' {content} | base64 -d > {q}"#,
        dir = dir,
        q = q,
        stamp = stamp,
        keep_plus_one = KEEP + 1,
        content = shell_quote(content_b64),
    )
}

/// Take the copy without writing anything new.
///
/// An upload streams its own bytes over SFTP, so it cannot carry the write
/// inside this script the way `backup_then_write` does. The copy still has to
/// happen first, and a failure here has to stop the upload - which is why it
/// is a separate call rather than a best-effort afterthought.
pub fn backup_only(path: &str, stamp: u64) -> String {
    let dir = dir_word(path);
    let q = shell_quote(path);
    format!(
        r#"set -e
dir={dir}
mkdir -p "$dir" && chmod 700 "$dir"
if [ -e {q} ]; then
  mode=$(stat -c '%a' {q} 2>/dev/null || stat -f '%Lp' {q} 2>/dev/null || echo 644)
  cp -p {q} "$dir/{stamp}.$mode"
  chmod 600 "$dir/{stamp}.$mode"
else
  : > "$dir/{stamp}.absent"
  chmod 600 "$dir/{stamp}.absent"
fi
ls -1 "$dir" | sort -r | tail -n +{keep_plus_one} | while read -r old; do rm -f "$dir/$old"; done"#,
        dir = dir,
        q = q,
        stamp = stamp,
        keep_plus_one = KEEP + 1,
    )
}

/// Put a version back. `None` means the most recent one.
///
/// Restoring a marker deletes the file: that is what undoing "this file did
/// not exist" means, and it is why the marker is written at all.
pub fn restore(path: &str, version: Option<&str>) -> String {
    let dir = dir_word(path);
    let q = shell_quote(path);
    let pick = match version {
        Some(v) => format!("want={}", shell_quote(v)),
        None => r#"want=$(ls -1 "$dir" | sort -r | head -n 1)"#.to_string(),
    };
    format!(
        r#"set -e
dir={dir}
if [ ! -d "$dir" ]; then echo "no backups for this path" >&2; exit 3; fi
{pick}
if [ -z "$want" ] || [ ! -e "$dir/$want" ]; then echo "no such version" >&2; exit 4; fi
case "$want" in
  *.absent)
    rm -f {q}
    printf 'deleted %s (it did not exist when the backup was taken)\n' {q}
    ;;
  *)
    mode=${{want##*.}}
    cp -p "$dir/$want" {q}
    chmod "$mode" {q}
    printf 'restored %s from %s\n' {q} "$want"
    ;;
esac"#,
        dir = dir,
        pick = pick,
        q = q,
    )
}

/// List what is kept for a path, newest first.
pub fn list(path: &str) -> String {
    format!(r#"ls -1 {dir} 2>/dev/null | sort -r"#, dir = dir_word(path))
}

/// One kept version, as the tools describe it.
#[derive(serde::Serialize, Debug, PartialEq)]
pub struct Version {
    /// The filename, which is what `restore_file` takes back.
    pub version: String,
    /// Unix seconds, from the name.
    pub taken_at: u64,
    /// True when this records that the file did not exist.
    pub absent: bool,
}

/// Read `ls` output into versions, newest first, ignoring anything that does
/// not look like ours - a directory somebody else put there is not a version.
pub fn parse_versions(listing: &str) -> Vec<Version> {
    let mut out: Vec<Version> = listing
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .filter_map(|name| {
            let (stamp, suffix) = name.split_once('.')?;
            let taken_at = stamp.parse::<u64>().ok()?;
            let absent = suffix == "absent";
            // Anything else has to be a mode, or it is not one of ours.
            if !absent && (suffix.is_empty() || !suffix.chars().all(|c| c.is_ascii_digit())) {
                return None;
            }
            Some(Version {
                version: name.to_string(),
                taken_at,
                absent,
            })
        })
        .collect();
    out.sort_by_key(|v| std::cmp::Reverse(v.taken_at));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const STAMP: u64 = 1_700_000_000;

    #[test]
    fn backups_live_under_the_users_own_home_and_not_in_tmp() {
        let script = backup_then_write("/etc/nginx/nginx.conf", "Zm9v", STAMP);
        assert!(script.contains("$HOME/.kino/backups/"), "{script}");
        assert!(!script.contains("/tmp"), "{script}");
    }

    #[test]
    fn the_copy_is_taken_before_the_write() {
        let script = backup_then_write("/etc/hosts", "Zm9v", STAMP);
        let copy = script.find("cp -p").unwrap();
        let write = script.find("base64 -d >").unwrap();
        assert!(copy < write, "the backup must happen first:\n{script}");
    }

    #[test]
    fn the_whole_thing_stops_if_the_backup_fails() {
        // Without `set -e` a failed cp would be followed cheerfully by the
        // write, which is the one outcome worth preventing.
        let script = backup_then_write("/etc/hosts", "Zm9v", STAMP);
        assert!(script.starts_with("set -e"), "{script}");
    }

    #[test]
    fn a_file_that_does_not_exist_yet_leaves_a_marker() {
        let script = backup_then_write("/etc/new.conf", "Zm9v", STAMP);
        assert!(script.contains(&format!("{STAMP}.absent")), "{script}");
    }

    #[test]
    fn the_copies_are_not_readable_by_anyone_else() {
        // The previous version of a config is as sensitive as the config, and
        // is often a password that has since been rotated.
        let script = backup_then_write("/etc/app.conf", "Zm9v", STAMP);
        assert!(script.contains("chmod 700"), "the directory: {script}");
        assert!(script.contains("chmod 600"), "and the copies: {script}");
    }

    #[test]
    fn only_five_versions_are_kept() {
        let script = backup_then_write("/etc/app.conf", "Zm9v", STAMP);
        assert!(script.contains("tail -n +6"), "{script}");
    }

    /// Run a generated script for real, with `$HOME` pointed at a temp
    /// directory, and say what it printed.
    ///
    /// Grepping a script for dangerous-looking text proves nothing: correctly
    /// quoted text contains the dangerous text, which is the whole point of
    /// quoting. Running it does prove something.
    #[cfg(unix)]
    fn run(script: &str, home: &std::path::Path) -> std::process::Output {
        std::process::Command::new("sh")
            .arg("-c")
            .arg(script)
            .env("HOME", home)
            // So an injected `touch pwned` would land somewhere this test can
            // see, rather than in the source tree.
            .current_dir(home)
            .output()
            .expect("sh")
    }

    #[cfg(unix)]
    #[test]
    fn a_path_cannot_escape_into_the_script() {
        // The path comes from the assistant. If the quoting were wrong, this
        // one would run `touch $HOME/pwned` on the host.
        let home = tempfile::tempdir().unwrap();
        let nasty = format!("{}/x'; touch pwned; echo '", home.path().display());

        let out = run(&backup_then_write(&nasty, "aGVsbG8=", STAMP), home.path());
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            !home.path().join("pwned").exists(),
            "the injected command ran"
        );
        // And the file it was actually asked to write does exist, under the
        // silly name it was given.
        assert_eq!(std::fs::read_to_string(&nasty).unwrap(), "hello");
    }

    #[cfg(unix)]
    #[test]
    fn the_content_is_quoted_too() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("app.conf");
        let content = "aGk=' ; touch pwned ; '";

        let out = run(
            &backup_then_write(&path.display().to_string(), content, STAMP),
            home.path(),
        );
        assert!(!home.path().join("pwned").exists(), "the injection ran");
        // base64 refuses the nonsense, and `set -e` means the write does not
        // silently produce an empty file.
        assert!(
            !out.status.success() || !path.exists() || std::fs::read(&path).unwrap().is_empty()
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_version_name_is_quoted_like_everything_else() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("app.conf");
        std::fs::write(&path, "original").unwrap();
        run(
            &backup_then_write(&path.display().to_string(), "bmV3", STAMP),
            home.path(),
        );

        let version = "x'; touch pwned; echo '".to_string();
        run(
            &restore(&path.display().to_string(), Some(&version)),
            home.path(),
        );
        assert!(!home.path().join("pwned").exists(), "the injection ran");
    }

    #[cfg(unix)]
    #[test]
    fn a_write_and_its_undo_round_trip() {
        // The whole point of F14, end to end: the old contents come back, and
        // so does the mode.
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("app.conf");
        std::fs::write(&path, "original\n").unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        }

        let p = path.display().to_string();
        let out = run(&backup_then_write(&p, "cmVwbGFjZWQK", STAMP), home.path());
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "replaced\n");

        let out = run(&restore(&p, None), home.path());
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "original\n");
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640, "the mode came back too");
    }

    #[cfg(unix)]
    #[test]
    fn a_copy_can_be_taken_without_writing_anything() {
        // What an upload needs: the bytes arrive over SFTP, so the backup
        // cannot ride along inside the write script.
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("app.conf");
        std::fs::write(&path, b"original\n").unwrap();

        let out = run(
            &backup_only(&path.display().to_string(), STAMP),
            home.path(),
        );
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "original\n",
            "the file itself is untouched"
        );

        // And it is the copy restore_file would use.
        let out = run(&restore(&path.display().to_string(), None), home.path());
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "original\n");
    }

    #[cfg(unix)]
    #[test]
    fn undoing_a_file_the_assistant_created_removes_it() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("new.conf");
        let p = path.display().to_string();

        run(&backup_then_write(&p, "bmV3", STAMP), home.path());
        assert!(path.exists(), "it was created");

        let out = run(&restore(&p, None), home.path());
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!path.exists(), "undoing a creation means deleting it");
    }

    #[cfg(unix)]
    #[test]
    fn only_the_last_five_versions_survive() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("app.conf");
        let p = path.display().to_string();
        for i in 0..8 {
            run(&backup_then_write(&p, "eA==", STAMP + i), home.path());
        }
        let listing = run(&list(&p), home.path());
        let versions = parse_versions(&String::from_utf8_lossy(&listing.stdout));
        assert_eq!(versions.len(), KEEP, "{versions:?}");
        assert_eq!(
            versions[0].taken_at,
            STAMP + 7,
            "and it is the newest five that are kept"
        );
    }

    #[test]
    fn two_paths_never_share_a_backup_directory() {
        assert_ne!(backup_dir("/etc/a.conf"), backup_dir("/etc/b.conf"));
        assert_eq!(
            backup_dir("/etc/a.conf"),
            backup_dir("/etc/a.conf"),
            "and the same path always gets the same one"
        );
    }

    #[test]
    fn restoring_a_marker_deletes_the_file() {
        let script = restore("/etc/new.conf", Some("1700000000.absent"));
        assert!(script.contains("*.absent)"), "{script}");
        assert!(script.contains("rm -f"), "{script}");
    }

    #[test]
    fn restoring_puts_the_mode_back_too() {
        let script = restore("/etc/app.conf", None);
        assert!(script.contains("chmod \"$mode\""), "{script}");
        assert!(script.contains("mode=${want##*.}"), "{script}");
    }

    #[test]
    fn restoring_with_no_version_takes_the_newest() {
        let script = restore("/etc/app.conf", None);
        assert!(script.contains("sort -r"), "{script}");
        assert!(script.contains("head -n 1"), "{script}");
    }

    #[test]
    fn restoring_something_that_was_never_backed_up_fails_rather_than_guessing() {
        let script = restore("/etc/app.conf", Some("nope"));
        assert!(script.contains("no such version"), "{script}");
        assert!(script.contains("exit 4"), "{script}");
    }

    #[test]
    fn versions_are_read_newest_first() {
        let listing = "1700000000.644\n1700000500.600\n1700000200.absent\n";
        let versions = parse_versions(listing);
        assert_eq!(
            versions.iter().map(|v| v.taken_at).collect::<Vec<_>>(),
            [1_700_000_500, 1_700_000_200, 1_700_000_000]
        );
        assert!(versions[1].absent, "the marker is flagged, not hidden");
    }

    #[test]
    fn anything_that_is_not_ours_is_ignored() {
        let versions = parse_versions("README\n1700000000.644\nnotes.txt\n.\n..\n");
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version, "1700000000.644");
    }

    #[test]
    fn an_empty_listing_is_no_versions_rather_than_an_error() {
        assert!(parse_versions("").is_empty());
        assert!(parse_versions("\n\n").is_empty());
    }
}
