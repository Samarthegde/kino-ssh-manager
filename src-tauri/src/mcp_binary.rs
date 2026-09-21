//! Where `kino-mcp` lives, and whether the one an assistant runs is ours.
//!
//! Tauri bundles every binary in the crate, so each installer carries
//! `kino-mcp` next to the app's own executable: `/usr/bin` for a .deb or .rpm,
//! the install directory on Windows. Both paths are stable, so an assistant's
//! config can name them directly and nothing has to be downloaded, renamed or
//! moved.
//!
//! The exception is an AppImage. It runs from a fresh `/tmp/.mount_XXXX` on
//! every launch, so a path copied out of it is dead by the next restart. There
//! the app installs a copy to a fixed place instead, and keeps that copy in
//! step with the AppImage it came from.
//!
//! The check is local. The copy inside the install arrived with the signed
//! installer (or the signed update), which makes it the reference - there is
//! nothing a release's checksum list could add, and no network to wait on.

use serde::Serialize;
use std::path::{Path, PathBuf};

const EXE: &str = if cfg!(windows) {
    "kino-mcp.exe"
} else {
    "kino-mcp"
};

/// What the MCP panel shows about the binary.
#[derive(Serialize, Default, Debug)]
pub struct McpBinaryStatus {
    /// The copy this install carries. `None` in a development build that has
    /// not compiled `kino-mcp`.
    pub bundled: Option<String>,
    /// The path to put in an assistant's config. `None` until there is one
    /// that will survive a restart - an AppImage before its copy is installed.
    pub command: Option<String>,
    /// Running from an AppImage, whose own copy moves every launch.
    pub needs_install: bool,
    /// Where an installed copy goes.
    pub install_path: String,
    /// An installed copy exists but is not the one this version carries.
    pub install_stale: bool,
    /// What a bare `kino-mcp` resolves to, which is what an older config that
    /// names no path will run.
    pub on_path: Option<String>,
    /// `Some(false)` when that is a different file from the bundled one.
    pub on_path_matches: Option<bool>,
}

/// The facts the status is worked out from, gathered once so tests can
/// supply their own.
struct Env {
    exe_dir: Option<PathBuf>,
    appimage: bool,
    install_path: PathBuf,
    path_var: Option<std::ffi::OsString>,
}

impl Env {
    fn current() -> Env {
        Env {
            exe_dir: std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(Path::to_path_buf)),
            // Set by the AppImage runtime for the process it launches.
            appimage: std::env::var_os("APPIMAGE").is_some(),
            install_path: install_path(),
            path_var: std::env::var_os("PATH"),
        }
    }

    fn bundled(&self) -> Option<PathBuf> {
        let p = self.exe_dir.as_ref()?.join(EXE);
        // An empty file is not a binary; treat it as missing rather than
        // point an assistant at it.
        let len = std::fs::metadata(&p).ok().filter(|m| m.is_file())?.len();
        (len > 0).then_some(p)
    }

    fn on_path(&self) -> Option<PathBuf> {
        let paths = self.path_var.as_ref()?;
        std::env::split_paths(paths)
            .map(|dir| dir.join(EXE))
            .find(|p| p.is_file())
    }
}

/// A per-user location that needs no administrator rights.
fn install_path() -> PathBuf {
    if cfg!(windows) {
        dirs::data_local_dir()
            .unwrap_or_default()
            .join("Programs")
            .join("Kino")
            .join(EXE)
    } else {
        dirs::home_dir()
            .unwrap_or_default()
            .join(".local")
            .join("bin")
            .join(EXE)
    }
}

fn same_contents(a: &Path, b: &Path) -> bool {
    use sha2::{Digest, Sha256};
    let hash = |p: &Path| std::fs::read(p).ok().map(|b| Sha256::digest(&b));
    match (hash(a), hash(b)) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

fn status_in(env: &Env) -> McpBinaryStatus {
    let bundled = env.bundled();
    let installed = env.install_path.is_file().then(|| env.install_path.clone());
    let install_stale = match (&bundled, &installed) {
        (Some(b), Some(i)) => !same_contents(b, i),
        _ => false,
    };

    let command = if env.appimage {
        installed.filter(|_| !install_stale)
    } else {
        bundled.clone()
    };

    let on_path = env.on_path();
    let on_path_matches = match (&bundled, &on_path) {
        (Some(b), Some(p)) => Some(same_contents(b, p)),
        _ => None,
    };

    McpBinaryStatus {
        bundled: bundled.map(|p| p.to_string_lossy().into_owned()),
        command: command.map(|p| p.to_string_lossy().into_owned()),
        needs_install: env.appimage,
        install_path: env.install_path.to_string_lossy().into_owned(),
        install_stale,
        on_path: on_path.map(|p| p.to_string_lossy().into_owned()),
        on_path_matches,
    }
}

/// Copy the bundled binary to the install path.
///
/// Written beside the target and renamed over it, so an assistant starting
/// `kino-mcp` at that moment gets the old file or the new one, never half of
/// either.
fn install_in(env: &Env) -> Result<PathBuf, String> {
    let src = env
        .bundled()
        .ok_or("This build does not carry kino-mcp, so there is nothing to install.")?;
    let dest = &env.install_path;
    let dir = dest.parent().ok_or("The install path has no directory")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("Could not create {}: {e}", dir.display()))?;

    let tmp = dir.join(format!(".{EXE}.{}.tmp", std::process::id()));
    std::fs::copy(&src, &tmp).map_err(|e| format!("Could not copy kino-mcp: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("Could not make kino-mcp executable: {e}"))?;
    }
    std::fs::rename(&tmp, dest).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        if cfg!(windows) {
            format!("Could not replace {}: {e}. If an assistant is running kino-mcp, close it and try again.", dest.display())
        } else {
            format!("Could not replace {}: {e}", dest.display())
        }
    })?;
    Ok(dest.clone())
}

/// Keep an installed copy in step with the AppImage it came from.
///
/// Only ever replaces a copy the user already asked for - it never installs
/// one unprompted - and only from an AppImage, the one case where that copy
/// is what assistants run. Without this, updating the AppImage would leave
/// every assistant on the previous version's `kino-mcp`.
fn refresh_in(env: &Env) -> Option<PathBuf> {
    if !env.appimage || !env.install_path.is_file() {
        return None;
    }
    let bundled = env.bundled()?;
    if same_contents(&bundled, &env.install_path) {
        return None;
    }
    install_in(env).ok()
}

/// The path to write into a config, without hashing anything. Falls back to
/// the bare name, which is what a config needs when nothing better exists.
pub fn command_hint() -> String {
    let env = Env::current();
    let path = if env.appimage {
        env.install_path.is_file().then(|| env.install_path.clone())
    } else {
        env.bundled()
    };
    path.map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| EXE.to_string())
}

/// Called once at startup, off the main thread.
pub fn refresh_installed_copy() {
    if let Some(p) = refresh_in(&Env::current()) {
        eprintln!("[kino] updated {} to this version's kino-mcp", p.display());
    }
}

/// Async so hashing a 17 MB file or two never holds the window: Tauri runs a
/// plain `fn` command on the main thread.
#[tauri::command]
pub async fn check_mcp_binary() -> McpBinaryStatus {
    tokio::task::spawn_blocking(|| status_in(&Env::current()))
        .await
        .unwrap_or_default()
}

#[tauri::command]
pub async fn install_mcp_binary() -> Result<McpBinaryStatus, String> {
    tokio::task::spawn_blocking(|| {
        let env = Env::current();
        install_in(&env)?;
        Ok(status_in(&env))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        _dir: tempfile::TempDir,
        app: PathBuf,
        bin: PathBuf,
        home: PathBuf,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let app = dir.path().join("app");
        let bin = dir.path().join("bin");
        let home = dir.path().join("home").join(".local").join("bin");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::create_dir_all(&bin).unwrap();
        Fixture {
            app,
            bin,
            home,
            _dir: dir,
        }
    }

    impl Fixture {
        fn env(&self, appimage: bool) -> Env {
            Env {
                exe_dir: Some(self.app.clone()),
                appimage,
                install_path: self.home.join(EXE),
                path_var: Some(std::env::join_paths([&self.bin, &self.home]).unwrap()),
            }
        }
        fn bundle(&self, contents: &[u8]) {
            std::fs::write(self.app.join(EXE), contents).unwrap();
        }
    }

    #[test]
    fn an_installed_app_points_at_its_own_copy() {
        let f = fixture();
        f.bundle(b"v1");
        let s = status_in(&f.env(false));
        assert_eq!(s.command, s.bundled);
        assert!(s.command.unwrap().ends_with(EXE));
        assert!(!s.needs_install);
    }

    #[test]
    fn an_appimage_has_no_command_until_it_installs_one() {
        let f = fixture();
        f.bundle(b"v1");
        let env = f.env(true);
        let s = status_in(&env);
        assert!(s.needs_install);
        assert_eq!(s.command, None, "the mount path dies on restart");

        install_in(&env).unwrap();
        let s = status_in(&env);
        assert_eq!(s.command.as_deref(), Some(s.install_path.as_str()));
        assert_eq!(std::fs::read(&env.install_path).unwrap(), b"v1");
    }

    #[cfg(unix)]
    #[test]
    fn the_installed_copy_is_executable() {
        use std::os::unix::fs::PermissionsExt;
        let f = fixture();
        f.bundle(b"v1");
        let env = f.env(true);
        install_in(&env).unwrap();
        let mode = std::fs::metadata(&env.install_path)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o755);
    }

    #[test]
    fn an_appimage_update_refreshes_the_installed_copy() {
        let f = fixture();
        f.bundle(b"v1");
        let env = f.env(true);
        install_in(&env).unwrap();

        f.bundle(b"v2");
        let s = status_in(&env);
        assert!(s.install_stale);
        assert_eq!(
            s.command, None,
            "a stale copy is not offered as the command"
        );

        assert!(refresh_in(&env).is_some());
        assert_eq!(std::fs::read(&env.install_path).unwrap(), b"v2");
        assert!(!status_in(&env).install_stale);
    }

    #[test]
    fn refresh_never_installs_a_copy_nobody_asked_for() {
        let f = fixture();
        f.bundle(b"v1");
        let env = f.env(true);
        assert!(refresh_in(&env).is_none());
        assert!(!env.install_path.exists());
    }

    #[test]
    fn refresh_leaves_a_package_install_alone() {
        // Outside an AppImage the bundled copy is what configs name; a file in
        // ~/.local/bin belongs to the user, whatever it is.
        let f = fixture();
        f.bundle(b"v2");
        let env = f.env(false);
        std::fs::create_dir_all(&f.home).unwrap();
        std::fs::write(&env.install_path, b"theirs").unwrap();
        assert!(refresh_in(&env).is_none());
        assert_eq!(std::fs::read(&env.install_path).unwrap(), b"theirs");
    }

    #[test]
    fn a_different_kino_mcp_earlier_on_path_is_reported() {
        // The old README said to mv the download into /usr/local/bin, which
        // comes before /usr/bin - so a config that says just `kino-mcp` keeps
        // running that file after the .deb installs its own.
        let f = fixture();
        f.bundle(b"v2");
        std::fs::write(f.bin.join(EXE), b"v1").unwrap();
        let s = status_in(&f.env(false));
        assert_eq!(s.on_path_matches, Some(false));
        assert!(s.on_path.unwrap().starts_with(f.bin.to_str().unwrap()));
    }

    #[test]
    fn the_same_file_on_path_matches() {
        let f = fixture();
        f.bundle(b"v2");
        std::fs::write(f.bin.join(EXE), b"v2").unwrap();
        assert_eq!(status_in(&f.env(false)).on_path_matches, Some(true));
    }

    #[test]
    fn an_empty_placeholder_is_not_a_binary() {
        let f = fixture();
        f.bundle(b"");
        let env = f.env(false);
        let s = status_in(&env);
        assert_eq!(s.bundled, None);
        assert_eq!(s.command, None);
        assert!(install_in(&env).is_err());
    }
}
