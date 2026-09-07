//! Lightweight update check against the GitHub Releases API.
//!
//! This module only *compares versions*. It is not the thing that decides
//! whether an update may be installed: `tauri_plugin_updater` does that, and it
//! verifies a minisign signature against the public key in `tauri.conf.json`
//! before applying anything. Keeping the two apart matters - a version number
//! fetched over HTTPS says what is newest, and says nothing at all about who
//! built it.
//!
//! Done in Rust (via `ureq`) rather than the webview to avoid CORS/CSP
//! restrictions.

use serde::Serialize;

const REPO: &str = "Samarthegde/kino-ssh-manager";

#[derive(Serialize)]
pub struct UpdateInfo {
    /// Version this build is running (from Cargo).
    pub current: String,
    /// Latest published release version (tag, `v` stripped). Empty if unknown.
    pub latest: String,
    /// True when `latest` is strictly newer than `current`.
    pub available: bool,
    /// Page to open for the update (release page, falls back to /releases).
    pub url: String,
}

/// Parse a dotted version into numeric components, ignoring any pre-release
/// suffix (`0.4.1-rc.2` - `[0, 4, 1]`).
fn parts(v: &str) -> Vec<u64> {
    v.trim()
        .trim_start_matches('v')
        // Drop any pre-release/build suffix before splitting on dots.
        .split('-')
        .next()
        .unwrap_or("")
        .split('.')
        .map(|p| p.parse().unwrap_or(0))
        .collect()
}

fn is_newer(latest: &str, current: &str) -> bool {
    let (l, c) = (parts(latest), parts(current));
    for i in 0..l.len().max(c.len()) {
        let lv = l.get(i).copied().unwrap_or(0);
        let cv = c.get(i).copied().unwrap_or(0);
        if lv != cv {
            return lv > cv;
        }
    }
    false
}

/// The minisign key id the updater will verify against.
///
/// Read out of the running app's own config rather than hardcoded, so it
/// cannot drift from the key that actually gates an install. Shown to the user
/// before they apply an update: "signed by E417F3D9D4D9C4E1" is checkable
/// against the key published in the repo, where "signature valid" alone asks
/// them to take our word for which key.
#[tauri::command]
pub fn updater_key_id(app: tauri::AppHandle) -> Option<String> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let pubkey = app
        .config()
        .plugins
        .0
        .get("updater")?
        .get("pubkey")?
        .as_str()?
        .to_string();
    let decoded = String::from_utf8(STANDARD.decode(pubkey).ok()?).ok()?;
    // `untrusted comment: minisign public key: E417F3D9D4D9C4E1`
    decoded
        .lines()
        .next()?
        .rsplit(':')
        .next()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// What the `kino-mcp` binary on this machine is, against what the release
/// says it should be.
#[derive(Serialize, Default)]
pub struct McpBinaryCheck {
    /// The asset name for this platform, so the user knows what to download.
    pub asset: String,
    /// SHA-256 from the release's signed SHA256SUMS. `None` when the release
    /// predates checksums, or could not be reached.
    pub expected: Option<String>,
    /// Where `kino-mcp` was found on PATH, if it was.
    pub path: Option<String>,
    /// SHA-256 of that file.
    pub actual: Option<String>,
    /// Only `Some` when both halves are known - never a guess.
    pub matches: Option<bool>,
    /// Why a half is missing, in words worth showing.
    pub detail: Option<String>,
}

fn mcp_asset_name() -> &'static str {
    if cfg!(windows) {
        "kino-mcp-windows-x86_64.exe"
    } else {
        "kino-mcp-linux-x86_64"
    }
}

/// Find `kino-mcp` the way a shell would.
fn mcp_on_path() -> Option<std::path::PathBuf> {
    let exe = if cfg!(windows) {
        "kino-mcp.exe"
    } else {
        "kino-mcp"
    };
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(exe))
            .find(|p| p.is_file())
    })
}

fn sha256_of(path: &std::path::Path) -> Option<String> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path).ok()?;
    Some(format!("{:x}", Sha256::digest(&bytes)))
}

/// Compare the installed `kino-mcp` against the release it claims to be from.
///
/// `kino-mcp` is a separate download that the user places on their PATH
/// themselves, so nothing in the app has ever confirmed it is the file this
/// version shipped. It can reach every host exposed to it, which makes that
/// worth answering rather than assuming.
///
/// Both halves can legitimately be missing - the binary may not be installed,
/// and a release older than SHA256SUMS has nothing to compare against - so
/// `matches` stays `None` unless both are known.
#[tauri::command]
pub fn check_mcp_binary() -> McpBinaryCheck {
    let asset = mcp_asset_name().to_string();
    let version = env!("CARGO_PKG_VERSION");
    let mut out = McpBinaryCheck {
        asset: asset.clone(),
        ..Default::default()
    };

    if let Some(path) = mcp_on_path() {
        out.actual = sha256_of(&path);
        out.path = Some(path.to_string_lossy().into_owned());
    } else {
        out.detail = Some("kino-mcp was not found on your PATH.".into());
    }

    let url = format!("https://github.com/{REPO}/releases/download/v{version}/SHA256SUMS");
    let fetched = ureq::get(&url)
        .set("User-Agent", "kino-ssh-manager")
        .call()
        .ok()
        .and_then(|r| r.into_string().ok());
    match fetched {
        Some(body) => {
            out.expected = body
                .lines()
                .find(|l| l.ends_with(&asset))
                .and_then(|l| l.split_whitespace().next())
                .map(str::to_string);
            if out.expected.is_none() {
                out.detail = Some(format!("v{version}'s SHA256SUMS does not list {asset}."));
            }
        }
        None => {
            out.detail = Some(format!(
                "Could not fetch SHA256SUMS for v{version} - it may predate signed checksums, \
                 or you may be offline."
            ));
        }
    }

    out.matches = match (&out.expected, &out.actual) {
        (Some(e), Some(a)) => Some(e.eq_ignore_ascii_case(a)),
        _ => None,
    };
    out
}

#[tauri::command]
pub fn check_for_update() -> Result<UpdateInfo, String> {
    let current = env!("CARGO_PKG_VERSION").to_string();
    let url = format!("https://api.github.com/repos/{REPO}/releases/latest");

    let json: serde_json::Value = ureq::get(&url)
        .set("User-Agent", "kino-ssh-manager")
        .set("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| format!("Update check failed: {e}"))?
        .into_json()
        .map_err(|e| format!("Invalid response: {e}"))?;

    let latest = json
        .get("tag_name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim_start_matches('v')
        .to_string();

    let url = json
        .get("html_url")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("https://github.com/{REPO}/releases"));

    let available = !latest.is_empty() && is_newer(&latest, &current);
    Ok(UpdateInfo {
        current,
        latest,
        available,
        url,
    })
}

#[cfg(test)]
mod tests {
    use super::is_newer;

    #[test]
    fn compares_versions() {
        assert!(is_newer("0.4.1", "0.4.0"));
        assert!(is_newer("0.5.0", "0.4.9"));
        assert!(is_newer("1.0.0", "0.9.9"));
        assert!(!is_newer("0.4.0", "0.4.0"));
        assert!(!is_newer("0.3.9", "0.4.0"));
        // pre-release suffixes are ignored for the numeric compare
        assert!(!is_newer("0.4.0-rc.1", "0.4.0"));
    }
}
