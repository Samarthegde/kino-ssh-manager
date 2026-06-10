//! Lightweight update check against the GitHub Releases API.
//!
//! No auto-install or signing — we just compare the latest published release
//! tag to the running version and let the UI link to the release page. Done in
//! Rust (via `ureq`) to avoid webview CORS/CSP restrictions.

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
/// suffix (`0.4.1-rc.2` → `[0, 4, 1]`).
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
