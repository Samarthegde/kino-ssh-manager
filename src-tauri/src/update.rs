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
use std::time::Duration;

/// HTTP for this module, with the limits ureq does not set.
///
/// Its defaults are a 30-second connect timeout and no read timeout at all -
/// so a connection that opens and then stalls, as a captive portal or a
/// half-broken proxy will, waits forever. Neither call here is worth more than
/// a few seconds.
fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .build()
}

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

/// Async so it runs off the main thread. Tauri runs a non-`async` command *on*
/// the main thread, and this runs at startup - so as a plain `fn` a slow or
/// absent network held the window frozen while the app was still opening.
#[tauri::command]
pub async fn check_for_update() -> Result<UpdateInfo, String> {
    tokio::task::spawn_blocking(check_for_update_now)
        .await
        .map_err(|e| e.to_string())?
}

fn check_for_update_now() -> Result<UpdateInfo, String> {
    let current = env!("CARGO_PKG_VERSION").to_string();
    let url = format!("https://api.github.com/repos/{REPO}/releases/latest");

    let json: serde_json::Value = agent()
        .get(&url)
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

    /// The case that used to hang forever: a server that accepts the
    /// connection and then never says anything, which is what a captive portal
    /// or a wedged proxy looks like. ureq's defaults have no read timeout, so
    /// this waited indefinitely - on the main thread, freezing the window.
    ///
    /// Ignored by default only because it takes the full ten seconds.
    ///
    ///     cargo test --lib update -- --ignored
    #[test]
    #[ignore = "waits out the full request timeout"]
    fn a_server_that_never_answers_does_not_hang_the_request() {
        use std::time::{Duration, Instant};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        // Accept, hold the socket open, say nothing.
        std::thread::spawn(move || {
            let _held: Vec<_> = listener.incoming().take(1).collect();
            std::thread::sleep(Duration::from_secs(60));
        });

        let started = Instant::now();
        let result = super::agent()
            .get(&format!("http://{addr}/SHA256SUMS"))
            .call();
        let took = started.elapsed();

        assert!(result.is_err(), "a silent server cannot have answered");
        assert!(
            took < Duration::from_secs(15),
            "waited {took:?} - the request is not bounded"
        );
        println!("gave up after {took:?}");
    }

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
