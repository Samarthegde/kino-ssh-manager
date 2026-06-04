//! Cloud sync of the encrypted vault blob.
//!
//! Design: the vault on disk (`vault.enc`) is already an opaque AES-GCM
//! ciphertext with its salt embedded, so syncing is just "push/pull one blob".
//! The plaintext and master password never leave the device — the remote only
//! ever sees the encrypted file. Conflict detection is delegated to the backend
//! (for GitHub: the blob `sha` required by the Contents API; a stale sha yields
//! a 409/422 which we surface as a conflict rather than clobbering).

use crate::vault::{load_encrypted, save_encrypted, vault_path};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Sentinel error string meaning "remote moved under us — don't clobber".
/// Commands translate this into a structured outcome for the frontend.
const CONFLICT: &str = "__SYNC_CONFLICT__";

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ── Config ──────────────────────────────────────────────────────────────────

/// Persisted sync settings. Stored encrypted (with the vault key) in
/// `sync.enc` so the access token is never at rest in plaintext. This is
/// device-local: each device is configured once with its own copy.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SyncConfig {
    /// Currently only "github".
    pub provider: String,
    pub token: String,
    pub owner: String,
    pub repo: String,
    /// Path of the blob within the repo, e.g. "vault.enc".
    pub path: String,
    pub branch: String,
    /// Blob sha we last successfully synced — our optimistic-concurrency token.
    #[serde(default)]
    pub last_sha: Option<String>,
    /// Same, for the sibling history blob (history follows the vault).
    #[serde(default)]
    pub history_sha: Option<String>,
    /// Same, for the sibling snippets-library blob.
    #[serde(default)]
    pub snippets_sha: Option<String>,
    #[serde(default)]
    pub last_synced_at: Option<u64>,
}

/// Remote path of a sibling blob (e.g. history / snippets) next to the vault.
fn sibling_remote_path(config: &SyncConfig, filename: &str) -> String {
    match config.path.rfind('/') {
        Some(i) => format!("{}/{}", &config.path[..i], filename),
        None => filename.to_string(),
    }
}

pub fn history_remote_path(config: &SyncConfig) -> String {
    sibling_remote_path(config, "history.enc")
}

pub fn snippets_remote_path(config: &SyncConfig) -> String {
    sibling_remote_path(config, "snippets.enc")
}

/// What the frontend may see — never includes the token itself.
#[derive(Serialize)]
pub struct SyncConfigView {
    pub configured: bool,
    pub provider: String,
    pub owner: String,
    pub repo: String,
    pub path: String,
    pub branch: String,
    pub has_token: bool,
    pub last_synced_at: Option<u64>,
}

/// What the frontend sends when saving settings. An empty `token` means
/// "keep the existing one" so the user doesn't have to retype it.
#[derive(Deserialize)]
pub struct SyncConfigInput {
    pub token: String,
    pub owner: String,
    pub repo: String,
    pub path: Option<String>,
    pub branch: Option<String>,
}

pub fn config_path() -> PathBuf {
    vault_path().parent().unwrap().join("sync.enc")
}

pub fn load_config(key: &[u8; 32]) -> Option<SyncConfig> {
    let path = config_path();
    if !path.exists() {
        return None;
    }
    load_encrypted::<SyncConfig>(&path, key).ok()
}

pub fn save_config(config: &SyncConfig, key: &[u8; 32], salt: &[u8; 16]) -> Result<(), String> {
    save_encrypted(&config_path(), config, key, salt)
}

impl SyncConfig {
    pub fn view(&self) -> SyncConfigView {
        SyncConfigView {
            configured: !self.owner.is_empty() && !self.repo.is_empty() && !self.token.is_empty(),
            provider: self.provider.clone(),
            owner: self.owner.clone(),
            repo: self.repo.clone(),
            path: self.path.clone(),
            branch: self.branch.clone(),
            has_token: !self.token.is_empty(),
            last_synced_at: self.last_synced_at,
        }
    }
}

// ── Backend abstraction ───────────────────────────────────────────────────────

pub struct RemoteBlob {
    pub data: Vec<u8>,
    pub sha: String,
}

/// A pluggable sync target. Implementations only ever move opaque bytes.
pub trait SyncBackend {
    /// Fetch the remote blob and its version id. `Ok(None)` if it doesn't exist yet.
    fn pull(&self) -> Result<Option<RemoteBlob>, String>;

    /// Upload `data`. `expected_sha` is the version we last saw (`None` = create new).
    /// Returns the new version id, or the `CONFLICT` sentinel error if the remote
    /// moved since `expected_sha`.
    fn push(&self, data: &[u8], expected_sha: Option<&str>) -> Result<String, String>;
}

pub fn backend_for(config: &SyncConfig) -> Result<Box<dyn SyncBackend>, String> {
    backend_for_path(config, config.path.clone())
}

/// Build a backend bound to an arbitrary path in the same target (e.g. the
/// sibling history blob).
pub fn backend_for_path(config: &SyncConfig, path: String) -> Result<Box<dyn SyncBackend>, String> {
    match config.provider.as_str() {
        "github" | "" => Ok(Box::new(GitHubBackend::for_path(config, path))),
        other => Err(format!("Unknown sync provider: {}", other)),
    }
}

// ── GitHub Contents-API backend ────────────────────────────────────────────────

pub struct GitHubBackend {
    token: String,
    owner: String,
    repo: String,
    path: String,
    branch: String,
}

impl GitHubBackend {
    pub fn for_path(c: &SyncConfig, path: String) -> Self {
        GitHubBackend {
            token: c.token.clone(),
            owner: c.owner.clone(),
            repo: c.repo.clone(),
            path,
            branch: c.branch.clone(),
        }
    }

    fn url(&self) -> String {
        format!(
            "https://api.github.com/repos/{}/{}/contents/{}",
            self.owner, self.repo, self.path
        )
    }

    fn auth(&self, req: ureq::Request) -> ureq::Request {
        req.set("Authorization", &format!("Bearer {}", self.token))
            .set("Accept", "application/vnd.github+json")
            .set("X-GitHub-Api-Version", "2022-11-28")
            .set("User-Agent", "ssh-manager")
    }
}

/// Turn a non-2xx GitHub response into a readable error.
fn github_err(code: u16, resp: ureq::Response) -> String {
    let body: serde_json::Value = resp.into_json().unwrap_or(serde_json::Value::Null);
    let msg = body
        .get("message")
        .and_then(|m| m.as_str())
        .unwrap_or("request failed");
    match code {
        401 => "GitHub rejected the token (401). Check the token and that it has Contents read/write.".to_string(),
        403 => format!("GitHub denied access (403): {}", msg),
        404 => format!("Repo or path not found (404): {}/{} — also returned when the token can't see a private repo.", code, msg),
        _ => format!("GitHub error {}: {}", code, msg),
    }
}

impl SyncBackend for GitHubBackend {
    fn pull(&self) -> Result<Option<RemoteBlob>, String> {
        let req = self.auth(ureq::get(&self.url())).query("ref", &self.branch);
        match req.call() {
            Ok(resp) => {
                let v: serde_json::Value = resp.into_json().map_err(|e| e.to_string())?;
                let sha = v["sha"]
                    .as_str()
                    .ok_or("GitHub response missing sha")?
                    .to_string();
                // The Contents API returns base64 with embedded newlines.
                let content = v["content"]
                    .as_str()
                    .unwrap_or("")
                    .replace(['\n', '\r'], "");
                let data = STANDARD
                    .decode(content)
                    .map_err(|e| format!("Bad base64 from GitHub: {}", e))?;
                Ok(Some(RemoteBlob { data, sha }))
            }
            Err(ureq::Error::Status(404, _)) => Ok(None),
            Err(ureq::Error::Status(code, resp)) => Err(github_err(code, resp)),
            Err(e) => Err(format!("Network error reaching GitHub: {}", e)),
        }
    }

    fn push(&self, data: &[u8], expected_sha: Option<&str>) -> Result<String, String> {
        let mut body = serde_json::json!({
            "message": format!("vault sync @ {}", now_secs()),
            "content": STANDARD.encode(data),
            "branch": self.branch,
        });
        if let Some(sha) = expected_sha {
            body["sha"] = serde_json::Value::String(sha.to_string());
        }

        match self.auth(ureq::put(&self.url())).send_json(body) {
            Ok(resp) => {
                let v: serde_json::Value = resp.into_json().map_err(|e| e.to_string())?;
                v["content"]["sha"]
                    .as_str()
                    .map(|s| s.to_string())
                    .ok_or_else(|| "GitHub response missing content.sha".to_string())
            }
            // 409: stale sha. 422 with no sha supplied: file already exists remotely
            // while we thought it was new — both mean "remote moved, resolve it".
            Err(ureq::Error::Status(409, _)) => Err(CONFLICT.to_string()),
            Err(ureq::Error::Status(422, _)) if expected_sha.is_none() => Err(CONFLICT.to_string()),
            Err(ureq::Error::Status(code, resp)) => Err(github_err(code, resp)),
            Err(e) => Err(format!("Network error reaching GitHub: {}", e)),
        }
    }
}

// ── Outcomes returned to the frontend ──────────────────────────────────────────

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PushOutcome {
    /// Uploaded successfully.
    Pushed { sha: String, synced_at: u64 },
    /// Remote changed since our last sync — caller should pull or force.
    Conflict,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PullOutcome {
    /// Remote was newer; local vault was replaced. Returns the fresh host list.
    Pulled {
        sha: String,
        synced_at: u64,
        hosts: Vec<crate::vault::Host>,
    },
    /// Local already matches the remote sha; nothing to do.
    UpToDate,
    /// Nothing has been pushed to the remote yet.
    NoRemote,
}

pub fn is_conflict(err: &str) -> bool {
    err == CONFLICT
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(path: &str) -> SyncConfig {
        SyncConfig {
            provider: "github".into(),
            token: "ghp_secret".into(),
            owner: "octocat".into(),
            repo: "vault".into(),
            path: path.into(),
            branch: "main".into(),
            last_sha: None,
            history_sha: None,
            snippets_sha: None,
            last_synced_at: None,
        }
    }

    #[test]
    fn sibling_paths_are_derived_from_the_vault_path() {
        assert_eq!(history_remote_path(&cfg("vault.enc")), "history.enc");
        assert_eq!(snippets_remote_path(&cfg("vault.enc")), "snippets.enc");
        assert_eq!(
            history_remote_path(&cfg("dir/vault.enc")),
            "dir/history.enc"
        );
        assert_eq!(snippets_remote_path(&cfg("a/b/v.enc")), "a/b/snippets.enc");
    }

    #[test]
    fn conflict_sentinel_round_trips() {
        assert!(is_conflict(CONFLICT));
        assert!(!is_conflict("some other error"));
    }

    #[test]
    fn config_view_never_exposes_the_token() {
        let view = cfg("vault.enc").view();
        assert!(view.configured);
        assert!(view.has_token);
        let json = serde_json::to_string(&view).unwrap();
        // `has_token` (a bool) is fine; a `"token"` field or the secret value is not.
        assert!(
            !json.contains("\"token\""),
            "the token field must not be serialized"
        );
        assert!(
            !json.contains("ghp_secret"),
            "the token value must never leak"
        );
    }

    #[test]
    fn config_view_reports_unconfigured_without_credentials() {
        let mut c = cfg("vault.enc");
        c.token = String::new();
        c.owner = String::new();
        let view = c.view();
        assert!(!view.configured);
        assert!(!view.has_token);
    }
}
