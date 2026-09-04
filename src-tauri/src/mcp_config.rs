//! MCP Server configuration.
//!
//! The MCP server gets its own encrypted vault (`mcp_vault.enc`) containing
//! *only* the hosts the user chose to expose, encrypted under a **separate**
//! MCP password — the master vault password never leaves the Tauri app.
//!
//! Two files live next to the main vault:
//!
//! - `mcp_config.enc` — persists the list of exposed host IDs and the MCP
//!   vault's salt. Encrypted with the *master* vault key so only the GUI
//!   can modify it.
//!
//! - `mcp_vault.enc` — a self-contained encrypted blob of the selected hosts
//!   and their referenced snippets. Encrypted with the *MCP* password.
//!   This is the only file the `kino-mcp` binary reads.

use crate::mcp_policy::{HostPolicy, Rule};
use crate::snippets::Snippet;
use crate::vault::{self, load_encrypted, save_encrypted, vault_path, Host};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

// ── Persisted config (encrypted with the master key) ─────────────────────────

/// What the Kino UI stores about MCP: which hosts to expose and the salt
/// for the MCP vault's own key derivation.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct McpConfig {
    /// IDs of hosts the user chose to expose via MCP.
    pub exposed_host_ids: Vec<String>,
    /// Base64-encoded salt used to derive the MCP vault encryption key.
    /// Generated once when the MCP password is first set; regenerated on
    /// password change.
    pub mcp_salt_b64: String,
    /// True once the user has set an MCP password.
    pub configured: bool,
    /// Per-host access policy, keyed by host id. A host with no entry is
    /// `ReadOnly` - the default lives in `HostPolicy::default()` rather than
    /// here, so a host ticked before this existed lands in the safe mode.
    #[serde(default)]
    pub host_policies: HashMap<String, HostPolicy>,
    /// Rules applied to every exposed host, after that host's own.
    #[serde(default)]
    pub global_rules: Vec<Rule>,
    /// The MCP password itself, kept here so the exposed vault can be rebuilt
    /// whenever a host changes.
    ///
    /// This file is encrypted with the *master* key, which already protects
    /// every host credential in the vault - so storing the MCP password beside
    /// them gives away nothing new. The separation that matters is the other
    /// one: `mcp_vault.enc` is encrypted with *this* password, so the headless
    /// binary never needs, and never sees, the master password.
    ///
    /// Without it the exposed vault silently went stale after every restart:
    /// the password lived only in memory, so edits (a rotated key, a host
    /// removed from the list) never reached the file the AI actually reads.
    #[serde(default)]
    pub password: Option<String>,
}

/// One host's policy as the editor works with it: a mode, and the rules in
/// the line-per-rule text the user typed.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HostPolicyView {
    pub mode: String,
    pub rules_text: String,
}

/// The view returned to the frontend (no secrets).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct McpConfigView {
    pub exposed_host_ids: Vec<String>,
    pub configured: bool,
    pub mcp_vault_path: String,
    pub binary_hint: String,
    /// Per-host policy in the form the panel edits. Hosts with no entry are
    /// read-only; the panel shows that rather than an empty cell.
    pub host_policies: HashMap<String, HostPolicyView>,
    /// The global rule block in its text form, ready for the editor.
    pub global_rules_text: String,
}

/// Which hosts and snippets a given exposure list actually yields.
///
/// Split out from `export_mcp_vault` so the filtering - the part that decides
/// what an AI can reach - is testable without touching the filesystem.
pub fn build_mcp_vault(
    all_hosts: &[Host],
    all_snippets: &[Snippet],
    exposed_ids: &[String],
    host_policies: &HashMap<String, HostPolicy>,
    global_rules: &[Rule],
) -> McpVault {
    let hosts: Vec<Host> = all_hosts
        .iter()
        .filter(|h| exposed_ids.contains(&h.id))
        .cloned()
        .collect();

    // Only the snippets the exposed hosts actually reference travel with them.
    let referenced: std::collections::HashSet<&str> = hosts
        .iter()
        .flat_map(|h| h.on_connect_snippets.iter().map(|s| s.as_str()))
        .collect();
    let snippets: Vec<Snippet> = all_snippets
        .iter()
        .filter(|s| referenced.contains(s.id.as_str()))
        .cloned()
        .collect();

    // Every exposed host gets an explicit policy, defaulting to read-only.
    // Only the exposed hosts' policies travel: a rule written for a host that
    // isn't shared is nobody's business but this machine's.
    let policies = hosts
        .iter()
        .map(|h| {
            (
                h.id.clone(),
                host_policies.get(&h.id).cloned().unwrap_or_default(),
            )
        })
        .collect();

    McpVault {
        hosts,
        snippets,
        policies,
        global_rules: global_rules.to_vec(),
    }
}

pub fn config_path() -> PathBuf {
    vault_path().parent().unwrap().join("mcp_config.enc")
}

pub fn mcp_vault_path() -> PathBuf {
    vault_path().parent().unwrap().join("mcp_vault.enc")
}

pub fn load_config(key: &[u8; 32]) -> Result<McpConfig, String> {
    let path = config_path();
    if !path.exists() {
        return Ok(McpConfig::default());
    }
    load_encrypted(&path, key).or_else(|_| Ok(McpConfig::default()))
}

pub fn save_config(config: &McpConfig, key: &[u8; 32], salt: &[u8; 16]) -> Result<(), String> {
    save_encrypted(&config_path(), config, key, salt)
}

// ── MCP vault (encrypted with the MCP password) ─────────────────────────────

/// What the `kino-mcp` binary deserialises after decrypting `mcp_vault.enc`.
///
/// The policy travels *with* the hosts rather than being read from
/// `mcp_config.enc`, which is sealed under the master key the headless binary
/// never has. That is what lets `kino-mcp` enforce the rules itself instead of
/// trusting a caller to have checked them.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct McpVault {
    pub hosts: Vec<Host>,
    pub snippets: Vec<Snippet>,
    /// One entry per exposed host, written explicitly even when it is the
    /// default, so the vault says what it means without the reader guessing.
    #[serde(default)]
    pub policies: HashMap<String, HostPolicy>,
    #[serde(default)]
    pub global_rules: Vec<Rule>,
}

/// Build and write the MCP vault: filter hosts to only those in
/// `exposed_host_ids`, include any snippets they reference, encrypt the
/// bundle under the MCP password, and write to `mcp_vault.enc`.
pub fn export_mcp_vault(
    all_hosts: &[Host],
    all_snippets: &[Snippet],
    exposed_ids: &[String],
    host_policies: &HashMap<String, HostPolicy>,
    global_rules: &[Rule],
    mcp_password: &str,
    mcp_salt: &[u8; 16],
) -> Result<(), String> {
    let vault = build_mcp_vault(
        all_hosts,
        all_snippets,
        exposed_ids,
        host_policies,
        global_rules,
    );
    let mcp_key = vault::derive_key(mcp_password, mcp_salt)?;
    save_encrypted(&mcp_vault_path(), &vault, &mcp_key, mcp_salt)?;

    // Wipe the derived key.
    let mut key = mcp_key;
    use zeroize::Zeroize;
    key.zeroize();
    Ok(())
}

/// Load the MCP vault (used by the `kino-mcp` binary).
pub fn load_mcp_vault(password: &str) -> Result<McpVault, String> {
    load_mcp_vault_at(&mcp_vault_path(), password)
}

/// The real work, taking a path so the binary's load path can be tested rather
/// than approximated. The salt comes from the file itself: the headless binary
/// has only the password, and nothing else to derive a key from.
pub fn load_mcp_vault_at(path: &PathBuf, password: &str) -> Result<McpVault, String> {
    use base64::{engine::general_purpose::STANDARD, Engine};

    let bytes = std::fs::read(path).map_err(|e| format!("Cannot read MCP vault: {}", e))?;
    let enc: vault::EncryptedFile =
        serde_json::from_slice(&bytes).map_err(|e| format!("Corrupt MCP vault: {}", e))?;

    let salt_vec = STANDARD
        .decode(&enc.salt)
        .map_err(|e| format!("Corrupt MCP vault salt: {}", e))?;
    let salt: [u8; 16] = salt_vec
        .try_into()
        .map_err(|_| "Invalid salt length in MCP vault".to_string())?;

    let key = vault::derive_key(password, &salt)?;
    let vault: McpVault = load_encrypted(path, &key)
        .map_err(|_| "Wrong MCP password or corrupt MCP vault".to_string())?;

    let mut k = key;
    use zeroize::Zeroize;
    k.zeroize();
    Ok(vault)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp_policy::McpMode;

    fn sample_hosts() -> Vec<Host> {
        vec![
            Host {
                id: "h1".into(),
                name: "web-prod".into(),
                hostname: "10.0.0.1".into(),
                port: 22,
                username: "root".into(),
                default_auth: "Password".into(),
                password: Some("secret".into()),
                private_key: None,
                public_key: None,
                passphrase: None,
                port_forwards: vec![],
                on_connect_snippets: vec!["s1".into()],
                color: None,
                notes: None,
                group: None,
                os: None,
                connection_mode: None,
                agent_id: None,
                relay_url: None,
                relay_token: None,
                control_url: None,
                proxy_type: None,
                proxy_host: None,
                proxy_port: None,
                proxy_username: None,
                proxy_password: None,
                jump_host: None,
                jump: None,
                key_added_at: None,
                ntfy_topic: None,
            },
            Host {
                id: "h2".into(),
                name: "db-prod".into(),
                hostname: "10.0.0.2".into(),
                port: 22,
                username: "admin".into(),
                default_auth: "SshKey".into(),
                password: None,
                private_key: Some("KEY".into()),
                public_key: None,
                passphrase: None,
                port_forwards: vec![],
                on_connect_snippets: vec![],
                color: None,
                notes: None,
                group: None,
                os: None,
                connection_mode: None,
                agent_id: None,
                relay_url: None,
                relay_token: None,
                control_url: None,
                proxy_type: None,
                proxy_host: None,
                proxy_port: None,
                proxy_username: None,
                proxy_password: None,
                jump_host: None,
                jump: None,
                key_added_at: None,
                ntfy_topic: None,
            },
        ]
    }

    fn no_policies() -> HashMap<String, HostPolicy> {
        HashMap::new()
    }

    fn sample_snippets() -> Vec<Snippet> {
        vec![
            Snippet {
                id: "s1".into(),
                name: "setup".into(),
                commands: "echo hello".into(),
            },
            Snippet {
                id: "s2".into(),
                name: "unused".into(),
                commands: "echo bye".into(),
            },
        ]
    }

    #[test]
    fn only_exposed_hosts_are_included() {
        // The whole security claim of the feature: the AI sees the hosts the
        // user ticked and nothing else.
        let v = build_mcp_vault(
            &sample_hosts(),
            &sample_snippets(),
            &["h1".to_string()],
            &no_policies(),
            &[],
        );
        assert_eq!(v.hosts.len(), 1);
        assert_eq!(v.hosts[0].name, "web-prod");
        assert!(!v.hosts.iter().any(|h| h.name == "db-prod"));
    }

    #[test]
    fn exposing_nothing_yields_nothing() {
        let v = build_mcp_vault(
            &sample_hosts(),
            &sample_snippets(),
            &[],
            &no_policies(),
            &[],
        );
        assert!(v.hosts.is_empty());
        assert!(v.snippets.is_empty());
    }

    #[test]
    fn an_unknown_host_id_is_ignored() {
        let v = build_mcp_vault(
            &sample_hosts(),
            &sample_snippets(),
            &["deleted".to_string()],
            &no_policies(),
            &[],
        );
        assert!(v.hosts.is_empty());
    }

    #[test]
    fn only_snippets_the_exposed_hosts_reference_travel() {
        let v = build_mcp_vault(
            &sample_hosts(),
            &sample_snippets(),
            &["h1".to_string()],
            &no_policies(),
            &[],
        );
        assert_eq!(v.snippets.len(), 1);
        assert_eq!(v.snippets[0].name, "setup");
        // "unused" belongs to no exposed host and must not leave the vault.
        assert!(!v.snippets.iter().any(|s| s.name == "unused"));

        // h2 references none, so exposing it alone carries no snippets at all.
        let v2 = build_mcp_vault(
            &sample_hosts(),
            &sample_snippets(),
            &["h2".to_string()],
            &no_policies(),
            &[],
        );
        assert!(v2.snippets.is_empty());
    }

    #[test]
    fn every_exposed_host_gets_an_explicit_read_only_policy() {
        // The binary must not have to know what the default is. A host nobody
        // configured travels with a policy that says so.
        let v = build_mcp_vault(
            &sample_hosts(),
            &sample_snippets(),
            &["h1".to_string(), "h2".to_string()],
            &no_policies(),
            &[],
        );
        assert_eq!(v.policies.len(), 2);
        assert_eq!(v.policies["h1"].mode, McpMode::ReadOnly);
        assert_eq!(v.policies["h2"].mode, McpMode::ReadOnly);
    }

    #[test]
    fn a_configured_policy_travels_with_its_host() {
        let mut policies = no_policies();
        policies.insert(
            "h1".into(),
            HostPolicy {
                mode: McpMode::Full,
                rules: crate::mcp_policy::parse_rules("deny rm -rf *", "host").unwrap(),
            },
        );
        let v = build_mcp_vault(
            &sample_hosts(),
            &sample_snippets(),
            &["h1".to_string()],
            &policies,
            &crate::mcp_policy::parse_rules("deny shutdown *", "global").unwrap(),
        );
        assert_eq!(v.policies["h1"].mode, McpMode::Full);
        assert_eq!(v.policies["h1"].rules.len(), 1);
        assert_eq!(v.global_rules.len(), 1);
    }

    #[test]
    fn a_policy_for_an_unexposed_host_stays_home() {
        // Rules written for a host that isn't shared say something about the
        // fleet; the exposed vault has no business carrying them.
        let mut policies = no_policies();
        policies.insert(
            "h2".into(),
            HostPolicy {
                mode: McpMode::Full,
                rules: vec![],
            },
        );
        let v = build_mcp_vault(
            &sample_hosts(),
            &sample_snippets(),
            &["h1".to_string()],
            &policies,
            &[],
        );
        assert!(!v.policies.contains_key("h2"));
        assert_eq!(v.policies.len(), 1);
    }

    #[test]
    fn exposed_hosts_keep_the_credentials_needed_to_connect() {
        // The MCP vault is the only thing the headless binary reads, so an
        // exposed host has to carry its own secret with it.
        let v = build_mcp_vault(
            &sample_hosts(),
            &sample_snippets(),
            &["h1".to_string()],
            &no_policies(),
            &[],
        );
        assert_eq!(v.hosts[0].password.as_deref(), Some("secret"));
    }

    #[test]
    fn export_filters_hosts_and_snippets() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp_vault.enc");

        // Temporarily override the path (we can't in this unit test, so
        // we test the filtering logic directly instead).
        let all_hosts = sample_hosts();
        let all_snippets = sample_snippets();
        let exposed = ["h1".to_string()];

        // Filter manually to test the logic.
        let hosts: Vec<Host> = all_hosts
            .iter()
            .filter(|h| exposed.contains(&h.id))
            .cloned()
            .collect();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].name, "web-prod");

        let referenced: std::collections::HashSet<&str> = hosts
            .iter()
            .flat_map(|h| h.on_connect_snippets.iter().map(|s| s.as_str()))
            .collect();
        let snippets: Vec<Snippet> = all_snippets
            .iter()
            .filter(|s| referenced.contains(s.id.as_str()))
            .cloned()
            .collect();
        assert_eq!(snippets.len(), 1);
        assert_eq!(snippets[0].name, "setup");

        // Round-trip through encryption.
        let salt = [42u8; 16];
        let key = vault::derive_key("mcp-pass", &salt).unwrap();
        let vault = McpVault {
            hosts,
            snippets,
            policies: no_policies(),
            global_rules: vec![],
        };
        save_encrypted(&path, &vault, &key, &salt).unwrap();
        let loaded: McpVault = load_encrypted(&path, &key).unwrap();
        assert_eq!(loaded.hosts.len(), 1);
        assert_eq!(loaded.hosts[0].password.as_deref(), Some("secret"));
        assert_eq!(loaded.snippets.len(), 1);
    }

    #[test]
    fn the_binarys_load_path_round_trips() {
        // Exercises exactly what `kino-mcp` does: derive from the password
        // alone, taking the salt out of the file, and get the hosts back.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp_vault.enc");
        let salt = [11u8; 16];
        let key = vault::derive_key("mcp-pass", &salt).unwrap();

        let built = build_mcp_vault(
            &sample_hosts(),
            &sample_snippets(),
            &["h1".to_string()],
            &no_policies(),
            &[],
        );
        save_encrypted(&path, &built, &key, &salt).unwrap();

        let loaded = load_mcp_vault_at(&path, "mcp-pass").unwrap();
        assert_eq!(loaded.hosts.len(), 1);
        assert_eq!(loaded.hosts[0].name, "web-prod");
        assert_eq!(loaded.snippets.len(), 1);
    }

    #[test]
    fn the_binary_rejects_the_wrong_password() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp_vault.enc");
        let salt = [11u8; 16];
        let key = vault::derive_key("right", &salt).unwrap();
        let built = build_mcp_vault(
            &sample_hosts(),
            &sample_snippets(),
            &["h1".to_string()],
            &no_policies(),
            &[],
        );
        save_encrypted(&path, &built, &key, &salt).unwrap();

        let err = load_mcp_vault_at(&path, "wrong").unwrap_err();
        assert!(err.contains("Wrong MCP password"), "got: {}", err);
    }

    #[test]
    fn wrong_mcp_password_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp_vault.enc");
        let salt = [7u8; 16];
        let key = vault::derive_key("right", &salt).unwrap();
        let vault = McpVault {
            hosts: vec![],
            snippets: vec![],
            policies: no_policies(),
            global_rules: vec![],
        };
        save_encrypted(&path, &vault, &key, &salt).unwrap();

        let wrong = vault::derive_key("wrong", &salt).unwrap();
        let res: Result<McpVault, String> = load_encrypted(&path, &wrong);
        assert!(res.is_err());
    }
}
