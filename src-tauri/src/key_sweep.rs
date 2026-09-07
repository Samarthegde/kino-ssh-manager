//! Find the private keys lying around on this machine.
//!
//! The September 2025 npm compromises and the worm that followed made
//! credential harvesting from developer workstations the ordinary case rather
//! than the exotic one, and those payloads walk `~/.ssh` specifically. An
//! unencrypted `id_rsa` on disk is a live liability, and Kino happens to have
//! exactly the right place to put it instead.
//!
//! This module only *finds and describes*. Importing a key into the vault and
//! removing it from disk is a separate, deliberate step: one of these two
//! things deletes a private key, and it should not share a code path with the
//! thing that merely looks.
//!
//! ## Deliberate limits
//!
//! - It scans `~/.ssh` and one level below, plus whatever the user adds. Not
//!   the home directory: a sweep that reads everything is a sweep nobody runs
//!   twice, and it would spend most of its time in `node_modules`.
//! - It never asks for a passphrase and never decrypts anything. Whether a key
//!   is encrypted is readable from its header; that is all we need to know.
//! - It reads keys and reports on them. It does not copy them anywhere, log
//!   them, or send them anywhere, and there is no code path here that could.

use crate::vault::Host;
use serde::Serialize;
use ssh_key::{HashAlg, PrivateKey};
use std::path::{Path, PathBuf};

/// Bigger than this is not a key. A 4096-bit RSA private key is about 3 KB;
/// the ceiling is generous so that a certificate bundle is still skipped.
const MAX_KEY_BYTES: u64 = 64 * 1024;

/// How much of a file to sniff before deciding it is worth reading at all.
const SNIFF_BYTES: usize = 128;

/// What a key file turned out to be.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct KeyOnDisk {
    pub path: String,
    /// "openssh" | "pem" | "pkcs8" | "ppk"
    pub format: String,
    /// "ed25519", "rsa", "dsa"… `None` when the format cannot be read without
    /// a passphrase or a converter, which is the honest answer for PPK.
    pub algorithm: Option<String>,
    pub bits: Option<u32>,
    /// `SHA256:…`, the same string `ssh-keygen -lf` prints. Used to match a
    /// key against the vault without comparing private halves.
    pub fingerprint: Option<String>,
    pub encrypted: bool,
    pub comment: Option<String>,
    /// Unix permission bits, `None` on Windows where the model is an ACL.
    pub mode: Option<u32>,
    pub modified: Option<i64>,
    pub findings: Vec<crate::audit::Finding>,
}

/// What one sweep found.
#[derive(Serialize, Clone, Debug, Default)]
pub struct SweepReport {
    pub keys: Vec<KeyOnDisk>,
    /// Directories that were looked at, so the user can see the scope.
    pub scanned: Vec<String>,
    /// Problems that are not about one key - a bad `~/.ssh/config` setting.
    pub findings: Vec<crate::audit::Finding>,
    pub critical: usize,
    pub high: usize,
}

fn finding(id: &str, severity: &str, title: &str, detail: String) -> crate::audit::Finding {
    crate::audit::Finding {
        id: id.into(),
        severity: severity.into(),
        title: title.into(),
        detail,
    }
}

/// Does this look like a private key at all?
///
/// Cheap enough to run on every file in the directory, and specific enough not
/// to drag in `known_hosts` or a `.pub`.
pub fn looks_like_a_key(head: &str) -> bool {
    let window = &head[..head.len().min(SNIFF_BYTES)];
    (window.contains("-----BEGIN") && window.contains("PRIVATE KEY-----"))
        || window.contains("PuTTY-User-Key-File-")
}

/// Which on-disk format, from the header alone.
fn format_of(text: &str) -> &'static str {
    if text.contains("PuTTY-User-Key-File-") {
        "ppk"
    } else if text.contains("-----BEGIN OPENSSH PRIVATE KEY-----") {
        "openssh"
    } else if text.contains("-----BEGIN PRIVATE KEY-----")
        || text.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----")
    {
        "pkcs8"
    } else {
        "pem"
    }
}

/// Everything about a key that can be read without its passphrase.
///
/// Pure: takes the text and the file facts, returns the description. The
/// filesystem stays in `sweep`, so every shape a key file can take is a unit
/// test rather than something that needs a fixture directory.
pub fn classify(
    path: &str,
    text: &str,
    mode: Option<u32>,
    modified: Option<i64>,
) -> Option<KeyOnDisk> {
    if !looks_like_a_key(text) {
        return None;
    }
    let format = format_of(text);

    // PPK and traditional PEM are not shapes `ssh-key` reads. Saying "format
    // ppk, cannot read further" is better than guessing, and the permission
    // and vault findings below still apply to it.
    let parsed = PrivateKey::from_openssh(text.trim()).ok();
    let (algorithm, bits, fingerprint, encrypted, comment) = match &parsed {
        Some(k) => {
            let public = k.public_key();
            let (alg, bits) = crate::audit::describe_algorithm(public);
            (
                Some(alg),
                bits,
                Some(public.fingerprint(HashAlg::Sha256).to_string()),
                k.is_encrypted(),
                Some(k.comment().to_string()).filter(|c| !c.is_empty()),
            )
        }
        // A header is enough to know it is protected, even unparsed: OpenSSH
        // and PKCS#8 both say so in plain text, and PPK carries an Encryption
        // line.
        None => (
            None,
            None,
            None,
            text.contains("ENCRYPTED")
                || text.contains("Proc-Type: 4,ENCRYPTED")
                || text.contains("Encryption: aes"),
            None,
        ),
    };

    let mut findings = Vec::new();

    if !encrypted {
        findings.push(finding(
            "unencrypted-key",
            "critical",
            "Private key has no passphrase",
            "Anything running as you can read and use this key: a malicious npm \
             or pip package, a compromised editor extension, a stray script. \
             Import it into the vault, where it is encrypted at rest, and take \
             it off the disk."
                .into(),
        ));
    }

    if let Some(m) = mode {
        if m & 0o077 != 0 {
            findings.push(finding(
                "permissive-mode",
                "high",
                &format!("Readable beyond you ({:o})", m & 0o777),
                "Other accounts on this machine can read this key. OpenSSH \
                 refuses keys like this for exactly that reason. `chmod 600` it."
                    .into(),
            ));
        }
    }

    if algorithm.as_deref() == Some("dsa") {
        findings.push(finding(
            "dsa-key",
            "high",
            "DSA key",
            "DSA is fixed at 1024 bits, OpenSSH has refused it by default since \
             7.0, and OpenSSH 10 removed it entirely. This key almost certainly \
             no longer opens anything."
                .into(),
        ));
    }
    if algorithm.as_deref() == Some("rsa") && bits.is_some_and(|b| b < 2048) {
        findings.push(finding(
            "weak-rsa",
            "high",
            &format!("RSA key is only {} bits", bits.unwrap_or(0)),
            "Below 2048 bits an RSA key is doing less work than the ed25519 key \
             that would replace it. Generate a new one."
                .into(),
        ));
    }

    Some(KeyOnDisk {
        path: path.to_string(),
        format: format.to_string(),
        algorithm,
        bits,
        fingerprint,
        encrypted,
        comment,
        mode,
        modified,
        findings,
    })
}

/// Note which keys the vault already holds, and which nothing references.
///
/// Matching is by fingerprint, so it never compares private halves and works
/// even when the vault stores only the public key.
pub fn cross_reference(keys: &mut [KeyOnDisk], vault: &[Host], config_identities: &[String]) {
    let known: std::collections::HashSet<String> = vault
        .iter()
        .filter_map(|h| crate::audit::inspect(h).ok())
        .map(|f| f.fingerprint)
        .collect();

    // The same key saved under several names: rotating it means finding every
    // copy, and a copy you forgot is a copy that still opens the door.
    let mut seen: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    for key in keys.iter() {
        if let Some(fp) = &key.fingerprint {
            let name = Path::new(&key.path)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            seen.entry(fp.clone()).or_default().push(name);
        }
    }

    for key in keys.iter_mut() {
        if let Some(fp) = &key.fingerprint {
            let others: Vec<String> = seen
                .get(fp)
                .map(|names| {
                    let mine = Path::new(&key.path)
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string());
                    names
                        .iter()
                        .filter(|n| Some(*n) != mine.as_ref())
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();
            if !others.is_empty() {
                key.findings.push(finding(
                    "duplicate-key",
                    "medium",
                    "The same key is saved elsewhere too",
                    format!(
                        "Byte for byte the same key as {}. Rotating it means replacing every \
                         copy, and the one you forget still opens the door.",
                        others.join(", ")
                    ),
                ));
            }
        }

        let in_vault = key
            .fingerprint
            .as_deref()
            .is_some_and(|fp| known.contains(fp));
        // `~/.ssh/config` names paths, so compare on the filename rather than
        // the full path: `IdentityFile ~/.ssh/id_ed25519` and an absolute path
        // are the same key.
        let file_name = Path::new(&key.path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let referenced = config_identities.iter().any(|i| {
            Path::new(i)
                .file_name()
                .map(|n| n.to_string_lossy() == file_name)
                .unwrap_or(false)
        });

        if !in_vault {
            key.findings.push(finding(
                "not-in-vault",
                "medium",
                "Not in the vault",
                "Kino has no copy of this key, so it is protected only by the \
                 filesystem. Import it if you use it."
                    .into(),
            ));
        }
        if !in_vault && !referenced {
            key.findings.push(finding(
                "orphan-key",
                "low",
                "Nothing refers to this key",
                "It is not in the vault and no `~/.ssh/config` entry names it. \
                 It may be left over from a machine or a job that is gone."
                    .into(),
            ));
        }
    }
}

/// `ForwardAgent yes` set for every host is worth saying out loud: it lets any
/// box you land on use your keys for as long as you are connected.
pub fn config_findings(config_text: &str) -> Vec<crate::audit::Finding> {
    let mut in_global = true;
    for raw in config_text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let lower = line.to_lowercase();
        if lower.starts_with("host ") || lower.starts_with("match ") {
            in_global = lower.starts_with("host *") || lower == "host *";
            continue;
        }
        if in_global
            && lower
                .replace('=', " ")
                .split_whitespace()
                .eq(["forwardagent", "yes"])
        {
            return vec![finding(
                "agent-forwarding",
                "medium",
                "Agent forwarding is on for every host",
                "`ForwardAgent yes` without a Host restriction lets root on any \
                 server you connect to use your keys while you are logged in. \
                 Scope it to the hosts that need it."
                    .into(),
            )];
        }
    }
    Vec::new()
}

/// The identity files named anywhere in an ssh config.
pub fn identities_in_config(config_text: &str) -> Vec<String> {
    config_text
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| {
            let lower = l.to_lowercase();
            let rest = lower.strip_prefix("identityfile")?;
            let value = l[l.len() - rest.len()..].trim_start_matches(['=', ' ', '\t']);
            Some(value.trim().trim_matches('"').to_string())
        })
        .filter(|v| !v.is_empty())
        .collect()
}

// ── The filesystem half ─────────────────────────────────────────────────────

fn ssh_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".ssh"))
}

#[cfg(unix)]
fn file_facts(path: &Path) -> (Option<u32>, Option<i64>, u64) {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path) {
        Ok(m) => (
            Some(m.permissions().mode()),
            m.modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64),
            m.len(),
        ),
        Err(_) => (None, None, 0),
    }
}

#[cfg(not(unix))]
fn file_facts(path: &Path) -> (Option<u32>, Option<i64>, u64) {
    // Windows has an ACL, not a mode. Reporting a fabricated one would be
    // worse than reporting none; the permission finding simply does not fire.
    match std::fs::metadata(path) {
        Ok(m) => (
            None,
            m.modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64),
            m.len(),
        ),
        Err(_) => (None, None, 0),
    }
}

/// Walk one directory and the level below it, collecting anything that reads
/// like a private key.
fn scan_dir(dir: &Path, out: &mut Vec<KeyOnDisk>, depth: usize) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if depth > 0 {
                scan_dir(&path, out, depth - 1);
            }
            continue;
        }
        // `.pub` halves are not secrets and would double every row.
        if path.extension().is_some_and(|e| e == "pub") {
            continue;
        }
        let (mode, modified, len) = file_facts(&path);
        if len == 0 || len > MAX_KEY_BYTES {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue; // binary, or not ours to read
        };
        if let Some(key) = classify(&path.to_string_lossy(), &text, mode, modified) {
            out.push(key);
        }
    }
}

/// Sweep the standard location plus any extra directories the user named.
///
/// Detection deliberately does not need an unlocked vault - finding an
/// unencrypted key on disk is useful before you have typed anything. The
/// cross-reference against stored hosts is skipped when locked, and the report
/// says so by simply not raising "not in the vault".
#[tauri::command]
pub fn sweep_keys(
    state: tauri::State<'_, crate::AppState>,
    extra_dirs: Vec<String>,
) -> Result<SweepReport, String> {
    let mut dirs: Vec<PathBuf> = ssh_dir().into_iter().collect();
    dirs.extend(extra_dirs.iter().map(PathBuf::from));

    let mut keys = Vec::new();
    let mut scanned = Vec::new();
    for dir in &dirs {
        if dir.is_dir() {
            scanned.push(dir.to_string_lossy().to_string());
            scan_dir(dir, &mut keys, 1);
        }
    }

    let config_text = ssh_dir()
        .map(|d| d.join("config"))
        .and_then(|p| std::fs::read_to_string(p).ok())
        .unwrap_or_default();

    let unlocked = state.vault_key.lock().unwrap().is_some();
    if unlocked {
        let hosts = state.hosts.lock().unwrap().clone();
        cross_reference(&mut keys, &hosts, &identities_in_config(&config_text));
    }

    // Worst first: this list is read from the top and then acted on.
    let rank = |k: &KeyOnDisk| {
        k.findings
            .iter()
            .map(|f| match f.severity.as_str() {
                "critical" => 0,
                "high" => 1,
                "medium" => 2,
                _ => 3,
            })
            .min()
            .unwrap_or(4)
    };
    keys.sort_by_key(rank);

    let count = |sev: &str| {
        keys.iter()
            .flat_map(|k| &k.findings)
            .filter(|f| f.severity == sev)
            .count()
    };
    Ok(SweepReport {
        critical: count("critical"),
        high: count("high"),
        findings: config_findings(&config_text),
        keys,
        scanned,
    })
}

// ── Import, and then removal ────────────────────────────────────────────────
//
// Two commands, deliberately not one. Importing a key is ordinary vault work.
// Removing it from disk destroys the only other copy, and the gap between them
// is where the user gets to change their mind.

/// What an import did, so the panel can say it plainly.
#[derive(Serialize, Clone, Debug)]
pub struct ImportOutcome {
    pub host_id: String,
    pub host_name: String,
    pub fingerprint: String,
    /// True once the key has been read back out of the *saved* vault file.
    /// Removal is refused until this has happened.
    pub verified_in_saved_vault: bool,
}

/// Is this fingerprint in the vault as it exists on disk right now?
///
/// Reads the file rather than `AppState`, and that is the entire point. An
/// in-memory host proves the user pressed a button; the file proves the key
/// survived being written. Only the second is a safe basis for deleting the
/// copy the filesystem is holding.
fn fingerprint_in_saved_vault(key_bytes: &[u8; 32], fingerprint: &str) -> Result<bool, String> {
    let hosts: Vec<Host> = crate::vault::load_encrypted(&crate::vault::vault_path(), key_bytes)
        .map_err(|e| format!("Could not re-read the vault to verify the import: {e}"))?;
    Ok(hosts
        .iter()
        .filter_map(|h| crate::audit::inspect(h).ok())
        .any(|f| f.fingerprint == fingerprint))
}

/// Why a key must not be removed from disk yet. Empty means it may be.
///
/// Pure, so the rules can be read in one place and tested without a
/// filesystem. Every one of these is re-checked in `evict_key_from_disk`
/// itself: the panel calls this to decide what to offer, and the command does
/// not trust the panel.
pub fn eviction_blockers(
    parsed: bool,
    in_saved_vault: bool,
    config_references: bool,
    override_config: bool,
) -> Vec<&'static str> {
    let mut out = Vec::new();
    if !parsed {
        out.push(
            "Kino cannot read this key format, so it cannot prove it holds a copy.              Remove it yourself if you are sure.",
        );
    }
    if !in_saved_vault {
        out.push(
            "This key is not in the saved vault. Import it first - and the vault has to be              written to disk, not merely changed on screen.",
        );
    }
    if config_references && !override_config {
        out.push(
            "Your ~/.ssh/config names this key, so `ssh` on the command line will stop working              for those hosts.",
        );
    }
    out
}

/// Import a key file into the vault, then prove it landed.
///
/// The passphrase of an encrypted key is *not* asked for and *not* stored: the
/// encrypted key text goes into the vault as it is, so it keeps its own
/// protection on top of the vault's.
#[tauri::command]
pub fn import_key_from_disk(
    state: tauri::State<'_, crate::AppState>,
    path: String,
    host_id: Option<String>,
    name: String,
) -> Result<ImportOutcome, String> {
    let text = std::fs::read_to_string(&path).map_err(|e| format!("Cannot read {path}: {e}"))?;
    let parsed = PrivateKey::from_openssh(text.trim())
        .map_err(|e| format!("Kino cannot read this key format: {e}"))?;
    let fingerprint = parsed.public_key().fingerprint(HashAlg::Sha256).to_string();
    let public = parsed.public_key().to_openssh().unwrap_or_default();

    let key_guard = state.vault_key.lock().unwrap();
    let key = *key_guard.as_ref().ok_or("Vault is locked")?;
    let salt_guard = state.vault_salt.lock().unwrap();
    let salt = *salt_guard.as_ref().ok_or("Vault is locked")?;

    let (host_id, host_name) = {
        let mut hosts = state.hosts.lock().unwrap();
        match host_id.and_then(|id| hosts.iter_mut().find(|h| h.id == id)) {
            Some(existing) => {
                existing.private_key = Some(text.clone());
                existing.public_key = Some(public);
                existing.default_auth = "SshKey".into();
                existing.key_added_at = Some(now_secs());
                (existing.id.clone(), existing.name.clone())
            }
            None => {
                // Written out rather than `..Default::default()`: `Host` has
                // no `Default` on purpose, because one would hand out port 0.
                let host = Host {
                    id: uuid::Uuid::new_v4().to_string(),
                    name: name.clone(),
                    // Left blank for the user to fill in. A key on its own says
                    // nothing about which machine it opens, and inventing a
                    // hostname would be worse than an obvious gap.
                    hostname: String::new(),
                    port: 22,
                    username: String::new(),
                    default_auth: "SshKey".into(),
                    password: None,
                    private_key: Some(text.clone()),
                    public_key: Some(public),
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
                    key_added_at: Some(now_secs()),
                    ntfy_topic: None,
                    environment: None,
                };
                let pair = (host.id.clone(), host.name.clone());
                hosts.push(host);
                pair
            }
        }
    };

    {
        let hosts = state.hosts.lock().unwrap();
        crate::vault::save_vault(&hosts, &key, &salt)?;
    }

    Ok(ImportOutcome {
        verified_in_saved_vault: fingerprint_in_saved_vault(&key, &fingerprint)?,
        host_id,
        host_name,
        fingerprint,
    })
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Overwrite a file's bytes, then unlink it.
///
/// The overwrite is worth doing and is not a guarantee. On a copy-on-write or
/// journalling filesystem, on anything with a flash translation layer, and on
/// any snapshotted volume, the old blocks may still exist somewhere this
/// process cannot reach. The UI says so; so does this comment, because the
/// next person to read it deserves to know what it is really buying.
fn overwrite_and_remove(path: &Path) -> Result<(), String> {
    use std::io::Write;
    let len = std::fs::metadata(path)
        .map_err(|e| format!("Cannot stat {}: {e}", path.display()))?
        .len()
        .min(MAX_KEY_BYTES) as usize;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|e| format!("Cannot open {} for overwriting: {e}", path.display()))?;
    file.write_all(&vec![0u8; len])
        .map_err(|e| format!("Overwrite failed, so nothing was deleted: {e}"))?;
    file.sync_all()
        .map_err(|e| format!("Overwrite could not be flushed, so nothing was deleted: {e}"))?;
    drop(file);

    std::fs::remove_file(path).map_err(|e| format!("Could not remove {}: {e}", path.display()))
}

/// Remove a key from disk, once every precondition holds.
///
/// Re-checks all of them here rather than trusting whatever the panel decided,
/// and re-reads the vault file to confirm the key really is stored. The order
/// matters: prove the copy exists, then destroy the original. Never the other
/// way round - the same rule key rotation follows.
#[tauri::command]
pub fn evict_key_from_disk(
    state: tauri::State<'_, crate::AppState>,
    path: String,
    override_config: bool,
) -> Result<String, String> {
    let key_guard = state.vault_key.lock().unwrap();
    let key = *key_guard.as_ref().ok_or("Vault is locked")?;

    let text = std::fs::read_to_string(&path).map_err(|e| format!("Cannot read {path}: {e}"))?;
    let parsed = PrivateKey::from_openssh(text.trim()).ok();
    let fingerprint = parsed
        .as_ref()
        .map(|k| k.public_key().fingerprint(HashAlg::Sha256).to_string());

    let in_saved_vault = match &fingerprint {
        Some(fp) => fingerprint_in_saved_vault(&key, fp)?,
        None => false,
    };

    let config_text = ssh_dir()
        .map(|d| d.join("config"))
        .and_then(|p| std::fs::read_to_string(p).ok())
        .unwrap_or_default();
    let file_name = Path::new(&path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let referenced = identities_in_config(&config_text).iter().any(|i| {
        Path::new(i)
            .file_name()
            .map(|n| n.to_string_lossy() == file_name)
            .unwrap_or(false)
    });

    let blockers = eviction_blockers(
        fingerprint.is_some(),
        in_saved_vault,
        referenced,
        override_config,
    );
    if !blockers.is_empty() {
        return Err(blockers.join(" "));
    }

    overwrite_and_remove(Path::new(&path))?;
    Ok(format!(
        "{file_name} was overwritten and deleted. The vault's copy is the only one now - \
         write it back from Vault keys if you need the file again."
    ))
}

/// Create a file that is private from the moment it exists.
///
/// The obvious version - write it, then `chmod 600` - leaves a window in which
/// the key sits on disk readable by everyone on the machine. It is a short
/// window, and a key only has to be read once. So the mode goes on in the
/// `open` call, before any bytes are written.
///
/// On Windows the file inherits the directory's ACL; there is no mode to set,
/// and pretending otherwise would be worse than saying so.
fn create_private(path: &Path) -> Result<std::fs::File, String> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            format!(
                "{} already exists. Kino will not overwrite a key file - move it aside first.",
                path.display()
            )
        } else {
            format!("Cannot create {}: {e}", path.display())
        }
    })
}

/// Write a vault key back out to disk.
///
/// This is what makes removing a key from disk a decision rather than a
/// one-way door: whatever was evicted can be written back when `ssh` on the
/// command line turns out to need it. It refuses to overwrite anything, so it
/// cannot be the thing that destroys a key.
#[tauri::command]
pub fn export_key_to_disk(
    state: tauri::State<'_, crate::AppState>,
    host_id: String,
    path: String,
    include_public: bool,
) -> Result<String, String> {
    use std::io::Write;

    let (private, public, name) = {
        let hosts = state.hosts.lock().unwrap();
        let host = hosts
            .iter()
            .find(|h| h.id == host_id)
            .ok_or("That host is no longer in the vault")?;
        let private = host
            .private_key
            .clone()
            .filter(|k| !k.trim().is_empty())
            .ok_or_else(|| format!("'{}' has no private key stored", host.name))?;
        (private, host.public_key.clone(), host.name.clone())
    };

    let target = Path::new(&path);
    let mut file = create_private(target)?;
    file.write_all(private.as_bytes())
        .map_err(|e| format!("Could not write the key: {e}"))?;
    if !private.ends_with('\n') {
        let _ = file.write_all(b"\n");
    }
    file.sync_all()
        .map_err(|e| format!("Could not flush the key to disk: {e}"))?;

    let mut wrote = 1;
    if include_public {
        if let Some(pub_text) = public.filter(|p| !p.trim().is_empty()) {
            let pub_path = target.with_extension("pub");
            // A public key is not a secret, so an existing one is not worth
            // failing the whole export over.
            if let Ok(mut f) = std::fs::File::create(&pub_path) {
                let _ = f.write_all(pub_text.trim_end().as_bytes());
                let _ = f.write_all(b"\n");
                wrote += 1;
            }
        }
    }

    Ok(format!(
        "Wrote {} file{} for '{}' to {}{}",
        wrote,
        if wrote == 1 { "" } else { "s" },
        name,
        path,
        if cfg!(unix) { " (mode 600)" } else { "" }
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generated once with `ssh-keygen -t ed25519 -N ""`, then edited to be
    /// obviously fake. It parses; it opens nothing.
    const ED25519_PLAIN: &str =
        "-----BEGIN OPENSSH PRIVATE KEY-----\nnot-a-real-key\n-----END OPENSSH PRIVATE KEY-----\n";

    fn ids(k: &KeyOnDisk) -> Vec<&str> {
        k.findings.iter().map(|f| f.id.as_str()).collect()
    }

    /// Against a real `~/.ssh` rather than only the strings in this file,
    /// because the neighbours of a key - `known_hosts`, a `config`, a `.pub` -
    /// are exactly what a sniff test gets wrong, and no fixture I write will
    /// surprise me the way a real directory does.
    ///
    /// Prints paths and findings only. No key material is read out.
    ///
    ///     cargo test --lib key_sweep -- --ignored --nocapture
    #[test]
    #[ignore = "reads the real ~/.ssh on this machine"]
    fn sweeps_the_real_ssh_directory() {
        let dir = ssh_dir().expect("no home directory");
        let mut keys = Vec::new();
        scan_dir(&dir, &mut keys, 1);

        let config = std::fs::read_to_string(dir.join("config")).unwrap_or_default();
        cross_reference(&mut keys, &[], &identities_in_config(&config));

        println!("scanned {}", dir.display());
        for k in &keys {
            let name = Path::new(&k.path).file_name().unwrap().to_string_lossy();
            println!(
                "  {name}  [{}] {} {}",
                k.format,
                k.algorithm.as_deref().unwrap_or("?"),
                if k.encrypted {
                    "encrypted"
                } else {
                    "PLAINTEXT"
                }
            );
            for f in &k.findings {
                println!("      [{}] {}", f.severity, f.title);
            }
        }
        for f in config_findings(&config) {
            println!("  config: [{}] {}", f.severity, f.title);
        }

        // The point of the test: the things that are not keys stay out.
        for k in &keys {
            let name = Path::new(&k.path).file_name().unwrap().to_string_lossy();
            assert!(!name.starts_with("known_hosts"), "picked up {name}");
            assert!(!name.ends_with(".pub"), "picked up {name}");
            assert_ne!(name, "config", "picked up the ssh config as a key");
        }
    }

    #[test]
    fn the_bytes_are_gone_before_the_file_is() {
        // A hard link survives the unlink, so it can be read afterwards to see
        // what was actually written. Asserting "the file is gone" alone would
        // pass even if the overwrite silently did nothing.
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("id_ed25519");
        let witness = dir.path().join("same_inode");
        std::fs::write(&key, b"-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n").unwrap();
        std::fs::hard_link(&key, &witness).unwrap();

        overwrite_and_remove(&key).unwrap();

        assert!(!key.exists(), "the file should be gone");
        let left = std::fs::read(&witness).unwrap();
        assert!(
            left.iter().all(|b| *b == 0),
            "bytes survived the overwrite: {:?}",
            String::from_utf8_lossy(&left)
        );
        assert!(
            !left.is_empty(),
            "the file should have been overwritten, not truncated"
        );
    }

    #[test]
    fn removing_something_that_is_not_there_is_an_error_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        assert!(overwrite_and_remove(&dir.path().join("gone")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn an_exported_key_is_private_from_the_moment_it_exists() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id_ed25519");
        let file = create_private(&path).unwrap();
        // Checked before a single byte is written: writing first and chmodding
        // after would leave the key readable in between.
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "created as {mode:o}");
        drop(file);
    }

    #[test]
    fn exporting_never_overwrites_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id_ed25519");
        std::fs::write(&path, b"something already here").unwrap();

        let err = create_private(&path).unwrap_err();
        assert!(err.contains("already exists"), "{err}");
        // And the original is untouched.
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "something already here"
        );
    }

    // ── The rules that stand between a key and its deletion ────────────────
    //
    // These are the only tests here that guard something irreversible, so they
    // enumerate rather than sample: every combination that must refuse, and
    // the single combination that may proceed.

    #[test]
    fn nothing_is_deleted_unless_the_vault_provably_has_it() {
        // parsed, in_saved_vault, config_references, override_config
        assert!(!eviction_blockers(true, false, false, false).is_empty());
        assert!(!eviction_blockers(false, false, false, false).is_empty());
        // Parsing but absent from the saved vault is the dangerous near-miss:
        // the host may exist on screen and never have been written.
        let why = eviction_blockers(true, false, false, false);
        assert!(why[0].contains("not in the saved vault"), "{why:?}");
        assert!(why[0].contains("written to disk"), "{why:?}");
    }

    #[test]
    fn a_key_kino_cannot_read_is_never_deleted() {
        // No fingerprint means no proof of a copy, whatever else is true.
        let why = eviction_blockers(false, true, false, true);
        assert!(!why.is_empty());
        assert!(why[0].contains("cannot read this key format"), "{why:?}");
    }

    #[test]
    fn an_ssh_config_reference_blocks_until_it_is_overridden() {
        assert!(!eviction_blockers(true, true, true, false).is_empty());
        // Overriding is allowed, because `ssh` on the command line is the
        // user's business - but it has to be said out loud.
        assert!(eviction_blockers(true, true, true, true).is_empty());
    }

    #[test]
    fn the_only_way_through_is_every_precondition_at_once() {
        assert!(eviction_blockers(true, true, false, false).is_empty());

        // Exhaustive: any single failure refuses.
        for (parsed, saved, refd, over) in [
            (false, true, false, false),
            (true, false, false, false),
            (true, true, true, false),
        ] {
            assert!(
                !eviction_blockers(parsed, saved, refd, over).is_empty(),
                "({parsed}, {saved}, {refd}, {over}) should refuse"
            );
        }
    }

    /// The destructive path, on the real filesystem, in the real directory -
    /// same permissions, same mount, same everything the code will meet in
    /// use. It creates its own key and destroys only that; nothing already in
    /// `~/.ssh` is touched.
    ///
    ///     cargo test --lib key_sweep -- --ignored --nocapture
    #[test]
    #[ignore = "writes and deletes a throwaway key inside the real ~/.ssh"]
    fn removes_a_key_from_the_real_ssh_directory() {
        let dir = ssh_dir().expect("no home directory");
        let key = dir.join("kino_selftest_key");
        let witness = dir.join("kino_selftest_witness");
        let _ = std::fs::remove_file(&key);
        let _ = std::fs::remove_file(&witness);

        std::fs::write(&key, b"-----BEGIN OPENSSH PRIVATE KEY-----\npretend\n").unwrap();
        std::fs::hard_link(&key, &witness).unwrap();
        println!("created {}", key.display());

        overwrite_and_remove(&key).unwrap();

        assert!(!key.exists(), "{} should be gone", key.display());
        let left = std::fs::read(&witness).unwrap();
        assert!(left.iter().all(|b| *b == 0), "bytes survived: {left:?}");
        println!("deleted it; {} bytes were zeroed first", left.len());

        std::fs::remove_file(&witness).unwrap();
        // And the sweep no longer reports it.
        let mut found = Vec::new();
        scan_dir(&dir, &mut found, 1);
        assert!(
            !found.iter().any(|k| k.path.contains("kino_selftest")),
            "the sweep still lists the deleted key"
        );
        println!("the sweep no longer lists it");
    }

    #[test]
    fn recognises_the_shapes_that_are_keys() {
        assert!(looks_like_a_key("-----BEGIN OPENSSH PRIVATE KEY-----"));
        assert!(looks_like_a_key("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(looks_like_a_key("-----BEGIN ENCRYPTED PRIVATE KEY-----"));
        assert!(looks_like_a_key("PuTTY-User-Key-File-2: ssh-rsa"));
    }

    #[test]
    fn ignores_the_shapes_that_are_not() {
        // The neighbours of a key in ~/.ssh, none of which are secrets.
        assert!(!looks_like_a_key("ssh-ed25519 AAAAC3Nza… me@box"));
        assert!(!looks_like_a_key("github.com ssh-rsa AAAAB3Nz…"));
        assert!(!looks_like_a_key("Host prod\n  User root\n"));
        assert!(!looks_like_a_key("-----BEGIN CERTIFICATE-----"));
        assert!(!looks_like_a_key(""));
    }

    #[test]
    fn a_key_with_no_passphrase_is_critical() {
        let k = classify("/home/me/.ssh/id_ed25519", ED25519_PLAIN, Some(0o600), None).unwrap();
        assert!(!k.encrypted);
        assert!(ids(&k).contains(&"unencrypted-key"));
        assert_eq!(k.findings[0].severity, "critical");
    }

    #[test]
    fn an_encrypted_key_is_not_flagged_for_it() {
        let text =
            "-----BEGIN OPENSSH PRIVATE KEY-----\nENCRYPTED\n-----END OPENSSH PRIVATE KEY-----\n";
        let k = classify("/home/me/.ssh/id_rsa", text, Some(0o600), None).unwrap();
        assert!(k.encrypted);
        assert!(!ids(&k).contains(&"unencrypted-key"));
    }

    #[test]
    fn permissions_wider_than_the_owner_are_flagged() {
        for mode in [0o644, 0o640, 0o604, 0o777] {
            let k = classify("/k", ED25519_PLAIN, Some(mode), None).unwrap();
            assert!(ids(&k).contains(&"permissive-mode"), "mode {mode:o}");
        }
        for mode in [0o600, 0o400] {
            let k = classify("/k", ED25519_PLAIN, Some(mode), None).unwrap();
            assert!(!ids(&k).contains(&"permissive-mode"), "mode {mode:o}");
        }
    }

    #[test]
    fn no_mode_means_no_permission_finding_rather_than_a_guess() {
        // Windows. An invented mode would be worse than none.
        let k = classify("/k", ED25519_PLAIN, None, None).unwrap();
        assert!(!ids(&k).contains(&"permissive-mode"));
    }

    #[test]
    fn formats_are_told_apart() {
        assert_eq!(format_of("-----BEGIN OPENSSH PRIVATE KEY-----"), "openssh");
        assert_eq!(format_of("-----BEGIN PRIVATE KEY-----"), "pkcs8");
        assert_eq!(format_of("-----BEGIN ENCRYPTED PRIVATE KEY-----"), "pkcs8");
        assert_eq!(format_of("-----BEGIN RSA PRIVATE KEY-----"), "pem");
        assert_eq!(format_of("PuTTY-User-Key-File-3: ssh-ed25519"), "ppk");
    }

    #[test]
    fn a_ppk_is_described_as_far_as_it_can_be() {
        // Not a format `ssh-key` reads. Reporting "ppk, unknown algorithm" is
        // the honest answer; inventing one would not be.
        let text = "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: aes256-cbc\n";
        let k = classify("/home/me/.ssh/key.ppk", text, Some(0o600), None).unwrap();
        assert_eq!(k.format, "ppk");
        assert_eq!(k.algorithm, None);
        assert!(k.encrypted, "the Encryption line says so");
        assert!(!ids(&k).contains(&"unencrypted-key"));
    }

    #[test]
    fn identity_files_come_out_of_a_config() {
        let cfg = "Host prod\n  IdentityFile ~/.ssh/prod_ed25519\n\nHost dev\n  IdentityFile=/home/me/.ssh/dev\n# IdentityFile ~/.ssh/commented\n";
        let ids = identities_in_config(cfg);
        assert_eq!(ids, vec!["~/.ssh/prod_ed25519", "/home/me/.ssh/dev"]);
    }

    #[test]
    fn global_agent_forwarding_is_reported() {
        assert_eq!(config_findings("ForwardAgent yes\n").len(), 1);
        assert_eq!(config_findings("Host *\n  ForwardAgent yes\n").len(), 1);
        // Scoped to one host is a choice, not a finding.
        assert!(config_findings("Host bastion\n  ForwardAgent yes\n").is_empty());
        assert!(config_findings("ForwardAgent no\n").is_empty());
        assert!(config_findings("").is_empty());
    }

    #[test]
    fn the_same_key_under_two_names_is_reported_on_both() {
        let mut keys = vec![
            classify("/home/me/.ssh/work", ED25519_PLAIN, Some(0o600), None).unwrap(),
            classify(
                "/home/me/.ssh/backup_of_work",
                ED25519_PLAIN,
                Some(0o600),
                None,
            )
            .unwrap(),
        ];
        // Fingerprints only exist for keys that parse; give both the same one.
        keys[0].fingerprint = Some("SHA256:same".into());
        keys[1].fingerprint = Some("SHA256:same".into());
        cross_reference(&mut keys, &[], &[]);

        for (i, other) in [(0, "backup_of_work"), (1, "work")] {
            let f = keys[i]
                .findings
                .iter()
                .find(|f| f.id == "duplicate-key")
                .unwrap();
            assert!(f.detail.contains(other), "{}", f.detail);
        }
    }

    #[test]
    fn a_key_that_is_only_in_one_place_is_not_a_duplicate() {
        let mut keys =
            vec![classify("/home/me/.ssh/only", ED25519_PLAIN, Some(0o600), None).unwrap()];
        keys[0].fingerprint = Some("SHA256:unique".into());
        cross_reference(&mut keys, &[], &[]);
        assert!(!ids(&keys[0]).contains(&"duplicate-key"));
    }

    #[test]
    fn a_key_nothing_refers_to_is_an_orphan() {
        let mut keys =
            vec![classify("/home/me/.ssh/old_key", ED25519_PLAIN, Some(0o600), None).unwrap()];
        cross_reference(&mut keys, &[], &["~/.ssh/current".into()]);
        assert!(ids(&keys[0]).contains(&"not-in-vault"));
        assert!(ids(&keys[0]).contains(&"orphan-key"));
    }

    #[test]
    fn a_key_the_config_names_is_not_an_orphan() {
        let mut keys =
            vec![classify("/home/me/.ssh/prod", ED25519_PLAIN, Some(0o600), None).unwrap()];
        // Matched on the file name, so `~` and an absolute path agree.
        cross_reference(&mut keys, &[], &["~/.ssh/prod".into()]);
        assert!(ids(&keys[0]).contains(&"not-in-vault"));
        assert!(!ids(&keys[0]).contains(&"orphan-key"));
    }
}
