//! Key hygiene: what's in the vault, and rotating it without locking anyone out.
//!
//! The audit is entirely local - it reads the keys already in the vault and says
//! what they are. Nothing is sent anywhere and no host is contacted.
//!
//! Rotation is the part that can hurt. The order below is the whole design:
//!
//! 1. generate a new ed25519 pair
//! 2. append the new public key to the host's `authorized_keys`
//! 3. **open a fresh connection that can only authenticate with the new key**
//! 4. only then remove the old key
//! 5. only then write the new key into the vault
//!
//! Every failure before step 3 leaves the host exactly as it was. A failure at
//! step 3 leaves an extra, unused public key on the host and changes nothing
//! else - untidy, harmless, and reported. The one ordering that must never
//! happen is removing the old key before proving the new one works, which is
//! why step 3 exists at all rather than trusting that step 2 succeeded.

use serde::Serialize;
use ssh_key::{HashAlg, PrivateKey, PublicKey};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter};

use crate::vault::Host;

/// Below this, an RSA key is doing less work than the ed25519 key we'd replace
/// it with. 2048 is still respectable; NIST's floor, and where "fine, but" ends.
const RSA_WEAK: u32 = 2048;
const RSA_ADVISORY: u32 = 3072;

/// A key older than this is worth a look. Not a rule - a prompt.
const STALE_DAYS: i64 = 365;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ── Model ─────────────────────────────────────────────────────────────────────

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Finding {
    /// Stable id, for the UI to key off: "weak-rsa", "reused-key", …
    pub id: String,
    /// "high" | "medium" | "low". Ordering only; nothing branches on it.
    pub severity: String,
    pub title: String,
    pub detail: String,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct KeyFacts {
    /// "ed25519", "rsa", "ecdsa (nistp256)", "dsa".
    pub algorithm: String,
    /// Only meaningful for RSA/DSA; the others are fixed by their curve.
    pub bits: Option<u32>,
    /// `SHA256:…`, the same string `ssh-keygen -lf` prints.
    pub fingerprint: String,
    /// The stored private key is passphrase-protected.
    pub encrypted: bool,
}

#[derive(Serialize, Clone, Debug)]
pub struct HostAudit {
    pub host_id: String,
    pub host_name: String,
    /// "SshKey" | "Password" | "Agent".
    pub auth: String,
    /// `None` when the host has no key, or one that couldn't be read.
    pub key: Option<KeyFacts>,
    pub key_added_at: Option<i64>,
    /// Names of the other hosts sharing this key, if any.
    pub shared_with: Vec<String>,
    pub findings: Vec<Finding>,
}

#[derive(Serialize, Clone, Debug)]
pub struct AuditReport {
    pub hosts: Vec<HostAudit>,
    pub generated_at: i64,
    /// Counts by severity across every host, for the summary line.
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

// ── Inspection ────────────────────────────────────────────────────────────────

pub(crate) fn describe_algorithm(key: &PublicKey) -> (String, Option<u32>) {
    use ssh_key::Algorithm;
    match key.algorithm() {
        Algorithm::Ed25519 => ("ed25519".into(), None),
        Algorithm::Rsa { .. } => ("rsa".into(), rsa_bits(key)),
        Algorithm::Dsa => ("dsa".into(), Some(1024)),
        Algorithm::Ecdsa { curve } => (format!("ecdsa ({})", curve.as_str()), None),
        Algorithm::SkEd25519 => ("ed25519-sk".into(), None),
        Algorithm::SkEcdsaSha2NistP256 => ("ecdsa-sk (nistp256)".into(), None),
        other => (other.as_str().to_string(), None),
    }
}

/// Modulus length in bits. `as_positive_bytes` drops the sign padding byte that
/// would otherwise report a 2048-bit key as 2056.
pub(crate) fn rsa_bits(key: &PublicKey) -> Option<u32> {
    let rsa = key.key_data().rsa()?;
    let bytes = rsa.n.as_positive_bytes()?;
    Some((bytes.len() * 8) as u32)
}

/// Read whatever the vault holds for this host: the public key if it's stored,
/// otherwise the public half of the private key (which OpenSSH keeps in
/// cleartext even when the private half is encrypted).
pub fn inspect(host: &Host) -> Result<KeyFacts, String> {
    let mut encrypted = false;
    let public = match host.public_key.as_deref().map(str::trim) {
        Some(text) if !text.is_empty() => {
            PublicKey::from_openssh(text).map_err(|e| format!("public key: {e}"))?
        }
        _ => {
            let text = host
                .private_key
                .as_deref()
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .ok_or("no key stored")?;
            let private =
                PrivateKey::from_openssh(text).map_err(|e| format!("private key: {e}"))?;
            encrypted = private.is_encrypted();
            private.public_key().clone()
        }
    };

    // The public key alone can't say whether the private half has a passphrase.
    if !encrypted {
        if let Some(text) = host.private_key.as_deref().map(str::trim) {
            if !text.is_empty() {
                if let Ok(private) = PrivateKey::from_openssh(text) {
                    encrypted = private.is_encrypted();
                }
            }
        }
    }

    let (algorithm, bits) = describe_algorithm(&public);
    Ok(KeyFacts {
        algorithm,
        bits,
        fingerprint: public.fingerprint(HashAlg::Sha256).to_string(),
        encrypted,
    })
}

fn finding(id: &str, severity: &str, title: &str, detail: String) -> Finding {
    Finding {
        id: id.into(),
        severity: severity.into(),
        title: title.into(),
        detail,
    }
}

fn algorithm_findings(facts: &KeyFacts) -> Vec<Finding> {
    let mut out = Vec::new();
    if facts.algorithm == "dsa" {
        out.push(finding(
            "dsa-key",
            "high",
            "DSA key",
            "DSA is fixed at 1024 bits and OpenSSH has refused it by default \
             since version 7.0. This key most likely no longer works at all."
                .into(),
        ));
    }
    if facts.algorithm == "rsa" {
        match facts.bits {
            Some(bits) if bits < RSA_WEAK => out.push(finding(
                "weak-rsa",
                "high",
                "Undersized RSA key",
                format!("{bits}-bit RSA is below the {RSA_WEAK}-bit floor and should be replaced."),
            )),
            Some(bits) if bits < RSA_ADVISORY => out.push(finding(
                "small-rsa",
                "low",
                "Ageing RSA key",
                format!(
                    "{bits}-bit RSA is still sound, but an ed25519 key is smaller, faster \
                     and the modern default."
                ),
            )),
            _ => {}
        }
    }
    if facts.algorithm.starts_with("ecdsa") && !facts.algorithm.contains("-sk") {
        out.push(finding(
            "nist-ecdsa",
            "low",
            "NIST-curve key",
            "ECDSA on a NIST curve works, but it depends on the quality of its \
             random nonce in a way ed25519 does not."
                .into(),
        ));
    }
    out
}

fn age_findings(added_at: Option<i64>, now: i64) -> Vec<Finding> {
    match added_at {
        Some(ts) => {
            let days = (now - ts) / 86_400;
            if days >= STALE_DAYS {
                vec![finding(
                    "stale-key",
                    "medium",
                    "Key is over a year old",
                    format!("Generated {days} days ago and not rotated since."),
                )]
            } else {
                Vec::new()
            }
        }
        None => vec![finding(
            "age-unknown",
            "low",
            "Age unknown",
            "This key predates Kino recording when keys were created. Rotating it \
             starts the clock."
                .into(),
        )],
    }
}

/// Audit a set of hosts. Pure - takes the clock so it can be tested.
pub fn audit_hosts(hosts: &[Host], now: i64) -> AuditReport {
    // Group by fingerprint first: reuse is a property of the set, not of a key.
    // Keyed by id, not name - two hosts may legitimately share a name, and
    // filtering the owner out by name would cancel a real finding.
    let mut by_fingerprint: HashMap<String, Vec<(String, String)>> = HashMap::new();
    let mut facts_by_host: HashMap<String, Result<KeyFacts, String>> = HashMap::new();

    for host in hosts {
        let facts = inspect(host);
        if let Ok(f) = &facts {
            by_fingerprint
                .entry(f.fingerprint.clone())
                .or_default()
                .push((host.id.clone(), host.name.clone()));
        }
        facts_by_host.insert(host.id.clone(), facts);
    }

    let mut out = Vec::with_capacity(hosts.len());
    for host in hosts {
        let mut findings = Vec::new();
        let mut shared_with = Vec::new();
        let facts = facts_by_host.get(&host.id).unwrap();

        let key = match facts {
            Ok(f) => {
                findings.extend(algorithm_findings(f));
                findings.extend(age_findings(host.key_added_at, now));

                let sharers: Vec<String> = by_fingerprint
                    .get(&f.fingerprint)
                    .map(|owners| {
                        owners
                            .iter()
                            .filter(|(id, _)| *id != host.id)
                            .map(|(_, name)| name.clone())
                            .collect()
                    })
                    .unwrap_or_default();
                if !sharers.is_empty() {
                    // One key on many hosts means one compromise reaches all of
                    // them, and no way to revoke access to just one.
                    let severity = if sharers.len() >= 4 { "high" } else { "medium" };
                    findings.push(finding(
                        "reused-key",
                        severity,
                        "Key is reused",
                        format!(
                            "The same key authenticates {} other host{}: {}. Losing it loses \
                             all of them at once, and revoking it revokes all of them at once.",
                            sharers.len(),
                            if sharers.len() == 1 { "" } else { "s" },
                            sharers.join(", ")
                        ),
                    ));
                }
                shared_with = sharers;
                Some(f.clone())
            }
            Err(e) if e == "no key stored" => {
                if host.default_auth == "Password" {
                    findings.push(finding(
                        "password-auth",
                        "medium",
                        "Password authentication",
                        "This host has no key. A password is replayable and can be \
                         brute-forced; rotating installs a key and switches to it."
                            .into(),
                    ));
                }
                None
            }
            Err(e) => {
                findings.push(finding(
                    "unreadable-key",
                    "high",
                    "Key can't be read",
                    format!("The stored key didn't parse ({e}), so connecting with it will fail."),
                ));
                None
            }
        };

        // High first - the list is read top down and acted on in that order.
        findings.sort_by_key(|f| match f.severity.as_str() {
            "high" => 0,
            "medium" => 1,
            _ => 2,
        });

        out.push(HostAudit {
            host_id: host.id.clone(),
            host_name: host.name.clone(),
            auth: host.default_auth.clone(),
            key,
            key_added_at: host.key_added_at,
            shared_with,
            findings,
        });
    }

    let count = |sev: &str| {
        out.iter()
            .flat_map(|h| &h.findings)
            .filter(|f| f.severity == sev)
            .count()
    };
    AuditReport {
        generated_at: now,
        high: count("high"),
        medium: count("medium"),
        low: count("low"),
        hosts: out,
    }
}

#[tauri::command]
pub fn audit_keys(state: tauri::State<'_, crate::AppState>) -> Result<AuditReport, String> {
    if state.vault_key.lock().unwrap().is_none() {
        return Err("Vault is locked".to_string());
    }
    let hosts = state.hosts.lock().unwrap().clone();
    Ok(audit_hosts(&hosts, now()))
}

// ── Rotation ──────────────────────────────────────────────────────────────────

#[derive(Serialize, Clone, Debug)]
pub struct RotateOutcome {
    pub fingerprint: String,
    /// False when the old key couldn't be identified or removed. The new key
    /// works either way; this says whether the old one is really gone.
    pub old_key_removed: bool,
    /// Human-readable note when `old_key_removed` is false.
    pub note: Option<String>,
}

/// The base64 blob from an OpenSSH public key line - the part that identifies
/// the key regardless of what comment is tacked on the end.
fn key_blob(public_key: &str) -> Option<String> {
    let blob = public_key.split_whitespace().nth(1)?;
    let ok = !blob.is_empty()
        && blob
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=');
    ok.then(|| blob.to_string())
}

/// Remove every line carrying `old_blob`, but only if `new_blob` survives.
///
/// The file is rewritten through `cat`, not `mv`, so its mode and ownership are
/// the ones sshd already accepted. Both blobs are base64 and validated by
/// `key_blob`, so neither can escape the quoting.
fn remove_key_command(old_blob: &str, new_blob: &str) -> String {
    format!(
        "f=\"$HOME/.ssh/authorized_keys\"; \
         [ -f \"$f\" ] || {{ echo KINO_NOFILE >&2; exit 7; }}; \
         tmp=\"${{TMPDIR:-/tmp}}/kino-ak.$$\"; \
         grep -v '{old}' \"$f\" > \"$tmp\"; \
         if ! grep -q '{new}' \"$tmp\"; then rm -f \"$tmp\"; echo KINO_NEWKEY_MISSING >&2; exit 8; fi; \
         cat \"$tmp\" > \"$f\"; rc=$?; rm -f \"$tmp\"; exit $rc",
        old = old_blob,
        new = new_blob,
    )
}

/// Attach the resolved bastion chain a host needs to be reachable.
///
/// A stored host references its bastion by id; only `jump` - the resolved hop -
/// makes `connect_to_host` tunnel. The interactive path resolves this in the
/// frontend before every connect, but rotation reads hosts straight out of the
/// vault, so it has to do the same or a bastion-only host is simply unreachable.
/// Cycles and dangling references end the chain rather than looping.
fn with_resolved_jump(host: &Host, all: &[Host]) -> Host {
    let mut chain: Vec<Host> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    seen.insert(host.id.clone());

    let mut current = host.clone();
    while let Some(id) = current
        .jump_host
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let Some(next) = all.iter().find(|h| h.id == id) else {
            break;
        };
        if !seen.insert(next.id.clone()) {
            break;
        }
        chain.push(next.clone());
        current = next.clone();
    }

    // Rebuild from the far end inwards so each hop carries the one beyond it.
    let mut resolved: Option<Box<Host>> = None;
    for mut hop in chain.into_iter().rev() {
        hop.jump = resolved;
        resolved = Some(Box::new(hop));
    }
    let mut out = host.clone();
    out.jump = resolved;
    out
}

fn step(app: &AppHandle, host_id: &str, message: &str) {
    let _ = app.emit(&format!("rotate-{}", host_id), message);
}

/// Generate a fresh ed25519 key for a host, install it, prove it works, and only
/// then retire the old one. See the module docs for why the order is what it is.
#[tauri::command]
pub async fn rotate_key(
    app: AppHandle,
    state: tauri::State<'_, crate::AppState>,
    host_id: String,
) -> Result<RotateOutcome, String> {
    let host = {
        let hosts = state.hosts.lock().unwrap();
        let host = hosts
            .iter()
            .find(|h| h.id == host_id)
            .ok_or("No such host")?;
        with_resolved_jump(host, &hosts)
    };
    if host.connection_mode.as_deref() == Some("agent") {
        return Err("Rotation isn't supported for relay/agent hosts yet".to_string());
    }

    step(&app, &host_id, "Generating a new ed25519 key");
    let pair = crate::keygen::generate_ed25519()?;
    let new_blob = key_blob(&pair.public_key).ok_or("Generated an unreadable public key")?;

    step(&app, &host_id, "Installing the new key on the host");
    crate::install_public_key(host.clone(), pair.public_key.clone()).await?;

    // The proof. A host that authenticates only with the new key - if this
    // succeeds, the new key is genuinely accepted by sshd, which is the one
    // thing that must be true before the old key can go.
    step(&app, &host_id, "Checking the new key authenticates");
    let mut probe = host.clone();
    probe.default_auth = "SshKey".to_string();
    probe.private_key = Some(pair.private_key.clone());
    probe.public_key = Some(pair.public_key.clone());
    probe.passphrase = None;
    crate::ssh_session::exec_once(&probe, "true")
        .await
        .map_err(|e| {
            format!(
                "The new key was added to the host but doesn't authenticate ({e}). \
                 Nothing else was changed - the old key still works. You may want to \
                 remove the unused key from ~/.ssh/authorized_keys."
            )
        })?;

    // From here the host is reachable with the new key no matter what fails.
    let mut old_key_removed = false;
    let mut note = None;

    let old_public = host.public_key.clone().or_else(|| {
        host.private_key
            .as_deref()
            .and_then(|t| PrivateKey::from_openssh(t.trim()).ok())
            .and_then(|k| k.public_key().to_openssh().ok())
    });

    match old_public.as_deref().and_then(key_blob) {
        Some(old_blob) if old_blob != new_blob => {
            step(&app, &host_id, "Removing the old key");
            match crate::ssh_session::exec_once(&probe, &remove_key_command(&old_blob, &new_blob))
                .await
            {
                Ok(_) => old_key_removed = true,
                Err(e) => {
                    note = Some(format!(
                        "The new key is installed and working, but the old one couldn't be \
                         removed ({e}). Remove it from ~/.ssh/authorized_keys by hand."
                    ))
                }
            }
        }
        Some(_) => {
            note = Some("The old and new keys are identical - nothing to remove.".into());
        }
        None => {
            note = Some(
                "The new key is installed and working. There was no old public key on \
                 record, so nothing was removed from ~/.ssh/authorized_keys."
                    .into(),
            );
        }
    }

    step(&app, &host_id, "Saving the new key to the vault");
    {
        let key_guard = state.vault_key.lock().unwrap();
        let key = key_guard.as_ref().ok_or("Vault is locked")?;
        let salt_guard = state.vault_salt.lock().unwrap();
        let salt = salt_guard.as_ref().ok_or("Vault is locked")?;
        let mut hosts = state.hosts.lock().unwrap();
        let entry = hosts
            .iter_mut()
            .find(|h| h.id == host_id)
            .ok_or("The host was deleted while its key was being rotated")?;
        entry.private_key = Some(pair.private_key.clone());
        entry.public_key = Some(pair.public_key.clone());
        entry.passphrase = None;
        entry.default_auth = "SshKey".to_string();
        entry.key_added_at = Some(now());
        crate::vault::save_vault(&hosts, key, salt)?;
    }

    let fingerprint = PublicKey::from_openssh(pair.public_key.trim())
        .map(|k| k.fingerprint(HashAlg::Sha256).to_string())
        .unwrap_or_default();

    step(&app, &host_id, "Done");
    Ok(RotateOutcome {
        fingerprint,
        old_key_removed,
        note,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;
    const DAY: i64 = 86_400;

    fn host(name: &str) -> Host {
        Host {
            id: name.to_string(),
            name: name.to_string(),
            hostname: "10.0.0.1".into(),
            port: 22,
            username: "root".into(),
            default_auth: "SshKey".into(),
            password: None,
            private_key: None,
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
            key_added_at: Some(NOW - 10 * DAY),
            ntfy_topic: None,
        }
    }

    fn with_generated_key(name: &str) -> Host {
        let pair = crate::keygen::generate_ed25519().unwrap();
        let mut h = host(name);
        h.private_key = Some(pair.private_key);
        h.public_key = Some(pair.public_key);
        h
    }

    fn has(a: &HostAudit, id: &str) -> bool {
        a.findings.iter().any(|f| f.id == id)
    }

    #[test]
    fn reads_a_generated_ed25519_key() {
        let h = with_generated_key("web");
        let facts = inspect(&h).unwrap();
        assert_eq!(facts.algorithm, "ed25519");
        assert!(facts.fingerprint.starts_with("SHA256:"));
        assert!(!facts.encrypted);
        assert_eq!(facts.bits, None);
    }

    #[test]
    fn a_fresh_ed25519_key_raises_nothing() {
        let report = audit_hosts(&[with_generated_key("web")], NOW);
        assert_eq!(report.hosts[0].findings, vec![], "a good key must be quiet");
        assert_eq!((report.high, report.medium, report.low), (0, 0, 0));
    }

    #[test]
    fn derives_the_public_key_when_only_the_private_half_is_stored() {
        let mut h = with_generated_key("web");
        let expected = inspect(&h).unwrap().fingerprint;
        h.public_key = None;
        assert_eq!(inspect(&h).unwrap().fingerprint, expected);
    }

    #[test]
    fn flags_a_key_shared_between_hosts() {
        let a = with_generated_key("web");
        let mut b = host("db");
        b.private_key = a.private_key.clone();
        b.public_key = a.public_key.clone();
        let mut c = host("cache");
        c.private_key = a.private_key.clone();
        c.public_key = a.public_key.clone();

        let report = audit_hosts(&[a, b, c], NOW);
        for h in &report.hosts {
            assert!(has(h, "reused-key"), "{} should be flagged", h.host_name);
            assert_eq!(h.shared_with.len(), 2);
        }
        assert_eq!(report.hosts[0].shared_with, vec!["db", "cache"]);
        // Two others is a medium; the loud one is reserved for a wider blast radius.
        let f = report.hosts[0]
            .findings
            .iter()
            .find(|f| f.id == "reused-key")
            .unwrap();
        assert_eq!(f.severity, "medium");
    }

    #[test]
    fn distinct_keys_are_not_reuse() {
        let report = audit_hosts(&[with_generated_key("web"), with_generated_key("db")], NOW);
        assert!(report.hosts.iter().all(|h| h.shared_with.is_empty()));
        assert!(report.hosts.iter().all(|h| !has(h, "reused-key")));
    }

    #[test]
    fn two_hosts_of_the_same_name_do_not_flag_themselves() {
        // shared_with filters by name, so identically named hosts must not
        // silently swallow a real reuse finding.
        let a = with_generated_key("web");
        let mut b = host("web");
        b.id = "web-2".into();
        b.private_key = a.private_key.clone();
        b.public_key = a.public_key.clone();
        let report = audit_hosts(&[a, b], NOW);
        assert!(
            report.hosts.iter().all(|h| has(h, "reused-key")),
            "same-named hosts sharing a key is still reuse"
        );
    }

    #[test]
    fn flags_an_old_key_and_an_unknown_age() {
        let mut old = with_generated_key("web");
        old.key_added_at = Some(NOW - 400 * DAY);
        let mut unknown = with_generated_key("db");
        unknown.key_added_at = None;

        let report = audit_hosts(&[old, unknown], NOW);
        assert!(has(&report.hosts[0], "stale-key"));
        assert!(report.hosts[0].findings[0].detail.contains("400 days ago"));
        assert!(has(&report.hosts[1], "age-unknown"));
        assert!(!has(&report.hosts[1], "stale-key"));
    }

    #[test]
    fn flags_a_password_only_host() {
        let mut h = host("legacy");
        h.default_auth = "Password".into();
        h.password = Some("hunter2".into());
        let report = audit_hosts(&[h], NOW);
        assert!(has(&report.hosts[0], "password-auth"));
        assert!(report.hosts[0].key.is_none());
        // No key means no key age to complain about.
        assert!(!has(&report.hosts[0], "age-unknown"));
    }

    #[test]
    fn flags_an_unreadable_key() {
        let mut h = host("broken");
        h.private_key = Some("-----BEGIN OPENSSH PRIVATE KEY-----\nnope\n".into());
        let report = audit_hosts(&[h], NOW);
        assert!(has(&report.hosts[0], "unreadable-key"));
        assert_eq!(report.high, 1);
    }

    #[test]
    fn an_agent_host_without_a_key_is_not_scolded_for_a_password() {
        let mut h = host("agent-host");
        h.default_auth = "Agent".into();
        let report = audit_hosts(&[h], NOW);
        assert_eq!(report.hosts[0].findings, vec![]);
    }

    #[test]
    fn rsa_sizes_are_graded() {
        let weak = KeyFacts {
            algorithm: "rsa".into(),
            bits: Some(1024),
            fingerprint: "SHA256:x".into(),
            encrypted: false,
        };
        let mid = KeyFacts {
            bits: Some(2048),
            ..weak.clone()
        };
        let fine = KeyFacts {
            bits: Some(4096),
            ..weak.clone()
        };

        assert_eq!(algorithm_findings(&weak)[0].id, "weak-rsa");
        assert_eq!(algorithm_findings(&weak)[0].severity, "high");
        assert_eq!(algorithm_findings(&mid)[0].id, "small-rsa");
        assert_eq!(algorithm_findings(&mid)[0].severity, "low");
        assert!(algorithm_findings(&fine).is_empty());
    }

    #[test]
    fn dsa_and_nist_curves_are_called_out() {
        let dsa = KeyFacts {
            algorithm: "dsa".into(),
            bits: Some(1024),
            fingerprint: "SHA256:x".into(),
            encrypted: false,
        };
        assert_eq!(algorithm_findings(&dsa)[0].id, "dsa-key");

        let ecdsa = KeyFacts {
            algorithm: "ecdsa (nistp256)".into(),
            bits: None,
            ..dsa.clone()
        };
        assert_eq!(algorithm_findings(&ecdsa)[0].id, "nist-ecdsa");

        // A hardware-backed key is not the thing being warned about.
        let sk = KeyFacts {
            algorithm: "ecdsa-sk (nistp256)".into(),
            ..dsa.clone()
        };
        assert!(algorithm_findings(&sk).is_empty());
    }

    #[test]
    fn findings_are_ordered_worst_first() {
        let mut h = host("bad");
        h.private_key = Some("garbage".into());
        h.key_added_at = None;
        let report = audit_hosts(&[h], NOW);
        assert_eq!(report.hosts[0].findings[0].severity, "high");
    }

    #[test]
    fn resolves_a_bastion_chain() {
        let mut inner = host("bastion-inner");
        inner.id = "b2".into();
        let mut outer = host("bastion-outer");
        outer.id = "b1".into();
        outer.jump_host = Some("b2".into());
        let mut target = host("prod");
        target.id = "t".into();
        target.jump_host = Some("b1".into());

        let all = vec![target.clone(), outer, inner];
        let resolved = with_resolved_jump(&target, &all);

        let hop1 = resolved.jump.as_ref().expect("first hop");
        assert_eq!(hop1.name, "bastion-outer");
        let hop2 = hop1.jump.as_ref().expect("second hop");
        assert_eq!(hop2.name, "bastion-inner");
        assert!(hop2.jump.is_none());
    }

    #[test]
    fn a_direct_host_gets_no_chain() {
        let h = host("plain");
        assert!(with_resolved_jump(&h, std::slice::from_ref(&h))
            .jump
            .is_none());
    }

    #[test]
    fn a_jump_cycle_terminates() {
        // Two hosts pointing at each other must not resolve forever.
        let mut a = host("a");
        a.id = "a".into();
        a.jump_host = Some("b".into());
        let mut b = host("b");
        b.id = "b".into();
        b.jump_host = Some("a".into());

        let resolved = with_resolved_jump(&a, &[a.clone(), b]);
        let hop = resolved.jump.as_ref().expect("one hop");
        assert_eq!(hop.name, "b");
        assert!(hop.jump.is_none(), "the cycle must stop here");
    }

    #[test]
    fn a_dangling_jump_reference_is_dropped() {
        let mut h = host("orphan");
        h.jump_host = Some("deleted-host".into());
        assert!(with_resolved_jump(&h, std::slice::from_ref(&h))
            .jump
            .is_none());
    }

    #[test]
    fn extracts_a_key_blob() {
        let pair = crate::keygen::generate_ed25519().unwrap();
        let blob = key_blob(&pair.public_key).unwrap();
        assert!(pair.public_key.contains(&blob));
        assert!(!blob.contains(' '));
        // A comment on the end must not change the blob.
        let with_comment = format!("{} alice@laptop", pair.public_key.trim());
        assert_eq!(key_blob(&with_comment).unwrap(), blob);
    }

    // ── The removal command, against a real authorized_keys ──────────────────
    //
    // This is the only step that destroys anything, so it is exercised on a real
    // shell rather than reasoned about. A stand-in $HOME holds a file with the
    // usual mess in it: other people's keys, comments, options, blank lines.

    fn authorized_keys(dir: &std::path::Path, body: &str) -> std::path::PathBuf {
        let ssh = dir.join(".ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        let path = ssh.join("authorized_keys");
        std::fs::write(&path, body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        path
    }

    async fn run_in(dir: &std::path::Path, cmd: &str) -> crate::exec::ExecOutput {
        crate::exec::exec(None, &format!("HOME=\"{}\"; {}", dir.display(), cmd))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn removes_only_the_old_key() {
        let dir = tempfile::tempdir().unwrap();
        let old = crate::keygen::generate_ed25519().unwrap();
        let new = crate::keygen::generate_ed25519().unwrap();
        let someone_else = crate::keygen::generate_ed25519().unwrap();

        let body = format!(
            "# deploy keys\n\
             {other} ci@builder\n\
             \n\
             restrict,command=\"/usr/bin/backup\" {old} old@laptop\n\
             {new} kino-rotated\n",
            other = someone_else.public_key.trim(),
            old = old.public_key.trim(),
            new = new.public_key.trim(),
        );
        let path = authorized_keys(dir.path(), &body);

        let cmd = remove_key_command(
            &key_blob(&old.public_key).unwrap(),
            &key_blob(&new.public_key).unwrap(),
        );
        let out = run_in(dir.path(), &cmd).await;
        assert_eq!(out.code, Some(0), "stderr: {}", out.stderr);

        let after = std::fs::read_to_string(&path).unwrap();
        assert!(!after.contains(key_blob(&old.public_key).unwrap().as_str()));
        assert!(after.contains(key_blob(&new.public_key).unwrap().as_str()));
        assert!(
            after.contains(key_blob(&someone_else.public_key).unwrap().as_str()),
            "another operator's key must survive"
        );
        assert!(after.contains("# deploy keys"), "comments must survive");

        // Rewritten through `cat`, so sshd's view of the file's mode is unchanged.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "permissions must be preserved");
        }
    }

    #[tokio::test]
    async fn refuses_to_write_a_file_without_the_new_key() {
        // The failure that would lock someone out: if the new key isn't in the
        // result, the rewrite must not happen at all.
        let dir = tempfile::tempdir().unwrap();
        let old = crate::keygen::generate_ed25519().unwrap();
        let new = crate::keygen::generate_ed25519().unwrap();
        let body = format!("{}\n", old.public_key.trim());
        let path = authorized_keys(dir.path(), &body);

        let cmd = remove_key_command(
            &key_blob(&old.public_key).unwrap(),
            &key_blob(&new.public_key).unwrap(),
        );
        let out = run_in(dir.path(), &cmd).await;

        assert_eq!(out.code, Some(8));
        assert!(out.stderr.contains("KINO_NEWKEY_MISSING"));
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            body,
            "the file must be untouched when the guard trips"
        );
    }

    #[tokio::test]
    async fn reports_a_missing_authorized_keys() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".ssh")).unwrap();
        let out = run_in(dir.path(), &remove_key_command("AAAAold", "AAAAnew")).await;
        assert_eq!(out.code, Some(7));
        assert!(out.stderr.contains("KINO_NOFILE"));
    }

    #[test]
    fn rejects_a_blob_that_could_break_out_of_the_command() {
        assert!(key_blob("ssh-ed25519 AAAA'; rm -rf /; ' x").is_none());
        assert!(key_blob("ssh-ed25519").is_none());
        assert!(key_blob("").is_none());
    }
}
