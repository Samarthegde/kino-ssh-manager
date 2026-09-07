//! What cryptography a server would actually use, found out without logging in.
//!
//! OpenSSH 9.9 and 10.x made `mlkem768x25519-sha256` the default key exchange
//! and started warning when a connection cannot negotiate a post-quantum one.
//! OpenSSH 10 also dropped DSA outright. So people with a fleet of
//! mixed-vintage boxes now see warnings and have no way to find out which
//! hosts are responsible.
//!
//! Kino is already in better shape than its users know: it does not override
//! russh's preferences, and russh's `SAFE_KEX_ORDER` begins with
//! `mlkem768x25519-sha256`, so a hybrid PQ exchange already happens wherever
//! the server supports it. It simply never says so.
//!
//! ## Why a probe rather than reading it off a live session
//!
//! `russh::negotiation::Names` is public but is not surfaced through
//! `client::Handle`, and forking russh to reach it would buy the wrong thing
//! anyway. A session tells you the one algorithm that won. An audit wants the
//! whole list the server offered, because that is what says *why* it won and
//! what would happen against a different client.
//!
//! So this speaks just enough of the protocol to ask: exchange version
//! banners, read the server's `SSH_MSG_KEXINIT`, and hang up. No
//! authentication, no credentials, no session. It works with the vault locked.
//!
//! The parsing here is pure and takes bytes, so every shape a server can send
//! - truncated, absurd lengths, empty lists, unknown names - is a unit test
//!   rather than something discovered against somebody's production sshd.

use serde::{Deserialize, Serialize};

/// The `SSH_MSG_KEXINIT` message id.
const MSG_KEXINIT: u8 = 20;

/// A server offering more than this is not being honest, and the number only
/// has to be big enough for a real one: OpenSSH sends a few hundred bytes.
const MAX_PACKET: usize = 256 * 1024;

/// Everything the server said it can do.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Offered {
    /// The version banner, e.g. `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5`.
    pub banner: String,
    pub kex: Vec<String>,
    pub host_key: Vec<String>,
    /// Server-to-client ciphers. The two directions are almost always equal
    /// and reporting both would double the width of the table for nothing.
    pub cipher: Vec<String>,
    pub mac: Vec<String>,
    pub compression: Vec<String>,
}

impl Offered {
    /// The software name out of the banner, e.g. `OpenSSH_9.6p1`.
    ///
    /// Findings quote this so the remediation names the version in front of
    /// the user rather than talking about versions in the abstract.
    pub fn software(&self) -> Option<&str> {
        self.banner.strip_prefix("SSH-2.0-")?.split(' ').next()
    }
}

/// How good the negotiated set would be.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Grade {
    /// A hybrid post-quantum key exchange would be selected.
    Pq,
    /// Sound, but nothing post-quantum on offer.
    Classical,
    /// Something in the negotiated set is deprecated or broken.
    Weak,
}

/// One thing worth telling the user, with the fix.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Finding {
    /// "critical" | "high" | "medium" | "low"
    pub severity: String,
    pub title: String,
    /// What to change on the server. Names the host's own version where it
    /// can - generic advice is not worth the row it takes up.
    pub remediation: String,
}

/// What a probe concluded.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Assessment {
    pub grade: Grade,
    /// What would be selected against Kino's own preferences.
    pub kex: Option<String>,
    pub host_key: Option<String>,
    pub cipher: Option<String>,
    pub mac: Option<String>,
    pub findings: Vec<Finding>,
}

// ── The client side of the comparison ───────────────────────────────────────
//
// Mirrors russh 0.61's `SAFE_KEX_ORDER` and its default cipher and MAC
// preferences. Duplicated rather than imported because russh does not export
// them, and because an audit wants to state plainly what it compared against.

const CLIENT_KEX: &[&str] = &[
    "mlkem768x25519-sha256",
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group14-sha256",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
];

const CLIENT_HOST_KEY: &[&str] = &[
    "ssh-ed25519",
    "rsa-sha2-512",
    "rsa-sha2-256",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "ssh-rsa",
];

const CLIENT_CIPHER: &[&str] = &[
    "chacha20-poly1305@openssh.com",
    "aes256-gcm@openssh.com",
    "aes128-gcm@openssh.com",
    "aes256-ctr",
    "aes192-ctr",
    "aes128-ctr",
];

const CLIENT_MAC: &[&str] = &[
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512",
    "hmac-sha2-256",
    "hmac-sha1",
];

/// Key exchanges that carry a post-quantum component.
const PQ_KEX: &[&str] = &[
    "mlkem768x25519-sha256",
    "sntrup761x25519-sha512",
    "sntrup761x25519-sha512@openssh.com",
    "sntrup4591761x25519-sha512@tinyssh.org",
];

/// Key exchanges nobody should still be negotiating. All SHA-1 based, or the
/// 1024-bit group that Logjam made indefensible.
const WEAK_KEX: &[&str] = &[
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
    "rsa1024-sha1",
];

/// First of ours the server also has. Client order is the preference, which is
/// how the negotiation in RFC 4253 works.
fn negotiate(client: &[&str], server: &[String]) -> Option<String> {
    client
        .iter()
        .find(|c| server.iter().any(|s| s == *c))
        .map(|c| c.to_string())
}

/// Judge what a connection to this server would actually use.
pub fn assess(offered: &Offered) -> Assessment {
    let kex = negotiate(CLIENT_KEX, &offered.kex);
    let host_key = negotiate(CLIENT_HOST_KEY, &offered.host_key);
    let cipher = negotiate(CLIENT_CIPHER, &offered.cipher);
    let mac = negotiate(CLIENT_MAC, &offered.mac);

    let mut findings = Vec::new();
    let version = offered
        .software()
        .map(|s| format!("This host reports {s}."))
        .unwrap_or_default();

    // Judge what the server *offers*, not only what would be selected.
    //
    // The first version of this only looked at the negotiated algorithm, and
    // so said nothing at all about a host offering only SHA-1 key exchange or
    // only a DSA host key - Kino will not negotiate either, so there was
    // nothing to look at. That is exactly the host an audit exists to find.
    let weak_kex_offered: Vec<&str> = offered
        .kex
        .iter()
        .filter(|k| WEAK_KEX.contains(&k.as_str()))
        .map(String::as_str)
        .collect();
    let offers_dsa = offered.host_key.iter().any(|h| h == "ssh-dss");

    if kex.is_none() {
        let all_weak = !offered.kex.is_empty() && weak_kex_offered.len() == offered.kex.len();
        let why = if all_weak {
            "Everything it offers is SHA-1 based or a 1024-bit group, which no current client \
             will negotiate."
        } else {
            "Its sshd offers none of the key exchanges Kino will use."
        };
        findings.push(Finding {
            severity: "critical".into(),
            title: "No key exchange in common with Kino".into(),
            remediation: format!(
                "Kino cannot connect to this host at all. {why} Add `curve25519-sha256` to \
                 KexAlgorithms in sshd_config. {version}"
            )
            .trim_end()
            .to_string(),
        });
    } else if let Some(k) = &kex {
        if WEAK_KEX.contains(&k.as_str()) {
            findings.push(Finding {
                severity: "high".into(),
                title: format!("Would negotiate {k}"),
                remediation: format!(
                    "This key exchange relies on SHA-1 or a 1024-bit group and should not be \
                     in use. Set KexAlgorithms in sshd_config to `curve25519-sha256` or better. \
                     {version}"
                )
                .trim_end()
                .to_string(),
            });
        } else if !weak_kex_offered.is_empty() {
            // Not what we would pick, but another client might, and the server
            // is the thing being audited.
            findings.push(Finding {
                severity: "medium".into(),
                title: format!("Still offers {}", weak_kex_offered.join(", ")),
                remediation: format!(
                    "Kino would not choose these, but an older client can. Remove them from \
                     KexAlgorithms in sshd_config. {version}"
                )
                .trim_end()
                .to_string(),
            });
        }
    }

    if offers_dsa && host_key.is_none() {
        findings.push(Finding {
            severity: "critical".into(),
            title: "The only host key is DSA".into(),
            remediation: format!(
                "OpenSSH 10 removed DSA, so it and Kino cannot connect to this host at all. \
                 Generate an ed25519 host key: `ssh-keygen -t ed25519 -f \
                 /etc/ssh/ssh_host_ed25519_key`, then restart sshd. {version}"
            )
            .trim_end()
            .to_string(),
        });
    } else if host_key.as_deref() == Some("ssh-rsa") {
        findings.push(Finding {
            severity: "high".into(),
            title: "Host key algorithm would be ssh-rsa".into(),
            remediation: format!(
                "`ssh-rsa` means RSA with SHA-1 signatures, disabled by default since \
                 OpenSSH 8.8. Enable `rsa-sha2-256`/`rsa-sha2-512`, or better, add an \
                 ed25519 host key. {version}"
            )
            .trim_end()
            .to_string(),
        });
    } else if offers_dsa {
        findings.push(Finding {
            severity: "low".into(),
            title: "Still offers a DSA host key".into(),
            remediation: format!(
                "Not used here, since a better host key is available, but OpenSSH 10 dropped \
                 DSA and it serves no purpose now. Remove the ssh_host_dsa_key lines from \
                 sshd_config. {version}"
            )
            .trim_end()
            .to_string(),
        });
    } else if host_key.is_none() {
        findings.push(Finding {
            severity: "critical".into(),
            title: "No host key algorithm in common with Kino".into(),
            remediation: format!(
                "Kino cannot verify this host, so it cannot connect. Add an ed25519 host key. \
                 {version}"
            )
            .trim_end()
            .to_string(),
        });
    }

    // CBC and truncated MACs. Not negotiated by Kino, but worth reporting: a
    // fleet audit is about the server's posture, not only this client's session.
    let cbc: Vec<&String> = offered
        .cipher
        .iter()
        .filter(|c| c.contains("-cbc"))
        .collect();
    if !cbc.is_empty() {
        findings.push(Finding {
            severity: "medium".into(),
            title: format!("Still offers {} CBC cipher(s)", cbc.len()),
            remediation: format!(
                "CBC modes are vulnerable to the Terrapin-era padding attacks and other \
                 clients may still pick them. Restrict Ciphers in sshd_config to the CTR and \
                 GCM ones. {version}"
            )
            .trim_end()
            .to_string(),
        });
    }
    if offered.mac.iter().any(|m| m.starts_with("hmac-sha1")) {
        findings.push(Finding {
            severity: "medium".into(),
            title: "Still offers SHA-1 MACs".into(),
            remediation: format!(
                "Restrict MACs in sshd_config to the `-etm@openssh.com` SHA-2 variants. \
                 {version}"
            )
            .trim_end()
            .to_string(),
        });
    }

    let pq = kex.as_deref().is_some_and(|k| PQ_KEX.contains(&k));
    if !pq && kex.is_some() && findings.iter().all(|f| f.severity != "critical") {
        // A server can be post-quantum capable in a way Kino cannot use.
        // OpenSSH 9.x shipped `sntrup761x25519-sha512@openssh.com` well before
        // `mlkem768x25519-sha256`, and russh implements only the latter. Saying
        // "no post-quantum key exchange" to the owner of such a host would be
        // wrong, and it would be blaming them for our own gap.
        let theirs: Vec<&str> = offered
            .kex
            .iter()
            .filter(|k| PQ_KEX.contains(&k.as_str()))
            .map(String::as_str)
            .collect();
        let finding = if theirs.is_empty() {
            Finding {
                severity: "low".into(),
                title: "No post-quantum key exchange".into(),
                remediation: format!(
                    "This session's key material could be recorded now and broken later by a \
                     quantum computer. OpenSSH 9.9 or newer offers `mlkem768x25519-sha256`, \
                     and Kino prefers it automatically once the server has it. {version}"
                )
                .trim_end()
                .to_string(),
            }
        } else {
            Finding {
                severity: "low".into(),
                title: "Post-quantum key exchange offered, but not one Kino speaks".into(),
                remediation: format!(
                    "This host offers {}, which is post-quantum, but Kino only implements \
                     `mlkem768x25519-sha256` and so falls back to a classical exchange. \
                     OpenSSH 9.9 or newer offers both. This one is as much Kino's gap as the \
                     host's. {version}",
                    theirs.join(", ")
                )
                .trim_end()
                .to_string(),
            }
        };
        findings.push(finding);
    }

    let grade = if findings
        .iter()
        .any(|f| f.severity == "critical" || f.severity == "high")
    {
        Grade::Weak
    } else if pq {
        Grade::Pq
    } else {
        Grade::Classical
    };

    Assessment {
        grade,
        kex,
        host_key,
        cipher,
        mac,
        findings,
    }
}

// ── Wire parsing ────────────────────────────────────────────────────────────

/// A reader that refuses to read past the end rather than panicking. Every
/// length here came off a socket from a machine that may not be friendly.
struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Reader { b, at: 0 }
    }

    fn u32(&mut self) -> Result<u32, String> {
        let end = self.at.checked_add(4).ok_or("length overflowed")?;
        let s = self
            .b
            .get(self.at..end)
            .ok_or("truncated: wanted 4 bytes")?;
        self.at = end;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.at.checked_add(n).ok_or("length overflowed")?;
        let s = self.b.get(self.at..end).ok_or_else(|| {
            format!(
                "truncated: wanted {n} bytes, {} left",
                self.b.len() - self.at
            )
        })?;
        self.at = end;
        Ok(s)
    }

    /// An RFC 4251 name-list: a length, then comma-separated ASCII names.
    fn name_list(&mut self) -> Result<Vec<String>, String> {
        let len = self.u32()? as usize;
        if len > MAX_PACKET {
            return Err(format!("name-list claims {len} bytes"));
        }
        let raw = self.take(len)?;
        let s = std::str::from_utf8(raw).map_err(|_| "name-list is not UTF-8".to_string())?;
        Ok(s.split(',')
            .map(str::trim)
            .filter(|n| !n.is_empty())
            .map(str::to_string)
            .collect())
    }
}

/// Pull the algorithm lists out of an `SSH_MSG_KEXINIT` payload.
///
/// Takes the payload - message id first, padding already removed.
pub fn parse_kexinit(payload: &[u8], banner: &str) -> Result<Offered, String> {
    let mut r = Reader::new(payload);
    let id = *r.take(1)?.first().ok_or("empty payload")?;
    if id != MSG_KEXINIT {
        return Err(format!(
            "expected SSH_MSG_KEXINIT ({MSG_KEXINIT}), got message {id}"
        ));
    }
    r.take(16)?; // cookie

    let kex = r.name_list()?;
    let host_key = r.name_list()?;
    let _cipher_c2s = r.name_list()?;
    let cipher = r.name_list()?;
    let _mac_c2s = r.name_list()?;
    let mac = r.name_list()?;
    let _comp_c2s = r.name_list()?;
    let compression = r.name_list()?;

    Ok(Offered {
        banner: banner.trim_end().to_string(),
        kex,
        host_key,
        cipher,
        mac,
        compression,
    })
}

/// Strip the binary packet framing: length, padding length, payload, padding.
///
/// Only valid before encryption is turned on, which is the only place this is
/// ever used.
pub fn unwrap_packet(buf: &[u8]) -> Result<&[u8], String> {
    let mut r = Reader::new(buf);
    let len = r.u32()? as usize;
    if !(2..=MAX_PACKET).contains(&len) {
        return Err(format!("implausible packet length {len}"));
    }
    let pad = *r.take(1)?.first().ok_or("no padding length")? as usize;
    let payload_len = len
        .checked_sub(pad + 1)
        .ok_or("padding is longer than the packet")?;
    r.take(payload_len)
}

// ── Talking to a real server ────────────────────────────────────────────────

use crate::vault::Host;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Long enough for a slow WAN round trip, short enough that a dead host does
/// not stall a sweep. Same order as `health.rs`, for the same reason.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// What Kino announces itself as. Servers log this, so it says what it is
/// rather than impersonating a client that is about to authenticate.
const CLIENT_BANNER: &str = "SSH-2.0-Kino_probe\r\n";

/// One host's result, as the fleet table needs it.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HostProbe {
    pub id: String,
    /// "ok" | "unknown" | "unreachable"
    pub status: String,
    pub offered: Option<Offered>,
    pub assessment: Option<Assessment>,
    /// Why it was not probed, or why it failed.
    pub detail: Option<String>,
    /// Unix seconds, so the UI can call a stale result stale.
    pub checked_at: i64,
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn skipped(id: &str, why: &str) -> HostProbe {
    HostProbe {
        id: id.to_string(),
        status: "unknown".into(),
        offered: None,
        assessment: None,
        detail: Some(why.to_string()),
        checked_at: now(),
    }
}

/// Exchange banners, read the server's KEXINIT, and hang up.
///
/// No authentication is attempted and no credential is read, so this works
/// with the vault locked. A well-behaved sshd records a connection and no
/// login; the documentation says so rather than implying the probe is
/// invisible.
async fn read_kexinit(host: &Host) -> Result<Offered, String> {
    let mut stream = crate::ssh_session::open_target_stream(host).await?;
    stream
        .write_all(CLIENT_BANNER.as_bytes())
        .await
        .map_err(|e| format!("Could not send the version banner: {e}"))?;

    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut chunk = [0u8; 2048];

    // RFC 4253 lets a server send any number of lines before its version line,
    // so read until one of them starts with "SSH-".
    let banner = loop {
        if let Some(b) = take_banner(&buf) {
            break b;
        }
        if buf.len() > MAX_PACKET {
            return Err("Server sent no version line".into());
        }
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|e| format!("Connection failed while reading the banner: {e}"))?;
        if n == 0 {
            return Err("Server closed the connection before sending a version".into());
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    // Whatever followed the banner is the start of the first packet.
    let consumed = banner.len() + 2;
    let mut packet = buf[consumed..].to_vec();
    loop {
        if packet.len() >= 4 {
            let want = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]) as usize;
            if want > MAX_PACKET {
                return Err(format!("Server announced a {want}-byte packet"));
            }
            if packet.len() >= want + 4 {
                break;
            }
        }
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|e| format!("Connection failed while reading KEXINIT: {e}"))?;
        if n == 0 {
            return Err("Server closed the connection before offering its algorithms".into());
        }
        packet.extend_from_slice(&chunk[..n]);
    }

    let payload = unwrap_packet(&packet)?;
    parse_kexinit(payload, &banner)
    // `stream` drops here, which is the whole disconnect.
}

/// The server's version line, if the buffer holds a complete one.
fn take_banner(buf: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(buf);
    let mut at = 0usize;
    while let Some(nl) = text[at..].find("\r\n") {
        let line = &text[at..at + nl];
        if line.starts_with("SSH-") {
            return Some(line.to_string());
        }
        at += nl + 2;
    }
    None
}

/// Probe one host, refusing to guess about the ones that cannot be reached by
/// a plain connection.
async fn probe_one(host: &Host) -> HostProbe {
    if host.connection_mode.as_deref() == Some("agent") {
        return skipped(&host.id, "Reached through a relay - not probed");
    }
    if host
        .jump_host
        .as_deref()
        .map(str::trim)
        .is_some_and(|s| !s.is_empty())
    {
        return skipped(&host.id, "Reached through a jump host - not probed");
    }

    match tokio::time::timeout(PROBE_TIMEOUT, read_kexinit(host)).await {
        Ok(Ok(offered)) => {
            let assessment = assess(&offered);
            HostProbe {
                id: host.id.clone(),
                status: "ok".into(),
                offered: Some(offered),
                assessment: Some(assessment),
                detail: None,
                checked_at: now(),
            }
        }
        Ok(Err(e)) => HostProbe {
            id: host.id.clone(),
            status: "unreachable".into(),
            offered: None,
            assessment: None,
            detail: Some(e),
            checked_at: now(),
        },
        Err(_) => HostProbe {
            id: host.id.clone(),
            status: "unreachable".into(),
            offered: None,
            assessment: None,
            detail: Some("Timed out".into()),
            checked_at: now(),
        },
    }
}

/// Probe a set of hosts. Manual or scheduled - never an automatic sweep on
/// launch, and capped so a large fleet does not open a hundred sockets at once.
#[tauri::command]
pub async fn probe_host_algorithms(hosts: Vec<Host>) -> Vec<HostProbe> {
    use futures_util::stream::{self, StreamExt};
    stream::iter(hosts.iter())
        .map(probe_one)
        .buffer_unordered(8)
        .collect()
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn offered(banner: &str, kex: &[&str], host_key: &[&str]) -> Offered {
        Offered {
            banner: banner.into(),
            kex: names(kex),
            host_key: names(host_key),
            cipher: names(&["chacha20-poly1305@openssh.com", "aes256-ctr"]),
            mac: names(&["hmac-sha2-256-etm@openssh.com"]),
            compression: names(&["none"]),
        }
    }

    // ── Grading ─────────────────────────────────────────────────────────────

    #[test]
    fn a_modern_openssh_grades_pq() {
        let a = assess(&offered(
            "SSH-2.0-OpenSSH_9.9p1",
            &["mlkem768x25519-sha256", "curve25519-sha256"],
            &["ssh-ed25519"],
        ));
        assert_eq!(a.grade, Grade::Pq);
        assert_eq!(a.kex.as_deref(), Some("mlkem768x25519-sha256"));
        assert!(a.findings.is_empty(), "{:?}", a.findings);
    }

    #[test]
    fn an_older_openssh_grades_classical_and_names_its_version() {
        let a = assess(&offered(
            "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
            &["curve25519-sha256"],
            &["ssh-ed25519"],
        ));
        assert_eq!(a.grade, Grade::Classical);
        assert_eq!(a.findings.len(), 1);
        assert_eq!(a.findings[0].severity, "low");
        // The remediation has to name what is actually running, not "an old version".
        assert!(
            a.findings[0].remediation.contains("OpenSSH_8.9p1"),
            "{}",
            a.findings[0].remediation
        );
    }

    #[test]
    fn a_server_offering_only_sha1_key_exchange_cannot_be_reached_at_all() {
        // Kino will not negotiate SHA-1, so there is nothing in common - and
        // saying so is more useful than "would negotiate something weak".
        let a = assess(&offered(
            "SSH-2.0-OpenSSH_6.6.1",
            &["diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1"],
            &["ssh-ed25519"],
        ));
        assert_eq!(a.grade, Grade::Weak);
        assert_eq!(a.kex, None);
        let f = &a.findings[0];
        assert_eq!(f.severity, "critical");
        assert!(f.remediation.contains("SHA-1 based"), "{}", f.remediation);
    }

    #[test]
    fn a_weak_algorithm_that_would_not_be_chosen_is_still_reported() {
        // The bug this was written for: only inspecting the negotiated
        // algorithm meant a server offering both said nothing about the bad one.
        let a = assess(&offered(
            "SSH-2.0-OpenSSH_9.9p1",
            &["mlkem768x25519-sha256", "diffie-hellman-group1-sha1"],
            &["ssh-ed25519", "ssh-dss"],
        ));
        // Kino itself is fine here, so the grade stays PQ.
        assert_eq!(a.grade, Grade::Pq);
        assert_eq!(a.kex.as_deref(), Some("mlkem768x25519-sha256"));
        // But both leftovers are reported, because another client may take them.
        let kex_f = a
            .findings
            .iter()
            .find(|f| f.title.starts_with("Still offers d"))
            .unwrap();
        assert_eq!(kex_f.severity, "medium");
        let dsa_f = a.findings.iter().find(|f| f.title.contains("DSA")).unwrap();
        assert_eq!(dsa_f.severity, "low");
    }

    #[test]
    fn a_dsa_only_host_is_critical_because_openssh_10_cannot_connect() {
        let a = assess(&offered(
            "SSH-2.0-OpenSSH_6.6.1",
            &["curve25519-sha256"],
            &["ssh-dss"],
        ));
        assert_eq!(a.grade, Grade::Weak);
        assert_eq!(
            a.host_key, None,
            "ssh-dss is not something Kino will accept"
        );
        let f = a.findings.iter().find(|f| f.title.contains("DSA")).unwrap();
        assert_eq!(f.severity, "critical");
        assert!(f.remediation.contains("ssh-keygen -t ed25519"));
    }

    #[test]
    fn an_rsa_sha1_host_key_is_reported_when_it_is_the_best_on_offer() {
        let a = assess(&offered(
            "SSH-2.0-OpenSSH_7.4",
            &["curve25519-sha256"],
            &["ssh-rsa"],
        ));
        assert_eq!(a.grade, Grade::Weak);
        assert_eq!(a.host_key.as_deref(), Some("ssh-rsa"));
        assert!(a.findings.iter().any(|f| f.severity == "high"));
    }

    #[test]
    fn nothing_in_common_says_so_rather_than_grading_it() {
        let a = assess(&offered(
            "SSH-2.0-Dropbear_2020.80",
            &["kex-i-invented"],
            &["ssh-ed25519"],
        ));
        assert_eq!(a.grade, Grade::Weak);
        assert_eq!(a.kex, None);
        assert!(a.findings[0].title.contains("No key exchange in common"));
    }

    #[test]
    fn cbc_ciphers_and_sha1_macs_are_reported_even_when_unused() {
        // Kino would not pick either, but the audit is about the server.
        let mut o = offered(
            "SSH-2.0-OpenSSH_9.9p1",
            &["mlkem768x25519-sha256"],
            &["ssh-ed25519"],
        );
        o.cipher.push("aes128-cbc".into());
        o.mac.push("hmac-sha1".into());
        let a = assess(&o);
        assert!(a.findings.iter().any(|f| f.title.contains("CBC")));
        assert!(a.findings.iter().any(|f| f.title.contains("SHA-1 MAC")));
        // Still PQ: these are medium findings about what else is on offer.
        assert_eq!(a.grade, Grade::Pq);
    }

    #[test]
    fn a_pq_algorithm_kino_cannot_speak_is_not_blamed_on_the_server() {
        // Found by probing a real OpenSSH 9.6, which offers sntrup761 but not
        // mlkem. Saying "no post-quantum key exchange" there would be false.
        let a = assess(&offered(
            "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.18",
            &["sntrup761x25519-sha512@openssh.com", "curve25519-sha256"],
            &["ssh-ed25519"],
        ));
        assert_eq!(a.grade, Grade::Classical);
        assert_eq!(a.kex.as_deref(), Some("curve25519-sha256"));
        let f = a
            .findings
            .iter()
            .find(|f| f.title.contains("quantum"))
            .unwrap();
        assert!(f.title.contains("not one Kino speaks"), "{}", f.title);
        assert!(f.remediation.contains("sntrup761"), "{}", f.remediation);
        assert!(f.remediation.contains("Kino's gap"), "{}", f.remediation);
    }

    #[test]
    fn client_order_decides_not_server_order() {
        // Server lists curve25519 first; we still take mlkem, because RFC 4253
        // says the client's preference wins.
        let a = assess(&offered(
            "SSH-2.0-OpenSSH_9.9p1",
            &["curve25519-sha256", "mlkem768x25519-sha256"],
            &["ssh-ed25519"],
        ));
        assert_eq!(a.kex.as_deref(), Some("mlkem768x25519-sha256"));
    }

    #[test]
    fn the_software_name_comes_out_of_the_banner() {
        let o = offered("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5", &[], &[]);
        assert_eq!(o.software(), Some("OpenSSH_9.6p1"));
        let o = offered("SSH-2.0-dropbear", &[], &[]);
        assert_eq!(o.software(), Some("dropbear"));
        let o = offered("nonsense", &[], &[]);
        assert_eq!(o.software(), None);
    }

    // ── Parsing ─────────────────────────────────────────────────────────────

    fn name_list_bytes(names: &str) -> Vec<u8> {
        let mut v = (names.len() as u32).to_be_bytes().to_vec();
        v.extend_from_slice(names.as_bytes());
        v
    }

    fn kexinit_payload() -> Vec<u8> {
        let mut p = vec![MSG_KEXINIT];
        p.extend_from_slice(&[0u8; 16]); // cookie
        p.extend(name_list_bytes("mlkem768x25519-sha256,curve25519-sha256"));
        p.extend(name_list_bytes("ssh-ed25519,rsa-sha2-512"));
        p.extend(name_list_bytes("aes128-ctr")); // c2s cipher
        p.extend(name_list_bytes("chacha20-poly1305@openssh.com,aes256-ctr"));
        p.extend(name_list_bytes("hmac-sha1")); // c2s mac
        p.extend(name_list_bytes("hmac-sha2-256-etm@openssh.com"));
        p.extend(name_list_bytes("none")); // c2s compression
        p.extend(name_list_bytes("none,zlib@openssh.com"));
        p
    }

    /// Against a real sshd rather than bytes I made up, because a parser that
    /// only ever sees its author's fixtures is a parser that has not been
    /// tested. Ignored by default: it needs a server on 127.0.0.1:22, which CI
    /// does not have.
    ///
    ///     cargo test --lib algo_probe -- --ignored --nocapture
    #[test]
    #[ignore = "needs a local sshd on 127.0.0.1:22"]
    fn probes_the_local_sshd() {
        let mut h = super::tests::local_host();
        h.port = 22;
        let probe = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(probe_one(&h));

        assert_eq!(probe.status, "ok", "detail: {:?}", probe.detail);
        let o = probe.offered.unwrap();
        println!("banner:   {}", o.banner);
        println!("kex:      {}", o.kex.join(", "));
        println!("host key: {}", o.host_key.join(", "));
        println!("cipher:   {}", o.cipher.join(", "));
        let a = probe.assessment.unwrap();
        println!("grade:    {:?}  kex={:?}", a.grade, a.kex);
        for f in &a.findings {
            println!("  [{}] {}", f.severity, f.title);
        }
        assert!(o.banner.starts_with("SSH-2.0-"));
        assert!(!o.kex.is_empty() && !o.host_key.is_empty() && !o.cipher.is_empty());
    }

    fn local_host() -> Host {
        Host {
            id: "local".into(),
            name: "local".into(),
            hostname: "127.0.0.1".into(),
            port: 22,
            username: "probe".into(),
            default_auth: "Password".into(),
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
            key_added_at: None,
            ntfy_topic: None,
            environment: None,
        }
    }

    #[test]
    fn parses_a_kexinit() {
        let o = parse_kexinit(&kexinit_payload(), "SSH-2.0-OpenSSH_9.9p1\r\n").unwrap();
        assert_eq!(o.banner, "SSH-2.0-OpenSSH_9.9p1");
        assert_eq!(
            o.kex,
            names(&["mlkem768x25519-sha256", "curve25519-sha256"])
        );
        assert_eq!(o.host_key, names(&["ssh-ed25519", "rsa-sha2-512"]));
        // Server-to-client, not client-to-server: the c2s lists are skipped.
        assert_eq!(
            o.cipher,
            names(&["chacha20-poly1305@openssh.com", "aes256-ctr"])
        );
        assert_eq!(o.mac, names(&["hmac-sha2-256-etm@openssh.com"]));
        assert_eq!(o.compression, names(&["none", "zlib@openssh.com"]));
    }

    #[test]
    fn refuses_a_message_that_is_not_kexinit() {
        let err = parse_kexinit(&[21, 0, 0], "b").unwrap_err();
        assert!(err.contains("got message 21"), "{err}");
    }

    #[test]
    fn truncation_is_an_error_not_a_panic() {
        let full = kexinit_payload();
        // Every prefix of a valid payload must fail cleanly.
        for cut in 0..full.len() {
            let r = parse_kexinit(&full[..cut], "b");
            assert!(r.is_err(), "prefix of {cut} bytes parsed as valid");
        }
    }

    #[test]
    fn an_absurd_length_is_rejected_rather_than_allocated() {
        let mut p = vec![MSG_KEXINIT];
        p.extend_from_slice(&[0u8; 16]);
        p.extend_from_slice(&u32::MAX.to_be_bytes());
        let err = parse_kexinit(&p, "b").unwrap_err();
        assert!(err.contains("claims"), "{err}");
    }

    #[test]
    fn an_empty_name_list_is_empty_not_a_list_of_one_empty_name() {
        let mut p = vec![MSG_KEXINIT];
        p.extend_from_slice(&[0u8; 16]);
        for _ in 0..8 {
            p.extend(name_list_bytes(""));
        }
        let o = parse_kexinit(&p, "b").unwrap();
        assert!(o.kex.is_empty());
    }

    #[test]
    fn unwraps_the_binary_packet_framing() {
        let payload = b"hello";
        let pad: &[u8] = &[0u8; 6];
        let len = (1 + payload.len() + pad.len()) as u32;
        let mut pkt = len.to_be_bytes().to_vec();
        pkt.push(pad.len() as u8);
        pkt.extend_from_slice(payload);
        pkt.extend_from_slice(pad);
        assert_eq!(unwrap_packet(&pkt).unwrap(), payload);
    }

    #[test]
    fn rejects_framing_that_does_not_add_up() {
        // Padding longer than the packet claims to be.
        let mut pkt = 3u32.to_be_bytes().to_vec();
        pkt.push(200);
        pkt.extend_from_slice(&[0u8; 8]);
        assert!(unwrap_packet(&pkt).is_err());

        assert!(unwrap_packet(&0u32.to_be_bytes()).is_err());
        assert!(unwrap_packet(&[0, 1]).is_err());
        assert!(unwrap_packet(&u32::MAX.to_be_bytes()).is_err());
    }
}
