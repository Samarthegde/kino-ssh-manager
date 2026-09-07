//! Import hosts from the user's OpenSSH client config (`~/.ssh/config`).
//!
//! We parse `Host` blocks, skipping wildcard patterns (`*`, `?`, `!`), and map
//! the common directives (HostName / User / Port / IdentityFile) to kino hosts.
//! Nothing here writes to disk - the caller decides which parsed hosts to save.

use crate::vault::Host;
use std::path::PathBuf;

/// Accumulates directives for the current `Host` block while parsing.
#[derive(Default, Clone)]
struct Block {
    aliases: Vec<String>,
    hostname: Option<String>,
    user: Option<String>,
    port: Option<u16>,
    identity_file: Option<String>,
}

fn ssh_config_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".ssh").join("config"))
}

/// The current OS user, used when a Host block omits `User`.
fn current_user() -> Option<String> {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .ok()
        .filter(|s| !s.is_empty())
}

/// Expand a leading `~` to the user's home directory.
fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(path)
}

fn is_wildcard(pattern: &str) -> bool {
    pattern.contains('*') || pattern.contains('?') || pattern.contains('!')
}

/// Turn a finished block into one host per non-wildcard alias.
fn block_to_hosts(block: &Block, default_user: Option<&str>) -> Vec<Host> {
    let mut out = Vec::new();
    for alias in &block.aliases {
        if is_wildcard(alias) {
            continue;
        }
        let hostname = block.hostname.clone().unwrap_or_else(|| alias.clone());
        if hostname.is_empty() {
            continue;
        }
        let username = block
            .user
            .clone()
            .or_else(|| default_user.map(str::to_string))
            .unwrap_or_default();

        // If an identity file is present and readable, store the key and default
        // to key auth; otherwise fall back to SSH-agent auth.
        let private_key = block
            .identity_file
            .as_deref()
            .map(expand_tilde)
            .and_then(|p| std::fs::read_to_string(p).ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let default_auth = if private_key.is_some() {
            "SshKey"
        } else {
            "Agent"
        };

        out.push(Host {
            id: String::new(),
            name: alias.clone(),
            hostname,
            port: block.port.unwrap_or(22),
            username,
            default_auth: default_auth.to_string(),
            password: None,
            private_key,
            public_key: None,
            passphrase: None,
            port_forwards: Vec::new(),
            on_connect_snippets: Vec::new(),
            color: None,
            notes: None,
            group: Some("Imported".to_string()),
            os: None,
            connection_mode: Some("direct".to_string()),
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
        });
    }
    out
}

/// Parse raw `ssh_config` text into hosts. `Match` blocks are ignored.
pub fn parse(text: &str, default_user: Option<&str>) -> Vec<Host> {
    let mut hosts = Vec::new();
    let mut current: Option<Block> = None;
    let mut in_match = false;

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Split "Key value..." on the first run of whitespace or an '='.
        let (key, value) = match line.split_once(|c: char| c.is_whitespace() || c == '=') {
            Some((k, v)) => (
                k.trim().to_lowercase(),
                v.trim().trim_matches('"').to_string(),
            ),
            None => (line.to_lowercase(), String::new()),
        };

        match key.as_str() {
            "host" => {
                in_match = false;
                if let Some(block) = current.take() {
                    hosts.extend(block_to_hosts(&block, default_user));
                }
                let aliases = value
                    .split_whitespace()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>();
                current = Some(Block {
                    aliases,
                    ..Default::default()
                });
            }
            "match" => {
                // Flush any open Host block; skip directives until the next Host.
                in_match = true;
                if let Some(block) = current.take() {
                    hosts.extend(block_to_hosts(&block, default_user));
                }
            }
            _ if in_match => {}
            "hostname" => {
                if let Some(b) = current.as_mut() {
                    b.hostname = Some(value);
                }
            }
            "user" => {
                if let Some(b) = current.as_mut() {
                    b.user = Some(value);
                }
            }
            "port" => {
                if let Some(b) = current.as_mut() {
                    if let Ok(p) = value.parse::<u16>() {
                        b.port = Some(p);
                    }
                }
            }
            "identityfile" => {
                if let Some(b) = current.as_mut() {
                    if b.identity_file.is_none() && !value.is_empty() {
                        b.identity_file = Some(value);
                    }
                }
            }
            _ => {}
        }
    }
    if let Some(block) = current.take() {
        hosts.extend(block_to_hosts(&block, default_user));
    }
    hosts
}

const BLOCK_START: &str = "# >>> kino start >>>";
const BLOCK_END: &str = "# <<< kino end <<<";

/// Drop any previously-written kino block, leaving the user's own config intact.
/// Unterminated blocks (hand-edited file) are dropped to end-of-file.
fn strip_managed_block(text: &str) -> String {
    let mut out = Vec::new();
    let mut inside = false;
    for line in text.lines() {
        let t = line.trim();
        if t == BLOCK_START {
            inside = true;
            continue;
        }
        if t == BLOCK_END {
            inside = false;
            continue;
        }
        if !inside {
            out.push(line);
        }
    }
    let mut s = out.join("\n");
    while s.ends_with('\n') {
        s.pop();
    }
    s
}

/// Render hosts as an ssh_config block.
///
/// Only the connection identity is emitted (HostName/User/Port). Private keys
/// live in the encrypted vault and are deliberately never written to disk, so
/// no `IdentityFile` is produced. Agent-mode (relay) hosts have no reachable
/// hostname and are skipped.
pub fn render_block(hosts: &[Host]) -> (String, usize) {
    let mut body = String::new();
    let mut count = 0;
    for host in hosts {
        if host.connection_mode.as_deref() == Some("agent") {
            continue;
        }
        if host.hostname.trim().is_empty() || host.name.trim().is_empty() {
            continue;
        }
        // An alias with whitespace would parse as multiple patterns.
        let alias = host.name.trim().replace(char::is_whitespace, "-");
        body.push_str(&format!("Host {}\n", alias));
        body.push_str(&format!("  HostName {}\n", host.hostname.trim()));
        if !host.username.trim().is_empty() {
            body.push_str(&format!("  User {}\n", host.username.trim()));
        }
        body.push_str(&format!("  Port {}\n", host.port));
        body.push('\n');
        count += 1;
    }
    let block = format!(
        "{BLOCK_START}\n# Managed by Kino SSH Manager - edits inside this block are overwritten.\n{}{BLOCK_END}\n",
        body
    );
    (block, count)
}

/// Write the given hosts into a marked, auto-managed block in `~/.ssh/config`,
/// preserving everything outside the block. Returns how many hosts were written.
pub fn export(hosts: &[Host]) -> Result<usize, String> {
    let path = ssh_config_path().ok_or("Could not locate your home directory")?;
    let dir = path.parent().ok_or("Invalid ssh config path")?;
    std::fs::create_dir_all(dir)
        .map_err(|e| format!("Could not create {}: {}", dir.display(), e))?;

    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let kept = strip_managed_block(&existing);
    let (block, count) = render_block(hosts);

    let mut out = String::new();
    if !kept.trim().is_empty() {
        out.push_str(&kept);
        out.push_str("\n\n");
    }
    out.push_str(&block);

    std::fs::write(&path, out).map_err(|e| format!("Could not write {}: {}", path.display(), e))?;

    // ssh refuses a world-readable config for some directives; match OpenSSH.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }

    Ok(count)
}

/// Read and parse `~/.ssh/config`. Returns an empty list if the file is absent.
pub fn import() -> Result<Vec<Host>, String> {
    let path = ssh_config_path().ok_or("Could not locate your home directory")?;
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("Could not read {}: {}", path.display(), e)),
    };
    Ok(parse(&text, current_user().as_deref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_blocks_and_skips_wildcards() {
        let cfg = "\
Host *
  ServerAliveInterval 60

Host prod
  HostName 10.0.0.5
  User deploy
  Port 2222

Host bastion gw
  HostName gw.example.com
";
        let hosts = parse(cfg, Some("me"));
        // "*" skipped; "prod" + "bastion" + "gw" = 3 hosts.
        assert_eq!(hosts.len(), 3);
        let prod = hosts.iter().find(|h| h.name == "prod").unwrap();
        assert_eq!(prod.hostname, "10.0.0.5");
        assert_eq!(prod.username, "deploy");
        assert_eq!(prod.port, 2222);
        // No identity file - agent auth, default user applied where User omitted.
        assert_eq!(prod.default_auth, "Agent");
        let gw = hosts.iter().find(|h| h.name == "gw").unwrap();
        assert_eq!(gw.username, "me");
        assert_eq!(gw.hostname, "gw.example.com");
        assert_eq!(gw.port, 22);
    }

    #[test]
    fn hostname_falls_back_to_alias() {
        let hosts = parse("Host myserver\n  User root\n", None);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].hostname, "myserver");
    }

    #[test]
    fn ignores_match_blocks() {
        let cfg = "Match host foo\n  User bar\nHost real\n  HostName r.example.com\n";
        let hosts = parse(cfg, None);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].name, "real");
    }

    fn host(name: &str, hostname: &str, port: u16) -> Host {
        let mut hosts = parse(
            &format!("Host {name}\n  HostName {hostname}\n  User bob\n"),
            None,
        );
        let mut h = hosts.remove(0);
        h.port = port;
        h
    }

    #[test]
    fn strip_removes_only_the_managed_block() {
        let text = format!(
            "Host mine\n  HostName keep.example.com\n\n{BLOCK_START}\nHost gen\n  HostName x\n{BLOCK_END}\n"
        );
        let kept = strip_managed_block(&text);
        assert!(kept.contains("keep.example.com"));
        assert!(!kept.contains("Host gen"));
    }

    #[test]
    fn strip_handles_unterminated_block() {
        let text =
            format!("Host mine\n  HostName keep.me\n{BLOCK_START}\nHost gen\n  HostName x\n");
        let kept = strip_managed_block(&text);
        assert!(kept.contains("keep.me"));
        assert!(!kept.contains("Host gen"));
    }

    #[test]
    fn render_skips_agent_hosts_and_emits_parsable_config() {
        let mut agent = host("relayed", "ignored", 22);
        agent.connection_mode = Some("agent".to_string());
        agent.hostname = String::new();
        let hosts = vec![host("prod", "10.0.0.5", 2222), agent];

        let (block, count) = render_block(&hosts);
        assert_eq!(count, 1);
        assert!(!block.contains("relayed"));
        // Never write private keys to disk.
        assert!(!block.contains("IdentityFile"));

        // Round-trip: what we emit must parse back to the same connection.
        let reparsed = parse(&block, None);
        assert_eq!(reparsed.len(), 1);
        assert_eq!(reparsed[0].name, "prod");
        assert_eq!(reparsed[0].hostname, "10.0.0.5");
        assert_eq!(reparsed[0].port, 2222);
        assert_eq!(reparsed[0].username, "bob");
    }

    #[test]
    fn render_collapses_whitespace_in_alias() {
        // Display names come from the UI and may contain spaces; an alias with
        // whitespace would parse back as several Host patterns.
        let mut h = host("tmp", "h.example.com", 22);
        h.name = "my server".to_string();
        let (block, _) = render_block(&[h]);
        assert!(block.contains("Host my-server"));
        assert_eq!(parse(&block, None).len(), 1);
    }
}
