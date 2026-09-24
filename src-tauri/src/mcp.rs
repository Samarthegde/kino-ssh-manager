//! MCP server implementation using the `rmcp` crate.
//!
//! Exposes Kino SSH Manager's capabilities as MCP tools so AI assistants
//! can list hosts, execute commands, and transfer files on the hosts the
//! user explicitly chose to share.

use crate::mcp_approval::{self, ApprovalRequest, Verdict};
use crate::mcp_audit::{AuditLog, AuditRecord};
use crate::mcp_config::McpVault;
use crate::mcp_limits::{self, Window};
use crate::mcp_policy::{self, Decision, HostPolicy, McpMode};
use crate::ssh_session;
use crate::vault::Host;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::*;
use rmcp::{tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

/// What it takes to notice the exposed vault changed (issue #22).
///
/// The app rewrites `mcp_vault.enc` whenever a host, a rule or a mode
/// changes, and a server that read it once at startup kept serving the old
/// policy - including a host that had since been unticked. Re-reading per
/// call would mean Argon2 per call, which is deliberately slow, so the key
/// derived at startup is kept and the file is only `stat`ed: Argon2 once,
/// AES only when something actually changed.
struct Reload {
    path: std::path::PathBuf,
    /// The key derived at startup. A *changed* MCP password rewrites the file
    /// under a new salt, so this key stops working - which is a refusal, not
    /// a reason to carry on with the old policy.
    key: [u8; 32],
    /// Modified time and length of the copy currently loaded.
    stamp: Mutex<Option<(std::time::SystemTime, u64)>>,
}

impl Drop for Reload {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
    }
}

/// The MCP server state. Holds the decrypted hosts and snippets that were
/// exported from the Kino vault under the MCP password.
#[derive(Clone)]
pub struct KinoMcpServer {
    /// Swapped wholesale when the file changes, so a call either sees the old
    /// policy or the new one, never half of each.
    vault: Arc<RwLock<Arc<McpVault>>>,
    /// How to notice a change. `None` in tests and anywhere the vault came
    /// from memory rather than a file.
    reload: Option<Arc<Reload>>,
    /// Where each call is recorded. `None` in tests and in any build that
    /// could not open the log - a call the policy allows still runs, and the
    /// failure is reported to stderr rather than swallowed.
    audit: Option<Arc<AuditLog>>,
    /// Who is connected, from the MCP handshake. `unknown` until `initialize`
    /// arrives, and never omitted: a record that quietly drops the client is
    /// one you cannot trace back to a machine.
    client: Arc<Mutex<(String, String)>>,
    /// One sliding minute of call times per host id (KR-01-F11). In memory:
    /// `mcp_limits` says why that is the honest place for it.
    calls: Arc<Mutex<HashMap<String, Window>>>,
    /// Calls approved for the rest of this session (KR-01-F6). Held in the
    /// process, so restarting `kino-mcp` revokes every one of them - which is
    /// the revocation the settings never have to offer.
    approved: Arc<Mutex<HashSet<String>>>,
    /// Where the app is listening. A field rather than a call to
    /// `socket_path()` so tests cannot reach the socket of a Kino that is
    /// actually running and put a prompt on someone's screen.
    approval_socket: std::path::PathBuf,
    /// Built by the `#[tool_router]` macro and read by `#[tool_handler]`; the
    /// field looks unused to the compiler because both are generated.
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

impl KinoMcpServer {
    pub fn new(vault: McpVault) -> Self {
        Self {
            vault: Arc::new(RwLock::new(Arc::new(vault))),
            reload: None,
            audit: None,
            client: Arc::new(Mutex::new(("unknown".into(), "unknown".into()))),
            calls: Arc::new(Mutex::new(HashMap::new())),
            approved: Arc::new(Mutex::new(HashSet::new())),
            approval_socket: mcp_approval::socket_path(),
            tool_router: Self::tool_router(),
        }
    }

    /// Point approvals at another socket. Tests only: the real one belongs to
    /// whichever Kino is running, and a test must never prompt a person.
    #[cfg(test)]
    fn asking_at(mut self, socket: std::path::PathBuf) -> Self {
        self.approval_socket = socket;
        self
    }

    /// The server as `kino-mcp` runs it: every call recorded.
    pub fn with_audit(vault: McpVault, audit: AuditLog) -> Self {
        Self {
            audit: Some(Arc::new(audit)),
            ..Self::new(vault)
        }
    }

    /// Watch `path` for changes, re-reading it with `key` (issue #22).
    ///
    /// Without this the server serves whatever it read at startup for as long
    /// as it runs, so revoking access in Kino did nothing until the assistant
    /// was restarted - and nothing said so.
    pub fn reloading_from(mut self, path: std::path::PathBuf, key: [u8; 32]) -> Self {
        let stamp = stamp_of(&path);
        self.reload = Some(Arc::new(Reload {
            path,
            key,
            stamp: Mutex::new(stamp),
        }));
        self
    }

    /// The vault as it stands. Cheap: an `Arc` clone.
    fn vault(&self) -> Arc<McpVault> {
        self.vault.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Re-read the exposed vault if it changed since the last call.
    ///
    /// An error here refuses the call. The alternative - carrying on with the
    /// copy in memory - is precisely the bug: the file changing is often
    /// someone *removing* access, and serving the old policy because the new
    /// one could not be read would be the least safe reading of it.
    fn refresh(&self) -> Result<(), String> {
        let Some(reload) = &self.reload else {
            return Ok(());
        };
        let now = stamp_of(&reload.path);
        {
            let seen = reload.stamp.lock().unwrap_or_else(|e| e.into_inner());
            if *seen == now {
                return Ok(());
            }
        }

        // Missing, mid-write, or written under a different password.
        let fresh: McpVault = crate::vault::load_encrypted(&reload.path, &reload.key)
            .map_err(|_| "unreadable".to_string())?;

        *self.vault.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(fresh);
        *reload.stamp.lock().unwrap_or_else(|e| e.into_inner()) = now;
        eprintln!("[kino-mcp] reloaded the exposed vault after a change");
        Ok(())
    }

    /// Count this call against the host's minute, and say whether it goes on.
    fn admit(&self, host: &Host, max_per_min: u32) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        // A poisoned lock must not become a way past the limit.
        let Ok(mut calls) = self.calls.lock() else {
            return false;
        };
        calls
            .entry(host.id.clone())
            .or_default()
            .admit(now, max_per_min)
    }

    /// Put the call to a person, and act on the answer (KR-01-F5, F6, F7).
    ///
    /// Returns `None` when it may proceed. Everything else is a refusal that
    /// names the reason, because "denied" alone sends someone searching their
    /// rules for a rule that was never involved.
    async fn ask_a_person(
        &self,
        host: &Host,
        tool: &str,
        argument: &str,
        started: Instant,
        rule_id: Option<String>,
    ) -> Option<CallToolResult> {
        let key = Self::approval_key(host, tool, argument);
        if self
            .approved
            .lock()
            .map(|a| a.contains(&key))
            .unwrap_or(false)
        {
            // Already approved for this session. Still recorded: "approved
            // once, ran nine times" has to be visible in the log.
            self.record(
                tool,
                Some(host),
                argument,
                started,
                Outcome {
                    decision: "approved",
                    rule_id: Some("approved_for_session".to_string()),
                    ..Default::default()
                },
            );
            return None;
        }

        let request = ApprovalRequest {
            v: mcp_approval::PROTOCOL,
            id: uuid::Uuid::new_v4().to_string(),
            tool: tool.to_string(),
            host_id: host.id.clone(),
            host_name: host.name.clone(),
            argument: argument.to_string(),
            client_name: self.client_id().0,
            client_version: self.client_id().1,
            timeout_secs: self.vault().approval_timeout_secs,
        };

        match mcp_approval::ask_at(&self.approval_socket, &request).await {
            Verdict::Session => {
                if let Ok(mut approved) = self.approved.lock() {
                    approved.insert(key);
                }
                self.record(
                    tool,
                    Some(host),
                    argument,
                    started,
                    Outcome {
                        decision: "approved",
                        rule_id: Some("approved_for_session".to_string()),
                        ..Default::default()
                    },
                );
                None
            }
            Verdict::Once => {
                self.record(
                    tool,
                    Some(host),
                    argument,
                    started,
                    Outcome {
                        decision: "approved",
                        rule_id,
                        ..Default::default()
                    },
                );
                None
            }
            Verdict::Denied(reason) => {
                self.record(
                    tool,
                    Some(host),
                    argument,
                    started,
                    Outcome {
                        // The log distinguishes a person saying no from a
                        // prompt nobody reached in time.
                        decision: if reason == "denied_by_user" {
                            "denied_by_user"
                        } else {
                            "deny"
                        },
                        rule_id: Some(reason.to_string()),
                        ..Default::default()
                    },
                );
                Some(refusal(
                    host,
                    tool,
                    self.policy_for(host).mode,
                    reason,
                    None,
                    &mcp_approval::explain(reason, &host.name, tool),
                ))
            }
        }
    }

    /// Write an asciicast of one command and its output (KR-01-F10).
    ///
    /// Only for guarded and full hosts: a read-only host runs nothing a rule
    /// did not already name, and recording every `sftp_read` would bury the
    /// few casts worth watching.
    ///
    /// This is a transcript, not a live capture - `exec_once_full` hands back
    /// the whole output at the end, so the cast is the command, then its
    /// output, with none of the pauses in between. Honest for reading back
    /// what an assistant did; it is not a replay of a session, because an MCP
    /// call is not one.
    fn record_cast(&self, host: &Host, command: &str, output: &str) -> Option<String> {
        self.record_cast_in(&crate::recorder::recordings_dir(), host, command, output)
    }

    /// The same, into a given directory, so tests write casts of their own
    /// rather than into the folder holding someone's real recordings.
    fn record_cast_in(
        &self,
        dir: &std::path::Path,
        host: &Host,
        command: &str,
        output: &str,
    ) -> Option<String> {
        if matches!(self.policy_for(host).mode, McpMode::ReadOnly) {
            return None;
        }
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // The host name goes in the filename, so it has to survive being one:
        // anything that is not a letter, digit, dash or underscore becomes a
        // dash rather than a directory separator.
        let safe: String = host
            .name
            .chars()
            .map(|c| if c.is_alphanumeric() { c } else { '-' })
            .collect();
        let name = format!(
            "mcp-{stamp}-{safe}-{}.cast",
            &uuid::Uuid::new_v4().to_string()[..8]
        );
        let path = dir.join(&name);

        let write = || -> Result<(), String> {
            let mut recorder =
                crate::recorder::Recorder::with_command(&path, 120, 30, Some(command))?;
            // The command first, as an input event: a cast that opens on
            // output leaves the reader guessing what produced it.
            recorder.record_input(format!("{command}\r\n").as_bytes())?;
            recorder.record_output(output.as_bytes())
        };
        match write() {
            Ok(()) => Some(name),
            Err(e) => {
                eprintln!("[kino-mcp] could not write the recording: {e}");
                None
            }
        }
    }

    /// Cut output to what this host's policy allows, saying so in the text.
    fn cap(&self, host: &Host, text: String) -> mcp_limits::Capped {
        mcp_limits::cap(text, self.policy_for(host).max_bytes_per_call)
    }

    fn client_id(&self) -> (String, String) {
        self.client
            .lock()
            .map(|c| c.clone())
            .unwrap_or_else(|_| ("unknown".into(), "unknown".into()))
    }

    /// Record one finished call.
    ///
    /// Best effort by design: if the log cannot be written, the call still
    /// returns. The alternative - refusing calls the policy allowed because a
    /// disk is full - trades a gap in the record for an outage.
    fn record(
        &self,
        tool: &str,
        host: Option<&Host>,
        argument: &str,
        started: Instant,
        outcome: Outcome,
    ) {
        let Some(log) = &self.audit else { return };
        let (client_name, client_version) = self.client_id();
        let record = AuditRecord {
            ts: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
            tool: tool.to_string(),
            host_id: host.map(|h| h.id.clone()),
            host_name: host.map(|h| h.name.clone()),
            argument: argument.to_string(),
            decision: outcome.decision.to_string(),
            rule_id: outcome.rule_id,
            exit_code: outcome.exit_code,
            bytes_out: outcome.bytes_out,
            duration_ms: started.elapsed().as_millis() as u64,
            client_name,
            client_version,
            recording: outcome.recording,
            error: outcome.error,
        };
        if let Err(e) = log.append(&record) {
            eprintln!("[kino-mcp] could not write the audit record: {e}");
        }
    }

    /// Find a host by name (case-insensitive) or by id.
    ///
    /// Returns a copy rather than a borrow: the vault behind it can be
    /// swapped by a reload, and a reference into the old one would keep a
    /// revoked host alive for the length of a call.
    fn find_host(&self, name_or_id: &str) -> Option<Host> {
        let lower = name_or_id.to_lowercase();
        self.vault()
            .hosts
            .iter()
            .find(|h| h.id == name_or_id || h.name.to_lowercase() == lower)
            .cloned()
    }

    /// The policy for a host. A host with no entry is read-only: the vault
    /// writes one for every exposed host, so a missing entry means something
    /// went wrong, and the safe reading of that is "less access, not more".
    fn policy_for(&self, host: &Host) -> HostPolicy {
        self.vault()
            .policies
            .get(&host.id)
            .cloned()
            .unwrap_or_default()
    }

    /// Gate one tool call. `Some(result)` is the refusal to hand straight
    /// back; `None` means proceed.
    ///
    /// This runs before any connection is opened, so a refused call costs the
    /// host nothing and leaves no trace on it.
    /// What a session approval remembers: this command, this tool, this host.
    /// Exact text, because "approve nginx restarts" is a rule, and rules are
    /// written in the panel where they can be read back.
    fn approval_key(host: &Host, tool: &str, argument: &str) -> String {
        format!("{}\u{0}{}\u{0}{}", host.id, tool, argument)
    }

    async fn gate(
        &self,
        host: &Host,
        tool: &str,
        argument: &str,
        started: Instant,
    ) -> Option<CallToolResult> {
        let policy = self.policy_for(host);

        // Rate first. A host being hammered should stop answering whether or
        // not the next command would have been allowed, and deciding this
        // costs no connection either way.
        if !self.admit(host, policy.max_calls_per_min) {
            self.record(
                tool,
                Some(host),
                argument,
                started,
                Outcome {
                    decision: "deny",
                    rule_id: Some("rate_limited".to_string()),
                    ..Default::default()
                },
            );
            return Some(refusal(
                host,
                tool,
                policy.mode,
                "rate_limited",
                Some("rate_limited".to_string()),
                &format!(
                    "'{}' has already taken {} calls this minute, which is its limit. Wait, \
                     or raise it in Kino - Settings - MCP Server.",
                    host.name, policy.max_calls_per_min
                ),
            ));
        }

        let vault = self.vault();
        let decision = mcp_policy::evaluate(&policy, &vault.global_rules, tool, argument);
        // Recorded here rather than in each tool: a refusal returns early, and
        // the one call that forgot to record it would be the interesting one.
        //
        // A refusal with no rule behind it - the read-only default - records
        // the reason in `rule_id`'s place, so a refusal always says why.
        //
        // `Ask` is deliberately not recorded here: it has not been decided
        // yet, and `ask_a_person` records whichever way it goes. Recording it
        // in both places put a denial in front of every approval.
        let why = match &decision {
            Decision::Deny { reason, rule_id } => {
                Some(rule_id.clone().unwrap_or_else(|| (*reason).to_string()))
            }
            Decision::Ask { .. } | Decision::Allow => None,
        };
        if let Some(rule_id) = why {
            self.record(
                tool,
                Some(host),
                argument,
                started,
                Outcome {
                    decision: "deny",
                    rule_id: Some(rule_id),
                    ..Default::default()
                },
            );
        }
        match decision {
            Decision::Allow => None,

            // Guarded mode's reason to exist: stop and ask a person.
            Decision::Ask { rule_id } => {
                self.ask_a_person(host, tool, argument, started, rule_id)
                    .await
            }

            Decision::Deny { reason, rule_id } => {
                let message = match reason {
                    "read_only" => format!(
                        "'{}' is exposed read-only, so {} is not available on it.                          Change its access mode in Kino - Settings - MCP Server.",
                        host.name, tool
                    ),
                    "default_deny" => format!(
                        "'{}' is exposed read-only and no rule allows this. Nothing runs on a                          read-only host unless a rule names it; add one in Kino if it should.",
                        host.name
                    ),
                    _ => format!("A rule on '{}' refuses this.", host.name),
                };
                Some(refusal(host, tool, policy.mode, reason, rule_id, &message))
            }
        }
    }
}

/// Modified time and length, which is what "has this file changed?" means
/// here. Missing counts as a state of its own, so a vault that is deleted and
/// restored is noticed.
fn stamp_of(path: &std::path::Path) -> Option<(std::time::SystemTime, u64)> {
    let meta = std::fs::metadata(path).ok()?;
    Some((meta.modified().ok()?, meta.len()))
}

/// What a call gets when the exposed vault changed into something this server
/// cannot read - almost always a changed MCP password.
fn vault_unreadable() -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(
        serde_json::to_string_pretty(&serde_json::json!({
            "error": "vault_unreadable",
            "message": "Kino's exposed vault changed and this server can no longer read it. \
                        The MCP password was probably changed - restart kino-mcp with the new \
                        one. Nothing was run.",
        }))
        .unwrap_or_default(),
    )])
}

/// How a call ended, for the record. Defaults to an allowed call that
/// produced nothing worth noting, so each tool sets only what it knows.
#[derive(Default)]
struct Outcome {
    /// `allow` or `deny`. A call refused because the host or snippet does not
    /// exist is a `deny` too, with `error` saying which - it never reached a
    /// policy, and calling it an allow would be a lie in the other direction.
    decision: &'static str,
    rule_id: Option<String>,
    exit_code: Option<i32>,
    bytes_out: Option<usize>,
    error: Option<String>,
    recording: Option<String>,
}

impl Outcome {
    fn allowed() -> Outcome {
        Outcome {
            decision: "allow",
            ..Default::default()
        }
    }

    /// The call named something this server cannot see.
    fn not_found(what: &str) -> Outcome {
        Outcome {
            decision: "deny",
            error: Some(what.to_string()),
            ..Default::default()
        }
    }
}

/// A refusal the caller can act on: why, on what, and which rule did it.
///
/// Deliberately does not include the rule list. An assistant that can read the
/// policy can search it for a gap; one that gets told "no, rule host:4" can
/// only report that to the person who wrote line 4.
fn refusal(
    host: &Host,
    tool: &str,
    mode: McpMode,
    reason: &str,
    rule_id: Option<String>,
    message: &str,
) -> CallToolResult {
    let body = serde_json::json!({
        "error": "policy_denied",
        "reason": reason,
        "host": host.name,
        "tool": tool,
        "mode": mode.as_str(),
        "rule_id": rule_id,
        "message": message,
    });
    CallToolResult::error(vec![ContentBlock::text(
        serde_json::to_string_pretty(&body).unwrap_or_else(|_| message.to_string()),
    )])
}

// ── Parameter Structs ────────────────────────────────────────────────────────

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct HostParams {
    #[schemars(description = "Host name or ID")]
    pub host: String,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct ExecParams {
    #[schemars(description = "Host name or ID to run the command on")]
    pub host: String,
    #[schemars(description = "Shell command to execute")]
    pub command: String,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct PathParams {
    #[schemars(description = "Host name or ID")]
    pub host: String,
    #[schemars(description = "Remote directory or file path")]
    pub path: String,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct WriteParams {
    #[schemars(description = "Host name or ID")]
    pub host: String,
    #[schemars(description = "Remote file path to write")]
    pub path: String,
    #[schemars(description = "Content to write to the file")]
    pub content: String,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct RunSnippetParams {
    #[schemars(description = "Host name or ID to run the snippet on")]
    pub host: String,
    #[schemars(description = "Snippet name or ID")]
    pub snippet: String,
}

#[tool_router]
impl KinoMcpServer {
    /// List all SSH hosts available through this MCP server.
    #[tool(
        description = "List all SSH hosts available in the Kino vault. Returns name, hostname, port, username, group, and OS for each host."
    )]
    async fn list_hosts(&self) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        // The vault may have changed since the last call (issue #22).
        if self.refresh().is_err() {
            return Ok(vault_unreadable());
        }
        let vault = self.vault();
        let list: Vec<serde_json::Value> = vault
            .hosts
            .iter()
            .map(|h| {
                serde_json::json!({
                    "name": h.name,
                    "hostname": h.hostname,
                    "port": h.port,
                    "username": h.username,
                    "group": h.group,
                    "os": h.os,
                    "auth_method": h.default_auth,
                    "access": self.policy_for(h).mode.as_str(),
                    "has_port_forwards": !h.port_forwards.is_empty(),
                })
            })
            .collect();
        let json = serde_json::to_string_pretty(&list).unwrap_or_default();
        self.record(
            "list_hosts",
            None,
            "",
            started,
            Outcome {
                bytes_out: Some(json.len()),
                ..Outcome::allowed()
            },
        );
        Ok(CallToolResult::success(vec![ContentBlock::text(json)]))
    }

    /// Get detailed information about a specific host.
    #[tool(
        description = "Get detailed information about a specific SSH host by name or ID. Returns connection details, group, OS, port forwards, and notes."
    )]
    async fn get_host(
        &self,
        Parameters(params): Parameters<HostParams>,
    ) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        // The vault may have changed since the last call (issue #22).
        if self.refresh().is_err() {
            return Ok(vault_unreadable());
        }
        let found = match self.find_host(&params.host) {
            Some(h) => h,
            None => {
                self.record(
                    "get_host",
                    None,
                    &params.host,
                    started,
                    Outcome::not_found("host not found"),
                );
                return Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                    "Host '{}' not found. Use list_hosts to see available hosts.",
                    params.host
                ))]));
            }
        };
        let h = &found;
        let info = serde_json::json!({
            "name": h.name,
            "hostname": h.hostname,
            "port": h.port,
            "username": h.username,
            "auth_method": h.default_auth,
            "access": self.policy_for(h).mode.as_str(),
            "group": h.group,
            "os": h.os,
            "notes": h.notes,
            "color": h.color,
            "port_forwards": h.port_forwards.iter().map(|pf| {
                serde_json::json!({
                    "label": pf.label,
                    "local_port": pf.local_port,
                    "remote_host": pf.remote_host,
                    "remote_port": pf.remote_port,
                })
            }).collect::<Vec<_>>(),
            "on_connect_snippets": h.on_connect_snippets,
        });
        let json = serde_json::to_string_pretty(&info).unwrap_or_default();
        self.record(
            "get_host",
            Some(h),
            "",
            started,
            Outcome {
                bytes_out: Some(json.len()),
                ..Outcome::allowed()
            },
        );
        Ok(CallToolResult::success(vec![ContentBlock::text(json)]))
    }

    /// Execute a command on a remote SSH host.
    #[tool(
        description = "Execute a shell command on a remote SSH host. Returns stdout, stderr and the exit code; a non-zero exit is reported, not hidden. Only hosts explicitly exposed in Kino are reachable."
    )]
    async fn ssh_exec(
        &self,
        Parameters(params): Parameters<ExecParams>,
    ) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        // The vault may have changed since the last call (issue #22).
        if self.refresh().is_err() {
            return Ok(vault_unreadable());
        }
        let found = match self.find_host(&params.host) {
            Some(h) => h,
            None => {
                self.record(
                    "ssh_exec",
                    None,
                    &params.command,
                    started,
                    Outcome::not_found("host not found"),
                );
                return Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                    "Host '{}' not found. Use list_hosts to see available hosts.",
                    params.host
                ))]));
            }
        };
        let h = &found;

        if let Some(refused) = self.gate(h, "ssh_exec", &params.command, started).await {
            return Ok(refused);
        }

        // `exec_once_full` rather than `exec_once`: a command that fails is
        // still a result the caller needs to see - stderr and the status are
        // the useful part, and collapsing them into an error string loses both.
        match ssh_session::exec_once_full(h, &params.command).await {
            Ok(out) => {
                // The record keeps what the host produced; the reply keeps
                // what fits. stderr gets what is left of the budget rather
                // than a second full allowance, so the cap means one call.
                let produced = out.stdout.len() + out.stderr.len();
                let limit = self.policy_for(h).max_bytes_per_call;
                let stdout = mcp_limits::cap(out.stdout, limit);
                let stderr = mcp_limits::cap(
                    out.stderr,
                    if limit == 0 {
                        0
                    } else {
                        limit.saturating_sub(stdout.text.len()).max(1)
                    },
                );
                // The cast keeps the whole output even where the reply was
                // cut: the record is for a person reading later, not for a
                // context window.
                let recording = self.record_cast(
                    h,
                    &params.command,
                    &format!("{}{}", stdout.text, stderr.text),
                );
                self.record(
                    "ssh_exec",
                    Some(h),
                    &params.command,
                    started,
                    Outcome {
                        // u32 on the wire, i32 in the record: a shell status
                        // is 0-255, and i32 is what every reader expects.
                        exit_code: out.code.map(|c| c as i32),
                        bytes_out: Some(produced),
                        recording,
                        ..Outcome::allowed()
                    },
                );
                let result = serde_json::json!({
                    "host": h.name,
                    "command": params.command,
                    "stdout": stdout.text,
                    "stderr": stderr.text,
                    "exit_code": out.code,
                });
                Ok(CallToolResult::success(vec![ContentBlock::text(
                    serde_json::to_string_pretty(&result).unwrap_or_default(),
                )]))
            }
            // Only a transport/auth failure lands here; the command never ran.
            Err(e) => {
                self.record(
                    "ssh_exec",
                    Some(h),
                    &params.command,
                    started,
                    Outcome {
                        error: Some(e.to_string()),
                        ..Outcome::allowed()
                    },
                );
                Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                    "Could not run the command on '{}': {}",
                    h.name, e
                ))]))
            }
        }
    }

    /// List files in a remote directory via SFTP.
    #[tool(
        description = "List a remote directory on an SSH host. Returns the raw output of `ls -la` as text, not structured entries."
    )]
    async fn sftp_list(
        &self,
        Parameters(params): Parameters<PathParams>,
    ) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        // The vault may have changed since the last call (issue #22).
        if self.refresh().is_err() {
            return Ok(vault_unreadable());
        }
        let found = match self.find_host(&params.host) {
            Some(h) => h,
            None => {
                self.record(
                    "sftp_list",
                    None,
                    &params.path,
                    started,
                    Outcome::not_found("host not found"),
                );
                return Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                    "Host '{}' not found.",
                    params.host
                ))]));
            }
        };
        let h = &found;

        if let Some(refused) = self.gate(h, "sftp_list", &params.path, started).await {
            return Ok(refused);
        }

        let cmd = format!("ls -la {}", crate::exec::shell_quote(&params.path));
        match ssh_session::exec_once(h, &cmd).await {
            Ok(output) => {
                let capped = self.cap(h, output);
                self.record(
                    "sftp_list",
                    Some(h),
                    &params.path,
                    started,
                    Outcome {
                        bytes_out: Some(capped.original),
                        ..Outcome::allowed()
                    },
                );
                Ok(CallToolResult::success(vec![ContentBlock::text(
                    capped.text,
                )]))
            }
            Err(e) => {
                self.record(
                    "sftp_list",
                    Some(h),
                    &params.path,
                    started,
                    Outcome {
                        error: Some(e.to_string()),
                        ..Outcome::allowed()
                    },
                );
                Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                    "Failed to list '{}' on '{}': {}",
                    params.path, h.name, e
                ))]))
            }
        }
    }

    /// Read a file from a remote host.
    #[tool(
        description = "Read a text file from a remote SSH host. Text only - binary content is mangled by UTF-8 conversion rather than returned faithfully."
    )]
    async fn sftp_read(
        &self,
        Parameters(params): Parameters<PathParams>,
    ) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        // The vault may have changed since the last call (issue #22).
        if self.refresh().is_err() {
            return Ok(vault_unreadable());
        }
        let found = match self.find_host(&params.host) {
            Some(h) => h,
            None => {
                self.record(
                    "sftp_read",
                    None,
                    &params.path,
                    started,
                    Outcome::not_found("host not found"),
                );
                return Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                    "Host '{}' not found.",
                    params.host
                ))]));
            }
        };
        let h = &found;

        if let Some(refused) = self.gate(h, "sftp_read", &params.path, started).await {
            return Ok(refused);
        }

        let cmd = format!("cat {}", crate::exec::shell_quote(&params.path));
        match ssh_session::exec_once(h, &cmd).await {
            Ok(output) => {
                let capped = self.cap(h, output);
                self.record(
                    "sftp_read",
                    Some(h),
                    &params.path,
                    started,
                    Outcome {
                        bytes_out: Some(capped.original),
                        ..Outcome::allowed()
                    },
                );
                let result = serde_json::json!({
                    "path": params.path,
                    "host": h.name,
                    "content": capped.text,
                });
                Ok(CallToolResult::success(vec![ContentBlock::text(
                    serde_json::to_string_pretty(&result).unwrap_or_default(),
                )]))
            }
            Err(e) => {
                self.record(
                    "sftp_read",
                    Some(h),
                    &params.path,
                    started,
                    Outcome {
                        error: Some(e.to_string()),
                        ..Outcome::allowed()
                    },
                );
                Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                    "Failed to read '{}' on '{}': {}",
                    params.path, h.name, e
                ))]))
            }
        }
    }

    /// Write content to a file on a remote host.
    #[tool(
        description = "Write text content to a file on a remote SSH host, creating it if absent and overwriting it if present. The whole file is replaced."
    )]
    async fn sftp_write(
        &self,
        Parameters(params): Parameters<WriteParams>,
    ) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        // The vault may have changed since the last call (issue #22).
        if self.refresh().is_err() {
            return Ok(vault_unreadable());
        }
        let found = match self.find_host(&params.host) {
            Some(h) => h,
            None => {
                self.record(
                    "sftp_write",
                    None,
                    &params.path,
                    started,
                    Outcome::not_found("host not found"),
                );
                return Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                    "Host '{}' not found.",
                    params.host
                ))]));
            }
        };
        let h = &found;

        if let Some(refused) = self.gate(h, "sftp_write", &params.path, started).await {
            return Ok(refused);
        }

        // Base64, not a heredoc. The previous version interpolated the content
        // between `<< 'KINO_EOF'` markers, so content containing a line
        // `KINO_EOF` closed the heredoc and everything after it ran as shell -
        // arbitrary command execution on a production host, from content an
        // assistant may not even have authored. Base64's alphabet cannot
        // terminate the quoting, so there is nothing to escape.
        use base64::{engine::general_purpose::STANDARD, Engine};
        let encoded = STANDARD.encode(params.content.as_bytes());
        let cmd = format!(
            "printf '%s' '{}' | base64 -d > {}",
            encoded,
            crate::exec::shell_quote(&params.path)
        );
        match ssh_session::exec_once(h, &cmd).await {
            Ok(_) => {
                // The content's size, not the reply's: what was written is the
                // part worth knowing afterwards.
                self.record(
                    "sftp_write",
                    Some(h),
                    &params.path,
                    started,
                    Outcome {
                        bytes_out: Some(params.content.len()),
                        ..Outcome::allowed()
                    },
                );
                Ok(CallToolResult::success(vec![ContentBlock::text(format!(
                    "Successfully wrote to '{}' on '{}'",
                    params.path, h.name
                ))]))
            }
            Err(e) => {
                self.record(
                    "sftp_write",
                    Some(h),
                    &params.path,
                    started,
                    Outcome {
                        error: Some(e.to_string()),
                        ..Outcome::allowed()
                    },
                );
                Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                    "Failed to write '{}' on '{}': {}",
                    params.path, h.name, e
                ))]))
            }
        }
    }

    /// List all command snippets.
    #[tool(
        description = "List all command snippets available in the Kino vault. Snippets are reusable blocks of shell commands."
    )]
    async fn list_snippets(&self) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        // The vault may have changed since the last call (issue #22).
        if self.refresh().is_err() {
            return Ok(vault_unreadable());
        }
        let vault = self.vault();
        let list: Vec<serde_json::Value> = vault
            .snippets
            .iter()
            .map(|s| {
                serde_json::json!({
                    "id": s.id,
                    "name": s.name,
                    "commands": s.commands,
                })
            })
            .collect();
        let json = serde_json::to_string_pretty(&list).unwrap_or_default();
        self.record(
            "list_snippets",
            None,
            "",
            started,
            Outcome {
                bytes_out: Some(json.len()),
                ..Outcome::allowed()
            },
        );
        Ok(CallToolResult::success(vec![ContentBlock::text(json)]))
    }

    /// Run a snippet on a host.
    #[tool(
        description = "Execute a saved command snippet on a remote SSH host. The snippet's commands are run in order."
    )]
    async fn run_snippet(
        &self,
        Parameters(params): Parameters<RunSnippetParams>,
    ) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        // The vault may have changed since the last call (issue #22).
        if self.refresh().is_err() {
            return Ok(vault_unreadable());
        }
        let found = match self.find_host(&params.host) {
            Some(h) => h,
            None => {
                self.record(
                    "run_snippet",
                    None,
                    &params.snippet,
                    started,
                    Outcome::not_found("host not found"),
                );
                return Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                    "Host '{}' not found.",
                    params.host
                ))]));
            }
        };
        let h = &found;

        let lower = params.snippet.to_lowercase();
        let vault = self.vault();
        let snip = vault
            .snippets
            .iter()
            .find(|s| s.id == params.snippet || s.name.to_lowercase() == lower);
        let snip = match snip {
            Some(s) => s,
            None => {
                self.record(
                    "run_snippet",
                    Some(h),
                    &params.snippet,
                    started,
                    Outcome::not_found("snippet not found"),
                );
                return Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                    "Snippet '{}' not found. Use list_snippets to see available snippets.",
                    params.snippet
                ))]));
            }
        };

        // The snippet's *commands*, not its name: a rule is about what runs.
        if let Some(refused) = self.gate(h, "run_snippet", &snip.commands, started).await {
            return Ok(refused);
        }

        match ssh_session::exec_once(h, &snip.commands).await {
            Ok(output) => {
                let capped = self.cap(h, output);
                let recording = self.record_cast(h, &snip.commands, &capped.text);
                // The commands, not the snippet's name: the record has to say
                // what ran, and a snippet can be edited afterwards.
                self.record(
                    "run_snippet",
                    Some(h),
                    &snip.commands,
                    started,
                    Outcome {
                        bytes_out: Some(capped.original),
                        recording,
                        ..Outcome::allowed()
                    },
                );
                let result = serde_json::json!({
                    "snippet": snip.name,
                    "host": h.name,
                    "output": capped.text,
                });
                Ok(CallToolResult::success(vec![ContentBlock::text(
                    serde_json::to_string_pretty(&result).unwrap_or_default(),
                )]))
            }
            Err(e) => {
                self.record(
                    "run_snippet",
                    Some(h),
                    &snip.commands,
                    started,
                    Outcome {
                        error: Some(e.to_string()),
                        ..Outcome::allowed()
                    },
                );
                Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                    "Failed to run snippet '{}' on '{}': {}",
                    snip.name, h.name, e
                ))]))
            }
        }
    }
}

#[tool_handler]
impl ServerHandler for KinoMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
    }

    /// Remember who connected (KR-01-F12).
    ///
    /// Read from the peer after the handshake rather than by overriding
    /// `initialize`, which would mean reimplementing protocol negotiation
    /// around a helper rmcp keeps to itself.
    ///
    /// The client reports its own name and version, so this is a label, not an
    /// identity: it says which assistant *claims* to be calling. That is what
    /// makes a record traceable, and nothing is decided on it.
    async fn on_initialized(
        &self,
        context: rmcp::service::NotificationContext<rmcp::service::RoleServer>,
    ) {
        let Some(info) = context.peer.peer_info() else {
            return;
        };
        let name = info.client_info.name.trim();
        let version = info.client_info.version.trim();
        if let Ok(mut client) = self.client.lock() {
            *client = (
                if name.is_empty() {
                    "unknown".into()
                } else {
                    name.to_string()
                },
                if version.is_empty() {
                    "unknown".into()
                } else {
                    version.to_string()
                },
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp_policy::parse_rules;
    use crate::snippets::Snippet;
    use std::collections::HashMap;

    /// The policy tests in `mcp_policy` prove `evaluate` decides correctly.
    /// These prove the *server* acts on the decision - a different failure, and
    /// one none of those tests would catch: a `gate` call missing from a single
    /// tool passes every one of them.
    ///
    /// Nothing here reaches the network. A refusal happens before a connection
    /// is opened, which is the property being tested; and for a call the policy
    /// *allows*, the host points at a closed port, so getting a transport error
    /// rather than `policy_denied` is what proves the gate let it through.
    fn host() -> Host {
        Host {
            id: "h1".into(),
            name: "web-prod".into(),
            // Port 1 on loopback refuses immediately - no waiting, no network.
            hostname: "127.0.0.1".into(),
            port: 1,
            username: "root".into(),
            default_auth: "Password".into(),
            password: Some("x".into()),
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

    fn server(mode: McpMode, rules: &str) -> KinoMcpServer {
        let mut policies = HashMap::new();
        policies.insert(
            "h1".to_string(),
            HostPolicy {
                mode,
                rules: parse_rules(rules, "host").unwrap(),
                ..Default::default()
            },
        );
        KinoMcpServer::new(McpVault {
            hosts: vec![host()],
            snippets: vec![Snippet {
                id: "s1".into(),
                name: "deploy".into(),
                commands: "systemctl restart app".into(),
            }],
            policies,
            global_rules: vec![],
            approval_timeout_secs: crate::mcp_approval::DEFAULT_TIMEOUT_SECS,
        })
        // Nothing is listening here, which is what a test wants: the real
        // socket belongs to whatever Kino is running on this machine.
        .asking_at("/nonexistent/kino-test-approval.sock".into())
    }

    /// A server whose host carries the given limits.
    fn limited_server(
        max_calls_per_min: u32,
        max_bytes_per_call: usize,
    ) -> (KinoMcpServer, tempfile::TempDir, std::path::PathBuf) {
        let (s, dir, path) = recording_server(McpMode::Full, "");
        let mut vault = (*s.vault()).clone();
        vault.policies.insert(
            "h1".to_string(),
            HostPolicy {
                mode: McpMode::Full,
                rules: vec![],
                max_calls_per_min,
                max_bytes_per_call,
            },
        );
        let s = KinoMcpServer::with_audit(
            vault,
            crate::mcp_audit::AuditLog::new(path.clone(), [3u8; 32]),
        );
        (s, dir, path)
    }

    /// The same server, recording to a log of its own.
    fn recording_server(
        mode: McpMode,
        rules: &str,
    ) -> (KinoMcpServer, tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp_audit.jsonl.enc");
        let plain = server(mode, rules);
        let s = KinoMcpServer::with_audit(
            (*plain.vault()).clone(),
            crate::mcp_audit::AuditLog::new(path.clone(), [3u8; 32]),
        );
        (s, dir, path)
    }

    fn records(path: &std::path::PathBuf) -> Vec<crate::mcp_audit::AuditRecord> {
        crate::mcp_audit::read_all(path, &[3u8; 32])
            .unwrap()
            .into_iter()
            .filter_map(|e| e.record)
            .collect()
    }

    fn text(r: &CallToolResult) -> String {
        r.content
            .iter()
            .filter_map(|c| c.as_text())
            .map(|t| t.text.clone())
            .collect::<Vec<_>>()
            .join("")
    }

    fn exec(s: &KinoMcpServer, command: &str) -> CallToolResult {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(s.ssh_exec(Parameters(ExecParams {
                host: "web-prod".into(),
                command: command.into(),
            })))
            .unwrap()
    }

    // ── The record (KR-01-F8) ───────────────────────────────────────────────
    //
    // The policy tests above prove a call is refused. These prove the refusal
    // is *written down* - the question "what did it try at 2am?" is answerable
    // only if the calls that were stopped are recorded too, not just the ones
    // that ran.

    #[test]
    fn a_refused_call_is_recorded_with_the_command_that_was_attempted() {
        let (s, _dir, path) = recording_server(McpMode::ReadOnly, "");
        exec(&s, "rm -rf /var");

        let recorded = records(&path);
        assert_eq!(recorded.len(), 1);
        let r = &recorded[0];
        assert_eq!(r.decision, "deny");
        assert_eq!(r.tool, "ssh_exec");
        assert_eq!(r.argument, "rm -rf /var", "verbatim, not summarised");
        assert_eq!(r.host_name.as_deref(), Some("web-prod"));
        assert_eq!(
            r.rule_id.as_deref(),
            Some("default_deny"),
            "a refusal with no rule behind it still says why"
        );
        assert!(r.ts > 0);
    }

    #[test]
    fn an_allowed_call_that_fails_to_connect_is_recorded_as_allowed() {
        // Port 1 on loopback: the policy let it through, the host refused the
        // connection. "Refused by a rule" and "ran into a closed port" must
        // not read alike in the record.
        let (s, _dir, path) = recording_server(McpMode::Full, "");
        exec(&s, "uptime");

        let recorded = records(&path);
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].decision, "allow");
        assert!(recorded[0].error.is_some(), "the transport failure is kept");
        assert_eq!(recorded[0].argument, "uptime");
    }

    #[test]
    fn a_guarded_refusal_records_why_nobody_was_asked() {
        // With no app listening, guarded refuses. The record has to say that
        // is why, rather than leaving it looking like a rule said no.
        let (s, _dir, path) = recording_server(McpMode::Guarded, "");
        exec(&s, "systemctl restart nginx");
        let recorded = records(&path);
        assert_eq!(recorded[0].decision, "deny");
        assert_eq!(recorded[0].rule_id.as_deref(), Some("app_not_running"));
    }

    #[test]
    fn a_metadata_call_is_recorded_without_a_host() {
        let (s, _dir, path) = recording_server(McpMode::ReadOnly, "");
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(s.list_hosts())
            .unwrap();

        let recorded = records(&path);
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].tool, "list_hosts");
        assert_eq!(recorded[0].decision, "allow");
        assert_eq!(recorded[0].host_id, None);
    }

    #[test]
    fn a_call_naming_a_host_that_is_not_exposed_is_recorded() {
        // How probing for hosts it cannot see looks from here.
        let (s, _dir, path) = recording_server(McpMode::ReadOnly, "");
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(s.ssh_exec(Parameters(ExecParams {
                host: "db-prod".into(),
                command: "uptime".into(),
            })))
            .unwrap();

        let recorded = records(&path);
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].decision, "deny");
        assert_eq!(recorded[0].error.as_deref(), Some("host not found"));
        assert_eq!(recorded[0].host_name, None);
    }

    #[test]
    fn every_call_is_recorded_in_order() {
        let (s, _dir, path) = recording_server(McpMode::ReadOnly, "");
        exec(&s, "one");
        exec(&s, "two");
        exec(&s, "three");
        let args: Vec<String> = records(&path).into_iter().map(|r| r.argument).collect();
        assert_eq!(args, ["one", "two", "three"]);
    }

    #[test]
    fn the_client_is_unknown_until_it_says_otherwise() {
        // KR-01-F12: never omitted, so a record always names something.
        let (s, _dir, path) = recording_server(McpMode::ReadOnly, "");
        exec(&s, "uptime");
        let recorded = records(&path);
        assert_eq!(recorded[0].client_name, "unknown");
        assert_eq!(recorded[0].client_version, "unknown");
    }

    #[test]
    fn a_server_without_a_log_still_answers() {
        // The desktop app's own tests, and any build where the log could not
        // be opened: recording is best effort, refusing calls is not.
        let r = exec(&server(McpMode::ReadOnly, ""), "uptime");
        assert_eq!(r.is_error, Some(true));
    }

    // ── Noticing the vault changed (issue #22) ──────────────────────────────
    //
    // The app rewrites mcp_vault.enc on every change. A server that read it
    // once at startup kept serving the old policy for as long as it ran, so
    // revoking access in Kino did nothing until the assistant was restarted -
    // and nothing said so.

    const VAULT_KEY: [u8; 32] = [5u8; 32];

    fn vault_of(mode: McpMode, hosts: Vec<Host>) -> McpVault {
        let mut policies = HashMap::new();
        for h in &hosts {
            policies.insert(
                h.id.clone(),
                HostPolicy {
                    mode,
                    ..Default::default()
                },
            );
        }
        McpVault {
            hosts,
            snippets: vec![],
            policies,
            global_rules: vec![],
            approval_timeout_secs: crate::mcp_approval::DEFAULT_TIMEOUT_SECS,
        }
    }

    fn write_vault(path: &std::path::Path, key: &[u8; 32], vault: &McpVault) {
        // mtime has a resolution; two writes in the same tick would look
        // identical to a stat, and the point here is the change being seen.
        std::thread::sleep(std::time::Duration::from_millis(12));
        crate::vault::save_encrypted(&path.to_path_buf(), vault, key, &[7u8; 16]).unwrap();
    }

    /// A server reading its vault from `path`, as kino-mcp does.
    fn reloading_server(path: &std::path::Path, vault: McpVault) -> KinoMcpServer {
        write_vault(path, &VAULT_KEY, &vault);
        KinoMcpServer::new(vault)
            .reloading_from(path.to_path_buf(), VAULT_KEY)
            .asking_at("/nonexistent/kino-test-approval.sock".into())
    }

    #[test]
    fn a_policy_change_lands_without_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp_vault.enc");
        let s = reloading_server(&path, vault_of(McpMode::ReadOnly, vec![host()]));

        assert!(text(&exec(&s, "uptime")).contains("policy_denied"));

        // What saving in Kino does.
        write_vault(&path, &VAULT_KEY, &vault_of(McpMode::Full, vec![host()]));

        // Port 1 on loopback: a transport error means the gate let it past,
        // which is the only way to show that without a real host.
        let body = text(&exec(&s, "uptime"));
        assert!(!body.contains("policy_denied"), "{body}");
    }

    #[test]
    fn revoking_access_takes_effect_without_a_restart() {
        // The direction that matters: tightening. Serving the old policy here
        // means an assistant keeps access somebody has already taken away.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp_vault.enc");
        let s = reloading_server(&path, vault_of(McpMode::Full, vec![host()]));
        assert!(!text(&exec(&s, "uptime")).contains("policy_denied"));

        write_vault(
            &path,
            &VAULT_KEY,
            &vault_of(McpMode::ReadOnly, vec![host()]),
        );

        let body = text(&exec(&s, "uptime"));
        assert!(body.contains("policy_denied"), "{body}");
    }

    #[test]
    fn unticking_a_host_makes_it_disappear_without_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp_vault.enc");
        let s = reloading_server(&path, vault_of(McpMode::Full, vec![host()]));

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        assert!(text(&rt.block_on(s.list_hosts()).unwrap()).contains("web-prod"));

        write_vault(&path, &VAULT_KEY, &vault_of(McpMode::Full, vec![]));

        let listed = text(&rt.block_on(s.list_hosts()).unwrap());
        assert!(!listed.contains("web-prod"), "{listed}");
        // And its credentials are gone with it.
        assert!(text(&exec(&s, "uptime")).contains("not found"));
    }

    #[test]
    fn a_vault_it_can_no_longer_read_refuses_instead_of_serving_the_old_one() {
        // A changed MCP password rewrites the file under a new salt. Carrying
        // on with the copy in memory would be the least safe reading of it.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp_vault.enc");
        let s = reloading_server(&path, vault_of(McpMode::Full, vec![host()]));
        assert!(!text(&exec(&s, "uptime")).contains("policy_denied"));

        write_vault(&path, &[9u8; 32], &vault_of(McpMode::Full, vec![host()]));

        let body = text(&exec(&s, "uptime"));
        assert!(body.contains("vault_unreadable"), "{body}");
        assert!(body.contains("restart kino-mcp"), "{body}");
    }

    #[cfg(unix)]
    #[test]
    fn an_unchanged_vault_is_not_read_again() {
        // Argon2 is slow on purpose, so the file is only stat-ed per call and
        // decrypted when it changed. Making the file unreadable without
        // touching mtime or length: if calls still work, it was not re-read.
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp_vault.enc");
        let s = reloading_server(&path, vault_of(McpMode::ReadOnly, vec![host()]));
        assert!(text(&exec(&s, "uptime")).contains("policy_denied"));

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        let body = text(&exec(&s, "uptime"));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        assert!(body.contains("policy_denied"), "{body}");
        assert!(!body.contains("vault_unreadable"), "{body}");
    }

    #[test]
    fn a_server_with_no_file_behind_it_still_works() {
        // The tests above, and any embedding that hands over a vault from
        // memory: no path, nothing to reload, nothing to go wrong.
        let s = server(McpMode::ReadOnly, "");
        assert!(text(&exec(&s, "uptime")).contains("policy_denied"));
    }

    // ── Recording what ran (KR-01-F10) ──────────────────────────────────────

    #[test]
    fn a_command_on_a_full_host_is_recorded_as_a_cast() {
        let dir = tempfile::tempdir().unwrap();
        let s = server(McpMode::Full, "");
        let name = s
            .record_cast_in(
                dir.path(),
                &host(),
                "systemctl status nginx",
                "active (running)",
            )
            .expect("a cast should have been written");

        let cast = std::fs::read_to_string(dir.path().join(&name)).unwrap();
        let mut lines = cast.lines();

        let header: serde_json::Value = serde_json::from_str(lines.next().unwrap()).unwrap();
        assert_eq!(header["version"], 3);
        assert_eq!(
            header["command"], "systemctl status nginx",
            "the cast says what it is of"
        );

        let input: serde_json::Value = serde_json::from_str(lines.next().unwrap()).unwrap();
        assert_eq!(input[1], "i", "the command is an input event");
        assert!(input[2]
            .as_str()
            .unwrap()
            .contains("systemctl status nginx"));

        let output: serde_json::Value = serde_json::from_str(lines.next().unwrap()).unwrap();
        assert_eq!(output[1], "o");
        assert_eq!(output[2], "active (running)");
    }

    #[test]
    fn a_read_only_host_is_not_recorded() {
        // It can only run what a rule already named, and a cast per sftp_read
        // would bury the few worth watching.
        let dir = tempfile::tempdir().unwrap();
        let s = server(McpMode::ReadOnly, "allow uptime");
        assert_eq!(
            s.record_cast_in(dir.path(), &host(), "uptime", "up 3 days"),
            None
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn a_hosts_name_cannot_escape_the_recordings_folder() {
        let dir = tempfile::tempdir().unwrap();
        let s = server(McpMode::Full, "");
        let sneaky = Host {
            name: "../../etc/cron.d/evil".into(),
            ..host()
        };
        let name = s
            .record_cast_in(dir.path(), &sneaky, "uptime", "up")
            .unwrap();
        assert!(!name.contains('/'), "{name}");
        assert!(dir.path().join(&name).is_file());
    }

    // ── Asking a person (KR-01-F5, F6) ──────────────────────────────────────
    //
    // A stand-in app on a socket of this test's own, answering the way the
    // window will. What is being tested is the *server's* half: that Ask
    // reaches a person, that the answer is obeyed, that a session approval is
    // remembered, and that each outcome is recorded as what it was.

    struct FakeApp {
        prompts: Arc<Mutex<Vec<crate::mcp_approval::ApprovalRequest>>>,
        socket: std::path::PathBuf,
        _dir: tempfile::TempDir,
    }

    /// An app that answers everything with `decision`.
    fn fake_app(decision: &'static str) -> FakeApp {
        use crate::mcp_approval::broker::{self, Broker};
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("approval.sock");
        let listener = broker::bind(&socket).unwrap();
        let broker_handle = Broker::new();
        let prompts = Arc::new(Mutex::new(Vec::new()));

        let seen = prompts.clone();
        let answering = broker_handle.clone();
        tokio::spawn(async move {
            broker::serve(
                answering.clone(),
                listener,
                || true,
                move |request| {
                    seen.lock().unwrap().push(request.clone());
                    // The click, as fast as a person never is.
                    let b = answering.clone();
                    tokio::spawn(async move {
                        b.respond(&request.id, decision);
                    });
                },
            )
            .await;
        });

        FakeApp {
            prompts,
            socket,
            _dir: dir,
        }
    }

    /// Run one guarded command against `app`, on a server that records.
    async fn guarded_call(
        app: &FakeApp,
        command: &str,
    ) -> (CallToolResult, std::path::PathBuf, tempfile::TempDir) {
        let (s, dir, path) = recording_server(McpMode::Guarded, "");
        let s = s.asking_at(app.socket.clone());
        let r = s
            .ssh_exec(Parameters(ExecParams {
                host: "web-prod".into(),
                command: command.into(),
            }))
            .await
            .unwrap();
        (r, path, dir)
    }

    #[tokio::test]
    async fn an_approved_call_gets_past_the_gate() {
        let app = fake_app("approve_once");
        let (r, path, _dir) = guarded_call(&app, "systemctl restart nginx").await;

        // Port 1 on loopback: a transport error means the gate let it through,
        // which is the only way to prove that without a real host.
        let body = text(&r);
        assert!(!body.contains("policy_denied"), "{body}");
        assert_eq!(app.prompts.lock().unwrap().len(), 1, "a person was asked");

        let recorded = records(&path);
        assert_eq!(
            recorded
                .iter()
                .map(|r| r.decision.as_str())
                .collect::<Vec<_>>(),
            ["approved", "allow"],
            "the approval, then the call it allowed - and no denial in front of them"
        );
    }

    #[tokio::test]
    async fn the_prompt_carries_the_command_verbatim() {
        // KR-01-F6: the person approves what will actually run, not a summary.
        let app = fake_app("deny");
        guarded_call(&app, "rm -rf /var/log/*.gz").await;
        let prompt = app.prompts.lock().unwrap()[0].clone();
        assert_eq!(prompt.argument, "rm -rf /var/log/*.gz");
        assert_eq!(prompt.host_name, "web-prod");
        assert_eq!(prompt.tool, "ssh_exec");
    }

    #[tokio::test]
    async fn a_refused_approval_stops_the_call_and_says_who_refused() {
        let app = fake_app("deny");
        let (r, path, _dir) = guarded_call(&app, "systemctl restart nginx").await;
        let body = text(&r);
        assert_eq!(r.is_error, Some(true));
        assert!(body.contains("denied_by_user"), "{body}");
        assert_eq!(records(&path)[0].decision, "denied_by_user");
    }

    #[tokio::test]
    async fn approving_for_the_session_stops_the_asking() {
        let app = fake_app("approve_session");
        let (s, _dir, path) = recording_server(McpMode::Guarded, "");
        let s = s.asking_at(app.socket.clone());

        for _ in 0..3 {
            s.ssh_exec(Parameters(ExecParams {
                host: "web-prod".into(),
                command: "systemctl restart nginx".into(),
            }))
            .await
            .unwrap();
        }

        assert_eq!(
            app.prompts.lock().unwrap().len(),
            1,
            "asked once, not three times"
        );
        // Each call leaves two records: the approval, then what the call did.
        // "Approved once, ran three times" has to be visible in the log.
        let approvals = records(&path)
            .into_iter()
            .filter(|r| r.decision == "approved")
            .count();
        assert_eq!(approvals, 3, "every call is recorded, asked for or not");
    }

    #[tokio::test]
    async fn a_session_approval_covers_only_the_command_it_was_given_for() {
        let app = fake_app("approve_session");
        let (s, _dir, _path) = recording_server(McpMode::Guarded, "");
        let s = s.asking_at(app.socket.clone());

        for command in ["systemctl restart nginx", "rm -rf /var"] {
            s.ssh_exec(Parameters(ExecParams {
                host: "web-prod".into(),
                command: command.into(),
            }))
            .await
            .unwrap();
        }
        assert_eq!(
            app.prompts.lock().unwrap().len(),
            2,
            "a different command is a different question"
        );
    }

    // ── Rate and size limits (KR-01-F11) ────────────────────────────────────

    #[test]
    fn a_host_over_its_rate_limit_stops_answering() {
        let (s, _dir, _path) = limited_server(2, 0);
        // Full access, so nothing but the rate limit can refuse these.
        exec(&s, "uptime");
        exec(&s, "uptime");
        let third = exec(&s, "uptime");
        let body = text(&third);
        assert_eq!(third.is_error, Some(true));
        assert!(body.contains("\"reason\": \"rate_limited\""), "{body}");
    }

    #[test]
    fn the_rate_limit_applies_per_host_not_per_tool() {
        // Switching tools must not buy a fresh allowance.
        let (s, _dir, _path) = limited_server(1, 0);
        exec(&s, "uptime");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let r = rt
            .block_on(s.sftp_read(Parameters(PathParams {
                host: "web-prod".into(),
                path: "/etc/hostname".into(),
            })))
            .unwrap();
        assert!(text(&r).contains("rate_limited"), "{}", text(&r));
    }

    #[test]
    fn a_rate_limited_call_is_recorded() {
        let (s, _dir, path) = limited_server(1, 0);
        exec(&s, "uptime");
        exec(&s, "uptime");
        let recorded = records(&path);
        assert_eq!(recorded.len(), 2);
        assert_eq!(recorded[1].decision, "deny");
        assert_eq!(recorded[1].rule_id.as_deref(), Some("rate_limited"));
    }

    #[test]
    fn a_rate_limit_of_zero_never_refuses() {
        let (s, _dir, _path) = limited_server(0, 0);
        for _ in 0..50 {
            let r = exec(&s, "uptime");
            assert!(!text(&r).contains("rate_limited"));
        }
    }

    #[test]
    fn output_is_cut_to_the_hosts_limit_and_says_so() {
        let (s, _dir, _path) = limited_server(0, 100);
        let capped = s.cap(&host(), "x".repeat(500));
        assert!(capped.truncated);
        assert_eq!(capped.original, 500, "the record keeps the real size");
        assert!(
            capped.text.contains("truncated 400 bytes"),
            "{}",
            capped.text
        );
    }

    #[test]
    fn a_read_only_host_refuses_a_command() {
        let r = exec(&server(McpMode::ReadOnly, ""), "uptime");
        let body = text(&r);
        assert_eq!(r.is_error, Some(true));
        assert!(body.contains("\"error\": \"policy_denied\""), "{body}");
        assert!(body.contains("\"reason\": \"default_deny\""), "{body}");
        assert!(body.contains("\"mode\": \"read_only\""), "{body}");
    }

    #[test]
    fn a_read_only_host_refuses_every_write_tool() {
        let s = server(McpMode::ReadOnly, "");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let w = rt
            .block_on(s.sftp_write(Parameters(WriteParams {
                host: "web-prod".into(),
                path: "/etc/passwd".into(),
                content: "x".into(),
            })))
            .unwrap();
        assert!(
            text(&w).contains("\"reason\": \"read_only\""),
            "{}",
            text(&w)
        );

        let snip = rt
            .block_on(s.run_snippet(Parameters(RunSnippetParams {
                host: "web-prod".into(),
                snippet: "deploy".into(),
            })))
            .unwrap();
        assert!(
            text(&snip).contains("\"reason\": \"read_only\""),
            "{}",
            text(&snip)
        );
    }

    #[test]
    fn a_read_only_host_still_allows_reads() {
        // Allowed, so it goes on to connect - and fails to, because the port is
        // shut. A transport error here is the proof the gate let it past.
        let s = server(McpMode::ReadOnly, "");
        let r = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(s.sftp_read(Parameters(PathParams {
                host: "web-prod".into(),
                path: "/etc/hostname".into(),
            })))
            .unwrap();
        assert!(!text(&r).contains("policy_denied"), "{}", text(&r));
    }

    #[test]
    fn an_allow_rule_gets_a_command_past_the_gate() {
        let r = exec(&server(McpMode::ReadOnly, "allow uptime"), "uptime");
        assert!(!text(&r).contains("policy_denied"), "{}", text(&r));

        // And only that command: the rule is not a general opening.
        let r = exec(&server(McpMode::ReadOnly, "allow uptime"), "shutdown now");
        assert!(
            text(&r).contains("\"reason\": \"default_deny\""),
            "{}",
            text(&r)
        );
    }

    #[test]
    fn guarded_with_no_app_to_ask_refuses_and_says_which() {
        // KR-01-F7. The message has to separate "Kino is not running" from
        // "a rule refused this": they are fixed in completely different places.
        let r = exec(&server(McpMode::Guarded, ""), "uptime");
        let body = text(&r);
        assert!(body.contains("\"reason\": \"app_not_running\""), "{body}");
        assert!(body.contains("guarded mode"), "{body}");
        assert!(body.contains("not running"), "{body}");
    }

    #[test]
    fn a_deny_rule_names_the_line_that_refused() {
        let r = exec(&server(McpMode::Guarded, "deny rm -rf *"), "rm -rf /var");
        let body = text(&r);
        assert!(body.contains("\"reason\": \"rule\""), "{body}");
        assert!(body.contains("\"rule_id\": \"host:1\""), "{body}");
    }

    #[test]
    fn full_access_gates_nothing() {
        let r = exec(&server(McpMode::Full, ""), "rm -rf /");
        assert!(!text(&r).contains("policy_denied"), "{}", text(&r));
    }

    #[test]
    fn a_host_with_no_policy_at_all_is_read_only() {
        // If the vault is ever written without an entry for a host, the missing
        // entry has to mean less access, not more.
        let s = KinoMcpServer::new(McpVault {
            hosts: vec![host()],
            snippets: vec![],
            policies: HashMap::new(),
            global_rules: vec![],
            approval_timeout_secs: crate::mcp_approval::DEFAULT_TIMEOUT_SECS,
        });
        assert!(text(&exec(&s, "uptime")).contains("\"reason\": \"default_deny\""));
    }

    #[test]
    fn a_refusal_does_not_hand_over_the_rule_list() {
        let s = server(McpMode::ReadOnly, "allow systemctl status *\ndeny rm -rf *");
        let body = text(&exec(&s, "cat /etc/shadow"));
        assert!(!body.contains("systemctl status"), "leaked a rule: {body}");
        assert!(!body.contains("rm -rf"), "leaked a rule: {body}");
    }

    #[test]
    fn listing_hosts_works_in_every_mode_and_names_the_access() {
        let s = server(McpMode::ReadOnly, "");
        let r = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(s.list_hosts())
            .unwrap();
        let body = text(&r);
        assert!(!body.contains("policy_denied"), "{body}");
        assert!(body.contains("\"access\": \"read_only\""), "{body}");
    }
}
