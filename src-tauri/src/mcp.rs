//! MCP server implementation using the `rmcp` crate.
//!
//! Exposes Kino SSH Manager's capabilities as MCP tools so AI assistants
//! can list hosts, execute commands, and transfer files on the hosts the
//! user explicitly chose to share.

use crate::mcp_audit::{AuditLog, AuditRecord};
use crate::mcp_config::McpVault;
use crate::mcp_policy::{self, Decision, HostPolicy, McpMode};
use crate::ssh_session;
use crate::vault::Host;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::*;
use rmcp::{tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// The MCP server state. Holds the decrypted hosts and snippets that were
/// exported from the Kino vault under the MCP password.
#[derive(Clone)]
pub struct KinoMcpServer {
    vault: Arc<McpVault>,
    /// Where each call is recorded. `None` in tests and in any build that
    /// could not open the log - a call the policy allows still runs, and the
    /// failure is reported to stderr rather than swallowed.
    audit: Option<Arc<AuditLog>>,
    /// Who is connected, from the MCP handshake. `unknown` until `initialize`
    /// arrives, and never omitted: a record that quietly drops the client is
    /// one you cannot trace back to a machine.
    client: Arc<Mutex<(String, String)>>,
    /// Built by the `#[tool_router]` macro and read by `#[tool_handler]`; the
    /// field looks unused to the compiler because both are generated.
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

impl KinoMcpServer {
    pub fn new(vault: McpVault) -> Self {
        Self {
            vault: Arc::new(vault),
            audit: None,
            client: Arc::new(Mutex::new(("unknown".into(), "unknown".into()))),
            tool_router: Self::tool_router(),
        }
    }

    /// The server as `kino-mcp` runs it: every call recorded.
    pub fn with_audit(vault: McpVault, audit: AuditLog) -> Self {
        Self {
            audit: Some(Arc::new(audit)),
            ..Self::new(vault)
        }
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
            error: outcome.error,
        };
        if let Err(e) = log.append(&record) {
            eprintln!("[kino-mcp] could not write the audit record: {e}");
        }
    }

    /// Find a host by name (case-insensitive) or by id.
    fn find_host(&self, name_or_id: &str) -> Option<&Host> {
        let lower = name_or_id.to_lowercase();
        self.vault
            .hosts
            .iter()
            .find(|h| h.id == name_or_id || h.name.to_lowercase() == lower)
    }

    /// The policy for a host. A host with no entry is read-only: the vault
    /// writes one for every exposed host, so a missing entry means something
    /// went wrong, and the safe reading of that is "less access, not more".
    fn policy_for(&self, host: &Host) -> HostPolicy {
        self.vault
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
    fn gate(
        &self,
        host: &Host,
        tool: &str,
        argument: &str,
        started: Instant,
    ) -> Option<CallToolResult> {
        let policy = self.policy_for(host);
        let decision = mcp_policy::evaluate(&policy, &self.vault.global_rules, tool, argument);
        // Recorded here rather than in each tool: a refusal returns early, and
        // the one call that forgot to record it would be the interesting one.
        //
        // A refusal with no rule behind it - the read-only default, or guarded
        // mode with nobody to ask - records the reason in `rule_id`'s place.
        // Otherwise the record says a call was refused without saying why,
        // which is the one thing it exists to answer.
        let why = match &decision {
            Decision::Deny { reason, rule_id } => {
                Some(rule_id.clone().unwrap_or_else(|| (*reason).to_string()))
            }
            Decision::Ask { rule_id } => Some(
                rule_id
                    .clone()
                    .unwrap_or_else(|| "approval_unavailable".to_string()),
            ),
            Decision::Allow => None,
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

            // No approval broker exists yet, so guarded mode refuses rather
            // than blocking forever on an answer nothing can give. When the
            // broker lands this arm asks the desktop app instead; the rest of
            // the decision is already correct.
            Decision::Ask { rule_id } => Some(refusal(
                host, tool, policy.mode, "approval_unavailable", rule_id,
                &format!(
                    "'{}' is in guarded mode, so a person has to approve this call.                      Approval isn't available in this version - either add an allow rule                      for it in Kino, or run it yourself.",
                    host.name
                ),
            )),

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
        let list: Vec<serde_json::Value> = self
            .vault
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
        let h = match self.find_host(&params.host) {
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
        let h = match self.find_host(&params.host) {
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

        if let Some(refused) = self.gate(h, "ssh_exec", &params.command, started) {
            return Ok(refused);
        }

        // `exec_once_full` rather than `exec_once`: a command that fails is
        // still a result the caller needs to see - stderr and the status are
        // the useful part, and collapsing them into an error string loses both.
        match ssh_session::exec_once_full(h, &params.command).await {
            Ok(out) => {
                self.record(
                    "ssh_exec",
                    Some(h),
                    &params.command,
                    started,
                    Outcome {
                        // u32 on the wire, i32 in the record: a shell status
                        // is 0-255, and i32 is what every reader expects.
                        exit_code: out.code.map(|c| c as i32),
                        bytes_out: Some(out.stdout.len() + out.stderr.len()),
                        ..Outcome::allowed()
                    },
                );
                let result = serde_json::json!({
                    "host": h.name,
                    "command": params.command,
                    "stdout": out.stdout,
                    "stderr": out.stderr,
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
        let h = match self.find_host(&params.host) {
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

        if let Some(refused) = self.gate(h, "sftp_list", &params.path, started) {
            return Ok(refused);
        }

        let cmd = format!("ls -la {}", crate::exec::shell_quote(&params.path));
        match ssh_session::exec_once(h, &cmd).await {
            Ok(output) => {
                self.record(
                    "sftp_list",
                    Some(h),
                    &params.path,
                    started,
                    Outcome {
                        bytes_out: Some(output.len()),
                        ..Outcome::allowed()
                    },
                );
                Ok(CallToolResult::success(vec![ContentBlock::text(output)]))
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
        let h = match self.find_host(&params.host) {
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

        if let Some(refused) = self.gate(h, "sftp_read", &params.path, started) {
            return Ok(refused);
        }

        let cmd = format!("cat {}", crate::exec::shell_quote(&params.path));
        match ssh_session::exec_once(h, &cmd).await {
            Ok(output) => {
                self.record(
                    "sftp_read",
                    Some(h),
                    &params.path,
                    started,
                    Outcome {
                        bytes_out: Some(output.len()),
                        ..Outcome::allowed()
                    },
                );
                let result = serde_json::json!({
                    "path": params.path,
                    "host": h.name,
                    "content": output,
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
        let h = match self.find_host(&params.host) {
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

        if let Some(refused) = self.gate(h, "sftp_write", &params.path, started) {
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
        let list: Vec<serde_json::Value> = self
            .vault
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
        let h = match self.find_host(&params.host) {
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

        let lower = params.snippet.to_lowercase();
        let snip = self
            .vault
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
        if let Some(refused) = self.gate(h, "run_snippet", &snip.commands, started) {
            return Ok(refused);
        }

        match ssh_session::exec_once(h, &snip.commands).await {
            Ok(output) => {
                // The commands, not the snippet's name: the record has to say
                // what ran, and a snippet can be edited afterwards.
                self.record(
                    "run_snippet",
                    Some(h),
                    &snip.commands,
                    started,
                    Outcome {
                        bytes_out: Some(output.len()),
                        ..Outcome::allowed()
                    },
                );
                let result = serde_json::json!({
                    "snippet": snip.name,
                    "host": h.name,
                    "output": output,
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
        })
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
            (*plain.vault).clone(),
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
    fn a_guarded_refusal_records_that_nobody_could_be_asked() {
        // Until the approval broker lands, guarded refuses. The record has to
        // say that is why - not leave it looking like a rule said no.
        let (s, _dir, path) = recording_server(McpMode::Guarded, "");
        exec(&s, "systemctl restart nginx");
        let recorded = records(&path);
        assert_eq!(recorded[0].decision, "deny");
        assert_eq!(recorded[0].rule_id.as_deref(), Some("approval_unavailable"));
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
    fn guarded_says_plainly_that_approval_does_not_exist_yet() {
        let r = exec(&server(McpMode::Guarded, ""), "uptime");
        let body = text(&r);
        assert!(
            body.contains("\"reason\": \"approval_unavailable\""),
            "{body}"
        );
        assert!(body.contains("guarded mode"), "{body}");
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
