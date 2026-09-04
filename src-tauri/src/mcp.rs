//! MCP server implementation using the `rmcp` crate.
//!
//! Exposes Kino SSH Manager's capabilities as MCP tools so AI assistants
//! can list hosts, execute commands, and transfer files on the hosts the
//! user explicitly chose to share.

use crate::mcp_config::McpVault;
use crate::mcp_policy::{self, Decision, HostPolicy, McpMode};
use crate::ssh_session;
use crate::vault::Host;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::*;
use rmcp::{tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler};
use std::sync::Arc;

/// The MCP server state. Holds the decrypted hosts and snippets that were
/// exported from the Kino vault under the MCP password.
#[derive(Clone)]
pub struct KinoMcpServer {
    vault: Arc<McpVault>,
    /// Built by the `#[tool_router]` macro and read by `#[tool_handler]`; the
    /// field looks unused to the compiler because both are generated.
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

impl KinoMcpServer {
    pub fn new(vault: McpVault) -> Self {
        Self {
            vault: Arc::new(vault),
            tool_router: Self::tool_router(),
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
    fn gate(&self, host: &Host, tool: &str, argument: &str) -> Option<CallToolResult> {
        let policy = self.policy_for(host);
        match mcp_policy::evaluate(&policy, &self.vault.global_rules, tool, argument) {
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
        let h = match self.find_host(&params.host) {
            Some(h) => h,
            None => {
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
        Ok(CallToolResult::success(vec![ContentBlock::text(
            serde_json::to_string_pretty(&info).unwrap_or_default(),
        )]))
    }

    /// Execute a command on a remote SSH host.
    #[tool(
        description = "Execute a shell command on a remote SSH host. Returns stdout, stderr and the exit code; a non-zero exit is reported, not hidden. Only hosts explicitly exposed in Kino are reachable."
    )]
    async fn ssh_exec(
        &self,
        Parameters(params): Parameters<ExecParams>,
    ) -> Result<CallToolResult, McpError> {
        let h = match self.find_host(&params.host) {
            Some(h) => h,
            None => {
                return Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                    "Host '{}' not found. Use list_hosts to see available hosts.",
                    params.host
                ))]));
            }
        };

        if let Some(refused) = self.gate(h, "ssh_exec", &params.command) {
            return Ok(refused);
        }

        // `exec_once_full` rather than `exec_once`: a command that fails is
        // still a result the caller needs to see - stderr and the status are
        // the useful part, and collapsing them into an error string loses both.
        match ssh_session::exec_once_full(h, &params.command).await {
            Ok(out) => {
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
            Err(e) => Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                "Could not run the command on '{}': {}",
                h.name, e
            ))])),
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
        let h = match self.find_host(&params.host) {
            Some(h) => h,
            None => {
                return Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                    "Host '{}' not found.",
                    params.host
                ))]))
            }
        };

        if let Some(refused) = self.gate(h, "sftp_list", &params.path) {
            return Ok(refused);
        }

        let cmd = format!("ls -la {}", crate::exec::shell_quote(&params.path));
        match ssh_session::exec_once(h, &cmd).await {
            Ok(output) => Ok(CallToolResult::success(vec![ContentBlock::text(output)])),
            Err(e) => Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                "Failed to list '{}' on '{}': {}",
                params.path, h.name, e
            ))])),
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
        let h = match self.find_host(&params.host) {
            Some(h) => h,
            None => {
                return Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                    "Host '{}' not found.",
                    params.host
                ))]))
            }
        };

        if let Some(refused) = self.gate(h, "sftp_read", &params.path) {
            return Ok(refused);
        }

        let cmd = format!("cat {}", crate::exec::shell_quote(&params.path));
        match ssh_session::exec_once(h, &cmd).await {
            Ok(output) => {
                let result = serde_json::json!({
                    "path": params.path,
                    "host": h.name,
                    "content": output,
                });
                Ok(CallToolResult::success(vec![ContentBlock::text(
                    serde_json::to_string_pretty(&result).unwrap_or_default(),
                )]))
            }
            Err(e) => Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                "Failed to read '{}' on '{}': {}",
                params.path, h.name, e
            ))])),
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
        let h = match self.find_host(&params.host) {
            Some(h) => h,
            None => {
                return Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                    "Host '{}' not found.",
                    params.host
                ))]))
            }
        };

        if let Some(refused) = self.gate(h, "sftp_write", &params.path) {
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
            Ok(_) => Ok(CallToolResult::success(vec![ContentBlock::text(format!(
                "Successfully wrote to '{}' on '{}'",
                params.path, h.name
            ))])),
            Err(e) => Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                "Failed to write '{}' on '{}': {}",
                params.path, h.name, e
            ))])),
        }
    }

    /// List all command snippets.
    #[tool(
        description = "List all command snippets available in the Kino vault. Snippets are reusable blocks of shell commands."
    )]
    async fn list_snippets(&self) -> Result<CallToolResult, McpError> {
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
        let h = match self.find_host(&params.host) {
            Some(h) => h,
            None => {
                return Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                    "Host '{}' not found.",
                    params.host
                ))]))
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
                return Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                    "Snippet '{}' not found. Use list_snippets to see available snippets.",
                    params.snippet
                ))]))
            }
        };

        // The snippet's *commands*, not its name: a rule is about what runs.
        if let Some(refused) = self.gate(h, "run_snippet", &snip.commands) {
            return Ok(refused);
        }

        match ssh_session::exec_once(h, &snip.commands).await {
            Ok(output) => {
                let result = serde_json::json!({
                    "snippet": snip.name,
                    "host": h.name,
                    "output": output,
                });
                Ok(CallToolResult::success(vec![ContentBlock::text(
                    serde_json::to_string_pretty(&result).unwrap_or_default(),
                )]))
            }
            Err(e) => Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                "Failed to run snippet '{}' on '{}': {}",
                snip.name, h.name, e
            ))])),
        }
    }
}

#[tool_handler]
impl ServerHandler for KinoMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
    }
}
