//! `kino-mcp` — headless MCP server for Kino SSH Manager.
//!
//! Reads `KINO_MCP_PASSWORD` from the environment, decrypts the MCP vault
//! (`~/.local/share/ssh-manager/mcp_vault.enc`), and serves MCP tools over
//! stdio. Only hosts the user chose to expose in the Kino UI are visible.
//!
//! Usage:
//!   KINO_MCP_PASSWORD=mypass kino-mcp

use ssh_manager_lib::mcp::KinoMcpServer;
use ssh_manager_lib::mcp_audit::{audit_path, AuditLog};
use ssh_manager_lib::mcp_config;

#[tokio::main]
async fn main() {
    // Returning `Err` from `main` prints it with `Debug`, which turns the
    // multi-line guidance below into one line full of literal `\n`s.
    if let Err(message) = run().await {
        eprintln!("{}", message);
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    // TLS provider for SSH connections through agent/relay.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let password = std::env::var("KINO_MCP_PASSWORD").map_err(|_| {
        "KINO_MCP_PASSWORD environment variable is not set.\n\
         Set it to the MCP password you configured in Kino SSH Manager.\n\
         \n\
         Example:\n  KINO_MCP_PASSWORD=mypass kino-mcp"
    })?;

    if password.is_empty() {
        return Err("KINO_MCP_PASSWORD cannot be empty".into());
    }

    let (vault, key) = mcp_config::load_mcp_vault_and_key(&password).map_err(|e| {
        format!(
            "Failed to decrypt the MCP vault: {}\n\
             \n\
             Make sure you:\n\
             1. Set up the MCP password in Kino → Settings → Tools → MCP Server\n\
             2. Selected at least one host to expose\n\
             3. Used the correct MCP password (not the master vault password)",
            e
        )
    })?;

    let host_count = vault.hosts.len();
    let snippet_count = vault.snippets.len();

    // Print to stderr — stdout is the MCP JSON-RPC stream.
    eprintln!(
        "[kino-mcp] Loaded {} host{} and {} snippet{}",
        host_count,
        if host_count == 1 { "" } else { "s" },
        snippet_count,
        if snippet_count == 1 { "" } else { "s" },
    );

    // Every call is recorded (KR-01-F8), under the same key as the vault -
    // the only one this process has. The same key re-reads the vault when the
    // app rewrites it, so a policy change lands without a restart (issue #22).
    let server = KinoMcpServer::with_audit(vault, AuditLog::new(audit_path(), key))
        .reloading_from(mcp_config::mcp_vault_path(), key);

    // Serve over stdio (the standard MCP transport for local tools).
    use rmcp::ServiceExt;
    let service = server.serve(rmcp::transport::io::stdio()).await?;
    service.waiting().await?;

    Ok(())
}
