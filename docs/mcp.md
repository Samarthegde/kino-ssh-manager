# The MCP server

Kino ships a second, headless binary - `kino-mcp` - that exposes chosen hosts
to an AI assistant over the [Model Context Protocol](https://modelcontextprotocol.io).
This page is the whole of it: getting the binary, configuring what an
assistant may do, and what to expect when something refuses.

It can list your hosts, run commands, read and write files and run saved
snippets - **on the hosts you tick and no others**. A newly ticked host is
read-only, and every call is recorded.

## 1. Get the binary

**It comes with the app.** Every installer carries `kino-mcp` alongside Kino
itself, and it updates whenever the app does:

| Installed from | `kino-mcp` is at |
| --- | --- |
| `.deb` / `.rpm` | `/usr/bin/kino-mcp` - already on your `PATH` |
| `.msi` / `.exe` | the install directory, next to Kino |
| `.app` / `.dmg` | inside the `.app` bundle, next to the main binary |
| `.AppImage` | inside the AppImage - see below |

The MCP panel shows the exact path and puts it in the config it gives you to
copy, so there is nothing to find by hand.

An AppImage runs from a different temporary directory every launch, so a path
into it stops working after a restart. From an AppImage, the panel offers
**Install kino-mcp**, which copies it to `~/.local/bin/kino-mcp`; Kino then
refreshes that copy each time the AppImage updates.

If you followed an older version of these instructions, delete the
`/usr/local/bin/kino-mcp` you put there. It comes before `/usr/bin` on `PATH`,
so a config that just says `kino-mcp` would keep running the old file. The
panel warns you when this is the case.

#### On a machine without the desktop app

Every release also attaches the server on its own, next to the installers on
the [releases page](https://github.com/Samarthegde/kino-ssh-manager/releases):

| Platform | Asset | Contains |
| --- | --- | --- |
| Linux | `kino-mcp-linux-x86_64.tar.gz` | `kino-mcp`, already executable |
| Windows | `kino-mcp-windows-x86_64.zip` | `kino-mcp.exe` |
| macOS | `kino-mcp-macos-aarch64.tar.gz` | `kino-mcp`, already executable |

Each has a `.sig` beside it, and the release's `SHA256SUMS` (itself signed)
covers every asset. Check before you run it - this binary can reach the hosts
you expose to it:

```bash
# What GitHub Actions says it built, and from which commit (needs gh 2.49+)
gh attestation verify kino-mcp-linux-x86_64.tar.gz --repo Samarthegde/kino-ssh-manager

# Or against the project's signing key. Tauri base64-wraps its signatures, so
# decode it first - minisign reads `<file>.minisig` sitting next to the file.
base64 -d kino-mcp-linux-x86_64.tar.gz.sig > kino-mcp-linux-x86_64.tar.gz.minisig
minisign -Vm kino-mcp-linux-x86_64.tar.gz -p minisign.pub

# Then unpack it straight onto your PATH
sudo tar -xzf kino-mcp-linux-x86_64.tar.gz -C /usr/local/bin
```

Building from source works too, if you'd rather:

```bash
cargo build --release --manifest-path src-tauri/Cargo.toml --bin kino-mcp
# -> src-tauri/target/release/kino-mcp
```

`npm run tauri build` puts it in the installers it builds, too - Tauri bundles
every binary in the crate.

## 2. Configure it in Kino

**Settings → Shortcuts & Tools → MCP Server**

- **Set an MCP password.** This is *not* your master password. It encrypts a
  separate file, `mcp_vault.enc`, holding only the hosts you expose - which is
  how the headless binary reads them without ever being given the master
  password.
- **Tick the hosts to expose.** Everything unticked is absent from that file
  entirely, so the assistant cannot see it, name it, or reach it.

Kino rewrites `mcp_vault.enc` whenever a host, a snippet or the exposure list
changes, and a running `kino-mcp` picks the change up on its next call - so
unticking a host, tightening a mode or adding a rule takes effect without
restarting your assistant. It checks the file's timestamp per call and only
re-reads when it actually changed, because deriving the key is deliberately
slow. Changing the **MCP password** is the exception: that rewrites the file
under a new key, and the running server refuses every call, saying so, until
it is restarted with the new password.

## 3. Point a client at it

The server speaks MCP over stdio. The MCP panel's **Copy** button gives you
this with the full path to your `kino-mcp` filled in. For Claude Desktop or
Claude Code, it looks like:

```json
{
  "mcpServers": {
    "kino": {
      "command": "kino-mcp",
      "env": { "KINO_MCP_PASSWORD": "your-mcp-password" }
    }
  }
}
```

Use the absolute path if the binary isn't on `PATH`. The panel in Kino shows
this snippet with a copy button.

## What it exposes

| Tool | What it does |
| --- | --- |
| `list_hosts` | Name, hostname, port, user, group and OS of each exposed host |
| `get_host` | Connection details for one host |
| `ssh_exec` | Runs a shell command; returns stdout, stderr and the exit code |
| `sftp_list` | `ls -la` of a remote directory, as text |
| `sftp_read` | Contents of a remote text file |
| `sftp_write` | Writes a file, creating or replacing it |
| `list_snippets` / `run_snippet` | Lists and runs saved command snippets |

## Worth knowing

- **A newly exposed host is read-only.** It will read files and listings, refuse
  to write, and run a command only if one of your rules names it. Two other
  modes exist per host: **guarded**, where anything unnamed needs a person to
  approve it, and **full**, which is the unrestricted shell and takes a separate
  confirmation naming the host.
- **Rules are matched against the command as written.** They are `allow`,
  `deny` or `ask` plus a pattern, the first match wins, and a host's own rules
  are read before the global ones. This is not shell parsing and must not be
  mistaken for it: a deny rule catches `rm -rf /`, and catches nothing that
  assembles itself at runtime. The read-only default is the boundary that
  actually holds, because it refuses what it was not told to permit.
- **Guarded mode asks you.** A call no rule covers stops, and Kino shows the
  command exactly as it was sent, with the host, the client that asked and a
  countdown. You can approve it once, approve it for as long as that
  `kino-mcp` keeps running, or refuse. Refusing is the default, and nothing
  runs while the prompt is up.

  If Kino is closed, or the vault is locked, the call is refused
  **immediately** and the refusal says which of the two it was, rather than
  leaving an assistant waiting two minutes for a prompt nobody can see. Same
  if nobody answers in time. The prompt arrives over a Unix socket beside the
  vault, mode `0600`, so another user on the machine cannot answer for you.
  Windows has no channel yet: there, a guarded call is still refused, with a
  message saying so.
- **Each host has limits.** 60 calls a minute and 256 KiB returned per call by
  default, both editable per host next to its rules. Over the rate, calls are
  refused with `rate_limited` until the minute passes; over the size, the reply
  is cut and says `…[truncated N bytes]` in the output itself, so an assistant
  cannot summarise a log from its first page and present that as the whole. The
  audit record keeps the untruncated size. 0 turns either limit off, and the
  count is per host and held in memory, so restarting `kino-mcp` clears it.
- **Commands on guarded and full hosts are recorded.** `ssh_exec` and
  `run_snippet` write an asciicast into *Kino Recordings*, named after the
  host, and the activity view has a Replay button for each. It is a
  transcript rather than a live capture: an MCP call hands back its output at
  the end, so the cast is the command and then its output, without the pauses
  between. Read-only hosts are not recorded - they run only what a rule
  already named.
- **Every call is recorded.** `kino-mcp` writes each tool call to
  `mcp_audit.jsonl.enc` beside the vault - what was called, on which host, the
  command verbatim, whether it was allowed or refused and why, the exit code,
  and which client asked. The refused calls are recorded too: a run of
  refusals is what an assistant testing its limits looks like. Read it in
  **Settings → Security → MCP activity**, where it can be filtered and
  exported as JSONL.

  Each record is sealed on its own line under the **MCP** password, so the
  headless binary can write it without ever holding your master password, and
  appending never rewrites what is already there. A line that will not decrypt
  is shown as unreadable rather than skipped - that is what tampering looks
  like, and it is also what changing the MCP password looks like.

  The command is stored as it was sent, so a command containing a secret puts
  that secret in the log. The file is encrypted, stays on this machine, and is
  never uploaded: cloud sync carries a named list of files and this is not one
  of them, and a profile export contains a single host and nothing else.
- **Host keys are still enforced.** `kino-mcp` refuses any host whose key hasn't
  already been trusted in the GUI - it will not trust-on-first-use. Connect once
  from Kino before expecting MCP to reach a new host.
- **The password comes from the environment.** `KINO_MCP_PASSWORD` is readable
  by other processes running as you, so this protects the vault file at rest,
  not against someone already on your machine as you.
- Each tool call opens its own SSH connection, so a host behind a slow handshake
  will feel slow per call.

## If it doesn't start

`kino-mcp` writes diagnostics to stderr (stdout is the JSON-RPC stream), and
most MCP clients surface that in their logs. Run it directly to see them:

```bash
KINO_MCP_PASSWORD=your-mcp-password kino-mcp
```

- *"KINO_MCP_PASSWORD environment variable is not set"* - the client config is
  missing the `env` block.
- *"Cannot read MCP vault"* - no MCP password has been set in Kino yet, so the
  file doesn't exist.
- *"Wrong MCP password or corrupt MCP vault"* - you're using the master password,
  or the MCP password was changed in Kino since.
