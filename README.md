# Kino SSH Manager

A secure, cross-platform SSH credential manager and terminal, built with [Tauri 2](https://tauri.app/) (Rust) and React. Credentials live in a single encrypted vault on your machine - your master password and secrets never leave the device unless you explicitly enable cloud sync, and even then only the encrypted blob is uploaded.

## Features

- **Encrypted vault** - Argon2 key derivation + AES-256-GCM. One master password unlocks everything.
- **SSH terminal** - full xterm.js terminal per host, with split panes, broadcast input, copy/paste (Ctrl+Shift+C/V), adjustable font size, and configurable scrollback up to 200,000 lines (clear it any time with Ctrl+Shift+K).
- **Find in terminal** - Ctrl+F reports how many matches there are and which one you're on, highlights every hit, and marks them on the scrollbar so you can see where they sit in a long scrollback. Case-sensitive, whole-word and regex toggles.
- **Output highlighting** - timestamps, severity words, IP addresses, URLs and file paths are coloured from the active theme's palette, in the spirit of MobaXterm's. Never applied inside full-screen programs like vim, htop or less, and never over output the host has already coloured.
- **Flexible auth** - store a password and/or an SSH key per host (including encrypted keys with a passphrase); import `.pem`/`.key`/`.ppk` files or generate ed25519 keypairs. Uses the SSH agent (OpenSSH agent / Pageant) when asked.
- **Jump host / bastion** - route a connection through another saved host, like `ssh -J`. Each hop's host key is verified independently, and bastions can chain.
- **Port forwarding** - local (`-L`), remote (`-R`), and dynamic SOCKS5 (`-D`) tunnels, started and stopped independently per session; optional dial-through SOCKS5/HTTP proxy per host. Each tunnel is drawn as a three-station diagram showing which machine opens the port, where the destination is resolved, and which way traffic flows - so `-L` and `-R` can't be confused.
- **SFTP file browser & editor** - browse, upload/download with progress, rename, delete, new folder, chmod, and edit remote files in a built-in Monaco editor that saves straight back over SFTP.
- **AI copilot (optional)** - a bring-your-own-key assistant in the terminal, powered by [OpenRouter](https://openrouter.ai). Ask about a host, explain an error, or select output and send it to the copilot. The key is encrypted in the vault; off by default.
- **Docker, metrics, processes, cron & archaeology** - manage containers/images/volumes/networks with live logs and one-click shells, watch a streaming CPU/mem/disk/network dashboard, browse processes as a tree and signal them, edit the host's crontab, and excavate the shell history of past sessions - all over the SSH connection. Together with the file browser and session recording they live behind one **Tools** menu in the tab bar.
- **Process tree & signals** - processes group under their parents, branches fold, and a collapsed row says how many it's hiding; filtering keeps a match's ancestors so a hit never floats without the chain that spawned it. Signal any process with SIGTERM, SIGINT, SIGHUP, SIGSTOP, SIGCONT or SIGKILL, each named for what it does.
- **Archaeology** - reads `~/.bash_history` and `~/.zsh_history` for the account you connect as and keeps them in an encrypted archive per host, so the commands `HISTSIZE` has already trimmed off the server survive. A de-duplicated set rather than a timeline; captures command lines verbatim, including anything secret typed on one, and is excluded from exported host profiles.
- **Notes** - encrypted free-text storage for recovery codes, licence keys and API tokens, kept in a sibling blob beside the vault under the same key and synced with it. Bodies stay blurred until clicked.
- **Tray & heartbeat alerts** - minimising sends Kino to the notification area and closing the window leaves it running, with Show and Quit in the tray menu. When a host that was up goes down you get a desktop notification, and optionally an [ntfy](https://ntfy.sh) push to your phone. The vault stays unlocked while hidden; idle auto-lock still applies.
- **Cron editor** - reads the host's crontab and writes every schedule out in plain English ("At 04:00 on Tuesday"), with the next times each job will fire in the host's clock. Add, edit, pause and remove jobs, or edit the file directly. Only the lines you change are rewritten, so comments, `PATH=`/`MAILTO=` and anything unrecognised survive untouched, and a save is refused outright if the crontab changed on the host in the meantime.
- **Key audit & rotation** - checks every stored key for weak algorithms, reuse across hosts and age, entirely on your machine. One click rotates a host to a fresh ed25519 key: install, prove it authenticates on a second connection, *then* remove the old one - never the other way round.
- **Copy output as an image** - select terminal output and get a PNG with its colours, bold and highlighting intact. Not a screenshot: the buffer cells are re-rendered, so the image is sharp and trimmed to the content. Choose between the Kino frame, a plain window title bar or a minimal crop, toggle the host name and timestamp, and add an accent wash for pasting onto light backgrounds.
- **Host health indicators** - optional background probe showing a reachability dot and round-trip latency per host in the sidebar.
- **Session recording** - record any SSH or local session to an asciicast file and replay it in-app.
- **Agent connection mode (optional)** - reach hosts that have **no inbound SSH port** (behind NAT, CGNAT, or a firewall) through a relay, using a companion agent that dials out. Off by default; enable it under Settings - Kino Agent. See [Agent connection mode](#agent-connection-mode).
- **Encrypted profile sharing** - export a host as a password-encrypted `.sshm` file (Argon2 + AES-256-GCM) to share it safely; the recipient needs only the password to import it.
- **Snippets** - a reusable command library; selected snippets auto-run on connect, per host.
- **Cloud sync (optional)** - sync the *encrypted* vault to a private GitHub repo (Contents API, sha-based conflict detection). Optional auto-sync (pull on unlock, push on change).
- **In-app updates** - install a new signed release from within About, with a fallback to the release page (AppImage on Linux; `.deb`/`.rpm` update via the system package manager). After an upgrade the unlock screen shows what changed in that version, once.
- **Security niceties** - idle auto-lock, change-master-password (re-key), TOFU host-key verification, secrets zeroized in memory on lock.
- **Appearance** - 15 themes, six bundled monospace faces for the terminal plus an optional background override, and a choice of interface font including [Atkinson Hyperlegible](https://www.brailleinstitute.org/freefont/). Every face ships with the app, so nothing is fetched at runtime. A **reduced motion & effects** switch stops all animation and drops the decorative paint layers if you want the interface cheaper to draw.
- **Quality of life** - host health & latency, home favorites, session restore on unlock, customizable keyboard shortcuts, host groups, per-host accent colors, pinned/renamable panes, searchable connection history, and `~/.ssh/config` import/export.

## Agent connection mode

Not every host is directly reachable - a homelab box behind NAT, a laptop on a
café network, a cloud VM with no public SSH. Agent mode reaches these without
opening any inbound port:

- A companion **[kino-agent](https://github.com/Samarthegde/kino-agent)** runs on
  the target machine and makes an *outbound* connection to a public
  **[kino-relay](https://github.com/Samarthegde/kino-relay)** you control.
- **Kino Cloud (easiest):** paste your account key under Settings once, then
  the host editor's agent mode becomes a machine picker - add a machine, run
  the one-line install command it shows, connect. Relay discovery, tokens, and
  rotation are handled automatically; the app stores only the agent id.
- **Self-hosted (advanced):** enter a relay URL (`wss://...`) and agent id
  yourself - plus a relay token if the relay requires auth, and/or a
  kino-control URL for relay discovery. The editor shows the exact command to
  run on the target to install the agent.
- The manager connects through the relay to that agent, which forwards to the
  host's local SSH daemon. The SSH session remains **end-to-end encrypted** - the
  relay only moves bytes and never sees your credentials, and the host's SSH key
  is still verified (pinned per agent id).

Enable the feature under **Settings - Kino Agent** (it is off by default). See the
[kino-agent](https://github.com/Samarthegde/kino-agent) and
[kino-relay](https://github.com/Samarthegde/kino-relay) repositories for
installation and self-hosting.

## MCP server

Kino ships a second, headless binary - `kino-mcp` - that exposes hosts to an AI
assistant over the [Model Context Protocol](https://modelcontextprotocol.io).
The assistant can list your hosts, run commands, read and write files, and run
saved snippets, **on the hosts you explicitly tick and no others**.

### 1. Get the binary

Every release attaches it, next to the installers on the
[releases page](https://github.com/Samarthegde/kino-ssh-manager/releases):

| Platform | Asset |
| --- | --- |
| Linux | `kino-mcp-linux-x86_64` |
| Windows | `kino-mcp-windows-x86_64.exe` |

Download it, make it executable, and put it somewhere on your `PATH`:

```bash
chmod +x kino-mcp-linux-x86_64
sudo mv kino-mcp-linux-x86_64 /usr/local/bin/kino-mcp
```

It is not inside the `.deb`/`.rpm`/`.AppImage`/`.msi` - it's a separate download,
because it's a server you run rather than an app you launch.

Building from source works too, if you'd rather:

```bash
cargo build --release --manifest-path src-tauri/Cargo.toml --bin kino-mcp
# -> src-tauri/target/release/kino-mcp
```

### 2. Configure it in Kino

**Settings → Shortcuts & Tools → MCP Server**

- **Set an MCP password.** This is *not* your master password. It encrypts a
  separate file, `mcp_vault.enc`, holding only the hosts you expose - which is
  how the headless binary reads them without ever being given the master
  password.
- **Tick the hosts to expose.** Everything unticked is absent from that file
  entirely, so the assistant cannot see it, name it, or reach it.

Kino rewrites `mcp_vault.enc` whenever a host, a snippet or the exposure list
changes, so a rotated key or a removed host takes effect immediately.

### 3. Point a client at it

The server speaks MCP over stdio. For Claude Desktop or Claude Code, add:

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

### What it exposes

| Tool | What it does |
| --- | --- |
| `list_hosts` | Name, hostname, port, user, group and OS of each exposed host |
| `get_host` | Connection details for one host |
| `ssh_exec` | Runs a shell command; returns stdout, stderr and the exit code |
| `sftp_list` | `ls -la` of a remote directory, as text |
| `sftp_read` | Contents of a remote text file |
| `sftp_write` | Writes a file, creating or replacing it |
| `list_snippets` / `run_snippet` | Lists and runs saved command snippets |

### Worth knowing

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
- **Guarded mode currently refuses rather than asks.** The approval prompt is
  not built yet, so a call that would need approval is declined with a message
  saying so. Use rules, or full access, until it lands.
- **Host keys are still enforced.** `kino-mcp` refuses any host whose key hasn't
  already been trusted in the GUI - it will not trust-on-first-use. Connect once
  from Kino before expecting MCP to reach a new host.
- **The password comes from the environment.** `KINO_MCP_PASSWORD` is readable
  by other processes running as you, so this protects the vault file at rest,
  not against someone already on your machine as you.
- Each tool call opens its own SSH connection, so a host behind a slow handshake
  will feel slow per call.

### If it doesn't start

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

## Security model

- The vault (`vault.enc`) is an AES-256-GCM ciphertext; the key is derived from your master password with Argon2 and a random 16-byte salt stored alongside the ciphertext.
- History and the snippet library are stored as sibling encrypted files under the same key.
- Cloud sync uploads only the encrypted blobs - the server (GitHub) never sees plaintext or your master password.
- Notes and harvested shell history live in sibling encrypted blobs (`notes.enc`, `shell-history.enc`) under the same key as the vault - never on a `Host`, which is what profile export serialises to plaintext JSON.
- The MCP server reads only `mcp_vault.enc` - the hosts you explicitly exposed, encrypted under a separate MCP password. Your master password is never passed to it, and the rest of the vault is not in the file at all. Host-key pinning is enforced there too: a host the GUI hasn't trusted is refused rather than trusted on first use.
- The key audit runs entirely on your machine, against the keys already in the vault. No host is contacted to produce the report, and nothing is sent anywhere.
- Key rotation never removes a key it hasn't first proved it can do without: the new key is verified on its own connection before the old one is touched, and the rewrite of `authorized_keys` is refused if the new key isn't present in the result.
- See [SECURITY.md](SECURITY.md) for the threat model, what is and isn't protected, and how to report vulnerabilities.

## Getting started

### Prerequisites
- [Rust](https://rustup.rs/) (stable) and the [Tauri 2 prerequisites](https://tauri.app/start/prerequisites/) for your OS
- Node.js 18+
- On Linux, the tray icon needs an AppIndicator library at runtime (`libayatana-appindicator3`, packaged as `libappindicator3-dev` for building). Without it Kino still runs, but minimising to the notification area has nowhere to go.

### Run it
```bash
npm install
npm run tauri dev
```
First launch asks you to create a vault. The master password has no recovery - if you lose it, the vault is gone.

### Build installers
```bash
npm run tauri build
```
Output lands in `src-tauri/target/release/bundle/` - `.deb`, `.rpm` and `.AppImage` on Linux, `.msi` and `.exe` on Windows.

### A throwaway vault, for demos and testing
Kino keeps everything under the platform's local data directory, which on Linux follows `XDG_DATA_HOME`. Pointing that elsewhere gives you a completely separate, empty vault, leaving your real one untouched:

```bash
XDG_DATA_HOME=/tmp/kino-demo npm run tauri dev
```

Useful for screenshots, for trying a feature against invented hosts, or for reproducing a first-run experience. Delete `/tmp/kino-demo` when you're done.

## Tech stack

- **Backend:** Rust - `russh` (SSH/SFTP), `aes-gcm` + `argon2` (vault crypto), `ureq` (cloud sync / model API), `zeroize`.
- **Frontend:** React + TypeScript + Vite, Zustand for state, xterm.js for the terminal, Monaco for the remote editor.

## Contributing

Contributions are welcome - see [CONTRIBUTING.md](CONTRIBUTING.md). Because this is a security-sensitive app, changes touching the vault, crypto, or auth paths get extra scrutiny.

## License

[GNU GPL-3.0](LICENSE)
