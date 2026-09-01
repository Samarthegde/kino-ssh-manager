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

## Security model

- The vault (`vault.enc`) is an AES-256-GCM ciphertext; the key is derived from your master password with Argon2 and a random 16-byte salt stored alongside the ciphertext.
- History and the snippet library are stored as sibling encrypted files under the same key.
- Cloud sync uploads only the encrypted blobs - the server (GitHub) never sees plaintext or your master password.
- Notes and harvested shell history live in sibling encrypted blobs (`notes.enc`, `shell-history.enc`) under the same key as the vault - never on a `Host`, which is what profile export serialises to plaintext JSON.
- The key audit runs entirely on your machine, against the keys already in the vault. No host is contacted to produce the report, and nothing is sent anywhere.
- Key rotation never removes a key it hasn't first proved it can do without: the new key is verified on its own connection before the old one is touched, and the rewrite of `authorized_keys` is refused if the new key isn't present in the result.
- See [SECURITY.md](SECURITY.md) for the threat model, what is and isn't protected, and how to report vulnerabilities.

## Getting started

### Prerequisites
- [Rust](https://rustup.rs/) (stable) and the [Tauri 2 prerequisites](https://tauri.app/start/prerequisites/) for your OS
- Node.js 18+

### Develop
```bash
npm install
npm run tauri dev
```

### Build
```bash
npm run tauri build
```

## Tech stack

- **Backend:** Rust - `russh` (SSH/SFTP), `aes-gcm` + `argon2` (vault crypto), `ureq` (cloud sync / model API), `zeroize`.
- **Frontend:** React + TypeScript + Vite, Zustand for state, xterm.js for the terminal, Monaco for the remote editor.

## Contributing

Contributions are welcome - see [CONTRIBUTING.md](CONTRIBUTING.md). Because this is a security-sensitive app, changes touching the vault, crypto, or auth paths get extra scrutiny.

## License

[GNU GPL-3.0](LICENSE)
