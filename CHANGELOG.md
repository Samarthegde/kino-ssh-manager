# Changelog

All notable changes to Kino SSH Manager are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [0.4.0] - 2026-06-10

### Added
- **Docker management** — a per-session panel to manage Docker over the existing
  SSH connection (or the local daemon from a local-shell tab):
  - Containers: start / stop / restart / pause / remove, with live status.
  - **Shell access** — drop into an interactive shell inside any running
    container (`docker exec`, prefers `bash`, falls back to `sh`) as a new
    terminal tab.
  - **Live log streaming** — follow a container's logs in real time.
  - **Images / Volumes / Networks** tabs for browsing the daemon.
- **Live system metrics** — a streaming dashboard (CPU, memory, disk, load
  average, uptime, network throughput) sampled once a second, for remote hosts
  and the local machine.
- **Remote (reverse) port forwarding** (`ssh -R`) and a **dynamic SOCKS5 proxy**
  (`ssh -D`), alongside the existing local forwards. Pick the tunnel type per
  rule in the host editor.
- **Operating-system tags** — choose a host's OS in the editor; the sidebar
  shows a matching OS icon (Linux, Ubuntu, Debian, Fedora, Arch, Alpine,
  Windows, macOS) tinted with the host color.
- **Collapsible, resizable sidebar** — hide it from the header toggle or drag
  its edge to resize; the width and collapsed state persist.

### Changed
- **Async networking backend** — the SSH/SFTP/forwarding stack was rewritten
  from the synchronous `ssh2` (libssh2) to the asynchronous `russh` (Tokio).
  A single connection is now multiplexed, so Docker queries, metrics, SFTP, and
  port forwards run in the background without lagging or dropping the terminal.
- Host color is now shown as a top accent line plus an OS/initial tile, instead
  of a full border.
- The sidebar "Sort by" dropdown now follows the active theme.

### Fixed
- App could abort on connect (`ptr::copy_nonoverlapping` UB-check) due to
  pre-release RustCrypto crates pulled in by `russh`; debug-assertions are now
  disabled for dependencies so the benign check no longer crashes dev builds.

### Compatibility
- The new `os` host field is additive; existing vaults load unchanged.
- Port-forward rules without an explicit type default to local forwards.

## [0.3.0] - 2026-06-09

### Added
- **Folders / Groups** — dynamically organize hosts in the sidebar using tag-based groups.
- **Quick Connect Bar** — instantly connect to any transient host directly from the sidebar by typing `user@host:port` without cluttering the vault.
- **Local Shell Tabs** — open a local PowerShell (Windows) or Bash/Zsh (Unix) terminal right inside the app, alongside your remote SSH tabs.

### Fixed
- **Windows SSH authentication (Error 19)** — libssh2 could fail to parse keys with `\r\n` line endings on Windows. Private and public keys are now normalized to use `\n` line endings internally before being sent to the authentication backend.

### Compatibility
- The `group` field for Folders is fully backward compatible; existing vaults will load seamlessly without it.

## [0.2.0] - 2026-06-04

### Added
- **Per-host notes** — store free-form notes on any connection. Notes are
  searchable from the sidebar and shown via a note indicator and row tooltip.
- **Master password confirmation** on first-time vault creation, with a
  "no recovery if you forget this" reminder.
- **Show/hide password toggle** on the unlock screen.
- **Resizable host editor** — drag the bottom-right corner of the Add/Edit Host
  dialog.
- **Windows installers** (`.msi` / `.exe`) are now built and published alongside
  the Linux packages.

### Changed
- Refreshed UI: softer shapes, focus rings, button depth, animated modals, and a
  glassier unlock screen.
- Modals no longer close when clicking outside — only via the ✕ or Cancel/Done
  buttons, to prevent accidental dismissal.

### Fixed
- The auto-lock dropdown now follows the selected theme instead of using the OS
  default colors.
- **SSH key authentication on Windows** — ed25519/OpenSSH keys failed to
  authenticate on the Windows build because libssh2 could not derive the public
  key from the in-memory private key. The public key is now supplied (stored, or
  derived in Rust) so key-based auth works across platforms.
- The Windows build now compiles `libssh2` against a vendored OpenSSL so
  in-memory key auth is available there (keys are never written to disk).

### Compatibility
- The `notes` field is additive; existing vaults continue to load unchanged.
- The Windows key-auth fix is read-only at connect time and changes no vault
  data or format.

## [0.1.0]

### Added
- Initial public release.
- Encrypted vault (Argon2 + AES-256-GCM) unlocked by a single master password.
- Per-host password and/or SSH key auth; ed25519 generation and `.pem`/`.key`/`.ppk` import.
- Built-in xterm.js terminal with scrollback search and font sizing.
- Port forwarding (local tunnels) per host.
- SFTP file browser: browse, upload/download with progress, rename, delete,
  new folder, chmod.
- Snippets library with per-host auto-run on connect.
- Optional encrypted cloud sync to a private GitHub repo, with auto-sync.
- Host key verification (trust-on-first-use) with mismatch protection.
- Security niceties: idle auto-lock, change master password (re-key), in-memory
  secret zeroization, per-host color tags, 6 themes, connection history,
  session logging.
