# Changelog

All notable changes to Kino SSH Manager are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

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
