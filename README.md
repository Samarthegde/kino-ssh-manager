# Kino SSH Manager

A secure, cross-platform SSH credential manager and terminal, built with [Tauri 2](https://tauri.app/) (Rust) and React. Credentials live in a single encrypted vault on your machine — your master password and secrets never leave the device unless you explicitly enable cloud sync, and even then only the encrypted blob is uploaded.

## Features

- **Encrypted vault** — Argon2 key derivation + AES-256-GCM. One master password unlocks everything.
- **SSH terminal** — full xterm.js terminal per host, with scrollback search (Ctrl+F) and adjustable font size (Ctrl +/-/0).
- **Flexible auth** — store a password and/or an SSH key per host (including encrypted keys with a passphrase); import `.pem`/`.key`/`.ppk` files or generate ed25519 keypairs.
- **Port forwarding** — per-host local tunnels you can start/stop per session.
- **SFTP file browser** — browse, upload, download (with progress bars), rename, delete, new folder, and chmod.
- **Snippets** — a reusable command library; selected snippets auto-run on connect, per host.
- **Cloud sync (optional)** — sync the *encrypted* vault to a private GitHub repo (Contents API, sha-based conflict detection). Optional auto-sync (pull on unlock, push on change).
- **Security niceties** — idle auto-lock, change-master-password (re-key), secrets zeroized in memory on lock.
- **Quality of life** — host search, per-host accent colors (flag prod!), 6 themes, connection history, session logging.

## Security model

- The vault (`vault.enc`) is an AES-256-GCM ciphertext; the key is derived from your master password with Argon2 and a random 16-byte salt stored alongside the ciphertext.
- History and the snippet library are stored as sibling encrypted files under the same key.
- Cloud sync uploads only the encrypted blobs — the server (GitHub) never sees plaintext or your master password.
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

- **Backend:** Rust — `ssh2` (SSH/SFTP), `aes-gcm` + `argon2` (vault crypto), `ureq` (cloud sync), `zeroize`.
- **Frontend:** React + TypeScript + Vite, Zustand for state, xterm.js for the terminal.

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Because this is a security-sensitive app, changes touching the vault, crypto, or auth paths get extra scrutiny.

## License

[MIT](LICENSE)
