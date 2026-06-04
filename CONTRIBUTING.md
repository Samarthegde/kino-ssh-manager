# Contributing to Kino SSH Manager

Thanks for your interest in contributing! This is a security-sensitive desktop app, so a little process keeps everyone safe.

## Development setup

Prerequisites: [Rust](https://rustup.rs/) (stable), Node.js 18+, and the [Tauri 2 prerequisites](https://tauri.app/start/prerequisites/) for your OS.

```bash
npm install
npm run tauri dev
```

## Project layout

- `src-tauri/src/` — Rust backend
  - `vault.rs` — `Host` struct + vault encryption (Argon2 + AES-256-GCM)
  - `lib.rs` — app state and all Tauri command handlers
  - `ssh_session.rs` — interactive terminal sessions
  - `forwarding.rs` — port-forward tunnels
  - `sftp_session.rs` — SFTP sessions (browse/transfer/manage)
  - `sync.rs` — encrypted-blob cloud sync (pluggable `SyncBackend`, GitHub impl)
  - `snippets.rs`, `history.rs`, `keygen.rs`
- `src/` — React + TypeScript frontend
  - `store/index.ts` — Zustand store (state + IPC calls)
  - `components/` — UI

## Before you open a PR

Please make sure both sides build cleanly:

```bash
# Frontend type-check
npx tsc --noEmit

# Backend
cargo check --manifest-path src-tauri/Cargo.toml
cargo clippy --manifest-path src-tauri/Cargo.toml -- -D warnings
cargo fmt --manifest-path src-tauri/Cargo.toml
```

## Guidelines

- **Match the surrounding style.** The codebase favors small, focused modules and `Result<_, String>` at the command boundary.
- **Crypto/auth/vault changes get extra scrutiny.** If you touch `vault.rs`, the sync code, or authentication, explain the reasoning in the PR and add tests where practical.
- **Never log or transmit secrets.** Passwords, private keys, and tokens must stay in the encrypted vault and in memory only while unlocked.
- **Keep the IPC surface tight.** New Tauri commands should validate that the vault is unlocked where relevant.
- Keep PRs scoped to one feature or fix; include a short description of what you changed and how you verified it.

## Reporting security issues

Do **not** file public issues for vulnerabilities — see [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
