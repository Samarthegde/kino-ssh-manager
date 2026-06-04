# Security Policy

Kino SSH Manager stores SSH credentials, so security is a first-class concern. This document describes the threat model and how to report issues.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Use GitHub's private vulnerability reporting: go to the repository's **Security** tab → **Report a vulnerability**. Include details and, if possible, a proof of concept. We aim to acknowledge reports within a few days and will coordinate a fix and disclosure timeline with you. Please give us reasonable time to address the issue before any public disclosure.

## How the vault works

- The vault file (`vault.enc`) is encrypted with **AES-256-GCM**.
- The encryption key is derived from your master password using **Argon2** with a random 16-byte salt, which is stored alongside the ciphertext.
- Connection history (`history.enc`) and the snippet library (`snippets.enc`) are encrypted as sibling files under the same key.
- On lock (manual or idle auto-lock), the derived key is wiped from memory with `zeroize`.

## Cloud sync

- Cloud sync is **opt-in**. When enabled, only the **already-encrypted** blobs are uploaded to your chosen private GitHub repository.
- Your master password and decrypted secrets are **never** transmitted. The sync provider cannot decrypt your data.
- The GitHub personal access token you provide is stored encrypted inside the vault directory.

## What this protects against

- Someone obtaining a copy of the vault file (e.g. a stolen disk or a leaked sync repo) cannot read it without your master password.
- Network observers and the sync host see only ciphertext.

## What this does NOT protect against

- **A compromised local machine.** While the vault is unlocked, the derived key and decrypted secrets exist in process memory. Malware running as your user, or with debugger access to the process, can read them.
- **A weak master password.** Argon2 slows brute force but cannot rescue a trivially guessable password. Use a strong, unique one — there is no recovery if you forget it.
- **The remote hosts you connect to.** Once you connect, the remote server can see whatever you type/transfer.

## Host key verification

Connections verify the server's host key on a trust-on-first-use (TOFU) basis:

- On first contact the app shows the server's **SHA256 fingerprint** and asks you to confirm it before connecting. Verify it out-of-band (e.g. `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the server) when you can.
- Accepted fingerprints are stored in `known_hosts.json` (keyed by `host:port`).
- If a server later presents a **different** key, the connection is **refused** with a mismatch warning — this is the man-in-the-middle protection. After a legitimate server rebuild you can re-trust the new key from the dialog.
- Verification is enforced in the backend before any credentials are sent, including for port forwards and SFTP — not just in the UI.

## Supported versions

This project is pre-1.0; security fixes are applied to the latest `main`. Pin a commit if you need stability.
