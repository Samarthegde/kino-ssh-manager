<div align="center">

# Kino SSH Manager

**An SSH client that keeps your hosts, keys and passwords in one encrypted vault on your own machine.**

No account, no cloud, no telemetry. Free and open source under the GPL.

[**Website**](https://samarthegde.github.io/kino-ssh-manager/) · [Releases](https://github.com/Samarthegde/kino-ssh-manager/releases) · [Security](SECURITY.md)

</div>

## Download

| | | |
| --- | --- | --- |
| <img src="https://cdn.simpleicons.org/linux/9aa0a6" width="18" align="center"> **Linux** | [`.deb`](https://github.com/Samarthegde/kino-ssh-manager/releases/latest/download/kino-linux-x86_64.deb) · [`.rpm`](https://github.com/Samarthegde/kino-ssh-manager/releases/latest/download/kino-linux-x86_64.rpm) · [`.AppImage`](https://github.com/Samarthegde/kino-ssh-manager/releases/latest/download/kino-linux-x86_64.AppImage) | x86-64 |
| <img src="https://cdn.simpleicons.org/windows/9aa0a6" width="18" align="center"> **Windows** | [`.msi`](https://github.com/Samarthegde/kino-ssh-manager/releases/latest/download/kino-windows-x86_64.msi) · [`.exe`](https://github.com/Samarthegde/kino-ssh-manager/releases/latest/download/kino-windows-x86_64-setup.exe) | x86-64 |
| <img src="https://cdn.simpleicons.org/apple/9aa0a6" width="18" align="center"> **macOS** | not built yet - [#31](https://github.com/Samarthegde/kino-ssh-manager/issues/31) | |

Every release is signed, and carries a signed `SHA256SUMS` plus a GitHub build
attestation. [How to check them](SECURITY.md#verifying-what-you-downloaded).

## What it does

- **One encrypted vault.** Argon2 and AES-256-GCM; one master password unlocks
  every host, key and snippet. Nothing leaves the machine unless you turn on
  cloud sync, and then only the encrypted blob.
- **A real terminal per host.** Split panes, broadcast input, search with match
  counts, 200,000 lines of scrollback, and output coloured by the active theme.
- **The whole session in one window.** SFTP browser with a built-in editor,
  Docker, live metrics, a process tree you can signal, the host's crontab in
  plain English, and recorded sessions you can replay.
- **Tunnels and bastions.** Local, remote and dynamic forwards, each drawn as a
  diagram so `-L` and `-R` can't be confused, and jump hosts that chain.
- **Fleet answers, on your own machine.** What cryptography each host would
  actually negotiate, which private keys are lying around in `~/.ssh`, what
  updates are waiting, and which stored keys are weak, shared or old.
- **Production guard.** A marked host gets a framed terminal, and a dangerous
  command there has to be confirmed against the hostname.
- **AI, if you want it.** An opt-in copilot with your own key, and an
  [MCP server](docs/mcp.md) that exposes chosen hosts to an assistant -
  read-only until you say otherwise, and every call recorded.
- **Reach hosts with no open port.** Optional agent mode dials out through a
  relay, so a box behind NAT or CGNAT needs no inbound SSH.

The full tour, with pictures, is on [the website](https://samarthegde.github.io/kino-ssh-manager/).

## Security

The vault is AES-256-GCM with an Argon2-derived key. History, notes, snippets
and harvested shell history sit in sibling encrypted files under that same key.
Host keys are pinned on first use and refused on any mismatch. Key rotation
proves the new key works on its own connection before removing the old one. The
transport audit and the key sweep both run with the vault locked and never
decrypt a credential.

[SECURITY.md](SECURITY.md) has the threat model, what is *not* protected, and
how to report a vulnerability.

## Build it yourself

You need [Rust](https://rustup.rs/), Node 18+, and the
[Tauri 2 prerequisites](https://tauri.app/start/prerequisites/) for your OS.

```bash
npm install
npm run tauri dev      # run it
npm run tauri build    # installers land in src-tauri/target/release/bundle/
```

First launch asks you to create a vault. **The master password has no recovery.**

To try it without touching your real vault, point the data directory somewhere
else - on Linux, `XDG_DATA_HOME=/tmp/kino-demo npm run tauri dev`.

## Contributing

Issues and pull requests are welcome, and some issues are
[tagged for newcomers](https://github.com/Samarthegde/kino-ssh-manager/labels/good%20first%20issue).
See [CONTRIBUTING.md](CONTRIBUTING.md). Anything touching the vault, crypto or
authentication gets extra scrutiny.

Built with [Tauri 2](https://tauri.app/) - Rust (`russh`, `aes-gcm`, `argon2`)
and React with xterm.js.

## License

[GNU GPL-3.0](LICENSE)
