# Security Policy

Kino SSH Manager stores SSH credentials, so security is a first-class concern.
This document is the *process*: how to report something, what happens after you
do, and which versions get fixes. The design question - what someone in each
position can actually reach - is in
[docs/threat-model.md](docs/threat-model.md).

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Two routes, either is fine:

- **GitHub private vulnerability reporting** - the repository's **Security**
  tab, then **Report a vulnerability**. Preferred: the report, the fix, the
  advisory and the CVE request all happen in one place, and you keep access to
  the thread.
- **Email `samarth@nanokernel.net`**, with `kino security` in the subject. Use
  this when GitHub is unreachable, when you would rather not have an account,
  or when the report is about GitHub-side exposure. There is no PGP key yet, so
  treat the mail as unencrypted: send the shape of the problem, not a working
  exploit against someone else's host.

Useful to include: the version and commit (**About** shows both), the operating
system, what you did, and what you expected instead. A proof of concept helps
and is not required.

### What happens next, and when

Working days, Europe/London, counted from when the report arrives.

| Stage | Target |
|---|---|
| Acknowledgement from a human | 5 working days |
| Assessment - severity, affected versions, in scope or not | 10 working days |
| Fix released for a critical or high finding | 30 days from assessment |
| Fix released for a medium finding | the next release, and within 90 days |
| Fix released for a low finding | the backlog, in public, once it is clear it is not exploitable |

The limit worth stating: this is one maintainer, not a rota. If five working
days pass with nothing, send the email route as well - the likeliest
explanation is a notification that never arrived, not a decision.

## Severity

CVSS v3.1 base scores, because that is what GitHub Security Advisories record:
critical 9.0-10.0, high 7.0-8.9, medium 4.0-6.9, low 0.1-3.9.

Three cases are rated **high at minimum** whatever the vector string says,
because they break a promise this app is built on:

- Vault plaintext - a key, password or passphrase - reachable without the
  master password.
- Host key verification bypassed, skipped, or satisfied by the wrong key.
- An MCP tool call exceeding the capability its host's access mode allows -
  a write through a read-only host, a command past the rule set, a transfer
  outside the transfers folder.

A finding that needs the attacker to already have code execution as your user
is usually low: at that point the vault is unlocked in a process they can read.
That is stated plainly in the threat model rather than treated as a surprise.

## Disclosure

- **90 days** from acknowledgement, by default, after which the advisory is
  published whether or not a fix shipped. Earlier if a fix is out sooner;
  later if you ask and the reason holds.
- **Credit** in the advisory under whatever name or handle you give, unless you
  ask for none.
- **A CVE is requested** for every medium or higher finding in a released
  version, through GitHub as CNA, by the maintainer. You are welcome to request
  one yourself instead - say so and it will not be requested twice.
- **Embargo**: while a fix is being prepared, the work happens in a private
  fork and the commit lands with an ordinary message. The advisory, not the
  commit log, is where the detail is published.

## How a report is handled

1. **Triage.** The report gets the `security` label, plus one of `confirmed`,
   `needs-info` or `not-a-vulnerability` - the last one with the reasoning
   written out, not just a close.
2. **Scope.** Which versions, which platforms, and whether the default
   configuration is affected. A finding that needs a non-default setting says
   which one.
3. **Advisory draft.** A GitHub Security Advisory, private, with the affected
   version range and the fixed version filled in before the fix is pushed.
4. **Fix, with a test.** A regression test that fails without the fix - the
   same rule as any other bug here.
5. **Release.** The advisory is published, and the fix is announced in the
   release notes, in the in-app **What's new** panel, and through the updater
   prompt. The advisory feed is at
   [/security/advisories](https://github.com/Samarthegde/kino-ssh-manager/security/advisories)
   and is worth watching if you deploy this.

## Supported versions

Pre-1.0, with releases roughly fortnightly, the window is deliberately short:

| Version | Security fixes |
|---|---|
| Latest release (currently 0.9.x) | Yes |
| The previous minor | 30 days after its successor ships |
| Anything older | No - upgrade |
| `main` | Fixes land here first |

A fix is delivered as a new release, not as a patch to an old one: there is no
0.8.x branch to backport to. The in-app updater verifies a signature before it
installs anything, so taking the upgrade is the supported path.

## Software bill of materials

Every release carries `kino-ssh-manager-<version>.cdx.json` - a CycloneDX
document covering both dependency trees, the Rust crate and the frontend,
generated in CI from the same commit that built the installers.

```bash
gh release download v0.9.4 -p '*.cdx.json' -R Samarthegde/kino-ssh-manager
jq -r '.components[] | "\(.name) \(.version)"' kino-ssh-manager-0.9.4.cdx.json | sort
```

That answers the question an advisory about a library actually raises: does
*this* build contain it, and at which version. The SBOM is listed in
`SHA256SUMS` with everything else, so it is covered by the same signature.

## How the vault works

- The vault file (`vault.enc`) is encrypted with **AES-256-GCM**.
- The encryption key is derived from your master password using **Argon2** with
  a random 16-byte salt, which is stored alongside the ciphertext.
- Connection history (`history.enc`) and the snippet library (`snippets.enc`)
  are encrypted as sibling files under the same key.
- On lock (manual or idle auto-lock), the derived key is wiped from memory with
  `zeroize`.

## The recovery kit

One printed key, made while the vault is unlocked, that opens it when the
master password is gone. Settings - Vault & Sync - Recovery key.

- The key is **256 random bits**, shown **once**, and stored nowhere by Kino.
  What goes on disk is `recovery.enc`: the vault's own AES key, encrypted under
  a key derived from the recovery key with Argon2. Without the printed key that
  file is as opaque as the vault beside it.
- It is a **second credential of equal power**. Anyone with it opens every host
  in the vault without knowing your password. Keep it the way you would keep a
  spare key to the building - not beside the vault, and not in it.
- Using it **sets a new master password in the same step**, because a vault
  opened by recovery has no password anybody knows. The kit is spent at that
  point and Kino offers a fresh one.
- **Changing the master password retires it.** The kit holds the key the old
  password derived, which opens nothing afterwards, so the file is deleted and
  the settings panel asks for a new one. (The honest fix is a key-slot layout,
  where a password change re-wraps a random master key instead of re-encrypting
  everything; that is a vault format change and has not been made.)
- It is **not synced**. The kit stays on the machine it was made on; the
  printed key is what crosses machines.
- No kit can be made after the password is lost. That is the whole point of
  making one early.

## Vault sync

- Sync is **opt-in**. When enabled, only the **already-encrypted** blobs leave
  the machine - to a private GitHub repository, or to a folder you choose
  (`Documents/ssh-manager`), which is where a third-party sync client such as
  Dropbox or Syncthing can pick them up.
- Your master password and decrypted secrets are **never** transmitted. The
  sync provider cannot decrypt your data.
- The GitHub personal access token you provide is stored encrypted inside the
  vault directory.

## What this protects against

- Someone obtaining a copy of the vault file (e.g. a stolen disk or a leaked
  sync repo) cannot read it without your master password.
- Network observers and the sync host see only ciphertext.

## What this does NOT protect against

- **A compromised local machine.** While the vault is unlocked, the derived key
  and decrypted secrets exist in process memory. Malware running as your user,
  or with debugger access to the process, can read them.
- **A weak master password.** Argon2 slows brute force but cannot rescue a
  trivially guessable password. Use a strong, unique one. Forgetting it means
  the vault is gone unless you made a recovery kit first - see below.
- **The remote hosts you connect to.** Once you connect, the remote server can
  see whatever you type/transfer.

## Verifying what you downloaded

Every release asset is signed with the project's minisign key, whose public
half is in [`minisign.pub`](minisign.pub) and in `src-tauri/tauri.conf.json`.
Releases also carry a `SHA256SUMS` covering every asset, and `SHA256SUMS.sig`.
Per-asset signatures prove each file; the signed `SHA256SUMS` proves the *set*,
which per-asset signatures cannot.

Tauri base64-wraps the signatures it writes, so decode one before handing it to
`minisign`, which expects `<file>.minisig` beside the file:

```bash
base64 -d SHA256SUMS.sig > SHA256SUMS.minisig
minisign -Vm SHA256SUMS -p minisign.pub && sha256sum -c SHA256SUMS --ignore-missing
```

GitHub Actions also attests each asset, which says which workflow at which
commit produced it - something a signature alone cannot:

```bash
gh attestation verify <file> --repo Samarthegde/kino-ssh-manager
```

The in-app updater verifies a signature before applying anything, and refuses
rather than offering to continue. `kino-mcp` is a separate download and worth
checking by hand: it can reach every host you expose to it.

## The AI copilot

The copilot is optional and off by default. When it is on, terminal output -
which a compromised host controls - reaches a third-party model, and the model
proposes commands. That surface has its own document:
[docs/copilot-threat-model.md](docs/copilot-threat-model.md), covering the
injection paths, the redaction pass that runs before anything is sent, and the
residual risks none of it removes.

In short: no model output ever runs without a confirmation showing the command
verbatim, secrets are stripped from prompts in the backend rather than the UI,
and the copilot has no vault access.

## Host key verification

Connections verify the server's host key on a trust-on-first-use (TOFU) basis:

- On first contact the app shows the server's **SHA256 fingerprint** and asks
  you to confirm it before connecting. Verify it out-of-band (e.g.
  `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the server) when you
  can.
- Accepted fingerprints are stored in `known_hosts.json` (keyed by `host:port`).
- If a server later presents a **different** key, the connection is **refused**
  with a mismatch warning - this is the man-in-the-middle protection. After a
  legitimate server rebuild you can re-trust the new key from the dialog.
- Verification is enforced in the backend before any credentials are sent,
  including for port forwards and SFTP - not just in the UI.
