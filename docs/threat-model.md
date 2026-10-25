# Threat model

What Kino SSH Manager protects, who it protects it from, and where the edges
are. [SECURITY.md](../SECURITY.md) is the process - how to report something and
what happens next. This is the design.

**Scope.** The desktop app and `kino-mcp`, which ship from this repository and
run on your machine. Nothing here describes a server you would have to trust:
there is no Kino account, no telemetry, and no hosted component in this
product. The AI copilot has its own, longer document -
[copilot-threat-model.md](copilot-threat-model.md) - because an attacker who
controls terminal output gets to write to the model's prompt, and that deserves
more than a row in a table.

Written against 0.9.4. Where a mitigation is partial, it says so; a threat
model that lists only its wins is advertising.

## What is worth taking

In rough order of how badly you would want it back.

| Asset | Where it lives | At rest |
|---|---|---|
| Master password | Your head, and process memory while unlocked | Never written anywhere |
| Derived vault key | Process memory only, wiped with `zeroize` on lock | Never written |
| SSH keys, passwords, passphrases | `vault.enc` | AES-256-GCM, Argon2 from the master password |
| Host list, ports, usernames, notes | `vault.enc`, `notes.enc` | Same key |
| Connection history and snippets | `history.enc`, `snippets.enc` | Same key |
| Sync credentials (GitHub token) | `sync.enc`, `cloud.enc` | Same key |
| AI provider key | `ai.enc` | Same key |
| Which hosts an assistant may reach, and how | `mcp_vault.enc`, `mcp_config.enc` | Separate key, from the same password |
| What an assistant did | `audit.enc` | Sealed per line, append-only |
| Spending so far this hour | `mcp_budget.enc` | Sealed |
| Accepted host fingerprints | `known_hosts.json` | **Plaintext, by design** - see below |
| Session recordings | `~/Videos/Kino Recordings/*.cast` | **Plaintext** - they are evidence, meant to be read |
| Pre-change backups of remote files | `~/.kino/backups/`, mode 0700/0600 | Plaintext |
| Files moved by SFTP tools | The transfers folder you nominate | Plaintext - they are your files |

The vault directory is `~/.local/share/ssh-manager` on Linux,
`~/Library/Application Support/ssh-manager` on macOS, and
`%LOCALAPPDATA%\ssh-manager` on Windows.

`known_hosts.json` is deliberately not encrypted: it must be readable to be
*checked* by you, and a fingerprint is public information - it is what the
server presents to anyone who connects. What matters is that it cannot be
silently rewritten, which is a filesystem permission question, not an
encryption one. On a machine where another local account can write your home
directory, that assumption is gone, and so is everything else here.

## Who is on the other side

| Adversary | Position | What they want |
|---|---|---|
| Disk thief | A copy of your drive, a stolen laptop, a backup tape | The vault |
| Leaked-sync observer | Read access to your sync repo or sync folder | The vault |
| Network attacker | On the path to a host you connect to | Credentials, a session |
| Malicious or compromised host | A machine you connect to, legitimately | Your other hosts, your attention |
| Hostile assistant or MCP client | Driving `kino-mcp`, possibly with an injected prompt | Arbitrary commands on your fleet |
| Local malware as your user | Same uid, same session | Everything, while unlocked |
| Shoulder surfer / walk-up | Your unlocked screen | A live session |
| Supply chain | A dependency, or the release pipeline | Every user at once |

Out of scope, and honestly so: an attacker with root on your machine, with
physical DMA or cold-boot access, or with your master password. Also out of
scope: hiding *that* you use SSH, or who you connect to, from someone watching
your network. Kino does no traffic shaping and makes no such claim.

## The boundaries

Nine places where data crosses from something trusted to something less so.

### 1. Disk to process - the vault at rest

Everything sensitive is encrypted with AES-256-GCM under a key derived by
Argon2 from your master password with a random 16-byte salt stored beside the
ciphertext. Writes go to a temporary file and are renamed into place, so an
interrupted save leaves the previous vault intact rather than a truncated one.

**Still true after the mitigation:** file sizes and modification times leak
roughly how many hosts you have and when you last changed them. A weak master
password is a weak vault, and Argon2 only buys time.

### 2. You to the app - unlock and idle lock

The derived key exists only while unlocked, and is zeroized on manual lock, on
idle auto-lock, and on quit. Changing the master password re-encrypts every
sibling blob under the new key.

**Still true:** between unlock and lock, the key and plaintext are in process
memory. Anything running as your user can read that, and no amount of
in-process hygiene fixes it. The idle timeout is the one control that bounds
that window, and it ships **off** - `Settings - idle lock` is worth a minute of
your attention on a machine you walk away from.

### 3. The app to `sshd` - host key verification

Trust on first use. On first contact Kino shows the SHA256 fingerprint and
waits; accepted keys go to `known_hosts.json`, keyed by `host:port`. A later
mismatch is a refusal with a warning, not a prompt to continue. The check runs
in the backend, before credentials are sent, on every path that opens a
connection - shells, port forwards, SFTP, MCP calls.

**Still true:** first contact is unverified unless you compare the fingerprint
out of band. TOFU detects a change; it cannot detect an attacker who was there
from the beginning.

Keyboard-interactive authentication adds a second thing to say: the prompt text
is written by the server, so on a compromised host it is written by an
attacker. "Enter your Kino master password" is a prompt a hostile server can
send. Kino shows that text verbatim - eliding it would hide what is being
asked - but the window labels it as the host's words, says that Kino never asks
for the vault password there, and keeps nothing that is typed. A stored
password is only ever sent in answer to a prompt that asks for a password and
mentions no second factor; a prompt asking for a code is always passed to you.
What remains is a person who could still type a secret into a field a hostile
server labelled convincingly.

### 4. The app to a sync backend - GitHub, or a folder

Only sealed blobs leave the machine. The backend never sees the master
password, the derived key, or any plaintext, and a sync provider with full read
access learns the sizes and timing of your vault writes, nothing more. Writes
are conditional - an `ETag` on GitHub, a content hash for a folder - so a
second device that changed the same blob produces a conflict rather than an
overwrite.

**Still true:** two devices writing in the same instant is the one case the
check cannot catch. A sync host can also *withhold* or roll back - it cannot
read your vault, but it can serve you an older one, and nothing in the protocol
proves freshness. The GitHub token is stored encrypted in the vault, so a
stolen vault file does not hand over your repository; a compromised unlocked
machine does.

### 5. The app to an AI provider - the copilot

Off by default. When on, terminal output goes to a third-party model after a
backend redaction pass, and model output is never executed: a proposed command
is shown verbatim, and Apply opens a terminal with it ready rather than running
it. The copilot has no vault access.

**Still true:** redaction is pattern matching, and a determined host can shape
output to defeat it. The full treatment, including the injection paths, is in
[copilot-threat-model.md](copilot-threat-model.md).

### 6. An MCP client to `kino-mcp` - the assistant boundary

This is the newest boundary and the widest, because on the other side of it is
a model that may be reading instructions from a compromised host. Seven
controls, layered, each of which assumes the ones outside it have failed:

- **Exposure is opt-in per host.** A host an assistant cannot see does not
  exist to it. Nothing is exposed by default.
- **Each exposed host has a mode.** `read_only` (the default a host lands in
  when someone ticks it without reading anything), `guarded`, or `full`. Every
  tool declares what it does - metadata, read, exec or write - and the mode
  reasons about that rather than about tool names, so a tool added later has to
  state its blast radius to compile. A tool missing from the map is treated as
  a write, the most restrictive answer, so it fails closed instead of slipping
  through.
- **Rules match the command as written**, allow or deny, per host. They catch
  mistakes and casual overreach, not someone determined to get around them -
  shell quoting is a large space.
- **Guarded mode asks you** before anything not already allowed, over a Unix
  socket at `mcp_approval.sock` beside the vault, mode 0600. A closed socket, a locked vault, or a timeout is a
  refusal, not a pass.
- **Budgets bound the blast radius**: changes per hour, hosts per call, calls
  per hour, concurrency, bytes per transfer. A ledger on disk survives restarts,
  so a crash loop cannot reset the count.
- **The halt is a plain file.** `touch mcp_halt` in the vault directory, or the
  tray switch, and everything refuses. Anything other than a clean "file not
  found" counts as halted, so a permissions problem or a broken mount stops the
  assistant instead of waving it through.
- **Everything is written down.** One sealed line per call in `audit.enc`,
  decision included, readable in **Security - MCP activity**. Refusals are
  recorded too; a log that only holds successes cannot answer the question you
  will actually have.

**Still true:** `exec` on a host is a shell on that host, and no rule set makes
that safe - it is why the mode exists separately from `read`. An assistant with
`write` can break a host in ways a backup of one file does not undo. The halt
file stops new calls; it does not reach into a command already running on a
remote machine.

### 7. `kino-mcp` to a remote host

The same code path as the app's own connections: the same host key check, the
same credentials from the same vault. `kino-mcp` holds no secrets of its own -
it reads an export of the vault that contains only the hosts you exposed, under
a key derived from your master password. Starting it without that password gets
you a server that can do nothing.

**Still true:** it is a separate binary a client spawns, so it inherits that
client's environment. On Windows, guarded mode refuses rather than prompting -
there is no named-pipe equivalent of the approval socket yet, and refusing is
the safe side of that gap.

### 8. The transfers folder - files, not context

An SFTP tool refuses unless you have nominated a folder; there is no default.
Downloads land inside it, uploads come only from inside it, and the resolver
rejects absolute paths, `..`, and symlinks that point out. **File contents are
never returned to the model.** A transfer reports a name, a byte count and a
SHA-256, which is what a transfer needs and not what a prompt would carry away.
A failed transfer removes its own `.part` rather than leaving half a file for
something else to read.

**Still true:** the folder is yours and is plaintext. Anything that can read
your home directory can read what was transferred, and an assistant can still
choose *which* remote file to fetch into it - it just cannot read the result.

### 9. The release pipeline to your machine

Every asset is signed with a minisign key whose public half is in the
repository and in `tauri.conf.json`; a signed `SHA256SUMS` covers the whole
set; each asset is attested by GitHub Actions to the workflow and commit that
built it; and each release carries a CycloneDX SBOM of both dependency trees.
The in-app updater verifies the signature before installing and refuses rather
than offering to continue.

**Still true:** the signing key lives in GitHub Actions secrets, so an attacker
with repository admin and the key can sign something; attestation is what makes
that visible, by naming the workflow run. A first install is still trust on
first use of the publisher - the signature proves continuity, not identity.

## What we are not modelling

- **Agent mode, the relay and the controller.** Those live in separate
  repositories with their own trust boundaries, and nothing in this build
  depends on them. They are not covered here and should not be assumed secure
  by association.
- **Multi-user machines.** Kino assumes your user account is yours. Vault
  permissions are set, but a machine where another account can write your home
  directory is outside the model.
- **Hardware and operating system.** Cold boot, DMA, a malicious kernel, a
  keylogger in the firmware: all out of reach of an application.
- **Availability.** This is a credential manager, not a service. Denial of
  service against your own app is not a threat we spend design budget on.

## If you find a hole in this

[SECURITY.md](../SECURITY.md) has the two reporting routes and the response
targets. A report that one of the "still true" paragraphs above is *worse* than
stated is as welcome as a report of a bug - a mitigation that is weaker than
its documentation is the same defect as a missing one.
