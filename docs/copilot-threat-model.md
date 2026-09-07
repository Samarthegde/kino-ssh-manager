# The copilot's threat model

The AI copilot reads terminal output and proposes shell commands. Terminal
output is written by the machine you are connected to, and if that machine is
compromised, an attacker writes it. This document says what that means, what
Kino does about it, and - the part most documents skip - what it still cannot
protect you from.

The copilot is **off by default** and needs an [OpenRouter](https://openrouter.ai)
key you supply. If it is not configured, none of this applies to you.

---

## What crosses which boundary

```
  the host                 your machine                      a third party
 ───────────              ──────────────                   ────────────────

  sshd ──► terminal ──► scrollback buffer
                              │
                        CopilotPanel.tsx
                        builds the prompt
                              │
                        ┌─────▼─────┐
                        │   scrub   │  ai.rs - redaction, in Rust
                        └─────┬─────┘
                              │  HTTPS
                              └──────────────────────►  OpenRouter ──► a model
                                                              │
                        ┌─────────────────────────────────────┘
                        │  the reply, rendered as prose + code blocks
                        ▼
                   Insert  │  Run… ──► confirmation ──► your session ──► sshd
                 (no send) │
```

Three things are worth reading off that picture:

- **Host output reaches a model.** Not by accident - it is the feature - but it
  means text an attacker controls reaches a system that generates commands.
- **The redaction step is on your machine, in Rust**, not in the panel and not
  at the provider. See [Redaction](#redaction).
- **Nothing crosses back into your session without you.** The arrow from the
  reply to `sshd` passes through a confirmation dialog every time.

## What an attacker wants

Not your terminal output. Your **shell access to the host**, and the access to
every other host that a person with your shell can reach. The copilot is
interesting to an attacker only as a way to get a command executed that you
would not have typed.

Your SSH credentials are not part of this picture: they are never placed in a
prompt. The copilot has no vault access at all - `CopilotPanel` pulls exactly
four functions from the store (`aiGetConfig`, `aiSend`, `aiPreview`,
`aiCancel`) and cannot enumerate hosts, read keys, or reach a host other than
the session it is open in.

## The adversaries

| | Controls | Wants |
|---|---|---|
| **A compromised host** | every byte of output: MOTD, logs, filenames, command results | a command run as you, on it or elsewhere |
| **A hostile `.sshm` profile** | the host record: name, username, notes | the same, before you have connected to anything |
| **The provider or model** | the reply | out of scope for injection, in scope for confidentiality |
| **A network observer** | nothing (TLS) | the prompt contents |

---

## The injection surface, enumerated

Five ways text you did not write reaches the model. Each was a real gap; each
is listed with what closed it.

### 1. Attached terminal output

The *Attach terminal output* tick sends the last 6 000 characters of
scrollback. This was always fenced in `<terminal_output>` tags - but nothing
told the model what the tags **meant**, so the fence was decoration.

*Now:* the system prompt states that anything inside the tags is data captured
from a machine, never an instruction, and asks the copilot to say so out loud
if it finds something in there addressed to it.

### 2. A terminal selection

Selecting output and choosing "explain this" was the weaker path by far: the
selection went into a **user** message, raw - no sanitising, no fence -
indistinguishable from something you had typed.

*Now:* the same fence, through the same helper. There is one way in.

### 3. Host notes

`host.notes` was interpolated into the **system** message as
`Notes about this host: …`. Notes travel inside imported `.sshm` profiles, so
they are not necessarily words you wrote, and the system message is the
strongest position an injected line could ask for.

*Now:* fenced like any other untrusted text.

### 4. Host name, username, hostname

Also profile-carried, also in the system message, and still there - a name is a
name, and stating it plainly is what makes the context useful. They now go
through the same sweep, so a host name carrying a fence tag or a control
character cannot forge a boundary.

### 5. The model's reply

The reply is rendered into prose and fenced code blocks, and a code block used
to carry a single **Run** button wired to paste the text *and press Enter*. The
whole distance between "a model proposed this" and "the server ran it" was one
click, on a suggestion shaped by whatever the host had printed.

*Now:* **Insert** (the default) puts the command on the command line and stops.
**Run…** opens a confirmation showing the command verbatim with the target host
named, Cancel focused.

---

## Sanitising

Every path carrying host text goes through one function, `sanitizeHostText`:

- ANSI CSI and OSC escapes are removed, so the model reads text and not control
  codes;
- the remaining C0 control characters and DEL are removed, `\n` and `\t`
  excepted, so nothing invisible survives;
- a literal `</terminal_output>` **printed by the host** is defanged, so output
  cannot close the fence early and continue as though it were you speaking.

That last one is the forgery that actually matters, and it is the reason the
sweep exists at all rather than just the system-prompt wording.

## Redaction

Attaching output is one tick, and what was on screen a minute ago is easy to
forget: a key you `cat`ed, an `export AWS_SECRET_ACCESS_KEY=`, a `curl -H
"Authorization: Bearer …"`. OpenRouter is a third party.

`redact.rs` sweeps the whole prompt for private key blocks (including one the
6 000-character tail cut off mid-key, which is the common case), AWS access
keys, bearer tokens, JWTs, and `NAME=value` assignments whose name looks like a
credential. An assignment keeps its name - `DB_PASSWORD=` stays legible, only
the value goes.

It runs **at the command boundary in Rust**, not in the panel that happens to
build the prompt today: a redaction the frontend performs is one a future
caller forgets. The only way past it is an explicit per-send override, and the
panel tells you afterwards what was held back.

## Showing you the bytes

"Trust us, we redacted it" is not good enough when the answer is knowable.
**Inspect**, beside the composer, shows the exact text a send would transmit,
produced by the same `scrub` the request itself runs through - so the preview
cannot drift from the reality. The byte count is on screen without opening
anything.

---

## Residual risk

Every item above raises the cost of an attack. None of them makes one
impossible, and it would be dishonest to imply otherwise.

**A convinced user is still the weakest link.** A sufficiently persuasive
injected instruction can cause the model to propose a plausible-looking command
that you then read, believe, and approve. The confirmation dialog is a speed
bump against habit, not a proof against persuasion. If the copilot suggests
something you did not expect, that is the signal - not the dialog.

**The prose can lie about the command.** The model writes both the explanation
and the code block, and an injection influences both. Read the command, not the
description of it.

**Insert is not free.** It puts text on your command line. If you then press
Enter without reading, you have run it. Insert is the safer default because it
gives you a moment, not because it is inert.

**Redaction is pattern matching.** A secret that does not look like one goes
straight through. It lowers the cost of forgetting what was on screen; it is
not a guarantee, and it is not a reason to attach output you know is sensitive.

**Fencing is a convention, not a mechanism.** The model is *asked* to treat
fenced text as data. Nothing enforces it. A model that ignores the instruction
ignores it, and models differ.

**The provider sees the prompt.** You chose them and you hold the key, but
everything that survives redaction reaches OpenRouter and whichever model it
routes to. Use **Inspect** if you want to know exactly what that is.

**A compromised host does not need the copilot.** It already has your session.
The copilot matters because it can extend that reach to a *second* host, or to
a command you would have refused - not because it is the first foothold.

## What Kino will not do

- **Auto-execute.** No model output reaches a session without a click on a
  dialog that shows the command verbatim.
- **Give the copilot tools.** It has no agentic loop, no tool calls, no ability
  to act on its own. It writes text; a person acts.
- **Touch the vault.** No credentials in prompts, no host enumeration, no
  access to a session other than the one it is open in.

If you need an assistant that *can* act on hosts, that is `kino-mcp`, a
separate binary with its own password and its own exposure list - and its own
threat model, which is not this one.

## Reporting

Found a way around any of this? Please use GitHub's private vulnerability
reporting rather than a public issue - see [SECURITY.md](../SECURITY.md).

## Where to look

| Concern | File |
|---|---|
| Prompt assembly, fencing, the two buttons | `src/components/CopilotPanel.tsx` |
| Redaction patterns and their tests | `src-tauri/src/redact.rs` |
| `scrub`, `ai_send`, `ai_preview` | `src-tauri/src/ai.rs` |
| What a paste actually does | `src/terminalRegistry.ts` |
