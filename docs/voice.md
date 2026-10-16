# How Kino talks

Kino runs the booth. You decide what plays.

The projectionist works at the back, in the dark, while everyone watches
something else. They check the splice before the reel goes on, they know which
frame it broke at last Tuesday because they wrote it down, they never walk out
in front of the screen, and they can stop the show in a second.

That is the voice. It is already in the code; this page writes it down so a
pull request can be reviewed against something.

It applies to every string a person reads: buttons, hints, empty states,
errors, MCP tool descriptions and refusals, the changelog, release notes, the
website, and replies on issues.

## The five rules

**1. Say what happened, and what didn't.**

> `Could not keep a copy of the existing /etc/app.conf on 'web-01'. Nothing was uploaded.`

The second sentence is the one that matters at 3am. A message that says only
what failed leaves the reader wondering what got half done.

**2. Name the next move, and where.**

> `Host 'db-07' not found. Use list_hosts to see available hosts.`
> `'web-prod' is exposed read-only, so sftp_write is not available on it. Change its access mode in Kino - Settings - MCP Server.`

Not "permission denied". Which host, which rule, which screen.

**3. Admit the limit.**

> `Two devices writing in the same moment is the one case this cannot detect.`
> `Rules match the command as written - they catch mistakes, not someone determined to get around them.`

Where a mitigation is partial, the copy says so. This is the rule that earns
the rest: a tool that admits what it cannot do can be believed about what it
can.

**4. Don't report what you didn't check.**

A package manager that cannot separate security updates gets a blank, not a
zero. A host that was not reached stays in the list with its reason. "Unknown"
is a finding; a confident wrong number is not.

**5. The user decides.**

> `Apply opens a terminal with the command ready, rather than running it for you.`

Kino threads the reel. It does not start the show, does not tidy up after
itself unasked, and never quietly does the bigger version of what was asked.

## House style

- **Sentence case.** "Exposed hosts", not "Exposed Hosts".
- **No exclamation marks.** The app has three, all of them `Copied!`, and they
  could go. Nothing else earns one.
- **No emoji** in the interface. The website may use them in the way any
  website does; the app does not.
- **A spaced hyphen for an aside** - like this - rather than an em dash. It
  matches the rest of the codebase.
- **Second person, present tense.** "Kino keeps a copy" / "you can restore it".
- **Numbers that mean something.** "60 calls a minute" beats "rate limited".
- **Paths, hosts and commands verbatim.** Never elide the middle of a command a
  person is being asked to approve: the elided part is the one that matters.

## Words we don't use

| Not this | Because |
|---|---|
| "Oops", "Whoops", "Uh oh" | Something went wrong on a production host. It isn't funny. |
| "Successfully" | Say what happened. "Successfully" is usually written by code that didn't check. |
| "Simply", "just", "easy" | If it were easy the message wouldn't be needed. |
| "Please wait…" | Say what is being waited on: "Asking each host…" |
| "Invalid input" | Say which field, what was wrong, and what is accepted. |
| "Are you sure?" | Say what will happen. "Restart nginx on 12 hosts?" |

## Writing an error

Four things, in this order, and stop:

1. **What happened**, in the user's terms rather than the API's.
2. **What did not happen** — did anything change?
3. **What to do about it.**
4. **Where to do it**, if it is a setting.

Worked example, from the MCP server:

> `'web-prod' has already taken 60 calls this minute, which is its limit.
> Wait, or raise it in Kino - Settings - MCP Server.`

What happened, the number, the way out, the screen. No stack trace, no error
code the reader cannot search for, no apology.

## Naming things

- **Tools and settings say what they do**, not what they are made of:
  "Stop all MCP activity", not "Set halt flag".
- **Dangerous things are named plainly.** The mode is called `full`, the
  confirmation says "full, unrestricted access", and the panel makes you type
  the word `production` before an assistant may change one. A euphemism here
  is a lie.
- **Features are named after the question they answer.** "What did the
  assistant do?" is *MCP activity*. "What cryptography does this host
  actually use?" is *Transport audit*.

## When in doubt

Read it back as the projectionist, at 3am, to someone whose site is down.
If it would sound glib, or vague, or like it is covering something up, rewrite
it. If it would sound like a colleague who knows what they did and is telling
you plainly - it is right.
