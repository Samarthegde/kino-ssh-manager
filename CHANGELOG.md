# Changelog

All notable changes to Kino SSH Manager are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **An MCP server, so an AI assistant can work on hosts you choose.** A headless
  `kino-mcp` binary serves Model Context Protocol tools over stdio: list hosts,
  run a command, list a directory, read and write files, and run a saved
  snippet. Configure it under **Settings → Shortcuts & Tools → MCP Server**.

  The point of the design is what the assistant *cannot* see. It reads a
  separate file, `mcp_vault.enc`, holding only the hosts you tick and the
  snippets those hosts reference - encrypted under a **separate MCP password**,
  so the headless binary never needs, and never receives, your master password.
  Everything else in your vault is invisible to it. That file is rewritten
  whenever a host, a snippet or the exposure list changes, so a rotated key or a
  deleted host propagates immediately.

  Host-key verification still applies: the MCP server refuses any host whose key
  hasn't already been trusted in Kino, so it can't be steered onto an impostor.

  Every exposed host carries an **access mode**, and a newly ticked one is
  **read-only**: reads are fine, writes are refused outright, and a command runs
  only if a rule you wrote names it. **Guarded** makes everything reachable but
  requires approval for anything unnamed - and since the approval prompt isn't
  built yet, such a call is refused with a message saying so. **Full** is the
  unrestricted shell, and choosing it takes a second confirmation naming the
  host.

  Rules are `allow`, `deny` or `ask` plus a pattern (`*` for anything, `re:`
  for a regex), one per line, first match wins, a host's own before the global
  ones. They are matched against the command as written - which catches
  mistakes, not somebody determined to get around them. The read-only default
  is the part that actually holds, because it refuses what it wasn't told to
  permit, and no rule can talk it into writing.

  Enforcement lives in `kino-mcp` itself, not in the app that configures it:
  the policy travels inside `mcp_vault.enc` alongside the hosts, so the headless
  binary decides for itself and a refusal costs the host nothing - the check
  runs before any connection is opened. A refused call comes back as structured
  JSON naming the reason, the mode and the rule, without handing the assistant
  the rule list to pick at.

  `kino-mcp` is attached to each release as a separate download
  (`kino-mcp-linux-x86_64`, `kino-mcp-windows-x86_64.exe`) rather than bundled
  into the installers - it's a server you run, not an app you launch.

## [0.9.0] - 2026-09-01

### Added
- **Process tree and a full signal menu.** The process list can now be grouped
  into the tree it always described - `ps` was already reporting each process's
  parent, it just wasn't being used. Branches fold, a collapsed row says how many
  processes it's hiding, and filtering keeps the ancestors of a match so a hit
  never floats without the chain that spawned it. Processes whose parent didn't
  make the 500-row cut become roots rather than disappearing.

  **End** has become **Signal**, offering SIGTERM, SIGINT, SIGHUP, SIGSTOP,
  SIGCONT and SIGKILL by name and effect instead of just two buttons. A suspended
  process now shows its `T` state in the alert colour, since a frozen process is
  otherwise indistinguishable from an idle one and only SIGCONT brings it back.
- **Notes.** Encrypted free-text storage for the things that belong beside your
  hosts - recovery codes, licence keys, API tokens - under **Settings → Vault →
  Notes**. Stored in a sibling blob next to the vault under the same key and
  salt, and synced, pulled and re-keyed exactly like history and snippets.

  Deliberately not a field on a host: the vault is rewritten whole on every host
  edit, and a host is what profile export serialises to plaintext JSON, so
  anything secret living there would leave the machine the moment a profile was
  shared. Note bodies open blurred and reveal on click, so a stored recovery code
  isn't sitting on screen when somebody walks past.
- **Archaeology.** **Tools → Archaeology** reads `~/.bash_history` and
  `~/.zsh_history` for the account you connect as, and keeps what it finds in an
  encrypted archive of its own, per host. Filter it, copy any line back out. The
  point is that it accumulates: `HISTSIZE` trims the host's own file, and what
  was already archived survives that.

  It is a de-duplicated set, not a timeline, and it captures command lines
  verbatim - including anything secret typed on one. The archive is encrypted
  with your vault and is deliberately excluded from exported host profiles.
- **Kino runs in the tray.** Minimising sends it to the notification area rather
  than the taskbar, and closing the window leaves it running. The tray menu has
  **Show Kino** and **Quit Kino** - the menu is what makes the window
  recoverable, since on Linux the tray delivers menu activations and no click
  events at all.

  Worth knowing: the vault stays unlocked while the window is hidden. Idle
  auto-lock still applies, but closing the window no longer implies locking it.
- **Heartbeat alerts.** When a host that was up goes down, Kino raises a desktop
  notification. Give a host an **ntfy topic** in its settings and the same event
  is posted there, so a flatline at 3am reaches your phone. Requires health
  polling to be on.
- **Image export options** under **Settings → Appearance**. Three frames - the
  Kino caption rule and perforation rail, a plain window title bar, or minimal
  with the text tightly cropped - plus toggles for the host name and timestamp in
  the caption, and an optional accent wash so a dark capture doesn't float
  unanchored when pasted onto a light page.

### Fixed
- **Archaeology could restore a superseded SSH key.** The panel saved the merged
  command history back through `saveHost`, using the copy of the host captured
  when the tab was opened - so it rewrote every other field from that snapshot
  too. Rotate a key, then sync a tab opened beforehand, and the old private key
  went back into the vault while the host had already stopped accepting it. The
  archive is now its own store, keyed by host id, and the panel never writes a
  host at all.
- **Shell history is no longer part of an exported host profile.** It lived on
  `Host`, and `export_host` serialises `Host` to plaintext JSON - so sharing a
  profile handed over every command captured from that machine, which is exactly
  where passwords typed on a command line and tokens in `curl` calls end up. It
  now lives in `shell-history.enc`, a sibling blob beside the vault under the
  same key and salt, synced and re-keyed like history and snippets, and removed
  when its host is deleted.
- **A re-sync no longer replaces the archive with a smaller one.** Merging ran
  against whatever list the UI happened to be holding, which was the stale
  snapshot above - usually empty. It now merges against what's on disk, so the
  history that `HISTSIZE` has already trimmed off the host survives, which is the
  point of keeping an archive.
- **Captured commands are no longer rewritten.** The pipeline trimmed lines with
  `awk '{$1=$1};1'`, which rejoins fields on single spaces: `grep "foo    bar"`
  came back as `grep "foo bar"` and `-e "A=1     B=2"` as `-e "A=1 B=2"`. Copying
  one out gave you a command that did something different from the one that ran.
  Trimming is anchored to the ends now, and the list is displayed with the
  spacing intact rather than collapsed by HTML.
- **Desktop notifications could never fire.** The heartbeat notification code was
  written, the plugin installed and registered, but `notification:default` was
  missing from the app's capabilities and Tauri 2 denies any plugin command not
  listed there.
- **The shell-history fetch is bounded.** It returned the whole file - a
  long-lived box can hold a six-figure history, every line of which crossed IPC
  and became a table row. Capped at 5,000 unique commands per host.

## [0.8.0] - 2026-08-13

### Added
- **Release notes on first launch after an upgrade.** Upgrading used to be
  silent: the app you opened was simply different from the one you closed. The
  unlock screen now shows what changed, once, and never again for that version.
  A fresh install doesn't see it - nothing is "new" to someone who has never run
  an older build.
- **Copy a selection as an image.** Select terminal output and the tooltip now
  offers **Image** alongside Copy: a PNG of exactly what was on screen, colours
  and all, ready to paste into Slack or an issue.

  It is not a screenshot and not a picture of plain text. `getSelection()` hands
  back characters with every attribute stripped, so this walks the buffer cells
  instead and keeps what was actually rendered - 16-colour and 256-colour
  palettes, 24-bit colour, bold, dim, italic, underline, strikethrough and
  inverse - resolved against the theme and font you're using. Trailing blank
  space is trimmed, so the image is as wide as the output rather than as wide as
  the terminal. Each capture is captioned with the host and the local time.

  Where the clipboard refuses images - WebKitGTK on Linux, mainly - Kino opens a
  save dialog instead of failing, since the picture is already made by then.

- **A key audit, and one-click rotation.** Kino has always stored keys without
  ever having an opinion about them. **Settings → Vault → Key audit** now reads
  every key in the vault and reports what it finds: undersized RSA and DSA keys,
  keys shared across several hosts, keys over a year old, hosts still on a
  password, and keys that no longer parse at all. It runs entirely on this
  machine - no host is contacted to produce the report.

  **Rotate key** generates a fresh ed25519 pair, installs it, and only then
  retires the old one. The order is the point: the new key is proved by opening a
  second connection that can *only* authenticate with it, and the old key is
  removed after that succeeds - never before. Any failure earlier in the sequence
  leaves the host exactly as it was, and the removal step refuses to rewrite
  `authorized_keys` at all unless the new key is present in the result. Other
  operators' keys, comments and `command=` options in that file are left alone.

  Two limits worth stating. Keys carry no creation date of their own, so the age
  of a key that predates this release reads as "unknown" rather than a guess;
  rotating starts the clock. And hosts that authenticate through your ssh-agent
  have no key in the vault to rotate, so they're listed but the button is off.

- **A cron editor.** `crontab -e` drops you into vi with a comment block for a
  manual page, and a mistyped field is a job that silently never runs. **Tools →
  Cron jobs** reads the crontab on the connected host (or the local machine),
  and shows each job with its schedule written out - "At 04:00 every day",
  "Every 15 minutes", "At 05:00 on Monday" - and the next three times it will
  actually fire, in the host's clock rather than yours. Jobs can be added,
  edited, paused (commented out, the way people do it by hand) and removed.
  Editing a schedule shows what it means as you type.

  The panel never regenerates a crontab; it rewrites individual lines of the one
  that is there. Comments, `PATH=` and `MAILTO=`, blank lines, unusual spacing
  and anything it doesn't recognise survive a save byte for byte, and the **Raw**
  tab edits the file directly when that's what you want. Saving is a
  compare-and-swap: if the crontab changed on the host since the panel loaded
  it, the write is refused rather than quietly overwriting a `crontab -e` you
  left open in another window.

  Cron's day-of-month/day-of-week rule is honoured, including the one that
  catches everybody - when both fields are set, the job runs if **either**
  matches, and the description says so out loud.

## [0.7.1] - 2026-08-06

### Added
- **The new menus were unreadable on light themes.** The Tools menu, the
  sidebar's New menu and the themed select were added after the light-theme
  corrections were written, so they never joined them: their offset shadow is
  mixed from the page background, which on a light theme is white and therefore
  invisible, and their panels were slightly translucent. The result was a
  near-white panel on a near-white page with no edge and no shadow - a washed
  out ghost with the list behind showing through. They are opaque now, carry a
  visible shadow on light themes, and their second lines were lifted out of the
  grey they were disappearing into.
- **Dropdowns follow the theme.** A native `<select>` can be styled shut but
  not open: on Linux the popup list is drawn by GTK, which ignores the page's
  stylesheet entirely - so picking a theme or a font opened a list in the
  system's colours and system font in the middle of a dark, custom-typeset app.
  The selects in **Settings** are now the app's own, using the same ink and type
  as everything else, scrollable and keyboard-navigable. Being ours, they can
  also **draw each font option in the face it names**, which is what makes a
  font picker a picker rather than a list of words.
- **A New menu in the sidebar.** Add host, local shell, import profile and
  import SSH config were four buttons wrapping onto two rows in a narrow
  sidebar, three of them reading "Import"-something and hard to tell apart.
  They are now one **New** button, and each option gets a line saying what it
  does ("A shared .sshm file", "Hosts from ~/.ssh/config"). Adding a host is one
  click deeper than before; it remains a single step from the command palette.
- **A Tools menu.** Files, Docker, Metrics, Copilot, Processes and session
  recording now sit behind one **Tools** button in the tab bar instead of six
  separate ones. Those buttons appeared and disappeared depending on the
  session, so the strip's width shifted as you moved between tabs; one menu
  holds it steady and leaves room for real labels. A tool that can't run in the
  current session stays listed but disabled with the reason beside it - Files
  reads "SSH sessions only" on a local shell - rather than silently not being
  there. Recording shows a mark on the Tools button itself, since that state
  outlives the menu being open. Tunnels keeps its own button, because it opens
  a panel rather than a window.
- **Reduced motion & effects** - one switch under **Settings - Appearance** that
  makes the interface still and cheap to draw. It stops every animation,
  including the fifteen that otherwise never end (the perforation rail, the
  carrier pulse on each live status pip, the travelling tunnel pulses, the
  copilot caret, the SFTP progress shimmer), and drops the two expensive paints:
  the film grain, which is a full-viewport layer with a blend mode, and the page
  atmosphere, three stacked gradients pinned with `background-attachment: fixed`.
  Both make the compositor redo work on every repaint, which is felt hardest on
  Linux where WebKitGTK's compositing is weakest. The design's *form* is
  untouched - type, hairlines, slabs and the letterpress offsets all still
  paint, because a hard-edged shadow is free to draw. Worth turning on if the
  interface feels sluggish. Separate from the system "reduce motion" setting,
  which already stops the animations on its own.
- **Output highlighting** - timestamps, severity words, IP addresses, URLs and
  file paths are coloured in terminal output, in the spirit of MobaXterm's.
  Colours come from the active theme's own palette. It is on by default and can
  be turned off under **Settings - Terminal**. Three deliberate limits keep it
  from ever getting in the way:
  - It never touches the alternate screen, so vim, htop, less and every other
    full-screen program are left exactly as they paint themselves.
  - It never repaints a line the host has already coloured; the program wins.
  - It stands aside on large bursts. The pass runs at roughly 5 MB/s, so
    letting it run unconditionally would have re-created the bottleneck 0.7.x
    removed. Highlighting is a reading aid, and above about 650 KB/s nobody is
    reading - so past that it simply passes output straight through.
  Severity words are matched uppercase-only, so the word "error" in an ordinary
  sentence is left alone.
- **Port forwards are drawn, not described** - the Tunnels panel now shows each
  forward as a three-station patch diagram: which machine opens the port, that
  it runs through the SSH tunnel, and where it comes out. Previously it read
  `localhost:5432 - db.internal:5432`, and that dash quietly meant opposite
  things for a local and a remote forward - which end listens is the classic
  port-forwarding mistake. Local forwards now say the destination is resolved
  **server-side**, remote forwards read right-to-left from the host back to this
  machine, and SOCKS shows its destination as whatever each connection asks for.
  A live tunnel colours its stations and sends a pulse along the wire.
- **Find in terminal, finished** - the search bar now reports **how many
  matches there are and which one you're on** ("3/47"), highlights every match
  rather than only the current one, and marks each one on the scrollbar so you
  can see where they sit in the scrollback. Case-sensitive, whole-word and
  regular-expression toggles sit alongside. The addon supported all of this
  already; none of it was switched on. Paired with configurable scrollback,
  searching 200,000 lines is now something you can actually do.
- **Filter the vault history** - history only ever grows, and had no way in.
  The filter matches both the message and the event type, so "vault" or
  "deleted" each narrow it usefully.
- **Configurable scrollback** - how much terminal history to keep is now a
  setting (**Settings - Terminal**), from 1,000 lines up to 200,000, instead of
  being fixed at 5,000. It applies to terminals that are already open, so there
  is no need to reconnect a live session to change it.
- **Terminal font and background** - pick from six bundled monospace faces
  (JetBrains Mono, Fira Code, IBM Plex Mono, Source Code Pro, Inconsolata,
  Ubuntu Mono) and optionally override the terminal background colour, under
  **Settings - Terminal**. A live preview shows the choice against the active
  theme's real terminal colours. Every face ships with the app and is loaded
  from disk, so terminals render identically on every machine and with no
  network. Changes apply to open terminals immediately.
- **Interface font** - choose the face the app itself is set in, under
  **Settings - Appearance**: Chivo (the default), IBM Plex Sans, Atkinson
  Hyperlegible, or your system font. Atkinson Hyperlegible is drawn by the
  Braille Institute to maximise the distinction between easily-confused
  characters, which is the point of offering the choice at all. The display face
  used for the wordmark and slab headings is deliberately fixed - it is the Kino
  Projection identity rather than a preference.
- **Clear scrollback** - discard a terminal's history from the toolbar, the
  command palette, or **Ctrl+Shift+K** (rebindable under Shortcuts). It clears
  the visible scrollback, the buffer used to repaint a terminal after a pane
  move, and the "Save log" capture - so what you cleared doesn't reappear later
  in a saved log.

### Fixed
- **Scrolling up showed command history instead of earlier output.** Making
  scrollback configurable introduced a defaulting bug: `Number(null)` is `0`
  rather than `NaN`, so an install that had never opened the setting read its
  stored value as zero and ran with **no scrollback at all**. With no scrollback
  xterm reports `hasScrollback === false` and converts wheel events into cursor
  keys instead of scrolling, which the shell answers with its command history.
  An unset value now falls back to the 5,000-line default, and zero can no
  longer be stored.
- **Overlays no longer render behind the terminal.** The Tunnels dropdown, the
  toast and the command palette were all being painted underneath it. The film
  grain introduced in 0.7.0 sits above the app chrome, and the terminal was
  lifted above the grain to keep its text clean - which also lifted it above
  almost every overlay in the app. There is now one documented layer scale
  (chrome, grain, picture, popover, modal) and everything that must appear over
  the terminal sits above it. The Docker log viewer was also sitting *below* the
  Docker window it opens from, and is fixed by the same scale.
- **Four dialogs were referencing CSS variables that don't exist.** The vault
  history, cloud sync, snippets and change-password dialogs styled themselves
  with `--color-surface`, `--color-border`, `--color-text-dim` and similar - none
  of which are defined anywhere in the app. Every one of those declarations was
  invalid and silently did nothing, so those dialogs had drifted out of the
  design language entirely. They now use the real names. The history dialog's
  event tags were also hardcoded to Catppuccin colours and ignored the active
  theme; they follow it now.
- **The host export menu no longer vanishes when you reach for it.** The row's
  action buttons are revealed on hover, and the export menu hangs below the row,
  so moving the pointer down into the menu left the row and faded the menu out
  mid-click. Because a fully transparent element still accepts clicks, the menu
  was invisible but live. The actions now stay put while the pointer is over the
  row, while focus is inside it, or while the menu is open. The delete button's
  "click again to confirm" state was disappearing the same way and is fixed with
  it.
- **The primary button no longer collides with scrollbars.** Its letterpress
  shadow is painted outside the button's box and, like every box-shadow, takes
  part in no layout - so a panel's padding never held room for it, and flush
  against the right edge of a scrolling area it ran into the scrollbar. The
  button now reserves the space its shadow actually occupies.

- **The export menu is no longer clipped by the host list.** It was positioned
  inside the sidebar's scrolling list, which cuts off anything that overflows it,
  so for any host low in the list the menu was sliced down to its heading. It is
  now positioned against the window instead, and flips above the button when
  there isn't room below.

### Changed
- **Terminal throughput** - heavy output (a build log, `cat` on a large file, a
  chatty tail) no longer stalls the terminal. Two independent bottlenecks were
  removed:
  - The two rolling buffers behind "Save log" and pane-to-pane replay were
    rebuilt with `(buf + text).slice(-cap)` on **every** packet, re-copying up
    to 6 MB once they reached their caps. They are now chunked rings, so an
    append costs time proportional to that packet rather than to everything
    already buffered. Measured in JavaScriptCore - the engine the Linux build
    runs on - 4.1 MB of output went from ~3,200 ms to ~2 ms on this path, and a
    hard ~1.3 MB/s ceiling disappeared with it.
  - Output is now **coalesced** before crossing into the webview. Each `emit`
    costs a JSON serialisation plus a JavaScript `eval` in the webview - on
    Linux, a cross-process hop into WebKitGTK - and the SSH read loop was paying
    that per packet. Bytes arriving inside a ~12 ms window are batched into one
    event, which is 14-62x fewer round-trips on a fast stream. The first packet
    after an idle period is still sent immediately, so keystroke echo is exactly
    as responsive as before; batches are capped at 256 KB, and anything still
    buffered is flushed before a session reports itself closed. Applies to both
    SSH sessions and local shells. Session recordings are unaffected - output is
    still recorded as it arrives, so asciicast timing keeps the host's original
    pacing.
- **Renderer is no longer a mystery** - the terminal now reports whether it got
  the GPU (`webgl`) or the software fallback (`dom`) when a session opens. It
  prints to the app's own log, and **About** shows it too, so the question is
  answerable in a release build where there is no web inspector. On Linux,
  WebKitGTK frequently has no usable GL context and silently drops to the much
  slower DOM renderer; a context lost mid-session is reported as well.

## [0.7.0] - 2026-07-31

### Added
- **Kino Cloud** - managed relays, so agent mode no longer needs you to run your
  own infrastructure. Paste an account key once under **Settings - Agent &
  Cloud**; the host editor's agent mode then becomes a machine picker. Add a
  machine, run the one-line install command it prints on the target, and
  connect. The vault stores only the agent id - the relay address and a
  short-lived connection token are fetched from kino-control at connect time, so
  nothing goes stale and tokens rotate on their own. The account key is
  encrypted under the vault key like every other secret, and the decrypted copy
  is dropped when the vault locks.
- **Relay discovery for self-hosted setups** - a host can point at a
  **kino-control URL** instead of a fixed relay, and the manager asks it where
  the agent is currently parked. The saved Relay URL becomes a fallback, so a
  control-plane outage degrades to "reuse where it was" instead of locking you
  out. The manual relay fields now live under **Advanced: self-hosted relay**
  once Kino Cloud is configured.
- **Relay tokens** - agent-mode hosts can carry a bearer token for relays that
  require auth (a relay's static token, or a kino-control manager token). It is
  sent as an `Authorization` header rather than a query parameter, so it stays
  out of relay and proxy access logs.

### Changed
- **New look: "Kino Projection"** - the app now shares one film-poster design
  language with the Kino Cloud web UI. A new default theme of the same name (two
  inks on bitumen black), a wordmark masthead with a printed colour bar and a
  35mm perforation rail, and a rebuilt unlock screen. Big Shoulders, Chivo, and
  JetBrains Mono ship with the app and are loaded locally - no webfont requests
  at runtime. Existing theme choices are untouched; Kino Projection only applies
  to installs that never picked a theme.
- **Settings is now sectioned** - General, Agent & Cloud, Copilot, Vault, and
  Tools, instead of one long scroll.

### Compatibility
- The new `relay_token` and `control_url` host fields are additive; existing
  vaults load unchanged and hosts with a plain relay URL keep connecting exactly
  as before.

### License
- **Relicensed from MIT to GNU GPL-3.0.** Contributions are accepted under
  GPL-3.0 with a relicensing grant to the maintainer, which keeps dual licensing
  possible - see [CONTRIBUTING.md](CONTRIBUTING.md).

## [0.6.1] - 2026-07-23

### Added
- **Jump host / bastion (ProxyJump)** - route a connection through another saved
  host, like `ssh -J`. Pick a bastion in the host editor's Advanced step; kino
  opens an SSH session to it and tunnels to the target over a direct-tcpip
  channel. Each hop's host key is verified independently, and bastions can
  themselves have a jump host, forming a chain. Works with any auth method the
  bastion uses (including agent-mode relays).
- **In-app updates** - when a new release is available, About now offers
  **Install update**: the signed package is downloaded in place with a progress
  bar and applied, then the app offers to relaunch. Updates are cryptographically
  verified against the bundled public key; if no signed package is available the
  UI falls back to the release page. Linux in-app updates apply to the AppImage
  build; `.deb`/`.rpm` installs continue to update through the system package
  manager or the release page.
- **Host health indicators** - an opt-in background probe TCP-connects to each
  host's SSH port and shows a green/red dot plus round-trip latency in the
  sidebar. Configurable under **Settings - Host health checks** (Off by default;
  30s / 1 min / 5 min). Hosts reached through a relay or a jump host report
  "unknown" rather than a misleading "down", since probing them would mean
  standing up a full session each cycle.
- **Copy / paste toasts** - copying or pasting in a terminal now confirms what
  happened ("Copied 3 lines"), including clipboard writes the remote host makes
  via OSC 52, which were previously invisible.

## [0.6.0] - 2026-07-22

### Added
- **AI copilot** - an opt-in, bring-your-own-key assistant embedded in the
  terminal, powered by [OpenRouter](https://openrouter.ai) (one key reaches
  every major model). Ask about the host you're on, paste an error, or have it
  explain recent output; suggested shell commands come as one-click "Run"
  blocks. The key is encrypted in the vault like every other secret and only
  ever leaves the machine to call OpenRouter. **Off by default** - enable it
  under **Settings - AI Copilot**.
- **Select text - Copy / Explain by AI** - selecting text in any terminal now
  shows a small tooltip to copy it, or send it straight to the copilot for an
  explanation.
- **Customizable keyboard shortcuts** - rebind the command palette, broadcast
  toggle, terminal find, copy, paste, and font-size shortcuts under **Settings -
  Keyboard Shortcuts**, with live conflict detection and per-action reset.
- **Session restore on unlock** - optionally remember the open tabs and pane
  layout (including pane names) and rebuild them the next time you unlock,
  reconnecting each host into its original pane. Opt-in under Settings.
- **Home favorites** - pin hosts to the empty-pane landing view for one-click
  connect. Star a host in the sidebar or use its right-click menu.
- **Rename panes** - give split panes their own names; the names also appear in
  the tab "Move to pane" menu.
- **Terminal copy & paste shortcuts** - `Ctrl+Shift+C` copies the selection and
  `Ctrl+Shift+V` pastes, alongside the existing right-click and OSC 52 paths.
- **Eight more themes** - Solarized Dark/Light, One Dark, Monokai Pro, Rosé
  Pine, Everforest Dark, Ayu Mirage, and GitHub Light (14 total). The Settings
  theme picker is now a single grouped dropdown.
- **Update available on the login screen** - the release check now runs at
  launch and surfaces a badge on the unlock screen, not just after unlocking.
- **Choose an existing group** - the host editor's Folder / Group field offers a
  dropdown of groups already in use, preventing near-duplicates.

### Changed
- The AI copilot is now OpenRouter-only. The previous Claude (Anthropic) and
  Gemini (Google) providers - including the Anthropic sign-in flow - have been
  removed in favor of a single provider that fronts every model.

## [0.5.0] - 2026-07-14

### Added
- **Agent connection mode** - reach hosts that expose **no inbound SSH port** -
  behind NAT, CGNAT, or a firewall - through a relay, instead of connecting to a
  hostname directly:
  - The host editor gains a **Kino Agent** connection mode. Instead of a hostname
    and port, you provide a **relay URL** (`wss://...`) and an **agent id**.
  - A companion [kino-agent](https://github.com/Samarthegde/kino-agent) runs on
    the target machine and dials *out* to a [kino-relay](https://github.com/Samarthegde/kino-relay);
    the manager reaches it through that relay. The host editor shows the exact
    command to run on the target.
  - The SSH session stays end-to-end encrypted - the relay only forwards bytes
    and never sees your credentials.
  - **Off by default.** Enable it under **Settings - Kino Agent**; when off, all
    agent/relay UI is hidden. It auto-enables if your vault already contains
    agent hosts, so existing configuration is never hidden.
  - A default relay URL can be set in Settings and is pre-filled for new hosts.
- **Password-encrypted profile export** - exporting a host profile now offers a
  password-encrypted `.sshm` file (Argon2 + AES-256-GCM), protected by a
  standalone password you share out-of-band, with a built-in password generator.
  Importing an encrypted profile prompts for the password. Plain (unencrypted)
  export is still available and clearly marked.

### Changed
- **Host editor redesigned as a stepper** - the long Add/Edit Host form is now
  organized into steps (**Connection & Auth**, **Port Forwards**, **Advanced**)
  that double as clickable tabs, so you can jump straight to a field when editing
  without scrolling. Save is available on every step.

### Fixed
- **`wss://` relay URLs now work.** TLS is compiled into the WebSocket client
  (rustls), fixing a `TLS support not compiled in` failure when connecting to a
  `wss://` relay.
- **Host-key verification for agent hosts.** Agent hosts have no hostname, so they
  were all keyed as `:22` in the known-hosts store - trusting one overwrote
  another and later raised a false "possible man-in-the-middle" mismatch. They are
  now keyed by agent id, so each agent's SSH fingerprint is tracked independently.
- **Agent hosts no longer display as `user@:22`** in the sidebar, connect dialog,
  and host-key prompt; they show `user@agent <id>` instead, and are searchable by
  agent id.

## [0.4.3] - 2026-06-30

### Added
- **Session recording & replay** - capture any SSH or local-shell session to an
  [asciicast](https://docs.asciinema.org/) (`.cast`) file:
  - A **Record / Stop** toggle in the terminal toolbar starts and stops capture
    for the active session, with a live "recording" indicator.
  - Recordings are saved to `~/Videos/Kino Recordings`.
  - A **Recordings** manager (Settings - Recordings) lists every recording with
    its date and size, and plays them back in an embedded asciinema player or
    deletes them.
- **Remote file editor** - open a text file from the SFTP browser to edit it in
  a built-in Monaco (VS Code) editor and save it straight back over SFTP, with
  no download/re-upload round trip. Syntax highlighting is picked from the file
  extension and the editor follows the app's active theme.

## [0.4.2] - 2026-06-29

### Changed
- **Full-screen Docker panel** - the Docker management modal now opens maximized,
  so the containers / images / volumes / networks lists use the full window
  height instead of a fixed-height box.
- **Full-screen log viewer** - clicking a container's logs now opens a dedicated
  full-screen modal with larger, more readable text, layered above the Docker
  panel, instead of the small panel that was docked at the bottom. Live
  streaming, auto-scroll, and copy-to-clipboard are unchanged. Closing it (✕ or
  click-away) stops the stream and returns to the Docker panel.

### Removed
- Dropped the unused `resolve_public_key` helper left over from the `ssh2`
  backend; `russh` derives the public key itself during key-based auth.

## [0.4.1] - 2026-06-10

### Added
- **Copy Docker logs** - a one-click button in the container log viewer copies
  the current log buffer to the clipboard.

## [0.4.0] - 2026-06-10

### Added
- **Docker management** - a per-session panel to manage Docker over the existing
  SSH connection (or the local daemon from a local-shell tab):
  - Containers: start / stop / restart / pause / remove, with live status.
  - **Shell access** - drop into an interactive shell inside any running
    container (`docker exec`, prefers `bash`, falls back to `sh`) as a new
    terminal tab.
  - **Live log streaming** - follow a container's logs in real time.
  - **Images / Volumes / Networks** tabs for browsing the daemon.
- **Live system metrics** - a streaming dashboard (CPU, memory, disk, load
  average, uptime, network throughput) sampled once a second, for remote hosts
  and the local machine.
- **Remote (reverse) port forwarding** (`ssh -R`) and a **dynamic SOCKS5 proxy**
  (`ssh -D`), alongside the existing local forwards. Pick the tunnel type per
  rule in the host editor.
- **Operating-system tags** - choose a host's OS in the editor; the sidebar
  shows a matching OS icon (Linux, Ubuntu, Debian, Fedora, Arch, Alpine,
  Windows, macOS) tinted with the host color.
- **Collapsible, resizable sidebar** - hide it from the header toggle or drag
  its edge to resize; the width and collapsed state persist.

### Changed
- **Async networking backend** - the SSH/SFTP/forwarding stack was rewritten
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
- **Folders / Groups** - dynamically organize hosts in the sidebar using tag-based groups.
- **Quick Connect Bar** - instantly connect to any transient host directly from the sidebar by typing `user@host:port` without cluttering the vault.
- **Local Shell Tabs** - open a local PowerShell (Windows) or Bash/Zsh (Unix) terminal right inside the app, alongside your remote SSH tabs.

### Fixed
- **Windows SSH authentication (Error 19)** - libssh2 could fail to parse keys with `\r\n` line endings on Windows. Private and public keys are now normalized to use `\n` line endings internally before being sent to the authentication backend.

### Compatibility
- The `group` field for Folders is fully backward compatible; existing vaults will load seamlessly without it.

## [0.2.0] - 2026-06-04

### Added
- **Per-host notes** - store free-form notes on any connection. Notes are
  searchable from the sidebar and shown via a note indicator and row tooltip.
- **Master password confirmation** on first-time vault creation, with a
  "no recovery if you forget this" reminder.
- **Show/hide password toggle** on the unlock screen.
- **Resizable host editor** - drag the bottom-right corner of the Add/Edit Host
  dialog.
- **Windows installers** (`.msi` / `.exe`) are now built and published alongside
  the Linux packages.

### Changed
- Refreshed UI: softer shapes, focus rings, button depth, animated modals, and a
  glassier unlock screen.
- Modals no longer close when clicking outside - only via the ✕ or Cancel/Done
  buttons, to prevent accidental dismissal.

### Fixed
- The auto-lock dropdown now follows the selected theme instead of using the OS
  default colors.
- **SSH key authentication on Windows** - ed25519/OpenSSH keys failed to
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
