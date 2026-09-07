/**
 * What's new, shown once on the unlock screen after an upgrade.
 *
 * Adding a release means adding an entry here; a version with no entry shows
 * nothing at all, which is the right behaviour for a patch release that has
 * nothing worth interrupting anyone for.
 */

export interface ReleaseNote {
  version: string;
  /** One line under the version stamp. */
  headline: string;
  items: { title: string; detail: string }[];
}

export const RELEASE_NOTES: ReleaseNote[] = [
  {
    version: "0.9.1",
    headline: "An assistant can reach your hosts now - on a short leash, and only the ones you pick.",
    items: [
      {
        title: "MCP server",
        detail:
          "Settings → Shortcuts & Tools → MCP Server exposes chosen hosts to an AI assistant " +
          "over the Model Context Protocol. A newly ticked host is read-only: it can read " +
          "files and listings, and runs a command only if a rule you wrote names it. The " +
          "assistant never sees the rest of your vault, and never gets your master password.",
      },
      {
        title: "Production guard",
        detail:
          "Mark a host production and its terminal gets a frame and a label. A dangerous " +
          "command pressed there opens a confirmation naming the host in large type, and it " +
          "won't dismiss for five seconds. Long pastes are held for a look, and broadcast " +
          "input skips production hosts entirely.",
      },
      {
        title: "The copilot treats host output as data",
        detail:
          "Terminal text and host notes are fenced and labelled so a machine's output can't " +
          "pose as your instructions. Secrets are stripped before a request leaves the " +
          "machine, Inspect shows the exact prompt, and a suggested command takes Insert or " +
          "a confirmation rather than running on one click.",
      },
      {
        title: "Transport audit and key sweep",
        detail:
          "Security → Transport asks each host what cryptography it would actually use - " +
          "without logging in - and grades the fleet weakest-first. Security → On disk finds " +
          "the private keys lying around in ~/.ssh, and can move one into the vault and take " +
          "it off the filesystem.",
      },
    ],
  },
  {
    version: "0.9.0",
    headline: "Kino now lives in the tray, and knows what your servers have been up to.",
    items: [
      {
        title: "Runs in the tray",
        detail:
          "Minimising sends Kino to the notification area instead of the taskbar, and " +
          "closing the window leaves it running. Show and Quit are in the tray menu. When " +
          "a host that was up goes down you get a desktop notification - give it an ntfy " +
          "topic and the alert reaches your phone too.",
      },
      {
        title: "Archaeology",
        detail:
          "Tools → Archaeology pulls the shell history of the account you connect as and " +
          "keeps it in an encrypted archive per host. It accumulates, so the commands " +
          "HISTSIZE has already trimmed off the server survive here.",
      },
      {
        title: "Notes",
        detail:
          "Settings → Vault → Notes: recovery codes, licence keys and tokens, encrypted " +
          "under your master password and synced with the vault. Bodies stay blurred " +
          "until you click to reveal.",
      },
      {
        title: "Process tree, and every signal",
        detail:
          "Processes group under their parents, branches fold, and filtering keeps a " +
          "match's ancestors. End has become Signal - SIGTERM, SIGINT, SIGHUP, SIGSTOP, " +
          "SIGCONT and SIGKILL, each named for what it does.",
      },
    ],
  },
  {
    version: "0.8.0",
    headline: "Three new tools, and a safer way to keep your keys fresh.",
    items: [
      {
        title: "Cron editor",
        detail:
          "Tools → Cron jobs reads the host's crontab and writes each schedule out in plain " +
          "English, with the next times it will actually fire. Add, edit and pause jobs " +
          "without vi. Comments and PATH= lines survive every save untouched.",
      },
      {
        title: "Key audit & rotation",
        detail:
          "Settings → Vault → Key audit checks every stored key for weak algorithms, reuse " +
          "across hosts, and age. Rotating installs a fresh ed25519 key, proves it works on a " +
          "second connection, and only then removes the old one.",
      },
      {
        title: "Copy output as an image",
        detail:
          "Select terminal output and choose Image: a PNG with the colours, bold and " +
          "highlighting intact, ready to paste into Slack or an issue.",
      },
    ],
  },
];

/** localStorage key holding the last version whose notes were acknowledged. */
const SEEN_KEY = "kino:whats-new-seen";

export function notesFor(version: string): ReleaseNote | undefined {
  return RELEASE_NOTES.find((n) => n.version === version);
}

export function markSeen(version: string): void {
  try {
    localStorage.setItem(SEEN_KEY, version);
  } catch {
    // A vault that won't persist a dismissal is not worth failing an unlock over.
  }
}

function seenVersion(): string | null {
  try {
    return localStorage.getItem(SEEN_KEY);
  } catch {
    return null;
  }
}

/**
 * Should the notes for `version` be shown right now?
 *
 * Two cases are deliberately silent:
 *
 * - **A fresh install.** Nothing about this release is "new" to someone who has
 *   never run an older one. The version is marked seen on the spot, which also
 *   stops the notes appearing the second time they launch - by then a vault
 *   exists, and without this they'd look exactly like an upgrading user.
 * - **A version with no entry.** Not every release has something to say.
 *
 * An upgrade from before this feature existed has no stored version but does
 * have a vault, and that is precisely the case that should see the notes.
 */
export function shouldShowNotes(version: string, vaultExists: boolean): boolean {
  if (!version || !notesFor(version)) return false;
  if (!vaultExists) {
    markSeen(version);
    return false;
  }
  return seenVersion() !== version;
}
