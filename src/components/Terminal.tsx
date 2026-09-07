import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { save as saveDialog } from "@tauri-apps/plugin-dialog";
import { openUrl } from "@tauri-apps/plugin-opener";
import { FitAddon } from "@xterm/addon-fit";
import { SearchAddon } from "@xterm/addon-search";
import { WebLinksAddon } from "@xterm/addon-web-links";
import { WebglAddon } from "@xterm/addon-webgl";
import { Terminal as XTerm } from "@xterm/xterm";
import "@xterm/xterm/css/xterm.css";
import { DangerMatch, Host, Tab, terminalFontStack, useVaultStore } from "../store";
import { comboFromEvent } from "../keymap";
import { toast } from "../utils";
import { THEMES } from "../themes";
import { appendTerminalOutput, clearTerminalOutput, getTerminalOutput, RollingText } from "../terminalBuffer";
import { registerClearHandler, registerTerminal, unregisterTerminal } from "../terminalRegistry";
import { highlightChunk } from "../highlight";
import { blobToBase64, captureSelection } from "../terminalImage";

interface Props {
  sessionId: string;
  kind: "ssh" | "local";
  active: boolean;
  /** Tab identity + host, needed for in-place auto-reconnect. */
  tabId?: string;
  host?: Host;
  /** When set, the selection tooltip offers "Explain by AI" for the picked text. */
  onExplain?: (text: string) => void;
}

/** Max consecutive auto-reconnect attempts before giving up. */
const MAX_RECONNECT_ATTEMPTS = 6;

/** How long the production confirmation makes you wait before it will act.
 *  Long enough to read the hostname, short enough not to be theatre. */
const PRODUCTION_COUNTDOWN_SECONDS = 5;

/** Beyond this, a paste into production is a script rather than a command, and
 *  worth looking at before it lands. */
const PRODUCTION_PASTE_LIMIT = 500;

const writeCommandFor = (kind: "ssh" | "local") =>
  kind === "local" ? "local_write" : "ssh_write";

/** "Copied 3 lines" / "Copied 42 characters" - enough to confirm what landed. */
function amount(text: string): string {
  const lines = text.split("\n").length;
  if (lines > 1) return `${lines} lines`;
  return `${text.length} character${text.length === 1 ? "" : "s"}`;
}
const copiedLabel = (text: string) => `Copied ${amount(text)}`;
const pastedLabel = (text: string) => `Pasted ${amount(text)}`;

export function Terminal({ sessionId, kind, active, tabId, host, onExplain }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const wrapRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<XTerm | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const searchRef = useRef<SearchAddon | null>(null);
  // Set by the mount effect so the toolbar button, which renders outside it,
  // can trigger the same action as the keybinding.
  const clearScrollbackRef = useRef<() => void>(() => {});
  // Lazily constructed so a re-render doesn't allocate a throwaway buffer.
  const logRef = useRef<RollingText | null>(null);
  if (logRef.current === null) logRef.current = new RollingText(4_000_000);
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [searchOpts, setSearchOpts] = useState({ caseSensitive: false, wholeWord: false, regex: false });
  // Reported by the addon after every search: how many matches, and which one
  // is selected. Without it the search box gave no sign whether a query matched
  // twice or two hundred times.
  const [searchHits, setSearchHits] = useState<{ index: number; count: number } | null>(null);
  // Floating "Copy / Explain" tooltip anchored to the mouse when text is selected.
  const [selMenu, setSelMenu] = useState<{ x: number; y: number; text: string } | null>(null);
  // The xterm key handler is installed once at mount; read the latest bindings
  // through a ref so rebinding in Settings takes effect without a remount.
  const keybindings = useVaultStore((s) => s.keybindings);
  const keybindingsRef = useRef(keybindings);
  useEffect(() => { keybindingsRef.current = keybindings; }, [keybindings]);
  // Same pattern: the data listener is installed once, so it reads the current
  // setting through a ref rather than being torn down when it changes.
  const syntaxHighlight = useVaultStore((s) => s.syntaxHighlight);
  const highlightRef = useRef(syntaxHighlight);
  useEffect(() => { highlightRef.current = syntaxHighlight; }, [syntaxHighlight]);
  const { markTabDisconnected, theme: themeId } = useVaultStore();

  // Auto-reconnect: -1 countdown = permanently failed; otherwise seconds left.
  const [reconnect, setReconnect] = useState<{ attempt: number; countdown: number } | null>(null);
  const attemptRef = useRef(0);
  const reconnectTimerRef = useRef<number | null>(null);
  const activeRef = useRef(active);
  useEffect(() => { activeRef.current = active; }, [active]);
  // Same pattern again: onData is installed once, so it reads the host through
  // a ref - otherwise marking a host production mid-session would not take.
  /** So the "skipped production" notice appears once per broadcast, not once
   *  per keystroke. Reset when broadcast is turned off. */
  const warnedBroadcastRef = useRef(false);
  const broadcastOn = useVaultStore((s) => s.broadcastInput);
  useEffect(() => {
    if (!broadcastOn) warnedBroadcastRef.current = false;
  }, [broadcastOn]);
  const hostRef = useRef(host);
  useEffect(() => { hostRef.current = host; }, [host]);

  /** A command held back by the production guard, waiting to be confirmed. */
  const [danger, setDanger] = useState<{
    hit: DangerMatch;
    line: string;
    bytes: number[];
  } | null>(null);
  const [countdown, setCountdown] = useState(0);
  const isProduction = host?.environment === "production";

  // The countdown is the pause, not the permission: the button is disabled
  // while it runs so the dialog cannot be dismissed by a reflex click landing
  // where "Cancel" was a moment ago.
  useEffect(() => {
    if (!danger) return;
    setCountdown(PRODUCTION_COUNTDOWN_SECONDS);
    const t = setInterval(() => {
      setCountdown((c) => {
        if (c <= 1) {
          clearInterval(t);
          return 0;
        }
        return c - 1;
      });
    }, 1000);
    return () => clearInterval(t);
  }, [danger]);

  /** A paste too large to have been typed, held for a look. */
  const [bigPaste, setBigPaste] = useState<{ text: string; bytes: number[] } | null>(null);

  function sendHeldPaste() {
    if (!bigPaste) return;
    invoke(writeCommandFor(kind), { sessionId, data: bigPaste.bytes }).catch(() => {});
    setBigPaste(null);
  }

  function sendHeldCommand() {
    if (!danger) return;
    invoke(writeCommandFor(kind), { sessionId, data: danger.bytes }).catch(() => {});
    setDanger(null);
  }

  const clearReconnectTimer = () => {
    if (reconnectTimerRef.current !== null) {
      clearInterval(reconnectTimerRef.current);
      reconnectTimerRef.current = null;
    }
  };

  async function doReconnect() {
    clearReconnectTimer();
    setReconnect((r) => (r ? { ...r, countdown: 0 } : r));
    try {
      if (!tabId) throw new Error("no tab");
      await useVaultStore.getState().reconnectTab(tabId);
      attemptRef.current = 0;
      setReconnect(null); // sessionId prop changes - main effect rebinds listeners
    } catch {
      attemptRef.current += 1;
      if (attemptRef.current >= MAX_RECONNECT_ATTEMPTS) {
        setReconnect({ attempt: attemptRef.current, countdown: -1 });
      } else {
        scheduleReconnect();
      }
    }
  }

  function scheduleReconnect() {
    const attempt = attemptRef.current;
    const delayMs = Math.min(1000 * 2 ** attempt, 30000);
    let remaining = Math.ceil(delayMs / 1000);
    setReconnect({ attempt: attempt + 1, countdown: remaining });
    clearReconnectTimer();
    reconnectTimerRef.current = window.setInterval(() => {
      remaining -= 1;
      if (remaining <= 0) {
        void doReconnect();
      } else {
        setReconnect({ attempt: attempt + 1, countdown: remaining });
      }
    }, 1000);
  }

  function cancelReconnect() {
    clearReconnectTimer();
    attemptRef.current = 0;
    setReconnect(null);
  }

  useEffect(() => {
    if (!containerRef.current) return;

    // Initialised during render, so it's non-null by the time any effect runs.
    const log = logRef.current!;

    // Read theme + terminal prefs at mount time via getState so they don't need
    // to be effect deps (which would tear down and rebuild the terminal).
    const { theme: currentThemeId, scrollbackLines, terminalFont, terminalBackground } =
      useVaultStore.getState();
    const t = THEMES.find((t) => t.id === currentThemeId) ?? THEMES[0];

    const savedFont = Number(localStorage.getItem("ssh-mgr:term-fontsize") ?? "14") || 14;
    const term = new XTerm({
      cursorBlink: true,
      fontSize: savedFont,
      fontFamily: terminalFontStack(terminalFont),
      theme: { ...t.term, background: terminalBackground || t.term.background },
      allowTransparency: false,
      scrollback: scrollbackLines,
    });

    const fitAddon = new FitAddon();
    const searchAddon = new SearchAddon();
    // Route link clicks through Tauri's opener - the webview blocks window.open().
    const webLinksAddon = new WebLinksAddon((_event, uri) => {
      openUrl(uri).catch((e) => console.error("Failed to open link:", e));
    });

    term.loadAddon(fitAddon);
    term.loadAddon(searchAddon);
    // resultIndex is -1 when nothing matches (or the query is empty).
    searchAddon.onDidChangeResults((e) =>
      setSearchHits(e.resultCount > 0 ? { index: e.resultIndex + 1, count: e.resultCount } : null)
    );
    term.loadAddon(webLinksAddon);

    term.open(containerRef.current);

    // WebGL rendering is much cheaper on busy terminals, but needs a GL context
    // and must load after open(). Fall back to the default renderer if either
    // the context can't be created or it's lost later (e.g. GPU reset).
    // Which renderer we actually got matters a lot on Linux, where WebKitGTK
    // often has no usable GL context and silently leaves us on the much slower
    // DOM renderer. Say so in the console rather than leaving it a mystery.
    // Reported to the backend as well as the console: console.* only reaches
    // the webview inspector, which `tauri dev` never shows and release builds
    // don't have. localStorage lets About show it without a terminal open.
    const noteRenderer = (renderer: "webgl" | "dom", detail?: string) => {
      localStorage.setItem("ssh-mgr:renderer", renderer);
      console.info(`[kino] terminal renderer: ${renderer}${detail ? ` (${detail})` : ""}`);
      invoke("report_terminal_renderer", { renderer, detail: detail ?? null }).catch(() => {});
    };

    try {
      const webgl = new WebglAddon();
      webgl.onContextLoss(() => {
        noteRenderer("dom", "WebGL context lost");
        webgl.dispose();
      });
      term.loadAddon(webgl);
      noteRenderer("webgl");
    } catch (e) {
      noteRenderer("dom", e instanceof Error ? e.message : String(e));
    }

    // OSC 52: let the remote side (tmux/vim "+y) put text on the local clipboard.
    // Payload is "<targets>;<base64>"; "?" is a read-back request, which we
    // deliberately don't answer - it would leak clipboard contents to the host.
    term.parser.registerOscHandler(52, (data) => {
      const sep = data.indexOf(";");
      if (sep === -1) return false;
      const payload = data.slice(sep + 1);
      if (payload === "?") return false;
      try {
        const bytes = Uint8Array.from(atob(payload), (c) => c.charCodeAt(0));
        const text = new TextDecoder().decode(bytes);
        navigator.clipboard
          .writeText(text)
          // The remote wrote the clipboard with no visible sign - say so.
          .then(() => toast(`${copiedLabel(text)} (from the remote host)`))
          .catch(() => {});
      } catch {
        return false; // not valid base64 - let the default handler have it
      }
      return true;
    });

    fitAddon.fit();

    termRef.current = term;
    fitRef.current = fitAddon;
    searchRef.current = searchAddon;
    // Expose this terminal for programmatic (bracketed) paste from elsewhere.
    registerTerminal(sessionId, term);

    const resizeCommand = kind === "local" ? "local_resize" : "ssh_resize";
    const writeCommand = kind === "local" ? "local_write" : "ssh_write";
    const dataEvent = kind === "local" ? `local-data-${sessionId}` : `ssh-data-${sessionId}`;
    const closeEvent = kind === "local" ? `local-closed-${sessionId}` : `ssh-closed-${sessionId}`;

    // If this session already produced output (e.g. the tab was moved to another
    // pane and this xterm is a fresh view of a still-running session), repaint it
    // so the terminal isn't blank. Empty on a first connect.
    const prior = getTerminalOutput(sessionId);
    if (prior) {
      term.write(prior);
      log.reset(prior);
    }

    // Ctrl+F search, Ctrl +/-/0 font size - intercepted before the shell sees them.
    const applyFont = (size: number) => {
      const s = Math.min(28, Math.max(8, size));
      term.options.fontSize = s;
      localStorage.setItem("ssh-mgr:term-fontsize", String(s));
      fitAddon.fit();
      invoke(resizeCommand, { sessionId, cols: term.cols, rows: term.rows }).catch(() => {});
    };
    // Terminal shortcuts are resolved against the customizable keymap. A matched
    // action runs and is swallowed (preventDefault + return false) so the shell
    // never sees the keystroke - e.g. Ctrl+Shift+C copies instead of hitting the
    // webview's own copy, which would otherwise fire a second time.
    term.attachCustomKeyEventHandler((e) => {
      if (e.type !== "keydown") return true;
      const combo = comboFromEvent(e);
      if (!combo) return true;
      const kb = keybindingsRef.current;
      const swallow = () => { e.preventDefault(); return false; };
      switch (combo) {
        case kb["term-copy"]: {
          const sel = term.getSelection();
          if (sel) {
            navigator.clipboard
              .writeText(sel)
              .then(() => toast(copiedLabel(sel)))
              .catch(() => toast("Couldn't copy to clipboard"));
            term.clearSelection();
          }
          return swallow();
        }
        case kb["term-paste"]:
          navigator.clipboard
            .readText()
            .then((t) => {
              if (!t) return;
              term.paste(t);
              toast(pastedLabel(t));
            })
            .catch(() => toast("Couldn't read the clipboard"));
          return swallow();
        case kb["term-find"]:
          setSearchOpen(true);
          return swallow();
        case kb["term-font-inc"]:
          applyFont((term.options.fontSize ?? 14) + 1);
          return swallow();
        case kb["term-font-dec"]:
          applyFont((term.options.fontSize ?? 14) - 1);
          return swallow();
        case kb["term-font-reset"]:
          applyFont(14);
          return swallow();
        case kb["term-clear"]:
          clearScrollback();
          return swallow();
        default:
          return true;
      }
    });

    term.onData((data) => {
      const bytes = Array.from(new TextEncoder().encode(data));
      const st = useVaultStore.getState();

      // A large paste into production. Bracketed-paste markers add a few bytes
      // and change nothing about the judgement, so the raw length is fine.
      if (
        hostRef.current?.environment === "production" &&
        data.length > PRODUCTION_PASTE_LIMIT
      ) {
        setBigPaste({ text: data, bytes });
        return;
      }

      // Production guard. Only on Enter, only on a host marked production, so
      // ordinary sessions pay nothing at all - not a check, not a round trip.
      //
      // The line is read off the *screen* rather than accumulated from
      // keystrokes. Tracking keystrokes would miss the two ways a dangerous
      // command most often arrives: recalled from history with Up, or finished
      // by tab completion. Neither passes through onData as text, but both are
      // sitting right there on the row the cursor is on.
      if (
        data.includes("\r") &&
        hostRef.current?.environment === "production" &&
        term.buffer.active.type === "normal"
      ) {
        const line = term.buffer.active
          .getLine(term.buffer.active.baseY + term.buffer.active.cursorY)
          ?.translateToString(true);
        if (line && line.trim()) {
          void useVaultStore
            .getState()
            .checkCommandDanger(line)
            .then((hit) => {
              if (hit) setDanger({ hit, line: line.trim(), bytes });
              else invoke(writeCommand, { sessionId, data: bytes }).catch(() => {});
            })
            .catch(() => {
              // A failed check must not swallow the keystroke: the guard is a
              // courtesy, and breaking Enter would be worse than missing one.
              invoke(writeCommand, { sessionId, data: bytes }).catch(() => {});
            });
          return;
        }
      }

      // Broadcast mode: fan keystrokes out to the active tab of every pane.
      if (st.broadcastInput && activeRef.current) {
        const targets = st.panes
          .map((p) => st.activeTabIds[p])
          .map((tid) => st.tabs.find((t) => t.id === tid && t.connected))
          .filter((t): t is Tab => !!t);
        // Broadcast never reaches a production host. Typing into several
        // machines at once is exactly the situation where you have lost track
        // of which ones they are, so the safe default is to leave those out
        // and say so rather than ask mid-keystroke.
        const production = targets.filter(
          (t) => t.host?.environment === "production"
        );
        const safe = targets.filter((t) => !production.includes(t));
        if (production.length > 0 && !warnedBroadcastRef.current) {
          warnedBroadcastRef.current = true;
          toast(
            `Broadcast skipped ${production.length} production host${
              production.length === 1 ? "" : "s"
            }`
          );
        }
        if (safe.length > 0) {
          safe.forEach((t) => {
            const cmd = t.kind === "local" ? "local_write" : "ssh_write";
            invoke(cmd, { sessionId: t.sessionId, data: bytes }).catch(() => {});
          });
          return;
        }
      }
      invoke(writeCommand, { sessionId, data: bytes }).catch(() => {});
    });

    // Forget this terminal's history: the visible scrollback, the buffer used to
    // repaint after a pane move, and the "Save log" capture. Clearing the screen
    // but leaving the log full of what you just cleared would be a surprise.
    const clearScrollback = () => {
      term.clear();
      log.reset();
      clearTerminalOutput(sessionId);
      toast("Scrollback cleared");
    };
    clearScrollbackRef.current = clearScrollback;
    registerClearHandler(sessionId, clearScrollback);

    const decoder = new TextDecoder();
    const unlistenData = listen<number[]>(dataEvent, (event) => {
      const bytes = new Uint8Array(event.payload);
      const text = decoder.decode(bytes, { stream: true });

      // Highlighting rewrites the stream, so it only runs on the normal buffer:
      // inside the alternate screen (vim, htop, less) a program paints its own
      // colours and places the cursor exactly, and injected escapes corrupt it.
      const painted =
        highlightRef.current && term.buffer.active.type === "normal"
          ? highlightChunk(text)
          : null;
      // Unhighlighted, write the raw bytes: xterm reassembles a multi-byte
      // character split across packets, whereas the decoded string would have
      // deferred it.
      term.write(painted ?? bytes);
      // Both buffers below are chunked rings (see RollingText): appending is
      // proportional to this packet, not to the megabytes already held. The
      // previous `+= text` / `slice(-cap)` pair re-copied ~6 MB per packet once
      // full, which is what made heavy output crawl.
      //
      // They keep the *raw* text, not the painted version, so a saved log has
      // no injected escapes in it.
      // Buffer output for "Save log" (cap ~4 MB to bound memory).
      log.append(text);
      // Also feed the cross-mount buffer so a moved terminal can repaint.
      appendTerminalOutput(sessionId, text);
    });

    const unlistenClose = listen(closeEvent, () => {
      term.writeln("\r\n\x1b[33m[Connection closed]\x1b[0m");
      const st = useVaultStore.getState();
      // Was this tab still considered connected? (Intentional closes remove the
      // tab first, so it won't be found - and we won't try to reconnect.)
      const tab = tabId ? st.tabs.find((t) => t.id === tabId) : undefined;
      const wasConnected = !!tab?.connected;
      markTabDisconnected(sessionId);
      if (kind === "ssh" && host && tabId && wasConnected && st.autoReconnect) {
        attemptRef.current = 0;
        scheduleReconnect();
      }
    });

    const resizeObserver = new ResizeObserver(() => {
      fitAddon.fit();
      invoke(resizeCommand, { sessionId, cols: term.cols, rows: term.rows }).catch(() => {});
    });
    resizeObserver.observe(containerRef.current);

    // Selection tooltip: show Copy / Explain when a drag leaves text selected,
    // anchored just above the mouse. A fresh mousedown or an emptied selection
    // hides it again.
    const onMouseUp = (e: MouseEvent) => {
      const text = term.getSelection();
      if (!text.trim() || !wrapRef.current) return;
      const rect = wrapRef.current.getBoundingClientRect();
      setSelMenu({ x: e.clientX - rect.left, y: e.clientY - rect.top, text });
    };
    const onMouseDown = () => setSelMenu(null);
    containerRef.current.addEventListener("mouseup", onMouseUp);
    containerRef.current.addEventListener("mousedown", onMouseDown);
    const selDisposable = term.onSelectionChange(() => {
      if (!term.hasSelection()) setSelMenu(null);
    });

    return () => {
      resizeObserver.disconnect();
      containerRef.current?.removeEventListener("mouseup", onMouseUp);
      containerRef.current?.removeEventListener("mousedown", onMouseDown);
      selDisposable.dispose();
      unlistenData.then((fn) => fn());
      unlistenClose.then((fn) => fn());
      unregisterTerminal(sessionId);
      clearReconnectTimer();
      term.dispose();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId, kind]);

  // Update terminal theme without recreating the terminal instance
  useEffect(() => {
    if (!termRef.current) return;
    const t = THEMES.find((t) => t.id === themeId) ?? THEMES[0];
    // Keep honouring the background override when the theme changes underneath.
    const bg = useVaultStore.getState().terminalBackground;
    termRef.current.options.theme = { ...t.term, background: bg || t.term.background };
  }, [themeId]);

  useEffect(() => {
    if (active && termRef.current) {
      termRef.current.focus();
      fitRef.current?.fit();
    }
  }, [active]);

  /**
   * Search options, including the decorations that mark every hit.
   *
   * The colours come from the active theme's own ANSI palette rather than the
   * chrome ink, because they are painted onto terminal cells and have to sit
   * legibly against whatever the terminal's background is. Matches get a subtle
   * fill; the selected one gets an outline instead of a brighter fill, which
   * stays readable no matter how light a theme's accent happens to be.
   */
  function searchOptions(extra?: { incremental?: boolean }) {
    const t = (THEMES.find((x) => x.id === useVaultStore.getState().theme) ?? THEMES[0]).term;
    return {
      ...searchOpts,
      ...extra,
      decorations: {
        matchBackground: t.brightBlack,
        matchOverviewRuler: t.yellow,
        activeMatchBorder: t.yellow,
        activeMatchColorOverviewRuler: t.cyan,
      },
    };
  }

  function runSearch(query: string, forward: boolean) {
    if (!query) return;
    const opts = searchOptions();
    if (forward) searchRef.current?.findNext(query, opts);
    else searchRef.current?.findPrevious(query, opts);
  }

  /** Re-run from the top when a toggle changes, so the result set updates. */
  function setOpt(key: "caseSensitive" | "wholeWord" | "regex", value: boolean) {
    const next = { ...searchOpts, [key]: value };
    setSearchOpts(next);
    if (searchQuery) {
      const t = (THEMES.find((x) => x.id === useVaultStore.getState().theme) ?? THEMES[0]).term;
      searchRef.current?.findNext(searchQuery, {
        ...next,
        incremental: true,
        decorations: {
          matchBackground: t.brightBlack,
          matchOverviewRuler: t.yellow,
          activeMatchBorder: t.yellow,
          activeMatchColorOverviewRuler: t.cyan,
        },
      });
    }
  }

  async function saveLog() {
    // Strip ANSI escape sequences for a readable plaintext log.
    // eslint-disable-next-line no-control-regex
    const clean = logRef.current!.toString().replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, "");
    const path = await saveDialog({ defaultPath: `session-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}.log` });
    if (!path) return;
    await invoke("save_session_log", { content: clean, path }).catch((e) => console.error(e));
  }

  function copySelection() {
    if (selMenu) {
      const text = selMenu.text;
      navigator.clipboard
        .writeText(text)
        .then(() => toast(copiedLabel(text)))
        .catch(() => toast("Couldn't copy to clipboard"));
    }
    termRef.current?.clearSelection();
    setSelMenu(null);
  }

  function explainSelection() {
    if (selMenu) onExplain?.(selMenu.text);
    setSelMenu(null);
  }

  /**
   * Copy the selection as a PNG, keeping its colours and attributes.
   *
   * The clipboard is tried first because that's the whole point - straight into
   * a chat window. Image writes aren't universally supported (WebKitGTK is the
   * one that matters here), and when they aren't, the fallback is a save dialog
   * rather than an error: the picture has already been rendered by then, and
   * throwing it away because one API is missing would be silly.
   */
  async function copySelectionAsImage() {
    const term = termRef.current;
    if (!term || !selMenu) return;
    setSelMenu(null);
    const state = useVaultStore.getState();
    const theme = THEMES.find((t) => t.id === state.theme) ?? THEMES[0];

    let blob: Blob | null;
    try {
      blob = await captureSelection({
        term,
        theme: { ...theme.term, background: state.terminalBackground || theme.term.background },
        fontFamily: terminalFontStack(state.terminalFont),
        title: host?.name ?? (kind === "local" ? "Local Shell" : "Session"),
        accent: theme.ui.blue,
        options: state.imageExport,
      });
    } catch (e) {
      toast(`Couldn't render the image: ${e}`);
      return;
    }
    if (!blob) {
      toast("Nothing selected to capture");
      return;
    }

    try {
      await navigator.clipboard.write([new ClipboardItem({ "image/png": blob })]);
      toast("Copied image to clipboard");
      term.clearSelection();
      return;
    } catch {
      // Falls through to the save dialog below.
    }

    try {
      const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
      const path = await saveDialog({ defaultPath: `kino-${stamp}.png` });
      if (!path) return;
      await invoke("save_image_png", { dataBase64: await blobToBase64(blob), path });
      toast("This clipboard won't take images - saved the PNG instead");
      term.clearSelection();
    } catch (e) {
      toast(`Couldn't save the image: ${e}`);
    }
  }

  return (
    <div
      ref={wrapRef}
      className={`terminal-wrap${isProduction ? " is-production" : ""}`}
      style={{ display: active ? "block" : "none" }}
    >
      {/* Not colour alone: the word survives colour-vision deficiency, and it
          survives the reduced motion and effects mode stripping the frame. */}
      {isProduction && <span className="production-badge">PRODUCTION</span>}

      {bigPaste && (
        <div className="modal-overlay danger-overlay" onClick={() => setBigPaste(null)}>
          <div className="modal danger-modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>Paste {bigPaste.text.length} characters into production?</h2>
              <button className="icon-btn" onClick={() => setBigPaste(null)}>✕</button>
            </div>
            <div className="connect-body">
              <p className="danger-host">{host?.name}</p>
              <p className="hint" style={{ margin: 0 }}>
                {bigPaste.text.split("\n").length} lines. Shells run a pasted block as it
                arrives, so this is worth a look before it lands.
              </p>
              {/* First and last line: enough to recognise what this is without
                  turning the dialog into a file viewer. */}
              <pre className="danger-line mono">
                {bigPaste.text.split("\n")[0]}
                {bigPaste.text.split("\n").length > 2 && "\n  …\n"}
                {bigPaste.text.split("\n").length > 1 &&
                  bigPaste.text.split("\n").filter((l) => l.trim()).slice(-1)[0]}
              </pre>
            </div>
            <div className="modal-footer">
              <button className="btn" onClick={() => setBigPaste(null)} autoFocus>
                Cancel
              </button>
              <button className="btn btn-danger" onClick={sendHeldPaste}>
                Paste into {host?.name}
              </button>
            </div>
          </div>
        </div>
      )}

      {danger && (
        <div className="modal-overlay danger-overlay" onClick={() => setDanger(null)}>
          <div className="modal danger-modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>Run this on production?</h2>
              <button className="icon-btn" onClick={() => setDanger(null)}>✕</button>
            </div>
            <div className="connect-body">
              {/* The host name is the thing being got wrong, so it is the
                  largest thing in the dialog. */}
              <p className="danger-host">{host?.name}</p>
              <p className="hint" style={{ margin: 0 }}>
                <code>{danger.hit.matched}</code> {danger.hit.explains}.
              </p>
              <pre className="danger-line mono">{danger.line}</pre>
            </div>
            <div className="modal-footer">
              <button className="btn" onClick={() => setDanger(null)} autoFocus>
                Cancel
              </button>
              <button
                className="btn btn-danger"
                disabled={countdown > 0}
                onClick={sendHeldCommand}
              >
                {countdown > 0 ? `Wait ${countdown}…` : `Run on ${host?.name}`}
              </button>
            </div>
          </div>
        </div>
      )}
      {selMenu && (
        <div
          className="term-sel-menu"
          style={{ left: selMenu.x, top: Math.max(4, selMenu.y - 10) }}
          onMouseDown={(e) => e.preventDefault() /* keep the xterm selection alive */}
        >
          <button className="term-sel-btn" onClick={copySelection}>
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
              <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
            </svg>
            Copy
          </button>
          <button
            className="term-sel-btn"
            onClick={() => void copySelectionAsImage()}
            title="Copy the selection as a PNG, colours and all"
          >
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <rect x="3" y="4" width="18" height="16" rx="2" />
              <circle cx="8.5" cy="9.5" r="1.5" />
              <path d="M21 16l-5-5-4 4-2-2-7 7" />
            </svg>
            Image
          </button>
          {onExplain && (
            <button className="term-sel-btn" onClick={explainSelection}>
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 3l1.9 4.6 4.6 1.9-4.6 1.9L12 16l-1.9-4.6L5.5 9.5l4.6-1.9z" />
              </svg>
              Explain by AI
            </button>
          )}
        </div>
      )}
      {reconnect && (
        <div className={`term-reconnect ${reconnect.countdown < 0 ? "failed" : ""}`}>
          {reconnect.countdown < 0 ? (
            <>
              <span>Could not reconnect after {reconnect.attempt} attempts.</span>
              <button className="btn btn-sm btn-primary" onClick={() => { attemptRef.current = 0; scheduleReconnect(); }}>
                Try again
              </button>
              <button className="btn btn-sm" onClick={cancelReconnect}>Dismiss</button>
            </>
          ) : reconnect.countdown === 0 ? (
            <span>Reconnecting…</span>
          ) : (
            <>
              <span>Connection lost. Reconnecting in {reconnect.countdown}s (attempt {reconnect.attempt})…</span>
              <button className="btn btn-sm btn-primary" onClick={() => doReconnect()}>Reconnect now</button>
              <button className="btn btn-sm" onClick={cancelReconnect}>Cancel</button>
            </>
          )}
        </div>
      )}
      <div className="term-toolbar">
        <button className="term-tool-btn" title="Find (Ctrl+F)" onClick={() => setSearchOpen((v) => !v)}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="11" cy="11" r="7" />
            <line x1="21" y1="21" x2="16.65" y2="16.65" />
          </svg>
        </button>
        <button
          className="term-tool-btn"
          title="Clear scrollback (Ctrl+Shift+K)"
          onClick={() => clearScrollbackRef.current()}
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M3 6h18" />
            <path d="M8 6V4h8v2" />
            <path d="M19 6l-1 14H6L5 6" />
          </svg>
        </button>
        <button className="term-tool-btn" title="Save session log" onClick={saveLog}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
            <polyline points="7 10 12 15 17 10" />
            <line x1="12" y1="15" x2="12" y2="3" />
          </svg>
        </button>
      </div>
      {searchOpen && (
        <div className="term-search">
          <input
            autoFocus
            value={searchQuery}
            placeholder="Find in terminal…"
            onChange={(e) => {
              setSearchQuery(e.target.value);
              searchRef.current?.findNext(e.target.value, searchOptions({ incremental: true }));
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter") runSearch(searchQuery, !e.shiftKey);
              if (e.key === "Escape") { setSearchOpen(false); setSearchQuery(""); termRef.current?.focus(); }
            }}
          />
          <span className={`term-search-count ${searchQuery && !searchHits ? "none" : ""}`}>
            {!searchQuery ? "" : searchHits ? `${searchHits.index}/${searchHits.count}` : "0"}
          </span>
          <button
            className={`term-search-opt ${searchOpts.caseSensitive ? "on" : ""}`}
            title="Match case"
            aria-pressed={searchOpts.caseSensitive}
            onClick={() => setOpt("caseSensitive", !searchOpts.caseSensitive)}
          >Aa</button>
          <button
            className={`term-search-opt ${searchOpts.wholeWord ? "on" : ""}`}
            title="Whole word"
            aria-pressed={searchOpts.wholeWord}
            onClick={() => setOpt("wholeWord", !searchOpts.wholeWord)}
          >W</button>
          <button
            className={`term-search-opt ${searchOpts.regex ? "on" : ""}`}
            title="Regular expression"
            aria-pressed={searchOpts.regex}
            onClick={() => setOpt("regex", !searchOpts.regex)}
          >.*</button>
          <button className="btn btn-sm" title="Previous" onClick={() => runSearch(searchQuery, false)}>↑</button>
          <button className="btn btn-sm" title="Next" onClick={() => runSearch(searchQuery, true)}>↓</button>
          <button className="btn btn-sm" title="Close (Esc)" onClick={() => { setSearchOpen(false); setSearchQuery(""); termRef.current?.focus(); }}>✕</button>
        </div>
      )}
      <div ref={containerRef} className="terminal-container" />
    </div>
  );
}
