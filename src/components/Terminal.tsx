import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { save as saveDialog } from "@tauri-apps/plugin-dialog";
import { openUrl } from "@tauri-apps/plugin-opener";
import { FitAddon } from "@xterm/addon-fit";
import { SearchAddon } from "@xterm/addon-search";
import { WebLinksAddon } from "@xterm/addon-web-links";
import { Terminal as XTerm } from "@xterm/xterm";
import "@xterm/xterm/css/xterm.css";
import { useVaultStore } from "../store";
import { THEMES } from "../themes";

interface Props {
  sessionId: string;
  kind: "ssh" | "local";
  active: boolean;
}

export function Terminal({ sessionId, kind, active }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<XTerm | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const searchRef = useRef<SearchAddon | null>(null);
  const logRef = useRef<string>("");
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const { markTabDisconnected, theme: themeId } = useVaultStore();

  useEffect(() => {
    if (!containerRef.current) return;

    // Read theme at mount time via getState so we don't need it in deps
    const { theme: currentThemeId } = useVaultStore.getState();
    const t = THEMES.find((t) => t.id === currentThemeId) ?? THEMES[0];

    const savedFont = Number(localStorage.getItem("ssh-mgr:term-fontsize") ?? "14") || 14;
    const term = new XTerm({
      cursorBlink: true,
      fontSize: savedFont,
      fontFamily: '"JetBrains Mono", "Fira Code", "Cascadia Code", monospace',
      theme: t.term,
      allowTransparency: false,
      scrollback: 5000,
    });

    const fitAddon = new FitAddon();
    const searchAddon = new SearchAddon();
    // Route link clicks through Tauri's opener — the webview blocks window.open().
    const webLinksAddon = new WebLinksAddon((_event, uri) => {
      openUrl(uri).catch((e) => console.error("Failed to open link:", e));
    });

    term.loadAddon(fitAddon);
    term.loadAddon(searchAddon);
    term.loadAddon(webLinksAddon);

    term.open(containerRef.current);
    fitAddon.fit();

    termRef.current = term;
    fitRef.current = fitAddon;
    searchRef.current = searchAddon;

    const resizeCommand = kind === "local" ? "local_resize" : "ssh_resize";
    const writeCommand = kind === "local" ? "local_write" : "ssh_write";
    const dataEvent = kind === "local" ? `local-data-${sessionId}` : `ssh-data-${sessionId}`;
    const closeEvent = kind === "local" ? `local-closed-${sessionId}` : `ssh-closed-${sessionId}`;

    // Ctrl+F search, Ctrl +/-/0 font size — intercepted before the shell sees them.
    const applyFont = (size: number) => {
      const s = Math.min(28, Math.max(8, size));
      term.options.fontSize = s;
      localStorage.setItem("ssh-mgr:term-fontsize", String(s));
      fitAddon.fit();
      invoke(resizeCommand, { sessionId, cols: term.cols, rows: term.rows }).catch(() => {});
    };
    term.attachCustomKeyEventHandler((e) => {
      if (e.type !== "keydown" || !e.ctrlKey) return true;
      if (e.key === "f" || e.key === "F") { setSearchOpen(true); return false; }
      if (e.key === "=" || e.key === "+") { applyFont((term.options.fontSize ?? 14) + 1); return false; }
      if (e.key === "-" || e.key === "_") { applyFont((term.options.fontSize ?? 14) - 1); return false; }
      if (e.key === "0") { applyFont(14); return false; }
      return true;
    });

    term.onData((data) => {
      const bytes = Array.from(new TextEncoder().encode(data));
      invoke(writeCommand, { sessionId, data: bytes }).catch(() => {});
    });

    const decoder = new TextDecoder();
    const unlistenData = listen<number[]>(dataEvent, (event) => {
      const bytes = new Uint8Array(event.payload);
      term.write(bytes);
      // Buffer output for "Save log" (cap ~4 MB to bound memory).
      logRef.current += decoder.decode(bytes, { stream: true });
      if (logRef.current.length > 4_000_000) {
        logRef.current = logRef.current.slice(-4_000_000);
      }
    });

    const unlistenClose = listen(closeEvent, () => {
      term.writeln("\r\n\x1b[33m[Connection closed]\x1b[0m");
      markTabDisconnected(sessionId);
    });

    const resizeObserver = new ResizeObserver(() => {
      fitAddon.fit();
      invoke(resizeCommand, { sessionId, cols: term.cols, rows: term.rows }).catch(() => {});
    });
    resizeObserver.observe(containerRef.current);

    return () => {
      resizeObserver.disconnect();
      unlistenData.then((fn) => fn());
      unlistenClose.then((fn) => fn());
      term.dispose();
    };
  }, [sessionId, kind]);

  // Update terminal theme without recreating the terminal instance
  useEffect(() => {
    if (!termRef.current) return;
    const t = THEMES.find((t) => t.id === themeId) ?? THEMES[0];
    termRef.current.options.theme = t.term;
  }, [themeId]);

  useEffect(() => {
    if (active && termRef.current) {
      termRef.current.focus();
      fitRef.current?.fit();
    }
  }, [active]);

  function runSearch(query: string, forward: boolean) {
    if (!query) return;
    if (forward) searchRef.current?.findNext(query);
    else searchRef.current?.findPrevious(query);
  }

  async function saveLog() {
    // Strip ANSI escape sequences for a readable plaintext log.
    // eslint-disable-next-line no-control-regex
    const clean = logRef.current.replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, "");
    const path = await saveDialog({ defaultPath: `session-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}.log` });
    if (!path) return;
    await invoke("save_session_log", { content: clean, path }).catch((e) => console.error(e));
  }

  return (
    <div className="terminal-wrap" style={{ display: active ? "block" : "none" }}>
      <div className="term-toolbar">
        <button className="term-tool-btn" title="Find (Ctrl+F)" onClick={() => setSearchOpen((v) => !v)}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="11" cy="11" r="7" />
            <line x1="21" y1="21" x2="16.65" y2="16.65" />
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
            onChange={(e) => { setSearchQuery(e.target.value); searchRef.current?.findNext(e.target.value, { incremental: true }); }}
            onKeyDown={(e) => {
              if (e.key === "Enter") runSearch(searchQuery, !e.shiftKey);
              if (e.key === "Escape") { setSearchOpen(false); setSearchQuery(""); termRef.current?.focus(); }
            }}
          />
          <button className="btn btn-sm" title="Previous" onClick={() => runSearch(searchQuery, false)}>↑</button>
          <button className="btn btn-sm" title="Next" onClick={() => runSearch(searchQuery, true)}>↓</button>
          <button className="btn btn-sm" title="Close (Esc)" onClick={() => { setSearchOpen(false); setSearchQuery(""); termRef.current?.focus(); }}>✕</button>
        </div>
      )}
      <div ref={containerRef} className="terminal-container" />
    </div>
  );
}
