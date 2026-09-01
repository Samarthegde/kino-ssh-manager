import { useEffect, useState } from "react";
import { applyAppFont, applyLiteMode, useVaultStore } from "./store";
import { comboFromEvent } from "./keymap";
import { THEMES, applyTheme } from "./themes";
import { Sidebar } from "./components/Sidebar";
import { Terminal } from "./components/Terminal";
import { ForwardingPanel } from "./components/ForwardingPanel";
import { SftpModal } from "./components/SftpModal";
import { DockerPanel } from "./components/DockerPanel";
import { MetricsPanel } from "./components/MetricsPanel";
import { ProcessesPanel } from "./components/ProcessesPanel";
import { CronPanel } from "./components/CronPanel";
import { ArchaeologyPanel } from "./components/ArchaeologyPanel";
import { CopilotPanel } from "./components/CopilotPanel";
import { HomePanel } from "./components/HomePanel";
import { AiSettingsModal } from "./components/AiSettingsModal";
import { SettingsMenu } from "./components/SettingsMenu";
import { Unlock } from "./components/Unlock";
import { ContextMenu, MenuItem } from "./components/ContextMenu";
import { CommandPalette } from "./components/CommandPalette";
import { ToolsMenu } from "./components/ToolsMenu";
import "./index.css";

const SIDEBAR_MIN = 190;
const SIDEBAR_MAX = 480;

function App() {
  const {
    unlocked,
    tabs,
    panes,
    activePaneId,
    activeTabIds,
    paneNames,
    closeTab,
    setActiveTab,
    splitPane,
    closePane,
    setActivePane,
    renamePane,
    moveTabToPane,
    moveTabToNewSplit,
    lock,
    theme,
    idleLockMinutes,
    checkForUpdate,
    broadcastInput,
    setBroadcastInput,
    copilotEnabled,
    keybindings,
    restoreSessionEnabled,
    restoreLastSession,
    healthIntervalSec,
    checkHostsHealth,
    appFont,
    liteMode,
  } = useVaultStore();
  const [sftpTabId, setSftpTabId] = useState<string | null>(null);
  const [dockerTabId, setDockerTabId] = useState<string | null>(null);
  const [metricsTabId, setMetricsTabId] = useState<string | null>(null);
  const [procTabId, setProcTabId] = useState<string | null>(null);
  const [cronTabId, setCronTabId] = useState<string | null>(null);
  const [archaeologyTabId, setArchaeologyTabId] = useState<string | null>(null);
  const [copilotTabId, setCopilotTabId] = useState<string | null>(null);
  // Text handed to the Copilot to explain (from a terminal selection); one-shot.
  const [copilotSeed, setCopilotSeed] = useState<string | null>(null);
  const [aiSettingsOpen, setAiSettingsOpen] = useState(false);
  const [tabMenu, setTabMenu] = useState<{ x: number; y: number; tabId: string } | null>(null);
  // Which pane's name is being edited inline, and the working draft text.
  const [editingPaneId, setEditingPaneId] = useState<string | null>(null);
  const [paneNameDraft, setPaneNameDraft] = useState("");
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [toast, setToast] = useState<string | null>(null);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(
    () => localStorage.getItem("ssh-mgr:sidebar-collapsed") === "1"
  );
  const [sidebarWidth, setSidebarWidth] = useState(() => {
    const saved = Number(localStorage.getItem("ssh-mgr:sidebar-width"));
    return saved >= SIDEBAR_MIN && saved <= SIDEBAR_MAX ? saved : 260;
  });

  const toggleSidebar = () => {
    setSidebarCollapsed((prev) => {
      const next = !prev;
      localStorage.setItem("ssh-mgr:sidebar-collapsed", next ? "1" : "0");
      return next;
    });
  };

  // Drag the divider to resize; clamp to [MIN, MAX] and persist on release.
  const startResize = (e: React.MouseEvent) => {
    e.preventDefault();
    const startX = e.clientX;
    const startW = sidebarWidth;
    let latest = startW;
    const onMove = (ev: MouseEvent) => {
      latest = Math.min(SIDEBAR_MAX, Math.max(SIDEBAR_MIN, startW + ev.clientX - startX));
      setSidebarWidth(latest);
    };
    const onUp = () => {
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseup", onUp);
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
      localStorage.setItem("ssh-mgr:sidebar-width", String(latest));
    };
    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseup", onUp);
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
  };

  useEffect(() => {
    const t = THEMES.find((t) => t.id === theme) ?? THEMES[0];
    applyTheme(t);
  }, [theme]);

  // The interface font is a CSS variable, so it has to be pushed at the document
  // on boot - the stylesheet only carries the default.
  useEffect(() => {
    applyAppFont(appFont);
  }, [appFont]);

  useEffect(() => {
    applyLiteMode(liteMode);
  }, [liteMode]);

  // Check for a newer release on launch (silent if offline). Runs before unlock
  // too - the check hits GitHub, not the vault - so the login screen can show it.
  useEffect(() => {
    checkForUpdate();
  }, [checkForUpdate]);

  // Rebuild the previous tabs/panes right after unlocking, if enabled.
  useEffect(() => {
    if (unlocked && restoreSessionEnabled) restoreLastSession();
  }, [unlocked, restoreSessionEnabled, restoreLastSession]);

  // Poll host reachability on the configured interval (0 = off).
  useEffect(() => {
    if (!unlocked || healthIntervalSec <= 0) return;
    checkHostsHealth();
    const timer = window.setInterval(checkHostsHealth, healthIntervalSec * 1000);
    return () => window.clearInterval(timer);
  }, [unlocked, healthIntervalSec, checkHostsHealth]);

  // Auto-lock the vault after a period of no user activity.
  useEffect(() => {
    if (!unlocked || idleLockMinutes <= 0) return;
    let timer: number;
    const reset = () => {
      clearTimeout(timer);
      timer = window.setTimeout(() => lock(), idleLockMinutes * 60_000);
    };
    const events = ["mousemove", "mousedown", "keydown", "touchstart", "wheel"];
    events.forEach((e) => window.addEventListener(e, reset, { passive: true }));
    reset();
    return () => {
      clearTimeout(timer);
      events.forEach((e) => window.removeEventListener(e, reset));
    };
  }, [unlocked, idleLockMinutes, lock]);

  // Global shortcuts, resolved against the (customizable) keymap.
  useEffect(() => {
    if (!unlocked) return;
    const onKey = (e: KeyboardEvent) => {
      const combo = comboFromEvent(e);
      if (!combo) return;
      if (combo === keybindings["command-palette"]) {
        e.preventDefault();
        setPaletteOpen((v) => !v);
      } else if (combo === keybindings["broadcast-toggle"]) {
        e.preventDefault();
        setBroadcastInput(!useVaultStore.getState().broadcastInput);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [unlocked, setBroadcastInput, keybindings]);

  // Lightweight toast, fired via a window event (e.g. from the command palette).
  useEffect(() => {
    const onToast = (e: Event) => {
      setToast((e as CustomEvent<string>).detail);
      window.setTimeout(() => setToast(null), 3000);
    };
    window.addEventListener("kino:toast", onToast as EventListener);
    return () => window.removeEventListener("kino:toast", onToast as EventListener);
  }, []);

  if (!unlocked) {
    return <Unlock />;
  }

  const sftpTab = tabs.find((t) => t.id === sftpTabId);
  const dockerTab = tabs.find((t) => t.id === dockerTabId);
  const metricsTab = tabs.find((t) => t.id === metricsTabId);
  const procTab = tabs.find((t) => t.id === procTabId);
  const cronTab = tabs.find((t) => t.id === cronTabId);
  const archaeologyTab = tabs.find((t) => t.id === archaeologyTabId);
  const copilotTab = tabs.find((t) => t.id === copilotTabId);

  return (
    <div className="app-root">
      {/* 35mm perforation rail; decoration only, hidden on narrow windows. */}
      <div className="filmstrip" aria-hidden="true" />

      <header className="app-header">
        <div className="app-header-left">
          <button
            className="icon-btn sidebar-toggle"
            onClick={toggleSidebar}
            title={sidebarCollapsed ? "Show sidebar" : "Hide sidebar"}
            aria-label={sidebarCollapsed ? "Show sidebar" : "Hide sidebar"}
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <rect x="3" y="3" width="18" height="18" rx="2" />
              <line x1="9" y1="3" x2="9" y2="21" />
            </svg>
          </button>
          <span className="wordmark" aria-label="Kino SSH Manager">
            <span className="wordmark-mark" aria-hidden="true" />
            <span className="wordmark-name">Kino</span>
            <span className="wordmark-sub">SSH</span>
          </span>
        </div>
        <div className="app-header-right">
          <SettingsMenu onLock={lock} />
        </div>
      </header>
      {/* The poster's colour bar, printed under the masthead. */}
      <div className="ink-band" aria-hidden="true" />

      <div className="app-layout">
        {!sidebarCollapsed && (
          <>
            <Sidebar width={sidebarWidth} />
            <div
              className="sidebar-resizer"
              onMouseDown={startResize}
              title="Drag to resize"
            />
          </>
        )}

        <main className="main-area" style={{ display: "flex", flexDirection: "row", overflow: "hidden" }}>
          {panes.length === 0 ? (
             <div className="welcome">
               <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1">
                 <rect x="2" y="3" width="20" height="14" rx="2" />
                 <polyline points="8 21 12 17 16 21" />
               </svg>
               <p>Select a host from the sidebar to connect</p>
             </div>
          ) : (
            panes.map((paneId, index) => {
              const paneTabs = tabs.filter(t => t.paneId === paneId);
              const activeTabId = activeTabIds[paneId];
              const activeTab = paneTabs.find(t => t.id === activeTabId);
              const isPaneActive = paneId === activePaneId;

              return (
                <div 
                  key={paneId} 
                  className={`pane-container ${isPaneActive ? "pane-active" : ""}`}
                  style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0, borderLeft: index > 0 ? "1px solid var(--border)" : "none" }}
                  onClickCapture={() => {
                    if (!isPaneActive) setActivePane(paneId);
                  }}
                >
                  <div className="tab-bar" style={{ opacity: isPaneActive || paneTabs.length === 0 ? 1 : 0.7 }}>
                    <div className="tab-strip">
                      {paneTabs.map((tab) => (
                        <div
                          key={tab.id}
                          className={`tab ${tab.id === activeTabId ? "active" : ""} ${!tab.connected ? "disconnected" : ""}`}
                          onClick={() => setActiveTab(tab.id)}
                          onContextMenu={(e) => {
                            e.preventDefault();
                            setTabMenu({ x: e.clientX, y: e.clientY, tabId: tab.id });
                          }}
                          style={tab.host?.color ? { borderTop: `2px solid ${tab.host.color}` } : undefined}
                        >
                          <span
                            className={`tab-dot ${tab.connected ? "online" : "offline"}`}
                            style={tab.host?.color ? { background: tab.host.color } : undefined}
                          />
                          <span className="tab-label">{tab.title ?? (tab.kind === "local" ? "Local Shell" : tab.host?.name)}</span>
                          <button
                            className="tab-close"
                            title="Close tab"
                            onClick={(e) => {
                              e.stopPropagation();
                              closeTab(tab.id);
                            }}
                          >
                            ✕
                          </button>
                        </div>
                      ))}
                      {paneTabs.length === 0 && (
                        <div className="tab" style={{ background: "transparent", color: "var(--subtle)", paddingLeft: 16 }}>
                          Empty Pane
                        </div>
                      )}
                    </div>
                    
                    <div className="tab-bar-tools">
                      {activeTab && activeTab.connected && (
                        <ToolsMenu
                          tab={activeTab}
                          onOpenSftp={() => setSftpTabId(activeTab.id)}
                          onOpenDocker={() => setDockerTabId(activeTab.id)}
                          onOpenMetrics={() => setMetricsTabId(activeTab.id)}
                          onOpenCopilot={() => setCopilotTabId(activeTab.id)}
                          onOpenProcesses={() => setProcTabId(activeTab.id)}
                          onOpenCron={() => setCronTabId(activeTab.id)}
                          onOpenArchaeology={() => setArchaeologyTabId(activeTab.id)}
                        />
                      )}

                      {activeTab?.kind === "ssh" && activeTab.host && (
                        <ForwardingPanel sessionId={activeTab.sessionId} host={activeTab.host} />
                      )}
                      
                      {panes.length > 1 && (
                        editingPaneId === paneId ? (
                          <input
                            className="pane-name-input"
                            autoFocus
                            value={paneNameDraft}
                            placeholder={`Pane ${index + 1}`}
                            onChange={(e) => setPaneNameDraft(e.target.value)}
                            onClick={(e) => e.stopPropagation()}
                            onBlur={() => { renamePane(paneId, paneNameDraft); setEditingPaneId(null); }}
                            onKeyDown={(e) => {
                              if (e.key === "Enter") { renamePane(paneId, paneNameDraft); setEditingPaneId(null); }
                              if (e.key === "Escape") setEditingPaneId(null);
                            }}
                          />
                        ) : (
                          <button
                            className="pane-name-label"
                            title="Rename pane"
                            onClick={(e) => {
                              e.stopPropagation();
                              setPaneNameDraft(paneNames[paneId] ?? "");
                              setEditingPaneId(paneId);
                            }}
                          >
                            {paneNames[paneId] ?? `Pane ${index + 1}`}
                          </button>
                        )
                      )}

                      {panes.length > 1 && (
                        <button
                          className={`fwd-trigger ${broadcastInput ? "active" : ""}`}
                          onClick={() => setBroadcastInput(!broadcastInput)}
                          title={broadcastInput ? "Broadcast input: ON - typing goes to every pane (Ctrl+Shift+B)" : "Broadcast input to all panes (Ctrl+Shift+B)"}
                        >
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <circle cx="12" cy="12" r="2" />
                            <path d="M16.24 7.76a6 6 0 0 1 0 8.49M7.76 16.24a6 6 0 0 1 0-8.49M19.07 4.93a10 10 0 0 1 0 14.14M4.93 19.07a10 10 0 0 1 0-14.14" />
                          </svg>
                          {broadcastInput ? "Broadcast" : ""}
                        </button>
                      )}

                      <button className="fwd-trigger" onClick={() => splitPane(paneId)} title="Split Right">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <rect x="3" y="3" width="18" height="18" rx="2" ry="2" />
                          <line x1="12" y1="3" x2="12" y2="21" />
                        </svg>
                      </button>

                      {panes.length > 1 && (
                        <button className="fwd-trigger" onClick={() => closePane(paneId)} title="Close Pane">
                          ✕
                        </button>
                      )}
                    </div>
                  </div>

                  <div className="terminal-area">
                    {paneTabs.length === 0 ? (
                      <HomePanel paneId={paneId} />
                    ) : (
                      paneTabs.map((tab) => (
                        <Terminal
                          key={tab.id}
                          sessionId={tab.sessionId}
                          kind={tab.kind}
                          active={tab.id === activeTabId}
                          tabId={tab.id}
                          host={tab.host}
                          onExplain={copilotEnabled ? (text) => { setCopilotSeed(text); setCopilotTabId(tab.id); } : undefined}
                        />
                      ))
                    )}
                  </div>
                </div>
              );
            })
          )}
        </main>
      </div>

      {sftpTab && sftpTab.host && (
        <SftpModal
          key={sftpTab.id}
          sessionId={sftpTab.sessionId}
          host={sftpTab.host}
          onClose={() => setSftpTabId(null)}
        />
      )}

      {dockerTab && (
        <DockerPanel
          key={dockerTab.id}
          sessionId={dockerTab.sessionId}
          local={dockerTab.kind === "local"}
          title={dockerTab.kind === "local" ? "Local Shell" : dockerTab.host?.name ?? "Host"}
          onClose={() => setDockerTabId(null)}
        />
      )}

      {metricsTab && (
        <MetricsPanel
          key={metricsTab.id}
          sessionId={metricsTab.sessionId}
          local={metricsTab.kind === "local"}
          title={metricsTab.title ?? (metricsTab.kind === "local" ? "Local Shell" : metricsTab.host?.name ?? "Host")}
          onClose={() => setMetricsTabId(null)}
        />
      )}

      {procTab && (
        <ProcessesPanel
          key={procTab.id}
          sessionId={procTab.sessionId}
          local={procTab.kind === "local"}
          title={procTab.title ?? (procTab.kind === "local" ? "Local Shell" : procTab.host?.name ?? "Host")}
          onClose={() => setProcTabId(null)}
        />
      )}

      {cronTab && (
        <CronPanel
          key={cronTab.id}
          sessionId={cronTab.sessionId}
          local={cronTab.kind === "local"}
          title={cronTab.title ?? (cronTab.kind === "local" ? "Local Shell" : cronTab.host?.name ?? "Host")}
          onClose={() => setCronTabId(null)}
        />
      )}

      {archaeologyTab && (
        <ArchaeologyPanel
          key={archaeologyTab.id}
          sessionId={archaeologyTab.sessionId}
          title={archaeologyTab.title ?? (archaeologyTab.kind === "local" ? "Local Shell" : archaeologyTab.host?.name ?? "Host")}
          onClose={() => setArchaeologyTabId(null)}
        />
      )}

      {copilotEnabled && copilotTab && (
        <CopilotPanel
          key={copilotTab.id}
          sessionId={copilotTab.sessionId}
          host={copilotTab.host}
          local={copilotTab.kind === "local"}
          title={copilotTab.title ?? (copilotTab.kind === "local" ? "Local Shell" : copilotTab.host?.name ?? "Host")}
          initialPrompt={copilotSeed}
          onClose={() => { setCopilotTabId(null); setCopilotSeed(null); }}
          onOpenSettings={() => { setCopilotTabId(null); setAiSettingsOpen(true); }}
        />
      )}

      {aiSettingsOpen && <AiSettingsModal onClose={() => setAiSettingsOpen(false)} />}

      {paletteOpen && <CommandPalette onClose={() => setPaletteOpen(false)} />}

      {toast && <div className="app-toast">{toast}</div>}

      {tabMenu && (() => {
        const tab = tabs.find((t) => t.id === tabMenu.tabId);
        if (!tab) return null;
        const items: MenuItem[] = [{ label: "Move to pane", header: true }];
        panes.forEach((pid, i) => {
          if (pid === tab.paneId) return;
          items.push({ label: paneNames[pid] ?? `Pane ${i + 1}`, onClick: () => moveTabToPane(tab.id, pid) });
        });
        items.push({ label: "New split -", onClick: () => moveTabToNewSplit(tab.id) });
        return (
          <ContextMenu x={tabMenu.x} y={tabMenu.y} items={items} onClose={() => setTabMenu(null)} />
        );
      })()}
    </div>
  );
}

export default App;
