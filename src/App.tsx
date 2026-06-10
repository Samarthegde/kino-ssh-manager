import { useEffect, useState } from "react";
import { useVaultStore } from "./store";
import { THEMES, applyTheme } from "./themes";
import { Sidebar } from "./components/Sidebar";
import { Terminal } from "./components/Terminal";
import { ForwardingPanel } from "./components/ForwardingPanel";
import { SftpModal } from "./components/SftpModal";
import { DockerPanel } from "./components/DockerPanel";
import { MetricsPanel } from "./components/MetricsPanel";
import { SettingsMenu } from "./components/SettingsMenu";
import { Unlock } from "./components/Unlock";
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
    closeTab,
    setActiveTab,
    splitPane,
    closePane,
    setActivePane,
    lock,
    theme,
    idleLockMinutes,
    checkForUpdate,
  } = useVaultStore();
  const [sftpTabId, setSftpTabId] = useState<string | null>(null);
  const [dockerTabId, setDockerTabId] = useState<string | null>(null);
  const [metricsTabId, setMetricsTabId] = useState<string | null>(null);
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

  // Check for a newer release once the vault is unlocked (silent if offline).
  useEffect(() => {
    if (unlocked) checkForUpdate();
  }, [unlocked, checkForUpdate]);

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

  if (!unlocked) {
    return <Unlock />;
  }

  const sftpTab = tabs.find((t) => t.id === sftpTabId);
  const dockerTab = tabs.find((t) => t.id === dockerTabId);
  const metricsTab = tabs.find((t) => t.id === metricsTabId);

  return (
    <div className="app-root">
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
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <rect x="2" y="3" width="20" height="14" rx="2" />
            <polyline points="8 21 12 17 16 21" />
          </svg>
          <span>Kino SSH Manager</span>
        </div>
        <div className="app-header-right">
          <SettingsMenu onLock={lock} />
        </div>
      </header>

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
                      {activeTab && activeTab.connected && activeTab.kind === "ssh" && (
                        <button
                          className="fwd-trigger"
                          onClick={() => setSftpTabId(activeTab.id)}
                          title="Browse files (SFTP)"
                        >
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
                          </svg>
                          Files
                        </button>
                      )}
                      {activeTab && activeTab.connected && (
                        <button
                          className="fwd-trigger"
                          onClick={() => setDockerTabId(activeTab.id)}
                          title="Manage Docker containers"
                        >
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <rect x="3" y="9" width="4" height="4" />
                            <rect x="9" y="9" width="4" height="4" />
                            <rect x="15" y="9" width="4" height="4" />
                            <rect x="9" y="4" width="4" height="4" />
                            <path d="M2 13c0 4 3 6 8 6 6 0 10-3 11-8 1 0 2-1 2-2-1-1-3-1-4 0" />
                          </svg>
                          Docker
                        </button>
                      )}
                      {activeTab && activeTab.connected && (
                        <button
                          className="fwd-trigger"
                          onClick={() => setMetricsTabId(activeTab.id)}
                          title="Live system metrics"
                        >
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M3 3v18h18" />
                            <polyline points="7 13 11 9 14 12 19 6" />
                          </svg>
                          Metrics
                        </button>
                      )}
                      {activeTab?.kind === "ssh" && activeTab.host && (
                        <ForwardingPanel sessionId={activeTab.sessionId} host={activeTab.host} />
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
                      <div className="welcome" style={{ height: '100%' }}>
                        <p style={{ color: 'var(--subtle)', fontSize: '13px' }}>Select a host to connect in this pane</p>
                      </div>
                    ) : (
                      paneTabs.map((tab) => (
                        <Terminal
                          key={tab.id}
                          sessionId={tab.sessionId}
                          kind={tab.kind}
                          active={tab.id === activeTabId}
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
    </div>
  );
}

export default App;
