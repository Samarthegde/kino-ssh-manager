import { useEffect, useState } from "react";
import { useVaultStore } from "./store";
import { THEMES, applyTheme } from "./themes";
import { Sidebar } from "./components/Sidebar";
import { Terminal } from "./components/Terminal";
import { ForwardingPanel } from "./components/ForwardingPanel";
import { SftpModal } from "./components/SftpModal";
import { SettingsMenu } from "./components/SettingsMenu";
import { Unlock } from "./components/Unlock";
import "./index.css";

function App() {
  const { unlocked, tabs, activeTabId, closeTab, setActiveTab, lock, theme, idleLockMinutes } = useVaultStore();
  const [sftpTabId, setSftpTabId] = useState<string | null>(null);

  useEffect(() => {
    const t = THEMES.find((t) => t.id === theme) ?? THEMES[0];
    applyTheme(t);
  }, [theme]);

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

  const activeTab = tabs.find((t) => t.id === activeTabId);
  const sftpTab = tabs.find((t) => t.id === sftpTabId);

  return (
    <div className="app-root">
      <header className="app-header">
        <div className="app-header-left">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <rect x="2" y="3" width="20" height="14" rx="2" />
            <polyline points="8 21 12 17 16 21" />
          </svg>
          <span>Kino SSH Manager</span>
        </div>
        <div className="app-header-right">
          {activeTab?.connected && (
            <button
              className="header-icon-btn header-icon-btn--danger"
              title="Disconnect active session"
              onClick={() => closeTab(activeTab.id)}
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M18.36 6.64a9 9 0 1 1-12.73 0" />
                <line x1="12" y1="2" x2="12" y2="12" />
              </svg>
            </button>
          )}
          <SettingsMenu onLock={lock} />
        </div>
      </header>

      <div className="app-layout">
        <Sidebar />

        <main className="main-area">
          {tabs.length === 0 ? (
            <div className="welcome">
              <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1">
                <rect x="2" y="3" width="20" height="14" rx="2" />
                <polyline points="8 21 12 17 16 21" />
              </svg>
              <p>Select a host from the sidebar to connect</p>
            </div>
          ) : (
            <>
              <div className="tab-bar">
                <div className="tab-strip">
                  {tabs.map((tab) => (
                    <div
                      key={tab.id}
                      className={`tab ${tab.id === activeTabId ? "active" : ""} ${!tab.connected ? "disconnected" : ""}`}
                      onClick={() => setActiveTab(tab.id)}
                      style={tab.host.color ? { borderTop: `2px solid ${tab.host.color}` } : undefined}
                    >
                      <span
                        className={`tab-dot ${tab.connected ? "online" : "offline"}`}
                        style={tab.host.color ? { background: tab.host.color } : undefined}
                      />
                      <span className="tab-label">{tab.host.name}</span>
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
                </div>
                {activeTab && (
                  <div className="tab-bar-tools">
                    {activeTab.connected && (
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
                    <ForwardingPanel sessionId={activeTab.sessionId} host={activeTab.host} />
                  </div>
                )}
              </div>

              <div className="terminal-area">
                {tabs.map((tab) => (
                  <Terminal
                    key={tab.id}
                    sessionId={tab.sessionId}
                    active={tab.id === activeTabId}
                  />
                ))}
              </div>
            </>
          )}
        </main>
      </div>

      {sftpTab && (
        <SftpModal
          key={sftpTab.id}
          sessionId={sftpTab.sessionId}
          host={sftpTab.host}
          onClose={() => setSftpTabId(null)}
        />
      )}
    </div>
  );
}

export default App;
