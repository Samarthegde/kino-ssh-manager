import { useEffect, useRef, useState } from "react";
import { openUrl } from "@tauri-apps/plugin-opener";
import { THEMES } from "../themes";
import { useVaultStore } from "../store";
import { HistoryModal } from "./HistoryModal";
import { SyncModal } from "./SyncModal";
import { SnippetsModal } from "./SnippetsModal";
import { ChangePasswordModal } from "./ChangePasswordModal";
import { AboutModal } from "./AboutModal";

interface Props {
  onLock: () => void;
}

export function SettingsMenu({ onLock }: Props) {
  const { theme: themeId, setTheme, idleLockMinutes, setIdleLockMinutes, updateInfo } = useVaultStore();
  const [open, setOpen] = useState(false);
  const [showHistory, setShowHistory] = useState(false);
  const [showSync, setShowSync] = useState(false);
  const [showSnippets, setShowSnippets] = useState(false);
  const [showChangePw, setShowChangePw] = useState(false);
  const [showAbout, setShowAbout] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function onClickOutside(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", onClickOutside);
    return () => document.removeEventListener("mousedown", onClickOutside);
  }, []);

  function handleLock() {
    setOpen(false);
    onLock();
  }

  return (
    <div className="settings-wrap" ref={ref}>
      <button
        className={`header-icon-btn ${open ? "active" : ""}`}
        onClick={() => setOpen((v) => !v)}
        title="Settings"
      >
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="12" cy="12" r="3" />
          <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
        </svg>
        {updateInfo?.available && <span className="update-badge" title="Update available" />}
      </button>

      {open && (
        <div className="settings-dropdown">
          {updateInfo?.available && (
            <>
              <button
                className="settings-action settings-update"
                onClick={() => { setOpen(false); openUrl(updateInfo.url).catch(() => {}); }}
              >
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M12 3v12" />
                  <polyline points="7 10 12 15 17 10" />
                  <path d="M5 21h14" />
                </svg>
                Update available — v{updateInfo.latest}
              </button>
              <div className="settings-divider" />
            </>
          )}
          <p className="settings-section-label">Theme</p>
          {THEMES.map((t) => (
            <button
              key={t.id}
              className={`settings-theme-option ${t.id === themeId ? "active" : ""}`}
              onClick={() => setTheme(t.id)}
            >
              <div className="theme-swatches">
                <span className="swatch" style={{ background: t.ui.surface }} />
                <span className="swatch" style={{ background: t.ui.blue }} />
                <span className="swatch" style={{ background: t.ui.green }} />
                <span className="swatch" style={{ background: t.ui.red }} />
              </div>
              <span className="settings-theme-name">
                {t.name}
                {!t.dark && <span className="theme-light-tag">light</span>}
              </span>
              {t.id === themeId && (
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                  <polyline points="20 6 9 17 4 12" />
                </svg>
              )}
            </button>
          ))}

          <div className="settings-divider" />

          <div className="settings-row">
            <span>Auto-lock</span>
            <select
              className="settings-select"
              value={idleLockMinutes}
              onChange={(e) => setIdleLockMinutes(Number(e.target.value))}
            >
              <option value={0}>Off</option>
              <option value={5}>5 min</option>
              <option value={15}>15 min</option>
              <option value={30}>30 min</option>
              <option value={60}>1 hour</option>
            </select>
          </div>

          <div className="settings-divider" />

          <button className="settings-action" onClick={() => { setOpen(false); setShowHistory(true); }}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="10" />
              <polyline points="12 6 12 12 16 14" />
            </svg>
            View History
          </button>

          <button className="settings-action" onClick={() => { setOpen(false); setShowSnippets(true); }}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <polyline points="16 18 22 12 16 6" />
              <polyline points="8 6 2 12 8 18" />
            </svg>
            Snippets
          </button>

          <button className="settings-action" onClick={() => { setOpen(false); setShowSync(true); }}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M21 12a9 9 0 0 0-9-9 9 9 0 0 0-6.74 3M3 12a9 9 0 0 0 9 9 9 9 0 0 0 6.74-3" />
              <polyline points="3 4 3 9 8 9" />
              <polyline points="21 20 21 15 16 15" />
            </svg>
            Cloud Sync
          </button>

          <button className="settings-action" onClick={() => { setOpen(false); setShowChangePw(true); }}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <rect x="3" y="11" width="18" height="11" rx="2" />
              <path d="M7 11V7a5 5 0 0 1 9.9-1" />
            </svg>
            Change Master Password
          </button>

          <div className="settings-divider" />

          <button className="settings-action" onClick={() => { setOpen(false); setShowAbout(true); }}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="10" />
              <line x1="12" y1="16" x2="12" y2="12" />
              <line x1="12" y1="8" x2="12.01" y2="8" />
            </svg>
            About
          </button>

          <button className="settings-action settings-action-danger" onClick={handleLock}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <rect x="5" y="11" width="14" height="10" rx="2" />
              <path d="M8 11V7a4 4 0 0 1 8 0v4" />
            </svg>
            Lock Vault
          </button>
        </div>
      )}

      {showHistory && <HistoryModal onClose={() => setShowHistory(false)} />}
      {showSync && <SyncModal onClose={() => setShowSync(false)} />}
      {showSnippets && <SnippetsModal onClose={() => setShowSnippets(false)} />}
      {showChangePw && <ChangePasswordModal onClose={() => setShowChangePw(false)} />}
      {showAbout && <AboutModal onClose={() => setShowAbout(false)} />}
    </div>
  );
}
