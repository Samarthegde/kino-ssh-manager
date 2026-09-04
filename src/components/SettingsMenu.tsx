import { ReactNode, useEffect, useState } from "react";
import { createPortal } from "react-dom";
import { openUrl } from "@tauri-apps/plugin-opener";
import { THEMES } from "../themes";
import { APP_FONTS, TERMINAL_FONTS, terminalFontStack, useVaultStore } from "../store";
import { HistoryModal } from "./HistoryModal";
import { SyncModal } from "./SyncModal";
import { SnippetsModal } from "./SnippetsModal";
import { ChangePasswordModal } from "./ChangePasswordModal";
import { AboutModal } from "./AboutModal";
import { RecordingsModal } from "./RecordingsModal";
import { AiSettingsModal } from "./AiSettingsModal";
import { KeybindingsModal } from "./KeybindingsModal";
import { SecurityPanel } from "./SecurityPanel";
import { NotesModal } from "./NotesModal";
import { McpSettingsModal } from "./McpSettingsModal";
import { Select } from "./Select";

interface Props {
  onLock: () => void;
}

type Section = "general" | "connectivity" | "copilot" | "vault" | "tools";

/* ── Small layout primitives for the page ─────────────────────────────────── */

function Group({ title, desc, children }: { title: string; desc?: string; children: ReactNode }) {
  return (
    <section className="settings-group">
      <header className="settings-group-header">
        <h3>{title}</h3>
        {desc && <p>{desc}</p>}
      </header>
      <div className="settings-group-body">{children}</div>
    </section>
  );
}

function Item({ label, desc, children }: { label: string; desc?: string; children: ReactNode }) {
  return (
    <div className="settings-item">
      <div className="settings-item-text">
        <span className="settings-item-label">{label}</span>
        {desc && <span className="settings-item-desc">{desc}</span>}
      </div>
      <div className="settings-item-control">{children}</div>
    </div>
  );
}

function ActionItem({
  label, desc, buttonLabel, onClick, disabled,
}: { label: string; desc?: string; buttonLabel: string; onClick: () => void; disabled?: boolean }) {
  return (
    <Item label={label} desc={desc}>
      <button className="settings-btn" onClick={onClick} disabled={disabled}>
        {buttonLabel}
      </button>
    </Item>
  );
}

function OnOff({ value, onChange }: { value: boolean; onChange: (on: boolean) => void }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={value}
      className={`settings-switch ${value ? "on" : ""}`}
      onClick={() => onChange(!value)}
    >
      <span className="settings-switch-knob" />
    </button>
  );
}

/* ── Nav icons (16px, stroke style shared with the rest of the app) ───────── */

const ICONS: Record<Section, ReactNode> = {
  general: (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <line x1="4" y1="21" x2="4" y2="14" /><line x1="4" y1="10" x2="4" y2="3" />
      <line x1="12" y1="21" x2="12" y2="12" /><line x1="12" y1="8" x2="12" y2="3" />
      <line x1="20" y1="21" x2="20" y2="16" /><line x1="20" y1="12" x2="20" y2="3" />
      <line x1="1" y1="14" x2="7" y2="14" /><line x1="9" y1="8" x2="15" y2="8" /><line x1="17" y1="16" x2="23" y2="16" />
    </svg>
  ),
  connectivity: (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <circle cx="12" cy="12" r="10" />
      <line x1="2" y1="12" x2="22" y2="12" />
      <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
    </svg>
  ),
  copilot: (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M12 3l1.9 4.6 4.6 1.9-4.6 1.9L12 16l-1.9-4.6L5.5 9.5l4.6-1.9z" />
      <path d="M18 15l.8 2.2 2.2.8-2.2.8L18 21l-.8-2.2-2.2-.8 2.2-.8z" />
    </svg>
  ),
  vault: (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <rect x="3" y="11" width="18" height="11" rx="2" />
      <path d="M7 11V7a5 5 0 0 1 10 0v4" />
    </svg>
  ),
  tools: (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z" />
    </svg>
  ),
};

const SECTIONS: { id: Section; label: string }[] = [
  { id: "general", label: "General" },
  { id: "connectivity", label: "Agent & Cloud" },
  { id: "copilot", label: "AI Copilot" },
  { id: "vault", label: "Vault & Sync" },
  { id: "tools", label: "Shortcuts & Tools" },
];

/* ── The gear button + full-page settings view ────────────────────────────── */

export function SettingsMenu({ onLock }: Props) {
  const {
    theme: themeId,
    setTheme,
    idleLockMinutes,
    setIdleLockMinutes,
    updateInfo,
    relayEnabled,
    setRelayEnabled,
    defaultRelayUrl,
    setDefaultRelayUrl,
    copilotEnabled,
    setCopilotEnabled,
    restoreSessionEnabled,
    setRestoreSessionEnabled,
    healthIntervalSec,
    setHealthIntervalSec,
    scrollbackLines,
    setScrollbackLines,
    terminalFont,
    setTerminalFont,
    terminalBackground,
    setTerminalBackground,
    appFont,
    setAppFont,
    syntaxHighlight,
    setSyntaxHighlight,
    liteMode,
    setLiteMode,
    imageExport,
    setImageExport,
    autoReconnect,
    setAutoReconnect,
    exportSshConfig,
    cloudGetConfig,
    cloudSetConfig,
  } = useVaultStore();

  // Terminal colours of the active theme - the preview and the colour picker's
  // starting value both need them.
  const currentTerm = (THEMES.find((t) => t.id === themeId) ?? THEMES[0]).term;
  const currentTermBg = currentTerm.background;

  const [open, setOpen] = useState(false);
  const [showMcp, setShowMcp] = useState(false);
  const [section, setSection] = useState<Section>("general");
  const [exportingConfig, setExportingConfig] = useState(false);
  const [showHistory, setShowHistory] = useState(false);
  const [showRecordings, setShowRecordings] = useState(false);
  const [showSync, setShowSync] = useState(false);
  const [showSnippets, setShowSnippets] = useState(false);
  const [showChangePw, setShowChangePw] = useState(false);
  const [showAbout, setShowAbout] = useState(false);
  const [showAi, setShowAi] = useState(false);
  const [showKeys, setShowKeys] = useState(false);
  const [showAudit, setShowAudit] = useState(false);
  const [showNotes, setShowNotes] = useState(false);

  const [cloudUrl, setCloudUrl] = useState("");
  const [cloudKey, setCloudKey] = useState("");
  const [cloudKeySet, setCloudKeySet] = useState(false);
  const [cloudMsg, setCloudMsg] = useState("");

  const anyModalOpen =
    showHistory || showRecordings || showSync || showSnippets ||
    showChangePw || showAbout || showAi || showKeys || showAudit || showNotes;

  // Esc closes the page - but not while a sub-dialog is open (those own Esc).
  useEffect(() => {
    if (!open) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape" && !anyModalOpen) setOpen(false);
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, anyModalOpen]);

  useEffect(() => {
    if (!open) return;
    cloudGetConfig()
      .then((c) => {
        // Default to the hosted controller; self-hosters overwrite it.
        setCloudUrl(c?.control_url || "https://kino.samarthkombemane.com");
        setCloudKeySet(c?.key_set ?? false);
      })
      .catch(() => {});
  }, [open, cloudGetConfig]);

  async function handleSaveCloud() {
    setCloudMsg("");
    try {
      const view = await cloudSetConfig({ control_url: cloudUrl, account_key: cloudKey });
      setCloudKey("");
      setCloudKeySet(view.key_set);
      setCloudMsg("Saved ✓");
      setTimeout(() => setCloudMsg(""), 2000);
    } catch (e) {
      setCloudMsg(String(e));
    }
  }

  function handleLock() {
    setOpen(false);
    onLock();
  }

  async function handleExportSshConfig() {
    setExportingConfig(true);
    try {
      const count = await exportSshConfig();
      window.dispatchEvent(new CustomEvent("kino:toast", {
        detail: `Wrote ${count} host${count === 1 ? "" : "s"} to ~/.ssh/config`,
      }));
    } catch (e) {
      alert(`Could not write ~/.ssh/config: ${e}`);
    } finally {
      setExportingConfig(false);
    }
  }

  return (
    <>
      <button
        className={`header-icon-btn ${open ? "active" : ""}`}
        onClick={() => setOpen(true)}
        title="Settings"
      >
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="12" cy="12" r="3" />
          <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
        </svg>
        {updateInfo?.available && <span className="update-badge" title="Update available" />}
      </button>

      {/* Portalled to <body>. This component renders inside .app-header, which
          is a z-index:30 stacking context - a .settings-page (z-300) or any
          .modal-overlay (z-500) left in here gets trapped under the masthead
          colour bar, the perforation rail and the film grain, and would also
          be re-anchored by any transform/filter animation on the header. */}
      {createPortal(
        <>
      {open && (
        <div className="settings-page">
          <header className="settings-page-header">
            <h2>Settings</h2>
            {updateInfo?.available && (
              <button
                className="settings-btn settings-btn-accent"
                onClick={() => openUrl(updateInfo.url).catch(() => {})}
              >
                Update available - v{updateInfo.latest}
              </button>
            )}
            <button className="settings-page-close" onClick={() => setOpen(false)} title="Close (Esc)">
              ✕
            </button>
          </header>

          <div className="settings-page-body">
            <nav className="settings-nav">
              {SECTIONS.map((s) => (
                <button
                  key={s.id}
                  className={`settings-nav-item ${section === s.id ? "active" : ""}`}
                  onClick={() => setSection(s.id)}
                >
                  {ICONS[s.id]}
                  {s.label}
                </button>
              ))}
              <div style={{ flex: 1 }} />
              <button className="settings-nav-item" onClick={() => setShowAbout(true)}>
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="10" />
                  <line x1="12" y1="16" x2="12" y2="12" />
                  <line x1="12" y1="8" x2="12.01" y2="8" />
                </svg>
                About
              </button>
              <button className="settings-nav-item settings-nav-danger" onClick={handleLock}>
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <rect x="5" y="11" width="14" height="10" rx="2" />
                  <path d="M8 11V7a4 4 0 0 1 8 0v4" />
                </svg>
                Lock Vault
              </button>
            </nav>

            <div className="settings-content">
              {section === "general" && (
                <>
                  <Group title="Appearance">
                    <Item label="Theme" desc="Applies to the app and every terminal.">
                      <Select
                        className="settings-select"
                        aria-label="Theme"
                        value={themeId}
                        onChange={setTheme}
                        options={THEMES.map((t) => ({
                          value: t.id,
                          label: t.name,
                          hint: t.dark ? "Dark" : "Light",
                        }))}
                      />
                    </Item>

                    <Item
                      label="Reduced motion & effects"
                      desc="Stops every animation and drops the film grain and background gradients. Lighter to draw - worth turning on if the interface feels sluggish."
                    >
                      <OnOff value={liteMode} onChange={setLiteMode} />
                    </Item>

                    <Item
                      label="Interface font"
                      desc="The face used for the app's own text. Atkinson Hyperlegible is designed for maximum character distinction."
                    >
                      <Select
                        className="settings-select"
                        aria-label="Interface font"
                        value={appFont}
                        onChange={setAppFont}
                        options={APP_FONTS.map((f) => ({
                          value: f.id,
                          label: f.label,
                          hint: f.note || undefined,
                          labelStyle:
                            f.id === "system"
                              ? undefined
                              : { fontFamily: `"${f.id}", sans-serif` },
                        }))}
                      />
                    </Item>
                  </Group>

                  <Group
                    title="Image export"
                    desc="How “Copy as image” frames a terminal selection."
                  >
                    <Item label="Frame" desc="The chrome drawn around the capture.">
                      <Select
                        className="settings-select"
                        aria-label="Frame"
                        value={imageExport.frame}
                        onChange={(v) => setImageExport({ frame: v as typeof imageExport.frame })}
                        options={[
                          { value: "kino", label: "Kino", hint: "Caption rule and perforation rail" },
                          { value: "window", label: "Window", hint: "Title bar with three dots" },
                          { value: "minimal", label: "Minimal", hint: "Just the text, tightly cropped" },
                        ]}
                      />
                    </Item>
                    <Item label="Show host name" desc="Names the machine the output came from.">
                      <OnOff
                        value={imageExport.showHost}
                        onChange={(on) => setImageExport({ showHost: on })}
                      />
                    </Item>
                    <Item label="Show timestamp" desc="Local time of the capture, not UTC.">
                      <OnOff
                        value={imageExport.showTimestamp}
                        onChange={(on) => setImageExport({ showTimestamp: on })}
                      />
                    </Item>
                    <Item
                      label="Background wash"
                      desc="Adds a soft accent border, so a dark capture doesn't float on a light page."
                    >
                      <OnOff
                        value={imageExport.background}
                        onChange={(on) => setImageExport({ background: on })}
                      />
                    </Item>
                  </Group>

                  <Group title="Behavior">
                    <Item label="Auto-lock" desc="Lock the vault after this much inactivity.">
                      <Select
                        className="settings-select"
                        aria-label="Idle auto-lock"
                        value={String(idleLockMinutes)}
                        onChange={(v) => setIdleLockMinutes(Number(v))}
                        options={[
                          { value: "0", label: "Never" },
                          { value: "5", label: "5 minutes" },
                          { value: "15", label: "15 minutes" },
                          { value: "30", label: "30 minutes" },
                          { value: "60", label: "1 hour" },
                        ]}
                      />
                    </Item>
                    <Item label="Auto-reconnect" desc="Re-establish dropped SSH sessions with backoff.">
                      <OnOff value={autoReconnect} onChange={setAutoReconnect} />
                    </Item>
                    <Item label="Restore session on unlock" desc="Reopen the tabs and panes you had before locking.">
                      <OnOff value={restoreSessionEnabled} onChange={setRestoreSessionEnabled} />
                    </Item>
                    <Item label="Host health checks" desc="Probe each host's SSH port and show a status dot in the sidebar.">
                      <Select
                        className="settings-select"
                        aria-label="Host health checks"
                        value={String(healthIntervalSec)}
                        onChange={(v) => setHealthIntervalSec(Number(v))}
                        options={[
                          { value: "0", label: "Off" },
                          { value: "30", label: "Every 30s" },
                          { value: "60", label: "Every 1 min" },
                          { value: "300", label: "Every 5 min" },
                        ]}
                      />
                    </Item>
                  </Group>

                  <Group
                    title="Terminal"
                    desc="Applies to every open terminal straight away - no need to reconnect."
                  >
                    <Item
                      label="Scrollback"
                      desc="Lines of history kept per terminal. More costs memory; Maximum is 200,000 lines."
                    >
                      <Select
                        className="settings-select"
                        aria-label="Scrollback"
                        value={String(scrollbackLines)}
                        onChange={(v) => setScrollbackLines(Number(v))}
                        options={[
                          { value: "1000", label: "1,000" },
                          { value: "5000", label: "5,000" },
                          { value: "20000", label: "20,000" },
                          { value: "50000", label: "50,000" },
                          { value: "200000", label: "Maximum" },
                        ]}
                      />
                    </Item>

                    <Item
                      label="Font"
                      desc="Bundled with the app, so it renders the same on every machine and offline."
                    >
                      <Select
                        className="settings-select"
                        aria-label="Terminal font"
                        value={terminalFont}
                        onChange={setTerminalFont}
                        options={TERMINAL_FONTS.map((f) => ({
                          value: f,
                          label: f,
                          // Drawn in the face it names - the whole point of a
                          // font picker, and impossible with a native select.
                          labelStyle: { fontFamily: terminalFontStack(f) },
                        }))}
                      />
                    </Item>

                    <Item
                      label="Background"
                      desc="Overrides the theme's terminal background. Leave on Theme default to follow it."
                    >
                      <div className="term-bg-control">
                        <input
                          type="color"
                          className="term-bg-swatch"
                          aria-label="Terminal background colour"
                          value={terminalBackground || currentTermBg}
                          onChange={(e) => setTerminalBackground(e.target.value)}
                        />
                        <button
                          className="settings-btn"
                          onClick={() => setTerminalBackground("")}
                          disabled={!terminalBackground}
                        >
                          {terminalBackground ? "Reset" : "Theme default"}
                        </button>
                      </div>
                    </Item>

                    <Item
                      label="Highlight output"
                      desc="Colours timestamps, severities, IPs, URLs and paths in output the host hasn't already coloured. Never applied inside full-screen programs like vim, htop or less."
                    >
                      <OnOff value={syntaxHighlight} onChange={setSyntaxHighlight} />
                    </Item>

                    <div className="settings-item term-preview-row">
                      <div
                        className="term-preview"
                        style={{
                          fontFamily: terminalFontStack(terminalFont),
                          background: terminalBackground || currentTermBg,
                        }}
                      >
                        <span style={{ color: currentTerm.green }}>user@prod-edge-01</span>
                        <span style={{ color: currentTerm.foreground }}>:</span>
                        <span style={{ color: currentTerm.blue }}>~</span>
                        <span style={{ color: currentTerm.foreground }}>$ tail -f /var/log/syslog</span>
                        <br />
                        <span style={{ color: currentTerm.brightBlack }}>Aug 04 15:32:11 </span>
                        <span style={{ color: currentTerm.red }}>ERROR</span>
                        <span style={{ color: currentTerm.foreground }}> connection refused 10.0.4.21:22</span>
                      </div>
                    </div>
                  </Group>
                </>
              )}

              {section === "connectivity" && (
                <>
                  <Group
                    title="Kino Agent"
                    desc="Reach machines with no inbound SSH port - behind NAT, CGNAT, or a firewall - through a relay."
                  >
                    <Item label="Enable agent connections" desc="Adds the Kino Agent mode to the host editor.">
                      <OnOff value={relayEnabled} onChange={setRelayEnabled} />
                    </Item>
                  </Group>

                  {relayEnabled && (
                    <>
                      <Group
                        title="Kino Cloud"
                        desc="Managed relays and machines. Paste an account key from your dashboard; your machines then appear in the host editor."
                      >
                        <Item label="Kino Cloud URL">
                          <input
                            type="text"
                            className="settings-input"
                            placeholder="https://kino.samarthkombemane.com"
                            value={cloudUrl}
                            onChange={(e) => setCloudUrl(e.target.value)}
                          />
                        </Item>
                        <Item label="Account key" desc="Stored encrypted in the vault; never shown again.">
                          <input
                            type="password"
                            className="settings-input"
                            placeholder={cloudKeySet ? "saved - paste to replace" : "kck_..."}
                            value={cloudKey}
                            onChange={(e) => setCloudKey(e.target.value)}
                          />
                        </Item>
                        <Item label="" desc={cloudMsg}>
                          <button className="settings-btn" onClick={handleSaveCloud}>Save</button>
                        </Item>
                      </Group>

                      <Group
                        title="Self-hosted relay"
                        desc="Running your own kino-relay instead? Set the default URL pre-filled in the host editor."
                      >
                        <Item label="Default relay URL">
                          <input
                            type="text"
                            className="settings-input"
                            placeholder="wss://relay.example.com"
                            value={defaultRelayUrl}
                            onChange={(e) => setDefaultRelayUrl(e.target.value)}
                          />
                        </Item>
                      </Group>
                    </>
                  )}
                </>
              )}

              {section === "copilot" && (
                <Group
                  title="AI Copilot"
                  desc="Bring-your-own-key assistant in the terminal. Off by default; the API key is encrypted in the vault."
                >
                  <Item label="Enable AI Copilot">
                    <OnOff value={copilotEnabled} onChange={setCopilotEnabled} />
                  </Item>
                  {copilotEnabled && (
                    <ActionItem
                      label="Provider & API key"
                      desc="Choose the model and paste your OpenRouter key."
                      buttonLabel="Configure…"
                      onClick={() => setShowAi(true)}
                    />
                  )}
                </Group>
              )}

              {section === "vault" && (
                <>
                  <Group title="Vault" desc="Your credentials never leave this machine unencrypted.">
                    <ActionItem
                      label="Master password"
                      desc="Re-encrypts the vault with a new key."
                      buttonLabel="Change…"
                      onClick={() => setShowChangePw(true)}
                    />
                    <ActionItem
                      label="Notes"
                      desc="Recovery codes, licence keys and tokens, encrypted under your master password and synced with the vault."
                      buttonLabel="Open…"
                      onClick={() => setShowNotes(true)}
                    />
                    <ActionItem
                      label="Key audit"
                      desc="Checks every stored key for weak algorithms, reuse and age, and rotates one when you say so. Runs on this machine; no host is contacted."
                      buttonLabel="Open…"
                      onClick={() => setShowAudit(true)}
                    />
                    <ActionItem
                      label="Connection history"
                      desc="When each host was used, stored encrypted."
                      buttonLabel="View…"
                      onClick={() => setShowHistory(true)}
                    />
                    <ActionItem
                      label="~/.ssh/config"
                      desc="Write your hosts into a managed block for plain ssh. Keys are never exported."
                      buttonLabel={exportingConfig ? "Exporting…" : "Export"}
                      onClick={handleExportSshConfig}
                      disabled={exportingConfig}
                    />
                  </Group>
                  <Group title="Cloud Sync" desc="Back the encrypted vault up to a private GitHub repo - only ciphertext leaves this machine.">
                    <ActionItem
                      label="Sync settings"
                      desc="Repo, token, and auto-sync behavior."
                      buttonLabel="Open…"
                      onClick={() => setShowSync(true)}
                    />
                  </Group>
                </>
              )}

              {section === "tools" && (
                <Group title="Shortcuts & Tools">
                  <ActionItem
                    label="Keyboard shortcuts"
                    desc="Rebind any action; chords supported."
                    buttonLabel="Edit…"
                    onClick={() => setShowKeys(true)}
                  />
                  <ActionItem
                    label="Snippets"
                    desc="Reusable command library; snippets can auto-run on connect."
                    buttonLabel="Manage…"
                    onClick={() => setShowSnippets(true)}
                  />
                  <ActionItem
                    label="Session recordings"
                    desc="Asciicast recordings of past sessions, replayable in-app."
                    buttonLabel="Browse…"
                    onClick={() => setShowRecordings(true)}
                  />
                  <ActionItem
                    label="MCP Server"
                    desc="Configure the Model Context Protocol headless server for AI assistants."
                    buttonLabel="Configure…"
                    onClick={() => setShowMcp(true)}
                  />
                </Group>
              )}
            </div>
          </div>
        </div>
      )}

      {showHistory && <HistoryModal onClose={() => setShowHistory(false)} />}
      {showRecordings && <RecordingsModal onClose={() => setShowRecordings(false)} />}
      {showSync && <SyncModal onClose={() => setShowSync(false)} />}
      {showSnippets && <SnippetsModal onClose={() => setShowSnippets(false)} />}
      {showChangePw && <ChangePasswordModal onClose={() => setShowChangePw(false)} />}
      {showAi && <AiSettingsModal onClose={() => setShowAi(false)} />}
      {showKeys && <KeybindingsModal onClose={() => setShowKeys(false)} />}
      {showAbout && <AboutModal onClose={() => setShowAbout(false)} />}
      {showAudit && <SecurityPanel onClose={() => setShowAudit(false)} />}
      {showNotes && <NotesModal onClose={() => setShowNotes(false)} />}
      {showMcp && <McpSettingsModal onClose={() => setShowMcp(false)} />}
        </>,
        document.body
      )}
    </>
  );
}
