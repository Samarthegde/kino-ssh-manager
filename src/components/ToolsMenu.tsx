import { ReactNode, useEffect, useRef, useState } from "react";
import { Tab, useVaultStore } from "../store";

interface Props {
  tab: Tab;
  onOpenSftp: () => void;
  onOpenDocker: () => void;
  onOpenMetrics: () => void;
  onOpenCopilot: () => void;
  onOpenProcesses: () => void;
  onOpenCron: () => void;
  onOpenArchaeology: () => void;
}

interface ToolItem {
  id: string;
  label: string;
  icon: ReactNode;
  run: () => void;
  /** Set when the tool can't run here; shown in place of the shortcut hint. */
  unavailable?: string;
  /** Rendered instead of the label when the tool is in an active state. */
  active?: boolean;
}

const ICON = {
  files: (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
    </svg>
  ),
  docker: (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <rect x="3" y="9" width="4" height="4" /><rect x="9" y="9" width="4" height="4" />
      <rect x="15" y="9" width="4" height="4" /><rect x="9" y="4" width="4" height="4" />
      <path d="M2 13c0 4 3 6 8 6 6 0 10-3 11-8 1 0 2-1 2-2-1-1-3-1-4 0" />
    </svg>
  ),
  metrics: (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M3 3v18h18" /><polyline points="7 13 11 9 14 12 19 6" />
    </svg>
  ),
  copilot: (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M12 3l1.9 4.6 4.6 1.9-4.6 1.9L12 16l-1.9-4.6L5.5 9.5l4.6-1.9z" />
      <path d="M18 15l.8 2.2 2.2.8-2.2.8L18 21l-.8-2.2-2.2-.8 2.2-.8z" />
    </svg>
  ),
  processes: (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <rect x="4" y="4" width="16" height="16" rx="2" /><rect x="9" y="9" width="6" height="6" />
      <path d="M9 2v2M15 2v2M9 20v2M15 20v2M2 9h2M2 15h2M20 9h2M20 15h2" />
    </svg>
  ),
  cron: (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <circle cx="12" cy="12" r="9" /><polyline points="12 7 12 12 16 14" />
    </svg>
  ),
  record: (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <circle cx="12" cy="12" r="6" />
    </svg>
  ),
  archaeology: (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8" />
      <path d="M3 3v5h5" />
      <path d="M12 7v5l4 2" />
    </svg>
  ),
  tools: (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z" />
    </svg>
  ),
};

/**
 * The per-session tools, gathered behind one button.
 *
 * These used to be six separate buttons competing for room in the tab bar with
 * the pane controls, and they appeared and disappeared depending on the session
 * - so the strip's width changed as you moved between tabs. One menu keeps the
 * bar stable and gives each tool room for a real label.
 *
 * A tool that can't run in this session stays listed but disabled, with the
 * reason next to it: "why is there no Files here?" is a better question to have
 * answered than to be left guessing at a button that isn't there.
 */
export function ToolsMenu({
  tab, onOpenSftp, onOpenDocker, onOpenMetrics, onOpenCopilot, onOpenProcesses, onOpenCron, onOpenArchaeology,
}: Props) {
  const { copilotEnabled, recordingSessions, startRecording, stopRecording, setRecordingState } =
    useVaultStore();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    function onClickOutside(e: MouseEvent) {
      if (!ref.current?.contains(e.target as Node)) setOpen(false);
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false);
    }
    document.addEventListener("mousedown", onClickOutside);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onClickOutside);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const isRecording = recordingSessions.has(tab.sessionId);

  async function toggleRecording() {
    if (isRecording) {
      await stopRecording(tab.sessionId);
      setRecordingState(tab.sessionId, false);
      return;
    }
    const hostName = tab.host?.name ?? "local";
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    try {
      await startRecording(tab.sessionId, `${hostName}-${stamp}.cast`);
      setRecordingState(tab.sessionId, true);
    } catch (e) {
      window.dispatchEvent(
        new CustomEvent("kino:toast", { detail: `Couldn't start recording: ${e}` })
      );
    }
  }

  const items: ToolItem[] = [
    {
      id: "files",
      label: "Files",
      icon: ICON.files,
      run: onOpenSftp,
      // SFTP rides the SSH connection, so a local shell has nothing to browse.
      unavailable: tab.kind === "ssh" ? undefined : "SSH sessions only",
    },
    { id: "docker", label: "Docker", icon: ICON.docker, run: onOpenDocker },
    { id: "metrics", label: "Metrics", icon: ICON.metrics, run: onOpenMetrics },
    ...(copilotEnabled
      ? [{ id: "copilot", label: "Copilot", icon: ICON.copilot, run: onOpenCopilot }]
      : []),
    { id: "processes", label: "Processes", icon: ICON.processes, run: onOpenProcesses },
    { id: "cron", label: "Cron jobs", icon: ICON.cron, run: onOpenCron },
    { id: "archaeology", label: "Archaeology", icon: ICON.archaeology, run: onOpenArchaeology, unavailable: tab.kind === "ssh" ? undefined : "SSH sessions only" },
    {
      id: "record",
      label: isRecording ? "Stop recording" : "Record session",
      icon: ICON.record,
      run: () => void toggleRecording(),
      active: isRecording,
    },
  ];

  return (
    <div className="tools-wrap" ref={ref}>
      <button
        className={`fwd-trigger ${open ? "active" : ""}`}
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="menu"
        aria-expanded={open}
        title="Session tools"
      >
        {ICON.tools}
        Tools
        {/* Recording is the one tool with state that outlives the menu, so it
            has to be visible without opening it. */}
        {isRecording && <span className="tools-rec-dot" title="Recording" />}
      </button>

      {open && (
        <div className="tools-dropdown" role="menu">
          <p className="fwd-dropdown-title">Tools</p>
          {items.map((item) => (
            <button
              key={item.id}
              role="menuitem"
              className={`tools-item ${item.active ? "active" : ""}`}
              disabled={!!item.unavailable}
              onClick={() => {
                if (item.unavailable) return;
                setOpen(false);
                item.run();
              }}
            >
              <span className="tools-item-icon">{item.icon}</span>
              <span className="tools-item-label">{item.label}</span>
              {item.unavailable && <span className="tools-item-note">{item.unavailable}</span>}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
