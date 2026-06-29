import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { confirm as confirmDialog } from "@tauri-apps/plugin-dialog";
import { listen } from "@tauri-apps/api/event";
import {
  DockerAction,
  DockerContainer,
  DockerImage,
  DockerNetwork,
  DockerVolume,
  useVaultStore,
} from "../store";

interface Props {
  sessionId: string;
  /** Title shown in the header — host name for SSH, "Local Shell" for local. */
  title: string;
  /** When true, run docker against the local daemon instead of over SSH. */
  local: boolean;
  onClose: () => void;
}

type View = "containers" | "images" | "volumes" | "networks";
const VIEWS: View[] = ["containers", "images", "volumes", "networks"];

function isRunning(state: string): boolean {
  return state === "running" || state === "restarting";
}

function shortStatus(status: string): string {
  return status.split(" ").slice(0, 3).join(" ");
}

function splitPorts(ports: string): string[] {
  return ports
    .split(",")
    .map((p) => p.trim())
    .filter(Boolean);
}

const ICONS: Record<string, ReactNode> = {
  play: <polygon points="6 4 20 12 6 20 6 4" />,
  stop: <rect x="6" y="6" width="12" height="12" rx="1" />,
  restart: (
    <>
      <path d="M3 2v6h6" />
      <path d="M3 13a9 9 0 1 0 3-7.7L3 8" />
    </>
  ),
  pause: (
    <>
      <rect x="6" y="4" width="4" height="16" />
      <rect x="14" y="4" width="4" height="16" />
    </>
  ),
  logs: (
    <>
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
      <polyline points="14 2 14 8 20 8" />
      <line x1="8" y1="13" x2="16" y2="13" />
      <line x1="8" y1="17" x2="14" y2="17" />
    </>
  ),
  terminal: (
    <>
      <rect x="2.5" y="4" width="19" height="16" rx="2" />
      <polyline points="6.5 9 9.5 12 6.5 15" />
      <line x1="11.5" y1="15" x2="16" y2="15" />
    </>
  ),
  trash: (
    <>
      <polyline points="3 6 5 6 21 6" />
      <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
    </>
  ),
  chevron: <polyline points="6 9 12 15 18 9" />,
};

function Icon({ name, size = 14 }: { name: keyof typeof ICONS; size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill={name === "play" ? "currentColor" : "none"}
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      {ICONS[name]}
    </svg>
  );
}

function IconBtn({
  icon,
  title,
  onClick,
  disabled,
  variant,
}: {
  icon: keyof typeof ICONS;
  title: string;
  onClick: () => void;
  disabled?: boolean;
  variant?: "start" | "danger";
}) {
  return (
    <button
      className={`docker-iconbtn ${variant ?? ""}`}
      title={title}
      disabled={disabled}
      onClick={(e) => {
        e.stopPropagation();
        onClick();
      }}
    >
      <Icon name={icon} />
    </button>
  );
}

export function DockerPanel({ sessionId, title, local, onClose }: Props) {
  const {
    dockerPs,
    dockerImages,
    dockerVolumes,
    dockerNetworks,
    dockerAction,
    dockerShell,
    dockerLogsStream,
    dockerLogsStreamStop,
  } = useVaultStore();

  const [view, setView] = useState<View>("containers");
  const [containers, setContainers] = useState<DockerContainer[]>([]);
  const [images, setImages] = useState<DockerImage[]>([]);
  const [volumes, setVolumes] = useState<DockerVolume[]>([]);
  const [networks, setNetworks] = useState<DockerNetwork[]>([]);
  const [showStopped, setShowStopped] = useState(true);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [logsFor, setLogsFor] = useState<DockerContainer | null>(null);
  const [logsText, setLogsText] = useState("");
  const [copiedLogs, setCopiedLogs] = useState(false);
  const logsRef = useRef<HTMLPreElement>(null);

  async function copyLogs() {
    try {
      await navigator.clipboard.writeText(logsText);
      setCopiedLogs(true);
      setTimeout(() => setCopiedLogs(false), 1500);
    } catch {
      /* clipboard unavailable — ignore */
    }
  }

  const loadView = useCallback(
    async (v: View) => {
      setLoading(true);
      setError("");
      try {
        if (v === "containers") setContainers(await dockerPs(sessionId, local, true));
        else if (v === "images") setImages(await dockerImages(sessionId, local));
        else if (v === "volumes") setVolumes(await dockerVolumes(sessionId, local));
        else setNetworks(await dockerNetworks(sessionId, local));
      } catch (e: any) {
        setError(String(e));
      } finally {
        setLoading(false);
      }
    },
    [sessionId, local, dockerPs, dockerImages, dockerVolumes, dockerNetworks]
  );

  useEffect(() => {
    loadView(view);
  }, [view, loadView]);

  // Live log streaming: start on open, append chunks, stop on close/unmount.
  useEffect(() => {
    if (!logsFor) return;
    let streamId: string | null = null;
    let unlisten: (() => void) | null = null;
    let cancelled = false;
    setLogsText("");
    (async () => {
      try {
        streamId = await dockerLogsStream(sessionId, local, logsFor.id, 300);
        if (cancelled) {
          dockerLogsStreamStop(streamId).catch(() => {});
          return;
        }
        unlisten = await listen<string>(`docker-log-${streamId}`, (e) => {
          setLogsText((prev) => {
            const next = prev + e.payload;
            // Cap buffer so a chatty container can't grow memory unbounded.
            return next.length > 200_000 ? next.slice(next.length - 200_000) : next;
          });
        });
      } catch (e: any) {
        setLogsText(`Failed to stream logs: ${e}`);
      }
    })();
    return () => {
      cancelled = true;
      if (unlisten) unlisten();
      if (streamId) dockerLogsStreamStop(streamId).catch(() => {});
    };
  }, [logsFor, sessionId, local, dockerLogsStream, dockerLogsStreamStop]);

  // Keep the log view pinned to the bottom as new lines arrive.
  useEffect(() => {
    const el = logsRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [logsText]);

  function toggleExpand(id: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  }

  async function runAction(c: DockerContainer, action: DockerAction) {
    if (action === "remove") {
      const ok = await confirmDialog(`Remove container "${c.name || c.id}"? This cannot be undone.`, {
        title: "Remove container",
        kind: "warning",
      });
      if (!ok) return;
    }
    setBusy(c.id);
    setError("");
    try {
      await dockerAction(sessionId, local, c.id, action);
      await loadView("containers");
    } catch (e: any) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  }

  async function openShell(c: DockerContainer) {
    setError("");
    try {
      await dockerShell(sessionId, local, c.id, c.name);
      onClose(); // surface the new terminal tab
    } catch (e: any) {
      setError(String(e));
    }
  }

  const runningCount = containers.filter((c) => isRunning(c.state)).length;
  const visible = showStopped
    ? containers
    : containers.filter((c) => isRunning(c.state) || c.state === "paused");

  const count =
    view === "containers"
      ? `${runningCount} running · ${containers.length} total`
      : view === "images"
        ? `${images.length} images`
        : view === "volumes"
          ? `${volumes.length} volumes`
          : `${networks.length} networks`;

  return (
    <>
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal docker-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>Docker — {title}</h2>
          <button className="icon-btn" onClick={onClose} title="Close">
            ✕
          </button>
        </div>

        <div className="docker-tabs">
          {VIEWS.map((v) => (
            <button
              key={v}
              className={`docker-tab ${view === v ? "active" : ""}`}
              onClick={() => setView(v)}
            >
              {v}
            </button>
          ))}
        </div>

        <div className="docker-toolbar">
          <span className="docker-count">
            <span className="docker-count-dot" />
            {count}
          </span>
          <span style={{ flex: 1 }} />
          {view === "containers" && (
            <button
              className={`docker-chip ${showStopped ? "active" : ""}`}
              onClick={() => setShowStopped((v) => !v)}
              title="Show stopped containers"
            >
              all
            </button>
          )}
          <button className="docker-chip" onClick={() => loadView(view)} disabled={loading}>
            {loading ? "…" : "refresh"}
          </button>
        </div>

        {error && <div className="form-error docker-error">{error}</div>}

        <div className="docker-list">
          {view === "containers" ? (
            loading && containers.length === 0 ? (
              <div className="docker-empty">Loading containers…</div>
            ) : visible.length === 0 ? (
              <div className="docker-empty">
                {containers.length === 0 ? "No containers" : "No running containers"}
              </div>
            ) : (
              visible.map((c) => {
                const running = isRunning(c.state);
                const paused = c.state === "paused";
                const acting = busy === c.id;
                const isOpen = expanded.has(c.id);
                const ports = splitPorts(c.ports);
                return (
                  <div key={c.id} className="docker-card" data-open={isOpen} data-busy={acting}>
                    <div className="docker-row-main" onClick={() => toggleExpand(c.id)}>
                      <span className={`docker-dot ${running ? "running" : paused ? "paused" : "stopped"}`} />
                      <div className="docker-meta">
                        <span className="docker-name">{c.name || c.id}</span>
                        <span className="docker-image mono">{c.image}</span>
                      </div>
                      <span className="docker-status">{shortStatus(c.status)}</span>
                      <div className="docker-actions" onClick={(e) => e.stopPropagation()}>
                        {running ? (
                          <>
                            <IconBtn icon="terminal" title="Open shell" variant="start" disabled={acting} onClick={() => openShell(c)} />
                            <IconBtn icon="stop" title="Stop" disabled={acting} onClick={() => runAction(c, "stop")} />
                            <IconBtn icon="restart" title="Restart" disabled={acting} onClick={() => runAction(c, "restart")} />
                            <IconBtn icon="pause" title="Pause" disabled={acting} onClick={() => runAction(c, "pause")} />
                          </>
                        ) : paused ? (
                          <IconBtn icon="play" title="Resume" variant="start" disabled={acting} onClick={() => runAction(c, "unpause")} />
                        ) : (
                          <IconBtn icon="play" title="Start" variant="start" disabled={acting} onClick={() => runAction(c, "start")} />
                        )}
                        <IconBtn icon="logs" title="Logs" disabled={acting} onClick={() => setLogsFor(c)} />
                        <IconBtn icon="trash" title="Remove" variant="danger" disabled={acting} onClick={() => runAction(c, "remove")} />
                      </div>
                      <span className={`docker-chevron ${isOpen ? "open" : ""}`}>
                        <Icon name="chevron" size={12} />
                      </span>
                    </div>

                    {isOpen && (
                      <div className="docker-details">
                        <span className="mono docker-id">{c.id}</span>
                        {ports.length > 0 && (
                          <div className="docker-ports">
                            {ports.map((p, i) => (
                              <span key={i} className="docker-port mono">
                                {p}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })
            )
          ) : view === "images" ? (
            images.length === 0 ? (
              <div className="docker-empty">{loading ? "Loading…" : "No images"}</div>
            ) : (
              images.map((img, i) => (
                <div key={`${img.id}-${i}`} className="docker-card">
                  <div className="docker-row-main static">
                    <div className="docker-meta">
                      <span className="docker-name">{img.repo_tag || "<none>"}</span>
                      <span className="docker-image mono">{img.id}</span>
                    </div>
                    <span className="docker-status">{img.size}</span>
                  </div>
                </div>
              ))
            )
          ) : view === "volumes" ? (
            volumes.length === 0 ? (
              <div className="docker-empty">{loading ? "Loading…" : "No volumes"}</div>
            ) : (
              volumes.map((v, i) => (
                <div key={`${v.name}-${i}`} className="docker-card">
                  <div className="docker-row-main static">
                    <div className="docker-meta">
                      <span className="docker-name">{v.name}</span>
                      <span className="docker-image mono">{v.driver}</span>
                    </div>
                  </div>
                </div>
              ))
            )
          ) : networks.length === 0 ? (
            <div className="docker-empty">{loading ? "Loading…" : "No networks"}</div>
          ) : (
            networks.map((n, i) => (
              <div key={`${n.id}-${i}`} className="docker-card">
                <div className="docker-row-main static">
                  <div className="docker-meta">
                    <span className="docker-name">{n.name}</span>
                    <span className="docker-image mono">{n.id}</span>
                  </div>
                  <span className="docker-status">{n.driver}</span>
                </div>
              </div>
            ))
          )}
        </div>

      </div>
    </div>

    {logsFor && (
      <div className="modal-overlay docker-logs-overlay" onClick={() => setLogsFor(null)}>
        <div className="modal docker-logs-modal" onClick={(e) => e.stopPropagation()}>
          <div className="modal-header">
            <h2 className="docker-logs-title mono">
              <span className="metrics-live-dot" /> logs · {logsFor.name || logsFor.id}
            </h2>
            <div className="docker-logs-actions">
              <button
                className="icon-btn"
                onClick={copyLogs}
                disabled={!logsText}
                title="Copy logs to clipboard"
              >
                {copiedLogs ? (
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>
                ) : (
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
                  </svg>
                )}
              </button>
              <button className="icon-btn" onClick={() => setLogsFor(null)} title="Stop & close logs">
                ✕
              </button>
            </div>
          </div>
          <pre ref={logsRef} className="docker-logs-body mono">
            {logsText || "waiting for output…"}
          </pre>
        </div>
      </div>
    )}
    </>
  );
}
