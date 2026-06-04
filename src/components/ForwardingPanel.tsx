import { useEffect, useRef, useState } from "react";
import { Host, useVaultStore } from "../store";

interface Props {
  sessionId: string;
  host: Host;
}

export function ForwardingPanel({ sessionId, host }: Props) {
  const { activeForwards, startForward, stopForward } = useVaultStore();
  const [open, setOpen] = useState(false);
  const [pending, setPending] = useState<string | null>(null);
  const [err, setErr] = useState("");
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function onClickOutside(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", onClickOutside);
    return () => document.removeEventListener("mousedown", onClickOutside);
  }, []);

  const forwards = host.port_forwards ?? [];
  if (forwards.length === 0) return null;

  const activeCount = forwards.filter((f) =>
    activeForwards.has(`${sessionId}:${f.id}`)
  ).length;

  async function toggle(forwardId: string) {
    const key = `${sessionId}:${forwardId}`;
    const isActive = activeForwards.has(key);
    const fwd = forwards.find((f) => f.id === forwardId)!;
    setPending(forwardId);
    setErr("");
    try {
      if (isActive) {
        await stopForward(sessionId, forwardId);
      } else {
        await startForward(sessionId, fwd, host);
      }
    } catch (e: any) {
      setErr(String(e));
    } finally {
      setPending(null);
    }
  }

  return (
    <div className="fwd-wrap" ref={ref}>
      <button
        className={`fwd-trigger ${open ? "active" : ""}`}
        onClick={() => setOpen((v) => !v)}
        title="Port forwards / Tunnels"
      >
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>
          <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>
        </svg>
        Tunnels
        {activeCount > 0 && <span className="fwd-badge">{activeCount}</span>}
      </button>

      {open && (
        <div className="fwd-dropdown">
          <p className="fwd-dropdown-title">Port Forwards — {host.name}</p>
          {err && <p className="fwd-error">{err}</p>}
          {forwards.map((fwd) => {
            const isActive = activeForwards.has(`${sessionId}:${fwd.id}`);
            const isLoading = pending === fwd.id;
            return (
              <div key={fwd.id} className={`fwd-item ${isActive ? "active" : ""}`}>
                <div className="fwd-status-dot" title={isActive ? "Active" : "Inactive"} />
                <div className="fwd-info">
                  <span className="fwd-label">{fwd.label || "Tunnel"}</span>
                  <span className="fwd-meta">
                    localhost:{fwd.local_port} → {fwd.remote_host}:{fwd.remote_port}
                  </span>
                </div>
                <button
                  className={`fwd-toggle ${isActive ? "stop" : "start"}`}
                  onClick={() => toggle(fwd.id)}
                  disabled={isLoading}
                >
                  {isLoading ? "…" : isActive ? "Stop" : "Start"}
                </button>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
