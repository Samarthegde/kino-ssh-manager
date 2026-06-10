import { useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { MetricsSnapshot, useVaultStore } from "../store";

interface Props {
  sessionId: string;
  title: string;
  local: boolean;
  onClose: () => void;
}

function fmtBytes(kb: number): string {
  let v = kb;
  const units = ["KB", "MB", "GB", "TB"];
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${units[i]}`;
}

function fmtRate(bytesPerSec: number): string {
  let v = bytesPerSec;
  const units = ["B/s", "KB/s", "MB/s", "GB/s"];
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${units[i]}`;
}

function fmtUptime(secs: number): string {
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const parts = [];
  if (d) parts.push(`${d}d`);
  if (h || d) parts.push(`${h}h`);
  parts.push(`${m}m`);
  return parts.join(" ");
}

function barClass(pct: number): string {
  if (pct >= 90) return "metric-fill danger";
  if (pct >= 75) return "metric-fill warn";
  return "metric-fill";
}

function Bar({ label, pct, detail }: { label: string; pct: number; detail: string }) {
  const clamped = Math.min(100, Math.max(0, pct));
  return (
    <div className="metric-row">
      <div className="metric-head">
        <span className="metric-label">{label}</span>
        <span className="metric-value mono">{detail}</span>
      </div>
      <div className="metric-track">
        <div className={barClass(clamped)} style={{ width: `${clamped}%` }} />
      </div>
    </div>
  );
}

export function MetricsPanel({ sessionId, title, local, onClose }: Props) {
  const { metricsStart, metricsStop } = useVaultStore();
  const [snap, setSnap] = useState<MetricsSnapshot | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let streamId: string | null = null;
    let unlisten: (() => void) | null = null;
    let cancelled = false;

    (async () => {
      try {
        streamId = await metricsStart(sessionId, local);
        if (cancelled) {
          metricsStop(streamId).catch(() => {});
          return;
        }
        const un = await listen<MetricsSnapshot>(`metrics-${streamId}`, (e) => setSnap(e.payload));
        unlisten = un;
      } catch (e: any) {
        if (!cancelled) setError(String(e));
      }
    })();

    return () => {
      cancelled = true;
      if (unlisten) unlisten();
      if (streamId) metricsStop(streamId).catch(() => {});
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId, local]);

  const memPct = snap && snap.mem_total_kb > 0 ? (snap.mem_used_kb / snap.mem_total_kb) * 100 : 0;
  const disk = snap?.disks?.[0];
  const diskPct = disk && disk.total_kb > 0 ? (disk.used_kb / disk.total_kb) * 100 : 0;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal metrics-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>
            Metrics — {title}
            <span className="metrics-live">
              <span className="metrics-live-dot" />
              live
            </span>
          </h2>
          <button className="icon-btn" onClick={onClose} title="Close">
            ✕
          </button>
        </div>

        {error ? (
          <div className="form-error docker-error">{error}</div>
        ) : !snap ? (
          <div className="docker-empty">Sampling…</div>
        ) : (
          <div className="metrics-body">
            <Bar label="CPU" pct={snap.cpu_percent} detail={`${snap.cpu_percent.toFixed(0)}%`} />
            <Bar
              label="Memory"
              pct={memPct}
              detail={`${fmtBytes(snap.mem_used_kb)} / ${fmtBytes(snap.mem_total_kb)}`}
            />
            {disk && (
              <Bar
                label={`Disk (${disk.mount})`}
                pct={diskPct}
                detail={`${fmtBytes(disk.used_kb)} / ${fmtBytes(disk.total_kb)}`}
              />
            )}

            <div className="metric-stats">
              <div className="metric-stat">
                <span className="metric-stat-label">Load avg</span>
                <span className="metric-stat-value mono">
                  {snap.load1.toFixed(2)} · {snap.load5.toFixed(2)} · {snap.load15.toFixed(2)}
                </span>
              </div>
              <div className="metric-stat">
                <span className="metric-stat-label">Uptime</span>
                <span className="metric-stat-value mono">{fmtUptime(snap.uptime_secs)}</span>
              </div>
              <div className="metric-stat">
                <span className="metric-stat-label">Network ↓</span>
                <span className="metric-stat-value mono">{fmtRate(snap.net_rx_bytes_per_sec)}</span>
              </div>
              <div className="metric-stat">
                <span className="metric-stat-label">Network ↑</span>
                <span className="metric-stat-value mono">{fmtRate(snap.net_tx_bytes_per_sec)}</span>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
