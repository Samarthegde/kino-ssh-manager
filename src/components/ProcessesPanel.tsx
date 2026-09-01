import { useCallback, useEffect, useMemo, useState } from "react";
import { KillSignal, ProcessInfo, useVaultStore } from "../store";
import { buildTree, filterTree, flattenTree, sortTree, TreeRow } from "../processTree";
import { ContextMenu, MenuItem } from "./ContextMenu";

interface Props {
  sessionId: string;
  title: string;
  local: boolean;
  onClose: () => void;
}

function fmtRss(kb: number): string {
  let v = kb;
  const units = ["KB", "MB", "GB"];
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${units[i]}`;
}

type SortKey = "cpu" | "mem" | "pid" | "command";

/** The signals worth offering, in the order you'd reach for them. */
const SIGNALS: { sig: KillSignal; label: string; hint: string; danger?: boolean }[] = [
  { sig: "TERM", label: "Terminate", hint: "SIGTERM - ask it to exit cleanly" },
  { sig: "INT", label: "Interrupt", hint: "SIGINT - what Ctrl+C sends" },
  { sig: "HUP", label: "Hang up", hint: "SIGHUP - many daemons reload their config" },
  { sig: "STOP", label: "Suspend", hint: "SIGSTOP - freeze until resumed" },
  { sig: "CONT", label: "Resume", hint: "SIGCONT - continue a suspended process" },
  { sig: "KILL", label: "Kill", hint: "SIGKILL - cannot be caught or ignored", danger: true },
];

export function ProcessesPanel({ sessionId, title, local, onClose }: Props) {
  const { processesList, processKill } = useVaultStore();
  const [procs, setProcs] = useState<ProcessInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("cpu");
  const [busyPid, setBusyPid] = useState<number | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [tree, setTree] = useState(false);
  const [collapsed, setCollapsed] = useState<Set<number>>(new Set());
  /** Which process the signal menu is for, and where to draw it. */
  const [sigMenu, setSigMenu] = useState<{ x: number; y: number; proc: ProcessInfo } | null>(null);

  const load = useCallback(async () => {
    try {
      const list = await processesList(sessionId, local);
      setProcs(list);
      setError(null);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, [processesList, sessionId, local]);

  useEffect(() => { void load(); }, [load]);

  useEffect(() => {
    if (!autoRefresh) return;
    const id = window.setInterval(() => { void load(); }, 4000);
    return () => clearInterval(id);
  }, [autoRefresh, load]);

  async function signal(pid: number, sig: KillSignal) {
    setBusyPid(pid);
    setSigMenu(null);
    try {
      await processKill(sessionId, local, pid, sig);
      // Give the process a moment to actually react before refreshing.
      window.setTimeout(() => void load(), 400);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusyPid(null);
    }
  }

  function toggle(pid: number) {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(pid)) next.delete(pid);
      else next.add(pid);
      return next;
    });
  }

  const q = filter.trim().toLowerCase();
  const matches = useCallback(
    (p: ProcessInfo) =>
      !q ||
      p.command.toLowerCase().includes(q) ||
      p.user.toLowerCase().includes(q) ||
      String(p.pid).includes(q),
    [q]
  );

  const compare = useCallback(
    (a: ProcessInfo, b: ProcessInfo) => {
      switch (sortKey) {
        case "pid": return a.pid - b.pid;
        case "mem": return b.mem - a.mem;
        case "command": return a.command.localeCompare(b.command);
        default: return b.cpu - a.cpu;
      }
    },
    [sortKey]
  );

  // Both views produce the same row shape, so the table below doesn't branch.
  const rows: TreeRow[] = useMemo(() => {
    if (!tree) {
      return procs
        .filter(matches)
        .sort(compare)
        .map((proc) => ({ proc, depth: 0, hasChildren: false, hiddenCount: 0 }));
    }
    let nodes = sortTree(buildTree(procs), compare);
    if (q) nodes = filterTree(nodes, matches);
    return flattenTree(nodes, collapsed);
  }, [procs, tree, matches, compare, collapsed, q]);

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal proc-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>Processes - {title}</h2>
          <button className="icon-btn" onClick={onClose}>✕</button>
        </div>

        <div className="proc-toolbar">
          <input
            className="proc-filter"
            placeholder="Filter by command, user or pid…"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
          <button
            className={`btn btn-sm ${tree ? "active" : ""}`}
            onClick={() => setTree((v) => !v)}
            title={tree ? "Show a flat list" : "Group children under their parent"}
          >
            {tree ? "Tree" : "Flat"}
          </button>
          <select
            className="settings-select"
            value={sortKey}
            onChange={(e) => setSortKey(e.target.value as SortKey)}
            title={tree ? "Sort siblings by" : "Sort by"}
          >
            <option value="cpu">Sort: CPU</option>
            <option value="mem">Sort: Memory</option>
            <option value="pid">Sort: PID</option>
            <option value="command">Sort: Command</option>
          </select>
          <label className="proc-auto" title="Refresh every 4s">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
            />
            Auto
          </label>
          <button className="btn btn-sm" onClick={() => void load()} disabled={loading}>
            Refresh
          </button>
        </div>

        {error && <p className="form-error">{error}</p>}

        <div className="proc-list">
          {loading && procs.length === 0 ? (
            <div className="docker-empty">Loading processes…</div>
          ) : rows.length === 0 ? (
            <div className="docker-empty">
              {procs.length === 0 ? "No processes returned." : `No matches for “${filter}”.`}
            </div>
          ) : (
            <table className="proc-table">
              <thead>
                <tr>
                  <th>PID</th>
                  <th>User</th>
                  <th className="num">CPU%</th>
                  <th className="num">MEM%</th>
                  <th className="num">RSS</th>
                  <th>S</th>
                  <th>Command</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {rows.map(({ proc: p, depth, hasChildren, hiddenCount }) => (
                  <tr key={p.pid} className={busyPid === p.pid ? "busy" : undefined}>
                    <td className="mono">{p.pid}</td>
                    <td>{p.user}</td>
                    <td className={`num mono ${p.cpu >= 50 ? "hot" : ""}`}>{p.cpu.toFixed(1)}</td>
                    <td className={`num mono ${p.mem >= 25 ? "hot" : ""}`}>{p.mem.toFixed(1)}</td>
                    <td className="num mono">{fmtRss(p.rss_kb)}</td>
                    {/* T is `ps` for "stopped" - the one state you must be able to
                        see, or a suspended process just looks idle. */}
                    <td className={`mono ${p.state.startsWith("T") ? "hot" : ""}`} title={p.state}>
                      {p.state}
                    </td>
                    <td className="proc-cmd mono" title={p.command}>
                      <span className="proc-tree-cell" style={{ paddingLeft: depth * 14 }}>
                        {hasChildren ? (
                          <button
                            className="proc-twisty"
                            onClick={() => toggle(p.pid)}
                            title={collapsed.has(p.pid) ? "Expand" : "Collapse"}
                          >
                            {collapsed.has(p.pid) ? "▸" : "▾"}
                          </button>
                        ) : (
                          depth > 0 && <span className="proc-twisty-spacer" />
                        )}
                        {p.command}
                        {hiddenCount > 0 && <span className="proc-hidden">+{hiddenCount}</span>}
                      </span>
                    </td>
                    <td className="proc-actions">
                      <button
                        className="btn btn-sm"
                        disabled={busyPid === p.pid}
                        onClick={(e) =>
                          setSigMenu({ x: e.clientX, y: e.clientY, proc: p })
                        }
                        title="Send a signal to this process"
                      >
                        Signal
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {sigMenu && (() => {
          const p = sigMenu.proc;
          const items: MenuItem[] = [
            { label: `${p.pid} · ${p.command.slice(0, 40)}`, header: true },
            ...SIGNALS.map((s) => ({
              label: `${s.label}  (SIG${s.sig})`,
              onClick: () => void signal(p.pid, s.sig),
            })),
          ];
          return (
            <ContextMenu
              x={sigMenu.x}
              y={sigMenu.y}
              items={items}
              onClose={() => setSigMenu(null)}
            />
          );
        })()}
      </div>
    </div>
  );
}
