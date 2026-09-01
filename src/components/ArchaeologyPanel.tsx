import { useCallback, useEffect, useMemo, useState } from "react";
import { useVaultStore } from "../store";

interface Props {
  sessionId: string;
  title: string;
  onClose: () => void;
}

/**
 * What has been run on this host, gathered from the connecting user's shell
 * history files and kept in an encrypted archive of its own.
 *
 * The archive is keyed by host id and merged in the backend. Nothing here ever
 * writes a `Host`: an earlier version saved the merged list back through
 * `saveHost`, using the copy of the host captured when the tab was opened -
 * which quietly restored whatever that snapshot held, including a key that had
 * since been rotated away.
 */
export function ArchaeologyPanel({ sessionId, title, onClose }: Props) {
  const { fetchShellHistory, getShellHistory, clearShellHistory, tabs } = useVaultStore();
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [copied, setCopied] = useState<number | null>(null);
  const [confirmClear, setConfirmClear] = useState(false);
  const [history, setHistory] = useState<string[]>([]);

  const tab = tabs.find((t) => t.sessionId === sessionId);
  const hostId = tab?.host?.id ?? "";

  const load = useCallback(async () => {
    if (!hostId) {
      setLoading(false);
      return;
    }
    try {
      setHistory(await getShellHistory(hostId));
      setError(null);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, [getShellHistory, hostId]);

  useEffect(() => { void load(); }, [load]);

  async function sync() {
    if (!hostId) return;
    setSyncing(true);
    setError(null);
    try {
      setHistory(await fetchShellHistory(sessionId, hostId));
    } catch (e) {
      setError(String(e));
    } finally {
      setSyncing(false);
    }
  }

  async function clear() {
    if (!hostId) return;
    try {
      await clearShellHistory(hostId);
      setHistory([]);
      setConfirmClear(false);
    } catch (e) {
      setError(String(e));
    }
  }

  function copyCmd(cmd: string, index: number) {
    navigator.clipboard.writeText(cmd).catch(() => {});
    setCopied(index);
    window.setTimeout(() => setCopied(null), 1200);
  }

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return q ? history.filter((h) => h.toLowerCase().includes(q)) : history;
  }, [history, search]);

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal proc-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>Archaeology - {title}</h2>
          <button className="icon-btn" onClick={onClose}>✕</button>
        </div>

        <div className="proc-toolbar">
          <input
            className="proc-filter"
            placeholder="Filter commands…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <span className="arch-count">
            {history.length} {history.length === 1 ? "command" : "commands"}
          </span>
          <button className="btn btn-sm" onClick={() => void sync()} disabled={syncing || !hostId}>
            {syncing ? "Syncing…" : "Sync"}
          </button>
          {history.length > 0 && (
            confirmClear ? (
              <>
                <button className="btn btn-sm delete-btn confirm" onClick={() => void clear()}>
                  Forget all
                </button>
                <button className="btn btn-sm" onClick={() => setConfirmClear(false)}>✕</button>
              </>
            ) : (
              <button className="btn btn-sm" onClick={() => setConfirmClear(true)}>Forget</button>
            )
          )}
        </div>

        {error && <p className="form-error">{error}</p>}

        <div className="proc-list">
          {!hostId ? (
            <div className="docker-empty">Archaeology is only available for saved SSH hosts.</div>
          ) : loading ? (
            <div className="docker-empty">Reading the archive…</div>
          ) : history.length === 0 ? (
            <div className="docker-empty">
              Nothing archived for this host yet. Sync reads ~/.bash_history and
              ~/.zsh_history for the account you connect as, and keeps what it finds
              encrypted in your vault.
            </div>
          ) : filtered.length === 0 ? (
            <div className="docker-empty">No commands match “{search}”.</div>
          ) : (
            <table className="proc-table">
              <thead>
                <tr>
                  <th>Command</th>
                  <th style={{ width: 60 }} />
                </tr>
              </thead>
              <tbody>
                {filtered.map((cmd, i) => (
                  <tr key={`${i}-${cmd}`}>
                    <td className="proc-cmd mono" title={cmd}>{cmd}</td>
                    <td className="proc-actions">
                      <button
                        className="btn btn-sm"
                        onClick={() => copyCmd(cmd, i)}
                        title="Copy to clipboard"
                      >
                        {copied === i ? "✓" : "Copy"}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <p className="arch-foot">
          Commands are de-duplicated, so this is a set rather than a timeline. Anything
          typed on a command line - passwords, tokens - is captured verbatim; the archive
          is encrypted with your vault and is not part of an exported host profile.
        </p>
      </div>
    </div>
  );
}
