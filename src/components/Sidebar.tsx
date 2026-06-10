import { useState, useEffect } from "react";
import { Host, HostKeyVerdict, useVaultStore } from "../store";
import { ConnectDialog, getSavedAuthPref } from "./ConnectDialog";
import { ExportMenu, promptImportHost } from "./ExportMenu";
import { HostForm } from "./HostForm";
import { HostKeyDialog } from "./HostKeyDialog";
import { OsIcon } from "./OsIcon";

type HostKeyPrompt = { host: Host; verdict: Extract<HostKeyVerdict, { status: "new" | "changed" }> };

export function Sidebar({ width }: { width: number }) {
  const { hosts, connectToHost, deleteHost, importHostFromFile, verifyHostKey, trustHostKey, getHistory, openLocalShell } =
    useVaultStore();
  const [showForm, setShowForm] = useState(false);
  const [editHost, setEditHost] = useState<Host | undefined>();
  const [connecting, setConnecting] = useState<string | null>(null);
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null);
  const [dialogHost, setDialogHost] = useState<Host | null>(null);
  const [hostKeyPrompt, setHostKeyPrompt] = useState<HostKeyPrompt | null>(null);
  const [importing, setImporting] = useState(false);
  const [query, setQuery] = useState("");
  const [sortOption, setSortOption] = useState<"name" | "recent">(() =>
    (localStorage.getItem("ssh-mgr:sort") as "name" | "recent") || "recent"
  );
  const [lastUsedMap, setLastUsedMap] = useState<Record<string, number>>({});

  useEffect(() => {
    getHistory().then((events) => {
      const map: Record<string, number> = {};
      for (const ev of events) {
        if (ev.host_id && ev.event_type === "connection") {
          if (!map[ev.host_id] || ev.timestamp > map[ev.host_id]) {
            map[ev.host_id] = ev.timestamp;
          }
        }
      }
      setLastUsedMap(map);
    }).catch(console.error);
  }, [getHistory, connecting]);

  const q = query.trim().toLowerCase();
  const visibleHosts = (q
    ? hosts.filter((h) =>
      [h.name, h.hostname, h.username, h.notes ?? ""].some((f) =>
        f.toLowerCase().includes(q)
      )
    )
    : [...hosts]
  ).sort((a, b) => {
    if (sortOption === "recent") {
      const aTime = lastUsedMap[a.id] || 0;
      const bTime = lastUsedMap[b.id] || 0;
      if (aTime !== bTime) return bTime - aTime;
    }
    return a.name.localeCompare(b.name);
  });

  const [expandedGroups, setExpandedGroups] = useState<Record<string, boolean>>({});
  const [quickConnectInput, setQuickConnectInput] = useState("");

  const groupedHosts = visibleHosts.reduce((acc, host) => {
    const groupName = host.group || "";
    if (!acc[groupName]) acc[groupName] = [];
    acc[groupName].push(host);
    return acc;
  }, {} as Record<string, Host[]>);

  const groupKeys = Object.keys(groupedHosts).sort((a, b) => {
    if (a === "") return -1;
    if (b === "") return 1;
    return a.localeCompare(b);
  });

  function handleQuickConnect(e: React.FormEvent) {
    e.preventDefault();
    if (!quickConnectInput.trim()) return;

    let user = "root";
    let port = 22;
    let hostname = quickConnectInput.trim();

    if (hostname.includes("@")) {
      const parts = hostname.split("@");
      user = parts[0];
      hostname = parts.slice(1).join("@");
    }

    if (hostname.includes(":")) {
      const parts = hostname.split(":");
      const p = parseInt(parts[parts.length - 1], 10);
      if (!isNaN(p)) {
        port = p;
        hostname = parts.slice(0, -1).join(":");
      }
    }

    const qcHost: Host = {
      id: "quick-connect-" + Date.now(),
      name: hostname,
      hostname: hostname,
      username: user,
      port: port,
      default_auth: "Password",
    };

    setDialogHost(qcHost);
    setQuickConnectInput("");
  }

  // Actually open the session — assumes the host key is already trusted.
  async function establish(host: Host) {
    setConnecting(host.id);
    try {
      // Don't save quick connect hosts to history using store saveHost,
      // connectToHost handles it directly.
      await connectToHost(host);
    } catch (e) {
      alert(`Connection failed: ${e}`);
    } finally {
      setConnecting(null);
    }
  }

  async function doConnect(host: Host) {
    setDialogHost(null);
    setConnecting(host.id);
    let verdict: HostKeyVerdict;
    try {
      verdict = await verifyHostKey(host);
    } catch (e) {
      setConnecting(null);
      alert(`Cannot verify host key: ${e}`);
      return;
    }
    if (verdict.status === "trusted") {
      await establish(host);
    } else {
      setConnecting(null);
      setHostKeyPrompt({ host, verdict });
    }
  }

  async function handleTrustHostKey() {
    if (!hostKeyPrompt) return;
    const { host, verdict } = hostKeyPrompt;
    setHostKeyPrompt(null);
    try {
      await trustHostKey(host, verdict.fingerprint);
    } catch (e) {
      alert(`Could not save host key: ${e}`);
      return;
    }
    await establish(host);
  }

  function handleConnect(host: Host) {
    const hasBoth = !!host.private_key && !!host.password;
    if (!hasBoth) {
      doConnect(host);
      return;
    }
    const pref = getSavedAuthPref(host.id);
    if (pref === "SshKey") {
      doConnect({ ...host, default_auth: "SshKey" });
    } else {
      setDialogHost(host);
    }
  }

  async function handleDelete(host: Host) {
    if (deleteConfirm === host.id) {
      await deleteHost(host.id);
      setDeleteConfirm(null);
    } else {
      setDeleteConfirm(host.id);
      setTimeout(() => setDeleteConfirm(null), 3000);
    }
  }

  async function handleImport() {
    setImporting(true);
    try {
      await promptImportHost(importHostFromFile);
    } catch (e) {
      alert(`Import failed: ${e}`);
    } finally {
      setImporting(false);
    }
  }

  function authLabel(host: Host) {
    if (host.private_key && host.password) return "Key+PW";
    if (host.private_key) return "SSH Key";
    return "Password";
  }

  function authClass(host: Host) {
    if (host.private_key && host.password) return "both";
    if (host.private_key) return "key";
    return "pw";
  }

  return (
    <>
      <aside className="sidebar" style={{ width, minWidth: width, maxWidth: width }}>
        <div className="sidebar-header">
          <span className="sidebar-title">Hosts</span>
        </div>

        <form onSubmit={handleQuickConnect} className="sidebar-search" style={{ paddingBottom: "8px", borderBottom: "1px solid var(--muted)" }}>
          <input
            type="text"
            placeholder="Quick Connect (user@host:port)"
            value={quickConnectInput}
            onChange={(e) => setQuickConnectInput(e.target.value)}
            style={{ background: "var(--overlay)", borderColor: "transparent" }}
          />
        </form>

        {hosts.length > 0 && (
          <div className="sidebar-search" style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
            <input
              type="text"
              placeholder="Search hosts…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
            <div className="settings-row">
              <span>Sort by:</span>
              <select
                className="settings-select"
                value={sortOption}
                onChange={(e) => {
                  const val = e.target.value as "name" | "recent";
                  setSortOption(val);
                  localStorage.setItem("ssh-mgr:sort", val);
                }}
              >
                <option value="recent">Recently used</option>
                <option value="name">Name (A-Z)</option>
              </select>
            </div>
          </div>
        )}

        <div className="host-list">
          {hosts.length === 0 ? (
            <p className="empty-state">No hosts yet.<br />Add one below.</p>
          ) : visibleHosts.length === 0 ? (
            <p className="empty-state">No matches for “{query}”.</p>
          ) : null}
          {groupKeys.map(groupName => {
            const groupHosts = groupedHosts[groupName];
            const isExpanded = expandedGroups[groupName] !== false;

            return (
              <div key={groupName} className="host-group">
                {groupName !== "" && (
                  <div
                    className="host-group-header"
                    onClick={() => setExpandedGroups(prev => ({ ...prev, [groupName]: !isExpanded }))}
                    style={{ padding: "6px 12px", fontSize: "11px", fontWeight: "bold", color: "var(--subtle)", cursor: "pointer", display: "flex", alignItems: "center", gap: "6px" }}
                  >
                    <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ transform: isExpanded ? "rotate(90deg)" : "none", transition: "transform 0.1s" }}>
                      <polyline points="9 18 15 12 9 6" />
                    </svg>
                    {groupName}
                  </div>
                )}
                {isExpanded && groupHosts.map((host) => (
                  <div
                    key={host.id}
                    className="host-item"
                    style={host.color ? { borderTopColor: host.color } : undefined}
                  >
                    <span
                      className="host-avatar"
                      style={
                        host.color
                          ? {
                              background: `color-mix(in srgb, ${host.color} 22%, transparent)`,
                              color: host.color,
                            }
                          : undefined
                      }
                    >
                      <OsIcon os={host.os} />
                    </span>
                    <div className="host-info" onClick={() => handleConnect(host)} title={host.notes || undefined}>
                      <span className="host-name">
                        {host.name}
                        {host.notes && (
                          <svg className="host-note-icon" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-label="Has notes">
                            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                            <polyline points="14 2 14 8 20 8" />
                            <line x1="8" y1="13" x2="16" y2="13" />
                            <line x1="8" y1="17" x2="13" y2="17" />
                          </svg>
                        )}
                      </span>
                      <span className="host-meta">
                        {host.username}@{host.hostname}:{host.port}
                      </span>
                      <span className={`auth-badge ${authClass(host)}`}>
                        {authLabel(host)}
                      </span>
                    </div>
                    <div className="host-actions">
                      {connecting === host.id ? (
                        <span className="connecting-spinner">…</span>
                      ) : (
                        <button
                          className="icon-btn connect-btn"
                          title="Connect"
                          onClick={() => handleConnect(host)}
                        >
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <polyline points="9 18 15 12 9 6" />
                          </svg>
                        </button>
                      )}
                      <ExportMenu host={host} />
                      <button
                        className="icon-btn"
                        title="Edit"
                        onClick={() => { setEditHost(host); setShowForm(true); }}
                      >
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" />
                          <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z" />
                        </svg>
                      </button>
                      <button
                        className={`icon-btn delete-btn ${deleteConfirm === host.id ? "confirm" : ""}`}
                        title={deleteConfirm === host.id ? "Click again to confirm" : "Delete"}
                        onClick={() => handleDelete(host)}
                      >
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <polyline points="3 6 5 6 21 6" />
                          <path d="M19 6l-1 14H6L5 6" />
                          <path d="M10 11v6M14 11v6" />
                          <path d="M9 6V4h6v2" />
                        </svg>
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            );
          })}
        </div>

        <div className="sidebar-footer">
          <button
            className="btn btn-primary add-btn"
            onClick={() => { setEditHost(undefined); setShowForm(true); }}
          >
            Add Host
          </button>
          <button
            className="btn import-btn"
            onClick={openLocalShell}
            title="Open a local terminal tab"
          >
            Shell
          </button>
          <button className="btn import-btn" onClick={handleImport} disabled={importing}>
            {importing ? "Importing…" : "Import"}
          </button>
        </div>
      </aside>

      {dialogHost && (
        <ConnectDialog
          host={dialogHost}
          onConnect={(h) => doConnect(h)}
          onCancel={() => setDialogHost(null)}
        />
      )}

      {hostKeyPrompt && (
        <HostKeyDialog
          host={hostKeyPrompt.host}
          verdict={hostKeyPrompt.verdict}
          onTrust={handleTrustHostKey}
          onCancel={() => setHostKeyPrompt(null)}
        />
      )}

      {showForm && (
        <HostForm
          host={editHost}
          onClose={() => { setShowForm(false); setEditHost(undefined); }}
        />
      )}
    </>
  );
}
