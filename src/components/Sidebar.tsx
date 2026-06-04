import { useState } from "react";
import { Host, HostKeyVerdict, useVaultStore } from "../store";
import { ConnectDialog, getSavedAuthPref } from "./ConnectDialog";
import { ExportMenu, promptImportHost } from "./ExportMenu";
import { HostForm } from "./HostForm";
import { HostKeyDialog } from "./HostKeyDialog";

type HostKeyPrompt = { host: Host; verdict: Extract<HostKeyVerdict, { status: "new" | "changed" }> };

export function Sidebar() {
  const { hosts, connectToHost, deleteHost, importHostFromFile, verifyHostKey, trustHostKey } =
    useVaultStore();
  const [showForm, setShowForm] = useState(false);
  const [editHost, setEditHost] = useState<Host | undefined>();
  const [connecting, setConnecting] = useState<string | null>(null);
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null);
  const [dialogHost, setDialogHost] = useState<Host | null>(null);
  const [hostKeyPrompt, setHostKeyPrompt] = useState<HostKeyPrompt | null>(null);
  const [importing, setImporting] = useState(false);
  const [query, setQuery] = useState("");

  const q = query.trim().toLowerCase();
  const visibleHosts = q
    ? hosts.filter((h) =>
        [h.name, h.hostname, h.username].some((f) => f.toLowerCase().includes(q))
      )
    : hosts;

  // Actually open the session — assumes the host key is already trusted.
  async function establish(host: Host) {
    setConnecting(host.id);
    try {
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
      <aside className="sidebar">
        <div className="sidebar-header">
          <span className="sidebar-title">Hosts</span>
        </div>

        {hosts.length > 0 && (
          <div className="sidebar-search">
            <input
              type="text"
              placeholder="Search hosts…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </div>
        )}

        <div className="host-list">
          {hosts.length === 0 ? (
            <p className="empty-state">No hosts yet.<br />Add one below.</p>
          ) : visibleHosts.length === 0 ? (
            <p className="empty-state">No matches for “{query}”.</p>
          ) : null}
          {visibleHosts.map((host) => (
            <div
              key={host.id}
              className="host-item"
              style={host.color ? { borderLeft: `3px solid ${host.color}` } : undefined}
            >
              <div className="host-info" onClick={() => handleConnect(host)}>
                <span className="host-name">{host.name}</span>
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

        <div className="sidebar-footer">
          <button
            className="btn btn-primary add-btn"
            onClick={() => { setEditHost(undefined); setShowForm(true); }}
          >
            + Add Host
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
