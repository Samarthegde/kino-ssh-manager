import { useCallback, useEffect, useState } from "react";
import { open as openDialog, save as saveDialog, confirm as confirmDialog } from "@tauri-apps/plugin-dialog";
import { listen } from "@tauri-apps/api/event";
import { Host, SftpEntry, useVaultStore } from "../store";

interface Props {
  sessionId: string;
  host: Host;
  onClose: () => void;
}

interface TransferProgress {
  direction: "download" | "upload";
  name: string;
  transferred: number;
  total: number;
  done: boolean;
}

function parentPath(path: string): string {
  if (path === "/" || !path.includes("/")) return "/";
  const trimmed = path.replace(/\/+$/, "");
  const idx = trimmed.lastIndexOf("/");
  return idx <= 0 ? "/" : trimmed.slice(0, idx);
}

function joinPath(dir: string, name: string): string {
  return dir.endsWith("/") ? `${dir}${name}` : `${dir}/${name}`;
}

function baseName(localPath: string): string {
  const parts = localPath.split(/[/\\]/);
  return parts[parts.length - 1] || localPath;
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let size = bytes / 1024;
  let i = 0;
  while (size >= 1024 && i < units.length - 1) {
    size /= 1024;
    i++;
  }
  return `${size.toFixed(1)} ${units[i]}`;
}

export function SftpModal({ sessionId, host, onClose }: Props) {
  const { sftpOpen, sftpList, sftpDownload, sftpUpload, sftpRename, sftpDelete, sftpMkdir, sftpChmod, sftpClose } =
    useVaultStore();
  const [path, setPath] = useState("");
  const [entries, setEntries] = useState<SftpEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState("");

  // Mutation UI state
  const [creatingFolder, setCreatingFolder] = useState(false);
  const [folderName, setFolderName] = useState("");
  const [renamingPath, setRenamingPath] = useState<string | null>(null);
  const [renameValue, setRenameValue] = useState("");
  const [confirmingDelete, setConfirmingDelete] = useState<string | null>(null);
  const [chmodPath, setChmodPath] = useState<string | null>(null);
  const [chmodValue, setChmodValue] = useState("");
  const [progress, setProgress] = useState<TransferProgress | null>(null);

  const navigate = useCallback(
    async (target: string) => {
      setLoading(true);
      setError("");
      setRenamingPath(null);
      setConfirmingDelete(null);
      setChmodPath(null);
      try {
        const list = await sftpList(sessionId, target);
        setEntries(list);
        setPath(target);
      } catch (e: any) {
        setError(String(e));
      } finally {
        setLoading(false);
      }
    },
    [sessionId, sftpList]
  );

  // Transfer progress events from the backend (one transfer at a time per session).
  useEffect(() => {
    const unlisten = listen<TransferProgress>(`sftp-progress-${sessionId}`, (event) => {
      setProgress(event.payload.done ? null : event.payload);
    });
    return () => {
      unlisten.then((fn) => fn());
    };
  }, [sessionId]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const home = await sftpOpen(sessionId, host);
        if (cancelled) return;
        await navigate(home);
      } catch (e: any) {
        if (!cancelled) {
          setError(String(e));
          setLoading(false);
        }
      }
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function handleClose() {
    sftpClose(sessionId).catch(() => {});
    onClose();
  }

  async function handleDownload(entry: SftpEntry) {
    const local = await saveDialog({ defaultPath: entry.name });
    if (!local) return;
    setBusy(entry.path);
    setError("");
    try {
      await sftpDownload(sessionId, entry.path, local);
    } catch (e: any) {
      setError(String(e));
    } finally {
      setBusy(null);
      setProgress(null);
    }
  }

  async function handleUpload() {
    const selected = await openDialog({ multiple: false });
    if (!selected) return;
    const local = Array.isArray(selected) ? selected[0] : selected;
    const name = baseName(local);
    if (entries.some((e) => e.name === name && !e.is_dir)) {
      const ok = await confirmDialog(`"${name}" already exists here. Overwrite it?`, {
        title: "Overwrite file?",
        kind: "warning",
      });
      if (!ok) return;
    }
    const remote = joinPath(path, name);
    setBusy("__upload__");
    setError("");
    try {
      await sftpUpload(sessionId, local, remote);
      await navigate(path);
    } catch (e: any) {
      setError(String(e));
    } finally {
      setBusy(null);
      setProgress(null);
    }
  }

  async function handleMkdir() {
    const name = folderName.trim();
    if (!name) return;
    setBusy("__mkdir__");
    setError("");
    try {
      await sftpMkdir(sessionId, joinPath(path, name));
      setCreatingFolder(false);
      setFolderName("");
      await navigate(path);
    } catch (e: any) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  }

  async function handleRename(entry: SftpEntry) {
    const name = renameValue.trim();
    if (!name || name === entry.name) {
      setRenamingPath(null);
      return;
    }
    setBusy(entry.path);
    setError("");
    try {
      await sftpRename(sessionId, entry.path, joinPath(path, name));
      setRenamingPath(null);
      setRenameValue("");
      await navigate(path);
    } catch (e: any) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  }

  async function handleDelete(entry: SftpEntry) {
    setBusy(entry.path);
    setError("");
    try {
      await sftpDelete(sessionId, entry.path, entry.is_dir);
      setConfirmingDelete(null);
      await navigate(path);
    } catch (e: any) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  }

  async function handleChmod(entry: SftpEntry) {
    const mode = parseInt(chmodValue.trim(), 8);
    if (!/^[0-7]{3,4}$/.test(chmodValue.trim()) || Number.isNaN(mode)) {
      setError("Enter octal permissions like 644 or 755.");
      return;
    }
    setBusy(entry.path);
    setError("");
    try {
      await sftpChmod(sessionId, entry.path, mode);
      setChmodPath(null);
      await navigate(path);
    } catch (e: any) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  }

  const atRoot = path === "/" || path === "";

  return (
    <div className="modal-overlay">
      <div className="modal" style={{ width: 700, maxHeight: "82vh", display: "flex", flexDirection: "column" }}>
        <div className="modal-header">
          <h2>Files — {host.name}</h2>
          <button className="icon-btn" onClick={handleClose}>✕</button>
        </div>

        <div className="sftp-toolbar">
          <button className="btn btn-sm" onClick={() => navigate(parentPath(path))} disabled={loading || atRoot} title="Up one level">
            ↑ Up
          </button>
          <button className="btn btn-sm" onClick={() => navigate(path)} disabled={loading} title="Refresh">
            ⟳
          </button>
          <code className="sftp-path" title={path}>{path || "…"}</code>
          <button
            className="btn btn-sm"
            onClick={() => { setCreatingFolder(true); setFolderName(""); }}
            disabled={loading}
          >
            + Folder
          </button>
          <button className="btn btn-sm btn-primary" onClick={handleUpload} disabled={loading || busy === "__upload__"}>
            {busy === "__upload__" ? "Uploading…" : "↥ Upload"}
          </button>
        </div>

        {creatingFolder && (
          <div className="sftp-inline-form">
            <input
              autoFocus
              placeholder="New folder name"
              value={folderName}
              onChange={(e) => setFolderName(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") handleMkdir();
                if (e.key === "Escape") setCreatingFolder(false);
              }}
            />
            <button className="btn btn-sm btn-primary" onClick={handleMkdir} disabled={busy === "__mkdir__" || !folderName.trim()}>
              Create
            </button>
            <button className="btn btn-sm" onClick={() => setCreatingFolder(false)}>Cancel</button>
          </div>
        )}

        {progress && (
          <div className="sftp-progress">
            <div className="sftp-progress-head">
              <span className="sftp-progress-label">
                {progress.direction === "upload" ? "Uploading" : "Downloading"} {progress.name}
              </span>
              <span className="sftp-progress-pct">
                {progress.total > 0
                  ? `${Math.floor((progress.transferred / progress.total) * 100)}%`
                  : formatSize(progress.transferred)}
              </span>
            </div>
            <div className="sftp-progress-track">
              <div
                className={`sftp-progress-fill ${progress.total === 0 ? "indeterminate" : ""}`}
                style={progress.total > 0 ? { width: `${(progress.transferred / progress.total) * 100}%` } : undefined}
              />
            </div>
          </div>
        )}

        {error && <p className="form-error" style={{ padding: "0 20px" }}>{error}</p>}

        <div className="sftp-list">
          {loading ? (
            <p className="hint" style={{ textAlign: "center" }}>Loading…</p>
          ) : entries.length === 0 ? (
            <p className="hint" style={{ textAlign: "center" }}>Empty directory.</p>
          ) : (
            entries.map((entry) => {
              const rowBusy = busy === entry.path;
              const isRenaming = renamingPath === entry.path;
              const isConfirming = confirmingDelete === entry.path;
              const isChmod = chmodPath === entry.path;
              const octal = (entry.perm & 0o777).toString(8).padStart(3, "0");
              return (
                <div
                  key={entry.path}
                  className={`sftp-row ${entry.is_dir ? "is-dir" : ""}`}
                  onDoubleClick={() => !isRenaming && entry.is_dir && navigate(entry.path)}
                >
                  <span className="sftp-icon">
                    {entry.is_dir ? (
                      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
                      </svg>
                    ) : (
                      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                        <polyline points="14 2 14 8 20 8" />
                      </svg>
                    )}
                  </span>

                  {isRenaming ? (
                    <input
                      className="sftp-rename-input"
                      autoFocus
                      value={renameValue}
                      onChange={(e) => setRenameValue(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") handleRename(entry);
                        if (e.key === "Escape") setRenamingPath(null);
                      }}
                    />
                  ) : (
                    <span
                      className="sftp-name"
                      onClick={() => entry.is_dir && navigate(entry.path)}
                      style={{ cursor: entry.is_dir ? "pointer" : "default" }}
                    >
                      {entry.name}
                    </span>
                  )}

                  {entry.perm > 0 && (
                    <button
                      className="sftp-perm mono"
                      title="Change permissions"
                      onClick={() => { setChmodPath(entry.path); setChmodValue(octal); setError(""); }}
                    >
                      {octal}
                    </button>
                  )}

                  <span className="sftp-size">{entry.is_dir ? "" : formatSize(entry.size)}</span>

                  <div className="sftp-actions">
                    {isChmod ? (
                      <>
                        <input
                          className="sftp-chmod-input mono"
                          autoFocus
                          value={chmodValue}
                          onChange={(e) => setChmodValue(e.target.value)}
                          onKeyDown={(e) => {
                            if (e.key === "Enter") handleChmod(entry);
                            if (e.key === "Escape") setChmodPath(null);
                          }}
                        />
                        <button className="btn btn-sm btn-primary" onClick={() => handleChmod(entry)} disabled={rowBusy}>Set</button>
                        <button className="btn btn-sm" onClick={() => setChmodPath(null)} disabled={rowBusy}>Cancel</button>
                      </>
                    ) : isRenaming ? (
                      <>
                        <button className="btn btn-sm btn-primary" onClick={() => handleRename(entry)} disabled={rowBusy}>Save</button>
                        <button className="btn btn-sm" onClick={() => setRenamingPath(null)} disabled={rowBusy}>Cancel</button>
                      </>
                    ) : isConfirming ? (
                      <>
                        <span className="sftp-confirm-label">Delete?</span>
                        <button className="btn btn-sm btn-danger" onClick={() => handleDelete(entry)} disabled={rowBusy}>
                          {rowBusy ? "…" : "Yes"}
                        </button>
                        <button className="btn btn-sm" onClick={() => setConfirmingDelete(null)} disabled={rowBusy}>No</button>
                      </>
                    ) : (
                      <>
                        {!entry.is_dir && (
                          <button className="btn btn-sm" onClick={() => handleDownload(entry)} disabled={rowBusy}>
                            {rowBusy ? "…" : "Download"}
                          </button>
                        )}
                        <button
                          className="btn btn-sm"
                          onClick={() => { setRenamingPath(entry.path); setRenameValue(entry.name); }}
                          disabled={rowBusy}
                        >
                          Rename
                        </button>
                        <button className="btn btn-sm" onClick={() => setConfirmingDelete(entry.path)} disabled={rowBusy}>
                          Delete
                        </button>
                      </>
                    )}
                  </div>
                </div>
              );
            })
          )}
        </div>

        <div className="modal-footer">
          <button className="btn btn-primary" onClick={handleClose}>Close</button>
        </div>
      </div>
    </div>
  );
}
