import { useEffect, useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { useVaultStore, isAutoSyncEnabled, setAutoSyncEnabled } from "../store";

interface Props {
  onClose: () => void;
}

type Status =
  | { kind: "idle" }
  | { kind: "busy"; msg: string }
  | { kind: "ok"; msg: string }
  | { kind: "error"; msg: string }
  | { kind: "conflict" };

export function SyncModal({ onClose }: Props) {
  const { syncGetConfig, syncSetConfig, syncTest, syncPush, syncPull } = useVaultStore();

  const [provider, setProvider] = useState("github");
  const [folder, setFolder] = useState("");
  const [owner, setOwner] = useState("");
  const [repo, setRepo] = useState("");
  const [path, setPath] = useState("vault.enc");
  const [branch, setBranch] = useState("main");
  const [token, setToken] = useState("");
  const [hasToken, setHasToken] = useState(false);
  const [lastSynced, setLastSynced] = useState<number | null>(null);

  const [pullPassword, setPullPassword] = useState("");
  const [showPullPrompt, setShowPullPrompt] = useState(false);
  const [status, setStatus] = useState<Status>({ kind: "idle" });
  const [autoSync, setAutoSync] = useState(isAutoSyncEnabled());

  useEffect(() => {
    syncGetConfig()
      .then((cfg) => {
        if (!cfg) return;
        setProvider(cfg.provider || "github");
        setFolder(cfg.folder || "");
        setOwner(cfg.owner);
        setRepo(cfg.repo);
        setPath(cfg.path || "vault.enc");
        setBranch(cfg.branch || "main");
        setHasToken(cfg.has_token);
        setLastSynced(cfg.last_synced_at ?? null);
      })
      .catch((e) => setStatus({ kind: "error", msg: String(e) }));
  }, [syncGetConfig]);

  const isFolder = provider === "folder";
  const canSave = isFolder
    ? !!folder.trim()
    : !!(owner.trim() && repo.trim() && (hasToken || token.trim()));

  async function pickFolder() {
    const picked = await open({
      directory: true,
      title: "Folder to sync through",
    });
    if (typeof picked === "string") setFolder(picked);
  }

  async function persistConfig(): Promise<boolean> {
    try {
      const view = await syncSetConfig({ provider, token, owner, repo, path, branch, folder });
      setHasToken(view.has_token);
      setLastSynced(view.last_synced_at ?? null);
      setToken(""); // never keep the token in component state after saving
      return true;
    } catch (e) {
      setStatus({ kind: "error", msg: String(e) });
      return false;
    }
  }

  async function handleSave() {
    setStatus({ kind: "busy", msg: "Saving settings…" });
    if (await persistConfig()) setStatus({ kind: "ok", msg: "Settings saved." });
  }

  async function handleTest() {
    setStatus({ kind: "busy", msg: "Testing connection…" });
    if (!(await persistConfig())) return;
    try {
      const exists = await syncTest();
      setStatus({
        kind: "ok",
        msg: exists
          ? "Connected. A vault already exists in this repo."
          : "Connected. No vault pushed yet - use Push to create it.",
      });
    } catch (e) {
      setStatus({ kind: "error", msg: String(e) });
    }
  }

  async function handlePush(force: boolean) {
    setStatus({ kind: "busy", msg: force ? "Overwriting cloud…" : "Pushing to cloud…" });
    if (!(await persistConfig())) return;
    try {
      const outcome = await syncPush(force);
      if (outcome.kind === "conflict") {
        setStatus({ kind: "conflict" });
      } else {
        setLastSynced(outcome.synced_at);
        setStatus({ kind: "ok", msg: "Pushed to cloud." });
      }
    } catch (e) {
      setStatus({ kind: "error", msg: String(e) });
    }
  }

  async function handlePull() {
    setStatus({ kind: "busy", msg: "Pulling from cloud…" });
    if (!(await persistConfig())) {
      setShowPullPrompt(false);
      return;
    }
    try {
      const outcome = await syncPull(pullPassword);
      setPullPassword("");
      setShowPullPrompt(false);
      if (outcome.kind === "no_remote") {
        setStatus({ kind: "error", msg: "Nothing in the cloud yet - push first." });
      } else if (outcome.kind === "up_to_date") {
        setStatus({ kind: "ok", msg: "Already up to date." });
      } else {
        setLastSynced(outcome.synced_at);
        setStatus({ kind: "ok", msg: `Pulled ${outcome.hosts.length} host(s) from cloud.` });
      }
    } catch (e) {
      setStatus({ kind: "error", msg: String(e) });
    }
  }

  const busy = status.kind === "busy";

  return (
    <div className="modal-overlay">
      <div className="modal" style={{ width: 520 }}>
        <div className="modal-header">
          <h2>Cloud Sync</h2>
          <button className="icon-btn" onClick={onClose}>✕</button>
        </div>

        <div className="host-form">
          <p className="hint" style={{ marginTop: 0 }}>
            Syncs the <strong>encrypted</strong> vault. Your master password and credentials
            never leave this device - the other end only ever holds ciphertext. Use the same
            master password on every device.
          </p>

          <div className="form-row">
            <label>Sync through</label>
            <div className="sync-providers">
              <label className="sync-provider">
                <input
                  type="radio"
                  checked={!isFolder}
                  onChange={() => setProvider("github")}
                />
                <span>
                  <strong>A private GitHub repo</strong>
                  <span className="hint-inline">Needs a token. Detects conflicts properly.</span>
                </span>
              </label>
              <label className="sync-provider">
                <input
                  type="radio"
                  checked={isFolder}
                  onChange={() => setProvider("folder")}
                />
                <span>
                  <strong>A folder</strong>
                  <span className="hint-inline">
                    One that Dropbox, Syncthing, iCloud Drive, OneDrive or a network share
                    already syncs. No account, no token.
                  </span>
                </span>
              </label>
            </div>
          </div>

          {isFolder ? (
            <>
              <div className="form-row">
                <label>Folder</label>
                <div className="sync-folder-row">
                  <input
                    value={folder}
                    onChange={(e) => setFolder(e.target.value)}
                    placeholder="~/Dropbox/Kino"
                  />
                  <button className="btn btn-sm" onClick={() => void pickFolder()}>
                    Choose…
                  </button>
                </div>
              </div>
              <p className="hint">
                Kino writes <span className="mono">vault.enc</span> and its sibling files there,
                and whatever you already use carries them to your other machines. Two devices
                writing in the same moment is the one case this cannot detect - the vault is
                only read when you unlock and written when you change something, so it takes
                some doing, and your sync tool will usually keep both copies if it happens.
              </p>
            </>
          ) : (
            <>
              <div className="form-row two-col">
                <div>
                  <label>Owner (user / org)</label>
                  <input value={owner} onChange={(e) => setOwner(e.target.value)} placeholder="your-username" />
                </div>
                <div>
                  <label>Repository</label>
                  <input value={repo} onChange={(e) => setRepo(e.target.value)} placeholder="ssh-vault" />
                </div>
              </div>

              <div className="form-row two-col">
                <div>
                  <label>File path</label>
                  <input value={path} onChange={(e) => setPath(e.target.value)} placeholder="vault.enc" />
                </div>
                <div>
                  <label>Branch</label>
                  <input value={branch} onChange={(e) => setBranch(e.target.value)} placeholder="main" />
                </div>
              </div>

              <div className="form-row">
                <label>
                  Personal access token{" "}
                  <span className="hint-inline">
                    {hasToken ? "(saved - leave blank to keep)" : "(fine-grained, Contents: read & write)"}
                  </span>
                </label>
                <input
                  type="password"
                  value={token}
                  onChange={(e) => setToken(e.target.value)}
                  placeholder={hasToken ? "••••••••••••" : "github_pat_…"}
                  autoComplete="off"
                />
              </div>
            </>
          )}

          {lastSynced && (
            <p className="hint">Last synced: {new Date(lastSynced * 1000).toLocaleString()}</p>
          )}

          <label className="remember-row" style={{ marginTop: 4 }}>
            <input
              type="checkbox"
              checked={autoSync}
              onChange={(e) => { setAutoSync(e.target.checked); setAutoSyncEnabled(e.target.checked); }}
            />
            Auto-sync: pull on unlock, push after every change
          </label>

          {status.kind === "error" && <p className="form-error">{status.msg}</p>}
          {status.kind === "ok" && (
            <p className="hint" style={{ color: "var(--green)" }}>{status.msg}</p>
          )}
          {status.kind === "busy" && <p className="hint">{status.msg}</p>}
          {status.kind === "conflict" && (
            <div className="form-error" style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              <span>
                The cloud vault changed since your last sync. Pull the cloud version, or force-push
                to overwrite it with this device's vault.
              </span>
              <div style={{ display: "flex", gap: 8 }}>
                <button className="btn btn-sm" onClick={() => setShowPullPrompt(true)} disabled={busy}>
                  Pull cloud
                </button>
                <button className="btn btn-sm" onClick={() => handlePush(true)} disabled={busy}>
                  Force push
                </button>
              </div>
            </div>
          )}

          {showPullPrompt && (
            <div className="form-row" style={{ marginTop: 8 }}>
              <label>Master password (to decrypt the pulled vault)</label>
              <input
                type="password"
                value={pullPassword}
                onChange={(e) => setPullPassword(e.target.value)}
                placeholder="Master password"
                autoFocus
                onKeyDown={(e) => e.key === "Enter" && pullPassword && handlePull()}
              />
              <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
                <button className="btn btn-primary btn-sm" onClick={handlePull} disabled={busy || !pullPassword}>
                  Confirm pull
                </button>
                <button className="btn btn-sm" onClick={() => { setShowPullPrompt(false); setPullPassword(""); }} disabled={busy}>
                  Cancel
                </button>
              </div>
              <p className="hint">Replaces the local vault. A backup is kept as vault.enc.bak.</p>
            </div>
          )}
        </div>

        <div className="modal-footer">
          <button className="btn" onClick={handleTest} disabled={busy || !canSave}>
            Test
          </button>
          <button className="btn" onClick={handleSave} disabled={busy || !canSave}>
            Save
          </button>
          <button
            className="btn"
            onClick={() => { setShowPullPrompt(true); setStatus({ kind: "idle" }); }}
            disabled={busy || !canSave}
          >
            Pull
          </button>
          <button className="btn btn-primary" onClick={() => handlePush(false)} disabled={busy || !canSave}>
            Push
          </button>
        </div>
      </div>
    </div>
  );
}
