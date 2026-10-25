import { useState, useEffect } from "react";
import { useVaultStore } from "../store";
import { getVersion } from "@tauri-apps/api/app";
import { openUrl } from "@tauri-apps/plugin-opener";
import { ReleaseNote, notesFor, shouldShowNotes } from "../releaseNotes";
import { WhatsNew } from "./WhatsNew";

const REPO_URL = "https://github.com/Samarthegde/kino-ssh-manager";

export function Unlock() {
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [isNew, setIsNew] = useState<boolean | null>(null);
  const [mode, setMode] = useState<"vault" | "restore" | "recover">("vault");

  // Recovery fields. The key is a textarea because people paste it with the
  // line breaks of whatever they wrote it on.
  const [recoveryKey, setRecoveryKey] = useState("");
  const [recoveryNewPw, setRecoveryNewPw] = useState("");
  const [recoveryConfirm, setRecoveryConfirm] = useState("");
  const [kitExists, setKitExists] = useState(false);

  // Restore-from-cloud fields
  const [restoreFrom, setRestoreFrom] = useState("github");
  const [folder, setFolder] = useState("");
  const [owner, setOwner] = useState("");
  const [repo, setRepo] = useState("");
  const [path, setPath] = useState("vault.enc");
  const [branch, setBranch] = useState("main");
  const [token, setToken] = useState("");
  const [version, setVersion] = useState("");
  const [whatsNew, setWhatsNew] = useState<ReleaseNote | null>(null);

  const {
    unlock,
    checkVaultExists,
    syncRestore,
    updateInfo,
    syncFolderPath,
    recoveryStatus,
    recoverVault,
  } = useVaultStore();

  useState(() => {
    checkVaultExists().then((exists) => setIsNew(!exists));
  });

  useEffect(() => {
    getVersion().then(setVersion).catch(() => setVersion(""));
    syncFolderPath().then(setFolder).catch(() => {});
    // Offered only when there is something to recover with: a link that leads
    // to "there is no kit on this machine" is a link that should not be there.
    recoveryStatus()
      .then((s) => setKitExists(s.exists))
      .catch(() => setKitExists(false));
  }, [syncFolderPath, recoveryStatus]);

  // Both answers are needed before the notes can be judged: which version this
  // is, and whether a vault already exists - a fresh install is not an upgrade
  // and gets nothing. `isNew` is null until that check comes back.
  useEffect(() => {
    if (!version || isNew === null) return;
    if (shouldShowNotes(version, !isNew)) setWhatsNew(notesFor(version) ?? null);
  }, [version, isNew]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!password) return;
    // On first-time vault creation, require the password to be confirmed.
    if (isNew && password !== confirm) {
      setError("Passwords don't match.");
      return;
    }
    setLoading(true);
    setError("");
    try {
      await unlock(password);
    } catch (err: any) {
      setError(err?.message || String(err));
    } finally {
      setLoading(false);
    }
  }

  async function handleRecover(e: React.FormEvent) {
    e.preventDefault();
    if (!recoveryKey.trim() || !recoveryNewPw) return;
    if (recoveryNewPw !== recoveryConfirm) {
      setError("The new passwords don't match.");
      return;
    }
    setLoading(true);
    setError("");
    try {
      await recoverVault(recoveryKey.trim(), recoveryNewPw);
    } catch (err: any) {
      setError(err?.message || String(err));
    } finally {
      setLoading(false);
    }
  }

  async function handleRestore(e: React.FormEvent) {
    e.preventDefault();
    const ready =
      restoreFrom === "folder"
        ? !!password
        : owner.trim() && repo.trim() && token.trim() && password;
    if (!ready) return;
    setLoading(true);
    setError("");
    try {
      await syncRestore({ provider: restoreFrom, token, owner, repo, path, branch }, password);
    } catch (err: any) {
      setError(err?.message || String(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="unlock-screen">
      <div className="unlock-card">
        <div className="unlock-logo">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <rect x="2" y="7" width="20" height="14" rx="2" ry="2" />
            <path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16" />
          </svg>
        </div>
        <h1>Kino SSH<span className="stop">.</span></h1>
        <p className="unlock-version">Version {version}</p>

        {updateInfo?.available && (
          <button
            className="unlock-update"
            onClick={() => openUrl(updateInfo.url).catch(() => {})}
            title={`v${updateInfo.current} - v${updateInfo.latest}`}
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 19V5" />
              <polyline points="5 12 12 5 19 12" />
            </svg>
            Update available - v{updateInfo.latest}
          </button>
        )}

        {mode === "recover" ? (
          <>
            <p className="unlock-subtitle">
              Type the recovery key you wrote down. It opens this vault once, and sets the new
              master password you choose here.
            </p>
            <form onSubmit={handleRecover}>
              <textarea
                className="unlock-input recovery-input mono"
                placeholder="XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"
                value={recoveryKey}
                onChange={(e) => setRecoveryKey(e.target.value)}
                rows={3}
                spellCheck={false}
                autoFocus
              />
              <input
                type="password"
                className="unlock-input"
                placeholder="New master password"
                value={recoveryNewPw}
                onChange={(e) => setRecoveryNewPw(e.target.value)}
                autoComplete="new-password"
              />
              <input
                type="password"
                className="unlock-input"
                placeholder="Confirm new master password"
                value={recoveryConfirm}
                onChange={(e) => setRecoveryConfirm(e.target.value)}
                autoComplete="new-password"
              />
              <p className="unlock-hint">
                Capitals, dashes and spaces don't matter. The key is spent afterwards - make a
                new one from Settings once you are in.
              </p>
              {error && <p className="unlock-error">{error}</p>}
              <button type="submit" className="btn btn-primary unlock-btn" disabled={loading}>
                {loading ? "Opening…" : "Recover vault"}
              </button>
            </form>
            <button
              type="button"
              className="unlock-link"
              onClick={() => { setMode("vault"); setError(""); }}
            >
              ← Back
            </button>
          </>
        ) : mode === "vault" ? (
          <>
            <p className="unlock-subtitle">
              {isNew === null
                ? ""
                : isNew
                  ? "Create your master password to secure your vault"
                  : "Enter your master password to unlock"}
            </p>
            <form onSubmit={handleSubmit}>
              <div className="unlock-pw-wrap">
                <input
                  type={showPassword ? "text" : "password"}
                  className="unlock-input"
                  placeholder="Master password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoFocus
                />
                <button
                  type="button"
                  className="unlock-pw-toggle"
                  onClick={() => setShowPassword((v) => !v)}
                  title={showPassword ? "Hide password" : "Show password"}
                  tabIndex={-1}
                >
                  {showPassword ? (
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" />
                      <line x1="1" y1="1" x2="23" y2="23" />
                    </svg>
                  ) : (
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                      <circle cx="12" cy="12" r="3" />
                    </svg>
                  )}
                </button>
              </div>
              {isNew && (
                <input
                  type={showPassword ? "text" : "password"}
                  className="unlock-input"
                  placeholder="Confirm master password"
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                />
              )}
              {isNew && (
                <p className="unlock-hint">
                  Store it safely. Nothing here can recover it - you can make a recovery key
                  afterwards, in Settings, and that is the only way back in.
                </p>
              )}
              {error && <p className="unlock-error">{error}</p>}
              <button type="submit" className="btn btn-primary unlock-btn" disabled={loading}>
                {loading ? "Unlocking…" : isNew ? "Create Vault" : "Unlock"}
              </button>
            </form>
            {isNew && (
              <button
                type="button"
                className="unlock-link"
                onClick={() => { setMode("restore"); setError(""); }}
              >
                Restore from cloud sync -
              </button>
            )}
            {!isNew && kitExists && (
              <button
                type="button"
                className="unlock-link"
                onClick={() => { setMode("recover"); setError(""); }}
              >
                Forgotten it? Use your recovery key -
              </button>
            )}
          </>
        ) : (
          <>
            <p className="unlock-subtitle">
              Pull your vault from wherever your other device syncs it. Use the same master
              password as that device.
            </p>
            <div className="unlock-restore-from">
              <button
                type="button"
                className={`audit-tab ${restoreFrom === "github" ? "on" : ""}`}
                onClick={() => setRestoreFrom("github")}
              >
                GitHub repo
              </button>
              <button
                type="button"
                className={`audit-tab ${restoreFrom === "folder" ? "on" : ""}`}
                onClick={() => setRestoreFrom("folder")}
              >
                A folder
              </button>
            </div>
            <form onSubmit={handleRestore}>
              {restoreFrom === "folder" ? (
                // Nothing to fill in: the folder is the same on every machine,
                // so the master password is the only thing this device lacks.
                <p className="unlock-foot-note">
                  Reading <span className="mono">{folder || "Documents/ssh-manager"}</span>.
                  Make sure your sync tool has carried it to this machine first.
                </p>
              ) : (
              <>
              <div className="form-row two-col">
                <input
                  className="unlock-input"
                  placeholder="Owner"
                  value={owner}
                  onChange={(e) => setOwner(e.target.value)}
                  autoFocus
                />
                <input
                  className="unlock-input"
                  placeholder="Repository"
                  value={repo}
                  onChange={(e) => setRepo(e.target.value)}
                />
              </div>
              <div className="form-row two-col">
                <input
                  className="unlock-input"
                  placeholder="File path"
                  value={path}
                  onChange={(e) => setPath(e.target.value)}
                />
                <input
                  className="unlock-input"
                  placeholder="Branch"
                  value={branch}
                  onChange={(e) => setBranch(e.target.value)}
                />
              </div>
              <input
                type="password"
                className="unlock-input"
                placeholder="Personal access token (Contents: read)"
                value={token}
                onChange={(e) => setToken(e.target.value)}
                autoComplete="off"
              />
              </>
              )}
              <input
                type="password"
                className="unlock-input"
                placeholder="Master password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
              {error && <p className="unlock-error">{error}</p>}
              <button type="submit" className="btn btn-primary unlock-btn" disabled={loading}>
                {loading ? "Restoring…" : "Restore Vault"}
              </button>
            </form>
            <button
              type="button"
              className="unlock-link"
              onClick={() => { setMode("vault"); setError(""); }}
            >
              ← Back
            </button>
          </>
        )}

        <div className="unlock-foot">
          <button
            className="btn btn-sm about-repo-btn"
            onClick={() => openUrl(REPO_URL).catch(() => { })}
          >
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22" />
            </svg>
            GitHub
          </button>
          <span className="unlock-foot-note">End&#8209;to&#8209;end encrypted</span>
        </div>
      </div>

      {whatsNew && <WhatsNew note={whatsNew} onClose={() => setWhatsNew(null)} />}
    </div>
  );
}
