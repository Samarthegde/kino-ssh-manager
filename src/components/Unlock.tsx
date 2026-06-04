import { useState } from "react";
import { useVaultStore } from "../store";

export function Unlock() {
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [isNew, setIsNew] = useState<boolean | null>(null);
  const [mode, setMode] = useState<"vault" | "restore">("vault");

  // Restore-from-cloud fields
  const [owner, setOwner] = useState("");
  const [repo, setRepo] = useState("");
  const [path, setPath] = useState("vault.enc");
  const [branch, setBranch] = useState("main");
  const [token, setToken] = useState("");

  const { unlock, checkVaultExists, syncRestore } = useVaultStore();

  useState(() => {
    checkVaultExists().then((exists) => setIsNew(!exists));
  });

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

  async function handleRestore(e: React.FormEvent) {
    e.preventDefault();
    if (!owner.trim() || !repo.trim() || !token.trim() || !password) return;
    setLoading(true);
    setError("");
    try {
      await syncRestore({ token, owner, repo, path, branch }, password);
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
        <h1>Kino SSH Manager</h1>

        {mode === "vault" ? (
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
                  There's no recovery if you forget this — store it safely.
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
                Restore from cloud sync →
              </button>
            )}
          </>
        ) : (
          <>
            <p className="unlock-subtitle">
              Pull your vault from a private GitHub repo. Use the same master password as your
              other device.
            </p>
            <form onSubmit={handleRestore}>
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
      </div>
    </div>
  );
}
