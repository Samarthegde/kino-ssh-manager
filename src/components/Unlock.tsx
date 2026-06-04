import { useState } from "react";
import { useVaultStore } from "../store";

export function Unlock() {
  const [password, setPassword] = useState("");
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
              <input
                type="password"
                className="unlock-input"
                placeholder="Master password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoFocus
              />
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
