import { useState } from "react";
import { DefaultAuth, Host, useVaultStore } from "../store";

const PREF_KEY = (hostId: string) => `ssh-mgr:auth-pref:${hostId}`;

export function getSavedAuthPref(hostId: string): DefaultAuth | null {
  return (localStorage.getItem(PREF_KEY(hostId)) as DefaultAuth) ?? null;
}

interface Props {
  host: Host;
  onConnect: (host: Host) => void;
  onCancel: () => void;
}

export function ConnectDialog({ host, onConnect, onCancel }: Props) {
  const { saveHost } = useVaultStore();

  const savedPref = getSavedAuthPref(host.id);
  const hasKey = !!host.private_key;
  const hasPassword = !!host.password;

  const [choice, setChoice] = useState<DefaultAuth>(
    savedPref ?? host.default_auth
  );
  const [password, setPassword] = useState(host.password ?? "");
  const [rememberChoice, setRememberChoice] = useState(!!savedPref);
  const [savePassword, setSavePassword] = useState(hasPassword);
  const [error, setError] = useState("");

  async function handleConnect() {
    if (choice === "Password" && !password) {
      setError("Enter a password to continue");
      return;
    }

    if (rememberChoice) {
      localStorage.setItem(PREF_KEY(host.id), choice);
    } else {
      localStorage.removeItem(PREF_KEY(host.id));
    }

    // Persist or clear password in vault if changed
    let updatedHost = { ...host, default_auth: choice };
    if (choice === "Password") {
      const newPw = savePassword ? password : null;
      if (newPw !== (host.password ?? null)) {
        updatedHost = { ...updatedHost, password: newPw };
        await saveHost(updatedHost);
      }
    }

    onConnect(updatedHost);
  }

  return (
    <div className="modal-overlay">
      <div className="modal connect-modal">
        <div className="modal-header">
          <div>
            <h2>Connect to {host.name}</h2>
            <span className="connect-host-meta">
              {host.username}@{host.hostname}:{host.port}
            </span>
          </div>
          <button className="icon-btn" onClick={onCancel}>✕</button>
        </div>

        <div className="connect-body">
          <p className="connect-label">Authentication method</p>

          {hasKey && (
            <label className={`auth-option ${choice === "SshKey" ? "selected" : ""}`}>
              <input
                type="radio"
                name="auth"
                checked={choice === "SshKey"}
                onChange={() => setChoice("SshKey")}
              />
              <div className="auth-option-content">
                <span className="auth-option-title">SSH Key</span>
                <span className="auth-option-desc">Use the stored ed25519 key</span>
              </div>
              <span className="auth-badge key">Key</span>
            </label>
          )}

          <label className={`auth-option ${choice === "Password" ? "selected" : ""}`}>
            <input
              type="radio"
              name="auth"
              checked={choice === "Password"}
              onChange={() => setChoice("Password")}
            />
            <div className="auth-option-content">
              <span className="auth-option-title">Password</span>
              <span className="auth-option-desc">
                {hasPassword ? "Saved password loaded" : "Enter password manually"}
              </span>
            </div>
            <span className="auth-badge pw">PW</span>
          </label>

          {choice === "Password" && (
            <>
              <input
                type="password"
                className="connect-pw-input"
                placeholder="Server password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleConnect()}
                autoFocus={!hasPassword}
              />
              <label className="remember-row">
                <input
                  type="checkbox"
                  checked={savePassword}
                  onChange={(e) => setSavePassword(e.target.checked)}
                />
                <span>
                  Save password in vault
                  {hasPassword && !savePassword && (
                    <span className="hint-inline"> (will remove saved password)</span>
                  )}
                </span>
              </label>
            </>
          )}

          {error && <p className="form-error">{error}</p>}

          <label className="remember-row">
            <input
              type="checkbox"
              checked={rememberChoice}
              onChange={(e) => setRememberChoice(e.target.checked)}
            />
            <span>Remember auth method for {host.name}</span>
          </label>
        </div>

        <div className="modal-footer" style={{ padding: "0 20px 20px" }}>
          <button className="btn" onClick={onCancel}>Cancel</button>
          <button className="btn btn-primary" onClick={handleConnect}>Connect</button>
        </div>
      </div>
    </div>
  );
}
