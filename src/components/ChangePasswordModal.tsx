import { useState } from "react";
import { useVaultStore } from "../store";

interface Props {
  onClose: () => void;
}

export function ChangePasswordModal({ onClose }: Props) {
  const { changeMasterPassword } = useVaultStore();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [done, setDone] = useState(false);

  async function handleSave() {
    if (!current || !next) {
      setError("Fill in all fields.");
      return;
    }
    if (next !== confirm) {
      setError("New passwords don't match.");
      return;
    }
    setSaving(true);
    setError("");
    try {
      await changeMasterPassword(current, next);
      setDone(true);
    } catch (e: any) {
      setError(String(e));
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="modal-overlay">
      <div className="modal" style={{ width: 440 }}>
        <div className="modal-header">
          <h2>Change Master Password</h2>
          <button className="icon-btn" onClick={onClose}>✕</button>
        </div>

        <div className="host-form">
          {done ? (
            <p className="hint" style={{ color: "var(--color-green)" }}>
              Master password changed. Your vault, history, and snippets were re-encrypted under the
              new password.
            </p>
          ) : (
            <>
              <p className="hint" style={{ marginTop: 0 }}>
                Re-encrypts the entire vault under a new password. There's no recovery if you forget
                it — store it safely.
              </p>
              <div className="form-row">
                <label>Current password</label>
                <input type="password" value={current} onChange={(e) => setCurrent(e.target.value)} autoFocus autoComplete="off" />
              </div>
              <div className="form-row">
                <label>New password</label>
                <input type="password" value={next} onChange={(e) => setNext(e.target.value)} autoComplete="off" />
              </div>
              <div className="form-row">
                <label>Confirm new password</label>
                <input
                  type="password"
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  autoComplete="off"
                  onKeyDown={(e) => e.key === "Enter" && handleSave()}
                />
              </div>
              {error && <p className="form-error">{error}</p>}
            </>
          )}
        </div>

        <div className="modal-footer">
          {done ? (
            <button className="btn btn-primary" onClick={onClose}>Done</button>
          ) : (
            <>
              <button className="btn" onClick={onClose} disabled={saving}>Cancel</button>
              <button className="btn btn-primary" onClick={handleSave} disabled={saving}>
                {saving ? "Re-encrypting…" : "Change password"}
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
