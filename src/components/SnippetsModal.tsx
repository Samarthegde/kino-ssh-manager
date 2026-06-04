import { useState } from "react";
import { Snippet, useVaultStore } from "../store";

interface Props {
  onClose: () => void;
}

const BLANK: Snippet = { id: "", name: "", commands: "" };

export function SnippetsModal({ onClose }: Props) {
  const { snippets, saveSnippet, deleteSnippet } = useVaultStore();
  const [editing, setEditing] = useState<Snippet | null>(null);
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);

  async function handleSave() {
    if (!editing) return;
    if (!editing.name.trim()) {
      setError("Give the snippet a name.");
      return;
    }
    setSaving(true);
    setError("");
    try {
      await saveSnippet({ ...editing, name: editing.name.trim() });
      setEditing(null);
    } catch (e: any) {
      setError(String(e));
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete(id: string) {
    try {
      await deleteSnippet(id);
      if (editing?.id === id) setEditing(null);
    } catch (e: any) {
      setError(String(e));
    }
  }

  return (
    <div className="modal-overlay">
      <div className="modal" style={{ width: 640, maxHeight: "80vh", display: "flex", flexDirection: "column" }}>
        <div className="modal-header">
          <h2>Snippets</h2>
          <button className="icon-btn" onClick={onClose}>✕</button>
        </div>

        <div className="host-form" style={{ flex: 1, overflowY: "auto" }}>
          <p className="hint" style={{ marginTop: 0 }}>
            Reusable command blocks. Attach them to a host (in the host's form) to run automatically
            right after you connect. Each line is sent to the shell in order.
          </p>

          {editing ? (
            <div className="form-section">
              <div className="form-row">
                <label>Name</label>
                <input
                  value={editing.name}
                  onChange={(e) => setEditing({ ...editing, name: e.target.value })}
                  placeholder="e.g. Tail app logs"
                  autoFocus
                />
              </div>
              <div className="form-row">
                <label>Commands <span className="hint-inline">(one per line)</span></label>
                <textarea
                  className="mono"
                  rows={8}
                  value={editing.commands}
                  onChange={(e) => setEditing({ ...editing, commands: e.target.value })}
                  placeholder={"cd /var/www/app\nsource .venv/bin/activate\ntail -f logs/app.log"}
                  style={{ width: "100%", resize: "vertical" }}
                />
              </div>
              {error && <p className="form-error">{error}</p>}
              <div style={{ display: "flex", gap: 8 }}>
                <button className="btn btn-primary btn-sm" onClick={handleSave} disabled={saving}>
                  {saving ? "Saving…" : "Save snippet"}
                </button>
                <button className="btn btn-sm" onClick={() => { setEditing(null); setError(""); }} disabled={saving}>
                  Cancel
                </button>
              </div>
            </div>
          ) : (
            <>
              <button className="btn btn-primary btn-sm" onClick={() => { setEditing({ ...BLANK }); setError(""); }}>
                + New snippet
              </button>
              {error && <p className="form-error">{error}</p>}
              <div style={{ display: "flex", flexDirection: "column", gap: 10, marginTop: 14 }}>
                {snippets.length === 0 ? (
                  <p className="hint">No snippets yet.</p>
                ) : (
                  snippets.map((s) => (
                    <div
                      key={s.id}
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "flex-start",
                        gap: 12,
                        padding: "12px 14px",
                        background: "var(--color-surface)",
                        border: "1px solid var(--color-border)",
                        borderRadius: 8,
                      }}
                    >
                      <div style={{ minWidth: 0 }}>
                        <div style={{ fontWeight: 600, marginBottom: 4 }}>{s.name}</div>
                        <pre
                          className="mono"
                          style={{
                            margin: 0,
                            fontSize: 12,
                            color: "var(--color-text-dim)",
                            whiteSpace: "pre-wrap",
                            wordBreak: "break-word",
                          }}
                        >
                          {s.commands || "(empty)"}
                        </pre>
                      </div>
                      <div style={{ display: "flex", gap: 6, flexShrink: 0 }}>
                        <button className="btn btn-sm" onClick={() => { setEditing({ ...s }); setError(""); }}>Edit</button>
                        <button className="btn btn-sm" onClick={() => handleDelete(s.id)}>Delete</button>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </>
          )}
        </div>

        <div className="modal-footer">
          <button className="btn btn-primary" onClick={onClose}>Done</button>
        </div>
      </div>
    </div>
  );
}
