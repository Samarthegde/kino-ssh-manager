import { useEffect, useMemo, useState } from "react";
import { Note, useVaultStore } from "../store";

interface Props {
  onClose: () => void;
}

function when(ts: number): string {
  if (!ts) return "never saved";
  const d = new Date(ts * 1000);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/**
 * Encrypted scratch storage for the things that live beside your hosts -
 * recovery codes, licence keys, tokens.
 *
 * Notes are a sibling blob under the vault key, not a field on a host: the
 * vault is rewritten whole on every host edit, and a host is what profile
 * export writes out as plaintext JSON.
 */
export function NotesModal({ onClose }: Props) {
  const { notes, refreshNotes, saveNote, deleteNote } = useVaultStore();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [title, setTitle] = useState("");
  const [body, setBody] = useState("");
  const [filter, setFilter] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [revealed, setRevealed] = useState(false);

  useEffect(() => { void refreshNotes().catch((e) => setError(String(e))); }, [refreshNotes]);

  const sorted = useMemo(() => {
    const q = filter.trim().toLowerCase();
    return [...notes]
      .filter((n) => !q || n.title.toLowerCase().includes(q) || n.body.toLowerCase().includes(q))
      .sort((a, b) => b.updated_at - a.updated_at);
  }, [notes, filter]);

  const selected = notes.find((n) => n.id === selectedId) ?? null;
  const dirty = selected
    ? title !== selected.title || body !== selected.body
    : title.trim() !== "" || body.trim() !== "";

  function open(note: Note) {
    setSelectedId(note.id);
    setTitle(note.title);
    setBody(note.body);
    setConfirmDelete(false);
    // A note is opened closed: the point of storing a recovery code here is
    // that it isn't sitting on screen when somebody walks past.
    setRevealed(false);
  }

  function blank() {
    setSelectedId(null);
    setTitle("");
    setBody("");
    setConfirmDelete(false);
    setRevealed(true);
  }

  async function save() {
    if (!title.trim() && !body.trim()) return;
    setSaving(true);
    try {
      const saved = await saveNote({
        id: selectedId ?? "",
        title: title.trim() || "Untitled",
        body,
        updated_at: 0,
      });
      setSelectedId(saved.id);
      setTitle(saved.title);
      setError(null);
    } catch (e) {
      setError(String(e));
    } finally {
      setSaving(false);
    }
  }

  async function remove() {
    if (!selectedId) return;
    try {
      await deleteNote(selectedId);
      blank();
      setSelectedId(null);
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <div className="modal-overlay" onClick={() => { if (!dirty) onClose(); }}>
      <div className="modal notes-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>Notes</h2>
          <button className="icon-btn" onClick={onClose}>✕</button>
        </div>

        {error && <p className="form-error">{error}</p>}

        <div className="notes-body">
          <div className="notes-side">
            <input
              className="proc-filter"
              placeholder="Search notes…"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            />
            <button className="btn btn-sm notes-new" onClick={blank}>+ New note</button>
            <div className="notes-list">
              {sorted.length === 0 ? (
                <p className="notes-empty">
                  {notes.length === 0 ? "No notes yet." : `No matches for “${filter}”.`}
                </p>
              ) : (
                sorted.map((n) => (
                  <button
                    key={n.id}
                    className={`notes-item ${n.id === selectedId ? "active" : ""}`}
                    onClick={() => open(n)}
                  >
                    <span className="notes-item-title">{n.title}</span>
                    <span className="notes-item-when">{when(n.updated_at)}</span>
                  </button>
                ))
              )}
            </div>
          </div>

          <div className="notes-editor">
            <input
              className="notes-title"
              placeholder="Title"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
            />
            <div className="notes-text-wrap">
              <textarea
                className={`notes-text ${revealed ? "" : "masked"}`}
                spellCheck={false}
                placeholder="Recovery codes, licence keys, anything that belongs with your hosts. Encrypted under your master password."
                value={body}
                onChange={(e) => setBody(e.target.value)}
              />
              {!revealed && body && (
                <button className="notes-reveal" onClick={() => setRevealed(true)}>
                  Click to reveal
                </button>
              )}
            </div>

            <div className="notes-actions">
              <button
                className="btn btn-primary btn-sm"
                onClick={() => void save()}
                disabled={saving || !dirty}
              >
                {saving ? "Saving…" : "Save"}
              </button>
              {selected && (
                <button
                  className="btn btn-sm"
                  onClick={() => { navigator.clipboard.writeText(body).catch(() => {}); }}
                  disabled={!body}
                >
                  Copy
                </button>
              )}
              {selected && (
                confirmDelete ? (
                  <>
                    <button className="btn btn-sm delete-btn confirm" onClick={() => void remove()}>
                      Delete
                    </button>
                    <button className="btn btn-sm" onClick={() => setConfirmDelete(false)}>✕</button>
                  </>
                ) : (
                  <button className="btn btn-sm" onClick={() => setConfirmDelete(true)}>Delete</button>
                )
              )}
              <span className="notes-foot-note">
                {dirty ? "Unsaved changes" : selected ? `Saved ${when(selected.updated_at)}` : "Encrypted in your vault"}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
