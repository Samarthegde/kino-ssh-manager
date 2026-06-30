import { useEffect, useState } from "react";
import { useVaultStore, RecordingInfo } from "../store";
import { ReplayModal } from "./ReplayModal";

interface Props {
  onClose: () => void;
}

export function RecordingsModal({ onClose }: Props) {
  const { listRecordings, deleteRecording } = useVaultStore();
  const [recordings, setRecordings] = useState<RecordingInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [playingFile, setPlayingFile] = useState<string | null>(null);

  async function fetchRecordings() {
    setLoading(true);
    try {
      const recs = await listRecordings();
      setRecordings(recs);
    } catch (e) {
      console.error("Failed to list recordings", e);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchRecordings();
  }, [listRecordings]);

  async function handleDelete(filename: string) {
    if (!confirm(`Are you sure you want to delete ${filename}?`)) return;
    try {
      await deleteRecording(filename);
      fetchRecordings();
    } catch (e) {
      alert(`Failed to delete recording: ${e}`);
    }
  }

  return (
    <div className="modal-overlay">
      <div className="modal docker-modal">
        <div className="modal-header">
          <h2>Session Recordings</h2>
          <button className="icon-btn" onClick={onClose} title="Close">
            ✕
          </button>
        </div>
        <div className="modal-body" style={{ flex: 1, overflowY: "auto", padding: 0 }}>
          {loading ? (
            <div style={{ padding: 20, color: "var(--subtle)" }}>Loading recordings...</div>
          ) : recordings.length === 0 ? (
            <div style={{ padding: 40, textAlign: "center", color: "var(--subtle)" }}>
              No recordings found.
              <div style={{ marginTop: 8, fontSize: 13 }}>
                Recordings are saved to your system's Videos folder.
              </div>
            </div>
          ) : (
            <table className="docker-table">
              <thead>
                <tr>
                  <th>Filename</th>
                  <th>Date</th>
                  <th>Size</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {recordings.map((rec) => (
                  <tr key={rec.name}>
                    <td style={{ fontFamily: "monospace" }}>{rec.name}</td>
                    <td>{new Date(rec.created * 1000).toLocaleString()}</td>
                    <td>{(rec.size / 1024).toFixed(1)} KB</td>
                    <td>
                      <div style={{ display: "flex", gap: "8px" }}>
                        <button
                          className="btn btn-primary"
                          style={{ padding: "4px 8px", fontSize: "12px" }}
                          onClick={() => setPlayingFile(rec.name)}
                        >
                          Play
                        </button>
                        <button
                          className="btn"
                          style={{ padding: "4px 8px", fontSize: "12px", color: "var(--red)" }}
                          onClick={() => handleDelete(rec.name)}
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
      
      {playingFile && (
        <ReplayModal
          filename={playingFile}
          onClose={() => setPlayingFile(null)}
        />
      )}
    </div>
  );
}
