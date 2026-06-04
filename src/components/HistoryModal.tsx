import { useEffect, useState } from "react";
import { HistoryEvent, useVaultStore } from "../store";

interface Props {
  onClose: () => void;
}

const ITEMS_PER_PAGE = 10;

export function HistoryModal({ onClose }: Props) {
  const { getHistory } = useVaultStore();
  const [history, setHistory] = useState<HistoryEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [currentPage, setCurrentPage] = useState(1);

  useEffect(() => {
    getHistory()
      .then((data) => {
        setHistory(data.sort((a, b) => b.timestamp - a.timestamp));
        setLoading(false);
      })
      .catch((err) => {
        console.error(err);
        setLoading(false);
      });
  }, [getHistory]);

  const totalPages = Math.ceil(history.length / ITEMS_PER_PAGE);
  const currentHistory = history.slice((currentPage - 1) * ITEMS_PER_PAGE, currentPage * ITEMS_PER_PAGE);

  return (
    <div className="modal-overlay">
      <div className="modal" style={{ width: 600, maxHeight: "80vh", display: "flex", flexDirection: "column" }}>
        <div className="modal-header">
          <h2>Vault History</h2>
          <button className="icon-btn" onClick={onClose}>✕</button>
        </div>
        
        <div style={{ flex: 1, overflowY: "auto", padding: "0 20px", marginTop: 10 }}>
          {loading ? (
            <p style={{ textAlign: "center", color: "var(--color-text-dim)" }}>Loading history...</p>
          ) : history.length === 0 ? (
            <p style={{ textAlign: "center", color: "var(--color-text-dim)" }}>No history available yet.</p>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 12, paddingBottom: 20 }}>
              {currentHistory.map((event) => (
                <div key={event.id} style={{ display: "flex", justifyContent: "space-between", padding: "12px 16px", background: "var(--color-surface)", borderRadius: 8, border: "1px solid var(--color-border)" }}>
                  <div>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                      {event.event_type === "connection" && (
                        <span style={{ color: "var(--color-blue)", fontSize: 12, fontWeight: 600, padding: "2px 6px", background: "rgba(137, 180, 250, 0.1)", borderRadius: 4 }}>Connection</span>
                      )}
                      {(event.event_type === "host_added" || event.event_type === "host_edited" || event.event_type === "host_deleted") && (
                        <span style={{ color: "var(--color-green)", fontSize: 12, fontWeight: 600, padding: "2px 6px", background: "rgba(166, 227, 161, 0.1)", borderRadius: 4 }}>Vault Update</span>
                      )}
                      {event.event_type.startsWith("vault_") && (
                        <span style={{ color: "var(--color-text)", fontSize: 12, fontWeight: 600, padding: "2px 6px", background: "rgba(205, 214, 244, 0.1)", borderRadius: 4 }}>System</span>
                      )}
                      {event.event_type.startsWith("key_") && (
                        <span style={{ color: "var(--color-yellow)", fontSize: 12, fontWeight: 600, padding: "2px 6px", background: "rgba(249, 226, 175, 0.1)", borderRadius: 4 }}>Key Action</span>
                      )}
                      {(event.event_type === "host_imported" || event.event_type === "host_exported") && (
                        <span style={{ color: "var(--color-mauve)", fontSize: 12, fontWeight: 600, padding: "2px 6px", background: "rgba(203, 166, 247, 0.1)", borderRadius: 4 }}>File I/O</span>
                      )}
                    </div>
                    <p style={{ fontSize: 14, color: "var(--color-text)", margin: 0 }}>{event.message}</p>
                  </div>
                  <div style={{ textAlign: "right", color: "var(--color-text-dim)", fontSize: 12 }}>
                    <div>{new Date(event.timestamp).toLocaleDateString()}</div>
                    <div>{new Date(event.timestamp).toLocaleTimeString()}</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="modal-footer" style={{ padding: "16px 20px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <button 
              className="btn" 
              onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
              disabled={currentPage === 1 || totalPages === 0}
            >
              Previous
            </button>
            <span style={{ fontSize: 14, color: "var(--color-text-dim)" }}>
              Page {totalPages === 0 ? 0 : currentPage} of {totalPages}
            </span>
            <button 
              className="btn" 
              onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
              disabled={currentPage === totalPages || totalPages === 0}
            >
              Next
            </button>
          </div>
          <button className="btn btn-primary" onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  );
}
