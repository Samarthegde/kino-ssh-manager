import { Host, HostKeyVerdict } from "../store";

interface Props {
  host: Host;
  verdict: Extract<HostKeyVerdict, { status: "new" | "changed" }>;
  onTrust: () => void;
  onCancel: () => void;
}

export function HostKeyDialog({ host, verdict, onTrust, onCancel }: Props) {
  const changed = verdict.status === "changed";

  return (
    <div className="modal-overlay">
      <div className="modal connect-modal">
        <div className="modal-header">
          <h2>{changed ? "⚠ Host key changed" : "Verify host key"}</h2>
          <button className="icon-btn" onClick={onCancel}>✕</button>
        </div>

        <div className="connect-body">
          {changed ? (
            <p className="form-error" style={{ margin: 0 }}>
              The host key for <strong>{host.hostname}:{host.port}</strong> is different from the one
              you previously trusted. This can happen after a legitimate server rebuild — but it can
              also mean someone is intercepting the connection. Only continue if you know why it
              changed.
            </p>
          ) : (
            <p className="hint" style={{ margin: 0 }}>
              You're connecting to <strong>{host.hostname}:{host.port}</strong> for the first time.
              Confirm the server's fingerprint matches what you expect before trusting it.
            </p>
          )}

          <div className="hostkey-fp-block">
            <span className="hostkey-fp-label">{changed ? "New fingerprint" : "Fingerprint"}</span>
            <code className="hostkey-fp mono">{verdict.fingerprint}</code>
          </div>

          {changed && (
            <div className="hostkey-fp-block">
              <span className="hostkey-fp-label">Previously trusted</span>
              <code className="hostkey-fp mono">{verdict.known}</code>
            </div>
          )}
        </div>

        <div className="modal-footer">
          <button className="btn" onClick={onCancel}>Cancel</button>
          <button className={`btn ${changed ? "btn-danger" : "btn-primary"}`} onClick={onTrust}>
            {changed ? "Trust new key & connect" : "Trust & connect"}
          </button>
        </div>
      </div>
    </div>
  );
}
