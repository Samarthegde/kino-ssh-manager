import { useEffect, useState } from "react";
import { getVersion } from "@tauri-apps/api/app";
import { openUrl } from "@tauri-apps/plugin-opener";
import { useVaultStore } from "../store";

const REPO_URL = "https://github.com/Samarthegde/kino-ssh-manager";

interface Props {
  onClose: () => void;
}

export function AboutModal({ onClose }: Props) {
  const { updateInfo, checkForUpdate } = useVaultStore();
  const [version, setVersion] = useState("");
  const [checking, setChecking] = useState(false);

  useEffect(() => {
    getVersion().then(setVersion).catch(() => setVersion(""));
  }, []);

  async function recheck() {
    setChecking(true);
    await checkForUpdate();
    setChecking(false);
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal about-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>About</h2>
          <button className="icon-btn" onClick={onClose} title="Close">
            ✕
          </button>
        </div>

        <div className="about-body">
          <div className="about-logo">
            <svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <rect x="2" y="3" width="20" height="14" rx="2" />
              <polyline points="8 21 12 17 16 21" />
            </svg>
          </div>
          <h3 className="about-name">Kino SSH Manager</h3>

          <p className="about-version mono">v{version || "…"}</p>
          <p className="about-desc">
            A secure, cross-platform SSH credential manager and terminal - with an
            encrypted vault sync, SFTP, port forwarding, live metrics, and Docker
            management over a single multiplexed connection.
          </p>

          {updateInfo?.available ? (
            <div className="about-update available">
              <span>Update available — v{updateInfo.latest}</span>
              <button className="btn btn-sm btn-primary" onClick={() => openUrl(updateInfo.url).catch(() => {})}>
                Download
              </button>
            </div>
          ) : (
            <div className="about-update">
              <span>{checking ? "Checking…" : "You're on the latest version"}</span>
              <button className="btn btn-sm" onClick={recheck} disabled={checking}>
                Check for updates
              </button>
            </div>
          )}

          <div className="about-meta">
            <span>MIT Licensed</span>
            <span className="about-dot">·</span>
            <span>Tauri · React · russh</span>
          </div>
          <span className="about-meta">Samarth Kombemane</span>
          <button
            className="btn btn-sm about-repo-btn"
            onClick={() => openUrl(REPO_URL).catch(() => {})}
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22" />
            </svg>
            View on GitHub
          </button>
        </div>
      </div>
    </div>
  );
}
