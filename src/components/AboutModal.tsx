import { useEffect, useState } from "react";
import { getVersion } from "@tauri-apps/api/app";
import { openUrl } from "@tauri-apps/plugin-opener";
import { check } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";
import { useVaultStore } from "../store";

const REPO_URL = "https://github.com/Samarthegde/kino-ssh-manager";

interface Props {
  onClose: () => void;
}

/** Where the in-app install currently is. */
type InstallPhase = "idle" | "working" | "downloading" | "verified" | "installed" | "failed";

export function AboutModal({ onClose }: Props) {
  const { updateInfo, checkForUpdate, updaterKeyId } = useVaultStore();
  const [version, setVersion] = useState("");
  const [renderer, setRenderer] = useState("");
  const [checking, setChecking] = useState(false);
  /** Set once a package has been downloaded and its signature checked. */
  const [verified, setVerified] = useState<{ version: string; bytes: number } | null>(null);
  const [pending, setPending] = useState<Awaited<ReturnType<typeof check>>>(null);
  const [keyId, setKeyId] = useState<string | null>(null);
  useEffect(() => {
    updaterKeyId().then(setKeyId).catch(() => setKeyId(null));
  }, [updaterKeyId]);

  const [phase, setPhase] = useState<InstallPhase>("idle");
  const [progress, setProgress] = useState({ received: 0, total: 0 });
  const [installError, setInstallError] = useState("");

  useEffect(() => {
    getVersion().then(setVersion).catch(() => setVersion(""));
    // Written by Terminal on mount; empty until a terminal has been opened.
    setRenderer(localStorage.getItem("ssh-mgr:renderer") ?? "");
  }, []);

  async function recheck() {
    setChecking(true);
    await checkForUpdate();
    setChecking(false);
  }

  /**
   * Download and install the signed release in place, then offer a relaunch.
   * If the updater isn't usable on this build (no signing key configured, no
   * published manifest, unsupported install target) we surface the reason and
   * fall back to the release page rather than leaving a dead button.
   */
  /**
   * Download, then say what was checked, then install - three steps rather
   * than one.
   *
   * `downloadAndInstall` does all of it in a single call, which means the
   * moment the signature is verified is also the moment the installer runs.
   * Splitting them puts a stop between "this package is signed by the key in
   * the app's config" and "this package is now on your disk", and lets the
   * user see the first before deciding on the second.
   *
   * There is no path from a failed verification to an install. The plugin
   * throws, and the only button offered afterwards opens the release page.
   */
  async function downloadUpdate() {
    setPhase("working");
    setInstallError("");
    setProgress({ received: 0, total: 0 });
    setVerified(null);
    try {
      const update = await check();
      if (!update) {
        setPhase("failed");
        setInstallError("No signed update package was published for this release.");
        return;
      }
      let received = 0;
      let total = 0;
      await update.download((event) => {
        if (event.event === "Started") {
          setPhase("downloading");
          total = event.data.contentLength ?? 0;
          setProgress({ received: 0, total });
        } else if (event.event === "Progress") {
          received += event.data.chunkLength;
          setProgress((p) => ({ ...p, received }));
        }
      });
      // Reaching here means the signature checked out: `download` verifies it
      // and throws otherwise.
      setPending(update);
      setVerified({ version: update.version, bytes: received || total });
      setPhase("verified");
    } catch (e) {
      setPhase("failed");
      const text = String(e);
      setInstallError(
        /signature|verif/i.test(text)
          ? `The downloaded package is not signed by this app's update key, so it was not installed. ${text}`
          : text
      );
    }
  }

  async function applyUpdate() {
    if (!pending) return;
    setPhase("working");
    try {
      await pending.install();
      setPhase("installed");
    } catch (e) {
      setPhase("failed");
      setInstallError(String(e));
    }
  }

  const pct =
    progress.total > 0 ? Math.min(100, Math.round((progress.received / progress.total) * 100)) : 0;

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
              {phase === "verified" && verified ? (
                <div className="update-verified">
                  <p className="update-verified-head">Checked before installing</p>
                  <ul>
                    <li>
                      Signed by update key <code>{keyId ?? "unknown"}</code>
                    </li>
                    <li>
                      v{verified.version}
                      {verified.bytes > 0 && ` · ${(verified.bytes / 1_048_576).toFixed(1)} MB`}
                    </li>
                  </ul>
                  <p className="hint">
                    That key is published as <code>minisign.pub</code> in the repository, so you
                    can compare it without trusting this window.
                  </p>
                  <div className="update-verified-actions">
                    <button
                      className="btn btn-sm"
                      onClick={() => {
                        setPhase("idle");
                        setVerified(null);
                      }}
                    >
                      Not now
                    </button>
                    <button className="btn btn-sm btn-primary" onClick={applyUpdate}>
                      Install v{verified.version}
                    </button>
                  </div>
                </div>
              ) : phase === "installed" ? (
                <>
                  <span>v{updateInfo.latest} installed - restart to finish</span>
                  <button className="btn btn-sm btn-primary" onClick={() => relaunch().catch(() => {})}>
                    Restart now
                  </button>
                </>
              ) : phase === "downloading" ? (
                <>
                  <span>
                    Downloading v{updateInfo.latest}
                    {progress.total > 0 ? ` - ${pct}%` : "…"}
                  </span>
                  <div className="update-bar" aria-label="Download progress">
                    <div className="update-bar-fill" style={{ width: `${progress.total > 0 ? pct : 30}%` }} />
                  </div>
                </>
              ) : phase === "working" ? (
                <span>Preparing v{updateInfo.latest}…</span>
              ) : (
                <>
                  <span>Update available - v{updateInfo.latest}</span>
                  <button className="btn btn-sm btn-primary" onClick={downloadUpdate}>
                    Download update
                  </button>
                  <button className="btn btn-sm" onClick={() => openUrl(updateInfo.url).catch(() => {})}>
                    Release notes
                  </button>
                </>
              )}
            </div>
          ) : (
            <div className="about-update">
              <span>{checking ? "Checking…" : "You're on the latest version"}</span>
              <button className="btn btn-sm" onClick={recheck} disabled={checking}>
                Check for updates
              </button>
            </div>
          )}

          {phase === "failed" && (
            <p className="hint" style={{ color: "var(--red)", maxWidth: "44ch", textAlign: "center" }}>
              Couldn't install automatically: {installError} — use{" "}
              <a
                href={updateInfo?.url ?? REPO_URL}
                onClick={(e) => { e.preventDefault(); openUrl(updateInfo?.url ?? REPO_URL).catch(() => {}); }}
              >
                the release page
              </a>{" "}
              instead.
            </p>
          )}

          <div className="about-meta">
            <span>GPL-3.0 Licensed</span>
            <span className="about-dot">·</span>
            <span>Tauri · React · russh</span>
            {renderer && (
              <>
                <span className="about-dot">·</span>
                {/* On Linux, WebKitGTK often has no usable GL context and falls
                    back to the much slower DOM renderer. Worth being able to
                    check without an inspector when a terminal feels sluggish. */}
                <span title={
                  renderer === "webgl"
                    ? "Terminal rendering is GPU accelerated"
                    : "No WebGL context - terminal redraws are slower under heavy output"
                }>
                  Renderer: {renderer}
                </span>
              </>
            )}
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
