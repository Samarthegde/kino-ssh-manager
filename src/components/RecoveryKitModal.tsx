import { useEffect, useState } from "react";
import { save } from "@tauri-apps/plugin-dialog";
import { useVaultStore } from "../store";

interface Props {
  /** True when a kit already exists, so the wording says "replace". */
  replacing: boolean;
  onClose: () => void;
}

/**
 * The one showing of a recovery key.
 *
 * Kino keeps no copy - the key is generated, wrapped around the vault's own
 * key on disk, and handed to this window once. Closing this is the moment it
 * becomes unrecoverable, so the window says that plainly and makes the person
 * tick a box confirming they have it somewhere else.
 *
 * What it says is as much the feature as what it does: a key that opens the
 * vault without the master password is a credential, and somebody who thinks
 * of it as a convenience will leave it in their Downloads folder.
 */
export function RecoveryKitModal({ replacing, onClose }: Props) {
  const { createRecoveryKit } = useVaultStore();
  const [key, setKey] = useState("");
  const [error, setError] = useState("");
  const [kept, setKept] = useState(false);
  const [copied, setCopied] = useState(false);
  const [saved, setSaved] = useState("");

  useEffect(() => {
    createRecoveryKit()
      .then(setKey)
      .catch((e) => setError(String(e)));
  }, [createRecoveryKit]);

  async function handleCopy() {
    await navigator.clipboard.writeText(key);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  async function handleSave() {
    const path = await save({
      title: "Save recovery key",
      defaultPath: "kino-recovery-key.txt",
      filters: [{ name: "Text", extensions: ["txt"] }],
    });
    if (!path) return;
    const sheet = [
      "Kino SSH Manager - vault recovery key",
      "",
      key,
      "",
      "This opens the vault on this machine without the master password.",
      "Keep it where you would keep a spare house key, not next to the vault.",
      "Using it sets a new master password and retires this key.",
      `Made ${new Date().toISOString().slice(0, 10)}.`,
      "",
    ].join("\n");
    try {
      await useVaultStore.getState().writeTextFile(sheet, path as string);
      setSaved(path as string);
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <div className="modal-overlay">
      <div className="modal recovery-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>{replacing ? "New recovery key" : "Recovery key"}</h2>
        </div>

        <div className="recovery-body">
          {error ? (
            <p className="unlock-error">{error}</p>
          ) : !key ? (
            <p className="hint">Generating…</p>
          ) : (
            <>
              <p className="hint">
                Write this down. It opens your vault without the master password, and it is
                shown once - Kino keeps no copy.
                {replacing && " The previous recovery key stopped working just now."}
              </p>

              <pre className="recovery-key mono">{key}</pre>

              <div className="recovery-actions">
                <button className="btn btn-sm" onClick={handleCopy}>
                  {copied ? "Copied" : "Copy"}
                </button>
                <button className="btn btn-sm" onClick={handleSave}>
                  Save to a file…
                </button>
              </div>
              {saved && <p className="hint">Saved to {saved}</p>}

              <ul className="recovery-notes">
                <li>
                  Treat it like a key to every host in the vault - because it is one. Not in
                  the same place as the vault, and not in the vault.
                </li>
                <li>
                  Using it sets a new master password and retires the key, so you will be
                  shown a fresh one afterwards.
                </li>
                <li>
                  Changing your master password retires it too. Kino will ask you for a new
                  one when that happens.
                </li>
                <li>It stays on this machine - it is not uploaded with a synced vault.</li>
              </ul>

              <label className="recovery-confirm">
                <input
                  type="checkbox"
                  checked={kept}
                  onChange={(e) => setKept(e.target.checked)}
                />
                I have written it down or saved it somewhere safe
              </label>
            </>
          )}
        </div>

        <div className="mcp-foot">
          <button
            className="btn btn-primary btn-sm"
            onClick={onClose}
            disabled={!error && (!key || !kept)}
          >
            Done
          </button>
        </div>
      </div>
    </div>
  );
}
