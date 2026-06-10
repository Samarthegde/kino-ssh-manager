import { useState } from "react";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import { DefaultAuth, Host, PortForward, useVaultStore } from "../store";
import { OS_OPTIONS, OsIcon } from "./OsIcon";

interface Props {
  host?: Host;
  onClose: () => void;
}

export function HostForm({ host, onClose }: Props) {
  const { saveHost, generateSshKey, loadKeyFile, snippets } = useVaultStore();

  const [name, setName] = useState(host?.name ?? "");
  const [hostname, setHostname] = useState(host?.hostname ?? "");
  const [port, setPort] = useState(host?.port ?? 22);
  const [username, setUsername] = useState(host?.username ?? "");
  const [defaultAuth, setDefaultAuth] = useState<DefaultAuth>(host?.default_auth ?? "Password");

  // Both stored independently — editing one never clears the other
  const [password, setPassword] = useState(host?.password ?? "");
  const [privateKey, setPrivateKey] = useState(host?.private_key ?? "");
  const [publicKey, setPublicKey] = useState(host?.public_key ?? "");
  const [passphrase, setPassphrase] = useState(host?.passphrase ?? "");

  const [portForwards, setPortForwards] = useState<PortForward[]>(host?.port_forwards ?? []);
  const [onConnectSnippets, setOnConnectSnippets] = useState<string[]>(host?.on_connect_snippets ?? []);
  const [color, setColor] = useState<string>(host?.color ?? "");
  const [notes, setNotes] = useState(host?.notes ?? "");
  const [group, setGroup] = useState(host?.group ?? "");
  const [os, setOs] = useState(host?.os ?? "");

  const TAG_COLORS = ["#f38ba8", "#fab387", "#f9e2af", "#a6e3a1", "#89b4fa", "#cba6f7", "#4c7ebf"];

  const [copiedPub, setCopiedPub] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [generating, setGenerating] = useState(false);

  function generatePassword() {
    const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_=+";
    const bytes = new Uint32Array(20);
    crypto.getRandomValues(bytes);
    setPassword(Array.from(bytes, (b) => chars[b % chars.length]).join(""));
    setShowPassword(true);
  }
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  function addForward() {
    setPortForwards((prev) => [
      ...prev,
      { id: crypto.randomUUID(), label: "", local_port: 8080, remote_host: "127.0.0.1", remote_port: 80 },
    ]);
  }

  function updateForward(id: string, field: keyof PortForward, value: string | number) {
    setPortForwards((prev) => prev.map((f) => (f.id === id ? { ...f, [field]: value } : f)));
  }

  function removeForward(id: string) {
    setPortForwards((prev) => prev.filter((f) => f.id !== id));
  }

  async function handleGenKey() {
    setGenerating(true);
    try {
      const pair = await generateSshKey();
      setPrivateKey(pair.private_key);
      setPublicKey(pair.public_key);
    } catch (e: any) {
      setError(String(e));
    } finally {
      setGenerating(false);
    }
  }

  async function handleLoadKeyFile() {
    const result = await openDialog({
      title: "Select private key (.pem / .key)",
      multiple: false,
      filters: [
        { name: "Private Key", extensions: ["pem", "key", "ppk"] },
        { name: "All Files", extensions: ["*"] },
      ],
    });
    if (!result) return;
    const path = Array.isArray(result) ? result[0] : result;
    try {
      const contents = await loadKeyFile(path as string);
      setPrivateKey(contents.trim());
      setPublicKey(""); // public key isn't derived from an imported .pem
      setDefaultAuth("SshKey");
      setError("");
    } catch (e: any) {
      setError(String(e));
    }
  }

  async function handleCopyPub() {
    await navigator.clipboard.writeText(publicKey);
    setCopiedPub(true);
    setTimeout(() => setCopiedPub(false), 2000);
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!name || !hostname || !username) {
      setError("Name, hostname, and username are required");
      return;
    }
    if (defaultAuth === "Password" && !password) {
      setError("Password is required when default auth is Password");
      return;
    }
    if (defaultAuth === "SshKey" && !privateKey) {
      setError("SSH private key is required when default auth is SSH Key");
      return;
    }
    setSaving(true);
    setError("");
    try {
      await saveHost({
        id: host?.id ?? "",
        name,
        hostname,
        port,
        username,
        default_auth: defaultAuth,
        password: password || null,
        private_key: privateKey || null,
        public_key: publicKey || null,
        passphrase: passphrase || null,
        port_forwards: portForwards,
        on_connect_snippets: onConnectSnippets,
        color: color || null,
        notes: notes.trim() || null,
        group: group.trim() || null,
        os: os || null,
      });
      onClose();
    } catch (e: any) {
      setError(String(e));
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="modal-overlay">
      <div className="modal modal-resizable">
        <div className="modal-header">
          <h2>{host ? "Edit Host" : "Add Host"}</h2>
          <button className="icon-btn" onClick={onClose}>✕</button>
        </div>

        <form onSubmit={handleSubmit} className="host-form">
          {/* Basic info */}
          <div className="form-row">
            <label>Display Name</label>
            <input value={name} onChange={(e) => setName(e.target.value)} placeholder="My Server" />
          </div>
          <div className="form-row two-col">
            <div>
              <label>Hostname / IP</label>
              <input
                value={hostname}
                onChange={(e) => setHostname(e.target.value)}
                placeholder="192.168.1.1"
              />
            </div>
            <div>
              <label>Port</label>
              <input
                type="number"
                value={port}
                onChange={(e) => setPort(Number(e.target.value))}
                min={1}
                max={65535}
              />
            </div>
          </div>
          <div className="form-row">
            <label>Username</label>
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="root"
            />
          </div>

          <div className="form-row">
            <label>Tag color <span className="hint-inline">(optional — flags the tab/host)</span></label>
            <div className="color-swatches">
              <button
                type="button"
                className={`color-swatch none ${color === "" ? "active" : ""}`}
                title="None"
                onClick={() => setColor("")}
              >
                ∅
              </button>
              {TAG_COLORS.map((c) => (
                <button
                  key={c}
                  type="button"
                  className={`color-swatch ${color === c ? "active" : ""}`}
                  style={{ background: c }}
                  title={c}
                  onClick={() => setColor(c)}
                />
              ))}
              <label
                className={`color-swatch ${color && !TAG_COLORS.includes(color) ? "active" : ""}`}
                style={{
                  background: color && !TAG_COLORS.includes(color) ? color : "var(--overlay)",
                  position: "relative",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  overflow: "hidden",
                  cursor: "pointer"
                }}
                title="Custom color"
              >
                {(!color || TAG_COLORS.includes(color)) && (
                  <span style={{ color: "var(--subtle)", fontSize: "16px", lineHeight: 1, marginTop: "-2px" }}>+</span>
                )}
                <input
                  type="color"
                  value={color && !TAG_COLORS.includes(color) ? color : "#ffffff"}
                  onChange={(e) => setColor(e.target.value)}
                  style={{ opacity: 0, position: "absolute", inset: 0, cursor: "pointer" }}
                />
              </label>
            </div>
          </div>

          <div className="form-row">
            <label>Notes <span className="hint-inline">(optional)</span></label>
            <textarea
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              placeholder="Anything worth remembering about this host…"
              rows={2}
              style={{ width: "100%", resize: "vertical" }}
            />
          </div>

          <div className="form-row">
            <label>Folder / Group <span className="hint-inline">(optional)</span></label>
            <input
              value={group}
              onChange={(e) => setGroup(e.target.value)}
              placeholder="e.g. Production, Homelab"
            />
          </div>

          <div className="form-row">
            <label>Operating system <span className="hint-inline">(optional — sets the host icon)</span></label>
            <div className="os-field">
              <span className="os-field-preview">
                <OsIcon os={os || undefined} />
              </span>
              <select className="settings-select" value={os} onChange={(e) => setOs(e.target.value)}>
                <option value="">Unset</option>
                {OS_OPTIONS.map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* Default auth selector */}
          <div className="form-row">
            <label>Default auth method</label>
            <div className="auth-tabs">
              <button
                type="button"
                className={defaultAuth === "Password" ? "active" : ""}
                onClick={() => setDefaultAuth("Password")}
              >
                Password
              </button>
              <button
                type="button"
                className={defaultAuth === "SshKey" ? "active" : ""}
                onClick={() => setDefaultAuth("SshKey")}
              >
                SSH Key
              </button>
            </div>
            <p className="hint">Both can be stored — this sets which is used by default when connecting.</p>
          </div>

          {/* Password section — always visible */}
          <div className="form-section">
            <div className="form-section-title">
              <span>Password</span>
              {defaultAuth === "Password" && <span className="default-badge">default</span>}
              <button
                type="button"
                className="btn btn-sm"
                onClick={() => setShowPassword((v) => !v)}
                style={{ marginLeft: "auto" }}
              >
                {showPassword ? "Hide" : "Show"}
              </button>
              <button type="button" className="btn btn-sm" onClick={generatePassword}>
                Generate
              </button>
            </div>
            <div className="form-row">
              <input
                type={showPassword ? "text" : "password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Server password"
                className={showPassword ? "mono" : ""}
              />
            </div>
          </div>

          {/* SSH Key section — always visible */}
          <div className="form-section">
            <div className="form-section-title">
              <span>SSH Key</span>
              {defaultAuth === "SshKey" && <span className="default-badge">default</span>}
              <button
                type="button"
                className="btn btn-sm"
                onClick={handleLoadKeyFile}
                style={{ marginLeft: "auto" }}
              >
                Load .pem file
              </button>
              <button
                type="button"
                className="btn btn-sm"
                onClick={handleGenKey}
                disabled={generating}
              >
                {generating ? "Generating…" : "Generate ed25519"}
              </button>
            </div>
            <div className="form-row">
              <label>Private Key (OpenSSH / PEM)</label>
              <textarea
                value={privateKey}
                onChange={(e) => setPrivateKey(e.target.value)}
                placeholder="-----BEGIN OPENSSH PRIVATE KEY----- or -----BEGIN RSA PRIVATE KEY-----"
                rows={5}
                className="mono"
              />
            </div>
            <div className="form-row">
              <label>Key passphrase <span className="hint-inline">(leave blank if unencrypted)</span></label>
              <input
                type="password"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                placeholder="Passphrase for encrypted key"
                autoComplete="off"
              />
            </div>
            {publicKey && (
              <div className="form-row">
                <div className="key-header">
                  <label>Public Key</label>
                  <button type="button" className="btn btn-sm" onClick={handleCopyPub}>
                    {copiedPub ? "Copied!" : "Copy"}
                  </button>
                </div>
                <textarea value={publicKey} readOnly rows={2} className="mono" />
                <p className="hint">Paste into ~/.ssh/authorized_keys on the server</p>
              </div>
            )}
          </div>

          {/* Port Forwards section */}
          <div className="form-section">
            <div className="form-section-title">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
                <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
              </svg>
              <span>Port Forwards</span>
              <button
                type="button"
                className="btn btn-sm"
                onClick={addForward}
                style={{ marginLeft: "auto" }}
              >
                + Add
              </button>
            </div>
            {portForwards.length === 0 && (
              <p className="hint">No tunnels configured. Add one to forward ports through this host.</p>
            )}
            {portForwards.map((fwd) => (
              <div key={fwd.id} className="fwd-config-row">
                <input
                  placeholder="Label"
                  value={fwd.label}
                  onChange={(e) => updateForward(fwd.id, "label", e.target.value)}
                  className="fwd-label-input"
                />
                <select
                  className="settings-select fwd-kind"
                  title="Forward type"
                  value={fwd.kind ?? "local"}
                  onChange={(e) => updateForward(fwd.id, "kind", e.target.value)}
                >
                  <option value="local">Local</option>
                  <option value="socks">SOCKS</option>
                  <option value="remote">Remote</option>
                </select>
                {(fwd.kind ?? "local") === "socks" ? (
                  <>
                    <input
                      type="number"
                      title="Local SOCKS port"
                      value={fwd.local_port}
                      onChange={(e) => updateForward(fwd.id, "local_port", Number(e.target.value))}
                      min={1}
                      max={65535}
                      className="fwd-port-input"
                    />
                    <span className="fwd-arrow" style={{ color: "var(--subtle)" }}>SOCKS5 proxy</span>
                  </>
                ) : (fwd.kind ?? "local") === "remote" ? (
                  <>
                    <input
                      placeholder="127.0.0.1"
                      title="Server bind host"
                      value={fwd.bind_host ?? ""}
                      onChange={(e) => updateForward(fwd.id, "bind_host", e.target.value)}
                      className="fwd-rhost-input"
                    />
                    <input
                      type="number"
                      title="Server bind port"
                      value={fwd.remote_port}
                      onChange={(e) => updateForward(fwd.id, "remote_port", Number(e.target.value))}
                      min={1}
                      max={65535}
                      className="fwd-port-input"
                    />
                    <span className="fwd-arrow">→</span>
                    <input
                      placeholder="target host"
                      title="Local target host"
                      value={fwd.remote_host}
                      onChange={(e) => updateForward(fwd.id, "remote_host", e.target.value)}
                      className="fwd-rhost-input"
                    />
                    <input
                      type="number"
                      title="Local target port"
                      value={fwd.local_port}
                      onChange={(e) => updateForward(fwd.id, "local_port", Number(e.target.value))}
                      min={1}
                      max={65535}
                      className="fwd-port-input"
                    />
                  </>
                ) : (
                  <>
                    <input
                      type="number"
                      title="Local port"
                      value={fwd.local_port}
                      onChange={(e) => updateForward(fwd.id, "local_port", Number(e.target.value))}
                      min={1}
                      max={65535}
                      className="fwd-port-input"
                    />
                    <span className="fwd-arrow">→</span>
                    <input
                      placeholder="Remote host"
                      title="Remote host"
                      value={fwd.remote_host}
                      onChange={(e) => updateForward(fwd.id, "remote_host", e.target.value)}
                      className="fwd-rhost-input"
                    />
                    <input
                      type="number"
                      title="Remote port"
                      value={fwd.remote_port}
                      onChange={(e) => updateForward(fwd.id, "remote_port", Number(e.target.value))}
                      min={1}
                      max={65535}
                      className="fwd-port-input"
                    />
                  </>
                )}
                <button
                  type="button"
                  className="icon-btn delete-btn"
                  title="Remove"
                  onClick={() => removeForward(fwd.id)}
                >
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
                  </svg>
                </button>
              </div>
            ))}
          </div>

          {/* Run on connect */}
          <div className="form-section">
            <div className="form-section-title">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <polyline points="16 18 22 12 16 6" />
                <polyline points="8 6 2 12 8 18" />
              </svg>
              <span>Run on connect</span>
            </div>
            {snippets.length === 0 ? (
              <p className="hint">No snippets yet. Create them in Settings → Snippets, then select them here.</p>
            ) : (
              <>
                <p className="hint">Selected snippets run automatically, in order, after connecting.</p>
                <div className="snippet-toggle-list">
                  {snippets.map((s) => {
                    const checked = onConnectSnippets.includes(s.id);
                    const preview = s.commands.split("\n").find((l) => l.trim()) ?? "";
                    return (
                      <label key={s.id} className={`snippet-toggle ${checked ? "checked" : ""}`}>
                        <input
                          type="checkbox"
                          checked={checked}
                          onChange={(e) =>
                            setOnConnectSnippets((prev) =>
                              e.target.checked ? [...prev, s.id] : prev.filter((id) => id !== s.id)
                            )
                          }
                        />
                        <span className="snippet-toggle-text">
                          <span className="snippet-toggle-name">{s.name}</span>
                          {preview && <span className="snippet-toggle-preview mono">{preview}</span>}
                        </span>
                      </label>
                    );
                  })}
                </div>
              </>
            )}
          </div>

          {error && <p className="form-error">{error}</p>}

          <div className="modal-footer">
            <button type="button" className="btn" onClick={onClose}>Cancel</button>
            <button type="submit" className="btn btn-primary" disabled={saving}>
              {saving ? "Saving…" : "Save"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
