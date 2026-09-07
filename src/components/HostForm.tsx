import { useEffect, useState } from "react";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import { CloudMachine, DefaultAuth, Host, PortForward, useVaultStore } from "../store";
import { OS_OPTIONS, OsIcon } from "./OsIcon";

interface Props {
  host?: Host;
  onClose: () => void;
}

const STEPS = [
  { id: "connection", label: "Connection & Auth" },
  { id: "forwards", label: "Port Forwards" },
  { id: "advanced", label: "Advanced" },
] as const;

const STEP_CONNECTION = 0;

export function HostForm({ host, onClose }: Props) {
  const { saveHost, generateSshKey, loadKeyFile, installPublicKey, snippets, relayEnabled, hosts } = useVaultStore();

  // Groups already in use, so the user can pick one instead of retyping (and
  // risking a near-duplicate like "Prod" vs "Production").
  const existingGroups = Array.from(
    new Set(hosts.map((h) => h.group?.trim()).filter((g): g is string => !!g))
  ).sort((a, b) => a.localeCompare(b));

  const [step, setStep] = useState(0);

  const [name, setName] = useState(host?.name ?? "");
  const [hostname, setHostname] = useState(host?.hostname ?? "");
  const [port, setPort] = useState(host?.port ?? 22);
  const [username, setUsername] = useState(host?.username ?? "");
  const [defaultAuth, setDefaultAuth] = useState<DefaultAuth>(host?.default_auth ?? "Password");

  // Both stored independently - editing one never clears the other
  const [password, setPassword] = useState(host?.password ?? "");
  const [privateKey, setPrivateKey] = useState(host?.private_key ?? "");
  const [publicKey, setPublicKey] = useState(host?.public_key ?? "");
  const [passphrase, setPassphrase] = useState(host?.passphrase ?? "");

  const [portForwards, setPortForwards] = useState<PortForward[]>(host?.port_forwards ?? []);
  const [onConnectSnippets, setOnConnectSnippets] = useState<string[]>(host?.on_connect_snippets ?? []);
  const [color, setColor] = useState<string>(host?.color ?? "");
  const [notes, setNotes] = useState(host?.notes ?? "");
  const [ntfyTopic, setNtfyTopic] = useState(host?.ntfy_topic ?? "");
  const [group, setGroup] = useState(host?.group ?? "");
  const [environment, setEnvironment] = useState(host?.environment ?? "");
  // Whether the group field is in "type a new name" mode vs. picking an existing one.
  const [creatingGroup, setCreatingGroup] = useState(false);
  const [os, setOs] = useState(host?.os ?? "");
  const [jumpHost, setJumpHost] = useState(host?.jump_host ?? "");
  const [connectionMode, setConnectionMode] = useState(host?.connection_mode ?? "direct");

  // Candidate bastions: every other saved host (a host can't jump through itself).
  const jumpCandidates = hosts.filter((h) => h.id && h.id !== host?.id);
  const [agentId, setAgentId] = useState(host?.agent_id ?? "");
  const [relayUrl, setRelayUrl] = useState(host?.relay_url ?? useVaultStore.getState().defaultRelayUrl);
  const [relayToken, setRelayToken] = useState(host?.relay_token ?? "");
  const [controlUrl, setControlUrl] = useState(host?.control_url ?? "");

  // Kino Cloud: configured in Settings; when present, agent mode becomes a
  // machine picker and the manual relay fields fold into "Advanced".
  const { cloudGetConfig, cloudListMachines, cloudAddMachine } = useVaultStore();
  const [cloudReady, setCloudReady] = useState(false);
  const [machines, setMachines] = useState<CloudMachine[]>([]);
  const [cloudError, setCloudError] = useState("");
  const [newMachineName, setNewMachineName] = useState("");
  const [installCmd, setInstallCmd] = useState("");
  const [addingMachine, setAddingMachine] = useState(false);

  useEffect(() => {
    if (connectionMode !== "agent") return;
    cloudGetConfig()
      .then((c) => {
        const ready = !!c && c.key_set && !!c.control_url;
        setCloudReady(ready);
        if (ready) refreshMachines();
      })
      .catch(() => setCloudReady(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [connectionMode]);

  function refreshMachines() {
    setCloudError("");
    cloudListMachines()
      .then(setMachines)
      .catch((e) => setCloudError(String(e)));
  }

  function pickMachine(id: string) {
    setAgentId(id);
    // A cloud host stores only the agent id - relay details are looked up at
    // connect time, so stale ones must not linger from a previous config.
    setRelayUrl("");
    setControlUrl("");
    setRelayToken("");
    const machine = machines.find((m) => m.agent_id === id);
    if (machine && !name) setName(machine.name);
  }

  async function handleAddMachine() {
    if (!newMachineName.trim()) return;
    setAddingMachine(true);
    setCloudError("");
    try {
      const added = await cloudAddMachine(newMachineName.trim());
      setInstallCmd(added.install_command);
      setNewMachineName("");
      refreshMachines();
      pickMachine(added.agent_id);
      if (!name) setName(added.name);
    } catch (e) {
      setCloudError(String(e));
    } finally {
      setAddingMachine(false);
    }
  }

  // Proxy (dial-through) config - only applies to direct connections.
  const [proxyType, setProxyType] = useState<string>(host?.proxy_type ?? "");
  const [proxyHost, setProxyHost] = useState(host?.proxy_host ?? "");
  const [proxyPort, setProxyPort] = useState<number>(host?.proxy_port ?? 1080);
  const [proxyUsername, setProxyUsername] = useState(host?.proxy_username ?? "");
  const [proxyPassword, setProxyPassword] = useState(host?.proxy_password ?? "");

  const TAG_COLORS = ["#f38ba8", "#fab387", "#f9e2af", "#a6e3a1", "#89b4fa", "#cba6f7", "#4c7ebf"];

  const [copiedPub, setCopiedPub] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [installing, setInstalling] = useState(false);
  const [installMsg, setInstallMsg] = useState("");

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

  /** Append the public key to the server's authorized_keys over a one-shot
   *  connection. Prefers password auth when one is stored, since the whole
   *  point is usually to bootstrap key auth before it works. */
  async function handleInstallKey() {
    setInstalling(true);
    setError("");
    setInstallMsg("");
    try {
      await installPublicKey(
        {
          id: host?.id ?? "",
          name,
          hostname,
          port,
          username,
          default_auth: password ? "Password" : defaultAuth,
          password: password || null,
          private_key: privateKey || null,
          public_key: publicKey || null,
          passphrase: passphrase || null,
          connection_mode: connectionMode,
          agent_id: agentId || null,
          relay_url: relayUrl || null,
          relay_token: relayToken || null,
          control_url: controlUrl || null,
          proxy_type: connectionMode === "direct" && proxyType ? proxyType : null,
          proxy_host: connectionMode === "direct" && proxyType ? proxyHost || null : null,
          proxy_port: connectionMode === "direct" && proxyType ? proxyPort : null,
          proxy_username: connectionMode === "direct" && proxyType ? proxyUsername || null : null,
          proxy_password: connectionMode === "direct" && proxyType ? proxyPassword || null : null,
        },
        publicKey
      );
      setInstallMsg("Installed - this host now accepts your key.");
    } catch (e: any) {
      setError(String(e));
    } finally {
      setInstalling(false);
    }
  }

  /** Report a validation failure on the step that owns the offending field. */
  function fail(onStep: number, message: string) {
    setStep(onStep);
    setError(message);
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (connectionMode === "direct" && (!name || !hostname || !username)) {
      fail(STEP_CONNECTION, "Name, hostname, and username are required");
      return;
    }
    if (connectionMode === "agent" && (!name || !agentId || !username)) {
      fail(STEP_CONNECTION, "Name, Agent ID, and username are required");
      return;
    }
    if (connectionMode === "agent" && !relayUrl && !controlUrl && !cloudReady) {
      fail(STEP_CONNECTION, "Pick a Kino Cloud machine, or enter a Relay URL / kino-control URL");
      return;
    }
    if (defaultAuth === "Password" && !password) {
      fail(STEP_CONNECTION, "Password is required when default auth is Password");
      return;
    }
    if (defaultAuth === "SshKey" && !privateKey) {
      fail(STEP_CONNECTION, "SSH private key is required when default auth is SSH Key");
      return;
    }
    if (connectionMode === "direct" && proxyType && !proxyHost.trim()) {
      fail(2, "Proxy host is required when a proxy is selected");
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
        ntfy_topic: ntfyTopic.trim() || null,
        group: group.trim() || null,
        environment: environment || null,
        os: os || null,
        connection_mode: connectionMode,
        agent_id: agentId || null,
        relay_url: relayUrl || null,
        relay_token: relayToken || null,
        control_url: controlUrl || null,
        jump_host: connectionMode === "direct" && jumpHost ? jumpHost : null,
        proxy_type: connectionMode === "direct" && proxyType ? proxyType : null,
        proxy_host: connectionMode === "direct" && proxyType ? proxyHost || null : null,
        proxy_port: connectionMode === "direct" && proxyType ? proxyPort : null,
        proxy_username: connectionMode === "direct" && proxyType ? proxyUsername || null : null,
        proxy_password: connectionMode === "direct" && proxyType ? proxyPassword || null : null,
      });
      onClose();
    } catch (e: any) {
      setError(String(e));
    } finally {
      setSaving(false);
    }
  }

  const current = STEPS[step].id;
  const isLast = step === STEPS.length - 1;

  return (
    <div className="modal-overlay">
      <div
        className="modal"
        style={{
          width: "min(880px, 96vw)",
          maxWidth: "none",
          height: "min(680px, 90vh)",
          maxHeight: "90vh",
          display: "flex",
          flexDirection: "column",
        }}
      >
        <div className="modal-header">
          <h2>{host ? "Edit Host" : "Add Host"}</h2>
          <button className="icon-btn" onClick={onClose}>✕</button>
        </div>

        <form
          onSubmit={handleSubmit}
          className="host-form"
          style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column" }}
        >
          <div className="form-stepper">
            {STEPS.map((s, i) => (
              <button
                key={s.id}
                type="button"
                className={`form-step ${i === step ? "active" : ""}`}
                onClick={() => setStep(i)}
              >
                <span className="form-step-num">{i + 1}</span>
                <span className="form-step-label">{s.label}</span>
              </button>
            ))}
          </div>

          <div className="form-step-body">
            {current === "connection" && (
              <>
                <div className="form-row">
                  <label>Display Name</label>
                  <input value={name} onChange={(e) => setName(e.target.value)} placeholder="My Server" />
                </div>

                {relayEnabled && (
                  <div className="form-row">
                    <label>Connection Mode</label>
                    <div className="auth-tabs">
                      <button
                        type="button"
                        className={connectionMode === "direct" ? "active" : ""}
                        onClick={() => setConnectionMode("direct")}
                      >
                        Direct SSH
                      </button>
                      <button
                        type="button"
                        className={connectionMode === "agent" ? "active" : ""}
                        onClick={() => {
                          setConnectionMode("agent");
                          if (!agentId) setAgentId(crypto.randomUUID());
                        }}
                      >
                        Kino Agent
                      </button>
                    </div>
                  </div>
                )}

                {connectionMode === "direct" ? (
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
                ) : relayEnabled ? (
                  <>
                    {cloudReady && (
                      <>
                        <div className="form-row two-col">
                          <div>
                            <label>Kino Cloud machine</label>
                            <select value={agentId} onChange={(e) => pickMachine(e.target.value)}>
                              <option value="">- pick a machine -</option>
                              {machines.map((m) => (
                                <option key={m.agent_id} value={m.agent_id}>
                                  {m.name}
                                  {m.relay_url ? "" : " (agent not installed yet)"}
                                </option>
                              ))}
                            </select>
                          </div>
                          <div>
                            <label>New machine</label>
                            <div style={{ display: "flex", gap: "8px" }}>
                              <input
                                value={newMachineName}
                                onChange={(e) => setNewMachineName(e.target.value)}
                                placeholder="homelab-pi"
                              />
                              <button
                                type="button"
                                className="btn-secondary"
                                disabled={addingMachine || !newMachineName.trim()}
                                onClick={handleAddMachine}
                              >
                                {addingMachine ? "Adding…" : "Add"}
                              </button>
                              <button type="button" className="btn-secondary" onClick={refreshMachines}>
                                ↻
                              </button>
                            </div>
                          </div>
                        </div>
                        {installCmd && (
                          <div className="form-row">
                            <div style={{ background: "var(--overlay)", padding: "12px", borderRadius: "8px", fontSize: "13px" }}>
                              <p style={{ margin: "0 0 8px 0", color: "var(--subtext)" }}>
                                Run this once on the new machine (the link inside is one-time):
                              </p>
                              <code style={{ background: "var(--bg)", padding: "6px 8px", display: "block", borderRadius: "4px", color: "var(--text)", userSelect: "all" }}>
                                {installCmd}
                              </code>
                            </div>
                          </div>
                        )}
                        {cloudError && (
                          <div className="form-row">
                            <div style={{ color: "var(--red, #f38ba8)", fontSize: "13px" }}>{cloudError}</div>
                          </div>
                        )}
                      </>
                    )}
                    <details open={!cloudReady} style={{ marginTop: cloudReady ? "8px" : 0 }}>
                      <summary style={{ cursor: "pointer", fontSize: "13px", color: "var(--subtext)", marginBottom: "8px" }}>
                        {cloudReady ? "Advanced: self-hosted relay" : "Relay settings"}
                      </summary>
                    <div className="form-row two-col">
                      <div>
                        <label>Relay URL</label>
                        <input
                          value={relayUrl}
                          onChange={(e) => setRelayUrl(e.target.value)}
                          placeholder="wss://relay.kino.app"
                        />
                      </div>
                      <div>
                        <label>Agent ID</label>
                        <input
                          value={agentId}
                          onChange={(e) => setAgentId(e.target.value)}
                          placeholder="UUID or any unique string"
                        />
                      </div>
                    </div>
                    <div className="form-row two-col">
                      <div>
                        <label>kino-control URL (optional)</label>
                        <input
                          value={controlUrl}
                          onChange={(e) => setControlUrl(e.target.value)}
                          placeholder="https://control.example.com"
                        />
                      </div>
                      <div>
                        <label>Relay token {controlUrl ? "(manager token)" : "(optional)"}</label>
                        <input
                          type="password"
                          value={relayToken}
                          onChange={(e) => setRelayToken(e.target.value)}
                          placeholder={controlUrl ? "Manager token from kino-control" : "Only if the relay requires auth"}
                        />
                      </div>
                    </div>
                    {controlUrl && (
                      <div className="form-row">
                        <div style={{ fontSize: "12px", color: "var(--subtext)" }}>
                          The relay is discovered from kino-control at connect time; the Relay URL
                          above becomes an optional fallback for when kino-control is unreachable.
                        </div>
                      </div>
                    )}
                    <div className="form-row">
                      <div style={{ background: "var(--overlay)", padding: "12px", borderRadius: "8px", fontSize: "13px" }}>
                        <p style={{ margin: "0 0 8px 0", color: "var(--subtext)" }}>Run this command on the target server to install and start the agent:</p>
                        <code style={{ background: "var(--bg)", padding: "6px 8px", display: "block", borderRadius: "4px", color: "var(--text)" }}>
                          kino-agent --relay-url {relayUrl} --agent-id {agentId}{relayToken ? " --token <agent token>" : ""}
                        </code>
                      </div>
                    </div>
                    </details>
                  </>
                ) : (
                  // Flag turned off while this host still uses agent mode. Don't surface the
                  // feature, but keep its saved config intact rather than silently clobbering it.
                  <div className="form-row">
                    <div style={{ background: "var(--overlay)", padding: "12px", borderRadius: "8px", fontSize: "13px", color: "var(--subtext)" }}>
                      This host connects through a relay, which is currently disabled. Enable it
                      in Settings to view or edit its connection settings.
                    </div>
                  </div>
                )}

                <div className="form-row">
                  <label>Username</label>
                  <input
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="root"
                  />
                </div>

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
                    <button
                      type="button"
                      className={defaultAuth === "Agent" ? "active" : ""}
                      onClick={() => setDefaultAuth("Agent")}
                    >
                      SSH Agent
                    </button>
                  </div>
                  <p className="hint">
                    {defaultAuth === "Agent"
                      ? "Authenticates via your running SSH agent (OpenSSH agent, or Pageant on Windows). No secret is stored in the vault."
                      : "Any of these can be stored - this sets which is used by default when connecting."}
                  </p>
                </div>

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
                        <button
                          type="button"
                          className="btn btn-sm btn-primary"
                          onClick={handleInstallKey}
                          disabled={installing || !hostname || !username || connectionMode !== "direct"}
                          title={
                            connectionMode !== "direct"
                              ? "Only available for direct SSH connections"
                              : "Append this key to ~/.ssh/authorized_keys on the server"
                          }
                        >
                          {installing ? "Installing…" : "Install on server"}
                        </button>
                      </div>
                      <textarea value={publicKey} readOnly rows={2} className="mono" />
                      {installMsg ? (
                        <p className="hint" style={{ color: "var(--green)" }}>{installMsg}</p>
                      ) : (
                        <p className="hint">
                          “Install on server” appends this to ~/.ssh/authorized_keys over SSH
                          (using the stored password, if any). The host key must already be trusted -
                          connect once first. Or copy it and paste it yourself.
                        </p>
                      )}
                    </div>
                  )}
                </div>
              </>
            )}

            {current === "forwards" && (
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
                        <span className="fwd-arrow">-</span>
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
                        <span className="fwd-arrow">-</span>
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
            )}

            {current === "advanced" && (
              <>
                <div className="form-row">
                  <label>Tag color <span className="hint-inline">(optional - flags the tab/host)</span></label>
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
                  <label>Heartbeat Ntfy Topic <span className="hint-inline">(optional)</span></label>
                  <input
                    value={ntfyTopic}
                    onChange={(e) => setNtfyTopic(e.target.value)}
                    placeholder="https://ntfy.sh/my-topic"
                  />
                  <p className="hint">
                    Receive push notifications via ntfy when this host goes offline.
                    Requires health polling to be enabled in Settings.
                  </p>
                </div>

                <div className="form-row">
                  <label>Environment <span className="hint-inline">(optional)</span></label>
                  <select
                    className="settings-select"
                    value={environment}
                    onChange={(e) => setEnvironment(e.target.value)}
                  >
                    <option value="">Not set</option>
                    <option value="development">Development</option>
                    <option value="staging">Staging</option>
                    <option value="production">Production</option>
                  </select>
                  <p className="hint">
                    Marking a host <strong>production</strong> frames its terminal, labels the
                    pane, and holds back commands like <code>rm -rf</code> or{" "}
                    <code>systemctl stop</code> behind a confirmation naming this host. It
                    catches the command meant for another window; it is not a guard against
                    someone determined to run it.
                  </p>
                </div>

                <div className="form-row">
                  <label>Folder / Group <span className="hint-inline">(optional)</span></label>
                  {existingGroups.length > 0 && !creatingGroup ? (
                    <select
                      className="settings-select"
                      value={existingGroups.includes(group) ? group : ""}
                      onChange={(e) => {
                        if (e.target.value === "__new__") {
                          setGroup("");
                          setCreatingGroup(true);
                        } else {
                          setGroup(e.target.value);
                        }
                      }}
                    >
                      <option value="">No group</option>
                      {existingGroups.map((g) => (
                        <option key={g} value={g}>
                          {g}
                        </option>
                      ))}
                      <option value="__new__">+ New group…</option>
                    </select>
                  ) : (
                    <div className="group-new-row">
                      <input
                        value={group}
                        onChange={(e) => setGroup(e.target.value)}
                        placeholder="e.g. Production, Homelab"
                        autoFocus={creatingGroup}
                      />
                      {existingGroups.length > 0 && (
                        <button
                          type="button"
                          className="btn btn-sm"
                          onClick={() => {
                            setGroup("");
                            setCreatingGroup(false);
                          }}
                        >
                          Pick existing
                        </button>
                      )}
                    </div>
                  )}
                </div>

                <div className="form-row">
                  <label>Operating system <span className="hint-inline">(optional - sets the host icon)</span></label>
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

                {connectionMode === "direct" && (
                  <div className="form-row">
                    <label>Jump host / bastion <span className="hint-inline">(optional - tunnel through another host)</span></label>
                    <select
                      className="settings-select"
                      value={jumpCandidates.some((h) => h.id === jumpHost) ? jumpHost : ""}
                      onChange={(e) => setJumpHost(e.target.value)}
                    >
                      <option value="">None (connect directly)</option>
                      {jumpCandidates.map((h) => (
                        <option key={h.id} value={h.id}>
                          {h.name} ({h.username}@{h.hostname})
                        </option>
                      ))}
                    </select>
                    {jumpHost && (
                      <p className="hint">
                        kino opens an SSH session to the bastion, then tunnels to this host through it
                        (like <span className="mono">ssh -J</span>). Each hop's host key is verified
                        independently. Bastions may themselves have a jump host, forming a chain.
                      </p>
                    )}
                  </div>
                )}

                {connectionMode === "direct" && (
                  <div className="form-section">
                    <div className="form-section-title">
                      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M4 12h16M4 6h16M4 18h16" />
                      </svg>
                      <span>Proxy</span>
                      <span className="hint-inline" style={{ marginLeft: "auto" }}>dial through a SOCKS5 / HTTP proxy</span>
                    </div>
                    <div className="form-row">
                      <select
                        className="settings-select"
                        value={proxyType}
                        onChange={(e) => setProxyType(e.target.value)}
                      >
                        <option value="">No proxy (direct)</option>
                        <option value="socks5">SOCKS5</option>
                        <option value="http">HTTP CONNECT</option>
                      </select>
                    </div>
                    {proxyType && (
                      <>
                        <div className="form-row two-col">
                          <div>
                            <label>Proxy host</label>
                            <input
                              value={proxyHost}
                              onChange={(e) => setProxyHost(e.target.value)}
                              placeholder="127.0.0.1"
                            />
                          </div>
                          <div>
                            <label>Proxy port</label>
                            <input
                              type="number"
                              value={proxyPort}
                              onChange={(e) => setProxyPort(Number(e.target.value))}
                              min={1}
                              max={65535}
                            />
                          </div>
                        </div>
                        <div className="form-row two-col">
                          <div>
                            <label>Proxy username <span className="hint-inline">(optional)</span></label>
                            <input
                              value={proxyUsername}
                              onChange={(e) => setProxyUsername(e.target.value)}
                              autoComplete="off"
                            />
                          </div>
                          <div>
                            <label>Proxy password <span className="hint-inline">(optional)</span></label>
                            <input
                              type="password"
                              value={proxyPassword}
                              onChange={(e) => setProxyPassword(e.target.value)}
                              autoComplete="off"
                            />
                          </div>
                        </div>
                        {proxyType === "socks5" && (
                          <p className="hint">The proxy resolves the hostname (no DNS leak).</p>
                        )}
                      </>
                    )}
                  </div>
                )}

                <div className="form-section">
                  <div className="form-section-title">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <polyline points="16 18 22 12 16 6" />
                      <polyline points="8 6 2 12 8 18" />
                    </svg>
                    <span>Run on connect</span>
                  </div>
                  {snippets.length === 0 ? (
                    <p className="hint">No snippets yet. Create them in Settings - Snippets, then select them here.</p>
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
              </>
            )}
          </div>

          {error && <p className="form-error">{error}</p>}

          <div className="modal-footer" style={{ paddingTop: "16px" }}>
            <button type="button" className="btn" onClick={onClose} style={{ marginRight: "auto" }}>
              Cancel
            </button>
            {step > 0 && (
              <button type="button" className="btn" onClick={() => setStep(step - 1)}>
                Back
              </button>
            )}
            {!isLast && (
              <button type="button" className="btn" onClick={() => setStep(step + 1)}>
                Next
              </button>
            )}
            <button type="submit" className="btn btn-primary" disabled={saving}>
              {saving ? "Saving…" : "Save"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
