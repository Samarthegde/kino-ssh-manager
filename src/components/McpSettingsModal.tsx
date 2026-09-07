import { useEffect, useMemo, useState } from "react";
import { McpBinaryCheck, McpConfig, McpMode, useVaultStore } from "../store";

interface Props {
  onClose: () => void;
}

/**
 * The MCP server's control panel.
 *
 * Two things are being decided here, and the UI has to make both obvious: the
 * password that encrypts the exposed vault, and *which hosts go into it*. The
 * second is the security boundary - anything ticked is reachable by an
 * assistant with a full shell, and anything unticked is invisible to it.
 */
const MODE_LABELS: Record<McpMode, string> = {
  read_only: "Read-only",
  guarded: "Guarded",
  full: "Full access",
};

/** What each mode actually permits, in the panel's own words. */
const MODE_BLURB: Record<McpMode, string> = {
  read_only:
    "Reads files and listings. Runs a command only if a rule below names it. Never writes.",
  guarded:
    "Everything is reachable, but anything no rule allows needs a person to approve it - and approval isn't wired up yet, so it is refused instead.",
  full: "No policy at all. The assistant has the access you have.",
};

type PolicyDraft = { mode: McpMode; rulesText: string };

export function McpSettingsModal({ onClose }: Props) {
  const {
    mcpGetConfig,
    mcpSetPassword,
    mcpSetExposedHosts,
    mcpSetHostPolicy,
    mcpSetGlobalRules,
    checkMcpBinary,
    hosts,
  } = useVaultStore();
  const [binary, setBinary] = useState<McpBinaryCheck | null>(null);
  useEffect(() => {
    checkMcpBinary().then(setBinary).catch(() => setBinary(null));
  }, [checkMcpBinary]);

  const [config, setConfig] = useState<McpConfig | null>(null);
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [exposed, setExposed] = useState<Set<string>>(new Set());
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState(false);
  const [copied, setCopied] = useState(false);
  const [policies, setPolicies] = useState<Record<string, PolicyDraft>>({});
  const [globalRules, setGlobalRules] = useState("");
  const [editingRules, setEditingRules] = useState<string | null>(null);
  /** A host whose jump to full access is waiting to be confirmed by name. */
  const [pendingFull, setPendingFull] = useState<string | null>(null);

  useEffect(() => {
    mcpGetConfig()
      .then((c) => {
        setConfig(c);
        setExposed(new Set(c.exposed_host_ids));
        const drafts: Record<string, PolicyDraft> = {};
        for (const [id, p] of Object.entries(c.host_policies)) {
          drafts[id] = { mode: p.mode, rulesText: p.rules_text };
        }
        setPolicies(drafts);
        setGlobalRules(c.global_rules_text);
      })
      .catch((e) => setError(String(e)));
  }, [mcpGetConfig]);

  const configured = config?.configured ?? false;

  /** A host with no saved policy is read-only. The panel says so rather than
   *  showing a blank, because the default is the thing worth being sure of. */
  function draft(id: string): PolicyDraft {
    return policies[id] ?? { mode: "read_only", rulesText: "" };
  }

  function setDraft(id: string, patch: Partial<PolicyDraft>) {
    setPolicies((prev) => ({ ...prev, [id]: { ...draft(id), ...patch } }));
  }

  /** Full access is the one choice that gives away everything, so it is the
   *  one choice that has to be made twice, with the host named. */
  function chooseMode(id: string, mode: McpMode) {
    if (mode === "full") {
      setPendingFull(id);
      return;
    }
    setPendingFull(null);
    setDraft(id, { mode });
  }

  const fullHosts = Array.from(exposed).filter((id) => draft(id).mode === "full");

  function toggleHost(id: string) {
    setExposed((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  async function save() {
    if (password && password !== confirmPassword) {
      setError("The passwords don't match.");
      return;
    }
    setSaving(true);
    setError("");
    try {
      if (password) await mcpSetPassword(password);
      await mcpSetExposedHosts(Array.from(exposed));
      await mcpSetGlobalRules(globalRules);
      // Only the exposed hosts: a policy for a host nobody shares is noise.
      for (const id of exposed) {
        const d = draft(id);
        await mcpSetHostPolicy(id, d.mode, d.rulesText);
      }
      setConfig(await mcpGetConfig());
      setPassword("");
      setConfirmPassword("");
      setSaved(true);
      window.setTimeout(() => setSaved(false), 2000);
    } catch (e) {
      setError(String(e));
    } finally {
      setSaving(false);
    }
  }

  // What to paste into an MCP client's config. The password is deliberately a
  // placeholder: it is not echoed back from the vault, and a config file is the
  // last place it should be copied from.
  const clientConfig = useMemo(
    () =>
      JSON.stringify(
        {
          mcpServers: {
            kino: {
              command: config?.binary_hint ?? "kino-mcp",
              env: { KINO_MCP_PASSWORD: "your-mcp-password" },
            },
          },
        },
        null,
        2
      ),
    [config]
  );

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal mcp-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>MCP server</h2>
          <button className="icon-btn" onClick={onClose}>✕</button>
        </div>

        <div className="mcp-body">
          <p className="mcp-intro">
            Lets an AI assistant list hosts, run commands and read or write files over SSH -
            but only on the hosts you tick below. Everything else in your vault stays invisible
            to it.
          </p>

          {fullHosts.length > 0 ? (
            <div className="mcp-warn">
              {fullHosts.length === 1 ? "One host is" : `${fullHosts.length} hosts are`} exposed
              with <strong>full access</strong>:{" "}
              {fullHosts.map((id) => hosts.find((h) => h.id === id)?.name ?? id).join(", ")}. On{" "}
              {fullHosts.length === 1 ? "it" : "those"} an assistant has an unrestricted shell -
              the same access you have.
            </div>
          ) : (
            <p className="mcp-hint">
              A newly ticked host is <strong>read-only</strong>: an assistant can read files and
              listings on it, and can run a command only if a rule you wrote names it.
            </p>
          )}

          <section className="mcp-section">
            <p className="mcp-section-title">
              Password
              {configured && <span className="mcp-badge">set</span>}
            </p>
            <p className="mcp-hint">
              Encrypts the exposed hosts into their own file, so <code>kino-mcp</code> can read
              them without ever seeing your master password. Changing it rewrites that file, and
              anything still using the old password stops working.
            </p>
            <input
              type="password"
              className="mcp-input"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder={configured ? "Leave blank to keep the current password" : "Choose an MCP password"}
              autoComplete="new-password"
            />
            {password && (
              <input
                type="password"
                className="mcp-input"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="Confirm it"
                autoComplete="new-password"
              />
            )}
          </section>

          <section className="mcp-section">
            <p className="mcp-section-title">
              Exposed hosts
              <span className="mcp-badge">{exposed.size} of {hosts.length}</span>
            </p>
            <div className="mcp-hosts">
              {hosts.length === 0 ? (
                <p className="mcp-empty">No hosts in the vault yet.</p>
              ) : (
                hosts.map((h) => {
                  const on = exposed.has(h.id);
                  const d = draft(h.id);
                  return (
                    <div key={h.id} className={`mcp-host ${on ? "on" : ""}`}>
                      <label className="mcp-host-tick">
                        <input type="checkbox" checked={on} onChange={() => toggleHost(h.id)} />
                        <span className="mcp-host-name">{h.name}</span>
                        <span className="mcp-host-addr">
                          {h.username}@{h.hostname}
                        </span>
                        {on && d.mode !== "read_only" && (
                          <span className={`mcp-mode-tag ${d.mode}`}>{MODE_LABELS[d.mode]}</span>
                        )}
                      </label>

                      {on && (
                        <div className="mcp-host-policy">
                          <select
                            className="mcp-mode"
                            value={d.mode}
                            onChange={(e) => chooseMode(h.id, e.target.value as McpMode)}
                          >
                            {(Object.keys(MODE_LABELS) as McpMode[]).map((m) => (
                              <option key={m} value={m}>
                                {MODE_LABELS[m]}
                              </option>
                            ))}
                          </select>
                          <button
                            type="button"
                            className="btn btn-sm"
                            onClick={() => setEditingRules(editingRules === h.id ? null : h.id)}
                          >
                            Rules
                          </button>
                          <span className="mcp-mode-blurb">{MODE_BLURB[d.mode]}</span>
                        </div>
                      )}

                      {on && pendingFull === h.id && (
                        <div className="mcp-warn mcp-confirm-full">
                          Give an assistant <strong>full, unrestricted access</strong> to{" "}
                          <strong>{h.name}</strong>? It will be able to run anything you can.
                          <span className="mcp-confirm-actions">
                            <button
                              type="button"
                              className="btn btn-sm"
                              onClick={() => setPendingFull(null)}
                            >
                              Cancel
                            </button>
                            <button
                              type="button"
                              className="btn btn-sm btn-danger"
                              onClick={() => {
                                setDraft(h.id, { mode: "full" });
                                setPendingFull(null);
                              }}
                            >
                              Yes, full access to {h.name}
                            </button>
                          </span>
                        </div>
                      )}

                      {on && editingRules === h.id && (
                        <div className="mcp-rules">
                          <p className="mcp-hint">
                            One rule per line: <code>allow</code>, <code>deny</code> or{" "}
                            <code>ask</code>, then a pattern. <code>*</code> matches anything;
                            prefix a pattern with <code>re:</code> for a regular expression. The
                            first matching rule wins, and a host's rules are read before the
                            global ones. Rules match the command as written - they catch
                            mistakes, not someone determined to get around them.
                          </p>
                          <textarea
                            rows={4}
                            className="mcp-rules-text mono"
                            value={d.rulesText}
                            onChange={(e) => setDraft(h.id, { rulesText: e.target.value })}
                            placeholder={"allow systemctl status *\ndeny rm -rf *"}
                          />
                        </div>
                      )}
                    </div>
                  );
                })
              )}
            </div>
          </section>

          <section className="mcp-section">
            <p className="mcp-section-title">Rules for every exposed host</p>
            <p className="mcp-hint">
              Read after each host's own rules, so a host can carve out an exception to
              something written here. Leave it empty to decide per host.
            </p>
            <textarea
              rows={3}
              className="mcp-rules-text mono"
              value={globalRules}
              onChange={(e) => setGlobalRules(e.target.value)}
              placeholder={"deny rm -rf *\ndeny shutdown*"}
            />
          </section>

          <section className="mcp-section">
            <p className="mcp-section-title">
              The binary
              {binary?.matches === true && <span className="mcp-badge">verified</span>}
            </p>
            {binary?.matches === true ? (
              <p className="mcp-hint">
                The <code>kino-mcp</code> at <code>{binary.path}</code> is the one this version
                published. Nothing has replaced it.
              </p>
            ) : binary?.matches === false ? (
              <div className="mcp-warn">
                The <code>kino-mcp</code> on your PATH is <strong>not</strong> the file this
                version published. Either it is left over from another version, or something
                replaced it. It can reach every host you expose, so check it before using it.
                <br />
                <code>{binary.path}</code>
              </div>
            ) : (
              <p className="mcp-hint">
                {binary?.detail ?? "Checking…"} The expected SHA-256 for{" "}
                <code>{binary?.asset}</code> is published in each release's signed{" "}
                <code>SHA256SUMS</code>.
              </p>
            )}
            {binary?.expected && (
              <pre className="mcp-config">
                expected {binary.expected}
                {binary.actual ? `\nfound    ${binary.actual}` : ""}
              </pre>
            )}
          </section>

          <section className="mcp-section">
            <p className="mcp-section-title">Point your assistant at it</p>
            <pre className="mcp-config">{clientConfig}</pre>
            <div className="mcp-config-actions">
              <button
                className="btn btn-sm"
                onClick={() => {
                  navigator.clipboard.writeText(clientConfig).catch(() => {});
                  setCopied(true);
                  window.setTimeout(() => setCopied(false), 1500);
                }}
              >
                {copied ? "Copied" : "Copy"}
              </button>
              <span className="mcp-hint">
                A host must be trusted in Kino first - the MCP server refuses hosts whose key it
                hasn't seen.
              </span>
            </div>
          </section>

          {error && <p className="form-error">{error}</p>}
        </div>

        <div className="mcp-foot">
          <button
            className="btn btn-primary btn-sm"
            onClick={() => void save()}
            disabled={saving || (!configured && !password)}
          >
            {saving ? "Saving…" : saved ? "Saved" : "Save"}
          </button>
          <button className="btn btn-sm" onClick={onClose}>Close</button>
          {!configured && !password && (
            <span className="mcp-hint">Set a password to enable the server.</span>
          )}
        </div>
      </div>
    </div>
  );
}
