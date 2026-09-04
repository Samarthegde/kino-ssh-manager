import { useCallback, useEffect, useMemo, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { save } from "@tauri-apps/plugin-dialog";
import {
  AuditReport,
  HostAudit,
  HostProbe,
  RotateOutcome,
  SshGrade,
  useVaultStore,
} from "../store";

interface Props {
  onClose: () => void;
}

const SEVERITY_ORDER = { high: 0, medium: 1, low: 2 } as const;

/** Weakest first. A fleet audit is read top-down and then stopped. */
const GRADE_ORDER: Record<SshGrade, number> = { weak: 0, classical: 1, pq: 2 };

const GRADE_LABEL: Record<SshGrade, string> = {
  weak: "Weak",
  classical: "Classical",
  pq: "Post-quantum",
};

/** Old enough that the host may have been patched since. */
const STALE_AFTER_SECONDS = 30 * 86_400;

function ago(unix: number, now: number): string {
  const secs = Math.max(0, now - unix);
  if (secs < 90) return "just now";
  if (secs < 5400) return `${Math.round(secs / 60)} min ago`;
  if (secs < 172_800) return `${Math.round(secs / 3600)} h ago`;
  return `${Math.round(secs / 86_400)} days ago`;
}

/** One CSV field, quoted only when it has to be. */
function csvField(v: string | null | undefined): string {
  const s = v ?? "";
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function worst(host: HostAudit): keyof typeof SEVERITY_ORDER | null {
  return host.findings.length === 0
    ? null
    : (host.findings[0].severity as keyof typeof SEVERITY_ORDER);
}

function keyAge(added: number | null, now: number): string {
  if (added === null) return "age unknown";
  const days = Math.floor((now - added) / 86_400);
  if (days < 1) return "added today";
  if (days < 60) return `${days} days old`;
  const months = Math.floor(days / 30);
  return months < 24 ? `${months} months old` : `${Math.floor(days / 365)} years old`;
}

/** `SHA256:abc…xyz` - enough to compare two by eye without filling the row. */
function shortFingerprint(fp: string): string {
  const body = fp.replace(/^SHA256:/, "");
  return body.length > 20 ? `SHA256:${body.slice(0, 10)}…${body.slice(-6)}` : fp;
}

/**
 * The key audit, and the rotation that acts on it.
 *
 * The audit itself never leaves this machine: it reads the keys already in the
 * vault and says what they are. Rotation is the only thing here that touches a
 * host, and it is deliberately one host at a time with a confirmation - there is
 * no "fix everything" button, because a rotation that goes wrong on ten hosts at
 * once is a very bad afternoon.
 */
export function SecurityPanel({ onClose }: Props) {
  const { auditKeys, rotateKey, probeHostAlgorithms, writeTextFile, hosts } = useVaultStore();
  const [view, setView] = useState<"keys" | "transport">("keys");
  const [report, setReport] = useState<AuditReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [confirmId, setConfirmId] = useState<string | null>(null);
  const [rotatingId, setRotatingId] = useState<string | null>(null);
  const [progress, setProgress] = useState<string>("");
  const [outcome, setOutcome] = useState<{ id: string; result: RotateOutcome } | null>(null);
  const [showClean, setShowClean] = useState(false);

  // Probe results live for as long as the panel is open and no longer.
  //
  // Persisting them would mean a new encrypted sibling file, and with it the
  // whole lifecycle every other blob has - sync, re-key, zeroize on lock,
  // exclusion from profile export. That is a lot of surface to protect data
  // that regenerates in five seconds, and a stale crypto audit is worth less
  // than a fresh one anyway. So: scan when asked, label the age, throw away.
  const [probes, setProbes] = useState<HostProbe[] | null>(null);
  const [scanning, setScanning] = useState(false);
  const [openProbe, setOpenProbe] = useState<string | null>(null);
  const [exported, setExported] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setReport(await auditKeys());
      setError(null);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, [auditKeys]);

  useEffect(() => { void load(); }, [load]);

  // The backend narrates rotation step by step; without it the button would sit
  // there for the length of two SSH handshakes with nothing to show for itself.
  useEffect(() => {
    if (!rotatingId) return;
    let stop: (() => void) | undefined;
    let cancelled = false;
    listen<string>(`rotate-${rotatingId}`, (e) => setProgress(e.payload)).then((un) => {
      if (cancelled) un();
      else stop = un;
    });
    return () => {
      cancelled = true;
      stop?.();
    };
  }, [rotatingId]);

  async function rotate(host: HostAudit) {
    setConfirmId(null);
    setRotatingId(host.host_id);
    setProgress("Starting…");
    setOutcome(null);
    try {
      const result = await rotateKey(host.host_id);
      setOutcome({ id: host.host_id, result });
      setError(null);
      await load();
    } catch (e) {
      setError(String(e));
    } finally {
      setRotatingId(null);
      setProgress("");
    }
  }

  function toggle(id: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  const now = report?.generated_at ?? 0;
  const flagged = report?.hosts.filter((h) => h.findings.length > 0) ?? [];
  const clean = report?.hosts.filter((h) => h.findings.length === 0) ?? [];
  const sorted = [...flagged].sort(
    (a, b) => SEVERITY_ORDER[worst(a)!] - SEVERITY_ORDER[worst(b)!]
  );

  function renderHost(host: HostAudit, isClean: boolean) {
    const open = expanded.has(host.host_id);
    const busy = rotatingId === host.host_id;
    const severity = worst(host);
    return (
      <div
        key={host.host_id}
        className={`audit-host ${severity ? `sev-${severity}` : "sev-none"} ${busy ? "busy" : ""}`}
      >
        <div className="audit-host-head">
          <button
            className="audit-host-toggle"
            onClick={() => toggle(host.host_id)}
            aria-expanded={open}
          >
            <span className="audit-host-name">{host.host_name}</span>
            <span className="audit-host-key">
              {host.key
                ? `${host.key.algorithm}${host.key.bits ? ` ${host.key.bits}` : ""} · ${keyAge(host.key_added_at, now)}`
                : host.auth === "Agent"
                  ? "ssh-agent"
                  : "no key stored"}
            </span>
            {!isClean && (
              <span className="audit-count">
                {host.findings.length} {host.findings.length === 1 ? "note" : "notes"}
              </span>
            )}
          </button>

          {busy ? (
            <span className="audit-progress">{progress}</span>
          ) : confirmId === host.host_id ? (
            <span className="audit-confirm">
              <span className="audit-confirm-text">
                Generate a new key, install it, verify it, then remove the old one?
              </span>
              <button className="btn btn-sm btn-primary" onClick={() => void rotate(host)}>
                Rotate
              </button>
              <button className="btn btn-sm" onClick={() => setConfirmId(null)}>✕</button>
            </span>
          ) : (
            <button
              className="btn btn-sm"
              disabled={!!rotatingId || host.auth === "Agent"}
              title={
                host.auth === "Agent"
                  ? "This host authenticates through your ssh-agent; Kino holds no key to rotate"
                  : "Replace this host's key with a fresh ed25519 one"
              }
              onClick={() => setConfirmId(host.host_id)}
            >
              Rotate key
            </button>
          )}
        </div>

        {outcome?.id === host.host_id && (
          <p className={`audit-outcome ${outcome.result.old_key_removed ? "" : "partial"}`}>
            New key installed - {shortFingerprint(outcome.result.fingerprint)}.{" "}
            {outcome.result.old_key_removed
              ? "The old key was removed from the host."
              : outcome.result.note}
          </p>
        )}

        {open && (
          <div className="audit-detail">
            {host.key && (
              <p className="audit-fingerprint">
                {host.key.fingerprint}
                {host.key.encrypted && <span className="audit-tag">passphrase</span>}
              </p>
            )}
            {host.findings.map((f) => (
              <div key={f.id} className={`audit-finding sev-${f.severity}`}>
                <p className="audit-finding-title">
                  <span className="audit-sev">{f.severity}</span>
                  {f.title}
                </p>
                <p className="audit-finding-detail">{f.detail}</p>
              </div>
            ))}
            {host.findings.length === 0 && (
              <p className="audit-finding-detail">Nothing to report on this key.</p>
            )}
          </div>
        )}
      </div>
    );
  }

  async function scan() {
    setScanning(true);
    setError(null);
    try {
      setProbes(await probeHostAlgorithms(hosts));
    } catch (e) {
      setError(String(e));
    } finally {
      setScanning(false);
    }
  }

  const nowSecs = Math.floor(Date.now() / 1000);

  /** Weakest first, then unreachable, then the ones that were not probed. */
  const rankedProbes = useMemo(() => {
    if (!probes) return [];
    const rank = (p: HostProbe) =>
      p.assessment ? GRADE_ORDER[p.assessment.grade] : p.status === "unreachable" ? 3 : 4;
    return [...probes].sort((a, b) => rank(a) - rank(b));
  }, [probes]);

  function hostName(id: string): string {
    return hosts.find((h) => h.id === id)?.name ?? id;
  }

  async function exportProbes(format: "csv" | "json") {
    if (!probes) return;
    const stamp = new Date().toISOString().slice(0, 10);
    const path = await save({
      title: "Export transport audit",
      defaultPath: `kino-transport-audit-${stamp}.${format}`,
      filters: [{ name: format.toUpperCase(), extensions: [format] }],
    });
    if (!path) return;

    let body: string;
    if (format === "json") {
      body = JSON.stringify(
        probes.map((p) => ({ host: hostName(p.id), ...p })),
        null,
        2
      );
    } else {
      const rows = [
        ["host", "status", "grade", "kex", "host_key", "cipher", "mac", "banner", "findings"],
        ...rankedProbes.map((p) => [
          hostName(p.id),
          p.status,
          p.assessment?.grade ?? "",
          p.assessment?.kex ?? "",
          p.assessment?.host_key ?? "",
          p.assessment?.cipher ?? "",
          p.assessment?.mac ?? "",
          p.offered?.banner ?? p.detail ?? "",
          (p.assessment?.findings ?? []).map((f) => `${f.severity}: ${f.title}`).join("; "),
        ]),
      ];
      body = rows.map((r) => r.map(csvField).join(",")).join("\n");
    }
    await writeTextFile(body, path as string);
    setExported(`Saved to ${path}`);
    window.setTimeout(() => setExported(""), 4000);
  }

  function renderTransport() {
    if (!probes) {
      return (
        <div className="docker-empty">
          <p>
            Asks each host which key exchange, host key and cipher it offers, then says what a
            connection would actually use.
          </p>
          <p className="hint">
            No credentials are read and no session is opened, so this works with the vault
            locked. A host will log the connection, and no login.
          </p>
        </div>
      );
    }
    if (probes.length === 0) return <div className="docker-empty">No hosts in the vault yet.</div>;

    return rankedProbes.map((p) => {
      const a = p.assessment;
      const open = openProbe === p.id;
      const stale = nowSecs - p.checked_at > STALE_AFTER_SECONDS;
      return (
        <div key={p.id} className={`audit-host tp-${a?.grade ?? p.status}`}>
          <div className="audit-host-head">
            <button className="audit-host-toggle" onClick={() => setOpenProbe(open ? null : p.id)}>
              <span className="audit-host-name">{hostName(p.id)}</span>
              <span className="audit-host-key">
                {a ? `${a.kex ?? "no kex in common"} · ${a.host_key ?? "no host key in common"}` : p.detail}
              </span>
              <span className={`tp-grade ${a?.grade ?? p.status}`}>
                {a ? GRADE_LABEL[a.grade] : p.status === "unreachable" ? "Unreachable" : "Not probed"}
              </span>
            </button>
            <span className="audit-progress">
              {ago(p.checked_at, nowSecs)}
              {stale && " · stale"}
            </span>
          </div>

          {open && (
            <div className="audit-detail">
              {p.offered && (
                <p className="audit-fingerprint">
                  {p.offered.banner}
                  {a?.cipher && <span className="audit-tag">{a.cipher}</span>}
                  {a?.mac && <span className="audit-tag">{a.mac}</span>}
                </p>
              )}
              {(a?.findings ?? []).map((f, i) => (
                <div key={i} className={`audit-finding sev-${f.severity}`}>
                  <p className="audit-finding-title">
                    <span className="audit-sev">{f.severity}</span>
                    {f.title}
                  </p>
                  <p className="audit-finding-detail">{f.remediation}</p>
                </div>
              ))}
              {a && a.findings.length === 0 && (
                <p className="audit-finding-detail">
                  Nothing to report. This host negotiates a post-quantum key exchange with Kino.
                </p>
              )}
              {!a && <p className="audit-finding-detail">{p.detail}</p>}
            </div>
          )}
        </div>
      );
    });
  }

  return (
    <div className="modal-overlay" onClick={() => { if (!rotatingId) onClose(); }}>
      <div className="modal audit-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>Security</h2>
          <button className="icon-btn" onClick={onClose} disabled={!!rotatingId}>✕</button>
        </div>

        <div className="audit-tabs">
          <button
            className={`audit-tab ${view === "keys" ? "on" : ""}`}
            onClick={() => setView("keys")}
          >
            Keys
          </button>
          <button
            className={`audit-tab ${view === "transport" ? "on" : ""}`}
            onClick={() => setView("transport")}
          >
            Transport
          </button>
        </div>

        <div className="audit-toolbar">
          {view === "transport" ? (
            <>
              {probes && (
                <div className="audit-summary">
                  {(["weak", "classical", "pq"] as SshGrade[]).map((g) => {
                    const n = probes.filter((p) => p.assessment?.grade === g).length;
                    return n === 0 ? null : (
                      <span key={g} className={`tp-grade ${g}`}>
                        {n} {GRADE_LABEL[g].toLowerCase()}
                      </span>
                    );
                  })}
                  <span className="audit-scope">
                    {probes.length} host{probes.length === 1 ? "" : "s"} · asked directly, nothing
                    authenticated
                  </span>
                </div>
              )}
              {probes && (
                <>
                  <button className="btn btn-sm" onClick={() => void exportProbes("csv")}>
                    CSV
                  </button>
                  <button className="btn btn-sm" onClick={() => void exportProbes("json")}>
                    JSON
                  </button>
                </>
              )}
              <button className="btn btn-sm" onClick={() => void scan()} disabled={scanning}>
                {scanning ? "Scanning…" : probes ? "Scan again" : "Scan hosts"}
              </button>
            </>
          ) : (
            <>
          {report && (
            <div className="audit-summary">
              <span className="audit-chip sev-high">{report.high} high</span>
              <span className="audit-chip sev-medium">{report.medium} medium</span>
              <span className="audit-chip sev-low">{report.low} low</span>
              <span className="audit-scope">
                {report.hosts.length} host{report.hosts.length === 1 ? "" : "s"} · read locally,
                nothing was contacted
              </span>
            </div>
          )}
          <button
            className="btn btn-sm"
            onClick={() => void load()}
            disabled={loading || !!rotatingId}
          >
            Re-run
          </button>
            </>
          )}
        </div>

        {exported && <p className="audit-exported">{exported}</p>}

        {error && <p className="form-error">{error}</p>}

        <div className="audit-body">
          {view === "transport" ? (
            scanning && !probes ? (
              <div className="docker-empty">Asking each host…</div>
            ) : (
              renderTransport()
            )
          ) : loading && !report ? (
            <div className="docker-empty">Reading keys…</div>
          ) : report?.hosts.length === 0 ? (
            <div className="docker-empty">No hosts in the vault yet.</div>
          ) : (
            <>
              {sorted.length === 0 ? (
                <div className="docker-empty">
                  Every key checks out - modern algorithm, not shared, not stale.
                </div>
              ) : (
                sorted.map((h) => renderHost(h, false))
              )}

              {clean.length > 0 && (
                <div className="audit-clean">
                  <button className="audit-clean-toggle" onClick={() => setShowClean((v) => !v)}>
                    {showClean ? "Hide" : "Show"} {clean.length} host
                    {clean.length === 1 ? "" : "s"} with nothing to report
                  </button>
                  {showClean && clean.map((h) => renderHost(h, true))}
                </div>
              )}
            </>
          )}
        </div>

        <p className="audit-footnote">
          {view === "transport"
            ? "Kino compares what each host offers against the algorithms it will itself negotiate, so a finding is about a connection you would actually make. Hosts reached through a relay or a jump host are not probed, and say so rather than being guessed at."
            : "Rotation generates an ed25519 key, installs it, opens a second connection that can only authenticate with the new key, and only then removes the old one. If any step before that fails, the host is left exactly as it was."}
        </p>
      </div>
    </div>
  );
}
