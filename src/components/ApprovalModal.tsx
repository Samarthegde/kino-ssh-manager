import { useCallback, useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { McpApprovalRequest, useVaultStore } from "../store";

/**
 * The prompt guarded mode exists for (KR-01-F6).
 *
 * An assistant has asked to run something no rule covers, and kino-mcp is
 * waiting on this window. Three things matter here:
 *
 * - The command is shown **verbatim and wrapped, never elided**. A command
 *   that looks harmless because the middle was cut is the exact failure this
 *   feature is meant to prevent.
 * - **Deny holds focus.** Return approves nothing; someone clearing a
 *   notification by muscle memory refuses, which is the recoverable mistake.
 * - The countdown is real. When it reaches zero kino-mcp has already refused
 *   on its own, so the window stops offering buttons that would do nothing.
 *
 * Requests queue rather than stack: an assistant can ask several times, and a
 * pile of modals is how someone ends up approving the second one by accident.
 */
export function ApprovalModal() {
  const { respondToApproval } = useVaultStore();
  const [queue, setQueue] = useState<McpApprovalRequest[]>([]);
  const [left, setLeft] = useState(0);
  const denyRef = useRef<HTMLButtonElement | null>(null);
  const current = queue[0];

  useEffect(() => {
    const un = listen<McpApprovalRequest>("mcp-approval", (e) => {
      setQueue((q) => (q.some((r) => r.id === e.payload.id) ? q : [...q, e.payload]));
    });
    return () => {
      void un.then((f) => f());
    };
  }, []);

  const drop = useCallback((id: string) => {
    setQueue((q) => q.filter((r) => r.id !== id));
  }, []);

  // One countdown per request, restarted when the next one comes forward.
  useEffect(() => {
    if (!current) return;
    setLeft(current.timeout_secs);
    const started = Date.now();
    const tick = window.setInterval(() => {
      const remaining = current.timeout_secs - Math.floor((Date.now() - started) / 1000);
      setLeft(remaining);
      // kino-mcp refused it the moment this hit zero; keeping the prompt up
      // would invite a click that quietly does nothing.
      if (remaining <= 0) drop(current.id);
    }, 250);
    return () => window.clearInterval(tick);
  }, [current, drop]);

  useEffect(() => {
    denyRef.current?.focus();
  }, [current?.id]);

  if (!current) return null;

  async function answer(decision: "approve_once" | "approve_session" | "deny") {
    const id = current.id;
    drop(id);
    try {
      await respondToApproval(id, decision);
    } catch {
      // The request expired or the assistant hung up. Nothing to undo: the
      // call was refused either way, which is the safe direction.
    }
  }

  return (
    <div className="modal-overlay approval-overlay">
      <div className="modal approval-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>Approve this command?</h2>
          <span className={`approval-countdown ${left <= 10 ? "urgent" : ""}`}>{left}s</span>
        </div>

        <div className="approval-body">
          <p className="mcp-hint">
            <strong>{current.client_name}</strong> {current.client_version} wants to run{" "}
            <code>{current.tool}</code> on <strong>{current.host_name}</strong>, which is in
            guarded mode. No rule covers it.
          </p>

          <pre className="approval-command mono">{current.argument}</pre>

          <p className="mcp-hint">
            Refusing is the default. An assistant can be steered by whatever it read on a host,
            so approve this only if you recognise it as work you asked for.
            {queue.length > 1 && ` ${queue.length - 1} more waiting.`}
          </p>
        </div>

        <div className="mcp-foot approval-foot">
          <button ref={denyRef} className="btn btn-sm" onClick={() => void answer("deny")}>
            Deny
          </button>
          <div className="approval-approve">
            <button className="btn btn-sm" onClick={() => void answer("approve_session")}>
              Approve while this session lasts
            </button>
            <button className="btn btn-primary btn-sm" onClick={() => void answer("approve_once")}>
              Approve once
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
