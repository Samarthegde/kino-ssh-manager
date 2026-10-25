import { useCallback, useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { KbiChallenge, useVaultStore } from "../store";

/**
 * The prompt a server sends when it wants more than a key: a verification
 * code, a password the vault does not hold, a Duo push to confirm.
 *
 * Three things this window has to get right:
 *
 * - **The server's words are shown verbatim**, and labelled as the server's.
 *   A compromised host can write anything here, including "enter your Kino
 *   master password" - which is refusable only if it is clear who is asking.
 *   Kino never asks for the vault password in this window, and says so.
 * - **The countdown is real.** When it reaches zero the connection has already
 *   been dropped, so the window stops offering a button that would do nothing.
 * - **Nothing is remembered.** Answers go straight to the connection waiting
 *   on them and are not kept, offered as a default, or written anywhere. A
 *   code is good once.
 *
 * Prompts queue rather than stack: a bastion and the host behind it can each
 * ask, and two dialogs on top of each other is how the wrong one gets typed
 * into.
 */
export function KbiModal() {
  const { answerKbi, cancelKbi } = useVaultStore();
  const [queue, setQueue] = useState<KbiChallenge[]>([]);
  const [answers, setAnswers] = useState<string[]>([]);
  const [left, setLeft] = useState(0);
  const firstField = useRef<HTMLInputElement | null>(null);
  const current = queue[0];

  useEffect(() => {
    const un = listen<KbiChallenge>("kbi-challenge", (e) => {
      setQueue((q) => (q.some((c) => c.id === e.payload.id) ? q : [...q, e.payload]));
    });
    return () => {
      void un.then((f) => f());
    };
  }, []);

  const drop = useCallback((id: string) => {
    setQueue((q) => q.filter((c) => c.id !== id));
  }, []);

  // A fresh set of empty fields whenever a different prompt comes forward -
  // never carried over from the last one.
  useEffect(() => {
    if (!current) return;
    setAnswers(current.prompts.map(() => ""));
  }, [current?.id, current]);

  useEffect(() => {
    if (!current) return;
    setLeft(current.timeout_secs);
    const started = Date.now();
    const tick = window.setInterval(() => {
      const remaining = current.timeout_secs - Math.floor((Date.now() - started) / 1000);
      setLeft(remaining);
      // The connection gave up the moment this hit zero.
      if (remaining <= 0) drop(current.id);
    }, 250);
    return () => window.clearInterval(tick);
  }, [current, drop]);

  useEffect(() => {
    firstField.current?.focus();
  }, [current?.id]);

  if (!current) return null;

  async function send() {
    const id = current.id;
    const typed = [...answers];
    drop(id);
    try {
      await answerKbi(id, typed);
    } catch {
      // The prompt expired or the connection dropped. Nothing to undo.
    }
  }

  async function dismiss() {
    const id = current.id;
    drop(id);
    try {
      await cancelKbi(id);
    } catch {
      // Already gone; the connection is closed either way.
    }
  }

  return (
    <div className="modal-overlay approval-overlay">
      <div className="modal approval-modal kbi-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>{current.host_name} is asking</h2>
          <span className={`approval-countdown ${left <= 15 ? "urgent" : ""}`}>{left}s</span>
        </div>

        <div className="approval-body">
          {current.name.trim() && <p className="kbi-name">{current.name.trim()}</p>}
          {current.instruction.trim() && (
            <pre className="kbi-instruction">{current.instruction.trim()}</pre>
          )}

          <form
            onSubmit={(e) => {
              e.preventDefault();
              void send();
            }}
          >
            {current.prompts.map((prompt, i) => (
              <div className="form-group" key={`${current.id}-${i}`}>
                {/* The server's wording, as sent. Trimmed of trailing space
                    only, so "Verification code:" reads as a label. */}
                <label htmlFor={`kbi-${current.id}-${i}`}>{prompt.text.trim()}</label>
                <input
                  id={`kbi-${current.id}-${i}`}
                  ref={i === 0 ? firstField : undefined}
                  type={prompt.echo ? "text" : "password"}
                  value={answers[i] ?? ""}
                  autoComplete="off"
                  spellCheck={false}
                  onChange={(e) =>
                    setAnswers((a) => a.map((v, j) => (j === i ? e.target.value : v)))
                  }
                />
              </div>
            ))}
            {/* Submit lives in the form so Return sends, which is what
                anyone typing a six-digit code expects. */}
            <div className="mcp-foot approval-foot">
              <button type="button" className="btn btn-sm" onClick={() => void dismiss()}>
                Cancel
              </button>
              <button type="submit" className="btn btn-primary btn-sm">
                Send
              </button>
            </div>
          </form>

          <p className="mcp-hint">
            Those words come from <strong>{current.host_name}</strong>, not from Kino. Kino never
            asks for your vault password here, and nothing you type is stored.
            {queue.length > 1 && ` ${queue.length - 1} more waiting.`}
          </p>
        </div>
      </div>
    </div>
  );
}
