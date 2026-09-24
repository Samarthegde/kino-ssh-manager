//! Asking a person (KR-01-F5, F6, F7).
//!
//! Guarded mode's whole point is the call nobody wrote a rule for: instead of
//! guessing, `kino-mcp` stops and asks. Until now there was nothing to ask, so
//! every `Ask` became a refusal. This is the channel.
//!
//! **The shape.** One JSON line in, one JSON line out, over a Unix socket
//! beside the vault. `kino-mcp` connects per request, the app answers, the
//! connection closes. No framing to get wrong, no state to resynchronise, and
//! a request that dies with its connection cannot leave an approval behind.
//!
//! **Deny is the answer to every failure.** Not reachable, not unlocked, not
//! answered in time, not parsed: all deny. The three of those a person can act
//! on - no app, locked vault, out of time - are named in the refusal, because
//! "denied" with no reason sends someone hunting through their rules for a
//! rule that does not exist.
//!
//! **Two of them are immediate** (KR-01-F7). A closed socket and a locked
//! vault are answers, not silence, so waiting out the timeout would only teach
//! an assistant that Kino hangs.
//!
//! **The reply cannot approve itself** (KR-01-S5). The decision is a field the
//! *app* fills in; nothing in the request influences it, and an unparseable
//! reply is a denial rather than a default.
//!
//! Unix only for now. Windows needs a named pipe with an ACL pinned to the
//! user's SID, and shipping an IPC channel I cannot test on a platform where
//! getting the ACL wrong means any local process can approve its own commands
//! is worse than the honest refusal Windows has today.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Bumped only if the line format changes incompatibly. An app and a binary
/// from different releases must not half-understand each other.
pub const PROTOCOL: u8 = 1;

/// How long the app has to answer before the call is denied.
pub const DEFAULT_TIMEOUT_SECS: u32 = 120;

/// What `kino-mcp` sends. Everything here is descriptive: the app decides.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ApprovalRequest {
    pub v: u8,
    /// Ties the reply to this request on a shared connection-less channel.
    pub id: String,
    pub tool: String,
    pub host_id: String,
    pub host_name: String,
    /// The command, path or snippet body, verbatim. The modal shows this
    /// unwrapped: a command that looks harmless because it was elided is the
    /// one failure this whole feature exists to prevent.
    pub argument: String,
    pub client_name: String,
    pub client_version: String,
    pub timeout_secs: u32,
}

/// What the app sends back.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ApprovalReply {
    pub id: String,
    /// `approve_once`, `approve_session` or `deny`. Unknown values are treated
    /// as `deny`, so a newer app can add a decision without an older binary
    /// mistaking it for permission.
    pub decision: String,
    /// Why, when it was denied: `denied_by_user`, `vault_locked`,
    /// `app_not_running`, `expired`, `broken_channel`, `unsupported_platform`.
    pub reason: Option<String>,
}

impl ApprovalReply {
    pub fn deny(id: &str, reason: &str) -> ApprovalReply {
        ApprovalReply {
            id: id.to_string(),
            decision: "deny".into(),
            reason: Some(reason.to_string()),
        }
    }
}

/// What the gate does with a reply.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Verdict {
    /// Allow this call only.
    Once,
    /// Allow this call, and the same one again without asking, until
    /// `kino-mcp` restarts. Restarting is the revocation.
    Session,
    /// Refuse, with a reason worth showing.
    Denied(&'static str),
}

/// Read a reply as a decision.
///
/// Anything unrecognised, malformed or mismatched is a denial. The id is
/// checked because a reply to a different request is not an answer to this
/// one, whatever it says.
pub fn verdict(reply: &ApprovalReply, expect_id: &str) -> Verdict {
    if reply.id != expect_id {
        return Verdict::Denied("broken_channel");
    }
    match reply.decision.as_str() {
        "approve_once" => Verdict::Once,
        "approve_session" => Verdict::Session,
        _ => match reply.reason.as_deref() {
            Some("vault_locked") => Verdict::Denied("vault_locked"),
            Some("expired") => Verdict::Denied("expired"),
            Some("app_not_running") => Verdict::Denied("app_not_running"),
            Some("broken_channel") => Verdict::Denied("broken_channel"),
            // Includes "denied_by_user" and anything a newer app invents: a
            // person refused, as far as this version can tell.
            _ => Verdict::Denied("denied_by_user"),
        },
    }
}

/// A sentence for the refusal, by reason. The assistant relays this to a
/// person, so it says what to do rather than only what happened.
pub fn explain(reason: &str, host: &str, tool: &str) -> String {
    match reason {
        "app_not_running" => format!(
            "'{host}' is in guarded mode, so {tool} needs approval in Kino - and Kino is not \
             running. Start it and try again, or add an allow rule for this command."
        ),
        "vault_locked" => format!(
            "'{host}' is in guarded mode, so {tool} needs approval in Kino - and the vault is \
             locked. Unlock it and try again."
        ),
        "expired" => format!(
            "Nobody answered the approval request for {tool} on '{host}' in time, so it was \
             refused. Try again while you are at the machine."
        ),
        "unsupported_platform" => format!(
            "'{host}' is in guarded mode, so {tool} needs approval in Kino - which this \
             platform cannot do yet. Add an allow rule for this command, or use full access."
        ),
        "denied_by_user" => format!("The approval for {tool} on '{host}' was refused in Kino."),
        _ => format!("The approval for {tool} on '{host}' could not be obtained."),
    }
}

/// Where the socket lives: beside the vault, in the directory Kino already
/// owns, so its permissions are the ones protecting the vault itself.
pub fn socket_path() -> PathBuf {
    crate::vault::vault_path()
        .parent()
        .unwrap()
        .join("mcp_approval.sock")
}

/// Ask the app, and wait for an answer (client side, in `kino-mcp`).
#[cfg(unix)]
pub async fn ask(request: &ApprovalRequest) -> Verdict {
    ask_at(&socket_path(), request).await
}

/// The same, against a given socket, so tests never reach for the one a
/// running Kino is listening on.
#[cfg(unix)]
pub async fn ask_at(path: &std::path::Path, request: &ApprovalRequest) -> Verdict {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    // Not reachable is an answer, and an instant one (KR-01-F7).
    let Ok(stream) = UnixStream::connect(path).await else {
        return Verdict::Denied("app_not_running");
    };

    let Ok(line) = serde_json::to_string(request) else {
        return Verdict::Denied("broken_channel");
    };

    let mut stream = BufReader::new(stream);
    if stream.get_mut().write_all(line.as_bytes()).await.is_err()
        || stream.get_mut().write_all(b"\n").await.is_err()
    {
        return Verdict::Denied("broken_channel");
    }

    // The app enforces the same deadline; this one covers an app that accepted
    // the connection and then stopped answering, which its own timer cannot.
    let mut reply = String::new();
    let deadline = std::time::Duration::from_secs(request.timeout_secs as u64 + 5);
    match tokio::time::timeout(deadline, stream.read_line(&mut reply)).await {
        Ok(Ok(n)) if n > 0 => match serde_json::from_str::<ApprovalReply>(&reply) {
            Ok(reply) => verdict(&reply, &request.id),
            Err(_) => Verdict::Denied("broken_channel"),
        },
        // Closed without answering: the app quit mid-prompt.
        Ok(_) => Verdict::Denied("app_not_running"),
        Err(_) => Verdict::Denied("expired"),
    }
}

#[cfg(not(unix))]
pub async fn ask(_request: &ApprovalRequest) -> Verdict {
    Verdict::Denied("unsupported_platform")
}

/// The app's side: listen, prompt, answer.
///
/// Knows nothing about Tauri. It is handed two closures - "is the vault
/// unlocked?" and "show this to the user" - so the whole path can be tested
/// with no window, and so the window code cannot accidentally decide policy.
///
/// `Broker` itself is available on every platform, even where there is no
/// socket to feed it: the app's state is then one shape everywhere, and the
/// platform difference stays in the two functions that touch the socket.
pub mod broker {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use tokio::sync::oneshot;

    #[derive(Default)]
    pub struct Broker {
        /// Requests waiting on a person, by id. A request is removed when it
        /// is answered, when it expires, or when the connection dies - never
        /// left behind, because a stale entry is an approval nobody asked for.
        pending: Mutex<HashMap<String, oneshot::Sender<ApprovalReply>>>,
    }

    impl Broker {
        pub fn new() -> Arc<Broker> {
            Arc::new(Broker::default())
        }

        /// Answer a waiting request. False if it had already gone - expired,
        /// or the assistant hung up - which the UI shows rather than pretending
        /// the click did something.
        pub fn respond(&self, id: &str, decision: &str) -> bool {
            let sender = self.pending.lock().ok().and_then(|mut p| p.remove(id));
            match sender {
                Some(tx) => tx
                    .send(ApprovalReply {
                        id: id.to_string(),
                        decision: decision.to_string(),
                        reason: (decision == "deny").then(|| "denied_by_user".to_string()),
                    })
                    .is_ok(),
                None => false,
            }
        }

        /// Ids still waiting, so the app can close prompts nobody can answer
        /// any more (the vault locked, or the window reopened).
        pub fn waiting(&self) -> Vec<String> {
            self.pending
                .lock()
                .map(|p| p.keys().cloned().collect())
                .unwrap_or_default()
        }

        /// Refuse everything outstanding - what locking the vault means for a
        /// prompt already on screen.
        pub fn deny_all(&self, reason: &str) {
            let taken: Vec<_> = self
                .pending
                .lock()
                .map(|mut p| p.drain().collect())
                .unwrap_or_default();
            for (id, tx) in taken {
                let _ = tx.send(ApprovalReply::deny(&id, reason));
            }
        }
    }

    /// Bind the socket, replacing one left behind by a crash.
    ///
    /// Permissions are set to 0600 (KR-01-S4): the socket decides whether
    /// commands run on production hosts, so another user on the machine must
    /// not be able to answer for you.
    ///
    /// Deliberately `std`, not `tokio`: the app binds this during Tauri's
    /// `setup`, which runs on the main thread with no reactor, and tokio's
    /// own `bind` panics there ("there is no reactor running"). `serve`
    /// adopts it once it is inside the runtime. Binding here also means a
    /// failure is reported at startup rather than lost in a background task.
    #[cfg(unix)]
    pub fn bind(path: &std::path::Path) -> Result<std::os::unix::net::UnixListener, String> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        // A socket file outlives the process that made it; a leftover one only
        // ever refuses connections, so removing it is safe and necessary.
        let _ = std::fs::remove_file(path);
        let listener = std::os::unix::net::UnixListener::bind(path).map_err(|e| e.to_string())?;
        // Tokio requires this of an adopted listener; without it the accept
        // loop blocks the runtime thread it is on.
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("Could not set the approval socket non-blocking: {e}"))?;
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("Could not lock down the approval socket: {e}"))?;
        }
        Ok(listener)
    }

    /// Serve requests until the listener dies.
    #[cfg(unix)]
    ///
    /// `unlocked` is asked per request rather than once: the vault can lock
    /// while the server is still up, and a prompt for a vault that cannot run
    /// the command anyway is worse than a refusal that says so.
    pub async fn serve<U, N>(
        broker: Arc<Broker>,
        listener: std::os::unix::net::UnixListener,
        unlocked: U,
        notify: N,
    ) where
        U: Fn() -> bool + Send + Sync + 'static,
        N: Fn(ApprovalRequest) + Send + Sync + 'static,
    {
        // Adopted here, inside the runtime, for the reason `bind` explains.
        let Ok(listener) = tokio::net::UnixListener::from_std(listener) else {
            eprintln!("[kino] the approval socket could not be adopted; guarded mode will refuse");
            return;
        };
        let unlocked = Arc::new(unlocked);
        let notify = Arc::new(notify);
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let broker = broker.clone();
            let unlocked = unlocked.clone();
            let notify = notify.clone();
            tokio::spawn(async move {
                handle(broker, stream, unlocked, notify).await;
            });
        }
    }

    #[cfg(unix)]
    async fn handle<U, N>(
        broker: Arc<Broker>,
        stream: tokio::net::UnixStream,
        unlocked: Arc<U>,
        notify: Arc<N>,
    ) where
        U: Fn() -> bool + Send + Sync + 'static,
        N: Fn(ApprovalRequest) + Send + Sync + 'static,
    {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let mut stream = BufReader::new(stream);
        let mut line = String::new();
        if stream.read_line(&mut line).await.is_err() {
            return;
        }
        let Ok(request) = serde_json::from_str::<ApprovalRequest>(&line) else {
            return;
        };

        let reply = if request.v != PROTOCOL {
            // Different releases of the app and the binary. Refusing beats
            // guessing what an unfamiliar request means.
            ApprovalReply::deny(&request.id, "broken_channel")
        } else if !unlocked() {
            // Immediate, not after the timeout (KR-01-F7).
            ApprovalReply::deny(&request.id, "vault_locked")
        } else {
            let (tx, rx) = oneshot::channel();
            if let Ok(mut pending) = broker.pending.lock() {
                pending.insert(request.id.clone(), tx);
            }
            notify(request.clone());

            let wait = std::time::Duration::from_secs(request.timeout_secs.max(1) as u64);
            match tokio::time::timeout(wait, rx).await {
                Ok(Ok(reply)) => reply,
                // Nobody answered, or the app dropped the sender: both deny.
                _ => {
                    if let Ok(mut pending) = broker.pending.lock() {
                        pending.remove(&request.id);
                    }
                    ApprovalReply::deny(&request.id, "expired")
                }
            }
        };

        if let Ok(out) = serde_json::to_string(&reply) {
            let _ = stream.get_mut().write_all(out.as_bytes()).await;
            let _ = stream.get_mut().write_all(b"\n").await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> ApprovalRequest {
        ApprovalRequest {
            v: PROTOCOL,
            id: "abc".into(),
            tool: "ssh_exec".into(),
            host_id: "h1".into(),
            host_name: "web-prod".into(),
            argument: "systemctl restart nginx".into(),
            client_name: "claude-desktop".into(),
            client_version: "1.2.3".into(),
            timeout_secs: DEFAULT_TIMEOUT_SECS,
        }
    }

    #[test]
    fn a_request_survives_the_wire() {
        let line = serde_json::to_string(&request()).unwrap();
        assert!(!line.contains('\n'), "one request is one line");
        let back: ApprovalRequest = serde_json::from_str(&line).unwrap();
        assert_eq!(back, request());
    }

    #[test]
    fn an_approval_is_an_approval() {
        let r = ApprovalReply {
            id: "abc".into(),
            decision: "approve_once".into(),
            reason: None,
        };
        assert_eq!(verdict(&r, "abc"), Verdict::Once);
    }

    #[test]
    fn a_session_approval_is_distinct_from_a_single_one() {
        let r = ApprovalReply {
            id: "abc".into(),
            decision: "approve_session".into(),
            reason: None,
        };
        assert_eq!(verdict(&r, "abc"), Verdict::Session);
    }

    #[test]
    fn a_reply_to_a_different_request_is_not_an_answer() {
        let r = ApprovalReply {
            id: "other".into(),
            decision: "approve_once".into(),
            reason: None,
        };
        assert_eq!(verdict(&r, "abc"), Verdict::Denied("broken_channel"));
    }

    #[test]
    fn a_decision_nobody_recognises_is_a_denial() {
        // A newer app inventing "approve_for_an_hour" must not read as yes.
        let r = ApprovalReply {
            id: "abc".into(),
            decision: "approve_for_an_hour".into(),
            reason: None,
        };
        assert!(matches!(verdict(&r, "abc"), Verdict::Denied(_)));
    }

    #[test]
    fn the_reason_survives_so_the_refusal_can_say_it() {
        for (reason, expected) in [
            ("vault_locked", "vault_locked"),
            ("expired", "expired"),
            ("app_not_running", "app_not_running"),
            ("denied_by_user", "denied_by_user"),
        ] {
            assert_eq!(
                verdict(&ApprovalReply::deny("abc", reason), "abc"),
                Verdict::Denied(expected)
            );
        }
    }

    #[test]
    fn every_reason_explains_itself_without_repeating_the_code() {
        for reason in [
            "app_not_running",
            "vault_locked",
            "expired",
            "denied_by_user",
            "unsupported_platform",
        ] {
            let text = explain(reason, "web-prod", "ssh_exec");
            assert!(text.contains("web-prod"), "{reason}: {text}");
            assert!(!text.contains(reason), "{reason} leaked its code: {text}");
        }
    }

    // The client against a real socket. Nothing here touches the socket a
    // running Kino owns - each test gets its own in a temp directory.
    #[cfg(unix)]
    mod over_a_socket {
        use super::*;
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::{UnixListener, UnixStream};

        /// A stand-in app that answers every request with `reply`.
        fn app_answering(path: std::path::PathBuf, reply: Option<ApprovalReply>) {
            let listener = UnixListener::bind(&path).unwrap();
            tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = BufReader::new(stream);
                let mut line = String::new();
                stream.read_line(&mut line).await.unwrap();
                if let Some(reply) = reply {
                    let out = serde_json::to_string(&reply).unwrap();
                    stream.get_mut().write_all(out.as_bytes()).await.unwrap();
                    stream.get_mut().write_all(b"\n").await.unwrap();
                } else {
                    // Accepted, then silent: the app that hung mid-prompt.
                    std::future::pending::<()>().await;
                }
            });
        }

        #[tokio::test]
        async fn no_socket_at_all_denies_at_once() {
            // KR-01-F7: with the app closed this must not sit for two minutes.
            let dir = tempfile::tempdir().unwrap();
            let started = std::time::Instant::now();
            let v = ask_at(
                &dir.path().join("nothing.sock"),
                &ApprovalRequest {
                    timeout_secs: 120,
                    ..request()
                },
            )
            .await;
            assert_eq!(v, Verdict::Denied("app_not_running"));
            assert!(
                started.elapsed().as_secs() < 2,
                "it waited: {:?}",
                started.elapsed()
            );
        }

        #[tokio::test]
        async fn an_approval_comes_back_as_one() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("a.sock");
            app_answering(
                path.clone(),
                Some(ApprovalReply {
                    id: "abc".into(),
                    decision: "approve_once".into(),
                    reason: None,
                }),
            );
            assert_eq!(ask_at(&path, &request()).await, Verdict::Once);
        }

        #[tokio::test]
        async fn a_refusal_comes_back_with_its_reason() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("b.sock");
            app_answering(
                path.clone(),
                Some(ApprovalReply::deny("abc", "denied_by_user")),
            );
            assert_eq!(
                ask_at(&path, &request()).await,
                Verdict::Denied("denied_by_user")
            );
        }

        #[tokio::test]
        async fn an_app_that_quits_mid_prompt_denies() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("c.sock");
            let listener = UnixListener::bind(&path).unwrap();
            tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                drop(stream); // closed without answering
            });
            assert_eq!(
                ask_at(&path, &request()).await,
                Verdict::Denied("app_not_running")
            );
        }

        #[tokio::test(start_paused = true)]
        async fn an_app_that_never_answers_denies_rather_than_waiting() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("d.sock");
            app_answering(path.clone(), None);
            // Paused clock: the wait is real to the code, instant to the test.
            assert_eq!(ask_at(&path, &request()).await, Verdict::Denied("expired"));
        }

        #[tokio::test]
        async fn the_request_reaches_the_app_intact() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("e.sock");
            let listener = UnixListener::bind(&path).unwrap();
            let seen = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = BufReader::new(stream);
                let mut line = String::new();
                stream.read_line(&mut line).await.unwrap();
                let out =
                    serde_json::to_string(&ApprovalReply::deny("abc", "denied_by_user")).unwrap();
                stream.get_mut().write_all(out.as_bytes()).await.unwrap();
                stream.get_mut().write_all(b"\n").await.unwrap();
                serde_json::from_str::<ApprovalRequest>(&line).unwrap()
            });
            ask_at(&path, &request()).await;
            let got = seen.await.unwrap();
            assert_eq!(got.argument, "systemctl restart nginx");
            assert_eq!(got.host_name, "web-prod");
            assert_eq!(got.client_name, "claude-desktop");
        }

        // Keeps the import used in every build of this module.
        #[allow(dead_code)]
        fn _unused(_: UnixStream) {}
    }

    /// The app's side, end to end: a real socket, a real request from the
    /// client, and a decision made the way the window will make it.
    #[cfg(unix)]
    mod with_the_broker {
        use super::super::broker::{self, Broker};
        use super::*;
        use std::sync::Arc;

        struct Running {
            broker: Arc<Broker>,
            path: std::path::PathBuf,
            /// Requests the "window" was shown.
            seen: Arc<std::sync::Mutex<Vec<ApprovalRequest>>>,
            _dir: tempfile::TempDir,
        }

        fn start(unlocked: bool) -> Running {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("approval.sock");
            let listener = broker::bind(&path).unwrap();
            let broker = Broker::new();
            let seen = Arc::new(std::sync::Mutex::new(Vec::new()));

            let b = broker.clone();
            let s = seen.clone();
            tokio::spawn(async move {
                broker::serve(
                    b,
                    listener,
                    move || unlocked,
                    move |req| s.lock().unwrap().push(req),
                )
                .await;
            });

            Running {
                broker,
                path,
                seen,
                _dir: dir,
            }
        }

        /// Wait for the prompt to arrive, the way the window does.
        async fn first_prompt(
            seen: &Arc<std::sync::Mutex<Vec<ApprovalRequest>>>,
        ) -> ApprovalRequest {
            for _ in 0..200 {
                if let Some(r) = seen.lock().unwrap().first().cloned() {
                    return r;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            panic!("no prompt ever appeared");
        }

        #[tokio::test]
        async fn approving_in_the_app_lets_the_call_through() {
            let app = start(true);
            let asking = {
                let path = app.path.clone();
                tokio::spawn(async move { ask_at(&path, &request()).await })
            };

            let prompt = first_prompt(&app.seen).await;
            assert_eq!(prompt.argument, "systemctl restart nginx");
            assert!(app.broker.respond(&prompt.id, "approve_once"));

            assert_eq!(asking.await.unwrap(), Verdict::Once);
        }

        #[tokio::test]
        async fn refusing_in_the_app_refuses_the_call() {
            let app = start(true);
            let asking = {
                let path = app.path.clone();
                tokio::spawn(async move { ask_at(&path, &request()).await })
            };
            let prompt = first_prompt(&app.seen).await;
            app.broker.respond(&prompt.id, "deny");
            assert_eq!(asking.await.unwrap(), Verdict::Denied("denied_by_user"));
        }

        #[tokio::test]
        async fn a_locked_vault_denies_without_asking_anyone() {
            // KR-01-F7: immediately, and no prompt - there is nothing a person
            // could usefully approve while the vault is shut.
            let app = start(false);
            let started = std::time::Instant::now();
            let v = ask_at(
                &app.path,
                &ApprovalRequest {
                    timeout_secs: 120,
                    ..request()
                },
            )
            .await;
            assert_eq!(v, Verdict::Denied("vault_locked"));
            assert!(started.elapsed().as_secs() < 2);
            assert!(app.seen.lock().unwrap().is_empty(), "nobody was prompted");
        }

        #[tokio::test]
        async fn locking_the_vault_refuses_a_prompt_already_on_screen() {
            let app = start(true);
            let asking = {
                let path = app.path.clone();
                tokio::spawn(async move { ask_at(&path, &request()).await })
            };
            first_prompt(&app.seen).await;
            app.broker.deny_all("vault_locked");
            assert_eq!(asking.await.unwrap(), Verdict::Denied("vault_locked"));
        }

        #[tokio::test(start_paused = true)]
        async fn a_prompt_nobody_answers_expires_into_a_refusal() {
            // Raw connection rather than `ask_at`: the client keeps its own
            // deadline a few seconds behind the app's, and under a paused
            // clock whichever timer is registered first wins the race. This
            // is about the app's timer, so the client's is left out of it.
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

            let app = start(true);
            let stream = tokio::net::UnixStream::connect(&app.path).await.unwrap();
            let mut stream = BufReader::new(stream);
            let line = serde_json::to_string(&ApprovalRequest {
                timeout_secs: 120,
                ..request()
            })
            .unwrap();
            stream.get_mut().write_all(line.as_bytes()).await.unwrap();
            stream.get_mut().write_all(b"\n").await.unwrap();

            let mut reply = String::new();
            stream.read_line(&mut reply).await.unwrap();
            let reply: ApprovalReply = serde_json::from_str(&reply).unwrap();
            assert_eq!(reply.decision, "deny");
            assert_eq!(reply.reason.as_deref(), Some("expired"));
            assert!(
                app.broker.waiting().is_empty(),
                "an expired request must not stay answerable"
            );
            assert!(
                !app.broker.respond("abc", "approve_once"),
                "and approving it afterwards must do nothing"
            );
        }

        #[tokio::test]
        async fn answering_something_that_already_expired_does_nothing() {
            let app = start(true);
            assert!(!app.broker.respond("never-existed", "approve_once"));
        }

        #[tokio::test]
        async fn a_request_from_a_different_protocol_version_is_refused() {
            let app = start(true);
            let v = ask_at(&app.path, &ApprovalRequest { v: 99, ..request() }).await;
            assert_eq!(v, Verdict::Denied("broken_channel"));
            assert!(app.seen.lock().unwrap().is_empty());
        }

        #[tokio::test]
        async fn the_socket_is_not_readable_by_other_users() {
            // KR-01-S4: this socket decides whether commands run on production.
            use std::os::unix::fs::PermissionsExt;
            let app = start(true);
            let mode = std::fs::metadata(&app.path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "mode was {:o}", mode & 0o777);
        }

        #[test]
        fn binding_needs_no_runtime() {
            // The app binds during Tauri's `setup`, which runs on the main
            // thread with no reactor - tokio's own bind panics there, and the
            // app died on startup because of it. A plain #[test] is the only
            // way to cover that: every #[tokio::test] has a reactor, so none
            // of them could ever have caught this.
            let dir = tempfile::tempdir().unwrap();
            assert!(broker::bind(&dir.path().join("startup.sock")).is_ok());
        }

        #[tokio::test]
        async fn a_socket_left_behind_by_a_crash_is_replaced() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("stale.sock");
            std::fs::write(&path, b"not really a socket").unwrap();
            assert!(
                broker::bind(&path).is_ok(),
                "a stale file must not stop startup"
            );
        }
    }
}
