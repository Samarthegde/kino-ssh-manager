//! Keyboard-interactive authentication - the path 2FA actually uses.
//!
//! Password and public-key auth are a single exchange: send the secret, get a
//! yes or a no. Keyboard-interactive is a conversation. The server sends a
//! round of prompts ("Password:", then "Verification code:"), the client
//! answers them, and the server may ask again - several times, or with no
//! prompts at all when it only wants to show a banner. OpenSSH with PAM, Duo,
//! Google Authenticator and every `KbdInteractiveAuthentication yes` host work
//! this way, and without this they cannot be reached at all.
//!
//! **Two rules hold this module together.**
//!
//! *A stored password answers a password prompt, and nothing else.* A host with
//! a password in the vault should not make someone retype it, but a prompt
//! asking for a one-time code must never be answered from storage: it would
//! send the password where the code goes, to a server that asked for the code.
//! [`is_password_prompt`] is deliberately narrow, and when it is unsure the
//! answer is to ask the person.
//!
//! *Only a person who is there can be asked.* A health probe, a fleet call or
//! a cron run has nobody at the window, so it refuses and says so, naming the
//! host - rather than hanging until something times out. That is what
//! [`Asker::Nobody`] is for.
//!
//! The prompt text comes from the server, which means it is attacker-controlled
//! on a compromised host. It is shown verbatim because eliding it would hide
//! what is being asked - and the window that shows it says where the words came
//! from, so "Enter your Kino master password" reads as the server asking,
//! which is the only thing that makes it refusable.

use crate::vault::Host;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::oneshot;

/// How long a prompt stays answerable. Long enough to pull out a phone, short
/// enough that a forgotten window does not hold a half-open connection open
/// all afternoon.
pub const TIMEOUT_SECS: u64 = 120;

/// A server that has asked this many times is not going to be satisfied, and
/// the loop has to end somewhere.
const MAX_ROUNDS: usize = 8;

/// One line the server wants answered.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Prompt {
    /// The server's words, verbatim.
    pub text: String,
    /// False for a secret: the field hides what is typed.
    pub echo: bool,
}

/// One round of prompts, on its way to the window.
///
/// Carries only what a person needs to answer - never the stored password,
/// never the host's other credentials.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Challenge {
    pub id: String,
    pub host_id: String,
    pub host_name: String,
    /// What the server called this round. Usually empty.
    pub name: String,
    /// The server's longer explanation, if it sent one. Usually empty.
    pub instruction: String,
    /// Only the prompts that could not be answered from the vault.
    pub prompts: Vec<Prompt>,
    pub timeout_secs: u64,
}

/// Is this a prompt a stored password should answer?
///
/// Narrow on purpose. A prompt that mentions a code, a token or a second
/// factor is never answered from the vault even when it also says "password" -
/// "One-time password:" is a TOTP prompt, and sending the account password
/// there hands it to the server as if it were the code.
pub fn is_password_prompt(text: &str) -> bool {
    let t = text.to_ascii_lowercase();
    const SECOND_FACTOR: [&str; 12] = [
        "verification",
        "one-time",
        "one time",
        "otp",
        "token",
        "passcode",
        "code",
        "2fa",
        "two-factor",
        "second factor",
        "authenticator",
        "duo",
    ];
    if SECOND_FACTOR.iter().any(|w| t.contains(w)) {
        return false;
    }
    t.contains("password") || t.contains("passwd")
}

/// What to send for each prompt: `Some` where the vault can answer, `None`
/// where only the person at the window can.
pub fn plan(prompts: &[Prompt], stored_password: Option<&str>) -> Vec<Option<String>> {
    let stored = stored_password.filter(|p| !p.is_empty());
    prompts
        .iter()
        .map(|p| match stored {
            Some(pw) if is_password_prompt(&p.text) => Some(pw.to_string()),
            _ => None,
        })
        .collect()
}

/// An answer coming back from the window.
#[derive(Debug, Clone, PartialEq)]
pub enum Reply {
    Answers(Vec<String>),
    /// Cancelled, or made unanswerable - the vault locked, the window closed.
    Cancelled(String),
}

/// Prompts waiting on a person, by id.
///
/// Knows nothing about Tauri: the window hands it answers, the connection
/// waits on them, and a test can play either part. An entry is removed when it
/// is answered, cancelled or expires - a stale one would be a prompt nobody
/// can clear.
#[derive(Default)]
pub struct Broker {
    pending: Mutex<HashMap<String, oneshot::Sender<Reply>>>,
}

impl Broker {
    pub fn new() -> Arc<Broker> {
        Arc::new(Broker::default())
    }

    fn register(&self, id: &str) -> oneshot::Receiver<Reply> {
        let (tx, rx) = oneshot::channel();
        if let Ok(mut pending) = self.pending.lock() {
            pending.insert(id.to_string(), tx);
        }
        rx
    }

    fn take(&self, id: &str) -> Option<oneshot::Sender<Reply>> {
        self.pending.lock().ok().and_then(|mut p| p.remove(id))
    }

    /// Answer a waiting prompt. False when it had already gone - expired, or
    /// the connection dropped - which the window shows rather than pretending
    /// the click did something.
    pub fn answer(&self, id: &str, answers: Vec<String>) -> bool {
        match self.take(id) {
            Some(tx) => tx.send(Reply::Answers(answers)).is_ok(),
            None => false,
        }
    }

    pub fn cancel(&self, id: &str, reason: &str) -> bool {
        match self.take(id) {
            Some(tx) => tx.send(Reply::Cancelled(reason.to_string())).is_ok(),
            None => false,
        }
    }

    /// Cancel everything outstanding - what locking the vault means for a
    /// prompt already on screen.
    pub fn cancel_all(&self, reason: &str) {
        let taken: Vec<_> = self
            .pending
            .lock()
            .map(|mut p| p.drain().collect())
            .unwrap_or_default();
        for (_id, tx) in taken {
            let _ = tx.send(Reply::Cancelled(reason.to_string()));
        }
    }

    /// Ids still waiting, so the app can close prompts nobody can answer.
    pub fn waiting(&self) -> Vec<String> {
        self.pending
            .lock()
            .map(|p| p.keys().cloned().collect())
            .unwrap_or_default()
    }
}

/// Somebody is at the window and can be asked.
pub struct Person {
    /// Put the challenge in front of them. What that means - an event, a
    /// window, a test's channel - is the caller's business.
    pub show: Box<dyn Fn(&Challenge) + Send + Sync>,
    pub broker: Arc<Broker>,
    pub timeout: Duration,
}

/// Who, if anyone, can answer a prompt for this connection.
pub enum Asker {
    Person(Person),
    /// Nobody: a background probe, a fleet call, an assistant's tool call.
    /// The string names what was running, so the refusal can say it.
    Nobody(String),
}

impl Asker {
    pub fn nobody(what: &str) -> Asker {
        Asker::Nobody(what.to_string())
    }

    /// One round, answered by a person.
    pub async fn ask(&self, challenge: &Challenge) -> Result<Vec<String>, String> {
        match self {
            Asker::Nobody(what) => Err(format!(
                "'{}' asks for something only you can answer ({}), and {} cannot ask you. \
                 Open a terminal to this host and answer it there. Nothing ran.",
                challenge.host_name,
                first_prompt(challenge),
                what
            )),
            Asker::Person(person) => {
                let waiting = person.broker.register(&challenge.id);
                (person.show)(challenge);
                match tokio::time::timeout(person.timeout, waiting).await {
                    Ok(Ok(Reply::Answers(answers))) => Ok(answers),
                    Ok(Ok(Reply::Cancelled(reason))) => Err(match reason.as_str() {
                        "vault_locked" => format!(
                            "The vault locked while '{}' was waiting for an answer, so the \
                             connection was dropped.",
                            challenge.host_name
                        ),
                        _ => format!("Connection to '{}' cancelled.", challenge.host_name),
                    }),
                    // The window went away without answering.
                    Ok(Err(_)) => Err(format!(
                        "Nothing answered the prompt from '{}', so the connection was dropped.",
                        challenge.host_name
                    )),
                    Err(_) => {
                        person.broker.cancel(&challenge.id, "timed_out");
                        Err(format!(
                            "No answer for '{}' in {} seconds, so the connection was dropped. \
                             Connect again when you have the code to hand.",
                            challenge.host_name,
                            person.timeout.as_secs()
                        ))
                    }
                }
            }
        }
    }
}

/// The first prompt's text, for a refusal that says what was wanted. Quoted
/// because it is the server's wording, not ours.
fn first_prompt(challenge: &Challenge) -> String {
    match challenge.prompts.first() {
        Some(p) => format!("\"{}\"", p.text.trim()),
        None => "a keyboard-interactive answer".to_string(),
    }
}

/// What to say when the server refused.
///
/// The case worth catching: the host is set to password auth, the password was
/// right, and the server rejected it anyway because it only accepts
/// keyboard-interactive - which is how PAM-driven 2FA presents itself. "Authentication
/// failed" sends someone to check a password that was never the problem, so
/// when the server's own list of remaining methods includes
/// keyboard-interactive, the message says so and names the setting to change.
pub fn refused_message(host_name: &str, configured: &str, offers_prompt: bool) -> String {
    let what = match configured {
        "Password" => "the stored password",
        "SshKey" => "that key",
        "Agent" => "any key your SSH agent offered",
        "KeyboardInteractive" => "that answer",
        _ => "that method",
    };
    if offers_prompt && configured != "KeyboardInteractive" {
        format!(
            "'{host_name}' refused {what}, and offers an interactive login instead - a prompt for \
             a password or a verification code. Set this host's method to '2FA prompt' in its \
             settings and connect again."
        )
    } else {
        format!("'{host_name}' refused {what}.")
    }
}

/// Run the keyboard-interactive conversation to its end.
///
/// `Ok(false)` means the server said no - the wrong code, or the method is not
/// accepted for this user. `Err` means the attempt could not be completed:
/// nobody to ask, no answer in time, or a server that would not stop asking.
pub async fn authenticate<H: russh::client::Handler>(
    handle: &mut russh::client::Handle<H>,
    host: &Host,
    asker: &Asker,
) -> Result<bool, String> {
    use russh::client::KeyboardInteractiveAuthResponse as Response;

    let mut response = handle
        .authenticate_keyboard_interactive_start(host.username.clone(), None)
        .await
        .map_err(|e| {
            format!(
                "'{}' did not accept a keyboard-interactive attempt: {e}",
                host.name
            )
        })?;

    for _round in 0..MAX_ROUNDS {
        match response {
            Response::Success => return Ok(true),
            Response::Failure {
                partial_success, ..
            } => {
                return if partial_success {
                    // The server wants a second method as well (publickey and
                    // then a code, say). Chaining methods is not something
                    // Kino does yet, and saying so is better than reporting a
                    // wrong code.
                    Err(format!(
                        "'{}' accepted that answer but requires another authentication method as \
                         well, which Kino cannot chain yet.",
                        host.name
                    ))
                } else {
                    Ok(false)
                };
            }
            Response::InfoRequest {
                name,
                instructions,
                prompts,
            } => {
                let prompts: Vec<Prompt> = prompts
                    .into_iter()
                    .map(|p| Prompt {
                        text: p.prompt,
                        echo: p.echo,
                    })
                    .collect();
                let answers = gather(host, asker, name, instructions, &prompts).await?;
                response = handle
                    .authenticate_keyboard_interactive_respond(answers)
                    .await
                    .map_err(|e| format!("'{}' dropped the exchange: {e}", host.name))?;
            }
        }
    }

    Err(format!(
        "'{}' asked for answers {MAX_ROUNDS} times over, so the attempt was given up on. \
         Nothing ran on the host.",
        host.name
    ))
}

/// Answers for one round: from the vault where that is right, from a person
/// where it is not.
async fn gather(
    host: &Host,
    asker: &Asker,
    name: String,
    instruction: String,
    prompts: &[Prompt],
) -> Result<Vec<String>, String> {
    // A round with no prompts is the server showing a banner. It still needs
    // an answer - an empty one - and nobody needs to be woken for it.
    if prompts.is_empty() {
        return Ok(Vec::new());
    }

    let mut planned = plan(prompts, host.password.as_deref());
    let to_ask: Vec<Prompt> = prompts
        .iter()
        .zip(&planned)
        .filter(|(_, answer)| answer.is_none())
        .map(|(prompt, _)| prompt.clone())
        .collect();

    if !to_ask.is_empty() {
        let challenge = Challenge {
            id: uuid::Uuid::new_v4().to_string(),
            host_id: host.id.clone(),
            host_name: host.name.clone(),
            name,
            instruction,
            prompts: to_ask.clone(),
            timeout_secs: match asker {
                Asker::Person(p) => p.timeout.as_secs(),
                Asker::Nobody(_) => 0,
            },
        };
        let typed = asker.ask(&challenge).await?;
        if typed.len() != to_ask.len() {
            return Err(format!(
                "'{}' asked {} question(s) and got {} answer(s), so nothing was sent.",
                host.name,
                to_ask.len(),
                typed.len()
            ));
        }
        let mut typed = typed.into_iter();
        for answer in planned.iter_mut() {
            if answer.is_none() {
                *answer = typed.next();
            }
        }
    }

    Ok(planned.into_iter().map(Option::unwrap_or_default).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prompt(text: &str, echo: bool) -> Prompt {
        Prompt {
            text: text.to_string(),
            echo,
        }
    }

    fn host_with_password(password: Option<&str>) -> Host {
        let mut host = crate::vault::bare_host();
        host.name = "web-prod".into();
        host.username = "deploy".into();
        host.password = password.map(str::to_string);
        host
    }

    #[test]
    fn a_password_prompt_is_recognised_in_the_shapes_servers_actually_send() {
        for text in [
            "Password:",
            "Password: ",
            "password",
            "deploy@web-prod's password:",
            "UNIX Password:",
            "Enter passwd:",
        ] {
            assert!(is_password_prompt(text), "{text:?} should be a password");
        }
    }

    /// The rule that matters: a second-factor prompt must never be answered
    /// from the vault, including the ones that say "password" too.
    #[test]
    fn a_second_factor_prompt_is_never_a_password_prompt() {
        for text in [
            "Verification code:",
            "One-time password:",
            "One time password (OTP):",
            "Enter your 2FA code:",
            "Duo two-factor login",
            "Passcode or option (1-3):",
            "YubiKey token:",
            "Authenticator code:",
            "Password or verification code:",
        ] {
            assert!(
                !is_password_prompt(text),
                "{text:?} must not be answered from the vault"
            );
        }
    }

    #[test]
    fn the_vault_answers_the_password_and_leaves_the_code_to_a_person() {
        let prompts = [
            prompt("Password:", false),
            prompt("Verification code:", false),
        ];
        let planned = plan(&prompts, Some("s3cret"));
        assert_eq!(planned, vec![Some("s3cret".to_string()), None]);
    }

    #[test]
    fn with_no_stored_password_every_prompt_goes_to_a_person() {
        let prompts = [prompt("Password:", false)];
        assert_eq!(plan(&prompts, None), vec![None]);
        assert_eq!(plan(&prompts, Some("")), vec![None]);
    }

    /// What reaches the window is only what has to be typed, and the stored
    /// password is not in it anywhere.
    #[tokio::test]
    async fn the_challenge_carries_the_unanswered_prompts_and_no_secret() {
        let host = host_with_password(Some("s3cret"));
        let seen = Arc::new(Mutex::new(Vec::<Challenge>::new()));
        let broker = Broker::new();
        let asker = Asker::Person(Person {
            show: {
                let seen = Arc::clone(&seen);
                let broker = Arc::clone(&broker);
                Box::new(move |challenge| {
                    seen.lock().unwrap().push(challenge.clone());
                    broker.answer(&challenge.id, vec!["123456".into()]);
                })
            },
            broker: Arc::clone(&broker),
            timeout: Duration::from_secs(5),
        });

        let answers = gather(
            &host,
            &asker,
            "Duo".into(),
            "Second factor".into(),
            &[
                prompt("Password:", false),
                prompt("Verification code:", false),
            ],
        )
        .await
        .unwrap();

        assert_eq!(answers, vec!["s3cret".to_string(), "123456".to_string()]);
        let shown = seen.lock().unwrap();
        assert_eq!(shown.len(), 1);
        assert_eq!(shown[0].prompts, vec![prompt("Verification code:", false)]);
        let json = serde_json::to_string(&shown[0]).unwrap();
        assert!(
            !json.contains("s3cret"),
            "the stored password reached the window: {json}"
        );
    }

    #[tokio::test]
    async fn a_banner_round_is_answered_without_asking_anyone() {
        let host = host_with_password(None);
        // An Asker that would fail the test if it were used.
        let asker = Asker::nobody("a one-off command");
        let answers = gather(&host, &asker, String::new(), "Welcome".into(), &[])
            .await
            .unwrap();
        assert!(answers.is_empty());
    }

    #[tokio::test]
    async fn nobody_to_ask_refuses_with_the_host_the_prompt_and_what_was_running() {
        let host = host_with_password(None);
        let err = gather(
            &host,
            &Asker::nobody("a health check"),
            String::new(),
            String::new(),
            &[prompt("Verification code:", false)],
        )
        .await
        .unwrap_err();
        assert!(err.contains("web-prod"), "{err}");
        assert!(err.contains("Verification code:"), "{err}");
        assert!(err.contains("a health check"), "{err}");
        assert!(err.contains("Nothing ran"), "{err}");
    }

    #[tokio::test(start_paused = true)]
    async fn an_unanswered_prompt_gives_up_rather_than_waiting_forever() {
        let host = host_with_password(None);
        let broker = Broker::new();
        let asker = Asker::Person(Person {
            // Shown, and then ignored - someone who walked away.
            show: Box::new(|_| {}),
            broker: Arc::clone(&broker),
            timeout: Duration::from_secs(TIMEOUT_SECS),
        });
        let err = gather(
            &host,
            &asker,
            String::new(),
            String::new(),
            &[prompt("Verification code:", false)],
        )
        .await
        .unwrap_err();
        assert!(err.contains("120 seconds"), "{err}");
        assert!(err.contains("dropped"), "{err}");
        // And nothing is left waiting behind it.
        assert!(broker.waiting().is_empty());
    }

    #[tokio::test]
    async fn cancelling_says_so_and_locking_the_vault_says_why() {
        for (reason, expected) in [("cancelled", "cancelled"), ("vault_locked", "vault locked")] {
            let host = host_with_password(None);
            let broker = Broker::new();
            let asker = Asker::Person(Person {
                show: {
                    let broker = Arc::clone(&broker);
                    let reason = reason.to_string();
                    Box::new(move |c| {
                        broker.cancel(&c.id, &reason);
                    })
                },
                broker: Arc::clone(&broker),
                timeout: Duration::from_secs(5),
            });
            let err = gather(
                &host,
                &asker,
                String::new(),
                String::new(),
                &[prompt("Verification code:", false)],
            )
            .await
            .unwrap_err();
            assert!(err.contains(expected), "{reason}: {err}");
        }
    }

    #[tokio::test]
    async fn too_few_answers_sends_nothing() {
        let host = host_with_password(None);
        let broker = Broker::new();
        let asker = Asker::Person(Person {
            show: {
                let broker = Arc::clone(&broker);
                // Two prompts, one answer.
                Box::new(move |c| {
                    broker.answer(&c.id, vec!["only-one".into()]);
                })
            },
            broker: Arc::clone(&broker),
            timeout: Duration::from_secs(5),
        });
        let err = gather(
            &host,
            &asker,
            String::new(),
            String::new(),
            &[
                prompt("Password:", false),
                prompt("Verification code:", false),
            ],
        )
        .await
        .unwrap_err();
        assert!(
            err.contains("2 question(s)") && err.contains("1 answer(s)"),
            "{err}"
        );
        assert!(err.contains("nothing was sent"), "{err}");
    }

    /// The message that saves someone an hour: the password was fine, the
    /// server just will not take one on its own.
    #[test]
    fn a_server_that_wants_a_prompt_is_named_in_the_refusal() {
        let msg = refused_message("web-prod", "Password", true);
        assert!(msg.contains("web-prod"), "{msg}");
        assert!(msg.contains("interactive login"), "{msg}");
        assert!(msg.contains("2FA prompt"), "{msg}");
    }

    #[test]
    fn an_ordinary_refusal_stays_short_and_says_what_was_refused() {
        assert_eq!(
            refused_message("web-prod", "SshKey", false),
            "'web-prod' refused that key."
        );
        assert_eq!(
            refused_message("web-prod", "Agent", false),
            "'web-prod' refused any key your SSH agent offered."
        );
        // Already on the interactive method: suggesting it would be absurd.
        let msg = refused_message("web-prod", "KeyboardInteractive", true);
        assert_eq!(msg, "'web-prod' refused that answer.");
    }

    #[test]
    fn answering_a_prompt_that_has_already_gone_reports_it_rather_than_pretending() {
        let broker = Broker::new();
        assert!(!broker.answer("never-registered", vec!["x".into()]));
        assert!(!broker.cancel("never-registered", "cancelled"));
    }

    #[tokio::test]
    async fn locking_the_vault_clears_every_waiting_prompt() {
        let broker = Broker::new();
        let first = broker.register("one");
        let second = broker.register("two");
        assert_eq!(broker.waiting().len(), 2);
        broker.cancel_all("vault_locked");
        assert!(broker.waiting().is_empty());
        for waiting in [first, second] {
            assert_eq!(
                waiting.await.unwrap(),
                Reply::Cancelled("vault_locked".to_string())
            );
        }
    }
}

/// The exchange itself, against a server that really does ask.
///
/// The unit tests above cover who answers what. These cover the part they
/// cannot: russh's keyboard-interactive conversation, end to end, with a
/// server built from russh's own server side - a banner round with no
/// prompts, a password round answered from the vault, a code round answered
/// by a person, and a wrong code refused.
#[cfg(test)]
mod against_a_server_that_asks {
    use super::*;
    use russh::client;
    use russh::server::{self, Auth, Response};
    use std::borrow::Cow;

    /// What the test server wants, in order. Each entry is one round.
    #[derive(Clone)]
    enum Round {
        /// Instructions, no prompts - a banner. The client must answer with
        /// nothing at all rather than wake anybody.
        Banner(&'static str),
        /// Prompts, and the answers that satisfy them.
        Ask(&'static [(&'static str, bool)], &'static [&'static str]),
    }

    struct Asking {
        rounds: Vec<Round>,
        /// Which round we are on.
        at: usize,
    }

    impl server::Handler for Asking {
        type Error = russh::Error;

        async fn auth_keyboard_interactive(
            &mut self,
            _user: &str,
            _submethods: &str,
            response: Option<Response<'_>>,
        ) -> Result<Auth, Self::Error> {
            // Check the answers to the round just sent, if it wanted any.
            if let Some(response) = response {
                let given: Vec<String> = response
                    .map(|bytes| String::from_utf8_lossy(&bytes).to_string())
                    .collect();
                if let Some(Round::Ask(_, expected)) = self.rounds.get(self.at - 1) {
                    if given != *expected {
                        return Ok(Auth::Reject {
                            proceed_with_methods: None,
                            partial_success: false,
                        });
                    }
                }
            }

            match self.rounds.get(self.at) {
                None => Ok(Auth::Accept),
                Some(round) => {
                    let (instructions, prompts) = match round {
                        Round::Banner(text) => (*text, Vec::new()),
                        Round::Ask(prompts, _) => (
                            "",
                            prompts
                                .iter()
                                .map(|(text, echo)| (Cow::Borrowed(*text), *echo))
                                .collect(),
                        ),
                    };
                    self.at += 1;
                    Ok(Auth::Partial {
                        name: Cow::Borrowed("Test"),
                        instructions: Cow::Borrowed(instructions),
                        prompts: Cow::Owned(prompts),
                    })
                }
            }
        }
    }

    struct Blind;

    impl client::Handler for Blind {
        type Error = russh::Error;
        async fn check_server_key(
            &mut self,
            _key: &russh::keys::PublicKey,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    /// Start a server that will serve exactly one connection, and connect to
    /// it. Loopback, ephemeral port, no fixtures on disk.
    async fn talk_to(rounds: Vec<Round>) -> client::Handle<Blind> {
        // Generated through the app's own keygen and re-parsed: russh carries a
        // newer ssh-key than the direct dependency, and this way the test
        // needs neither a key committed to the repo nor two rand_core
        // versions agreeing on an API.
        let pem = crate::keygen::generate_ed25519().unwrap().private_key;
        let key = russh::keys::PrivateKey::from_openssh(&pem).unwrap();
        let config = Arc::new(server::Config {
            keys: vec![key],
            ..Default::default()
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let session = server::run_stream(config, stream, Asking { rounds, at: 0 })
                .await
                .unwrap();
            let _ = session.await;
        });

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        client::connect_stream(Arc::new(client::Config::default()), stream, Blind)
            .await
            .unwrap()
    }

    fn host(password: Option<&str>) -> Host {
        let mut host = crate::vault::bare_host();
        host.name = "web-prod".into();
        host.username = "deploy".into();
        host.default_auth = "KeyboardInteractive".into();
        host.password = password.map(str::to_string);
        host
    }

    /// A person types the code, the vault supplies the password, and the
    /// server accepts - the whole point of the feature.
    #[tokio::test]
    async fn a_password_from_the_vault_and_a_code_from_a_person_gets_in() {
        let mut handle = talk_to(vec![Round::Ask(
            &[("Password:", false), ("Verification code:", false)],
            &["s3cret", "123456"],
        )])
        .await;

        let asked = Arc::new(Mutex::new(Vec::<Vec<Prompt>>::new()));
        let broker = Broker::new();
        let asker = Asker::Person(Person {
            show: {
                let asked = Arc::clone(&asked);
                let broker = Arc::clone(&broker);
                Box::new(move |c| {
                    asked.lock().unwrap().push(c.prompts.clone());
                    broker.answer(&c.id, vec!["123456".into()]);
                })
            },
            broker: Arc::clone(&broker),
            timeout: Duration::from_secs(10),
        });

        assert!(authenticate(&mut handle, &host(Some("s3cret")), &asker)
            .await
            .unwrap());
        // Only the code was ever put in front of anyone.
        let asked = asked.lock().unwrap();
        assert_eq!(asked.len(), 1);
        assert_eq!(asked[0].len(), 1);
        assert_eq!(asked[0][0].text, "Verification code:");
    }

    /// A password-only server is answered from the vault with nobody
    /// disturbed - which is what makes this method usable for hosts whose
    /// PAM stack just wants a password.
    #[tokio::test]
    async fn a_password_only_server_never_asks_the_person() {
        let mut handle = talk_to(vec![Round::Ask(&[("Password:", false)], &["s3cret"])]).await;
        let broker = Broker::new();
        let asker = Asker::Person(Person {
            show: Box::new(|c| panic!("should not have asked: {:?}", c.prompts)),
            broker,
            timeout: Duration::from_secs(10),
        });
        assert!(authenticate(&mut handle, &host(Some("s3cret")), &asker)
            .await
            .unwrap());
    }

    /// Servers send rounds with no prompts to show a banner. They still need
    /// an answer, and it is an empty one.
    #[tokio::test]
    async fn a_banner_round_is_answered_and_the_conversation_continues() {
        let mut handle = talk_to(vec![
            Round::Banner("Authorised users only"),
            Round::Ask(&[("Verification code:", false)], &["123456"]),
        ])
        .await;
        let broker = Broker::new();
        let asker = Asker::Person(Person {
            show: {
                let broker = Arc::clone(&broker);
                Box::new(move |c| {
                    broker.answer(&c.id, vec!["123456".into()]);
                })
            },
            broker: Arc::clone(&broker),
            timeout: Duration::from_secs(10),
        });
        assert!(authenticate(&mut handle, &host(None), &asker)
            .await
            .unwrap());
    }

    /// The wrong code is a plain no, not an error - the caller shows "refused"
    /// rather than "something went wrong".
    #[tokio::test]
    async fn a_wrong_code_is_refused_not_an_error() {
        let mut handle = talk_to(vec![Round::Ask(
            &[("Verification code:", false)],
            &["123456"],
        )])
        .await;
        let broker = Broker::new();
        let asker = Asker::Person(Person {
            show: {
                let broker = Arc::clone(&broker);
                Box::new(move |c| {
                    broker.answer(&c.id, vec!["000000".into()]);
                })
            },
            broker: Arc::clone(&broker),
            timeout: Duration::from_secs(10),
        });
        assert_eq!(
            authenticate(&mut handle, &host(None), &asker).await,
            Ok(false)
        );
    }

    /// Nobody to ask means the attempt stops with a message naming the host,
    /// rather than hanging on a prompt that will never appear.
    #[tokio::test]
    async fn a_background_connection_refuses_instead_of_waiting() {
        let mut handle = talk_to(vec![Round::Ask(
            &[("Verification code:", false)],
            &["123456"],
        )])
        .await;
        let err = authenticate(&mut handle, &host(None), &Asker::nobody("a health check"))
            .await
            .unwrap_err();
        assert!(err.contains("web-prod"), "{err}");
        assert!(err.contains("a health check"), "{err}");
    }
}
