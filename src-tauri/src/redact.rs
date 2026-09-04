//! Strip secrets out of anything on its way to the AI provider.
//!
//! The copilot's prompt is assembled from terminal output, a selection, and
//! notes saved against a host - all of which routinely contain the things a
//! person types at a shell: a private key pasted into `cat > id_ed25519`, an
//! `export AWS_SECRET_ACCESS_KEY=...`, a `curl -H "Authorization: Bearer ..."`.
//! OpenRouter is a third party. None of that should reach it because someone
//! ticked "attach terminal output" and forgot what was on screen.
//!
//! This runs in Rust, at the command boundary, rather than in the panel that
//! happens to build the prompt today. A redaction the frontend performs is one
//! a future caller forgets: a retry path, a second UI, a new command. Here
//! there is one door and it is closed by default.
//!
//! What this is not: a guarantee. These are patterns for the shapes secrets
//! usually take, and a secret that doesn't look like one goes straight through.
//! It lowers the cost of a mistake; it does not make mistakes impossible.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// One kind of secret and how many were removed. Deliberately carries no
/// sample of what matched - showing the user their own leaked key in a
/// "we redacted this" notice would put it right back on screen.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Hit {
    pub kind: String,
    pub count: usize,
}

struct Pattern {
    kind: &'static str,
    re: Regex,
    /// When set, the capture group whose text is kept in front of the
    /// placeholder, so `password=hunter2` still reads as a password
    /// assignment rather than becoming an anonymous blob.
    keep_prefix: bool,
}

fn patterns() -> &'static [Pattern] {
    static PATTERNS: OnceLock<Vec<Pattern>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            // A key block, whole. The trailing `$` alternative matters: the
            // terminal tail is a 6 000-character slice, so a key that was on
            // screen is very often cut off without its END line, and matching
            // only complete blocks would let exactly those through.
            Pattern {
                kind: "private_key",
                re: Regex::new(
                    r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)",
                )
                .unwrap(),
                keep_prefix: false,
            },
            Pattern {
                kind: "aws_access_key",
                re: Regex::new(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b").unwrap(),
                keep_prefix: false,
            },
            Pattern {
                kind: "bearer_token",
                re: Regex::new(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{12,}").unwrap(),
                keep_prefix: false,
            },
            // Three base64url segments after the `eyJ` that base64 gives every
            // JSON header. Without that anchor this matches any dotted triple -
            // a version number, a hostname, a filename.
            Pattern {
                kind: "jwt",
                re: Regex::new(
                    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
                )
                .unwrap(),
                keep_prefix: false,
            },
            // Two details carry this one.
            //
            // The leading `[A-Za-z0-9_.-]*` is why `DB_PASSWORD=` matches: `_`
            // is a word character, so `\bpassword` finds no boundary inside an
            // identifier and every prefixed variable - the common shape in a
            // shell - would sail past. The prefix is captured too, so the line
            // still reads as the assignment it was.
            //
            // `[ \t]*` rather than `\s*` is the other. With `\s*` the prompt
            // `Enter password:` followed by a newline swallows the first word
            // of the next line: an interactive prompt reads as a leak, and a
            // real line of the transcript disappears.
            Pattern {
                kind: "assignment",
                re: Regex::new(
                    r#"(?i)\b([A-Za-z0-9_.-]*(?:password|passwd|pwd|token|secret|api[_-]?key|access[_-]?key|private[_-]?key))[ \t]*[:=][ \t]*("[^"\n]*"|'[^'\n]*'|\S+)"#,
                )
                .unwrap(),
                keep_prefix: true,
            },
        ]
    })
}

/// Remove secrets from `text`, returning the cleaned copy and a tally.
///
/// Patterns are applied in the order declared, which is what lets the whole-key
/// rule win over the `private_key=` assignment rule for the same bytes.
pub fn redact(text: &str) -> (String, Vec<Hit>) {
    let mut out = text.to_string();
    let mut hits: Vec<Hit> = Vec::new();

    for p in patterns() {
        let count = p.re.find_iter(&out).count();
        if count == 0 {
            continue;
        }
        out = if p.keep_prefix {
            p.re.replace_all(&out, |c: &regex::Captures| {
                format!("{}=[redacted:{}]", &c[1], p.kind)
            })
            .into_owned()
        } else {
            p.re.replace_all(&out, format!("[redacted:{}]", p.kind).as_str())
                .into_owned()
        };
        hits.push(Hit {
            kind: p.kind.to_string(),
            count,
        });
    }

    (out, hits)
}

/// Fold one string's tally into a running one, so a caller can report across a
/// whole prompt rather than per message.
pub fn merge(into: &mut Vec<Hit>, from: Vec<Hit>) {
    for h in from {
        match into.iter_mut().find(|e| e.kind == h.kind) {
            Some(e) => e.count += h.count,
            None => into.push(h),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(text: &str) -> Vec<String> {
        redact(text).1.into_iter().map(|h| h.kind).collect()
    }

    #[test]
    fn removes_a_whole_private_key() {
        let text = "before\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\nAAAA\n-----END OPENSSH PRIVATE KEY-----\nafter";
        let (out, hits) = redact(text);
        assert_eq!(out, "before\n[redacted:private_key]\nafter");
        assert_eq!(
            hits,
            vec![Hit {
                kind: "private_key".into(),
                count: 1
            }]
        );
        assert!(!out.contains("b3BlbnNzaC1rZXk"));
    }

    #[test]
    fn removes_a_key_the_tail_cut_off() {
        // No END line: the 6 000-character slice ended mid-key.
        let text = "$ cat id_rsa\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA";
        let (out, _) = redact(text);
        assert_eq!(out, "$ cat id_rsa\n[redacted:private_key]");
        assert!(!out.contains("MIIEow"));
    }

    #[test]
    fn removes_aws_keys_and_tokens() {
        assert_eq!(kinds("AKIAIOSFODNN7EXAMPLE"), vec!["aws_access_key"]);
        assert_eq!(kinds("ASIAIOSFODNN7EXAMPLE"), vec!["aws_access_key"]);
        assert_eq!(
            kinds("curl -H 'Authorization: Bearer sk-or-v1-abcdef123456'"),
            vec!["bearer_token"]
        );
        assert_eq!(
            kinds("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            vec!["jwt"]
        );
    }

    #[test]
    fn keeps_the_name_of_an_assignment() {
        let (out, hits) = redact("export DB_PASSWORD=hunter2");
        assert_eq!(out, "export DB_PASSWORD=[redacted:assignment]");
        assert_eq!(
            hits,
            vec![Hit {
                kind: "assignment".into(),
                count: 1
            }]
        );

        assert_eq!(
            redact(r#"api_key: "abc123""#).0,
            "api_key=[redacted:assignment]"
        );
        assert_eq!(
            redact("--token=ghp_xxxx").0,
            "--token=[redacted:assignment]"
        );

        // Prefixed variables are the shape this actually meets in a shell.
        assert_eq!(
            redact("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI").0,
            "AWS_SECRET_ACCESS_KEY=[redacted:assignment]"
        );
        assert_eq!(
            redact("MYSQL_ROOT_PASSWORD: s3cr3t").0,
            "MYSQL_ROOT_PASSWORD=[redacted:assignment]"
        );
    }

    #[test]
    fn counts_every_occurrence() {
        let (_, hits) = redact("AKIAIOSFODNN7EXAMPLE and AKIAJJJJJJJJJJJJJJJJ");
        assert_eq!(
            hits,
            vec![Hit {
                kind: "aws_access_key".into(),
                count: 2
            }]
        );
    }

    // The near-misses. Each of these is ordinary terminal output, and redacting
    // it would corrupt a transcript the user asked the copilot to read.
    #[test]
    fn leaves_ordinary_output_alone() {
        for text in [
            // An interactive prompt, with the answer on the next line.
            "Enter password:\nsudo: 3 incorrect attempts",
            // Prose about a secret is not a secret.
            "The password is stored in the vault",
            "AKIA is the prefix AWS uses",
            // Too short to be an access key.
            "AKIA123",
            // A dotted triple that is not a JWT.
            "kino v1.2.3 released",
            "run tests in a.b.c order",
            // `bearer` as an English word.
            "the bearer of bad news",
            // A flag that merely mentions a key file.
            "ssh -i ~/.ssh/id_ed25519 host",
            "--password-file /etc/creds",
        ] {
            let (out, hits) = redact(text);
            assert_eq!(out, text, "rewrote: {text:?}");
            assert!(hits.is_empty(), "flagged: {text:?} -> {hits:?}");
        }
    }

    #[test]
    fn merge_folds_by_kind() {
        let mut acc = vec![Hit {
            kind: "jwt".into(),
            count: 1,
        }];
        merge(
            &mut acc,
            vec![
                Hit {
                    kind: "jwt".into(),
                    count: 2,
                },
                Hit {
                    kind: "assignment".into(),
                    count: 1,
                },
            ],
        );
        assert_eq!(
            acc,
            vec![
                Hit {
                    kind: "jwt".into(),
                    count: 3
                },
                Hit {
                    kind: "assignment".into(),
                    count: 1
                },
            ]
        );
    }

    #[test]
    fn empty_text_is_untouched() {
        assert_eq!(redact(""), (String::new(), vec![]));
    }
}
