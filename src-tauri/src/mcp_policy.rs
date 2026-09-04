//! What an assistant is allowed to do on an exposed host.
//!
//! Ticking a host in the MCP panel used to hand out an unrestricted shell -
//! the panel said so, which made it honest but no less true. This module is
//! the answer: a mode per host, an ordered rule list, and a default that
//! refuses rather than permits.
//!
//! Everything here is a pure function over its arguments. That is deliberate:
//! the decision about whether a command may run is the part most worth being
//! able to test exhaustively, and it should not need a filesystem, a network,
//! or a running assistant to exercise.
//!
//! ## What this cannot do
//!
//! Rules match the raw command string. This module does not parse shell and
//! must never be described as though it does. `rm -rf /` is caught by a deny
//! rule; `$(printf '\x72\x6d') -rf /` is not, and neither is anything else
//! that assembles itself at runtime. A denylist is a guard against accidents.
//! **The allowlist in `ReadOnly` is the only real boundary**, because it
//! refuses everything it was not explicitly told to permit.

use serde::{Deserialize, Serialize};

/// How much of an exposed host an assistant may reach.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum McpMode {
    /// Look, don't touch. Reads are fine; a command runs only if a rule says
    /// so by name; writing and running snippets are refused outright.
    ///
    /// The default, and the default matters more than the options: a host that
    /// someone ticked without reading this file lands here.
    #[default]
    ReadOnly,
    /// Everything is reachable, but anything not explicitly allowed has to be
    /// approved by a person first.
    Guarded,
    /// No policy. What ticking a host used to mean.
    Full,
}

impl McpMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            McpMode::ReadOnly => "read_only",
            McpMode::Guarded => "guarded",
            McpMode::Full => "full",
        }
    }
}

/// What a tool call actually does. The mode reasons about this, not about tool
/// names, so a tool added later has to declare its blast radius to compile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Capability {
    /// Names and connection details that are already in the exposure list.
    Metadata,
    /// Reads a file or a listing off the host.
    Read,
    /// Runs a command.
    Exec,
    /// Changes the host.
    Write,
}

/// Map a tool to what it can do. An unknown tool is treated as `Write` - the
/// most restricted class - so forgetting to add a case here fails closed.
pub fn capability(tool: &str) -> Capability {
    match tool {
        "list_hosts" | "get_host" | "list_snippets" => Capability::Metadata,
        "sftp_list" | "sftp_read" => Capability::Read,
        "ssh_exec" => Capability::Exec,
        "sftp_write" | "run_snippet" => Capability::Write,
        _ => Capability::Write,
    }
}

fn default_kind() -> String {
    "glob".to_string()
}

/// One line of policy.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Rule {
    /// Where the rule came from, e.g. `host:3` - the scope and the line the
    /// user wrote it on, so a refusal can point at something they can edit.
    pub id: String,
    pub pattern: String,
    /// `glob` (default) or `regex`.
    #[serde(default = "default_kind")]
    pub kind: String,
    /// `allow`, `deny` or `ask`.
    pub effect: String,
    #[serde(default)]
    pub note: Option<String>,
}

/// The policy attached to one exposed host.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct HostPolicy {
    #[serde(default)]
    pub mode: McpMode,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

/// What the policy decided, and enough about why to say so usefully.
#[derive(Debug, PartialEq, Clone)]
pub enum Decision {
    Allow,
    /// A person has to approve this call. Nothing resolves an `Ask` yet - see
    /// `mcp.rs`, where it currently becomes a refusal - but the decision is
    /// modelled properly so the approval broker is additive rather than a
    /// rewrite.
    Ask {
        rule_id: Option<String>,
    },
    Deny {
        reason: &'static str,
        rule_id: Option<String>,
    },
}

/// Translate a glob to an anchored regex.
///
/// Only `*` and `?` are special; everything else is escaped, so a pattern
/// containing `.` or `(` means those characters rather than quietly becoming a
/// regex the user did not write.
fn glob_to_regex(pattern: &str) -> String {
    let mut out = String::from("(?s)^");
    for ch in pattern.chars() {
        match ch {
            '*' => out.push_str(".*"),
            '?' => out.push('.'),
            c => out.push_str(&regex::escape(&c.to_string())),
        }
    }
    out.push('$');
    out
}

/// Does this rule cover this argument? An uncompilable pattern matches
/// nothing - a broken rule must not accidentally become a permissive one.
fn matches(rule: &Rule, argument: &str) -> bool {
    let source = if rule.kind == "regex" {
        rule.pattern.clone()
    } else {
        glob_to_regex(&rule.pattern)
    };
    regex::Regex::new(&source)
        .map(|re| re.is_match(argument))
        .unwrap_or(false)
}

/// Decide whether one tool call may proceed.
///
/// Host rules are consulted before global ones and the first match wins, so a
/// host can carve out an exception to a fleet-wide rule. `argument` is the
/// command for `ssh_exec`, the path for the SFTP tools, and - deliberately -
/// the *commands* for `run_snippet`, since a rule is about what runs, not
/// about what the thing that runs is called.
pub fn evaluate(
    policy: &HostPolicy,
    global_rules: &[Rule],
    tool: &str,
    argument: &str,
) -> Decision {
    let cap = capability(tool);

    // Full is the old behaviour, kept because some people genuinely want it.
    if policy.mode == McpMode::Full {
        return Decision::Allow;
    }

    // The exposure list itself. Refusing to name a host you deliberately
    // ticked would be theatre, not security.
    if cap == Capability::Metadata {
        return Decision::Allow;
    }

    // Read-only means read-only: no rule can talk it into writing. This check
    // sits above rule matching precisely so that an over-broad `allow *`
    // cannot turn a read-only host into a writable one.
    if policy.mode == McpMode::ReadOnly && cap == Capability::Write {
        return Decision::Deny {
            reason: "read_only",
            rule_id: None,
        };
    }

    for rule in policy.rules.iter().chain(global_rules.iter()) {
        if !matches(rule, argument) {
            continue;
        }
        return match rule.effect.as_str() {
            "allow" => Decision::Allow,
            "ask" => Decision::Ask {
                rule_id: Some(rule.id.clone()),
            },
            // An unrecognised effect denies. The alternative is a typo that
            // silently permits.
            _ => Decision::Deny {
                reason: "rule",
                rule_id: Some(rule.id.clone()),
            },
        };
    }

    match (policy.mode, cap) {
        (McpMode::ReadOnly, Capability::Read) => Decision::Allow,
        (McpMode::ReadOnly, _) => Decision::Deny {
            reason: "default_deny",
            rule_id: None,
        },
        (McpMode::Guarded, _) => Decision::Ask { rule_id: None },
        // Handled above; listed so a new mode cannot fall through silently.
        (McpMode::Full, _) => Decision::Allow,
    }
}

// ── Rules as text ───────────────────────────────────────────────────────────
//
// One rule per line, `<effect> <pattern>`, with `re:` in front of a pattern
// that is a regex. Blank lines and `#` comments are ignored. A textarea rather
// than a row builder because these are read far more often than written, and a
// list you can read top to bottom is easier to audit than a table of widgets.

/// Parse a rule block. `scope` names where the rules came from, and becomes
/// part of each rule's id along with its line number.
pub fn parse_rules(text: &str, scope: &str) -> Result<Vec<Rule>, String> {
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (effect, rest) = line.split_once(char::is_whitespace).ok_or_else(|| {
            format!(
                "Line {}: expected `allow`, `deny` or `ask`, then a pattern.",
                i + 1
            )
        })?;
        let effect = effect.to_lowercase();
        if !matches!(effect.as_str(), "allow" | "deny" | "ask") {
            return Err(format!(
                "Line {}: `{}` is not an effect - use `allow`, `deny` or `ask`.",
                i + 1,
                effect
            ));
        }
        let rest = rest.trim();
        if rest.is_empty() {
            return Err(format!("Line {}: the pattern is missing.", i + 1));
        }
        let (kind, pattern) = match rest.strip_prefix("re:") {
            Some(p) => ("regex", p.trim()),
            None => ("glob", rest),
        };
        if kind == "regex" {
            regex::Regex::new(pattern)
                .map_err(|e| format!("Line {}: that regex doesn't compile - {}", i + 1, e))?;
        }
        out.push(Rule {
            id: format!("{scope}:{}", i + 1),
            pattern: pattern.to_string(),
            kind: kind.to_string(),
            effect,
            note: None,
        });
    }
    Ok(out)
}

/// Render rules back to the text form, so the editor round-trips.
pub fn rules_to_text(rules: &[Rule]) -> String {
    rules
        .iter()
        .map(|r| {
            let prefix = if r.kind == "regex" { "re:" } else { "" };
            format!("{} {}{}", r.effect, prefix, r.pattern)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(effect: &str, pattern: &str) -> Rule {
        Rule {
            id: format!("test:{pattern}"),
            pattern: pattern.into(),
            kind: "glob".into(),
            effect: effect.into(),
            note: None,
        }
    }

    fn policy(mode: McpMode, rules: Vec<Rule>) -> HostPolicy {
        HostPolicy { mode, rules }
    }

    // ── The default is the whole point ──────────────────────────────────────

    #[test]
    fn a_host_nobody_configured_is_read_only() {
        assert_eq!(HostPolicy::default().mode, McpMode::ReadOnly);
    }

    #[test]
    fn read_only_refuses_a_command_by_default() {
        let p = policy(McpMode::ReadOnly, vec![]);
        assert_eq!(
            evaluate(&p, &[], "ssh_exec", "rm -rf /"),
            Decision::Deny {
                reason: "default_deny",
                rule_id: None
            }
        );
        // Even an innocuous one: the point is that nothing runs unasked.
        assert_eq!(
            evaluate(&p, &[], "ssh_exec", "uptime"),
            Decision::Deny {
                reason: "default_deny",
                rule_id: None
            }
        );
    }

    #[test]
    fn read_only_allows_reads_and_metadata() {
        let p = policy(McpMode::ReadOnly, vec![]);
        assert_eq!(evaluate(&p, &[], "list_hosts", ""), Decision::Allow);
        assert_eq!(evaluate(&p, &[], "get_host", "web"), Decision::Allow);
        assert_eq!(evaluate(&p, &[], "list_snippets", ""), Decision::Allow);
        assert_eq!(
            evaluate(&p, &[], "sftp_read", "/etc/hostname"),
            Decision::Allow
        );
        assert_eq!(evaluate(&p, &[], "sftp_list", "/var/log"), Decision::Allow);
    }

    #[test]
    fn read_only_refuses_writes_outright() {
        let p = policy(McpMode::ReadOnly, vec![]);
        for tool in ["sftp_write", "run_snippet"] {
            assert_eq!(
                evaluate(&p, &[], tool, "anything"),
                Decision::Deny {
                    reason: "read_only",
                    rule_id: None
                },
                "{tool} should be refused"
            );
        }
    }

    #[test]
    fn no_rule_can_talk_read_only_into_writing() {
        // The reason the capability check sits above rule matching: someone
        // writes `allow *` to unblock a command and silently gains writes.
        let p = policy(McpMode::ReadOnly, vec![rule("allow", "*")]);
        assert_eq!(
            evaluate(&p, &[], "sftp_write", "/etc/passwd"),
            Decision::Deny {
                reason: "read_only",
                rule_id: None
            }
        );
        // The same rule does unblock a command, which is what it was for.
        assert_eq!(evaluate(&p, &[], "ssh_exec", "uptime"), Decision::Allow);
    }

    // ── Rules ───────────────────────────────────────────────────────────────

    #[test]
    fn an_allow_rule_opens_exactly_what_it_names() {
        let p = policy(McpMode::ReadOnly, vec![rule("allow", "systemctl status *")]);
        assert_eq!(
            evaluate(&p, &[], "ssh_exec", "systemctl status nginx"),
            Decision::Allow
        );
        assert_eq!(
            evaluate(&p, &[], "ssh_exec", "systemctl stop nginx"),
            Decision::Deny {
                reason: "default_deny",
                rule_id: None
            }
        );
    }

    #[test]
    fn the_first_match_wins_and_host_rules_come_first() {
        let host = policy(McpMode::Guarded, vec![rule("allow", "reboot")]);
        let global = vec![rule("deny", "reboot")];
        // The host's exception beats the fleet-wide rule.
        assert_eq!(
            evaluate(&host, &global, "ssh_exec", "reboot"),
            Decision::Allow
        );

        // With no host rule, the global one applies.
        let bare = policy(McpMode::Guarded, vec![]);
        assert!(matches!(
            evaluate(&bare, &global, "ssh_exec", "reboot"),
            Decision::Deny { reason: "rule", .. }
        ));
    }

    #[test]
    fn a_deny_rule_reports_which_line_refused() {
        let rules = parse_rules("deny rm -rf *", "host").unwrap();
        let p = policy(McpMode::Guarded, rules);
        assert_eq!(
            evaluate(&p, &[], "ssh_exec", "rm -rf /var"),
            Decision::Deny {
                reason: "rule",
                rule_id: Some("host:1".into())
            }
        );
    }

    #[test]
    fn an_unrecognised_effect_denies() {
        let mut r = rule("allwo", "uptime"); // typo
        r.id = "host:1".into();
        let p = policy(McpMode::Guarded, vec![r]);
        assert!(matches!(
            evaluate(&p, &[], "ssh_exec", "uptime"),
            Decision::Deny { reason: "rule", .. }
        ));
    }

    #[test]
    fn a_broken_regex_matches_nothing_rather_than_everything() {
        let p = policy(
            McpMode::ReadOnly,
            vec![Rule {
                id: "host:1".into(),
                pattern: "([unclosed".into(),
                kind: "regex".into(),
                effect: "allow".into(),
                note: None,
            }],
        );
        assert_eq!(
            evaluate(&p, &[], "ssh_exec", "([unclosed"),
            Decision::Deny {
                reason: "default_deny",
                rule_id: None
            }
        );
    }

    #[test]
    fn globs_are_not_secretly_regexes() {
        // `.` and `(` are literal in a glob, not regex metacharacters.
        let p = policy(
            McpMode::ReadOnly,
            vec![rule("allow", "cat /etc/os-release")],
        );
        assert_eq!(
            evaluate(&p, &[], "ssh_exec", "cat /etc/os-release"),
            Decision::Allow
        );
        assert_eq!(
            evaluate(&p, &[], "ssh_exec", "cat /etcXos-release"),
            Decision::Deny {
                reason: "default_deny",
                rule_id: None
            }
        );
    }

    #[test]
    fn a_glob_is_anchored_at_both_ends() {
        let p = policy(McpMode::ReadOnly, vec![rule("allow", "uptime")]);
        assert_eq!(evaluate(&p, &[], "ssh_exec", "uptime"), Decision::Allow);
        // Not a prefix match: `uptime; rm -rf /` must not slip through.
        assert_eq!(
            evaluate(&p, &[], "ssh_exec", "uptime; rm -rf /"),
            Decision::Deny {
                reason: "default_deny",
                rule_id: None
            }
        );
    }

    #[test]
    fn a_glob_star_spans_a_whole_command_including_newlines() {
        let p = policy(McpMode::ReadOnly, vec![rule("allow", "deploy *")]);
        assert_eq!(
            evaluate(&p, &[], "ssh_exec", "deploy one\ntwo"),
            Decision::Allow
        );
    }

    // ── Modes ───────────────────────────────────────────────────────────────

    #[test]
    fn guarded_asks_for_anything_not_named() {
        let p = policy(McpMode::Guarded, vec![]);
        assert_eq!(
            evaluate(&p, &[], "ssh_exec", "uptime"),
            Decision::Ask { rule_id: None }
        );
        assert_eq!(
            evaluate(&p, &[], "sftp_write", "/tmp/x"),
            Decision::Ask { rule_id: None }
        );
        // Reads still ask - guarded is stricter than read-only about reads,
        // and looser about everything else.
        assert_eq!(
            evaluate(&p, &[], "sftp_read", "/etc/shadow"),
            Decision::Ask { rule_id: None }
        );
        // Naming a host is not worth interrupting someone for.
        assert_eq!(evaluate(&p, &[], "list_hosts", ""), Decision::Allow);
    }

    #[test]
    fn full_allows_everything_including_unknown_tools() {
        let p = policy(McpMode::Full, vec![rule("deny", "*")]);
        assert_eq!(evaluate(&p, &[], "ssh_exec", "rm -rf /"), Decision::Allow);
        assert_eq!(
            evaluate(&p, &[], "sftp_write", "/etc/passwd"),
            Decision::Allow
        );
    }

    #[test]
    fn an_unknown_tool_is_treated_as_a_write() {
        assert_eq!(capability("something_added_later"), Capability::Write);
        let p = policy(McpMode::ReadOnly, vec![]);
        assert_eq!(
            evaluate(&p, &[], "something_added_later", ""),
            Decision::Deny {
                reason: "read_only",
                rule_id: None
            }
        );
    }

    // ── The text form ───────────────────────────────────────────────────────

    #[test]
    fn parses_a_rule_block() {
        let rules = parse_rules(
            "# services only\nallow systemctl status *\n\ndeny  rm -rf *\nask re:^journalctl -u \\S+$\n",
            "host",
        )
        .unwrap();
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0].effect, "allow");
        assert_eq!(rules[0].kind, "glob");
        assert_eq!(
            rules[0].id, "host:2",
            "the id points at the line the user wrote"
        );
        assert_eq!(rules[2].kind, "regex");
        assert_eq!(rules[2].pattern, r"^journalctl -u \S+$");
    }

    #[test]
    fn rejects_rules_it_cannot_understand() {
        for (text, expect) in [
            ("permit uptime", "not an effect"),
            ("allow", "expected"),
            ("allow   ", "expected"),
            (r"ask re:([unclosed", "doesn't compile"),
        ] {
            let err = parse_rules(text, "host").unwrap_err();
            assert!(err.contains(expect), "{text:?} gave {err:?}");
        }
    }

    #[test]
    fn text_round_trips() {
        let text = "allow systemctl status *\ndeny rm -rf *\nask re:^journalctl";
        let rules = parse_rules(text, "host").unwrap();
        assert_eq!(rules_to_text(&rules), text);
    }

    #[test]
    fn an_empty_block_is_no_rules_not_an_error() {
        assert_eq!(parse_rules("", "host").unwrap(), vec![]);
        assert_eq!(
            parse_rules("\n\n# just a comment\n", "host").unwrap(),
            vec![]
        );
    }
}
