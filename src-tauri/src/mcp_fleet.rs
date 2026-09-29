//! Asking many hosts at once, and answering in a paragraph (KR-11-F5..F8).
//!
//! An assistant with one host per call spends its whole context window
//! discovering that forty-six machines have the same disk usage. It is not
//! only wasteful: by the time it has read them all, the thing that actually
//! differs is a thousand lines back.
//!
//! So a fleet call returns a *summary*. Identical output is stated once with
//! the hosts that produced it; anything that failed, timed out, or was refused
//! is listed on its own. That inverts the usual shape - the exceptions get the
//! room, and agreement costs one line.
//!
//! Nothing here opens a connection or decides policy. Selection and
//! summarising are pure functions so the parts that decide *which hosts* and
//! *what to say about them* can be tested without a network, and so the
//! gating stays in `mcp.rs` where every other tool's gating lives.

use crate::vault::Host;
use serde::{Deserialize, Serialize};

/// Which hosts a fleet call is about (KR-11-F5).
///
/// Fields are ANDed: `group: web` with `environment: staging` means the
/// staging web hosts, not both sets. Everything empty means every exposed
/// host, which is the only sensible reading of "no filter" and is why a
/// mutating fleet call has a separate ceiling on how many hosts it may touch.
#[derive(Deserialize, Serialize, Clone, Debug, Default, schemars::JsonSchema)]
pub struct Target {
    #[schemars(description = "Host group to match, as shown by list_hosts")]
    pub group: Option<String>,
    #[schemars(description = "Host environment to match, e.g. production or staging")]
    pub environment: Option<String>,
    #[schemars(description = "Explicit host names or IDs. Combined with group and environment.")]
    pub hosts: Option<Vec<String>>,
}

/// Which hosts `target` names, among the ones exposed.
///
/// A name that matches nothing is an error rather than a quiet omission: an
/// assistant that asked for `db-01` and silently got the other nine would
/// report the work as done.
pub fn resolve(all: &[Host], target: &Target) -> Result<Vec<Host>, String> {
    let named = target.hosts.as_deref().unwrap_or(&[]);
    if !named.is_empty() {
        let missing: Vec<&str> = named
            .iter()
            .filter(|n| !all.iter().any(|h| matches_name(h, n)))
            .map(|s| s.as_str())
            .collect();
        if !missing.is_empty() {
            return Err(format!(
                "Not exposed to this server, or not a host at all: {}. \
                 Use list_hosts to see what is available.",
                missing.join(", ")
            ));
        }
    }

    let chosen: Vec<Host> = all
        .iter()
        .filter(|h| {
            let by_name = named.is_empty() || named.iter().any(|n| matches_name(h, n));
            let by_group = match &target.group {
                Some(g) => h
                    .group
                    .as_deref()
                    .is_some_and(|hg| hg.eq_ignore_ascii_case(g)),
                None => true,
            };
            let by_env = match &target.environment {
                Some(e) => h
                    .environment
                    .as_deref()
                    .is_some_and(|he| he.eq_ignore_ascii_case(e)),
                None => true,
            };
            by_name && by_group && by_env
        })
        .cloned()
        .collect();

    if chosen.is_empty() {
        return Err(
            "No exposed host matches that. Use list_hosts to see what is available.".into(),
        );
    }
    Ok(chosen)
}

fn matches_name(host: &Host, name: &str) -> bool {
    host.id == name || host.name.eq_ignore_ascii_case(name)
}

/// How one host answered.
#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum HostOutcome {
    Ok {
        output: String,
        exit_code: Option<i32>,
    },
    /// Ran, and said no.
    NonZeroExit { output: String, exit_code: i32 },
    /// Took longer than the call allowed.
    Timeout,
    /// Never got as far as running: unreachable, refused, auth failed.
    Unreachable { detail: String },
    /// A rule, a mode or a limit said no. Reported rather than skipped: a host
    /// missing from the answer looks like a host that agreed.
    Denied { reason: String },
}

impl HostOutcome {
    fn label(&self) -> &'static str {
        match self {
            HostOutcome::Ok { .. } => "ok",
            HostOutcome::NonZeroExit { .. } => "nonzero_exit",
            HostOutcome::Timeout => "timeout",
            HostOutcome::Unreachable { .. } => "unreachable",
            HostOutcome::Denied { .. } => "denied",
        }
    }
}

/// One host's answer, with its name attached.
#[derive(Clone, Debug)]
pub struct HostResult {
    pub host: String,
    pub outcome: HostOutcome,
}

/// Hosts that said the same thing, said once.
#[derive(Serialize, Debug, PartialEq)]
pub struct Agreement {
    pub hosts: Vec<String>,
    pub output: String,
    pub exit_code: Option<i32>,
}

/// What a fleet call hands back (KR-11-F7).
#[derive(Serialize, Debug, PartialEq)]
pub struct FleetSummary {
    /// How many hosts ended each way: `ok`, `nonzero_exit`, `timeout`,
    /// `unreachable`, `denied`. Only the outcomes that happened appear.
    pub counts: std::collections::BTreeMap<String, usize>,
    /// Successful output, grouped. Largest group first, because the common
    /// answer is the one a reader wants to see stated and then dismiss.
    pub agreed: Vec<Agreement>,
    /// Everything that did not simply succeed, one entry each.
    pub attention: Vec<serde_json::Value>,
    /// Set when the total was cut to fit.
    pub truncated: Option<String>,
}

/// Total output a summary may carry before it is cut. Generous next to one
/// host's limit, because the point of a fleet call is breadth.
pub const TOTAL_BYTES: usize = 64 * 1024;

/// Turn per-host results into something worth reading (KR-11-F7).
///
/// Output is compared after trimming trailing whitespace: two hosts whose
/// answers differ only by a final newline agree, and saying otherwise would
/// manufacture an exception out of nothing.
pub fn summarise(results: Vec<HostResult>, total_bytes: usize) -> FleetSummary {
    let mut counts: std::collections::BTreeMap<String, usize> = Default::default();
    for r in &results {
        *counts.entry(r.outcome.label().to_string()).or_default() += 1;
    }

    // Group the successes by what they said.
    let mut groups: Vec<(String, Option<i32>, Vec<String>)> = Vec::new();
    let mut attention: Vec<serde_json::Value> = Vec::new();
    for r in &results {
        match &r.outcome {
            HostOutcome::Ok { output, exit_code } => {
                let key = output.trim_end().to_string();
                match groups.iter_mut().find(|(o, _, _)| *o == key) {
                    Some((_, _, hosts)) => hosts.push(r.host.clone()),
                    None => groups.push((key, *exit_code, vec![r.host.clone()])),
                }
            }
            other => {
                let mut entry = serde_json::json!({
                    "host": r.host,
                    "outcome": other.label(),
                });
                match other {
                    HostOutcome::NonZeroExit { output, exit_code } => {
                        entry["exit_code"] = serde_json::json!(exit_code);
                        entry["output"] = serde_json::json!(output.trim_end());
                    }
                    HostOutcome::Unreachable { detail } => {
                        entry["detail"] = serde_json::json!(detail);
                    }
                    HostOutcome::Denied { reason } => {
                        entry["reason"] = serde_json::json!(reason);
                    }
                    _ => {}
                }
                attention.push(entry);
            }
        }
    }

    // Largest group first: the answer most hosts gave is the one to state
    // and dismiss, and the odd ones out are what the reader is looking for.
    groups.sort_by_key(|(_, _, hosts)| std::cmp::Reverse(hosts.len()));
    let mut agreed: Vec<Agreement> = groups
        .into_iter()
        .map(|(output, exit_code, hosts)| Agreement {
            hosts,
            output,
            exit_code,
        })
        .collect();

    // Cut from the end - the smallest groups - so the answer most hosts gave
    // survives. Saying what was dropped matters more than dropping evenly.
    let mut used: usize = attention.iter().map(|a| a.to_string().len()).sum();
    let mut dropped = 0usize;
    let mut kept: Vec<Agreement> = Vec::new();
    for group in agreed.drain(..) {
        let size = group.output.len() + group.hosts.iter().map(|h| h.len() + 4).sum::<usize>();
        if used + size > total_bytes && !kept.is_empty() {
            dropped += group.hosts.len();
            continue;
        }
        used += size;
        kept.push(group);
    }

    FleetSummary {
        counts,
        agreed: kept,
        attention,
        truncated: (dropped > 0).then(|| {
            format!("{dropped} more hosts agreed with each other; their output did not fit.")
        }),
    }
}

/// What `check_drift` found on one host.
#[derive(Clone, Debug, PartialEq)]
pub enum FileState {
    /// SHA-256 of the contents.
    Hash(String),
    /// The path is not there. Different from unreadable, and often the answer.
    Missing,
    Unreadable(String),
    Denied(String),
}

/// Group hosts by what the file looks like on them (KR-11-F8).
///
/// The largest group is the baseline. That is a statement about the fleet,
/// not about correctness - if forty hosts are wrong and two are right, this
/// says the two differ, and it is still the right way round: what you want to
/// see is the minority, whichever it is.
pub fn drift(results: Vec<(String, FileState)>) -> serde_json::Value {
    let mut by_hash: Vec<(String, Vec<String>)> = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    let mut problems: Vec<serde_json::Value> = Vec::new();

    for (host, state) in results {
        match state {
            FileState::Hash(h) => match by_hash.iter_mut().find(|(k, _)| *k == h) {
                Some((_, hosts)) => hosts.push(host),
                None => by_hash.push((h, vec![host])),
            },
            FileState::Missing => missing.push(host),
            FileState::Unreadable(detail) => problems.push(serde_json::json!({
                "host": host, "outcome": "unreadable", "detail": detail
            })),
            FileState::Denied(reason) => problems.push(serde_json::json!({
                "host": host, "outcome": "denied", "reason": reason
            })),
        }
    }

    by_hash.sort_by_key(|(_, hosts)| std::cmp::Reverse(hosts.len()));
    let baseline = by_hash.first().map(|(h, _)| h.clone());
    let groups: Vec<serde_json::Value> = by_hash
        .iter()
        .enumerate()
        .map(|(i, (hash, hosts))| {
            serde_json::json!({
                "sha256": hash,
                "hosts": hosts,
                "count": hosts.len(),
                "baseline": i == 0,
            })
        })
        .collect();

    let drifted: usize = by_hash.iter().skip(1).map(|(_, h)| h.len()).sum();
    serde_json::json!({
        "baseline_sha256": baseline,
        "groups": groups,
        "drifted_hosts": drifted,
        "missing": missing,
        "problems": problems,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(id: &str, name: &str, group: Option<&str>, env: Option<&str>) -> Host {
        Host {
            id: id.into(),
            name: name.into(),
            group: group.map(str::to_string),
            environment: env.map(str::to_string),
            ..crate::vault::bare_host()
        }
    }

    fn fleet() -> Vec<Host> {
        vec![
            host("h1", "web-01", Some("web"), Some("production")),
            host("h2", "web-02", Some("web"), Some("production")),
            host("h3", "web-03", Some("web"), Some("staging")),
            host("h4", "db-01", Some("db"), Some("production")),
        ]
    }

    // ── Choosing hosts (KR-11-F5) ───────────────────────────────────────────

    #[test]
    fn no_filter_means_every_exposed_host() {
        let got = resolve(&fleet(), &Target::default()).unwrap();
        assert_eq!(got.len(), 4);
    }

    #[test]
    fn a_group_and_an_environment_are_anded_not_ored() {
        let got = resolve(
            &fleet(),
            &Target {
                group: Some("web".into()),
                environment: Some("production".into()),
                hosts: None,
            },
        )
        .unwrap();
        let names: Vec<&str> = got.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(names, ["web-01", "web-02"], "staging web is not production");
    }

    #[test]
    fn hosts_can_be_named_outright() {
        let got = resolve(
            &fleet(),
            &Target {
                hosts: Some(vec!["db-01".into(), "h1".into()]),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(got.len(), 2, "by name or by id");
    }

    #[test]
    fn a_name_that_matches_nothing_is_an_error() {
        // Silently returning the other nine would let an assistant report work
        // as done on a host it never touched.
        let err = resolve(
            &fleet(),
            &Target {
                hosts: Some(vec!["web-01".into(), "db-99".into()]),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(err.contains("db-99"), "{err}");
        assert!(!err.contains("web-01"), "only the missing one: {err}");
    }

    #[test]
    fn a_filter_matching_nothing_says_so() {
        let err = resolve(
            &fleet(),
            &Target {
                group: Some("cache".into()),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(err.contains("No exposed host"), "{err}");
    }

    #[test]
    fn matching_ignores_case_because_people_type_it() {
        let got = resolve(
            &fleet(),
            &Target {
                group: Some("WEB".into()),
                environment: Some("Production".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(got.len(), 2);
    }

    // ── Saying what happened (KR-11-F7) ─────────────────────────────────────

    fn ok(host: &str, out: &str) -> HostResult {
        HostResult {
            host: host.into(),
            outcome: HostOutcome::Ok {
                output: out.into(),
                exit_code: Some(0),
            },
        }
    }

    #[test]
    fn hosts_that_agree_are_stated_once() {
        let results = vec![
            ok("web-01", "3.2G"),
            ok("web-02", "3.2G"),
            ok("web-03", "9.9G"),
        ];
        let s = summarise(results, TOTAL_BYTES);
        assert_eq!(s.agreed.len(), 2);
        assert_eq!(
            s.agreed[0].hosts,
            ["web-01", "web-02"],
            "largest group first"
        );
        assert_eq!(s.agreed[0].output, "3.2G");
        assert_eq!(s.agreed[1].hosts, ["web-03"]);
        assert_eq!(s.counts["ok"], 3);
    }

    #[test]
    fn a_trailing_newline_is_not_a_disagreement() {
        let s = summarise(
            vec![ok("a", "up 3 days\n"), ok("b", "up 3 days")],
            TOTAL_BYTES,
        );
        assert_eq!(s.agreed.len(), 1, "{:?}", s.agreed);
    }

    #[test]
    fn everything_that_did_not_work_is_listed_on_its_own() {
        let results = vec![
            ok("web-01", "fine"),
            HostResult {
                host: "web-02".into(),
                outcome: HostOutcome::Timeout,
            },
            HostResult {
                host: "db-01".into(),
                outcome: HostOutcome::Unreachable {
                    detail: "connection refused".into(),
                },
            },
            HostResult {
                host: "db-02".into(),
                outcome: HostOutcome::Denied {
                    reason: "read_only".into(),
                },
            },
            HostResult {
                host: "db-03".into(),
                outcome: HostOutcome::NonZeroExit {
                    output: "no such file".into(),
                    exit_code: 2,
                },
            },
        ];
        let s = summarise(results, TOTAL_BYTES);
        assert_eq!(s.attention.len(), 4);
        assert_eq!(s.counts["timeout"], 1);
        assert_eq!(s.counts["unreachable"], 1);
        assert_eq!(s.counts["denied"], 1);
        assert_eq!(s.counts["nonzero_exit"], 1);
        let hosts: Vec<&str> = s
            .attention
            .iter()
            .map(|a| a["host"].as_str().unwrap())
            .collect();
        assert!(hosts.contains(&"db-02"), "a refused host is still reported");
    }

    #[test]
    fn a_refused_host_never_looks_like_agreement() {
        // The failure this guards: a host left out of the answer reads as a
        // host that said the same as the others.
        let s = summarise(
            vec![
                ok("web-01", "ok"),
                HostResult {
                    host: "web-02".into(),
                    outcome: HostOutcome::Denied {
                        reason: "rate_limited".into(),
                    },
                },
            ],
            TOTAL_BYTES,
        );
        assert_eq!(s.agreed[0].hosts, ["web-01"]);
        assert_eq!(s.attention[0]["reason"], "rate_limited");
    }

    #[test]
    fn a_huge_answer_keeps_the_common_one_and_says_what_it_dropped() {
        let mut results = vec![];
        for i in 0..20 {
            results.push(ok(&format!("common-{i}"), "the same short line"));
        }
        // Each of these says something different and long, so they cannot be
        // grouped away - which is what makes the total too big to keep.
        for i in 0..10 {
            results.push(ok(
                &format!("odd-{i}"),
                &format!("{i}{}", "x".repeat(5_000)),
            ));
        }
        let s = summarise(results, 8_000);
        assert_eq!(s.agreed[0].hosts.len(), 20, "the common answer survives");
        assert!(s.truncated.is_some(), "and the rest is accounted for");
        assert_eq!(s.counts["ok"], 30, "the counts are still of everything");
    }

    #[test]
    fn nothing_at_all_summarises_to_nothing_rather_than_panicking() {
        let s = summarise(vec![], TOTAL_BYTES);
        assert!(s.counts.is_empty());
        assert!(s.agreed.is_empty());
    }

    // ── Drift (KR-11-F8) ────────────────────────────────────────────────────

    #[test]
    fn the_majority_is_the_baseline_and_the_rest_are_named() {
        let v = drift(vec![
            ("web-01".into(), FileState::Hash("aaa".into())),
            ("web-02".into(), FileState::Hash("aaa".into())),
            ("web-03".into(), FileState::Hash("bbb".into())),
        ]);
        assert_eq!(v["baseline_sha256"], "aaa");
        assert_eq!(v["drifted_hosts"], 1);
        assert_eq!(v["groups"][0]["baseline"], true);
        assert_eq!(v["groups"][1]["hosts"][0], "web-03");
    }

    #[test]
    fn missing_is_not_the_same_as_unreadable() {
        // "The file is not there" is usually the answer; "I could not read it"
        // is a problem to fix. Collapsing them hides one behind the other.
        let v = drift(vec![
            ("a".into(), FileState::Hash("aaa".into())),
            ("b".into(), FileState::Missing),
            (
                "c".into(),
                FileState::Unreadable("permission denied".into()),
            ),
            ("d".into(), FileState::Denied("read_only".into())),
        ]);
        assert_eq!(v["missing"][0], "b");
        assert_eq!(v["problems"][0]["outcome"], "unreadable");
        assert_eq!(v["problems"][1]["outcome"], "denied");
        assert_eq!(v["drifted_hosts"], 0, "neither counts as drift");
    }

    #[test]
    fn a_fleet_that_agrees_completely_has_no_drift() {
        let v = drift(vec![
            ("a".into(), FileState::Hash("same".into())),
            ("b".into(), FileState::Hash("same".into())),
        ]);
        assert_eq!(v["drifted_hosts"], 0);
        assert_eq!(v["groups"].as_array().unwrap().len(), 1);
    }
}
