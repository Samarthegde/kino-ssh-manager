//! Changing many hosts, one careful stage at a time (KR-11-F9..F13).
//!
//! A fleet command that reads is a fleet command that reads. A fleet command
//! that *changes* is forty simultaneous chances to be wrong, and the whole
//! argument for letting an assistant do it unattended is that it cannot be
//! wrong forty times before anyone notices.
//!
//! So a change runs as a rollout: one host, then a check, then batches, with
//! a check after each. The first failure stops it. Whatever has already been
//! changed stays changed and is named in the result, because the useful thing
//! at that moment is knowing exactly which machines are now different.
//!
//! **The server drives it.** `rollout_start` runs the canary; the assistant
//! can only ask for the next batch. There is no parameter for skipping a
//! stage and no way to reach a batch the canary has not cleared - not because
//! an assistant is assumed hostile, but because "just this once, skip the
//! canary" is exactly the reasoning that makes a bad night worse.
//!
//! **It is lost on restart.** Rollout state lives in the process, so a
//! `kino-mcp` that restarts mid-rollout leaves an abandoned rollout rather
//! than a resumable one. Abandoned is the safe side: the alternative is
//! continuing a change nobody is watching any more.
//!
//! This module plans and judges. It opens no connections: the stages, the
//! ordering, and the decision to stop are pure functions, so the part that
//! decides how far a change spreads is tested without a network.

use crate::vault::Host;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// How a rollout is shaped, and what it is allowed to touch.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FleetPolicy {
    /// Share of the remaining hosts per batch after the canary, as a
    /// percentage. Always at least one host.
    #[serde(default = "d_batch")]
    pub batch_percent: u8,
    /// Failures across completed stages that stop the rollout, as a share of
    /// the hosts changed so far.
    #[serde(default = "d_ratio")]
    pub max_failure_ratio: f32,
    /// Off by default (KR-11-F13). Production hosts are not changed by an
    /// unattended rollout until someone says otherwise in the app.
    #[serde(default)]
    pub allow_production: bool,
    /// Snippet to run after each stage, keyed by `group:<name>` or
    /// `env:<name>`. A host with no entry is judged on the action's own exit
    /// code, and the result says so.
    #[serde(default)]
    pub health_checks: HashMap<String, String>,
}

fn d_batch() -> u8 {
    10
}

fn d_ratio() -> f32 {
    0.05
}

impl Default for FleetPolicy {
    fn default() -> Self {
        FleetPolicy {
            batch_percent: d_batch(),
            max_failure_ratio: d_ratio(),
            allow_production: false,
            health_checks: HashMap::new(),
        }
    }
}

impl FleetPolicy {
    /// Clamped where it is read, not where it is written: a config file edited
    /// by hand, or an older one, should not be able to describe a rollout that
    /// is one batch of everything.
    pub fn batch_share(&self) -> f32 {
        (self.batch_percent.clamp(1, 50) as f32) / 100.0
    }

    pub fn failure_ratio(&self) -> f32 {
        self.max_failure_ratio.clamp(0.0, 0.25)
    }

    /// The health check for a host, if one is configured. A host's own group
    /// wins over its environment: the more specific statement should.
    pub fn health_check_for(&self, host: &Host) -> Option<&str> {
        host.group
            .as_deref()
            .and_then(|g| {
                self.health_checks
                    .get(&format!("group:{}", g.to_lowercase()))
            })
            .or_else(|| {
                host.environment
                    .as_deref()
                    .and_then(|e| self.health_checks.get(&format!("env:{}", e.to_lowercase())))
            })
            .map(String::as_str)
    }
}

pub fn is_production(host: &Host) -> bool {
    host.environment
        .as_deref()
        .is_some_and(|e| e.eq_ignore_ascii_case("production"))
}

/// Split the target into the order it will be changed (KR-11-F9, F13).
///
/// The canary is one host, and never a production one while anything else is
/// available. Non-production hosts go first throughout, so by the time a
/// change reaches production it has already run somewhere that matters less.
pub fn plan(hosts: &[Host], policy: &FleetPolicy) -> Result<Vec<Vec<Host>>, String> {
    let (production, rest): (Vec<Host>, Vec<Host>) = hosts.iter().cloned().partition(is_production);

    // Every host is production and nobody has allowed it: there is no
    // canary to run first, so there is nothing safe to do here.
    if !policy.allow_production && !production.is_empty() && rest.is_empty() {
        return Err(format!(
            "Every host in this target is production ({}), and autonomous changes to \
                 production are off. Turn them on in Kino - Settings - MCP Server, or target \
                 something else.",
            production
                .iter()
                .map(|h| h.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    let mut ordered = rest;
    if policy.allow_production {
        ordered.extend(production);
    }
    if ordered.is_empty() {
        return Err("No host in this target can be changed.".into());
    }

    // The canary first, alone. Everything after it is a batch.
    let mut stages: Vec<Vec<Host>> = vec![vec![ordered.remove(0)]];
    let per_batch = ((ordered.len() as f32) * policy.batch_share())
        .ceil()
        .max(1.0) as usize;
    for chunk in ordered.chunks(per_batch) {
        stages.push(chunk.to_vec());
    }
    Ok(stages)
}

/// Hosts left out of the plan, and why - so the answer says what it did not do.
pub fn excluded(hosts: &[Host], policy: &FleetPolicy) -> Vec<String> {
    if policy.allow_production {
        return Vec::new();
    }
    hosts
        .iter()
        .filter(|h| is_production(h))
        .map(|h| h.name.clone())
        .collect()
}

/// What one host did in a stage.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct HostChange {
    pub host: String,
    pub changed: bool,
    /// Why it did not change, or why it is considered failed.
    pub detail: Option<String>,
    /// `None` when no health check is configured for that host.
    pub healthy: Option<bool>,
}

impl HostChange {
    pub fn failed(&self) -> bool {
        !self.changed || self.healthy == Some(false)
    }
}

/// Why a rollout stopped.
#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Stopped {
    /// The first host failed, so nothing else is tried.
    CanaryFailed,
    /// Failures across what has run exceeded the allowed share.
    TooManyFailures { failed: usize, of: usize },
    /// Everything stopped (KR-11-F1).
    Halted,
    /// The hour's budget would not cover the next stage.
    Budget { which: String },
    /// Asked for by the assistant, or by a person.
    Aborted,
    /// Nobody continued it in time.
    Expired,
}

/// Should this rollout go on? Pure, and the only place that decides (F12).
pub fn verdict(
    stage_index: usize,
    results: &[HostChange],
    all_so_far: &[HostChange],
    policy: &FleetPolicy,
) -> Option<Stopped> {
    // The canary is one host and gets no tolerance at all: a failure there is
    // the rollout working exactly as intended.
    if stage_index == 0 {
        return results
            .iter()
            .any(|r| r.failed())
            .then_some(Stopped::CanaryFailed);
    }

    let failed = all_so_far.iter().filter(|r| r.failed()).count();
    let of = all_so_far.len().max(1);
    let ratio = failed as f32 / of as f32;
    (ratio > policy.failure_ratio()).then_some(Stopped::TooManyFailures { failed, of })
}

/// How long a rollout nobody has advanced stays answerable (KR-11-F10).
pub const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30 * 60);

/// What a rollout is doing to each host.
#[derive(Clone, Debug)]
pub enum Action {
    Exec(String),
    Snippet { id: String, commands: String },
    Write { path: String, content: String },
}

impl Action {
    /// What the audit log and the policy see. For a snippet it is the
    /// commands, not the name: a rule is about what runs, and a snippet can
    /// be edited afterwards.
    pub fn argument(&self) -> &str {
        match self {
            Action::Exec(command) => command,
            Action::Snippet { commands, .. } => commands,
            Action::Write { path, .. } => path,
        }
    }

    pub fn tool(&self) -> &'static str {
        match self {
            Action::Exec(_) => "ssh_exec",
            Action::Snippet { .. } => "run_snippet",
            Action::Write { .. } => "sftp_write",
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Action::Exec(command) => format!("run `{command}`"),
            Action::Snippet { id, .. } => format!("run snippet {id}"),
            Action::Write { path, .. } => format!("write {path}"),
        }
    }
}

/// One rollout, as the server holds it.
pub struct Rollout {
    pub id: String,
    pub action: Action,
    pub stages: Vec<Vec<Host>>,
    pub stage_index: usize,
    /// Everything that has run, in order.
    pub results: Vec<HostChange>,
    pub excluded: Vec<String>,
    pub stopped: Option<Stopped>,
    pub last_touched: std::time::Instant,
    /// True once the action's own exit code was the only judge, so the result
    /// can say that rather than implying a health check passed.
    pub unchecked: bool,
}

impl Rollout {
    pub fn changed_hosts(&self) -> Vec<&str> {
        self.results
            .iter()
            .filter(|r| r.changed)
            .map(|r| r.host.as_str())
            .collect()
    }

    pub fn remaining(&self) -> usize {
        self.stages
            .iter()
            .skip(self.stage_index)
            .map(|s| s.len())
            .sum()
    }

    pub fn done(&self) -> bool {
        self.stopped.is_some() || self.stage_index >= self.stages.len()
    }

    /// What an assistant gets back. Always says what has changed, because at
    /// the moment a rollout stops that is the only thing worth knowing.
    pub fn report(&self) -> serde_json::Value {
        serde_json::json!({
            "rollout_id": self.id,
            "action": self.action.describe(),
            "stage": self.stage_index,
            "stages": self.stages.len(),
            "state": match &self.stopped {
                Some(_) => "stopped",
                None if self.stage_index >= self.stages.len() => "finished",
                None => "in_progress",
            },
            "stopped_because": self.stopped,
            "changed_hosts": self.changed_hosts(),
            "hosts_remaining": self.remaining(),
            "results": self.results,
            "excluded_production": self.excluded,
            "health_checks": if self.unchecked {
                "none configured for these hosts - judged on the command's exit code alone"
            } else {
                "run after each stage"
            },
        })
    }
}

/// Drop rollouts nobody came back to (KR-11-F10).
pub fn expire(rollouts: &mut HashMap<String, Rollout>, now: std::time::Instant) {
    rollouts.retain(|_, r| now.duration_since(r.last_touched) < IDLE_TIMEOUT);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(name: &str, env: Option<&str>, group: Option<&str>) -> Host {
        Host {
            id: name.into(),
            name: name.into(),
            environment: env.map(str::to_string),
            group: group.map(str::to_string),
            ..crate::vault::bare_host()
        }
    }

    fn staging(n: usize) -> Vec<Host> {
        (0..n)
            .map(|i| host(&format!("web-{i:02}"), Some("staging"), Some("web")))
            .collect()
    }

    fn change(host: &str, changed: bool, healthy: Option<bool>) -> HostChange {
        HostChange {
            host: host.into(),
            changed,
            detail: None,
            healthy,
        }
    }

    // ── Planning (KR-11-F9, F13) ────────────────────────────────────────────

    #[test]
    fn the_first_stage_is_one_host() {
        let stages = plan(&staging(20), &FleetPolicy::default()).unwrap();
        assert_eq!(stages[0].len(), 1, "the canary is one host, alone");
    }

    #[test]
    fn batches_are_a_share_of_what_is_left() {
        // 20 hosts: 1 canary, then 10% of the remaining 19, rounded up.
        let stages = plan(&staging(20), &FleetPolicy::default()).unwrap();
        assert_eq!(stages[1].len(), 2);
        assert_eq!(
            stages.iter().map(|s| s.len()).sum::<usize>(),
            20,
            "everything is planned exactly once"
        );
    }

    #[test]
    fn a_batch_is_never_zero_hosts() {
        // 3 hosts and a 10% batch would round to nothing, and a rollout that
        // can never advance is worse than a big batch.
        let stages = plan(&staging(3), &FleetPolicy::default()).unwrap();
        assert!(stages.iter().all(|s| !s.is_empty()));
        assert_eq!(stages.iter().map(|s| s.len()).sum::<usize>(), 3);
    }

    #[test]
    fn one_host_is_all_canary_and_nothing_else() {
        let stages = plan(&staging(1), &FleetPolicy::default()).unwrap();
        assert_eq!(stages.len(), 1);
        assert_eq!(stages[0].len(), 1);
    }

    #[test]
    fn production_is_left_out_unless_it_is_allowed() {
        let mut hosts = staging(2);
        hosts.push(host("db-prod", Some("production"), Some("db")));
        let stages = plan(&hosts, &FleetPolicy::default()).unwrap();
        let planned: Vec<&str> = stages.iter().flatten().map(|h| h.name.as_str()).collect();
        assert!(!planned.contains(&"db-prod"), "{planned:?}");
        assert_eq!(excluded(&hosts, &FleetPolicy::default()), ["db-prod"]);
    }

    #[test]
    fn a_target_of_only_production_is_refused_with_a_reason() {
        let hosts = vec![host("db-prod", Some("production"), None)];
        let err = plan(&hosts, &FleetPolicy::default()).unwrap_err();
        assert!(err.contains("db-prod"), "{err}");
        assert!(err.contains("production"), "{err}");
    }

    #[test]
    fn production_is_never_the_canary_even_when_allowed() {
        // The first host changed should be one where being wrong costs least.
        let policy = FleetPolicy {
            allow_production: true,
            ..Default::default()
        };
        let mut hosts = vec![host("db-prod", Some("production"), None)];
        hosts.extend(staging(3));
        let stages = plan(&hosts, &policy).unwrap();
        assert_ne!(stages[0][0].name, "db-prod");
        let last: &Host = stages.iter().flatten().last().unwrap();
        assert_eq!(last.name, "db-prod", "and it goes last");
    }

    #[test]
    fn production_alone_can_still_be_rolled_out_when_allowed() {
        let policy = FleetPolicy {
            allow_production: true,
            ..Default::default()
        };
        let hosts = vec![
            host("db-01", Some("production"), None),
            host("db-02", Some("production"), None),
        ];
        assert_eq!(plan(&hosts, &policy).unwrap().iter().flatten().count(), 2);
    }

    #[test]
    fn a_batch_percent_from_a_hand_edited_config_is_clamped() {
        let policy = FleetPolicy {
            batch_percent: 100,
            ..Default::default()
        };
        // 50% at most, so 20 hosts is never one batch of 19 after the canary.
        let stages = plan(&staging(21), &policy).unwrap();
        assert!(
            stages.len() >= 3,
            "{:?}",
            stages.iter().map(|s| s.len()).collect::<Vec<_>>()
        );
    }

    // ── Stopping (KR-11-F12) ────────────────────────────────────────────────

    #[test]
    fn a_failed_canary_stops_everything() {
        let results = vec![change("web-00", false, None)];
        assert_eq!(
            verdict(0, &results, &results, &FleetPolicy::default()),
            Some(Stopped::CanaryFailed)
        );
    }

    #[test]
    fn a_canary_that_fails_its_health_check_stops_everything_too() {
        // It ran, and the machine is worse for it. That is the case the
        // canary exists to catch.
        let results = vec![change("web-00", true, Some(false))];
        assert_eq!(
            verdict(0, &results, &results, &FleetPolicy::default()),
            Some(Stopped::CanaryFailed)
        );
    }

    #[test]
    fn a_healthy_canary_lets_the_rollout_go_on() {
        let results = vec![change("web-00", true, Some(true))];
        assert_eq!(
            verdict(0, &results, &results, &FleetPolicy::default()),
            None
        );
    }

    #[test]
    fn failures_past_the_share_stop_the_rest() {
        // One in ten is 10%, which is past the default 5%.
        let policy = FleetPolicy::default();
        let mut all: Vec<HostChange> = (0..9)
            .map(|i| change(&format!("web-{i}"), true, Some(true)))
            .collect();
        all.push(change("web-09", false, None));
        let stage = vec![all.last().unwrap().clone()];
        assert_eq!(
            verdict(1, &stage, &all, &policy),
            Some(Stopped::TooManyFailures { failed: 1, of: 10 })
        );
    }

    #[test]
    fn one_failure_in_a_large_batch_is_within_the_share() {
        // The other side of the same line: 1 in 21 is 4.8%, and stopping a
        // twenty-host rollout over one flaky machine would make the feature
        // useless.
        let policy = FleetPolicy::default();
        let mut all: Vec<HostChange> = (0..20)
            .map(|i| change(&format!("web-{i}"), true, Some(true)))
            .collect();
        all.push(change("web-20", false, None));
        assert_eq!(verdict(1, &all[20..], &all, &policy), None);
    }

    #[test]
    fn a_failure_within_the_share_does_not_stop_it() {
        let policy = FleetPolicy {
            max_failure_ratio: 0.10,
            ..Default::default()
        };
        let mut all: Vec<HostChange> = (0..19)
            .map(|i| change(&format!("web-{i}"), true, Some(true)))
            .collect();
        all.push(change("web-19", false, None));
        assert_eq!(verdict(1, &all[19..], &all, &policy), None, "1 in 20 is 5%");
    }

    #[test]
    fn the_failure_share_cannot_be_set_to_accept_everything() {
        let policy = FleetPolicy {
            max_failure_ratio: 1.0,
            ..Default::default()
        };
        let all: Vec<HostChange> = (0..10)
            .map(|i| change(&format!("web-{i}"), false, None))
            .collect();
        assert!(
            verdict(1, &all, &all, &policy).is_some(),
            "a ratio of 1.0 would let a rollout break every host it touched"
        );
    }

    // ── Health checks (KR-11-F11) ───────────────────────────────────────────

    #[test]
    fn a_health_check_is_found_by_group_or_environment() {
        let mut policy = FleetPolicy::default();
        policy
            .health_checks
            .insert("group:web".into(), "s-web".into());
        policy
            .health_checks
            .insert("env:staging".into(), "s-staging".into());

        let web = host("web-01", Some("staging"), Some("web"));
        assert_eq!(policy.health_check_for(&web), Some("s-web"), "group wins");

        let db = host("db-01", Some("staging"), Some("db"));
        assert_eq!(policy.health_check_for(&db), Some("s-staging"));

        let orphan = host("odd-01", None, None);
        assert_eq!(policy.health_check_for(&orphan), None);
    }

    // ── Expiry (KR-11-F10) ──────────────────────────────────────────────────

    #[test]
    fn a_rollout_nobody_continued_is_forgotten() {
        let mut rollouts = HashMap::new();
        rollouts.insert(
            "old".to_string(),
            Rollout {
                id: "old".into(),
                action: Action::Exec("uptime".into()),
                stages: vec![],
                stage_index: 0,
                results: vec![],
                excluded: vec![],
                stopped: None,
                last_touched: std::time::Instant::now() - IDLE_TIMEOUT * 2,
                unchecked: true,
            },
        );
        rollouts.insert(
            "fresh".to_string(),
            Rollout {
                id: "fresh".into(),
                action: Action::Exec("uptime".into()),
                stages: vec![],
                stage_index: 0,
                results: vec![],
                excluded: vec![],
                stopped: None,
                last_touched: std::time::Instant::now(),
                unchecked: true,
            },
        );
        expire(&mut rollouts, std::time::Instant::now());
        assert!(rollouts.contains_key("fresh"));
        assert!(
            !rollouts.contains_key("old"),
            "30 minutes idle is abandoned"
        );
    }
}
