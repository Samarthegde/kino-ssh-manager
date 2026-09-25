//! The stop button, and a ceiling on how much can change (KR-11-F1..F4).
//!
//! Policy decides whether one call is allowed. Rate limits decide how fast a
//! host may be called. Neither answers the two questions that matter once an
//! assistant works unattended:
//!
//! - **"Stop, now."** Not "change a setting and hope the next call reads it":
//!   a switch that takes effect on the very next call, that anything can
//!   throw, and that does not need the app to be running or the vault to be
//!   unlocked.
//! - **"How much can it change before someone looks?"** A loop that is
//!   individually within every rule can still restart nginx on forty hosts in
//!   a minute. The budget is the ceiling on the hour, across the fleet.
//!
//! **The halt is a plain file.** No encryption, no format, no key: its
//! presence is the whole signal. That is deliberate - `touch mcp_halt` from a
//! shell, a cron job, a monitoring alert or a panicking colleague all work,
//! and none of them need Kino open or your master password. Checking it costs
//! one `stat` per call.
//!
//! **It fails closed.** If the file cannot be examined - a permissions
//! problem, a broken mount - that counts as halted. The cost of being wrong in
//! that direction is an assistant that stops working; the other direction is
//! an assistant that keeps changing servers while someone is trying to stop
//! it.
//!
//! **Budgets are counted on disk**, sealed under the MCP key beside the audit
//! log, because a budget that resets when `kino-mcp` restarts is not a budget.
//! An assistant that can crash the server could otherwise clear its own limits
//! by doing so.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// What one hour is allowed to contain.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Budgets {
    /// Calls that change a host - `ssh_exec`, `sftp_write`, `run_snippet` -
    /// summed across hosts. A fleet call on 20 hosts will spend 20.
    #[serde(default = "d_changes")]
    pub max_changes_per_hour: u32,
    /// Hosts one changing call may touch. Trivially satisfied today, when
    /// every tool takes one host; it is the ceiling `fleet_exec` will meet.
    #[serde(default = "d_hosts")]
    pub max_hosts_per_call: u32,
    /// Every tool call, including the ones that only read.
    #[serde(default = "d_calls")]
    pub max_calls_per_hour: u32,
}

fn d_changes() -> u32 {
    50
}
fn d_hosts() -> u32 {
    25
}
fn d_calls() -> u32 {
    600
}

impl Default for Budgets {
    fn default() -> Self {
        Budgets {
            max_changes_per_hour: d_changes(),
            max_hosts_per_call: d_hosts(),
            max_calls_per_hour: d_calls(),
        }
    }
}

/// What a call spends.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Spend {
    /// Reads and metadata: counted as a call, and nothing else.
    Call,
    /// Changes `hosts` hosts, and is a call as well.
    Change { hosts: u32 },
}

/// One spend, as recorded.
#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub struct Entry {
    /// Unix milliseconds.
    pub ts: u64,
    /// Hosts changed. Zero for a call that changed nothing.
    pub changed: u32,
}

/// Why a call was refused, in the words the assistant is given.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Refusal {
    Halted,
    /// A budget is spent. Carries which one, and when it frees up.
    Budget {
        which: &'static str,
        retry_in_secs: u64,
    },
}

/// Would this spend fit? Pure, so the arithmetic is tested on its own.
///
/// `entries` may hold anything; only the last hour counts. Nothing is written
/// here - a refused call must not spend the budget it was refused by.
pub fn check(
    entries: &[Entry],
    now_ms: u64,
    budgets: &Budgets,
    spend: Spend,
) -> Result<(), Refusal> {
    let hosts = match spend {
        Spend::Call => 0,
        Spend::Change { hosts } => hosts,
    };

    // Per call, and first: a single call over the per-call ceiling is refused
    // whole rather than run on the hosts that happen to fit (KR-11-F2).
    if hosts > budgets.max_hosts_per_call {
        return Err(Refusal::Budget {
            which: "hosts per call",
            retry_in_secs: 0,
        });
    }

    let recent: Vec<&Entry> = entries
        .iter()
        .filter(|e| age(now_ms, e.ts) < HOUR)
        .collect();

    let calls = recent.len() as u32;
    if calls + 1 > budgets.max_calls_per_hour {
        return Err(Refusal::Budget {
            which: "calls per hour",
            retry_in_secs: frees_up(&recent, now_ms),
        });
    }

    if hosts > 0 {
        let changed: u32 = recent.iter().map(|e| e.changed).sum();
        if changed + hosts > budgets.max_changes_per_hour {
            return Err(Refusal::Budget {
                which: "changes per hour",
                // The oldest *change* is what frees a change budget; the
                // oldest read would report a time that changes nothing.
                retry_in_secs: frees_up(
                    &recent
                        .iter()
                        .copied()
                        .filter(|e| e.changed > 0)
                        .collect::<Vec<_>>(),
                    now_ms,
                ),
            });
        }
    }

    Ok(())
}

const HOUR: u64 = 60 * 60 * 1000;

fn age(now_ms: u64, ts: u64) -> u64 {
    now_ms.saturating_sub(ts)
}

/// Seconds until the oldest entry in the window ages out.
fn frees_up(recent: &[&Entry], now_ms: u64) -> u64 {
    recent
        .iter()
        .map(|e| e.ts)
        .min()
        .map(|oldest| (HOUR - age(now_ms, oldest).min(HOUR)).div_ceil(1000))
        .unwrap_or(0)
}

/// Drop everything older than the window, so the file cannot grow without
/// bound on a busy day.
pub fn prune(entries: Vec<Entry>, now_ms: u64) -> Vec<Entry> {
    entries
        .into_iter()
        .filter(|e| age(now_ms, e.ts) < HOUR)
        .collect()
}

// ── The halt file (KR-11-F1) ────────────────────────────────────────────────

pub fn halt_path() -> PathBuf {
    crate::vault::vault_path()
        .parent()
        .unwrap()
        .join("mcp_halt")
}

/// Is everything stopped?
///
/// Anything other than a clean "no such file" counts as halted: see the
/// module note on failing closed.
pub fn is_halted(path: &Path) -> bool {
    match std::fs::metadata(path) {
        Ok(_) => true,
        Err(e) => e.kind() != std::io::ErrorKind::NotFound,
    }
}

/// Set or clear the halt. Writing the time is a courtesy to whoever finds the
/// file later; nothing reads the contents.
pub fn set_halted(path: &Path, halted: bool) -> Result<(), String> {
    if halted {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        std::fs::write(
            path,
            format!("MCP activity stopped from Kino at unix {stamp}.\nDelete this file to allow it again.\n"),
        )
        .map_err(|e| format!("Could not write the halt file: {e}"))
    } else {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("Could not remove the halt file: {e}")),
        }
    }
}

// ── The ledger on disk (KR-11-F3) ───────────────────────────────────────────

/// The hour's spending, sealed under the MCP key.
pub struct Ledger {
    path: PathBuf,
    key: [u8; 32],
}

impl Drop for Ledger {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
    }
}

pub fn ledger_path() -> PathBuf {
    crate::vault::vault_path()
        .parent()
        .unwrap()
        .join("mcp_budget.enc")
}

impl Ledger {
    pub fn new(path: PathBuf, key: [u8; 32]) -> Ledger {
        Ledger { path, key }
    }

    /// What has been spent in the last hour.
    ///
    /// A file that will not open is an empty hour: the ledger is a limit on
    /// work, not a gate on it, and refusing every call because a counter file
    /// is unreadable trades a real outage for a bookkeeping problem. The halt
    /// is the switch that fails closed.
    pub fn recent(&self, now_ms: u64) -> Vec<Entry> {
        let entries: Vec<Entry> =
            crate::vault::load_encrypted(&self.path, &self.key).unwrap_or_default();
        prune(entries, now_ms)
    }

    /// Record a spend. Called only after `check` allowed it.
    pub fn record(&self, now_ms: u64, spend: Spend) -> Result<(), String> {
        let mut entries = self.recent(now_ms);
        entries.push(Entry {
            ts: now_ms,
            changed: match spend {
                Spend::Call => 0,
                Spend::Change { hosts } => hosts,
            },
        });
        // The salt is meaningless here - the key is derived from the MCP
        // vault's salt, not this file's - but the envelope wants one.
        crate::vault::save_encrypted(&self.path, &entries, &self.key, &[0u8; 16])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_700_000_000_000;

    fn entries(spec: &[(u64, u32)]) -> Vec<Entry> {
        spec.iter()
            .map(|(mins_ago, changed)| Entry {
                ts: NOW - mins_ago * 60_000,
                changed: *changed,
            })
            .collect()
    }

    #[test]
    fn an_empty_hour_allows_work() {
        assert_eq!(check(&[], NOW, &Budgets::default(), Spend::Call), Ok(()));
        assert_eq!(
            check(&[], NOW, &Budgets::default(), Spend::Change { hosts: 1 }),
            Ok(())
        );
    }

    #[test]
    fn changes_stop_at_the_budget() {
        let b = Budgets {
            max_changes_per_hour: 3,
            ..Default::default()
        };
        let spent = entries(&[(5, 1), (4, 1), (3, 1)]);
        assert!(matches!(
            check(&spent, NOW, &b, Spend::Change { hosts: 1 }),
            Err(Refusal::Budget {
                which: "changes per hour",
                ..
            })
        ));
    }

    #[test]
    fn reads_still_work_when_the_change_budget_is_spent() {
        // Stopping an assistant from *looking* because it changed too much
        // would leave it unable to report what it did.
        let b = Budgets {
            max_changes_per_hour: 2,
            ..Default::default()
        };
        let spent = entries(&[(5, 1), (4, 1)]);
        assert_eq!(check(&spent, NOW, &b, Spend::Call), Ok(()));
    }

    #[test]
    fn a_call_over_the_per_call_host_ceiling_is_refused_whole() {
        // Not "run on the 25 that fit": a partial fleet change is the worst
        // of both, and nobody asked for half of it.
        let b = Budgets {
            max_hosts_per_call: 25,
            ..Default::default()
        };
        assert!(matches!(
            check(&[], NOW, &b, Spend::Change { hosts: 26 }),
            Err(Refusal::Budget {
                which: "hosts per call",
                ..
            })
        ));
    }

    #[test]
    fn a_fleet_call_spends_one_per_host() {
        let b = Budgets {
            max_changes_per_hour: 10,
            ..Default::default()
        };
        assert_eq!(check(&[], NOW, &b, Spend::Change { hosts: 10 }), Ok(()));
        assert!(check(&[], NOW, &b, Spend::Change { hosts: 11 }).is_err());
    }

    #[test]
    fn the_window_is_the_last_hour_not_the_calendar_hour() {
        let b = Budgets {
            max_changes_per_hour: 2,
            ..Default::default()
        };
        // Two changes, one of them 61 minutes ago: only one still counts.
        let spent = entries(&[(61, 1), (5, 1)]);
        assert_eq!(check(&spent, NOW, &b, Spend::Change { hosts: 1 }), Ok(()));
    }

    #[test]
    fn a_refusal_says_when_it_frees_up() {
        let b = Budgets {
            max_changes_per_hour: 1,
            ..Default::default()
        };
        // Spent 20 minutes ago, so 40 minutes to wait.
        let spent = entries(&[(20, 1)]);
        match check(&spent, NOW, &b, Spend::Change { hosts: 1 }) {
            Err(Refusal::Budget { retry_in_secs, .. }) => {
                assert_eq!(retry_in_secs, 40 * 60);
            }
            other => panic!("expected a budget refusal, got {other:?}"),
        }
    }

    #[test]
    fn calls_have_a_ceiling_of_their_own() {
        let b = Budgets {
            max_calls_per_hour: 2,
            ..Default::default()
        };
        let spent = entries(&[(5, 0), (4, 0)]);
        assert!(matches!(
            check(&spent, NOW, &b, Spend::Call),
            Err(Refusal::Budget {
                which: "calls per hour",
                ..
            })
        ));
    }

    #[test]
    fn pruning_keeps_the_hour_and_drops_the_rest() {
        let kept = prune(entries(&[(61, 1), (59, 1), (1, 1)]), NOW);
        assert_eq!(kept.len(), 2);
    }

    // ── The halt file ───────────────────────────────────────────────────────

    #[test]
    fn no_file_means_running() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!is_halted(&dir.path().join("mcp_halt")));
    }

    #[test]
    fn the_file_existing_is_the_whole_signal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp_halt");
        // Written by hand, empty, from a shell script: still a halt.
        std::fs::write(&path, b"").unwrap();
        assert!(is_halted(&path));
    }

    #[test]
    fn setting_and_clearing_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp_halt");
        set_halted(&path, true).unwrap();
        assert!(is_halted(&path));
        set_halted(&path, false).unwrap();
        assert!(!is_halted(&path));
        // Clearing what is already clear is not an error - two people can
        // press the same button.
        set_halted(&path, false).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_halt_that_cannot_be_read_counts_as_halted() {
        // Failing closed: the cost of being wrong here is an assistant that
        // stops, and the other way is one that will not.
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("locked");
        std::fs::create_dir(&sub).unwrap();
        let path = sub.join("mcp_halt");
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o000)).unwrap();

        let halted = is_halted(&path);

        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o700)).unwrap();
        // Root ignores the permission bits, so only assert where it bites.
        if !nix_is_root() {
            assert!(halted, "an unreadable halt file must read as halted");
        }
    }

    #[cfg(unix)]
    fn nix_is_root() -> bool {
        std::process::Command::new("id")
            .arg("-u")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
            .unwrap_or(false)
    }

    // ── The ledger ──────────────────────────────────────────────────────────

    #[test]
    fn spending_survives_a_restart() {
        // KR-11-F3: otherwise restarting kino-mcp resets the hour, and an
        // assistant that can crash it can reset its own limits.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp_budget.enc");

        let first = Ledger::new(path.clone(), [4u8; 32]);
        first.record(NOW, Spend::Change { hosts: 3 }).unwrap();
        drop(first);

        let after_restart = Ledger::new(path, [4u8; 32]);
        let spent = after_restart.recent(NOW);
        assert_eq!(spent.len(), 1);
        assert_eq!(spent[0].changed, 3);
    }

    #[test]
    fn the_ledger_forgets_what_left_the_window() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp_budget.enc");
        let ledger = Ledger::new(path, [4u8; 32]);
        ledger
            .record(NOW - 2 * HOUR, Spend::Change { hosts: 1 })
            .unwrap();
        ledger.record(NOW, Spend::Change { hosts: 1 }).unwrap();
        assert_eq!(ledger.recent(NOW).len(), 1);
    }

    #[test]
    fn an_unreadable_ledger_is_an_empty_hour_rather_than_an_outage() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp_budget.enc");
        Ledger::new(path.clone(), [4u8; 32])
            .record(NOW, Spend::Change { hosts: 1 })
            .unwrap();
        // A changed MCP password: the counter cannot be read any more.
        assert!(Ledger::new(path, [9u8; 32]).recent(NOW).is_empty());
    }

    #[test]
    fn what_is_on_disk_is_not_readable_without_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp_budget.enc");
        Ledger::new(path.clone(), [4u8; 32])
            .record(NOW, Spend::Change { hosts: 7 })
            .unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("changed"));
    }
}
