//! Which of your servers have updates waiting, and which of those matter.
//!
//! A security advisory lands and the question is immediately "which of these
//! forty boxes is affected". Answering it today means connecting to each one
//! and running the right command for whatever it happens to run.
//!
//! ## Where the truth comes from
//!
//! The host's own package manager, and nothing else. Not NVD, not OSV, not any
//! third-party feed - Kino makes no external request for this at all. That is
//! deliberate: the distributions' own trackers never had the enrichment
//! backlog that made public vulnerability data unreliable through 2025, and
//! they are the only source that knows what is actually installed here. It
//! also means the feature works for someone whose laptop can reach their
//! servers and nothing else.
//!
//! ## Honesty about the security count
//!
//! Only some package managers can separate security updates from the rest.
//! Where one cannot, this reports that it cannot, rather than reporting zero.
//! A zero that means "no security updates" and a zero that means "I could not
//! tell" look identical on a dashboard and lead to opposite decisions.

use serde::Serialize;

/// One package with something newer available.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Pending {
    pub name: String,
    /// What is installed. `None` where the manager does not say.
    pub current: Option<String>,
    pub candidate: String,
    /// Known to be a security update. `false` here means "not known to be",
    /// which is why `HostPatches::security` can be `None` overall.
    pub security: bool,
}

/// Which package manager a host runs.
#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Manager {
    Apt,
    Dnf,
    Yum,
    Zypper,
    Apk,
    Pacman,
}

impl Manager {
    /// The short tag the gather script echoes back, and its inverse.
    pub fn tag(&self) -> &'static str {
        match self {
            Manager::Apt => "apt",
            Manager::Dnf => "dnf",
            Manager::Yum => "yum",
            Manager::Zypper => "zypper",
            Manager::Apk => "apk",
            Manager::Pacman => "pacman",
        }
    }

    pub fn from_tag(tag: &str) -> Option<Manager> {
        [
            Manager::Apt,
            Manager::Dnf,
            Manager::Yum,
            Manager::Zypper,
            Manager::Apk,
            Manager::Pacman,
        ]
        .into_iter()
        .find(|m| m.tag() == tag)
    }

    /// Can this manager tell a security update from an ordinary one?
    pub fn separates_security(&self) -> bool {
        matches!(
            self,
            Manager::Apt | Manager::Dnf | Manager::Yum | Manager::Zypper
        )
    }

    /// What to run to list pending updates. Read-only, no sudo, no prompts.
    pub fn list_command(&self) -> &'static str {
        match self {
            Manager::Apt => "apt list --upgradable 2>/dev/null",
            Manager::Dnf => "dnf -q check-update 2>/dev/null || true",
            Manager::Yum => "yum -q check-update 2>/dev/null || true",
            Manager::Zypper => "zypper -q list-updates 2>/dev/null",
            Manager::Apk => "apk version -l '<' 2>/dev/null",
            // `checkupdates` is in pacman-contrib and does not touch the
            // system database, unlike `pacman -Sy`, which would.
            Manager::Pacman => "checkupdates 2>/dev/null",
        }
    }

    /// What a person would type to actually apply the updates.
    ///
    /// Needs sudo, which is exactly why Kino inserts this on a command line
    /// rather than running it: a password prompt, a conffile question or a
    /// service restart all want somebody watching.
    pub fn upgrade_command(&self) -> &'static str {
        match self {
            Manager::Apt => "sudo apt-get upgrade",
            Manager::Dnf => "sudo dnf upgrade",
            Manager::Yum => "sudo yum update",
            Manager::Zypper => "sudo zypper update",
            Manager::Apk => "sudo apk upgrade",
            Manager::Pacman => "sudo pacman -Syu",
        }
    }

    /// What to run to list only security updates, where that is possible.
    pub fn security_command(&self) -> Option<&'static str> {
        match self {
            // apt says it in the suite name on each line, so the main listing
            // already carries it.
            Manager::Apt => None,
            Manager::Dnf => Some("dnf -q updateinfo list security 2>/dev/null || true"),
            Manager::Yum => Some("yum -q updateinfo list security 2>/dev/null || true"),
            Manager::Zypper => Some("zypper -q list-patches --category security 2>/dev/null"),
            Manager::Apk | Manager::Pacman => None,
        }
    }
}

// ── Parsers ─────────────────────────────────────────────────────────────────
//
// Each takes the captured stdout and returns what it found. Pure, so every
// format is a fixture in the tests below rather than something discovered
// against a stranger's server.

/// `nginx/jammy-updates,jammy-security 1.18.0-6ubuntu14.4 amd64 [upgradable from: 1.18.0-6ubuntu14.3]`
///
/// The suite list is where apt says "security", so the one listing answers
/// both questions.
pub fn parse_apt(text: &str) -> Vec<Pending> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            // "Listing..." and any WARNING apt feels like emitting.
            let (name_part, rest) = line.split_once('/')?;
            if name_part.is_empty() || name_part.contains(' ') {
                return None;
            }
            let mut fields = rest.split_whitespace();
            let suites = fields.next()?;
            let candidate = fields.next()?;
            let current = line
                .split_once("[upgradable from:")
                .and_then(|(_, tail)| tail.split(']').next())
                .map(|s| s.trim().to_string());
            Some(Pending {
                name: name_part.to_string(),
                current,
                candidate: candidate.to_string(),
                security: suites.contains("-security"),
            })
        })
        .collect()
}

/// `curl.x86_64      7.76.1-26.el9_3.2      baseos`
///
/// `security` is filled in afterwards from `updateinfo`, which names packages
/// in a separate listing.
pub fn parse_dnf(text: &str) -> Vec<Pending> {
    text.lines()
        .take_while(|l| !l.trim_start().starts_with("Obsoleting"))
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with("Last metadata") {
                return None;
            }
            let mut f = line.split_whitespace();
            let (name_arch, candidate, _repo) = (f.next()?, f.next()?, f.next()?);
            // A wrapped line has no third field; requiring the repo drops it.
            let name = name_arch
                .rsplit_once('.')
                .map(|(n, _)| n)
                .unwrap_or(name_arch);
            Some(Pending {
                name: name.to_string(),
                current: None,
                candidate: candidate.to_string(),
                security: false,
            })
        })
        .collect()
}

/// The package names inside `dnf updateinfo list security` output:
/// `RHSA-2024:1234 Important/Sec. curl-7.76.1-26.el9_3.2.x86_64`
pub fn parse_dnf_security(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let nvra = line.split_whitespace().last()?;
            // Strip `-version-release.arch` back to the package name.
            let without_arch = nvra.rsplit_once('.').map(|(a, _)| a).unwrap_or(nvra);
            let (name, _) = without_arch.rsplit_once('-')?;
            let (name, _) = name.rsplit_once('-')?;
            (!name.is_empty()).then(|| name.to_string())
        })
        .collect()
}

/// `v | repo-oss | curl | 7.66.0-1.1 | 7.66.0-2.1 | x86_64`
pub fn parse_zypper(text: &str) -> Vec<Pending> {
    text.lines()
        .filter_map(|line| {
            let cols: Vec<&str> = line.split('|').map(str::trim).collect();
            if cols.len() < 5 || cols[0] != "v" {
                return None;
            }
            Some(Pending {
                name: cols[2].to_string(),
                current: Some(cols[3].to_string()).filter(|s| !s.is_empty()),
                candidate: cols[4].to_string(),
                security: false,
            })
        })
        .collect()
}

/// `curl-7.80.0-r0 < 7.80.0-r1`
pub fn parse_apk(text: &str) -> Vec<Pending> {
    text.lines()
        .filter_map(|line| {
            let (installed, candidate) = line.split_once('<')?;
            let installed = installed.trim();
            // `name-version-rN`: two trailing segments are the version.
            let (rest, _rel) = installed.rsplit_once('-')?;
            let (name, ver) = rest.rsplit_once('-')?;
            Some(Pending {
                name: name.to_string(),
                current: Some(format!("{ver}-{_rel}")),
                candidate: candidate.trim().to_string(),
                security: false,
            })
        })
        .collect()
}

/// `curl 7.80.0-1 -> 7.81.0-1`
pub fn parse_pacman(text: &str) -> Vec<Pending> {
    text.lines()
        .filter_map(|line| {
            let mut f = line.split_whitespace();
            let (name, current, arrow, candidate) = (f.next()?, f.next()?, f.next()?, f.next()?);
            (arrow == "->").then(|| Pending {
                name: name.to_string(),
                current: Some(current.to_string()),
                candidate: candidate.to_string(),
                security: false,
            })
        })
        .collect()
}

/// Parse a listing for whichever manager produced it.
pub fn parse(manager: Manager, text: &str) -> Vec<Pending> {
    match manager {
        Manager::Apt => parse_apt(text),
        Manager::Dnf | Manager::Yum => parse_dnf(text),
        Manager::Zypper => parse_zypper(text),
        Manager::Apk => parse_apk(text),
        Manager::Pacman => parse_pacman(text),
    }
}

/// Mark the packages a security listing named.
pub fn apply_security(pending: &mut [Pending], names: &[String]) {
    for p in pending.iter_mut() {
        if names.iter().any(|n| n == &p.name) {
            p.security = true;
        }
    }
}

// ── Asking a host ───────────────────────────────────────────────────────────

use crate::vault::Host;
use std::time::Duration;

/// Long enough for a slow package manager on a slow box, short enough that one
/// stuck host does not hold up a sweep.
const HOST_TIMEOUT: Duration = Duration::from_secs(30);

/// How many hosts at once. A fleet sweep should not open forty SSH handshakes
/// simultaneously, on this machine or on whatever sits between.
const CONCURRENCY: usize = 8;

const MARK_MGR: &str = "__KINO_MGR__";
const MARK_LIST: &str = "__KINO_LIST__";
const MARK_SEC: &str = "__KINO_SEC__";
const MARK_REBOOT: &str = "__KINO_REBOOT__";

/// What one host had to say.
#[derive(Serialize, Clone, Debug)]
pub struct HostPatches {
    pub host_id: String,
    pub manager: Option<Manager>,
    pub total: usize,
    /// `None` where the manager cannot separate security updates. Not zero:
    /// "none" and "could not tell" lead to opposite decisions.
    pub security: Option<usize>,
    pub reboot_required: bool,
    /// What to type to apply them, for the terminal Kino opens.
    pub upgrade_command: Option<String>,
    pub packages: Vec<Pending>,
    pub error: Option<String>,
    pub checked_at: i64,
}

/// One script that detects the manager and gathers everything, so a host costs
/// one connection rather than one per question.
///
/// Branching happens on the host because only the host knows what it runs.
/// Pure, so the shape of it is a test rather than something read off a server.
pub fn gather_script() -> String {
    let mut out = String::new();
    for (probe, m) in [
        ("apt-get", Manager::Apt),
        ("dnf", Manager::Dnf),
        ("yum", Manager::Yum),
        ("zypper", Manager::Zypper),
        ("apk", Manager::Apk),
        ("pacman", Manager::Pacman),
    ] {
        let kw = if out.is_empty() { "if" } else { "elif" };
        let name = serde_json::to_string(&m).unwrap_or_default();
        let name = name.trim_matches('"');
        out.push_str(&format!(
            "{kw} command -v {probe} >/dev/null 2>&1; then \
             echo {MARK_MGR}{name}; echo {MARK_LIST}; {}; echo {MARK_SEC}; {}; ",
            m.list_command(),
            m.security_command().unwrap_or("true"),
        ));
    }
    out.push_str("fi; ");
    // Debian family leaves a flag file; the RHEL family answers with an exit
    // code, where 1 means "yes, reboot".
    out.push_str(&format!(
        "echo {MARK_REBOOT}; \
         if [ -f /var/run/reboot-required ]; then echo yes; \
         elif command -v needs-restarting >/dev/null 2>&1; then \
           needs-restarting -r >/dev/null 2>&1 || echo yes; \
         fi"
    ));
    out
}

/// Pull the sections back out of the script's output.
pub fn parse_gathered(text: &str) -> (Option<Manager>, Vec<Pending>, bool) {
    let section = |mark: &str| -> Option<&str> {
        let start = text.find(mark)? + mark.len();
        let rest = &text[start..];
        let end = [MARK_MGR, MARK_LIST, MARK_SEC, MARK_REBOOT]
            .iter()
            .filter_map(|m| rest.find(m))
            .min()
            .unwrap_or(rest.len());
        Some(&rest[..end])
    };

    let manager = section(MARK_MGR).and_then(|s| Manager::from_tag(s.lines().next()?.trim()));
    let reboot = section(MARK_REBOOT).is_some_and(|s| s.contains("yes"));

    let Some(manager) = manager else {
        return (None, vec![], reboot);
    };
    let mut pending = parse(manager, section(MARK_LIST).unwrap_or(""));
    if manager.separates_security() && manager.security_command().is_some() {
        let names = parse_dnf_security(section(MARK_SEC).unwrap_or(""));
        apply_security(&mut pending, &names);
    }
    (Some(manager), pending, reboot)
}

async fn check_one(host: &Host) -> HostPatches {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let mut out = HostPatches {
        host_id: host.id.clone(),
        manager: None,
        total: 0,
        security: None,
        reboot_required: false,
        upgrade_command: None,
        packages: vec![],
        error: None,
        checked_at: now,
    };

    match tokio::time::timeout(
        HOST_TIMEOUT,
        crate::ssh_session::exec_once(host, &gather_script()),
    )
    .await
    {
        Ok(Ok(text)) => {
            let (manager, packages, reboot) = parse_gathered(&text);
            out.security = manager
                .filter(|m| m.separates_security())
                .map(|_| packages.iter().filter(|p| p.security).count());
            if manager.is_none() {
                out.error = Some("No supported package manager found on this host.".into());
            }
            out.upgrade_command = manager.map(|m| m.upgrade_command().to_string());
            out.manager = manager;
            out.total = packages.len();
            out.packages = packages;
            out.reboot_required = reboot;
        }
        // A host that cannot be reached appears in the table with its reason.
        // Dropping it would quietly shrink the fleet you think you audited.
        Ok(Err(e)) => out.error = Some(e),
        Err(_) => out.error = Some("Timed out".into()),
    }
    out
}

/// Ask every supplied host what it has pending.
#[tauri::command]
pub async fn check_patches(hosts: Vec<Host>) -> Vec<HostPatches> {
    use futures_util::stream::{self, StreamExt};
    stream::iter(hosts.iter())
        .map(check_one)
        .buffer_unordered(CONCURRENCY)
        .collect()
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs the real script through a real shell against this machine's real
    /// package manager. Fixtures test the parsing; this tests that the thing
    /// being parsed is what the script actually produces - which no fixture
    /// I write can tell me.
    ///
    ///     cargo test --lib patches -- --ignored --nocapture
    #[test]
    #[ignore = "runs the gather script against this machine"]
    fn gathers_from_this_machine() {
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(gather_script())
            .output()
            .expect("could not run the script");
        let text = String::from_utf8_lossy(&out.stdout);

        let (manager, pending, reboot) = parse_gathered(&text);
        println!("manager: {manager:?}");
        println!("reboot required: {reboot}");
        println!("pending: {}", pending.len());
        for p in pending.iter().take(8) {
            println!(
                "  {} {} -> {}{}",
                p.name,
                p.current.as_deref().unwrap_or("?"),
                p.candidate,
                if p.security { "  [security]" } else { "" }
            );
        }
        assert!(manager.is_some(), "no package manager detected:\n{text}");
        assert!(
            out.stderr.is_empty(),
            "stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn the_gather_script_only_looks() {
        let script = gather_script();
        assert!(!script.contains("sudo"), "{script}");
        assert!(!script.contains("-Sy"), "{script}");
        assert!(!script.contains(" install"), "{script}");
        // Every manager gets a branch, so a host is asked once.
        for probe in ["apt-get", "dnf", "yum", "zypper", "apk", "pacman"] {
            assert!(script.contains(probe), "no branch for {probe}");
        }
    }

    #[test]
    fn applying_updates_is_never_something_kino_runs_itself() {
        // Every one of these needs sudo and may ask a question. They are for
        // inserting on a command line in front of a person, not for running.
        for m in [
            Manager::Apt,
            Manager::Dnf,
            Manager::Yum,
            Manager::Zypper,
            Manager::Apk,
            Manager::Pacman,
        ] {
            let cmd = m.upgrade_command();
            assert!(cmd.starts_with("sudo "), "{cmd}");
            assert!(
                !cmd.contains(" -y"),
                "{cmd} must not answer its own prompts"
            );
            assert!(!cmd.contains("--noconfirm"), "{cmd}");
        }
    }

    #[test]
    fn tags_round_trip() {
        for m in [
            Manager::Apt,
            Manager::Dnf,
            Manager::Yum,
            Manager::Zypper,
            Manager::Apk,
            Manager::Pacman,
        ] {
            assert_eq!(Manager::from_tag(m.tag()), Some(m));
        }
        assert_eq!(Manager::from_tag("nix"), None);
    }

    #[test]
    fn pulls_the_sections_out_of_a_gathered_reply() {
        let out = "__KINO_MGR__apt\n__KINO_LIST__\nListing...\n\
                   curl/jammy-security 1.2 amd64 [upgradable from: 1.1]\n\
                   __KINO_SEC__\n__KINO_REBOOT__\nyes\n";
        let (mgr, pending, reboot) = parse_gathered(out);
        assert_eq!(mgr, Some(Manager::Apt));
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].name, "curl");
        assert!(pending[0].security);
        assert!(reboot);
    }

    #[test]
    fn a_host_with_no_known_manager_reports_nothing_rather_than_guessing() {
        let (mgr, pending, reboot) = parse_gathered("__KINO_REBOOT__\n");
        assert_eq!(mgr, None);
        assert!(pending.is_empty());
        assert!(!reboot);
    }

    #[test]
    fn a_marker_appearing_in_package_output_does_not_swallow_the_rest() {
        // Sections end at the next marker, so output mentioning one is bounded.
        let out = "__KINO_MGR__apt\n__KINO_LIST__\ncurl/jammy 1.2 amd64\n__KINO_REBOOT__\n";
        let (mgr, pending, reboot) = parse_gathered(out);
        assert_eq!(mgr, Some(Manager::Apt));
        assert_eq!(pending.len(), 1);
        assert!(!reboot);
    }

    #[test]
    fn reads_real_apt_output() {
        // Verbatim from an Ubuntu 22.04 box, header and all.
        let out = "Listing...\n\
            curl/jammy-updates,jammy-security 7.81.0-1ubuntu1.15 amd64 [upgradable from: 7.81.0-1ubuntu1.14]\n\
            vim/jammy-updates 2:8.2.3995-1ubuntu2.15 amd64 [upgradable from: 2:8.2.3995-1ubuntu2.13]\n";
        let got = parse_apt(out);
        assert_eq!(
            got.len(),
            2,
            "the Listing... header must not become a package"
        );
        assert_eq!(got[0].name, "curl");
        assert_eq!(got[0].current.as_deref(), Some("7.81.0-1ubuntu1.14"));
        assert_eq!(got[0].candidate, "7.81.0-1ubuntu1.15");
        assert!(got[0].security, "jammy-security is in the suite list");
        assert!(
            !got[1].security,
            "jammy-updates alone is not a security update"
        );
    }

    #[test]
    fn apt_with_nothing_pending_is_empty_not_an_error() {
        assert_eq!(parse_apt("Listing...\n"), vec![]);
        assert_eq!(parse_apt(""), vec![]);
    }

    #[test]
    fn ignores_the_warnings_apt_likes_to_emit() {
        let out =
            "WARNING: apt does not have a stable CLI interface. Use with caution in scripts.\n\
                   Listing...\n\
                   curl/jammy-security 1.2 amd64 [upgradable from: 1.1]\n";
        let got = parse_apt(out);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, "curl");
    }

    #[test]
    fn reads_real_dnf_output() {
        let out = "Last metadata expiration check: 0:12:31 ago on Mon 02 Sep 2026.\n\n\
            curl.x86_64                7.76.1-26.el9_3.2               baseos\n\
            nginx.x86_64               1:1.20.1-14.el9_2.1             appstream\n\n\
            Obsoleting Packages\n\
            oldpkg.x86_64              1.0-1.el9                       appstream\n";
        let got = parse_dnf(out);
        assert_eq!(got.len(), 2, "obsoleted packages are not pending updates");
        assert_eq!(got[0].name, "curl");
        assert_eq!(got[0].candidate, "7.76.1-26.el9_3.2");
        assert!(got.iter().all(|p| p.name != "oldpkg"));
    }

    #[test]
    fn picks_package_names_out_of_dnf_advisories() {
        let out = "RHSA-2024:1234 Important/Sec. curl-7.76.1-26.el9_3.2.x86_64\n\
                   RHSA-2024:5678 Moderate/Sec.  nginx-1:1.20.1-14.el9_2.1.x86_64\n";
        assert_eq!(parse_dnf_security(out), vec!["curl", "nginx"]);
    }

    #[test]
    fn a_security_listing_marks_the_packages_it_names() {
        let mut pending = parse_dnf("curl.x86_64 7.76.1 baseos\nvim.x86_64 8.2 appstream\n");
        apply_security(&mut pending, &["curl".to_string()]);
        assert!(pending[0].security);
        assert!(!pending[1].security, "vim was not in the advisory");
    }

    #[test]
    fn reads_real_zypper_output() {
        let out = "S | Repository | Name | Current Version | Available Version | Arch\n\
                   --+------------+------+-----------------+-------------------+-------\n\
                   v | repo-oss   | curl | 7.66.0-1.1      | 7.66.0-2.1        | x86_64\n";
        let got = parse_zypper(out);
        assert_eq!(got.len(), 1, "the header and rule must not become packages");
        assert_eq!(got[0].name, "curl");
        assert_eq!(got[0].current.as_deref(), Some("7.66.0-1.1"));
        assert_eq!(got[0].candidate, "7.66.0-2.1");
    }

    #[test]
    fn reads_real_apk_and_pacman_output() {
        let apk = parse_apk("curl-7.80.0-r0 < 7.80.0-r1\nbusybox-1.35.0-r17 < 1.35.0-r29\n");
        assert_eq!(apk.len(), 2);
        assert_eq!(apk[0].name, "curl");
        assert_eq!(apk[0].current.as_deref(), Some("7.80.0-r0"));
        assert_eq!(apk[0].candidate, "7.80.0-r1");

        let pac = parse_pacman("curl 7.80.0-1 -> 7.81.0-1\nlinux 6.6.1-1 -> 6.6.2-1\n");
        assert_eq!(pac.len(), 2);
        assert_eq!(pac[1].name, "linux");
        assert_eq!(pac[1].candidate, "6.6.2-1");
    }

    #[test]
    fn a_manager_that_cannot_separate_security_says_so() {
        // The distinction the dashboard depends on: a zero that means "none"
        // and a zero that means "could not tell" must not look the same.
        assert!(Manager::Apt.separates_security());
        assert!(Manager::Dnf.separates_security());
        assert!(!Manager::Apk.separates_security());
        assert!(!Manager::Pacman.separates_security());
    }

    #[test]
    fn a_host_with_two_managers_is_asked_about_the_right_one() {
        // Debian derivatives sometimes have dnf installed; they are still
        // Debian. The script's branch order decides, so assert the order.
        let script = gather_script();
        let at = |probe: &str| script.find(probe).unwrap();
        assert!(at("apt-get") < at("dnf"), "apt must be checked before dnf");
        assert!(at("dnf") < at("yum"), "dnf must be checked before yum");
        assert!(at("zypper") < at("apk"));
    }

    #[test]
    fn nothing_reaches_for_the_network_or_sudo() {
        for m in [
            Manager::Apt,
            Manager::Dnf,
            Manager::Yum,
            Manager::Zypper,
            Manager::Apk,
            Manager::Pacman,
        ] {
            // "check-update" and "list-updates" contain the word and change
            // nothing; what matters is that none of these install anything or
            // rewrite the host's package database.
            for cmd in [Some(m.list_command()), m.security_command()]
                .into_iter()
                .flatten()
            {
                assert!(!cmd.contains("sudo"), "{cmd}");
                assert!(!cmd.contains(" install"), "{cmd}");
                assert!(!cmd.contains("upgrade"), "{cmd}");
                // `pacman -Sy` refreshes the database; `checkupdates` uses a
                // temporary copy precisely so it does not.
                assert!(!cmd.contains("-Sy"), "{cmd}");
                assert!(!cmd.contains("apt-get update"), "{cmd}");
                assert!(!cmd.contains("zypper ref"), "{cmd}");
            }
        }
    }
}
