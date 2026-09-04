//! The commands worth stopping someone from running by accident.
//!
//! The worst moment in operations is realising you were on production when you
//! thought you were on staging. The prompts look alike, the tab looks alike,
//! and the command was fine on the box you meant.
//!
//! ## What this is, and is not
//!
//! It matches the command line as written. It does **not** parse shell, and
//! must never be described as though it does. `rm -rf /` is caught;
//! `$(printf '\x72\x6d') -rf /` is not, and neither is anything else that
//! assembles itself at runtime, hides in a script, or arrives through an alias.
//!
//! That is not a flaw to be fixed later - it is the whole shape of the thing. A
//! guard against a determined operator is impossible, because the operator is
//! the one holding the shell. This exists to interrupt a reflex: the muscle
//! memory that types a command meant for another window. Against that it works
//! well, and it should be sold as nothing more.

use serde::{Deserialize, Serialize};

/// One rule and why it is here.
pub struct Danger {
    /// Matched case-insensitively against the whole line.
    pattern: &'static str,
    /// Shown in the confirmation, so the dialog says what is about to happen
    /// rather than only that something is.
    pub explains: &'static str,
}

/// What was matched, for the dialog to show.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct DangerMatch {
    /// The literal text that matched, so the user can see it in their line.
    pub matched: String,
    pub explains: String,
}

/// The default list.
///
/// Chosen for one property: each is something people genuinely run on the
/// wrong host, not everything that could conceivably be harmful. A list that
/// fires constantly gets clicked through without reading, which is worse than
/// no list at all - so `rm` alone is absent, and so is `kill`.
const DANGERS: &[Danger] = &[
    Danger {
        pattern: "rm -rf",
        explains: "deletes a directory tree with no confirmation and no undo",
    },
    Danger {
        pattern: "rm -fr",
        explains: "deletes a directory tree with no confirmation and no undo",
    },
    Danger {
        pattern: "mkfs",
        explains: "formats a filesystem, destroying everything on it",
    },
    Danger {
        pattern: "dd of=",
        explains: "writes directly over a device or file",
    },
    Danger {
        pattern: "> /dev/sd",
        explains: "writes directly over a disk",
    },
    Danger {
        pattern: "shutdown",
        explains: "powers the machine off; if it is remote you may not get it back",
    },
    Danger {
        pattern: "reboot",
        explains: "restarts the machine; anything not enabled at boot stays down",
    },
    Danger {
        pattern: "halt",
        explains: "stops the machine; if it is remote you may not get it back",
    },
    Danger {
        pattern: "init 0",
        explains: "powers the machine off",
    },
    Danger {
        pattern: "systemctl stop",
        explains: "stops a service that is presumably in use",
    },
    Danger {
        pattern: "systemctl disable",
        explains: "stops a service coming back after a reboot",
    },
    Danger {
        pattern: "iptables -f",
        explains: "flushes the firewall rules, which can lock you out",
    },
    Danger {
        pattern: "drop table",
        explains: "deletes a database table and everything in it",
    },
    Danger {
        pattern: "drop database",
        explains: "deletes an entire database",
    },
    Danger {
        pattern: "truncate table",
        explains: "empties a database table",
    },
    Danger {
        pattern: "chown -r",
        explains: "rewrites ownership across a tree, which can break a system",
    },
    Danger {
        pattern: "chmod -r",
        explains: "rewrites permissions across a tree, which can break a system",
    },
];

/// Does this line contain something worth stopping for?
///
/// Takes the whole visible line, prompt and all: the caller reads it off the
/// screen rather than tracking keystrokes, so history recall and tab
/// completion are covered. A prompt prefix cannot cause a false positive
/// because these patterns do not occur in one.
pub fn first_danger(line: &str) -> Option<DangerMatch> {
    let haystack = line.to_lowercase();
    DANGERS
        .iter()
        .find(|d| haystack.contains(d.pattern))
        .map(|d| {
            // Report the text as the user typed it, not as it was lowercased.
            let at = haystack.find(d.pattern).unwrap_or(0);
            DangerMatch {
                matched: line
                    .chars()
                    .skip(line.char_indices().take_while(|(i, _)| *i < at).count())
                    .take(d.pattern.chars().count())
                    .collect(),
                explains: d.explains.to_string(),
            }
        })
}

/// Check one command line. Returns `None` when there is nothing to stop for.
///
/// Called once per Enter in a session marked production, and not at all
/// otherwise, so the cost is paid exactly where the protection was asked for.
#[tauri::command]
pub fn check_command_danger(line: String) -> Option<DangerMatch> {
    first_danger(&line)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(line: &str) -> Option<String> {
        first_danger(line).map(|d| d.matched.to_lowercase())
    }

    #[test]
    fn catches_the_command_that_ruins_an_afternoon() {
        assert_eq!(hit("rm -rf /var/lib/postgresql"), Some("rm -rf".into()));
        assert_eq!(hit("sudo rm -fr /etc"), Some("rm -fr".into()));
        assert_eq!(hit("mkfs.ext4 /dev/sda1"), Some("mkfs".into()));
        assert_eq!(hit("dd of=/dev/sda if=image.iso"), Some("dd of=".into()));
        assert_eq!(hit("systemctl stop nginx"), Some("systemctl stop".into()));
        assert_eq!(hit("DROP TABLE users;"), Some("drop table".into()));
    }

    #[test]
    fn finds_it_through_the_prompt_the_line_is_read_with() {
        // The caller reads the whole visible row off the screen, so the prompt
        // comes along for the ride. It must not stop the match.
        assert_eq!(
            hit("root@web-prod:/var/www# rm -rf node_modules"),
            Some("rm -rf".into())
        );
        assert_eq!(hit("$ shutdown -h now"), Some("shutdown".into()));
    }

    #[test]
    fn case_does_not_matter_because_sql_is_shouted() {
        assert!(first_danger("drop database kino").is_some());
        assert!(first_danger("DROP DATABASE kino").is_some());
        assert!(first_danger("Drop Database kino").is_some());
    }

    #[test]
    fn reports_the_text_as_it_was_actually_typed() {
        // Lowercasing to match must not lowercase what is shown back.
        let m = first_danger("DROP TABLE users").unwrap();
        assert_eq!(m.matched, "DROP TABLE");
    }

    #[test]
    fn explains_what_the_command_does_not_merely_that_it_is_dangerous() {
        let m = first_danger("reboot").unwrap();
        assert!(m.explains.contains("restarts"), "{}", m.explains);
        assert!(!m.explains.is_empty());
    }

    // The other half of the job. A guard that fires on ordinary work gets
    // clicked through without being read, which is worse than no guard.
    #[test]
    fn stays_quiet_for_the_commands_of_an_ordinary_day() {
        for line in [
            "ls -la",
            "cd /var/log && tail -f syslog",
            "git status",
            "docker ps",
            "systemctl status nginx",
            "systemctl restart nginx",
            "journalctl -u nginx --no-pager",
            "df -h",
            "rm old.log",
            "rm -i notes.txt",
            "kill 1234",
            "SELECT * FROM users;",
            "vim /etc/nginx/nginx.conf",
            "npm run build",
        ] {
            assert_eq!(first_danger(line), None, "fired on: {line}");
        }
    }

    #[test]
    fn an_empty_line_is_not_a_danger() {
        assert_eq!(first_danger(""), None);
        assert_eq!(first_danger("   "), None);
    }
}
