use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// Which commit this binary came from, for About to show (KR-04-F5).
///
/// Three sources, in order of how much they can be trusted: CI knows
/// authoritatively, a working tree can be asked, and a build from a source
/// tarball has neither and says `unknown` rather than guessing.
fn commit() -> String {
    if let Ok(sha) = std::env::var("GITHUB_SHA") {
        if sha.len() >= 7 {
            return sha[..7].to_string();
        }
    }
    let out = Command::new("git")
        .args(["rev-parse", "--short=7", "HEAD"])
        .output();
    match out {
        Ok(out) if out.status.success() => {
            let sha = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if sha.is_empty() {
                "unknown".to_string()
            } else {
                sha
            }
        }
        _ => "unknown".to_string(),
    }
}

/// The build date as `YYYY-MM-DD`, in UTC.
///
/// A date, not a timestamp: the question it answers is "how old is this
/// binary", and seconds of resolution in a published artifact only make two
/// builds of the same commit differ for no reason. `SOURCE_DATE_EPOCH` wins
/// when it is set, which is what a reproducible-build packager sets it for.
fn build_date() -> String {
    let secs = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0)
        });
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    format!("{y:04}-{m:02}-{d:02}")
}

/// Days since 1970-01-01 to a calendar date - Howard Hinnant's `civil_from_days`.
///
/// Written out rather than pulled in: a build script that needs a date crate
/// adds a dependency to every build of this project, and this is eleven lines
/// that have been correct since 1970 and will be until 32767.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn main() {
    println!("cargo:rustc-env=KINO_COMMIT={}", commit());
    println!("cargo:rustc-env=KINO_BUILD_DATE={}", build_date());
    // Without this, a binary built before a commit goes on claiming the
    // commit it was built at - which is the one way this field can lie.
    println!("cargo:rerun-if-changed=../.git/HEAD");
    println!("cargo:rerun-if-env-changed=GITHUB_SHA");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    tauri_build::build()
}
