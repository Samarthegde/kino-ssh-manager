//! How often an assistant may call, and how much it gets back (KR-01-F11).
//!
//! Two different problems, both of which policy alone does not touch:
//!
//! - **Rate.** A rule says whether a command may run, not how many times a
//!   minute. An assistant in a retry loop can open an SSH connection per call
//!   for as long as it likes, which is a small denial of service against the
//!   host and an expensive one against the person paying for the model.
//! - **Size.** `sftp_read` on a 2 GB log returns 2 GB. The model's context
//!   cannot hold it, the transfer costs real money, and the useful part was
//!   the first few hundred lines.
//!
//! Both are per host, because hosts differ: a busy database is not a spare
//! Raspberry Pi. Both are deliberately blunt, a sliding count and a byte cap,
//! because anything cleverer would have to understand the workload, and
//! guessing wrong here means refusing work the user asked for.
//!
//! The counting is in memory, so restarting `kino-mcp` clears it. That is a
//! real gap and it is the honest place for it: an assistant cannot restart the
//! server, and a person who can restart it can also change the limit. KR-11's
//! budgets, which count changes rather than calls, persist for that reason.

use std::collections::VecDeque;

/// A sliding one-minute window of call times, per host.
#[derive(Default, Debug)]
pub struct Window(VecDeque<u64>);

impl Window {
    /// Record a call at `now_ms` and say whether it may proceed.
    ///
    /// `max_per_min` of 0 means no limit. A refused call is **not** counted:
    /// otherwise an assistant that keeps calling would hold itself over the
    /// limit indefinitely, and the minute would never expire.
    pub fn admit(&mut self, now_ms: u64, max_per_min: u32) -> bool {
        if max_per_min == 0 {
            return true;
        }
        // Age measured from each call, not against a cutoff: with a cutoff of
        // `now - 60_000`, every timestamp in the first minute after the epoch
        // (or after a clock jump backwards) saturates to 0 and is dropped as
        // if it were an hour old.
        while self
            .0
            .front()
            .is_some_and(|t| now_ms.saturating_sub(*t) >= 60_000)
        {
            self.0.pop_front();
        }
        if self.0.len() as u32 >= max_per_min {
            return false;
        }
        self.0.push_back(now_ms);
        true
    }

    /// Calls counted in the current window, for the refusal message.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Output after the cap, and what it was before.
#[derive(Debug, PartialEq)]
pub struct Capped {
    pub text: String,
    /// Bytes before truncation. The audit record keeps this, so the log says
    /// how much the host actually produced rather than how much fitted.
    pub original: usize,
    pub truncated: bool,
}

/// Cut `text` to `limit` bytes, saying so in the text itself.
///
/// The marker is part of the returned content on purpose: an assistant that
/// cannot see the output was cut will summarise a file from its first page and
/// report that as the whole. `limit` of 0 means no cap.
///
/// Truncation is at a character boundary, so the result is always valid UTF-8
/// - cutting mid-character would produce bytes no client can decode.
pub fn cap(text: String, limit: usize) -> Capped {
    let original = text.len();
    if limit == 0 || original <= limit {
        return Capped {
            text,
            original,
            truncated: false,
        };
    }
    let mut end = limit;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    let dropped = original - end;
    let mut out = text[..end].to_string();
    out.push_str(&format!("\n…[truncated {dropped} bytes]"));
    Capped {
        text: out,
        original,
        truncated: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calls_under_the_limit_all_go_through() {
        let mut w = Window::default();
        for i in 0..60 {
            assert!(w.admit(1_000 + i, 60), "call {i} should be admitted");
        }
    }

    #[test]
    fn the_call_over_the_limit_is_refused() {
        let mut w = Window::default();
        for i in 0..60 {
            w.admit(1_000 + i, 60);
        }
        assert!(!w.admit(1_100, 60));
    }

    #[test]
    fn a_refused_call_does_not_extend_the_block() {
        // The window must drain on time even while an assistant keeps trying.
        let mut w = Window::default();
        for _ in 0..10 {
            w.admit(1_000, 10);
        }
        for t in 1_001..1_500 {
            assert!(!w.admit(t, 10), "still over the limit");
        }
        // 60s after the originals, and nothing the refused calls did counts.
        assert!(w.admit(61_001, 10));
    }

    #[test]
    fn the_window_slides_rather_than_resetting() {
        let mut w = Window::default();
        w.admit(0, 2);
        w.admit(30_000, 2);
        assert!(!w.admit(30_001, 2), "both are still inside the minute");
        // The first has aged out; the second has not.
        assert!(w.admit(60_001, 2));
        assert!(!w.admit(60_002, 2));
    }

    #[test]
    fn zero_means_no_limit() {
        let mut w = Window::default();
        for i in 0..1_000 {
            assert!(w.admit(i, 0));
        }
        assert!(w.is_empty(), "nothing is even counted");
    }

    #[test]
    fn output_within_the_cap_is_untouched() {
        let c = cap("hello".to_string(), 256);
        assert_eq!(c.text, "hello");
        assert!(!c.truncated);
        assert_eq!(c.original, 5);
    }

    #[test]
    fn output_over_the_cap_says_how_much_was_dropped() {
        let c = cap("a".repeat(300), 100);
        assert!(c.truncated);
        assert_eq!(c.original, 300, "the size before the cut is kept");
        assert!(c.text.starts_with(&"a".repeat(100)));
        assert!(c.text.ends_with("…[truncated 200 bytes]"), "{}", c.text);
    }

    #[test]
    fn truncation_never_splits_a_character() {
        // 'é' is two bytes: cutting at 5 would land inside the third one.
        let c = cap("ééé".to_string(), 5);
        assert!(c.truncated);
        assert!(c.text.starts_with("éé"));
        assert!(!c.text.contains('\u{FFFD}'));
        assert_eq!(c.original, 6);
    }

    #[test]
    fn a_cap_of_zero_returns_everything() {
        let c = cap("a".repeat(10_000), 0);
        assert!(!c.truncated);
        assert_eq!(c.text.len(), 10_000);
    }
}
