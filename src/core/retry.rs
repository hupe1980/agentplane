//! Retry policy — how many times, how long apart, and when not at all.
//!
//! # Retrying is a safety decision before it is a reliability one
//!
//! Most runtimes treat retry as a reliability knob: the call failed, try again,
//! and push idempotency onto whoever wrote the tool. That is a defensible
//! trade when the worst case is a duplicate log line. It is the wrong trade
//! when the worst case is a duplicate payment, and it is wrong in a way that
//! only shows up in production, on the one call that timed out.
//!
//! So a policy here never decides alone. Three things do, in order:
//!
//! 1. The failure's [`Disposition`](crate::core::Disposition) — did the call
//!    reach the outside world? A refused connection and a timed-out request are
//!    both transient, and only one of them is safe to repeat.
//! 2. The effect's [`Recovery`](crate::core::Recovery) — for an in-doubt
//!    failure, is guessing permitted at all?
//! 3. This policy — and only then, how many times and how far apart.
//!
//! A policy cannot authorise a repeat that the first two refuse. Raising
//! `max_attempts` never makes a mutating in-doubt call retryable.
//!
//! # Backoff waits in-process, and that is deliberate
//!
//! A retry's backoff is a `tokio` sleep, so it holds the worker for its
//! duration. `max_backoff` is therefore not just a schedule ceiling — it is the
//! bound on how long one effect can occupy a frame, and it is why the default
//! is seconds rather than minutes.
//!
//! Suspending instead would be strictly worse here. Waking a suspended run
//! replays it from the beginning, so a run fifty steps deep pays fifty steps of
//! replay to avoid a five-second sleep. Durable suspension wins for waits
//! measured in minutes and hours; in-process wins for the seconds-scale jitter
//! that retry actually needs.
//!
//! So the boundary is drawn by purpose, not by duration:
//!
//! * **Retrying a flaky call** — this module. Bounded by `max_backoff`.
//! * **Waiting for the world** — a rate-limit window, a settlement date, five
//!   Werktage — is not a retry. Use
//!   [`StepCtx::sleep`](crate::runtime::StepCtx::sleep), which suspends the run
//!   and costs a row rather than a thread.
//!
//! Setting `max_backoff` to an hour is legal and will hold a worker for an
//! hour. That is stated rather than prevented, because a deployment that knows
//! its own concurrency may want exactly that.
//!
//! # Backoff is computed, not drawn
//!
//! The runtime forbids ambient randomness, so jitter cannot come from an RNG.
//! It is derived instead from the hash of the run, the effect key, and the
//! attempt number — which decorrelates concurrent runs the way jitter is
//! supposed to, while staying a pure function of things already in the journal.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::core::{Digest, EffectKey, RunId};

/// How many times to repeat a failed effect, and how far apart.
///
/// The defaults are safe rather than timid: three attempts with exponential
/// backoff. They are safe *because* [`Disposition`](crate::core::Disposition)
/// gates them — an effect whose failure is in-doubt is not repeated under this
/// policy unless its [`Recovery`](crate::core::Recovery) permits guessing, no
/// matter what `max_attempts` says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryPolicy {
    /// Total attempts including the first. `1` means "never repeat".
    pub max_attempts: u32,
    /// Delay before the second attempt.
    pub initial_backoff: Duration,
    /// Ceiling on the delay, however many attempts have passed.
    ///
    /// Also the bound on how long one effect holds a worker — see the module
    /// docs. For waits longer than a few seconds, the run should suspend
    /// instead: that is [`StepCtx::sleep`](crate::runtime::StepCtx::sleep), not
    /// a retry policy.
    pub max_backoff: Duration,
    /// Growth factor per attempt. An integer, so the schedule is exactly
    /// reproducible on any platform without depending on float rounding.
    pub multiplier: u32,
    /// Whether to spread the delay across runs. See the module docs — this is
    /// derived from a hash, not drawn from an RNG.
    pub jitter: bool,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(10),
            multiplier: 2,
            jitter: true,
        }
    }
}

impl RetryPolicy {
    /// Never repeat. The first failure is final.
    ///
    /// The right choice for an effect that is expensive, externally rate
    /// limited, or whose driver already retries internally — a policy stacked
    /// on a driver that retries is a multiplication, not an addition.
    #[must_use]
    pub const fn never() -> Self {
        Self {
            max_attempts: 1,
            initial_backoff: Duration::ZERO,
            max_backoff: Duration::ZERO,
            multiplier: 1,
            jitter: false,
        }
    }

    /// `n` total attempts with the default backoff schedule.
    #[must_use]
    pub fn attempts(n: u32) -> Self {
        Self {
            max_attempts: n.max(1),
            ..Self::default()
        }
    }

    /// Replace the backoff schedule, keeping the attempt count.
    #[must_use]
    pub fn with_backoff(mut self, initial: Duration, max: Duration) -> Self {
        self.initial_backoff = initial;
        self.max_backoff = max;
        self
    }

    /// Turn jitter off, making the schedule identical across runs.
    #[must_use]
    pub fn without_jitter(mut self) -> Self {
        self.jitter = false;
        self
    }

    /// Whether another attempt is left after `attempt` has failed.
    ///
    /// `attempt` is 1-based, matching what the journal records.
    #[must_use]
    pub fn permits(&self, attempt: u32) -> bool {
        attempt < self.max_attempts
    }

    /// How long to wait before `attempt` (1-based; attempt 1 never waits).
    ///
    /// Exponential with an integer multiplier and a ceiling, then optionally
    /// spread by a hash-derived factor in `[0.5, 1.0]` of the computed delay.
    /// Halving rather than scaling from zero keeps a floor under the schedule:
    /// full jitter can pick a near-zero delay and hammer a service that is
    /// already struggling.
    #[must_use]
    pub fn backoff(&self, run: RunId, key: EffectKey, attempt: u32) -> Duration {
        if attempt <= 1 {
            return Duration::ZERO;
        }

        // Saturating throughout: a large multiplier and a large attempt count
        // must produce `max_backoff`, not an overflow panic.
        let steps = attempt - 2;
        let mut delay = self.initial_backoff;
        for _ in 0..steps {
            delay = delay
                .saturating_mul(self.multiplier.max(1))
                .min(self.max_backoff);
            if delay >= self.max_backoff {
                break;
            }
        }
        let delay = delay.min(self.max_backoff);

        if !self.jitter || delay.is_zero() {
            return delay;
        }

        // Deterministic stand-in for an RNG draw. Including the run id is what
        // decorrelates two runs of the same plan retrying the same effect —
        // without it, identical keys would produce identical schedules and
        // reconverge into exactly the thundering herd jitter exists to prevent.
        let mut seed = Vec::with_capacity(64);
        seed.extend_from_slice(run.to_string().as_bytes());
        seed.extend_from_slice(&key.to_hex().into_bytes());
        seed.extend_from_slice(&attempt.to_be_bytes());
        let digest = Digest::of(&seed);
        let spread = u64::from_be_bytes(digest.as_bytes()[..8].try_into().expect("8 bytes"));

        // Map into [0.5, 1.0] of the computed delay, in integer arithmetic.
        let half = delay.as_nanos() / 2;
        let extra = (half.saturating_mul(u128::from(spread))) / u128::from(u64::MAX);
        Duration::from_nanos(u64::try_from(half + extra).unwrap_or(u64::MAX))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::StepId;

    fn key() -> EffectKey {
        EffectKey::derive(
            StepId(1),
            crate::core::Phase::Forward,
            0,
            1,
            "test.effect",
            b"{}",
        )
    }

    #[test]
    fn the_first_attempt_never_waits() {
        assert_eq!(
            RetryPolicy::default().backoff(RunId::generate(), key(), 1),
            Duration::ZERO
        );
    }

    #[test]
    fn backoff_grows_and_then_stops_at_the_ceiling() {
        let p = RetryPolicy {
            max_attempts: 10,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_millis(800),
            multiplier: 2,
            jitter: false,
        };
        let run = RunId::generate();
        let at = |n| p.backoff(run, key(), n);
        assert_eq!(at(2), Duration::from_millis(100));
        assert_eq!(at(3), Duration::from_millis(200));
        assert_eq!(at(4), Duration::from_millis(400));
        assert_eq!(at(5), Duration::from_millis(800));
        assert_eq!(at(6), Duration::from_millis(800), "ceiling holds");
        assert_eq!(at(50), Duration::from_millis(800), "and keeps holding");
    }

    #[test]
    fn an_absurd_schedule_saturates_instead_of_panicking() {
        let p = RetryPolicy {
            max_attempts: u32::MAX,
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_mins(1),
            multiplier: u32::MAX,
            jitter: true,
        };
        assert!(p.backoff(RunId::generate(), key(), u32::MAX) <= Duration::from_mins(1));
    }

    #[test]
    fn jitter_stays_within_half_the_delay() {
        let p = RetryPolicy {
            jitter: true,
            ..RetryPolicy::default()
        };
        let run = RunId::generate();
        for attempt in 2..8 {
            let d = p.backoff(run, key(), attempt);
            let plain = RetryPolicy { jitter: false, ..p }.backoff(run, key(), attempt);
            assert!(
                d >= plain / 2 && d <= plain,
                "attempt {attempt}: {d:?} outside [{:?}, {plain:?}]",
                plain / 2
            );
        }
    }

    #[test]
    fn jitter_decorrelates_runs_but_repeats_for_one_run() {
        let (a, b) = (RunId::generate(), RunId::generate());
        let p = RetryPolicy::default();
        assert_ne!(
            p.backoff(a, key(), 3),
            p.backoff(b, key(), 3),
            "two runs retrying the same effect must not reconverge"
        );
        assert_eq!(
            p.backoff(a, key(), 3),
            p.backoff(a, key(), 3),
            "and the schedule must be a pure function, not a draw"
        );
    }

    #[test]
    fn never_permits_no_second_attempt() {
        assert!(!RetryPolicy::never().permits(1));
        assert!(RetryPolicy::attempts(3).permits(1));
        assert!(RetryPolicy::attempts(3).permits(2));
        assert!(!RetryPolicy::attempts(3).permits(3));
    }
}
