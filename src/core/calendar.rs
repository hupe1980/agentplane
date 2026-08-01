//! The calendar seam — where domain-agnosticism gets stress-tested.
//!
//! Regulatory deadlines are rarely "now plus 24 hours". A realistic one reads:
//! *five working days, at 17:00 in a named timezone, excluding Saturdays,
//! Sundays, and public holidays — where a holiday observed in any single
//! federal state counts nationwide.* An off-by-one-hour error at a
//! daylight-saving transition is a compliance violation, not a rounding issue.
//!
//! None of that belongs in a domain-agnostic engine. All of it must be reachable
//! from one. So:
//!
//! | Core owns | Adapter owns |
//! |---|---|
//! | Durable registration, firing, cancellation | What "5 working days" resolves to |
//! | Warning thresholds, escalation | Holiday tables, timezone, cut-off hour |
//! | Breach recording | Calendar versioning |

use crate::core::{DeadlineSpec, Digest, Timestamp};

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CalendarError {
    #[error("this calendar does not implement deadline kind '{0}'")]
    UnknownKind(String),

    #[error("malformed parameters for '{kind}': {detail}")]
    BadParams { kind: String, detail: String },

    #[error("'{kind}' resolved outside the representable range")]
    OutOfRange { kind: String },
}

/// Resolves a domain-specific deadline description to an instant.
///
/// # Contract
///
/// Implementations **must be pure**: the same `(from, spec)` always resolves to
/// the same instant for a given [`digest`](Calendar::digest). The engine
/// journals the resolved instant and never calls back, so an impure calendar
/// would not corrupt an existing deadline — but it would make two runs
/// registered a millisecond apart disagree about the same regulatory window,
/// which is worse for being intermittent.
///
/// Changing the rules means changing the digest. That makes a shifted rule
/// visible in the journal instead of retroactive.
pub trait Calendar: Send + Sync + std::fmt::Debug {
    fn resolve(&self, from: Timestamp, spec: &DeadlineSpec) -> Result<Timestamp, CalendarError>;

    /// Identifies this calendar's ruleset. Recorded alongside every instant it
    /// produces.
    fn digest(&self) -> Digest;
}

/// The built-in calendar: plain wall-clock offsets.
///
/// Understands `hours` and `days` so the runtime is usable without an adapter.
/// It deliberately does **not** guess at working days or holidays — a wrong
/// answer there is worse than no answer, because it looks right.
#[derive(Debug, Clone, Copy, Default)]
pub struct WallClock;

impl WallClock {
    fn count(spec: &DeadlineSpec) -> Result<i64, CalendarError> {
        spec.params
            .get("n")
            .and_then(serde_json::Value::as_i64)
            .ok_or_else(|| CalendarError::BadParams {
                kind: spec.kind.clone(),
                detail: "expected an integer field `n`".into(),
            })
    }
}

impl Calendar for WallClock {
    fn resolve(&self, from: Timestamp, spec: &DeadlineSpec) -> Result<Timestamp, CalendarError> {
        let n = Self::count(spec)?;
        let delta = match spec.kind.as_str() {
            "hours" => time::Duration::hours(n),
            "days" => time::Duration::days(n),
            "minutes" => time::Duration::minutes(n),
            other => return Err(CalendarError::UnknownKind(other.to_owned())),
        };
        from.checked_add(delta).ok_or(CalendarError::OutOfRange {
            kind: spec.kind.clone(),
        })
    }

    fn digest(&self) -> Digest {
        Digest::of(b"agentplane.calendar.wallclock.v1")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn resolves_hours_and_days() {
        let base = datetime!(2026-07-30 09:00:00 UTC);
        assert_eq!(
            WallClock.resolve(base, &DeadlineSpec::hours(24)).unwrap(),
            datetime!(2026-07-31 09:00:00 UTC)
        );
        assert_eq!(
            WallClock.resolve(base, &DeadlineSpec::days(5)).unwrap(),
            datetime!(2026-08-04 09:00:00 UTC)
        );
    }

    /// Purity is the contract that keeps registered deadlines meaningful.
    #[test]
    fn resolution_is_pure() {
        let base = datetime!(2026-07-30 09:00:00 UTC);
        let spec = DeadlineSpec::hours(72);
        assert_eq!(
            WallClock.resolve(base, &spec).unwrap(),
            WallClock.resolve(base, &spec).unwrap()
        );
    }

    /// A calendar that cannot answer says so, rather than guessing. A wrong
    /// working-day answer is worse than no answer, because it looks right.
    #[test]
    fn unknown_rules_are_refused_not_approximated() {
        let err = WallClock
            .resolve(
                datetime!(2026-07-30 09:00:00 UTC),
                &DeadlineSpec::new("working-days", serde_json::json!({ "n": 5 })),
            )
            .unwrap_err();
        assert!(matches!(err, CalendarError::UnknownKind(_)));
    }

    #[test]
    fn malformed_parameters_are_refused() {
        let err = WallClock
            .resolve(
                datetime!(2026-07-30 09:00:00 UTC),
                &DeadlineSpec::new("hours", serde_json::json!({ "wrong": 1 })),
            )
            .unwrap_err();
        assert!(matches!(err, CalendarError::BadParams { .. }));
    }

    /// The digest identifies the ruleset; a different ruleset must be a
    /// different digest, or a shifted rule becomes retroactive.
    #[test]
    fn digest_is_stable_for_a_ruleset() {
        assert_eq!(WallClock.digest(), WallClock.digest());
    }
}
