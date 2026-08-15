//! Record schema evolution.
//!
//! The journal is forever, so record shapes must evolve without rewriting
//! history. Five rules, and the last two are the ones that are easy to get
//! wrong:
//!
//! 1. Records carry `(kind, v)`; every writer stamps the version.
//! 2. **Backward compatibility is permanent.** New code must read every shape
//!    ever written. There is no "we migrated past that".
//! 3. **Upcast on read; never rewrite history.**
//! 4. **Upcasters are pure and total.** One that reads a clock, a config file,
//!    or the network breaks replay — the same bug class as a non-deterministic
//!    effect, but harder to find because it only manifests on old records.
//! 5. **Hash the wire bytes, not the upcast form.** Rehashing after an upcast
//!    would destroy tamper evidence for all history the first time a schema
//!    changed. See [`Record::from_stored`](super::Record::from_stored), which
//!    verifies against the stored bytes and never re-serializes.

use serde_json::Value;

use crate::core::StoreError;

/// A pure, total transform from an older record version to the current one.
///
/// Lives inside the deterministic zone: given the same `(kind, version,
/// payload)` it must always produce the same output, in this process and in one
/// started a year from now.
pub trait Upcaster: Send + Sync + std::fmt::Debug {
    /// Highest version this upcaster knows how to produce.
    fn current_version(&self, kind: &str) -> u16;

    /// Lift one payload one or more versions forward.
    fn upcast(&self, kind: &str, version: u16, payload: Value) -> Result<Value, StoreError>;
}

/// The identity upcaster: every kind is at v1 and nothing needs lifting.
///
/// Kept as a real type rather than an `Option<Box<dyn Upcaster>>` so the call
/// site has no branch and the first genuine migration is a one-line swap.
#[derive(Debug, Clone, Copy, Default)]
pub struct Identity;

impl Upcaster for Identity {
    fn current_version(&self, _kind: &str) -> u16 {
        1
    }

    fn upcast(&self, kind: &str, version: u16, payload: Value) -> Result<Value, StoreError> {
        match version {
            1 => Ok(payload),
            // Refused rather than guessed at, in both directions.
            //
            // Below: pre-freeze record shapes change by hard cut, and the danger
            // is that an older record still *parses* — a field that moved or was
            // added comes back as its serde default, so the journal answers an
            // audit question falsely instead of failing to answer it. There is
            // also nothing to lift *to*: the missing field's value was never
            // written, and inventing one would fabricate provenance. The whole
            // journal is refused rather than the affected kinds, because a
            // journal holding one such record holds the rest.
            //
            // Above: a version this build has never heard of means somebody
            // deployed a writer ahead of its readers.
            _ => Err(StoreError::Corrupt {
                seq: 0,
                detail: format!(
                    "record {kind} is v{version}, and this build writes and reads v1 only. \
                     Record shapes change by hard cut until the format freeze, so a journal \
                     at another version is refused rather than read with fields quietly \
                     defaulted — a false answer to an audit question is worse than a \
                     refusal to answer. Start a fresh journal; if v{version} is the newer \
                     one, deploy readers before writers"
                ),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A journal from an older cut is refused, not read with fields missing.
    ///
    /// The danger is that it *parses*. A record whose shape has since changed
    /// still deserialises, with every moved or added field taking its serde
    /// default — so a resumed run reports, say, that no policy governed it. That
    /// is a false answer to an audit question, which is worse than a refusal to
    /// answer, and it is the reason nothing is lifted rather than refused.
    #[test]
    fn a_journal_from_an_older_cut_is_refused_rather_than_misread() {
        let err = Identity
            .upcast("RunAdmitted", 0, json!({ "agent": "a", "input": null }))
            .unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("fresh journal"),
            "the refusal must say what to do about it: {text}"
        );
    }

    /// A future-dated record means someone deployed a writer before the readers.
    /// Failing loudly beats silently dropping fields.
    #[test]
    fn future_versions_are_refused_not_guessed() {
        let err = Identity.upcast("EffectDone", 7, json!({})).unwrap_err();
        assert!(matches!(err, StoreError::Corrupt { .. }));
    }

    #[test]
    fn current_version_passes_through() {
        // Asked for rather than restated: a hardcoded number here silently
        // becomes a test of an *old* version the moment the format is bumped,
        // and then passes by being refused for the wrong reason.
        let v = Identity.current_version("EffectDone");
        assert_eq!(
            Identity.upcast("EffectDone", v, json!({"a": 1})).unwrap(),
            json!({"a": 1})
        );
    }

    /// Upcasting must be deterministic — the property that keeps replay sound
    /// once real migrations exist.
    #[test]
    fn upcasting_is_pure() {
        let v = Identity.current_version("StepStarted");
        let a = Identity
            .upcast("StepStarted", v, json!({"skill": "x"}))
            .unwrap();
        let b = Identity
            .upcast("StepStarted", v, json!({"skill": "x"}))
            .unwrap();
        assert_eq!(a, b);
    }
}
