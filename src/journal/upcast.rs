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
        4
    }

    fn upcast(&self, kind: &str, version: u16, payload: Value) -> Result<Value, StoreError> {
        match version {
            4 => Ok(payload),
            // Refused rather than lifted. v1 is readable — that is the problem:
            // `RunAdmitted.policy` became `policy_bundle` and `Declassified`
            // became `Released`, so a v1 record deserialises with the policy
            // digest silently absent and a resumed run would report that no
            // policy governed it. A false answer to an audit question is worse
            // than a refusal to answer.
            //
            // No lift is offered because there is nothing to lift *to*: the old
            // records do not carry the bundle identity the new shape requires,
            // and inventing one would fabricate provenance.
            1..=3 => Err(StoreError::Corrupt {
                seq: 0,
                detail: format!(
                    "record {kind} is v{version}: this journal predates the current format. \
                     Every one of these changes is dangerous precisely because the older \
                     record still *parses*. v1→v2: `RunAdmitted.policy` became \
                     `policy_bundle` and `Declassified` became `Released`, so the policy \
                     digest goes silently absent and a resumed run reports that no policy \
                     governed it. v3→v4: `RunAdmitted.agent` became `capability` and gained \
                     `governed_by`, so a v3 record names a capability in a field about \
                     identity and reports every run as ungoverned. The whole journal is \
                     refused rather than the affected kinds, because a journal containing \
                     one contains the others. No lift is offered: the old records do not \
                     carry the identity the new shape requires, and inventing one would \
                     fabricate provenance. Start a fresh journal — the project is \
                     pre-release and the cut is deliberate"
                ),
            }),
            _ => Err(StoreError::Corrupt {
                seq: 0,
                detail: format!(
                    "record {kind} v{version} is newer than this build understands (v4) — \
                     readers must be deployed before writers"
                ),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A future-dated record means someone deployed a writer before the readers.
    /// Failing loudly beats silently dropping fields.
    /// A pre-cut journal is refused, not read with fields quietly missing.
    ///
    /// The danger is that v1 *parses*: `RunAdmitted.policy` became
    /// `policy_bundle`, so an old record deserialises with the policy digest
    /// defaulting to absent, and a resumed run reports that nothing governed it.
    /// A false answer to an audit question is worse than a refusal to answer.
    #[test]
    fn a_pre_cut_journal_is_refused_rather_than_misread() {
        let err = Identity
            .upcast("RunAdmitted", 1, json!({ "agent": "a", "input": null }))
            .unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("policy_bundle") && text.contains("fresh journal"),
            "the refusal must name what changed and what to do about it: {text}"
        );
    }

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
