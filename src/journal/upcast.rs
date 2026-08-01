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
        if version == 1 {
            Ok(payload)
        } else {
            Err(StoreError::Corrupt {
                seq: 0,
                detail: format!(
                    "record {kind} v{version} is newer than this build understands (v1) — \
                     readers must be deployed before writers"
                ),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A future-dated record means someone deployed a writer before the readers.
    /// Failing loudly beats silently dropping fields.
    #[test]
    fn future_versions_are_refused_not_guessed() {
        let err = Identity.upcast("EffectDone", 7, json!({})).unwrap_err();
        assert!(matches!(err, StoreError::Corrupt { .. }));
    }

    #[test]
    fn current_version_passes_through() {
        assert_eq!(
            Identity.upcast("EffectDone", 1, json!({"a": 1})).unwrap(),
            json!({"a": 1})
        );
    }

    /// Upcasting must be deterministic — the property that keeps replay sound
    /// once real migrations exist.
    #[test]
    fn upcasting_is_pure() {
        let a = Identity
            .upcast("StepStarted", 1, json!({"skill": "x"}))
            .unwrap();
        let b = Identity
            .upcast("StepStarted", 1, json!({"skill": "x"}))
            .unwrap();
        assert_eq!(a, b);
    }
}
