//! One contract, run against every key ring.
//!
//! A key ring is the thing an erasure obligation rests on, so "it compiled" is
//! not evidence. The battery below is the same set of questions for an
//! in-process ring and for a key-management service, because the guarantee a
//! deployment is promised does not change with the implementation — and the
//! implementations fail in different places, which is exactly why one of them
//! passing proves nothing about the other.
//!
//! The properties are the ones an erasure story stands or falls on:
//!
//! * a data key is **fresh per call**, because that is what a service does and
//!   a caller that assumed otherwise would seal two payloads with one key;
//! * a wrapped key **opens back to the same material**, or nothing is readable;
//! * rewrapping **preserves the key** while changing its wrapping, which is what
//!   makes rotation cheap rather than a re-encryption of everything;
//! * destroying a scope makes its keys **unopenable**, which is the erasure;
//! * destruction is **idempotent**, because a retried erasure must not fail and
//!   must not rewrite its own record.

use crate::keyring::{KeyError, KeyRing};

use super::conformance::Report;

/// Run the battery against one key ring, using `scope` as a fresh erasure unit.
///
/// The scope must be unused: this destroys it, and a destroyed scope does not
/// come back.
pub async fn check(ring: &dyn KeyRing, scope: &str) -> Report {
    let mut report = Report::default();
    let at =
        crate::core::Timestamp::from_unix_timestamp(1_760_000_000).expect("a valid test instant");

    // A ring that cannot mint has nothing else worth asking about, so the rest
    // is skipped rather than reported as five more failures with one cause.
    let Some(minted) = mint(ring, scope, &mut report).await else {
        return report;
    };
    rewraps(ring, &minted, &mut report).await;
    erases(ring, scope, &minted, at, &mut report).await;
    report
}

/// A data key is fresh per call, and its wrapped form opens back to it.
async fn mint(
    ring: &dyn KeyRing,
    scope: &str,
    report: &mut Report,
) -> Option<(crate::keyring::DataKey, crate::keyring::WrappedKey)> {
    report.checked += 1;
    let first = match ring.data_key(scope).await {
        Ok(k) => k,
        Err(e) => {
            report.record("data_key mints a key", format!("minting failed: {e}"));
            return None;
        }
    };
    let second = match ring.data_key(scope).await {
        Ok(k) => k,
        Err(e) => {
            report.record(
                "data_key mints a key",
                format!("the second mint failed: {e}"),
            );
            return None;
        }
    };

    report.checked += 1;
    if first.0.expose() == second.0.expose() {
        report.record(
            "a data key is fresh per call",
            "two mints returned the same key material. A service mints one per \
             call; a ring that does not means two payloads in one scope share a \
             key, and a caller written against a real KMS will not expect it",
        );
    }

    report.checked += 1;
    match ring.open(&first.1).await {
        Ok(opened) if opened.expose() == first.0.expose() => {}
        Ok(_) => report.record(
            "open returns the key that was wrapped",
            "opening a wrapped key produced different material, so nothing \
             sealed with it can ever be read",
        ),
        Err(e) => report.record("open returns the key that was wrapped", format!("{e}")),
    }
    Some(first)
}

/// Rewrapping preserves the key and keeps the erasure unit.
async fn rewraps(
    ring: &dyn KeyRing,
    minted: &(crate::keyring::DataKey, crate::keyring::WrappedKey),
    report: &mut Report,
) {
    report.checked += 1;
    let rewrapped = match ring.rewrap(&minted.1).await {
        Ok(w) => w,
        Err(e) => {
            report.record("rewrap is supported", format!("{e}"));
            return;
        }
    };
    if rewrapped.scope != minted.1.scope {
        report.record(
            "rewrapping keeps the erasure unit",
            format!(
                "the scope moved from '{}' to '{}', so the key is now erased by \
                 a different request than the data it seals",
                minted.1.scope, rewrapped.scope
            ),
        );
    }

    report.checked += 1;
    match ring.open(&rewrapped).await {
        Ok(opened) if opened.expose() == minted.0.expose() => {}
        Ok(_) => report.record(
            "rewrapping preserves the key",
            "the rewrapped key opens to different material, so every payload \
             sealed before the rotation is now unreadable — a rotation that is \
             really an outage",
        ),
        Err(e) => report.record("rewrapping preserves the key", format!("{e}")),
    }
}

/// Destroying a scope is the erasure, and doing it twice is the same erasure.
async fn erases(
    ring: &dyn KeyRing,
    scope: &str,
    minted: &(crate::keyring::DataKey, crate::keyring::WrappedKey),
    at: crate::core::Timestamp,
    report: &mut Report,
) {
    report.checked += 1;
    if let Err(e) = ring.destroy(scope, at, "conformance battery").await {
        report.record("destroy erases a scope", format!("{e}"));
        return;
    }

    report.checked += 1;
    match ring.open(&minted.1).await {
        Err(KeyError::Destroyed { .. }) => {}
        Err(e) => report.record(
            "an erased scope reports itself erased",
            format!(
                "opening after destruction failed with `{e}` rather than \
                 `Destroyed`. A caller cannot tell a completed erasure from an \
                 outage, and will either retry forever or report data loss"
            ),
        ),
        Ok(_) => report.record(
            "destroy erases a scope",
            "a wrapped key still opened after its scope was destroyed, so the \
             erasure reached nothing at all",
        ),
    }

    report.checked += 1;
    match ring.data_key(scope).await {
        Err(KeyError::Destroyed { .. }) => {}
        Err(e) => report.record(
            "an erased scope cannot be written to",
            format!("minting after destruction failed with `{e}` rather than `Destroyed`"),
        ),
        Ok(_) => report.record(
            "an erased scope cannot be recreated",
            "a destroyed scope minted a fresh key, so a late write lands in a \
             unit already reported as erased and the next erasure finds data \
             the last one said was gone",
        ),
    }

    report.checked += 1;
    if let Err(e) = ring.destroy(scope, at, "a retry").await {
        report.record(
            "erasure is idempotent",
            format!(
                "a second destruction failed with `{e}`. Erasure is retried — by \
                 an operator, by a sweep, by a queue — and a retry that errors \
                 makes a completed erasure look unfinished"
            ),
        );
    }
}
