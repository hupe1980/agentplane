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
//! * a wrapped key **names the version that sealed it**, because sealed bytes
//!   are rotation-immutable and that name is the only record of which key
//!   version the deployment must keep admitting;
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
    names_its_version(scope, &minted, &mut report);
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

/// A wrap carries the erasure unit and the key version that sealed it.
///
/// Both halves are load-bearing and neither is checkable by opening a key,
/// which is why they are asked separately. The scope is what an erasure
/// request destroys, so a wrap that named a different one would be sealed by a
/// key no erasure of its data reaches. The version is what a deployment must
/// keep its key service admitting: sealed bytes are rotation-immutable, so
/// this string is the *only* record of which key version this envelope will
/// need for as long as it is retained, and a ring that left it empty leaves an
/// operator raising a version floor with nothing to check it against.
fn names_its_version(
    scope: &str,
    minted: &(crate::keyring::DataKey, crate::keyring::WrappedKey),
    report: &mut Report,
) {
    report.checked += 1;
    if minted.1.scope != scope {
        report.record(
            "a wrap names its erasure unit",
            format!(
                "the wrap claims scope '{}' but was minted for '{scope}', so \
                 erasing '{scope}' would destroy a key that does not reach the \
                 data this wrap seals — and report success",
                minted.1.scope
            ),
        );
    }

    report.checked += 1;
    if minted.1.wrapped_by.is_empty() {
        report.record(
            "a wrap names the key version that sealed it",
            "the wrap names no wrapping key. Sealed bytes are never re-wrapped, \
             so this field is the only surviving record of which key version \
             must stay decryptable for this payload to be readable; without it \
             a retired version is indistinguishable from data loss",
        );
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
