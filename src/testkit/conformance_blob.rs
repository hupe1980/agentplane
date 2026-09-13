//! One contract, run against every blob store.
//!
//! A blob store is where an Article 17 request actually lands, and where the
//! bytes a hash chain committed to actually live. Both of those are properties
//! of the *implementation* rather than of the trait: the journal never held the
//! bytes, so nothing above this layer can settle whether an erasure ran or
//! whether what came back is what was written.
//!
//! Three of these questions are not obvious, and each was answered differently
//! by two shipped backends before this battery existed:
//!
//! * **an expired address stays expired.** Content addressing makes the address
//!   the content, so writing the same bytes again lands on the erased object.
//!   Both backends took the write, so an erasure reported as discharged was
//!   undone by the next run that produced the same bytes — under a tombstone
//!   that still said when and why it went.
//! * **a tombstone is read or refused, never guessed.** It is the only evidence
//!   an erasure happened that outlives the bytes it describes, so a reader that
//!   fills in a default answers `Expired` with a date it invented and a
//!   compliance drill counts a completed erasure nobody performed.
//! * **`get` verifies and `get_raw` does not.** The second exists for envelope
//!   encryption, where the stored bytes are deliberately not the address; a
//!   store that verified in both would make sealing impossible, and one that
//!   verified in neither would serve altered bytes to a caller holding a digest
//!   the chain signed.
//!
//! The battery writes and erases, so it needs a store it may leave marked.

use std::sync::Arc;

use crate::blob::{BlobError, BlobStore};
use crate::core::{Digest, Timestamp};

use super::conformance::Report;

/// Run the battery every blob store answers, whatever it sits on.
///
/// `label` distinguishes this run's bytes from another's, so two stores sharing
/// a backend — two tenants of one bucket — do not collide.
///
/// The **envelope pair** is deliberately not here: a sealing decorator refuses
/// `put_at` and `get_raw` on purpose, so requiring them of every implementation
/// would fail the one store whose refusal is the guarantee. Run
/// [`check_backing`] as well against a store something may seal *onto*.
pub async fn check(store: &Arc<dyn BlobStore>, label: &str, report: &mut Report) {
    let at = Timestamp::from_unix_timestamp(1_760_000_000).expect("a valid test instant");
    the_store_computes_the_address(store, label, report).await;
    a_read_verifies_what_it_returns(store, label, report).await;
    an_absent_blob_is_not_an_erased_one(store, label, at, report).await;
    an_erasure_stands(store, label, at, report).await;
}

/// The extra contract a store answers if something may seal onto it.
///
/// [`put_at`](BlobStore::put_at) and [`get_raw`](BlobStore::get_raw) are the
/// envelope pair: bytes deliberately stored at an address they do not hash to,
/// read back without the verification that would reject them. A store that
/// verified in both directions makes sealing impossible; one that refuses them
/// is a decorator rather than a backing store, and should not be given this.
pub async fn check_backing(store: &Arc<dyn BlobStore>, label: &str, report: &mut Report) {
    let at = Timestamp::from_unix_timestamp(1_760_000_000).expect("a valid test instant");
    the_envelope_pair_round_trips(store, label, report).await;
    a_sealed_write_cannot_undo_an_erasure(store, label, at, report).await;
}

/// One run's bytes, distinct from every other run's.
fn bytes(label: &str, what: &str) -> Vec<u8> {
    format!("agentplane/conformance/{label}/{what}").into_bytes()
}

/// The address is the content, and writing the same bytes twice is one write.
async fn the_store_computes_the_address(store: &Arc<dyn BlobStore>, label: &str, r: &mut Report) {
    r.checked += 1;
    let payload = bytes(label, "addressed");
    let digest = match store.put(&payload).await {
        Ok(d) => d,
        Err(e) => {
            r.record("put stores bytes", format!("put failed: {e}"));
            return;
        }
    };
    if digest != Digest::of(&payload) {
        r.record(
            "put returns the content digest",
            "the address a caller links erasure traversal to is not the one the bytes \
             were stored at, so nothing that follows the link can reach them",
        );
        return;
    }

    r.checked += 1;
    match store.put(&payload).await {
        Ok(again) if again == digest => {}
        Ok(_) => r.record(
            "the same bytes are the same write",
            "a second write of identical bytes answered a different address",
        ),
        Err(e) => r.record(
            "the same bytes are the same write",
            format!("re-writing identical bytes failed: {e}"),
        ),
    }

    r.checked += 1;
    match store.has(digest).await {
        Ok(true) => {}
        Ok(false) => r.record("has sees a stored blob", "has answered false after a put"),
        Err(e) => r.record("has sees a stored blob", format!("has failed: {e}")),
    }
}

/// `get` returns what was stored, unchanged.
async fn a_read_verifies_what_it_returns(store: &Arc<dyn BlobStore>, label: &str, r: &mut Report) {
    let payload = bytes(label, "verified");
    let Ok(digest) = store.put(&payload).await else {
        r.record("put stores bytes", "put failed before the read checks");
        return;
    };

    r.checked += 1;
    match store.get(digest).await {
        Ok(back) if back == payload => {}
        Ok(_) => r.record("get returns what was stored", "the bytes came back changed"),
        Err(e) => r.record("get returns what was stored", format!("get failed: {e}")),
    }
}

/// The envelope pair: stored at an address the bytes do not hash to, read back
/// without the verification that would reject them — and `get` still refusing
/// them, which is what keeps the pair from being a hole in the verification.
async fn the_envelope_pair_round_trips(store: &Arc<dyn BlobStore>, label: &str, r: &mut Report) {
    let envelope = bytes(label, "envelope");
    let address = Digest::of(&bytes(label, "plaintext"));
    r.checked += 1;
    if let Err(e) = store.put_at(address, &envelope).await {
        r.record("put_at stores at a foreign address", format!("{e}"));
        return;
    }
    r.checked += 1;
    match store.get_raw(address).await {
        Ok(back) if back == envelope => {}
        Ok(_) => r.record("get_raw does not verify", "the envelope came back changed"),
        Err(e) => r.record(
            "get_raw does not verify",
            format!("a raw read of an envelope failed, so sealing cannot work here: {e}"),
        ),
    }
    r.checked += 1;
    match store.get(address).await {
        Err(BlobError::Corrupt { .. }) => {}
        other => r.record(
            "get verifies before returning",
            format!(
                "bytes that do not hash to their address were not reported corrupt: {}",
                describe(&other)
            ),
        ),
    }
}

/// The tombstone rule's other half.
///
/// `put_at` is the write path a sealed deployment takes, so a refusal that
/// covers only `put` is the configuration that loses the guarantee.
async fn a_sealed_write_cannot_undo_an_erasure(
    store: &Arc<dyn BlobStore>,
    label: &str,
    at: Timestamp,
    r: &mut Report,
) {
    let payload = bytes(label, "sealed-erased");
    let Ok(digest) = store.put(&payload).await else {
        r.record("put stores bytes", "put failed before the erasure check");
        return;
    };
    if let Err(e) = store.expire(digest, at, "art-17 request").await {
        r.record("expire drops the bytes", format!("expire failed: {e}"));
        return;
    }
    r.checked += 1;
    match store.put_at(digest, &payload).await {
        Err(BlobError::Expired { .. }) => {}
        Ok(()) => r.record(
            "a sealed write cannot undo an erasure",
            "put_at over an erased address was accepted, so the data is back while the \
             tombstone still says when it went",
        ),
        Err(e) => r.record(
            "a sealed write cannot undo an erasure",
            format!("the write was refused, but not as an erasure: {e}"),
        ),
    }
}

/// Nothing here, and nothing was ever here, is a different answer from erased.
async fn an_absent_blob_is_not_an_erased_one(
    store: &Arc<dyn BlobStore>,
    label: &str,
    at: Timestamp,
    r: &mut Report,
) {
    let never = Digest::of(&bytes(label, "never-written"));
    r.checked += 1;
    match store.get(never).await {
        Err(BlobError::NotFound(_)) => {}
        other => r.record(
            "an unwritten address is not found",
            format!(
                "an address nothing was ever written to answered {}",
                describe(&other)
            ),
        ),
    }
    r.checked += 1;
    match store.has(never).await {
        Ok(false) => {}
        Ok(true) => r.record("has is false for an unwritten address", "has answered true"),
        Err(e) => r.record("has is false for an unwritten address", format!("{e}")),
    }

    // Erasing something that was never written is legitimate: `erase_case`
    // walks the digests a case *linked*, and a crash between the link and the
    // write leaves one of those with no bytes. The tombstone is still the
    // honest answer.
    r.checked += 1;
    let dangling = Digest::of(&bytes(label, "linked-never-stored"));
    match store
        .expire(dangling, at, "a linked digest with no bytes")
        .await
    {
        Ok(()) => match store.get(dangling).await {
            Err(BlobError::Expired { .. }) => {}
            other => r.record(
                "erasing an unwritten address leaves a tombstone",
                format!("it answered {} afterwards", describe(&other)),
            ),
        },
        Err(e) => r.record(
            "erasing an unwritten address is allowed",
            format!("expire refused a linked digest with no bytes: {e}"),
        ),
    }
}

/// The property the whole store exists to carry.
async fn an_erasure_stands(store: &Arc<dyn BlobStore>, label: &str, at: Timestamp, r: &mut Report) {
    let payload = bytes(label, "erased");
    let Ok(digest) = store.put(&payload).await else {
        r.record("put stores bytes", "put failed before the erasure checks");
        return;
    };
    if let Err(e) = store.expire(digest, at, "art-17 request").await {
        r.record("expire drops the bytes", format!("expire failed: {e}"));
        return;
    }

    r.checked += 1;
    match store.get(digest).await {
        Err(BlobError::Expired {
            at: when, reason, ..
        }) => {
            if when != at.unix_timestamp() {
                r.record(
                    "a tombstone keeps the instant it was written with",
                    format!("expired at {when}, not {}", at.unix_timestamp()),
                );
            }
            if reason != "art-17 request" {
                r.record(
                    "a tombstone keeps the reason it was written with",
                    format!("the reason came back as {reason:?}"),
                );
            }
        }
        other => r.record(
            "an erased blob reads as expired",
            format!(
                "erasure and loss are different facts and only one is an incident; \
                 this answered {}",
                describe(&other)
            ),
        ),
    }

    r.checked += 1;
    match store.has(digest).await {
        Ok(false) => {}
        Ok(true) => r.record("has is false after an erasure", "the bytes are still there"),
        Err(e) => r.record("has is false after an erasure", format!("{e}")),
    }

    // Expiring twice keeps the first tombstone: a retry must not rewrite when
    // or why the data went.
    r.checked += 1;
    let later = Timestamp::from_unix_timestamp(1_790_000_000).expect("a later instant");
    match store.expire(digest, later, "a retry").await {
        Ok(()) => match store.get(digest).await {
            Err(BlobError::Expired { at: when, .. }) if when == at.unix_timestamp() => {}
            Err(BlobError::Expired { at: when, .. }) => r.record(
                "the first tombstone stands",
                format!("a repeated erasure moved the date to {when}"),
            ),
            other => r.record(
                "the first tombstone stands",
                format!("a repeated erasure answered {}", describe(&other)),
            ),
        },
        Err(e) => r.record("expiring twice is the same expiry", format!("{e}")),
    }

    // **An expired address stays expired.** The same bytes hash to the same
    // address, so an unguarded write puts the data back under a tombstone that
    // still claims it went.
    r.checked += 1;
    match store.put(&payload).await {
        Err(BlobError::Expired { .. }) => {}
        Ok(_) => r.record(
            "a write cannot undo an erasure",
            "re-writing the erased bytes was accepted, so the data is back while the \
             tombstone still says when it went — an erasure reported as discharged and \
             then silently reversed",
        ),
        Err(e) => r.record(
            "a write cannot undo an erasure",
            format!("the write was refused, but not as an erasure: {e}"),
        ),
    }
    r.checked += 1;
    match store.get(digest).await {
        Err(BlobError::Expired { .. }) => {}
        other => r.record(
            "the erasure survives the attempt to undo it",
            format!("after the refused writes it answered {}", describe(&other)),
        ),
    }
}

/// A short name for whatever a read answered, for a violation message.
fn describe(outcome: &Result<Vec<u8>, BlobError>) -> String {
    match outcome {
        Ok(bytes) => format!("{} byte(s) of content", bytes.len()),
        Err(e) => e.to_string(),
    }
}
