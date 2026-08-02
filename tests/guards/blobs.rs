//! Content-addressed storage, and the property that makes it safe to keep bytes
//! outside the hash chain.
//!
//! The journal refuses an oversized record; blobs are where those bytes go. That
//! only preserves tamper-evidence if a swapped blob is *detected*, so that is
//! what these check — against every backend, because a verification implemented
//! in one and forgotten in another is the failure the seam exists to prevent.

#![cfg(feature = "redb")]

use std::sync::Arc;

use agentplane::blob::{BlobError, BlobStore, MemoryBlobs};
use agentplane::core::{Digest, Timestamp};

fn ts(secs: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(secs).expect("representable")
}

fn stores() -> Vec<(&'static str, Arc<dyn BlobStore>)> {
    // `mut` only when a second backend exists to push. Without the annotation
    // this is an unused-mut error in every build that does not enable
    // `opendal` — which `--all-features` can never show you.
    #[cfg_attr(not(feature = "opendal"), allow(unused_mut))]
    let mut out: Vec<(&'static str, Arc<dyn BlobStore>)> =
        vec![("memory", Arc::new(MemoryBlobs::new()))];

    #[cfg(feature = "opendal")]
    {
        use agentplane::blob::OpenDalBlobs;
        let dir = std::env::temp_dir().join(format!("agentplane-blobs-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let op =
            opendal::Operator::new(opendal::services::Fs::default().root(&dir.to_string_lossy()))
                .expect("fs operator");
        out.push(("opendal-fs", Arc::new(OpenDalBlobs::new(op, "blobs"))));
    }
    out
}

#[tokio::test]
async fn bytes_come_back_from_the_address_they_went_to() {
    for (name, store) in stores() {
        let digest = store.put(b"printer on fire").await.expect("put");
        let back = store.get(digest).await.expect("get");
        assert_eq!(back, b"printer on fire", "{name} returned other bytes");
        assert!(
            store.has(digest).await.expect("has"),
            "{name} lost the blob"
        );
    }
}

/// The address is the content, so writing twice is writing once.
///
/// This is what makes a blob write safe to retry after an unknown outcome — the
/// disposition every effect in this crate has to reason about. A store that
/// allocated a fresh location per write would turn a retry into a leak.
#[tokio::test]
async fn the_same_bytes_land_at_the_same_address() {
    for (name, store) in stores() {
        let a = store.put(b"same").await.expect("put");
        let b = store.put(b"same").await.expect("put again");
        assert_eq!(a, b, "{name} gave one payload two addresses");
    }
    let mem = MemoryBlobs::new();
    mem.put(b"same").await.expect("put");
    mem.put(b"same").await.expect("put again");
    assert_eq!(
        mem.len(),
        1,
        "a second identical write stored a second copy"
    );
}

/// A blob the caller never wrote is absent, not empty.
#[tokio::test]
async fn a_missing_blob_is_not_silently_empty() {
    for (name, store) in stores() {
        match store.get(Digest::of(b"never written")).await {
            Err(BlobError::NotFound(_)) => {}
            Err(other) => panic!("{name} reported the wrong error: {other}"),
            Ok(bytes) => panic!("{name} invented {} bytes", bytes.len()),
        }
    }
}

/// Altered bytes are refused, not returned.
///
/// The point of keeping the digest in the chain rather than the payload: the
/// journal still commits to exactly these bytes, so storage is the least
/// trusted component and is treated that way. If this check were missing, a
/// blob could be edited by anyone with filesystem access and every later read
/// would hand the altered content to a caller that believed the chain vouched
/// for it.
#[tokio::test]
async fn altered_bytes_are_detected_rather_than_served() {
    let store = MemoryBlobs::new();
    let digest = store.put("€4,200 refund".as_bytes()).await.expect("put");

    store.tamper_for_test(digest, "$42,000 refund".as_bytes().to_vec());

    match store.get(digest).await {
        Err(BlobError::Corrupt { expected, actual }) => {
            assert_eq!(expected, digest.to_hex());
            assert_ne!(actual, expected, "a corrupt read must name what it found");
        }
        Err(other) => panic!("tampering was reported as something else: {other}"),
        Ok(bytes) => panic!(
            "altered bytes were served as authentic: {}",
            String::from_utf8_lossy(&bytes)
        ),
    }
}

/// **Erasure and loss are different answers, and the store must tell them apart.**
///
/// This is what makes retention possible at all. An Article 17 request removes
/// the bytes; an Article 12 obligation still requires proof of what happened.
/// Both hold *because* the chain committed to a digest rather than to content —
/// but only if a reader arriving afterwards can distinguish "deliberately
/// expired on this date, for this reason" from "gone, cause unknown". Collapse
/// the two and every erasure looks like data loss six months later.
#[tokio::test]
async fn an_expired_blob_is_not_reported_as_missing() {
    for (name, store) in stores() {
        let digest = store.put("personal data".as_bytes()).await.expect("put");
        store
            .expire(digest, ts(1_700_000_000), "art-17 erasure request")
            .await
            .expect("expire");

        match store.get(digest).await {
            Err(BlobError::Expired { at, reason, .. }) => {
                assert_eq!(at, 1_700_000_000, "{name} lost when the data went");
                assert!(
                    reason.contains("art-17"),
                    "{name} lost why the data went: {reason}"
                );
            }
            Err(BlobError::NotFound(_)) => panic!(
                "{name} reports a deliberate erasure as a missing blob — an \
                 operator cannot tell retention from data loss"
            ),
            Err(other) => panic!("{name}: wrong error: {other}"),
            Ok(b) => panic!("{name} served {} bytes that were erased", b.len()),
        }
    }
}

/// A blob nobody ever wrote is still simply absent.
///
/// Stated separately because the fix for the check above — returning `Expired`
/// for anything unreadable — would pass it while making the distinction
/// meaningless in the other direction.
#[tokio::test]
async fn a_blob_that_never_existed_is_still_not_found() {
    for (name, store) in stores() {
        match store.get(Digest::of(b"never written at all")).await {
            Err(BlobError::NotFound(_)) => {}
            Err(other) => panic!("{name}: wrong error for an absent blob: {other}"),
            Ok(_) => panic!("{name} invented a blob"),
        }
    }
}

/// Expiring twice does not rewrite when the data went.
///
/// The same rule as a repeated stop request: the first record of an
/// intervention is the one on the record, or "when was this erased?" has a
/// wrong answer that looks authoritative.
#[tokio::test]
async fn a_repeated_expiry_keeps_the_first_tombstone() {
    for (name, store) in stores() {
        let digest = store.put("twice".as_bytes()).await.expect("put");
        store
            .expire(digest, ts(1_000), "first")
            .await
            .expect("expire");
        store
            .expire(digest, ts(9_999), "second")
            .await
            .expect("again");

        match store.get(digest).await {
            Err(BlobError::Expired { at, reason, .. }) => {
                assert_eq!(at, 1_000, "{name} let a retry rewrite the erasure date");
                assert_eq!(reason, "first", "{name} let a retry rewrite the reason");
            }
            other => panic!("{name}: expected an expired blob, got {other:?}"),
        }
    }
}
