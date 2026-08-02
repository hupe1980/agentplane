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
use agentplane::core::Digest;

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
