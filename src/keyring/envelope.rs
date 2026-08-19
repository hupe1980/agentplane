//! The envelope a sealed payload travels in.
//!
//! Self-describing, so a restore needs nothing but the bytes and a ring that
//! can open the wrapping key:
//!
//! ```text
//! [u8 version][u32 len][wrapped data key][24-byte nonce][ciphertext ‖ tag]
//! ```
//!
//! A fresh data key per payload, wrapped under the scope's key, is what a
//! key-management service actually does — and it makes the **wrapping key**
//! the erasure unit: destroying it makes every payload ever sealed under that
//! scope unopenable at once, wherever the copies ended up.
//!
//! # The version byte names the whole construction
//!
//! One number, not a layout version beside a cipher identifier. Version 1 *is*
//! "u32-length-prefixed canonical [`WrappedKey`], 24-byte nonce,
//! `XChaCha20Poly1305` over the caller's associated data" — so changing the
//! AEAD is a new version, because it changes what the bytes mean and a reader
//! that guessed between two suites would be an oracle rather than a parser.
//! Two numbers would be two spellings of one decision, free to disagree.
//!
//! Sealed bytes are rotation-immutable (see the module documentation), so an
//! envelope is read by builds written after it for as long as it is retained.
//! That is the whole reason the byte is there: without it, a build that does
//! not know the construction reaches the AEAD anyway and reports *this payload
//! did not authenticate* — the sentence that pages somebody to look for
//! tampering, for a version skew whose remedy is running a different build.

use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};

use super::{DataKey, KeyError, KeyRing, WrappedKey};

/// The envelope construction this build writes and reads.
///
/// `0` is never written, so it stays available as the answer to *these bytes
/// are not an envelope at all*.
pub(super) const FORMAT_VERSION: u8 = 1;

/// The nonce width `XChaCha20Poly1305` uses.
const NONCE: usize = 24;

/// Version byte plus the wrapped key's length prefix.
const HEADER: usize = 1 + 4;

fn cipher(key: &DataKey) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(key.expose().into())
}

/// Seal `plaintext` under `scope`, bound to `aad`.
///
/// The associated data is what stops a sealed payload from being *moved*: an
/// envelope lifted into another run's history fails to authenticate rather
/// than opening as somebody else's data.
///
/// # Errors
///
/// If the ring cannot mint a data key, or the payload will not seal.
pub(super) async fn seal(
    keys: &dyn KeyRing,
    scope: &str,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, KeyError> {
    let (key, wrapped) = keys.data_key(scope).await?;
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let sealed = cipher(&key)
        .encrypt(
            &nonce,
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| KeyError::Refused(format!("sealing a payload failed: {e}")))?;

    // Canonical bytes, not plain serialisation: this crate enables
    // `preserve_order` transitively, so a wrapped key written by field order
    // would depend on declaration order.
    let wrapped_bytes = crate::core::canon::to_bytes(&wrapped)
        .map_err(|e| KeyError::Refused(format!("a wrapped key would not serialise: {e}")))?;
    let len = u32::try_from(wrapped_bytes.len())
        .map_err(|_| KeyError::Refused("the wrapped key is implausibly large".to_owned()))?;

    let mut envelope = Vec::with_capacity(HEADER + wrapped_bytes.len() + NONCE + sealed.len());
    envelope.push(FORMAT_VERSION);
    envelope.extend_from_slice(&len.to_be_bytes());
    envelope.extend_from_slice(&wrapped_bytes);
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&sealed);
    Ok(envelope)
}

/// An envelope's header, split from the bytes it describes.
struct Parsed<'a> {
    wrapped: WrappedKey,
    nonce: &'a [u8],
    sealed: &'a [u8],
}

/// Split an envelope into its parts, or say precisely why it is not one.
///
/// One parser, because a second reader of the same layout is free to disagree
/// with this one about where the ciphertext starts, and the disagreement
/// surfaces as a payload that does not authenticate — indistinguishable from
/// tampering.
fn parse(envelope: &[u8]) -> Result<Parsed<'_>, KeyError> {
    let Some((&version, rest)) = envelope.split_first() else {
        return Err(KeyError::Refused("the envelope is empty".to_owned()));
    };
    if version != FORMAT_VERSION {
        return Err(KeyError::UnknownFormat {
            version,
            supported: FORMAT_VERSION,
        });
    }
    if rest.len() < 4 {
        return Err(KeyError::Refused("the envelope has no header".to_owned()));
    }
    let (len_bytes, rest) = rest.split_at(4);
    let len = u32::from_be_bytes(len_bytes.try_into().unwrap_or([0; 4])) as usize;
    // `checked_add`, not `+`. The length is attacker-shaped — an envelope is
    // read back from a store, a backup, or a restored replica — and `len` can
    // be up to `u32::MAX`. A plain add is a debug panic and a release wrap on a
    // 32-bit target, and the wrap makes the bounds check *pass*, so `split_at`
    // below panics on the next line instead. A parser for untrusted bytes that
    // aborts the process is a denial of service, and this crate forbids unsafe
    // precisely so that failures stay recoverable.
    let fits = len
        .checked_add(NONCE)
        .is_some_and(|needed| rest.len() >= needed);
    if !fits {
        return Err(KeyError::Refused(
            "the envelope is shorter than its own header claims".to_owned(),
        ));
    }
    let (wrapped_bytes, rest) = rest.split_at(len);
    let wrapped: WrappedKey = serde_json::from_slice(wrapped_bytes)
        .map_err(|e| KeyError::Refused(format!("the wrapped key would not parse: {e}")))?;
    let (nonce, sealed) = rest.split_at(NONCE);
    Ok(Parsed {
        wrapped,
        nonce,
        sealed,
    })
}

/// The scope the envelope's wrapped key claims, without opening anything.
///
/// For callers that must *reconstruct* the associated data an envelope was
/// sealed under — the drill's probe holds a case id but not the tenant — and
/// the claim is safe to read before verification because it is not taken on
/// trust: the ring will only unwrap the data key if the named scope's wrapping
/// key actually seals it, so a relabelled scope fails at `open` rather than
/// opening under the wrong identity.
///
/// # Errors
///
/// The same refusals [`open`] gives for a header it cannot read. A `Result`
/// rather than an `Option` because the caller has already established that
/// these bytes claim to be sealed: past that point *no scope* is not an
/// ordinary answer, and returning one lets a probe report nothing about state
/// it exists to check.
pub(super) fn wrapped_scope(envelope: &[u8]) -> Result<String, KeyError> {
    parse(envelope).map(|parsed| parsed.wrapped.scope)
}

/// Open an envelope sealed by [`seal`], under the same `aad`.
///
/// # Errors
///
/// If the envelope is malformed, if it names a format version this build does
/// not read, if the wrapping key is gone — which is what erasure *is*, and it
/// fails for every copy at once — or if the payload does not authenticate
/// under `aad`.
pub(super) async fn open(
    keys: &dyn KeyRing,
    aad: &[u8],
    envelope: &[u8],
) -> Result<Vec<u8>, KeyError> {
    let Parsed {
        wrapped,
        nonce,
        sealed,
    } = parse(envelope)?;
    let key = keys.open(&wrapped).await?;
    cipher(&key)
        .decrypt(
            nonce.into(),
            chacha20poly1305::aead::Payload { msg: sealed, aad },
        )
        .map_err(|_| KeyError::Refused("the sealed payload did not authenticate".to_owned()))
}

#[cfg(all(test, feature = "testkit"))]
mod format_tests {
    use super::*;
    use crate::testkit::MemoryKeyRing;

    const AAD: &[u8] = b"case-state:acme:matter";

    async fn envelope() -> (MemoryKeyRing, Vec<u8>) {
        let ring = MemoryKeyRing::new();
        let bytes = seal(&ring, "acme/matter", AAD, b"the plaintext")
            .await
            .expect("seal");
        (ring, bytes)
    }

    /// The byte is written, and it is the one this build claims to write.
    ///
    /// Asserted on the *stored* bytes rather than through a round trip,
    /// because a round trip passes whatever pair of constants `seal` and
    /// `parse` happen to share — including no version byte at all.
    #[tokio::test]
    async fn an_envelope_leads_with_the_format_version_it_claims() {
        let (_ring, bytes) = envelope().await;
        assert_eq!(
            bytes.first().copied(),
            Some(FORMAT_VERSION),
            "the first byte of an envelope is the construction it was written to"
        );
        assert_eq!(
            FORMAT_VERSION,
            crate::keyring::ENVELOPE_FORMAT_VERSION,
            "the public constant and the byte on the wire are one number"
        );
    }

    /// A version this build does not read is its own answer, not tampering.
    ///
    /// The whole point of the byte. Without it the bumped envelope reaches the
    /// AEAD with a wrapped key parsed out of the wrong offsets and comes back
    /// as *did not authenticate* — the sentence a drill reports as loss or
    /// tampering, sending somebody to hunt a fault that does not exist while
    /// the cause is which build is running. So this asserts the classification
    /// and, separately, that the refusal is **not** the tampering one.
    #[tokio::test]
    async fn a_version_this_build_does_not_read_is_not_reported_as_tampering() {
        let (ring, mut bytes) = envelope().await;
        bytes[0] = FORMAT_VERSION.wrapping_add(1);

        let error = open(&ring, AAD, &bytes).await.expect_err("must refuse");
        assert_eq!(
            error,
            KeyError::UnknownFormat {
                version: FORMAT_VERSION.wrapping_add(1),
                supported: FORMAT_VERSION,
            },
            "a future envelope must name the version it needs"
        );
        assert!(
            !error.to_string().contains("authenticate"),
            "a version skew reported in the vocabulary of tampering: {error}"
        );

        assert_eq!(
            wrapped_scope(&bytes),
            Err(KeyError::UnknownFormat {
                version: FORMAT_VERSION.wrapping_add(1),
                supported: FORMAT_VERSION,
            }),
            "reading the scope must refuse the same envelope `open` refuses, or a \
             probe reconstructs an AAD from a header it could not parse"
        );
    }

    /// Damage inside the header is a refusal, and refusal is where it belongs:
    /// a truncated envelope is not a version skew and has no benign remedy.
    #[tokio::test]
    async fn a_truncated_envelope_is_refused_rather_than_read_short() {
        let (ring, bytes) = envelope().await;
        for cut in [0, 1, HEADER, HEADER + 4] {
            let short = &bytes[..cut.min(bytes.len())];
            let error = open(&ring, AAD, short).await.expect_err("must refuse");
            assert!(
                matches!(error, KeyError::Refused(_)),
                "a truncated envelope of {cut} bytes answered {error:?}"
            );
        }
    }

    /// The positive half: the construction round-trips under its own AAD.
    #[tokio::test]
    async fn an_envelope_opens_under_the_identity_that_sealed_it() {
        let (ring, bytes) = envelope().await;
        assert_eq!(
            open(&ring, AAD, &bytes).await.expect("opens"),
            b"the plaintext",
        );
        assert_eq!(
            wrapped_scope(&bytes).expect("scope"),
            "acme/matter",
            "the scope is readable without opening anything"
        );
    }
}
