//! The envelope a sealed payload travels in.
//!
//! Self-describing, so a restore needs nothing but the bytes and a ring that
//! can open the wrapping key:
//!
//! ```text
//! [u32 len][wrapped data key][24-byte nonce][ciphertext ‖ tag]
//! ```
//!
//! A fresh data key per payload, wrapped under the scope's key, is what a
//! key-management service actually does — and it makes the **wrapping key**
//! the erasure unit: destroying it makes every payload ever sealed under that
//! scope unopenable at once, wherever the copies ended up.

use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};

use super::{DataKey, KeyError, KeyRing, WrappedKey};

/// The nonce width `XChaCha20Poly1305` uses.
const NONCE: usize = 24;

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

    let mut envelope = Vec::with_capacity(4 + wrapped_bytes.len() + NONCE + sealed.len());
    envelope.extend_from_slice(&len.to_be_bytes());
    envelope.extend_from_slice(&wrapped_bytes);
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&sealed);
    Ok(envelope)
}

/// The scope the envelope's wrapped key claims, without opening anything.
///
/// For callers that must *reconstruct* the associated data an envelope was
/// sealed under — the drill's probe holds a case id but not the tenant — and
/// the claim is safe to read before verification because it is not taken on
/// trust: the ring will only unwrap the data key if the named scope's wrapping
/// key actually seals it, so a relabelled scope fails at `open` rather than
/// opening under the wrong identity.
pub(super) fn wrapped_scope(envelope: &[u8]) -> Option<String> {
    if envelope.len() < 4 {
        return None;
    }
    let (len_bytes, rest) = envelope.split_at(4);
    let len = u32::from_be_bytes(len_bytes.try_into().unwrap_or([0; 4])) as usize;
    let bytes = rest.get(..len)?;
    let wrapped: WrappedKey = serde_json::from_slice(bytes).ok()?;
    Some(wrapped.scope)
}

/// Open an envelope sealed by [`seal`], under the same `aad`.
///
/// # Errors
///
/// If the envelope is malformed, if the wrapping key is gone — which is what
/// erasure *is*, and it fails for every copy at once — or if the payload does
/// not authenticate under `aad`.
pub(super) async fn open(
    keys: &dyn KeyRing,
    aad: &[u8],
    envelope: &[u8],
) -> Result<Vec<u8>, KeyError> {
    if envelope.len() < 4 {
        return Err(KeyError::Refused("the envelope has no header".to_owned()));
    }
    let (len_bytes, rest) = envelope.split_at(4);
    let len = u32::from_be_bytes(len_bytes.try_into().unwrap_or([0; 4])) as usize;
    // `checked_add`, not `+`. The length is attacker-shaped — an envelope is
    // read back from a store, a backup, or a restored replica — and `len` can
    // be up to `u32::MAX`. A plain add is a debug panic and a release wrap on a
    // 32-bit target, and the wrap makes the bounds check *pass*, so `split_at`
    // below panics on the next line instead. A parser for untrusted bytes that
    // aborts the process is a denial of service, and this crate forbids unsafe
    // precisely so that failures stay recoverable.
    let needed = len
        .checked_add(NONCE)
        .filter(|needed| rest.len() >= *needed);
    if needed.is_none() {
        return Err(KeyError::Refused(
            "the envelope is shorter than its own header claims".to_owned(),
        ));
    }
    let (wrapped_bytes, rest) = rest.split_at(len);
    let wrapped: WrappedKey = serde_json::from_slice(wrapped_bytes)
        .map_err(|e| KeyError::Refused(format!("the wrapped key would not parse: {e}")))?;
    let (nonce, sealed) = rest.split_at(NONCE);

    let key = keys.open(&wrapped).await?;
    cipher(&key)
        .decrypt(
            nonce.into(),
            chacha20poly1305::aead::Payload { msg: sealed, aad },
        )
        .map_err(|_| KeyError::Refused("the sealed payload did not authenticate".to_owned()))
}
