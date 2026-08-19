//! Proving the **body** of a delivery, rather than the sender's token.
//!
//! # What a bearer header does not say
//!
//! [`PushAuthentication`](super::PushAuthentication) produces `Authorization:
//! <scheme> <credentials>`, and what a receiver learns from it is that whoever
//! opened the connection held a token. It says nothing about the bytes that
//! followed. That gap is not theoretical in a deployment: the token transits
//! every hop between here and the receiver — a TLS-terminating ingress, a mesh
//! sidecar, a proxy that logs headers — and each of those hops handles the body
//! afterwards. A receiver checking only the header cannot tell the event this
//! plane wrote from the same event with a field edited in transit, and it cannot
//! tell either from an event minted by anything that ever read the token.
//!
//! A body signature is a different claim, and a narrower one.
//!
//! # [Standard Webhooks], rather than a house convention
//!
//! Three headers ride with every delivery this plane signs:
//!
//! * `webhook-id` — the message's own identity, stable across retries. It is
//!   the receiver's idempotency key, and it is sent whether or not a
//!   destination is signed, because at-least-once delivery makes duplicates
//!   ordinary rather than exceptional.
//! * `webhook-timestamp` — Unix seconds, the instant *this attempt* was made.
//! * `webhook-signature` — `v1,<base64>` of `HMAC-SHA256(key, "{id}.{timestamp}.{body}")`.
//!
//! The id and the timestamp are inside the signed content, which is the point
//! of the construction: a signature over the body alone is replayable forever,
//! because a captured POST stays a genuine body genuinely signed. With both
//! bound in, a receiver that refuses timestamps outside a tolerance window and
//! deduplicates on `webhook-id` has a delivery that expires. Neither half works
//! alone — the window bounds how long a replay is useful, the id stops it
//! inside the window.
//!
//! Choosing the published spelling over a house one is what lets a receiver
//! verify with a library it did not write. The alternative shape — `sha256=`
//! hex over the bare body, the convention several vendors ship — is a signature
//! this plane could produce and no off-the-shelf verifier could check against a
//! replay.
//!
//! # What it still does not prove
//!
//! * **Who.** The key is symmetric and shared, so it proves the writer was *a*
//!   holder of it — this plane, the receiver itself, or anything holding the
//!   configuration. It is not a signature in the public-key sense and cannot be
//!   shown to a third party as evidence of origin.
//!
//! * **Confidentiality.** The body still travels in whatever the URL's scheme
//!   provides. Signing a plaintext delivery makes it unforgeable, not private.
//!
//! * **That a destination was signed at all.** A receiver must *require* the
//!   header. A missing signature is only a refusal if the receiver refuses it;
//!   a receiver that verifies when the header is present and accepts when it is
//!   absent has bought nothing, because an attacker simply omits it.
//!
//! # One algorithm, and no enum to say so
//!
//! `HMAC-SHA256` under the `v1` label. There is deliberately no algorithm enum
//! with one variant and no `X-…-Algorithm` header: both would be declarations
//! that decide nothing today, and the wire format already carries the label. A
//! second algorithm arrives as a second label a receiver can dispatch on, which
//! is exactly what the label is for — the spec's own `v1a` (Ed25519) is that
//! door.
//!
//! [Standard Webhooks]: https://www.standardwebhooks.com/

use base64::Engine as _;
use hmac::{KeyInit, Mac, SimpleHmac};
use sha2::Sha256;

use crate::core::Secret;

/// The message's own identity, and the receiver's idempotency key.
pub const HEADER_ID: &str = "webhook-id";
/// Unix seconds at which this attempt was made.
pub const HEADER_TIMESTAMP: &str = "webhook-timestamp";
/// `v1,<base64>` over `{id}.{timestamp}.{body}`.
pub const HEADER_SIGNATURE: &str = "webhook-signature";

/// The prefix Standard Webhooks gives a base64-encoded symmetric key.
const SYMMETRIC_KEY_PREFIX: &str = "whsec_";

/// The shortest key this accepts, in bytes.
///
/// The spec's range is 24–64 bytes. The floor is enforced and the ceiling is
/// not: a key shorter than this is a MAC an attacker can search, while a longer
/// one is only wasteful — HMAC hashes a key past the block size, which is a
/// documented branch and not a weakness.
const MIN_KEY_BYTES: usize = 24;

/// RFC 2104 over SHA-256, as `hmac` implements it.
///
/// A key longer than the block is replaced by its own hash and a shorter one is
/// zero-padded — handled by the crate, and the branch a hand-written HMAC most
/// often omits, whereupon every long key silently produces a MAC no other
/// implementation agrees with.
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    // `SimpleHmac` rather than `Hmac`: the latter needs `Sha256: EagerHash`,
    // and nothing here benefits from the specialised path — this runs once per
    // delivery, not per byte of a stream.
    let mut mac = <SimpleHmac<Sha256> as KeyInit>::new_from_slice(key)
        .expect("HMAC accepts a key of any length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// A shared signing key.
///
/// Constructed through [`Destination::signed_with`](super::Destination::signed_with)
/// in the ordinary case. The key is held as raw bytes rather than as the
/// configured string, because a `whsec_`-prefixed secret names base64 of the
/// key and not the key — signing the prefixed text would produce a MAC that
/// every conformant verifier rejects, and the failure would surface only as a
/// receiver refusing everything.
#[derive(Clone)]
pub struct BodySigning {
    key: Vec<u8>,
}

impl std::fmt::Debug for BodySigning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BodySigning")
            .field("key", &"<redacted>")
            .finish()
    }
}

impl Drop for BodySigning {
    fn drop(&mut self) {
        self.key.iter_mut().for_each(|byte| *byte = 0);
    }
}

impl BodySigning {
    /// Sign with `secret`.
    ///
    /// A secret spelled `whsec_<base64>` — Standard Webhooks' own form, and
    /// what a receiver's library will be handed — is decoded, so both ends use
    /// the same bytes. Any other string is the key itself.
    ///
    /// # Panics
    ///
    /// If the key is shorter than 24 bytes, or a `whsec_` secret is not
    /// base64. Both are configuration this deployment wrote about itself, and
    /// both would otherwise fail at the far end of a run: a short MAC key is a
    /// signature that can be searched, and a check that can be defeated reads
    /// exactly like one that means something.
    #[must_use]
    pub fn new(secret: &Secret) -> Self {
        let raw = secret.expose();
        let key = raw.strip_prefix(SYMMETRIC_KEY_PREFIX).map_or_else(
            || raw.as_bytes().to_vec(),
            |encoded| {
                base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .unwrap_or_else(|_| {
                        panic!(
                            "a push signing secret beginning '{SYMMETRIC_KEY_PREFIX}' names \
                             base64 of the key, and this one does not decode — every \
                             delivery would carry a MAC the receiver's library rejects"
                        )
                    })
            },
        );
        assert!(
            key.len() >= MIN_KEY_BYTES,
            "a push signing key of {} bytes is shorter than the {MIN_KEY_BYTES} \
             Standard Webhooks requires: a MAC key an attacker can search is a \
             check that reads exactly like one that means something",
            key.len()
        );
        Self { key }
    }

    /// The `webhook-signature` value for one delivery.
    ///
    /// `id` and `at` are inside the signed content, not merely beside it — a
    /// receiver that compares them against the headers is what makes a captured
    /// POST expire.
    pub(super) fn value_for(&self, id: &str, at: u64, body: &[u8]) -> String {
        let mut content = Vec::with_capacity(id.len() + 24 + body.len());
        content.extend_from_slice(id.as_bytes());
        content.push(b'.');
        content.extend_from_slice(at.to_string().as_bytes());
        content.push(b'.');
        content.extend_from_slice(body);
        let mac = hmac_sha256(&self.key, &content);
        format!(
            "v1,{}",
            base64::engine::general_purpose::STANDARD.encode(mac)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signing(secret: &str) -> BodySigning {
        BodySigning::new(&Secret::new(secret))
    }

    /// RFC 4231's published vectors, which is the outside authority the
    /// construction has. Case 1 is the ordinary path, case 2 a short text key,
    /// and case 6 the longer-than-block-size key that exercises the
    /// hash-the-key branch.
    #[test]
    fn the_construction_matches_rfc_4231() {
        assert_eq!(
            hex::encode(hmac_sha256(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            "RFC 4231 test case 1"
        );
        assert_eq!(
            hex::encode(hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            "RFC 4231 test case 2"
        );
        assert_eq!(
            hex::encode(hmac_sha256(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            "RFC 4231 test case 6: a key longer than the block must be hashed first"
        );
    }

    /// Standard Webhooks' own published example, which is what makes this
    /// interoperable rather than merely self-consistent: a receiver using any
    /// of the spec's libraries computes this value.
    #[test]
    fn the_signature_matches_the_standard_webhooks_example() {
        let signing = signing("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");
        assert_eq!(
            signing.value_for(
                "msg_p5jXN8AQM9LWM0D4loKWxJek",
                1_614_265_330,
                b"{\"test\": 2432232314}"
            ),
            "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=",
            "the spec's example verifies with every Standard Webhooks library, and \
             a value of our own verifies with none of them"
        );
    }

    /// Every input to the MAC changes it, including the two that make a
    /// captured delivery expire.
    #[test]
    fn the_signature_follows_the_body_the_id_and_the_instant() {
        let signing = signing("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");
        let value = signing.value_for("msg-1", 1_700_000_000, br#"{"a":1}"#);
        assert!(
            value.starts_with("v1,"),
            "the version label is how a receiver dispatches: {value}"
        );
        assert_ne!(
            value,
            signing.value_for("msg-1", 1_700_000_000, br#"{"a":2}"#),
            "one byte of the body changed and the signature did not"
        );
        assert_ne!(
            value,
            signing.value_for("msg-2", 1_700_000_000, br#"{"a":1}"#),
            "the id is not covered, so a replay under another id verifies"
        );
        assert_ne!(
            value,
            signing.value_for("msg-1", 1_700_000_001, br#"{"a":1}"#),
            "the instant is not covered, so a captured delivery never expires"
        );
        assert_ne!(
            value,
            BodySigning::new(&Secret::new(
                "whsec_bm90LXRoZS1zYW1lLWtleS1hdC1hbGwtaGVyZQ=="
            ))
            .value_for("msg-1", 1_700_000_000, br#"{"a":1}"#),
            "a different key produced the same signature"
        );
    }

    /// The key must not print itself.
    #[test]
    fn a_signing_key_is_redacted() {
        let signing = signing("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");
        let shown = format!("{signing:#?}");
        assert!(!shown.contains("MfKQ"), "{shown}");
    }

    #[test]
    #[should_panic(expected = "shorter than the 24")]
    fn a_short_signing_key_is_refused_at_configuration() {
        let _ = signing("too-short");
    }

    #[test]
    #[should_panic(expected = "does not decode")]
    fn a_whsec_secret_that_is_not_base64_is_refused_at_configuration() {
        let _ = signing("whsec_not base64 at all !!!");
    }
}
