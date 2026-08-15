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
//! # What the signature proves
//!
//! `HMAC-SHA256(secret, body)` over the **exact bytes posted**, sent as
//! `sha256=<lowercase hex>`. A receiver that recomputes it and finds a match
//! learns exactly one thing: *this byte string was written by a holder of the
//! shared secret, and reached me unaltered and untruncated*. That is the claim
//! embedders' other outbound webhooks make, and the reason it is worth having
//! beside the bearer token rather than instead of it — the token authenticates
//! the connection, this authenticates the payload.
//!
//! # What it does not prove, stated precisely
//!
//! * **Freshness.** There is no timestamp and no nonce in the signature's
//!   input, so a delivery captured off the wire (or replayed by any hop that
//!   holds a copy) can be posted again in an hour or in a year, and every check
//!   still passes — it is a genuine body, genuinely signed. Nothing here
//!   expires, and a receiver that treats "signature valid" as "this just
//!   happened" is wrong. The only thing that closes replay is the receiver
//!   deduplicating on the **delivery's own identity**, which the signature
//!   cannot supply.
//!
//!   Whether the payload *carries* such an identity is a property of the
//!   [`Projection`](super::Projection), not of this module, so it is worth
//!   saying which is true here:
//!   [`RunCompleted`](super::RunCompleted) carries `source` plus `id` — the run
//!   id — which is `CloudEvents`' uniqueness pair, so its deliveries **can** be
//!   deduplicated, and already must be: at-least-once delivery repeats events
//!   on an ordinary crash, so a receiver that cannot tell a duplicate from a
//!   second event is broken before any attacker turns up. A projection an
//!   embedder writes carries whatever that embedder put in it; one whose
//!   payloads hold nothing unique leaves a receiver with nothing to dedup on,
//!   and a signature does not fill that hole.
//!
//! * **Who.** The secret is symmetric and shared, so it proves the writer was
//!   *a* holder of it — this plane, the receiver itself, or anything holding
//!   the configuration. It is not a signature in the public-key sense and
//!   cannot be shown to a third party as evidence of origin.
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
//! HMAC-SHA256, prefixed `sha256=` — the GitHub and Stripe convention, which is
//! what receivers in the wild are already written against. There is deliberately
//! no algorithm enum with one variant and no `X-…-Algorithm` header: both would
//! be declarations that decide nothing today, and the wire format already
//! carries the label. A second algorithm arrives as a second prefix a receiver
//! can dispatch on, which is exactly what the prefix is for.
//!
//! # Why the construction is written out here
//!
//! There is no `hmac` crate in this tree, and `sha2` — which is here
//! unconditionally, hashing every journal record — is a hash, not a MAC.
//! The construction is `RustCrypto`'s `hmac`, not twenty-five lines of RFC 2104
//! written out here. It was written out here first, and passed RFC 4231's
//! vectors — which is the argument for keeping hand-rolled crypto and is not
//! good enough for this crate: a substrate whose pitch is auditability should
//! not ask a reviewer to check a MAC by eye when the audited implementation is
//! already being compiled into the same binary (`ed25519-dalek`, `aws-sigv4`
//! and `postgres-protocol` all pull it). The RFC 4231 vectors stayed, and now
//! prove this crate *uses* the construction correctly — key handling included,
//! which is the half a caller can still get wrong.

use hmac::{KeyInit, Mac, SimpleHmac};
use sha2::Sha256;

use crate::core::Secret;

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

/// A shared secret, and the header its signature rides in.
///
/// Constructed through [`Destination::signed_with`](super::Destination::signed_with)
/// in the ordinary case. The secret is a [`Secret`], so it is redacted in
/// `Debug` — including inside the [`Destination`](super::Destination) and the
/// sender that hold it — and wiped when the last copy drops.
#[derive(Debug, Clone)]
pub struct BodySigning {
    /// Parsed once, here, so the delivery path has no way to fail on it. A
    /// header name that could only be rejected mid-POST would turn a typo in
    /// the deployment's configuration into a delivery outcome, discovered by
    /// whoever reads the retry counter.
    header: reqwest::header::HeaderName,
    secret: Secret,
}

impl BodySigning {
    /// # Panics
    ///
    /// If `header` is not a valid HTTP field name, or `secret` is empty. Both
    /// are configuration this deployment wrote about itself, and both would
    /// otherwise fail at the far end of a run: an empty MAC key is a signature
    /// anyone can compute, which is worse than no signature at all because the
    /// receiver's check passes.
    #[must_use]
    pub fn new(header: impl Into<String>, secret: Secret) -> Self {
        let header = header.into();
        let name = reqwest::header::HeaderName::try_from(header.as_str()).unwrap_or_else(|_| {
            panic!(
                "push body-signing header '{header}' is not an HTTP field name, so \
                 every delivery to this destination would fail at the POST"
            )
        });
        assert!(
            !secret.is_empty(),
            "a push body-signing secret is empty: the receiver would verify a MAC \
             anybody can compute, and a check that always passes reads exactly \
             like one that means something"
        );
        Self {
            header: name,
            secret,
        }
    }

    /// The header this signature is sent in.
    #[must_use]
    pub fn header(&self) -> &str {
        self.header.as_str()
    }

    pub(super) const fn header_name(&self) -> &reqwest::header::HeaderName {
        &self.header
    }

    /// The header value for **these exact bytes**: `sha256=<lowercase hex>`.
    pub(super) fn value_for(&self, body: &[u8]) -> String {
        let mac = hmac_sha256(self.secret.expose().as_bytes(), body);
        format!("sha256={}", hex::encode(mac))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4231's published vectors, which is the only outside authority a
    /// hand-written MAC can have. Case 1 is the ordinary path, case 2 a short
    /// text key, and case 6 the longer-than-block-size key that exercises the
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

    /// The value is over the bytes, and the bytes decide it.
    #[test]
    fn the_signature_follows_the_body() {
        let signing = BodySigning::new("X-Mako-Signature", Secret::new("shared"));
        let value = signing.value_for(br#"{"a":1}"#);
        assert!(
            value.starts_with("sha256="),
            "the algorithm prefix is how a receiver dispatches: {value}"
        );
        assert_eq!(value.len(), "sha256=".len() + 64, "{value}");
        assert!(
            value[7..]
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
            "lowercase hex is the convention receivers compare against: {value}"
        );
        assert_ne!(
            value,
            signing.value_for(br#"{"a":2}"#),
            "one byte of the body changed and the signature did not"
        );
        assert_ne!(
            value,
            BodySigning::new("X-Mako-Signature", Secret::new("other")).value_for(br#"{"a":1}"#),
            "a different secret produced the same signature"
        );
    }

    /// The secret must not print itself, in any of the values that carry it.
    #[test]
    fn a_signing_secret_is_redacted() {
        let signing = BodySigning::new("X-Mako-Signature", Secret::new("sk-live-abcdef"));
        let shown = format!("{signing:#?}");
        assert!(!shown.contains("abcdef"), "{shown}");
    }

    #[test]
    #[should_panic(expected = "is not an HTTP field name")]
    fn a_header_name_that_cannot_be_sent_is_refused_at_configuration() {
        let _ = BodySigning::new("X Mako Signature", Secret::new("shared"));
    }

    #[test]
    #[should_panic(expected = "is empty")]
    fn an_empty_signing_secret_is_refused() {
        let _ = BodySigning::new("X-Mako-Signature", Secret::new(""));
    }
}
