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

/// A signing secret this deployment wrote about itself that cannot be used.
///
/// Configuration errors, decidable the moment the secret is read. Typed as well
/// as panicked because a deployment reads its configuration inside its own
/// builder, where `RuntimeBuilder::try_build` sets the precedent: refuse to
/// start with a diagnostic rather than abort from underneath the caller.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SigningKeyError {
    /// A `whsec_`-prefixed secret whose remainder is not base64.
    ///
    /// The prefix is a claim about the encoding, so the two disagreeing is not
    /// a key this can guess at: signing the prefixed text would produce a MAC
    /// every conformant verifier rejects, and the failure would surface only as
    /// a receiver refusing everything.
    #[error(
        "a push signing secret beginning '{SYMMETRIC_KEY_PREFIX}' names base64 of the key, \
         and this one does not decode — every delivery would carry a MAC the receiver's \
         library rejects"
    )]
    NotBase64,

    /// Shorter than [`MIN_KEY_BYTES`], which Standard Webhooks requires.
    ///
    /// A MAC key an attacker can search is a check that can be defeated, and a
    /// check that can be defeated reads exactly like one that means something.
    #[error(
        "a push signing key of {bytes} bytes is shorter than the {MIN_KEY_BYTES} \
         Standard Webhooks requires: a MAC key an attacker can search is a check \
         that reads exactly like one that means something"
    )]
    TooShort { bytes: usize },
}

/// Why a delivery was not accepted.
///
/// Every variant is a refusal; none is a reason to process the body anyway.
/// They are told apart because an operator needs to know which is happening — a
/// drifting clock and a replayed capture both present as [`Stale`](Self::Stale).
///
/// None carries a hint about how close a signature was: the comparison is
/// all-or-nothing, and quantifying the miss would be an oracle.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum WebhookRejected {
    /// A required header was absent.
    ///
    /// Including the signature itself — the refusal a receiver most often
    /// forgets, since verifying only when the header is present buys nothing.
    #[error("the delivery carried no '{0}' header, so there is nothing to verify")]
    MissingHeader(&'static str),

    /// The timestamp header was not Unix seconds.
    #[error("'{HEADER_TIMESTAMP}' is not Unix seconds: {0}")]
    MalformedTimestamp(String),

    /// The timestamp is outside the tolerance window, in either direction.
    ///
    /// Both directions: a delivery from the future is a clock this receiver
    /// cannot reason about, and accepting it would let whoever captured a POST
    /// choose a timestamp far enough ahead to stay valid indefinitely.
    #[error(
        "'{HEADER_TIMESTAMP}' is {skew_secs}s from now, outside the {tolerance_secs}s \
         tolerance — a signature proves the bytes, and only the window bounds how \
         long a captured POST stays useful"
    )]
    Stale { skew_secs: i64, tolerance_secs: u64 },

    /// The signature header carried no version this build can check.
    ///
    /// A sender deployed ahead of its receivers is a rollout to finish, not a
    /// key to investigate, so it is not reported as a mismatch.
    #[error(
        "'{HEADER_SIGNATURE}' carried no '{SCHEME}' signature — this build verifies \
         '{SCHEME}' (HMAC-SHA256) only, so a header with other labels means a sender \
         was deployed ahead of its receivers"
    )]
    NoSupportedScheme,

    /// No configured key produced any of the signatures offered.
    ///
    /// Which of the possible causes it is cannot be determined from here.
    #[error(
        "no configured key verifies this delivery — the bytes, the id or the \
         timestamp are not what was signed, or the writer did not hold the key"
    )]
    SignatureMismatch,
}

/// The message's own identity, and the receiver's idempotency key.
pub const HEADER_ID: &str = "webhook-id";
/// Unix seconds at which this attempt was made.
pub const HEADER_TIMESTAMP: &str = "webhook-timestamp";
/// `v1,<base64>` over `{id}.{timestamp}.{body}` — one element per configured
/// key, space-separated.
pub const HEADER_SIGNATURE: &str = "webhook-signature";
/// A2A's opaque per-task token, echoed on every delivery for the receiver
/// that registered it to validate against.
pub const HEADER_A2A_TOKEN: &str = "x-a2a-notification-token";

/// The prefix Standard Webhooks gives a base64-encoded symmetric key.
const SYMMETRIC_KEY_PREFIX: &str = "whsec_";

/// The one signature label this build produces and checks.
pub const SCHEME: &str = "v1";

/// How far a delivery's timestamp may sit from now, in either direction.
///
/// Five minutes, the spec's recommendation. A receiver behind a queue that
/// buffers for longer widens it with [`WebhookVerifier::within`] rather than
/// discovering its deliveries fail at the far end of a backlog — and widening
/// it is not a preference, it is deciding how long a captured POST stays useful.
pub const DEFAULT_TOLERANCE: std::time::Duration = std::time::Duration::from_secs(300);

/// The shortest key this accepts, in bytes.
///
/// Public because a deployment choosing a signing secret is the party the bound
/// applies to, and a number reachable only from an error message is one they
/// find out about after they got it wrong.
///
/// The spec's range is 24–64 bytes. The floor is enforced and the ceiling is
/// not: a key shorter than this is a MAC an attacker can search, while a longer
/// one is only wasteful — HMAC hashes a key past the block size, which is a
/// documented branch and not a weakness.
pub const MIN_KEY_BYTES: usize = 24;

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
    /// Every key a delivery is signed under, in configuration order.
    ///
    /// More than one only mid-rotation: Standard Webhooks makes
    /// `webhook-signature` a space-separated list precisely so a sender can
    /// sign under the old and the new key at once, and a receiver holding
    /// either verifies. A sender that can hold only one key turns every
    /// rotation into a flag day for the one party the mechanism was designed
    /// to spare.
    keys: Vec<Vec<u8>>,
}

impl std::fmt::Debug for BodySigning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BodySigning")
            .field("keys", &"<redacted>")
            .finish()
    }
}

impl Drop for BodySigning {
    fn drop(&mut self) {
        for key in &mut self.keys {
            for byte in key {
                *byte = 0;
            }
        }
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
    ///
    /// [`try_new`](Self::try_new) is the same check reported rather than thrown.
    #[must_use]
    pub fn new(secret: &Secret) -> Self {
        Self::try_new(secret).unwrap_or_else(|e| panic!("{e}"))
    }

    /// Sign with `secret`, reporting a bad key rather than aborting.
    ///
    /// For a deployment reading this out of its own configuration: a panic
    /// inside somebody's `build()` takes the process down before it reaches the
    /// diagnostic every other configuration error produces.
    ///
    /// # Errors
    ///
    /// [`SigningKeyError`] — a `whsec_` secret that is not base64, or a key
    /// under [`MIN_KEY_BYTES`].
    pub fn try_new(secret: &Secret) -> Result<Self, SigningKeyError> {
        Ok(Self {
            keys: vec![Self::key_bytes(secret)?],
        })
    }

    /// Sign under `secret` as well — the mid-rotation form.
    ///
    /// # Errors
    ///
    /// As [`try_new`](Self::try_new).
    pub fn try_also_with(mut self, secret: &Secret) -> Result<Self, SigningKeyError> {
        self.keys.push(Self::key_bytes(secret)?);
        Ok(self)
    }

    /// [`try_also_with`](Self::try_also_with), panicking on a bad key — for
    /// configuration written in code, as [`new`](Self::new) is.
    #[must_use]
    pub fn also_with(self, secret: &Secret) -> Self {
        self.try_also_with(secret).unwrap_or_else(|e| panic!("{e}"))
    }

    fn key_bytes(secret: &Secret) -> Result<Vec<u8>, SigningKeyError> {
        let raw = secret.expose();
        let key = match raw.strip_prefix(SYMMETRIC_KEY_PREFIX) {
            Some(encoded) => base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| SigningKeyError::NotBase64)?,
            None => raw.as_bytes().to_vec(),
        };
        if key.len() < MIN_KEY_BYTES {
            return Err(SigningKeyError::TooShort { bytes: key.len() });
        }
        Ok(key)
    }

    /// The `webhook-signature` value for one delivery.
    ///
    /// `id` and `at` are inside the signed content, not merely beside it — a
    /// receiver that compares them against the headers is what makes a captured
    /// POST expire. One `v1,<b64>` element per configured key, space-separated
    /// as the spec writes the list.
    pub(super) fn value_for(&self, id: &str, at: u64, body: &[u8]) -> String {
        let mut content = Vec::with_capacity(id.len() + 24 + body.len());
        content.extend_from_slice(id.as_bytes());
        content.push(b'.');
        content.extend_from_slice(at.to_string().as_bytes());
        content.push(b'.');
        content.extend_from_slice(body);
        self.keys
            .iter()
            .map(|key| {
                let mac = hmac_sha256(key, &content);
                format!(
                    "v1,{}",
                    base64::engine::general_purpose::STANDARD.encode(mac)
                )
            })
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// A delivery that verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDelivery {
    /// The message's own identity, stable across the emitter's retries.
    ///
    /// **The receiver's idempotency key**, and why this type exists rather than
    /// the verifier returning `Ok(())`: a verified signature says the bytes are
    /// genuine, not that they have not already been acted on.
    ///
    /// Hand it to
    /// [`Runtime::run_correlated_once`](crate::runtime::Runtime::run_correlated_once)
    /// and the duplicate is refused by the store rather than by a map in this
    /// process — deduplicating across a fleet rather than until the next
    /// restart.
    pub id: String,
    /// The instant the sender stamped on this attempt, Unix seconds.
    ///
    /// Already checked against the tolerance window; carried so a receiver can
    /// log the skew it is running with and see a clock drift before deliveries
    /// start being refused.
    pub timestamp: u64,
}

/// The check that [`BodySigning`] is one half of.
///
/// # Why this ships beside the signer
///
/// The interesting half of verification is not the HMAC — it is the two things
/// around it. A signature authenticates **bytes**, not freshness, so a captured
/// POST replays forever unless a stale timestamp is refused; and at-least-once
/// delivery makes duplicates ordinary, so genuine bytes arrive twice unless the
/// receiver deduplicates on the id. Both are what a second implementation omits,
/// because omitting them looks like working software: every test passes, every
/// delivery verifies, and the failure is a replay nobody sees.
///
/// This refuses the first and hands back the id for the second — see
/// [`VerifiedDelivery::id`].
///
/// It does not parse the body. Verification is over the exact bytes received; a
/// verifier that deserialized first would check a signature against a
/// re-serialization, which is what makes a whitespace-insensitive parser a
/// signature bypass.
#[derive(Debug, Clone)]
pub struct WebhookVerifier {
    keys: Vec<BodySigning>,
    tolerance: std::time::Duration,
}

impl WebhookVerifier {
    /// Accept deliveries signed with `secret`.
    ///
    /// # Errors
    ///
    /// [`SigningKeyError`], as [`BodySigning::try_new`].
    pub fn new(secret: &Secret) -> Result<Self, SigningKeyError> {
        Ok(Self {
            keys: vec![BodySigning::try_new(secret)?],
            tolerance: DEFAULT_TOLERANCE,
        })
    }

    /// Also accept deliveries signed with `secret`.
    ///
    /// What makes a key rotation possible without an outage: a sender cannot
    /// switch keys at the same instant as its receivers, so both are in flight
    /// for a window. Every key is tried against every offered signature, with no
    /// early exit, so a refusal's duration does not leak which matched.
    ///
    /// # Errors
    ///
    /// [`SigningKeyError`], as [`BodySigning::try_new`].
    pub fn also_accepting(mut self, secret: &Secret) -> Result<Self, SigningKeyError> {
        self.keys.push(BodySigning::try_new(secret)?);
        Ok(self)
    }

    /// Widen or narrow the freshness window from [`DEFAULT_TOLERANCE`].
    #[must_use]
    pub const fn within(mut self, tolerance: std::time::Duration) -> Self {
        self.tolerance = tolerance;
        self
    }

    /// Verify a delivery from its headers and the **raw** body.
    ///
    /// `headers` is anything that iterates `(name, value)` — an
    /// `http::HeaderMap` mapped to strings, an axum extractor, a `Vec`. Names
    /// are matched case-insensitively, as HTTP defines them, so a proxy that
    /// normalises case does not refuse every delivery.
    ///
    /// `now` is passed in rather than read, as every other clock in this crate
    /// is.
    ///
    /// # Errors
    ///
    /// [`WebhookRejected`].
    pub fn verify<'a, I>(
        &self,
        headers: I,
        body: &[u8],
        now: crate::core::Timestamp,
    ) -> Result<VerifiedDelivery, WebhookRejected>
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        let mut id = None;
        let mut timestamp = None;
        let mut signature = None;
        for (name, value) in headers {
            // Matched without allocating a lowercase copy per header: a
            // delivery carries a dozen of them and this runs per request.
            if name.eq_ignore_ascii_case(HEADER_ID) {
                id = Some(value);
            } else if name.eq_ignore_ascii_case(HEADER_TIMESTAMP) {
                timestamp = Some(value);
            } else if name.eq_ignore_ascii_case(HEADER_SIGNATURE) {
                signature = Some(value);
            }
        }
        self.verify_parts(
            id.ok_or(WebhookRejected::MissingHeader(HEADER_ID))?,
            timestamp.ok_or(WebhookRejected::MissingHeader(HEADER_TIMESTAMP))?,
            signature.ok_or(WebhookRejected::MissingHeader(HEADER_SIGNATURE))?,
            body,
            now,
        )
    }

    /// [`verify`](Self::verify) with the three header values already in hand.
    ///
    /// The function the header form is written in terms of, so there is one
    /// implementation of the check rather than two that can drift.
    ///
    /// # Errors
    ///
    /// [`WebhookRejected`], as [`verify`](Self::verify).
    pub fn verify_parts(
        &self,
        id: &str,
        timestamp: &str,
        signature: &str,
        body: &[u8],
        now: crate::core::Timestamp,
    ) -> Result<VerifiedDelivery, WebhookRejected> {
        let at: u64 = timestamp
            .trim()
            .parse()
            .map_err(|_| WebhookRejected::MalformedTimestamp(timestamp.to_owned()))?;

        // Freshness before the MAC, deliberately. A stale delivery is refused
        // whether or not its signature is good — that is the entire point of
        // binding the timestamp into the signed content — and checking it first
        // means a flood of replayed captures costs a subtraction each rather
        // than an HMAC each.
        let skew = now.unix_timestamp() - i64::try_from(at).unwrap_or(i64::MAX);
        let tolerance_secs = self.tolerance.as_secs();
        if skew.unsigned_abs() > tolerance_secs {
            return Err(WebhookRejected::Stale {
                skew_secs: skew,
                tolerance_secs,
            });
        }

        // Standard Webhooks allows a space-delimited list, which is how a
        // sender mid-rotation offers the same body under two keys. A receiver
        // that read only the first would refuse every delivery signed with the
        // new key for as long as the old one led the list.
        let offered: Vec<&str> = signature
            .split_whitespace()
            .filter_map(|part| part.strip_prefix(SCHEME).and_then(|r| r.strip_prefix(',')))
            .collect();
        if offered.is_empty() {
            return Err(WebhookRejected::NoSupportedScheme);
        }

        // Every key against every offered signature, with no early exit on a
        // match. Short-circuiting would make the refusal's duration depend on
        // which key and which signature matched, which is the timing channel
        // the constant-time comparison below exists to close — reintroduced by
        // control flow, exactly as it would be by `==`.
        let mut verified = false;
        for key in &self.keys {
            let expected = key.value_for(id, at, body);
            for candidate in &offered {
                verified |= constant_time_eq(
                    expected.as_bytes(),
                    format!("{SCHEME},{candidate}").as_bytes(),
                );
            }
        }
        if !verified {
            return Err(WebhookRejected::SignatureMismatch);
        }

        Ok(VerifiedDelivery {
            id: id.to_owned(),
            timestamp: at,
        })
    }
}

/// Compare without short-circuiting on the first differing byte.
///
/// A MAC compared with `==` leaks how many leading bytes an attacker guessed,
/// turning a forgery from infeasible into a byte-at-a-time search. Same
/// reasoning as [`Secret`]'s equality.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    // Length is not secret — it is fixed by the scheme, and visible on the
    // wire — but the contents must not short-circuit.
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mid-rotation, one delivery is signed under every configured key.
    ///
    /// Standard Webhooks makes `webhook-signature` a space-separated list so
    /// a receiver holding either the old or the new secret verifies; a sender
    /// that can hold only one key turns every rotation into a flag day.
    #[test]
    fn a_rotating_sender_signs_under_both_keys_in_one_header() {
        let old = Secret::new("whsec_C2FVsBQIhrscChlQIMV+b5sSYspob7oD");
        let new = Secret::new("this-is-a-brand-new-signing-secret");
        let both = BodySigning::new(&old).also_with(&new);
        let value = both.value_for("msg_p5jXN8AQM9LWM0D4loKWxJek", 1_614_265_330, b"{}");

        let parts: Vec<&str> = value.split(' ').collect();
        assert_eq!(parts.len(), 2, "one element per key: {value}");
        assert_eq!(
            parts[0],
            BodySigning::new(&old).value_for("msg_p5jXN8AQM9LWM0D4loKWxJek", 1_614_265_330, b"{}")
        );
        assert_eq!(
            parts[1],
            BodySigning::new(&new).value_for("msg_p5jXN8AQM9LWM0D4loKWxJek", 1_614_265_330, b"{}")
        );
        for part in parts {
            assert!(part.starts_with("v1,"), "spec spelling per element: {part}");
        }
    }

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

    /// The same two refusals, reported rather than thrown.
    ///
    /// The pair matters: a `try_` variant that accepted what `new` panics on
    /// would be a second door with a weaker rule, which is the shape this crate
    /// has already been bitten by — a check enforced at one of its two doors.
    #[test]
    fn the_fallible_constructor_refuses_exactly_what_the_panicking_one_does() {
        assert_eq!(
            BodySigning::try_new(&Secret::new("too-short")).unwrap_err(),
            SigningKeyError::TooShort { bytes: 9 }
        );
        assert_eq!(
            BodySigning::try_new(&Secret::new("whsec_not base64 at all !!!")).unwrap_err(),
            SigningKeyError::NotBase64
        );
        assert!(
            BodySigning::try_new(&Secret::new("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw")).is_ok(),
            "the spec's own example key must be accepted"
        );
    }

    // ── Verification ────────────────────────────────────────────────────────

    const KEY: &str = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
    const BODY: &[u8] = br#"{"claim":"C-1","amount":900}"#;
    const AT: u64 = 1_700_000_000;

    fn verifier() -> WebhookVerifier {
        WebhookVerifier::new(&Secret::new(KEY)).expect("the spec's own key")
    }

    fn now(secs: i64) -> crate::core::Timestamp {
        crate::core::Timestamp::from_unix_timestamp(secs).expect("representable")
    }

    fn headers(id: &str, at: u64, sig: &str) -> Vec<(String, String)> {
        vec![
            (HEADER_ID.to_owned(), id.to_owned()),
            (HEADER_TIMESTAMP.to_owned(), at.to_string()),
            (HEADER_SIGNATURE.to_owned(), sig.to_owned()),
        ]
    }

    fn verify(
        v: &WebhookVerifier,
        h: &[(String, String)],
        body: &[u8],
        at: i64,
    ) -> Result<VerifiedDelivery, WebhookRejected> {
        v.verify(
            h.iter().map(|(k, val)| (k.as_str(), val.as_str())),
            body,
            now(at),
        )
    }

    /// What this crate signs, this crate verifies.
    ///
    /// The round trip is the property a receiver actually depends on, and it is
    /// the one a signer shipped without a verifier can never state: both halves
    /// existing in one place is what makes "the scheme is implemented
    /// correctly" a testable claim rather than an intention.
    #[test]
    fn a_delivery_this_plane_signed_verifies_and_yields_its_dedup_key() {
        let sig = signing(KEY).value_for("msg-1", AT, BODY);
        let ok = verify(
            &verifier(),
            &headers("msg-1", AT, &sig),
            BODY,
            AT.cast_signed(),
        )
        .expect("a delivery we just signed");
        assert_eq!(
            ok,
            VerifiedDelivery {
                id: "msg-1".to_owned(),
                timestamp: AT
            },
            "the id must come back: it is the receiver's idempotency key, and handing it over is the point of returning a value at all"
        );
    }

    /// Every part of the signed content is actually checked.
    ///
    /// A verifier that recomputed over the body alone would pass the first of
    /// these and fail the rest — and would be exactly the ad-hoc scheme this
    /// one replaced, wearing the spec's header names.
    #[test]
    fn a_delivery_whose_body_id_or_instant_was_edited_is_refused() {
        let v = verifier();
        let sig = signing(KEY).value_for("msg-1", AT, BODY);
        let at = AT.cast_signed();

        for (what, headers, body) in [
            (
                "the body",
                headers("msg-1", AT, &sig),
                br#"{"claim":"C-1","amount":9000}"#.as_slice(),
            ),
            ("the id", headers("msg-2", AT, &sig), BODY),
            ("the instant", headers("msg-1", AT + 1, &sig), BODY),
        ] {
            assert_eq!(
                verify(&v, &headers, body, at).unwrap_err(),
                WebhookRejected::SignatureMismatch,
                "{what} was edited in transit and the delivery still verified"
            );
        }
    }

    /// A captured POST expires, which is the whole reason the instant is signed.
    ///
    /// Both directions. A delivery from the future is not a replay, but it is a
    /// clock this receiver cannot reason about — and accepting it would let
    /// whoever captured a POST choose a timestamp far enough ahead to stay
    /// valid indefinitely, which is the unbounded replay window closed by the
    /// front door.
    #[test]
    fn a_captured_delivery_stops_verifying_once_it_is_stale() {
        let v = verifier();
        let sig = signing(KEY).value_for("msg-1", AT, BODY);
        let h = headers("msg-1", AT, &sig);
        let at = AT.cast_signed();

        assert!(
            verify(&v, &h, BODY, at + 299).is_ok(),
            "inside the window a genuine delivery must still be accepted"
        );
        assert!(
            matches!(
                verify(&v, &h, BODY, at + 301).unwrap_err(),
                WebhookRejected::Stale { .. }
            ),
            "a delivery older than the tolerance is a replay this receiver cannot tell from the original"
        );
        assert!(
            matches!(
                verify(&v, &h, BODY, at - 301).unwrap_err(),
                WebhookRejected::Stale { .. }
            ),
            "a delivery from the future is a clock nobody can reason about"
        );
        assert!(
            verify(
                &v.clone().within(std::time::Duration::from_secs(3600)),
                &h,
                BODY,
                at + 3000
            )
            .is_ok(),
            "a receiver behind a slow queue must be able to widen the window deliberately rather than discover it at the far end of a backlog"
        );
    }

    /// A missing signature header is a refusal, not a pass.
    ///
    /// The failure a receiver most often ships: verifying when the header is
    /// present and accepting when it is absent buys nothing at all, because an
    /// attacker simply omits it.
    #[test]
    fn a_delivery_with_no_signature_is_refused_rather_than_waved_through() {
        let v = verifier();
        let sig = signing(KEY).value_for("msg-1", AT, BODY);
        let at = AT.cast_signed();
        let full = headers("msg-1", AT, &sig);

        for (missing, name) in [
            (HEADER_SIGNATURE, HEADER_SIGNATURE),
            (HEADER_ID, HEADER_ID),
            (HEADER_TIMESTAMP, HEADER_TIMESTAMP),
        ] {
            let without: Vec<_> = full.iter().filter(|(k, _)| k != missing).cloned().collect();
            assert_eq!(
                verify(&v, &without, BODY, at).unwrap_err(),
                WebhookRejected::MissingHeader(name)
            );
        }
    }

    /// Header names are matched the way HTTP defines them.
    ///
    /// A receiver behind a proxy that normalises case would otherwise refuse
    /// every delivery, for a reason with nothing to do with the signature —
    /// and the operator would be hunting a key mismatch that was never there.
    #[test]
    fn header_names_are_matched_case_insensitively() {
        let sig = signing(KEY).value_for("msg-1", AT, BODY);
        let shouting = vec![
            ("Webhook-Id".to_owned(), "msg-1".to_owned()),
            ("WEBHOOK-TIMESTAMP".to_owned(), AT.to_string()),
            ("Webhook-Signature".to_owned(), sig),
        ];
        assert!(verify(&verifier(), &shouting, BODY, AT.cast_signed()).is_ok());
    }

    /// A rotation works from both ends: several keys accepted, several
    /// signatures offered.
    ///
    /// A sender cannot switch keys at the same instant as its receivers, so
    /// there is always a window with both in flight. A verifier holding one key
    /// makes that window zero, and the usual answer to an impossible
    /// requirement is that the rotation never happens.
    #[test]
    fn a_key_rotation_verifies_from_both_directions() {
        let old = "whsec_bm90LXRoZS1zYW1lLWtleS1hdC1hbGwtaGVyZQ==";
        let v = verifier()
            .also_accepting(&Secret::new(old))
            .expect("a valid second key");
        let at = AT.cast_signed();

        // Signed with the second key alone: the receiver accepts both.
        let by_old = signing(old).value_for("msg-1", AT, BODY);
        assert!(verify(&v, &headers("msg-1", AT, &by_old), BODY, at).is_ok());

        // Signed with both and offered space-delimited, as the spec allows. A
        // receiver reading only the first would refuse for as long as the other
        // key led the list, so both orderings are checked.
        let by_new = signing(KEY).value_for("msg-1", AT, BODY);
        let only_new = verifier();
        for pair in [format!("{by_old} {by_new}"), format!("{by_new} {by_old}")] {
            assert!(
                verify(&only_new, &headers("msg-1", AT, &pair), BODY, at).is_ok(),
                "a receiver holding one key must find its signature anywhere in the offered list: {pair}"
            );
        }
    }

    /// A header carrying only labels this build cannot check says so.
    ///
    /// Distinct from a mismatch, and the distinction is operational: a sender
    /// deployed ahead of its receivers is a rollout to finish, while a mismatch
    /// is a key or a body to investigate. Reporting the first as the second
    /// sends somebody hunting the wrong thing.
    #[test]
    fn an_unknown_scheme_is_told_apart_from_a_bad_signature() {
        let v = verifier();
        assert_eq!(
            verify(
                &v,
                &headers("msg-1", AT, "v1a,c29tZXRoaW5nCg=="),
                BODY,
                AT.cast_signed()
            )
            .unwrap_err(),
            WebhookRejected::NoSupportedScheme
        );
        assert_eq!(
            verify(
                &v,
                &headers("msg-1", AT, "not-a-scheme"),
                BODY,
                AT.cast_signed()
            )
            .unwrap_err(),
            WebhookRejected::NoSupportedScheme
        );
    }

    /// A timestamp that is not a number is refused before any MAC is computed.
    #[test]
    fn a_malformed_timestamp_is_refused_by_name() {
        let sig = signing(KEY).value_for("msg-1", AT, BODY);
        let h = vec![
            (HEADER_ID.to_owned(), "msg-1".to_owned()),
            (HEADER_TIMESTAMP.to_owned(), "yesterday".to_owned()),
            (HEADER_SIGNATURE.to_owned(), sig),
        ];
        assert!(matches!(
            verify(&verifier(), &h, BODY, AT.cast_signed()).unwrap_err(),
            WebhookRejected::MalformedTimestamp(_)
        ));
    }

    /// The comparison does not short-circuit on the first differing byte.
    ///
    /// Checked structurally rather than by timing, which is what a unit test can
    /// honestly assert: a wall-clock measurement on a shared runner is noise,
    /// and a test that passes on noise is worse than none.
    #[test]
    fn the_comparison_is_constant_time_in_shape() {
        assert!(constant_time_eq(b"abcdef", b"abcdef"));
        assert!(!constant_time_eq(b"abcdef", b"abcdeg"));
        assert!(
            !constant_time_eq(b"abcdef", b"abcde"),
            "a length difference is not a match"
        );
        assert!(
            !constant_time_eq(b"zbcdef", b"abcdef"),
            "differing in the first byte is refused exactly as differing in the last"
        );
    }
}
