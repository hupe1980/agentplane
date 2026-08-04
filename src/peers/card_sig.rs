//! Signing an Agent Card, so a peer can check who published it.
//!
//! A card is what a caller reads *before* it trusts anything, fetched over an
//! unauthenticated path from a host it may not control. TLS says the bytes came
//! from that host; it says nothing about whether the host is the party whose
//! capabilities the card describes. A signature does.
//!
//! # This is a real JWS, not our own construction
//!
//! Everywhere else in this crate a signature covers a [`Digest`], because
//! everywhere else the thing being signed is already a hash. A card is not: it
//! is verified by software nobody here wrote, so the bytes signed must be the
//! ones RFC 7515 says they are — `BASE64URL(protected) || '.' || BASE64URL(payload)`
//! — with the signature computed over *that*, not over its hash.
//!
//! Signing `H(m)` with plain Ed25519 produces a perfectly valid signature over
//! the wrong message: every conforming verifier rejects it, and every test
//! written against our own verifier passes. That is why this has its own signing
//! seam rather than reusing [`Signer`](crate::core::Signer).
//!
//! # What is signed
//!
//! The payload is the card, canonicalized per RFC 8785, with the `signatures`
//! field removed — a signature cannot cover itself. Canonicalization is
//! [`crate::core::canon`], which orders keys by UTF-16 code unit precisely so
//! that a verifier elsewhere computes the same bytes.
//!
//! **The card carries no numbers**, and that is load-bearing rather than
//! incidental: RFC 8785's hardest requirement is ECMAScript number formatting,
//! and a card of strings, booleans, arrays and objects never reaches it. A guard
//! asserts the card stays that way, so the day somebody adds an integer field
//! the constraint is a failing test rather than a signature two implementations
//! disagree about.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::core::KeyId;

use super::card::AgentCard;

/// The JWS algorithm this crate signs cards with.
///
/// One algorithm, named, and not negotiable from the card. "Whatever the header
/// says" is how a verifier ends up accepting `none`, and an agent card is
/// exactly the kind of attacker-supplied document that attack was invented for.
pub const ALG: &str = "EdDSA";

/// A detached JWS over an Agent Card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CardSignature {
    /// `BASE64URL(UTF8(protected header JSON))`.
    pub protected: String,
    /// `BASE64URL(signature)`.
    pub signature: String,
    /// Unprotected header values. Not covered by the signature, so nothing
    /// security-relevant is read from here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<Value>,
}

/// Signs bytes, for the rare things a third party verifies.
///
/// Deliberately not [`Signer`](crate::core::Signer): that one takes a digest,
/// because its inputs are hashes and it runs on the journal's write path. This
/// one takes the exact bytes a standard says to sign, and runs once when a card
/// is published.
pub trait CardSigner: Send + Sync + std::fmt::Debug {
    /// The `kid` that goes in the protected header.
    fn key_id(&self) -> KeyId;
    /// An `EdDSA` signature over exactly these bytes.
    fn sign_bytes(&self, message: &[u8]) -> Vec<u8>;
}

/// Checks a card signature against a key.
pub trait CardVerifier: Send + Sync + std::fmt::Debug {
    /// Whether `signature` over exactly `message` was made by `key_id`.
    ///
    /// Returns `false` for an unknown key rather than erroring: an unknown
    /// publisher and a bad signature are the same answer to *may I believe this
    /// card*, and distinguishing them tells a prober which keys exist.
    fn verify_bytes(&self, key_id: &str, message: &[u8], signature: &[u8]) -> bool;
}

/// Why a card's signature was not acceptable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CardSignatureError {
    #[error("the card carries no signatures, and one was required")]
    Unsigned,
    #[error("a card signature is not valid base64url")]
    Malformed,
    #[error("a card signature's protected header is not JSON: {0}")]
    BadHeader(String),
    #[error(
        "a card signature declares algorithm '{0}', and this verifier only \
         accepts {ALG} — an algorithm read from the document being checked is \
         how a verifier is talked into accepting 'none'"
    )]
    WrongAlgorithm(String),
    #[error("no signature on this card verifies against a key this verifier trusts")]
    Untrusted,
    #[error("the card could not be canonicalized: {0}")]
    Canonical(String),
}

/// The exact bytes a signature covers.
///
/// Public because a deployment signing cards out of band — with a KMS, or an
/// offline key — needs to produce these without this crate's signer.
///
/// # Errors
///
/// If the card cannot be serialized.
pub fn signing_input(card: &AgentCard, protected_b64: &str) -> Result<Vec<u8>, CardSignatureError> {
    let mut value =
        serde_json::to_value(card).map_err(|e| CardSignatureError::Canonical(e.to_string()))?;
    // A signature cannot cover itself. Removed rather than emptied, because an
    // empty array and an absent field canonicalize differently and the two sides
    // must agree on which one they hashed.
    if let Some(obj) = value.as_object_mut() {
        obj.remove("signatures");
    }
    let payload = crate::core::canon::value_bytes(&value);

    let mut input = Vec::with_capacity(protected_b64.len() + 1 + payload.len() * 2);
    input.extend_from_slice(protected_b64.as_bytes());
    input.push(b'.');
    input.extend_from_slice(B64.encode(&payload).as_bytes());
    Ok(input)
}

impl AgentCard {
    /// Sign this card, appending the signature.
    ///
    /// Appending rather than replacing: A2A allows several signatures so a
    /// publisher can rotate keys without a window in which nobody can verify the
    /// card. Replacing would create exactly that window.
    ///
    /// # Errors
    ///
    /// If the card cannot be canonicalized.
    pub fn sign(&mut self, signer: &dyn CardSigner) -> Result<(), CardSignatureError> {
        let protected = serde_json::json!({ "alg": ALG, "kid": signer.key_id().as_str() });
        // Canonical bytes for the header too. A verifier uses the base64 string
        // exactly as it arrives, so this is not required for interop — but it
        // makes signing the same card twice produce the same header, which it
        // would not if `serde_json` were preserving insertion order (a
        // dependency can turn that on, and one does).
        let protected_b64 = B64.encode(crate::core::canon::value_bytes(&protected));

        // Signed over the card *without* its signatures, which is what
        // `signing_input` removes — so signing twice produces two signatures
        // over the same bytes rather than one over the other.
        let input = signing_input(self, &protected_b64)?;
        let signature = B64.encode(signer.sign_bytes(&input));

        self.signatures.push(CardSignature {
            protected: protected_b64,
            signature,
            header: None,
        });
        Ok(())
    }

    /// Check that some signature on this card was made by a trusted key.
    ///
    /// # Errors
    ///
    /// [`CardSignatureError::Unsigned`] when there are none,
    /// [`CardSignatureError::WrongAlgorithm`] for anything but [`ALG`], and
    /// [`CardSignatureError::Untrusted`] when none verifies.
    pub fn verify(&self, verifier: &dyn CardVerifier) -> Result<KeyId, CardSignatureError> {
        if self.signatures.is_empty() {
            return Err(CardSignatureError::Unsigned);
        }

        let mut wrong_alg = None;
        for sig in &self.signatures {
            let header = B64
                .decode(&sig.protected)
                .map_err(|_| CardSignatureError::Malformed)?;
            let header: Value = serde_json::from_slice(&header)
                .map_err(|e| CardSignatureError::BadHeader(e.to_string()))?;

            // The algorithm is checked against a constant, never taken from the
            // document. A verifier that believes the header is one an attacker
            // sets to `none`.
            let alg = header
                .get("alg")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if alg != ALG {
                wrong_alg = Some(alg.to_owned());
                continue;
            }
            let Some(kid) = header.get("kid").and_then(Value::as_str) else {
                continue;
            };

            let input = signing_input(self, &sig.protected)?;
            let Ok(raw) = B64.decode(&sig.signature) else {
                return Err(CardSignatureError::Malformed);
            };
            if verifier.verify_bytes(kid, &input, &raw) {
                return Ok(KeyId::from(kid.to_owned()));
            }
        }

        wrong_alg.map_or(Err(CardSignatureError::Untrusted), |alg| {
            Err(CardSignatureError::WrongAlgorithm(alg))
        })
    }
}
