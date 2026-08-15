//! Who wrote this history.
//!
//! # A hash chain answers the wrong question
//!
//! `hash = H(prev ‖ bytes)` proves a run's records are *internally consistent*:
//! nothing was edited, reordered, or removed within the run, by anyone who
//! cannot recompute every subsequent hash. It says nothing whatsoever about
//! **authorship**. Whoever can run SHA-256 owns the history, and the party
//! holding the store can always run SHA-256.
//!
//! That is a real limitation and not a theoretical one: the deployer is the
//! party an auditor is being asked to trust, and a chain they can regenerate
//! end-to-end is not evidence against them. A signature is.
//!
//! # What is signed, and why that is enough
//!
//! The record's **chain hash**, which already covers `prev_hash ‖ canonical
//! bytes`. Because the hash chains, one signature over record *n* transitively
//! commits to every record before it — so a forged prefix invalidates every
//! later signature, not just its own.
//!
//! Signing the hash rather than the body also avoids a circularity that is easy
//! to walk into: put the signature *inside* the body and the hash covers the
//! signature, which covers the hash.
//!
//! # This crate ships a seam, not a key manager
//!
//! Same reasoning as the policy engine and the tracing exporter. Production
//! signing identity belongs to the deployment's workload identity system —
//! SPIFFE SVIDs, which is what [`identity`](crate::core::identity) already
//! assumes and what the state of the art does. A crate that invented its own key
//! distribution would be wrong for every deployment that already has one.
//!
//! What the crate owns is the shape: a signature is attached where the chain is
//! sealed, verified where the chain is verified, and carries the **key id** so a
//! verifier can say *which* workload wrote a record rather than merely that
//! somebody with a key did.
//!
//! # What this still does not buy
//!
//! Signing binds authorship. It does not bind *existence*: an operator who
//! controls the signing identity can produce a perfectly signed alternative
//! history, and nothing here detects a whole run being deleted or two different
//! histories being shown to two auditors. Those need an anchor outside the
//! producing party — a witness-cosigned checkpoint — and that is deliberately a
//! separate mechanism rather than a bigger signature.

use std::fmt::Debug;

use serde::{Deserialize, Serialize};

use crate::core::Digest;

/// Names the key that produced a signature.
///
/// A SPIFFE ID in a deployment that has one (`spiffe://example.org/plane/a`),
/// or any stable string. Carried on every record because "somebody with a valid
/// key wrote this" is a much weaker statement than "this workload wrote this",
/// and the second is what an audit is asking for.
pub type KeyId = String;

/// A signature over a record's chain hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    /// Which key. Not which *algorithm* — that is the verifier's business, and a
    /// self-described algorithm is a downgrade attack waiting to be written.
    pub key_id: KeyId,
    #[serde(with = "hex_bytes")]
    pub signature: Vec<u8>,
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s).map_err(D::Error::custom)
    }
}

/// Signs a record's chain hash.
///
/// Implementations must be cheap enough to run on every append — this is on the
/// write path of every journaled effect — and must not perform I/O in `sign`. A
/// signer that calls out to a KMS per record turns the journal's write path into
/// a network dependency, which is the same mistake as a policy engine that can
/// fail open. Fetch and cache the credential elsewhere; sign locally.
pub trait Signer: Send + Sync + Debug {
    /// The identity this signer writes as.
    fn key_id(&self) -> KeyId;

    /// Sign a record's chain hash.
    fn sign(&self, hash: &Digest) -> Vec<u8>;

    /// Attach an attestation to a hash.
    fn attest(&self, hash: &Digest) -> Attestation {
        Attestation {
            key_id: self.key_id(),
            signature: self.sign(hash),
        }
    }
}

/// Bind a signature to what it is *about*, not just to the bytes it covers.
///
/// [`Signer::sign`] takes a bare 32-byte digest, so a signature over a manifest
/// and a signature over a record's chain hash are structurally identical: the
/// same key, the same algorithm, the same input shape. Nothing in either says
/// which question it was answering. That is the classic cross-protocol
/// confusion, and the defence is to hash a domain label in alongside the payload
/// so the two can never be mistaken for one another.
///
/// The label is separated from the payload by a `0x00` byte, so no domain can be
/// a prefix of another with the boundary landing inside the payload — the same
/// reason canonical encodings length-prefix their fields.
///
/// **Universal for every signature this crate defines**, which it was not when
/// it was written: manifests used it and record attestations and provenance
/// seals signed their digest directly. The caveat recorded here at the time said
/// the argument for leaving them — that confusing two would need a preimage —
/// "stops holding when somebody adds a surface where the signer's input is more
/// attacker-shaped". Provenance sealing was then added and is exactly that
/// surface: its payload carries a caller-chosen `target` and an arguments
/// digest, and the sealed block travels to third-party tool servers and peers.
///
/// So the three are separated rather than argued about.
///
/// The **one** signature deliberately not routed through here is the checkpoint
/// cosignature. Its input is a C2SP `signed-note` body, which is an
/// interoperable artifact: what a signature over it must cover is the format's
/// business and not this crate's, so adding a label of ours would be this crate
/// unilaterally redefining somebody else's wire. Separation there comes from the
/// note's own structure — an origin line, a size and a root hash — rather than
/// from a prefix, and the encoding is pinned by its own tests.
#[must_use]
pub fn signing_hash(domain: &str, payload: &Digest) -> Digest {
    let mut bytes = Vec::with_capacity(domain.len() + 33);
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0x00);
    bytes.extend_from_slice(payload.as_bytes());
    Digest::of(&bytes)
}

/// The domain a manifest signature is made under.
pub const DOMAIN_MANIFEST: &str = "io.github.hupe1980.agentplane/manifest/v1";

/// The domain a journal record's attestation is made under.
///
/// Answers *this key appended this record to this chain*. Distinct from
/// [`DOMAIN_PROVENANCE`] because the two are signed by the **same** workload key
/// on the same plane, and an attestation lifted from one to the other would say
/// something nobody attested to.
pub const DOMAIN_RECORD: &str = "io.github.hupe1980.agentplane/record/v1";

/// The domain a provenance seal is made under.
///
/// Answers *this plane made this call, for this run, with these arguments*. The
/// most exposed of the three: the sealed block is handed to tool servers and A2A
/// peers, so its verifier is often somebody else's code and its payload contains
/// values a caller chose.
pub const DOMAIN_PROVENANCE: &str = "io.github.hupe1980.agentplane/provenance/v1";

/// Signs the rare, high-value things: checkpoints and cosignatures.
///
/// A deliberate second trait, and the split is about **granularity**, not taste.
/// [`Signer`] runs on the write path of every journaled effect, so it must not
/// perform I/O — a network round trip per record would make the journal
/// unavailable whenever a KMS is. That constraint is right there and wrong here.
///
/// A checkpoint is signed once per seal; a witness cosignature once per
/// observation. At that rate a network call costs nothing, and the key involved
/// is the most valuable in the system: a witness key is the trust anchor, so
/// keeping it in the memory of the process whose history it vouches for
/// concedes the property it exists to provide. Dedicated witness hardware is
/// where this role is going in the wider ecosystem, and a trait that forbids I/O
/// cannot reach it.
///
/// Fallible, unlike [`Signer`]. A local key cannot fail to sign; a KMS can be
/// throttled, unreachable, or have revoked the key. Returning `Vec<u8>`
/// infallibly would force every remote implementation to panic or to fabricate
/// a signature, and a fabricated signature is worse than an outage.
///
/// Any [`Signer`] is usable here, so a deployment holding a local key writes no
/// adapter.
#[async_trait::async_trait]
pub trait CheckpointSigner: Send + Sync + Debug {
    /// The identity this signer writes as.
    fn key_id(&self) -> KeyId;

    /// Sign **the message**, or say why not.
    ///
    /// Bytes, not a [`Digest`], and the difference is interoperability rather
    /// than taste. A checkpoint's signature travels as a C2SP `signed-note`
    /// line, and that format specifies a signature over the note *text*: pure
    /// Ed25519, not Ed25519 over a pre-hash. Signing the hash instead produces
    /// sixty-four bytes of the right algorithm under the right key that verify
    /// against no witness, no auditor and no `signed-note` implementation.
    ///
    /// [`CardSigner`](crate::peers::CardSigner) carries the same reasoning for
    /// JWS — *"signing its hash instead would verify perfectly here and nowhere
    /// else"*.
    ///
    /// # Errors
    ///
    /// If the signing service refuses or cannot be reached.
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignError>;
}

/// Why a signature could not be produced.
///
/// Its own error rather than a string, because the two cases call for different
/// operator responses: a service that is merely unreachable will work again, and
/// a key that has been revoked or denied never will.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignError {
    /// The signing service could not be reached. Retryable.
    #[error("signing service unavailable: {0}")]
    Unavailable(String),
    /// The service answered and refused — revoked key, denied policy, wrong
    /// audience. Retrying reproduces it.
    #[error("signing refused for key '{key_id}': {detail}")]
    Refused { key_id: KeyId, detail: String },
}

// No blanket `impl<T: Signer> CheckpointSigner for T`, and it must stay that
// way. [`Signer`] covers a 32-byte digest; a checkpoint signature covers the
// note text. A blanket impl would let one stand in for the other at every call
// site without a cast to notice, and the two are the same length, the same
// algorithm and the same type — only a verifier can tell them apart. Each
// deployment writes the four lines naming which bytes its key covers; see
// `Ed25519Signer` under the `signing` feature.

/// Checks a signature against the key that claims to have made it.
///
/// Deliberately separate from [`Signer`]: an auditor verifies without being able
/// to sign, and that asymmetry is the entire point of using signatures rather
/// than a MAC. A verifier that could also sign would be a shared secret with
/// extra steps.
pub trait Verifier: Send + Sync + Debug {
    /// Whether `signature` over `hash` was made by `key_id`.
    ///
    /// Returns `false` for an unknown key rather than erroring: an unknown
    /// signer and a bad signature are the same answer to the only question
    /// being asked, which is *may I believe this record*.
    fn verify(&self, key_id: &str, hash: &Digest, signature: &[u8]) -> bool;
}

/// Why a chain's attestations were not acceptable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AttestError {
    /// A record carries no signature and one was required.
    ///
    /// Distinct from a bad signature on purpose: the two call for opposite
    /// responses. A bad signature means somebody tampered or a key rotated
    /// wrongly; a missing one usually means the plane wrote that history before
    /// signing was configured, which is an operational fact rather than an
    /// attack.
    #[error("record {seq} carries no signature, and this verification required one")]
    Unsigned { seq: crate::core::Seq },

    /// A signature did not check out.
    #[error(
        "record {seq} has a signature that '{key_id}' did not make — the chain is intact, so the record was rewritten by somebody who could recompute hashes but not sign"
    )]
    BadSignature {
        seq: crate::core::Seq,
        key_id: KeyId,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No two signature kinds share a signing input.
    ///
    /// The point of [`signing_hash`] is that a signature says *which question it
    /// answered*, and a bare digest does not. Three surfaces sign with the same
    /// key on the same plane — a manifest, a journal record, a provenance block
    /// — so if any two produced the same input for the same payload, a signature
    /// made for one would verify as the other.
    ///
    /// This is a *known-answer* comparison rather than a round trip: a round
    /// trip would pass identically if `signing_hash` ignored its domain and
    /// returned the payload unchanged, which is precisely the regression that
    /// removing the separation would be.
    #[test]
    fn the_domains_do_not_collide_and_none_is_the_bare_payload() {
        let payload = Digest::of(b"the same bytes under three questions");

        let inputs = [
            signing_hash(DOMAIN_MANIFEST, &payload),
            signing_hash(DOMAIN_RECORD, &payload),
            signing_hash(DOMAIN_PROVENANCE, &payload),
        ];

        for (i, a) in inputs.iter().enumerate() {
            assert_ne!(
                *a, payload,
                "domain {i} signs the bare payload, so its signatures are \
                 interchangeable with any surface that does not separate at all"
            );
            for b in &inputs[i + 1..] {
                assert_ne!(
                    a, b,
                    "two domains produce one signing input, so a signature made \
                     under one verifies under the other"
                );
            }
        }
    }

    /// The `0x00` boundary is what stops one domain being a prefix of another.
    ///
    /// Without it, `".../record/v1"` followed by a payload and `".../record/v1x"`
    /// followed by a shorter one could serialize to the same bytes. Concatenation
    /// without a separator is the classic way a domain label stops separating.
    #[test]
    fn a_domain_cannot_be_extended_into_another() {
        let payload = Digest::of(b"payload");
        assert_ne!(
            signing_hash("a", &payload),
            signing_hash("a\u{0}", &payload),
            "the label and the payload run together, so the boundary is guessable"
        );
    }
}
