//! Cosigning checkpoints, so an operator cannot show two histories.
//!
//! Everything else in this crate protects the record from *edits*: the hash
//! chain detects a rewritten record, the Merkle log detects a removed run, the
//! signatures say who wrote them. None of it detects the operator showing a
//! **different history to each auditor**, because both histories can be
//! internally perfect. Whoever controls the store controls every input to that
//! check.
//!
//! A witness breaks the symmetry by being somebody else. It keeps the last
//! checkpoint it saw for a log and will only cosign a new one that **provably
//! extends** it. Two divergent histories cannot both be cosigned, so a split
//! view stops being invisible and starts being a witness that refuses — or, if
//! the operator publishes anyway, two cosignatures that contradict each other
//! and can be shown to anyone.
//!
//! What this module is *not* is a network protocol. It is the seam and the
//! decision — "does this checkpoint extend what I last saw?" — which is the
//! part that has to be right. [`MemoryWitness`] implements it in-process, for
//! tests and for a single-operator deployment that wants the check without
//! running a second party yet. A remote witness speaking C2SP `tlog-witness`
//! plugs into the same trait, and only then does the guarantee become real:
//! **a witness you host yourself proves nothing about you.**

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::Mutex;

use async_trait::async_trait;

use crate::core::{Digest, KeyId, Signer, merkle};

use super::Checkpoint;

/// Why a witness would not cosign.
#[derive(Debug, thiserror::Error)]
pub enum WitnessError {
    /// The log is smaller than when this witness last saw it.
    ///
    /// Runs were removed. The single most important thing a witness catches,
    /// and the one an operator auditing itself structurally cannot.
    #[error("log '{origin}' shrank from {seen} to {offered} — runs were removed")]
    Shrank {
        origin: String,
        seen: u64,
        offered: u64,
    },

    /// The new checkpoint does not extend the one this witness last cosigned.
    ///
    /// Either history was rewritten, or this is a *different* history of the
    /// same log — the split view. A witness cannot tell which, and does not
    /// need to: both are refusals.
    #[error(
        "log '{origin}' at size {offered} does not extend the checkpoint this \
         witness cosigned at size {seen} — the history was rewritten or forked"
    )]
    Forked {
        origin: String,
        seen: u64,
        offered: u64,
    },

    /// A proof was required and none was usable.
    #[error("log '{origin}': a consistency proof is required to extend size {seen}")]
    ProofMissing { origin: String, seen: u64 },

    /// The witness could not be reached or refused for its own reasons.
    #[error("witness: {0}")]
    Unavailable(String),
}

/// A witness's attestation that it saw a log at this size and root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cosignature {
    /// Who cosigned. An auditor decides whether it trusts this identity; the
    /// crate does not, for the same reason it never mints its own signing key.
    pub key_id: KeyId,
    /// Over the checkpoint's canonical note text, not over its fields — so a
    /// verifier checks exactly the bytes an operator can hand it.
    pub signature: Vec<u8>,
}

/// Something that will vouch for having seen a log grow.
#[async_trait]
pub trait Witness: Send + Sync + Debug {
    /// Cosign `checkpoint`, given a consistency proof from what the witness
    /// last saw.
    ///
    /// The proof is supplied by the operator because only the operator has the
    /// log. That is not a weakness: the witness verifies it against a root it
    /// remembers, so a forged proof fails and a genuine one cannot be withheld
    /// without the refusal itself being evidence.
    ///
    /// # Errors
    ///
    /// [`WitnessError::Shrank`] or [`WitnessError::Forked`] if the checkpoint
    /// does not extend what this witness already cosigned.
    async fn cosign(
        &self,
        checkpoint: &Checkpoint,
        proof: &[Digest],
    ) -> Result<Cosignature, WitnessError>;
}

/// A witness that remembers, in this process.
///
/// Useful for tests and for proving the *logic*; useless as a trust anchor in
/// production, where the point is that the witness is somebody else. Named to
/// make that obvious at the call site.
#[derive(Debug)]
pub struct MemoryWitness {
    signer: std::sync::Arc<dyn Signer>,
    seen: Mutex<BTreeMap<String, (u64, Digest)>>,
}

impl MemoryWitness {
    /// A witness signing as this identity.
    #[must_use]
    pub fn new(signer: std::sync::Arc<dyn Signer>) -> Self {
        Self {
            signer,
            seen: Mutex::new(BTreeMap::new()),
        }
    }

    /// The last checkpoint this witness accepted for a log.
    ///
    /// # Panics
    ///
    /// If a previous caller panicked while holding the lock.
    #[must_use]
    pub fn last_seen(&self, origin: &str) -> Option<(u64, Digest)> {
        self.seen
            .lock()
            .expect("witness mutex")
            .get(origin)
            .copied()
    }
}

#[async_trait]
impl Witness for MemoryWitness {
    async fn cosign(
        &self,
        checkpoint: &Checkpoint,
        proof: &[Digest],
    ) -> Result<Cosignature, WitnessError> {
        let mut seen = self
            .seen
            .lock()
            .map_err(|_| WitnessError::Unavailable("witness mutex poisoned".into()))?;

        if let Some((old_size, old_root)) = seen.get(&checkpoint.origin).copied() {
            if checkpoint.size < old_size {
                return Err(WitnessError::Shrank {
                    origin: checkpoint.origin.clone(),
                    seen: old_size,
                    offered: checkpoint.size,
                });
            }
            // Same size and same root is a re-submission, which is fine and
            // needs no proof — an operator polling a witness must not be
            // punished for it.
            let unchanged = checkpoint.size == old_size && checkpoint.root == old_root;
            if !unchanged {
                // Distinguished from a proof that fails to verify, because the
                // two mean different things to whoever is called at 3am: an
                // absent proof is a caller that forgot, a failing one is a
                // history that does not extend. Collapsing them would make
                // every client bug look like an integrity event.
                // Only growth needs proving. A checkpoint of the *same* size
                // with a different root is a fork whatever it carries — there
                // is no extension to demonstrate — so asking for a proof there
                // would report a contradiction as a caller error.
                if proof.is_empty() && old_size > 0 && checkpoint.size > old_size {
                    return Err(WitnessError::ProofMissing {
                        origin: checkpoint.origin.clone(),
                        seen: old_size,
                    });
                }
                let old = usize::try_from(old_size).unwrap_or(usize::MAX);
                let new = usize::try_from(checkpoint.size).unwrap_or(usize::MAX);
                if !merkle::verify_consistency(old, &old_root, new, &checkpoint.root, proof) {
                    // One error for "rewritten" and "forked" on purpose: the
                    // witness cannot distinguish them and should not pretend
                    // to. Both mean *do not sign this*.
                    return Err(WitnessError::Forked {
                        origin: checkpoint.origin.clone(),
                        seen: old_size,
                        offered: checkpoint.size,
                    });
                }
            }
        }

        seen.insert(
            checkpoint.origin.clone(),
            (checkpoint.size, checkpoint.root),
        );
        drop(seen);

        // Signed over the note text — the artifact that actually leaves the
        // operator's control — so a verifier checks the bytes it was handed
        // rather than a re-serialization it has to trust.
        let note = checkpoint.to_note();
        Ok(Cosignature {
            key_id: self.signer.key_id(),
            signature: self.signer.sign(&Digest::of(note.as_bytes())),
        })
    }
}
