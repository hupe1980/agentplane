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

use crate::core::{CheckpointSigner, Digest, KeyId, SignError, merkle};

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

    /// The witness is at a different size than the proof starts from.
    ///
    /// A **stale client**, not an integrity event, and the distinction is the
    /// whole reason this is its own variant. The witness has simply moved past
    /// the checkpoint this proof was built from, and it says where it is, so the
    /// fix is to build a proof from there and retry.
    ///
    /// Collapsing it into [`Forked`](Self::Forked) would report a routine
    /// cursor mismatch as a history that does not extend — and a team paged
    /// twice for that stops believing the alert that matters.
    #[error(
        "log '{origin}': the witness is at size {witness_size}; build a consistency proof \
         from there and resubmit"
    )]
    Stale { origin: String, witness_size: u64 },

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
    /// The note key id the signature line carried — `SHA-256(name ‖ 0x0A ‖
    /// type ‖ public key)[..4]`.
    ///
    /// Kept because it is the field the ignore-unknown-keys rule is keyed on:
    /// `signed-note` says a verifier MUST ignore a signature sharing a name
    /// *or* an id with a known key but not both. Discarding it — which this
    /// type did — left the name as the only identity, and a name is whatever
    /// the answering server typed.
    pub note_key_id: [u8; 4],
    /// The `cosignature/v1` payload, exactly as a note line carries it: an
    /// eight-byte big-endian timestamp, then the signature over
    /// `cosignature/v1\ntime <t>\n` followed by the note body — never a bare
    /// signature over the note text.
    ///
    /// One layout for every producer, because this field is what an auditor
    /// re-verifies: two witness implementations disagreeing about what these
    /// bytes mean would hand the auditor a payload it can only check by
    /// knowing which implementation produced it, which is the drift this type
    /// exists to rule out.
    pub signature: Vec<u8>,
}

/// The message a cosignature signs, as C2SP `tlog-cosignature` states it: a
/// domain-separation header, the witness's own timestamp line, then the whole
/// note body — including its final newline, and **not** including any
/// signature lines, which is `signed-note`'s boundary rule.
///
/// The header is what keeps a cosignature from being mistaken for a log's own
/// note signature: the two cover different bytes under the same algorithm and
/// the same key length, so only the domain separation tells them apart.
#[must_use]
pub(crate) fn cosignature_message(timestamp: u64, note_text: &str) -> String {
    format!("cosignature/v1\ntime {timestamp}\n{note_text}")
}

/// Split a `cosignature/v1` payload into its halves: an eight-byte big-endian
/// timestamp, then the 64-byte Ed25519 signature.
///
/// A payload of any other length is not one, and `None` — never a guess — is
/// the answer: reading a 64-byte blob as "a signature with no timestamp" would
/// verify it over a message the witness did not sign, and reading a longer one
/// from the front would silently discard trailing bytes a verifier is being
/// asked to vouch for.
// Gated on the feature that consumes it — the HTTP client is the only reader
// of foreign payloads; producers in this file only build them.
#[cfg(feature = "witness-http")]
#[must_use]
pub(crate) fn cosignature_payload(blob: &[u8]) -> Option<(u64, &[u8])> {
    if blob.len() != 8 + 64 {
        return None;
    }
    let (stamp, signature) = blob.split_at(8);
    let timestamp = u64::from_be_bytes(stamp.try_into().expect("eight bytes"));
    Some((timestamp, signature))
}

/// Something that will vouch for having seen a log grow.
#[async_trait]
pub trait Witness: Send + Sync + Debug {
    /// Cosign `checkpoint`, given a consistency proof from `old_size`.
    ///
    /// `old_size` is stated by the caller rather than inferred, and that is not
    /// ceremony. A consistency proof is RFC 6962 `SUBPROOF` — **O(log n)
    /// hashes, not one per new entry** — so nothing about the proof reveals
    /// which size it starts from. A 50→100 proof carries seven hashes, and an
    /// implementation that guessed `size - proof.len()` would claim 93 and be
    /// rejected by every witness. Only the caller holds the log and knows.
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
        old_size: u64,
        proof: &[Digest],
    ) -> Result<Cosignature, WitnessError>;
}

/// A deployment's answer to *how many cosignatures suffice*.
///
/// The number itself is a trust decision only a deployment can make — one
/// public witness rules out a silent rewrite by the operator alone; three
/// independent ones rule out collusion with any single witness. What the
/// runtime owns is making the declared number **enforceable and its
/// shortfall loud**, which is the half that was missing: a deployment that
/// "uses witnesses" with no declared quorum has evidence when it happens to
/// have evidence.
///
/// Zero is refused at construction: a quorum of nothing reads in review as
/// witnessing that is on.
#[derive(Debug, Clone, Copy)]
pub struct WitnessQuorum {
    required: usize,
}

impl WitnessQuorum {
    /// Require `required` cosignatures per checkpoint.
    ///
    /// # Errors
    ///
    /// If `required` is zero — a quorum of nothing is witnessing that is off,
    /// spelled as if it were on.
    pub fn of(required: usize) -> Result<Self, &'static str> {
        if required == 0 {
            return Err(
                "a quorum of zero cosignatures is witnessing that is off, spelled as if \
                 it were on — omit witnessing instead of declaring an empty one",
            );
        }
        Ok(Self { required })
    }

    /// How many cosignatures this policy demands.
    #[must_use]
    pub const fn required(&self) -> usize {
        self.required
    }
}

/// What one submission round produced, against a declared quorum.
///
/// Availability never waits on this: witnessing is retrospective evidence,
/// gathered after sealing, off the run path — a run whose witnesses are
/// unreachable proceeded long ago, and refusing to proceed would make the
/// plane's availability depend on a third party, which is the wrong trade
/// for evidence that is read after the fact. What a deployment gets instead
/// is a report that cannot be mistaken for success: a shortfall is a finding
/// whoever operates the plane must clear, not a log line.
#[derive(Debug)]
pub struct QuorumOutcome {
    /// The cosignatures gathered, in witness order.
    pub cosignatures: Vec<Cosignature>,
    /// Routine failures, by witness index: unreachable, still stale after the
    /// retry, or a proof the caller could not supply. Self-healing or
    /// operational — resubmit later.
    pub routine: Vec<(usize, WitnessError)>,
    /// Integrity refusals, by witness index: a witness that saw this log
    /// **shrink or fork**. The event witnessing exists to detect, and it is
    /// reported even when the quorum was met — two honest cosigners do not
    /// silence a third that remembers a different history.
    pub integrity: Vec<(usize, WitnessError)>,
    required: usize,
}

impl QuorumOutcome {
    /// Whether enough witnesses cosigned.
    #[must_use]
    pub fn met(&self) -> bool {
        self.cosignatures.len() >= self.required
    }

    /// How many cosignatures are still missing.
    #[must_use]
    pub fn shortfall(&self) -> usize {
        self.required.saturating_sub(self.cosignatures.len())
    }

    /// Whether a person must look.
    ///
    /// True on a shortfall — the declared evidence bar was not reached — and
    /// true on **any** integrity refusal, met quorum or not: a fork report
    /// from one witness among five cosigners is the alarm, not noise, because
    /// the four may simply never have seen the history the fifth remembers.
    #[must_use]
    pub fn needs_attention(&self) -> bool {
        !self.met() || !self.integrity.is_empty()
    }
}

/// Submit one checkpoint to every witness and hold the result to a quorum.
///
/// Speaks the protocol each witness expects: a first submission from size
/// zero, and on a *stale* answer — the witness naming where it actually is —
/// a consistency proof is built from the store at that size and the
/// submission retried once. That is the C2SP 409 dance, and it is routine; a
/// witness whose cursor is **ahead of** the checkpoint is answered by the
/// witness itself with the shrink refusal, which is anything but.
///
/// # Errors
///
/// Only if the **store** cannot produce a consistency proof — a caller-side
/// failure. A witness failing is never an error here; it is what the
/// [`QuorumOutcome`] exists to report.
pub async fn cosign_quorum(
    store: &dyn super::JournalStore,
    checkpoint: &Checkpoint,
    witnesses: &[std::sync::Arc<dyn Witness>],
    quorum: WitnessQuorum,
) -> Result<QuorumOutcome, crate::core::StoreError> {
    let mut outcome = QuorumOutcome {
        cosignatures: Vec::new(),
        routine: Vec::new(),
        integrity: Vec::new(),
        required: quorum.required(),
    };
    for (index, witness) in witnesses.iter().enumerate() {
        let first = witness.cosign(checkpoint, 0, &[]).await;
        let result = match first {
            Err(WitnessError::Stale { witness_size, .. }) => {
                // The witness said where it is. A cursor ahead of this
                // checkpoint gets no proof — there is no growth to prove, and
                // the witness's own shrink refusal is the honest answer.
                let proof = if witness_size <= checkpoint.size {
                    store.consistency_proof(witness_size).await?
                } else {
                    Vec::new()
                };
                witness.cosign(checkpoint, witness_size, &proof).await
            }
            other => other,
        };
        match result {
            Ok(cosignature) => outcome.cosignatures.push(cosignature),
            Err(e @ (WitnessError::Forked { .. } | WitnessError::Shrank { .. })) => {
                outcome.integrity.push((index, e));
            }
            Err(e) => outcome.routine.push((index, e)),
        }
    }
    Ok(outcome)
}

/// A witness that remembers, in this process.
///
/// Its signer is a [`CheckpointSigner`], so the key may live in a KMS or an HSM
/// rather than in this process's memory. That matters more here than anywhere
/// else in the crate: a witness key is the trust anchor, and an anchor whose key
/// sits beside the history it vouches for is an anchor a single compromise
/// removes.
///
/// Useful for tests and for proving the *logic*; useless as a trust anchor in
/// production, where the point is that the witness is somebody else. Named to
/// make that obvious at the call site.
#[derive(Debug)]
pub struct MemoryWitness {
    signer: std::sync::Arc<dyn CheckpointSigner>,
    seen: Mutex<BTreeMap<String, (u64, Digest)>>,
}

impl MemoryWitness {
    /// A witness signing as this identity.
    #[must_use]
    pub fn new(signer: std::sync::Arc<dyn CheckpointSigner>) -> Self {
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
        old_size: u64,
        proof: &[Digest],
    ) -> Result<Cosignature, WitnessError> {
        // Scoped, so the guard cannot reach the signing await below. Signing may
        // now be a network call, and a lock held across it would serialise every
        // observation behind the slowest one — as well as making this future
        // non-`Send`, which is how the compiler found it.
        {
            let mut seen = self
                .seen
                .lock()
                .map_err(|_| WitnessError::Unavailable("witness mutex poisoned".into()))?;

            // An origin this witness has never seen is at size zero, and a caller
            // claiming to extend from anywhere else is as stale as one that
            // disagrees about a remembered size. Treating "unknown" as "whatever you
            // say" made this model *more permissive* than the remote witness it
            // stands in for — so a test could pass here and the same submission be
            // refused with a 409 in production.
            let remembered_size = seen.get(&checkpoint.origin).map_or(0, |(size, _)| *size);
            if old_size != remembered_size {
                return Err(WitnessError::Stale {
                    origin: checkpoint.origin.clone(),
                    witness_size: remembered_size,
                });
            }
            // A checkpoint whose own two halves contradict each other is
            // refused before it is remembered, and the first submission is why.
            // A witness has nothing to check a first checkpoint against, so it
            // records whatever it is given — and a size-0 claim beside a root
            // the empty tree does not have is a root no log will ever extend.
            // Every honest checkpoint afterwards then fails consistency and is
            // reported as `Forked`: a permanent integrity page for this origin,
            // bought with one malformed request, and indistinguishable from the
            // event witnessing exists to detect.
            if !checkpoint.is_coherent() {
                return Err(WitnessError::Unavailable(format!(
                    "log '{}': the checkpoint claims size {} with a root the empty tree \
                     does not have — refused rather than remembered, because a witness \
                     holds every later checkpoint to its first one",
                    checkpoint.origin, checkpoint.size
                )));
            }

            if let Some((remembered, old_root)) = seen.get(&checkpoint.origin).copied() {
                // Staleness is settled above, against `remembered_size`, and
                // it is settled once: a second comparison here could never be
                // reached, and a guarantee enforced twice is one whose real
                // enforcement nobody can point at.
                let old_size = remembered;
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

            // Recorded *before* signing, and the order is the safe one. A witness
            // that signed and then failed to record would forget it had vouched,
            // and could later cosign a divergent history at the same size — the
            // exact equivocation it exists to prevent. Remembering something it
            // might not have signed only ever refuses more.
            seen.insert(
                checkpoint.origin.clone(),
                (checkpoint.size, checkpoint.root),
            );
        }

        // Signed over the `cosignature/v1` message — the same construction a
        // remote witness signs — so every `Cosignature` this crate produces
        // means one thing and an auditor verifies both kinds with one rule.
        // The timestamp is zero because this witness has no clock of record:
        // an in-process observation carries no independent time claim, and
        // zero states that rather than dressing an ambient clock up as one.
        let message = cosignature_message(0, &checkpoint.to_note());
        // Awaited, because this signer is permitted to be a KMS or an HSM —
        // which is where the trust anchor's key belongs. A failure here is
        // reported, never swallowed: a cosignature that silently did not happen
        // is indistinguishable to an auditor from a witness that was never
        // asked, and the second is the thing witnessing exists to rule out.
        let signature = self
            .signer
            .sign(message.as_bytes())
            .await
            .map_err(|e| match e {
                SignError::Unavailable(d) => WitnessError::Unavailable(d),
                SignError::Refused { key_id, detail } => {
                    WitnessError::Unavailable(format!("key '{key_id}' refused: {detail}"))
                }
            })?;
        let mut payload = Vec::with_capacity(8 + signature.len());
        payload.extend_from_slice(&0u64.to_be_bytes());
        payload.extend_from_slice(&signature);
        Ok(Cosignature {
            key_id: self.signer.key_id(),
            // The in-process witness signs through the `Signer` seam, which
            // never exposes a public key — so there is no note key id to
            // compute here. Zero says "this cosignature did not arrive on a
            // note line" rather than inventing four bytes that would match
            // nothing a verifier could check.
            note_key_id: [0; 4],
            signature: payload,
        })
    }
}
