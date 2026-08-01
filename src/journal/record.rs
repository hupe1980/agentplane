//! Journal records and the hash chain.
//!
//! # The wire-bytes rule
//!
//! A record is hashed over the exact bytes that were written, and those bytes
//! are what the store keeps. Verification never re-serializes, and *upcasting an
//! old record to a new shape never changes its hash*.
//!
//! This is subtle and load-bearing. If the chain were computed over the upcast
//! form, then the first time a record schema changed, every historical hash
//! would change with it — silently destroying tamper evidence for all past
//! records, which is precisely the property the chain exists to provide.
//! Upcasting is a read-time view; the chain is over history as written.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::core::{
    AttestError, Attestation, CaseId, Compensation, DeadlineState, Digest, Disposition,
    EffectDescriptor, EffectKey, Epoch, Label, Phase, Principal, Recovery, RunId, Seq, Signer,
    Spend, StepId, StoreError, Timestamp, Verifier, canon,
};

/// The typed view of a record's `(kind, version, payload)`.
///
/// Serialized as an internally-tagged enum so the payload stays inspectable in
/// the database and in an audit export without this crate present.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "PascalCase")]
#[non_exhaustive]
pub enum RecordKind {
    /// A run was admitted: identity bound, budget reserved, input labeled.
    RunAdmitted {
        agent: String,
        input: Value,
        /// Which policy set governed this run, if any.
        ///
        /// `None` means no engine was configured — a fact worth recording,
        /// because "was policy switched on for this run" should be answerable
        /// from the journal years later rather than from someone's memory of how
        /// the deployment was wired. Journaled once here rather than per
        /// decision: this is an audit question, not a replay one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        policy: Option<Digest>,
    },

    /// The plan was compiled from trusted input and frozen.
    ///
    /// From here the plan is an authorization graph: the journal that follows
    /// can be checked against it, down to per-argument provenance.
    PlanFrozen {
        digest: Digest,
        /// Capability per step, for readability in a log listing.
        steps: Vec<String>,
        /// The plan itself, so replay reads it back rather than recompiling.
        ///
        /// Recompiling could produce a different graph — a changed manifest, a
        /// different router — and replay would then verify the run against a
        /// plan that never governed it.
        plan: Value,
    },

    StepStarted {
        skill: String,
    },
    StepFinished {
        outcome: String,
    },

    /// A run was correlated to a case — either joining an existing one or
    /// opening a new one.
    ///
    /// The case id itself lives in [`RecordBody::case`], which every record in a
    /// case-bound run carries — so the case's whole history is one indexed
    /// range scan, and this variant carries only what is specific to the
    /// binding event.
    ///
    /// Field names here must avoid `kind` (the enum's own serde tag) and `case`
    /// (the body's field), because this variant is flattened into the body and
    /// either collision would silently corrupt the wire format.
    CaseBound {
        case_kind: String,
        opened: bool,
    },

    /// An obligation was registered with a **resolved instant**.
    ///
    /// The instant is recorded, not the rule that produced it. Calendars change
    /// — a corrected holiday table, a new regulatory notice — and recomputing on
    /// replay would silently move a legally binding deadline under an audit. The
    /// `calendar_digest` says which ruleset produced this instant, so a changed
    /// rule is visible rather than retroactive.
    DeadlineRegistered {
        name: String,
        #[serde(with = "time::serde::rfc3339")]
        resolved_at: Timestamp,
        calendar_digest: Digest,
    },

    /// An obligation changed state: met, breached, warned, or cancelled.
    DeadlineTransition {
        name: String,
        from: DeadlineState,
        to: DeadlineState,
    },

    /// A run registered interest in a future event and stopped.
    ///
    /// Written **before** the frame is released, so an event arriving in the
    /// same instant finds a durable subscription rather than a gap.
    RunSuspended {
        reason: crate::core::SuspendReason,
    },

    /// Structured reasoning, recorded adjacent to the effects it explains.
    ///
    /// Adjacency is the point. A note sitting next to the action it claims to
    /// justify makes reasoning-versus-action mismatch detectable after the fact
    /// and testable under replay — which a summary written at the end of a run
    /// cannot do.
    Note {
        text: String,
    },

    /// Written **before** the effect is performed. An `EffectStarted` with no
    /// matching terminal record means a crash left the outcome unknown, and the
    /// declared [`Recovery`] decides what happens next — the runtime never
    /// guesses.
    EffectStarted {
        descriptor: EffectDescriptor,
        recovery: Recovery,
        mutates: bool,
        /// Which attempt this is, 1-based.
        ///
        /// Also part of the effect key, so attempts do not collide. Recorded
        /// here as well because reading "attempt 3, after 400ms" off a record
        /// beats recomputing hashes to work out how a run reached its fourth
        /// call to the same endpoint.
        attempt: u32,
        /// How long the runtime waited before this attempt, in milliseconds.
        /// Zero on the first.
        backoff_ms: u64,
    },

    EffectDone {
        output: Value,
        /// What this effect consumed.
        ///
        /// Recorded so replay adds up the same figures the original run did,
        /// and reaches the same budget verdict at the same point.
        #[serde(default, skip_serializing_if = "Spend::is_free_ref")]
        spend: Spend,
    },
    EffectFailed {
        error: String,
        /// What the attempt consumed before it failed.
        ///
        /// Usually nothing. Not nothing for a metered call that died partway —
        /// a model stream bills for what it generated — and recording it is what
        /// makes a replayed run reach the same budget verdict at the same point.
        #[serde(default, skip_serializing_if = "Spend::is_zero")]
        spend: Spend,
        /// What the failure says about whether the call reached the outside
        /// world.
        ///
        /// On the record because it is the input to every later decision — the
        /// retry taken at the time, and any operator judgement afterwards. A
        /// message can be reworded; a disposition is a fact about the run.
        disposition: Disposition,
    },

    /// A limit refused an operation before it started.
    ///
    /// Written **at the moment of refusal**, because the verdict is history: a
    /// run that stopped here stopped here, whatever budget is in force when it
    /// is replayed. Without this record a replayed run reaches the same point,
    /// finds no history, and reports that the *build* performs more effects
    /// than the record — sending an operator to look for a code change that
    /// does not exist.
    ///
    /// Carries an effect key when a specific operation was refused, and only a
    /// step when the step itself was never admitted.
    BudgetRefused {
        /// Which limit, in the words the operator will act on.
        limit: String,
        /// Where consumption actually reached. "Budget exhausted" alone does
        /// not tell anyone what to raise it to.
        used: String,
    },

    /// The delegation chain this run acts under, owner first.
    ///
    /// Recorded once, at admission, because "on whose behalf" is the question a
    /// log line cannot answer and an auditor always asks. Recorded rather than
    /// re-derived because credentials expire: re-verifying during replay would
    /// fail an audit of a decision that was perfectly sound when it was made.
    ///
    /// Absent entirely when no chain was supplied — an absent delegation must
    /// not be spelled the same way as an unrestricted one.
    IdentityBound {
        chain: Vec<Principal>,
    },

    /// Policy refused an effect before it was attempted.
    ///
    /// The twin of [`RecordKind::BudgetRefused`], and it exists for the same
    /// reason: a refusal is a place the run *stopped*, and a stop with no record
    /// replays as "this build performs more effects than the recorded one",
    /// sending an operator to look for a code change that does not exist.
    ///
    /// A *permit* gets no record. The effect's own `EffectStarted` is already
    /// the evidence that it was allowed, and journaling "yes" beside every call
    /// doubles the log to say nothing.
    PolicyDenied {
        /// Why, in the words an operator will act on. Never just "denied".
        reason: String,
        /// The action and resource that were refused, so the record is readable
        /// without reconstructing the request from the effect beside it.
        action: String,
        resource: String,
    },

    /// A completed step was undone because a later one failed.
    ///
    /// The declaration is on the record as well as the outcome, because "this
    /// step was skipped" and "this step said there was nothing to undo" look
    /// identical in a log and mean very different things to whoever is reading
    /// it six months later.
    StepCompensated {
        compensation: Compensation,
        outcome: String,
    },

    /// An unknown outcome was resolved by asking the provider.
    ///
    /// Written whenever a probe runs, including when it comes back
    /// inconclusive — "we did not know, we asked, and we still do not know" is
    /// exactly what an operator picking up the escalation needs to see, and
    /// leaving it out would make the escalation look like nobody tried.
    EffectReconciled {
        /// What the probe established, in the same vocabulary a failure uses.
        disposition: Disposition,
        /// The recovered result, present only when the probe found it landed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        output: Option<Value>,
        /// What the recovered call consumed. Zero unless the probe recovered a
        /// result to measure.
        #[serde(default, skip_serializing_if = "Spend::is_free_ref")]
        spend: Spend,
        /// What the probe reported, when it failed or could not tell.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },

    /// A labeled value left the information-flow lattice. Policy approved it and
    /// the reason is on the record, permanently.
    Declassified {
        reason: String,
        label: Label,
    },

    /// An operator's stop request, observed by the run's owner.
    ///
    /// The *request* lives beside the chain, unfenced, so that somebody who does
    /// not hold the lease can make it (see `JournalStore::request_cancel`). This
    /// record is written when the owner acts on it, which is what puts the
    /// asker's name and reason inside the hash chain — an intervention nobody
    /// signed is an outage, not oversight.
    ///
    /// Written at a **step boundary**, never mid-effect: interrupting between
    /// "announced" and "recorded" manufactures the in-doubt case the effect
    /// protocol exists to avoid.
    RunCancelled {
        actor: String,
        reason: String,
    },

    /// The chain is closed. The digest is the terminal hash, and it is what a
    /// signature covers.
    RunSealed {
        outcome: String,
        chain_head: Digest,
    },
}

impl RecordKind {
    /// Stable discriminator, stored in an indexed column.
    #[must_use]
    pub fn kind_str(&self) -> &'static str {
        match self {
            Self::RunAdmitted { .. } => "RunAdmitted",
            Self::PlanFrozen { .. } => "PlanFrozen",
            Self::StepStarted { .. } => "StepStarted",
            Self::StepFinished { .. } => "StepFinished",
            Self::Note { .. } => "Note",
            Self::RunSuspended { .. } => "RunSuspended",
            Self::CaseBound { .. } => "CaseBound",
            Self::DeadlineRegistered { .. } => "DeadlineRegistered",
            Self::DeadlineTransition { .. } => "DeadlineTransition",
            Self::EffectStarted { .. } => "EffectStarted",
            Self::EffectDone { .. } => "EffectDone",
            Self::EffectFailed { .. } => "EffectFailed",
            Self::EffectReconciled { .. } => "EffectReconciled",
            Self::StepCompensated { .. } => "StepCompensated",
            Self::BudgetRefused { .. } => "BudgetRefused",
            Self::IdentityBound { .. } => "IdentityBound",
            Self::PolicyDenied { .. } => "PolicyDenied",
            Self::Declassified { .. } => "Declassified",
            Self::RunCancelled { .. } => "RunCancelled",
            Self::RunSealed { .. } => "RunSealed",
        }
    }

    /// Current schema version for this kind.
    ///
    /// Bumping it is an RFC-level change: the journal is forever, so every
    /// version ever written must remain readable via an [`Upcaster`](super::Upcaster).
    #[must_use]
    pub fn version(&self) -> u16 {
        1
    }
}

/// The hashed portion of a record.
///
/// Field order here *is* the wire order (serde preserves struct declaration
/// order), and object keys inside `payload` are sorted by `serde_json`. Both are
/// required for the bytes to be canonical.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecordBody {
    pub seq: Seq,
    pub run: RunId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case: Option<CaseId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<StepId>,
    /// Whether this record belongs to the step's forward pass or its
    /// compensating one.
    ///
    /// Skipped when `Forward`, so the overwhelmingly common case costs no
    /// bytes and no hash input — and an existing forward record hashes
    /// identically whether or not compensation exists in the build.
    #[serde(default, skip_serializing_if = "Phase::is_forward_ref")]
    pub phase: Phase,
    pub epoch: Epoch,
    pub v: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect_key: Option<EffectKey>,
    #[serde(flatten)]
    pub kind: RecordKind,
}

/// A sealed journal entry: body, chain links, and the bytes that were hashed.
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    pub body: RecordBody,
    pub prev_hash: Digest,
    pub hash: Digest,
    /// Who wrote it, if the plane was configured to say.
    ///
    /// Beside the hash rather than inside the body, and that placement is
    /// forced: the signature covers the chain hash, so putting it in the body
    /// would make the hash cover the signature that covers the hash.
    ///
    /// `None` is an ordinary state, not a defect — a plane that has not been
    /// given a [`Signer`](crate::core::Signer) writes unsigned records, and
    /// history written before signing was configured stays unsigned forever.
    /// What must never happen is a *verifier* silently accepting that; see
    /// [`Record::verify_attested`].
    pub attestation: Option<Attestation>,
    raw: Vec<u8>,
}

impl Record {
    /// Serialize canonically and link into the chain.
    pub fn seal(body: RecordBody, prev_hash: Digest) -> Result<Self, StoreError> {
        Self::seal_signed(body, prev_hash, None)
    }

    /// Seal, and attest it as the given signer.
    ///
    /// The signature is taken over the chain hash, which already covers
    /// `prev_hash ‖ canonical(body)`. Because the hash chains, this signature
    /// transitively commits to every record before this one — so rewriting any
    /// part of the prefix invalidates every later signature, not just its own.
    pub fn seal_signed(
        body: RecordBody,
        prev_hash: Digest,
        signer: Option<&dyn Signer>,
    ) -> Result<Self, StoreError> {
        let raw = canon::to_bytes(&body)?;
        let hash = Digest::chain(prev_hash, &raw);
        Ok(Self {
            body,
            prev_hash,
            hash,
            attestation: signer.map(|s| s.attest(&hash)),
            raw,
        })
    }

    /// Reconstruct from storage, verifying the link before trusting the content.
    ///
    /// The body is decoded from `raw`; the hash is recomputed from `raw`. A
    /// record whose stored hash disagrees is rejected rather than returned with
    /// a warning — a journal you cannot trust is worse than no journal, because
    /// it produces an audit trail that is quietly a lie.
    pub fn from_stored(raw: Vec<u8>, prev_hash: Digest, hash: Digest) -> Result<Self, StoreError> {
        Self::from_stored_attested(raw, prev_hash, hash, None)
    }

    /// Reconstruct, carrying whatever signature the store kept.
    pub fn from_stored_attested(
        raw: Vec<u8>,
        prev_hash: Digest,
        hash: Digest,
        attestation: Option<Attestation>,
    ) -> Result<Self, StoreError> {
        let recomputed = Digest::chain(prev_hash, &raw);
        if recomputed != hash {
            let seq = serde_json::from_slice::<serde_json::Map<String, Value>>(&raw)
                .ok()
                .and_then(|m| m.get("seq").and_then(Value::as_u64))
                .unwrap_or(0);
            return Err(StoreError::Corrupt {
                seq,
                detail: format!(
                    "hash mismatch: stored {hash:?}, recomputed {recomputed:?} — \
                     record was altered after it was written"
                ),
            });
        }
        let body: RecordBody = serde_json::from_slice(&raw)?;
        Ok(Self {
            body,
            prev_hash,
            hash,
            attestation,
            raw,
        })
    }

    /// The exact bytes covered by [`Self::hash`].
    #[must_use]
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    #[must_use]
    pub fn seq(&self) -> Seq {
        self.body.seq
    }

    #[must_use]
    pub fn kind(&self) -> &RecordKind {
        &self.body.kind
    }

    #[must_use]
    pub fn effect_key(&self) -> Option<EffectKey> {
        self.body.effect_key
    }

    /// Verify a contiguous run of records links correctly.
    ///
    /// Checks both the chain and the sequence: a gap means records were deleted,
    /// which the per-record hash alone would not catch.
    pub fn verify_chain(records: &[Self], from: Digest) -> Result<Digest, StoreError> {
        let mut prev = from;
        let start = records.first().map_or(1, Record::seq);
        for (expect_seq, r) in (start..).zip(records.iter()) {
            if r.seq() != expect_seq {
                return Err(StoreError::Corrupt {
                    seq: r.seq(),
                    detail: format!("sequence gap: expected {expect_seq}, found {}", r.seq()),
                });
            }
            if r.prev_hash != prev {
                return Err(StoreError::Corrupt {
                    seq: r.seq(),
                    detail: "broken link: prev_hash does not match predecessor".into(),
                });
            }
            let recomputed = Digest::chain(prev, &r.raw);
            if recomputed != r.hash {
                return Err(StoreError::Corrupt {
                    seq: r.seq(),
                    detail: "hash does not cover the stored bytes".into(),
                });
            }
            prev = r.hash;
        }
        Ok(prev)
    }

    /// Verify the chain **and** that a known key signed every record.
    ///
    /// Two separate questions, deliberately answered by two separate calls. The
    /// chain says the records are consistent with each other; the signatures say
    /// who wrote them. A caller that only runs [`Self::verify_chain`] is asking
    /// the weaker question, and this crate's own store does exactly that on
    /// every read — because a plane without a configured verifier has no basis
    /// to reject anything, and failing closed there would make signing
    /// impossible to adopt incrementally.
    ///
    /// `require_signature` is what stops that leniency becoming a hole. With it
    /// set, an unsigned record is a failure rather than a shrug — which is the
    /// posture an *auditor* wants, and the opposite of the one a plane resuming
    /// its own history wants.
    ///
    /// # Errors
    ///
    /// [`StoreError::Corrupt`] if the chain is broken, or [`AttestError`] as a
    /// corrupt-record detail if a signature is missing or wrong.
    pub fn verify_attested(
        records: &[Self],
        from: Digest,
        verifier: &dyn Verifier,
        require_signature: bool,
    ) -> Result<Digest, StoreError> {
        let head = Self::verify_chain(records, from)?;
        for r in records {
            match &r.attestation {
                Some(a) if verifier.verify(&a.key_id, &r.hash, &a.signature) => {}
                Some(a) => {
                    return Err(StoreError::Corrupt {
                        seq: r.seq(),
                        detail: AttestError::BadSignature {
                            seq: r.seq(),
                            key_id: a.key_id.clone(),
                        }
                        .to_string(),
                    });
                }
                None if require_signature => {
                    return Err(StoreError::Corrupt {
                        seq: r.seq(),
                        detail: AttestError::Unsigned { seq: r.seq() }.to_string(),
                    });
                }
                None => {}
            }
        }
        Ok(head)
    }
}

/// What the runtime hands the store. Seq, chain links, and hashing are the
/// store's job, because only it knows the run's current head.
#[derive(Debug, Clone)]
pub struct Append {
    pub run: RunId,
    pub case: Option<CaseId>,
    pub step: Option<StepId>,
    pub phase: Phase,
    pub effect_key: Option<EffectKey>,
    pub kind: RecordKind,
}

impl Append {
    pub fn new(run: RunId, kind: RecordKind) -> Self {
        Self {
            run,
            case: None,
            step: None,
            phase: Phase::Forward,
            effect_key: None,
            kind,
        }
    }

    #[must_use]
    pub fn step(mut self, s: StepId) -> Self {
        self.step = Some(s);
        self
    }

    #[must_use]
    pub fn phase(mut self, p: Phase) -> Self {
        self.phase = p;
        self
    }

    #[must_use]
    pub fn case(mut self, c: CaseId) -> Self {
        self.case = Some(c);
        self
    }

    #[must_use]
    pub fn effect(mut self, k: EffectKey) -> Self {
        self.effect_key = Some(k);
        self
    }

    /// Materialize into a body at a given position.
    ///
    /// Sealing a record is a store's job, so this has no callers in a build with
    /// no store compiled in.
    #[cfg(any(feature = "turso", test))]
    pub(crate) fn into_body(self, seq: Seq, epoch: Epoch) -> RecordBody {
        RecordBody {
            seq,
            run: self.run,
            case: self.case,
            step: self.step,
            phase: self.phase,
            epoch,
            v: self.kind.version(),
            effect_key: self.effect_key,
            kind: self.kind,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn body(seq: Seq, kind: RecordKind) -> RecordBody {
        RecordBody {
            seq,
            run: RunId::generate(),
            case: None,
            step: None,
            phase: Phase::Forward,
            epoch: 1,
            v: kind.version(),
            effect_key: None,
            kind,
        }
    }

    fn chain_of(n: u64) -> Vec<Record> {
        let mut prev = Digest::ZERO;
        let mut out = Vec::new();
        for i in 1..=n {
            let r = Record::seal(
                body(
                    i,
                    RecordKind::StepStarted {
                        skill: format!("s{i}"),
                    },
                ),
                prev,
            )
            .unwrap();
            prev = r.hash;
            out.push(r);
        }
        out
    }

    #[test]
    fn sealing_is_deterministic() {
        let b = body(1, RecordKind::StepStarted { skill: "x".into() });
        let a = Record::seal(b.clone(), Digest::ZERO).unwrap();
        let c = Record::seal(b, Digest::ZERO).unwrap();
        assert_eq!(
            a.hash, c.hash,
            "same body + same prev must hash identically"
        );
    }

    #[test]
    fn valid_chain_verifies() {
        let records = chain_of(5);
        let head = Record::verify_chain(&records, Digest::ZERO).unwrap();
        assert_eq!(head, records.last().unwrap().hash);
    }

    #[test]
    fn tampered_payload_is_detected() {
        let records = chain_of(3);
        let mut tampered = records.clone();
        // Rewrite the bytes without updating the hash — the classic edit.
        tampered[1].raw = b"{\"seq\":2,\"tampered\":true}".to_vec();
        let err = Record::verify_chain(&tampered, Digest::ZERO).unwrap_err();
        assert!(
            matches!(err, StoreError::Corrupt { seq: 2, .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn deleted_record_is_detected_as_a_gap() {
        let records = chain_of(4);
        let mut with_hole = records.clone();
        with_hole.remove(2);
        let err = Record::verify_chain(&with_hole, Digest::ZERO).unwrap_err();
        assert!(matches!(err, StoreError::Corrupt { .. }));
    }

    #[test]
    fn reordered_records_break_the_chain() {
        let mut records = chain_of(4);
        records.swap(1, 2);
        assert!(Record::verify_chain(&records, Digest::ZERO).is_err());
    }

    #[test]
    fn from_stored_rejects_a_hash_that_does_not_cover_the_bytes() {
        let r = chain_of(1).pop().unwrap();
        let err = Record::from_stored(b"{\"seq\":1}".to_vec(), Digest::ZERO, r.hash).unwrap_err();
        assert!(matches!(err, StoreError::Corrupt { .. }));
    }

    #[test]
    fn from_stored_roundtrips_a_genuine_record() {
        let r = chain_of(1).pop().unwrap();
        let back = Record::from_stored(r.raw().to_vec(), r.prev_hash, r.hash).unwrap();
        assert_eq!(back.body, r.body);
    }

    #[test]
    fn effect_records_carry_their_key() {
        let key = EffectKey::from_hex(&Digest::of(b"k").to_hex()).unwrap();
        let a = Append::new(
            RunId::generate(),
            RecordKind::EffectDone {
                output: json!(1),
                spend: Spend::default(),
            },
        )
        .effect(key);
        let rec = Record::seal(a.into_body(1, 1), Digest::ZERO).unwrap();
        assert_eq!(rec.effect_key(), Some(key));
    }
}
