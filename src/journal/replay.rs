//! Replay: reading a run's history back instead of re-doing it.
//!
//! Replay re-executes the *deterministic* zone — plan traversal, guards, retry
//! decisions — and satisfies every effect from the journal. Nothing external is
//! touched: no tool is called twice, no invoice is issued twice, no clock is
//! read again.
//!
//! Two things can happen that are not "read the recorded output":
//!
//! * **Divergence.** The recomputed effect key differs from the journaled one,
//!   which means this code takes a different path than the code that produced
//!   the record. The run is quarantined. It is never allowed to continue, because
//!   a diverging replay silently rewrites history.
//! * **An orphan.** An `EffectStarted` with no terminal record — a crash landed
//!   between "sent the request" and "recorded the answer". Whether that is safe
//!   to re-run is undecidable from the journal, so the effect's declared
//!   [`Recovery`] decides, and the conservative default escalates to a human.
//!
//! # Order is verified per step, not globally
//!
//! Effect keys are derived from `(step, ordinal)`, so *ordinal* order is what
//! carries meaning — and ordinals restart in every step. A single globally
//! ordered cursor coincides with that only while a plan has one step; the moment
//! two steps interleave in the journal, a globally ordered cursor rejects a
//! perfectly faithful replay.
//!
//! Grouping by step is therefore not an optimisation but the correct
//! granularity. It also makes concurrent steps safe to replay: their journal
//! interleaving may differ run to run, and nothing downstream depends on it.

use std::collections::BTreeMap;

use crate::core::{
    Disposition, EffectDescriptor, EffectKey, Phase, Recovery, Seq, StepError, StepId,
};

use super::{Record, RecordKind};

/// What the journal has to say about one effect.
#[derive(Debug, Clone, PartialEq)]
pub enum EffectReplay {
    /// It completed; here is what it returned, and what it cost.
    ///
    /// The figure is recorded rather than recomputed, so a replayed run reaches
    /// the same budget verdict at the same point as the original.
    Done {
        output: serde_json::Value,
        /// Who sent it, when the effect was an awaited inbound event.
        ///
        /// Carried so a replayed run rebuilds the same provenance the live one
        /// had. Without it the two label the same value differently, and every
        /// taint gate downstream may reach a different verdict.
        source: Option<String>,
        spend: crate::core::Spend,
        /// The trust and sensitivity the effect declared when it landed.
        ///
        /// Read back for the same reason the spend is, and with a sharper
        /// consequence: these two are sourced from operator configuration
        /// rather than from code, so re-deriving them lets a catalogue edit
        /// relabel a value the run read months ago — with nothing diverging,
        /// because nothing about the call changed.
        declared: crate::core::DeclaredOutput,
    },
    /// It failed, and the failure is part of history — including what that
    /// failure said about whether the call reached the outside world.
    Failed {
        error: String,
        disposition: Disposition,
        /// What the attempt consumed before failing.
        ///
        /// Read back rather than recomputed so a replayed run reaches the same
        /// budget verdict at the same point — the same reason `Done` carries
        /// its spend.
        spend: crate::core::Spend,
        /// Whether the refusal was an answer no retry can change.
        ///
        /// Read back rather than recomputed for the same reason the
        /// disposition is: the retry decision is replayed, and a replay that
        /// could not see this bit would expect a retry the live run never
        /// made.
        permanent: bool,
    },
    /// A limit refused it before it started.
    ///
    /// Distinct from `Failed`: nothing was attempted, and the run stopped
    /// because it was told to rather than because something broke.
    Refused { limit: String, used: String },
    /// Policy refused it before it was attempted.
    ///
    /// Distinct from `Refused`, which is a *limit*. Both stop the run without
    /// attempting anything, and an operator's response to each is different: a
    /// budget is raised, a policy is argued with.
    Denied {
        reason: String,
        action: String,
        resource: String,
    },
    /// It started and we do not know whether it landed.
    Orphan {
        descriptor: Box<EffectDescriptor>,
        recovery: Recovery,
    },
}

/// One step's effects, in the order that step performed them.
///
/// Owned by the step that is replaying it rather than borrowed from a shared
/// map. That is what lets steps run concurrently: a step touches only its own
/// history, so handing each one its slice removes the last shared mutable state
/// between them.
#[derive(Debug, Clone, Default)]
pub struct StepCursor {
    effects: Vec<(EffectKey, Seq, EffectReplay)>,
    pos: usize,
}

impl StepCursor {
    /// Overwrite the most recent slot for `key` with a terminal replay state.
    ///
    /// Newest-first because a retried effect has one slot per attempt, and a
    /// terminal record always describes the latest one. One implementation
    /// rather than the same `iter_mut().rev().find(..)` at three call sites,
    /// where the fourth copy would be the one written subtly differently.
    fn settle(&mut self, key: EffectKey, state: EffectReplay) {
        if let Some(slot) = self.effects.iter_mut().rev().find(|(k, _, _)| *k == key) {
            slot.2 = state;
        }
    }

    /// Fold one record into this step's replay sequence.
    fn apply(&mut self, key: EffectKey, seq: Seq, kind: &RecordKind) {
        match kind {
            RecordKind::EffectStarted {
                descriptor,
                recovery,
                ..
            } => {
                self.effects.push((
                    key,
                    seq,
                    EffectReplay::Orphan {
                        descriptor: Box::new(descriptor.clone()),
                        recovery: recovery.clone(),
                    },
                ));
            }
            RecordKind::EffectDone {
                output,
                source,
                spend,
                declared,
            } => {
                self.settle(
                    key,
                    EffectReplay::Done {
                        output: output.clone(),
                        source: source.clone(),
                        spend: *spend,
                        declared: *declared,
                    },
                );
            }
            RecordKind::EffectReconciled {
                disposition,
                output,
                spend,
                declared,
                ..
            } => {
                self.settle(
                    key,
                    Self::reconciled(*disposition, output.as_ref(), *spend, *declared),
                );
            }
            // A refusal has no preceding `EffectStarted` — the whole point
            // is that nothing was announced — so it pushes its own entry
            // rather than updating one.
            RecordKind::BudgetRefused { limit, used } => {
                self.effects.push((
                    key,
                    seq,
                    EffectReplay::Refused {
                        limit: limit.clone(),
                        used: used.clone(),
                    },
                ));
            }
            RecordKind::PolicyDenied {
                reason,
                action,
                resource,
            } => {
                self.effects.push((
                    key,
                    seq,
                    EffectReplay::Denied {
                        reason: reason.clone(),
                        action: action.clone(),
                        resource: resource.clone(),
                    },
                ));
            }
            RecordKind::Released { .. } => self.record_release(key, seq),
            RecordKind::EffectFailed {
                error,
                disposition,
                spend,
                permanent,
            } => {
                self.settle(
                    key,
                    EffectReplay::Failed {
                        error: error.clone(),
                        disposition: *disposition,
                        spend: *spend,
                        permanent: *permanent,
                    },
                );
            }
            _ => {}
        }
    }

    /// A reconciliation verdict, in the vocabulary the replay loop already
    /// speaks — so nothing downstream needs a separate path for it:
    ///
    ///   `Landed`       -> the effect is done, with the recovered output
    ///   `DidNotHappen` -> a failure that is safe to repeat
    ///   `InDoubt`      -> a failure that is not
    ///
    /// It overwrites whatever the attempt's earlier record said, because the
    /// probe is the later and better-informed answer.
    fn reconciled(
        disposition: Disposition,
        output: Option<&serde_json::Value>,
        spend: crate::core::Spend,
        declared: Option<crate::core::DeclaredOutput>,
    ) -> EffectReplay {
        match (disposition, output) {
            (Disposition::Landed, Some(output)) => EffectReplay::Done {
                output: output.clone(),
                source: None,
                spend,
                // A `Landed` verdict without a declaration is a record this
                // runtime does not write. Reading it as trusted would be the
                // relabel the field exists to stop, so the conservative point
                // stands in.
                declared: declared.unwrap_or_else(crate::core::DeclaredOutput::untrusted),
            },
            (disposition, _) => EffectReplay::Failed {
                error: "resolved by reconciliation".to_owned(),
                disposition,
                spend: crate::core::Spend::default(),
                permanent: false,
            },
        }
    }

    fn record_release(&mut self, key: EffectKey, seq: Seq) {
        self.effects.push((
            key,
            seq,
            EffectReplay::Done {
                output: serde_json::Value::Null,
                source: None,
                spend: crate::core::Spend::default(),
                // A release records no value of its own to label: the released
                // value belongs to the caller and its new label is in the
                // `Released` record. The conservative point keeps this from
                // being the one synthesized `Done` that means *trusted*.
                declared: crate::core::DeclaredOutput::untrusted(),
            },
        ));
    }

    /// Whether this step's history is used up.
    ///
    /// Once it is, the step continues live — which is exactly how a crashed run
    /// resumes mid-step rather than restarting it.
    #[must_use]
    pub fn exhausted(&self) -> bool {
        self.pos >= self.effects.len()
    }

    /// The first journaled effect nothing has consumed, if any.
    ///
    /// The strict verifier's witness: a build that performs *fewer* effects
    /// than the record leaves this non-empty at the end, and the finding must
    /// name the key rather than merely count — an operator hunting a missing
    /// effect needs to know which one went missing.
    #[must_use]
    pub fn first_unconsumed(&self) -> Option<EffectKey> {
        self.effects.get(self.pos).map(|(k, _, _)| *k)
    }

    /// Whether the next journaled effect is `key`, without consuming it.
    ///
    /// Used to ask history a question it is the only authority on: after a
    /// recorded failure, did the run go on to retry? The answer is "the next
    /// effect is that attempt", and inferring it from the current retry policy
    /// instead would let a policy edit rewrite what happened.
    #[must_use]
    pub fn peek_is(&self, key: EffectKey) -> bool {
        self.effects
            .get(self.pos)
            .is_some_and(|(k, _, _)| *k == key)
    }

    /// Consume the next journaled effect, verifying it is the one being asked
    /// for.
    ///
    /// Returns `None` once history is exhausted, meaning "perform this one
    /// live".
    pub fn next(&mut self, recomputed: EffectKey) -> Result<Option<EffectReplay>, StepError> {
        let Some((expected, seq, replay)) = self.effects.get(self.pos) else {
            return Ok(None);
        };
        if *expected != recomputed {
            return Err(StepError::NonDeterminism {
                seq: *seq,
                expected: *expected,
                actual: recomputed,
            });
        }
        self.pos += 1;
        Ok(Some(replay.clone()))
    }
}

/// A read cursor over one run's journaled effects.
///
/// Order is checked, not just membership. A step that performs the same effects
/// in a different sequence has diverged just as surely as one that performs
/// different effects, and only ordered verification catches it.
#[derive(Debug, Clone, Default)]
pub struct ReplayCursor {
    /// Keyed by step **and phase**.
    ///
    /// Phase is not decoration here. A step's forward pass and its compensation
    /// are different work with different effect keys, and they can be replayed
    /// in either order — a run that is cancelled before its steps are
    /// re-dispatched compensates a step whose forward history is still
    /// unconsumed. Sharing one cursor between the two makes the compensating
    /// effect read the forward record and report non-determinism against
    /// history that is perfectly sound.
    by_step: BTreeMap<(StepId, Phase), StepCursor>,
}

impl ReplayCursor {
    /// Build from a run's records.
    #[must_use]
    pub fn from_records(records: &[Record]) -> Self {
        let mut by_step: BTreeMap<(StepId, Phase), StepCursor> = BTreeMap::new();

        for r in records {
            let Some(key) = r.effect_key() else { continue };
            // An effect without a step cannot be attributed, so it cannot be
            // replayed in order. Skipping it would silently drop history, so it
            // is treated as belonging to step 0 — which is where the runtime
            // puts effects it writes on a run's behalf.
            let step = r.body.step.unwrap_or(StepId(0));
            by_step
                .entry((step, r.body.phase))
                .or_default()
                .apply(key, r.seq(), r.kind());
        }

        Self { by_step }
    }

    /// Detach a step's history so the step can own it.
    ///
    /// Returns an empty cursor for a step with no recorded effects, which is
    /// the normal case for a live run.
    #[must_use]
    pub fn take(&mut self, step: StepId, phase: Phase) -> StepCursor {
        self.by_step.remove(&(step, phase)).unwrap_or_default()
    }

    /// Return a step's history after it has finished with it.
    pub fn restore(&mut self, step: StepId, phase: Phase, cursor: StepCursor) {
        self.by_step.insert((step, phase), cursor);
    }

    /// Whether this step's history is used up.
    #[must_use]
    pub fn exhausted(&self, step: StepId, phase: Phase) -> bool {
        self.by_step
            .get(&(step, phase))
            .is_none_or(StepCursor::exhausted)
    }

    /// Whether *any* step still has unread history.
    #[must_use]
    pub fn fully_exhausted(&self) -> bool {
        self.by_step.values().all(StepCursor::exhausted)
    }

    /// The first journaled effect nothing has consumed, with the step and
    /// phase it belongs to — the strict verifier's witness that this build
    /// performs fewer effects than the record.
    #[must_use]
    pub fn first_unconsumed(&self) -> Option<(StepId, Phase, EffectKey)> {
        self.by_step.iter().find_map(|((step, phase), cursor)| {
            cursor.first_unconsumed().map(|k| (*step, *phase, k))
        })
    }

    /// The first unconsumed effect in one `(step, phase)` slice, if any.
    #[must_use]
    pub fn unconsumed_in(&self, step: StepId, phase: Phase) -> Option<EffectKey> {
        self.by_step
            .get(&(step, phase))
            .and_then(StepCursor::first_unconsumed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{Digest, RunId};
    use crate::journal::Append;
    use serde_json::json;

    fn key(n: u8) -> EffectKey {
        EffectKey::from_hex(&Digest::of(&[n]).to_hex()).unwrap()
    }

    fn desc() -> EffectDescriptor {
        EffectDescriptor::nullary("test.effect")
    }

    fn records(entries: Vec<(StepId, EffectKey, RecordKind)>) -> Vec<Record> {
        let run = RunId::generate();
        let mut prev = Digest::ZERO;
        let mut out = Vec::new();
        for (i, (step, k, kind)) in entries.into_iter().enumerate() {
            let a = Append::new(run, kind).effect(k).step(step);
            let r = Record::seal(a.into_body(i as u64 + 1, 1), prev).unwrap();
            prev = r.hash;
            out.push(r);
        }
        out
    }

    fn started() -> RecordKind {
        RecordKind::EffectStarted {
            descriptor: desc(),
            recovery: Recovery::Retry,
            mutates: false,
            attempt: 1,
            backoff_ms: 0,
            outbound_label: None,
        }
    }

    const S0: StepId = StepId(0);
    const S1: StepId = StepId(1);

    /// Consume one step's next effect the way the runtime does: detach the
    /// step's slice, ask it, hand it back.
    fn next(
        cur: &mut ReplayCursor,
        step: StepId,
        key: EffectKey,
    ) -> Result<Option<EffectReplay>, StepError> {
        let mut slice = cur.take(step, Phase::Forward);
        let out = slice.next(key);
        cur.restore(step, Phase::Forward, slice);
        out
    }

    #[test]
    fn replays_a_completed_effect_without_performing_it() {
        let recs = records(vec![
            (S0, key(1), started()),
            (
                S0,
                key(1),
                RecordKind::EffectDone {
                    declared: crate::core::DeclaredOutput::untrusted(),
                    output: json!("recorded"),
                    source: None,
                    spend: crate::core::Spend::default(),
                },
            ),
        ]);
        let mut cur = ReplayCursor::from_records(&recs);
        assert_eq!(
            next(&mut cur, S0, key(1)).unwrap(),
            Some(EffectReplay::Done {
                declared: crate::core::DeclaredOutput::untrusted(),
                output: json!("recorded"),
                source: None,
                spend: crate::core::Spend::default()
            })
        );
        assert!(cur.exhausted(S0, Phase::Forward));
    }

    /// The critical safety property: a replay that would take a different path
    /// stops rather than quietly rewriting history.
    #[test]
    fn divergent_key_is_rejected() {
        let recs = records(vec![
            (S0, key(1), started()),
            (
                S0,
                key(1),
                RecordKind::EffectDone {
                    declared: crate::core::DeclaredOutput::untrusted(),
                    output: json!(1),
                    source: None,
                    spend: crate::core::Spend::default(),
                },
            ),
        ]);
        let mut cur = ReplayCursor::from_records(&recs);
        assert!(matches!(
            next(&mut cur, S0, key(99)).unwrap_err(),
            StepError::NonDeterminism { .. }
        ));
    }

    /// Same effects, wrong order within a step, is still divergence.
    #[test]
    fn reordered_effects_within_a_step_are_rejected() {
        let recs = records(vec![
            (S0, key(1), started()),
            (
                S0,
                key(1),
                RecordKind::EffectDone {
                    declared: crate::core::DeclaredOutput::untrusted(),
                    output: json!(1),
                    source: None,
                    spend: crate::core::Spend::default(),
                },
            ),
            (S0, key(2), started()),
            (
                S0,
                key(2),
                RecordKind::EffectDone {
                    declared: crate::core::DeclaredOutput::untrusted(),
                    output: json!(2),
                    source: None,
                    spend: crate::core::Spend::default(),
                },
            ),
        ]);
        let mut cur = ReplayCursor::from_records(&recs);
        assert!(
            next(&mut cur, S0, key(2)).is_err(),
            "order within a step is verified"
        );
    }

    /// **The property a global cursor gets wrong.**
    ///
    /// Two steps interleaved in the journal must each replay against their own
    /// history. A single global cursor would see step 1's effect where step 0's
    /// was expected and reject a perfectly faithful replay.
    #[test]
    fn steps_replay_independently_of_journal_interleaving() {
        let recs = records(vec![
            (S0, key(1), started()),
            (S1, key(10), started()),
            (
                S1,
                key(10),
                RecordKind::EffectDone {
                    declared: crate::core::DeclaredOutput::untrusted(),
                    output: json!("b"),
                    source: None,
                    spend: crate::core::Spend::default(),
                },
            ),
            (
                S0,
                key(1),
                RecordKind::EffectDone {
                    declared: crate::core::DeclaredOutput::untrusted(),
                    output: json!("a"),
                    source: None,
                    spend: crate::core::Spend::default(),
                },
            ),
        ]);
        let mut cur = ReplayCursor::from_records(&recs);

        // Step 0 asks first even though step 1 finished first in the journal.
        assert_eq!(
            next(&mut cur, S0, key(1)).unwrap(),
            Some(EffectReplay::Done {
                declared: crate::core::DeclaredOutput::untrusted(),
                output: json!("a"),
                source: None,
                spend: crate::core::Spend::default()
            })
        );
        assert_eq!(
            next(&mut cur, S1, key(10)).unwrap(),
            Some(EffectReplay::Done {
                declared: crate::core::DeclaredOutput::untrusted(),
                output: json!("b"),
                source: None,
                spend: crate::core::Spend::default()
            })
        );
        assert!(cur.fully_exhausted());
    }

    /// One step running out of history does not make another step's history
    /// unavailable.
    #[test]
    fn exhaustion_is_per_step() {
        let recs = records(vec![
            (S0, key(1), started()),
            (
                S0,
                key(1),
                RecordKind::EffectDone {
                    declared: crate::core::DeclaredOutput::untrusted(),
                    output: json!(1),
                    source: None,
                    spend: crate::core::Spend::default(),
                },
            ),
            (S1, key(10), started()),
            (
                S1,
                key(10),
                RecordKind::EffectDone {
                    declared: crate::core::DeclaredOutput::untrusted(),
                    output: json!(2),
                    source: None,
                    spend: crate::core::Spend::default(),
                },
            ),
        ]);
        let mut cur = ReplayCursor::from_records(&recs);
        next(&mut cur, S0, key(1)).unwrap();

        assert!(cur.exhausted(S0, Phase::Forward));
        assert!(
            !cur.exhausted(S1, Phase::Forward),
            "step 1 still has history to replay"
        );
        assert!(!cur.fully_exhausted());
    }

    #[test]
    fn an_unknown_step_has_no_history() {
        let cur = ReplayCursor::from_records(&[]);
        assert!(cur.exhausted(StepId(7), Phase::Forward));
        assert!(cur.fully_exhausted());
        assert!(cur.first_unconsumed().is_none());
    }

    #[test]
    fn exhausted_cursor_yields_none_so_execution_continues_live() {
        let recs = records(vec![
            (S0, key(1), started()),
            (
                S0,
                key(1),
                RecordKind::EffectDone {
                    declared: crate::core::DeclaredOutput::untrusted(),
                    output: json!(1),
                    source: None,
                    spend: crate::core::Spend::default(),
                },
            ),
        ]);
        let mut cur = ReplayCursor::from_records(&recs);
        next(&mut cur, S0, key(1)).unwrap();
        assert_eq!(
            next(&mut cur, S0, key(2)).unwrap(),
            None,
            "resume runs the rest live"
        );
    }

    /// A crash between "sent" and "recorded" leaves this shape, and it must be
    /// recognisable — the runtime decides what to do from the declared recovery.
    #[test]
    fn orphaned_start_is_surfaced_with_its_recovery_mode() {
        let recs = records(vec![(S0, key(1), started())]);
        let mut cur = ReplayCursor::from_records(&recs);
        match next(&mut cur, S0, key(1)).unwrap() {
            Some(EffectReplay::Orphan { recovery, .. }) => {
                assert!(matches!(recovery, Recovery::Retry));
            }
            other => panic!("expected orphan, got {other:?}"),
        }
    }

    #[test]
    fn failure_is_part_of_history() {
        let recs = records(vec![
            (S0, key(1), started()),
            (
                S0,
                key(1),
                RecordKind::EffectFailed {
                    error: "boom".into(),
                    disposition: Disposition::DidNotHappen,
                    spend: crate::core::Spend::default(),
                    permanent: false,
                },
            ),
        ]);
        let mut cur = ReplayCursor::from_records(&recs);
        assert_eq!(
            next(&mut cur, S0, key(1)).unwrap(),
            Some(EffectReplay::Failed {
                error: "boom".into(),
                disposition: Disposition::DidNotHappen,
                spend: crate::core::Spend::default(),
                permanent: false,
            })
        );
    }
}
