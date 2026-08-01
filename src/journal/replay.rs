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
        spend: crate::core::Spend,
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
    /// Whether this step's history is used up.
    ///
    /// Once it is, the step continues live — which is exactly how a crashed run
    /// resumes mid-step rather than restarting it.
    #[must_use]
    pub fn exhausted(&self) -> bool {
        self.pos >= self.effects.len()
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
            let cursor = by_step.entry((step, r.body.phase)).or_default();

            match r.kind() {
                RecordKind::EffectStarted {
                    descriptor,
                    recovery,
                    ..
                } => {
                    cursor.effects.push((
                        key,
                        r.seq(),
                        EffectReplay::Orphan {
                            descriptor: Box::new(descriptor.clone()),
                            recovery: recovery.clone(),
                        },
                    ));
                }
                RecordKind::EffectDone { output, spend } => {
                    if let Some(slot) = cursor.effects.iter_mut().rev().find(|(k, _, _)| *k == key)
                    {
                        slot.2 = EffectReplay::Done {
                            output: output.clone(),
                            spend: *spend,
                        };
                    }
                }
                // A reconciliation verdict collapses into the vocabulary the
                // replay loop already speaks, so nothing downstream needs a
                // separate path for it:
                //
                //   Landed        -> the effect is done, with the recovered output
                //   DidNotHappen  -> a failure that is safe to repeat
                //   InDoubt       -> a failure that is not
                //
                // It overwrites whatever the attempt's earlier record said,
                // because the probe is the later and better-informed answer.
                RecordKind::EffectReconciled {
                    disposition,
                    output,
                    spend,
                    ..
                } => {
                    if let Some(slot) = cursor.effects.iter_mut().rev().find(|(k, _, _)| *k == key)
                    {
                        slot.2 = match (disposition, output) {
                            (Disposition::Landed, Some(output)) => EffectReplay::Done {
                                output: output.clone(),
                                spend: *spend,
                            },
                            (d, _) => EffectReplay::Failed {
                                error: "resolved by reconciliation".to_owned(),
                                disposition: *d,
                                spend: crate::core::Spend::default(),
                            },
                        };
                    }
                }
                // A refusal has no preceding `EffectStarted` — the whole point
                // is that nothing was announced — so it pushes its own entry
                // rather than updating one.
                RecordKind::BudgetRefused { limit, used } => {
                    cursor.effects.push((
                        key,
                        r.seq(),
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
                    cursor.effects.push((
                        key,
                        r.seq(),
                        EffectReplay::Denied {
                            reason: reason.clone(),
                            action: action.clone(),
                            resource: resource.clone(),
                        },
                    ));
                }
                RecordKind::EffectFailed {
                    error,
                    disposition,
                    spend,
                } => {
                    if let Some(slot) = cursor.effects.iter_mut().rev().find(|(k, _, _)| *k == key)
                    {
                        slot.2 = EffectReplay::Failed {
                            error: error.clone(),
                            disposition: *disposition,
                            spend: *spend,
                        };
                    }
                }
                _ => {}
            }
        }

        Self { by_step }
    }

    /// Total journaled effects across all steps.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_step.values().map(|c| c.effects.len()).sum()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
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
        self.by_step.values().all(|c| c.pos >= c.effects.len())
    }

    /// Whether this step's next journaled effect is `key`, without consuming it.
    ///
    /// Used to ask history a question it is the only authority on: after a
    /// recorded failure, did the run go on to retry? The answer is "the next
    /// effect is that attempt", and inferring it from the current retry policy
    /// instead would let a policy edit rewrite what happened.
    #[must_use]
    pub fn peek_is(&self, step: StepId, phase: Phase, key: EffectKey) -> bool {
        self.by_step
            .get(&(step, phase))
            .and_then(|c| c.effects.get(c.pos))
            .is_some_and(|(k, _, _)| *k == key)
    }

    /// Consume this step's next journaled effect, verifying it is the one being
    /// asked for.
    ///
    /// Returns `None` once the step's history is exhausted, meaning "perform
    /// this one live".
    pub fn next(
        &mut self,
        step: StepId,
        phase: Phase,
        recomputed: EffectKey,
    ) -> Result<Option<EffectReplay>, StepError> {
        let Some(cursor) = self.by_step.get_mut(&(step, phase)) else {
            return Ok(None);
        };
        let Some((expected, seq, replay)) = cursor.effects.get(cursor.pos) else {
            return Ok(None);
        };
        if *expected != recomputed {
            return Err(StepError::NonDeterminism {
                seq: *seq,
                expected: *expected,
                actual: recomputed,
            });
        }
        cursor.pos += 1;
        Ok(Some(replay.clone()))
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
        }
    }

    const S0: StepId = StepId(0);
    const S1: StepId = StepId(1);

    #[test]
    fn replays_a_completed_effect_without_performing_it() {
        let recs = records(vec![
            (S0, key(1), started()),
            (
                S0,
                key(1),
                RecordKind::EffectDone {
                    output: json!("recorded"),
                    spend: crate::core::Spend::default(),
                },
            ),
        ]);
        let mut cur = ReplayCursor::from_records(&recs);
        assert_eq!(
            cur.next(S0, Phase::Forward, key(1)).unwrap(),
            Some(EffectReplay::Done {
                output: json!("recorded"),
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
                    output: json!(1),
                    spend: crate::core::Spend::default(),
                },
            ),
        ]);
        let mut cur = ReplayCursor::from_records(&recs);
        assert!(matches!(
            cur.next(S0, Phase::Forward, key(99)).unwrap_err(),
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
                    output: json!(1),
                    spend: crate::core::Spend::default(),
                },
            ),
            (S0, key(2), started()),
            (
                S0,
                key(2),
                RecordKind::EffectDone {
                    output: json!(2),
                    spend: crate::core::Spend::default(),
                },
            ),
        ]);
        let mut cur = ReplayCursor::from_records(&recs);
        assert!(
            cur.next(S0, Phase::Forward, key(2)).is_err(),
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
                    output: json!("b"),
                    spend: crate::core::Spend::default(),
                },
            ),
            (
                S0,
                key(1),
                RecordKind::EffectDone {
                    output: json!("a"),
                    spend: crate::core::Spend::default(),
                },
            ),
        ]);
        let mut cur = ReplayCursor::from_records(&recs);

        // Step 0 asks first even though step 1 finished first in the journal.
        assert_eq!(
            cur.next(S0, Phase::Forward, key(1)).unwrap(),
            Some(EffectReplay::Done {
                output: json!("a"),
                spend: crate::core::Spend::default()
            })
        );
        assert_eq!(
            cur.next(S1, Phase::Forward, key(10)).unwrap(),
            Some(EffectReplay::Done {
                output: json!("b"),
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
                    output: json!(1),
                    spend: crate::core::Spend::default(),
                },
            ),
            (S1, key(10), started()),
            (
                S1,
                key(10),
                RecordKind::EffectDone {
                    output: json!(2),
                    spend: crate::core::Spend::default(),
                },
            ),
        ]);
        let mut cur = ReplayCursor::from_records(&recs);
        cur.next(S0, Phase::Forward, key(1)).unwrap();

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
        assert!(cur.is_empty());
    }

    #[test]
    fn exhausted_cursor_yields_none_so_execution_continues_live() {
        let recs = records(vec![
            (S0, key(1), started()),
            (
                S0,
                key(1),
                RecordKind::EffectDone {
                    output: json!(1),
                    spend: crate::core::Spend::default(),
                },
            ),
        ]);
        let mut cur = ReplayCursor::from_records(&recs);
        cur.next(S0, Phase::Forward, key(1)).unwrap();
        assert_eq!(
            cur.next(S0, Phase::Forward, key(2)).unwrap(),
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
        match cur.next(S0, Phase::Forward, key(1)).unwrap() {
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
                },
            ),
        ]);
        let mut cur = ReplayCursor::from_records(&recs);
        assert_eq!(
            cur.next(S0, Phase::Forward, key(1)).unwrap(),
            Some(EffectReplay::Failed {
                error: "boom".into(),
                disposition: Disposition::DidNotHappen,
                spend: crate::core::Spend::default(),
            })
        );
    }
}
