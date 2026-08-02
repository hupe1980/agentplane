//! [`StepCtx`] — the only door out of a skill.
//!
//! Everything non-deterministic or externally visible passes through here, and
//! that is what makes replay sound. A skill holds no clock, no socket, and no
//! RNG of its own; it holds a context that journals.

use std::sync::{Arc, Mutex};

use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use serde_json::Value;

use crate::case::{CaseStore, EventStore, TaskStore, TimerStore};
use crate::core::{
    AwaitSpec, Calendar, CaseId, CaseStatus, CaseVersion, CorrelationKey, Deadline, DeadlineSpec,
    DeadlineState, Decision, Effect, EffectDescriptor, EffectKey, Epoch, Ledger, OnExpiry, Phase,
    PolicyError, RunId, StepError, StepId, Subscription, Tainted, Task, TaskId, TaskSpec,
    TaskState, Timestamp, canon,
};

/// The event kind a decision arrives as.
///
/// Human tasks reuse the durable-wait machinery wholesale: completing a task
/// delivers an event of this kind correlated to the task id, and the waiting run
/// resumes exactly as it would for any other message.
pub(crate) const TASK_DECIDED: &str = "agentplane.task.decided";
use crate::journal::{Append, EffectReplay, JournalStore, RecordKind, StepCursor};

use super::effects::{Clock, ResolveDeadline};
use super::metrics;
use super::telemetry;
use tracing::Instrument;

/// The case-facing services a step may reach, when the runtime has them.
#[derive(Clone)]
pub(crate) struct CaseContext {
    pub cases: Arc<dyn CaseStore>,
    /// Only human tasks need this.
    pub tasks: Option<Arc<dyn TaskStore>>,
    /// Only durable waits need this. Correlation, state, and obligations work
    /// without it, so a runtime that never waits is not made to configure one.
    pub events: Option<Arc<dyn EventStore>>,
    pub calendar: Arc<dyn Calendar>,
    pub case_id: CaseId,
}

impl CaseContext {
    pub(crate) fn id(&self) -> CaseId {
        self.case_id
    }
}

impl std::fmt::Debug for CaseContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaseContext")
            .field("case_id", &self.case_id)
            .finish_non_exhaustive()
    }
}

/// How a step is being executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Normal execution: effects are performed and journaled.
    Live,
    /// Re-execution from history. Effects are read back, never performed.
    ///
    /// When the cursor runs out, execution continues live — which is exactly
    /// how a crashed run resumes mid-flight instead of starting over.
    ///
    /// **Resume is for crashes, not for code changes.** It requires the journal
    /// to be a *prefix* of what the current code does. A journal written by a
    /// different program is divergence, and the run is quarantined rather than
    /// continued — which is the desired outcome, not a limitation. Continuing
    /// would graft new behaviour onto a history that never produced it, and the
    /// resulting audit trail would be a plausible lie.
    ///
    /// To run changed code against recorded inputs, use [`Mode::Strict`] as a
    /// regression check and start a fresh run for real work.
    Resume,
    /// Verification. Reaching the end of history is itself a failure, because it
    /// means this build does more than the recorded one did.
    Strict,
}

impl Mode {
    #[must_use]
    pub fn is_replaying(self) -> bool {
        matches!(self, Self::Resume | Self::Strict)
    }
}

/// What a step needs to know about itself.
///
/// Gathered into a struct because the alternative was eight positional
/// arguments, several of them the same shape — an ordering mistake waiting to
/// compile cleanly.
#[derive(Debug)]
pub(crate) struct Frame {
    pub run: RunId,
    pub epoch: Epoch,
    pub step: StepId,
    /// Whether this frame is doing the work or undoing it.
    pub phase: Phase,
    pub mode: Mode,
    pub case: Option<CaseContext>,
    /// Durable wake-ups. Deliberately *not* inside `CaseContext`: a timer has
    /// nothing to correlate and no business horizon to bound it, so requiring a
    /// case would deny durable sleep to exactly the plain runs that most want
    /// it — including a retry backing off past the point where holding a worker
    /// is reasonable.
    pub timers: Option<Arc<dyn TimerStore>>,
    pub ledger: Arc<Mutex<Ledger>>,
    /// The authorization engine, if this plane has one.
    ///
    /// `None` means no policy layer — which is the same behaviour as a
    /// permissive engine, and deliberately the only way to spell it. See
    /// `core::policy` on why there is no `AllowAll`.
    pub policy: Option<Arc<dyn crate::core::PolicyEngine>>,
    /// The chain this run acts under, for the policy context.
    pub identity: Option<crate::core::Delegation>,
    /// Who is acting, for the policy principal.
    pub agent: String,
    /// The plane's workload identity, for signing what it tells a callee.
    ///
    /// Separate from the store's signer even though a deployment should give
    /// both the same one: the store signs *records*, this signs *outward
    /// claims*, and a plane can legitimately have one without the other.
    pub signer: Option<Arc<dyn crate::core::Signer>>,
}

/// Per-step execution context.
#[derive(Debug)]
pub struct StepCtx<'a> {
    store: &'a Arc<dyn JournalStore>,
    run: RunId,
    epoch: Epoch,
    step: StepId,
    phase: Phase,
    ordinal: u32,
    mode: Mode,
    cursor: StepCursor,
    rng: ChaCha8Rng,
    case: Option<CaseContext>,
    timers: Option<Arc<dyn TimerStore>>,
    /// The run's budget. Shared because it spans steps; a step never gets its
    /// own allowance to blow.
    ledger: Arc<Mutex<Ledger>>,
    policy: Option<Arc<dyn crate::core::PolicyEngine>>,
    identity: Option<crate::core::Delegation>,
    agent: String,
    signer: Option<Arc<dyn crate::core::Signer>>,
}

impl<'a> StepCtx<'a> {
    pub(crate) fn new(store: &'a Arc<dyn JournalStore>, cursor: StepCursor, frame: Frame) -> Self {
        let Frame {
            run,
            epoch,
            step,
            phase,
            mode,
            case,
            timers,
            ledger,
            policy,
            identity,
            agent,
            signer,
        } = frame;
        Self {
            store,
            run,
            epoch,
            step,
            phase,
            ordinal: 0,
            mode,
            cursor,
            rng: seeded_rng(run, step),
            case,
            timers,
            ledger,
            policy,
            identity,
            agent,
            signer,
        }
    }

    /// What this run tells a callee about itself, sealed for one call.
    ///
    /// Unsigned when the plane has no workload identity, which is honest: a
    /// self-signed block would look attested and prove nothing, the same
    /// reasoning that leaves unsigned journal records unsigned.
    fn provenance(&self, key: EffectKey, descriptor: &EffectDescriptor) -> crate::core::Provenance {
        let block = crate::core::Provenance::new(self.run, key, self.agent.clone())
            .in_case(self.case.as_ref().map(|c| c.case_id));
        match &self.signer {
            Some(signer) => block.seal(signer.as_ref(), &descriptor.kind, &descriptor.args),
            None => block,
        }
    }

    /// Hand the step's history back once it has finished with it.
    pub(crate) fn into_cursor(self) -> StepCursor {
        self.cursor
    }

    #[must_use]
    pub fn run_id(&self) -> RunId {
        self.run
    }

    #[must_use]
    pub fn step_id(&self) -> StepId {
        self.step
    }

    #[must_use]
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// What this run has consumed so far, and against what limits.
    #[must_use]
    pub fn budget(&self) -> crate::core::Consumed {
        self.ledger.lock().expect("budget mutex").consumed()
    }

    /// Count one dispatched effect and add what it consumed.
    ///
    /// Called for failures as well as successes, with a zero spend, because a
    /// call that failed still *happened*: it took a slot against `max_effects`,
    /// and a budget that only counted successes could never bound a call that
    /// fails every time. Replay bills the same way from the same records, so the
    /// two paths reach the same verdict at the same point.
    ///
    /// A separate function so the guard's scope is a single statement and cannot
    /// accidentally span an await.
    fn bill(&self, spend: crate::core::Spend) {
        self.ledger
            .lock()
            .expect("budget mutex")
            .record_effect(spend);
    }

    /// A deterministic random source.
    ///
    /// Seeded from `(run_id, step)` rather than journaled per draw: the sequence
    /// is reproducible by construction, so replay reproduces it for free and the
    /// journal carries no entropy records at all. Cheaper *and* stronger than
    /// recording each value — there is no way for the recorded and recomputed
    /// streams to disagree.
    pub fn rng(&mut self) -> &mut impl rand::Rng {
        &mut self.rng
    }

    /// The current instant, as a journaled effect.
    ///
    /// On replay this returns the instant the original run saw, not the instant
    /// now — which is why a replayed run makes the same time-dependent decisions
    /// as the run it is reproducing.
    pub async fn now(&mut self) -> Result<Timestamp, StepError> {
        Ok(self.effect(Clock).await?.into_unlabelled())
    }

    /// Record structured reasoning in the journal, adjacent to the effects it
    /// explains.
    ///
    /// Adjacency is the point: a note next to the action it claims to justify
    /// makes reasoning-versus-action mismatch detectable after the fact and
    /// testable under replay. A summary written at the end of a run cannot do
    /// that, because by then the ordering evidence is gone.
    pub async fn note(&mut self, text: impl Into<String>) -> Result<(), StepError> {
        self.append(RecordKind::Note { text: text.into() }).await
    }

    /// Perform (or replay) an effect, repeating it if it fails and repeating is
    /// safe.
    ///
    /// The whole determinism boundary is this function.
    ///
    /// # Why one loop covers both replay and live execution
    ///
    /// A retry sequence is history like any other. Each attempt has its own
    /// effect key (the attempt number is hashed in), so the journal holds
    /// attempts 1..N as ordinary consecutive effects, and replay walks them the
    /// same way it walks anything else. There is no separate "replay the
    /// retries" path to drift out of sync with the live one.
    ///
    /// # History outranks policy
    ///
    /// While history has attempts left, they are consumed regardless of what
    /// the current [`RetryPolicy`](crate::core::RetryPolicy) says. A run that made four attempts under
    /// yesterday's policy still made four attempts, and a replay under a
    /// two-attempt policy that stopped early would leave unconsumed records and
    /// report divergence for a run that did nothing wrong. The policy governs
    /// only what happens *after* history runs out.
    /// # The result is labelled
    ///
    /// An effect is how the deterministic zone reaches the outside world, so
    /// what comes back *is* the outside world's data. It arrives as
    /// [`Tainted`], labelled from the effect's own [`Effect::trust`]
    /// declaration — which defaults to untrusted.
    ///
    /// That is what makes §12's architecture hold rather than merely be
    /// described. A tool result flowing into a downstream step's input is
    /// labelled automatically, so the replan refusal and the taint gate see it
    /// without the skill author having to remember; and a skill that wants to
    /// treat a tool response as trusted has to say so, in a call that leaves a
    /// record.
    pub async fn effect<E: Effect>(&mut self, effect: E) -> Result<Tainted<E::Output>, StepError> {
        let trust = effect.trust();
        let declared = effect.output_sensitivity();
        let kind = effect.descriptor().kind;
        let output = self.effect_unlabelled(effect).await?;

        let labelled = match trust {
            crate::core::Trust::Trusted => Tainted::trusted(output),
            crate::core::Trust::Untrusted => {
                Tainted::from_source(output, crate::core::SourceId::new(format!("effect:{kind}")))
            }
        };
        // Raised, never lowered: an untrusted result is already `Internal`, and
        // an effect that could declare its output *less* sensitive than its
        // provenance implies would be a laundering primitive.
        let sensitivity = labelled.label().sensitivity.max(declared);
        let label = labelled.label().clone().with_sensitivity(sensitivity);
        Ok(Tainted::with_label(labelled.into_unlabelled(), label))
    }

    /// The effect protocol itself, before the result is labelled.
    ///
    /// Split out so the label is applied at exactly one place: a second exit
    /// from this function that forgot to wrap would be an unlabelled tool
    /// result, which is the hole the labelling exists to close.
    async fn effect_unlabelled<E: Effect>(
        &mut self,
        mut effect: E,
    ) -> Result<E::Output, StepError> {
        let descriptor = effect.descriptor();
        let policy = effect.retry();
        let recovery = effect.recovery();
        let ordinal = self.ordinal;
        self.ordinal += 1;

        let mut attempt: u32 = 1;
        loop {
            let key = EffectKey::derive(
                self.step,
                self.phase,
                ordinal,
                attempt,
                &descriptor.kind,
                &canon::value_bytes(&descriptor.args),
            );

            // Hand the effect what it needs to identify itself to a callee.
            // After the key is derived and before anything is announced: the key
            // is part of the block, and the block is signed for *this* call.
            effect.attach(&self.provenance(key, &descriptor));

            // ── Replay: is this attempt already in history? ────────────────
            if self.mode.is_replaying() {
                match self.cursor.next(key)? {
                    Some(EffectReplay::Done { output, spend }) => {
                        self.replayed_done(&descriptor.kind, attempt, spend);
                        return Ok(serde_json::from_value(output)?);
                    }
                    // The recorded run was refused here, so this one is too —
                    // whatever budget is in force now. The verdict is history.
                    Some(EffectReplay::Refused { limit, used }) => {
                        return Err(StepError::Budget(crate::core::BudgetExceeded::Recorded {
                            limit,
                            used,
                        }));
                    }
                    // The recorded run was refused here, so this one is too —
                    // whatever the policy set says now. Re-evaluating would
                    // re-judge last year's run under this year's rules.
                    Some(EffectReplay::Denied {
                        reason,
                        action,
                        resource,
                    }) => {
                        return Err(StepError::Denied {
                            action,
                            resource,
                            reason,
                        });
                    }
                    Some(EffectReplay::Failed {
                        error,
                        disposition,
                        spend,
                    }) => {
                        // Billed on the way past, exactly as the live path bills
                        // it: a replayed run must reach the same budget verdict
                        // at the same point, and a metered failure is part of
                        // what the original run spent.
                        self.bill(spend);
                        attempt = self.recorded_failure(
                            &descriptor,
                            ordinal,
                            attempt,
                            key,
                            &recovery,
                            &policy,
                            &error,
                            disposition,
                        )?;
                        continue;
                    }
                    Some(EffectReplay::Orphan { recovery, .. }) => {
                        return self.resolve_orphan(&effect, key, attempt, &recovery).await;
                    }
                    // History exhausted: this attempt runs live, unless a
                    // strict pass is verifying — where reaching the end is
                    // itself the finding.
                    None if self.mode == Mode::Strict => {
                        return Err(StepError::ReplayOverrun { actual: key });
                    }
                    None => {}
                }
            }

            // ── Live ───────────────────────────────────────────────────────
            //
            // Admission is checked per attempt, not once per effect. A retry is
            // a real call that costs real money, and a budget that only counted
            // the first one would be a ceiling a retry storm walks straight
            // through.
            //
            // Checked *before* dispatch: the point of a budget is to stop the
            // spending, not to notice it. Only live execution is gated —
            // replay must reproduce whatever the original run did, or history
            // would change shape with the limit in force when you replayed it.
            //
            // Compensation is exempt. Refusing to undo because the ceiling was
            // reached is how a run ends with a charged card and no order — the
            // ceiling exists to bound work, not to strand it half-done. The
            // spend is still billed and journaled, so the overshoot is visible
            // rather than silent.
            self.gate(key, &descriptor, effect.mutates()).await?;

            let backoff = policy.backoff(self.run, key, attempt);
            if !backoff.is_zero() {
                tokio::time::sleep(backoff).await;
            }
            let waited = u64::try_from(backoff.as_millis()).unwrap_or(u64::MAX);

            let failure = match self.traced_attempt(&effect, key, attempt, waited).await? {
                Ok(output) => return Ok(output),
                Err(e) => e,
            };

            // An in-doubt failure on a reconcilable effect is a question, not a
            // verdict. Ask before deciding.
            let mut disposition = failure.disposition();
            if disposition == crate::core::Disposition::InDoubt
                && matches!(recovery, crate::core::Recovery::Reconcile)
            {
                match self.reconcile_and_record(&effect, key).await? {
                    crate::core::Reconciliation::Landed(output) => return Ok(output),
                    resolved => disposition = resolved.disposition(),
                }
            }

            if let Some(stop) = Self::stop_reason(
                disposition,
                &recovery,
                key,
                attempt,
                &policy,
                &failure.to_string(),
            ) {
                return Err(stop);
            }
            attempt += 1;
        }
    }

    /// An `EffectStarted` with no terminal record: a crash landed between
    /// "sent the request" and "recorded the answer".
    ///
    /// Whether the call landed is undecidable from the journal, so the declared
    /// recovery mode decides. This is the same question an
    /// [`InDoubt`](crate::core::Disposition::InDoubt) failure asks — a crash and
    /// a timeout leave the runtime knowing exactly as much — and it is answered
    /// the same way, by declaration rather than by guessing.
    async fn resolve_orphan<E: Effect>(
        &mut self,
        effect: &E,
        key: EffectKey,
        attempt: u32,
        recovery: &crate::core::Recovery,
    ) -> Result<E::Output, StepError> {
        use crate::core::{Reconciliation, Recovery};

        // Strict replay is a pure read, and resolving an orphan is not reading —
        // every branch below either performs an effect or probes a provider, and
        // both write to the journal being verified.
        //
        // An earlier version fell straight through to the `Retry` arm here, so
        // verifying a crashed run re-performed its interrupted effect for real
        // and appended to the history it was meant to be checking.
        if self.mode == Mode::Strict {
            return Err(StepError::Undecidable {
                key,
                recovery: recovery.clone(),
                detail: "the journal ends mid-effect; strict replay verifies history and will \
                         not perform or probe to complete it"
                    .into(),
            });
        }

        match recovery {
            // Re-performed under the *same* key, and without a second
            // `EffectStarted`: the announcement already in the journal covers
            // this call, and writing another would report two attempts where
            // one interrupted attempt was resumed.
            Recovery::Retry | Recovery::Idempotent { .. } => {
                match self.perform_once(effect, key, attempt, 0, false).await? {
                    Ok(output) => Ok(output),
                    Err(e) => Err(StepError::Effect(e)),
                }
            }
            // Ask, rather than assume. This is the only branch that turns an
            // undecidable outcome into a decided one without betting on it.
            Recovery::Reconcile => match self.reconcile_and_record(effect, key).await? {
                Reconciliation::Landed(output) => Ok(output),
                Reconciliation::DidNotHappen => {
                    match self.perform_once(effect, key, attempt, 0, false).await? {
                        Ok(output) => Ok(output),
                        Err(e) => Err(StepError::Effect(e)),
                    }
                }
                Reconciliation::Inconclusive => Err(StepError::Undecidable {
                    key,
                    recovery: recovery.clone(),
                    detail: "started before a crash, and the reconciliation probe could not \
                             establish whether it landed"
                        .into(),
                }),
            },
            Recovery::RequiresOperator => Err(StepError::Undecidable {
                key,
                recovery: recovery.clone(),
                detail: "started before a crash and never completed".into(),
            }),
        }
    }

    /// Ask the provider whether a call landed, and journal the answer.
    ///
    /// The verdict goes in the journal — including an inconclusive one, because
    /// "we did not know, we asked, and we still do not know" is exactly what an
    /// operator picking up the escalation needs to see. Omitting it would make
    /// the escalation look like nobody tried.
    ///
    /// Journaling also makes the probe replayable: it is a network call like any
    /// other, and replay reads its verdict back rather than asking again.
    async fn reconcile_and_record<E: Effect>(
        &mut self,
        effect: &E,
        key: EffectKey,
    ) -> Result<crate::core::Reconciliation<E::Output>, StepError> {
        use crate::core::Reconciliation;

        // A probe that fails tells us nothing new, so the doubt stands. It is
        // recorded rather than retried: a probe worth repeating is a probe the
        // driver should be repeating internally, and stacking a retry loop on
        // top of one is a multiplication nobody asked for.
        let (outcome, detail) = match effect.reconcile().await {
            Ok(r) => (r, None),
            Err(e) => (Reconciliation::Inconclusive, Some(e.to_string())),
        };

        let (output, spend) = match &outcome {
            Reconciliation::Landed(value) => {
                let spend = effect.spend(value);
                self.bill(spend);
                (Some(serde_json::to_value(value)?), spend)
            }
            _ => (None, crate::core::Spend::default()),
        };

        tracing::info!(
            target: telemetry::RECONCILED,
            run = %self.run,
            step = %self.step,
            verdict = ?outcome.disposition(),
        );
        metrics::count(metrics::RECONCILIATIONS, outcome.disposition().as_str());
        self.append_effect(
            key,
            RecordKind::EffectReconciled {
                disposition: outcome.disposition(),
                output,
                spend,
                detail,
            },
        )
        .await?;

        Ok(outcome)
    }

    /// What history says about a wait, if anything.
    ///
    /// `Ok(None)` means the journal has nothing here and the wait must be
    /// registered live. Every other arm is a decision the recorded run already
    /// made, reproduced rather than re-derived.
    async fn replayed_wait(
        &mut self,
        key: EffectKey,
        spec: &AwaitSpec,
        cx: &CaseContext,
    ) -> Result<Option<Tainted<Value>>, StepError> {
        match self.cursor.next(key)? {
            Some(EffectReplay::Done { output, spend }) => {
                self.bill(spend);
                Ok(Some(Self::label_inbound(output, &spec.kind)))
            }
            Some(EffectReplay::Refused { limit, used }) => {
                Err(StepError::Budget(crate::core::BudgetExceeded::Recorded {
                    limit,
                    used,
                }))
            }
            Some(EffectReplay::Denied {
                reason,
                action,
                resource,
            }) => Err(StepError::Denied {
                action,
                resource,
                reason,
            }),
            Some(EffectReplay::Failed { error, .. }) => {
                Err(StepError::Effect(crate::core::EffectError::Rejected(error)))
            }
            // A subscription with no delivery: the run is still waiting.
            // Suspend again rather than re-registering.
            Some(EffectReplay::Orphan { .. }) => {
                Err(StepError::Suspended(self.suspend_reason(spec, cx).await?))
            }
            None if self.mode == Mode::Strict => Err(StepError::ReplayOverrun { actual: key }),
            None => Ok(None),
        }
    }

    /// Account for an effect served from the journal rather than performed.
    ///
    /// Marked replayed so metrics like "effect latency by driver" do not average
    /// real calls with journal reads, and billed at the figure that was
    /// *recorded* — so a replayed run reaches the same budget verdict at the
    /// same point as the original.
    fn replayed_done(&mut self, kind: &str, attempt: u32, spend: crate::core::Spend) {
        tracing::debug!(
            target: telemetry::EFFECT_SPAN,
            kind = %kind,
            attempt,
            replayed = true,
            outcome = "done",
        );
        metrics::count(metrics::EFFECTS_REPLAYED, kind);
        self.bill(spend);
    }

    /// Everything that can refuse an attempt before it is dispatched.
    ///
    /// Authorization before accounting: both refuse before dispatch, but an
    /// unauthorized call should not first consume the run's allowance —
    /// otherwise a denied agent can still exhaust a budget by asking.
    ///
    /// Compensation is exempt from both, for the same reason: refusing to undo
    /// is how a run ends with a charged card and no order.
    async fn gate(
        &mut self,
        key: EffectKey,
        descriptor: &EffectDescriptor,
        mutates: bool,
    ) -> Result<(), StepError> {
        if !self.phase.is_forward() {
            return Ok(());
        }
        self.authorize(key, descriptor, mutates).await?;
        self.admit(key, &descriptor.kind).await
    }

    /// Check an effect against the policy in force, journalling any denial.
    ///
    /// Runs **only on live dispatch**. A replayed effect never reaches here,
    /// because its result comes back from the journal rather than from the
    /// world — which is what keeps a policy edit from re-judging a run that
    /// already happened. See `core::policy`.
    ///
    /// A permit is not recorded. The effect's own `EffectStarted` is already
    /// evidence it was allowed, and journaling "yes" beside every call doubles
    /// the log to say nothing.
    async fn authorize(
        &mut self,
        key: EffectKey,
        descriptor: &EffectDescriptor,
        mutates: bool,
    ) -> Result<(), StepError> {
        let Some(engine) = self.policy.as_ref() else {
            return Ok(());
        };

        let mut context = serde_json::json!({
            "run": self.run.to_string(),
            "step": self.step.0,
            "mutates": mutates,
            "args": descriptor.args,
        });
        merge_identity(&mut context, self.identity.as_ref());
        let request = crate::core::PolicyRequest {
            principal: &self.agent,
            action: crate::core::ACTION_PERFORM,
            resource: &descriptor.kind,
            context: &context,
        };

        // Before the policy is consulted, not after. A refusal is journaled as
        // it happens, so a ceiling applied afterwards bounds nothing an
        // observer can see — the record is already written and the bit is
        // already out. Refusing here means the attempt produces neither.
        if let Err(exceeded) = self
            .ledger
            .lock()
            .expect("budget mutex")
            .admit_policy_check()
        {
            return Err(StepError::Budget(exceeded));
        }

        let crate::core::PolicyDecision::Deny { reason } = engine.authorize(&request) else {
            return Ok(());
        };

        tracing::error!(
            target: telemetry::POLICY_DENIED,
            run = %self.run,
            step = %self.step,
            action = crate::core::ACTION_PERFORM,
            resource = %descriptor.kind,
            %reason,
        );
        metrics::count(metrics::POLICY_DENIALS, crate::core::ACTION_PERFORM);
        self.append_effect(
            key,
            RecordKind::PolicyDenied {
                reason: reason.clone(),
                action: crate::core::ACTION_PERFORM.to_owned(),
                resource: descriptor.kind.clone(),
            },
        )
        .await?;

        // Counted after the record, and the ordering matters: the refusal has
        // already happened and belongs in the journal whatever the ceiling says.
        // What the ceiling stops is the *next* attempt, which is the one that
        // would learn something the last one did not.
        if let Err(exceeded) = self.ledger.lock().expect("budget mutex").record_denial() {
            return Err(StepError::Budget(exceeded));
        }

        Err(StepError::Denied {
            action: crate::core::ACTION_PERFORM.to_owned(),
            resource: descriptor.kind.clone(),
            reason,
        })
    }

    /// Check an effect against the run's ceilings, journalling any refusal.
    ///
    /// The refusal goes in the journal under the key of the effect it refused.
    /// Without it a replayed run reaches this point, finds no history, and
    /// reports that the *build* performs more effects than the record — sending
    /// an operator to look for a code change that does not exist.
    async fn admit(&mut self, key: EffectKey, kind: &str) -> Result<(), StepError> {
        // Scoped so the guard is gone before any await below.
        let verdict = self.ledger.lock().expect("budget mutex").admit_effect();
        let Err(exceeded) = verdict else {
            return Ok(());
        };

        tracing::warn!(
            target: telemetry::BUDGET_REFUSED,
            run = %self.run,
            step = %self.step,
            %kind,
            limit = %exceeded,
        );
        metrics::count(metrics::BUDGET_REFUSALS, exceeded.as_str());
        self.append_effect(
            key,
            RecordKind::BudgetRefused {
                limit: exceeded.to_string(),
                used: format!("{:?}", self.budget()),
            },
        )
        .await?;
        Err(StepError::Budget(exceeded))
    }

    /// Perform one attempt inside its own span.
    ///
    /// One span per *attempt*, not per effect, so a retried call shows as
    /// several — which is what makes "how often does this driver need a second
    /// try" answerable at all.
    async fn traced_attempt<E: Effect>(
        &mut self,
        effect: &E,
        key: EffectKey,
        attempt: u32,
        waited_ms: u64,
    ) -> Result<Result<E::Output, crate::core::EffectError>, StepError> {
        let span = tracing::info_span!(
            telemetry::EFFECT_SPAN,
            { telemetry::EFFECT_KIND } = tracing::field::display(&effect.descriptor().kind),
            { telemetry::EFFECT_ATTEMPT } = attempt,
            { telemetry::EFFECT_MUTATES } = effect.mutates(),
            { telemetry::EFFECT_REPLAYED } = false,
            { telemetry::OUTCOME } = tracing::field::Empty,
            // Present only on the effects that *are* GenAI operations. Recorded
            // rather than declared with a value so a clock read does not carry
            // an empty `gen_ai.operation.name`, which would make the attribute
            // useless for the tooling that keys on it.
            { telemetry::GEN_AI_OPERATION } = tracing::field::Empty,
        );
        if let Some(op) = effect.gen_ai_operation() {
            span.record(telemetry::GEN_AI_OPERATION, op);
        }
        // `Instrument`, never `enter()`. An `Entered` guard held across an
        // `.await` stays entered on the *thread*, so when the future yields,
        // whatever runs next is attributed to this span. With concurrent step
        // dispatch that silently reparents a sibling's work.
        // Counted per *attempt*, matching the span: a driver that needs two
        // tries has performed two effects against the world, and a count that
        // collapsed them would hide exactly the retry rate an operator is
        // looking for.
        metrics::count(metrics::EFFECTS, &effect.descriptor().kind);
        let outcome = self
            .perform_once(effect, key, attempt, waited_ms, true)
            .instrument(span.clone())
            .await?;
        span.record(
            telemetry::OUTCOME,
            if outcome.is_ok() { "done" } else { "failed" },
        );
        Ok(outcome)
    }

    /// What to do about a failure the journal already holds.
    ///
    /// Returns the next attempt number to try. Errors if the recorded run
    /// stopped here — which is the faithful outcome, not a fault.
    #[allow(clippy::too_many_arguments)]
    fn recorded_failure(
        &mut self,
        descriptor: &EffectDescriptor,
        ordinal: u32,
        attempt: u32,
        key: EffectKey,
        recovery: &crate::core::Recovery,
        policy: &crate::core::RetryPolicy,
        error: &str,
        disposition: crate::core::Disposition,
    ) -> Result<u32, StepError> {
        // Billed on replay exactly as it was live, or a run that exhausted its
        // budget on failures would replay as healthy under the same limit.
        self.bill(crate::core::Spend::default());

        // Did the recorded run go on to retry? Ask history rather than infer:
        // if the next journaled effect is this one's attempt + 1, it retried.
        let next = EffectKey::derive(
            self.step,
            self.phase,
            ordinal,
            attempt + 1,
            &descriptor.kind,
            &canon::value_bytes(&descriptor.args),
        );
        if self.cursor.peek_is(next) {
            // Follow history, whatever the current policy says.
            return Ok(attempt + 1);
        }

        // History ends here. Recompute what the recorded run would have done
        // next — a pure function of the disposition, the recovery mode, and the
        // policy. If it would have stopped, this failure was final.
        if let Some(stop) = Self::stop_reason(disposition, recovery, key, attempt, policy, error) {
            return Err(stop);
        }

        // It would have retried, so it died between recording this failure and
        // starting the next attempt. A strict pass reports that rather than
        // performing anything; a resume carries on live.
        if self.mode == Mode::Strict {
            return Err(StepError::ReplayOverrun { actual: next });
        }
        Ok(attempt + 1)
    }

    /// Whether to stop after a failed attempt, and with what.
    ///
    /// Three gates in order, and a policy can only ever narrow what the first
    /// two allow:
    ///
    /// 1. [`Landed`](crate::core::Disposition::Landed) — the call took effect.
    ///    Repeating it would be a second real performance, so it never happens.
    /// 2. [`InDoubt`](crate::core::Disposition::InDoubt) — the same
    ///    undecidability a crash produces, resolved the same way: by the
    ///    declared [`Recovery`], never by guessing.
    /// 3. The policy's attempt count, which governs only failures the first two
    ///    have already cleared.
    ///
    /// Returns `None` when another attempt is permitted.
    fn stop_reason(
        disposition: crate::core::Disposition,
        recovery: &crate::core::Recovery,
        key: EffectKey,
        attempt: u32,
        policy: &crate::core::RetryPolicy,
        message: &str,
    ) -> Option<StepError> {
        use crate::core::{Disposition, Recovery};

        match disposition {
            Disposition::Landed => {
                return Some(StepError::Effect(crate::core::EffectError::Other(format!(
                    "effect {key} took effect and its response could not be used ({message}); \
                     repeating it would perform it a second time"
                ))));
            }
            Disposition::InDoubt => match recovery {
                // Safe to repeat by declaration: either genuinely idempotent,
                // or carrying an idempotency key the provider honours.
                Recovery::Retry | Recovery::Idempotent { .. } => {}
                Recovery::Reconcile => {
                    // Reached only once the probe has already run and come back
                    // inconclusive — the caller resolves what it can before
                    // asking this. The doubt survived being asked about.
                    return Some(StepError::Undecidable {
                        key,
                        recovery: recovery.clone(),
                        detail: format!(
                            "{message} — the reconciliation probe could not establish whether \
                             it landed"
                        ),
                    });
                }
                Recovery::RequiresOperator => {
                    return Some(StepError::Undecidable {
                        key,
                        recovery: recovery.clone(),
                        detail: format!("{message} — it may well have been applied"),
                    });
                }
            },
            Disposition::DidNotHappen => {}
        }

        (!policy.permits(attempt)).then(|| {
            StepError::Effect(crate::core::EffectError::Other(format!(
                "effect {key} failed on attempt {attempt} of {}: {message}",
                policy.max_attempts
            )))
        })
    }

    /// Suspend until an instant, durably.
    ///
    /// The run's frame is persisted and the task is dropped: a sleeping run
    /// costs a row, not a thread. A sweep wakes it when the instant arrives, so
    /// a plane can hold as many sleeping runs as it has disk and a restart loses
    /// none of them.
    ///
    /// The instant is recorded under an effect key, so replay reads it back
    /// rather than sleeping again — and a run that slept until Tuesday still
    /// says Tuesday when it is audited next year.
    pub async fn sleep_until(&mut self, until: Timestamp) -> Result<(), StepError> {
        let timers = self.timers.clone().ok_or_else(|| {
            StepError::Effect(crate::core::EffectError::Other(
                "durable timers need a timer store — build the runtime with `.timers(store)`"
                    .into(),
            ))
        })?;

        // Whole seconds, matching the store's precision. Two records of one
        // wake-up that disagree by a fraction of a second give "when does this
        // fire?" two answers.
        let until = until.replace_nanosecond(0).map_err(|e| {
            StepError::Effect(crate::core::EffectError::Other(format!(
                "unrepresentable wake instant: {e}"
            )))
        })?;

        // The sleep is an effect: its output is the instant it woke at. Replay
        // reads that back like any other recorded result, so none of the
        // suspension machinery exists twice.
        let descriptor = EffectDescriptor::new(
            "timer.sleep",
            serde_json::json!({ "until": until.unix_timestamp() }),
        );
        let key = EffectKey::derive(
            self.step,
            self.phase,
            self.ordinal,
            1,
            &descriptor.kind,
            &canon::value_bytes(&descriptor.args),
        );
        self.ordinal += 1;

        // ── Replay: the timer already fired ────────────────────────────────
        if self.mode.is_replaying() {
            match self.cursor.next(key)? {
                Some(EffectReplay::Done { spend, .. }) => {
                    self.bill(spend);
                    return Ok(());
                }
                Some(EffectReplay::Refused { limit, used }) => {
                    return Err(StepError::Budget(crate::core::BudgetExceeded::Recorded {
                        limit,
                        used,
                    }));
                }
                Some(EffectReplay::Denied {
                    reason,
                    action,
                    resource,
                }) => {
                    return Err(StepError::Denied {
                        action,
                        resource,
                        reason,
                    });
                }
                Some(EffectReplay::Failed { error, .. }) => {
                    return Err(StepError::Effect(crate::core::EffectError::Rejected(error)));
                }
                // Armed but not yet fired: still asleep. Suspend again rather
                // than re-arming, which would reset the clock every replay.
                Some(EffectReplay::Orphan { .. }) => {
                    return Err(StepError::Suspended(
                        crate::core::SuspendReason::AwaitingTime { until },
                    ));
                }
                None if self.mode == Mode::Strict => {
                    return Err(StepError::ReplayOverrun { actual: key });
                }
                None => {}
            }
        }

        // Announce before arming, so a crash between the two leaves an orphan
        // the resumed run recognises rather than a timer nobody is waiting on.
        self.append_effect(
            key,
            RecordKind::EffectStarted {
                descriptor,
                recovery: crate::core::Recovery::Retry,
                mutates: false,
                attempt: 1,
                backoff_ms: 0,
            },
        )
        .await?;

        timers
            .arm(&crate::core::Timer {
                run: self.run,
                case: self.case.as_ref().map(CaseContext::id),
                effect: key,
                step: self.step,
                phase: self.phase,
                fire_at: until,
            })
            .await?;

        Err(StepError::Suspended(
            crate::core::SuspendReason::AwaitingTime { until },
        ))
    }

    /// Suspend for a duration.
    ///
    /// The duration is resolved to an instant through the journaled clock, so
    /// the wake time is a recorded fact rather than a formula re-evaluated on
    /// every replay.
    pub async fn sleep(&mut self, how_long: std::time::Duration) -> Result<(), StepError> {
        let now = self.now().await?;
        let until = now
            .checked_add(time::Duration::try_from(how_long).map_err(|e| {
                StepError::Effect(crate::core::EffectError::Other(format!(
                    "unrepresentable sleep duration: {e}"
                )))
            })?)
            .ok_or_else(|| {
                StepError::Effect(crate::core::EffectError::Other(
                    "sleep duration overflows the representable range".into(),
                ))
            })?;
        self.sleep_until(until).await
    }

    /// Send a labeled value into a sink, enforcing the information-flow gates.
    ///
    /// Two checks, both of which are the reason labels exist at all:
    ///
    /// * **Egress ceiling** — a value's sensitivity may not exceed what the sink
    ///   is allowed to receive. This is the exfiltration path that actually
    ///   matters: not the network, but a legitimate-looking call carrying a
    ///   secret that was read three steps ago.
    /// * **Taint gate** — untrusted data may not reach a *mutating* sink without
    ///   an explicit, journaled declassification.
    pub async fn sink<E: Effect>(
        &mut self,
        effect: E,
        args: &Tainted<Value>,
    ) -> Result<Tainted<E::Output>, StepError> {
        let sink_name = effect.descriptor().kind;
        let label = args.label();

        let ceiling = effect.max_sensitivity();
        if label.sensitivity > ceiling {
            return Err(PolicyError::EgressCeiling {
                sink: sink_name,
                actual: label.sensitivity,
                ceiling,
            }
            .into());
        }

        if effect.mutates() && label.is_untrusted() {
            return Err(PolicyError::TaintGate { sink: sink_name }.into());
        }

        self.effect(effect).await
    }

    /// Take a value out of the information-flow lattice.
    ///
    /// The only exit, and it is never silent: the reason and the label it left
    /// with are written to the journal, permanently.
    pub async fn declassify<T>(
        &mut self,
        value: Tainted<T>,
        reason: impl Into<String>,
    ) -> Result<T, StepError> {
        let (inner, label) = value.into_parts();
        let reason = reason.into();
        self.append(RecordKind::Declassified { reason, label })
            .await?;
        Ok(inner)
    }

    /// Whether non-effect records should be written right now.
    ///
    /// Effects carry keys and are matched against history individually, so they
    /// look after themselves. Bookkeeping records — notes, declassifications —
    /// have no key, so they need this rule instead:
    ///
    /// * `Live` — always write.
    /// * `Resume` — write only once history is exhausted. Inside the replayed
    ///   prefix these records already exist; re-appending them would duplicate
    ///   history rather than reconstruct it.
    /// * `Strict` — never write. Verification is a pure read, and a
    ///   verification pass that mutates the journal would corrupt the very
    ///   history it is checking, moving the chain head every time someone ran a
    ///   regression test.
    fn writes_enabled(&self) -> bool {
        match self.mode {
            Mode::Live => true,
            Mode::Resume => self.cursor.exhausted(),
            Mode::Strict => false,
        }
    }

    /// One attempt: announce, act, record.
    ///
    /// The nested result separates two failures that must not be confused. The
    /// outer `StepError` is the runtime itself failing — the journal would not
    /// accept a write, the output would not encode — and is never retryable,
    /// because a runtime that cannot record what it did must not go on doing
    /// things. The inner `EffectError` is the *effect* failing, which is
    /// ordinary, journaled, and what the retry decision is made from.
    async fn perform_once<E: Effect>(
        &mut self,
        effect: &E,
        key: EffectKey,
        attempt: u32,
        backoff_ms: u64,
        write_start: bool,
    ) -> Result<Result<E::Output, crate::core::EffectError>, StepError> {
        // `EffectStarted` goes down *before* the call. If the process dies
        // between here and the terminal record, replay sees an orphan and the
        // declared recovery mode decides — which is only possible because the
        // start was durable first.
        if write_start {
            self.append_effect(
                key,
                RecordKind::EffectStarted {
                    descriptor: effect.descriptor(),
                    recovery: effect.recovery(),
                    mutates: effect.mutates(),
                    attempt,
                    backoff_ms,
                },
            )
            .await?;
        }

        match effect.perform().await {
            Ok(output) => {
                let json = serde_json::to_value(&output)?;
                let spend = effect.spend(&output);
                self.bill(spend);
                self.append_effect(
                    key,
                    RecordKind::EffectDone {
                        output: json,
                        spend,
                    },
                )
                .await?;
                Ok(Ok(output))
            }
            Err(e) => {
                // A failed call still occupied a call, which is what lets
                // `max_effects` bound an effect that never succeeds — and it may
                // also have spent real money before dying. A stream cut off
                // after five hundred tokens is billed for five hundred tokens.
                let spend = e.spend();
                self.bill(spend);
                // The disposition is recorded alongside the message because it
                // is what every later decision reads — the retry taken now, and
                // an operator's judgement afterwards. Messages get reworded;
                // this is a fact about the run.
                self.append_effect(
                    key,
                    RecordKind::EffectFailed {
                        error: e.to_string(),
                        spend,
                        disposition: e.disposition(),
                    },
                )
                .await?;
                Ok(Err(e))
            }
        }
    }

    async fn append_effect(&self, key: EffectKey, kind: RecordKind) -> Result<(), StepError> {
        self.store
            .append(self.epoch, vec![self.stamp(kind).effect(key)])
            .await?;
        Ok(())
    }

    async fn append(&self, kind: RecordKind) -> Result<(), StepError> {
        if !self.writes_enabled() {
            return Ok(());
        }
        self.store
            .append(self.epoch, vec![self.stamp(kind)])
            .await?;
        Ok(())
    }

    /// Tag a record with this step's run, step, and case.
    ///
    /// Every record of a case-bound run carries its case, which is what turns
    /// "show me everything about this matter" into one indexed range scan
    /// instead of a join across runs.
    fn stamp(&self, kind: RecordKind) -> Append {
        let mut a = Append::new(self.run, kind)
            .step(self.step)
            .phase(self.phase);
        if let Some(c) = &self.case {
            a = a.case(c.case_id);
        }
        a
    }
}

/// Wall-clock read for subscription bookkeeping.
///
/// Infrastructure metadata, not run-visible state: it never enters the journal
/// and therefore cannot affect replay. Run-visible time goes through
/// `StepCtx::now`, which journals the instant.
#[allow(clippy::disallowed_methods)]
fn subscription_clock() -> Timestamp {
    Timestamp::now_utc()
}

/// Derive a reproducible RNG stream for one step.
fn seeded_rng(run: RunId, step: StepId) -> ChaCha8Rng {
    let mut seed = [0u8; 32];
    seed[..16].copy_from_slice(&run.0.to_bytes());
    seed[16..20].copy_from_slice(&step.0.to_be_bytes());
    ChaCha8Rng::from_seed(seed)
}

/// Case-scoped operations.
///
/// Available only when the runtime was built with a case store and the run was
/// admitted with correlation keys. A run without a case is a perfectly ordinary
/// run — it simply has no long-lived state to reach.
impl StepCtx<'_> {
    /// The case this run belongs to, if any.
    #[must_use]
    pub fn case_id(&self) -> Option<CaseId> {
        self.case.as_ref().map(|c| c.case_id)
    }

    fn case_ctx(&self) -> Result<&CaseContext, StepError> {
        self.case.as_ref().ok_or_else(|| {
            StepError::Effect(crate::core::EffectError::Other(
                "this run has no case: build the runtime with a case store and admit the run \
                 with correlation keys"
                    .into(),
            ))
        })
    }

    /// Read the case's opaque state, and the revision it was read at.
    ///
    /// **A journaled effect**, so a replay reads back what the live run saw
    /// rather than whatever the case holds now. Case state is mutable storage
    /// shared by every run on the case; reading it is as non-deterministic as
    /// reading a clock, and treating it as free was a hole in exactly the
    /// property this crate exists to provide.
    ///
    /// The version comes back with the value because [`put_case_state`] needs
    /// it. Returning the value alone is what makes a lost update easy to write.
    ///
    /// [`put_case_state`]: Self::put_case_state
    ///
    /// # Errors
    ///
    /// [`StepError`] if this run has no case, or the read fails.
    pub async fn case_state(&mut self) -> Result<(Tainted<Value>, CaseVersion), StepError> {
        let cx = self.case_ctx()?.clone();
        let snapshot = self
            .effect(crate::runtime::effects::ReadCaseState {
                cases: Arc::clone(&cx.cases),
                case: cx.case_id,
            })
            .await?;
        let snapshot = snapshot.into_unlabelled();
        // Case state is data the engine never interprets, and it may well have
        // come from an earlier untrusted source. It is handed back labeled.
        Ok((
            Tainted::with_label(snapshot.state, crate::core::Label::trusted()),
            snapshot.version,
        ))
    }

    /// Replace the case's opaque state, if it is still at `at`.
    ///
    /// **A journaled effect**, so a replay does not write again.
    ///
    /// # Why you have to pass the version
    ///
    /// A case is shared by every run correlated to it, and the window between
    /// reading its state and writing it back contains a model call — which is
    /// unbounded. Two runs on one case overlap as a matter of course, and a
    /// blind write in that window silently discards whichever one lost, with
    /// nothing in the record to show it happened.
    ///
    /// Passing the version you read makes that unexpressible: the store rejects
    /// a write against a revision the case has moved past. The remedy is to
    /// re-read and decide again — **not** to retry the same write, which is the
    /// lost update this exists to prevent.
    ///
    /// # Errors
    ///
    /// [`StepError`] if this run has no case, or if the case has moved on since
    /// `at` — see [`StoreError::CaseConflict`](crate::core::StoreError::CaseConflict).
    pub async fn put_case_state(
        &mut self,
        at: CaseVersion,
        state: Value,
    ) -> Result<CaseVersion, StepError> {
        let cx = self.case_ctx()?.clone();
        let version = self
            .effect(crate::runtime::effects::WriteCaseState {
                cases: Arc::clone(&cx.cases),
                case: cx.case_id,
                expected: at,
                state,
            })
            .await?;
        Ok(version.into_unlabelled())
    }

    /// Move the case to a new status.
    pub async fn set_case_status(&mut self, status: CaseStatus) -> Result<(), StepError> {
        let cx = self.case_ctx()?.clone();
        cx.cases.set_status(cx.case_id, status).await?;
        Ok(())
    }

    /// Register a durable obligation on the case.
    ///
    /// Resolution goes through the configured [`Calendar`] as a journaled
    /// effect, so replay reads back the instant the original run registered
    /// rather than recomputing it against whatever the calendar says today.
    /// That is what keeps a corrected holiday table from retroactively moving a
    /// deadline that has already been relied upon.
    pub async fn deadline(
        &mut self,
        name: impl Into<String>,
        spec: &DeadlineSpec,
        warn_before: Option<time::Duration>,
    ) -> Result<Deadline, StepError> {
        let name = name.into();
        let cx = self.case_ctx()?.clone();

        let from = self.now().await?;
        let resolved = self
            .effect(ResolveDeadline {
                calendar: Arc::clone(&cx.calendar),
                name: name.clone(),
                from,
                spec: spec.clone(),
            })
            .await?
            .into_unlabelled();

        let deadline = Deadline {
            case: cx.case_id,
            name: name.clone(),
            resolved_at: resolved.at,
            calendar_digest: resolved.calendar_digest,
            warn_at: warn_before.and_then(|d| resolved.at.checked_sub(d)),
            state: DeadlineState::Pending,
        };

        // Idempotent by primary key, so a resumed run re-registering the same
        // obligation is a no-op rather than a duplicate.
        cx.cases.register_deadline(&deadline).await?;

        self.append(RecordKind::DeadlineRegistered {
            name,
            resolved_at: resolved.at,
            calendar_digest: resolved.calendar_digest,
        })
        .await?;

        Ok(deadline)
    }

    /// Mark an obligation satisfied.
    ///
    /// A case cannot be closed while any obligation is still open, so this is
    /// what turns "we did the thing" into "the case may now be concluded".
    pub async fn meet_deadline(&mut self, name: &str) -> Result<(), StepError> {
        self.transition_deadline(name, DeadlineState::Met).await
    }

    /// Withdraw an obligation that no longer applies.
    pub async fn cancel_deadline(&mut self, name: &str) -> Result<(), StepError> {
        self.transition_deadline(name, DeadlineState::Cancelled)
            .await
    }

    async fn transition_deadline(
        &mut self,
        name: &str,
        to: DeadlineState,
    ) -> Result<(), StepError> {
        let cx = self.case_ctx()?.clone();
        let before = cx
            .cases
            .deadlines(cx.case_id)
            .await?
            .into_iter()
            .find(|d| d.name == name)
            .map_or(DeadlineState::Pending, |d| d.state);

        cx.cases.set_deadline_state(cx.case_id, name, to).await?;
        self.append(RecordKind::DeadlineTransition {
            name: name.to_owned(),
            from: before,
            to,
        })
        .await?;
        Ok(())
    }
}

/// Durable waits.
impl StepCtx<'_> {
    /// Wait for an inbound event correlated by business key.
    ///
    /// On replay this returns the event that was recorded; on first execution it
    /// either finds one already buffered, or suspends the run.
    ///
    /// # The ordering that makes this safe
    ///
    /// An event can arrive *before* the run reaches this call — a fast
    /// counterparty, a slow earlier step, a retry that overtakes. So this looks
    /// in the durable buffer **first**, and only registers a subscription and
    /// suspends if nothing is there. Delivery and waiting meet in the store
    /// rather than in time, which is the only way to close the race.
    ///
    /// # Errors
    ///
    /// Returns [`StepError::Suspended`] when the event has not arrived. That is
    /// **not a failure** — propagate it with `?`. Catching it turns a durable
    /// wait into a silent hang: the subscription stays live, the event arrives
    /// later, and it resumes a run that already decided it was finished.
    pub async fn await_event(&mut self, spec: &AwaitSpec) -> Result<Tainted<Value>, StepError> {
        let correlation = spec.correlation.clone();
        self.wait_on(
            &spec.kind,
            move |_| correlation,
            &spec.deadline,
            |_| async { Ok(()) },
        )
        .await
    }

    /// Ask a human, and wait for the answer.
    ///
    /// The task is created, the run suspends, and a decision resumes it. Because
    /// the task id is derived from the awaiting effect rather than minted, a
    /// resumed run addresses the same task instead of opening a second one for
    /// the same decision.
    ///
    /// # Errors
    ///
    /// Returns [`StepError::Suspended`] until somebody decides. Propagate it —
    /// see [`Self::await_event`].
    pub async fn task(&mut self, spec: &TaskSpec) -> Result<Decision, StepError> {
        let cx = self.case_ctx()?.clone();
        let tasks = cx.tasks.clone().ok_or_else(|| {
            StepError::Effect(crate::core::EffectError::Other(
                "human tasks need a task store — build the runtime with `.tasks(store)`".into(),
            ))
        })?;

        // Acting unattended must be chosen deliberately, not picked off a list.
        if spec.on_expiry == OnExpiry::Proceed && !spec.allow_unattended {
            return Err(StepError::Effect(crate::core::EffectError::Other(
                "OnExpiry::Proceed requires `allow_unattended()`: acting without a human \
                 when the window closes must be an explicit decision, not a default"
                    .into(),
            )));
        }

        let due_at = self.deadline_instant(&cx, &spec.deadline).await?;
        let run = self.run;
        let case_id = cx.case_id;
        let spec = spec.clone();

        let answer = self
            .wait_on(
                TASK_DECIDED,
                |key| {
                    vec![CorrelationKey::new(
                        "task",
                        TaskId::derive(run, key).to_hex(),
                    )]
                },
                &spec.deadline.clone(),
                move |key| {
                    let tasks = Arc::clone(&tasks);
                    let spec = spec.clone();
                    async move {
                        let id = TaskId::derive(run, key);
                        tasks
                            .open(&Task {
                                id,
                                run,
                                case: Some(case_id),
                                kind: spec.kind.clone(),
                                justification: spec.justification.clone(),
                                candidate_roles: spec.candidate_roles.clone(),
                                excluded_actors: spec.excluded_actors.clone(),
                                assignee: None,
                                priority: spec.priority,
                                state: TaskState::Open,
                                on_expiry: spec.on_expiry,
                                created_at: due_at,
                                due_at: Some(due_at),
                            })
                            .await?;
                        Ok(())
                    }
                },
            )
            .await?;

        // A decision is a human's assertion, not a fact the engine verified.
        let decision: Decision = serde_json::from_value(answer.peek().clone())?;
        Ok(decision)
    }

    /// The shared machinery behind [`Self::await_event`] and [`Self::task`].
    ///
    /// `before_suspend` runs once, after the effect key is known and the
    /// subscription is registered, but before the buffer is consulted — the
    /// window in which a task row must exist so that a decision arriving
    /// immediately has something to attach to.
    async fn wait_on<C, F, Fut>(
        &mut self,
        kind: &str,
        correlate: C,
        deadline: &str,
        before_suspend: F,
    ) -> Result<Tainted<Value>, StepError>
    where
        C: FnOnce(EffectKey) -> Vec<CorrelationKey> + Send,
        F: FnOnce(EffectKey) -> Fut + Send,
        Fut: std::future::Future<Output = Result<(), StepError>> + Send,
    {
        // Correlation is computed from the key rather than passed in, because a
        // human task's correlation key *is* its id, and that id is derived from
        // the key. Taking a closure resolves the circularity without a second
        // identifier that could drift from the first.
        let key_preview = self.preview_key(kind, &[]);
        let spec = &AwaitSpec {
            kind: kind.to_owned(),
            correlation: correlate(key_preview),
            deadline: deadline.to_owned(),
        };
        let cx = self.case_ctx()?.clone();
        let events = cx.events.clone().ok_or_else(|| {
            StepError::Effect(crate::core::EffectError::Other(
                "durable waits need an event store — build the runtime with `.events(store)`"
                    .into(),
            ))
        })?;

        // The wait is an effect: its output is the event. That means replay
        // reads the event back like any other recorded result, and none of the
        // suspension machinery has to exist twice.
        let descriptor =
            EffectDescriptor::new("event.await", serde_json::json!({ "kind": spec.kind }));
        let key = self.preview_key(kind, &[]);
        debug_assert_eq!(
            key,
            EffectKey::derive(
                self.step,
                self.phase,
                self.ordinal,
                1,
                &descriptor.kind,
                &canon::value_bytes(&descriptor.args),
            ),
            "the previewed key must match the one the effect is recorded under"
        );
        self.ordinal += 1;

        // ── Replay: the event is already in history ────────────────────────
        if self.mode.is_replaying()
            && let Some(recorded) = self.replayed_wait(key, spec, &cx).await?
        {
            return Ok(recorded);
        }

        let subscription = Subscription {
            run: self.run,
            case: Some(cx.case_id),
            effect: key,
            step: self.step,
            phase: self.phase,
            kind: spec.kind.clone(),
            correlation: spec.correlation.clone(),
        };

        // NOTE: deliberately not `self.now()`. That is itself an effect, and
        // taking it here would give the clock a later ordinal but an earlier
        // journal position — replay verifies journal order, so the two must
        // agree. The subscription's timestamp is store metadata anyway, like a
        // lease: it never enters the journal and cannot affect replay.
        let now = subscription_clock();

        // Announce the wait before releasing the frame, so an event arriving in
        // the same instant finds a durable subscription rather than a gap.
        self.append_effect(
            key,
            RecordKind::EffectStarted {
                descriptor,
                recovery: crate::core::Recovery::Retry,
                mutates: false,
                attempt: 1,
                backoff_ms: 0,
            },
        )
        .await?;
        events.subscribe(&subscription, now).await?;

        // Whatever must exist for a decision to attach to — a task row, say —
        // is created here: after the subscription is durable, before the buffer
        // is consulted. An answer arriving in this window finds both.
        before_suspend(key).await?;

        // Look in the buffer: the event may already be here.
        if let Some(buffered) = events.claim_for(&subscription, now).await? {
            events.unsubscribe(self.run, key).await?;
            self.append_effect(
                key,
                RecordKind::EffectDone {
                    output: buffered.event.payload.clone(),
                    spend: crate::core::Spend::default(),
                },
            )
            .await?;
            return Ok(Self::label_inbound(buffered.event.payload, &spec.kind));
        }

        Err(StepError::Suspended(self.suspend_reason(spec, &cx).await?))
    }

    /// The key this wait will be recorded under, computed without advancing the
    /// ordinal.
    ///
    /// Needed because a human task's correlation key is derived from its own
    /// effect key, so the key must be known before the subscription is built.
    fn preview_key(&self, kind: &str, _unused: &[CorrelationKey]) -> EffectKey {
        // Attempt 1, always: a wait that times out suspends or dead-letters,
        // it never repeats, so there is no second attempt to distinguish.
        EffectKey::derive(
            self.step,
            self.phase,
            self.ordinal,
            1,
            "event.await",
            &canon::value_bytes(&serde_json::json!({ "kind": kind })),
        )
    }

    /// An inbound message is external data by definition, and is labeled as
    /// such — including when it comes from a first-party system.
    fn label_inbound(payload: Value, kind: &str) -> Tainted<Value> {
        Tainted::from_source(payload, crate::core::SourceId::new(format!("event:{kind}")))
    }

    /// The instant an obligation falls due.
    ///
    /// A wait's horizon is the obligation that bounds it, and the reviewer's
    /// deadline is the same fact — so both read it from one place rather than
    /// each computing their own.
    async fn deadline_instant(&self, cx: &CaseContext, name: &str) -> Result<Timestamp, StepError> {
        cx.cases
            .deadlines(cx.case_id)
            .await?
            .into_iter()
            .find(|d| d.name == name)
            .map(|d| d.resolved_at)
            .ok_or_else(|| {
                StepError::Effect(crate::core::EffectError::Other(format!(
                    "wait references deadline '{name}', which is not registered on this case \
                     — register it before waiting, or the run has no horizon"
                )))
            })
    }

    async fn suspend_reason(
        &self,
        spec: &AwaitSpec,
        cx: &CaseContext,
    ) -> Result<crate::core::SuspendReason, StepError> {
        let until = self.deadline_instant(cx, &spec.deadline).await?;

        Ok(crate::core::SuspendReason::AwaitingEvent {
            kind: spec.kind.clone(),
            correlation: spec.correlation.clone(),
            until,
        })
    }
}

/// Fold a delegation chain into a policy context object.
///
/// Merged rather than nested under a key so a rule reads `context.owner` and
/// `context.delegation_depth` directly — which is the shape §11.1's Cedar
/// examples assume, and a rule that has to reach through an extra level is a
/// rule somebody writes wrong once.
pub(crate) fn merge_identity(
    context: &mut serde_json::Value,
    identity: Option<&crate::core::Delegation>,
) {
    let (Some(chain), Some(obj)) = (identity, context.as_object_mut()) else {
        return;
    };
    if let Some(extra) = chain.as_context().as_object() {
        for (k, v) in extra {
            obj.insert(k.clone(), v.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng as _;

    #[test]
    fn rng_is_reproducible_for_the_same_run_and_step() {
        let run = RunId::generate();
        let mut a = seeded_rng(run, StepId(0));
        let mut b = seeded_rng(run, StepId(0));
        let xs: Vec<u64> = (0..8).map(|_| a.random()).collect();
        let ys: Vec<u64> = (0..8).map(|_| b.random()).collect();
        assert_eq!(xs, ys, "replay must reproduce the entropy stream exactly");
    }

    #[test]
    fn rng_differs_across_steps_and_runs() {
        let run = RunId::generate();
        let other = RunId::generate();
        let a: u64 = seeded_rng(run, StepId(0)).random();
        let b: u64 = seeded_rng(run, StepId(1)).random();
        let c: u64 = seeded_rng(other, StepId(0)).random();
        assert_ne!(a, b, "steps must not share a stream");
        assert_ne!(a, c, "runs must not share a stream");
    }
}
