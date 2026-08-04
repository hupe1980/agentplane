//! The sweeper: what turns a passing instant into something that happened.
//!
//! Until something runs on a clock, a deadline is a number in a table and an
//! unclaimed event is a row nobody reads. That is the failure mode this whole
//! runtime is built against — not a crash, but a silence. A breached regulatory
//! window that nothing announced is indistinguishable, from the outside, from
//! one that was met.
//!
//! One tick does five things:
//!
//! | Finding | What happens |
//! |---|---|
//! | An obligation is approaching | `DeadlineTransition` to `Warned` |
//! | An obligation has passed unmet | `DeadlineTransition` to `Breached`; the case is escalated |
//! | A human task's window closed | The declared `on_expiry` is applied — never decided in the moment |
//! | An event nobody claimed aged out | Dead-lettered with a reason |
//! | A sleeping run's instant arrived | The wake-up is journaled and the run resumes |
//!
//! Four of those are loud. The fifth is the system working: a fired timer is
//! reported so a quiet plane is distinguishable from a stalled one, not so
//! somebody is paged.

use std::sync::Arc;

use crate::core::{
    CaseId, CaseStatus, DeadlineState, Decision, InboundEvent, OnExpiry, RunId, RuntimeError,
    StoreError, SweptAction, TaskState, Timestamp,
};
use crate::journal::{Append, JournalStore, RecordKind};

use super::ctx::Mode;
use super::executor::{LEASE_TTL, Runtime};
use super::metrics::{self, Census};

/// The source a human decision arrives under.
///
/// This plane's own worklist, not an outside party — and named so a counterparty
/// cannot mint an event that deduplicates against a real decision or that a
/// policy would mistake for one.
pub const SOURCE_WORKLIST: &str = "agentplane://worklist";

/// What one tick did, accumulating into a run only if there is anything to say.
///
/// Lazy on purpose. A quiet plane sweeps constantly and should leave nothing
/// behind: opening a run per tick would fill the Merkle log with evidence that
/// nothing happened, and a log of nothings is where the somethings hide.
/// The epoch a sweep's own record is written under.
///
/// A sweep run is created here and never taken over, so there is no ownership
/// to arbitrate and the epoch never moves. It is named rather than spelled `1`
/// three times, because a literal repeated across a fence is how two of them
/// come to disagree.
const SWEEP_EPOCH: crate::core::Epoch = 1;

/// The outcome a sweep run is sealed with.
///
/// Not `Succeeded`: a sweep does not succeed or fail at a goal, it reports what
/// it found. Reusing a run status would make a tick that breached forty
/// obligations indistinguishable from a plan that completed.
const SWEEP_OUTCOME: &str = "swept";

struct SweepLedger {
    run: Option<RunId>,
    entries: Vec<crate::journal::Append>,
}

impl SweepLedger {
    const fn new() -> Self {
        Self {
            run: None,
            entries: Vec::new(),
        }
    }

    /// Note one action, opening the tick's run the first time.
    ///
    /// `case` stamps the record so `JournalStore::case_history` finds it. That
    /// is the whole point of writing this down: the question is *why is this
    /// case escalated*, and a sweep run belongs to no case, so a walk over the
    /// case's own runs would never reach it.
    fn note(
        &mut self,
        case: Option<CaseId>,
        subject: String,
        action: SweptAction,
        detail: Option<String>,
    ) {
        let run = *self.run.get_or_insert_with(RunId::generate);
        let mut entry = crate::journal::Append::new(
            run,
            RecordKind::Swept {
                subject,
                action,
                detail,
            },
        );
        if let Some(case) = case {
            entry = entry.case(case);
        }
        self.entries.push(entry);
    }

    /// Write the tick down and close it.
    ///
    /// Sealed, so it enters the Merkle log like any other run and the external
    /// audit tool checks it without being taught what a sweep is. Best-effort
    /// in the same sense settlement is: the work is already done and the state
    /// already changed, so failing the tick because its *record* would not
    /// write would turn a bookkeeping problem into an operational one — but it
    /// is loud, because a sweep whose evidence is missing is the case this
    /// whole mechanism exists to prevent.
    async fn seal(self, store: &Arc<dyn JournalStore>) -> Option<RunId> {
        let run = self.run?;
        if let Err(e) = store.append(SWEEP_EPOCH, self.entries).await {
            tracing::error!(%run, error = %e, "a sweep's own record could not be written");
            return None;
        }

        // The conclusion goes *in* the chain before the chain closes over it,
        // exactly as `conclude` does it for an ordinary run: tamper evidence
        // has to cover how the record ended, and the Merkle log commits to a
        // chain head that already includes its own sealing.
        let head = match store.head(run).await {
            Ok(head) => head,
            Err(e) => {
                tracing::error!(%run, error = %e, "a sweep's record could not be read back");
                return None;
            }
        };
        let sealed = crate::journal::Append::new(
            run,
            RecordKind::RunSealed {
                outcome: SWEEP_OUTCOME.to_owned(),
                chain_head: head.hash,
            },
        );
        if let Err(e) = store.append(SWEEP_EPOCH, vec![sealed]).await {
            tracing::error!(%run, error = %e, "a sweep's record could not be closed");
            return None;
        }
        if let Err(e) = store.seal(run, SWEEP_EPOCH, SWEEP_OUTCOME).await {
            tracing::error!(%run, error = %e, "a sweep's record could not be sealed");
            return None;
        }
        Some(run)
    }
}

/// Which sweeps hit their cap this tick.
///
/// A bounded query returns a list shaped exactly like a complete one, so a tick
/// that handled its cap and a tick that handled everything are indistinguishable
/// from the counters alone — and those are the two states an operator most needs
/// to tell apart, because the first means the backlog is growing while the
/// report looks normal.
///
/// Three named flags rather than a list of strings: a caller that wants to alert
/// on deadlines specifically should not be matching on a message, and a field
/// added here is a field the compiler makes every reader consider.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Saturation {
    /// Timers fired up to the cap; more may have been due.
    pub timers: bool,
    /// Obligations handled up to the cap; more may have been outstanding.
    pub deadlines: bool,
    /// Expired tasks handled up to the cap; more may have been overdue.
    pub tasks: bool,
}

impl Saturation {
    /// Whether any sweep was capped.
    ///
    /// A saturated tick means *at least* the cap was waiting, never that the
    /// cap was all there was.
    #[must_use]
    pub const fn any(self) -> bool {
        self.timers || self.deadlines || self.tasks
    }
}

/// How much one sweep will take on, per kind of work.
///
/// Bounded so a tick is bounded: a sweep that tried to drain an unbounded
/// backlog would hold a worker for as long as the backlog is deep, and a plane
/// whose sweeper is busy is a plane whose *next* obligation is not being
/// noticed either.
///
/// Each cap is paired with a saturation check that reaches
/// [`SweepReport::saturated`], because a bounded result is shaped exactly like
/// a complete one and the difference is the whole signal.
const TIMER_BATCH: usize = 128;
const DEADLINE_BATCH: usize = 512;
const TASK_BATCH: usize = 512;

/// What one tick found and did.
///
/// Every field is a number worth alerting on. `breached` above zero means a
/// window was missed; `dead_lettered` above zero means a correlation key is
/// wrong somewhere.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SweepReport {
    pub warned: usize,
    pub breached: usize,
    pub tasks_expired: usize,
    pub tasks_escalated: usize,
    pub dead_lettered: usize,
    /// Sleeping runs woken because their instant arrived.
    ///
    /// Not a number to alert on — a fired timer is the system working. It is
    /// reported so a quiet plane is distinguishable from a stalled one.
    pub timers_fired: usize,
    /// Which sweeps came back **full**, and therefore may not have seen
    /// everything that was waiting.
    pub saturated: Saturation,
    /// The sealed run holding this tick's own record, when it did anything.
    ///
    /// `None` for a quiet tick, which writes nothing. Present means the
    /// sweeper's decisions are answerable from the journal rather than only
    /// from the state they produced.
    pub record: Option<RunId>,
    /// What the plane is holding, as of this sweep.
    ///
    /// Carried on the report as well as emitted, so an embedder that wants the
    /// numbers does not have to stand up a metrics subscriber to see them.
    pub census: Census,
}

impl SweepReport {
    /// Whether this tick found anything a human should see.
    #[must_use]
    pub fn needs_attention(&self) -> bool {
        self.breached > 0
            || self.tasks_expired > 0
            || self.dead_lettered > 0
            // A saturated sweep is the case a human most needs to see: the
            // plane is keeping up with its cap rather than with its work.
            || self.saturated.any()
    }

    #[must_use]
    pub fn is_quiet(&self) -> bool {
        // Enumerated, not `*self == Self::default()`. That idiom ties the
        // meaning of "quiet" to the struct's field list, so adding a field
        // silently redefines it — which is exactly what happened when the
        // census arrived: a plane holding one open case stopped being quiet,
        // though the sweep had done nothing at all.
        //
        // The census is *state*, not activity. A plane with five hundred open
        // cases and nothing due is quiet; that is the whole distinction between
        // a gauge and a counter, and this predicate is about the counters.
        !self.saturated.any()
            && self.warned == 0
            && self.breached == 0
            && self.tasks_expired == 0
            && self.tasks_escalated == 0
            && self.dead_lettered == 0
            && self.timers_fired == 0
    }
}

impl Runtime {
    /// Run one sweep.
    ///
    /// Idempotent: a transition already applied is not applied twice, so calling
    /// this on a timer — or twice by accident, or from two instances — is safe.
    ///
    /// `now` is passed in rather than read so the caller controls the clock.
    /// That keeps the sweeper testable at all, and lets a simulation drive it
    /// through a year in milliseconds.
    pub async fn sweep(
        &self,
        now: Timestamp,
        event_grace: time::Duration,
    ) -> Result<SweepReport, RuntimeError> {
        let mut report = SweepReport::default();
        let mut ledger = SweepLedger::new();

        report.warned += self.sweep_deadlines(now, &mut report, &mut ledger).await?;
        self.sweep_tasks(now, &mut report, &mut ledger).await?;

        if self.events().is_some() {
            report.dead_lettered = self.sweep_events(event_grace).await?;
        }
        if self.timers().is_some() {
            report.timers_fired = self.fire_timers(now).await?;
            // `fire_timers` is public and answers "how many fired", so the cap
            // is checked here rather than folded into its return type: a
            // caller asking for a count should not have to destructure a
            // saturation signal it did not ask about.
            if report.timers_fired >= TIMER_BATCH {
                report.saturated.timers = true;
            }
        }

        // Written before the census so the record covers the decisions, not the
        // reading. A tick that decided nothing writes nothing.
        report.record = ledger.seal(self.store()).await;

        // Observed last, so the reading reflects what this sweep just resolved
        // rather than the backlog it was about to clear.
        report.census = self.census(now).await?;
        self.meter().census(&report.census);

        Ok(report)
    }

    /// Read the gauges: how much is open right now.
    ///
    /// Queried from the stores rather than accumulated, because a counter
    /// incremented on open and decremented on close drifts permanently the first
    /// time a process dies between the state change and the emission — and it
    /// drifts *plausibly*, which is worse than drifting obviously.
    ///
    /// Stores that were never configured contribute zero rather than an error: a
    /// plane with no human tasks has no open tasks, and refusing to report the
    /// gauges it *does* have would be the silent failure this exists to prevent.
    pub async fn census(&self, now: Timestamp) -> Result<Census, StoreError> {
        let mut c = Census::default();
        if let Some(cases) = self.cases() {
            let cc = cases.census(now).await?;
            c.open_cases = cc.open;
            c.oldest_case_age_secs = cc.oldest_age_secs;
            c.due_deadlines = cc.due;
        }
        if let Some(timers) = self.timers() {
            c.pending_timers = timers.pending_count().await?;
        }
        if let Some(tasks) = self.tasks() {
            c.open_tasks = tasks.open_count().await?;
        }
        Ok(c)
    }

    /// Wake the runs whose instant has arrived.
    ///
    /// The shape mirrors event delivery exactly, and for the same reasons:
    /// claim atomically so two sweepers cannot wake one run twice, record the
    /// wake-up as the sleeping effect's result, then let replay do the rest.
    /// The resumed run reads the timer back like any other completed effect,
    /// so none of the suspension machinery exists twice.
    pub async fn fire_timers(&self, now: Timestamp) -> Result<usize, RuntimeError> {
        let timers = self.timers().ok_or_else(|| {
            RuntimeError::PlanContract(
                "this runtime has no timer store — build it with `.timers(store)`".into(),
            )
        })?;

        let due = timers
            .claim_due(now, TIMER_BATCH)
            .await
            .map_err(RuntimeError::from_store)?;
        let mut fired = 0;
        for timer in due {
            let lease = self
                .store()
                .acquire(timer.run, self.owner_id(), LEASE_TTL)
                .await
                .map_err(RuntimeError::from_store)?;

            let mut record = Append::new(
                timer.run,
                RecordKind::EffectDone {
                    // The instant it *was due*, not the instant the sweep
                    // noticed. A sweep that ran late must not make the run
                    // believe it slept longer than it was told to, or a
                    // replayed run would compute different downstream deadlines
                    // than the original.
                    output: serde_json::json!({ "fired_at": timer.fire_at.unix_timestamp() }),
                    // A timer has no sender.
                    source: None,
                    spend: crate::core::Spend::default(),
                },
            )
            .effect(timer.effect)
            .step(timer.step)
            .phase(timer.phase);
            if let Some(c) = timer.case {
                record = record.case(c);
            }

            self.store()
                .append(lease.epoch, vec![record])
                .await
                .map_err(RuntimeError::from_store)?;

            timers
                .disarm(timer.run, timer.effect)
                .await
                .map_err(RuntimeError::from_store)?;

            tracing::info!(
                target: super::telemetry::TIMER_FIRED,
                run = %timer.run,
                step = %timer.step,
                due = %timer.fire_at,
            );
            self.meter().count(metrics::TIMERS_FIRED, "");
            self.replay(timer.run, Mode::Resume).await?;
            fired += 1;
        }

        Ok(fired)
    }

    /// Warn on approaching obligations; escalate breached ones.
    async fn sweep_deadlines(
        &self,
        now: Timestamp,
        report: &mut SweepReport,
        ledger: &mut SweepLedger,
    ) -> Result<usize, RuntimeError> {
        let Some(cases) = self.cases() else {
            return Ok(0);
        };

        let mut warned = 0;
        let due = cases
            .due(now, DEADLINE_BATCH)
            .await
            .map_err(RuntimeError::from_store)?;
        if due.len() >= DEADLINE_BATCH {
            report.saturated.deadlines = true;
        }
        for deadline in due {
            if deadline.is_due(now) {
                // Past the instant with the obligation unmet. This is the event
                // the whole deadline machinery exists to produce.
                cases
                    .set_deadline_state(deadline.case, &deadline.name, DeadlineState::Breached)
                    .await
                    .map_err(RuntimeError::from_store)?;
                cases
                    .set_status(deadline.case, CaseStatus::Escalated)
                    .await
                    .map_err(RuntimeError::from_store)?;
                ledger.note(
                    Some(deadline.case),
                    deadline.case.to_string(),
                    SweptAction::DeadlineBreached,
                    Some(format!(
                        "'{}' was due {} and was not met",
                        deadline.name, deadline.resolved_at
                    )),
                );
                ledger.note(
                    Some(deadline.case),
                    deadline.case.to_string(),
                    SweptAction::CaseEscalated,
                    Some(format!("obligation '{}' was breached", deadline.name)),
                );
                tracing::error!(
                    target: super::telemetry::DEADLINE_BREACHED,
                    case = %deadline.case,
                    obligation = %deadline.name,
                    due = %deadline.resolved_at,
                );
                self.meter().count(metrics::DEADLINE_BREACHES, "");
                report.breached += 1;
            } else if deadline.needs_warning(now) {
                cases
                    .set_deadline_state(deadline.case, &deadline.name, DeadlineState::Warned)
                    .await
                    .map_err(RuntimeError::from_store)?;
                ledger.note(
                    Some(deadline.case),
                    deadline.case.to_string(),
                    SweptAction::DeadlineWarned,
                    Some(format!(
                        "'{}' comes due {}",
                        deadline.name, deadline.resolved_at
                    )),
                );
                warned += 1;
            }
        }
        Ok(warned)
    }

    /// Apply the declared expiry policy to tasks nobody answered.
    async fn sweep_tasks(
        &self,
        now: Timestamp,
        report: &mut SweepReport,
        ledger: &mut SweepLedger,
    ) -> Result<(), RuntimeError> {
        let Some(tasks) = self.tasks() else {
            return Ok(());
        };

        let overdue = tasks
            .overdue(now, TASK_BATCH)
            .await
            .map_err(RuntimeError::from_store)?;
        if overdue.len() >= TASK_BATCH {
            report.saturated.tasks = true;
        }
        for task in overdue {
            match task.on_expiry {
                // Widen the audience and keep waiting. Escalating twice is a
                // no-op, which is what makes the sweep safe to run on a timer.
                OnExpiry::Escalate if task.state != TaskState::Escalated => {
                    tasks
                        .set_state(task.id, TaskState::Escalated)
                        .await
                        .map_err(RuntimeError::from_store)?;
                    ledger.note(
                        task.case,
                        task.id.to_hex(),
                        SweptAction::TaskEscalated,
                        Some("nobody answered inside the window".to_owned()),
                    );
                    report.tasks_escalated += 1;
                }
                OnExpiry::Escalate => {}

                // Deny or proceed: both are decisions that were made in advance,
                // and both resume the run with a recorded answer rather than
                // leaving it hanging.
                policy => {
                    let decision = Decision::expired(policy);
                    self.answer_task(task.id, &decision).await?;
                    tasks
                        .set_state(task.id, TaskState::Expired)
                        .await
                        .map_err(RuntimeError::from_store)?;
                    ledger.note(
                        task.case,
                        task.id.to_hex(),
                        SweptAction::TaskExpired,
                        // The *declared* policy, so the record says what was
                        // decided in advance rather than only what happened.
                        Some(format!("window closed; applied {policy:?}")),
                    );
                    report.tasks_expired += 1;
                }
            }
        }
        Ok(())
    }

    /// Record a human decision and resume the run waiting on it.
    ///
    /// The decision is delivered as an ordinary inbound event, so it travels the
    /// same buffered, deduplicated, single-consumer path as any other message —
    /// including the case where the run has not yet reached its wait.
    pub async fn answer_task(
        &self,
        id: crate::core::TaskId,
        decision: &Decision,
    ) -> Result<crate::core::Delivery, RuntimeError> {
        let event = InboundEvent::new(
            // The plane itself, not an outside party: a decision comes from the
            // worklist this runtime owns, and naming it as such keeps a
            // counterparty from minting an event that looks like one.
            SOURCE_WORKLIST,
            // One decision per task: the event id makes a double submit a
            // duplicate rather than a second answer.
            format!("task-decision:{}", id.to_hex()),
            super::ctx::TASK_DECIDED,
            serde_json::to_value(decision)?,
        )
        .correlate(crate::core::CorrelationKey::new("task", id.to_hex()));

        self.deliver(&event).await
    }

    /// Complete a task on behalf of a person, enforcing eligibility first.
    ///
    /// The claim is checked before the decision is recorded: an approval from
    /// somebody who was not permitted to give it is worse than no approval,
    /// because it looks like one.
    pub async fn decide_task(
        &self,
        id: crate::core::TaskId,
        decision: &Decision,
        roles: &[String],
    ) -> Result<crate::core::Delivery, RuntimeError> {
        let tasks = self
            .tasks()
            .ok_or_else(|| RuntimeError::PlanContract("this runtime has no task store".into()))?;

        // The refusal's reason is preserved rather than flattened: "you proposed
        // this action" and "you hold the wrong role" call for different fixes,
        // and an operator staring at a generic denial cannot tell them apart.
        tasks.claim(id, &decision.actor, roles).await.map_err(|e| {
            RuntimeError::PolicyDenied(crate::core::PolicyError::Denied {
                principal: decision.actor.clone(),
                action: "task/decide".into(),
                resource: format!("{id}: {e}"),
            })
        })?;

        let delivery = self.answer_task(id, decision).await?;
        tasks
            .set_state(id, TaskState::Completed)
            .await
            .map_err(RuntimeError::from_store)?;
        Ok(delivery)
    }
}
