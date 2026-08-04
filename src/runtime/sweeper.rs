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

use crate::core::{
    CaseStatus, DeadlineState, Decision, InboundEvent, OnExpiry, RuntimeError, StoreError,
    TaskState, Timestamp,
};
use crate::journal::{Append, RecordKind};

use super::ctx::Mode;
use super::executor::{LEASE_TTL, Runtime};
use super::metrics::{self, Census};

/// The source a human decision arrives under.
///
/// This plane's own worklist, not an outside party — and named so a counterparty
/// cannot mint an event that deduplicates against a real decision or that a
/// policy would mistake for one.
pub const SOURCE_WORKLIST: &str = "agentplane://worklist";

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
        self.breached > 0 || self.tasks_expired > 0 || self.dead_lettered > 0
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
        self.warned == 0
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

        report.warned += self.sweep_deadlines(now, &mut report).await?;
        self.sweep_tasks(now, &mut report).await?;

        if self.events().is_some() {
            report.dead_lettered = self.sweep_events(event_grace).await?;
        }
        if self.timers().is_some() {
            report.timers_fired = self.fire_timers(now).await?;
        }

        // Observed last, so the reading reflects what this sweep just resolved
        // rather than the backlog it was about to clear.
        report.census = self.census(now).await?;
        report.census.emit();

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
            .claim_due(now, 128)
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
            metrics::count(metrics::TIMERS_FIRED, "");
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
    ) -> Result<usize, RuntimeError> {
        let Some(cases) = self.cases() else {
            return Ok(0);
        };

        let mut warned = 0;
        for deadline in cases
            .due(now, 512)
            .await
            .map_err(RuntimeError::from_store)?
        {
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
                tracing::error!(
                    target: super::telemetry::DEADLINE_BREACHED,
                    case = %deadline.case,
                    obligation = %deadline.name,
                    due = %deadline.resolved_at,
                );
                metrics::count(metrics::DEADLINE_BREACHES, "");
                report.breached += 1;
            } else if deadline.needs_warning(now) {
                cases
                    .set_deadline_state(deadline.case, &deadline.name, DeadlineState::Warned)
                    .await
                    .map_err(RuntimeError::from_store)?;
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
    ) -> Result<(), RuntimeError> {
        let Some(tasks) = self.tasks() else {
            return Ok(());
        };

        for task in tasks
            .overdue(now, 512)
            .await
            .map_err(RuntimeError::from_store)?
        {
            match task.on_expiry {
                // Widen the audience and keep waiting. Escalating twice is a
                // no-op, which is what makes the sweep safe to run on a timer.
                OnExpiry::Escalate if task.state != TaskState::Escalated => {
                    tasks
                        .set_state(task.id, TaskState::Escalated)
                        .await
                        .map_err(RuntimeError::from_store)?;
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
