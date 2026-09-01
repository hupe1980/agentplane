//! The sweeper: what turns a passing instant into something that happened.
//!
//! Until something runs on a clock, a deadline is a number in a table and an
//! unclaimed event is a row nobody reads. That is the failure mode this whole
//! runtime is built against — not a crash, but a silence. A breached regulatory
//! window that nothing announced is indistinguishable, from the outside, from
//! one that was met.
//!
//! One tick does six things:
//!
//! | Finding | What happens |
//! |---|---|
//! | An instance died holding a run | The run is taken over at the next epoch and resumed |
//! | An obligation is approaching | `DeadlineTransition` to `Warned` |
//! | An obligation has passed unmet | `DeadlineTransition` to `Breached`; the case is escalated |
//! | A human task's window closed | The declared `on_expiry` is applied — never decided in the moment |
//! | An event nobody claimed aged out | Dead-lettered with a reason |
//! | A sleeping run's instant arrived | The wake-up is journaled and the run resumes |
//!
//! The middle four are loud. The first and the last are the system working — a
//! recovered run and a fired timer are reported so a quiet plane is
//! distinguishable from a stalled one, not so somebody is paged. A recovery
//! still means an *instance* died, which is worth a look for a different
//! reason than any run.

use std::sync::Arc;

use crate::core::{
    CaseId, CaseStatus, DeadlineState, Decision, InboundEvent, OnExpiry, RunId, RuntimeError,
    StoreError, SweptAction, TaskState, Timestamp,
};
use crate::journal::{Append, JournalStore, RecordKind};

use super::executor::{LEASE_TTL, Runtime};
use super::metrics::{self, Census};

/// The source a human decision arrives under.
///
/// This plane's own worklist, not an outside party — and named so a counterparty
/// cannot mint an event that deduplicates against a real decision or that a
/// policy would mistake for one.
pub const SOURCE_WORKLIST: &str = "agentplane://worklist";

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
///
/// `pub(crate)` so [`SEALED_OUTCOMES`](super::SEALED_OUTCOMES) can name it
/// rather than restate it — the list and the sealer must agree byte for byte.
pub(crate) const SWEEP_OUTCOME: &str = "swept";

/// What one tick did, opening a run only if there is anything to say.
///
/// Lazy on purpose. A quiet plane sweeps constantly and should leave nothing
/// behind: opening a run per tick would fill the Merkle log with evidence that
/// nothing happened, and a log of nothings is where the somethings hide.
///
/// **Each decision is durable before it is applied** — I2's
/// announce-before-act, applied to the sweeper itself. A note buffered until
/// the tick ends inverts that precisely where it matters most: the state
/// changes a sweep applies (a breach, an escalation) are idempotent
/// transitions, so a crash between applying one and writing its buffered
/// evidence orphans the record *permanently* — the next tick finds the
/// transition already applied and re-decides nothing. So `note` appends
/// immediately, before the caller touches state, and `seal` only closes the
/// run the notes already live in.
struct SweepLedger {
    run: Option<RunId>,
    /// Whether at least one note has durably landed — the difference between
    /// "the tick decided nothing" and "the tick's first note failed before
    /// anything was applied", both of which leave nothing to seal.
    wrote: bool,
}

impl SweepLedger {
    const fn new() -> Self {
        Self {
            run: None,
            wrote: false,
        }
    }

    /// Durably note one decision, opening the tick's run the first time.
    ///
    /// Called **before** the state change it describes; a note that cannot be
    /// written fails the decision, which is then not applied — an unrecorded
    /// breach is worse than a breach noticed one tick late.
    ///
    /// `case` stamps the record so `JournalStore::case_history` finds it. That
    /// is the whole point of writing this down: the question is *why is this
    /// case escalated*, and a sweep run belongs to no case, so a walk over the
    /// case's own runs would never reach it.
    async fn note(
        &mut self,
        store: &Arc<dyn JournalStore>,
        case: Option<CaseId>,
        subject: String,
        action: SweptAction,
        detail: Option<String>,
    ) -> Result<(), RuntimeError> {
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
        store
            .append(SWEEP_EPOCH, vec![entry])
            .await
            .map_err(RuntimeError::from_store)?;
        self.wrote = true;
        Ok(())
    }

    /// Close the tick's record.
    ///
    /// Sealed, so it enters the Merkle log like any other run and the external
    /// audit tool checks it without being taught what a sweep is. Best-effort
    /// in the same sense settlement is: the notes are already durable and the
    /// state already changed, so failing the tick because its *closure* would
    /// not write would turn a bookkeeping problem into an operational one — but
    /// it is loud, because a sweep whose evidence is missing is the case this
    /// whole mechanism exists to prevent.
    ///
    /// The three outcomes are distinct on purpose: one answer for both a quiet
    /// tick and a tick whose evidence write *failed* leaves a report unable to
    /// tell "nothing happened" from "something happened and its record did not"
    /// — the exact detection-without-delivery failure I13 rules out, applied to
    /// the one run whose whole purpose is to make the sweeper's decisions
    /// answerable from the journal.
    async fn seal(self, store: &Arc<dyn JournalStore>) -> SweepRecord {
        let Some(run) = self.run else {
            return SweepRecord::Quiet;
        };
        if !self.wrote {
            // The first note failed before anything was applied: no decision
            // stands, so there is nothing to seal — and the phase error that
            // stopped the tick is already on its way to the caller.
            return SweepRecord::Quiet;
        }

        // The conclusion goes *in* the chain before the chain closes over it,
        // exactly as `conclude` does it for an ordinary run: tamper evidence
        // has to cover how the record ended, and the Merkle log commits to a
        // chain head that already includes its own sealing.
        let head = match store.head(run).await {
            Ok(head) => head,
            Err(e) => {
                tracing::error!(%run, error = %e, "a sweep's record could not be read back");
                return SweepRecord::EvidenceLost;
            }
        };
        let sealed = crate::journal::Append::new(
            run,
            RecordKind::RunConcluded {
                outcome: SWEEP_OUTCOME.to_owned(),
                reason: None,
                exhaustion: None,
                live_spend: crate::core::Spend::default(),
                chain_head: head.hash,
            },
        );
        if let Err(e) = store.append(SWEEP_EPOCH, vec![sealed]).await {
            tracing::error!(%run, error = %e, "a sweep's record could not be closed");
            return SweepRecord::EvidenceLost;
        }
        if let Err(e) = store.seal(run, SWEEP_EPOCH, SWEEP_OUTCOME).await {
            tracing::error!(%run, error = %e, "a sweep's record could not be sealed");
            return SweepRecord::EvidenceLost;
        }
        SweepRecord::Recorded(run)
    }
}

/// The fate of a tick's own evidence.
///
/// Three outcomes rather than an `Option<RunId>`, because a quiet tick and a
/// tick whose evidence could not be written are the two states an operator most
/// needs to tell apart: the first is the plane resting, the second is a decision
/// with no durable account of who made it.
enum SweepRecord {
    /// The tick decided nothing, so there was nothing to record.
    Quiet,
    /// The tick's decisions are in this sealed run.
    Recorded(RunId),
    /// The tick decided something and its record could not be written. The state
    /// changed and the journal did not.
    EvidenceLost,
}

/// What one timer pass did: wakes delivered, and wakes that died trying.
///
/// Two numbers rather than one, because they call for opposite responses. A
/// fired timer is the system working; a failed one is a run whose wake is now
/// late, healing through the recovery pass rather than through this one. A
/// single count would let the second hide inside the first.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WokenRuns {
    /// Sleeping runs resumed because their instant arrived.
    pub fired: usize,
    /// Due timers whose wake or resume failed; retried by claim expiry, and a
    /// wake that was already recorded reaches the recovery pass.
    pub failed: usize,
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
// Four bools is what this struct *is*: one independent yes/no per capped
// sweep, each meaning "that backlog may be deeper than this tick saw". They
// are not a state machine wearing flags — no combination is invalid — and an
// enum over sixteen combinations would be the lint satisfied at the reader's
// expense.
#[allow(clippy::struct_excessive_bools)]
pub struct Saturation {
    /// Timers fired up to the cap; more may have been due.
    pub timers: bool,
    /// Obligations handled up to the cap; more may have been outstanding.
    pub deadlines: bool,
    /// Expired tasks handled up to the cap; more may have been overdue.
    pub tasks: bool,
    /// Abandoned runs recovered up to the cap; more may have been stranded.
    pub recovery: bool,
}

impl Saturation {
    /// Whether any sweep was capped.
    ///
    /// A saturated tick means *at least* the cap was waiting, never that the
    /// cap was all there was.
    #[must_use]
    pub const fn any(self) -> bool {
        self.timers || self.deadlines || self.tasks || self.recovery
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
/// The smallest cap of the four, deliberately. Recovering a run is not a row
/// update: it replays the run's journal and then executes **live** from the
/// frontier, which may dispatch a model call. One tick therefore takes on a
/// bounded number of resurrections, and a mass failure — a whole instance's
/// worth of runs orphaned at once — drains over several ticks with the
/// saturation flag up rather than holding one tick hostage for the duration.
const RECOVERY_BATCH: usize = 32;
/// Redelivery walks the waiting list and touches the store per subscription,
/// so it takes the same bounded bite the timer pass does.
const EVENT_BATCH: usize = 128;

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
    /// Claimed-but-undelivered events whose delivery this tick finished.
    ///
    /// Each is a message that arrived in time and whose delivery died between
    /// the claim and the resume — a crash in that window, or an owner that
    /// outlived the delivery's bounded retry. The redelivery is the system
    /// healing; a persistent count here means deliveries keep dying, which is
    /// worth asking why.
    pub events_redelivered: usize,
    /// Sleeping runs woken because their instant arrived.
    ///
    /// Not a number to alert on — a fired timer is the system working. It is
    /// reported so a quiet plane is distinguishable from a stalled one.
    pub timers_fired: usize,
    /// Wake-ups whose resume failed after the wake was durably recorded.
    ///
    /// The timer is gone but the run has not moved. It is not lost: the lease
    /// the wake acquired lapses unreleased, and the recovery pass picks the
    /// run up on a later tick — but a failure on this path means wakes are
    /// arriving late, and a human should know why the first attempt died.
    pub wake_failures: usize,
    /// Runs taken over and resumed because their owner's lease lapsed without
    /// release — an instance died holding them.
    ///
    /// Each is a crash the plane healed. The healing is routine; the dying is
    /// not, so [`needs_attention`](Self::needs_attention) stays quiet about
    /// this count only when it is zero **and** nothing failed — a steady
    /// recovery rate with healthy instances is a contradiction worth seeing.
    pub runs_recovered: usize,
    /// Abandoned runs the recovery pass tried to resume and could not.
    ///
    /// The run stays listed and is retried next tick, so a persistent count
    /// here is one stuck run rather than many — but it is stuck, nothing else
    /// will unstick it, and the reason is in the log of the tick that failed.
    pub recovery_failures: usize,
    /// Which sweeps came back **full**, and therefore may not have seen
    /// everything that was waiting.
    pub saturated: Saturation,
    /// The sealed run holding this tick's own record, when it did anything.
    ///
    /// `None` for a quiet tick, which writes nothing — **and** `None` when the
    /// evidence write failed, which is a different fact entirely and is carried
    /// separately in [`evidence_lost`](Self::evidence_lost). Present means the
    /// sweeper's decisions are answerable from the journal rather than only
    /// from the state they produced.
    pub record: Option<RunId>,
    /// The tick decided something and its own record could not be written.
    ///
    /// The most serious thing this report can carry: the state changed —
    /// obligations breached, cases escalated — and the durable, tamper-evident
    /// account of *who decided that and when* did not. Distinct from a quiet
    /// tick, which also leaves `record` empty but changed nothing, and it makes
    /// [`needs_attention`](Self::needs_attention) true so it cannot pass as one.
    pub evidence_lost: bool,
    /// What the plane is holding, as of this sweep.
    ///
    /// Carried on the report as well as emitted, so an embedder that wants the
    /// numbers does not have to stand up a metrics subscriber to see them.
    pub census: Census,
    /// The gauges could not be read this tick.
    ///
    /// The counters above are still real — the tick's work happened — but the
    /// census is a default, not a reading. Carried as a flag rather than an
    /// error because a report that arrives degraded beats one that was thrown
    /// away over a gauge: the breaches and recoveries it accounts for already
    /// happened.
    pub census_unavailable: bool,
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
            // A decision whose evidence never landed is the I13 failure this
            // report exists to surface: the state moved and the record did not.
            || self.evidence_lost
            // A recovery that keeps failing is a run nothing else will
            // unstick; a wake whose resume died is a run arriving late.
            // Recoveries that *succeeded* stay off this list — they are the
            // plane healing, findable in the report and the sweep's own run.
            || self.recovery_failures > 0
            || self.wake_failures > 0
            // Gauges that could not be read are a blind spot wearing a
            // default; somebody should know the numbers are missing, not
            // merely zero.
            || self.census_unavailable
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
            && self.events_redelivered == 0
            && self.timers_fired == 0
            && self.wake_failures == 0
            && self.runs_recovered == 0
            && self.recovery_failures == 0
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
        event_grace: std::time::Duration,
    ) -> Result<SweepReport, RuntimeError> {
        let mut report = SweepReport::default();
        let mut ledger = SweepLedger::new();

        // The fallible phases, folded into one result so the ledger outlives
        // whichever of them fails. The deadline pass may have breached an
        // obligation *into state* before a later phase errored, and evidence
        // already earned must not leave with the error — a `?` past an
        // unsealed ledger is the sweep silently dropping the account of
        // decisions it already applied, which is the exact failure the ledger
        // exists to prevent, reintroduced by control flow.
        let phases: Result<(), RuntimeError> = async {
            // Recovery first: an abandoned run may be one step from meeting a
            // deadline the pass below would otherwise breach.
            self.recover_abandoned(&mut report, &mut ledger).await?;
            report.warned += self.sweep_deadlines(now, &mut report, &mut ledger).await?;
            self.sweep_tasks(now, &mut report, &mut ledger).await?;

            if self.events().is_some() {
                // Deliveries that died between the claim and the resume — a
                // crash in that window, or an owner that outlived the
                // delivery's bounded retry. The claimed event blocks every
                // dedup'd retry of itself, so this pass is the only driver
                // left; without it the message that arrived in time is parked
                // forever behind its own claim.
                report.events_redelivered = self.redeliver_claimed(EVENT_BATCH).await?;
                report.dead_lettered = self.sweep_events(event_grace).await?;
            }
            if self.timers().is_some() {
                let woken = self.fire_timers(now).await?;
                report.timers_fired = woken.fired;
                report.wake_failures = woken.failed;
                // Failed wakes consumed claims too, so the cap is judged on
                // the whole batch: a tick that failed its way through the cap
                // has seen as little of the backlog as one that fired it.
                if woken.fired + woken.failed >= TIMER_BATCH {
                    report.saturated.timers = true;
                }
            }
            Ok(())
        }
        .await;

        // Written before the census so the record covers the decisions, not the
        // reading. A tick that decided nothing writes nothing — and a tick that
        // decided something and then *errored* still writes, which is why this
        // sits outside the block above rather than after a `?`.
        match ledger.seal(self.store()).await {
            SweepRecord::Quiet => {}
            SweepRecord::Recorded(run) => report.record = Some(run),
            SweepRecord::EvidenceLost => report.evidence_lost = true,
        }
        phases?;

        // Observed last, so the reading reflects what this sweep just resolved
        // rather than the backlog it was about to clear. A failed reading
        // **degrades** the report rather than discarding it: everything above
        // — the breaches, the recoveries, the sealed evidence run — already
        // happened, and a `?` here threw the whole account away because one
        // gauge could not be read at the end. The flag keeps the absence
        // loud; the counters keep what the tick actually did.
        match self.census(now).await {
            Ok(census) => {
                report.census = census;
                self.meter().census(&report.census);
            }
            Err(error) => {
                report.census_unavailable = true;
                tracing::error!(
                    %error,
                    "the census could not be read; this report carries the tick's \
                     counters and no gauges"
                );
            }
        }

        Ok(report)
    }

    /// Take over and resume the runs an instance died holding.
    ///
    /// The candidate set is exact, not heuristic: every clean exit — sealed,
    /// failed, suspended — hands its lease back, so a lease that **expired
    /// without release** names a run somebody was executing when their process
    /// stopped. Fencing makes this takeover safe (the resume bumps the epoch,
    /// and the store refuses the dead owner's next append), replay makes it
    /// correct (completed effects are read back, never redone), and this pass
    /// is what makes it *happen* — without it, a crashed run with no pending
    /// timer and no inbound event has no driver, appears in no backlog, and
    /// waits forever while looking exactly like work in progress.
    ///
    /// Per-run failures are contained: one unresumable run is counted, logged
    /// and retried next tick rather than blocking the runs behind it. A lease
    /// held by someone else is not a failure at all — another instance got
    /// there first, which is the mechanism working.
    async fn recover_abandoned(
        &self,
        report: &mut SweepReport,
        ledger: &mut SweepLedger,
    ) -> Result<(), RuntimeError> {
        let stranded = self
            .store()
            .abandoned_runs(RECOVERY_BATCH)
            .await
            .map_err(RuntimeError::from_store)?;
        if stranded.len() >= RECOVERY_BATCH {
            report.saturated.recovery = true;
        }
        for run in stranded {
            // The note lands **before** the takeover — the ledger's rule,
            // and this pass is where getting it backwards loses the record
            // permanently rather than briefly: a resume that concludes
            // releases the lease, the run leaves the driving query, and no
            // later tick can re-select it to write the account. The note
            // carries the lapse and the takeover attempt, deliberately not
            // the outcome — the recovered run's own journal answers that.
            ledger
                .note(
                    self.store(),
                    None,
                    run.to_string(),
                    SweptAction::RunRecovered,
                    Some(
                        "its owner's lease lapsed without release; taking the run \
                         over and resuming it"
                            .to_owned(),
                    ),
                )
                .await?;
            match self.recover_abandoned_run(run).await {
                Ok(outcome) => {
                    // A resume that concluded released its lease on the way
                    // out. The one path that does not is the closed-run
                    // no-op — a crash landed between `seal` and the release —
                    // and without this the same sealed run would be "recovered"
                    // every tick forever. Acquire-then-release is how a party
                    // with no epoch clears a lease it does not hold; a live
                    // lease refuses the acquire, which is the guard working.
                    if let Ok(lease) = self.store().acquire(run, self.owner_id(), LEASE_TTL).await {
                        let _ = self.store().release_lease(run, lease.epoch).await;
                    }
                    let status = outcome.status.as_str().to_owned();
                    tracing::info!(
                        target: super::telemetry::RUN_RECOVERED,
                        %run,
                        outcome = %status,
                    );
                    self.meter().count(metrics::RUNS_RECOVERED, &status);
                    report.runs_recovered += 1;
                }
                // Someone else holds it live: a second instance's recovery —
                // or the owner back from a stall, about to be fenced. Either
                // way it is being handled, and counting it as a failure would
                // page an operator about a race the design already settles.
                // The note above stands, and honestly: this instance observed
                // the lapse and moved to take the run over; the run's own
                // journal shows who won.
                Err(RuntimeError::Store(StoreError::LeaseHeld { .. })) => {}
                // A lease over an **empty** journal: admission acquired and
                // died before its first append landed. There is no run — the
                // atomic admission batch never committed, so nothing was
                // declared, authorized or performed. Clearing the lease is the
                // whole recovery; leaving this to the failure arm below would
                // retry a resume that cannot exist, every tick, forever. The
                // explanation is its own note, written before the clear it
                // describes.
                Err(RuntimeError::Store(StoreError::NotFound(_))) => {
                    ledger
                        .note(
                            self.store(),
                            None,
                            run.to_string(),
                            SweptAction::RunRecovered,
                            Some(
                                "its owner died between acquiring the lease and the \
                                 admission append; no run exists, so clearing the \
                                 lease is the whole recovery"
                                    .to_owned(),
                            ),
                        )
                        .await?;
                    if let Ok(lease) = self.store().acquire(run, self.owner_id(), LEASE_TTL).await {
                        if let Err(error) = self.release_empty_quota_reservation(run).await {
                            tracing::warn!(%run, %error, "could not release the quota slot of an empty abandoned admission");
                        }
                        let _ = self.store().release_lease(run, lease.epoch).await;
                    }
                    report.runs_recovered += 1;
                }
                Err(error) => {
                    tracing::error!(%run, %error, "an abandoned run could not be resumed");
                    self.meter().count(metrics::RECOVERY_FAILURES, "");
                    report.recovery_failures += 1;
                }
            }
        }
        Ok(())
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
    ///
    /// One run's failure does not block the runs behind it: a batch that stops
    /// at the first error hands a single unresumable run a veto over every
    /// later wake in the tick — and the failed run heals anyway: its wake was
    /// recorded under a lease this pass acquired and never released, so the
    /// recovery pass finds it once that lease lapses. The failure is counted
    /// rather than returned, because a caller that got a count and an error
    /// would have neither.
    pub async fn fire_timers(&self, now: Timestamp) -> Result<WokenRuns, RuntimeError> {
        let timers = self.timers().ok_or_else(|| {
            RuntimeError::PlanContract(
                "this runtime has no timer store — build it with `.timers(store)`".into(),
            )
        })?;

        let due = timers
            .claim_due(now, TIMER_BATCH)
            .await
            .map_err(RuntimeError::from_store)?;
        let mut woken = WokenRuns::default();
        for timer in due {
            match self.fire_one(&timer).await {
                Ok(()) => woken.fired += 1,
                Err(error) => {
                    tracing::error!(
                        run = %timer.run,
                        step = %timer.step,
                        %error,
                        "a due timer's wake failed; the claim lease retries it, \
                         and a wake recorded before the failure reaches the \
                         recovery pass",
                    );
                    woken.failed += 1;
                }
            }
        }

        Ok(woken)
    }

    /// Record one timer's wake and resume its run.
    async fn fire_one(&self, timer: &crate::core::Timer) -> Result<(), RuntimeError> {
        let lease = self
            .store()
            .acquire(timer.run, self.owner_id(), LEASE_TTL)
            .await
            .map_err(RuntimeError::from_store)?;

        // A crash between last tick's append and its disarm leaves the wake
        // recorded and the timer armed, so this claim fires again. The check
        // makes that a second *resume*, not a second record: an append here
        // would put a duplicate wake in the chain, and the journal is the one
        // place a retry must never show up twice.
        let already_recorded = self
            .store()
            .read(timer.run, 1)
            .await
            .map_err(RuntimeError::from_store)?
            .iter()
            .any(|record| {
                record.effect_key() == Some(timer.effect)
                    && matches!(record.kind(), RecordKind::EffectDone { .. })
            });
        if !already_recorded {
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
                    // The runtime's own instant, chosen and journaled here —
                    // one of the few values that crosses no trust boundary.
                    declared: crate::core::DeclaredOutput::trusted(),
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
        }

        self.timers()
            .ok_or_else(|| RuntimeError::PlanContract("timer store vanished mid-sweep".into()))?
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

        // The wake is recorded and the timer disarmed; the resume continues
        // under the *same* lease rather than releasing and re-acquiring. The
        // old release-then-acquire choreography opened a window this pass
        // could not see again: a crash between the release and the resume's
        // acquire left a released lease over a run whose timer was already
        // disarmed — no driver, and absent from the abandonment queue, which
        // lists only leases that expired while still naming an owner. Handing
        // the lease over keeps the run owned continuously from wake to
        // conclusion, so a crash anywhere in the resume leaves an owned lease
        // the sweep drains. A `LeaseHeld` can still surface if this lease
        // lapses mid-resume and somebody else claims the run — they will read
        // the recorded wake like any other completed effect.
        match self.resume_holding(timer.run, lease).await {
            Ok(_) | Err(RuntimeError::LeaseHeld { .. }) => Ok(()),
            Err(e) => Err(e),
        }
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
                //
                // The notes land **before** the transitions — I2, applied to
                // the sweeper. Acting first orphans the decision permanently:
                // the transition is idempotent, so the next tick finds it
                // already applied and writes nothing, leaving a breached case
                // with no durable account of who breached it or when. Written
                // first, a crash leaves a note whose transition the next tick
                // re-applies — a duplicate decision on the record, which is
                // honest, rather than an applied decision off it.
                ledger
                    .note(
                        self.store(),
                        Some(deadline.case),
                        deadline.case.to_string(),
                        SweptAction::DeadlineBreached,
                        Some(format!(
                            "'{}' was due {} and was not met",
                            deadline.name, deadline.resolved_at
                        )),
                    )
                    .await?;
                ledger
                    .note(
                        self.store(),
                        Some(deadline.case),
                        deadline.case.to_string(),
                        SweptAction::CaseEscalated,
                        Some(format!("obligation '{}' was breached", deadline.name)),
                    )
                    .await?;
                // The de-indexing write goes last. `due` selects obligations
                // that are still outstanding, so writing `Breached` is what
                // removes this one from the pass driving it — put anything
                // after that write and a crash there strands a breach no tick
                // will select again. Escalating twice is a no-op, so the order
                // that repeats work is the order that is safe. `sweep_tasks`
                // follows the same rule.
                cases
                    .set_status(deadline.case, CaseStatus::Escalated)
                    .await
                    .map_err(RuntimeError::from_store)?;
                cases
                    .set_deadline_state(deadline.case, &deadline.name, DeadlineState::Breached)
                    .await
                    .map_err(RuntimeError::from_store)?;
                tracing::error!(
                    target: super::telemetry::DEADLINE_BREACHED,
                    case = %deadline.case,
                    obligation = %deadline.name,
                    due = %deadline.resolved_at,
                );
                self.meter().count(metrics::DEADLINE_BREACHES, "");
                report.breached += 1;
            } else if deadline.needs_warning(now) {
                ledger
                    .note(
                        self.store(),
                        Some(deadline.case),
                        deadline.case.to_string(),
                        SweptAction::DeadlineWarned,
                        Some(format!(
                            "'{}' comes due {}",
                            deadline.name, deadline.resolved_at
                        )),
                    )
                    .await?;
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
                // Widen the audience, clear the stale reservation, and keep
                // waiting. `escalate` is the write that removes the task from
                // `overdue`, so it goes last (the note is already durable) —
                // a crash between the two re-selects the task next tick and
                // repeats the note, which is the affordable direction.
                OnExpiry::Escalate => {
                    ledger
                        .note(
                            self.store(),
                            task.case,
                            task.id.to_hex(),
                            SweptAction::TaskEscalated,
                            Some("nobody answered inside the window".to_owned()),
                        )
                        .await?;
                    tasks
                        .escalate(task.id)
                        .await
                        .map_err(RuntimeError::from_store)?;
                    report.tasks_escalated += 1;
                }

                // Deny or proceed: both are decisions that were made in advance,
                // and both resume the run with a recorded answer rather than
                // leaving it hanging.
                policy => {
                    let decision = Decision::expired(policy);
                    ledger
                        .note(
                            self.store(),
                            task.case,
                            task.id.to_hex(),
                            SweptAction::TaskExpired,
                            // The *declared* policy, so the record says what was
                            // decided in advance rather than only what happened.
                            Some(format!("window closed; applied {policy:?}")),
                        )
                        .await?;
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

        // The claim protocol's refusals surface as
        // [`RuntimeError::TaskClaim`], exactly as the claim verb reports them.
        // Wrapped as a policy denial they would claim a rule fired when none
        // did, and collapse three different answers into one class.
        tasks.claim(id, &decision.actor, roles).await?;

        let delivery = self.answer_task(id, decision).await?;
        tasks
            .set_state(id, TaskState::Completed)
            .await
            .map_err(RuntimeError::from_store)?;
        Ok(delivery)
    }
}
