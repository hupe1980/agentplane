//! The journal-as-outbox loop, with the payload left to the caller.
//!
//! # Why this is not inside the A2A server any more
//!
//! The cursor discipline — read from the journal past `next_seq`, POST, advance
//! only on 2xx, back off on anything else, give up on a permanent refusal — is
//! the part of push worth having, and it has nothing to do with A2A. It lived
//! inside `A2aPushWorker` because A2A was the first caller, which made the one
//! thing an operator most wants reachable only by speaking somebody else's
//! protocol and only for a **caller-supplied** URL.
//!
//! So the loop is here, parameterised by a [`Projection`]: *what should this
//! record be sent as, and does it end the stream?* A2A answers with
//! `StreamResponse`; a deployment answers with whatever its own bus consumes.
//! One implementation, because two copies of a retry policy agree everywhere
//! except the boundary nobody probes.
//!
//! # At-least-once, stated as a preference
//!
//! A crash after POST and before the cursor is persisted repeats an event. That
//! is the direction chosen deliberately: the alternative — advance first, then
//! POST — loses events on the same crash, and a receiver that must tolerate
//! duplicates is a receiver that can be built, while one that must tolerate
//! silence is not.

use std::fmt::Debug;
use std::sync::Arc;

use crate::core::StoreError;
use crate::journal::{JournalStore, Record, RecordKind};
use async_trait::async_trait;

use super::{Delivered, PushMessage, PushNamespace, PushRegistration, PushStore, PushTransport};

/// What one journal record should be delivered as.
///
/// Returning **several** messages for one record is deliberate: A2A's status and
/// artifact events are two messages derived from one append, and a projection
/// that could only answer with one would force the caller to invent a second
/// cursor. An empty vector means *nothing to send for this record*, and the
/// cursor still advances past it — which is how a projection filters.
#[async_trait]
pub trait Projection: Send + Sync + Debug {
    /// The messages this record becomes, in delivery order.
    ///
    /// Each carries its own media type and its own identity, because those are
    /// facts about the payload and not about the loop: two projections share
    /// this worker and speak different wires, and a receiver that cannot
    /// recognise a repeat has no defence against at-least-once delivery. See
    /// [`PushMessage`].
    ///
    /// # Errors
    ///
    /// [`StoreError`] when the record cannot be projected — a materialisation
    /// that needs a blob store, say. The worker treats this as **transient and
    /// this plane's own fault**: the cursor does not move, so the same record is
    /// tried again, and the retry ceiling still applies because a record that
    /// cannot be projected now will not project on the next tick either.
    async fn messages(&self, record: &Record) -> Result<Vec<PushMessage>, StoreError>;

    /// Whether this record ends the stream for its run.
    ///
    /// The registration is deleted once its payloads are acknowledged, because a
    /// cursor sitting forever at the end of a sealed run's journal is a row that
    /// is scanned on every tick and can never move.
    ///
    /// The default is [`RecordKind::RunSealed`], which is the honest answer for
    /// anything keyed on a run: nothing is appended after a seal.
    fn terminal(&self, record: &Record) -> bool {
        matches!(record.kind(), RecordKind::RunSealed { .. })
    }

    /// Which id namespace this worker serves.
    ///
    /// Two workers share one store: the A2A worker serves caller-registered
    /// webhooks, the outbox worker serves operator destinations. Without this
    /// each would deliver the other's rows with its own projection — an
    /// operator's `CloudEvents` message to a peer's A2A webhook, and a `StreamResponse` to
    /// the deployment's bus.
    ///
    /// A declaration rather than a per-row predicate, because the split is the
    /// **store's** discriminator: the worker hands it to
    /// [`PushStore::due_in`](super::PushStore::due_in) so the query itself
    /// filters, instead of reading a bounded window and dropping the rows it
    /// does not own — which starves this worker's rows the moment the other
    /// namespace fills the window.
    fn namespace(&self) -> PushNamespace;
}

/// Outcome of one bounded delivery sweep.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PushSweepReport {
    pub registrations: usize,
    pub records: usize,
    pub deliveries: usize,
    pub retries: usize,
    pub completed: usize,
    /// Registrations this sweep stopped delivering to: a permanent refusal, or
    /// a receiver that stayed unreachable past the worker's retry ceiling.
    ///
    /// Counted separately from `completed` because they are opposite outcomes
    /// wearing one shape — both take the registration out of the due order, and
    /// only one of them delivered anything. The rows themselves survive with
    /// their cursors, listed by [`PushStore::parked`](super::PushStore::parked);
    /// this number is how an operator learns there is a list to read.
    pub parked: usize,
    /// Due rows in the **other** id namespace — work this worker must not
    /// touch, surfaced so it cannot be invisible.
    ///
    /// A deployment that scheduled only one of the two workers has a backlog
    /// no sweep will ever serve, and before this field its report was
    /// byte-identical to a quiet plane's. Deliberately **not** part of
    /// [`needs_attention`](Self::needs_attention): whenever both workers run,
    /// the other's rows are legitimately due in the instants between its
    /// sweeps, and one tick cannot tell that ordinary overlap from an
    /// unserved namespace — so this is visibility, judged by the operator who
    /// knows which workers exist.
    pub unserved: usize,
    pub saturated: bool,
}

impl PushSweepReport {
    /// Whether this tick found anything a human should see.
    ///
    /// A webhook that will never be delivered to must not produce a line
    /// byte-identical to a receiver that is merely rebooting: a single
    /// `retries: 1` is the ordinary shape of both, and only parking
    /// distinguishes them.
    #[must_use]
    pub const fn needs_attention(&self) -> bool {
        // A backlog and a quiet plane must not produce the same numbers.
        self.saturated || self.parked > 0
    }
}

/// Durable outbound delivery, driven by an operator's scheduler.
///
/// The clock is the caller's: [`run_once`](Self::run_once) takes `at` rather
/// than reading one, so backoff is testable and a deployment owns its own
/// cadence. Several instances may sweep concurrently — duplicates are within
/// contract, and cursor updates advance monotonically so a race cannot lose an
/// event.
#[derive(Debug, Clone)]
pub struct DeliveryWorker {
    journal: Arc<dyn JournalStore>,
    store: Arc<dyn PushStore>,
    transport: Arc<dyn PushTransport>,
    projection: Arc<dyn Projection>,
    max_attempts: u32,
    max_in_flight: usize,
}

/// What one registration's turn achieved.
///
/// Separate from [`PushSweepReport`] because the two answer different
/// questions: this one is per-registration and is summed, while the report also
/// carries facts about the *sweep* — saturation, the other namespace's backlog
/// — that no single registration can observe. Folding into the report directly
/// would mean every concurrent turn holding the same mutable value, which is
/// the ordering the fan-out exists to remove.
#[derive(Debug, Default, Clone, Copy)]
struct Progress {
    records: usize,
    deliveries: usize,
    retries: usize,
    completed: usize,
    parked: usize,
}

impl DeliveryWorker {
    /// How many consecutive failures a receiver gets before it is parked.
    ///
    /// The schedule is `1 << min(attempts, 8)` seconds, jittered downward and
    /// capped at 256 s, so 32 attempts is between about fifty minutes and one
    /// hour forty of a receiver being down — a reboot, a deploy or a
    /// certificate renewal, and not a webhook that has gone away. Past it the
    /// registration is [parked](super::PushStore::park) and *reported*: the
    /// alternative is a row retried until the journal is deleted, and a queue
    /// that only ever grows is one nobody can read.
    pub const DEFAULT_MAX_ATTEMPTS: u32 = 32;

    /// The longest a receiver's own `Retry-After` may park a registration.
    ///
    /// Advice is honoured because a receiver naming its recovery knows better
    /// than a fixed schedule — but it is *advice*, from the one party with an
    /// interest in never being called again. An hour is long enough for any
    /// real rate limit and short enough that a hostile or broken value costs
    /// one wasted hour rather than the life of the deployment.
    pub const MAX_RETRY_AFTER: u64 = 3_600;

    /// How many receivers one sweep talks to at once.
    ///
    /// The number bounds *this plane's* outbound sockets, not any one
    /// receiver's load — two registrations pointing at the same host are
    /// ordinary, and spreading their retries is the backoff schedule's job
    /// rather than this ceiling's. Sixteen is enough that a handful of slow
    /// receivers cannot
    /// stall a sweep and small enough that a plane with a large backlog does
    /// not answer a scheduler tick by opening a thousand connections.
    pub const DEFAULT_MAX_IN_FLIGHT: usize = 16;

    #[must_use]
    pub fn new(
        journal: Arc<dyn JournalStore>,
        store: Arc<dyn PushStore>,
        transport: Arc<dyn PushTransport>,
        projection: Arc<dyn Projection>,
    ) -> Self {
        Self {
            journal,
            store,
            transport,
            projection,
            max_attempts: Self::DEFAULT_MAX_ATTEMPTS,
            max_in_flight: Self::DEFAULT_MAX_IN_FLIGHT,
        }
    }

    /// Change how many receivers one sweep talks to at once.
    ///
    /// # Panics
    ///
    /// If `n` is zero — a sweep that may contact nobody is not a concurrency
    /// setting, it is an off switch spelled as one, and it would report a
    /// perfectly quiet plane forever.
    #[must_use]
    pub const fn max_in_flight(mut self, n: usize) -> Self {
        assert!(
            n > 0,
            "a push concurrency of zero contacts no receiver and reports a \
             quiet plane; schedule no worker instead"
        );
        self.max_in_flight = n;
        self
    }

    /// Change the retry ceiling.
    ///
    /// # Panics
    ///
    /// If `attempts` is zero — that would spell *never deliver anything* as if
    /// it were a retry policy.
    #[must_use]
    pub const fn max_attempts(mut self, attempts: u32) -> Self {
        assert!(
            attempts > 0,
            "a push retry ceiling of zero abandons every receiver on its first \
             hiccup; configure no push instead"
        );
        self.max_attempts = attempts;
        self
    }

    /// Deliver at most `limit` due registrations once.
    ///
    /// `at` is Unix time in seconds and is explicit to make backoff tests
    /// deterministic. The operator owns scheduling and the clock.
    ///
    /// # Giving up is a state, not a deletion
    ///
    /// Two failures stop a registration rather than rescheduling it, and both
    /// are counted in [`PushSweepReport::parked`]: a **permanent** answer —
    /// [`PushError::is_permanent`](super::PushError::is_permanent) for a host
    /// taken off the allowlist, a URL that is not HTTPS or does not parse, and
    /// [`Delivered::is_permanent`] for a receiver answering 410 Gone — which no
    /// backoff improves; and a transient failure that has happened
    /// [`max_attempts`](Self::max_attempts) times, which is a receiver that is
    /// not coming back on its own.
    ///
    /// Either way the row keeps its cursor. That is the difference between a
    /// backlog and a loss: an operator who fixes the receiver calls
    /// [`PushStore::unpark`](super::PushStore::unpark) and delivery resumes at
    /// the first record that receiver never acknowledged.
    ///
    /// # Errors
    ///
    /// [`StoreError`] when the push store or the journal cannot be read.
    pub async fn run_once(
        &self,
        at: u64,
        limit: usize,
    ) -> Result<PushSweepReport, crate::core::StoreError> {
        use futures_util::StreamExt as _;

        // One over the limit, so a saturated sweep is distinguishable from one
        // that happened to fill the page exactly. The namespace filter rides
        // in the query itself: filtering a bounded read afterwards let rows of
        // the other namespace occupy the whole window, starving this worker's
        // own rows while its report read as a quiet plane.
        let batch = self
            .store
            .due_in(at, limit.saturating_add(1), self.projection.namespace())
            .await?;
        let saturated = batch.rows.len() > limit;
        let mut report = PushSweepReport {
            registrations: batch.rows.len().min(limit),
            unserved: batch.unserved,
            saturated,
            ..PushSweepReport::default()
        };

        // Registrations are independent — different tasks, different receivers,
        // different cursors — so nothing about the cursor discipline requires
        // them to be served in order. Serving them in order requires only that
        // every receiver be as fast as the slowest, which is not a property
        // anybody can arrange: one endpoint sitting on its 15 s timeout would
        // hold the whole sweep, and a plane with more registrations than a
        // sweep can reach in its tick falls permanently behind on all of them.
        //
        // Bounded rather than unbounded: a sweep is the one place this crate
        // knows how much outbound work exists, and `limit` is a page size
        // rather than a concurrency budget. Ordering **within** one
        // registration is untouched — that loop is still strictly sequential,
        // because its whole content is a cursor that may only move forward.
        let outcomes: Vec<_> = futures_util::stream::iter(
            batch
                .rows
                .into_iter()
                .take(limit)
                .map(|registration| self.deliver_one(registration, at)),
        )
        .buffer_unordered(self.max_in_flight)
        .collect()
        .await;

        for outcome in outcomes {
            let progress = outcome?;
            report.records += progress.records;
            report.deliveries += progress.deliveries;
            report.retries += progress.retries;
            report.completed += progress.completed;
            report.parked += progress.parked;
        }
        Ok(report)
    }

    /// Drain one registration's backlog, as far as its receiver allows.
    ///
    /// Sequential by construction, and that is the invariant rather than an
    /// implementation detail: the cursor is a promise that everything before it
    /// was acknowledged, so a record may not be delivered until the one before
    /// it was. Concurrency across registrations is free; concurrency within one
    /// would break the only thing the cursor means.
    async fn deliver_one(
        &self,
        registration: PushRegistration,
        at: u64,
    ) -> Result<Progress, crate::core::StoreError> {
        let mut progress = Progress::default();
        let mut attempts = registration.attempts;
        let records = self
            .journal
            .read(registration.config.task, registration.next_seq)
            .await?;
        if records.is_empty() && self.cleanup_acknowledged_terminal(&registration).await? {
            progress.completed += 1;
            return Ok(progress);
        }
        for record in records {
            let messages = match self.projection.messages(&record).await {
                Ok(messages) => messages,
                Err(error) => {
                    // A projection failure is this plane's own bug, never the
                    // receiver's, so it is always transient here — the ceiling
                    // still applies, because a record that cannot be projected
                    // cannot be projected on the next tick either and the
                    // cursor never moves past it.
                    self.give_up_or_retry(
                        &registration,
                        at,
                        attempts,
                        &Failure::transient(error.to_string()),
                        &mut progress,
                    )
                    .await?;
                    break;
                }
            };
            let mut failed = None;
            for message in messages {
                match self
                    .transport
                    .deliver(&registration.config, &message, at)
                    .await
                {
                    Ok(Delivered::Accepted) => progress.deliveries += 1,
                    Ok(other) => {
                        failed = Some(Failure {
                            error: format!("receiver outcome: {other:?}"),
                            permanent: other.is_permanent(),
                            retry_after: other.retry_after(),
                        });
                    }
                    Err(error) => {
                        failed = Some(Failure {
                            permanent: error.is_permanent(),
                            error: error.to_string(),
                            retry_after: None,
                        });
                    }
                }
                if failed.is_some() {
                    break;
                }
            }
            if let Some(failure) = failed {
                self.give_up_or_retry(&registration, at, attempts, &failure, &mut progress)
                    .await?;
                break;
            }
            self.store
                .advance(
                    registration.config.task,
                    &registration.config.id,
                    record.body.seq.saturating_add(1),
                )
                .await?;
            attempts = 0;
            progress.records += 1;
            if self.projection.terminal(&record) {
                self.store
                    .delete(registration.config.task, &registration.config.id)
                    .await?;
                progress.completed += 1;
                break;
            }
        }
        Ok(progress)
    }

    /// Reschedule one failed registration, or park it.
    ///
    /// One implementation, because the two call sites above are the same
    /// decision and a second copy of it is the shape that agrees everywhere
    /// except the boundary nobody probed.
    async fn give_up_or_retry(
        &self,
        registration: &PushRegistration,
        at: u64,
        attempts: u32,
        failure: &Failure,
        report: &mut Progress,
    ) -> Result<(), crate::core::StoreError> {
        // `attempts` counts the failures *before* this one, so the ceiling is
        // reached when this failure makes it up to the ceiling — not one tick
        // later, which would make `max_attempts(1)` mean two attempts.
        let exhausted = attempts.saturating_add(1) >= self.max_attempts;
        if failure.permanent || exhausted {
            let reason = if failure.permanent {
                "this destination answered permanently"
            } else {
                "the receiver did not answer within the retry ceiling"
            };
            tracing::warn!(
                task = %registration.config.task,
                config = %registration.config.id,
                url = %registration.config.url,
                attempts = attempts.saturating_add(1),
                error = %failure.error,
                "parking a push registration: {reason} — its cursor is kept, so \
                 `unpark` resumes at the first record the receiver never took"
            );
            self.store
                .park(
                    registration.config.task,
                    &registration.config.id,
                    &failure.error,
                )
                .await?;
            report.parked += 1;
            return Ok(());
        }
        self.store
            .retry(
                registration.config.task,
                &registration.config.id,
                Self::next_attempt_at(registration, at, attempts, failure.retry_after),
                &failure.error,
            )
            .await?;
        report.retries += 1;
        Ok(())
    }

    /// When to try this registration again.
    ///
    /// The receiver's own `Retry-After` wins when it named one, bounded by
    /// [`MAX_RETRY_AFTER`](Self::MAX_RETRY_AFTER). Otherwise the schedule is
    /// exponential — `1 << min(attempts, 8)`, capping at 256 s — with the delay
    /// drawn from the lower half of that window rather than sitting exactly on
    /// it.
    ///
    /// # Why the jitter is derived and not random
    ///
    /// Every registration that failed against one receiver failed in the same
    /// sweep, so an undithered schedule sends all of them back at the *same
    /// instant* — and the moment a receiver recovers it is hit by its entire
    /// backlog at once, which is how a recovering service is knocked over by
    /// the sender that was waiting politely. Spreading them is the fix; drawing
    /// the spread from a random source would make backoff untestable and every
    /// sweep unreproducible, which this worker deliberately is not — `at` is
    /// the caller's for exactly that reason. So the offset is a hash of the
    /// registration and its attempt count: fixed for a given row and tick,
    /// uncorrelated between rows.
    fn next_attempt_at(
        registration: &PushRegistration,
        at: u64,
        attempts: u32,
        advice: Option<u64>,
    ) -> u64 {
        if let Some(seconds) = advice {
            return at.saturating_add(seconds.clamp(1, Self::MAX_RETRY_AFTER));
        }
        let window = 1u64 << attempts.min(8);
        let half = window / 2;
        let offset = spread(registration, attempts) % (half.saturating_add(1));
        at.saturating_add(half.saturating_add(offset).max(1))
    }

    /// Remove a registration whose run sealed and whose seal was acknowledged.
    ///
    /// Needed because the terminal record may have been delivered by a sweep
    /// that crashed after `advance` and before `delete`. Without it the row
    /// stays forever, read on every tick, with nothing left to send.
    async fn cleanup_acknowledged_terminal(
        &self,
        registration: &PushRegistration,
    ) -> Result<bool, crate::core::StoreError> {
        if registration.next_seq <= 1 {
            return Ok(false);
        }
        let previous = self
            .journal
            .read(
                registration.config.task,
                registration.next_seq.saturating_sub(1),
            )
            .await?;
        let completed = previous.last().is_some_and(|record| {
            record.body.seq.saturating_add(1) == registration.next_seq
                && self.projection.terminal(record)
        });
        if completed {
            self.store
                .delete(registration.config.task, &registration.config.id)
                .await?;
        }
        Ok(completed)
    }
}

/// One failed attempt, as the retry decision needs to see it.
///
/// A struct rather than three positional arguments because the two call sites
/// disagreed about their order once, and a `bool` that means *permanent* next
/// to a `bool` that means anything else is a defect nothing catches.
struct Failure {
    error: String,
    permanent: bool,
    retry_after: Option<u64>,
}

impl Failure {
    fn transient(error: String) -> Self {
        Self {
            error,
            permanent: false,
            retry_after: None,
        }
    }
}

/// A registration's fixed place in the retry window, in seconds.
///
/// SHA-256 rather than `DefaultHasher`, whose output is stable only within one
/// Rust version: a backoff instant that moved with the toolchain would make
/// every schedule assertion a version pin.
fn spread(registration: &PushRegistration, attempts: u32) -> u64 {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(registration.config.task.to_string().as_bytes());
    hasher.update([0x1f]);
    hasher.update(registration.config.id.as_bytes());
    hasher.update([0x1f]);
    hasher.update(attempts.to_be_bytes());
    let digest = hasher.finalize();
    u64::from_be_bytes(digest[..8].try_into().expect("SHA-256 is 32 bytes"))
}
