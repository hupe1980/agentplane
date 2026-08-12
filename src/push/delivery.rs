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

use async_trait::async_trait;
use serde_json::Value;

use crate::core::StoreError;
use crate::journal::{JournalStore, Record, RecordKind};

use super::{Delivered, PushRegistration, PushStore, PushTransport};

/// What one journal record should be delivered as.
///
/// Returning **several** payloads for one record is deliberate: A2A's status and
/// artifact events are two messages derived from one append, and a projection
/// that could only answer with one would force the caller to invent a second
/// cursor. An empty vector means *nothing to send for this record*, and the
/// cursor still advances past it — which is how a projection filters.
#[async_trait]
pub trait Projection: Send + Sync + Debug {
    /// The payloads this record becomes, in delivery order.
    ///
    /// # Errors
    ///
    /// [`StoreError`] when the record cannot be projected — a materialisation
    /// that needs a blob store, say. The worker treats this as **transient and
    /// this plane's own fault**: the cursor does not move, so the same record is
    /// tried again, and the retry ceiling still applies because a record that
    /// cannot be projected now will not project on the next tick either.
    async fn payloads(&self, record: &Record) -> Result<Vec<Value>, StoreError>;

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

    /// Whether this worker owns a registration.
    ///
    /// Two workers share one store: the A2A worker serves caller-registered
    /// webhooks, the outbox worker serves operator destinations. Without this
    /// each would deliver the other's rows with its own projection — an
    /// operator's `CloudEvents` message to a peer's A2A webhook, and a `StreamResponse` to
    /// the deployment's bus.
    fn owns(&self, registration: &PushRegistration) -> bool;
}

/// Outcome of one bounded delivery sweep.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PushSweepReport {
    pub registrations: usize,
    pub records: usize,
    pub deliveries: usize,
    pub retries: usize,
    pub completed: usize,
    /// Registrations this sweep gave up on: a permanent refusal, or a receiver
    /// that stayed unreachable past the worker's retry ceiling.
    ///
    /// Counted separately from `completed` because they are opposite outcomes
    /// wearing one shape — both remove the registration, and only one of them
    /// delivered anything.
    pub abandoned: usize,
    pub saturated: bool,
}

impl PushSweepReport {
    /// Whether this tick found anything a human should see.
    ///
    /// The sweeper's own report has had this since the invariant was written
    /// down, and this one did not — so a webhook that will never be delivered to
    /// produced `retries: 1` on an *info* line, byte-identical to a receiver
    /// that is merely rebooting. Detection without delivery, in the report whose
    /// whole job is delivery.
    #[must_use]
    pub const fn needs_attention(&self) -> bool {
        // A backlog and a quiet plane must not produce the same numbers.
        self.saturated || self.abandoned > 0
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
}

impl DeliveryWorker {
    /// How many consecutive failures a receiver gets before it is abandoned.
    ///
    /// Backoff is `1 << min(attempts, 8)` seconds, so it caps at 256 s: this
    /// default is a little over two hours of a receiver being down, which is a
    /// reboot, a deploy or a certificate renewal and not a webhook that has gone
    /// away. Past it the registration is removed and *reported*, because the
    /// alternative is a row retried until the journal is deleted — and a queue
    /// that only ever grows is one nobody can read.
    pub const DEFAULT_MAX_ATTEMPTS: u32 = 32;

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
        }
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
    /// # Giving up is an outcome, not an omission
    ///
    /// Two failures end a registration rather than rescheduling it, and both are
    /// counted in [`PushSweepReport::abandoned`] so an operator can see them: a
    /// **permanent** refusal ([`PushError::is_permanent`](super::PushError::is_permanent)
    /// — a host taken off the allowlist, a URL that is not HTTPS, a URL that
    /// does not parse), which no backoff improves; and a transient failure that
    /// has happened [`max_attempts`](Self::max_attempts) times, which is a
    /// receiver that is not coming back.
    ///
    /// # Errors
    ///
    /// [`StoreError`] when the push store or the journal cannot be read.
    pub async fn run_once(
        &self,
        at: u64,
        limit: usize,
    ) -> Result<PushSweepReport, crate::core::StoreError> {
        // One over the limit, so a saturated sweep is distinguishable from one
        // that happened to fill the page exactly. Registrations this worker does
        // not own are skipped **after** the read, because the store's ordering is
        // the cursor's and filtering in it would need a second index.
        let due: Vec<PushRegistration> = self
            .store
            .due(at, limit.saturating_add(1))
            .await?
            .into_iter()
            .filter(|registration| self.projection.owns(registration))
            .collect();
        let saturated = due.len() > limit;
        let mut report = PushSweepReport {
            registrations: due.len().min(limit),
            saturated,
            ..PushSweepReport::default()
        };
        for registration in due.into_iter().take(limit) {
            let mut attempts = registration.attempts;
            let records = self
                .journal
                .read(registration.config.task, registration.next_seq)
                .await?;
            if records.is_empty() && self.cleanup_acknowledged_terminal(&registration).await? {
                report.completed += 1;
                continue;
            }
            for record in records {
                let payloads = match self.projection.payloads(&record).await {
                    Ok(payloads) => payloads,
                    Err(error) => {
                        // A projection failure is this plane's own bug, never
                        // the receiver's, so it is always transient here — the
                        // ceiling still applies, because a record that cannot be
                        // projected cannot be projected on the next tick either
                        // and the cursor never moves past it.
                        self.give_up_or_retry(
                            &registration,
                            at,
                            attempts,
                            &error.to_string(),
                            false,
                            &mut report,
                        )
                        .await?;
                        break;
                    }
                };
                let mut failed = None;
                for payload in payloads {
                    match self.transport.deliver(&registration.config, &payload).await {
                        Ok(Delivered::Accepted) => report.deliveries += 1,
                        Ok(other) => failed = Some((format!("receiver outcome: {other:?}"), false)),
                        Err(error) => failed = Some((error.to_string(), error.is_permanent())),
                    }
                    if failed.is_some() {
                        break;
                    }
                }
                if let Some((error, permanent)) = failed {
                    self.give_up_or_retry(
                        &registration,
                        at,
                        attempts,
                        &error,
                        permanent,
                        &mut report,
                    )
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
                report.records += 1;
                if self.projection.terminal(&record) {
                    self.store
                        .delete(registration.config.task, &registration.config.id)
                        .await?;
                    report.completed += 1;
                    break;
                }
            }
        }
        Ok(report)
    }

    /// Reschedule one failed registration, or stop.
    ///
    /// One implementation, because the two call sites above are the same
    /// decision and a second copy of it is the shape that agrees everywhere
    /// except the boundary nobody probed.
    async fn give_up_or_retry(
        &self,
        registration: &PushRegistration,
        at: u64,
        attempts: u32,
        error: &str,
        permanent: bool,
        report: &mut PushSweepReport,
    ) -> Result<(), crate::core::StoreError> {
        // `attempts` counts the failures *before* this one, so the ceiling is
        // reached when this failure makes it up to the ceiling — not one tick
        // later, which would make `max_attempts(1)` mean two attempts.
        let exhausted = attempts.saturating_add(1) >= self.max_attempts;
        if permanent || exhausted {
            let reason = if permanent {
                "the deployment no longer permits this destination"
            } else {
                "the receiver did not answer within the retry ceiling"
            };
            tracing::warn!(
                task = %registration.config.task,
                config = %registration.config.id,
                url = %registration.config.url,
                attempts = attempts.saturating_add(1),
                %error,
                "abandoning a push registration: {reason}"
            );
            self.store
                .delete(registration.config.task, &registration.config.id)
                .await?;
            report.abandoned += 1;
            return Ok(());
        }
        let exponent = attempts.min(8);
        self.store
            .retry(
                registration.config.task,
                &registration.config.id,
                at.saturating_add(1u64 << exponent),
                error,
            )
            .await?;
        report.retries += 1;
        Ok(())
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
