//! The inbound-event contract: durable buffering, subscriptions, dead letters.

use std::fmt::Debug;

use async_trait::async_trait;

use crate::core::{
    DeadLetter, EffectKey, InboundEvent, RunId, StoreError, Subscription, Timestamp,
};

/// A buffered event that a wait can claim.
#[derive(Debug, Clone, PartialEq)]
pub struct BufferedEvent {
    pub event: InboundEvent,
    pub received_at: Timestamp,
}

/// Result of delivering an event to one explicitly named waiting run.
///
/// A2A continuation carries a `taskId`, so ordinary correlation matching is
/// too weak: two tasks may legitimately wait on the same business key. The
/// store must insert and claim in one transaction, against that exact run.
#[derive(Debug, Clone, PartialEq)]
pub enum TargetedDelivery {
    /// The event was durably claimed for this subscription.
    Matched(Subscription),
    /// The same `(source, id)` was already accepted.
    Duplicate,
    /// The named run has no matching live subscription.
    NotWaiting,
}

/// Durable inbound-event handling.
///
/// The ordering rule that makes this correct, stated once:
///
/// > **Store the event before looking for anyone to give it to.**
///
/// An event that arrives before its waiter must survive until the waiter
/// appears. Matching first and discarding on a miss is the bug that makes a run
/// wait forever for something that already happened.
#[async_trait]
pub trait EventStore: Send + Sync + Debug {
    /// Record an inbound event, returning `false` if this `(source, id)` was
    /// already seen.
    ///
    /// Deduplication is by the **pair**, never the bare id — an id is unique
    /// only within one producer, and keying on it alone lets two
    /// counterparties swallow each other's messages as apparent retries. The
    /// pair is [`InboundEvent::dedup_key`], the one implementation of that
    /// identity.
    async fn buffer(&self, event: &InboundEvent, at: Timestamp) -> Result<bool, StoreError>;

    /// Register a run's interest in a future event.
    async fn subscribe(&self, sub: &Subscription, at: Timestamp) -> Result<(), StoreError>;

    /// Atomically find and claim a buffered event matching a subscription.
    ///
    /// Claiming is what makes an event single-delivery: two runs waiting on the
    /// same key cannot both consume one message.
    ///
    /// An event **already claimed by this subscription's run** is returned
    /// again rather than filtered out. That is crash recovery, not a second
    /// delivery: [`match_waiter`](Self::match_waiter) claims durably and the
    /// run resumes in a separate step, so a crash between the two leaves an
    /// event claimed for a run that never saw it — and a `claim_for` that
    /// hid the run's own claim from it would strand the wait until its
    /// deadline breached, losing a message that arrived in time. Single
    /// delivery is untouched, because only the claiming run can re-claim.
    async fn claim_for(
        &self,
        sub: &Subscription,
        at: Timestamp,
    ) -> Result<Option<BufferedEvent>, StoreError>;

    /// Atomically find and claim a subscription matching an arrived event.
    ///
    /// The mirror of [`claim_for`](EventStore::claim_for): one looks for a
    /// waiter given an event, the other for an event given a waiter. Both
    /// directions are needed precisely because either can arrive first.
    async fn match_waiter(
        &self,
        event: &InboundEvent,
        at: Timestamp,
    ) -> Result<Option<Subscription>, StoreError>;

    /// Atomically buffer `event` and claim it for the matching subscription of
    /// exactly `run`.
    ///
    /// Unlike [`buffer`](Self::buffer) followed by
    /// [`match_waiter`](Self::match_waiter), a failed targeted delivery leaves
    /// no unclaimed event behind for another run to consume. Implementations
    /// must decide duplicate/not-waiting/matched in one transaction.
    async fn deliver_to(
        &self,
        run: RunId,
        event: &InboundEvent,
        at: Timestamp,
    ) -> Result<TargetedDelivery, StoreError>;

    /// Drop a subscription once it has been satisfied.
    async fn unsubscribe(&self, run: RunId, effect: EffectKey) -> Result<(), StoreError>;

    /// Move events nobody claimed within the window to the dead-letter list.
    ///
    /// Dead-lettering deliberately happens here and not on arrival: "nobody is
    /// waiting yet" and "nobody will ever want this" are different claims, and
    /// only the second is safe to act on. Returns how many were retired.
    async fn sweep_unclaimed(
        &self,
        older_than: Timestamp,
        reason: &str,
    ) -> Result<usize, StoreError>;

    /// Events that aged out unclaimed, newest first.
    ///
    /// A non-empty list means a correlation key is wrong somewhere. That is the
    /// failure which otherwise presents as a process silently never completing.
    async fn dead_letters(&self, limit: usize) -> Result<Vec<DeadLetter>, StoreError>;

    /// Runs currently waiting, for operational visibility.
    async fn waiting(&self, limit: usize) -> Result<Vec<Subscription>, StoreError>;
}
