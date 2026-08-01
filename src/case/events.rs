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
    /// Record an inbound event, returning `false` if this id was already seen.
    ///
    /// Deduplication is by event id, so a counterparty that retries — which
    /// they all do — does not deliver the same message twice.
    async fn buffer(&self, event: &InboundEvent, at: Timestamp) -> Result<bool, StoreError>;

    /// Register a run's interest in a future event.
    async fn subscribe(&self, sub: &Subscription, at: Timestamp) -> Result<(), StoreError>;

    /// Atomically find and claim a buffered event matching a subscription.
    ///
    /// Claiming is what makes an event single-delivery: two runs waiting on the
    /// same key cannot both consume one message.
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
