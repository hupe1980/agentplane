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

/// Who minted a buffered event: an operator on this plane, or nobody.
///
/// Read back by [`EventStore::minter`]. `Nobody` is every message that
/// arrived over a wire, and every one this plane minted in nobody's name — an
/// expired approval window's answer is one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Minter {
    Nobody,
    Operator(crate::core::Operator),
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
/// The dead-letter reason of an unclaimed event whose payload was erased.
pub const ERASED_REASON: &str = "erased";

#[async_trait]
pub trait EventStore: Send + Sync + Debug {
    /// Whose rows this handle can reach.
    ///
    /// Defaults to [`TenantId::DEFAULT`](crate::core::TenantId::DEFAULT), the
    /// tenant a store serves until told otherwise. Override it with the tenant
    /// the handle is actually scoped to.
    ///
    /// This exists so a mismatch with the plane's tenant is a **startup
    /// refusal**. When a key ring is wired, `build()` seals this state under
    /// the plane's tenant while the store writes rows under its own; the two
    /// disagreeing is not a leak — the scopes simply differ — but it seals the
    /// state under a scope erasure will never destroy. That is an erasure that
    /// reports success and misses, which is the one failure a deletion
    /// guarantee cannot have.
    fn tenant(&self) -> &str {
        crate::core::TenantId::DEFAULT
    }

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
    ///
    /// A subscription whose run is sealed is passed over: the event goes to
    /// the next live waiter, or stays buffered, rather than being claimed for
    /// a run that will never consume it. So is a **parked** one
    /// ([`park_wait`](Self::park_wait)): it already holds its claimed event,
    /// and a second event elected for it would stay claimed for a satisfied
    /// wait for ever.
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
    ///
    /// Also the point where the buffer's copy of the run's **delivered**
    /// payloads is shed. Stripping earlier — at the claim — would lose the
    /// payload for a run that crashed between claim and resume, whose
    /// recovery re-reads it from the buffer; unsubscribe is the run's own
    /// signal that the wait is over, so the buffer row keeps only its
    /// `(source, id)` identity for dedup from here on.
    ///
    /// That places an **ordering obligation on the caller**: journal the
    /// delivered payload *before* unsubscribing. The delivery worker does —
    /// it appends `EffectDone` and only then retires the subscription. A
    /// caller that unsubscribes first has a crash window in which the buffer
    /// copy is gone and the journal copy never landed, and recovery then
    /// resumes the wait on a stripped row. What stripping here does **not**
    /// cover: unclaimed and dead-lettered rows, which never reach an
    /// unsubscribe and are erased through
    /// [`erase_payload`](Self::erase_payload) instead.
    async fn unsubscribe(&self, run: RunId, effect: EffectKey) -> Result<(), StoreError>;

    /// Drop every subscription a run holds, returning how many waits were
    /// retired.
    ///
    /// Called when the run concludes closed. Left registered, a closed run's
    /// wait is the oldest waiter on its key, and the next matching event is
    /// claimed for a run that will never consume it — while a live run
    /// waiting on the same key starves. Payloads the run holds claimed are
    /// shed exactly as [`unsubscribe`](Self::unsubscribe) sheds them.
    async fn unsubscribe_run(&self, run: RunId) -> Result<usize, StoreError>;

    /// Register a wait that already holds a claimed event, and mark it for
    /// redelivery.
    ///
    /// The delivery that claimed an event and could not resume the run —
    /// its owner held the lease past the retry window — parks the pair here,
    /// and [`parked_waits`](Self::parked_waits) is what the sweep's redelivery pass
    /// walks. A targeted delivery's claim is parked by
    /// [`deliver_to`](Self::deliver_to) itself. The mark goes with the
    /// subscription: [`unsubscribe`](Self::unsubscribe) and the claim that
    /// retires a wait both clear it.
    ///
    /// A parked wait is listed for redelivery and recovers its own event
    /// through [`claim_for`](Self::claim_for), but it is not matchable: no
    /// other event is claimed for it.
    async fn park_wait(&self, sub: &Subscription, at: Timestamp) -> Result<(), StoreError>;

    /// Waits holding a claimed event nothing has delivered yet.
    ///
    /// A separate listing from [`waiting`](Self::waiting) because that one
    /// is every registered wait in registration order, and a plane is
    /// expected to hold far more legitimately long waits than a redelivery
    /// page: the parked pair registered after them would never be reached.
    ///
    /// A sealed run's parked waits are retired rather than listed — it can
    /// record no delivery, so listing them has the pass fail on them every
    /// tick — and the payloads it held claimed are shed with them.
    async fn parked_waits(&self, limit: usize) -> Result<Vec<Subscription>, StoreError>;

    /// Remove one buffered event's payload while keeping its identity.
    ///
    /// The erasure verb the buffer was missing. The buffer keeps its copy of
    /// an inbound payload indefinitely — claimed rows stay for dedup, and
    /// dead-lettered rows stay for the operator — so a message that becomes
    /// the object of an erasure request had no path to erasure at all: the
    /// journal's copy is key-erasable, the buffer's was immortal.
    ///
    /// The **row survives**; only the payload goes. Dedup needs exactly
    /// `(source, id)`, so a replay of the erased message is still refused
    /// rather than accepted as new — erasure must not reopen the door it
    /// closed. Dead-letter entries likewise keep their identity, correlation
    /// keys and reason, because "what went unclaimed and why" is operational
    /// truth about the deployment, not the counterparty's content.
    ///
    /// A row **nobody had claimed** also leaves the claimable set: it becomes a
    /// dead letter whose reason is [`ERASED_REASON`], in the same write. Left
    /// live, the next matching waiter would claim the emptied row and be
    /// handed `null` as if the counterparty had sent it.
    ///
    /// So does a row **claimed and not yet delivered** — claimed, with its
    /// payload not yet shed by the claimant's unsubscribe. The claim is
    /// released and the claimant's wait that was parked holding it is
    /// unparked, so the wait stays open for its deadline to bound; the
    /// recovery that would have re-read the row finds nothing to hand over.
    /// Every erased row is marked erased, and [`claim_for`](Self::claim_for)
    /// never returns one, whatever its claim says.
    ///
    /// What this does **not** cover: the journaled copy of a *delivered*
    /// payload, which lives under the run's case and is erased by that case's
    /// key; and the correlation keys, which are business identifiers the row
    /// is filed under, not content. Returns whether a row existed.
    async fn erase_payload(&self, source: &str, id: &str) -> Result<bool, StoreError>;

    /// Who minted the buffered event `(source, id)`, or `None` when no such
    /// event was ever buffered.
    ///
    /// Survives both payload erasure and the unsubscribe that sheds a
    /// delivered payload, as the minter does on the row: who on this plane
    /// minted a message is not the counterparty's content. It is how a
    /// settler that meets a duplicate answer to a human task learns whose
    /// answer is already on record.
    async fn minter(&self, source: &str, id: &str) -> Result<Option<Minter>, StoreError>;

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
