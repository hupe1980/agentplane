//! An event buffer whose payloads are sealed at rest.
//!
//! # The erasure unit here is the event, and that is forced
//!
//! Everything else in this crate seals under the **case**, because the case is
//! the retention unit an erasure request names. An inbound event cannot use
//! it: an event is buffered *before* any subscription matches it, so at write
//! time it belongs to no case — and an event that is never claimed becomes a
//! **dead letter**, which by definition matched no case at all. There is no
//! case to erase it with, and inventing one would be worse than admitting it.
//!
//! So the event is its own erasure unit, scoped by the `(source, id)` pair
//! `CloudEvents` defines uniqueness by — the same identity the buffer already
//! deduplicates on. Destroying that scope erases exactly one message, which is
//! the granularity a request about one message actually wants.
//!
//! The *delivered* copy is a separate matter and already covered: claiming an
//! event journals its payload under the awaiting effect, sealed under the
//! run's case like every other journal payload. This seals the buffer's copy —
//! the one that outlives delivery when nobody claims it.
//!
//! `source`, `id`, `kind` and the correlation keys stay in the clear: they are
//! the dedup identity and the match keys, which is to say they are what the
//! store is asked questions *about*. Sealing them would leave a buffer that
//! cannot deduplicate or match.

use std::sync::Arc;

use async_trait::async_trait;

use crate::case::{BufferedEvent, EventStore, TargetedDelivery};
use crate::core::{
    DeadLetter, EffectKey, InboundEvent, RunId, StoreError, Subscription, TenantId, Timestamp,
};
use crate::journal::payload;

use super::KeyRing;

/// An [`EventStore`] that seals buffered payloads under a key ring.
#[derive(Debug)]
pub struct SealedEvents {
    inner: Arc<dyn EventStore>,
    keys: Arc<dyn KeyRing>,
    tenant: TenantId,
}

impl SealedEvents {
    /// Seal this store's buffered payloads under `keys`.
    ///
    /// `tenant` must be the tenant the wrapped store serves — see
    /// [`SealedCases::wrap`](super::SealedCases::wrap) for what a mismatch
    /// costs.
    #[must_use]
    pub fn wrap(inner: Arc<dyn EventStore>, keys: Arc<dyn KeyRing>, tenant: TenantId) -> Arc<Self> {
        Arc::new(Self {
            inner,
            keys,
            tenant,
        })
    }

    /// One message, one scope. `(source, id)` is the pair `CloudEvents`
    /// defines uniqueness by and the pair this buffer deduplicates on, so the
    /// erasure unit is exactly the message an erasure request names.
    fn scope_for(&self, event: &InboundEvent) -> String {
        super::scope(
            &self.tenant,
            &format!("event/{}/{}", event.source, event.id),
        )
    }

    fn aad(event: &InboundEvent) -> String {
        format!("{}/{}", event.source, event.id)
    }

    async fn sealed(&self, event: &InboundEvent) -> Result<InboundEvent, StoreError> {
        let plain = crate::core::canon::to_bytes(&event.payload).map_err(|e| {
            StoreError::Backend(format!("an event payload would not serialise: {e}"))
        })?;
        let envelope = super::envelope::seal(
            self.keys.as_ref(),
            &self.scope_for(event),
            Self::aad(event).as_bytes(),
            &plain,
        )
        .await
        .map_err(|e| StoreError::Backend(format!("sealing an event payload failed: {e}")))?;
        let mut sealed = event.clone();
        sealed.payload = payload::wrap(&envelope);
        Ok(sealed)
    }

    async fn opened(&self, mut event: InboundEvent) -> InboundEvent {
        let Some(envelope) = payload::unwrap(&event.payload) else {
            return event;
        };
        let aad = Self::aad(&event);
        // Left sealed when it will not open: an erased message must not make
        // the dead-letter list unreadable, since that list is how a wrong
        // correlation key is found in the first place.
        if let Ok(plain) =
            super::envelope::open(self.keys.as_ref(), aad.as_bytes(), &envelope).await
            && let Ok(value) = serde_json::from_slice(&plain)
        {
            event.payload = value;
        }
        event
    }
}

#[async_trait]
impl EventStore for SealedEvents {
    async fn buffer(&self, event: &InboundEvent, at: Timestamp) -> Result<bool, StoreError> {
        self.inner.buffer(&self.sealed(event).await?, at).await
    }

    async fn claim_for(
        &self,
        sub: &Subscription,
        at: Timestamp,
    ) -> Result<Option<BufferedEvent>, StoreError> {
        let claimed = self.inner.claim_for(sub, at).await?;
        Ok(match claimed {
            Some(mut buffered) => {
                buffered.event = self.opened(buffered.event).await;
                Some(buffered)
            }
            None => None,
        })
    }

    async fn match_waiter(
        &self,
        event: &InboundEvent,
        at: Timestamp,
    ) -> Result<Option<Subscription>, StoreError> {
        // Sealed on the way in for the same reason `buffer` seals: this path
        // stores the event when it finds no waiter, and a payload that reached
        // the buffer in the clear here would be readable exactly when nobody
        // was waiting for it — the dead-letter case.
        self.inner
            .match_waiter(&self.sealed(event).await?, at)
            .await
    }

    async fn deliver_to(
        &self,
        run: RunId,
        event: &InboundEvent,
        at: Timestamp,
    ) -> Result<TargetedDelivery, StoreError> {
        self.inner
            .deliver_to(run, &self.sealed(event).await?, at)
            .await
    }

    async fn subscribe(&self, sub: &Subscription, at: Timestamp) -> Result<(), StoreError> {
        self.inner.subscribe(sub, at).await
    }

    async fn unsubscribe(&self, run: RunId, effect: EffectKey) -> Result<(), StoreError> {
        self.inner.unsubscribe(run, effect).await
    }

    async fn sweep_unclaimed(
        &self,
        older_than: Timestamp,
        reason: &str,
    ) -> Result<usize, StoreError> {
        self.inner.sweep_unclaimed(older_than, reason).await
    }

    async fn dead_letters(&self, limit: usize) -> Result<Vec<DeadLetter>, StoreError> {
        let letters = self.inner.dead_letters(limit).await?;
        let mut out = Vec::with_capacity(letters.len());
        for mut letter in letters {
            letter.event = self.opened(letter.event).await;
            out.push(letter);
        }
        Ok(out)
    }

    async fn waiting(&self, limit: usize) -> Result<Vec<Subscription>, StoreError> {
        self.inner.waiting(limit).await
    }
}
