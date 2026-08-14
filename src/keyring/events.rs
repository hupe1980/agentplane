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
    /// erasure unit is exactly the message an erasure request names. Derived
    /// here and nowhere else: the seal path and [`erase_event`](Self::erase_event)
    /// must agree byte-for-byte about which key seals a message.
    fn scope_for(&self, source: &str, id: &str) -> String {
        super::scope(&self.tenant, &format!("event/{source}/{id}"))
    }

    /// The ciphertext binds tenant, purpose label and event identity as
    /// authenticated associated data — the same shape the journal and case
    /// decorators use. The purpose label separates this from every other
    /// envelope the same ring seals, and the tenant matters here more than
    /// anywhere: an event's `source` and `id` are **attacker-chosen strings**,
    /// so without these prefixes a counterparty could construct an identity
    /// whose bare `"{source}/{id}"` collides with another decorator's AAD and
    /// probe cross-purpose confusions. What the AAD does not do alone: scopes
    /// already differ per event, and the two controls are deliberately
    /// redundant rather than either being the only wall.
    /// `pub(super)` so the keyring's own tests can hold the three decorators'
    /// derivations side by side and prove colliding identifiers never share
    /// an AAD.
    pub(super) fn aad(tenant: &TenantId, event: &InboundEvent) -> String {
        format!("event:{tenant}:{}/{}", event.source, event.id)
    }

    async fn sealed(&self, event: &InboundEvent) -> Result<InboundEvent, StoreError> {
        let plain = crate::core::canon::to_bytes(&event.payload).map_err(|e| {
            StoreError::Backend(format!("an event payload would not serialise: {e}"))
        })?;
        let envelope = super::envelope::seal(
            self.keys.as_ref(),
            &self.scope_for(&event.source, &event.id),
            Self::aad(&self.tenant, event).as_bytes(),
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
        let aad = Self::aad(&self.tenant, &event);
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

    /// Cryptographically erase one buffered message, then shed its ciphertext.
    ///
    /// The strong form of [`EventStore::erase_payload`] for a sealed buffer:
    /// the scope this decorator sealed the message under is destroyed first,
    /// so every copy — replicas and backups included — stops opening at the
    /// same instant, and only then is the live ciphertext removed from the
    /// buffer row. A ciphertext-cleanup failure after the destroy is logged
    /// and reported as done, because the erasure already happened where it
    /// counts: in the key.
    ///
    /// `at` and `reason` come from the caller's audited lifecycle operation.
    /// What this does not cover: a payload buffered *before* the deployment
    /// configured sealing was stored in the clear, and destroying a key it was
    /// never sealed under erases nothing — the inner `erase_payload` is what
    /// removes those bytes.
    ///
    /// # Errors
    ///
    /// If the key ring cannot destroy the scope.
    pub async fn erase_event(
        &self,
        source: &str,
        id: &str,
        at: crate::core::Timestamp,
        reason: &str,
    ) -> Result<bool, StoreError> {
        let scope = self.scope_for(source, id);
        self.keys
            .destroy(&scope, at, reason)
            .await
            .map_err(|e| StoreError::Backend(format!("erasing an event's key failed: {e}")))?;
        match self.inner.erase_payload(source, id).await {
            Ok(existed) => Ok(existed),
            Err(error) => {
                tracing::warn!(%source, %id, %error, "event key was destroyed but ciphertext cleanup failed");
                Ok(true)
            }
        }
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

    async fn erase_payload(&self, source: &str, id: &str) -> Result<bool, StoreError> {
        // The plain verb removes the stored bytes — ciphertext here, which
        // also covers rows buffered before sealing was configured. Callers
        // holding this decorator concretely should prefer
        // [`SealedEvents::erase_event`], which destroys the message's key
        // first and therefore reaches replicas and backups too.
        self.inner.erase_payload(source, id).await
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

#[cfg(all(test, feature = "testkit"))]
mod aad_tests {
    use super::*;
    use crate::testkit::MemoryKeyRing;

    fn event(source: &str, id: &str) -> InboundEvent {
        InboundEvent {
            source: source.to_owned(),
            id: id.to_owned(),
            kind: "reply".to_owned(),
            correlation: Vec::new(),
            payload: serde_json::Value::Null,
        }
    }

    /// Colliding identifiers never share an AAD across decorators or tenants.
    ///
    /// An event's `source` and `id` are attacker-chosen strings, so without a
    /// tenant and purpose prefix a counterparty could construct an identity
    /// whose bare `"{a}/{b}"` spells exactly what another decorator
    /// authenticates with — here, a push registration's `"{task}/{id}"`. The
    /// cryptographic half seals under one AAD and proves the other cannot
    /// open it, which is the assertion that fails if either prefix is dropped
    /// and the two strings collapse into one.
    #[tokio::test]
    async fn colliding_identifiers_are_mutually_unopenable() {
        let ring = MemoryKeyRing::new();
        let tenant = TenantId::new("acme").expect("tenant");
        let run = crate::core::RunId::generate();

        // The constructible collision: an inbound event whose source is the
        // run id and whose id is the registration id.
        let colliding = event(&run.to_string(), "cfg");
        let event_aad = SealedEvents::aad(&tenant, &colliding);
        #[cfg(feature = "push")]
        let push_aad = super::super::push::SealedPush::aad(&tenant, run, "cfg");
        let task_aad = super::super::tasks::SealedTasks::aad(
            &tenant,
            crate::core::TaskId::derive(
                run,
                crate::core::EffectKey::from_hex(&format!("{:064x}", 7)).expect("hex key"),
            ),
        );
        let other_tenant = SealedEvents::aad(
            &TenantId::new("globex").expect("tenant"),
            &colliding,
        );

        #[cfg(feature = "push")]
        assert_ne!(
            event_aad, push_aad,
            "an event and a push registration built from the same identifiers \
             share an AAD — the cross-purpose collision is constructible again"
        );
        assert_ne!(event_aad, task_aad);
        assert_ne!(
            event_aad, other_tenant,
            "two tenants sharing a ring derive one AAD for one event identity"
        );

        let plain = b"the counterparty's payload";
        let envelope = super::super::envelope::seal(&ring, "acme/anything", event_aad.as_bytes(), plain)
            .await
            .expect("seal");
        assert_eq!(
            super::super::envelope::open(&ring, event_aad.as_bytes(), &envelope)
                .await
                .expect("the right identity opens"),
            plain,
            "the positive half: the sealing identity still opens its own envelope"
        );
        #[cfg(feature = "push")]
        assert!(
            super::super::envelope::open(&ring, push_aad.as_bytes(), &envelope)
                .await
                .is_err(),
            "a sealed event opened under a push registration's identity"
        );
        assert!(
            super::super::envelope::open(&ring, other_tenant.as_bytes(), &envelope)
                .await
                .is_err(),
            "a sealed event opened under another tenant's identity"
        );
    }

    /// `erase_event` destroys the message's own key scope, then sheds the
    /// ciphertext — and the dead-letter list keeps counting.
    #[cfg(feature = "redb")]
    #[tokio::test]
    async fn erase_event_destroys_the_scope_and_shreds_the_buffer_copy() {
        use crate::core::Timestamp;
        use crate::keyring::KeyRing as _;
        use std::sync::Arc;

        let at = |seconds| Timestamp::from_unix_timestamp(seconds).expect("time");
        let tenant = TenantId::new("event-erase").expect("tenant");
        let inner = Arc::new(crate::store::RedbStore::open_in_memory().expect("store"))
            as Arc<dyn EventStore>;
        let ring = Arc::new(MemoryKeyRing::new());
        let sealed = SealedEvents::wrap(
            Arc::clone(&inner),
            Arc::clone(&ring) as Arc<dyn KeyRing>,
            tenant.clone(),
        );

        let message = InboundEvent {
            source: "counterparty".to_owned(),
            id: "42".to_owned(),
            kind: "reply".to_owned(),
            correlation: vec![crate::core::CorrelationKey::new("order", "O-1")],
            payload: serde_json::json!({"pii": "erase me"}),
        };
        assert!(sealed.buffer(&message, at(1_000)).await.expect("buffer"));
        assert_eq!(
            sealed
                .sweep_unclaimed(at(2_000), "nobody came")
                .await
                .expect("sweep"),
            1
        );
        // The positive half: before erasure the sealed store opens its own
        // dead letter.
        let letters = sealed.dead_letters(10).await.expect("dead letters");
        assert_eq!(letters[0].event.payload, serde_json::json!({"pii": "erase me"}));

        assert!(
            sealed
                .erase_event("counterparty", "42", at(3_000), "erasure request")
                .await
                .expect("erase")
        );
        // The key is gone — the derivation pinned here must match the one the
        // seal path used, or the erasure destroyed a scope nothing was sealed
        // under.
        assert!(
            matches!(
                ring.data_key(&crate::keyring::scope(&tenant, "event/counterparty/42"))
                    .await,
                Err(crate::keyring::KeyError::Destroyed { .. })
            ),
            "erase_event left the message's key alive, so backups still open"
        );
        // The accounting survives; the content does not.
        let letters = sealed.dead_letters(10).await.expect("dead letters");
        assert_eq!(letters.len(), 1, "erasure removed the dead-letter row");
        assert_eq!(
            letters[0].event.payload,
            serde_json::Value::Null,
            "the buffer's ciphertext survived the erasure"
        );
        assert_eq!(letters[0].reason, "nobody came");
    }
}
