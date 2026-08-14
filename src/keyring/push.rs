//! Webhook registrations whose credentials are sealed at rest.
//!
//! A push registration is two things fused: a **destination** — task id, URL,
//! delivery cursor — and the **credentials** for it, A2A's opaque correlation
//! token and the receiver's own HTTP authentication. The concept spec is blunt
//! about what the second half means in the wrong hands: a leaked registration
//! is "a destination and a bearer token for it". The stores kept both halves
//! as they arrived, so every backup of the push table was a list of endpoints
//! anybody holding it could authenticate to.
//!
//! So the credentials are sealed and the destination is not, by the same
//! dividing rule every other decorator here follows: *what a store is asked
//! questions about stays readable; what it merely holds is sealed.* The due
//! query orders on `(next_attempt_at, task, id)` and filters on the id prefix;
//! the worker routes on the URL; nothing anywhere asks a question about a
//! token. Sealing the routing fields would leave a delivery table that cannot
//! deliver, and would buy nothing the sealed credentials do not already buy.
//!
//! # The erasure unit is the tenant
//!
//! Everything case-shaped in this crate seals under the case, because the case
//! is what an erasure request names. A webhook credential is not case data: it
//! belongs to the tenant's relationship with a receiver, it is reused across
//! every task that receiver registers for, and no erasure request about a
//! matter has ever meant "and stop being able to authenticate to my webhook".
//! The one erasure that does reach it is the one that erases the tenant — a
//! webhook token outlives no tenant — so the scope is `<tenant>/push`, one key
//! for the unit that goes away together.
//!
//! # What an erased credential reads back as
//!
//! Absent. A registration whose credentials no longer open comes back with no
//! token and no authentication rather than as an error, because the rows share
//! a store with every other tenant's: a sweep that died on the first erased
//! row would stop delivering for everyone still here. Delivery then goes out
//! unauthenticated, the receiver refuses it, and the registration ages out
//! through the ordinary retry ceiling — the failure lands on exactly the rows
//! whose tenant was erased, and nowhere else.

use std::sync::Arc;

use async_trait::async_trait;

use crate::core::{RunId, Secret, Seq, StoreError, TenantId};
use crate::journal::payload;
use crate::push::{DueBatch, PushConfig, PushNamespace, PushRegistration, PushStore};

use super::KeyRing;

/// A [`PushStore`] that seals webhook credentials under a key ring.
#[derive(Debug)]
pub struct SealedPush {
    inner: Arc<dyn PushStore>,
    keys: Arc<dyn KeyRing>,
    tenant: TenantId,
}

impl SealedPush {
    /// Seal this store's webhook credentials under `keys`.
    ///
    /// `tenant` must be the tenant the wrapped store serves — see
    /// [`SealedCases::wrap`](super::SealedCases::wrap) for why this argument
    /// exists and what a mismatch costs.
    #[must_use]
    pub fn wrap(inner: Arc<dyn PushStore>, keys: Arc<dyn KeyRing>, tenant: TenantId) -> Arc<Self> {
        Arc::new(Self {
            inner,
            keys,
            tenant,
        })
    }

    /// One scope for the whole tenant's credentials — the module docs say why
    /// the tenant, and not the task or a case, is the unit that goes away
    /// together.
    fn scope(&self) -> String {
        super::scope(&self.tenant, "push")
    }

    /// Bound to the registration, so a sealed credential lifted onto another
    /// row fails to authenticate rather than opening as authority to a
    /// destination it was never given for.
    fn aad(task: RunId, id: &str) -> String {
        format!("{task}/{id}")
    }

    async fn sealed_secret(&self, aad: &str, secret: &Secret) -> Result<Secret, StoreError> {
        let envelope = super::envelope::seal(
            self.keys.as_ref(),
            &self.scope(),
            aad.as_bytes(),
            secret.expose().as_bytes(),
        )
        .await
        .map_err(|e| StoreError::Backend(format!("sealing a webhook credential failed: {e}")))?;
        Ok(Secret::new(payload::wrap_text(&envelope)))
    }

    /// The stored shape: credentials sealed, routing untouched.
    async fn sealed(&self, config: &PushConfig) -> Result<PushConfig, StoreError> {
        let aad = Self::aad(config.task, &config.id);
        let mut sealed = config.clone();
        if let Some(token) = &config.token {
            sealed.token = Some(self.sealed_secret(&aad, token).await?);
        }
        if let Some(authentication) = &mut sealed.authentication {
            authentication.credentials = self
                .sealed_secret(&aad, &authentication.credentials)
                .await?;
        }
        Ok(sealed)
    }

    /// A stored credential back in the clear, or `None` once its key is gone.
    ///
    /// A secret that never was sealed passes through unchanged — the rows a
    /// deployment wrote before it configured a key ring must stay deliverable,
    /// exactly as the other decorators leave pre-sealing payloads readable.
    async fn opened_secret(&self, aad: &str, secret: Secret) -> Option<Secret> {
        let Some(envelope) = payload::unwrap_text(secret.expose()) else {
            return Some(secret);
        };
        let plain = super::envelope::open(self.keys.as_ref(), aad.as_bytes(), &envelope)
            .await
            .ok()?;
        String::from_utf8(plain).ok().map(Secret::new)
    }

    async fn opened(&self, mut config: PushConfig) -> PushConfig {
        let aad = Self::aad(config.task, &config.id);
        if let Some(token) = config.token.take() {
            config.token = self.opened_secret(&aad, token).await;
        }
        // The scheme stays; the credentials decide. An authentication whose
        // credentials were erased is no authentication at all, not a header
        // carrying ciphertext to a receiver.
        if let Some(authentication) = config.authentication.take() {
            config.authentication = self
                .opened_secret(&aad, authentication.credentials)
                .await
                .map(|credentials| crate::push::PushAuthentication {
                    scheme: authentication.scheme,
                    credentials,
                });
        }
        config
    }

    async fn opened_all(&self, rows: Vec<PushRegistration>) -> Vec<PushRegistration> {
        let mut out = Vec::with_capacity(rows.len());
        for mut registration in rows {
            registration.config = self.opened(registration.config).await;
            out.push(registration);
        }
        out
    }
}

#[async_trait]
impl PushStore for SealedPush {
    async fn put(&self, config: &PushConfig, next_seq: Seq) -> Result<(), StoreError> {
        self.inner.put(&self.sealed(config).await?, next_seq).await
    }

    async fn get(&self, task: RunId, id: &str) -> Result<Option<PushConfig>, StoreError> {
        let found = self.inner.get(task, id).await?;
        Ok(match found {
            Some(config) => Some(self.opened(config).await),
            None => None,
        })
    }

    async fn list(&self, task: RunId) -> Result<Vec<PushConfig>, StoreError> {
        let configs = self.inner.list(task).await?;
        let mut out = Vec::with_capacity(configs.len());
        for config in configs {
            out.push(self.opened(config).await);
        }
        Ok(out)
    }

    async fn due(&self, at: u64, limit: usize) -> Result<Vec<PushRegistration>, StoreError> {
        // The delivery worker's read: this is where the credentials come back,
        // because the POST that needs them happens on the other side of it.
        let rows = self.inner.due(at, limit).await?;
        Ok(self.opened_all(rows).await)
    }

    async fn due_in(
        &self,
        at: u64,
        limit: usize,
        namespace: PushNamespace,
    ) -> Result<DueBatch, StoreError> {
        // Forwarded rather than left to the trait default, which would page
        // over `self.due` and pay the decode twice — and would lose whatever
        // native filter the wrapped store implements.
        let mut batch = self.inner.due_in(at, limit, namespace).await?;
        batch.rows = self.opened_all(batch.rows).await;
        Ok(batch)
    }

    async fn advance(&self, task: RunId, id: &str, next_seq: Seq) -> Result<(), StoreError> {
        self.inner.advance(task, id, next_seq).await
    }

    async fn retry(
        &self,
        task: RunId,
        id: &str,
        next_attempt_at: u64,
        error: &str,
    ) -> Result<(), StoreError> {
        self.inner.retry(task, id, next_attempt_at, error).await
    }

    async fn delete(&self, task: RunId, id: &str) -> Result<(), StoreError> {
        self.inner.delete(task, id).await
    }
}
