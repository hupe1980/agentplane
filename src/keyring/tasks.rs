//! A worklist whose proposals are sealed at rest.
//!
//! A human task carries the most specific caller data in the system:
//! `Justification::proposed_action` is the *exact* thing a reviewer is shown —
//! for a payment approval, the amount and the destination account. The journal
//! seals its copy; this seals the worklist's, which is the copy an operator
//! queries.
//!
//! **`evidence` is sealed for the same reason `proposed_action` is**, and the
//! reason is structural rather than a guess about content: the trail behind a
//! proposal is *assembled from what tools and models produced*. A declared
//! dry-run preview is the clearest case — it is the answer a tool gave when
//! asked what the call would do, so it quotes the caller's data by
//! construction. The journal seals its copy; without this, the worklist's
//! copy outlived a case erasure in the one store an operator queries by hand.
//!
//! `summary` is deliberately **not** sealed. It is the line a reviewer reads
//! in a queue, and sealing it would leave a worklist of unreadable rows. That
//! it is the deployment's own sentence is checkable rather than assumed: it
//! is a `Tainted<String>`, so a summary built from a completion says so, and
//! a deployment that writes personal data into one has put it somewhere this
//! does not reach — visibly, rather than silently.

use std::sync::Arc;

use async_trait::async_trait;

use crate::case::{ClaimError, TaskStore};
use crate::core::{CaseId, StoreError, Task, TaskId, TaskState, TenantId, Timestamp};
use crate::journal::payload;

use super::KeyRing;

/// A [`TaskStore`] that seals task proposals under a key ring.
#[derive(Debug)]
pub struct SealedTasks {
    inner: Arc<dyn TaskStore>,
    keys: Arc<dyn KeyRing>,
    tenant: TenantId,
}

impl SealedTasks {
    /// Seal this store's proposals under `keys`.
    ///
    /// `tenant` must be the tenant the wrapped store serves — see
    /// [`SealedCases::wrap`](super::SealedCases::wrap) for why this argument
    /// exists and what a mismatch costs.
    ///
    /// # Panics
    ///
    /// If `tenant` is not the tenant `inner` serves — see
    /// [`SealedCases::wrap`](super::SealedCases::wrap) for why that pair is
    /// checked rather than trusted.
    #[must_use]
    pub fn wrap(inner: Arc<dyn TaskStore>, keys: Arc<dyn KeyRing>, tenant: TenantId) -> Arc<Self> {
        super::assert_serves(inner.tenant(), &tenant, "task");
        Arc::new(Self {
            inner,
            keys,
            tenant,
        })
    }

    /// The case when the task has one — the scope `erase_case` destroys — and
    /// the run otherwise, which is still a unit somebody can name.
    fn scope_for(&self, task: &Task) -> String {
        task.case.map_or_else(
            || super::scope(&self.tenant, &task.run.to_string()),
            |c| super::scope(&self.tenant, &c.to_string()),
        )
    }

    /// Bound to tenant, purpose label and task, so a proposal lifted onto
    /// another task fails to authenticate rather than opening as somebody
    /// else's decision. The `task:{tenant}:` prefix follows the journal and
    /// case decorators: a bare task id as AAD was a string another decorator's
    /// identifier could collide with, and while task ids are generated rather
    /// than attacker-chosen, the AAD's job is to make cross-purpose confusion
    /// inexpressible rather than merely unlikely. What the AAD does not do
    /// alone: the sealing scope also separates envelopes, and the two are
    /// deliberately redundant.
    /// `pub(super)` so the keyring's own tests can hold the three decorators'
    /// derivations side by side and prove colliding identifiers never share
    /// an AAD.
    pub(super) fn aad(tenant: &TenantId, id: TaskId) -> String {
        format!("task:{tenant}:{id}")
    }

    /// One task's sealed proposal and evidence, back in the clear.
    ///
    /// # Errors
    ///
    /// Every key failure but an erasure. A proposal whose key was
    /// **destroyed** stays sealed — an erased matter must not make the queue
    /// unreadable, and a reviewer seeing a sealed row knows the matter was
    /// erased. A ring that is unreachable must not produce that same row,
    /// because the reviewer would decide on a trail that is intact and
    /// temporarily unreadable while being shown one that is gone.
    async fn opened(&self, mut task: Task) -> Result<Task, StoreError> {
        let aad = Self::aad(&self.tenant, task.id);
        let open = async |envelope: Vec<u8>| {
            super::envelope::open_or_erased(self.keys.as_ref(), aad.as_bytes(), &envelope)
                .await
                .map_err(|e| StoreError::Backend(e.to_string()))
        };
        if let Some(envelope) = payload::unwrap(&task.justification.proposed_action)
            && let Some(plain) = open(envelope).await?
            && let Ok(value) = serde_json::from_slice(&plain)
        {
            task.justification.proposed_action = value;
        }
        for item in &mut task.justification.evidence {
            // Each entry on its own, so one erased line does not take the rest
            // of the trail with it.
            if let Some(envelope) = payload::unwrap_text(item.peek())
                && let Some(plain) = open(envelope).await?
                && let Ok(text) = String::from_utf8(plain)
            {
                *item = item.clone().map(|_| text);
            }
        }
        Ok(task)
    }

    async fn opened_all(&self, tasks: Vec<Task>) -> Result<Vec<Task>, StoreError> {
        let mut out = Vec::with_capacity(tasks.len());
        for task in tasks {
            out.push(self.opened(task).await?);
        }
        Ok(out)
    }
}

#[async_trait]
impl TaskStore for SealedTasks {
    fn tenant(&self) -> &str {
        self.tenant.as_str()
    }

    async fn open(&self, task: &Task) -> Result<Task, StoreError> {
        let plain = crate::core::canon::to_bytes(&task.justification.proposed_action)
            .map_err(|e| StoreError::Backend(format!("a proposal would not serialise: {e}")))?;
        let envelope = super::envelope::seal(
            self.keys.as_ref(),
            &self.scope_for(task),
            Self::aad(&self.tenant, task.id).as_bytes(),
            &plain,
        )
        .await
        .map_err(|e| StoreError::Backend(format!("sealing a proposal failed: {e}")))?;

        let mut sealed = task.clone();
        sealed.justification.proposed_action = payload::wrap(&envelope);
        for item in &mut sealed.justification.evidence {
            let wrapped = super::envelope::seal(
                self.keys.as_ref(),
                &self.scope_for(task),
                Self::aad(&self.tenant, task.id).as_bytes(),
                item.peek().as_bytes(),
            )
            .await
            .map_err(|e| StoreError::Backend(format!("sealing a task's evidence failed: {e}")))?;
            // The label rides through untouched: *who wrote this* is what the
            // reviewer needs whether or not the words are still readable, and
            // it is not the caller's data.
            *item = item.clone().map(|_| payload::wrap_text(&wrapped));
        }
        let written = self.inner.open(&sealed).await?;
        // Handed back opened, so the caller that just wrote a proposal reads
        // back what it wrote rather than its envelope.
        self.opened(written).await
    }

    async fn task(&self, id: TaskId) -> Result<Option<Task>, StoreError> {
        let found = self.inner.task(id).await?;
        Ok(match found {
            Some(task) => Some(self.opened(task).await?),
            None => None,
        })
    }

    async fn claim(&self, id: TaskId, actor: &str, roles: &[String]) -> Result<Task, ClaimError> {
        let claimed = self.inner.claim(id, actor, roles).await?;
        Ok(self.opened(claimed).await?)
    }

    async fn take_over(
        &self,
        id: TaskId,
        from: &str,
        actor: &str,
        roles: &[String],
    ) -> Result<Task, ClaimError> {
        let taken = self.inner.take_over(id, from, actor, roles).await?;
        Ok(self.opened(taken).await?)
    }

    async fn release(&self, id: TaskId, actor: &str) -> Result<(), ClaimError> {
        self.inner.release(id, actor).await
    }

    async fn set_state(&self, id: TaskId, state: TaskState) -> Result<(), StoreError> {
        self.inner.set_state(id, state).await
    }

    async fn escalate(&self, id: TaskId) -> Result<Task, StoreError> {
        let escalated = self.inner.escalate(id).await?;
        self.opened(escalated).await
    }

    async fn queue(&self, roles: &[String], limit: usize) -> Result<Vec<Task>, StoreError> {
        let tasks = self.inner.queue(roles, limit).await?;
        self.opened_all(tasks).await
    }

    async fn for_case(&self, case: CaseId) -> Result<Vec<Task>, StoreError> {
        let tasks = self.inner.for_case(case).await?;
        self.opened_all(tasks).await
    }

    async fn open_count(&self) -> Result<u64, StoreError> {
        self.inner.open_count().await
    }

    async fn overdue(&self, now: Timestamp, limit: usize) -> Result<Vec<Task>, StoreError> {
        let tasks = self.inner.overdue(now, limit).await?;
        self.opened_all(tasks).await
    }
}
