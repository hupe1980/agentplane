//! A case layer whose state is sealed at rest.
//!
//! The journal's copy of a case write is sealed by
//! [`SealedJournal`](super::SealedJournal); this is the *other* copy — the one
//! the case store keeps so that `case()` can answer without replaying a run.
//! Both are needed, and sealing one without the other leaves the data readable
//! in the place an operator is most likely to look.
//!
//! Only `state` is sealed. Correlation keys, status, deadlines and timestamps
//! stay in the clear, because they are what the store is *asked questions
//! about*: correlate by business key, list what is due, count by status. That
//! is the same division the journal makes — the caller's data is sealed, the
//! routing is not — and it has the same consequence: a business key is a
//! lookup key, so a deployment that considers its business keys personal data
//! must choose keys that are not.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

use crate::case::{CaseStore, Correlation};
use crate::core::{
    Case, CaseId, CaseStatus, CaseVersion, CorrelationKey, Deadline, DeadlineState, Digest, RunId,
    StoreError, TenantId, Timestamp,
};
use crate::journal::payload;

use super::KeyRing;

/// A [`CaseStore`] that seals case state under a key ring.
#[derive(Debug)]
pub struct SealedCases {
    inner: Arc<dyn CaseStore>,
    keys: Arc<dyn KeyRing>,
    tenant: TenantId,
}

impl SealedCases {
    /// Seal this store's case state under `keys`.
    ///
    /// `tenant` is the tenant the wrapped store serves, and it is **checked
    /// against the store** rather than trusted.
    ///
    /// A mismatch does not leak across tenants — the two scopes are both real —
    /// but it seals case state under a scope `erase_case` will never name, so
    /// the erasure destroys its key, reports success, and leaves these rows
    /// readable. Refusing here is what keeps the sealing scope and the row
    /// scope one fact rather than two that agree by convention.
    ///
    /// # Panics
    ///
    /// If `tenant` is not the tenant `inner` serves. This is the deployment's
    /// own wiring, decided once at startup, so it is refused where it is
    /// written rather than at the far end of a deletion request.
    #[must_use]
    pub fn wrap(inner: Arc<dyn CaseStore>, keys: Arc<dyn KeyRing>, tenant: TenantId) -> Arc<Self> {
        super::assert_serves(inner.tenant(), &tenant, "case");
        Arc::new(Self {
            inner,
            keys,
            tenant,
        })
    }

    /// The erasure unit: the case itself, which is the scope `erase_case`
    /// already destroys for blobs and for the journal's copy. One act, every
    /// copy — rather than three mechanisms that could disagree about extent.
    fn scope_for(&self, case: CaseId) -> String {
        super::scope(&self.tenant, &case.to_string())
    }

    /// The associated data case state authenticates under.
    ///
    /// The ciphertext binds tenant, record identity and purpose as
    /// authenticated associated data. The purpose label separates this from every other envelope the
    /// same ring seals; the tenant stops a state envelope crossing tenants
    /// that share a ring (case ids are generated, but `import_case` accepts
    /// them verbatim, so an id is not a tenant boundary); and the case id
    /// stops a sealed state lifted onto another case from opening as somebody
    /// else's matter.
    fn aad(&self, case: CaseId) -> String {
        format!("case-state:{}:{case}", self.tenant)
    }

    async fn open_state(&self, case: CaseId, state: Value) -> Value {
        let Some(envelope) = payload::unwrap(&state) else {
            return state;
        };
        let aad = self.aad(case);
        // Left sealed when it will not open. A destroyed key is a completed
        // erasure, not an outage: the case must stay listable, countable and
        // closable afterwards.
        match super::envelope::open(self.keys.as_ref(), aad.as_bytes(), &envelope).await {
            Ok(plain) => serde_json::from_slice(&plain).unwrap_or(state),
            Err(_) => state,
        }
    }

    async fn opened(&self, case: Option<Case>) -> Option<Case> {
        let mut case = case?;
        case.state = self
            .open_state(case.id, std::mem::take(&mut case.state))
            .await;
        Some(case)
    }
}

/// Prove a case's sealed state still opens, without keeping the plaintext.
///
/// `None` for state that is not sealed — an ordinary answer, not a defect.
/// `Some(Ok(()))` means the ring opened it; the opened bytes are dropped here,
/// which is the property that makes this a probe rather than a decryption
/// oracle. `Some(Err(..))` carries the ring's own vocabulary, whose
/// [`Destroyed`](super::KeyError::Destroyed) variant is the one a caller must
/// keep distinct: a destroyed key is a completed erasure reporting itself.
///
/// This lives beside [`SealedCases`] rather than in the drill because the AAD
/// rule — the state is bound to tenant, purpose and case id — is this
/// decorator's own, and a second spelling of it in another module is the
/// sign/verify split that fails silently in one direction.
///
/// The probe holds a case id and no tenant, so the tenant half of the AAD is
/// recovered from the envelope's own wrapped-key scope — safe, because the
/// scope is not taken on trust: the ring only unwraps a data key its named
/// scope's wrapping key actually seals, so a relabelled scope fails at `open`
/// rather than opening under a borrowed identity. The scope must also name
/// exactly this case, or the envelope was written for a different matter.
pub async fn probe_sealed_case_state(
    keys: &dyn KeyRing,
    case: CaseId,
    state: &Value,
) -> Option<Result<(), super::KeyError>> {
    let envelope = payload::unwrap(state)?;
    let scope = super::envelope::wrapped_scope(&envelope)?;
    let tenant = scope.strip_suffix(&format!("/{case}"))?;
    let aad = format!("case-state:{tenant}:{case}");
    Some(
        super::envelope::open(keys, aad.as_bytes(), &envelope)
            .await
            .map(drop),
    )
}

#[async_trait]
impl CaseStore for SealedCases {
    fn tenant(&self) -> &str {
        self.tenant.as_str()
    }

    async fn put_state(
        &self,
        case: CaseId,
        expected: CaseVersion,
        state: Value,
    ) -> Result<CaseVersion, StoreError> {
        let plain = crate::core::canon::to_bytes(&state)
            .map_err(|e| StoreError::Backend(format!("case state would not serialise: {e}")))?;
        let envelope = super::envelope::seal(
            self.keys.as_ref(),
            &self.scope_for(case),
            self.aad(case).as_bytes(),
            &plain,
        )
        .await
        .map_err(|e| StoreError::Backend(format!("sealing case state failed: {e}")))?;
        self.inner
            .put_state(case, expected, payload::wrap(&envelope))
            .await
    }

    async fn case(&self, id: CaseId) -> Result<Option<Case>, StoreError> {
        let found = self.inner.case(id).await?;
        Ok(self.opened(found).await)
    }

    async fn by_status(&self, status: CaseStatus, limit: usize) -> Result<Vec<Case>, StoreError> {
        let cases = self.inner.by_status(status, limit).await?;
        let mut out = Vec::with_capacity(cases.len());
        for case in cases {
            if let Some(opened) = self.opened(Some(case)).await {
                out.push(opened);
            }
        }
        Ok(out)
    }

    async fn correlate(&self, keys: &[CorrelationKey]) -> Result<Option<CaseId>, StoreError> {
        self.inner.correlate(keys).await
    }

    async fn correlate_or_open(
        &self,
        kind: &str,
        keys: &[CorrelationKey],
        at: Timestamp,
    ) -> Result<Correlation, StoreError> {
        self.inner.correlate_or_open(kind, keys, at).await
    }

    // Deliberately **not** opened, either direction — and this is the one place
    // the decorator's job is to stand aside. `cases` is the export's read, and
    // an export that carried plaintext would quietly undo erasure: destroying
    // the wrapping key would no longer reach the copy somebody exported last
    // month. The rows travel sealed, restore writes them back sealed, and a
    // plane holding the same ring reads them through `case()` exactly as
    // before. A caller who wants readable state has `case()`; this pair wants
    // the stored representation, which is the same thing the journal export
    // carries.
    async fn cases(&self, after: Option<CaseId>, limit: usize) -> Result<Vec<Case>, StoreError> {
        self.inner.cases(after, limit).await
    }

    async fn import_case(
        &self,
        case: &Case,
        deadlines: &[crate::core::Deadline],
        blobs: &[crate::core::Digest],
    ) -> Result<(), StoreError> {
        self.inner.import_case(case, deadlines, blobs).await
    }

    async fn attach_run(&self, case: CaseId, run: RunId) -> Result<(), StoreError> {
        self.inner.attach_run(case, run).await
    }

    async fn link_blob(
        &self,
        case: CaseId,
        digest: Digest,
        at: Timestamp,
    ) -> Result<(), StoreError> {
        self.inner.link_blob(case, digest, at).await
    }

    async fn blobs_of(&self, case: CaseId) -> Result<Vec<Digest>, StoreError> {
        self.inner.blobs_of(case).await
    }

    async fn set_status(&self, case: CaseId, status: CaseStatus) -> Result<(), StoreError> {
        self.inner.set_status(case, status).await
    }

    async fn close(&self, case: CaseId) -> Result<(), StoreError> {
        self.inner.close(case).await
    }

    async fn register_deadline(&self, deadline: &Deadline) -> Result<(), StoreError> {
        self.inner.register_deadline(deadline).await
    }

    async fn deadlines(&self, case: CaseId) -> Result<Vec<Deadline>, StoreError> {
        self.inner.deadlines(case).await
    }

    async fn set_deadline_state(
        &self,
        case: CaseId,
        name: &str,
        state: DeadlineState,
    ) -> Result<(), StoreError> {
        self.inner.set_deadline_state(case, name, state).await
    }

    async fn due(&self, now: Timestamp, limit: usize) -> Result<Vec<Deadline>, StoreError> {
        self.inner.due(now, limit).await
    }

    async fn census(&self, now: Timestamp) -> Result<crate::case::CaseCensus, StoreError> {
        self.inner.census(now).await
    }
}
