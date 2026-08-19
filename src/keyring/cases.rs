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
///
/// # Exactly one thing is an ordinary `None`
///
/// State that is **not marked sealed**. Every step after that marker is a
/// question the probe was asked and must answer: base64 that will not decode,
/// a header that does not parse, a format version this build does not read, a
/// scope naming another case. Each of those is a value that claims to be
/// sealed and cannot be shown to open — the precise condition this probe
/// exists to surface — and answering `None` to any of them reports *nothing
/// to check* about the state most in need of checking, in a report whose only
/// job is to find it.
pub async fn probe_sealed_case_state(
    keys: &dyn KeyRing,
    case: CaseId,
    state: &Value,
) -> Option<Result<(), super::KeyError>> {
    if !payload::is_sealed(state) {
        return None;
    }
    let Some(envelope) = payload::unwrap(state) else {
        return Some(Err(super::KeyError::Refused(
            "the state is marked sealed and its envelope is not valid base64".to_owned(),
        )));
    };
    let scope = match super::envelope::wrapped_scope(&envelope) {
        Ok(scope) => scope,
        Err(e) => return Some(Err(e)),
    };
    let Some(tenant) = scope.strip_suffix(&format!("/{case}")) else {
        return Some(Err(super::KeyError::Refused(format!(
            "this case's sealed state names erasure scope '{scope}', which is not this \
             case — the envelope was written for a different matter, so erasing this \
             case would leave it readable"
        ))));
    };
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

#[cfg(all(test, feature = "testkit"))]
mod probe_tests {
    use super::*;
    use crate::testkit::MemoryKeyRing;
    use serde_json::json;

    fn matter() -> CaseId {
        CaseId::generate()
    }

    async fn sealed_state(ring: &MemoryKeyRing, tenant: &str, case: CaseId) -> Value {
        let aad = format!("case-state:{tenant}:{case}");
        let plain = crate::core::canon::to_bytes(&json!({ "about": "the matter" })).expect("canon");
        let envelope =
            super::super::envelope::seal(ring, &format!("{tenant}/{case}"), aad.as_bytes(), &plain)
                .await
                .expect("seal");
        payload::wrap(&envelope)
    }

    /// Readable state is not a defect, and it is the only ordinary `None`.
    #[tokio::test]
    async fn state_that_was_never_sealed_is_an_ordinary_absence() {
        let ring = MemoryKeyRing::new();
        assert!(
            probe_sealed_case_state(&ring, matter(), &json!({ "about": "plain" }))
                .await
                .is_none(),
            "unsealed state is not something a sealing probe has an answer about"
        );
    }

    /// The positive half, so the refusals below are not vacuous.
    #[tokio::test]
    async fn sealed_state_that_opens_reports_that_it_opened() {
        let ring = MemoryKeyRing::new();
        let case = matter();
        let state = sealed_state(&ring, "acme", case).await;
        assert_eq!(
            probe_sealed_case_state(&ring, case, &state).await,
            Some(Ok(())),
        );
    }

    /// **Marked sealed and unreadable must never answer "nothing to check".**
    ///
    /// Each row is a value whose `$sealed` marker says *this is ciphertext*
    /// and which cannot then be shown to open — the precise condition the
    /// probe exists to surface. Answering `None` to any of them makes the
    /// drill count the case as carrying no sealed state at all: no finding, no
    /// unchecked entry, and a report that says everything opens over state it
    /// never opened. That is detection without delivery in the pass whose only
    /// job is detection.
    ///
    /// The bad-base64 and foreign-scope rows are `Refused` on purpose. Neither
    /// has a benign remedy — one is damage in the store, the other is an
    /// envelope written for a different matter, which means erasing this case
    /// would leave it readable — so both belong in the drill's tampering arm,
    /// where somebody is paged.
    #[tokio::test]
    async fn sealed_state_this_build_cannot_read_is_answered_not_skipped() {
        let ring = MemoryKeyRing::new();
        let case = matter();
        let state = sealed_state(&ring, "acme", case).await;
        let envelope = payload::unwrap(&state).expect("sealed");

        let mut bumped = envelope.clone();
        bumped[0] = bumped[0].wrapping_add(1);

        let rows: [(&str, CaseId, Value); 3] = [
            (
                "a format version this build does not read",
                case,
                payload::wrap(&bumped),
            ),
            (
                // The same envelope, filed against a case it was not sealed
                // for. Erasing *this* case would destroy a key that does not
                // reach these bytes, so they would survive the request.
                "an envelope sealed for another matter",
                matter(),
                state.clone(),
            ),
            (
                "a marker whose payload is not base64",
                case,
                json!({ payload::SEALED: "not base64 !!" }),
            ),
        ];

        for (label, case, value) in rows {
            assert!(
                payload::is_sealed(&value),
                "{label}: the row stopped claiming to be sealed, so it proves nothing"
            );
            let answer = probe_sealed_case_state(&ring, case, &value).await;
            assert!(
                matches!(answer, Some(Err(_))),
                "{label} was reported as nothing to check: {answer:?}"
            );
        }

        // And the version skew carries the classification the drill routes on,
        // rather than the one that reads as loss or tampering.
        assert!(
            matches!(
                probe_sealed_case_state(&ring, case, &payload::wrap(&bumped)).await,
                Some(Err(super::super::KeyError::UnknownFormat { .. }))
            ),
            "a version skew must not reach the drill as a suspected loss"
        );
    }
}
