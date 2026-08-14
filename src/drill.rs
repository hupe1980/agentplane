//! The live half of the case-layer drill: the questions no exported file can
//! answer.
//!
//! [`export::verify`](crate::export::verify) proves an export sound from its
//! own bytes, and honestly reports two checks as beyond it: whether the blob
//! **bytes** behind the exported digests are still present and unaltered, and
//! whether sealed case state can still be **opened**. Both are questions about
//! live stores — a blob store and a key ring — so they belong to whoever runs
//! the plane, with the stores the plane actually runs with.
//!
//! # Erasure is an answer, not a failure
//!
//! The entire value of this pass is telling three states apart, because only
//! one of them is an incident:
//!
//! | state | means | verdict |
//! |---|---|---|
//! | present, hashes | the artifact is intact | sound |
//! | tombstoned / key destroyed | retention did its job, on a date, for a reason | **erased by design** |
//! | missing, corrupt, or unopenable with the key still alive | loss or tampering | **finding** |
//!
//! A drill that counted an erased blob as missing would teach operators that
//! findings are noise, which is how a real loss gets ignored six months later.
//! The blob store's error taxonomy and [`KeyError::Destroyed`] exist precisely
//! so this distinction survives to a report.
//!
//! # What this deliberately does not do
//!
//! It does not return plaintext. Proving a sealed state opens requires opening
//! it, and the opened bytes are dropped on the spot — a drill that surfaced
//! them would be a decryption oracle wearing an ops hat.
//!
//! It does not walk the journal. [`audit`](crate::audit) owns *is the history
//! sound*; this owns *are the artifacts and keys the case layer references
//! still there*. Folding them would re-create the module split both were cut
//! along.
//!
//! [`KeyError::Destroyed`]: crate::keyring::KeyError::Destroyed

use std::sync::Arc;

use crate::blob::{BlobError, BlobStore};
use crate::case::CaseStore;
use crate::core::StoreError;

/// How many cases one enumeration page holds. Interior: the walk is complete
/// either way, and the page only bounds memory.
const CASE_PAGE: usize = 256;

/// What a live drill established, and what it could not look at.
///
/// The same shape as [`AuditReport`](crate::audit::AuditReport) and
/// [`VerifyReport`](crate::export::VerifyReport), for the same reason: a pass
/// that reports only failures describes its coverage by omission, and the
/// difference between *sound* and *nothing I checked was wrong* is the
/// `not_checked` list.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DrillReport {
    /// Cases walked.
    pub cases: usize,
    /// Blob references whose bytes are present and hash to their address.
    pub blobs_present: usize,
    /// Blob references answered by a tombstone — retention working, not loss.
    pub blobs_erased: usize,
    /// Sealed states that opened. The plaintext was dropped unread.
    pub sealed_open: usize,
    /// Sealed states whose key was deliberately destroyed — erasure working.
    pub sealed_erased: usize,
    /// What is wrong: bytes missing with no tombstone, bytes altered, or a
    /// sealed state that neither opens nor was destroyed.
    pub findings: Vec<String>,
    /// What this pass could not establish, and why.
    pub not_checked: Vec<String>,
}

impl DrillReport {
    /// Whether every check that ran, passed. See [`Self::not_checked`].
    #[must_use]
    pub fn is_sound(&self) -> bool {
        self.findings.is_empty()
    }
}

/// The stores a drill runs against.
///
/// Optional individually, exactly as [`audit`](crate::audit)'s evidence is: a
/// plane with no blob store has no bytes to check, and saying *unchecked* is a
/// different and better answer than saying nothing. The same struct-of-refs
/// shape too, so a caller cannot transpose two stores positionally.
#[derive(Debug)]
pub struct Stores<'a> {
    /// The case layer to walk. Required — it is the thing being drilled.
    pub cases: &'a Arc<dyn CaseStore>,
    /// Where the bytes behind each case's blob digests should be.
    pub blobs: Option<&'a Arc<dyn BlobStore>>,
    /// The ring that should still open sealed case state.
    #[cfg(feature = "keyring")]
    pub keys: Option<&'a Arc<dyn crate::keyring::KeyRing>>,
}

/// Walk every case and hold its references against the live stores.
///
/// # Errors
///
/// Only if the case layer itself cannot be enumerated. A store that fails on
/// one blob or one envelope is a *report entry*, not an error — the drill's
/// job is to keep going and say what it saw.
pub async fn drill(stores: &Stores<'_>) -> Result<DrillReport, StoreError> {
    let mut report = DrillReport {
        cases: 0,
        blobs_present: 0,
        blobs_erased: 0,
        sealed_open: 0,
        sealed_erased: 0,
        findings: Vec::new(),
        not_checked: Vec::new(),
    };
    if stores.blobs.is_none() {
        report.not_checked.push(
            "blob bytes — no blob store was supplied, so presence and integrity of the \
             artifacts each case references were not established"
                .to_owned(),
        );
    }
    #[cfg(feature = "keyring")]
    if stores.keys.is_none() {
        report.not_checked.push(
            "sealed-state keys — no key ring was supplied, so whether sealed case state \
             still opens was not established"
                .to_owned(),
        );
    }
    #[cfg(not(feature = "keyring"))]
    report.not_checked.push(
        "sealed-state keys — this build carries no `keyring` feature, so whether sealed \
         case state still opens was not established"
            .to_owned(),
    );

    let mut after = None;
    loop {
        let page = stores.cases.cases(after, CASE_PAGE).await?;
        let Some(last) = page.last() else { break };
        after = Some(last.id);
        let full = page.len() >= CASE_PAGE;
        for case in page {
            report.cases += 1;
            if let Some(blobs) = stores.blobs {
                check_blobs(&mut report, stores.cases, blobs.as_ref(), case.id).await?;
            }
            #[cfg(feature = "keyring")]
            if let Some(keys) = stores.keys {
                check_sealed(&mut report, keys.as_ref(), case.id, &case.state).await;
            }
        }
        if !full {
            break;
        }
    }
    Ok(report)
}

/// Hold one case's blob references against the store that should have them.
async fn check_blobs(
    report: &mut DrillReport,
    cases: &Arc<dyn CaseStore>,
    blobs: &dyn BlobStore,
    case: crate::core::CaseId,
) -> Result<(), StoreError> {
    for digest in cases.blobs_of(case).await? {
        // `get`, not `has`: presence without integrity is the check that
        // passes over altered bytes, and altered bytes are the one state
        // somebody must be paged about.
        match blobs.get(digest).await {
            Ok(bytes) => {
                drop(bytes);
                report.blobs_present += 1;
            }
            Err(BlobError::Expired { .. }) => report.blobs_erased += 1,
            Err(BlobError::NotFound(_)) => report.findings.push(format!(
                "case {case}, blob {digest}: the bytes are gone with no tombstone — \
                 unexplained loss, which is a different fact from erasure and cannot be \
                 settled from the journal, because the journal deliberately never held \
                 the bytes"
            )),
            Err(e @ BlobError::Corrupt { .. }) => report.findings.push(format!(
                "case {case}, blob {digest}: {e} — content that cannot be trusted is \
                 worse than content that is missing, because it is used"
            )),
            Err(BlobError::Backend(e)) => report.not_checked.push(format!(
                "case {case}, blob {digest}: the blob store could not be reached ({e}) — \
                 presence was not established either way"
            )),
        }
    }
    Ok(())
}

/// Prove one case's sealed state still opens, without keeping the plaintext.
#[cfg(feature = "keyring")]
async fn check_sealed(
    report: &mut DrillReport,
    keys: &dyn crate::keyring::KeyRing,
    case: crate::core::CaseId,
    state: &serde_json::Value,
) {
    use crate::keyring::KeyError;

    match crate::keyring::probe_sealed_case_state(keys, case, state).await {
        None => {}
        Some(Ok(())) => report.sealed_open += 1,
        Some(Err(KeyError::Destroyed { .. })) => report.sealed_erased += 1,
        Some(Err(KeyError::Unavailable(e))) => report.not_checked.push(format!(
            "case {case}: the key ring could not be reached ({e}) — whether the sealed \
             state opens was not established either way"
        )),
        Some(Err(e)) => report.findings.push(format!(
            "case {case}: sealed state neither opens nor was its key destroyed ({e}) — \
             an erasure would have said so, which makes this loss or tampering"
        )),
    }
}
