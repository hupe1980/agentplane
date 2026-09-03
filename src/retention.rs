//! Time-windowed erasure: the retention verb, and what it honestly cannot do.
//!
//! # The question this answers
//!
//! *Keep the chain, drop the payloads older than N.*
//! [`erase_case`](crate::blob::erase_case) erases one unit; this is the same
//! act on a window, so that a retention period is a policy a plane runs
//! rather than a routine each deployment writes.
//!
//! # Why "older than" means *opened* and not *closed*
//!
//! A [`Case`](crate::core::Case) records `opened_at` and nothing else about
//! time. That is not an accident to route around: the retention rules this
//! serves are written as *N years from the start of the business matter*, which
//! is what `opened_at` is. A closure date would also be the wrong anchor for
//! the case that reopens.
//!
//! Only **closed** cases are erased. A case still open is a matter still
//! running, and erasing the data underneath a live run turns a retention pass
//! into an outage.
//!
//! # What it destroys, and what it provably does not
//!
//! With a key ring: the case's blobs are tombstoned and the case's key scope is
//! destroyed, which reaches every replica and every backup at once — because
//! what was destroyed was never in them. The journal's records stay readable as
//! *records*: the chain, the routing fields, the fact the run happened. That is
//! the design, not a shortfall — the chain committed to ciphertext precisely so
//! an auditor with no keys can still verify a run whose payloads are gone.
//!
//! **Without a key ring, journal payloads are permanent.** Blob tombstones
//! still land, and they cover the live store only. This is the residual the
//! erasure page names, and this pass reports it in
//! [`RetentionReport::not_erasable`] rather than returning a clean number that
//! means less than it looks like — the same reason `DrillReport` carries
//! `not_checked` and `AuditReport` carries its coverage.

use std::sync::Arc;

use crate::blob::BlobStore;
use crate::case::CaseStore;
use crate::core::{CaseStatus, StoreError, Timestamp};

/// One page of the case walk, shared with the export's so "every case" has one
/// definition rather than two that drift.
use crate::export::CASE_PAGE;

/// What a retention pass did, and what it could not reach.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RetentionReport {
    /// Cases considered.
    pub scanned: usize,
    /// Closed cases past the window that this pass acted on.
    pub erased: usize,
    /// Blob references tombstoned across those cases.
    pub blobs_expired: usize,
    /// Cases that were past the window and could not be erased, with why.
    ///
    /// A failure per case rather than an error for the pass: one unreachable
    /// blob store must not stop the other four hundred cases from being
    /// erased, and an operator needs the list rather than the first entry.
    pub failures: Vec<String>,
    /// What this pass, by construction, did not make unreadable.
    ///
    /// The difference between *retention ran* and *nothing is left*. A number
    /// with no coverage statement beside it is the shape that lets a deployment
    /// believe an erasure obligation is discharged when the journal still holds
    /// the payload verbatim.
    pub not_erasable: Vec<String>,
}

impl RetentionReport {
    /// Whether every case this pass acted on was erased without error.
    ///
    /// Deliberately **not** "everything is gone": see
    /// [`not_erasable`](Self::not_erasable), which is a separate answer and the
    /// one an erasure request actually turns on.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.failures.is_empty()
    }
}

/// What a pass would act on, before it acts.
///
/// The selection rule lives here and nowhere else: a dry run that walked the
/// cases with its own copy of *closed and opened before the cutoff* would be
/// two implementations of one rule, and the one that drifts is whichever the
/// operator trusted last.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RetentionPlan {
    /// Cases considered.
    pub scanned: usize,
    /// Closed cases opened before the cutoff, in walk order.
    pub due: Vec<crate::core::CaseId>,
}

/// Select every closed case opened before `older_than`, erasing nothing.
///
/// # Errors
///
/// If the case layer cannot be enumerated.
pub async fn plan(
    cases: &dyn CaseStore,
    older_than: Timestamp,
) -> Result<RetentionPlan, StoreError> {
    let mut plan = RetentionPlan {
        scanned: 0,
        due: Vec::new(),
    };
    let mut after = None;
    loop {
        let page = cases.cases(after, CASE_PAGE).await?;
        if page.is_empty() {
            break;
        }
        let full = page.len() >= CASE_PAGE;
        after = page.last().map(|c| c.id);
        for case in page {
            plan.scanned += 1;
            // A case still open is a matter still running. Erasing underneath a
            // live run turns a retention pass into an outage.
            if case.status == CaseStatus::Closed && case.opened_at < older_than {
                plan.due.push(case.id);
            }
        }
        if !full {
            break;
        }
    }
    Ok(plan)
}

/// The stores a retention pass runs against.
///
/// A struct of refs for the same reason [`crate::drill::Stores`] is: a caller
/// cannot transpose two stores positionally, and a missing one is *reported as
/// uncovered* rather than silently skipped.
#[derive(Debug)]
pub struct Stores<'a> {
    /// The case layer to walk. Required — a case is the erasure unit, because
    /// it is what a request actually names; nobody asks to forget a digest.
    pub cases: &'a Arc<dyn CaseStore>,
    /// Where the bytes behind each case's digests are.
    pub blobs: Option<&'a Arc<dyn BlobStore>>,
    /// The ring whose destruction is what reaches backups.
    #[cfg(feature = "keyring")]
    pub keys: Option<&'a Arc<dyn crate::keyring::KeyRing>>,
    /// Whose cases these are. Blob addresses and key scopes are derived under
    /// the tenant, so a pass that assumed one would tombstone another tenant's
    /// addresses — or, worse, none.
    pub tenant: &'a crate::core::TenantId,
}

/// Erase every closed case opened before `older_than`.
///
/// `reason` lands on each tombstone and on the key destruction, so a later read
/// says *expired, on this date, for this reason* rather than *missing*. It is
/// required for the same reason a halt's is: the next person to look will be
/// somebody else, and *why* is the whole question.
///
/// `at` is the instant recorded on the tombstones. A parameter, not a clock
/// read, for the reason the sweeper's is: a pass that read the clock itself
/// could not be tested against a year of ageing cases.
///
/// # Errors
///
/// Only if the case layer cannot be enumerated. A store that fails on one case
/// is a *report entry*, not an error — the pass's job is to keep going and say
/// what it could not do.
pub async fn retain(
    stores: &Stores<'_>,
    older_than: Timestamp,
    at: Timestamp,
    reason: &str,
) -> Result<RetentionReport, StoreError> {
    let mut report = RetentionReport {
        scanned: 0,
        erased: 0,
        blobs_expired: 0,
        failures: Vec::new(),
        not_erasable: Vec::new(),
    };

    // Stated before anything is erased, so a report that fails early still
    // carries its coverage. A number with no coverage statement is how a
    // deployment comes to believe an obligation is discharged.
    //
    // No blob store does not stop the pass: the erasure unit is the key scope,
    // and a plane sealing its journal with a ring and storing no blobs is an
    // ordinary shape. What it loses is the tombstone, and the line says so.
    if stores.blobs.is_none() {
        report.not_erasable.push(
            "no blob store is wired: linked blobs were not tombstoned. On a sealed plane \
             their bytes are unreadable through the destroyed key; on an unsealed one they \
             are untouched"
                .to_owned(),
        );
    }
    #[cfg(feature = "keyring")]
    if stores.keys.is_none() {
        report.not_erasable.push(
            "no key ring is wired: blob tombstones cover the live store only, and journal \
             payloads — run input, prompts, tool arguments, effect outputs — stay verbatim \
             and permanent. Wire `RuntimeBuilder::keyring(..)`, or declare \
             `max_sensitivity_journaled` and keep the data out of records"
                .to_owned(),
        );
    }
    #[cfg(not(feature = "keyring"))]
    report.not_erasable.push(
        "this build has no `keyring` feature: blob tombstones cover the live store only, and \
         journal payloads stay verbatim and permanent"
            .to_owned(),
    );

    let selected = plan(stores.cases.as_ref(), older_than).await?;
    report.scanned = selected.scanned;
    for case in selected.due {
        let erased = crate::blob::erase_case(
            stores.blobs.map(std::convert::AsRef::as_ref),
            stores.cases.as_ref(),
            #[cfg(feature = "keyring")]
            stores.keys.map(std::convert::AsRef::as_ref),
            stores.tenant,
            case,
            at,
            reason,
        )
        .await;
        match erased {
            Ok(n) => {
                report.erased += 1;
                report.blobs_expired += n;
            }
            Err(e) => report
                .failures
                .push(format!("case {case} could not be erased: {e}")),
        }
    }
    Ok(finish(report))
}

/// The coverage lines that hold whether or not the walk ran.
fn finish(mut report: RetentionReport) -> RetentionReport {
    report.not_erasable.push(
        "journal records are append-only: the chain, the routing fields and the fact each run \
         happened remain — by design, so an auditor with no keys still verifies a run whose \
         payloads are gone"
            .to_owned(),
    );
    report.not_erasable.push(
        "a run that belongs to no case is not reached by a case walk; erase one with \
         `blob::erase_run`"
            .to_owned(),
    );
    report
}
