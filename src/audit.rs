//! Checking a plane's history without trusting the plane.
//!
//! # Why this is a deliverable and not a property
//!
//! Every mechanism underneath — the hash chain, per-record signatures, the
//! Merkle log — is only *checkable*. Somebody has to actually check it, and if
//! the only code that can is inside the runtime being audited, the claim
//! collapses: the party under examination is also the party running the
//! examination.
//!
//! So this module is deliberately shaped to run **against a store it did not
//! write**, with inputs an auditor holds rather than inputs the plane supplies:
//!
//! * a **prior checkpoint** they were given earlier — the one artifact that has
//!   to have left the operator's control;
//! * a **public key**, if they were told which workload should have signed.
//!
//! Neither is required, and what can be concluded shrinks accordingly. That
//! shrinkage is reported rather than hidden, because an audit that says "fine"
//! when it checked three things out of five is worse than one that checked
//! nothing.
//!
//! # What each input buys
//!
//! | Given | Answers |
//! |---|---|
//! | nothing | Is each run's chain internally consistent? |
//! | a public key | Who wrote each record? |
//! | a prior checkpoint | Has anything been **removed** since it was issued? |
//!
//! Only the third detects deletion, and only because the checkpoint came from
//! outside. That is the whole architecture of the thing in one row.

use std::sync::Arc;

use crate::core::{Digest, RunId, StoreError, Verifier, merkle};
use crate::journal::{Checkpoint, JournalStore, Record};

/// What an audit concluded, and what it could not look at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditReport {
    /// The checkpoint the store reports now.
    pub current: Checkpoint,
    /// Runs whose chain, signatures and inclusion all checked out.
    pub sound: Vec<RunId>,
    /// What went wrong, in the order found.
    pub findings: Vec<Finding>,
    /// Checks that were not performed, and why.
    ///
    /// Reported as loudly as failures. An audit that quietly skipped signature
    /// verification because no key was supplied, and then said "verified", is
    /// exactly the reassuring-but-empty artifact this crate exists to avoid.
    pub not_checked: Vec<String>,
    /// Every point at which a label was raised, in the order found.
    ///
    /// Not a finding — a release is a legitimate, authorized decision, and
    /// flagging it as a problem would train a reader to ignore the list. It is
    /// reported because it is the **only discretionary act in the system**: the
    /// chain, the signatures and the inclusion proofs all verify that history is
    /// intact, and none of them surfaces the moment somebody decided untrusted
    /// data could be treated as trusted. An auditor verifying integrity while
    /// never seeing that is checking the envelope and not the letter.
    ///
    /// Each entry answers the questions the decision was required to record:
    /// who, on what basis, toward what destination, over which fields, on what
    /// evidence.
    pub releases: Vec<ReleaseRecord>,
    /// What authorized each run: the declaration it ran under, and the policy
    /// bundle that governed it.
    ///
    /// Not a finding, for the same reason `releases` is not: an authorized run
    /// is the ordinary case. It is reported because **an audit that verifies
    /// history is intact and never says what warranted it has checked the
    /// letter and not the warrant** — the mirror of the argument one field up.
    ///
    /// The load-bearing entry is the one where `policy` is `None`. A run that
    /// executed with **no policy engine configured at all** verifies exactly as
    /// soundly as a governed one: its chain is intact, its signatures check, its
    /// leaf is included. Nothing in an integrity report distinguishes them, so
    /// an auditor reading `sound` would conclude a run was governed when the
    /// deployment had no gate wired. *Was policy switched on for this run* is an
    /// audit question the journal answers and this report did not surface.
    ///
    /// The digest is what makes the declaration half meaningful: a name and
    /// version identify a file that may since have been edited, and only the
    /// digest pins what it actually said — the system prompt included.
    pub warrants: Vec<Warrant>,
}

/// What authorized one run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Warrant {
    /// The run this describes.
    pub run: RunId,
    /// The agent declaration that governed it, if one did.
    ///
    /// `None` for a run started from code rather than from a manifest, which is
    /// a legitimate shape and a different one from a manifest-governed run.
    pub declaration: Option<crate::journal::AgentIdentity>,
    /// The complete policy bundle that governed it.
    ///
    /// `None` means **no engine was configured**. That is the entry an auditor
    /// most needs and the one an integrity-only report cannot show.
    pub policy: Option<crate::core::PolicyBundleIdentity>,
}

/// One journaled decision to improve a label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseRecord {
    pub run: RunId,
    /// The agent or operator the decision was recorded against.
    pub releaser: String,
    /// Why, in the releaser's own words.
    pub basis: String,
    /// Where the value was being released *to*. A release is always toward
    /// something; one with no destination is a permission with no boundary.
    pub destination: String,
    /// Which fields moved — `""` for the whole value.
    pub fields: Vec<String>,
    /// What was cited. An empty set is impossible: `Release::validate` refuses
    /// it, and this being non-empty is that rule observed from the outside.
    pub evidence: Vec<String>,
    /// The digest of the value that was released, so a reader can tie the
    /// decision to the bytes rather than to a description of them.
    pub value: Digest,
}

impl AuditReport {
    /// Whether every check that ran, passed.
    ///
    /// Note the qualifier. A report with findings is a failure; a report with
    /// *no* findings and a long `not_checked` is not a pass, and callers are
    /// expected to look. [`Self::assert_complete`] is the strict form.
    #[must_use]
    pub fn is_sound(&self) -> bool {
        self.findings.is_empty()
    }

    /// Panic unless everything passed **and** everything was checkable.
    ///
    /// # Panics
    ///
    /// If anything failed, or if any check was skipped.
    pub fn assert_complete(&self) {
        assert!(
            self.findings.is_empty(),
            "the audit found {} problem(s):\n{}",
            self.findings.len(),
            self.findings
                .iter()
                .map(|f| format!("  • {f}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
        assert!(
            self.not_checked.is_empty(),
            "the audit passed but could not check everything:\n{}",
            self.not_checked
                .iter()
                .map(|s| format!("  • {s}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}

/// One thing wrong with a plane's history.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Finding {
    #[error("run {run}: {detail}")]
    Chain { run: RunId, detail: String },

    #[error("run {run} is sealed but is not in the log — no checkpoint covers it")]
    NotInLog { run: RunId },

    #[error("run {run} claims a position the log's own root does not support")]
    BadInclusion { run: RunId },

    /// The one that needs an outside artifact.
    #[error(
        "the log cannot prove it only grew since the checkpoint of size {old_size} — \
         something committed to earlier is no longer committed to now"
    )]
    NotAppendOnly { old_size: u64 },

    #[error("the prior checkpoint names log '{theirs}', this store is '{ours}'")]
    WrongLog { theirs: String, ours: String },

    #[error(
        "the prior checkpoint is larger ({old_size}) than this log ({now}) — a log \
         cannot shrink, so runs were removed or this is a different plane"
    )]
    Shrunk { old_size: u64, now: u64 },
}

/// What an auditor brought with them.
///
/// Hand-written `Debug` because a `Verifier` is a trait object with no useful
/// rendering, and deriving would demand one.
#[derive(Default)]
pub struct Evidence<'a> {
    /// A checkpoint issued earlier, from outside this store.
    pub prior: Option<&'a Checkpoint>,
    /// The key the records should carry.
    pub verifier: Option<&'a dyn Verifier>,
    /// Whether an unsigned record is a failure.
    ///
    /// Off by default: history written before signing was configured is
    /// legitimately unsigned, and an auditor who does not know that would read a
    /// wall of failures for a plane that is fine.
    pub require_signatures: bool,
}

impl std::fmt::Debug for Evidence<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Evidence")
            .field("prior", &self.prior)
            .field("verifier", &self.verifier.is_some())
            .field("require_signatures", &self.require_signatures)
            .finish()
    }
}

/// Check a plane's history.
///
/// `runs` is what to look at — an auditor sampling, or everything they were
/// given. The log-level checks do not depend on it.
///
/// # Errors
///
/// [`StoreError`] only when the store cannot be read at all. A *finding* is a
/// result, not an error: an audit that stopped at the first problem would report
/// one defect in a store with forty.
/// Every label-raising decision in one run's history.
fn releases_in(run: RunId, records: &[Record]) -> Vec<ReleaseRecord> {
    records
        .iter()
        .filter_map(|record| match record.kind() {
            crate::journal::RecordKind::Released {
                releaser,
                release,
                value,
                ..
            } => Some(ReleaseRecord {
                run,
                releaser: releaser.clone(),
                basis: release.basis().to_owned(),
                destination: release.destination().to_owned(),
                fields: release.fields_scope().iter().cloned().collect(),
                evidence: release.evidence().iter().cloned().collect(),
                value: *value,
            }),
            _ => None,
        })
        .collect()
}

/// What authorized one run, from the record that opened it.
///
/// `RunAdmitted` carries both, and carries them once: the declaration because
/// *which manifest governed this* must be answerable years later, and the bundle
/// because *was policy switched on* must be too. Reading them here rather than
/// re-deriving from today's wiring is the whole point — an audit runs against a
/// store it did not write, on a machine that may have no engine configured at
/// all.
fn warrant_in(run: RunId, records: &[Record]) -> Option<Warrant> {
    records.iter().find_map(|record| match record.kind() {
        crate::journal::RecordKind::RunAdmitted {
            governed_by,
            policy_bundle,
            ..
        } => Some(Warrant {
            run,
            declaration: governed_by.clone(),
            policy: policy_bundle.clone(),
        }),
        _ => None,
    })
}

pub async fn audit(
    store: &Arc<dyn JournalStore>,
    runs: &[RunId],
    evidence: &Evidence<'_>,
) -> Result<AuditReport, StoreError> {
    let current = store.checkpoint().await?;
    let mut findings = Vec::new();
    let mut not_checked = Vec::new();
    let mut sound = Vec::new();
    let mut releases = Vec::new();
    let mut warrants = Vec::new();

    if evidence.verifier.is_none() {
        not_checked.push(
            "signatures — no public key was supplied, so this audit cannot say who \
             wrote anything"
                .to_owned(),
        );
    }
    if evidence.prior.is_none() {
        not_checked.push(
            "deletion — no earlier checkpoint was supplied, so this audit cannot \
             detect a run that was removed. Every check below passes over a store \
             somebody emptied"
                .to_owned(),
        );
    }

    // ── Per run ────────────────────────────────────────────────────────────
    for &run in runs {
        let records = store.read(run, 1).await?;
        let chain = match evidence.verifier {
            Some(v) => {
                Record::verify_attested(&records, Digest::ZERO, v, evidence.require_signatures)
            }
            None => Record::verify_chain(&records, Digest::ZERO),
        };
        if let Err(e) = chain {
            findings.push(Finding::Chain {
                run,
                detail: e.to_string(),
            });
            continue;
        }

        // Collected after the chain verified, so a reader is never shown a
        // decision — or a warrant — drawn from records whose integrity did not
        // hold. A forged `RunAdmitted` naming a policy bundle nobody configured
        // is exactly the claim an auditor must not be handed.
        releases.extend(releases_in(run, &records));
        warrants.extend(warrant_in(run, &records));

        match store.inclusion_proof(run).await? {
            Some(inc) => {
                let leaf = merkle::leaf_hash(&inc.seal);
                let ok = merkle::verify_inclusion(
                    &leaf,
                    usize::try_from(inc.index).unwrap_or(usize::MAX),
                    usize::try_from(inc.size).unwrap_or(0),
                    &inc.proof,
                    &current.root,
                );
                if ok {
                    sound.push(run);
                } else {
                    findings.push(Finding::BadInclusion { run });
                }
            }
            // An unsealed run is not in the log because it has not finished, and
            // that is not a finding. A *sealed* one missing from the log is —
            // but only the store knows which, so this is reported as
            // not-in-log and left to the reader.
            None => findings.push(Finding::NotInLog { run }),
        }
    }

    // ── Against what the auditor brought ───────────────────────────────────
    if let Some(prior) = evidence.prior {
        if prior.origin != current.origin {
            findings.push(Finding::WrongLog {
                theirs: prior.origin.clone(),
                ours: current.origin.clone(),
            });
        } else if prior.size > current.size {
            findings.push(Finding::Shrunk {
                old_size: prior.size,
                now: current.size,
            });
        } else {
            let proof = store.consistency_proof(prior.size).await?;
            let ok = merkle::verify_consistency(
                usize::try_from(prior.size).unwrap_or(0),
                &prior.root,
                usize::try_from(current.size).unwrap_or(0),
                &current.root,
                &proof,
            );
            if !ok {
                findings.push(Finding::NotAppendOnly {
                    old_size: prior.size,
                });
            }
        }
    }

    Ok(AuditReport {
        current,
        sound,
        findings,
        not_checked,
        releases,
        warrants,
    })
}
