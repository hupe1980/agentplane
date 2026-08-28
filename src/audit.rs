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
///
/// `Serialize` is deliberate and load-bearing: the independent party this
/// report exists for should not have to link this crate to read it. The
/// findings render as the sentences they display as, because an auditor reads
/// prose and a machine that wants structure has the run ids beside it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AuditReport {
    /// The checkpoint the store reports now.
    pub current: Checkpoint,
    /// Runs whose chain, signatures and inclusion all checked out.
    ///
    /// An **open** run — one whose last conclusion does not seal, or which has
    /// no conclusion yet — appears here on chain and signatures alone: it has
    /// no Merkle leaf, so there is no inclusion to check, and [`not_checked`]
    /// says so once rather than a finding saying it per run. A run whose own
    /// records carry a *sealing* conclusion but which the log holds no leaf
    /// for is the opposite case, and that one is a finding.
    ///
    /// [`not_checked`]: Self::not_checked
    pub sound: Vec<RunId>,
    /// What went wrong, in the order found.
    ///
    /// Serialised as the rendered sentence rather than as a tagged variant: the
    /// consumer is a person or a SIEM, and a variant name is this crate's
    /// internal vocabulary. The run id each finding names is in the text.
    #[serde(serialize_with = "as_sentences")]
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
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

/// Render findings as the sentences they display as.
fn as_sentences<S: serde::Serializer>(f: &[Finding], s: S) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeSeq;
    let mut seq = s.serialize_seq(Some(f.len()))?;
    for finding in f {
        seq.serialize_element(&finding.to_string())?;
    }
    seq.end()
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

    /// The chain the store *served* is not the chain the log committed to.
    ///
    /// The one that catches a truncated-but-internally-consistent record set:
    /// a prefix of a chain verifies on its own, and the leaf the log holds is
    /// the terminal hash of the *whole* run — so an audit that verified the
    /// records and then checked the store-supplied leaf against the tree,
    /// without ever holding the two to each other, was verifying two halves of
    /// two different claims.
    #[error(
        "run {run}: the log's leaf is not the verified chain's head — records were \
         removed or replaced after sealing, and the served history is not the one \
         the checkpoint commits to"
    )]
    LeafMismatch { run: RunId },

    /// The sealing record's own claim disagrees with the chain it sits in.
    ///
    /// `RunSealed.chain_head` is the head the conclusion was drawn over — by
    /// construction, the record's own `prev_hash`. A mismatch means the
    /// conclusion was composed against a different history than the one it was
    /// appended to, which no honest writer produces.
    #[error(
        "run {run}: the sealing record claims a chain head that is not the head it \
         sits on — the conclusion was drawn over a different history"
    )]
    SealClaim { run: RunId },

    /// A sealed conclusion over an undecided transactional unit.
    ///
    /// `GroupOpened`/`GroupSettled` bracket several effects that take together
    /// or not at all, and the settlement is the most consequential thing a
    /// group does. A run still open with a group unsettled is the ordinary
    /// crash shape — the resume re-walks the members and settles, and the run
    /// itself sits in a findable backlog until it does. A **sealed** run is
    /// the state no honest writer produces: nothing may resume it, so nothing
    /// will ever settle the group, and whether its members were taken or taken
    /// back is permanently unanswerable from a history that claims to be
    /// complete.
    #[error(
        "run {run} is sealed but group '{group}' was opened and never settled — \
         nothing may resume a sealed run, so whether the group's members were \
         taken or taken back is permanently undecided"
    )]
    GroupUnsettled { run: RunId, group: String },

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

/// Where one run stands relative to the Merkle log.
enum Placement {
    /// In the log, at a position the root supports.
    Sound,
    /// Not in the log because it has not concluded with a sealing outcome —
    /// a state, not a defect. Chain and signatures were verified upstream.
    Open,
    /// The run's own records carry a sealing conclusion, and the log holds no
    /// leaf for it: history the log no longer commits to.
    NotInLog,
    /// The log holds a leaf that is not the verified chain's head: the served
    /// records are not the history the log committed to.
    LeafMismatch,
    /// In the log by its own claim, at a position the root does not support.
    BadInclusion,
    /// The log grew faster than the audit could catch its checkpoint up, so
    /// nothing ties this run's proof to one root. Honest, and rare: it takes a
    /// seal landing between two adjacent store calls, twice.
    Unpinned,
}

/// Decide one run's [`Placement`], catching `current` up if the log grew.
///
/// The catch-up is the part that earns a comment: the log can grow while the
/// audit walks it, and a proof computed against a larger tree than the
/// checkpoint in hand fails for a reason that is time, not tampering — a false
/// integrity alarm teaches the reader to ignore the true one. One refresh
/// covers the realistic race; a plane sealing continuously lands in
/// [`Placement::Unpinned`] rather than in a finding.
async fn placement(
    store: &Arc<dyn JournalStore>,
    run: RunId,
    records: &[Record],
    head: Digest,
    current: &mut Checkpoint,
) -> Result<Placement, StoreError> {
    let Some(inc) = store.inclusion_proof(run).await? else {
        // The store holds no leaf, and whether that is a finding is decided by
        // the run's own records rather than assumed. An **open** run — failed,
        // exhausted, still executing — was never in the log; reporting it as a
        // defect would flag every healthy resumable run and teach the reader
        // to skim past the flag that matters.
        return Ok(if has_sealing_conclusion(records) {
            Placement::NotInLog
        } else {
            Placement::Open
        });
    };

    // The leaf must be the verified chain's own head, checked **before** the
    // tree math and independent of any checkpoint race. `inc.seal` is
    // store-supplied; the head was recomputed from the served bytes. Verifying
    // each without holding them to each other let a store serve a truncated —
    // but internally consistent — prefix of a sealed run and have both halves
    // pass: the prefix's chain verifies, and the log's genuine leaf verifies
    // against the genuine tree.
    if inc.seal != head {
        return Ok(Placement::LeafMismatch);
    }

    if inc.size != current.size {
        *current = store.checkpoint().await?;
    }
    if inc.size != current.size {
        return Ok(Placement::Unpinned);
    }
    let leaf = merkle::leaf_hash(&inc.seal);
    let ok = merkle::verify_inclusion(
        leaf,
        usize::try_from(inc.index).unwrap_or(usize::MAX),
        usize::try_from(inc.size).unwrap_or(0),
        &inc.proof,
        &current.root,
    );
    Ok(if ok {
        Placement::Sound
    } else {
        Placement::BadInclusion
    })
}

/// Whether the run's last conclusion is one nothing may resume.
///
/// The outcome list is the library's own ([`crate::runtime::SEALED_OUTCOMES`]),
/// not a re-spelling of it: two copies of *which conclusions close* is the
/// duplicate-rule shape, and the copy in an offline checker is the one that
/// drifts.
fn has_sealing_conclusion(records: &[Record]) -> bool {
    records
        .iter()
        .rev()
        .find_map(|r| match r.kind() {
            crate::journal::RecordKind::RunSealed { outcome, .. } => Some(outcome.as_str()),
            _ => None,
        })
        .is_some_and(|o| crate::runtime::SEALED_OUTCOMES.contains(&o))
}

/// Groups opened and never settled, in the order opened.
///
/// Counted per writing step, phase and name — two *distinct* groups may
/// legitimately share a name within one step (opened, settled, opened again),
/// so each settlement excuses exactly one opening, which is the same
/// arithmetic the executor's own resume bookkeeping uses.
fn unsettled_groups(records: &[Record]) -> Vec<String> {
    use std::collections::BTreeMap;
    type Key<'a> = (Option<crate::core::StepId>, crate::core::Phase, &'a str);
    let mut open: BTreeMap<Key<'_>, u64> = BTreeMap::new();
    let mut order: Vec<Key<'_>> = Vec::new();
    for r in records {
        match r.kind() {
            crate::journal::RecordKind::GroupOpened { group, .. } => {
                let key = (r.body.step, r.body.phase, group.as_str());
                *open.entry(key).or_insert(0) += 1;
                order.push(key);
            }
            crate::journal::RecordKind::GroupSettled { group, .. } => {
                if let Some(n) = open.get_mut(&(r.body.step, r.body.phase, group.as_str())) {
                    *n = n.saturating_sub(1);
                }
            }
            _ => {}
        }
    }
    // Whatever count a settlement did not excuse is unsettled. Leftovers are
    // attributed newest-first, because a settlement pairs with the most recent
    // opening of its name still standing.
    let mut out = Vec::new();
    for key in order.into_iter().rev() {
        if let Some(n) = open.get_mut(&key)
            && *n > 0
        {
            *n -= 1;
            out.push(key.2.to_owned());
        }
    }
    out.reverse();
    out
}

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

/// What an audit cannot conclude from the evidence it was given.
///
/// Reported up front and as loudly as failures: an audit that quietly skipped
/// a check it had no inputs for, and then said "verified", is the
/// reassuring-but-empty artifact this module exists to avoid.
fn missing_evidence(evidence: &Evidence<'_>) -> Vec<String> {
    let mut out = Vec::new();
    if evidence.verifier.is_none() {
        out.push(
            "signatures — no public key was supplied, so this audit cannot say who \
             wrote anything"
                .to_owned(),
        );
    }
    if evidence.prior.is_none() {
        out.push(
            "deletion — no earlier checkpoint was supplied, so this audit cannot \
             detect a run that was removed. Every check below passes over a store \
             somebody emptied"
                .to_owned(),
        );
    }
    out
}

/// The sealing record's own claim, held to the chain it sits in.
///
/// `RunSealed.chain_head` is the head the conclusion was drawn over, which is
/// by construction its own record's `prev_hash` — checkable only after the
/// chain has verified, so `prev_hash` is evidence rather than input. A run
/// with no conclusion has made no claim, and holds vacuously.
fn seal_claim_holds(records: &[Record]) -> bool {
    records
        .iter()
        .rev()
        .find_map(|r| match r.kind() {
            crate::journal::RecordKind::RunSealed { chain_head, .. } => {
                Some(*chain_head == r.prev_hash)
            }
            _ => None,
        })
        .unwrap_or(true)
}

/// The deletion check, against the checkpoint the auditor brought.
///
/// The proof must be paired with the checkpoint it is verified against, and
/// the log can grow between the two store calls — the same race `placement`
/// refreshes for, handled the same way, because two halves of one audit
/// reporting one race differently teaches the reader that findings are
/// weather. A proof computed over a log larger than the checkpoint in hand
/// fails for a reason that is time, not tampering, and a false `NotAppendOnly`
/// is the alarm this whole module exists to make believable. One refresh
/// covers the realistic race; a plane sealing continuously lands in
/// `not_checked` rather than in a finding.
///
/// What this does NOT cover: it decides nothing about tampering on the
/// unpinned path — a store that really did rewrite history and also keeps
/// growing is only caught by re-running against a quiesced store, which the
/// entry says in words.
async fn check_append_only(
    store: &Arc<dyn JournalStore>,
    prior: &Checkpoint,
    current: &mut Checkpoint,
    findings: &mut Vec<Finding>,
    not_checked: &mut Vec<String>,
) -> Result<(), StoreError> {
    if prior.origin != current.origin {
        findings.push(Finding::WrongLog {
            theirs: prior.origin.clone(),
            ours: current.origin.clone(),
        });
        return Ok(());
    }
    if prior.size > current.size {
        findings.push(Finding::Shrunk {
            old_size: prior.size,
            now: current.size,
        });
        return Ok(());
    }
    let mut proof = store.consistency_proof(prior.size).await?;
    let mut latest = store.checkpoint().await?;
    if latest.size != current.size {
        *current = latest;
        proof = store.consistency_proof(prior.size).await?;
        latest = store.checkpoint().await?;
    }
    if latest.size == current.size {
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
    } else {
        *current = latest;
        not_checked.push(
            "append-only consistency: the log grew throughout the audit, so the proof \
             could not be pinned to one checkpoint — re-run against a quiesced store"
                .to_owned(),
        );
    }
    Ok(())
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
pub async fn audit(
    store: &Arc<dyn JournalStore>,
    runs: &[RunId],
    evidence: &Evidence<'_>,
) -> Result<AuditReport, StoreError> {
    let mut current = store.checkpoint().await?;
    let mut findings = Vec::new();
    let mut not_checked = missing_evidence(evidence);
    let mut sound = Vec::new();
    let mut releases = Vec::new();
    let mut warrants = Vec::new();
    let mut open_runs = 0usize;

    // ── Per run ────────────────────────────────────────────────────────────
    for &run in runs {
        let records = store.read(run, 1).await?;
        // A run the store returns nothing for is unchecked, never sound.
        // Both backends answer an unknown run with an empty read rather than
        // an error, and every check downstream holds vacuously over nothing:
        // `verify_chain(&[])` passes, the seal claim is absent, and a missing
        // leaf reads as an ordinary open run — so a mistyped or deleted run id
        // audited as "chain and signatures verified" without one record ever
        // being looked at. Not a finding either: an unknown id and a run whose
        // records are genuinely gone cannot be told apart from an empty read,
        // and deletion is the prior-checkpoint check's question, which answers
        // it with evidence rather than a guess.
        if records.is_empty() {
            not_checked.push(format!(
                "run {run}: the store returned no records, so nothing about it was \
                 verified — an empty history holds every check vacuously, which is a \
                 different statement from sound"
            ));
            continue;
        }
        let chain = match evidence.verifier {
            Some(v) => {
                Record::verify_attested(&records, Digest::ZERO, v, evidence.require_signatures)
            }
            None => Record::verify_chain(&records, Digest::ZERO),
        };
        // The head is kept, not merely the verdict: it is the one value that
        // ties the verified bytes to the log's leaf below, and discarding it
        // was what let the two halves of this audit verify two different
        // histories.
        let head = match chain {
            Ok(head) => head,
            Err(e) => {
                findings.push(Finding::Chain {
                    run,
                    detail: e.to_string(),
                });
                continue;
            }
        };

        if !seal_claim_holds(&records) {
            findings.push(Finding::SealClaim { run });
            continue;
        }

        // Only under a sealing conclusion — an open run's unsettled group
        // is the crash shape a resume repairs, and flagging it would teach
        // the reader this finding is weather. `Finding::GroupUnsettled`
        // carries the argument.
        if has_sealing_conclusion(&records) {
            let mut undecided = false;
            for group in unsettled_groups(&records) {
                undecided = true;
                findings.push(Finding::GroupUnsettled { run, group });
            }
            if undecided {
                continue;
            }
        }

        // Collected after the chain verified, so a reader is never shown a
        // decision — or a warrant — drawn from records whose integrity did not
        // hold. A forged `RunAdmitted` naming a policy bundle nobody configured
        // is exactly the claim an auditor must not be handed.
        releases.extend(releases_in(run, &records));
        warrants.extend(warrant_in(run, &records));

        match placement(store, run, &records, head, &mut current).await? {
            Placement::Sound => sound.push(run),
            Placement::Open => {
                open_runs += 1;
                sound.push(run);
            }
            Placement::NotInLog => findings.push(Finding::NotInLog { run }),
            Placement::LeafMismatch => findings.push(Finding::LeafMismatch { run }),
            Placement::BadInclusion => findings.push(Finding::BadInclusion { run }),
            Placement::Unpinned => not_checked.push(format!(
                "run {run}: the log grew throughout the audit, so this run's inclusion \
                 could not be pinned to one checkpoint — re-run against a quiesced store"
            )),
        }
    }

    // Said once rather than per run, and in `not_checked` rather than as a
    // finding: an open run's tail has no leaf to pin it, so truncating it is
    // undetectable until it seals — a limit of what an open run *is*, reported
    // so a clean audit over open runs is not read as more than it proved.
    if open_runs > 0 {
        not_checked.push(format!(
            "{open_runs} open run(s): an open run has no Merkle leaf, so nothing pins its \
             tail — chain and signatures verified, and a truncated tail is undetectable \
             until the run seals"
        ));
    }

    // The audit's scope, stated rather than implied. `runs` is whatever the
    // caller sampled, and the log commits to `current.size` sealed runs — a
    // clean report over three runs of a three-thousand-run log is a true
    // statement about three runs, and nothing in the findings list would ever
    // say so. Stated as unchecked coverage, because that is what it is. What
    // this does NOT cover: it counts the runs *named*, not the runs verified —
    // duplicates in the sample, open runs, and runs the store returned nothing
    // for all inflate the count, so it is an upper bound on coverage and the
    // per-run entries above are the exact record.
    let examined = u64::try_from(runs.len()).unwrap_or(u64::MAX);
    if examined < current.size {
        not_checked.push(format!(
            "scope — this audit examined {examined} named run(s) and the log commits to \
             {} sealed run(s); the remainder was not looked at, and a clean report speaks \
             only for the runs it names",
            current.size
        ));
    }

    // ── Against what the auditor brought ───────────────────────────────────
    if let Some(prior) = evidence.prior {
        check_append_only(store, prior, &mut current, &mut findings, &mut not_checked).await?;
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
