//! Keeping a record beside an agent this plane does not execute.
//!
//! # What this is, and the one sentence that bounds it
//!
//! A seat beside somebody else's agent produces **evidence, not control**.
//! Every oversight wire on offer puts the verdict in the hands of the party
//! being governed — the observed agent applies its own dispositions, and the
//! client picks from a list the agent wrote — so what a seat can honestly
//! produce is a record of what was asked, what the agent reported doing, and
//! what a person allowed. That record is worth keeping: nothing in the editor
//! ecosystem produces a tamper-evident, offline-verifiable, independently
//! anchored account of it.
//!
//! What it may never do is read as this plane's own work. An observation is
//! *asserted* — the agent's account of itself — where a journaled effect is
//! *deterministically attached*: this runtime announced it, dispatched it under
//! authority, recorded the outcome. The rungs are kept apart by the record
//! kind, so the separation survives every reader, including ones written later
//! and elsewhere.
//!
//! # A run of its own, in the one journal
//!
//! An observed session is a run with **no admission record**, its own record
//! kind, and its own sealing outcome — the shape a sweep's run already takes.
//! One history, one Merkle root, one audit: an external verifier checks an
//! observation without being taught what one is, because verification is
//! payload-agnostic. Selective disclosure survives because an export names the
//! runs it carries, so disclosing an observed session does not disclose the
//! plane's own work.
//!
//! The cost is stated rather than hidden: the journal now holds runs this plane
//! did not execute, so a query meaning *work this plane did* must key on the
//! run's status rather than assume it.

use std::sync::Arc;

use crate::core::{ObservedStep, RunId, RuntimeError, Tainted};
use crate::journal::{Append, JournalStore, RecordKind};

#[cfg(feature = "acp")]
pub mod acp;

/// The epoch an observed session's records are written under.
///
/// Fixed, for the reason a sweep's is: this run is opened here and never taken
/// over, so there is no ownership to arbitrate. A lease would be arbitrating
/// between writers that do not exist.
const OBSERVED_EPOCH: crate::core::Epoch = 1;

/// A session being recorded, open until it is sealed.
///
/// Opened lazily in the same sense a sweep's run is: the first step is what
/// creates it, so a client that connects and disconnects without the agent
/// doing anything leaves no evidence of nothing happening.
#[derive(Debug)]
pub struct Session {
    store: Arc<dyn JournalStore>,
    id: String,
    run: RunId,
    case: Option<crate::core::CaseId>,
    steps: usize,
}

impl Session {
    /// Open a record for a session this plane does not execute.
    ///
    /// `session` is the identifier the observed party uses. It lands on every
    /// record this writes, for the reason [`RecordKind::Observed`] gives.
    #[must_use]
    pub fn new(store: Arc<dyn JournalStore>, session: impl Into<String>) -> Self {
        Self {
            store,
            id: session.into(),
            run: RunId::generate(),
            case: None,
            steps: 0,
        }
    }

    /// Bind this session's records to a case, so they can be found by the only
    /// identifier the party asking holds.
    ///
    /// **Without one, an observed session is findable but not indexed.** The
    /// records carry the session id, so answering *show me the record for
    /// session X* means listing runs by the `observed` outcome and reading the
    /// first record of each — a scan, correct and bounded and not a lookup.
    ///
    /// A case is the mechanism this plane already has for exactly that
    /// question: correlate one on the session id and the lookup is a single
    /// indexed read, with the obligation and legal-hold machinery available on
    /// the same matter. Optional rather than automatic, because opening a
    /// business matter per editor session is a decision about what a case
    /// *means* in a deployment, and this crate does not get to make it.
    ///
    /// ```no_run
    /// # use agentplane::core::CorrelationKey;
    /// # async fn f(cases: &dyn agentplane::case::CaseStore, at: agentplane::core::Timestamp)
    /// # -> Result<(), Box<dyn std::error::Error>> {
    /// let case = cases
    ///     .correlate_or_open("acp-session", &[CorrelationKey::new("session", "sess-1")], at)
    ///     .await?
    ///     .case_id();
    /// # Ok(()) }
    /// ```
    #[must_use]
    pub const fn in_case(mut self, case: crate::core::CaseId) -> Self {
        self.case = Some(case);
        self
    }

    /// The source every value from this session carries.
    ///
    /// Named after the session rather than left generic: two sessions observed
    /// by one plane are two boundaries crossed, and a provenance set that
    /// collapsed them would say a value came from *an* observed agent rather
    /// than from the one an investigator is asking about.
    #[must_use]
    pub fn source(&self) -> crate::core::SourceId {
        crate::core::SourceId::new(format!("observed:{}", self.id))
    }

    /// The run this session's records are being written into.
    ///
    /// An `audit` or an `export` is asked for runs by id, and this is the id an
    /// observed session answers to.
    #[must_use]
    pub const fn run(&self) -> RunId {
        self.run
    }

    /// Record one thing the observed party reported.
    ///
    /// `detail` is their own words — the instruction a user typed, a tool's
    /// title, the sentence a person was shown — and this labels them for the
    /// caller rather than taking a label on trust. There is exactly one honest
    /// answer: the value crossed a trust boundary from the observed session,
    /// and [`source`](Self::source) is what it is named. A caller handing in a
    /// `Tainted` could hand in a trusted one, and a sealed record carrying the
    /// observed party's prose under this plane's own label is the laundering
    /// this whole module is arranged to prevent.
    ///
    /// # Errors
    ///
    /// If the journal cannot be written. A step that cannot be recorded is not
    /// swallowed: an observation log missing its middle is worse than one that
    /// says it stopped.
    pub async fn step(
        &mut self,
        step: ObservedStep,
        detail: Option<String>,
    ) -> Result<(), RuntimeError> {
        let mut entry = Append::new(
            self.run,
            RecordKind::Observed {
                session: self.id.clone(),
                reported: step,
                // Labelled here, from the one source it can have had.
                detail: detail.map(|d| Tainted::from_source(d, self.source()).peek().clone()),
            },
        );
        if let Some(case) = self.case {
            entry = entry.case(case);
        }
        self.store
            .append(OBSERVED_EPOCH, vec![entry])
            .await
            .map_err(RuntimeError::from_store)?;
        self.steps += 1;
        Ok(())
    }

    /// Close the record, sealing it into the Merkle log.
    ///
    /// A session that recorded nothing seals nothing: there is no run to close,
    /// and a leaf per empty session is a log of nothings where the somethings
    /// hide.
    ///
    /// The conclusion carries no reason. The session ended because the party
    /// running it ended it, and this plane is in no position to say why —
    /// inventing one would be the empty-summary failure in its other direction.
    ///
    /// # Errors
    ///
    /// If the chain head cannot be read or the conclusion cannot be appended.
    pub async fn seal(self) -> Result<Option<RunId>, RuntimeError> {
        if self.steps == 0 {
            return Ok(None);
        }
        // The conclusion goes *in* the chain before the chain closes over it,
        // exactly as an ordinary run's does: tamper evidence has to cover how
        // the record ended.
        let head = self
            .store
            .head(self.run)
            .await
            .map_err(RuntimeError::from_store)?;
        let mut sealed = Append::new(
            self.run,
            RecordKind::RunConcluded {
                outcome: crate::runtime::OBSERVED_OUTCOME.to_owned(),
                reason: None,
                exhaustion: None,
                live_spend: crate::core::Spend::default(),
                chain_head: head.hash,
            },
        );
        if let Some(case) = self.case {
            sealed = sealed.case(case);
        }
        self.store
            .append(OBSERVED_EPOCH, vec![sealed])
            .await
            .map_err(RuntimeError::from_store)?;
        self.store
            .seal(self.run, OBSERVED_EPOCH, crate::runtime::OBSERVED_OUTCOME)
            .await
            .map_err(RuntimeError::from_store)?;
        Ok(Some(self.run))
    }
}
