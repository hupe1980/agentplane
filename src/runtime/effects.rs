//! Built-in effects.
//!
//! These are the runtime's own drivers — the small set of non-deterministic
//! things it needs before any tool or model exists. Each is journaled like any
//! other effect, which is why a replayed run sees the instant the original run
//! saw rather than the instant now.

use async_trait::async_trait;
use serde_json::json;

use crate::core::{Effect, EffectDescriptor, EffectError, Recovery, Sensitivity, Timestamp};

/// Reads the wall clock.
///
/// Non-mutating and freely retryable: re-reading a clock after a crash is
/// harmless, which is why this is one of the few effects that does not need an
/// operator when its outcome is unknown.
#[derive(Debug, Clone, Copy)]
pub struct Clock;

#[async_trait]
impl Effect for Clock {
    /// Trusted: does not cross a trust boundary.
    ///
    /// The journaled clock. The instant comes from the runtime and is written
    /// to the journal, so it is the runtime's own data rather than the world's —
    /// and a timestamp that arrived untrusted could not be used for the deadline
    /// arithmetic it exists for.
    fn trust(&self) -> crate::core::Trust {
        crate::core::Trust::Trusted
    }

    type Output = Timestamp;

    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::nullary("clock.now")
    }

    fn mutates(&self) -> bool {
        false
    }

    fn recovery(&self) -> Recovery {
        Recovery::Retry
    }

    fn max_sensitivity(&self) -> Sensitivity {
        Sensitivity::Public
    }

    // The single legitimate ambient clock read in the crate: its result is
    // written to the journal as `EffectDone`, so every later replay reads that
    // record instead of calling this again.
    #[allow(clippy::disallowed_methods)]
    async fn perform(&self) -> Result<Timestamp, EffectError> {
        Ok(Timestamp::now_utc())
    }
}

/// A test/demo effect that records an externally visible action.
///
/// Counts its own invocations so tests can assert the property the whole design
/// exists for: **replay does not perform it again**.
#[derive(Debug, Clone)]
pub struct Recorded {
    pub name: String,
    pub payload: serde_json::Value,
    pub calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    pub mutates: bool,
    pub max_sensitivity: Sensitivity,
}

impl Recorded {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            payload: json!(null),
            calls: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            mutates: true,
            max_sensitivity: Sensitivity::Secret,
        }
    }

    #[must_use]
    pub fn counter(mut self, c: std::sync::Arc<std::sync::atomic::AtomicUsize>) -> Self {
        self.calls = c;
        self
    }

    #[must_use]
    pub fn payload(mut self, v: serde_json::Value) -> Self {
        self.payload = v;
        self
    }

    #[must_use]
    pub fn ceiling(mut self, s: Sensitivity) -> Self {
        self.max_sensitivity = s;
        self
    }

    #[must_use]
    pub fn read_only(mut self) -> Self {
        self.mutates = false;
        self
    }
}

#[async_trait]
impl Effect for Recorded {
    /// Trusted: does not cross a trust boundary.
    ///
    /// A value the runtime recorded for itself. Its trust is whatever the
    /// original source's was, carried separately; this wrapper adds none.
    fn trust(&self) -> crate::core::Trust {
        crate::core::Trust::Trusted
    }

    type Output = serde_json::Value;

    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new(format!("test.{}", self.name), self.payload.clone())
    }

    fn mutates(&self) -> bool {
        self.mutates
    }

    fn max_sensitivity(&self) -> Sensitivity {
        self.max_sensitivity
    }

    fn sink_arguments(&self) -> Option<&serde_json::Value> {
        Some(&self.payload)
    }

    fn recovery(&self) -> Recovery {
        Recovery::Retry
    }

    async fn perform(&self) -> Result<serde_json::Value, EffectError> {
        let n = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(json!({ "call": n, "payload": self.payload }))
    }
}

/// Resolves a deadline description to an instant via the configured calendar.
///
/// This is an effect, not a plain function call, for one reason: the answer
/// depends on a calendar whose rules change over time. Journaling the resolved
/// instant means a corrected holiday table or a new regulatory notice cannot
/// retroactively move an obligation that was already registered — the instant
/// is a recorded fact, and the calendar digest beside it says which ruleset
/// produced it.
#[derive(Debug, Clone)]
pub struct ResolveDeadline {
    pub(crate) calendar: std::sync::Arc<dyn crate::core::Calendar>,
    pub(crate) name: String,
    pub(crate) from: Timestamp,
    pub(crate) spec: crate::core::DeadlineSpec,
}

/// What a calendar produced, and which ruleset produced it.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ResolvedDeadline {
    #[serde(with = "time::serde::rfc3339")]
    pub at: Timestamp,
    pub calendar_digest: crate::core::Digest,
}

#[async_trait]
impl Effect for ResolveDeadline {
    /// Trusted: does not cross a trust boundary.
    ///
    /// A `Calendar` is configured by the operator, not supplied by the
    /// world. Its answer is an instant the deployment chose the rules for.
    fn trust(&self) -> crate::core::Trust {
        crate::core::Trust::Trusted
    }

    type Output = ResolvedDeadline;

    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new(
            "deadline.resolve",
            json!({
                "name": self.name,
                "spec": self.spec,
                // `from` is part of the identity: the same rule anchored at a
                // different instant is a different obligation.
                "from": self.from.unix_timestamp(),
            }),
        )
    }

    fn mutates(&self) -> bool {
        false
    }

    fn recovery(&self) -> Recovery {
        Recovery::Retry
    }

    async fn perform(&self) -> Result<ResolvedDeadline, EffectError> {
        let at = self
            .calendar
            .resolve(self.from, &self.spec)
            .map_err(|e| EffectError::Rejected(e.to_string()))?;

        // Truncate to whole seconds, deliberately and once.
        //
        // A deadline is a wall-clock instant; sub-second precision in a
        // regulatory window is noise. More importantly, the instant is recorded
        // in two places — the journal and the case store — and if they disagree
        // by a fraction of a second then "which one is the obligation?" has two
        // answers. Truncating here means they cannot drift.
        let at = at
            .replace_nanosecond(0)
            .map_err(|e| EffectError::Rejected(format!("deadline instant out of range: {e}")))?;

        Ok(ResolvedDeadline {
            at,
            calendar_digest: self.calendar.digest(),
        })
    }
}

/// Reading a case's state.
///
/// **A journaled effect, and it has to be.** Case state is mutable storage
/// shared by every run correlated to the case; reading it is exactly as
/// non-deterministic as reading a clock. Before this was an effect, a strict
/// replay re-read the *current* state and the run's own logic reached a
/// different answer from the same journal — the divergence the whole design
/// exists to make impossible.
#[derive(Debug, Clone)]
pub struct ReadCaseState {
    pub(crate) cases: std::sync::Arc<dyn crate::case::CaseStore>,
    pub(crate) case: crate::core::CaseId,
}

/// A case's state, and the revision it was read at.
///
/// The version travels with the value because a write has to name it. Handing
/// back the value alone is what makes a lost update easy to write.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CaseSnapshot {
    pub state: serde_json::Value,
    pub version: crate::core::CaseVersion,
}

#[async_trait]
impl Effect for ReadCaseState {
    type Output = CaseSnapshot;

    /// Trusted: the plane's own storage, not the world's.
    ///
    /// The *contents* may well have come from an untrusted source, and the
    /// caller receives them labeled accordingly — but the store itself is not a
    /// trust boundary the way a tool or a peer is.
    fn trust(&self) -> crate::core::Trust {
        crate::core::Trust::Trusted
    }

    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new("case.read_state", json!({ "case": self.case.to_string() }))
    }

    fn mutates(&self) -> bool {
        false
    }

    fn recovery(&self) -> Recovery {
        Recovery::Retry
    }

    async fn perform(&self) -> Result<CaseSnapshot, EffectError> {
        let case = self
            .cases
            .case(self.case)
            .await
            .map_err(|e| EffectError::Other(e.to_string()))?
            .ok_or_else(|| EffectError::Rejected(format!("no case {}", self.case)))?;
        Ok(CaseSnapshot {
            state: case.state,
            version: case.version,
        })
    }
}

/// Writing a case's state, if it has not moved.
///
/// Journaled for two reasons that are usually the same reason: replay must not
/// perform it again, and the *outcome* — the new version — is something the run
/// goes on to use. A replay that re-derived the version by writing again would
/// be writing again.
#[derive(Debug, Clone)]
pub struct WriteCaseState {
    pub(crate) cases: std::sync::Arc<dyn crate::case::CaseStore>,
    pub(crate) case: crate::core::CaseId,
    pub(crate) expected: crate::core::CaseVersion,
    pub(crate) state: serde_json::Value,
}

#[async_trait]
impl Effect for WriteCaseState {
    type Output = crate::core::CaseVersion;

    fn trust(&self) -> crate::core::Trust {
        crate::core::Trust::Trusted
    }

    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new(
            "case.write_state",
            json!({
                "case": self.case.to_string(),
                // Both in the key: writing different bytes is a different
                // effect, and so is writing the same bytes against a different
                // revision — the second one is a different claim about what the
                // case said when the decision was made.
                "expected": self.expected.0,
                "state": self.state,
            }),
        )
    }

    /// It changes state other runs can observe. That is what mutating means.
    fn mutates(&self) -> bool {
        true
    }

    /// Not retryable, and the version is why.
    ///
    /// A retry re-sends the same `expected`. If the first attempt landed, the
    /// case has already moved past it and the retry fails as a conflict — a
    /// confusing report of a write that in fact succeeded. Whether it landed is
    /// exactly what the effect protocol is for.
    fn recovery(&self) -> Recovery {
        Recovery::Reconcile
    }

    async fn perform(&self) -> Result<crate::core::CaseVersion, EffectError> {
        self.cases
            .put_state(self.case, self.expected, self.state.clone())
            .await
            .map_err(|e| match e {
                // A conflict is a decision the caller has to make again, not a
                // transport failure. `Rejected` so it does not read as in-doubt.
                crate::core::StoreError::CaseConflict { .. } => {
                    EffectError::Rejected(e.to_string())
                }
                other => EffectError::Other(other.to_string()),
            })
    }
}

/// Recalling memories, as an effect.
///
/// Journaled because memory is mutable state outside the chain: a lookup done
/// inside the deterministic zone would make a replayed run retrieve whatever the
/// store holds *now*, reach different conclusions, and produce a history that
/// disagrees with itself.
///
/// The output is the **selection** — ids, versions and content digests — and not
/// the content. Two reasons, and both matter. Personal data must not enter a
/// hash chain that cannot be redacted; and pinning versions means a replay
/// re-materialises exactly what was read rather than re-running a ranking that
/// drifts as the corpus grows.
#[derive(Debug, Clone)]
pub struct RecallMemory {
    pub(crate) memories: std::sync::Arc<dyn crate::memory::MemoryStore>,
    pub(crate) query: crate::memory::Recall,
}

#[async_trait]
impl Effect for RecallMemory {
    type Output = Vec<crate::memory::Selected>;

    /// Trusted: this plane's own store, not the world's.
    ///
    /// The *contents* are another matter entirely, and the caller receives them
    /// labelled from each item's declared provenance — see
    /// [`StepCtx::recall`](crate::runtime::StepCtx::recall).
    fn trust(&self) -> crate::core::Trust {
        crate::core::Trust::Trusted
    }

    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new(
            "memory.recall",
            serde_json::to_value(&self.query).unwrap_or(json!(null)),
        )
    }

    fn mutates(&self) -> bool {
        false
    }

    fn recovery(&self) -> Recovery {
        Recovery::Retry
    }

    async fn perform(&self) -> Result<Self::Output, EffectError> {
        let found = self
            .memories
            .recall(&self.query)
            .await
            .map_err(|e| EffectError::Other(e.to_string()))?;
        Ok(found
            .iter()
            .map(|item| crate::memory::Selected {
                id: item.id.clone(),
                version: item.version,
                digest: item.selection_digest(),
            })
            .collect())
    }
}

/// Writing a memory, as an effect.
///
/// A write is external mutable state, so a replay that performed it again would
/// append a second version of a memory the run wrote once — and the version
/// number the run went on to use would be wrong.
#[derive(Debug, Clone)]
pub struct RememberMemory {
    pub(crate) memories: std::sync::Arc<dyn crate::memory::MemoryStore>,
    pub(crate) item: crate::memory::MemoryItem,
}

#[async_trait]
impl Effect for RememberMemory {
    type Output = u64;

    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new(
            "memory.remember",
            json!({
                "id": self.item.id,
                "subject": self.item.subject,
                "purpose": self.item.purpose,
                "provenance": self.item.provenance,
                "sensitivity": self.item.sensitivity,
                "trust": self.item.trust,
                "created_at": self.item.created_at,
                "derived_from": self.item.derived_from,
                // The content's digest, not the content: an effect key is
                // recorded verbatim, and a memory's content belongs in a store
                // that can be erased.
                "content": self.item.digest().to_hex(),
            }),
        )
    }

    async fn perform(&self) -> Result<u64, EffectError> {
        self.memories
            .remember(&self.item)
            .await
            .map_err(|e| EffectError::Other(e.to_string()))
    }
}

/// Changing a case's status, as an effect.
///
/// # Why this is not a plain store call
///
/// A case's status is shared mutable state that outlives the run: several runs
/// and an operator all write it over months. A write performed outside the
/// journal has two holes, and the second one is worse.
///
/// It is performed **again on every replay**. Replaying last quarter's history
/// to answer a question would close a case that has since been reopened — a
/// replay is supposed to read history, not rewrite the world it happened in.
///
/// And it leaves **no record**. *Who closed this case, and when* is exactly the
/// question the journal exists to answer, and a status that changed without one
/// is a change nobody can attribute.
#[derive(Debug, Clone)]
pub struct SetCaseStatus {
    pub(crate) cases: std::sync::Arc<dyn crate::case::CaseStore>,
    pub(crate) case: crate::core::CaseId,
    pub(crate) status: crate::core::CaseStatus,
}

#[async_trait]
impl Effect for SetCaseStatus {
    type Output = ();

    /// The runtime's own write against a store it owns. Nothing crosses a trust
    /// boundary, and the value is `()`.
    fn trust(&self) -> crate::core::Trust {
        crate::core::Trust::Trusted
    }

    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new(
            "case.set_status",
            json!({ "case": self.case.to_string(), "status": self.status }),
        )
    }

    /// It changes state other runs observe.
    fn mutates(&self) -> bool {
        true
    }

    /// Setting a status is idempotent in the value: the second write of
    /// `Closed` leaves the case exactly as the first did. So a repeat is safe,
    /// unlike a versioned state write where the retry would report a conflict
    /// for a write that in fact succeeded.
    fn recovery(&self) -> Recovery {
        Recovery::Retry
    }

    async fn perform(&self) -> Result<(), EffectError> {
        self.cases
            .set_status(self.case, self.status)
            .await
            .map_err(|e| EffectError::Other(e.to_string()))
    }
}

/// Moving a deadline out of `Pending`, as an effect.
///
/// Same reasoning as [`SetCaseStatus`], plus one of its own: the transition was
/// previously written to the store and *then* journaled, so a crash in between
/// left an obligation marked met with nothing saying who met it. Announce
/// before act is the rule, and it was inverted here.
#[derive(Debug, Clone)]
pub struct TransitionDeadline {
    pub(crate) cases: std::sync::Arc<dyn crate::case::CaseStore>,
    pub(crate) case: crate::core::CaseId,
    pub(crate) name: String,
    pub(crate) to: crate::core::DeadlineState,
}

#[async_trait]
impl Effect for TransitionDeadline {
    /// The state it was in before, so the record can say what changed rather
    /// than only what it became.
    type Output = crate::core::DeadlineState;

    fn trust(&self) -> crate::core::Trust {
        crate::core::Trust::Trusted
    }

    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new(
            "case.transition_deadline",
            json!({
                "case": self.case.to_string(),
                "name": self.name,
                "to": self.to,
            }),
        )
    }

    fn mutates(&self) -> bool {
        true
    }

    /// Idempotent in the value, as above.
    fn recovery(&self) -> Recovery {
        Recovery::Retry
    }

    async fn perform(&self) -> Result<crate::core::DeadlineState, EffectError> {
        let before = self
            .cases
            .deadlines(self.case)
            .await
            .map_err(|e| EffectError::Other(e.to_string()))?
            .into_iter()
            .find(|d| d.name == self.name)
            .map_or(crate::core::DeadlineState::Pending, |d| d.state);

        self.cases
            .set_deadline_state(self.case, &self.name, self.to)
            .await
            .map_err(|e| EffectError::Other(e.to_string()))?;
        Ok(before)
    }
}
