//! Journal records and the hash chain.
//!
//! # The wire-bytes rule
//!
//! A record is hashed over the exact bytes that were written, and those bytes
//! are what the store keeps. Verification never re-serializes, and *upcasting an
//! old record to a new shape never changes its hash*.
//!
//! This is subtle and load-bearing. If the chain were computed over the upcast
//! form, then the first time a record schema changed, every historical hash
//! would change with it — silently destroying tamper evidence for all past
//! records, which is precisely the property the chain exists to provide.
//! Upcasting is a read-time view; the chain is over history as written.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::core::{
    AttestError, Attestation, CaseId, Compensation, DeadlineState, Digest, Disposition,
    EffectDescriptor, EffectKey, Epoch, Label, Phase, PolicyBundleIdentity, Principal, Recovery,
    RunId, Seq, Signer, Spend, StepId, StoreError, Timestamp, Verifier, canon,
};

/// Which declaration governed a run.
///
/// Name and version say *what to look for*; the digest says *what it said*. Only
/// the last of those survives the file being edited, which is why all three are
/// recorded rather than a reference that has to be resolved against a registry
/// that may no longer hold that version — or may be the compromised party.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentIdentity {
    /// `metadata.name` from the manifest.
    pub name: String,
    /// `metadata.version` from the manifest.
    pub version: String,
    /// The digest over the manifest's canonical bytes.
    pub digest: Digest,
    /// Who vouched for this declaration, when it came from a verified registry
    /// resolution rather than a parsed file.
    ///
    /// The stable, unforgeable grouping. A workload identity is per-instance and
    /// a digest names one revision, so neither is what a rule about *a set of
    /// agents* wants; a name or role is a string the manifest author typed.
    /// `None` means nobody vouched — which is a fact worth recording, not a
    /// blank to be read as "trusted".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher: Option<crate::core::KeyId>,
}

/// The typed view of a record's `(kind, version, payload)`.
///
/// Serialized as an internally-tagged enum so the payload stays inspectable in
/// the database and in an audit export without this crate present.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "PascalCase", deny_unknown_fields)]
#[non_exhaustive]
pub enum RecordKind {
    /// A run was admitted: identity bound, budget reserved, input labeled.
    RunAdmitted {
        /// The capability this run was asked for.
        ///
        /// Named for what it is. It held the plan's first capability under the
        /// field name `agent`, which read as an identity and was not one — the
        /// stringly-typed mistake, in the one record where "who did this" is the
        /// question being asked.
        capability: String,
        /// Which declared agent governed this run, if a declared one did.
        ///
        /// `None` means the run was served by a skill registered directly on the
        /// plane, with no manifest — a legitimate shape, and worth telling apart
        /// from a governed run rather than leaving both blank.
        ///
        /// This is what makes *"which declaration governed this run"* answerable
        /// from the journal years later. The digest is the load-bearing part:
        /// a name and version identify a file that may since have been edited,
        /// and only the digest pins what it actually said — including the system
        /// prompt, which is inside it.
        ///
        /// Boxed for the enum's sake, invisibly to the wire: this variant is
        /// one of the largest in the journal's vocabulary, and every record
        /// in every run pays its size in memory whether admitted or not.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        governed_by: Option<Box<AgentIdentity>>,
        input: Value,
        /// What the input's label was at admission.
        ///
        /// Journaled because a replay must reproduce it. Recomputing would give
        /// whatever today's caller would have said, so a run started from a
        /// specialist's untrusted answer would replay as trusted and every taint
        /// gate downstream would reach a different verdict than the live run.
        ///
        /// Required rather than defaulted: a missing label read as *trusted* is
        /// the failure this field exists to remove.
        input_label: crate::core::Label,
        /// Which complete policy bundle governed this run, if any.
        ///
        /// `None` means no engine was configured — a fact worth recording,
        /// because "was policy switched on for this run" should be answerable
        /// from the journal years later rather than from someone's memory of how
        /// the deployment was wired. Journaled once here rather than per
        /// decision: this is an audit question, not a replay one.
        ///
        /// Boxed as `governed_by` is, for the same reason.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        policy_bundle: Option<Box<PolicyBundleIdentity>>,
        /// Which canonicalization rule produced this run's derived digests.
        ///
        /// Journaled once, here, because it is a property of the whole run and
        /// replay needs it before it recomputes anything. Deliberately
        /// **required**: a record without it is malformed, because reading
        /// absence as "today's rule" is the one wrong answer available.
        ///
        /// See [`canon::VERSION`](crate::core::canon::VERSION) for what the
        /// distinction buys — a run under another rule is *unverifiable*, not
        /// *divergent*, and reporting the second for the first quarantines
        /// healthy history.
        canon: u16,
        /// The admission key this run claimed, if it was admitted idempotently.
        ///
        /// The **claim itself**, not a copy of one: the store derives its
        /// `(tenant, key)` uniqueness index from this field inside `append`, so
        /// the key is taken exactly when the run becomes real. A ledger written
        /// before the append could instead strand the key over a run that never
        /// existed.
        ///
        /// `None` for an ordinary admission. The key must carry its producer —
        /// see [`InboundEvent::dedup_key`](crate::core::InboundEvent::dedup_key).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        idempotency_key: Option<String>,
    },

    /// A live execution pass began under this record body's fencing epoch.
    ///
    /// Written before any effect the pass may dispatch. `period` is captured
    /// once so recovery never moves spend across a billing boundary; `release_slot`
    /// distinguishes fresh admission from a resume, which is deliberately not
    /// gated by the concurrency ceiling.
    QuotaPassStarted {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        period: Option<String>,
        release_slot: bool,
    },

    /// The plan was compiled from trusted input and frozen.
    ///
    /// From here the plan is an authorization graph: the journal that follows
    /// can be checked against it, down to per-argument provenance.
    PlanFrozen {
        /// Capability per step, for readability in a log listing.
        steps: Vec<String>,
        /// The plan itself, so replay reads it back rather than recompiling.
        ///
        /// Recompiling could produce a different graph — a changed manifest, a
        /// different router — and replay would then verify the run against a
        /// plan that never governed it. The plan is content-addressed, so its
        /// digest is `plan.digest()` recomputed on demand rather than a second
        /// copy stored beside it that a future writer could let disagree.
        plan: Value,
    },

    StepStarted {
        skill: String,
    },
    StepFinished {
        outcome: String,
    },

    /// A run was correlated to a case — either joining an existing one or
    /// opening a new one.
    ///
    /// The case id itself lives in [`RecordBody::case`], which every record in a
    /// case-bound run carries — so the case's whole history is one indexed
    /// range scan, and this variant carries only what is specific to the
    /// binding event.
    ///
    /// Field names here must avoid `kind` (the enum's own serde tag) and `case`
    /// (the body's field), because this variant is flattened into the body and
    /// either collision would silently corrupt the wire format.
    CaseBound {
        case_kind: String,
        opened: bool,
        /// The case's business keys **as they stood when this run bound to it**.
        ///
        /// Recorded rather than looked up, for the reason the case binding
        /// itself is: a resume re-reads history instead of re-correlating,
        /// because a case accumulates keys over months and a later message can
        /// add one. A run that resolved its memory subject from
        /// `$correlation/meter` would otherwise resolve it against a *different*
        /// set on resume, write a second memory under a second subject, and
        /// diverge from its own journal with nothing on the record saying why.
        ///
        /// `#[serde(default)]` because a journal written before bindings existed
        /// has no such field. An empty list is honest there and fails loudly at
        /// the one thing that reads it — resolving a binding — rather than
        /// resolving to something plausible.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        correlation: Vec<crate::core::CorrelationKey>,
    },

    /// An obligation was registered with a **resolved instant**.
    ///
    /// The instant is recorded, not the rule that produced it. Calendars change
    /// — a corrected holiday table, a new regulatory notice — and recomputing on
    /// replay would silently move a legally binding deadline under an audit. The
    /// `calendar_digest` says which ruleset produced this instant, so a changed
    /// rule is visible rather than retroactive.
    DeadlineRegistered {
        name: String,
        #[serde(with = "time::serde::rfc3339")]
        resolved_at: Timestamp,
        calendar_digest: Digest,
    },

    /// An obligation changed state: met, breached, warned, or cancelled.
    DeadlineTransition {
        name: String,
        from: DeadlineState,
        to: DeadlineState,
    },

    /// A run registered interest in a future event and stopped.
    ///
    /// Written **before** the frame is released, so an event arriving in the
    /// same instant finds a durable subscription rather than a gap.
    RunSuspended {
        reason: crate::core::SuspendReason,
    },

    /// Structured reasoning, recorded adjacent to the effects it explains.
    ///
    /// Adjacency is the point. A note sitting next to the action it claims to
    /// justify makes reasoning-versus-action mismatch detectable after the fact
    /// and testable under replay — which a summary written at the end of a run
    /// cannot do.
    Note {
        text: String,
    },

    /// Written **before** the effect is performed. An `EffectStarted` with no
    /// matching terminal record means a crash left the outcome unknown, and the
    /// declared [`Recovery`] decides what happens next — the runtime never
    /// guesses.
    EffectStarted {
        descriptor: EffectDescriptor,
        recovery: Recovery,
        mutates: bool,
        /// Which attempt this is, 1-based.
        ///
        /// Also part of the effect key, so attempts do not collide. Recorded
        /// here as well because reading "attempt 3, after 400ms" off a record
        /// beats recomputing hashes to work out how a run reached its fourth
        /// call to the same endpoint.
        attempt: u32,
        /// How long the runtime waited before this attempt, in milliseconds.
        /// Zero on the first.
        backoff_ms: u64,
        /// The label of the value this effect will send, when it binds one.
        ///
        /// Recorded because **authorization consults it**, and a decision whose
        /// inputs are not on the record cannot be re-derived by anyone who was
        /// not there. Policy is total and side-effect free, so an auditor
        /// holding the bundle identity, the descriptor and this can reach the
        /// same verdict offline — and without it they must take the runtime's
        /// word that the right label was presented.
        ///
        /// Absent for `cx.effect`, which binds no value and presents none, so
        /// the ordinary case costs no bytes and hashes identically.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        outbound_label: Option<Label>,
    },

    EffectDone {
        output: Value,
        /// Who sent it, when this effect was an awaited inbound event.
        ///
        /// Journaled because the label must be reproducible: a replayed run
        /// rebuilds the awaited value's provenance from this record, and a
        /// source known only to the live delivery would give the two runs
        /// different labels — divergence at every taint gate downstream.
        ///
        /// Absent for every other effect, and absent on records written before
        /// this existed. Absence fails *closed*: the label simply lacks that
        /// provenance, so a field requiring it is refused rather than admitted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source: Option<String>,
        /// What this effect consumed.
        ///
        /// Recorded so replay adds up the same figures the original run did,
        /// and reaches the same budget verdict at the same point.
        #[serde(default, skip_serializing_if = "Spend::is_free_ref")]
        spend: Spend,
        /// The trust and sensitivity this effect declared for its own output.
        ///
        /// Required rather than defaulted, for the same reason
        /// [`RunAdmitted`](Self::RunAdmitted)'s input label is: both halves of a
        /// missing answer here read as *more permissive than the truth*, and a
        /// value silently relabelled trusted or public is the one failure this
        /// field exists to prevent. See
        /// [`DeclaredOutput`](crate::core::DeclaredOutput) for why re-reading
        /// the effect is not equivalent.
        declared: crate::core::DeclaredOutput,
    },
    EffectFailed {
        error: String,
        /// What the attempt consumed before it failed.
        ///
        /// Usually nothing. Not nothing for a metered call that died partway —
        /// a model stream bills for what it generated — and recording it is what
        /// makes a replayed run reach the same budget verdict at the same point.
        #[serde(default, skip_serializing_if = "Spend::is_free_ref")]
        spend: Spend,
        /// What the failure says about whether the call reached the outside
        /// world.
        ///
        /// On the record because it is the input to every later decision — the
        /// retry taken at the time, and any operator judgement afterwards. A
        /// message can be reworded; a disposition is a fact about the run.
        disposition: Disposition,
        /// Whether the refusal is an **answer** rather than a fault — the peer
        /// understood the request and said no, so no retry can change it.
        ///
        /// On the record for the same reason the disposition is: the retry
        /// decision is recomputed on replay, and a replay that could not see
        /// this bit would expect a retry the live run never made and report
        /// divergence over a faithful history. Skipped when false, so the
        /// ordinary failure costs no bytes and no hash input.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        permanent: bool,
    },

    /// A limit refused an operation before it started.
    ///
    /// Written **at the moment of refusal**, because the verdict is history: a
    /// run that stopped here stopped here, whatever budget is in force when it
    /// is replayed. Without this record a replayed run reaches the same point,
    /// finds no history, and reports that the *build* performs more effects
    /// than the record — sending an operator to look for a code change that
    /// does not exist.
    ///
    /// Carries an effect key when a specific operation was refused, and only a
    /// step when the step itself was never admitted.
    BudgetRefused {
        /// Which limit, in the words the operator will act on.
        limit: String,
        /// Where consumption actually reached. "Budget exhausted" alone does
        /// not tell anyone what to raise it to.
        used: String,
    },

    /// A step the recorded run was refused on was admitted again, under the
    /// ceilings in force at resume.
    ///
    /// Exhaustion is a pause, not a fault: an operator raises the ceiling and
    /// resumes. The resume re-evaluates the recorded step refusal against the
    /// ledger now in force, and when it admits, *that decision* is a fact
    /// about the run and goes on the record — beside the refusal it
    /// supersedes, never instead of it. Without this record a strict replay of
    /// the resumed history stops at the old refusal and reports `Exhausted`
    /// about a run whose own later records show it finishing: the refusal
    /// followed by the continuation would read as divergence.
    ///
    /// Carries the step in the record body, like the refusal it answers.
    BudgetReadmitted {
        /// The ceiling the step was admitted under, in the operator's words —
        /// so "who raised what to let this continue" is answerable from the
        /// chain.
        limit: String,
    },

    /// The delegation chain this run acts under, owner first.
    ///
    /// Recorded once, at admission, because "on whose behalf" is the question a
    /// log line cannot answer and an auditor always asks. Recorded rather than
    /// re-derived because credentials expire: re-verifying during replay would
    /// fail an audit of a decision that was perfectly sound when it was made.
    ///
    /// Absent entirely when no chain was supplied — an absent delegation must
    /// not be spelled the same way as an unrestricted one.
    IdentityBound {
        chain: Vec<Principal>,
    },

    /// Policy refused an effect before it was attempted.
    ///
    /// The twin of [`RecordKind::BudgetRefused`], and it exists for the same
    /// reason: a refusal is a place the run *stopped*, and a stop with no record
    /// replays as "this build performs more effects than the recorded one",
    /// sending an operator to look for a code change that does not exist.
    ///
    /// A *permit* gets no record. The effect's own `EffectStarted` is already
    /// the evidence that it was allowed, and journaling "yes" beside every call
    /// doubles the log to say nothing.
    PolicyDenied {
        /// Why, in the words an operator will act on. Never just "denied".
        reason: String,
        /// The action and resource that were refused, so the record is readable
        /// without reconstructing the request from the effect beside it.
        action: String,
        resource: String,
    },

    /// A set of effects that must take together was opened.
    ///
    /// Brackets the members the way `StepStarted` brackets a step, and it earns
    /// its place on the crash path: a run that died mid-group otherwise shows a
    /// handful of effects with nothing saying they were one unit. An opened
    /// group with no [`GroupSettled`](Self::GroupSettled) beside it is the query
    /// an operator runs to find work that was neither taken nor taken back.
    GroupOpened {
        group: String,
        /// What the group declared it may touch. Every member is checked
        /// against this, so the record is the footprint that was enforced
        /// rather than one that was described.
        resources: Vec<String>,
    },

    /// How a group ended.
    ///
    /// `detail` carries the failing invariant, the reversal that would not
    /// come back, or the reason an abort was asked for — the sentence whoever
    /// picks up the escalation needs, rather than a status they have to
    /// reconstruct the meaning of.
    GroupSettled {
        group: String,
        outcome: crate::core::GroupOutcome,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },

    /// A person answered a quarantine.
    ///
    /// The runtime's most serious conclusion is the one it cannot reach by
    /// itself, and this is the only record that answers it. It sits **in** the
    /// chain rather than beside it, unlike a cancellation request: a stop is
    /// asked for by somebody who is not the run's owner and may be racing a
    /// live executor, whereas a quarantine is answered over a run that has
    /// already stopped, so the answer is history and belongs where history is
    /// kept.
    ///
    /// Written before the decision is acted on, so a crash in between leaves
    /// the instruction standing rather than lost: the next resume finds it and
    /// finishes the job.
    QuarantineDecided {
        /// Who decided. Required, and never derived from a session or a
        /// default — the whole weight of this record is that a named person
        /// took responsibility for a fact the runtime could not establish.
        decider: String,
        /// Why, in the words the next reader needs. What was checked, in which
        /// system, and what it said.
        reason: String,
        decision: crate::core::QuarantineDecision,
    },

    /// A completed step was undone because a later one failed.
    ///
    /// The declaration is on the record as well as the outcome, because "this
    /// step was skipped" and "this step said there was nothing to undo" look
    /// identical in a log and mean very different things to whoever is reading
    /// it six months later.
    StepCompensated {
        compensation: Compensation,
        outcome: String,
    },

    /// An unknown outcome was resolved by asking the provider.
    ///
    /// Written whenever a probe runs, including when it comes back
    /// inconclusive — "we did not know, we asked, and we still do not know" is
    /// exactly what an operator picking up the escalation needs to see, and
    /// leaving it out would make the escalation look like nobody tried.
    EffectReconciled {
        /// What the probe established, in the same vocabulary a failure uses.
        disposition: Disposition,
        /// The recovered result, present only when the probe found it landed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        output: Option<Value>,
        /// What the recovered call consumed. Zero unless the probe recovered a
        /// result to measure.
        #[serde(default, skip_serializing_if = "Spend::is_free_ref")]
        spend: Spend,
        /// What the probe reported, when it failed or could not tell.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
        /// The trust and sensitivity declared for a recovered output.
        ///
        /// Present exactly when `output` is: a probe that recovered nothing
        /// labelled nothing. Recorded for the reason
        /// [`EffectDone`](Self::EffectDone)'s copy is — a recovered result is
        /// still a result, and the path that reaches one must not be the path
        /// where a catalogue edit can rewrite the label.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        declared: Option<crate::core::DeclaredOutput>,
        /// Who established this, when it was not the effect's own probe.
        ///
        /// Absent for a [`reconcile`](crate::core::Effect::reconcile) call: the
        /// effect asked the provider that would know, which is the ordinary
        /// path and is attributed by the run itself. Present when a person
        /// answered out of band, because "the provider told us" and "somebody
        /// asserted it" are different evidence and only one of them can be
        /// confidently wrong about a thing it could not see.
        ///
        /// It is the field that makes an operator's answer auditable rather
        /// than merely effective — without it, a resolution and a probe are
        /// the same record and the question *who decided this run could carry
        /// on* has no answer in the chain.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        asserted_by: Option<String>,
    },

    /// Policy approved a typed label improvement. The record binds the decision
    /// to the exact value digest and prior whole/field labels; the value remains
    /// inside the information-flow lattice. The marks the release attaches are
    /// not restated here — they are determined by `release`, and a second
    /// spelling of one decision is free to drift from the rule that derives it.
    Released {
        releaser: String,
        release: crate::core::Release,
        label: Label,
        field_labels: BTreeMap<String, Label>,
        value: Digest,
    },

    /// An operator's stop request, observed by the run's owner.
    ///
    /// The *request* lives beside the chain, unfenced, so that somebody who does
    /// not hold the lease can make it (see `JournalStore::request_cancel`). This
    /// record is written when the owner acts on it, which is what puts the
    /// asker's name and reason inside the hash chain — an intervention nobody
    /// signed is an outage, not oversight.
    ///
    /// Written at a **step boundary**, never mid-effect: interrupting between
    /// "announced" and "recorded" manufactures the in-doubt case the effect
    /// protocol exists to avoid.
    RunCancelled {
        actor: String,
        reason: String,
    },

    /// The run concluded. The digest is the chain head the conclusion was
    /// drawn over, and the stores derive the outcome index from this record —
    /// last conclusion wins.
    ///
    /// A conclusion is not always a closure. `succeeded`, `quarantined` and
    /// `cancelled` are followed by the seal that freezes the journal and
    /// enters the Merkle log (`RunStatus::seals`); `failed` and `exhausted`
    /// leave the run open, because both may legitimately be resumed — a
    /// resumed run reads its completed effects back from history, appends past
    /// this record, and concludes again. That is why one chain may carry more
    /// than one of these, and why the *last* one is the run's answer.
    RunConcluded {
        outcome: String,
        /// Why the run ended this way, when the ending has a why.
        ///
        /// `None` for a success, which has none. Without it the chain records
        /// *that* a run failed and not *why*, so the reason survives only in
        /// the log of the process that wrote it — and an operator asking six
        /// weeks later, or a redelivery asking which conclusion it is being
        /// answered with, gets the word "failed" and nothing else.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        /// The typed ceiling verdict when `outcome == "exhausted"`.
        ///
        /// A rendered reason is for people, not reconstruction. Without this
        /// value a duplicate admission can only turn an exhausted pause into a
        /// generic failure or parse prose back into control flow. Both are
        /// wrong: exhaustion is resumable and its variant carries the numbers
        /// an operator needs to raise the right ceiling.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exhaustion: Option<crate::core::BudgetExceeded>,
        /// What this execution pass dispatched, excluding its replayed prefix.
        ///
        /// The quota receipt is derived from durable records on recovery. A
        /// conclusion carries the authoritative total because it can include a
        /// provider result this process observed but could not record at the
        /// effect's terminal record before a later append recovered.
        #[serde(default, skip_serializing_if = "Spend::is_free_ref")]
        live_spend: Spend,
        chain_head: Digest,
    },

    /// An operator deliberately crossed the tenant boundary.
    ///
    /// Every other row in the isolation table keeps a cross-tenant read from
    /// being reached by accident. This is the designed exception, and an exception with no
    /// record is indistinguishable from the breach it is meant to be — so the
    /// access is written into the journal of the tenant whose data was
    /// reached, in a sealed run of its own, **before** any of it is served.
    /// That tenant's own audit therefore shows who crossed, under what
    /// authority, and why, without anyone having to be told that break-glass
    /// exists.
    BreakGlass {
        /// The authenticated operator, from the credential — never a body.
        actor: String,
        /// The roles that credential carried, so an auditor can see which
        /// grant was used rather than only which person.
        roles: Vec<String>,
        /// Why. Refused when blank: an unexplained exception is the thing
        /// this record exists to prevent.
        reason: String,
    },

    /// Something the sweeper did to work nobody was watching.
    ///
    /// The sweeper acts on a clock rather than on a request, so there is no run
    /// whose history explains why a case became `Escalated`. State alone cannot
    /// distinguish *the sweep breached this at 02:00* from *somebody set it*,
    /// and for the plane's most consequential automated decisions that is the
    /// difference between an audit trail and a database.
    ///
    /// Written into a sweep's own sealed run, so it inherits the chain, the
    /// signature and the Merkle inclusion every other record has — and the
    /// external audit tool checks it without being taught anything new.
    Swept {
        /// The case, task or event acted on.
        subject: String,
        action: crate::core::SweptAction,
        /// The obligation's name, the expiry policy applied, the reason an
        /// event aged out — whatever makes the entry readable six months later
        /// without reconstructing it from the state it produced.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },
}

impl RecordKind {
    /// Stable discriminator, stored in an indexed column.
    #[must_use]
    pub fn kind_str(&self) -> &'static str {
        match self {
            Self::RunAdmitted { .. } => "RunAdmitted",
            Self::QuotaPassStarted { .. } => "QuotaPassStarted",
            Self::PlanFrozen { .. } => "PlanFrozen",
            Self::StepStarted { .. } => "StepStarted",
            Self::StepFinished { .. } => "StepFinished",
            Self::Note { .. } => "Note",
            Self::RunSuspended { .. } => "RunSuspended",
            Self::CaseBound { .. } => "CaseBound",
            Self::DeadlineRegistered { .. } => "DeadlineRegistered",
            Self::DeadlineTransition { .. } => "DeadlineTransition",
            Self::EffectStarted { .. } => "EffectStarted",
            Self::EffectDone { .. } => "EffectDone",
            Self::EffectFailed { .. } => "EffectFailed",
            Self::EffectReconciled { .. } => "EffectReconciled",
            Self::StepCompensated { .. } => "StepCompensated",
            Self::QuarantineDecided { .. } => "QuarantineDecided",
            Self::GroupOpened { .. } => "GroupOpened",
            Self::GroupSettled { .. } => "GroupSettled",
            Self::BudgetRefused { .. } => "BudgetRefused",
            Self::BudgetReadmitted { .. } => "BudgetReadmitted",
            Self::IdentityBound { .. } => "IdentityBound",
            Self::PolicyDenied { .. } => "PolicyDenied",
            Self::Released { .. } => "Released",
            Self::RunCancelled { .. } => "RunCancelled",
            Self::RunConcluded { .. } => "RunConcluded",
            Self::BreakGlass { .. } => "BreakGlass",
            Self::Swept { .. } => "Swept",
        }
    }

    /// Current schema version for this kind.
    ///
    /// **1 until the format freeze**, which is the same answer
    /// [`canon::VERSION`](crate::core::canon::VERSION) and
    /// [`export::FORMAT_VERSION`](crate::export::FORMAT_VERSION) give, and for
    /// the same reason: the project is pre-release, every shape change is a
    /// hard cut, and a journal written by an older build is refused rather than
    /// migrated. A number that counted the cuts would suggest those journals are
    /// readable, which is the opposite of the intent.
    ///
    /// After the freeze it becomes an RFC-level change to bump: the journal is
    /// forever, so from then on every version ever written must remain readable
    /// through an [`Upcaster`](super::Upcaster) — which is what that seam
    /// exists for and why it is wired now rather than later.
    #[must_use]
    pub fn version(&self) -> u16 {
        1
    }
}

/// Lift a record written at another shape into the one this build reads.
///
/// Separated from the read path because it is the cold half: it parses the
/// bytes a second time, into an untyped value, so the upcaster sees the record
/// as written rather than as this build's struct happened to receive it.
fn lift(
    upcaster: &dyn super::Upcaster,
    raw: &[u8],
    kind: &str,
    version: u16,
) -> Result<RecordBody, StoreError> {
    let written: Value = serde_json::from_slice(raw)?;
    let lifted = upcaster.upcast(kind, version, written)?;
    serde_json::from_value(lifted).map_err(StoreError::Encoding)
}

/// What the bytes claim to be, without trusting them to be a record.
///
/// Both halves or nothing: a version with no kind names no shape, and a kind
/// with no version is a record from before versions existed, which is not a
/// shape any upcaster is asked to reach. Returning `None` sends the caller back
/// to the parse error, which is the honest answer for bytes that are not a
/// record at all.
fn version_claimed(raw: &[u8]) -> Option<(String, u16)> {
    let value: Value = serde_json::from_slice(raw).ok()?;
    let kind = value.get("kind")?.as_str()?.to_owned();
    let version = u16::try_from(value.get("v")?.as_u64()?).ok()?;
    Some((kind, version))
}

/// The hashed portion of a record.
///
/// Field order here *is* the wire order (serde preserves struct declaration
/// order), and object keys inside `payload` are sorted by `serde_json`. Both are
/// required for the bytes to be canonical.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecordBody {
    pub seq: Seq,
    pub run: RunId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case: Option<CaseId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<StepId>,
    /// Whether this record belongs to the step's forward pass or its
    /// compensating one.
    ///
    /// Skipped when `Forward`, so the overwhelmingly common case costs no
    /// bytes and no hash input — and an existing forward record hashes
    /// identically whether or not compensation exists in the build.
    #[serde(default, skip_serializing_if = "Phase::is_forward_ref")]
    pub phase: Phase,
    pub epoch: Epoch,
    pub v: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect_key: Option<EffectKey>,
    #[serde(flatten)]
    pub kind: RecordKind,
}

/// A sealed journal entry: body, chain links, and the bytes that were hashed.
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    pub body: RecordBody,
    pub prev_hash: Digest,
    pub hash: Digest,
    /// Who wrote it, if the plane was configured to say.
    ///
    /// Beside the hash rather than inside the body, and that placement is
    /// forced: the signature covers the chain hash, so putting it in the body
    /// would make the hash cover the signature that covers the hash.
    ///
    /// `None` is an ordinary state, not a defect — a plane that has not been
    /// given a [`Signer`](crate::core::Signer) writes unsigned records, and
    /// history written before signing was configured stays unsigned forever.
    /// What must never happen is a *verifier* silently accepting that; see
    /// [`Record::verify_attested`].
    pub attestation: Option<Attestation>,
    raw: Vec<u8>,
}

/// What a record attestation is taken over: the chain hash under the record
/// domain.
///
/// A free function rather than two call sites, because signing and verifying
/// must agree byte for byte and the two live 130 lines apart. Signing a labelled
/// digest and verifying a bare one rejects every genuine signature, which is
/// loud; doing it the other way round accepts a signature made for something
/// else, which is not.
///
/// The label matters because the plane's workload key also seals
/// [`Provenance`](crate::core::Provenance) blocks that travel to tool servers
/// and peers. Without it those two signatures are the same shape over the same
/// key, and nothing in either says which question it answered.
fn record_signing_input(hash: Digest) -> Digest {
    crate::core::signing_hash(crate::core::DOMAIN_RECORD, &hash)
}

impl Record {
    /// Serialize canonically and link into the chain.
    pub fn seal(body: RecordBody, prev_hash: Digest) -> Result<Self, StoreError> {
        Self::seal_signed(body, prev_hash, None)
    }

    /// The largest a single journal record may be.
    ///
    /// A megabyte is generous for a record describing an effect and far too
    /// small for an inlined image, which is the intent: media belongs outside a
    /// chain that can never forget it. The number is in the same range the
    /// field settled on — Temporal caps payloads at 2 MB and claim-checks above
    /// 256 KiB — and is deliberately a hard refusal rather than a truncation,
    /// because a silently shortened record is a journal that lies.
    ///
    /// Enforced in [`Record::seal_signed`], which is the one function every
    /// backend seals through, so no store can be added that quietly skips it.
    pub const MAX_RECORD_BYTES: usize = 1 << 20;

    /// Seal, and attest it as the given signer.
    ///
    /// The signature is taken over the chain hash, which already covers
    /// `prev_hash ‖ canonical(body)`. Because the hash chains, this signature
    /// transitively commits to every record before this one — so rewriting any
    /// part of the prefix invalidates every later signature, not just its own.
    pub fn seal_signed(
        body: RecordBody,
        prev_hash: Digest,
        signer: Option<&dyn Signer>,
    ) -> Result<Self, StoreError> {
        let raw = canon::to_bytes(&body)?;
        if raw.len() > Self::MAX_RECORD_BYTES {
            return Err(StoreError::RecordTooLarge {
                bytes: raw.len(),
                limit: Self::MAX_RECORD_BYTES,
            });
        }
        let hash = Digest::chain(prev_hash, &raw);
        Ok(Self {
            body,
            prev_hash,
            hash,
            attestation: signer.map(|s| s.attest(&record_signing_input(hash))),
            raw,
        })
    }

    /// Reconstruct from storage, verifying the link before trusting the content.
    ///
    /// The body is decoded from `raw`; the hash is recomputed from `raw`. A
    /// record whose stored hash disagrees is rejected rather than returned with
    /// a warning — a journal you cannot trust is worse than no journal, because
    /// it produces an audit trail that is quietly a lie.
    pub fn from_stored(raw: Vec<u8>, prev_hash: Digest, hash: Digest) -> Result<Self, StoreError> {
        Self::from_stored_attested(raw, prev_hash, hash, None)
    }

    /// Reconstruct, carrying whatever signature the store kept.
    ///
    /// Reads under the [`Identity`](super::Identity) upcaster — this build's
    /// shapes and no others. A store that carries a real upcaster calls
    /// [`from_stored_with`](Self::from_stored_with) instead.
    pub fn from_stored_attested(
        raw: Vec<u8>,
        prev_hash: Digest,
        hash: Digest,
        attestation: Option<Attestation>,
    ) -> Result<Self, StoreError> {
        Self::from_stored_with(&super::Identity, raw, prev_hash, hash, attestation)
    }

    /// Reconstruct, lifting the record forward if it was written at an older
    /// shape.
    ///
    /// **The version is checked on every read, not only when something looks
    /// wrong.** A record carries `v`, and a reader that writes it and never
    /// reads it back has a version field for decoration: a journal written by a
    /// build one shape ahead parses cleanly here, with the fields this build
    /// has never heard of dropped on the floor, and every decision downstream
    /// is then made over a record nobody fully read. So the version is the
    /// first thing asked about the parsed body, and the answer comes from the
    /// [`Upcaster`](super::Upcaster) rather than from a constant — which is
    /// what makes the seam a live path rather than a declaration waiting for
    /// its first migration to also be its first exercise.
    ///
    /// **The hash stays over the bytes that were written.** An upcast produces
    /// a body this build understands and leaves `raw` and `hash` alone, so
    /// tamper evidence is unaffected by the reader's age — the rule
    /// [`Upcaster`](super::Upcaster) states, enforced here by construction
    /// because the lift happens after the link is verified and never touches
    /// the bytes.
    ///
    /// # Errors
    ///
    /// [`StoreError::Corrupt`] if the stored hash does not cover the bytes,
    /// [`StoreError::UnknownRecordVersion`] if no upcaster can reach this
    /// build's shape from the one on the record, and
    /// [`StoreError::Encoding`] if the bytes are not a record at all.
    pub fn from_stored_with(
        upcaster: &dyn super::Upcaster,
        raw: Vec<u8>,
        prev_hash: Digest,
        hash: Digest,
        attestation: Option<Attestation>,
    ) -> Result<Self, StoreError> {
        let recomputed = Digest::chain(prev_hash, &raw);
        if recomputed != hash {
            let seq = serde_json::from_slice::<serde_json::Map<String, Value>>(&raw)
                .ok()
                .and_then(|m| m.get("seq").and_then(Value::as_u64))
                .unwrap_or(0);
            return Err(StoreError::Corrupt {
                seq,
                detail: format!(
                    "hash mismatch: stored {hash:?}, recomputed {recomputed:?} — \
                     record was altered after it was written"
                ),
            });
        }
        let body = match serde_json::from_slice::<RecordBody>(&raw) {
            // The overwhelming case: one parse, one integer comparison, no
            // allocation. Everything below is the cold path.
            Ok(body) if body.v == upcaster.current_version(body.kind.kind_str()) => body,
            // Parsed, and from another shape. The *raw* value is what the
            // upcaster is handed — the parsed body has already lost whatever
            // this build does not know, and lifting from it would lift a
            // record with the interesting part missing.
            Ok(body) => lift(upcaster, &raw, body.kind.kind_str(), body.v)?,
            // Did not parse. Either it is not a record, or it is one whose
            // shape moved — and those are different answers, so the version is
            // read from the bytes before the parse failure is believed.
            Err(parse) => match version_claimed(&raw) {
                Some((kind, v)) if v != upcaster.current_version(&kind) => {
                    lift(upcaster, &raw, &kind, v)?
                }
                _ => return Err(StoreError::Encoding(parse)),
            },
        };
        Ok(Self {
            body,
            prev_hash,
            hash,
            attestation,
            raw,
        })
    }

    /// The exact bytes covered by [`Self::hash`].
    #[must_use]
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    #[must_use]
    pub fn seq(&self) -> Seq {
        self.body.seq
    }

    #[must_use]
    pub fn kind(&self) -> &RecordKind {
        &self.body.kind
    }

    #[must_use]
    pub fn effect_key(&self) -> Option<EffectKey> {
        self.body.effect_key
    }

    /// The same record with its payload opened — a **read-time view**.
    ///
    /// `raw`, `hash` and `prev_hash` are untouched, so the chain still
    /// verifies over the bytes that were written. This is the move upcasting
    /// already makes: stored bytes are history, the typed body is a view of
    /// them. Swapping a sealed payload for its plaintext therefore cannot
    /// change what any proof commits to.
    #[cfg(feature = "keyring")]
    #[must_use]
    pub(crate) fn with_opened_kind(mut self, kind: RecordKind) -> Self {
        self.body.kind = kind;
        self
    }

    /// Verify a contiguous run of records links correctly.
    ///
    /// Checks both the chain and the sequence: a gap means records were deleted,
    /// which the per-record hash alone would not catch.
    pub fn verify_chain(records: &[Self], from: Digest) -> Result<Digest, StoreError> {
        let mut prev = from;
        let start = records.first().map_or(1, Record::seq);
        for (expect_seq, r) in (start..).zip(records.iter()) {
            if r.seq() != expect_seq {
                return Err(StoreError::Corrupt {
                    seq: r.seq(),
                    detail: format!("sequence gap: expected {expect_seq}, found {}", r.seq()),
                });
            }
            if r.prev_hash != prev {
                return Err(StoreError::Corrupt {
                    seq: r.seq(),
                    detail: "broken link: prev_hash does not match predecessor".into(),
                });
            }
            let recomputed = Digest::chain(prev, &r.raw);
            if recomputed != r.hash {
                return Err(StoreError::Corrupt {
                    seq: r.seq(),
                    detail: "hash does not cover the stored bytes".into(),
                });
            }
            prev = r.hash;
        }
        Ok(prev)
    }

    /// Verify the chain **and** that a known key signed every record.
    ///
    /// Two separate questions, deliberately answered by two separate calls. The
    /// chain says the records are consistent with each other; the signatures say
    /// who wrote them. A caller that only runs [`Self::verify_chain`] is asking
    /// the weaker question, and this crate's own store does exactly that on
    /// every read — because a plane without a configured verifier has no basis
    /// to reject anything, and failing closed there would make signing
    /// impossible to adopt incrementally.
    ///
    /// `require_signature` is what stops that leniency becoming a hole. With it
    /// set, an unsigned record is a failure rather than a shrug — which is the
    /// posture an *auditor* wants, and the opposite of the one a plane resuming
    /// its own history wants.
    ///
    /// # Errors
    ///
    /// [`StoreError::Corrupt`] if the chain is broken, or [`AttestError`] as a
    /// corrupt-record detail if a signature is missing or wrong.
    pub fn verify_attested(
        records: &[Self],
        from: Digest,
        verifier: &dyn Verifier,
        require_signature: bool,
    ) -> Result<Digest, StoreError> {
        let head = Self::verify_chain(records, from)?;
        for r in records {
            match &r.attestation {
                // Under the same domain `seal_signed` signed it. Verifying the
                // bare chain hash here while signing a labelled one there would
                // reject every genuine signature — and getting it backwards, so
                // that a *labelled* signature verified against a bare digest,
                // would silently restore the confusion the label exists to
                // prevent. One helper, called from both, is why neither happens.
                Some(a)
                    if verifier.verify(&a.key_id, &record_signing_input(r.hash), &a.signature) => {}
                Some(a) => {
                    return Err(StoreError::Corrupt {
                        seq: r.seq(),
                        detail: AttestError::BadSignature {
                            seq: r.seq(),
                            key_id: a.key_id.clone(),
                        }
                        .to_string(),
                    });
                }
                None if require_signature => {
                    return Err(StoreError::Corrupt {
                        seq: r.seq(),
                        detail: AttestError::Unsigned { seq: r.seq() }.to_string(),
                    });
                }
                None => {}
            }
        }
        Ok(head)
    }
}

/// What the runtime hands the store. Seq, chain links, and hashing are the
/// store's job, because only it knows the run's current head.
#[derive(Debug, Clone)]
pub struct Append {
    pub run: RunId,
    pub case: Option<CaseId>,
    pub step: Option<StepId>,
    pub phase: Phase,
    pub effect_key: Option<EffectKey>,
    pub kind: RecordKind,
}

impl Append {
    pub fn new(run: RunId, kind: RecordKind) -> Self {
        Self {
            run,
            case: None,
            step: None,
            phase: Phase::Forward,
            effect_key: None,
            kind,
        }
    }

    #[must_use]
    pub fn step(mut self, s: StepId) -> Self {
        self.step = Some(s);
        self
    }

    #[must_use]
    pub fn phase(mut self, p: Phase) -> Self {
        self.phase = p;
        self
    }

    #[must_use]
    pub fn case(mut self, c: CaseId) -> Self {
        self.case = Some(c);
        self
    }

    #[must_use]
    pub fn effect(mut self, k: EffectKey) -> Self {
        self.effect_key = Some(k);
        self
    }

    /// Rebuild the append that produced a body.
    ///
    /// The inverse of the crate-private `into_body`, and the whole of what a
    /// restore needs: `seq` and `epoch` are supplied by the write path, and
    /// everything else travels here. Written as a function rather than left to
    /// each caller because the field list is the thing that would drift — a
    /// restore that forgot `phase` would replay a compensation as a forward
    /// record, and the chain would hash differently for a reason no diff shows.
    ///
    /// Ungated, unlike `into_body` below: a restore reads an export rather than
    /// a store, so it is reachable in a build with no backend compiled in.
    #[must_use]
    pub fn from_body(body: RecordBody) -> Self {
        Self {
            run: body.run,
            case: body.case,
            step: body.step,
            phase: body.phase,
            effect_key: body.effect_key,
            kind: body.kind,
        }
    }

    /// Materialize into a body at a given position.
    ///
    /// Sealing a record is a store's job, so this has no callers in a build with
    /// no store compiled in. Both backends are stores: the gate read `redb`
    /// alone while `PostgresStore` calls this on every append, which nothing
    /// noticed because no configuration ever compiled Postgres without redb.
    #[cfg(any(feature = "redb", feature = "postgres", test))]
    pub(crate) fn into_body(self, seq: Seq, epoch: Epoch) -> RecordBody {
        RecordBody {
            seq,
            run: self.run,
            case: self.case,
            step: self.step,
            phase: self.phase,
            epoch,
            v: self.kind.version(),
            effect_key: self.effect_key,
            kind: self.kind,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn body(seq: Seq, kind: RecordKind) -> RecordBody {
        RecordBody {
            seq,
            run: RunId::generate(),
            case: None,
            step: None,
            phase: Phase::Forward,
            epoch: 1,
            v: kind.version(),
            effect_key: None,
            kind,
        }
    }

    /// An oversized record is refused, not written.
    ///
    /// The journal is append-only and hash-chained, so a record that lands
    /// cannot be pruned, rewritten, or skipped on read. Refusing at seal time is
    /// the only moment the problem is still cheap — which is why every engine in
    /// this field caps it rather than discovering it later as a store nobody can
    /// read.
    #[test]
    fn a_record_larger_than_the_limit_is_refused() {
        let huge = "x".repeat(Record::MAX_RECORD_BYTES + 1);
        let sealed = Record::seal(
            body(
                1,
                RecordKind::RunAdmitted {
                    capability: huge,
                    governed_by: None,
                    input: json!(null),
                    input_label: crate::core::Label::trusted(),
                    policy_bundle: None,
                    canon: crate::core::canon::VERSION,
                    idempotency_key: None,
                },
            ),
            Digest::ZERO,
        );
        match sealed {
            Err(StoreError::RecordTooLarge { bytes, limit }) => {
                assert!(bytes > limit, "the error must report the real overage");
                assert_eq!(limit, Record::MAX_RECORD_BYTES);
            }
            Err(other) => panic!("refused for the wrong reason: {other}"),
            Ok(r) => panic!(
                "a {}-byte record was accepted into an append-only chain",
                r.raw().len()
            ),
        }
    }

    /// The limit does not bite ordinary records.
    ///
    /// Stated separately because a ceiling set too low is the same defect
    /// wearing the opposite sign: it would refuse the work the plane exists to
    /// do, and the test above would still pass.
    #[test]
    fn an_ordinary_record_is_nowhere_near_the_limit() {
        let r = Record::seal(
            body(
                1,
                RecordKind::RunAdmitted {
                    capability: "auditor@2.0.0".into(),
                    governed_by: None,
                    input: json!({ "ticket": "printer on fire" }),
                    input_label: crate::core::Label::trusted(),
                    policy_bundle: None,
                    canon: crate::core::canon::VERSION,
                    idempotency_key: None,
                },
            ),
            Digest::ZERO,
        )
        .expect("an ordinary record seals");
        assert!(
            r.raw().len() * 100 < Record::MAX_RECORD_BYTES,
            "an ordinary record is {} bytes against a {}-byte ceiling; the \
             ceiling is too close to normal traffic to be a safety net",
            r.raw().len(),
            Record::MAX_RECORD_BYTES
        );
    }

    fn chain_of(n: u64) -> Vec<Record> {
        let mut prev = Digest::ZERO;
        let mut out = Vec::new();
        for i in 1..=n {
            let r = Record::seal(
                body(
                    i,
                    RecordKind::StepStarted {
                        skill: format!("s{i}"),
                    },
                ),
                prev,
            )
            .unwrap();
            prev = r.hash;
            out.push(r);
        }
        out
    }

    #[test]
    fn sealing_is_deterministic() {
        let b = body(1, RecordKind::StepStarted { skill: "x".into() });
        let a = Record::seal(b.clone(), Digest::ZERO).unwrap();
        let c = Record::seal(b, Digest::ZERO).unwrap();
        assert_eq!(
            a.hash, c.hash,
            "same body + same prev must hash identically"
        );
    }

    #[test]
    fn valid_chain_verifies() {
        let records = chain_of(5);
        let head = Record::verify_chain(&records, Digest::ZERO).unwrap();
        assert_eq!(head, records.last().unwrap().hash);
    }

    #[test]
    fn tampered_payload_is_detected() {
        let records = chain_of(3);
        let mut tampered = records.clone();
        // Rewrite the bytes without updating the hash — the classic edit.
        tampered[1].raw = b"{\"seq\":2,\"tampered\":true}".to_vec();
        let err = Record::verify_chain(&tampered, Digest::ZERO).unwrap_err();
        assert!(
            matches!(err, StoreError::Corrupt { seq: 2, .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn deleted_record_is_detected_as_a_gap() {
        let records = chain_of(4);
        let mut with_hole = records.clone();
        with_hole.remove(2);
        let err = Record::verify_chain(&with_hole, Digest::ZERO).unwrap_err();
        assert!(matches!(err, StoreError::Corrupt { .. }));
    }

    #[test]
    fn reordered_records_break_the_chain() {
        let mut records = chain_of(4);
        records.swap(1, 2);
        assert!(Record::verify_chain(&records, Digest::ZERO).is_err());
    }

    #[test]
    fn from_stored_rejects_a_hash_that_does_not_cover_the_bytes() {
        let r = chain_of(1).pop().unwrap();
        let err = Record::from_stored(b"{\"seq\":1}".to_vec(), Digest::ZERO, r.hash).unwrap_err();
        assert!(matches!(err, StoreError::Corrupt { .. }));
    }

    #[test]
    fn from_stored_roundtrips_a_genuine_record() {
        let r = chain_of(1).pop().unwrap();
        let back = Record::from_stored(r.raw().to_vec(), r.prev_hash, r.hash).unwrap();
        assert_eq!(back.body, r.body);
    }

    #[test]
    fn effect_records_carry_their_key() {
        let key = EffectKey::from_hex(&Digest::of(b"k").to_hex()).unwrap();
        let a = Append::new(
            RunId::generate(),
            RecordKind::EffectDone {
                declared: crate::core::DeclaredOutput::untrusted(),
                output: json!(1),
                source: None,
                spend: Spend::default(),
            },
        )
        .effect(key);
        let rec = Record::seal(a.into_body(1, 1), Digest::ZERO).unwrap();
        assert_eq!(rec.effect_key(), Some(key));
    }
}
