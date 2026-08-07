//! The error taxonomy.
//!
//! Every variant here is a *loud* failure. Principle P7 — no silent anything —
//! is enforced by the absence of fallbacks: there is no "log a warning and
//! continue" path for divergence, truncation, or a failed compensation, because
//! the dominant production failure mode is the one nothing reported.

use serde::{Deserialize, Serialize};

use crate::core::Spend;
use crate::core::{EffectKey, Sensitivity, Seq};

/// Failures reaching the operator.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RuntimeError {
    #[error("policy denied: {0}")]
    PolicyDenied(#[from] PolicyError),

    #[error("plan contract violation: {0}")]
    PlanContract(String),

    /// An open run would continue under policy semantics other than the bundle
    /// recorded at admission.
    #[error(
        "policy bundle changed while resuming an open run: recorded {recorded:?}, configured {configured:?}"
    )]
    PolicyBundleChanged {
        recorded: Option<crate::core::Digest>,
        configured: Option<crate::core::Digest>,
    },

    #[error("no skill provides capability '{0}'")]
    NoProvider(String),

    /// The tenant is at a ceiling, so nothing was admitted.
    ///
    /// Distinct from a policy denial, because they call for opposite responses.
    /// A denial says *you may not*, and retrying is pointless. A quota refusal
    /// says *not right now*, and the caller should come back — a concurrency
    /// ceiling clears when a run finishes. Collapsing them would teach callers
    /// to retry denials or to give up on back-pressure.
    #[error("quota: {0}")]
    QuotaExceeded(#[from] crate::quota::QuotaError),

    /// The journal's hash chain does not verify. Either a record was altered
    /// after the fact, or a writer produced bytes it did not hash.
    #[error("journal integrity broken at seq {seq}: {detail}")]
    ChainBroken { seq: Seq, detail: String },

    /// A write was rejected because another instance owns this run at a higher
    /// epoch. Not an error to retry blindly: this instance has been fenced and
    /// must drop the run.
    #[error("fenced at run {run}: held epoch {held}, store is at {current}")]
    Fenced {
        run: String,
        held: u64,
        current: u64,
    },

    /// Another instance holds a live lease on this run. Retryable *after* the
    /// lease expires — unlike [`Fenced`](Self::Fenced), which never is.
    #[error("run {run} is leased by '{owner}' for another {remaining_secs}s")]
    LeaseHeld {
        run: String,
        owner: String,
        remaining_secs: u64,
    },

    #[error(transparent)]
    Store(#[from] StoreError),

    #[error(transparent)]
    Encoding(#[from] serde_json::Error),
}

/// What a failure says about whether the call reached the outside world.
///
/// This is the distinction retry safety rests on, and it is not the same
/// question as "was the error transient". A refused connection and a timed-out
/// request are both transient; only one of them is safe to repeat against a
/// ledger.
///
/// The vocabulary is borrowed from distributed transactions, where a
/// participant whose outcome is unknown after a failure has been called
/// **in-doubt** since the XA specification. The situation is identical: the
/// journal cannot distinguish "never applied" from "applied, and the
/// acknowledgement was lost", and no amount of retrying makes it decidable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    /// The call provably never took effect — refused before dispatch, or
    /// rejected by the peer with the request intact. Safe to repeat, even for
    /// something that mutates.
    DidNotHappen,

    /// The outcome is unknown. The request may or may not have been applied,
    /// and nothing observable distinguishes the two.
    ///
    /// Identical in kind to the orphan a crash leaves behind, so it is resolved
    /// the same way: by the effect's declared [`Recovery`](crate::core::Recovery),
    /// never by guessing.
    InDoubt,

    /// It definitely took effect, and something went wrong afterwards — most
    /// often a response that would not decode.
    ///
    /// Never retried. A repeat would be a second real performance, and the
    /// second one would fail to decode exactly like the first.
    Landed,
}

impl Disposition {
    /// The variant name, for a metric label.
    ///
    /// Deliberately not `Display`: a metric dimension must be bounded, and a
    /// rendered message carries values. One label per distinct limit or detail
    /// string is a cardinality explosion that takes a metrics backend down —
    /// which is why every dimension in `runtime::metrics` comes from an accessor
    /// like this one rather than from a formatted error.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DidNotHappen => "did_not_happen",
            Self::InDoubt => "in_doubt",
            Self::Landed => "landed",
        }
    }

    /// Whether repeating the call is safe on its own terms, before the
    /// effect's [`Recovery`](crate::core::Recovery) gets a say.
    #[must_use]
    pub fn is_definitely_safe_to_repeat(self) -> bool {
        matches!(self, Self::DidNotHappen)
    }
}

/// Failure of a single external interaction.
///
/// Every variant declares a [`Disposition`], because the runtime cannot infer
/// one from a message and must not guess. Anything that does not say is treated
/// as [`InDoubt`](Disposition::InDoubt) — the same conservative default that
/// makes [`Recovery::RequiresOperator`](crate::core::Recovery::RequiresOperator)
/// the fallback for an effect that does not declare itself.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EffectError {
    /// The driver could not dispatch at all — no connection, no credentials,
    /// no route. Nothing reached the peer.
    #[error("driver '{driver}' unavailable: {detail}")]
    Unavailable { driver: String, detail: String },

    /// The peer received the call and refused it. The request is intact and
    /// nothing was applied.
    #[error("effect rejected: {0}")]
    Rejected(String),

    /// The peer accepted the request and never answered in time.
    ///
    /// The canonical in-doubt case, and the one that separates this runtime
    /// from a retry loop: a timed-out payment may well have been taken.
    #[error("driver '{driver}' did not answer within {waited_ms}ms")]
    Timeout { driver: String, waited_ms: u64 },

    /// The connection died mid-flight, after the request went out.
    #[error("driver '{driver}' interrupted: {detail}")]
    Interrupted { driver: String, detail: String },

    /// The call consumed metered resources and then failed.
    ///
    /// A model stream that dies after five hundred tokens has *spent* them: the
    /// provider bills for what it generated whether or not the answer arrived.
    /// Every other failure variant reports nothing consumed, which is right for
    /// a refused connection and wrong for this — and wrong in the direction that
    /// matters, because the token and cost ceilings exist to bound exactly the
    /// runaway a flaky provider produces.
    ///
    /// Carries its own disposition because only the driver knows: a stream that
    /// died mid-response definitely reached the provider, while a request
    /// refused before generation did not.
    #[error("effect consumed resources and failed: {detail}")]
    Metered {
        detail: String,
        spend: Spend,
        disposition: Disposition,
    },

    /// The peer performed the operation and reported that it failed.
    ///
    /// Distinct from [`Rejected`](EffectError::Rejected), which means the peer
    /// declined *before* doing anything. Here the work was attempted, so a
    /// repeat is a second attempt — and whether the first one changed something
    /// before failing is not knowable from the answer.
    ///
    /// Treated as `Landed` rather than `InDoubt` deliberately. `InDoubt` invites
    /// the effect's `Recovery` to resolve it, and for an outcome the peer has
    /// already reported there is nothing to resolve: asking again returns the
    /// same error, and repeating the call is the only other option.
    #[error("effect performed and failed: {0}")]
    Performed(String),

    /// It landed and answered, and the answer did not match the declared type.
    #[error("effect output did not match its declared type: {0}")]
    OutputShape(#[from] serde_json::Error),

    /// Every permitted attempt failed, and this is the last one's verdict.
    ///
    /// Carries the **disposition** rather than flattening it. A driver that
    /// said [`Rejected`](Self::Rejected) — refused before anything happened —
    /// must not be reported upward as undecidable merely because the runtime
    /// stopped retrying. Anything deciding whether it is safe to unwind would
    /// then refuse to, for a call that provably did nothing; and the failure
    /// that most needs an operator would be indistinguishable from the one that
    /// needs nobody.
    #[error("{detail}")]
    Final {
        detail: String,
        disposition: Disposition,
    },

    #[error("{0}")]
    Other(String),
}

impl EffectError {
    /// What this failure says about whether the call reached the outside world.
    /// What this failure cost, if anything.
    ///
    /// Zero for everything that never reached a meter. The runtime bills this on
    /// the failure path, so a call that burned tokens and then died is counted
    /// against the run's ceiling rather than being free.
    #[must_use]
    pub fn spend(&self) -> Spend {
        match self {
            Self::Metered { spend, .. } => *spend,
            _ => Spend::default(),
        }
    }

    #[must_use]
    pub fn disposition(&self) -> Disposition {
        match self {
            Self::Metered { disposition, .. } | Self::Final { disposition, .. } => *disposition,
            Self::Unavailable { .. } | Self::Rejected(_) => Disposition::DidNotHappen,
            Self::OutputShape(_) | Self::Performed(_) => Disposition::Landed,
            // `Other` shares the in-doubt arm deliberately: an error that does
            // not say what it did is treated as dangerous. A driver that wants
            // its failures retried has to state that they did not happen.
            Self::Timeout { .. } | Self::Interrupted { .. } | Self::Other(_) => {
                Disposition::InDoubt
            }
        }
    }
}

/// Failure inside a skill.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SkillError {
    #[error("input did not match the declared schema: {0}")]
    Input(String),

    #[error(transparent)]
    Step(#[from] StepError),

    /// A tool call could not be prepared: the tool is not in the operator's
    /// catalogue, or the arguments do not match what it declared.
    ///
    /// Here so that `?` works on `ToolCall::prepare`, which is the second thing
    /// the getting-started page teaches and the first thing every skill that
    /// touches the world does. Without it the published snippet did not compile
    /// — *the trait `From<ToolError>` is not implemented for `SkillError`* — and
    /// every real caller wrote the same
    /// `.map_err(|e| SkillError::Other(e.to_string()))` incantation, which
    /// throws the typed error away and leaves three copies of one decision.
    /// A skill-facing operation deserves a skill-facing conversion.
    #[error(transparent)]
    Tool(#[from] crate::tools::ToolError),

    #[error("{0}")]
    Other(String),
}

/// Failure surfaced to a skill through [`StepCtx`](crate::runtime::StepCtx).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StepError {
    #[error(transparent)]
    Effect(#[from] EffectError),

    #[error(transparent)]
    Policy(#[from] PolicyError),

    #[error(transparent)]
    Store(#[from] StoreError),

    #[error("{0}")]
    Encoding(#[from] serde_json::Error),

    /// The outcome of an effect cannot be determined, and its declared
    /// [`Recovery`](crate::core::Recovery) forbids guessing.
    ///
    /// Reached two ways, which are the same situation from different
    /// directions: a crash landed between "sent" and "recorded", or the call
    /// itself failed [`InDoubt`](Disposition::InDoubt). Either way the journal
    /// cannot distinguish "never applied" from "applied, acknowledgement lost",
    /// and for anything that mutates, the runtime escalates rather than guess.
    ///
    /// A distinct variant rather than a message, because the executor
    /// quarantines on it — and a run's disposition must not hinge on the
    /// wording of a string.
    #[error(
        "effect {key} is undecidable ({detail}); recovery mode {recovery:?} forbids \
         guessing — run quarantined"
    )]
    Undecidable {
        key: EffectKey,
        recovery: crate::core::Recovery,
        detail: String,
    },

    /// Surfaced when replay finds the recorded run took a different path.
    #[error("non-determinism at seq {seq}: expected {expected}, recomputed {actual}")]
    NonDeterminism {
        seq: Seq,
        expected: EffectKey,
        actual: EffectKey,
    },

    /// A limit stopped the run before it spent more.
    ///
    /// Not a fault: the run did what it was told, and what it was told included
    /// a ceiling. Distinct from an ordinary failure so an operator can tell
    /// "this needs a bigger budget" from "this is broken".
    #[error(transparent)]
    Budget(#[from] crate::core::BudgetExceeded),

    /// **Not a failure.** The run is waiting for something that has not
    /// happened, and its frame has been persisted.
    ///
    /// Propagate it with `?`. A skill that catches this turns a durable wait
    /// into a silent hang: the subscription stays registered, the event
    /// eventually arrives, and it resumes a run that has already decided it
    /// finished. It is modelled as an error only because that is how control
    /// leaves a skill — the run is healthy.
    #[error("suspended: {0}")]
    Suspended(crate::core::SuspendReason),

    /// Policy refused the effect.
    ///
    /// Separate from `Budget` because the two are answered differently: a limit
    /// is raised, a rule is argued with. Collapsing them would put "ask for more
    /// quota" and "you are not allowed to do this" behind one message.
    #[error("policy denied '{action}' on '{resource}': {reason}")]
    Denied {
        action: String,
        resource: String,
        reason: String,
    },

    /// A member did not fit the group it was added to.
    ///
    /// A footprint violation, a mutating effect declared as a read, a nested
    /// group, or an empty footprint. Every one of these is caught **before**
    /// the effect runs, which is the only time catching it is free.
    #[error("effect group '{group}': {detail}")]
    GroupFootprint { group: String, detail: String },

    /// A group was taken back whole, and nothing it did is standing.
    ///
    /// Not a quarantine and not a silent failure: every reversible member was
    /// reversed, no deferred member ran, and `what` says which condition
    /// stopped it. A caller may handle this and carry on, which is the point of
    /// grouping in the first place.
    #[error("effect group aborted and fully reversed: {what}")]
    GroupAborted { what: String },

    /// A group could be neither committed nor taken back.
    ///
    /// A reversal failed, or a member is in doubt. The run is quarantined,
    /// because a partially unwound group is a state nobody declared and no
    /// later code can reason about. This is the honest report of the situation
    /// that other systems surface as a success with a warning.
    #[error("effect group '{group}' could not be settled: {detail} — run quarantined")]
    GroupUnsettled { group: String, detail: String },

    /// Strict replay reached the end of history and the code asked for another
    /// effect. The recorded run did less than this code does — divergence that
    /// ordered key comparison alone cannot see, because there is nothing left to
    /// compare against.
    #[error(
        "replay overrun: journal is exhausted but the run requested {actual} — \
         this build performs more effects than the recorded one"
    )]
    ReplayOverrun { actual: EffectKey },
}

/// Authorization failure.
///
/// Evaluation is total and side-effect free, so this never means "the policy
/// engine was unreachable" — that state cannot arise.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PolicyError {
    #[error("principal '{principal}' may not '{action}' on '{resource}'")]
    Denied {
        principal: String,
        action: String,
        resource: String,
    },

    /// An argument derived from untrusted data reached a mutating sink without
    /// an explicit, policy-authorized release.
    #[error("untrusted data may not reach mutating sink '{sink}' without an authorized release")]
    TaintGate { sink: String },

    /// A sink did not expose the value it will send, so the runtime cannot bind
    /// the information-flow decision to the outbound call.
    #[error("sink '{sink}' does not bind the arguments it sends to the value checked by policy")]
    UnboundSinkArguments { sink: String },

    /// A caller tried to dispatch an outbound-value effect through the generic
    /// effect API, bypassing information-flow enforcement.
    #[error("sink '{sink}' must be dispatched with StepCtx::sink so its outbound value is checked")]
    SinkGateRequired { sink: String },

    /// The labeled value presented to the gate differs from the value the sink
    /// will send.
    #[error(
        "sink '{sink}' attempted to send arguments other than the labeled value policy checked"
    )]
    SinkArgumentsMismatch { sink: String },

    /// A field the sink declares security-sensitive is absent from the value.
    #[error("sink '{sink}' requires protected field '{path}', but the argument is absent")]
    ProtectedFieldMissing { sink: String, path: String },

    /// Untrusted data attempted to choose a protected sink argument.
    #[error("untrusted data may not select protected field '{path}' of sink '{sink}'")]
    ProtectedFieldTaint { sink: String, path: String },

    /// A protected field derives from a source outside its operator declaration.
    #[error(
        "protected field '{path}' of sink '{sink}' derives from undeclared source '{actual_source}'"
    )]
    ProtectedFieldSource {
        sink: String,
        path: String,
        actual_source: String,
    },

    /// A protected field exceeds its own sensitivity ceiling.
    #[error(
        "protected field '{path}' sensitivity {actual:?} exceeds sink '{sink}' field ceiling {ceiling:?}"
    )]
    ProtectedFieldSensitivity {
        sink: String,
        path: String,
        actual: Sensitivity,
        ceiling: Sensitivity,
    },

    /// A field-specific release was requested for a value whose field lineage
    /// was never tracked.
    #[error(
        "release scope contains a missing or untracked field; use Tainted::object/array before releasing selected fields"
    )]
    UntrackedReleaseField,

    /// A serialized release bypassed the safe constructors and violated the
    /// typed-release invariants.
    #[error("invalid release: {detail}")]
    InvalidRelease { detail: String },

    /// A value's sensitivity exceeds what this agent may write into the
    /// journal.
    ///
    /// Distinct from [`EgressCeiling`](Self::EgressCeiling), and the
    /// distinction is the whole point: egress asks *may this leave*, this asks
    /// *may this be written down forever*. The journal is append-only, so an
    /// argument recorded there — a prompt, a tool call's arguments — is never
    /// removed. A deployment with an erasure obligation has two answers and
    /// this ceiling is the first: **refuse** the data at dispatch, rather than
    /// meet an impossibility at the erasure request. The second is to **seal**
    /// it — `RuntimeBuilder::keyring` puts payloads under a per-case key that
    /// `erase_case` destroys — and the two compose: a deployment may seal
    /// everything and still refuse the classes it would rather never hold.
    ///
    /// The message names both, because a reader who has configured a key ring
    /// and then meets this refusal would otherwise conclude the seal is not
    /// working.
    #[error(
        "sensitivity {actual:?} exceeds the journal ceiling {ceiling:?} for sink \
         '{sink}' — the journal is append-only, so this argument could not be \
         removed afterwards. Put the bytes in a blob and pass the digest, or \
         configure a key ring so payloads are sealed under a key erasure destroys"
    )]
    JournalCeiling {
        sink: String,
        actual: crate::core::Sensitivity,
        ceiling: crate::core::Sensitivity,
    },

    /// A value's sensitivity exceeds what the sink is allowed to receive. This
    /// is the exfiltration path that matters: not the network, but a
    /// legitimate-looking tool call carrying a secret read three steps ago.
    #[error("sensitivity {actual:?} exceeds sink '{sink}' ceiling {ceiling:?}")]
    EgressCeiling {
        sink: String,
        actual: Sensitivity,
        ceiling: Sensitivity,
    },

    /// A handoff would make the authority chain deeper than this agent's
    /// reviewed declaration permits.
    #[error("delegation depth {actual} exceeds sink '{sink}' ceiling {ceiling}")]
    DelegationDepth {
        sink: String,
        actual: usize,
        ceiling: usize,
    },
}

/// What a model may be told about a refusal.
///
/// # A denial reason is an oracle
///
/// Every message in [`PolicyError`] is written for an operator reading a
/// journal, and each one is precise on purpose: which principal, which sink,
/// what sensitivity, which ceiling. That precision is exactly what makes it
/// unsafe to hand back to a model.
///
/// An agent loop that feeds the refusal into its next prompt turns the policy
/// into a queryable service. Injected content steering the agent can probe it:
/// vary the request, watch which variants come back refused, and read the
/// boundary off the answers. `EgressCeiling` is the sharpest case — it reports
/// the *sensitivity of the data* and the sink's ceiling, so a few probes
/// classify data the run was never allowed to reveal, without any of it ever
/// crossing the boundary.
///
/// So the split is deliberate: **the journal keeps everything, the model is told
/// one uniform sentence.** An auditor needs to know why; the thing that might be
/// attacking the policy must not learn anything it can differentiate.
///
/// This does not remove the denied/allowed bit itself. Nothing can, short of
/// fabricating success. What bounds *that* channel is
/// [`Budget::max_denials`](crate::core::Budget::max_denials): a run that keeps
/// hitting the policy is probing it, and it is stopped.
pub const REFUSED: &str = "this action was not permitted";

impl PolicyError {
    /// The one sentence a model may be shown.
    ///
    /// Uniform across every variant, deliberately — see [`REFUSED`]. Use
    /// [`Display`](std::fmt::Display) for the journal and for operators, and
    /// this for anything that reaches a prompt.
    #[must_use]
    pub const fn for_model(&self) -> &'static str {
        REFUSED
    }
}

/// Persistence failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    #[error("backend: {0}")]
    Backend(String),

    #[error("not found: {0}")]
    NotFound(String),

    /// A single record exceeded the size a journal will hold.
    ///
    /// Refused rather than written, and the distinction is the whole point. The
    /// journal is append-only and hash-chained: an oversized record cannot be
    /// pruned later, cannot be rewritten, and is replayed on every read of that
    /// run. Every durable-execution engine in the field caps this — Temporal at
    /// 2 MB with a claim check above ~256 KiB, Restate at 32 MiB after
    /// oversized entries drove it into an unrecoverable state — and the failure
    /// they all avoid is the one where the write succeeds and the problem
    /// surfaces months later as a store nobody can read quickly.
    ///
    /// The fix is at the call site, not here: put the bytes somewhere addressed
    /// by a digest and journal the digest.
    #[error(
        "record of {bytes} bytes exceeds the {limit}-byte journal limit — \
         journal a digest and keep the bytes outside the chain"
    )]
    RecordTooLarge { bytes: usize, limit: usize },

    /// The `(run_id, effect_key)` unique index rejected a second start for one
    /// effect. Exactly-once is a database invariant here, not a code path.
    #[error("effect {0} already started in this run")]
    DuplicateEffect(EffectKey),

    /// A case-state write named a version the case has moved past.
    ///
    /// Somebody else wrote to this case between the read and the write. The
    /// caller must re-read and decide again — *not* retry the same write, which
    /// would be the lost update this error exists to prevent.
    #[error("case {case} has moved to {current}; the write was made against {expected}")]
    CaseConflict {
        case: String,
        expected: u64,
        current: u64,
    },

    /// The writer did not present the current lease epoch. A stale writer has
    /// been taken over; a future epoch was never acquired. Neither owns the run,
    /// and neither may retry blindly.
    #[error("fenced: run {run} is owned at epoch {current}, writer held {held}")]
    Fenced {
        run: String,
        held: u64,
        current: u64,
    },

    /// A transaction's `COMMIT` was sent and no acknowledgement arrived.
    ///
    /// The one in-doubt window a native transaction keeps: the server either
    /// committed or did not, but the *client's knowledge* of which was lost —
    /// a connection dropped between sending `COMMIT` and receiving its answer.
    /// A commit the server **refused** (a serialization or constraint failure,
    /// returned as a database error) is not this; that is a clean rollback and
    /// stays an ordinary [`Backend`](Self::Backend) error. The two must stay
    /// distinguishable, because they call for opposite handling: a refusal is
    /// a cheap abort, and an unknown outcome must be treated as a standing
    /// write until somebody reconciles it — settling `Aborted` over it would
    /// be the journal claiming *taken back whole* about a write that may
    /// stand.
    #[error(
        "the transaction's outcome is unknown — COMMIT may or may not have \
         been applied: {detail}"
    )]
    CommitUnknown { detail: String },

    /// The run is sealed; its journal is frozen.
    ///
    /// A seal freezes the chain head the Merkle log's leaf commits to. An
    /// append past it — even by the caller that legitimately holds the current
    /// epoch — advances the true head past the leaf every checkpoint attests,
    /// so the store refuses it inside the same transaction that would have
    /// written it. The executor's own refusal to resume a closed run is
    /// application logic a future caller can bypass; this is the constraint
    /// that cannot be.
    #[error("run {run} is sealed as '{outcome}'; a sealed journal accepts no appends")]
    RunSealed { run: String, outcome: String },

    /// Another instance holds a *live* lease. Distinct from being fenced: this
    /// writer is not stale, it is simply not the owner yet. The correct response
    /// is to wait for expiry (or for an operator to force a takeover), which is
    /// why it is a separate variant rather than a `Fenced` with placeholder
    /// numbers in it.
    #[error("run {run} is leased by '{owner}' at epoch {epoch} for another {remaining_secs}s")]
    LeaseHeld {
        run: String,
        owner: String,
        epoch: u64,
        remaining_secs: u64,
    },

    #[error("corrupt record at seq {seq}: {detail}")]
    Corrupt { seq: Seq, detail: String },

    #[error(transparent)]
    Encoding(#[from] serde_json::Error),
}

impl RuntimeError {
    /// Lift a store error into the operator-facing taxonomy.
    ///
    /// Two promotions matter, because both change what a human should do:
    ///
    /// * **Fenced** — "I lost ownership of this run" (drop it; another instance
    ///   has it), as opposed to "the database is unhappy" (retry).
    /// * **Corrupt → [`ChainBroken`](Self::ChainBroken)** — the journal does not
    ///   verify. That is never a retryable storage hiccup; it means the history
    ///   has been altered and nothing downstream of it can be trusted. Leaving
    ///   it as a generic store error would bury the one failure that must never
    ///   be shrugged off.
    #[must_use]
    pub fn from_store(e: StoreError) -> Self {
        match e {
            StoreError::Fenced { run, held, current } => Self::Fenced { run, held, current },
            StoreError::LeaseHeld {
                run,
                owner,
                remaining_secs,
                ..
            } => Self::LeaseHeld {
                run,
                owner,
                remaining_secs,
            },
            StoreError::Corrupt { seq, detail } => Self::ChainBroken { seq, detail },
            other => Self::Store(other),
        }
    }

    /// Whether this run should be abandoned by *this* instance rather than
    /// retried. Both cases are terminal for the current owner: fencing means
    /// someone else owns it, and a broken chain means the recorded history can
    /// no longer be trusted to describe anything.
    ///
    /// Divergence is deliberately not here. It is not a `RuntimeError` at all —
    /// a replay that recomputes a different key quarantines the *run*, through
    /// [`StepError::NonDeterminism`], and a run status is not something an
    /// owner abandons. A second spelling of it lived on this enum, unconstructed
    /// and pointed at by the crate's own front page, until a guard noticed.
    #[must_use]
    pub fn is_terminal_for_owner(&self) -> bool {
        matches!(self, Self::Fenced { .. } | Self::ChainBroken { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::{Disposition, RuntimeError};

    /// Two embedder-facing predicates, each of which was public, documented,
    /// and called by nothing — so a wrong `matches!` arm would have been
    /// invisible. Neither claims to *be* a control, which is what separates
    /// them from `PolicyError::for_model`; they are still decisions an embedder
    /// makes recovery choices on.
    #[test]
    fn only_a_call_that_never_left_is_safe_to_repeat_on_its_own_terms() {
        assert!(Disposition::DidNotHappen.is_definitely_safe_to_repeat());
        // The two that matter. `InDoubt` is the whole reason this is not a
        // negation of `Landed`: a timed-out payment may well have been taken.
        assert!(!Disposition::InDoubt.is_definitely_safe_to_repeat());
        assert!(!Disposition::Landed.is_definitely_safe_to_repeat());
    }

    #[test]
    fn an_owner_abandons_a_fenced_run_and_a_broken_chain_and_nothing_else() {
        assert!(
            RuntimeError::Fenced {
                run: "run-1".into(),
                held: 1,
                current: 2,
            }
            .is_terminal_for_owner()
        );
        assert!(
            RuntimeError::ChainBroken {
                seq: 1,
                detail: "hash mismatch".into(),
            }
            .is_terminal_for_owner()
        );
        // An ordinary store failure is retryable by this instance: nobody else
        // owns the run and the history is still trustworthy.
        assert!(
            !RuntimeError::Store(crate::core::StoreError::Backend("timeout".into()))
                .is_terminal_for_owner()
        );
    }
}
