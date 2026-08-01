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

    #[error("no skill provides capability '{0}'")]
    NoProvider(String),

    /// Replay recomputed a different effect key than the journal holds — the
    /// deterministic zone took a different path than the recorded run.
    ///
    /// The run is quarantined. It is never allowed to silently diverge, because
    /// a diverging replay produces an audit trail that is quietly a lie.
    #[error(
        "non-determinism at seq {seq}: journal has {expected}, replay recomputed {actual} \
         — the deterministic zone is not deterministic; run quarantined"
    )]
    NonDeterminism {
        seq: Seq,
        expected: EffectKey,
        actual: EffectKey,
    },

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
            Self::Metered { disposition, .. } => *disposition,
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
    /// an explicit, journaled declassification.
    #[error("untrusted data may not reach mutating sink '{sink}' without declassification")]
    TaintGate { sink: String },

    /// A value's sensitivity exceeds what the sink is allowed to receive. This
    /// is the exfiltration path that matters: not the network, but a
    /// legitimate-looking tool call carrying a secret read three steps ago.
    #[error("sensitivity {actual:?} exceeds sink '{sink}' ceiling {ceiling:?}")]
    EgressCeiling {
        sink: String,
        actual: Sensitivity,
        ceiling: Sensitivity,
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

    /// The writer's epoch is below the current lease: it has been taken over and
    /// is now a zombie. It must drop the run, not retry.
    #[error("fenced: run {run} is owned at epoch {current}, writer held {held}")]
    Fenced {
        run: String,
        held: u64,
        current: u64,
    },

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
    /// someone else owns it, divergence means the recorded history can no longer
    /// be trusted to describe this code.
    #[must_use]
    pub fn is_terminal_for_owner(&self) -> bool {
        matches!(
            self,
            Self::Fenced { .. } | Self::NonDeterminism { .. } | Self::ChainBroken { .. }
        )
    }
}
