//! What the runtime could not decide, and how a person answers it.
//!
//! A quarantine is this runtime's most serious conclusion and its most honest
//! one: an effect was announced, the process died or the provider went quiet,
//! and whether the call reached the world is unanswerable from the journal.
//! The rule that follows — never unwind around an unknown outcome — is what
//! separates a saga that is truthful about distributed systems from one that
//! tidies up and hopes.
//!
//! The rule has a cost, and this module is where the cost is paid. A run that
//! stops on doubt stops for good unless somebody supplies the fact the runtime
//! lacks, so the types here are the vocabulary of that supply: what is in
//! doubt ([`Undecided`]), why ([`Doubt`]), and what a person decided to do
//! about it ([`QuarantineDecision`]).
//!
//! Two properties are deliberate:
//!
//! * **A person's answer is evidence, not authority.** An operator asserts what
//!   happened to one *effect*; the runtime still re-decides the *run*. Nobody
//!   gets to declare a run successful.
//! * **Giving up is a recorded outcome, not a silence.** A doubt that is never
//!   resolved outlives the run's status, because a status is something a later
//!   action can overwrite and a finding is not.

use serde::{Deserialize, Serialize};

use super::{EffectKey, Phase, StepId};

/// Why one effect's outcome is unknown.
///
/// Two shapes, and an operator investigates them differently: one says the
/// runtime never heard back, the other says it heard back and was told nothing
/// useful.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Doubt {
    /// Announced, and no terminal record follows.
    ///
    /// The crash shape: the request was sent and the process died before the
    /// answer could be written. Nothing about the call is known beyond the fact
    /// that it left.
    Announced,
    /// The attempt concluded, reporting that it could not tell.
    ///
    /// A timeout, a dropped connection mid-write, a probe that came back
    /// empty. Distinct from the announcement shape because something *did*
    /// report — there is a message to read, and a provider that has already
    /// been asked once.
    Inconclusive,
}

impl Doubt {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Announced => "announced",
            Self::Inconclusive => "inconclusive",
        }
    }
}

/// One effect whose outcome the journal cannot establish.
///
/// Derived from records rather than remembered, so the same list is produced by
/// the executor deciding whether an unwind is safe, by the operator API
/// answering *what do I have to look up*, and by an offline audit of a history
/// nothing may resume. Three readers, one rule.
///
/// Only **mutating** effects appear. A read that never came back is safe to
/// repeat and nobody has to adjudicate it; the question here is exclusively
/// *did this change the outside world*.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Undecided {
    /// The effect, by the key an operator quotes back when they answer it.
    pub effect: EffectKey,
    pub step: StepId,
    /// Forward work or a compensation. A compensation left in doubt is the
    /// worse of the two: the run is partially unwound.
    pub phase: Phase,
    /// What the call was, in the descriptor's own vocabulary — `http.post`,
    /// `tool://payments/charge`. The operator needs it to know which system to
    /// go and look in.
    pub kind: String,
    pub doubt: Doubt,
}

/// What a person decided about a run the runtime could not decide.
///
/// The two honest answers, and there is deliberately no third. "Mark it
/// succeeded" is not here: a run's outcome is structural, and a person who
/// could declare one would be able to close a run over work that never
/// happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineDecision {
    /// The doubt is answered; decide the run again.
    ///
    /// The runtime re-runs the same judgement it made before, over a history
    /// that now contains whatever the operator established. It may reach the
    /// same quarantine — if the answer was incomplete, or a second effect is
    /// still open — and that is the point: the person supplies facts, the
    /// runtime supplies verdicts.
    Reopen,
    /// Nothing will establish what happened. Close the run where it stands.
    ///
    /// Nothing is unwound, because unwinding around an unknown outcome is the
    /// one thing quarantine exists to forbid and an operator's impatience is
    /// not new evidence. The world keeps whatever the run left in it, the run
    /// seals as [`Abandoned`](crate::runtime::RunStatus::Abandoned), and the
    /// doubt remains reportable from the journal for as long as the journal
    /// exists.
    Abandon,
}

impl QuarantineDecision {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reopen => "reopen",
            Self::Abandon => "abandon",
        }
    }
}

/// What a person asserts about an effect the runtime could not decide.
///
/// The same two answers a [`Reconciliation`](crate::core::Reconciliation) probe
/// can reach, minus the third. `Inconclusive` is missing on purpose: a probe
/// records it because *having asked* is a fact about the run, and the doubt
/// stands either way. A person who cannot tell has already left the doubt
/// standing, and their finding belongs in the reason on the decision that
/// closes the run — where somebody will read it — rather than in a record that
/// changes nothing.
#[derive(Debug, Clone, PartialEq)]
pub enum Assertion {
    /// The call never took. Nothing changed outside, and the effect is safe to
    /// perform again — which is what a reopened run will do.
    DidNotHappen,
    /// The call took, and this is the result the run reads back.
    ///
    /// # The label this value carries
    ///
    /// **Untrusted and `Internal`**, always, and it is not a caller's choice.
    /// Every other output in this runtime is labelled by the effect that
    /// produced it — `trust()` and `output_sensitivity()`, declared in code or
    /// in operator configuration — and there is no effect here: an offline verb
    /// has no instance in hand, and the person typing the value is not the
    /// provider that returned it.
    ///
    /// So it takes the conservative point of the lattice, the same one an
    /// inbound event's payload gets, and the consequence is stated rather than
    /// hidden: a reopened run reaches its sinks with a value the gates judge on
    /// its merits, and a run that needed this output to be trusted will be
    /// refused there and unwind. That is the honest ending. The alternative —
    /// letting the resolution declare its own trust — makes the 3 a.m. verb
    /// the one place in this design where a person can declassify by typing.
    Landed(serde_json::Value),
}

impl Assertion {
    /// The assertion in the vocabulary a failure and a probe both use.
    #[must_use]
    pub const fn disposition(&self) -> super::Disposition {
        match self {
            Self::Landed(_) => super::Disposition::Landed,
            Self::DidNotHappen => super::Disposition::DidNotHappen,
        }
    }
}
