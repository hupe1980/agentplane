//! Judging a high-stakes step more than once, and disagreeing usefully.
//!
//! The measurement is the whole argument: an agent at 61 % pass^1 is around
//! **25 % at pass^8**. A single execution of a judgement that moves money or
//! closes a regulatory case is therefore not adequate evidence, however
//! confident it sounds.
//!
//! # Diversity, not repetition
//!
//! The obvious implementation runs the same judgement three times and takes the
//! majority. That buys almost nothing: identical prompts against the same model
//! share the same blind spots, so three runs agree confidently and wrongly about
//! precisely the cases a second opinion existed to catch. Redundancy catches
//! *variance*; only diversity catches *bias*.
//!
//! So a quorum declares **lenses** — distinct angles the same work is judged
//! from — and duplicate lenses are rejected at construction rather than warned
//! about. A quorum of three identical lenses is repetition wearing diversity's
//! clothing, and the type refuses to express it.
//!
//! # No quorum is an answer, and it is not the majority
//!
//! The one thing this must never do is fall back to "pick whichever side had
//! more votes". A panel that split 2–2, or that reached 2 of 3 where 3 was
//! required, is the strongest available signal that a human should look — it is
//! the case where the judgement is genuinely hard. Silently resolving it is how
//! a system converts *we do not know* into *approved*.
//!
//! [`Outcome::NoQuorum`] therefore carries the tally and offers no accessor that
//! resolves it. There is no `majority()`, deliberately: the caller escalates,
//! because there is nothing else the type lets them do.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// How many judgements, from how many angles, and how many must agree.
///
/// # Deserialization takes the same door as `new`
///
/// A derived `Deserialize` would reach the private fields directly, which is
/// the `Quorum::new(need, lenses)` this type deliberately does not offer. It is
/// the door that matters most here: a [`PlanNode`] carries an optional quorum,
/// plans are deserialized — from a store, from a journal, from a [`Replanner`]
/// parsing a model's proposal — and a panel is exactly the control a hijacked
/// plan wants weakened. `need: 0` then reports [`Verdict::Pass`] having judged
/// nothing, and a non-majority threshold reports whichever side `tally`
/// happens to count first.
///
/// [`PlanNode`]: crate::core::PlanNode
/// [`Replanner`]: crate::plan::Replanner
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "DeclaredQuorum")]
pub struct Quorum {
    /// How many must agree for the panel to have decided.
    need: u32,
    /// The angles to judge from. One judgement per lens.
    lenses: Vec<String>,
}

/// The wire form of a [`Quorum`], before it has been checked.
///
/// Exists only so `serde` has a shape to build that is *not* a `Quorum`. It
/// carries no invariant, which is the point: the only way across is
/// [`Quorum::new`].
#[derive(Deserialize)]
struct DeclaredQuorum {
    need: u32,
    lenses: Vec<String>,
}

impl TryFrom<DeclaredQuorum> for Quorum {
    type Error = QuorumError;

    fn try_from(d: DeclaredQuorum) -> Result<Self, Self::Error> {
        Self::new(d.need, d.lenses)
    }
}

impl Quorum {
    /// Declare a quorum of `need` agreeing judgements across `lenses`.
    ///
    /// # Errors
    ///
    /// [`QuorumError`] — every variant is a way of declaring a panel that
    /// cannot do the job it is being asked to do, so all are refused at
    /// construction rather than discovered at run time.
    pub fn new<I, S>(need: u32, lenses: I) -> Result<Self, QuorumError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let lenses: Vec<String> = lenses.into_iter().map(Into::into).collect();
        let of = u32::try_from(lenses.len()).unwrap_or(u32::MAX);

        if need == 0 {
            return Err(QuorumError::NeedsNobody);
        }
        if need > of {
            return Err(QuorumError::Unreachable { need, of });
        }
        // Two lenses agreeing out of two is unanimity, which is a legitimate
        // and strict choice. One of two is not a quorum at all — it is "any
        // judge may decide alone", with the second judge's disagreement
        // discarded. That is worse than a single judgement, because it looks
        // like a panel.
        if of > 1 && need * 2 <= of {
            return Err(QuorumError::NotAMajority { need, of });
        }
        let unique: BTreeSet<&String> = lenses.iter().collect();
        if unique.len() != lenses.len() {
            return Err(QuorumError::RepeatedLens);
        }
        if lenses.iter().any(|l| l.trim().is_empty()) {
            return Err(QuorumError::UnnamedLens);
        }
        Ok(Self { need, lenses })
    }

    #[must_use]
    pub const fn need(&self) -> u32 {
        self.need
    }

    /// How many judgements this panel takes.
    #[must_use]
    pub fn of(&self) -> u32 {
        u32::try_from(self.lenses.len()).unwrap_or(u32::MAX)
    }

    pub fn lenses(&self) -> impl Iterator<Item = &str> {
        self.lenses.iter().map(String::as_str)
    }

    /// Tally judgements into a decision, or into an escalation.
    ///
    /// Verdicts are expected one per lens, in lens order. A panel that returned
    /// fewer than it was asked for has not reached quorum — a missing judgement
    /// is not an abstention that the others can outvote, it is evidence the
    /// panel did not run.
    #[must_use]
    pub fn tally(&self, verdicts: &[Verdict]) -> Outcome {
        let passed = verdicts.iter().filter(|v| **v == Verdict::Pass).count();
        let failed = verdicts.iter().filter(|v| **v == Verdict::Fail).count();
        let tally = Tally {
            passed: u32::try_from(passed).unwrap_or(u32::MAX),
            failed: u32::try_from(failed).unwrap_or(u32::MAX),
            asked: self.of(),
        };
        if tally.passed >= self.need {
            return Outcome::Reached(Verdict::Pass, tally);
        }
        if tally.failed >= self.need {
            return Outcome::Reached(Verdict::Fail, tally);
        }
        Outcome::NoQuorum(tally)
    }
}

/// One judge's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Pass,
    Fail,
}

/// What the panel produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tally {
    pub passed: u32,
    pub failed: u32,
    /// How many judgements were asked for — so a short panel is visible.
    pub asked: u32,
}

/// The panel's decision, or its failure to reach one.
///
/// Note what is missing: there is no way to extract a decision from
/// [`NoQuorum`](Outcome::NoQuorum). That is the point. A panel that could not
/// agree is the signal a person should look, and an accessor returning "whoever
/// had more votes" would turn the one useful thing this mechanism produces back
/// into a confident answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Reached(Verdict, Tally),
    NoQuorum(Tally),
}

impl Outcome {
    /// The decision, if there was one.
    #[must_use]
    pub const fn decided(&self) -> Option<Verdict> {
        match self {
            Self::Reached(v, _) => Some(*v),
            Self::NoQuorum(_) => None,
        }
    }

    #[must_use]
    pub const fn tally(&self) -> Tally {
        match self {
            Self::Reached(_, t) | Self::NoQuorum(t) => *t,
        }
    }
}

/// Why a declared panel was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QuorumError {
    #[error("a quorum needing zero agreeing judgements decides nothing")]
    NeedsNobody,

    #[error("a quorum of {need} cannot be reached from {of} judgement(s)")]
    Unreachable { need: u32, of: u32 },

    #[error(
        "{need} of {of} is not a majority: the panel could reach a quorum for \
         'pass' and for 'fail' at once, and which one is reported would depend \
         on tally order rather than on the judgements"
    )]
    NotAMajority { need: u32, of: u32 },

    #[error(
        "a lens is repeated; identical judges share their blind spots, so a \
         repeated lens is repetition rather than the diversity a quorum is for"
    )]
    RepeatedLens,

    #[error("a lens with no name cannot be a distinct angle")]
    UnnamedLens,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q(need: u32, lenses: &[&str]) -> Quorum {
        Quorum::new(need, lenses.iter().copied()).expect("valid")
    }

    #[test]
    fn a_declared_panel_reports_its_shape() {
        let quorum = q(2, &["correctness", "policy", "arithmetic"]);
        assert_eq!(quorum.need(), 2);
        assert_eq!(quorum.of(), 3);
        assert_eq!(
            quorum.lenses().collect::<Vec<_>>(),
            vec!["correctness", "policy", "arithmetic"]
        );
    }

    /// The rule the whole mechanism rests on.
    #[test]
    fn repeating_a_lens_is_refused() {
        let err = Quorum::new(2, ["correctness", "correctness", "policy"])
            .expect_err("identical judges are not a panel");
        assert_eq!(err, QuorumError::RepeatedLens);
    }

    #[test]
    fn a_quorum_larger_than_the_panel_is_refused() {
        assert_eq!(
            Quorum::new(4, ["a", "b", "c"]).expect_err("unreachable"),
            QuorumError::Unreachable { need: 4, of: 3 }
        );
    }

    #[test]
    fn a_quorum_of_zero_is_refused() {
        assert_eq!(
            Quorum::new(0, ["a"]).expect_err("decides nothing"),
            QuorumError::NeedsNobody
        );
    }

    /// A non-majority threshold can be met by both sides at once.
    #[test]
    fn a_threshold_that_both_sides_could_meet_is_refused() {
        assert_eq!(
            Quorum::new(2, ["a", "b", "c", "d"]).expect_err("2 of 4 is not a majority"),
            QuorumError::NotAMajority { need: 2, of: 4 }
        );
        assert_eq!(
            Quorum::new(1, ["a", "b"]).expect_err("1 of 2 is any judge deciding alone"),
            QuorumError::NotAMajority { need: 1, of: 2 }
        );
    }

    /// Unanimity is strict, not invalid.
    #[test]
    fn unanimity_is_allowed() {
        assert!(Quorum::new(2, ["a", "b"]).is_ok());
        assert!(Quorum::new(3, ["a", "b", "c"]).is_ok());
        assert!(Quorum::new(1, ["a"]).is_ok(), "a panel of one is a panel");
    }

    #[test]
    fn an_agreeing_panel_decides() {
        let quorum = q(2, &["a", "b", "c"]);
        let out = quorum.tally(&[Verdict::Pass, Verdict::Pass, Verdict::Fail]);
        assert_eq!(out.decided(), Some(Verdict::Pass));
        assert_eq!(out.tally().passed, 2);
        assert_eq!(out.tally().failed, 1);
    }

    #[test]
    fn a_panel_agreeing_to_refuse_also_decides() {
        let quorum = q(2, &["a", "b", "c"]);
        let out = quorum.tally(&[Verdict::Fail, Verdict::Fail, Verdict::Pass]);
        assert_eq!(out.decided(), Some(Verdict::Fail));
    }

    /// **The property the design turns on.**
    #[test]
    fn a_split_panel_decides_nothing() {
        let quorum = q(3, &["a", "b", "c"]);
        let out = quorum.tally(&[Verdict::Pass, Verdict::Pass, Verdict::Fail]);
        assert_eq!(
            out.decided(),
            None,
            "2 of 3 where 3 was required is a disagreement, and reporting the \
             majority converts 'we do not know' into 'approved'"
        );
        assert!(matches!(out, Outcome::NoQuorum(_)));
        assert_eq!(out.tally().passed, 2, "the tally is still reported");
    }

    /// A panel that did not fully run has not agreed.
    #[test]
    fn a_short_panel_does_not_reach_quorum() {
        let quorum = q(2, &["a", "b", "c"]);
        let out = quorum.tally(&[Verdict::Pass]);
        assert_eq!(out.decided(), None);
        assert_eq!(out.tally().asked, 3, "the shortfall is visible");
    }

    #[test]
    fn an_empty_panel_decides_nothing() {
        let quorum = q(2, &["a", "b", "c"]);
        assert_eq!(quorum.tally(&[]).decided(), None);
    }

    #[test]
    fn an_unnamed_lens_is_refused() {
        assert_eq!(
            Quorum::new(1, ["  "]).expect_err("unnamed"),
            QuorumError::UnnamedLens
        );
    }
}
