//! What a strict replay found, as an author or a CI job can act on it.
//!
//! [`Runtime::verify`](super::Runtime::verify) replays one recorded run under
//! the declarations this plane holds and answers in one of three ways: the
//! record was reproduced, this build parted from it at a named effect, or the
//! run cannot be re-derived here at all. The third is never reported as the
//! second — an author told their edit broke a run it never reached has been
//! told something false.
//!
//! Both revisions travel with every answer: the declaration the run was
//! admitted under and the one in hand. *No divergence* under a different
//! digest is a statement about this run's history, never *the two revisions
//! are the same*, and a report that dropped either digest would let a reader
//! take it for the second.

use crate::core::RunId;
use crate::journal::{AgentIdentity, Divergence};

/// One run's answer to a strict replay.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Verdict {
    pub run: RunId,
    /// The declaration the run was admitted under — `None` for a coded skill,
    /// which records none.
    pub recorded: Option<AgentIdentity>,
    /// The declaration this plane holds under the recorded agent's name —
    /// `None` when it holds none by that name.
    pub candidate: Option<AgentIdentity>,
    pub finding: Finding,
}

/// What the replay found.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Finding {
    /// Every recorded effect was asked for again, in order, and the run
    /// reached the ending it recorded — a recorded failure included, since the
    /// recorded ending is what is verified, not whether it was a success.
    Verified { outcome: String },
    /// This build asked for a different effect, more effects, or fewer.
    Diverged(Divergence),
    /// Every effect matched and the run still ended differently.
    OutcomeDiffers { recorded: String, replayed: String },
    /// The run cannot be re-derived here, for a reason that is not the edit.
    CannotReplay(CannotReplay),
}

/// Why a run cannot be replayed — each one a reason, never a divergence.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CannotReplay {
    /// Its payloads are sealed to a key the ring reports destroyed.
    Erased,
    /// Its payloads are sealed and this plane holds no key ring.
    KeyAbsent,
    /// Its keys were derived under another canonicalization rule.
    CanonicalizationChanged { recorded: u16, implemented: u16 },
    /// Nothing on this plane provides a capability the run executed.
    EntryPointRemoved { capability: String },
    /// The run has not ended, so there is no recorded ending to verify.
    NotConcluded,
    /// A person or the plane ended it, not its own steps — a cancellation, an
    /// abandonment, a sweep — so re-deriving its steps says nothing about it.
    EndedByAnAct { outcome: String },
}

impl Verdict {
    /// Whether the record was reproduced.
    #[must_use]
    pub const fn is_verified(&self) -> bool {
        matches!(self.finding, Finding::Verified { .. })
    }

    /// Whether this build parted from the record.
    #[must_use]
    pub const fn is_diverged(&self) -> bool {
        matches!(
            self.finding,
            Finding::Diverged(_) | Finding::OutcomeDiffers { .. }
        )
    }

    /// Whether both sides name one declaration digest.
    ///
    /// Two coded-skill runs name none, which is the same answer.
    #[must_use]
    pub fn same_revision(&self) -> bool {
        match (&self.recorded, &self.candidate) {
            (Some(a), Some(b)) => a.digest == b.digest,
            (None, None) => true,
            _ => false,
        }
    }
}

impl std::fmt::Display for CannotReplay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Erased => f.write_str("erased — its payloads are sealed to a destroyed key"),
            Self::KeyAbsent => f.write_str(
                "key absent — its payloads are sealed and this plane holds no key ring; nothing \
                 is known to be erased",
            ),
            Self::CanonicalizationChanged {
                recorded,
                implemented,
            } => write!(
                f,
                "canonicalization changed — recorded under rule {recorded}, this build \
                 implements {implemented}"
            ),
            Self::EntryPointRemoved { capability } => write!(
                f,
                "entry point removed — nothing here provides `{capability}`, which the run \
                 executed"
            ),
            Self::NotConcluded => {
                f.write_str("not concluded — the run has no recorded ending to verify")
            }
            Self::EndedByAnAct { outcome } => write!(
                f,
                "ended by an act — the run is `{outcome}`, which its own steps did not decide"
            ),
        }
    }
}

fn revision(f: &mut std::fmt::Formatter<'_>, who: &str, r: &AgentIdentity) -> std::fmt::Result {
    writeln!(f, "  {who}: {} {} {}", r.name, r.version, r.digest)
}

/// The report block `agentplane replay --strict` prints, one per run.
impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let headline = match &self.finding {
            Finding::Verified { outcome } if self.same_revision() => {
                format!("verified — the recorded `{outcome}` ending was reproduced")
            }
            // Never "unchanged": this run's history reached nothing the edit
            // touched, which says nothing about the next input.
            Finding::Verified { outcome } => format!(
                "verified — no divergence on this run under a different declaration; the \
                 recorded `{outcome}` ending was reproduced"
            ),
            Finding::Diverged(_) => "diverged".to_owned(),
            Finding::OutcomeDiffers { recorded, replayed } => format!(
                "diverged — every effect matched, and the run ended `{replayed}` where it \
                 recorded `{recorded}`"
            ),
            Finding::CannotReplay(why) => format!("cannot replay: {why}"),
        };
        writeln!(f, "run {} — {headline}", self.run)?;
        match &self.recorded {
            Some(r) => revision(f, "recorded", r)?,
            None => writeln!(f, "  recorded: no declaration (a coded skill)")?,
        }
        match (&self.candidate, &self.recorded) {
            (Some(c), _) => {
                revision(f, "candidate", c)?;
                writeln!(
                    f,
                    "  ({})",
                    if self.same_revision() {
                        "same digest"
                    } else {
                        "different digest"
                    }
                )?;
            }
            (None, Some(r)) => writeln!(
                f,
                "  candidate: this plane holds no declaration named `{}`",
                r.name
            )?,
            (None, None) => {}
        }
        if let Finding::Diverged(d) = &self.finding {
            let kind = d.kind.as_deref().unwrap_or("an effect");
            let key = |k: Option<crate::core::EffectKey>| {
                k.map_or_else(|| "none".to_owned(), |k| k.to_string())
            };
            writeln!(
                f,
                "  first divergence: step {}, {} phase, `{kind}` — history {}, this build {}",
                d.step,
                d.phase.as_str(),
                key(d.recorded),
                key(d.recomputed),
            )?;
            writeln!(f, "  {}", d.detail)?;
        }
        Ok(())
    }
}
