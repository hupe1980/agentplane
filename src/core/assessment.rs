//! A person's verdict on what a run answered.
//!
//! Recorded as a run of its own, never appended to the run it judges: a
//! concluded run is sealed, and an act about something is written the way
//! every other act about something is — so it carries the chain, the
//! signature, Merkle inclusion and the witness, and an offline reader checks
//! it without being taught what an assessment is.

use serde::{Deserialize, Serialize};

use crate::core::{Operator, RunId, Timestamp};

/// What a verdict says: yes or no, a number, or one of a few words.
///
/// Untagged on the wire, because a JSON boolean, number and string are already
/// three types a reader tells apart.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum Score {
    /// `helpful: true`.
    Pass(bool),
    /// A finite number on whatever scale the metric's name implies.
    Number(f64),
    /// One of a small set of words — `sent`, `edited`, `dismissed` — in the
    /// same grammar as a metric name, so it cannot carry prose.
    Label(String),
}

/// Why an assessment cannot be recorded as given.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AssessmentError {
    /// A metric name or label outside the token grammar.
    #[error(
        "'{0}' is not a metric name or label: 1 to 64 of a-z, 0-9, '.', '_' or '-', starting with a letter or digit"
    )]
    NotAToken(String),
    /// A number that is not finite.
    #[error("a score must be a finite number")]
    NotFinite,
    /// A rationale longer than a rationale.
    #[error("a rationale is limited to {max} bytes, and this one is {len}")]
    RationaleTooLong { len: usize, max: usize },
}

/// One person's verdict on one metric of one run.
///
/// Built only through [`new`](Self::new), so a name or label that would carry
/// prose — which stays clear and outlives an erasure — cannot reach a record.
#[derive(Debug, Clone, PartialEq)]
pub struct Assessment {
    of: RunId,
    name: String,
    value: Score,
    by: Operator,
    at: Timestamp,
    rationale: Option<String>,
}

impl Assessment {
    /// The run judged.
    #[must_use]
    pub const fn of(&self) -> RunId {
        self.of
    }

    /// What was judged — `helpful`, `action` — in the token grammar.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn value(&self) -> &Score {
        &self.value
    }

    /// Who judged, and what established it.
    #[must_use]
    pub const fn by(&self) -> &Operator {
        &self.by
    }

    #[must_use]
    pub const fn at(&self) -> Timestamp {
        self.at
    }

    /// Why, in their words — `None` when none was given, and when the words
    /// cannot be read here: erased with the judged run's data, or sealed to a
    /// key ring this plane does not hold.
    #[must_use]
    pub fn rationale(&self) -> Option<&str> {
        self.rationale.as_deref()
    }

    /// A verdict as the journal recorded it — the runtime's reader, which
    /// trusts the record rather than re-judging what an older build wrote.
    pub(crate) const fn recorded(
        of: RunId,
        name: String,
        value: Score,
        by: Operator,
        at: Timestamp,
        rationale: Option<String>,
    ) -> Self {
        Self {
            of,
            name,
            value,
            by,
            at,
            rationale,
        }
    }

    /// The parts, for the record that carries them.
    pub(crate) fn into_parts(self) -> (RunId, String, Score, Operator, Timestamp, Option<String>) {
        (
            self.of,
            self.name,
            self.value,
            self.by,
            self.at,
            self.rationale,
        )
    }

    /// The longest rationale an assessment carries, in bytes.
    pub const MAX_RATIONALE: usize = 4096;

    /// A verdict, checked.
    ///
    /// # Errors
    ///
    /// [`AssessmentError`] for a name or label outside the grammar, a number
    /// that is not finite, or a rationale over
    /// [`MAX_RATIONALE`](Self::MAX_RATIONALE).
    pub fn new(
        of: RunId,
        name: impl Into<String>,
        value: Score,
        by: Operator,
        at: Timestamp,
        rationale: Option<String>,
    ) -> Result<Self, AssessmentError> {
        let name = name.into();
        token(&name)?;
        match &value {
            Score::Label(label) => token(label)?,
            Score::Number(n) if !n.is_finite() => return Err(AssessmentError::NotFinite),
            Score::Pass(_) | Score::Number(_) => {}
        }
        if let Some(text) = &rationale
            && text.len() > Self::MAX_RATIONALE
        {
            return Err(AssessmentError::RationaleTooLong {
                len: text.len(),
                max: Self::MAX_RATIONALE,
            });
        }
        Ok(Self {
            of,
            name,
            value,
            by,
            at,
            rationale: rationale.filter(|text| !text.trim().is_empty()),
        })
    }
}

/// A metric name or a label: low-cardinality by construction.
fn token(text: &str) -> Result<(), AssessmentError> {
    let mut chars = text.chars();
    let lead = chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    let rest = chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "._-".contains(c));
    if lead && rest && text.len() <= 64 {
        Ok(())
    } else {
        Err(AssessmentError::NotAToken(text.to_owned()))
    }
}

/// Every assessment of one run, in log order.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Assessments {
    /// All of them — a verdict later replaced stays here, because what a
    /// person said and then withdrew is a fact a review asks about.
    pub history: Vec<Assessment>,
}

impl Assessments {
    /// The verdicts standing now: the last by each actor on each metric.
    ///
    /// Derived on every read; nothing marks an earlier verdict replaced.
    #[must_use]
    pub fn current(&self) -> Vec<&Assessment> {
        let mut standing: Vec<&Assessment> = Vec::new();
        for assessment in &self.history {
            if let Some(held) = standing
                .iter_mut()
                .find(|held| held.by == assessment.by && held.name == assessment.name)
            {
                *held = assessment;
            } else {
                standing.push(assessment);
            }
        }
        standing
    }
}

#[cfg(test)]
mod tests {
    use super::{Assessment, AssessmentError, Score};
    use crate::core::{Operator, RunId, Timestamp};

    fn at() -> Timestamp {
        Timestamp::from_unix_timestamp(1_760_000_000).unwrap()
    }

    fn by() -> Operator {
        Operator::authenticated("alice").unwrap()
    }

    #[test]
    fn prose_is_not_a_metric_or_a_label() {
        let run = RunId::generate();
        for bad in ["", "Helpful", "not helpful", "-x", &"a".repeat(65)] {
            assert!(
                matches!(
                    Assessment::new(run, bad, Score::Pass(true), by(), at(), None),
                    Err(AssessmentError::NotAToken(_))
                ),
                "'{bad}' was accepted as a metric name"
            );
        }
        assert!(
            Assessment::new(
                run,
                "action",
                Score::Label("sent as is".into()),
                by(),
                at(),
                None
            )
            .is_err()
        );
        assert!(Assessment::new(run, "helpful.v2", Score::Pass(false), by(), at(), None).is_ok());
    }

    #[test]
    fn a_number_must_be_finite() {
        let run = RunId::generate();
        assert_eq!(
            Assessment::new(run, "score", Score::Number(f64::NAN), by(), at(), None),
            Err(AssessmentError::NotFinite)
        );
    }
}
