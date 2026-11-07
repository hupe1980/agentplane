//! What a capability's runs came to over a window: how they ended, and what
//! people said about them.
//!
//! A reading for a catalog, never evidence. The store derives it from indexes
//! it writes with each run's admission and each verdict's seal, so it agrees
//! with the journal at every commit and a restore rebuilds it; nothing here is
//! signed.
//!
//! **The window selects runs, and everything counted is about those runs.** A
//! run is in the window when it was *admitted* in it — the instant minted into
//! its id, which travels with an export — and its conclusion and the verdicts
//! on it are counted as they stand now, whenever they were reached. So the
//! verdicts and the runs they judge are one cohort, and a share computed from
//! the two means what it says.

use std::collections::BTreeMap;

use crate::core::{Digest, Timestamp};

/// A capability's runs admitted in `[since, until)`, per declaration revision.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct TrackRecord {
    /// What the runs were asked for.
    pub capability: String,
    /// The first instant of the window.
    pub since: Timestamp,
    /// The first instant after it.
    pub until: Timestamp,
    /// One entry per revision that served a run in the window, ordered by
    /// revision; a run served with no declaration is the entry whose `agent`
    /// is `None`, first.
    pub revisions: Vec<RevisionRecord>,
}

impl TrackRecord {
    /// An empty record for this window.
    #[must_use]
    pub const fn new(capability: String, since: Timestamp, until: Timestamp) -> Self {
        Self {
            capability,
            since,
            until,
            revisions: Vec::new(),
        }
    }

    /// Every revision's track, together.
    #[must_use]
    pub fn total(&self) -> Track {
        let mut total = Track::default();
        for revision in &self.revisions {
            total.merge(&revision.track);
        }
        total
    }

    /// The track of `agent`'s revision, created empty on first use.
    ///
    /// What a store folds its rows into, so both backends build the record the
    /// same way.
    pub fn revision_mut(&mut self, agent: Option<Revision>) -> &mut Track {
        let at = match self
            .revisions
            .binary_search_by(|held| held.agent.cmp(&agent))
        {
            Ok(at) => at,
            Err(at) => {
                self.revisions.insert(
                    at,
                    RevisionRecord {
                        agent,
                        track: Track::default(),
                    },
                );
                at
            }
        };
        &mut self.revisions[at].track
    }
}

/// The written run ids bounding `[since, until)`, or `None` for an empty
/// window: the first id of each bound's millisecond. A run id's text sorts by
/// the instant minted into it, so a window is one range of an index keyed by
/// it — under byte comparison.
pub(crate) fn run_window(since: Timestamp, until: Timestamp) -> Option<(String, String)> {
    let from = crate::core::RunId::first_at(since).to_string();
    let to = crate::core::RunId::first_at(until).to_string();
    (from < to).then_some((from, to))
}

/// The runs one declaration revision served.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct RevisionRecord {
    /// The declaration that governed them, or `None` for a skill registered
    /// with no manifest.
    pub agent: Option<Revision>,
    pub track: Track,
}

/// One revision of a declaration: what `RunAdmitted.governed_by` names.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub struct Revision {
    /// `metadata.name`.
    pub name: String,
    /// `metadata.version`, as the author typed it.
    pub version: String,
    /// The digest over the declaration's canonical bytes: what tells two
    /// revisions apart when the version was not bumped.
    pub digest: Digest,
}

impl Revision {
    #[must_use]
    pub const fn new(name: String, version: String, digest: Digest) -> Self {
        Self {
            name,
            version,
            digest,
        }
    }
}

/// Runs and the verdicts on them, counted.
#[derive(Debug, Clone, PartialEq, Default)]
#[non_exhaustive]
pub struct Track {
    /// Runs admitted.
    pub admitted: u64,
    /// Runs by how they stand concluded now — the last conclusion, so a run
    /// that failed and then succeeded on resume is counted once, as
    /// succeeded. A run still working is in none.
    pub outcomes: BTreeMap<String, u64>,
    /// The standing verdicts on these runs, by metric: each person's last in
    /// log order on each run.
    pub metrics: BTreeMap<String, MetricSummary>,
}

impl Track {
    /// Runs admitted that have not concluded.
    #[must_use]
    pub fn open(&self) -> u64 {
        self.admitted
            .saturating_sub(self.outcomes.values().sum::<u64>())
    }

    /// Add `other`'s counts to these.
    pub fn merge(&mut self, other: &Self) {
        self.admitted += other.admitted;
        for (outcome, runs) in &other.outcomes {
            *self.outcomes.entry(outcome.clone()).or_default() += runs;
        }
        for (metric, summary) in &other.metrics {
            self.metrics
                .entry(metric.clone())
                .or_default()
                .merge(summary);
        }
    }
}

/// The standing verdicts on one metric.
#[derive(Debug, Clone, PartialEq, Default)]
#[non_exhaustive]
pub struct MetricSummary {
    /// Runs with at least one standing verdict on this metric.
    pub runs: u64,
    /// `true` verdicts.
    pub passed: u64,
    /// `false` verdicts.
    pub failed: u64,
    /// Label verdicts, by label.
    pub labels: BTreeMap<String, u64>,
    /// Number verdicts, if any.
    pub numbers: Option<NumberSummary>,
}

impl MetricSummary {
    /// Every standing verdict on this metric, of whatever kind.
    #[must_use]
    pub fn verdicts(&self) -> u64 {
        self.passed
            + self.failed
            + self.labels.values().sum::<u64>()
            + self.numbers.as_ref().map_or(0, |n| n.count)
    }

    /// Add `other`'s counts to these.
    pub fn merge(&mut self, other: &Self) {
        self.runs += other.runs;
        self.passed += other.passed;
        self.failed += other.failed;
        for (label, count) in &other.labels {
            *self.labels.entry(label.clone()).or_default() += count;
        }
        if let Some(theirs) = &other.numbers {
            match &mut self.numbers {
                Some(ours) => ours.merge(theirs),
                None => self.numbers = Some(theirs.clone()),
            }
        }
    }
}

/// Number verdicts: how many, their total, and the least and greatest. The
/// count and the bounds are exact; the total is a floating-point sum, and past
/// the range of `f64` it is infinite.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct NumberSummary {
    pub count: u64,
    pub sum: f64,
    pub min: f64,
    pub max: f64,
}

impl NumberSummary {
    #[must_use]
    pub const fn new(count: u64, sum: f64, min: f64, max: f64) -> Self {
        Self {
            count,
            sum,
            min,
            max,
        }
    }

    /// The mean, or `None` with nothing counted.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn mean(&self) -> Option<f64> {
        (self.count > 0).then(|| self.sum / self.count as f64)
    }

    /// Add `other`'s numbers to these.
    pub fn merge(&mut self, other: &Self) {
        self.count += other.count;
        self.sum += other.sum;
        self.min = self.min.min(other.min);
        self.max = self.max.max(other.max);
    }
}

#[cfg(test)]
mod tests {
    use super::{MetricSummary, NumberSummary, Revision, Track, TrackRecord};
    use crate::core::{Digest, Timestamp};

    fn at(s: i64) -> Timestamp {
        Timestamp::from_unix_timestamp(s).unwrap()
    }

    #[test]
    fn the_total_folds_every_revision_and_open_is_what_did_not_conclude() {
        let mut record = TrackRecord::new("triage".into(), at(0), at(10));
        let v1 = Revision::new("triage".into(), "1".into(), Digest::ZERO);
        {
            let t = record.revision_mut(Some(v1.clone()));
            t.admitted = 3;
            t.outcomes.insert("succeeded".into(), 2);
            t.metrics.insert(
                "score".into(),
                MetricSummary {
                    runs: 1,
                    numbers: Some(NumberSummary::new(1, 4.0, 4.0, 4.0)),
                    ..MetricSummary::default()
                },
            );
        }
        {
            let t = record.revision_mut(None);
            t.admitted = 2;
            t.outcomes.insert("failed".into(), 1);
            t.metrics.insert(
                "score".into(),
                MetricSummary {
                    runs: 1,
                    passed: 1,
                    numbers: Some(NumberSummary::new(1, 1.0, 1.0, 1.0)),
                    ..MetricSummary::default()
                },
            );
        }
        assert_eq!(record.revisions[0].agent, None, "undeclared sorts first");
        assert_eq!(
            record.revision_mut(Some(v1)).admitted,
            3,
            "found, not added"
        );
        assert_eq!(record.revisions.len(), 2);

        let total: Track = record.total();
        assert_eq!(total.admitted, 5);
        assert_eq!(total.open(), 2);
        let score = &total.metrics["score"];
        assert_eq!(score.runs, 2);
        assert_eq!(score.verdicts(), 3);
        let numbers = score.numbers.as_ref().unwrap();
        assert_eq!((numbers.min, numbers.max), (1.0, 4.0));
        assert_eq!(numbers.mean(), Some(2.5));
    }
}
