//! One question: does anything on this plane need a person right now.
//!
//! **Why this exists as a call rather than as four predicates.** A report knows
//! whether *it* found something — the sweep, the witness pass, the push run, a
//! batch — and each says so with its own `needs_attention`. What none of them
//! answers is the question an operator actually asks, which is about the plane
//! and not about an operation they just ran. Asked that way, it also reaches the
//! conditions no report has: a quarantine standing since last week, an
//! obligation nobody accounted for, a run whose wait expired while the process
//! that armed it was gone.
//!
//! **It is not a threshold.** Nothing here decides whether a backlog is large
//! enough to page somebody; that is a deployment's policy and this crate keeps
//! out of it. What this decides is the part a deployment cannot: *which*
//! conditions mean a person, and where each one is read from.

use crate::core::{RuntimeError, Timestamp};

/// One condition that currently wants a person, and what to do about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Condition {
    /// A stable key, so a script routes on the condition rather than on prose.
    pub kind: &'static str,
    /// How many were found **on the page that was read**. Paired with
    /// [`at_least`](Self::at_least) so a ceiling reads as a ceiling rather than
    /// as a total.
    pub found: usize,
    /// The page filled, so the real number is this or more.
    pub at_least: bool,
    /// What the person this reaches actually does.
    pub remedy: &'static str,
}

/// What on this plane needs a person, condition by condition.
///
/// **Named rather than summed.** An operator acts on *which* one, and a count
/// across conditions would be a number nobody can act on — three quarantines
/// and one dead letter is not "four" of anything.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Attention {
    /// Every condition that is currently true. Empty means nothing does.
    pub conditions: Vec<Condition>,
    /// What this pass could not establish, and why.
    ///
    /// A plane with no push store cannot answer about parked registrations, and
    /// an empty `conditions` list would otherwise read as *nothing is wrong*
    /// when the honest answer is *nobody looked*. The same rule `drill` and
    /// `verify` are held to.
    pub not_checked: Vec<&'static str>,
}

impl Attention {
    /// Whether anything needs a person.
    #[must_use]
    pub fn any(&self) -> bool {
        !self.conditions.is_empty()
    }

    fn note(&mut self, kind: &'static str, found: usize, page: usize, remedy: &'static str) {
        if found > 0 {
            self.conditions.push(Condition {
                kind,
                found,
                at_least: found >= page,
                remedy,
            });
        }
    }
}

impl super::Runtime {
    /// Does anything on this plane need a person right now, and which thing.
    ///
    /// **What counts is not a judgement made here twice.** It comes from the
    /// run vocabulary: `failed`, `exhausted`, `withheld` and `quarantined` all
    /// leave a run open, and three of them name a party who can answer — a
    /// raised ceiling, a lifted withdrawal, a person deciding a doubt. `failed`
    /// is the one a resume may clear alone, so it is absent. Beside those sit
    /// the backlogs that already have a listing and a verb that empties them.
    ///
    /// **The clock is the caller's** — the same decision the task listing and
    /// the push sweep make — so a fixed instant makes this testable and a
    /// deployment owns its cadence. `page` bounds every query, and a condition
    /// says whether its page filled rather than pretending to a total.
    ///
    /// # Errors
    ///
    /// If a store this plane *does* hold is unreachable: a backlog that cannot
    /// be read is not an empty one.
    pub async fn attention(&self, at: Timestamp, page: usize) -> Result<Attention, RuntimeError> {
        let mut out = Attention::default();

        // The condition key beside the outcome it reads, rather than derived
        // from it by a second match with a catch-all: a fourth outcome added
        // to this list would have taken the wildcard and been reported to an
        // operator under the third one's name and the third one's remedy.
        for (outcome, kind, remedy) in [
            (
                "quarantined",
                "run.quarantined",
                "establish the undecided effect with `reconcile`, then `quarantine` \
                 to reopen or abandon",
            ),
            // Not *abandon*: that answers a doubt, and an exhaustion is not
            // one — `quarantine` refuses any run whose conclusion is
            // something else. The operator who is not raising the ceiling is
            // stopping the run.
            (
                "exhausted",
                "run.exhausted",
                "raise the ceiling and `replay`, or `cancel` the run",
            ),
            (
                "withheld",
                "run.withheld",
                "lift the withdrawal with `halt --lift`, then `replay` — or `cancel` \
                 the run",
            ),
        ] {
            let found = self
                .store()
                .runs_by_outcome(outcome, page)
                .await
                .map_err(RuntimeError::from_store)?;
            out.note(kind, found.len(), page, remedy);
        }

        let abandoned = self
            .store()
            .abandoned_runs(page)
            .await
            .map_err(RuntimeError::from_store)?;
        out.note(
            "run.abandoned",
            abandoned.len(),
            page,
            "the recovery sweep resumes these; one that keeps reappearing is a \
             run nothing can drive",
        );

        // Only the ones whose instant has passed. A run waiting for next
        // Tuesday is the system working, and a listing that called it a
        // finding would cry wolf every time somebody scheduled something.
        let overdue = self
            .store()
            .waiting_runs(page)
            .await
            .map_err(RuntimeError::from_store)?
            .into_iter()
            .filter(|w| w.reason.until() <= at)
            .count();
        out.note(
            "run.wait_expired",
            overdue,
            page,
            "`replay` the run: it reaches the announced wait and re-arms it",
        );

        self.backlogs(&mut out, page, at).await?;
        Ok(out)
    }

    /// The four backlogs that live outside the journal, each with a listing and
    /// a verb that empties it.
    ///
    /// Split from the run conclusions above because the two answer from
    /// different places: those read the journal every plane has, and these read
    /// stores a plane may not have been given — which is why every arm here has
    /// a `None` that says so rather than passing over it.
    async fn backlogs(
        &self,
        out: &mut Attention,
        page: usize,
        now: Timestamp,
    ) -> Result<(), RuntimeError> {
        match self.cases() {
            Some(cases) => {
                let breached = cases
                    .breached(page)
                    .await
                    .map_err(RuntimeError::from_store)?;
                out.note(
                    "obligation.breached",
                    breached.len(),
                    page,
                    "`acknowledge` the breach, saying what was done about it",
                );
            }
            None => out.not_checked.push(
                "obligations — this plane holds no case store, so whether any went \
                 unaccounted for was not established",
            ),
        }

        // A recovery rehearsal that found unrecoverable references is the
        // clearest "somebody must look" this plane has, and it stays true
        // until a later drill passes — which is the point, not noise.
        //
        // Deliberately **not** raised for a plane that has never drilled: a
        // fresh plane is not broken, and a condition that fires on every new
        // deployment is one operators learn to clear without reading. Nor for
        // `not_checked`, which on a plane with no blob store is permanent and
        // would make this condition unclearable.
        match self.cases() {
            Some(cases) => {
                let failed = cases
                    .last_drill()
                    .await
                    .map_err(RuntimeError::from_store)?
                    .is_some_and(|d| !d.sound);
                out.note(
                    "drill.failed",
                    usize::from(failed),
                    // Not a page: there is one row, so it can never be a
                    // ceiling, and reporting it as one would be a lie in the
                    // shape of a number.
                    usize::MAX,
                    "the last recovery rehearsal found unrecoverable references — \
                     re-run `drill` and resolve what it names",
                );
            }
            None => out.not_checked.push(
                "recovery rehearsal — this plane holds no case store, so there is \
                 nothing to drill and no verdict to read",
            ),
        }

        match self.tasks() {
            Some(tasks) => {
                let overdue = tasks
                    .overdue(now, page)
                    .await
                    .map_err(RuntimeError::from_store)?;
                out.note(
                    "task.overdue",
                    overdue.len(),
                    page,
                    "`decide` them. Escalation is not an operator act — the sweeper widens \
                 the audience itself when the window closes",
                );
            }
            None => out.not_checked.push(
                "worklist — this plane holds no task store, so whether any approval is \
                 overdue was not established",
            ),
        }

        match self.events() {
            Some(events) => {
                let dead = events
                    .dead_letters(page)
                    .await
                    .map_err(RuntimeError::from_store)?;
                out.note(
                    "event.dead_lettered",
                    dead.len(),
                    page,
                    "nothing here resolves one: the correlation key belongs to the \
                     emitter, so this is a diagnosis to carry to them",
                );
            }
            None => out.not_checked.push(
                "dead letters — this plane holds no event store, so whether an inbound \
                 message went unclaimed was not established",
            ),
        }

        // Behind the feature, and *said* rather than silently absent: a build
        // without outbound delivery has no parked registrations to find, and a
        // reader comparing two planes' answers needs to know which of them
        // could even look.
        #[cfg(feature = "push")]
        match self.push() {
            Some(push) => {
                let parked = push.parked(page).await.map_err(RuntimeError::from_store)?;
                out.note(
                    "push.parked",
                    parked.len(),
                    page,
                    "fix the endpoint, then `rearm` the registration",
                );
            }
            None => out.not_checked.push(
                "push registrations — this plane holds no push store, so whether a \
                 worker gave up on one was not established",
            ),
        }
        #[cfg(not(feature = "push"))]
        out.not_checked
            .push("push registrations — this build has no outbound delivery");

        Ok(())
    }
}
