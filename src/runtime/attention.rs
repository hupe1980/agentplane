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

/// How many subject ids one condition lists.
///
/// A condition is a pointer to a backlog, not the backlog: the listing verb for
/// each kind pages the rest. Ten is enough to act on the first ones without an
/// answer that grows with the incident.
pub const SUBJECTS_LISTED: usize = 10;

/// What a person does about a condition, in the vocabulary of each surface
/// that reports it.
///
/// Two strings rather than one, because the terminal and the operator API do
/// not have the same verbs: a remedy is only useful in the words of the
/// surface it was read on, and where that surface has no verb for it, it says
/// which one does. A remedy with nothing to run says `no verb:` and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Remedy {
    /// In `agentplane` verbs.
    pub cli: &'static str,
    /// In operator API routes, naming the `agentplane` verb where the API has
    /// none.
    pub http: &'static str,
}

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
    /// The ids the remedy acts on — a run, a task, a case and obligation, a
    /// message, a push registration — at most [`SUBJECTS_LISTED`], in the order
    /// the backlog lists them: newest first for run conclusions, most overdue
    /// first for waits and tasks.
    ///
    /// Every verb a remedy names takes an id, so a condition that counted its
    /// subjects without naming them would send the operator to a second
    /// listing before they could act on the first.
    pub subjects: Vec<String>,
    /// How many of [`found`](Self::found) are not in
    /// [`subjects`](Self::subjects).
    pub unlisted: usize,
    /// What the person this reaches actually does.
    pub remedy: Remedy,
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

    /// Record a condition when anything was found.
    ///
    /// `found` is passed beside `subjects` because one condition — a failed
    /// drill — has a verdict and no id to act on.
    fn note(
        &mut self,
        kind: &'static str,
        found: usize,
        subjects: impl IntoIterator<Item = String>,
        page: usize,
        remedy: Remedy,
    ) {
        if found > 0 {
            let subjects: Vec<String> = subjects.into_iter().take(SUBJECTS_LISTED).collect();
            self.conditions.push(Condition {
                kind,
                found,
                at_least: found >= page,
                unlisted: found.saturating_sub(subjects.len()),
                subjects,
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
    /// is the one a resume may clear alone, so it is listed only where the run
    /// stands on landed work no compensation undid. Beside those sit
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
        // Every run standing in a conclusion that waits on a person, for the
        // reservation check below: those are the holds nothing will release.
        let mut stopped = std::collections::BTreeSet::new();

        // The condition key beside the outcome it reads, rather than derived
        // from it by a second match with a catch-all: a fourth outcome added
        // to this list would have taken the wildcard and been reported to an
        // operator under the third one's name and the third one's remedy.
        for (outcome, kind, remedy) in [
            // Two causes share the outcome, and the reason on the run says
            // which: an effect nobody can decide, or a resume refused because
            // the declaration or policy bundle it was admitted under is not the
            // one this plane holds.
            (
                "quarantined",
                "run.quarantined",
                Remedy {
                    cli: "establish an undecided effect with `reconcile`, or bring back the \
                          declaration or policy bundle the run was admitted under — then \
                          `quarantine` to reopen or abandon",
                    http: "establish an undecided effect with \
                           `POST /runs/{run}/reconcile`, or bring back the declaration or \
                           policy bundle the run was admitted under — then \
                           `POST /runs/{run}/reopen` or `POST /runs/{run}/abandon`",
                },
            ),
            // Not *abandon*: that answers a doubt, and an exhaustion is not
            // one — `quarantine` refuses any run whose conclusion is
            // something else. The operator who is not raising the ceiling is
            // stopping the run.
            (
                "exhausted",
                "run.exhausted",
                Remedy {
                    cli: "raise the ceiling — or, stopped by a tool's rate ceiling, wait for \
                          its window to pass — and `replay`, or `cancel` the run",
                    http: "raise the ceiling — or, stopped by a tool's rate ceiling, wait \
                           for its window to pass — and resume the run with `agentplane \
                           replay` (this API does not resume runs), or \
                           `POST /runs/{run}/cancel`",
                },
            ),
            (
                "withheld",
                "run.withheld",
                Remedy {
                    cli: "lift the withdrawal with `halt --lift`, then `replay` — or \
                          `cancel` the run",
                    http: "lift the withdrawal with `POST /halts/lift`, then resume the \
                           run with `agentplane replay` — or `POST /runs/{run}/cancel`",
                },
            ),
        ] {
            let found = self
                .store()
                .runs_by_outcome(outcome, page)
                .await
                .map_err(RuntimeError::from_store)?;
            stopped.extend(found.iter().copied());
            out.note(
                kind,
                found.len(),
                found.iter().map(ToString::to_string),
                page,
                remedy,
            );
        }

        stopped.extend(self.failed_on_landed_work(&mut out, page).await?);
        self.held_by_stopped_runs(&mut out, &stopped, page).await?;

        let abandoned = self
            .store()
            .abandoned_runs(page)
            .await
            .map_err(RuntimeError::from_store)?;
        out.note(
            "run.abandoned",
            abandoned.len(),
            abandoned.iter().map(ToString::to_string),
            page,
            Remedy {
                cli: "no verb: the recovery sweep resumes these; one that keeps \
                      reappearing is a run nothing can drive",
                http: "no verb: the recovery sweep resumes these; one that keeps \
                       reappearing is a run nothing can drive",
            },
        );

        // Only the ones whose instant has passed. A run waiting for next
        // Tuesday is the system working, and a listing that called it a
        // finding would cry wolf every time somebody scheduled something.
        let overdue: Vec<String> = self
            .store()
            .waiting_runs(page)
            .await
            .map_err(RuntimeError::from_store)?
            .into_iter()
            .filter(|w| w.reason.until() <= at)
            .map(|w| w.run.to_string())
            .collect();
        out.note(
            "run.wait_expired",
            overdue.len(),
            overdue,
            page,
            Remedy {
                cli: "`replay` the run: it reaches the announced wait and re-arms it",
                http: "resume the run with `agentplane replay` (this API does not \
                       resume runs): it reaches the announced wait and re-arms it",
            },
        );

        self.backlogs(&mut out, page, at).await?;
        Ok(out)
    }

    /// Failed runs standing on landed work nothing undid.
    ///
    /// `failed` is left off the run conclusions because a resume may clear
    /// it — except where the run stands on landed work: the failing step's own
    /// mutation stays in the world until somebody finishes the run or unwinds
    /// it, and nothing drives either.
    async fn failed_on_landed_work(
        &self,
        out: &mut Attention,
        page: usize,
    ) -> Result<Vec<crate::core::RunId>, RuntimeError> {
        let failed = self
            .store()
            .runs_by_outcome("failed", page)
            .await
            .map_err(RuntimeError::from_store)?;
        let mut landed = Vec::new();
        for run in &failed {
            if self.holds_landed_work(*run).await? {
                landed.push(run.to_string());
            }
        }
        // The page bounds the failed runs read, not the ones found: a full
        // page of failures means there may be more on landed work, so the
        // count is a floor whenever that page filled.
        let ceiling = if failed.len() >= page {
            landed.len()
        } else {
            page
        };
        out.note(
            "run.failed_with_landed_work",
            landed.len(),
            landed,
            ceiling,
            Remedy {
                cli: "`replay` the run to finish its work, or `cancel` it to unwind what \
                      landed",
                http: "resume the run with `agentplane replay` (this API does not resume \
                       runs) to finish its work, or `POST /runs/{run}/cancel` to unwind \
                       what landed",
            },
        );

        Ok(failed)
    }

    /// Stopped runs still holding spend against the tenant's period.
    ///
    /// A reservation is released when its run concludes, so one held by a run
    /// that waits on a person is capacity nobody gets back until that person
    /// acts — and a period filled by them refuses every new run while
    /// settling nothing. A suspended run waiting on its own wait is not here:
    /// it will resume and spend what it holds, which is what holding it is for.
    async fn held_by_stopped_runs(
        &self,
        out: &mut Attention,
        stopped: &std::collections::BTreeSet<crate::core::RunId>,
        page: usize,
    ) -> Result<(), RuntimeError> {
        let Some(quotas) = self.quota_store_if_wired() else {
            out.not_checked.push(
                "quota reservations — this plane holds no quota store, so whether a \
                 stopped run holds part of the tenant's period was not established",
            );
            return Ok(());
        };
        let held = quotas
            .reservations(page)
            .await
            .map_err(RuntimeError::Store)?;
        let named: Vec<String> = held
            .iter()
            .filter(|h| stopped.contains(&h.run))
            .map(|h| h.run.to_string())
            .collect();
        // The page bounds the holds read, so a full page is a floor.
        let ceiling = if held.len() >= page {
            named.len()
        } else {
            page
        };
        out.note(
            "quota.held_by_stopped_run",
            named.len(),
            named,
            ceiling,
            Remedy {
                cli: "each holds spend its tenant's period cannot admit against until it \
                      concludes: answer the run's own condition — `replay` it to finish, \
                      `cancel` it, or answer its `quarantine` — and what it did not spend \
                      is released",
                http: "each holds spend its tenant's period cannot admit against until it \
                       concludes: resume it with `agentplane replay`, \
                       `POST /runs/{run}/cancel` it, or `POST /runs/{run}/abandon` a \
                       quarantine — and what it did not spend is released",
            },
        );
        Ok(())
    }

    /// The four backlogs that live outside the journal, each with a listing and
    /// a verb that empties it.
    ///
    /// Split from the run conclusions above because the two answer from
    /// different places: those read the journal every plane has, and these read
    /// stores a plane may not have been given — which is why every arm here has
    /// a `None` that says so rather than passing over it.
    #[allow(clippy::too_many_lines)]
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
                    breached.iter().map(|d| format!("{}/{}", d.case, d.name)),
                    page,
                    Remedy {
                        cli: "`acknowledge` the breach, saying what was done about it \
                              (each subject is <case>/<obligation>)",
                        http: "`POST /obligations/acknowledge` the breach, saying what \
                               was done about it (each subject is <case>/<obligation>)",
                    },
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
                    // A verdict, not a backlog: there is nothing to name.
                    std::iter::empty(),
                    // Not a page: there is one row, so it can never be a
                    // ceiling, and reporting it as one would be a lie in the
                    // shape of a number.
                    usize::MAX,
                    Remedy {
                        cli: "the last recovery rehearsal found unrecoverable references — \
                              re-run `drill` and resolve what it names",
                        http: "the last recovery rehearsal found unrecoverable references \
                               (`GET /drill` reads the verdict) — re-run it with \
                               `agentplane drill` and resolve what it names",
                    },
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
                    overdue.iter().map(|t| t.id.to_string()),
                    page,
                    Remedy {
                        cli: "`decide` them. Escalation is not an operator act — the \
                              sweeper widens the audience itself when the window closes",
                        http: "`POST /tasks/{task}/decide` them. Escalation is not an \
                               operator act — the sweeper widens the audience itself when \
                               the window closes",
                    },
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
                    dead.iter()
                        .map(|d| format!("{} {}", d.event.source, d.event.id)),
                    page,
                    Remedy {
                        cli: "no verb: the correlation key belongs to the emitter, so \
                              this is a diagnosis to carry to them (each subject is \
                              <source> <id>)",
                        http: "no verb: the correlation key belongs to the emitter, so \
                               this is a diagnosis to carry to them — `GET /dead-letters` \
                               lists what arrived",
                    },
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
                    parked
                        .iter()
                        .map(|p| format!("{}/{}", p.config.task, p.config.id)),
                    page,
                    Remedy {
                        cli: "fix the endpoint, then `rearm` the registration (each \
                              subject is <run>/<id>)",
                        http: "fix the endpoint, then `POST /push/rearm` the registration \
                               (each subject is <run>/<id>)",
                    },
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
