//! The in-process half of [`Runtime::drain`](crate::runtime::Runtime::drain):
//! the set of runs this instance is executing, and the gate that closes
//! admission.
//!
//! What a drain promises a caller, and the three things it deliberately does
//! not cover, are documented on that method — this file is the mechanism.
//!
//! Two details here are load-bearing and invisible from the outside. The
//! waiter is registered **before** the emptiness check, or a run finishing
//! between the two notifies nobody and the drain waits out its whole grace
//! period with nothing left to wait for. And a run is registered **before**
//! admission rather than after, so a drain beginning inside admission's several
//! store writes cannot take a snapshot without it and report a complete stop.

use std::collections::BTreeSet;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::Notify;

use crate::core::RunId;

/// What a drain settled, and what it left for the next instance.
///
/// Returned by [`Runtime::drain`](crate::runtime::Runtime::drain).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrainReport {
    /// Background runs this instance was executing when the drain began.
    pub at_start: Vec<RunId>,
    /// Those still executing when the grace period ran out.
    ///
    /// Not a loss and not a backlog of its own: each is a run whose lease this
    /// instance still holds and will stop renewing, so it expires unreleased and
    /// the recovery sweep takes it over — the same path a crash takes. It is
    /// named here so an operator watching a deploy can see the price of the
    /// grace period they chose.
    pub unfinished: Vec<RunId>,
}

impl DrainReport {
    /// How many background runs reached a journaled resting point in time.
    ///
    /// Counted as a difference of *sets* rather than of lengths. The two lists
    /// are read at different instants, and a run admitted in the window between
    /// them appears in the second and not the first — a subtraction of counts
    /// would then underflow on a report that is otherwise correct.
    #[must_use]
    pub fn settled(&self) -> usize {
        self.at_start
            .iter()
            .filter(|run| !self.unfinished.contains(run))
            .count()
    }

    /// Whether every run this instance was executing finished first.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.unfinished.is_empty()
    }
}

/// The runs a process is executing on a task of its own, and the gate that
/// stops it taking on more.
///
/// The gate is not an optimisation. Without it a drain answers about an instant:
/// the set empties, the report says so, and a caller admits another run a
/// microsecond later — a report that was true when written and false when read.
/// Closing admission first is what makes the answer outlive the call.
#[derive(Debug, Default)]
pub(crate) struct InFlight {
    running: Mutex<BTreeSet<RunId>>,
    idle: Notify,
    draining: AtomicBool,
}

impl InFlight {
    /// Whether this instance has stopped admitting.
    pub(crate) fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Acquire)
    }

    /// Register a run as executing here until the returned ticket is dropped.
    ///
    /// Dropped rather than returned, so a panicking task deregisters too. A run
    /// that stayed registered after its task died would make every later drain
    /// wait out its whole grace period for a task nobody is running.
    pub(crate) fn enter(self: &std::sync::Arc<Self>, run: RunId) -> Ticket {
        crate::core::poison::recover(&self.running).insert(run);
        Ticket {
            inflight: std::sync::Arc::clone(self),
            run,
        }
    }

    fn leave(&self, run: RunId) {
        let empty = {
            let mut running = crate::core::poison::recover(&self.running);
            running.remove(&run);
            running.is_empty()
        };
        if empty {
            self.idle.notify_waiters();
        }
    }

    fn snapshot(&self) -> Vec<RunId> {
        crate::core::poison::recover(&self.running)
            .iter()
            .copied()
            .collect()
    }

    /// Close admission, then wait up to `grace` for the background runs to end.
    pub(crate) async fn drain(&self, grace: Duration) -> DrainReport {
        self.draining.store(true, Ordering::Release);
        let at_start = self.snapshot();
        let deadline = tokio::time::Instant::now() + grace;
        loop {
            // Registered before the emptiness check, or a run finishing between
            // the two would notify nobody and this would wait out the whole
            // grace period with nothing left to wait for.
            let waiter = self.idle.notified();
            tokio::pin!(waiter);
            waiter.as_mut().enable();
            if crate::core::poison::recover(&self.running).is_empty() {
                break;
            }
            tokio::select! {
                () = waiter => {}
                () = tokio::time::sleep_until(deadline) => break,
            }
        }
        DrainReport {
            at_start,
            unfinished: self.snapshot(),
        }
    }
}

/// A run's registration in [`InFlight`], released on drop.
pub(crate) struct Ticket {
    inflight: std::sync::Arc<InFlight>,
    run: RunId,
}

impl Drop for Ticket {
    fn drop(&mut self) {
        self.inflight.leave(self.run);
    }
}

#[cfg(test)]
mod tests {
    use super::{DrainReport, InFlight};
    use crate::core::RunId;
    use std::sync::Arc;
    use std::time::Duration;

    #[tokio::test]
    async fn a_drain_with_nothing_running_returns_at_once() {
        let inflight = Arc::new(InFlight::default());
        let report = inflight.drain(Duration::from_secs(30)).await;
        assert!(report.is_complete());
        assert_eq!(report.settled(), 0);
        assert!(inflight.is_draining());
    }

    /// The race the `enable()` call exists for: a ticket dropped while the drain
    /// is between its emptiness check and its wait would notify nobody.
    #[tokio::test]
    async fn a_run_that_ends_during_the_drain_is_not_waited_out() {
        let inflight = Arc::new(InFlight::default());
        let run = RunId::generate();
        let ticket = inflight.enter(run);
        let waiting = tokio::spawn({
            let inflight = Arc::clone(&inflight);
            async move { inflight.drain(Duration::from_secs(600)).await }
        });
        tokio::task::yield_now().await;
        drop(ticket);
        let report = waiting.await.expect("the drain task");
        assert_eq!(report.at_start, vec![run]);
        assert!(report.is_complete());
    }

    #[tokio::test]
    async fn a_run_that_outlasts_the_grace_period_is_named() {
        let inflight = Arc::new(InFlight::default());
        let run = RunId::generate();
        let _ticket = inflight.enter(run);
        let report = inflight.drain(Duration::from_millis(50)).await;
        assert_eq!(report.unfinished, vec![run]);
        assert_eq!(report.settled(), 0);
        assert!(!report.is_complete());
    }

    #[test]
    fn a_report_counts_what_settled_rather_than_what_started() {
        let (settled, stuck) = (RunId::generate(), RunId::generate());
        let report = DrainReport {
            at_start: vec![settled, stuck],
            unfinished: vec![stuck],
        };
        assert_eq!(report.settled(), 1);
        assert!(!report.is_complete());
    }

    /// The window a length subtraction would panic on.
    ///
    /// The two lists are read at different instants, so a run registered between
    /// them is in the second and not the first. Counting the difference of the
    /// *sets* makes that report merely unusual rather than an arithmetic
    /// underflow in the middle of somebody's shutdown.
    #[test]
    fn a_run_that_appeared_after_the_drain_began_does_not_underflow_the_count() {
        let report = DrainReport {
            at_start: Vec::new(),
            unfinished: vec![RunId::generate()],
        };
        assert_eq!(report.settled(), 0);
        assert!(!report.is_complete());
    }
}
