//! A hint that a run's journal grew: *look now*.
//!
//! It carries no record. A follower that wakes reads the journal from its own
//! cursor, so a missed wake-up costs one poll interval and a spurious one costs
//! one read. Neither loses anything, which is why this can be a hint and not a
//! second record of what happened.
//!
//! Raised only after the append is durable. A follower that woke and read
//! before the commit would see nothing new, take the wake-up as spent, and wait
//! for the next one with the record sitting unread.

use std::collections::HashMap;
use std::sync::Mutex;

use tokio::sync::watch;

use crate::core::RunId;

/// The per-run signals one store raises, shared by every handle onto the same
/// durable state.
#[derive(Debug, Default)]
pub struct AppendSignals {
    runs: Mutex<HashMap<(String, RunId), watch::Sender<u64>>>,
}

impl AppendSignals {
    /// Follow `run` in `tenant`'s keyspace.
    ///
    /// Subscribe **before** reading: an append between a read and a
    /// subscription would otherwise wake nobody.
    pub fn subscribe(&self, tenant: &str, run: RunId) -> AppendWatch {
        let mut runs = self
            .runs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let rx = runs
            .entry((tenant.to_owned(), run))
            .or_insert_with(|| watch::channel(0).0)
            .subscribe();
        AppendWatch { rx }
    }

    /// Say that `run` now ends at `head`. Call only after the append committed.
    ///
    /// A run nobody follows has no entry and costs a lookup. An entry whose
    /// followers have all gone is dropped here rather than kept for a run that
    /// may never append again.
    pub fn raise(&self, tenant: &str, run: RunId, head: u64) {
        let mut runs = self
            .runs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = (tenant.to_owned(), run);
        let Some(tx) = runs.get(&key) else { return };
        if tx.receiver_count() == 0 {
            runs.remove(&key);
            return;
        }
        // Never backwards: two raises can arrive out of order (a local one and
        // a notification for the same append), and a head that moved back would
        // wake a follower for nothing.
        tx.send_if_modified(|seen| {
            if head > *seen {
                *seen = head;
                true
            } else {
                false
            }
        });
    }
}

/// One follower of one run.
#[derive(Debug, Clone)]
pub struct AppendWatch {
    rx: watch::Receiver<u64>,
}

impl AppendWatch {
    /// Wait until the run's journal grows past what this follower last saw,
    /// and return the head it grew to.
    ///
    /// `None` when the store behind it has gone, which a follower takes as a
    /// reason to fall back to polling.
    pub async fn changed(&mut self) -> Option<u64> {
        self.rx.changed().await.ok()?;
        Some(*self.rx.borrow_and_update())
    }

    /// The highest head raised so far, `0` before the first.
    #[must_use]
    pub fn head(&self) -> u64 {
        *self.rx.borrow()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_run_nobody_follows_any_more_is_forgotten() {
        let signals = AppendSignals::default();
        let run = RunId::generate();
        drop(signals.subscribe("t", run));
        signals.raise("t", run, 1);
        assert!(signals.runs.lock().expect("lock").is_empty());
    }
}
