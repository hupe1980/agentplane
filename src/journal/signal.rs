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
    /// Runs a poller is already looking at, for a handle whose writer is
    /// another process.
    polled: Mutex<std::collections::HashSet<(String, RunId)>>,
    /// Every append in a tenant, for a follower of the whole feed.
    tenants: Mutex<HashMap<String, watch::Sender<u64>>>,
    /// Tenants a poller already watches as a whole.
    polled_all: Mutex<std::collections::HashSet<String>>,
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
        self.raise_all(tenant);
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

impl AppendSignals {
    /// Follow every run in `tenant`'s keyspace.
    pub fn subscribe_all(&self, tenant: &str) -> AppendWatch {
        let rx = self
            .tenants
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(tenant.to_owned())
            .or_insert_with(|| watch::channel(0).0)
            .subscribe();
        AppendWatch { rx }
    }

    /// Say that something in `tenant` appended. The value a follower sees is
    /// a count of raises, meaningful only as *it moved*.
    pub fn raise_all(&self, tenant: &str) {
        let tenants = self
            .tenants
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(tx) = tenants.get(tenant) {
            tx.send_modify(|seen| *seen = seen.wrapping_add(1));
        }
    }

    /// Whether anybody still follows the whole of `tenant`.
    pub fn followed_all(&self, tenant: &str) -> bool {
        self.tenants
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(tenant)
            .is_some_and(|tx| tx.receiver_count() > 0)
    }

    /// Take the one poller slot for the whole of `tenant`.
    pub fn claim_poll_all(&self, tenant: &str) -> bool {
        self.polled_all
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(tenant.to_owned())
    }

    /// Give the poller slot for the whole of `tenant` back.
    pub fn release_poll_all(&self, tenant: &str) {
        self.polled_all
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(tenant);
    }

    /// Whether anybody still follows `run`.
    pub fn followed(&self, tenant: &str, run: RunId) -> bool {
        self.runs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&(tenant.to_owned(), run))
            .is_some_and(|tx| tx.receiver_count() > 0)
    }

    /// Take the one poller slot for `run`; `false` when a poller holds it.
    pub fn claim_poll(&self, tenant: &str, run: RunId) -> bool {
        self.polled
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert((tenant.to_owned(), run))
    }

    /// Give the poller slot for `run` back.
    pub fn release_poll(&self, tenant: &str, run: RunId) {
        self.polled
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&(tenant.to_owned(), run));
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
