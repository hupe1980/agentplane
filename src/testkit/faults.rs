//! A store that fails on purpose, deterministically.
//!
//! # Why this is not `madsim`
//!
//! Deterministic simulation in the `FoundationDB` / `TigerBeetle` lineage
//! normally means replacing the async runtime, so that every task interleaving
//! and every network packet is under a seeded scheduler. The Rust ecosystem
//! offers `madsim` for this, and it is good work — but it is aimed at a shape
//! this crate does not have.
//!
//! `madsim`'s leverage is the runtime and the network. This crate touches
//! `tokio` at three call sites and has no network at all: the plane is a library
//! embedded in someone else's process. Meanwhile the component whose failures
//! actually matter here is the **store**, and a store is the one thing a
//! simulated runtime cannot simulate — a real one is a C library writing to a
//! real disk.
//!
//! The precondition `madsim` exists to create is already true here for other
//! reasons: ambient clock, ambient RNG, and ambient I/O are lint-denied, the
//! calendar is a seam, the per-step RNG is seeded from `(run, step)`, and every
//! store is a trait. Determinism is the expensive half of simulation, and this
//! crate pays it as a design rule rather than as a dependency. What remains is
//! injecting faults, and the right place to inject them is the seam that has
//! them — which is this one.
//!
//! # The fault this exists for
//!
//! `tests/engine/simulation.rs` sweeps crash points by truncating a journal, on the
//! reasoning that every prefix of an append-only history is a crash that could
//! have happened. That is true, and it is not the whole space, because **a
//! truncation is always clean**. It cannot produce the state where a write
//! *committed* and the caller never found out: connection lost after commit,
//! the process killed between `COMMIT` and the syscall returning, a proxy
//! timing out a request the database went on to apply.
//!
//! That state is [`Fault::CommittedThenLost`], and it is the store-level twin of
//! the in-doubt effect the specs model at the world level: the write is durable,
//! the writer believes it failed, and retrying blindly is how a chain acquires a
//! second copy of the same record. It is unreachable by prefix truncation and it
//! is the most dangerous thing a store can do, so it is the reason this file
//! exists.
//!
//! # Determinism
//!
//! A fault schedule is a seed, not a coin. [`Faulty`] derives each decision from
//! `H(seed ‖ call-ordinal)`, so a failing schedule is a number that reproduces
//! forever, and two runs of the same seed fail in the same place. Nothing here
//! reads the ambient clock or the ambient RNG — the determinism gate in
//! `clippy.toml` applies to this module exactly as it does to the runtime.

use std::fmt::Debug;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use sha2::{Digest as _, Sha256};

use crate::core::{Digest, Epoch, RunId, Seq, StoreError};
use crate::journal::{Append, Head, JournalStore, Lease, Record};

/// What a store can do to a caller besides working.
///
/// Ordered by how hard each is to survive, which is also the order in which a
/// runtime tends to stop handling them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Fault {
    /// The call fails and nothing was written.
    ///
    /// The benign case: retrying is correct and the journal is unchanged.
    /// Present so that a schedule can contain faults a runtime *should* shrug
    /// off, and so a test can tell "handled it" from "never saw one".
    FailedClean,

    /// The call fails and the write **committed anyway**.
    ///
    /// The reason this module exists. Unreachable by truncating a journal,
    /// because a truncation is a clean cut and this is not: the record is
    /// durably present while the caller holds an `Err`. A runtime that responds
    /// by retrying the append writes the record twice, and the chain now has two
    /// entries claiming the same position in history.
    ///
    /// Surviving this is not about retry policy. It is about the write being
    /// identifiable — which is what the store's exactly-once constraint on
    /// `EffectStarted` is for, and why a chain is verified rather than trusted.
    CommittedThenLost,

    /// The call fails after the lease was taken by someone else.
    ///
    /// Models the pause that fencing exists for: this instance stalled, its
    /// lease expired, another instance claimed the run, and the first one wakes
    /// up still believing it owns the chain.
    Fenced,
}

/// How often to fail, and with what.
///
/// A schedule is deliberately not a probability distribution over "some errors".
/// It is a list of (call ordinal, fault) pairs, because the interesting
/// question is never "does it survive 5 % failures" — it is "does it survive a
/// [`Fault::CommittedThenLost`] on *the append that records the effect*".
#[derive(Debug, Clone, Default)]
pub struct Schedule {
    seed: u64,
    every: Option<(u64, Fault)>,
    at: Vec<(u64, Fault)>,
    on_kind: Vec<(&'static str, Fault)>,
    unreadable: Vec<RunId>,
    leafless: Vec<RunId>,
}

impl Schedule {
    /// A schedule that never fails. Build faults onto it.
    #[must_use]
    pub const fn healthy() -> Self {
        Self {
            seed: 0,
            every: None,
            at: Vec::new(),
            on_kind: Vec::new(),
            unreadable: Vec::new(),
            leafless: Vec::new(),
        }
    }

    /// Reproduce a previous run's schedule.
    ///
    /// The seed is the whole reproduction artifact for the parts of a schedule
    /// that are derived rather than pinned.
    #[must_use]
    pub const fn seeded(seed: u64) -> Self {
        Self {
            seed,
            every: None,
            at: Vec::new(),
            on_kind: Vec::new(),
            unreadable: Vec::new(),
            leafless: Vec::new(),
        }
    }

    /// Make one run unreadable, as a damaged page or a lost shard would.
    ///
    /// Reads had no fault injection at all, and the omission had a shape: this
    /// module was written for the append path, where the interesting failure is
    /// a write that lands while the caller is told it did not. But a *reader* of
    /// history — an audit, an export, a recovery — has its own bad state, and it
    /// is one a healthy store never produces on request, so a test that wants it
    /// cannot get there by asking for a run that does not exist. Both backends
    /// answer an unknown run with an empty read rather than an error, which is
    /// correct and is exactly why the absent case needs injecting.
    #[must_use]
    pub fn unreadable(mut self, run: RunId) -> Self {
        self.unreadable.push(run);
        self
    }

    /// Answer no inclusion for one run, as a log whose leaf was dropped would.
    ///
    /// A healthy store cannot produce this state on request — sealing always
    /// writes the leaf — and it is precisely the state an audit exists to name:
    /// a run whose own records carry a sealing conclusion, in a log that no
    /// longer commits to it. Without injection, the finding for the most
    /// serious integrity state an audit reports would be reachable by no test.
    #[must_use]
    pub fn leafless(mut self, run: RunId) -> Self {
        self.leafless.push(run);
        self
    }

    /// Fail the *n*-th append (1-based) with `fault`.
    #[must_use]
    pub fn at(mut self, n: u64, fault: Fault) -> Self {
        self.at.push((n, fault));
        self
    }

    /// Fail any append whose batch contains a record of this kind.
    ///
    /// More useful than an ordinal in most tests: "fail the append that records
    /// the effect" is a statement about meaning, and it does not silently start
    /// pointing at a different append when the runtime's write pattern changes.
    #[must_use]
    pub fn on_kind(mut self, kind: &'static str, fault: Fault) -> Self {
        self.on_kind.push((kind, fault));
        self
    }

    /// Fail every *n*-th append.
    #[must_use]
    pub const fn every(mut self, n: u64, fault: Fault) -> Self {
        self.every = Some((n, fault));
        self
    }

    /// The decision for call `n`, derived rather than drawn.
    fn decide(&self, n: u64, kinds: &[&str]) -> Option<Fault> {
        for &(at, fault) in &self.at {
            if at == n {
                return Some(fault);
            }
        }
        for &(kind, fault) in &self.on_kind {
            if kinds.contains(&kind) {
                return Some(fault);
            }
        }
        let (period, fault) = self.every?;
        // Derived from the seed so that two schedules with the same period but
        // different seeds do not fail in lockstep.
        let mut h = Sha256::new();
        h.update(self.seed.to_be_bytes());
        h.update(n.to_be_bytes());
        let d = h.finalize();
        let draw = u64::from_be_bytes(d[..8].try_into().unwrap_or([0; 8]));
        (period != 0 && draw % period == 0).then_some(fault)
    }
}

/// Wraps any [`JournalStore`] and fails it on a schedule.
///
/// Reads are never faulted. A read that fails is a retry and nothing more; the
/// asymmetry is the point, because only a write can leave the world and the
/// caller disagreeing about what happened.
#[derive(Debug)]
pub struct Faulty {
    inner: Arc<dyn JournalStore>,
    schedule: Schedule,
    calls: AtomicU64,
    injected: Arc<std::sync::Mutex<Vec<(u64, Fault)>>>,
    runs: Arc<std::sync::Mutex<Vec<RunId>>>,
}

impl Faulty {
    /// Wrap a store.
    #[must_use]
    pub fn new(inner: Arc<dyn JournalStore>, schedule: Schedule) -> Self {
        Self {
            inner,
            schedule,
            calls: AtomicU64::new(0),
            injected: Arc::new(std::sync::Mutex::new(Vec::new())),
            runs: Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    /// The faults actually delivered, in order.
    ///
    /// A fault-injection test that never injected anything passes for the wrong
    /// reason, and that is not visible from the assertions. Every test here
    /// asserts on this before asserting on behaviour.
    #[must_use]
    pub fn injected(&self) -> Vec<(u64, Fault)> {
        self.injected
            .lock()
            .map_or_else(|e| e.into_inner().clone(), |g| g.clone())
    }

    /// Run ids this store has been asked to write, in first-seen order.
    ///
    /// A run whose *first* write is broken never returns an id to its caller,
    /// and a fault test still has to find the journal it damaged. Reading it off
    /// the store is the only place it exists.
    #[must_use]
    pub fn runs(&self) -> Vec<RunId> {
        self.runs
            .lock()
            .map_or_else(|e| e.into_inner().clone(), |g| g.clone())
    }

    fn record(&self, n: u64, fault: Fault) {
        if let Ok(mut g) = self.injected.lock() {
            g.push((n, fault));
        }
    }
}

#[async_trait]
impl JournalStore for Faulty {
    /// What it wraps. Injecting faults does not change the topology, and a
    /// fault harness that claimed otherwise would test a different plane.
    fn is_shared(&self) -> bool {
        self.inner.is_shared()
    }

    /// The wrapped store's atomic capability, passed through undamaged.
    ///
    /// The trait's default answers `None`, so leaving this to the default
    /// silently *removed* a capability: a plane whose backend offers atomic
    /// effect enrolment lost it the moment a test wrapped the store in faults,
    /// and the fault suite exercised a differently-wired plane than the one
    /// production runs. Note what this does NOT do: the atomic handle returned
    /// here is the inner store's own, so faults are never injected on the
    /// atomic path — the schedule covers `append` only.
    fn atomic(&self) -> Option<&dyn crate::journal::AtomicJournal> {
        self.inner.atomic()
    }

    /// The wrapped store's tenant, passed through undamaged.
    ///
    /// Taking the default instead would make a faulty wrapper around a
    /// tenant-scoped store *misreport* who it serves — and the runtime
    /// builder's startup check, which exists to refuse exactly that mismatch,
    /// would refuse a correctly-scoped store or admit a wrongly-scoped one
    /// depending on which side wore the wrapper.
    fn tenant(&self) -> &str {
        self.inner.tenant()
    }

    async fn append(&self, epoch: Epoch, batch: Vec<Append>) -> Result<Vec<Record>, StoreError> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        let kinds: Vec<&str> = batch.iter().map(|a| a.kind.kind_str()).collect();
        if let (Some(a), Ok(mut seen)) = (batch.first(), self.runs.lock())
            && !seen.contains(&a.run)
        {
            seen.push(a.run);
        }

        match self.schedule.decide(n, &kinds) {
            None => self.inner.append(epoch, batch).await,

            // Nothing was written, so the caller's `Err` is the truth.
            Some(f @ Fault::FailedClean) => {
                self.record(n, f);
                Err(StoreError::Backend(
                    "injected: append failed, nothing written".into(),
                ))
            }

            // The write lands and the caller is told it did not. Everything
            // downstream must cope with a journal that is ahead of what the
            // process believes it wrote.
            Some(f @ Fault::CommittedThenLost) => {
                self.inner.append(epoch, batch).await?;
                self.record(n, f);
                Err(StoreError::Backend(
                    "injected: connection lost after commit".into(),
                ))
            }

            Some(f @ Fault::Fenced) => {
                self.record(n, f);
                Err(StoreError::Fenced {
                    run: batch
                        .first()
                        .map_or_else(String::new, |a| a.run.to_string()),
                    held: epoch,
                    current: epoch + 1,
                })
            }
        }
    }

    async fn read(&self, run: RunId, from: Seq) -> Result<Vec<Record>, StoreError> {
        if self.schedule.unreadable.contains(&run) {
            return Err(StoreError::Backend(format!(
                "injected: run {run} cannot be read"
            )));
        }
        self.inner.read(run, from).await
    }

    async fn admitted_as(&self, key: &str) -> Result<Option<crate::core::RunId>, StoreError> {
        self.inner.admitted_as(key).await
    }

    async fn forget_admissions(
        &self,
        older_than: crate::core::Timestamp,
    ) -> Result<usize, StoreError> {
        self.inner.forget_admissions(older_than).await
    }

    async fn runs_by_outcome(
        &self,
        outcome: &str,
        limit: usize,
    ) -> Result<Vec<crate::core::RunId>, StoreError> {
        self.inner.runs_by_outcome(outcome, limit).await
    }

    async fn recent_runs(
        &self,
        after: Option<(u64, RunId)>,
        limit: usize,
    ) -> Result<Vec<(RunId, u64)>, StoreError> {
        self.inner.recent_runs(after, limit).await
    }

    async fn case_history(
        &self,
        case: crate::core::CaseId,
        limit: usize,
    ) -> Result<Vec<Record>, StoreError> {
        self.inner.case_history(case, limit).await
    }

    async fn head(&self, run: RunId) -> Result<Head, StoreError> {
        self.inner.head(run).await
    }

    async fn acquire(&self, run: RunId, owner: &str, ttl: Duration) -> Result<Lease, StoreError> {
        self.inner.acquire(run, owner, ttl).await
    }

    async fn renew(
        &self,
        run: RunId,
        owner: &str,
        epoch: Epoch,
        ttl: Duration,
    ) -> Result<Lease, StoreError> {
        self.inner.renew(run, owner, epoch, ttl).await
    }

    async fn release_lease(&self, run: RunId, epoch: Epoch) -> Result<(), StoreError> {
        self.inner.release_lease(run, epoch).await
    }

    async fn abandoned_runs(&self, limit: usize) -> Result<Vec<RunId>, StoreError> {
        self.inner.abandoned_runs(limit).await
    }

    async fn seal(&self, run: RunId, epoch: Epoch, outcome: &str) -> Result<Digest, StoreError> {
        self.inner.seal(run, epoch, outcome).await
    }

    async fn checkpoint(&self) -> Result<crate::journal::Checkpoint, StoreError> {
        self.inner.checkpoint().await
    }

    async fn consistency_proof(&self, old_size: u64) -> Result<Vec<Digest>, StoreError> {
        self.inner.consistency_proof(old_size).await
    }

    async fn inclusion_proof(
        &self,
        run: RunId,
    ) -> Result<Option<crate::journal::Inclusion>, StoreError> {
        if self.schedule.leafless.contains(&run) {
            return Ok(None);
        }
        self.inner.inclusion_proof(run).await
    }

    // Stop requests pass through unfaulted. The schedule injects faults on
    // *appends*, because that is where a lost commit changes what the runtime
    // may conclude; a dropped stop request is an operator retrying a click.
    async fn request_cancel(
        &self,
        run: RunId,
        actor: &str,
        reason: &str,
    ) -> Result<bool, StoreError> {
        self.inner.request_cancel(run, actor, reason).await
    }

    async fn cancellation(
        &self,
        run: RunId,
    ) -> Result<Option<crate::journal::Cancellation>, StoreError> {
        self.inner.cancellation(run).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A store that offers the atomic capability and a scoped tenant.
    ///
    /// Only `atomic()` and `tenant()` matter here; every data method is
    /// unreachable in this test and says so. The stub exists because neither
    /// capability can be observed through a backend the test suite can build
    /// in-process — redb offers no atomic journal — and the trait's *defaults*
    /// are exactly the wrong answers a forgetful wrapper would give.
    #[derive(Debug)]
    struct Capable;

    #[async_trait]
    impl crate::journal::AtomicJournal for Capable {
        async fn append_atomic(
            &self,
            _run: RunId,
            _epoch: Epoch,
            _work: &dyn crate::journal::AtomicWork,
        ) -> Result<Vec<Record>, StoreError> {
            Err(StoreError::Backend("the test never commits".into()))
        }
    }

    #[async_trait]
    impl JournalStore for Capable {
        fn is_shared(&self) -> bool {
            true
        }
        fn atomic(&self) -> Option<&dyn crate::journal::AtomicJournal> {
            Some(self)
        }
        // The literal is the point: the stub must answer something other
        // than the trait default, and the trait's signature fixes the
        // lifetime whether or not the value here is 'static.
        #[allow(clippy::unnecessary_literal_bound)]
        fn tenant(&self) -> &str {
            "acme"
        }
        async fn append(&self, _: Epoch, _: Vec<Append>) -> Result<Vec<Record>, StoreError> {
            unreachable!("the test reads capabilities only")
        }
        async fn read(&self, _: RunId, _: Seq) -> Result<Vec<Record>, StoreError> {
            unreachable!("the test reads capabilities only")
        }
        async fn runs_by_outcome(&self, _: &str, _: usize) -> Result<Vec<RunId>, StoreError> {
            unreachable!("the test reads capabilities only")
        }
        async fn admitted_as(&self, _: &str) -> Result<Option<RunId>, StoreError> {
            unreachable!("the test reads capabilities only")
        }
        async fn forget_admissions(&self, _: crate::core::Timestamp) -> Result<usize, StoreError> {
            unreachable!("the test reads capabilities only")
        }
        async fn recent_runs(
            &self,
            _: Option<(u64, RunId)>,
            _: usize,
        ) -> Result<Vec<(RunId, u64)>, StoreError> {
            unreachable!("the test reads capabilities only")
        }
        async fn case_history(
            &self,
            _: crate::core::CaseId,
            _: usize,
        ) -> Result<Vec<Record>, StoreError> {
            unreachable!("the test reads capabilities only")
        }
        async fn head(&self, _: RunId) -> Result<Head, StoreError> {
            unreachable!("the test reads capabilities only")
        }
        async fn acquire(&self, _: RunId, _: &str, _: Duration) -> Result<Lease, StoreError> {
            unreachable!("the test reads capabilities only")
        }
        async fn renew(
            &self,
            _: RunId,
            _: &str,
            _: Epoch,
            _: Duration,
        ) -> Result<Lease, StoreError> {
            unreachable!("the test reads capabilities only")
        }
        async fn abandoned_runs(&self, _: usize) -> Result<Vec<RunId>, StoreError> {
            unreachable!("the test reads capabilities only")
        }
        async fn release_lease(&self, _: RunId, _: Epoch) -> Result<(), StoreError> {
            unreachable!("the test reads capabilities only")
        }
        async fn seal(&self, _: RunId, _: Epoch, _: &str) -> Result<Digest, StoreError> {
            unreachable!("the test reads capabilities only")
        }
        async fn checkpoint(&self) -> Result<crate::journal::Checkpoint, StoreError> {
            unreachable!("the test reads capabilities only")
        }
        async fn consistency_proof(&self, _: u64) -> Result<Vec<Digest>, StoreError> {
            unreachable!("the test reads capabilities only")
        }
        async fn inclusion_proof(
            &self,
            _: RunId,
        ) -> Result<Option<crate::journal::Inclusion>, StoreError> {
            unreachable!("the test reads capabilities only")
        }
        async fn request_cancel(&self, _: RunId, _: &str, _: &str) -> Result<bool, StoreError> {
            unreachable!("the test reads capabilities only")
        }
        async fn cancellation(
            &self,
            _: RunId,
        ) -> Result<Option<crate::journal::Cancellation>, StoreError> {
            unreachable!("the test reads capabilities only")
        }
    }

    /// The wrapper forwards capabilities instead of shadowing them with the
    /// trait defaults.
    ///
    /// Delete either override in `Faulty` and one half of this fails: the
    /// default `atomic()` answers `None`, silently dropping the capability
    /// from every fault test, and the default `tenant()` answers the default
    /// tenant, misreporting a scoped store to the runtime builder's startup
    /// check.
    #[test]
    fn capabilities_pass_through_the_fault_wrapper() {
        let faulty = Faulty::new(Arc::new(Capable), Schedule::healthy());
        assert!(
            faulty.atomic().is_some(),
            "wrapping in faults dropped the atomic capability"
        );
        assert_eq!(
            faulty.tenant(),
            "acme",
            "wrapping in faults misreported the tenant"
        );
        assert!(faulty.is_shared(), "topology must pass through too");
    }
}
