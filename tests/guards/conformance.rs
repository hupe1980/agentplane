//! The journal-store contract, checked against every backend this crate ships.
//!
//! One battery, in `testkit::conformance`, run here against each store. The
//! point is not that redb passes — it is the default backend, so the rest of the
//! suite exercises it constantly — but that the battery is *real*, so that when
//! a second backend is run against it a pass means something. The test below it
//! breaks one guarantee on purpose and requires the battery to notice.
//!
//! Postgres is checked separately, behind a container, so this run stays in the
//! fast path.

#![cfg(all(feature = "redb", feature = "testkit"))]

use std::sync::Arc;

use agentplane::journal::JournalStore;
use agentplane::store::RedbStore;
use agentplane::testkit::conformance;

/// **The built-in calendar against the contract every calendar carries.**
///
/// This is the seam most likely to be replaced: a real regulatory deadline is
/// working days in a named timezone with a holiday table, and none of that
/// belongs in a domain-agnostic engine. The replacement computes a legally
/// binding instant that nothing above it can check, so the battery is what an
/// implementer gets instead of a review.
#[test]
fn the_built_in_calendar_satisfies_the_contract() {
    use agentplane::core::{DeadlineSpec, WallClock};
    use agentplane::testkit::conformance::Report;
    use agentplane::testkit::conformance_calendar;

    let mut report = Report::default();
    conformance_calendar::check(
        &WallClock,
        &[
            DeadlineSpec::hours(24),
            DeadlineSpec::days(5),
            DeadlineSpec::new("minutes", serde_json::json!({ "n": 90 })),
        ],
        &mut report,
    );
    report.assert_conforms("WallClock");
}

/// **And the battery refuses a calendar that guesses.**
///
/// A conformance suite nothing can fail is the shape this project catalogues.
/// The double here is the calendar an implementer writes by accident: it
/// approximates a rule it does not know, and it hands a hostile count straight
/// to `time`'s arithmetic — which is the defect the built-in calendar shipped
/// with until it was found.
#[test]
fn the_calendar_battery_rejects_one_that_approximates() {
    use agentplane::core::{Calendar, CalendarError, DeadlineSpec, Digest, Timestamp};
    use agentplane::testkit::conformance::Report;
    use agentplane::testkit::conformance_calendar;

    #[derive(Debug)]
    struct Guesses;

    impl Calendar for Guesses {
        fn resolve(
            &self,
            from: Timestamp,
            spec: &DeadlineSpec,
        ) -> Result<Timestamp, CalendarError> {
            let n = spec
                .params
                .get("n")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(1);
            // Everything it does not know becomes days, and a count it finds
            // implausible is quietly clamped into range. Both are failures the
            // battery names: the first answers a rule it does not implement,
            // and the second turns a typo with no correct reading into an
            // obligation nobody will ever be warned about.
            let seconds = n.clamp(-3_650, 3_650).saturating_mul(86_400);
            from.checked_add(time::Duration::seconds(seconds))
                .ok_or_else(|| CalendarError::OutOfRange {
                    kind: spec.kind.clone(),
                })
        }

        fn digest(&self) -> Digest {
            Digest::of(b"guesses")
        }
    }

    let mut report = Report::default();
    conformance_calendar::check(&Guesses, &[DeadlineSpec::days(5)], &mut report);
    let named: Vec<&str> = report.violations.iter().map(|v| v.invariant).collect();
    assert!(
        named.contains(&"an unknown rule is refused, never approximated"),
        "the battery accepted a calendar that answers rules it does not implement: \
         {named:?}"
    );
    assert!(
        named.contains(&"a count no instant can carry is refused"),
        "the battery accepted a calendar that clamps a count into range, so the \
         hostile half of it reaches nothing: {named:?}"
    );
}

#[tokio::test]
async fn redb_satisfies_the_journal_store_contract() {
    // Signing is switched on for the whole battery, not only for the check that
    // is about it. Two reasons: the attestation round-trip check would otherwise
    // skip itself against an unsigned store and report success having asserted
    // nothing, and running every other check against a signing store proves
    // signing does not disturb fencing, exactly-once, or chaining.
    let report = conformance::check(&|| {
        Box::pin(async {
            Arc::new(
                RedbStore::open_in_memory()
                    .expect("in-memory store")
                    .signing_as(Arc::new(agentplane::testkit::StubSigner::default())),
            ) as Arc<dyn JournalStore>
        })
    })
    .await;

    report.assert_conforms("RedbStore");
}

/// The battery must be able to fail.
///
/// A conformance suite that cannot reject anything is the same shape as a test
/// that passes for the wrong reason, and this project has shipped one of those.
/// So a store that deliberately breaks one guarantee — accepting a second
/// `EffectStarted` for an effect key it has already seen — is run through the
/// same battery, and the exactly-once violation must be reported.
#[tokio::test]
async fn the_battery_rejects_a_store_that_drops_exactly_once() {
    let report = conformance::check(&|| {
        Box::pin(async {
            Arc::new(NoExactlyOnce {
                inner: RedbStore::open_in_memory().expect("in-memory store"),
            }) as Arc<dyn JournalStore>
        })
    })
    .await;

    assert!(
        report
            .violations
            .iter()
            .any(|v| v.invariant == "exactly-once"),
        "the battery must notice a store that permits a duplicate effect start; \
         it reported: {:?}",
        report.violations
    );
}

/// A store that quietly swallows the duplicate rather than rejecting it.
///
/// Written the way a real backend gets it wrong: not by removing the index, but
/// by treating the conflict as "already recorded, nothing to do" — which reads
/// like idempotence and is in fact a second performance waiting to happen.
#[derive(Debug)]
struct NoExactlyOnce {
    inner: RedbStore,
}

#[async_trait::async_trait]
impl JournalStore for NoExactlyOnce {
    fn is_shared(&self) -> bool {
        self.inner.is_shared()
    }

    async fn append(
        &self,
        epoch: agentplane::core::Epoch,
        batch: Vec<agentplane::journal::Append>,
    ) -> Result<Vec<agentplane::journal::Record>, agentplane::core::StoreError> {
        match self.inner.append(epoch, batch).await {
            Err(agentplane::core::StoreError::DuplicateEffect(_)) => Ok(Vec::new()),
            other => other,
        }
    }
    async fn read(
        &self,
        run: agentplane::core::RunId,
        from: agentplane::core::Seq,
    ) -> Result<Vec<agentplane::journal::Record>, agentplane::core::StoreError> {
        self.inner.read(run, from).await
    }

    async fn read_page(
        &self,
        run: agentplane::core::RunId,
        from: agentplane::core::Seq,
        limit: usize,
    ) -> Result<Vec<agentplane::journal::Record>, agentplane::core::StoreError> {
        self.inner.read_page(run, from, limit).await
    }
    async fn admitted_as(
        &self,
        key: &str,
    ) -> Result<Option<agentplane::core::RunId>, agentplane::core::StoreError> {
        self.inner.admitted_as(key).await
    }

    async fn forget_admissions(
        &self,
        older_than: agentplane::core::Timestamp,
    ) -> Result<usize, agentplane::core::StoreError> {
        self.inner.forget_admissions(older_than).await
    }
    async fn runs_by_outcome(
        &self,
        outcome: &str,
        limit: usize,
    ) -> Result<Vec<agentplane::core::RunId>, agentplane::core::StoreError> {
        self.inner.runs_by_outcome(outcome, limit).await
    }

    async fn count_by_outcome(&self, outcome: &str) -> Result<u64, agentplane::core::StoreError> {
        self.inner.count_by_outcome(outcome).await
    }

    async fn abandoned_runs(
        &self,
        limit: usize,
    ) -> Result<Vec<agentplane::core::RunId>, agentplane::core::StoreError> {
        self.inner.abandoned_runs(limit).await
    }

    async fn recent_runs(
        &self,
        after: Option<(u64, agentplane::core::RunId)>,
        limit: usize,
    ) -> Result<Vec<(agentplane::core::RunId, u64)>, agentplane::core::StoreError> {
        self.inner.recent_runs(after, limit).await
    }

    async fn case_history(
        &self,
        case: agentplane::core::CaseId,
        limit: usize,
    ) -> Result<Vec<agentplane::journal::Record>, agentplane::core::StoreError> {
        self.inner.case_history(case, limit).await
    }

    async fn head(
        &self,
        run: agentplane::core::RunId,
    ) -> Result<agentplane::journal::Head, agentplane::core::StoreError> {
        self.inner.head(run).await
    }
    async fn acquire(
        &self,
        run: agentplane::core::RunId,
        owner: &str,
        ttl: std::time::Duration,
    ) -> Result<agentplane::journal::Lease, agentplane::core::StoreError> {
        self.inner.acquire(run, owner, ttl).await
    }
    async fn release_lease(
        &self,
        run: agentplane::core::RunId,
        epoch: agentplane::core::Epoch,
    ) -> Result<(), agentplane::core::StoreError> {
        self.inner.release_lease(run, epoch).await
    }
    async fn renew(
        &self,
        run: agentplane::core::RunId,
        owner: &str,
        epoch: agentplane::core::Epoch,
        ttl: std::time::Duration,
    ) -> Result<agentplane::journal::Lease, agentplane::core::StoreError> {
        self.inner.renew(run, owner, epoch, ttl).await
    }
    async fn seal(
        &self,
        run: agentplane::core::RunId,
        epoch: agentplane::core::Epoch,
        outcome: &str,
    ) -> Result<agentplane::core::Digest, agentplane::core::StoreError> {
        self.inner.seal(run, epoch, outcome).await
    }
    async fn checkpoint(
        &self,
    ) -> Result<agentplane::journal::Checkpoint, agentplane::core::StoreError> {
        self.inner.checkpoint().await
    }
    async fn consistency_proof(
        &self,
        old_size: u64,
    ) -> Result<Vec<agentplane::core::Digest>, agentplane::core::StoreError> {
        self.inner.consistency_proof(old_size).await
    }
    async fn inclusion_proof(
        &self,
        run: agentplane::core::RunId,
    ) -> Result<Option<agentplane::journal::Inclusion>, agentplane::core::StoreError> {
        self.inner.inclusion_proof(run).await
    }
    async fn request_cancel(
        &self,
        run: agentplane::core::RunId,
        actor: &str,
        reason: &str,
    ) -> Result<bool, agentplane::core::StoreError> {
        self.inner.request_cancel(run, actor, reason).await
    }
    async fn cancellation(
        &self,
        run: agentplane::core::RunId,
    ) -> Result<Option<agentplane::journal::Cancellation>, agentplane::core::StoreError> {
        self.inner.cancellation(run).await
    }
}

/// The case-layer stores, against redb.
///
/// Each battery covers one race: two messages for one matter, one event to one
/// waiter, one wake-up fired once, one decision held by one reviewer, one item
/// keeping its run id. These are the invariants a second backend reimplements
/// *nearly* correctly.
#[tokio::test]
async fn redb_satisfies_the_case_layer_contracts() {
    use agentplane::batch::BatchStore;
    use agentplane::case::{CaseStore, EventStore, TaskStore, TimerStore};
    use agentplane::testkit::conformance_case as cc;

    let store = Arc::new(RedbStore::open_in_memory().expect("in-memory store"));
    let mut report = agentplane::testkit::conformance::Report::default();

    cc::check_cases(&(Arc::clone(&store) as Arc<dyn CaseStore>), &mut report).await;
    cc::check_events(&(Arc::clone(&store) as Arc<dyn EventStore>), &mut report).await;
    cc::check_timers(&(Arc::clone(&store) as Arc<dyn TimerStore>), &mut report).await;
    cc::check_tasks(&(Arc::clone(&store) as Arc<dyn TaskStore>), &mut report).await;
    cc::check_batches(&(Arc::clone(&store) as Arc<dyn BatchStore>), &mut report).await;

    // Two tenant handles onto the *same* database, because the tenancy check
    // is about one backend keeping two tenants apart — two databases would
    // pass vacuously.
    let mine = Arc::new(
        store
            .as_ref()
            .clone()
            .for_tenant(agentplane::core::TenantId::new("acme").expect("valid")),
    ) as Arc<dyn EventStore>;
    let other = Arc::new(
        store
            .as_ref()
            .clone()
            .for_tenant(agentplane::core::TenantId::new("globex").expect("valid")),
    ) as Arc<dyn EventStore>;
    cc::check_waiting_tenancy(&mine, &other, &mut report).await;

    report.assert_conforms("RedbStore (case layer)");
}
