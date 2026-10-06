//! What a run's own history says about it, on the surfaces that answer.
//!
//! Two of this plane's endings are runs it writes about *itself* — a sweep's
//! pass and an operator crossing a tenant boundary — and both seal like any
//! other. The reader that turns a recorded ending back into a status is a match
//! over strings with a catch-all, so it went on compiling while those two were
//! added to the writer's list, and answered `Quarantined` about records this
//! plane had written itself.

#![cfg(feature = "redb")]

use std::sync::Arc;
use std::time::Duration;

use agentplane::core::{Digest, Epoch, RunId, Seq, StoreError};
use agentplane::journal::{Append, Head, JournalStore, Lease, Record};
use agentplane::runtime::{RunStatus, Runtime};
use agentplane::store::RedbStore;

/// An operator for a fixture, on the weakest basis a real caller could present.
///
/// `Asserted`: a suite that only built the authenticated form would leave the
/// basis a store persists untested on the path an incident actually takes.
fn operator(actor: &str) -> agentplane::core::Operator {
    agentplane::core::Operator::asserted(actor).expect("a fixture names its operator")
}

fn plane() -> (Arc<Runtime>, Arc<RedbStore>) {
    let store = Arc::new(RedbStore::open_in_memory().expect("a store"));
    let runtime = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>).build();
    (runtime, store)
}

/// **A crossing names who crossed, and says why in their words.**
///
/// The whole value of break-glass is the record, and the record is two facts.
/// Reported as a quarantine, the operator's reason is replaced by a sentence
/// about the build — so an incident review reading the surface the operations
/// page sends it to learns neither.
#[tokio::test]
async fn a_break_glass_crossing_names_who_crossed() {
    let (runtime, _store) = plane();
    let run = runtime
        .record_break_glass(
            &operator("ops:hupe"),
            &["admin".to_owned()],
            "INC-42: stuck settlement",
        )
        .await
        .expect("the crossing is recorded");

    let outcome = runtime
        .recorded_outcome(run)
        .await
        .expect("a readable journal")
        .expect("a concluded run");

    assert_eq!(
        outcome.status.as_str(),
        "broke-glass",
        "{:?}",
        outcome.status
    );
    assert_eq!(
        outcome.status.actor(),
        Some(&operator("ops:hupe")),
        "a crossing must name the operator who made it: {:?}",
        outcome.status
    );
    assert_eq!(
        outcome.reason().as_deref(),
        Some("INC-42: stuck settlement"),
        "a crossing must answer with the reason it refused to be recorded \
         without, not with a sentence about this build"
    );
    assert!(
        !outcome.status.is_quarantined(),
        "a crossing this plane wrote itself is not a run the runtime could not \
         decide about"
    );
}

/// The sweep's own pass reads back as what it is.
///
/// No reason, deliberately: it pursued no goal, and what it decided is on its
/// own records rather than in a one-line summary.
#[tokio::test]
async fn a_sweep_reads_back_as_a_sweep() {
    use agentplane::case::CaseStore;
    use agentplane::core::{CorrelationKey, Deadline, DeadlineState, Digest, Timestamp};

    let store = Arc::new(RedbStore::open_in_memory().expect("a store"));
    let cases = Arc::clone(&store) as Arc<dyn CaseStore>;
    let now = Timestamp::from_unix_timestamp(1_800_000_000).expect("a time");

    // A sweep with nothing to decide writes no run at all — deliberately, so a
    // quiet plane does not mint a sealed run every tick. So give it one.
    let case = cases
        .correlate_or_open("matter", &[CorrelationKey::new("matter", "M-1")], now)
        .await
        .expect("a case")
        .case_id();
    cases
        .register_deadline(&Deadline {
            case,
            name: "respond-by".to_owned(),
            resolved_at: now - std::time::Duration::from_secs(3600),
            calendar_digest: Digest::of(b"test-calendar"),
            warn_at: None,
            state: DeadlineState::Pending,
            acknowledged: None,
        })
        .await
        .expect("a deadline");

    let runtime = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .cases(Arc::clone(&cases))
        .build();
    runtime
        .sweep(now, std::time::Duration::from_secs(3600))
        .await
        .expect("a sweep");

    let swept = runtime
        .journal()
        .runs_by_outcome("swept", 10)
        .await
        .expect("the outcome index");
    let run = *swept.first().expect("the sweep sealed a run of its own");

    let outcome = runtime
        .recorded_outcome(run)
        .await
        .expect("a readable journal")
        .expect("a concluded run");
    assert!(
        matches!(outcome.status, RunStatus::Swept),
        "the sweep's own run reads back as {:?}",
        outcome.status
    );
    assert!(outcome.status.actor().is_none());
    assert!(
        outcome.reason().is_none(),
        "a sweep pursued no goal, so there is no ending to explain"
    );
}

fn instant(secs: i64) -> agentplane::core::Timestamp {
    agentplane::core::Timestamp::from_unix_timestamp(secs).expect("a time")
}

fn authenticated(actor: &str) -> agentplane::core::Operator {
    agentplane::core::Operator::authenticated(actor).expect("a fixture names its operator")
}

/// A plane with a journal, a quota register and a case register, all one store.
fn registers() -> (Arc<Runtime>, Arc<RedbStore>) {
    use agentplane::case::CaseStore;
    use agentplane::quota::{QuotaStore, TenantQuota};
    let store = Arc::new(RedbStore::open_in_memory().expect("a store"));
    let runtime = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .quota(
            Arc::clone(&store) as Arc<dyn QuotaStore>,
            TenantQuota::default(),
        )
        .cases(Arc::clone(&store) as Arc<dyn CaseStore>)
        .build();
    (runtime, store)
}

/// The one record of each run sealed under `outcome`.
async fn sole_records(runtime: &Runtime, outcome: &str) -> Vec<agentplane::journal::Record> {
    let runs = runtime
        .journal()
        .runs_by_outcome(outcome, 10)
        .await
        .expect("the outcome index");
    let mut found = Vec::new();
    for run in runs {
        let records = runtime
            .journal()
            .read(run, 1)
            .await
            .expect("a readable run");
        assert_eq!(
            records.len(),
            2,
            "a lift run holds its record and its conclusion, nothing else: {records:?}"
        );
        found.push(records[0].clone());
    }
    found
}

/// **A lifted halt names who lifted it, and the stop it ended.**
///
/// Throwing a halt names its operator; a lift that only deleted the row would
/// erase every trace of who let the work start again.
#[tokio::test]
async fn a_lifted_halt_names_who_lifted_it() {
    use agentplane::journal::RecordKind;
    use agentplane::quota::HaltScope;

    let (runtime, _store) = registers();
    let scope = HaltScope::agent("payments-clerk");

    let nothing = runtime
        .lift_halt(&scope, &authenticated("carol"), instant(1_800_000_100))
        .await
        .expect("a lift of nothing is an answer, not an error");
    assert!(
        nothing.is_none(),
        "nothing was standing, so nothing is recorded"
    );
    assert_eq!(sole_records(&runtime, "halt-lifted").await, []);

    runtime
        .set_halt(
            &scope,
            &operator("bob"),
            instant(1_800_000_000),
            "INC-7: runaway refunds",
        )
        .await
        .expect("a halt");
    let run = runtime
        .lift_halt(&scope, &authenticated("carol"), instant(1_800_000_100))
        .await
        .expect("the lift is recorded")
        .expect("a halt was standing");
    assert!(run.removed, "the lift removed the row it recorded");
    let run = run.record;

    assert!(
        runtime.halts().await.expect("the register").is_empty(),
        "the halt is no longer standing"
    );
    let records = sole_records(&runtime, "halt-lifted").await;
    assert_eq!(records.len(), 1, "one lift, one record");
    assert_eq!(records[0].body.run, run);
    match records[0].kind() {
        RecordKind::HaltLifted {
            scope: lifted,
            by,
            at,
            reason,
            thrown_by,
            thrown_at,
        } => {
            assert_eq!(lifted, &scope.key());
            assert_eq!(by, &authenticated("carol"));
            assert_eq!(*at, instant(1_800_000_100));
            assert_eq!(reason, "INC-7: runaway refunds");
            assert_eq!(thrown_by, &operator("bob"));
            assert_eq!(*thrown_at, instant(1_800_000_000));
        }
        other => panic!("a halt lift run holds a lift record, not {other:?}"),
    }

    let outcome = runtime
        .recorded_outcome(run)
        .await
        .expect("a readable journal")
        .expect("a concluded run");
    assert_eq!(
        outcome.status.as_str(),
        "halt-lifted",
        "{:?}",
        outcome.status
    );
    assert_eq!(outcome.status.actor(), Some(&authenticated("carol")));
    assert!(!outcome.status.is_quarantined());

    let history = runtime.lifted_halts(10).await.expect("the history");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].body.run, run);
}

/// **A released hold names who released it — and not why it was placed.**
///
/// The hold's reason is free text about a matter an erasure may destroy; the
/// release record outlives the matter, so it carries the names and instants
/// and nothing else.
#[tokio::test]
async fn a_released_hold_names_who_released_it() {
    use agentplane::case::CaseStore;
    use agentplane::core::{CorrelationKey, LegalHold};
    use agentplane::journal::RecordKind;

    let (runtime, store) = registers();
    let cases = Arc::clone(&store) as Arc<dyn CaseStore>;
    let case = cases
        .correlate_or_open(
            "matter",
            &[CorrelationKey::new("matter", "M-9")],
            instant(1_800_000_000),
        )
        .await
        .expect("a case")
        .case_id();

    let nothing = runtime
        .release_hold(case, &authenticated("carol"), instant(1_800_000_100))
        .await
        .expect("a release of nothing is an answer");
    assert!(nothing.is_none());

    cases
        .place_hold(
            case,
            &LegalHold {
                placed_at: instant(1_800_000_000),
                reason: "litigation hold LH-secret-77".to_owned(),
                by: operator("bob"),
            },
        )
        .await
        .expect("a hold");
    let run = runtime
        .release_hold(case, &authenticated("carol"), instant(1_800_000_100))
        .await
        .expect("the release is recorded")
        .expect("a hold was standing");
    assert!(run.removed, "the release removed the row it recorded");
    let run = run.record;

    assert!(cases.hold(case).await.expect("the register").is_none());
    let records = sole_records(&runtime, "hold-released").await;
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.body.run, run);
    assert_eq!(
        record.body.case,
        Some(case),
        "the release is stamped with its case"
    );
    match record.kind() {
        RecordKind::HoldReleased {
            by,
            at,
            placed_by,
            placed_at,
        } => {
            assert_eq!(by, &authenticated("carol"));
            assert_eq!(*at, instant(1_800_000_100));
            assert_eq!(placed_by, &operator("bob"));
            assert_eq!(*placed_at, instant(1_800_000_000));
        }
        other => panic!("a hold release run holds a release record, not {other:?}"),
    }
    assert!(
        !String::from_utf8_lossy(record.raw()).contains("LH-secret-77"),
        "the hold's reason must not outlive the matter in the release record"
    );

    let outcome = runtime
        .recorded_outcome(run)
        .await
        .expect("a readable journal")
        .expect("a concluded run");
    assert_eq!(
        outcome.status.as_str(),
        "hold-released",
        "{:?}",
        outcome.status
    );
    assert_eq!(outcome.status.actor(), Some(&authenticated("carol")));

    let history = runtime
        .journal()
        .case_history(case, 10)
        .await
        .expect("the case history");
    assert!(
        history
            .iter()
            .any(|r| matches!(r.kind(), RecordKind::HoldReleased { .. })),
        "the matter's history holds its release"
    );
    assert_eq!(
        runtime.released_holds(10).await.expect("the history").len(),
        1
    );
}

/// A journal that refuses every append when `refuse` is set, fails the next
/// `seals_to_fail` seals, and answers everything else.
#[derive(Debug)]
struct RefusesAppends {
    inner: Arc<dyn JournalStore>,
    refuse: bool,
    seals_to_fail: std::sync::Mutex<usize>,
}

#[async_trait::async_trait]
impl JournalStore for RefusesAppends {
    fn is_shared(&self) -> bool {
        self.inner.is_shared()
    }
    fn seals(&self) -> bool {
        self.inner.seals()
    }
    fn atomic(&self) -> Option<&dyn agentplane::journal::AtomicJournal> {
        self.inner.atomic()
    }
    fn tenant(&self) -> &str {
        self.inner.tenant()
    }
    async fn append(&self, epoch: Epoch, batch: Vec<Append>) -> Result<Vec<Record>, StoreError> {
        if self.refuse {
            return Err(StoreError::Backend(
                "the journal refuses every append".to_owned(),
            ));
        }
        self.inner.append(epoch, batch).await
    }
    async fn read(&self, run: RunId, from: Seq) -> Result<Vec<Record>, StoreError> {
        self.inner.read(run, from).await
    }

    async fn read_page(
        &self,
        run: RunId,
        from: Seq,
        _limit: usize,
    ) -> Result<Vec<Record>, StoreError> {
        self.read(run, from).await
    }
    async fn runs_by_outcome(&self, outcome: &str, limit: usize) -> Result<Vec<RunId>, StoreError> {
        self.inner.runs_by_outcome(outcome, limit).await
    }

    async fn count_by_outcome(&self, outcome: &str) -> Result<u64, StoreError> {
        self.inner.count_by_outcome(outcome).await
    }
    async fn admitted_as(&self, key: &str) -> Result<Option<RunId>, StoreError> {
        self.inner.admitted_as(key).await
    }

    async fn forget_admissions(
        &self,
        older_than: agentplane::core::Timestamp,
    ) -> Result<usize, StoreError> {
        self.inner.forget_admissions(older_than).await
    }
    async fn runs_by_id(
        &self,
        after: Option<RunId>,
        limit: usize,
    ) -> Result<Vec<RunId>, StoreError> {
        self.inner.runs_by_id(after, limit).await
    }
    async fn recent_runs(
        &self,
        after: Option<(u64, RunId)>,
        limit: usize,
    ) -> Result<Vec<(RunId, u64)>, StoreError> {
        self.inner.recent_runs(after, limit).await
    }
    async fn recent_runs_from(
        &self,
        source: &str,
        after: Option<(u64, RunId)>,
        limit: usize,
    ) -> Result<Vec<(RunId, u64)>, StoreError> {
        self.inner.recent_runs_from(source, after, limit).await
    }
    async fn case_history(
        &self,
        case: agentplane::core::CaseId,
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
    async fn waiting_runs(
        &self,
        limit: usize,
    ) -> Result<Vec<agentplane::journal::WaitingRun>, StoreError> {
        self.inner.waiting_runs(limit).await
    }
    async fn seal(&self, run: RunId, epoch: Epoch, outcome: &str) -> Result<Digest, StoreError> {
        let failing = {
            let mut left = self.seals_to_fail.lock().unwrap();
            left.checked_sub(1).map(|n| *left = n).is_some()
        };
        if failing {
            return Err(StoreError::Backend(
                "the process died before the seal".to_owned(),
            ));
        }
        self.inner.seal(run, epoch, outcome).await
    }
    async fn checkpoint(&self) -> Result<agentplane::journal::Checkpoint, StoreError> {
        self.inner.checkpoint().await
    }
    async fn consistency_proof(&self, old_size: u64) -> Result<Vec<Digest>, StoreError> {
        self.inner.consistency_proof(old_size).await
    }
    async fn inclusion_proof(
        &self,
        run: RunId,
    ) -> Result<Option<agentplane::journal::Inclusion>, StoreError> {
        self.inner.inclusion_proof(run).await
    }
    async fn request_cancel(
        &self,
        run: RunId,
        actor: &agentplane::core::Operator,
        reason: &str,
    ) -> Result<bool, StoreError> {
        self.inner.request_cancel(run, actor, reason).await
    }
    async fn cancellation(
        &self,
        run: RunId,
    ) -> Result<Option<agentplane::journal::Cancellation>, StoreError> {
        self.inner.cancellation(run).await
    }
}

/// **The record comes first: a lift that cannot be recorded does not happen.**
///
/// The journal and the register share no transaction. Removing the row first
/// fails toward a lift nobody is named on, which is the defect the record
/// exists to remove; recording first fails toward the control staying in force.
#[tokio::test]
async fn a_lift_whose_record_cannot_be_written_leaves_the_halt_standing() {
    use agentplane::case::CaseStore;
    use agentplane::core::{CorrelationKey, LegalHold};
    use agentplane::quota::{HaltScope, QuotaStore, TenantQuota};

    let store = Arc::new(RedbStore::open_in_memory().expect("a store"));
    let refusing = Arc::new(RefusesAppends {
        inner: Arc::clone(&store) as Arc<dyn JournalStore>,
        refuse: true,
        seals_to_fail: std::sync::Mutex::new(0),
    });
    let runtime = Runtime::builder(refusing as Arc<dyn JournalStore>)
        .quota(
            Arc::clone(&store) as Arc<dyn QuotaStore>,
            TenantQuota::default(),
        )
        .cases(Arc::clone(&store) as Arc<dyn CaseStore>)
        .build();

    runtime
        .set_halt(
            &HaltScope::Tenant,
            &operator("bob"),
            instant(1_800_000_000),
            "INC-8",
        )
        .await
        .expect("a halt");
    runtime
        .lift_halt(
            &HaltScope::Tenant,
            &operator("carol"),
            instant(1_800_000_100),
        )
        .await
        .expect_err("a lift that cannot be recorded is refused");
    assert_eq!(
        runtime.halts().await.expect("the register").len(),
        1,
        "the halt still stands"
    );

    let cases = Arc::clone(&store) as Arc<dyn CaseStore>;
    let case = cases
        .correlate_or_open(
            "matter",
            &[CorrelationKey::new("matter", "M-3")],
            instant(1_800_000_000),
        )
        .await
        .expect("a case")
        .case_id();
    cases
        .place_hold(
            case,
            &LegalHold {
                placed_at: instant(1_800_000_000),
                reason: "LH-3".to_owned(),
                by: operator("bob"),
            },
        )
        .await
        .expect("a hold");
    runtime
        .release_hold(case, &operator("carol"), instant(1_800_000_100))
        .await
        .expect_err("a release that cannot be recorded is refused");
    assert!(
        cases.hold(case).await.expect("the register").is_some(),
        "the hold still stands"
    );
}

/// **A seal its writer died before is finished by the next sweep.**
///
/// An operator act's run holds no lease, so recovery never selects it. Its
/// conclusion alone lists it in the history; until the seal, the audit finds
/// it in no log.
#[tokio::test]
async fn a_lift_concluded_but_not_sealed_is_sealed_by_the_next_sweep() {
    use agentplane::quota::{HaltScope, QuotaStore, TenantQuota};

    let store = Arc::new(RedbStore::open_in_memory().expect("a store"));
    let journal = Arc::new(RefusesAppends {
        inner: Arc::clone(&store) as Arc<dyn JournalStore>,
        refuse: false,
        seals_to_fail: std::sync::Mutex::new(1),
    });
    let runtime = Runtime::builder(Arc::clone(&journal) as Arc<dyn JournalStore>)
        .quota(
            Arc::clone(&store) as Arc<dyn QuotaStore>,
            TenantQuota::default(),
        )
        .build();
    runtime
        .set_halt(
            &HaltScope::Tenant,
            &operator("bob"),
            instant(1_800_000_000),
            "INC-9",
        )
        .await
        .expect("a halt");
    runtime
        .lift_halt(
            &HaltScope::Tenant,
            &operator("carol"),
            instant(1_800_000_100),
        )
        .await
        .expect_err("the seal failed");
    let concluded = store
        .runs_by_outcome("halt-lifted", 10)
        .await
        .expect("the index");
    assert_eq!(concluded.len(), 1, "the conclusion was written");
    let audited = Arc::clone(&store) as Arc<dyn JournalStore>;
    let before = agentplane::audit::audit(
        &audited,
        &concluded,
        &agentplane::audit::Evidence::default(),
    )
    .await
    .expect("audit");
    assert!(!before.is_sound(), "an unsealed conclusion reads as sound");

    let report = runtime
        .sweep(instant(1_800_000_200), Duration::from_secs(60))
        .await
        .expect("a sweep");
    assert_eq!(report.seals_finished, 1, "{report:?}");
    assert!(!report.is_quiet(), "finishing a seal is activity");
    let after = agentplane::audit::audit(
        &audited,
        &concluded,
        &agentplane::audit::Evidence::default(),
    )
    .await
    .expect("audit");
    assert!(after.is_sound(), "{:?}", after.findings);

    let again = runtime
        .sweep(instant(1_800_000_300), Duration::from_secs(60))
        .await
        .expect("a sweep");
    assert_eq!(again.seals_finished, 0, "a sealed run is not sealed twice");
}
