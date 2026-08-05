//! `PostgreSQL`, checked against the same contract `SQLite` is.
//!
//! The battery lives in `testkit::conformance` and is run here unchanged. That
//! is the whole design: a second backend is where invariants drift, and they
//! drift because the new store gets whatever tests its author happened to think
//! of — which are the ones they were already thinking about while writing it.
//!
//! The container is managed by `testcontainers`, so this needs a Docker daemon
//! and nothing else. If none is running the test skips rather than fails: a red
//! suite on a laptop without Docker teaches people to ignore red suites.
//!
//! # The version is pinned here, not inherited
//!
//! `testcontainers-modules` defaults to **`postgres:11-alpine`**, which reached
//! end of life in November 2023. Left alone, this file would certify the
//! Postgres backend against a release that receives no fixes and that nobody
//! should be running — and would say "`PostgresStore` conforms" while doing it.
//!
//! So the tag is stated. Pinned rather than tracking `latest` for the reason
//! every other version in this crate is pinned: a store that silently changes
//! under a passing suite is how a backend starts failing in production and
//! green in CI. Moving it is a deliberate edit, and the failure that follows is
//! information.

#![cfg(all(feature = "postgres", feature = "testkit"))]

use std::sync::Arc;

use agentplane::journal::JournalStore;
use agentplane::store::PostgresStore;
use agentplane::testkit::conformance;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

/// The `PostgreSQL` release this backend is certified against.
///
/// A supported one, deliberately: the crate's own default is four majors behind
/// and out of support.
const PG: &str = "18-alpine";

#[tokio::test]
async fn postgres_satisfies_the_journal_store_contract() {
    let Ok(container) = Postgres::default().with_tag(PG).start().await else {
        eprintln!("skipping: no Docker daemon available");
        return;
    };
    let port = container.get_host_port_ipv4(5432).await.expect("port");
    let url = format!("postgresql://postgres:postgres@127.0.0.1:{port}/postgres");

    // A **distinct tenant per handle**, because the battery's `fresh()` means
    // "a store with no history" and one database does not provide that by
    // reconnecting to it. redb's in-memory handle is genuinely fresh; Postgres
    // reconnects to the same rows, so checks that count what the store holds —
    // the Merkle log's size against the number of sealed runs — saw every
    // earlier check's runs and passed only by accident of ordering.
    //
    // Isolating by tenant rather than by database is deliberate: the schema is
    // tenant-first precisely so one tenant cannot see another's rows, so this
    // exercises the isolation the store claims instead of working around it.
    let next = std::sync::atomic::AtomicUsize::new(0);
    let report = conformance::check(&|| {
        let url = url.clone();
        let n = next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async move {
            Arc::new(
                PostgresStore::connect(&url)
                    .await
                    .expect("connect to the test container")
                    .for_tenant(
                        agentplane::core::TenantId::new(format!("conformance-{n}"))
                            .expect("a legal tenant id"),
                    ),
            ) as Arc<dyn JournalStore>
        })
    })
    .await;

    report.assert_conforms("PostgresStore");
}

/// Governed memory has the same semantics on the active-active backend.
#[tokio::test]
async fn postgres_satisfies_the_memory_store_contract() {
    use agentplane::memory::MemoryStore;

    let Ok(container) = Postgres::default().with_tag(PG).start().await else {
        eprintln!("skipping: no Docker daemon available");
        return;
    };
    let port = container.get_host_port_ipv4(5432).await.expect("port");
    let url = format!("postgresql://postgres:postgres@127.0.0.1:{port}/postgres");
    let base = PostgresStore::connect(&url).await.expect("connect");
    let tenant = agentplane::core::TenantId::new("memory-conformance").expect("tenant");
    let store = Arc::new(base.clone().for_tenant(tenant.clone())) as Arc<dyn MemoryStore>;

    conformance::memory(store).await;

    memory_revisions_are_shared_and_serialized(
        Arc::new(base.clone().for_tenant(tenant.clone())),
        Arc::new(base.clone().for_tenant(tenant.clone())),
    )
    .await;
    memory_erasure_serializes_with_derivative_creation(
        Arc::new(base.clone().for_tenant(tenant.clone())),
        Arc::new(base.for_tenant(tenant)),
    )
    .await;
}

async fn memory_revisions_are_shared_and_serialized(
    first: Arc<PostgresStore>,
    second: Arc<PostgresStore>,
) {
    use agentplane::core::{Sensitivity, SourceId, Timestamp, Trust};
    use agentplane::memory::{MemoryItem, MemoryStore, Recall};
    use serde_json::json;

    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let write = |store: Arc<PostgresStore>, barrier: Arc<tokio::sync::Barrier>, value: u64| {
        tokio::spawn(async move {
            let item = MemoryItem {
                id: "shared-memory".to_owned(),
                subject: "team/research".to_owned(),
                purpose: "findings".to_owned(),
                content: json!({"writer": value}),
                provenance: vec![SourceId::new(format!("agent:{value}"))],
                sensitivity: Sensitivity::Internal,
                trust: Trust::Untrusted,
                written_by: format!("run-{value}"),
                version: 0,
                created_at: Timestamp::from_unix_timestamp(
                    1_760_000_100 + i64::try_from(value).expect("small writer id"),
                )
                .expect("time"),
                superseded_at: None,
                derived_from: Vec::new(),
            };
            barrier.wait().await;
            store.remember(&item).await.expect("concurrent revision")
        })
    };

    let a = write(Arc::clone(&first), Arc::clone(&barrier), 1);
    let b = write(Arc::clone(&second), barrier, 2);
    let mut versions = vec![a.await.expect("writer a"), b.await.expect("writer b")];
    versions.sort_unstable();
    assert_eq!(
        versions,
        vec![1, 2],
        "concurrent writes allocated one version twice"
    );

    let current = second
        .recall(&Recall::about("team/research").for_purpose("findings"))
        .await
        .expect("shared recall");
    assert_eq!(
        current.len(),
        1,
        "two current revisions survived concurrently"
    );
    assert_eq!(current[0].version, 2);
    assert!(
        first
            .version("shared-memory", 1)
            .await
            .expect("v1")
            .is_some()
    );
    assert!(
        second
            .version("shared-memory", 2)
            .await
            .expect("v2")
            .is_some()
    );
}

async fn memory_erasure_serializes_with_derivative_creation(
    first: Arc<PostgresStore>,
    second: Arc<PostgresStore>,
) {
    use agentplane::core::{Sensitivity, SourceId, Timestamp, Trust};
    use agentplane::memory::{MemoryItem, MemoryStore, Selected};
    use serde_json::json;

    let source = MemoryItem {
        id: "erase-race-source".to_owned(),
        subject: "team/erase-race".to_owned(),
        purpose: "facts".to_owned(),
        content: json!({"fact": "personal"}),
        provenance: vec![SourceId::new("test")],
        sensitivity: Sensitivity::Internal,
        trust: Trust::Untrusted,
        written_by: "test".to_owned(),
        version: 1,
        created_at: Timestamp::from_unix_timestamp(1_760_000_200).expect("time"),
        superseded_at: None,
        derived_from: Vec::new(),
    };
    first.remember(&source).await.expect("source");

    let mut derivative = source.clone();
    "erase-race-derivative".clone_into(&mut derivative.id);
    derivative.content = json!({"summary": "personal"});
    derivative.version = 0;
    derivative.derived_from = vec![Selected {
        id: source.id.clone(),
        version: 1,
        digest: source.selection_digest(),
    }];

    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let observer = Arc::clone(&first);
    let writer = {
        let barrier = Arc::clone(&barrier);
        tokio::spawn(async move {
            barrier.wait().await;
            second.remember(&derivative).await
        })
    };
    let eraser = tokio::spawn(async move {
        barrier.wait().await;
        first.forget_cascading("erase-race-source").await
    });

    let _ = writer.await.expect("writer joined");
    eraser
        .await
        .expect("eraser joined")
        .expect("cascading erasure");
    assert!(
        observer
            .version("erase-race-source", 1)
            .await
            .expect("source lookup")
            .is_none()
    );
    assert!(
        observer
            .version("erase-race-derivative", 1)
            .await
            .expect("derivative lookup")
            .is_none(),
        "a derivative committed during cascading erasure survived"
    );
}

/// The case layer, against the same battery `SQLite` is held to.
#[tokio::test]
async fn postgres_satisfies_the_case_layer_contracts() {
    use agentplane::batch::BatchStore;
    use agentplane::case::{CaseStore, EventStore, TaskStore, TimerStore};
    use agentplane::testkit::conformance_case as cc;

    let Ok(container) = Postgres::default().with_tag(PG).start().await else {
        eprintln!("skipping: no Docker daemon available");
        return;
    };
    let port = container.get_host_port_ipv4(5432).await.expect("port");
    let url = format!("postgresql://postgres:postgres@127.0.0.1:{port}/postgres");
    let store = Arc::new(PostgresStore::connect(&url).await.expect("connect"));

    let mut report = agentplane::testkit::conformance::Report::default();
    agentplane::testkit::conformance_quota::check(store.as_ref(), &mut report).await;
    cc::check_cases(&(Arc::clone(&store) as Arc<dyn CaseStore>), &mut report).await;
    cc::check_events(&(Arc::clone(&store) as Arc<dyn EventStore>), &mut report).await;
    cc::check_timers(&(Arc::clone(&store) as Arc<dyn TimerStore>), &mut report).await;
    cc::check_tasks(&(Arc::clone(&store) as Arc<dyn TaskStore>), &mut report).await;
    cc::check_batches(&(Arc::clone(&store) as Arc<dyn BatchStore>), &mut report).await;

    report.assert_conforms("PostgresStore (case layer)");
}

/// The tenant is a key component here, checked against a real server.
///
/// Postgres is the backend that exists for several plane instances sharing one
/// store, which makes it the one where a missing predicate is *most* likely and
/// worst: a `WHERE` clause somebody forgot is invisible until two tenants are on
/// it. Each half below is paired with a positive assertion, because a query that
/// returns nothing for everybody would pass every negative test here.
#[tokio::test]
async fn postgres_keeps_tenants_apart() {
    use agentplane::core::{TenantId, Timestamp};

    let Ok(container) = Postgres::default().with_tag(PG).start().await else {
        eprintln!("skipping: no Docker daemon available");
        return;
    };
    let port = container.get_host_port_ipv4(5432).await.expect("port");
    let url = format!("postgresql://postgres:postgres@127.0.0.1:{port}/postgres");
    let base = PostgresStore::connect(&url).await.expect("connect");
    let acme = base
        .clone()
        .for_tenant(TenantId::new("acme").expect("valid"));
    let globex = base.for_tenant(TenantId::new("globex").expect("valid"));
    let at = Timestamp::from_unix_timestamp(1_760_000_000).expect("an instant");

    journal_is_apart(&acme, &globex).await;
    memories_are_apart(&acme, &globex, at).await;
    cases_are_apart(&acme, &globex, at).await;
    events_are_apart(&acme, &globex, at).await;
}

async fn memories_are_apart(
    acme: &PostgresStore,
    globex: &PostgresStore,
    at: agentplane::core::Timestamp,
) {
    use agentplane::core::{Sensitivity, SourceId, Trust};
    use agentplane::memory::{MemoryItem, MemoryStore, Recall};
    use serde_json::json;

    acme.remember(&MemoryItem {
        id: "shared-business-id".to_owned(),
        subject: "account-7".to_owned(),
        purpose: "support".to_owned(),
        content: json!({"tenant": "acme"}),
        provenance: vec![SourceId::new("test")],
        sensitivity: Sensitivity::Internal,
        trust: Trust::Untrusted,
        written_by: "test".to_owned(),
        version: 0,
        created_at: at,
        superseded_at: None,
        derived_from: Vec::new(),
    })
    .await
    .expect("acme memory");

    assert!(
        globex
            .recall(&Recall::about("account-7"))
            .await
            .expect("globex recall")
            .is_empty(),
        "one tenant recalled another tenant's memory"
    );
    assert!(
        globex
            .version("shared-business-id", 1)
            .await
            .expect("globex by id")
            .is_none(),
        "one tenant read another tenant's memory by id"
    );
    assert_eq!(
        acme.recall(&Recall::about("account-7"))
            .await
            .expect("acme recall")
            .len(),
        1
    );
}

/// A valid run id from another tenant names nothing here.
async fn journal_is_apart(acme: &PostgresStore, globex: &PostgresStore) {
    use agentplane::core::RunId;
    use agentplane::journal::{Append, RecordKind};

    let run = RunId::generate();
    let lease = acme
        .acquire(run, "acme-worker", std::time::Duration::from_mins(1))
        .await
        .expect("acme leases");
    acme.append(
        lease.epoch,
        vec![Append::new(
            run,
            RecordKind::RunAdmitted {
                capability: "tenancy".into(),
                governed_by: None,
                input_label: agentplane::core::Label::trusted(),
                input: serde_json::Value::Null,
                policy_bundle: None,
            },
        )],
    )
    .await
    .expect("acme appends");

    assert!(
        globex.read(run, 0).await.expect("globex reads").is_empty(),
        "a store handle for one tenant read another tenant's journal while \
         holding nothing but a run id"
    );
    assert_eq!(
        acme.read(run, 0).await.expect("acme reads").len(),
        1,
        "the owning tenant lost its own record, so the scoping broke reads \
         rather than isolating them"
    );

    // Fencing is per tenant too: globex taking a lease on an id it cannot see
    // must not raise the epoch acme is writing under.
    let ours = acme.head(run).await.expect("acme head");
    assert_eq!(ours.seq, 1);
    assert_eq!(
        globex.head(run).await.expect("globex head").seq,
        0,
        "another tenant's chain head leaked, which tells them a run exists"
    );
}

/// A business key two tenants both use opens two cases, not one.
async fn cases_are_apart(
    acme: &PostgresStore,
    globex: &PostgresStore,
    at: agentplane::core::Timestamp,
) {
    use agentplane::case::CaseStore;
    use agentplane::core::CorrelationKey;

    let key = [CorrelationKey::new("document", "DOC-1")];
    let theirs = acme
        .correlate_or_open("clearing", &key, at)
        .await
        .expect("acme opens");
    let mine = globex
        .correlate_or_open("clearing", &key, at)
        .await
        .expect("globex opens");
    assert_ne!(
        theirs.case_id(),
        mine.case_id(),
        "the partial unique index on the correlation key is not scoped to the \
         tenant, so one tenant's run joined another's case and the two share a \
         history, a deadline set and an erasure unit"
    );
    assert_eq!(
        acme.correlate(&key).await.expect("acme correlates"),
        Some(theirs.case_id())
    );
    assert_eq!(
        globex.correlate(&key).await.expect("globex correlates"),
        Some(mine.case_id())
    );
}

/// One tenant's message does not resume another tenant's waiting run.
async fn events_are_apart(
    acme: &PostgresStore,
    globex: &PostgresStore,
    at: agentplane::core::Timestamp,
) {
    use agentplane::case::EventStore;
    use agentplane::core::{
        CorrelationKey, EffectKey, InboundEvent, Phase, RunId, StepId, Subscription,
    };

    let waiting = RunId::generate();
    let sub = Subscription {
        run: waiting,
        effect: EffectKey::from_hex(&"bb".repeat(32)).expect("a key"),
        case: None,
        step: StepId(0),
        phase: Phase::Forward,
        kind: "ack.received".to_owned(),
        correlation: vec![CorrelationKey::new("shipment", "SHP-9")],
    };
    globex.subscribe(&sub, at).await.expect("globex subscribes");

    let event = InboundEvent {
        source: "erp".to_owned(),
        id: "evt-1".to_owned(),
        kind: "ack.received".to_owned(),
        correlation: vec![CorrelationKey::new("shipment", "SHP-9")],
        payload: serde_json::json!({"ok": true}),
    };
    assert!(acme.buffer(&event, at).await.expect("acme buffers"));
    assert!(
        acme.match_waiter(&event, at)
            .await
            .expect("acme matches")
            .is_none(),
        "one tenant's message resumed another tenant's waiting run, handing it \
         a payload nobody sent it"
    );

    // The same message inside globex does resume it — so the match path works
    // and this test failed above for the reason it claims.
    assert!(globex.buffer(&event, at).await.expect("globex buffers"));
    let matched = globex
        .match_waiter(&event, at)
        .await
        .expect("globex matches")
        .expect("globex's own event must resume its own waiter");
    assert_eq!(matched.run, waiting);
}

/// A resource in the journal's own database commits with it, or not at all.
///
/// The property the [`StagedAtomic`](agentplane::testkit::StagedAtomic) fixture
/// deliberately cannot demonstrate: that fixture *models* the contract by
/// staging statements in memory, and a green test against it would be evidence
/// about the fixture. Here a `ROLLBACK` is a rollback.
///
/// Two directions, because either alone proves nothing:
///
/// * a unit of work that succeeds leaves **both** the resource row and the
///   journal records;
/// * a unit of work that refuses leaves **neither** — so nobody can find a
///   ledger posting with no record of it, or a record of a posting that never
///   happened.
mod atomic_fixtures {
    use super::{Arc, PostgresStore};
    use agentplane::core::{EffectDescriptor, EffectError, RunId};
    use agentplane::journal::{
        Append, AtomicResource, AtomicTx, AtomicWork, JournalStore, RecordKind, SqlValue,
    };
    use serde_json::{Value, json};
    use std::sync::{Arc as StdArc, Mutex};

    /// The deployment's own table, not one this crate defines. That is the whole
    /// premise: the resource is already there, beside the journal.
    pub struct CreateTable;

    #[async_trait::async_trait]
    impl AtomicWork for CreateTable {
        async fn run(&self, tx: &dyn AtomicTx) -> Result<Vec<Append>, EffectError> {
            let fail = |e: agentplane::core::StoreError| EffectError::Other(e.to_string());
            tx.execute(
                "CREATE TABLE IF NOT EXISTS ledger (account TEXT PRIMARY KEY, balance BIGINT)",
                &[],
            )
            .await
            .map_err(fail)?;
            tx.execute(
                "INSERT INTO ledger VALUES ('AC-1', 0) ON CONFLICT DO NOTHING",
                &[],
            )
            .await
            .map_err(fail)?;
            Ok(Vec::new())
        }
    }

    #[derive(Debug)]
    pub struct Ledger {
        pub refuses: bool,
    }

    #[async_trait::async_trait]
    impl AtomicResource for Ledger {
        fn descriptor(&self) -> EffectDescriptor {
            EffectDescriptor::new("ledger.post", json!({ "account": "AC-1" }))
        }

        async fn apply(&self, tx: &dyn AtomicTx) -> Result<Value, EffectError> {
            tx.execute(
                "UPDATE ledger SET balance = balance + $2 WHERE account = $1",
                &[SqlValue::from("AC-1"), SqlValue::from(129_i64)],
            )
            .await
            .map_err(|e| EffectError::Other(e.to_string()))?;
            if self.refuses {
                // *After* the write, which is the case that matters: the row was
                // changed inside the transaction and must not survive it.
                return Err(EffectError::Rejected("the account is closed".into()));
            }
            Ok(json!({ "posted": 129 }))
        }
    }

    /// Applies one resource and records that it happened.
    pub struct Post(pub StdArc<Ledger>, pub RunId);

    #[async_trait::async_trait]
    impl AtomicWork for Post {
        async fn run(&self, tx: &dyn AtomicTx) -> Result<Vec<Append>, EffectError> {
            let output = self.0.apply(tx).await?;
            Ok(vec![Append::new(
                self.1,
                RecordKind::EffectDone {
                    output,
                    source: None,
                    spend: agentplane::core::Spend::default(),
                },
            )])
        }
    }

    struct Read(StdArc<Mutex<i64>>);

    #[async_trait::async_trait]
    impl AtomicWork for Read {
        async fn run(&self, tx: &dyn AtomicTx) -> Result<Vec<Append>, EffectError> {
            let rows = tx
                .query("SELECT balance FROM ledger WHERE account = 'AC-1'", &[])
                .await
                .map_err(|e| EffectError::Other(e.to_string()))?;
            // `as_i64`, not a null-tolerant read: a seam that answered `null`
            // for a bigint would make this assertion pass against nothing.
            *self.0.lock().expect("read") = rows[0]["balance"].as_i64().expect("a bigint column");
            Ok(Vec::new())
        }
    }

    pub async fn balance(store: &PostgresStore) -> i64 {
        let seen = StdArc::new(Mutex::new(-1));
        store
            .atomic()
            .expect("atomic")
            .append_atomic(RunId::generate(), 1, &Read(StdArc::clone(&seen)))
            .await
            .expect("read the balance");
        *seen.lock().expect("read")
    }

    /// Bring up a container and the resource table, or say why not.
    pub async fn ready(url: &str) -> Arc<PostgresStore> {
        let store = Arc::new(PostgresStore::connect(url).await.expect("connect"));
        store
            .atomic()
            .expect("postgres lends its transaction")
            .append_atomic(RunId::generate(), 1, &CreateTable)
            .await
            .expect("set up the resource table");
        store
    }
}

/// A committed unit of work leaves **both** the resource row and the records.
#[tokio::test]
async fn a_co_located_resource_commits_with_the_journal() {
    use agentplane::core::RunId;
    use atomic_fixtures::{Ledger, Post, balance, ready};
    use std::sync::Arc as StdArc;

    let Ok(container) = Postgres::default().with_tag(PG).start().await else {
        eprintln!("skipping: no Docker daemon available");
        return;
    };
    let port = container.get_host_port_ipv4(5432).await.expect("port");
    let url = format!("postgresql://postgres:postgres@127.0.0.1:{port}/postgres");
    let store = ready(&url).await;
    assert_eq!(
        balance(&store).await,
        0,
        "the fixture did not start at zero"
    );

    let ok_run = RunId::generate();
    store
        .atomic()
        .expect("atomic")
        .append_atomic(
            ok_run,
            1,
            &Post(StdArc::new(Ledger { refuses: false }), ok_run),
        )
        .await
        .expect("commit");
    assert_eq!(
        balance(&store).await,
        129,
        "the resource write did not commit"
    );
    assert_eq!(
        store.read(ok_run, 1).await.expect("read").len(),
        1,
        "the record did not commit beside the write"
    );
}

/// A refused unit of work leaves **neither**.
///
/// The direction that matters most: nobody can find a ledger posting with no
/// record of it, or a record of a posting that never happened.
#[tokio::test]
async fn a_refused_co_located_resource_leaves_nothing_behind() {
    use agentplane::core::RunId;
    use atomic_fixtures::{Ledger, Post, balance, ready};
    use std::sync::Arc as StdArc;

    let Ok(container) = Postgres::default().with_tag(PG).start().await else {
        eprintln!("skipping: no Docker daemon available");
        return;
    };
    let port = container.get_host_port_ipv4(5432).await.expect("port");
    let url = format!("postgresql://postgres:postgres@127.0.0.1:{port}/postgres");
    let store = ready(&url).await;

    let bad_run = RunId::generate();
    let err = store
        .atomic()
        .expect("atomic")
        .append_atomic(
            bad_run,
            1,
            &Post(StdArc::new(Ledger { refuses: true }), bad_run),
        )
        .await
        .expect_err("a refusing resource committed");
    assert!(
        err.to_string().contains("closed"),
        "the refusal was reworded on the way out: {err}"
    );
    assert_eq!(
        balance(&store).await,
        0,
        "a resource write survived a unit of work that refused — the row moved \
         and nothing recorded that it had"
    );
    assert!(
        store.read(bad_run, 1).await.expect("read").is_empty(),
        "a record survived a unit of work that refused, so the journal claims a \
         posting the ledger never took"
    );
}

/// Every parameter type binds to the column it claims, and reads back.
///
/// The mapping between [`SqlValue`](agentplane::journal::SqlValue) and this
/// driver's types is the kind of code that is obviously right and wrong in
/// three places. Two directions per type, because binding a value correctly and
/// reading it back correctly are separate mistakes:
///
/// * `bind` must produce a parameter Postgres accepts *for that column type* — a
///   float bound as text fails at the statement, not silently;
/// * `column_json` must convert the column back. It converts per Postgres type
///   rather than asking for a `Value` and taking what comes, because only
///   `json`/`jsonb` answer that and every other column would read as **null** —
///   a wrong answer wearing the shape of a missing one. This test is what makes
///   that claim checkable.
#[tokio::test]
async fn every_parameter_type_binds_and_reads_back() {
    use agentplane::core::{EffectError, RunId};
    use agentplane::journal::{Append, AtomicTx, AtomicWork, SqlValue};
    use serde_json::json;
    use std::sync::{Arc as StdArc, Mutex};

    struct RoundTrip(StdArc<Mutex<serde_json::Value>>);

    #[async_trait::async_trait]
    impl AtomicWork for RoundTrip {
        async fn run(&self, tx: &dyn AtomicTx) -> Result<Vec<Append>, EffectError> {
            let fail = |e: agentplane::core::StoreError| EffectError::Other(e.to_string());
            tx.execute(
                "CREATE TABLE IF NOT EXISTS every_type (
                     b BOOLEAN, i BIGINT, f DOUBLE PRECISION,
                     t TEXT, y BYTEA, j JSONB, n BIGINT)",
                &[],
            )
            .await
            .map_err(fail)?;
            tx.execute("DELETE FROM every_type", &[])
                .await
                .map_err(fail)?;
            tx.execute(
                "INSERT INTO every_type VALUES ($1, $2, $3, $4, $5, $6, $7)",
                &[
                    SqlValue::Bool(true),
                    SqlValue::Int(-42),
                    SqlValue::Float(1.5),
                    SqlValue::Text("hello".to_owned()),
                    SqlValue::Bytes(vec![0xde, 0xad]),
                    SqlValue::Json(json!({ "k": [1, 2] })),
                    SqlValue::Null,
                ],
            )
            .await
            .map_err(fail)?;
            let rows = tx
                .query("SELECT * FROM every_type", &[])
                .await
                .map_err(fail)?;
            *self.0.lock().expect("row") = rows.into_iter().next().expect("one row");
            Ok(Vec::new())
        }
    }

    let Ok(container) = Postgres::default().with_tag(PG).start().await else {
        eprintln!("skipping: no Docker daemon available");
        return;
    };
    let port = container.get_host_port_ipv4(5432).await.expect("port");
    let url = format!("postgresql://postgres:postgres@127.0.0.1:{port}/postgres");
    let store = Arc::new(PostgresStore::connect(&url).await.expect("connect"));

    let seen = StdArc::new(Mutex::new(serde_json::Value::Null));
    store
        .atomic()
        .expect("atomic")
        .append_atomic(RunId::generate(), 1, &RoundTrip(StdArc::clone(&seen)))
        .await
        .expect("round trip");

    let row = seen.lock().expect("row").clone();
    assert_eq!(row["b"], json!(true), "bool");
    assert_eq!(row["i"], json!(-42), "bigint");
    assert_eq!(row["f"], json!(1.5), "double precision");
    assert_eq!(row["t"], json!("hello"), "text");
    assert_eq!(row["y"], json!("dead"), "bytea, hex-encoded");
    assert_eq!(row["j"], json!({ "k": [1, 2] }), "jsonb");
    assert_eq!(
        row["n"],
        serde_json::Value::Null,
        "a NULL column must read as null — and only a genuinely null column may"
    );
}

/// A column type the seam does not convert is an error, not a null.
///
/// The failure mode this exists to prevent: a resource selecting a `timestamptz`
/// gets `null`, treats it as absent, and writes a row for the epoch. Refusing
/// tells whoever wrote the query something they can act on.
#[tokio::test]
async fn an_unconvertible_column_is_refused_rather_than_nulled() {
    use agentplane::core::{EffectError, RunId};
    use agentplane::journal::{Append, AtomicTx, AtomicWork};

    struct SelectsATimestamp;

    #[async_trait::async_trait]
    impl AtomicWork for SelectsATimestamp {
        async fn run(&self, tx: &dyn AtomicTx) -> Result<Vec<Append>, EffectError> {
            tx.query("SELECT now() AS at", &[])
                .await
                .map_err(|e| EffectError::Other(e.to_string()))?;
            Ok(Vec::new())
        }
    }

    let Ok(container) = Postgres::default().with_tag(PG).start().await else {
        eprintln!("skipping: no Docker daemon available");
        return;
    };
    let port = container.get_host_port_ipv4(5432).await.expect("port");
    let url = format!("postgresql://postgres:postgres@127.0.0.1:{port}/postgres");
    let store = Arc::new(PostgresStore::connect(&url).await.expect("connect"));

    let err = store
        .atomic()
        .expect("atomic")
        .append_atomic(RunId::generate(), 1, &SelectsATimestamp)
        .await
        .expect_err("an unconvertible column was silently nulled");
    let msg = err.to_string();
    assert!(
        msg.contains("at") && msg.contains("does not convert"),
        "the refusal did not say which column or why: {msg}"
    );
}
