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

/// Standing authority has the same semantics on the active-active backend.
///
/// This is the backend the guarantee is about. On redb a single writer
/// serialises every draw for free; here two instances can draw on one authority
/// at the same instant, and only the row lock the draw takes keeps them from
/// both passing a check the other has already invalidated.
#[tokio::test]
async fn postgres_satisfies_the_authority_store_contract() {
    use agentplane::authority::AuthorityStore;

    let Ok(container) = Postgres::default().with_tag(PG).start().await else {
        eprintln!("skipping: no Docker daemon available");
        return;
    };
    let port = container.get_host_port_ipv4(5432).await.expect("port");
    let url = format!("postgresql://postgres:postgres@127.0.0.1:{port}/postgres");
    let base = PostgresStore::connect(&url).await.expect("connect");
    let tenant = agentplane::core::TenantId::new("authority-conformance").expect("tenant");
    let store = Arc::new(base.for_tenant(tenant)) as Arc<dyn AuthorityStore>;

    conformance::authority(store).await;
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

#[cfg(feature = "push")]
#[tokio::test]
async fn postgres_persists_push_delivery_cursors() {
    use agentplane::core::{RunId, Secret};
    use agentplane::push::{PushAuthentication, PushConfig, PushStore};

    let Ok(container) = Postgres::default().with_tag(PG).start().await else {
        eprintln!("skipping: no Docker daemon available");
        return;
    };
    let port = container.get_host_port_ipv4(5432).await.expect("port");
    let url = format!("postgresql://postgres:postgres@127.0.0.1:{port}/postgres");
    let store = PostgresStore::connect(&url)
        .await
        .expect("connect")
        .for_tenant(agentplane::core::TenantId::new("push-postgres").unwrap());
    let task = RunId::generate();
    let config = PushConfig {
        id: "cfg".to_owned(),
        task,
        url: "https://client.example/hook".to_owned(),
        token: Some(Secret::new("opaque")),
        authentication: Some(PushAuthentication {
            scheme: "Bearer".to_owned(),
            credentials: Secret::new("credential"),
        }),
    };
    store.put(&config, 3).await.expect("put");
    let due = store.due(0, 10).await.expect("due");
    assert_eq!(due[0].next_seq, 3);
    assert_eq!(
        due[0]
            .config
            .authentication
            .as_ref()
            .map(|auth| auth.credentials.expose()),
        Some("credential")
    );
    store.retry(task, "cfg", 20, "offline").await.unwrap();
    assert!(store.due(19, 10).await.unwrap().is_empty());
    store.advance(task, "cfg", 7).await.unwrap();
    assert_eq!(store.due(0, 10).await.unwrap()[0].next_seq, 7);
    let mut replacement = config.clone();
    replacement.url = "https://client.example/new-hook".to_owned();
    store.put(&replacement, 99).await.expect("replace");
    let replaced = store.due(0, 10).await.unwrap();
    assert_eq!(replaced[0].config.url, replacement.url);
    assert_eq!(
        replaced[0].next_seq, 7,
        "replacement acknowledged pending events"
    );
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
                expires_at: None,
                access_retention_seconds: None,
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
        expires_at: None,
        access_retention_seconds: None,
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
        expires_at: None,
        access_retention_seconds: None,
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
                canon: agentplane::core::canon::VERSION,
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

    // A dead run is not another tenant's to recover. The recovery sweep
    // *resumes* everything `abandoned_runs` returns, so a cross-tenant row is
    // not a leaked identifier — it is another tenant's run executed under this
    // plane's identity, policy engine and budget.
    let dead = RunId::generate();
    acme.acquire(dead, "acme-doomed", std::time::Duration::from_secs(1))
        .await
        .expect("acme leases");
    tokio::time::sleep(std::time::Duration::from_millis(1_500)).await;
    let theirs = globex.abandoned_runs(10).await.expect("globex sweeps");
    assert!(
        !theirs.contains(&dead),
        "another tenant's dead run was offered for recovery"
    );
    assert!(
        acme.abandoned_runs(10)
            .await
            .expect("acme sweeps")
            .contains(&dead),
        "the owning tenant must still find its own dead run, or the scoping \
         removed the feature rather than isolating it"
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

/// The erasure lock actually excludes a second instance.
///
/// Gated on `keyring` as well as `postgres`, because the coordinator is only
/// meaningful beside an `EncryptedMemoryStore` — and `just test-postgres` turns
/// both on so this runs where the backend it is about lives.
///
/// The property the whole coordinator seam exists for, and the one a
/// process-local mutex cannot have. `EncryptedMemoryStore` used to serialise
/// subject erasure against writes and legal-hold changes with a
/// `tokio::sync::Mutex` — correct on a single writer, and silently nothing on an
/// active-active plane, where a write on the second instance lands under a scope
/// the first is destroying and the erasure reports success over a row sealed to
/// a key that no longer exists.
///
/// Two coordinators here are two *instances*: separate objects, separate pooled
/// sessions, one database. The first holds the lock; the second must not get it
/// until the first releases. Both halves are asserted, because a coordinator
/// that never grants is as broken as one that always does — and the second half
/// is what a `try_lock`-shaped mistake would fail.
#[cfg(feature = "keyring")]
#[tokio::test]
async fn the_erasure_lock_excludes_a_second_instance() {
    use agentplane::keyring::ErasureCoordinator;

    let Ok(container) = Postgres::default().with_tag(PG).start().await else {
        eprintln!("skipping: no Docker daemon available");
        return;
    };
    let port = container.get_host_port_ipv4(5432).await.expect("port");
    let url = format!("postgresql://postgres:postgres@127.0.0.1:{port}/postgres");

    let one = PostgresStore::connect(&url).await.expect("connect");
    let two = PostgresStore::connect(&url).await.expect("connect");
    let a = one.erasure_coordinator();
    let b = two.erasure_coordinator();
    assert!(
        a.is_distributed(),
        "a coordinator that answers `false` here would be refused beside a \
         shared store, which is the point of asking"
    );

    let scope = "acme/memory-lifecycle";
    let held = a
        .acquire(scope)
        .await
        .expect("first instance takes the lock");

    // Probed with `pg_try_advisory_lock` on a third session rather than by
    // cancelling a real `acquire`. Dropping an in-flight `pg_advisory_lock`
    // returns a connection to the pool with a query still outstanding and the
    // lock's fate unknown — so the obvious `timeout(b.acquire(..))` deadlocks
    // the *next* user of that connection, which is how this test first hung.
    // The hazard is real beyond the test and is recorded on `acquire`: it is
    // not cancel-safe, and callers must use `under_lock`.
    let probe = PostgresStore::connect(&url).await.expect("connect");
    let held_by_someone: bool = probe
        .erasure_probe(scope)
        .await
        .expect("probe the lock without taking it");
    assert!(
        held_by_someone,
        "a second session could take a lock the first was holding — the erasure \
         window this seam exists to close is open"
    );

    // The negative half: an unheld scope probes as free, or the probe is a
    // constant and the assertion above proves nothing.
    assert!(
        !probe
            .erasure_probe("nobody/memory-lifecycle")
            .await
            .expect("probe"),
        "the probe reports every scope as locked, so it distinguishes nothing"
    );

    // And it is granted once the holder releases, or the lock is a deadlock.
    a.release(held).await.expect("release");
    let after = tokio::time::timeout(std::time::Duration::from_secs(30), b.acquire(scope))
        .await
        .expect("the second instance never got the lock after it was released")
        .expect("acquire");
    b.release(after).await.expect("release");

    // A different scope is never contended, or one tenant's erasure would stop
    // every other tenant's writes.
    let x = a.acquire("acme/memory-lifecycle").await.expect("a");
    let y = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        b.acquire("other/memory-lifecycle"),
    )
    .await
    .expect("a different scope must not be blocked by this one")
    .expect("acquire");
    a.release(x).await.expect("release");
    b.release(y).await.expect("release");
}

/// **The run ceiling holds under the concurrency it exists for.**
///
/// This is the backend the guarantee is about: a per-tenant ceiling is
/// accounted in the store precisely so it survives scaling out, redb gets
/// that free from a single writer, and the
/// `PostgreSQL` reserve once ran without any serialisation at all — its comment
/// claimed the decision happened "inside the row lock the write takes", and no
/// such lock exists for INSERTs of different rows. Under READ COMMITTED each
/// racing statement counted its own snapshot, so two admissions racing for one
/// remaining slot both passed `count < limit` and both landed: a ceiling of N
/// admitting N+k under exactly the load a ceiling is for.
///
/// Sixteen tasks race for four slots on one pool, which is the shape a
/// sequential battery structurally cannot produce — and why this file's own
/// header says a sequential test proves the result, not the reason.
#[tokio::test]
async fn postgres_run_ceiling_holds_under_concurrent_admission() {
    use agentplane::quota::{QuotaError, QuotaStore};

    let Ok(container) = Postgres::default().with_tag(PG).start().await else {
        eprintln!("skipping: no Docker daemon available");
        return;
    };
    let port = container.get_host_port_ipv4(5432).await.expect("port");
    let url = format!("postgresql://postgres:postgres@127.0.0.1:{port}/postgres");
    let base = PostgresStore::connect(&url).await.expect("connect");
    let tenant = agentplane::core::TenantId::new("quota-race").expect("tenant");
    let store = Arc::new(base.for_tenant(tenant));
    let (limit, racers) = (4u32, 16usize);
    let at = agentplane::core::Timestamp::from_unix_timestamp(1_760_000_000).expect("time");

    let mut admissions = tokio::task::JoinSet::new();
    for _ in 0..racers {
        let store = Arc::clone(&store);
        admissions.spawn(async move {
            store
                .reserve(agentplane::core::RunId::generate(), Some(limit), at)
                .await
        });
    }
    let mut admitted = 0u32;
    let mut refused = 0u32;
    while let Some(outcome) = admissions.join_next().await {
        match outcome.expect("no task panicked") {
            Ok(()) => admitted += 1,
            Err(QuotaError::TooManyRuns { .. }) => refused += 1,
            Err(other) => panic!("an admission failed for a non-ceiling reason: {other}"),
        }
    }

    assert_eq!(
        admitted, limit,
        "{admitted} admissions landed through a ceiling of {limit} — the count \
         and the insert are not serialised, and the ceiling yields under \
         exactly the load it exists for ({refused} refused)"
    );
    let running = QuotaStore::running(store.as_ref()).await.expect("gauge");
    assert_eq!(
        running, limit,
        "the running set disagrees with the admissions that were granted"
    );
}

/// **Concurrent draws serialise on the balance row's lock — corroborated as a
/// race, not assumed from the statement shape.**
///
/// The run-ceiling next door made the case for running these: its comment
/// claimed a serialisation its statement did not have, and every sequential
/// test agreed with the comment. The draw's `FOR UPDATE` is the real thing —
/// racing sixteen instances at a ceiling that affords exactly three of them
/// is what says so with evidence rather than by reading the SQL.
#[tokio::test]
async fn postgres_authority_draws_serialise_on_the_row_lock() {
    use agentplane::authority::{AuthorityError, AuthorityId, AuthorityStore, StandingAuthority};
    use agentplane::core::{Phase, Spend, StepId};

    let Ok(container) = Postgres::default().with_tag(PG).start().await else {
        eprintln!("skipping: no Docker daemon available");
        return;
    };
    let port = container.get_host_port_ipv4(5432).await.expect("port");
    let url = format!("postgresql://postgres:postgres@127.0.0.1:{port}/postgres");
    let base = PostgresStore::connect(&url).await.expect("connect");
    let tenant = agentplane::core::TenantId::new("authority-race").expect("tenant");
    let store = Arc::new(base.for_tenant(tenant));

    store
        .issue(&StandingAuthority::new(
            "mandate-race",
            "approval:RACE-1",
            Spend::money(100),
        ))
        .await
        .expect("issue");

    let at = agentplane::core::Timestamp::from_unix_timestamp(1_760_000_000).expect("time");
    let mut draws = tokio::task::JoinSet::new();
    for n in 0..16u32 {
        let store = Arc::clone(&store);
        draws.spawn(async move {
            // A distinct dispatch key per draw: sixteen *different* purchases,
            // not sixteen retries of one.
            let key = agentplane::core::EffectKey::for_effect(
                StepId(0),
                Phase::Forward,
                n,
                1,
                &agentplane::core::EffectDescriptor::new(
                    "authority.draw",
                    serde_json::json!({ "purchase": n }),
                ),
            );
            store
                .draw(&AuthorityId::new("mandate-race"), key, Spend::money(30), at)
                .await
        });
    }
    let (mut landed, mut refused) = (0u32, 0u32);
    while let Some(outcome) = draws.join_next().await {
        match outcome.expect("no task panicked") {
            Ok(_) => landed += 1,
            Err(AuthorityError::Exhausted { .. }) => refused += 1,
            Err(other) => panic!("a draw failed for a non-ceiling reason: {other}"),
        }
    }
    assert_eq!(
        (landed, refused),
        (3, 13),
        "a €100 mandate affords exactly three €30 draws, however they race"
    );
    let state = store
        .state(&AuthorityId::new("mandate-race"))
        .await
        .expect("state")
        .expect("issued");
    assert_eq!(
        state.drawn,
        Spend::money(90),
        "the ledger and the admissions disagree"
    );
    assert_eq!(state.draws, 3);
}

/// **Sixteen reviewers race one task; one holds it.** The claim is a single
/// guarded `UPDATE`, and this is the evidence rather than the SQL-reading.
#[tokio::test]
async fn postgres_task_claim_admits_exactly_one_reviewer() {
    use agentplane::case::{ClaimError, TaskStore};
    use agentplane::core::{
        Justification, OnExpiry, Phase, Priority, RunId, StepId, Task, TaskId, TaskState,
    };

    let Ok(container) = Postgres::default().with_tag(PG).start().await else {
        eprintln!("skipping: no Docker daemon available");
        return;
    };
    let port = container.get_host_port_ipv4(5432).await.expect("port");
    let url = format!("postgresql://postgres:postgres@127.0.0.1:{port}/postgres");
    // A pool deliberately smaller than the racers. The deadlock this test
    // exists to catch — a claim holding one connection while a nested read
    // waited for a second — reproduces only where the pool can be exhausted,
    // so with the default CPU-derived size a large machine passes over the
    // defect a CI runner hangs on. Four connections under sixteen claimers
    // makes the exhaustion condition a property of the test rather than of
    // whichever machine runs it.
    let base = PostgresStore::connect_sized(&url, Some(4))
        .await
        .expect("connect");
    let tenant = agentplane::core::TenantId::new("task-race").expect("tenant");
    let store = Arc::new(base.for_tenant(tenant));

    let run = RunId::generate();
    let effect = agentplane::core::EffectKey::for_effect(
        StepId(0),
        Phase::Forward,
        0,
        1,
        &agentplane::core::EffectDescriptor::new("approval", serde_json::json!({})),
    );
    let task = Task {
        id: TaskId::derive(run, effect),
        run,
        case: None,
        kind: "approval".into(),
        justification: Justification::new("needs a person", serde_json::json!({})),
        candidate_roles: vec!["ops".into()],
        assignee: None,
        priority: Priority::Normal,
        state: TaskState::Open,
        on_expiry: OnExpiry::Deny,
        excluded_actors: Vec::new(),
        created_at: agentplane::core::Timestamp::from_unix_timestamp(1_760_000_000).expect("time"),
        due_at: None,
    };
    store.open(&task).await.expect("open");

    let roles = vec!["ops".to_owned()];
    let mut claims = tokio::task::JoinSet::new();
    for n in 0..16 {
        let store = Arc::clone(&store);
        let roles = roles.clone();
        let id = task.id;
        claims.spawn(async move { store.claim(id, &format!("reviewer-{n}"), &roles).await });
    }
    let (mut held, mut contended) = (0u32, 0u32);
    while let Some(outcome) = claims.join_next().await {
        match outcome.expect("no task panicked") {
            Ok(_) => held += 1,
            Err(ClaimError::AlreadyClaimed { .. }) => contended += 1,
            Err(other) => panic!("a claim failed for a non-contention reason: {other}"),
        }
    }
    assert_eq!(
        (held, contended),
        (1, 15),
        "two reviewers both believe they hold one task"
    );
}

/// **Two sweepers partition the due timers; no wake-up fires twice.** The
/// `SKIP LOCKED` claim, raced rather than read.
#[tokio::test]
async fn postgres_two_sweepers_partition_the_due_timers() {
    use agentplane::case::TimerStore;
    use agentplane::core::{Phase, RunId, StepId, Timer};

    let Ok(container) = Postgres::default().with_tag(PG).start().await else {
        eprintln!("skipping: no Docker daemon available");
        return;
    };
    let port = container.get_host_port_ipv4(5432).await.expect("port");
    let url = format!("postgresql://postgres:postgres@127.0.0.1:{port}/postgres");
    let base = PostgresStore::connect(&url).await.expect("connect");
    let tenant = agentplane::core::TenantId::new("timer-race").expect("tenant");
    let store = Arc::new(base.for_tenant(tenant));

    let due = agentplane::core::Timestamp::from_unix_timestamp(1_760_000_000).expect("time");
    let mut armed = std::collections::BTreeSet::new();
    for n in 0..12u8 {
        let timer = Timer {
            run: RunId::generate(),
            case: None,
            effect: agentplane::core::EffectKey::for_effect(
                StepId(0),
                Phase::Forward,
                u32::from(n),
                1,
                &agentplane::core::EffectDescriptor::new("sleep", serde_json::json!({ "n": n })),
            ),
            step: StepId(0),
            phase: Phase::Forward,
            fire_at: due,
        };
        armed.insert(timer.run);
        store.arm(&timer).await.expect("arm");
    }

    let later = agentplane::core::Timestamp::from_unix_timestamp(1_760_000_100).expect("time");
    let (a, b) = tokio::join!(
        {
            let store = Arc::clone(&store);
            async move { store.claim_due(later, 12).await.expect("sweep a") }
        },
        {
            let store = Arc::clone(&store);
            async move { store.claim_due(later, 12).await.expect("sweep b") }
        }
    );
    let claimed_a: std::collections::BTreeSet<_> = a.iter().map(|t| t.run).collect();
    let claimed_b: std::collections::BTreeSet<_> = b.iter().map(|t| t.run).collect();
    assert!(
        claimed_a.is_disjoint(&claimed_b),
        "two sweepers claimed the same wake-up — the run it belongs to resumes twice"
    );
    let union: std::collections::BTreeSet<_> = claimed_a.union(&claimed_b).copied().collect();
    assert_eq!(
        union, armed,
        "the two sweeps together must fire every due timer exactly once"
    );
}
