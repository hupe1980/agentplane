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

    let report = conformance::check(&|| {
        let url = url.clone();
        Box::pin(async move {
            Arc::new(
                PostgresStore::connect(&url)
                    .await
                    .expect("connect to the test container"),
            ) as Arc<dyn JournalStore>
        })
    })
    .await;

    report.assert_conforms("PostgresStore");
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
    cases_are_apart(&acme, &globex, at).await;
    events_are_apart(&acme, &globex, at).await;
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
