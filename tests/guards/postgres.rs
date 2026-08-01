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
    cc::check_cases(&(Arc::clone(&store) as Arc<dyn CaseStore>), &mut report).await;
    cc::check_events(&(Arc::clone(&store) as Arc<dyn EventStore>), &mut report).await;
    cc::check_timers(&(Arc::clone(&store) as Arc<dyn TimerStore>), &mut report).await;
    cc::check_tasks(&(Arc::clone(&store) as Arc<dyn TaskStore>), &mut report).await;
    cc::check_batches(&(Arc::clone(&store) as Arc<dyn BatchStore>), &mut report).await;

    report.assert_conforms("PostgresStore (case layer)");
}
