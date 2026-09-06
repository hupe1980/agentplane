//! Cross-backend store contracts, pinned outside the conformance battery.
//!
//! Every test here exists because the two backends *disagreed* about one of
//! these behaviours — a re-claim that redb honoured and Postgres refused, a
//! queue ordering the trait promised and one backend ignored, a TTL both
//! stores silently rewrote. The conformance battery is the home for the broad
//! contract; this file pins the specific seams that drifted, with a negative
//! half that fails when the enforcement is removed and a positive half that
//! proves the negative one is not vacuous.
//!
//! The embedded half runs everywhere. The Postgres half follows the pattern
//! `guards/postgres.rs` established: a `testcontainers`-managed server,
//! skipped rather than failed when no Docker daemon is available, pinned to a
//! supported image tag.

/// The embedded backend, in memory, no gate.
#[cfg(feature = "redb")]
mod embedded {
    use std::time::Duration;

    use agentplane::case::{ClaimError, EventStore, TaskStore, TimerStore};
    use agentplane::core::{
        CorrelationKey, EffectKey, InboundEvent, Justification, OnExpiry, Phase, Priority, RunId,
        StepId, Subscription, Task, TaskId, TaskState, TenantId, Timer, Timestamp,
    };
    use agentplane::journal::JournalStore;
    use agentplane::store::RedbStore;

    fn at(secs: i64) -> Timestamp {
        Timestamp::from_unix_timestamp(secs).expect("an instant")
    }

    fn task(n: u32, priority: Priority, created: i64) -> Task {
        let run = RunId::generate();
        let effect = EffectKey::for_effect(
            StepId(0),
            Phase::Forward,
            n,
            1,
            &agentplane::core::EffectDescriptor::new("approval", serde_json::json!({ "n": n })),
        );
        Task {
            id: TaskId::derive(run, effect),
            run,
            case: None,
            kind: "approval".into(),
            justification: Justification::new("needs a person", serde_json::json!({})),
            candidate_roles: Vec::new(),
            assignee: None,
            priority,
            state: TaskState::Open,
            on_expiry: OnExpiry::Deny,
            escalate_to: Vec::new(),
            excluded_actors: Vec::new(),
            created_at: at(created),
            due_at: None,
        }
    }

    /// A TTL below the store's whole-second granularity is refused, not
    /// clamped up to a second — and an overflowing one is refused, not
    /// wrapped into the past.
    ///
    /// The positive half asserts the refusals consumed nothing: the first
    /// *legal* acquire still gets epoch 1.
    #[tokio::test]
    async fn a_sub_second_lease_ttl_is_refused_not_clamped() {
        let store = RedbStore::open_in_memory().expect("store");
        let run = RunId::generate();

        let err = store
            .acquire(run, "w", Duration::ZERO)
            .await
            .expect_err("a zero TTL used to be clamped to one second");
        assert!(
            err.to_string().contains("granularity"),
            "the refusal must say why: {err}"
        );
        store
            .acquire(run, "w", Duration::from_millis(900))
            .await
            .expect_err("900ms truncates to zero whole seconds and must refuse");
        let err = store
            .acquire(run, "w", Duration::from_secs(u64::MAX))
            .await
            .expect_err("an overflowing expiry would be born in the past");
        assert!(
            err.to_string().contains("overflow"),
            "the refusal must say why: {err}"
        );

        let lease = store
            .acquire(run, "w", Duration::from_secs(60))
            .await
            .expect("a whole-second TTL is served");
        assert_eq!(
            lease.epoch, 1,
            "the refusals must not have written anything — the first legal \
             claim is the first claim"
        );

        // `renew` holds the same contract.
        store
            .renew(run, "w", 1, Duration::ZERO)
            .await
            .expect_err("renew must refuse a sub-second TTL like acquire does");
        store
            .renew(run, "w", 1, Duration::from_secs(60))
            .await
            .expect("a legal renewal still works after the refusal");
    }

    /// The timer gauge counts this tenant's timers, not everybody's.
    #[tokio::test]
    async fn pending_count_is_scoped_to_the_tenant() {
        let base = RedbStore::open_in_memory().expect("store");
        let acme = base
            .clone()
            .for_tenant(TenantId::new("acme").expect("tenant"));
        let globex = base.for_tenant(TenantId::new("globex").expect("tenant"));

        let arm = |store: RedbStore, n: u32| async move {
            store
                .arm(&Timer {
                    run: RunId::generate(),
                    case: None,
                    effect: EffectKey::for_effect(
                        StepId(0),
                        Phase::Forward,
                        n,
                        1,
                        &agentplane::core::EffectDescriptor::new(
                            "sleep",
                            serde_json::json!({ "n": n }),
                        ),
                    ),
                    step: StepId(0),
                    phase: Phase::Forward,
                    fire_at: at(1_760_000_000),
                })
                .await
                .expect("arm");
        };
        arm(acme.clone(), 0).await;
        arm(acme.clone(), 1).await;
        arm(globex.clone(), 2).await;

        assert_eq!(
            acme.pending_count().await.expect("count"),
            2,
            "the gauge must count acme's timers and only acme's"
        );
        assert_eq!(
            globex.pending_count().await.expect("count"),
            1,
            "a whole-table count would answer 3 here — every tenant's timers \
             reported as this one's"
        );
    }

    /// Same-holder re-claim is idempotent success; another holder is refused.
    #[tokio::test]
    async fn a_holders_own_reclaim_is_idempotent() {
        let store = RedbStore::open_in_memory().expect("store");
        let t = task(0, Priority::Normal, 1_760_000_000);
        store.open(&t).await.expect("open");

        store.claim(t.id, "alice", &[]).await.expect("first claim");
        let again = store
            .claim(t.id, "alice", &[])
            .await
            .expect("a retried claim by the holder must converge on 'you hold it'");
        assert_eq!(again.assignee.as_deref(), Some("alice"));
        assert_eq!(again.state, TaskState::Claimed);

        match store.claim(t.id, "bob", &[]).await {
            Err(ClaimError::AlreadyClaimed { holder, .. }) => {
                assert_eq!(holder, "alice", "the refusal names the real holder");
            }
            other => panic!("bob's claim on alice's task must refuse: {other:?}"),
        }
    }

    /// The queue serves the most urgent task first, however young it is.
    #[tokio::test]
    async fn the_queue_serves_priority_before_age() {
        let store = RedbStore::open_in_memory().expect("store");
        let old_normal = task(0, Priority::Normal, 1_000);
        store.open(&old_normal).await.expect("open");
        store
            .open(&task(1, Priority::Normal, 1_001))
            .await
            .expect("open");
        store
            .open(&task(2, Priority::Normal, 1_002))
            .await
            .expect("open");
        // Older than the urgent one and one rank below it, so the page's first
        // two entries separate *adjacent* ranks. A page proving only that
        // urgent beats normal passes on a rank table where two neighbours
        // share a number.
        let old_high = task(4, Priority::High, 1_500);
        store.open(&old_high).await.expect("open");
        let young_urgent = task(3, Priority::Urgent, 2_000);
        store.open(&young_urgent).await.expect("open");

        let page = store.queue(&[], 3).await.expect("queue");
        assert_eq!(page.len(), 3);
        assert_eq!(
            page[0].id, young_urgent.id,
            "an urgent task behind older normal ones must lead the page, not \
             fall off it"
        );
        assert_eq!(
            page[1].id, old_high.id,
            "high outranks normal, and every adjacent pair of ranks must be \
             one the queue can tell apart"
        );
        assert_eq!(
            page[2].id, old_normal.id,
            "within what the page has room for, oldest first"
        );
    }

    /// When one run has two waits matching one event, the lowest effect key
    /// is elected — the order both backends must share, because which wait a
    /// targeted delivery satisfies is observable in the resumed step.
    #[tokio::test]
    async fn targeted_delivery_elects_the_lowest_effect_key() {
        let store = RedbStore::open_in_memory().expect("store");
        let run = RunId::generate();
        let low = EffectKey::from_hex(&"aa".repeat(32)).expect("key");
        let high = EffectKey::from_hex(&"bb".repeat(32)).expect("key");
        let sub = |effect: EffectKey| Subscription {
            run,
            effect,
            case: None,
            step: StepId(0),
            phase: Phase::Forward,
            kind: "ack.received".to_owned(),
            correlation: vec![CorrelationKey::new("shipment", "SHP-1")],
        };
        // The higher key is registered *first* and *earlier*, so an
        // implementation electing by registration time picks it — the drift
        // this test exists to refuse.
        store
            .subscribe(&sub(high), at(1_000))
            .await
            .expect("subscribe");
        store
            .subscribe(&sub(low), at(2_000))
            .await
            .expect("subscribe");

        let event = InboundEvent {
            source: "erp".to_owned(),
            id: "evt-1".to_owned(),
            kind: "ack.received".to_owned(),
            correlation: vec![CorrelationKey::new("shipment", "SHP-1")],
            payload: serde_json::json!({ "ok": true }),
        };
        match store
            .deliver_to(run, &event, at(3_000))
            .await
            .expect("deliver")
        {
            agentplane::case::TargetedDelivery::Matched(matched) => {
                assert_eq!(
                    matched.effect, low,
                    "both backends must elect the same waiter: lowest effect key"
                );
            }
            other => panic!("the run was waiting: {other:?}"),
        }
    }

    /// A retirement that recorded no reason reads `unclaimed` — one wording
    /// across backends, so an operator scripting on the field does not have
    /// to know which store the plane journals to.
    #[tokio::test]
    async fn an_unnamed_dead_letter_reason_reads_unclaimed() {
        let store = RedbStore::open_in_memory().expect("store");
        let event = |n: u32| InboundEvent {
            source: "erp".to_owned(),
            id: format!("evt-{n}"),
            kind: "ack.received".to_owned(),
            correlation: vec![CorrelationKey::new("shipment", format!("SHP-{n}"))],
            payload: serde_json::json!({}),
        };

        store.buffer(&event(1), at(1_000)).await.expect("buffer");
        assert_eq!(
            store.sweep_unclaimed(at(1_000), "").await.expect("sweep"),
            1
        );
        store.buffer(&event(2), at(2_000)).await.expect("buffer");
        assert_eq!(
            store
                .sweep_unclaimed(at(2_000), "gave up waiting")
                .await
                .expect("sweep"),
            1
        );

        let letters = store.dead_letters(10).await.expect("dead letters");
        assert_eq!(letters.len(), 2);
        // Newest first.
        assert_eq!(
            letters[0].reason, "gave up waiting",
            "a stated reason is preserved verbatim"
        );
        assert_eq!(
            letters[1].reason, "unclaimed",
            "an unstated reason reads 'unclaimed', never an empty string"
        );
    }
}

/// The shared backend, behind a container — the `guards/postgres.rs` pattern:
/// skip without a Docker daemon, image tag pinned to a supported release.
#[cfg(feature = "postgres")]
mod shared {
    use std::sync::Arc;
    use std::time::Duration;

    use agentplane::case::{ClaimError, EventStore, TaskStore};
    use agentplane::core::{
        CorrelationKey, EffectKey, InboundEvent, Justification, OnExpiry, Phase, Priority, RunId,
        StepId, StoreError, Subscription, Task, TaskId, TaskState, Timestamp,
    };
    use agentplane::journal::JournalStore;
    use agentplane::store::PostgresStore;
    use testcontainers_modules::postgres::Postgres;
    use testcontainers_modules::testcontainers::ImageExt;
    use testcontainers_modules::testcontainers::runners::AsyncRunner;

    /// The `PostgreSQL` release these guards certify against — the same pin,
    /// for the same reason, as `guards/postgres.rs`.
    const PG: &str = "18-alpine";

    fn at(secs: i64) -> Timestamp {
        Timestamp::from_unix_timestamp(secs).expect("an instant")
    }

    /// **Two instances first-acquire one run; exactly one holds it.**
    ///
    /// The race this pins: `SELECT … FOR UPDATE` locks nothing when the row
    /// is absent, so two concurrent *first* acquires both read `None`, both
    /// computed epoch 1, and the loser's unguarded upsert overwrote the
    /// winner — both returned `Lease { epoch: 1 }` and both passed the append
    /// fence. Split-brain under a single fencing token, on the one backend
    /// whose reason to exist is preventing it. The claim is now a single
    /// guarded statement, and this is the evidence rather than the
    /// SQL-reading.
    ///
    /// Raced over several rounds because a race that reproduces once in
    /// twenty runs is a race the suite blesses nineteen times.
    #[tokio::test]
    async fn postgres_first_acquire_admits_exactly_one_instance() {
        let Ok(container) = Postgres::default().with_tag(PG).start().await else {
            eprintln!("skipping: no Docker daemon available");
            return;
        };
        let port = container.get_host_port_ipv4(5432).await.expect("port");
        let url = format!("postgresql://postgres:postgres@127.0.0.1:{port}/postgres");
        let tenant = agentplane::core::TenantId::new("acquire-race").expect("tenant");
        // Two *instances*: separate pools onto one database.
        let a = Arc::new(
            PostgresStore::connect(&url)
                .await
                .expect("connect")
                .for_tenant(tenant.clone()),
        );
        let b = Arc::new(
            PostgresStore::connect(&url)
                .await
                .expect("connect")
                .for_tenant(tenant),
        );

        for round in 0..8u32 {
            let run = RunId::generate();
            let barrier = Arc::new(tokio::sync::Barrier::new(2));
            let race = |store: Arc<PostgresStore>, owner: &'static str| {
                let barrier = Arc::clone(&barrier);
                tokio::spawn(async move {
                    barrier.wait().await;
                    let outcome = store.acquire(run, owner, Duration::from_secs(60)).await;
                    (store, owner, outcome)
                })
            };
            let first = race(Arc::clone(&a), "instance-a");
            let second = race(Arc::clone(&b), "instance-b");
            let outcomes = vec![
                first.await.expect("no panic"),
                second.await.expect("no panic"),
            ];

            let mut winner: Option<(Arc<PostgresStore>, &'static str)> = None;
            let mut refusal: Option<StoreError> = None;
            for (store, owner, outcome) in outcomes {
                match outcome {
                    Ok(lease) => {
                        assert_eq!(
                            lease.epoch, 1,
                            "round {round}: a first acquire hands out epoch 1"
                        );
                        assert!(
                            winner.replace((store, owner)).is_none(),
                            "round {round}: both instances hold epoch 1 on one \
                             run — split-brain under a single fencing token"
                        );
                    }
                    Err(e) => {
                        assert!(
                            refusal.replace(e).is_none(),
                            "round {round}: both instances were refused, so \
                             nobody owns the run"
                        );
                    }
                }
            }
            let (winner_store, winner_owner) = winner.expect("one winner");
            match refusal.expect("one refusal") {
                StoreError::LeaseHeld { owner, epoch, .. } => {
                    assert_eq!(epoch, 1, "round {round}: the loser sees the winner's epoch");
                    assert_eq!(
                        owner, winner_owner,
                        "round {round}: the loser is told who actually holds it"
                    );
                }
                other => panic!("round {round}: the loser must see LeaseHeld: {other}"),
            }
            // The winner's row survived the loser's attempt: a renewal under
            // the winner's exact `(owner, epoch)` still succeeds. Under the
            // racy shape the loser overwrote the owner column and this fails.
            winner_store
                .renew(run, winner_owner, 1, Duration::from_secs(60))
                .await
                .expect("the winner's lease must survive the loser's attempt");
        }
    }

    /// The TTL granularity refusal, on the shared backend.
    #[tokio::test]
    async fn postgres_refuses_a_sub_second_lease_ttl() {
        let Ok(container) = Postgres::default().with_tag(PG).start().await else {
            eprintln!("skipping: no Docker daemon available");
            return;
        };
        let port = container.get_host_port_ipv4(5432).await.expect("port");
        let url = format!("postgresql://postgres:postgres@127.0.0.1:{port}/postgres");
        let store = PostgresStore::connect(&url)
            .await
            .expect("connect")
            .for_tenant(agentplane::core::TenantId::new("ttl-guard").expect("tenant"));
        let run = RunId::generate();

        let err = store
            .acquire(run, "w", Duration::ZERO)
            .await
            .expect_err("a zero TTL used to be clamped to one second");
        assert!(err.to_string().contains("granularity"), "{err}");
        let err = store
            .acquire(run, "w", Duration::from_secs(u64::MAX))
            .await
            .expect_err("an overflowing expiry would be born in the past");
        assert!(err.to_string().contains("overflow"), "{err}");

        let lease = store
            .acquire(run, "w", Duration::from_secs(60))
            .await
            .expect("a whole-second TTL is served");
        assert_eq!(lease.epoch, 1, "the refusals wrote nothing");
        store
            .renew(run, "w", 1, Duration::ZERO)
            .await
            .expect_err("renew holds the same granularity contract");
    }

    struct Statement(&'static str);

    #[async_trait::async_trait]
    impl agentplane::journal::AtomicWork for Statement {
        async fn run(
            &self,
            tx: &dyn agentplane::journal::AtomicTx,
        ) -> Result<Vec<agentplane::journal::Append>, agentplane::core::EffectError> {
            tx.execute(self.0, &[])
                .await
                .map_err(|e| agentplane::core::EffectError::Other(e.to_string()))?;
            Ok(Vec::new())
        }
    }

    /// A co-located resource cannot dissolve the atomic seam from inside.
    #[tokio::test]
    async fn postgres_atomic_member_cannot_end_the_transaction() {
        let Ok(container) = Postgres::default().with_tag(PG).start().await else {
            eprintln!("skipping: no Docker daemon available");
            return;
        };
        let port = container.get_host_port_ipv4(5432).await.expect("port");
        let url = format!("postgresql://postgres:postgres@127.0.0.1:{port}/postgres");
        let store = PostgresStore::connect(&url).await.expect("connect");
        let atomic = store.atomic().expect("postgres lends its transaction");

        for sql in [
            "COMMIT",
            "rollback;",
            "BEGIN",
            "START TRANSACTION",
            "SAVEPOINT escape_hatch",
            "RELEASE SAVEPOINT escape_hatch",
            "PREPARE TRANSACTION 'gtx'",
            "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE",
            "END",
            "ABORT",
        ] {
            let err = atomic
                .append_atomic(RunId::generate(), 1, &Statement(sql))
                .await
                .expect_err("a transaction-control statement must be refused");
            assert!(
                err.to_string().contains("transaction"),
                "the refusal for {sql:?} must say what it protects: {err}"
            );
        }

        // The positive halves: ordinary statements — including a bare
        // PREPARE, which shares its first keyword with the forbidden
        // PREPARE TRANSACTION — still pass.
        atomic
            .append_atomic(RunId::generate(), 1, &Statement("SELECT 1"))
            .await
            .expect("an ordinary statement passes the guard");
        atomic
            .append_atomic(
                RunId::generate(),
                1,
                &Statement("PREPARE guard_probe AS SELECT 1"),
            )
            .await
            .expect("statement preparation is not transaction control");
    }

    fn task(n: u32, priority: Priority, created: i64) -> Task {
        let run = RunId::generate();
        let effect = EffectKey::for_effect(
            StepId(0),
            Phase::Forward,
            n,
            1,
            &agentplane::core::EffectDescriptor::new("approval", serde_json::json!({ "n": n })),
        );
        Task {
            id: TaskId::derive(run, effect),
            run,
            case: None,
            kind: "approval".into(),
            justification: Justification::new("needs a person", serde_json::json!({})),
            candidate_roles: Vec::new(),
            assignee: None,
            priority,
            state: TaskState::Open,
            on_expiry: OnExpiry::Deny,
            escalate_to: Vec::new(),
            excluded_actors: Vec::new(),
            created_at: at(created),
            due_at: None,
        }
    }

    /// The worklist contracts redb already held: same-holder re-claim is
    /// idempotent, and the queue serves priority before age.
    #[tokio::test]
    async fn postgres_reclaim_and_queue_match_the_embedded_backend() {
        let Ok(container) = Postgres::default().with_tag(PG).start().await else {
            eprintln!("skipping: no Docker daemon available");
            return;
        };
        let port = container.get_host_port_ipv4(5432).await.expect("port");
        let url = format!("postgresql://postgres:postgres@127.0.0.1:{port}/postgres");
        let store = PostgresStore::connect(&url)
            .await
            .expect("connect")
            .for_tenant(agentplane::core::TenantId::new("worklist-guard").expect("tenant"));

        // Same-holder re-claim: idempotent success, exactly as on redb. This
        // backend used to answer `AlreadyClaimed { holder: yourself }`.
        let held = task(0, Priority::Normal, 1_760_000_000);
        store.open(&held).await.expect("open");
        store
            .claim(held.id, "alice", &[])
            .await
            .expect("first claim");
        let again = store
            .claim(held.id, "alice", &[])
            .await
            .expect("a retried claim by the holder must converge on 'you hold it'");
        assert_eq!(again.assignee.as_deref(), Some("alice"));
        assert_eq!(again.state, TaskState::Claimed);
        match store.claim(held.id, "bob", &[]).await {
            Err(ClaimError::AlreadyClaimed { holder, .. }) => assert_eq!(holder, "alice"),
            other => panic!("bob's claim on alice's task must refuse: {other:?}"),
        }

        // Queue ordering: an urgent task behind a page of older normal ones
        // must lead the page, not be absent from it — the trait's "highest
        // priority and oldest first", which this backend served as age-only.
        let old_normal = task(1, Priority::Normal, 1_000);
        store.open(&old_normal).await.expect("open");
        store
            .open(&task(2, Priority::Normal, 1_001))
            .await
            .expect("open");
        store
            .open(&task(3, Priority::Normal, 1_002))
            .await
            .expect("open");
        let old_high = task(5, Priority::High, 1_500);
        store.open(&old_high).await.expect("open");
        let young_urgent = task(4, Priority::Urgent, 2_000);
        store.open(&young_urgent).await.expect("open");

        let page = store.queue(&[], 3).await.expect("queue");
        assert_eq!(page.len(), 3);
        assert_eq!(
            page[0].id, young_urgent.id,
            "an urgent task behind older normal ones must lead the page"
        );
        assert_eq!(
            page[1].id, old_high.id,
            "and every adjacent pair of ranks must be one the queue can tell apart"
        );
        assert_eq!(page[2].id, old_normal.id, "then oldest first");
    }

    /// The event-side alignments: waiter election by lowest effect key, and
    /// the `unclaimed` dead-letter wording.
    #[tokio::test]
    async fn postgres_event_contracts_match_the_embedded_backend() {
        let Ok(container) = Postgres::default().with_tag(PG).start().await else {
            eprintln!("skipping: no Docker daemon available");
            return;
        };
        let port = container.get_host_port_ipv4(5432).await.expect("port");
        let url = format!("postgresql://postgres:postgres@127.0.0.1:{port}/postgres");
        let store = PostgresStore::connect(&url)
            .await
            .expect("connect")
            .for_tenant(agentplane::core::TenantId::new("events-guard").expect("tenant"));

        // Waiter election. The higher effect key is registered first and
        // earlier, so an implementation electing by registration time picks
        // it — the drift this pins out.
        let run = RunId::generate();
        let low = EffectKey::from_hex(&"aa".repeat(32)).expect("key");
        let high = EffectKey::from_hex(&"bb".repeat(32)).expect("key");
        let sub = |effect: EffectKey| Subscription {
            run,
            effect,
            case: None,
            step: StepId(0),
            phase: Phase::Forward,
            kind: "ack.received".to_owned(),
            correlation: vec![CorrelationKey::new("shipment", "SHP-1")],
        };
        store
            .subscribe(&sub(high), at(1_000))
            .await
            .expect("subscribe");
        store
            .subscribe(&sub(low), at(2_000))
            .await
            .expect("subscribe");
        let event = InboundEvent {
            source: "erp".to_owned(),
            id: "evt-1".to_owned(),
            kind: "ack.received".to_owned(),
            correlation: vec![CorrelationKey::new("shipment", "SHP-1")],
            payload: serde_json::json!({ "ok": true }),
        };
        match store
            .deliver_to(run, &event, at(3_000))
            .await
            .expect("deliver")
        {
            agentplane::case::TargetedDelivery::Matched(matched) => {
                assert_eq!(
                    matched.effect, low,
                    "both backends must elect the same waiter: lowest effect key"
                );
            }
            other => panic!("the run was waiting: {other:?}"),
        }

        // Dead-letter wording: an unstated reason reads `unclaimed`, a stated
        // one is preserved.
        let stray = |n: u32| InboundEvent {
            source: "erp".to_owned(),
            id: format!("stray-{n}"),
            kind: "nobody.waits".to_owned(),
            correlation: vec![CorrelationKey::new("order", format!("ORD-{n}"))],
            payload: serde_json::json!({}),
        };
        store.buffer(&stray(1), at(1_000)).await.expect("buffer");
        assert_eq!(
            store.sweep_unclaimed(at(1_000), "").await.expect("sweep"),
            1
        );
        store.buffer(&stray(2), at(2_000)).await.expect("buffer");
        assert_eq!(
            store
                .sweep_unclaimed(at(2_000), "gave up waiting")
                .await
                .expect("sweep"),
            1
        );
        let letters = store.dead_letters(10).await.expect("dead letters");
        assert_eq!(letters.len(), 2);
        assert_eq!(letters[0].reason, "gave up waiting");
        assert_eq!(
            letters[1].reason, "unclaimed",
            "an unstated reason reads 'unclaimed', never an empty string"
        );
    }

    /// Plants rows no correct writer produces: a lease and an outcome entry
    /// under a run id that does not parse. Fixture for the corruption guard.
    struct Plant(String);

    #[async_trait::async_trait]
    impl agentplane::journal::AtomicWork for Plant {
        async fn run(
            &self,
            tx: &dyn agentplane::journal::AtomicTx,
        ) -> Result<Vec<agentplane::journal::Append>, agentplane::core::EffectError> {
            use agentplane::journal::SqlValue;
            let fail = |e: agentplane::core::StoreError| {
                agentplane::core::EffectError::Other(e.to_string())
            };
            tx.execute(
                "INSERT INTO run_lease (tenant, run_id, owner, epoch, expires_at)
                 VALUES ($1, 'not-a-run-id', 'w', 1, 0)",
                &[SqlValue::from(self.0.as_str())],
            )
            .await
            .map_err(fail)?;
            tx.execute(
                "INSERT INTO run_outcome (tenant, run_id, outcome, ordinal)
                 VALUES ($1, 'not-a-run-id', 'failed', 1)",
                &[SqlValue::from(self.0.as_str())],
            )
            .await
            .map_err(fail)?;
            Ok(Vec::new())
        }
    }

    /// A stored run id that does not parse is corruption, not a skipped row —
    /// the contract both backends now share. The rows are planted through the
    /// atomic seam because no public write path produces them, which is
    /// exactly why a silent skip would hide them forever.
    #[tokio::test]
    async fn postgres_reports_an_unparsable_run_id_as_corruption() {
        let Ok(container) = Postgres::default().with_tag(PG).start().await else {
            eprintln!("skipping: no Docker daemon available");
            return;
        };
        let port = container.get_host_port_ipv4(5432).await.expect("port");
        let url = format!("postgresql://postgres:postgres@127.0.0.1:{port}/postgres");
        let tenant = agentplane::core::TenantId::new("corrupt-scan").expect("tenant");
        let store = PostgresStore::connect(&url)
            .await
            .expect("connect")
            .for_tenant(tenant.clone());

        // Positive halves first, so the errors below come from the garbage
        // rather than from scans that refuse everything: a genuinely
        // abandoned run is listed, and a tenant with no conclusions answers
        // an empty page.
        let stranded = RunId::generate();
        store
            .acquire(stranded, "doomed", Duration::from_secs(1))
            .await
            .expect("lease");
        tokio::time::sleep(Duration::from_millis(1_500)).await;
        assert!(
            store
                .abandoned_runs(10)
                .await
                .expect("a clean sweep")
                .contains(&stranded)
        );
        assert!(
            store
                .runs_by_outcome("failed", 10)
                .await
                .expect("a clean listing")
                .is_empty()
        );

        store
            .atomic()
            .expect("atomic")
            .append_atomic(RunId::generate(), 1, &Plant(tenant.to_string()))
            .await
            .expect("plant the corrupt rows");

        let err = store
            .abandoned_runs(10)
            .await
            .expect_err("an unparsable lease row must refuse the sweep, not vanish from it");
        assert!(matches!(err, StoreError::Corrupt { .. }), "{err}");
        let err = store
            .runs_by_outcome("failed", 10)
            .await
            .expect_err("an unparsable outcome row must refuse the listing, not vanish from it");
        assert!(matches!(err, StoreError::Corrupt { .. }), "{err}");
    }
}
