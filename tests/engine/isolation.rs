//! Two planes in one process share nothing.
//!
//! A host serving several projects runs one `Runtime` per project, each on its
//! own store. Nothing in the process connects them: a halt, a delivery, a
//! lease, a wait, a follower's signal or a listing on one never reaches the
//! other. The tenant is not this boundary — it partitions one store.

#![cfg(feature = "redb")]
#![allow(clippy::disallowed_methods)]

use std::sync::Arc;
use std::time::Duration;

use agentplane::core::{
    AwaitSpec, CorrelationKey, DeadlineSpec, Delivery, InboundEvent, Outcome, Skill,
    SkillDescriptor, SkillError, Tainted,
};
use agentplane::journal::JournalStore;
use agentplane::quota::HaltScope;
use agentplane::runtime::{RunTerms, Runtime, StepCtx};
use agentplane::store::RedbStore;
use serde_json::{Value, json};

/// Waits for one message, then finishes with it.
#[derive(Debug)]
struct Waits;

#[async_trait::async_trait]
impl Skill for Waits {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("waits").provides("waits")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        cx.deadline("window", &DeadlineSpec::days(1), None).await?;
        let v = cx
            .await_event(
                &AwaitSpec::new("go", "window").correlate(CorrelationKey::new("matter", "M-1")),
            )
            .await?;
        Ok(Outcome::done(v))
    }
}

fn plane(store: Arc<RedbStore>) -> Arc<Runtime> {
    Runtime::builder_on(store).skill(Waits).build()
}

fn operator() -> agentplane::core::Operator {
    agentplane::core::Operator::asserted("ops").expect("a fixture names its operator")
}

async fn waiting(rt: &Runtime) -> agentplane::core::RunId {
    let out = rt
        .start("waits", Tainted::trusted(json!({})))
        .terms(RunTerms::default().correlated("matter", &[CorrelationKey::new("matter", "M-1")]))
        .run()
        .await
        .unwrap();
    assert!(out.status.is_suspended(), "{:?}", out.status);
    out.run_id
}

async fn two_planes_share_nothing(a: Arc<RedbStore>, b: Arc<RedbStore>) {
    let (one, two) = (plane(Arc::clone(&a)), plane(Arc::clone(&b)));
    let first = waiting(&one).await;
    let second = waiting(&two).await;

    // A listing on one plane holds its own runs only.
    let listed = |store: &Arc<RedbStore>| {
        let store = Arc::clone(store);
        async move {
            (store as Arc<dyn JournalStore>)
                .recent_runs(None, 100)
                .await
                .unwrap()
                .into_iter()
                .map(|(run, _)| run)
                .collect::<Vec<_>>()
        }
    };
    assert_eq!(
        listed(&a).await,
        vec![first],
        "plane one lists another plane's run"
    );
    assert_eq!(
        listed(&b).await,
        vec![second],
        "plane two lists another plane's run"
    );

    // A follower on one plane hears nothing of the other's appends.
    let mut follower = (Arc::clone(&a) as Arc<dyn JournalStore>)
        .watch(second)
        .await
        .expect("a follower");

    // A halt on one plane stops that plane only.
    one.set_halt(
        &HaltScope::Tenant,
        &operator(),
        agentplane::core::Timestamp::now_utc(),
        "stop one",
    )
    .await
    .unwrap();
    assert!(
        two.halts().await.unwrap().is_empty(),
        "a halt crossed planes"
    );

    // A delivery resumes the waiting run on its own plane, and reaches no
    // waiter on the other.
    let go = InboundEvent::new("urn:test", "E-1", "go", json!({ "ok": true }))
        .correlate(CorrelationKey::new("matter", "M-1"));
    assert_eq!(
        two.deliver(&go).await.unwrap(),
        Delivery::Resumed { run: second }
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), follower.changed())
            .await
            .is_err(),
        "a follower on one plane woke on another plane's append"
    );
    let first_state = one.recorded_outcome(first).await.unwrap().expect("resting");
    assert!(
        first_state.status.is_suspended(),
        "a delivery on one plane resumed a run on the other: {:?}",
        first_state.status
    );
}

/// Two in-memory planes in one process.
#[tokio::test]
async fn two_planes_in_memory_share_nothing() {
    two_planes_share_nothing(
        Arc::new(RedbStore::open_in_memory().unwrap()),
        Arc::new(RedbStore::open_in_memory().unwrap()),
    )
    .await;
}

/// Two planes on two journal files in one process.
#[tokio::test]
async fn two_planes_on_files_share_nothing() {
    let dir = std::env::temp_dir().join(format!(
        "agentplane-isolation-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    two_planes_share_nothing(
        Arc::new(RedbStore::open(dir.join("one.redb")).unwrap()),
        Arc::new(RedbStore::open(dir.join("two.redb")).unwrap()),
    )
    .await;
    let _ = std::fs::remove_dir_all(&dir);
}
