//! Commissions that run while the skill continues.
//!
//! A coded skill starts several commissions and awaits each; the sub-runs work
//! at the same time. The start is the ordinary `agent.commission` effect, and
//! a start re-performed after a crash finds the sub-run it already admitted.

#![cfg(feature = "redb")]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use agentplane::core::{Outcome, RunId, Skill, SkillDescriptor, SkillError, Tainted};
use agentplane::journal::{Append, JournalStore, Record, RecordKind};
use agentplane::runtime::{Mode, RunStatus, Runtime, StepCtx};
use agentplane::store::RedbStore;
use serde_json::{Value, json};

/// Meets its sibling at a barrier: it finishes only if both run at once.
#[derive(Debug)]
struct Reviewer {
    name: &'static str,
    barrier: Arc<tokio::sync::Barrier>,
    runs: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl Skill for Reviewer {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new(self.name).provides(self.name)
    }

    async fn invoke(
        &self,
        _cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        self.runs.fetch_add(1, Ordering::SeqCst);
        if tokio::time::timeout(Duration::from_secs(5), self.barrier.wait())
            .await
            .is_err()
        {
            return Ok(Outcome::fail(
                "the other reviewer never ran beside this one",
            ));
        }
        Ok(Outcome::done(
            input.map(|v| json!({ "reviewed": v, "by": self.name })),
        ))
    }
}

/// Starts both reviews, then awaits both.
#[derive(Debug)]
struct Editor;

#[async_trait::async_trait]
impl Skill for Editor {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("editor").provides("edit")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let style = cx.start_commission("review.style", input.clone()).await?;
        let facts = cx.start_commission("review.facts", input).await?;
        let style = cx.await_commission(&style).await?;
        let facts = cx.await_commission(&facts).await?;
        let sources: Vec<String> = [&style, &facts]
            .iter()
            .flat_map(|answer| answer.label().provenance.iter().map(ToString::to_string))
            .collect();
        Ok(Outcome::done(Tainted::trusted(json!({
            "style": style.peek()["by"],
            "facts": facts.peek()["by"],
            "sources": sources,
        }))))
    }
}

fn plane(store: &Arc<RedbStore>, runs: &Arc<AtomicUsize>) -> Arc<Runtime> {
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    Runtime::builder(Arc::clone(store) as Arc<dyn JournalStore>)
        .skill(Editor)
        .skill(Reviewer {
            name: "review.style",
            barrier: Arc::clone(&barrier),
            runs: Arc::clone(runs),
        })
        .skill(Reviewer {
            name: "review.facts",
            barrier,
            runs: Arc::clone(runs),
        })
        .build()
}

/// **Two started commissions work at the same time**, and each answer comes
/// back labelled as from its own agent.
#[tokio::test]
async fn started_commissions_run_at_the_same_time() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let runs = Arc::new(AtomicUsize::new(0));
    let rt = plane(&store, &runs);
    let out = rt
        .start("edit", Tainted::trusted(json!("a draft")))
        .run()
        .await
        .unwrap();
    assert_eq!(out.status, RunStatus::Succeeded, "{:?}", out.status);
    let answer = out.output.expect("an answer").peek().clone();
    assert_eq!(answer["style"], "review.style");
    assert_eq!(answer["facts"], "review.facts");
    let sources = answer["sources"].to_string();
    assert!(
        sources.contains("agent/review.style") && sources.contains("agent/review.facts"),
        "an answer lost the agent it came from: {sources}"
    );
    assert_eq!(
        runs.load(Ordering::SeqCst),
        2,
        "a reviewer ran more than once"
    );
}

/// Copy `records` of `run` into `store`, as the run wrote them.
async fn copied(store: &RedbStore, run: RunId, records: &[Record]) {
    let lease = store
        .acquire(run, "copy", Duration::from_mins(5))
        .await
        .unwrap();
    for r in records {
        let mut a = Append::new(run, r.kind().clone()).phase(r.body.phase);
        if let Some(step) = r.body.step {
            a = a.step(step);
        }
        if let Some(key) = r.effect_key() {
            a = a.effect(key);
        }
        store.append(lease.epoch, vec![a]).await.unwrap();
    }
    store.release_lease(run, lease.epoch).await.unwrap();
}

fn started_sub_runs(records: &[Record]) -> usize {
    records
        .iter()
        .filter(|r| {
            matches!(r.kind(), RecordKind::EffectDone { .. })
                && records.iter().any(|s| {
                    s.effect_key() == r.effect_key()
                        && matches!(s.kind(), RecordKind::EffectStarted { descriptor, .. }
                            if descriptor.kind == "agent.commission")
                })
        })
        .count()
}

/// **A start re-performed after a crash finds its sub-run.** The parent's
/// journal is cut just after its first start was announced, beside every
/// record its sub-runs wrote; the resume performs that start again and must
/// attach to the sub-run already admitted, not commission a second.
#[tokio::test]
async fn a_resumed_start_reattaches_to_its_sub_run() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let runs = Arc::new(AtomicUsize::new(0));
    let rt = plane(&store, &runs);
    let out = rt
        .start("edit", Tainted::trusted(json!("a draft")))
        .run()
        .await
        .unwrap();
    assert_eq!(out.status, RunStatus::Succeeded);
    let parent = store.read(out.run_id, 1).await.unwrap();
    assert_eq!(started_sub_runs(&parent), 2);

    // The crash: just after the first start's announcement.
    let cut = parent
        .iter()
        .position(|r| {
            matches!(r.kind(), RecordKind::EffectStarted { descriptor, .. }
                if descriptor.kind == "agent.commission")
        })
        .expect("a start")
        + 1;
    let crashed = Arc::new(RedbStore::open_in_memory().unwrap());
    let all = (store.clone() as Arc<dyn JournalStore>)
        .runs_by_id(None, 100)
        .await
        .unwrap();
    for run in all.iter().filter(|r| **r != out.run_id) {
        copied(&crashed, *run, &store.read(*run, 1).await.unwrap()).await;
    }
    copied(&crashed, out.run_id, &parent[..cut]).await;

    let before = (crashed.clone() as Arc<dyn JournalStore>)
        .runs_by_id(None, 100)
        .await
        .unwrap()
        .len();
    let resumed = plane(&crashed, &Arc::new(AtomicUsize::new(0)))
        .replay(out.run_id, Mode::Resume)
        .await
        .unwrap();
    let after = (crashed.clone() as Arc<dyn JournalStore>)
        .runs_by_id(None, 100)
        .await
        .unwrap()
        .len();
    assert_eq!(
        after, before,
        "the re-performed start admitted a second sub-run beside the first"
    );
    assert_eq!(resumed.status, RunStatus::Succeeded, "{:?}", resumed.status);
}

/// Two parents commissioning the same work in the same order get two
/// sub-runs: the admission key names the parent run, so no run can attach to
/// another's.
#[tokio::test]
async fn two_parents_never_share_a_sub_run() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let runs = Arc::new(AtomicUsize::new(0));
    let rt = plane(&store, &runs);
    for _ in 0..2 {
        let out = rt
            .start("edit", Tainted::trusted(json!("a draft")))
            .run()
            .await
            .unwrap();
        assert_eq!(out.status, RunStatus::Succeeded, "{:?}", out.status);
    }
    assert_eq!(
        runs.load(Ordering::SeqCst),
        4,
        "a parent attached to another's sub-run"
    );
}
