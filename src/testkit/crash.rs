//! Every point a process could have died during a recorded run.
//!
//! A crash truncates an append-only journal, so **every prefix of a real run's
//! journal is a crash that could have happened**. [`crash_points`] rebuilds each
//! prefix into a store of its own; the caller builds its runtime over it,
//! resumes, and [`assert_resumed_honestly`] checks what the journal alone can
//! show:
//!
//! - the chain verifies after the resume;
//! - replay read every finished effect back: the store's exactly-once index,
//!   which refuses a second announcement, was never what stopped the run;
//! - a refusal or a quarantine has a cause in the prefix: a run that crashed
//!   before its plan was frozen never started, and only an effect announced
//!   with no outcome can be undecidable.
//!
//! What it cannot see is the world. An embedder whose effects touch files or
//! processes checks those itself, against [`CrashPoint::done`].
//!
//! ```ignore
//! for point in crash_points(&*store, run).await? {
//!     let rt = build(Arc::clone(&point.store));
//!     let resumed = rt.replay(run, Mode::Resume).await;
//!     assert_resumed_honestly(&point, run, &resumed).await;
//! }
//! ```

use std::collections::BTreeSet;
use std::sync::Arc;

use crate::core::{EffectKey, RunId, RuntimeError, StoreError};
use crate::journal::{Append, JournalStore, Record, RecordKind};
use crate::runtime::{RunOutcome, RunStatus};
use crate::store::RedbStore;

/// The journal as a crash after its first `appended` records left it, in an
/// in-memory store of its own with the lease released.
#[derive(Debug, Clone)]
pub struct CrashPoint {
    /// How many records survived the crash.
    pub appended: usize,
    /// The surviving journal, ready to resume.
    pub store: Arc<RedbStore>,
    prefix: Vec<Record>,
}

impl CrashPoint {
    /// The effects the prefix records as finished. A resume reads them back
    /// and must never perform them again.
    #[must_use]
    pub fn done(&self) -> BTreeSet<EffectKey> {
        self.prefix
            .iter()
            .filter(|r| matches!(r.kind(), RecordKind::EffectDone { .. }))
            .filter_map(Record::effect_key)
            .collect()
    }

    /// Effects announced with no outcome: the only state an undecidable
    /// effect, and so a quarantine, can come from.
    fn in_flight(&self) -> BTreeSet<EffectKey> {
        let mut open = BTreeSet::new();
        for r in &self.prefix {
            let Some(key) = r.effect_key() else { continue };
            match r.kind() {
                RecordKind::EffectStarted { .. } => {
                    open.insert(key);
                }
                RecordKind::EffectDone { .. }
                | RecordKind::EffectFailed { .. }
                | RecordKind::EffectReconciled { .. } => {
                    open.remove(&key);
                }
                _ => {}
            }
        }
        open
    }

    fn froze_a_plan(&self) -> bool {
        self.prefix
            .iter()
            .any(|r| matches!(r.kind(), RecordKind::PlanFrozen { .. }))
    }
}

/// Every crash point of `run`: one per record after the first.
///
/// # Errors
///
/// What reading `store`, or writing a prefix into a fresh one, refuses.
pub async fn crash_points(
    store: &dyn JournalStore,
    run: RunId,
) -> Result<Vec<CrashPoint>, StoreError> {
    let records = store.read(run, 1).await?;
    let mut points = Vec::with_capacity(records.len().saturating_sub(1));
    for appended in 1..records.len() {
        let prefix = records[..appended].to_vec();
        points.push(CrashPoint {
            appended,
            store: rebuilt(run, &prefix).await?,
            prefix,
        });
    }
    Ok(points)
}

/// Re-forms a prefix through `append`, so the chain is rebuilt from contents
/// exactly as the run built it.
async fn rebuilt(run: RunId, prefix: &[Record]) -> Result<Arc<RedbStore>, StoreError> {
    let store = Arc::new(RedbStore::open_in_memory()?);
    let lease = store
        .acquire(run, "crash-point", std::time::Duration::from_mins(5))
        .await?;
    for r in prefix {
        let mut a = Append::new(run, r.kind().clone()).phase(r.body.phase);
        if let Some(step) = r.body.step {
            a = a.step(step);
        }
        if let Some(case) = r.body.case {
            a = a.case(case);
        }
        if let Some(key) = r.effect_key() {
            a = a.effect(key);
        }
        store.append(lease.epoch, vec![a]).await?;
    }
    // What a crash leaves is a lease anyone may claim, not one still held.
    store.release_lease(run, lease.epoch).await?;
    Ok(store)
}

/// Panic unless a resume from `point` ended as the design allows.
///
/// # Panics
///
/// If the chain no longer verifies; if the resume was stopped by the store's
/// exactly-once index; if it was
/// refused although the prefix froze a plan; or if it quarantined although no
/// effect was in flight at the crash.
pub async fn assert_resumed_honestly(
    point: &CrashPoint,
    run: RunId,
    resumed: &Result<RunOutcome, RuntimeError>,
) {
    let at = format!("crash after record {}", point.appended);
    super::assert_replay_was_not_backstopped(&at, resumed);
    point
        .store
        .verify(run)
        .await
        .unwrap_or_else(|e| panic!("{at}: the chain does not verify after the resume: {e}"));

    match resumed {
        Err(e) => assert!(
            !point.froze_a_plan(),
            "{at}: the resume was refused, though the prefix froze a plan: {e}"
        ),
        Ok(outcome) => {
            if let RunStatus::Quarantined(why) = &outcome.status {
                assert!(
                    !point.in_flight().is_empty(),
                    "{at}: the run quarantined with no effect in flight at the crash: {why}"
                );
            }
        }
    }
}
