//! One battery pinning every native `due_in` to the trait's own default.
//!
//! `PushStore::due_in` ships a paging default that is correct against any
//! backend, and both stores override it with an in-query filter for the reason
//! the trait documents. An override is where semantics drift: a filter that
//! reads `LIKE` where the default reads `owns_id`, or a scan that stops where
//! the default keeps counting, would hand each worker a slightly different
//! plane — and nothing would fail until a deployment ran one worker and read
//! its backlog number as zero.
//!
//! So each backend is run against **its own default**: the same store, wrapped
//! so the trait's paging implementation runs over it, and the two answers are
//! compared. Where the due set fits the limit the two must agree exactly —
//! rows and `unserved` both, because an exhausted read leaves no window for
//! them to differ in. Where the limit truncates, the rows must still be the
//! same rows (the head of the store's stable order) and the counts may differ
//! only in the direction `unserved`'s contract allows: it is documented as a
//! lower bound, and the native overrides count the *whole* foreign backlog
//! while the default counts what its final window happened to hold.

use std::sync::Arc;

use agentplane::core::{RunId, Secret, StoreError};
use agentplane::push::{DueBatch, PushConfig, PushNamespace, PushRegistration, PushStore};

/// The trait's default `due_in`, forced over any backend.
///
/// Forwards every method except `due_in`, so the default paging implementation
/// runs against the same rows the native override reads. This is the fixture
/// that keeps "override" meaning *faster*, never *different*.
#[derive(Debug)]
pub struct DefaultPaged(pub Arc<dyn PushStore>);

#[async_trait::async_trait]
impl PushStore for DefaultPaged {
    async fn put(&self, config: &PushConfig, next_seq: u64) -> Result<(), StoreError> {
        self.0.put(config, next_seq).await
    }

    async fn get(&self, task: RunId, id: &str) -> Result<Option<PushConfig>, StoreError> {
        self.0.get(task, id).await
    }

    async fn list(&self, task: RunId) -> Result<Vec<PushConfig>, StoreError> {
        self.0.list(task).await
    }

    async fn due(&self, at: u64, limit: usize) -> Result<Vec<PushRegistration>, StoreError> {
        self.0.due(at, limit).await
    }

    // `due_in` deliberately absent: the trait default is the point.

    async fn advance(&self, task: RunId, id: &str, next_seq: u64) -> Result<(), StoreError> {
        self.0.advance(task, id, next_seq).await
    }

    async fn retry(
        &self,
        task: RunId,
        id: &str,
        next_attempt_at: u64,
        error: &str,
    ) -> Result<(), StoreError> {
        self.0.retry(task, id, next_attempt_at, error).await
    }

    async fn delete(&self, task: RunId, id: &str) -> Result<(), StoreError> {
        self.0.delete(task, id).await
    }
}

fn config(task: RunId, id: &str) -> PushConfig {
    PushConfig {
        id: id.to_owned(),
        task,
        url: "https://hooks.acme.example/a2a".to_owned(),
        token: Some(Secret::new("opaque")),
        authentication: None,
    }
}

/// The identity of a due row, for comparing two implementations' answers.
fn shape(rows: &[PushRegistration]) -> Vec<(RunId, String, u64, u32, u64)> {
    rows.iter()
        .map(|registration| {
            (
                registration.config.task,
                registration.config.id.clone(),
                registration.next_seq,
                registration.attempts,
                registration.next_attempt_at,
            )
        })
        .collect()
}

async fn both(
    store: &Arc<dyn PushStore>,
    at: u64,
    limit: usize,
    namespace: PushNamespace,
) -> (DueBatch, DueBatch) {
    let native = store.due_in(at, limit, namespace).await.expect("native");
    let paged = DefaultPaged(Arc::clone(store))
        .due_in(at, limit, namespace)
        .await
        .expect("default");
    (native, paged)
}

/// Run the pin against one backend.
///
/// The scenario mixes both namespaces across two tasks, staggers the retry
/// instants so the stable order is not the insertion order, and leaves one row
/// of each namespace not yet due — so the due filter, the namespace filter and
/// the count are all load-bearing at once.
pub async fn pin_due_in_against_the_default(store: Arc<dyn PushStore>) {
    let (t1, t2) = (RunId::generate(), RunId::generate());
    for (task, id, retry_at) in [
        // Three caller webhooks due at 20, one not.
        (t1, "hook-a", None),
        (t1, "hook-b", Some(5)),
        (t2, "hook-c", Some(10)),
        (t2, "hook-late", Some(200)),
        // Two operator destinations due at 20, one not.
        (t1, "operator:bus", None),
        (t2, "operator:audit", Some(7)),
        (t2, "operator:late", Some(100)),
    ] {
        store.put(&config(task, id), 1).await.expect("put");
        if let Some(at) = retry_at {
            store.retry(task, id, at, "staggered").await.expect("retry");
        }
    }

    for namespace in [PushNamespace::Caller, PushNamespace::Operator] {
        // Exhausted: the limit covers every due row, so the default reads the
        // store to the end and there is no window left to disagree in. Rows
        // and unserved must both match exactly.
        let (native, paged) = both(&store, 20, 10, namespace).await;
        assert_eq!(
            shape(&native.rows),
            shape(&paged.rows),
            "the native due_in and the trait default disagree about which rows \
             {namespace:?} owns"
        );
        assert_eq!(
            native.unserved, paged.unserved,
            "the native due_in and the trait default disagree about the \
             foreign backlog visible past an exhausted read"
        );

        // Saturated: the limit truncates. The rows must still be the head of
        // the same stable order; `unserved` is a lower bound in both, and the
        // native override's whole-backlog count may only ever be the larger.
        let (native, paged) = both(&store, 20, 1, namespace).await;
        assert_eq!(
            shape(&native.rows),
            shape(&paged.rows),
            "under a truncating limit the native due_in serves different rows \
             than the default would"
        );
        assert!(
            native.unserved >= paged.unserved,
            "the native override reported a smaller foreign backlog than the \
             default saw, so the lower bound shrank ({} < {})",
            native.unserved,
            paged.unserved
        );

        // An earlier instant: only the rows never retried are due — one per
        // namespace — so the due predicate is shown to be load-bearing rather
        // than every assertion above passing against a store where everything
        // is always due.
        let (native, paged) = both(&store, 0, 10, namespace).await;
        assert_eq!(shape(&native.rows), shape(&paged.rows));
        assert_eq!(
            native.rows.len(),
            1,
            "the due instant stopped filtering: {namespace:?} saw rows whose \
             retry is still in the future"
        );
        assert_eq!(native.unserved, paged.unserved);
        assert_eq!(native.unserved, 1);
    }
}
