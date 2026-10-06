//! A memory store whose erasures reach the semantic index built from it.

use std::sync::Arc;

use async_trait::async_trait;

use super::{Cascade, Forgotten, MemoryItem, MemoryStore, Recall, SemanticRetriever};
use crate::core::{StoreError, Timestamp};

/// A [`MemoryStore`] that tells a [`SemanticRetriever`] what every erasure
/// removed.
///
/// The index is derived from the store, so an erasure that stops at the store
/// leaves the embedding behind — and an embedding is reconstructible content.
/// Every erasure verb here erases from the store first and then tells the
/// index; an index that could not be told turns the call into an error naming
/// what it still holds, so an erasure never reports success while a copy
/// survives.
///
/// What the index was not told is owed, not dropped: the store no longer
/// holds those rows, so repeating the verb would find nothing to tell. Every
/// later erasure verb — the runtime's next expiry sweep among them, even one
/// that erases nothing — delivers what is owed, and fails while it cannot. The debt lives in this
/// process; a restart between the erasure and the delivery loses it.
///
/// The runtime wraps its memory store in this when
/// [`semantic_memory`](crate::runtime::RuntimeBuilder::semantic_memory) is
/// wired, which covers the sweep it performs. Erasures a deployment makes on
/// its own handle reach the index only through this wrapper, so a sealing
/// store must hold it beneath the seal — the runtime refuses one that does
/// not.
#[derive(Debug, Clone)]
pub struct IndexedMemoryStore {
    inner: Arc<dyn MemoryStore>,
    index: Arc<dyn SemanticRetriever>,
    owed: Arc<tokio::sync::Mutex<Vec<Forgotten>>>,
}

impl IndexedMemoryStore {
    #[must_use]
    pub fn new(inner: Arc<dyn MemoryStore>, index: Arc<dyn SemanticRetriever>) -> Self {
        Self {
            inner,
            index,
            owed: Arc::default(),
        }
    }

    /// Tells the index what the store just erased, after whatever earlier
    /// erasures still owe it; what it refuses stays owed.
    async fn tell(&self, forgotten: Vec<Forgotten>) -> Result<(), StoreError> {
        let mut owed = self.owed.lock().await;
        owed.extend(forgotten);
        while let Some(forgotten) = owed.first() {
            self.index.forget(forgotten).await.map_err(|e| {
                StoreError::Backend(format!(
                    "erased from memory, but the semantic index still holds {forgotten:?} \
                     until a later erasure delivers it: {e}"
                ))
            })?;
            owed.remove(0);
        }
        Ok(())
    }
}

#[async_trait]
impl MemoryStore for IndexedMemoryStore {
    fn tenant(&self) -> &str {
        self.inner.tenant()
    }

    fn erasure_is_distributed(&self) -> Option<bool> {
        self.inner.erasure_is_distributed()
    }

    fn seals(&self) -> bool {
        self.inner.seals()
    }

    /// This index — unless a sealing layer sits beneath, whose own subject
    /// erasure runs below this wrapper and reaches only an index beneath it.
    fn erasure_index(&self) -> Option<Arc<dyn SemanticRetriever>> {
        if self.inner.seals() {
            self.inner.erasure_index()
        } else {
            Some(Arc::clone(&self.index))
        }
    }

    async fn remember(&self, item: &MemoryItem) -> Result<u64, StoreError> {
        self.inner.remember(item).await
    }

    async fn recall(&self, query: &Recall) -> Result<Vec<MemoryItem>, StoreError> {
        self.inner.recall(query).await
    }

    async fn subject_ids(&self, subject: &str) -> Result<Vec<String>, StoreError> {
        self.inner.subject_ids(subject).await
    }

    async fn version(&self, id: &str, version: u64) -> Result<Option<MemoryItem>, StoreError> {
        self.inner.version(id, version).await
    }

    async fn current(
        &self,
        id: &str,
        as_of: Option<Timestamp>,
    ) -> Result<Option<MemoryItem>, StoreError> {
        self.inner.current(id, as_of).await
    }

    async fn forget(&self, id: &str) -> Result<(), StoreError> {
        self.inner.forget(id).await?;
        self.tell(vec![Forgotten::Ids(vec![id.to_owned()])]).await
    }

    async fn forget_subject(&self, subject: &str) -> Result<usize, StoreError> {
        let count = self.inner.forget_subject(subject).await?;
        self.tell(vec![Forgotten::Subject(subject.to_owned())])
            .await?;
        Ok(count)
    }

    async fn derivatives(&self, id: &str) -> Result<Vec<MemoryItem>, StoreError> {
        self.inner.derivatives(id).await
    }

    async fn forget_cascading(&self, id: &str) -> Result<Cascade, StoreError> {
        let cascade = self.inner.forget_cascading(id).await?;
        let mut forgotten = Vec::new();
        if !cascade.erased.is_empty() {
            forgotten.push(Forgotten::Ids(
                cascade.erased.iter().map(|(id, _)| id.clone()).collect(),
            ));
        }
        if !cascade.trimmed.is_empty() {
            forgotten.push(Forgotten::Versions(cascade.trimmed.clone()));
        }
        self.tell(forgotten).await?;
        Ok(cascade)
    }

    async fn set_legal_hold(&self, id: &str, held: bool) -> Result<(), StoreError> {
        self.inner.set_legal_hold(id, held).await
    }

    async fn legal_hold(&self, id: &str) -> Result<bool, StoreError> {
        self.inner.legal_hold(id).await
    }

    async fn legal_holds(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<String>, StoreError> {
        self.inner.legal_holds(after, limit).await
    }

    async fn sweep_expired(&self, at: Timestamp) -> Result<Vec<(String, u64)>, StoreError> {
        let swept = self.inner.sweep_expired(at).await?;
        let mut forgotten = Vec::new();
        if !swept.is_empty() {
            forgotten.push(Forgotten::Ids(
                swept.iter().map(|(id, _)| id.clone()).collect(),
            ));
        }
        self.tell(forgotten).await?;
        Ok(swept)
    }

    async fn touch(&self, ids: &[String], at: Timestamp) -> Result<(), StoreError> {
        self.inner.touch(ids, at).await
    }
}
