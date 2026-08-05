//! Memory an agent keeps between runs, and the rules that keep it survivable.
//!
//! # Writable memory is delayed code
//!
//! A vector store bolted onto an agent looks like a cache and behaves like a
//! program. Whatever is written today is read back tomorrow *into a context
//! window*, where a model treats it as established fact — so a single poisoned
//! write becomes a standing instruction that fires on every later session. The
//! literature calls this the attack that waits, and its distinguishing property
//! is that nothing at read time looks wrong.
//!
//! Three rules follow, and none of them is about the storage engine.
//!
//! # Trust comes from provenance, never from content
//!
//! A recalled item is labelled by **where it came from**, not by what it says.
//! Content-inferred trust is adversarially gameable by construction: text that
//! asserts its own reliability is the cheapest thing an attacker can write.
//!
//! So [`MemoryItem`] carries its sources, and [`StepCtx::recall`] hands back a
//! [`Tainted`] value whose label is the join of them. An item written from a
//! model's output is untrusted forever, however many times it is re-read, and
//! reaching a mutating sink with it takes the same journaled release as any
//! other untrusted value.
//!
//! [`StepCtx::recall`]: crate::runtime::StepCtx::recall
//! [`Tainted`]: crate::core::Tainted
//!
//! # Retrieval is an effect, not a lookup
//!
//! Memory is mutable state outside the journal, so reading it from inside the
//! deterministic zone would make replay depend on what the store happens to hold
//! *now*. A run replayed after a later write would retrieve different items,
//! reach different conclusions, and produce a history that disagrees with itself
//! — the exact failure the effect protocol exists to prevent.
//!
//! So a recall is journaled: the query, the filters, and the **selection** — item
//! ids with their exact versions and content digests. Replay reads that record
//! and re-materialises those versions rather than re-running the search, so the
//! ranking is not re-computed and cannot drift with the corpus.
//!
//! # Content is versioned and supersedable, never edited in place
//!
//! A memory that can be rewritten in place cannot be audited, and cannot be
//! repaired: there is no way to ask what the agent believed last Tuesday, and no
//! way to undo one bad write without guessing what it replaced. Writes append a
//! new version and mark the old version's lifecycle metadata superseded. Its
//! content and security metadata remain unchanged, forgetting is selective, and
//! lineage survives correction so a later erasure can still traverse it.

use std::fmt::Debug;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::core::{Digest, Label, Sensitivity, SourceId, StoreError, Timestamp, Trust};

/// One remembered thing.
///
/// The fields beyond `content` are not bookkeeping. Each answers a question that
/// an agent acting on a memory has to be able to ask, and that a store holding
/// only text cannot answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryItem {
    /// Stable across versions: this is *the same memory*, revised. Subject and
    /// purpose cannot change under it, and it is not reusable after forgetting;
    /// use a new id for another scope or unrelated content.
    pub id: String,
    /// What this is about — an account, a customer, a matter. The primary
    /// retrieval axis, and the unit selective forgetting works on.
    pub subject: String,
    /// Why it was kept. Retrieval filters on it, so a memory written for
    /// support triage is not silently read into a payments decision.
    pub purpose: String,
    /// The remembered content.
    pub content: Value,
    /// Where it came from.
    ///
    /// The label is derived from this and never from `content` — see the module
    /// docs on why content-inferred trust is gameable.
    pub provenance: Vec<SourceId>,
    /// How far this may travel.
    pub sensitivity: Sensitivity,
    /// Whether the content may be believed without a release.
    ///
    /// Set by the writer from the source, not inferred. Anything derived from a
    /// model, a peer, or an inbound message is untrusted.
    pub trust: Trust,
    /// The run that wrote it, so a bad write is attributable to a history.
    pub written_by: String,
    /// Monotonic per `id`. A write appends; nothing is edited in place.
    pub version: u64,
    pub created_at: Timestamp,
    /// Set when a later version replaced this one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superseded_at: Option<Timestamp>,
    /// The memories this one was derived from, at the versions actually read.
    ///
    /// Empty for an ordinary write. Populated by compaction, and it is what
    /// makes a summary repairable: without it, forgetting a poisoned memory
    /// leaves every summary that absorbed it in place, and the attack survives
    /// its own remedy. Stores validate every source commitment and require the
    /// derived memory to remain in the same subject, so subject erasure reaches
    /// the whole derivation graph.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub derived_from: Vec<Selected>,
}

impl MemoryItem {
    /// The label a recalled value carries.
    ///
    /// Derived from the declared trust, sensitivity and sources — never from
    /// reading the content. That is the whole defence: an item that says
    /// "verified by the security team" is a string, and a string cannot promote
    /// itself.
    #[must_use]
    pub fn label(&self) -> Label {
        let mut label = if self.trust == Trust::Trusted {
            Label::trusted()
        } else {
            Label::untrusted(SourceId::new(format!("memory:{}", self.id)))
        };
        for source in &self.provenance {
            label.provenance.insert(source.clone());
        }
        label.sensitivity = self.sensitivity;
        label
    }

    /// What the journal records instead of the content.
    ///
    /// Personal data belongs in an erasable store, not in a hash chain that
    /// cannot be redacted — so a recall journals this and re-materialises the
    /// content on replay.
    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::of(&crate::core::canon::value_bytes(&self.content))
    }

    /// Commitment used when this version is selected for a run.
    ///
    /// Content alone is insufficient: changing an item's trust, provenance,
    /// sensitivity, scope, or attribution changes what a replay may do with the
    /// same bytes. `id` and `version` travel beside this digest in [`Selected`];
    /// `superseded_at` is deliberately excluded because it is lifecycle state
    /// that may change after a run selected the version.
    #[must_use]
    pub fn selection_digest(&self) -> Digest {
        Digest::of(&crate::core::canon::value_bytes(&serde_json::json!({
            "subject": self.subject,
            "purpose": self.purpose,
            "content": self.digest().to_hex(),
            "provenance": self.provenance,
            "sensitivity": self.sensitivity,
            "trust": self.trust,
            "written_by": self.written_by,
            "created_at": self.created_at,
            "derived_from": self.derived_from,
        })))
    }
}

/// What to recall.
///
/// Deliberately not a free-text similarity query alone. `subject` and `purpose`
/// are the axes an operator can reason about and a policy can be written
/// against; a store may rank within them however it likes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Recall {
    pub subject: String,
    /// Restrict to memories kept for this purpose, when given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    /// At most this many, newest first.
    pub limit: usize,
}

impl Recall {
    #[must_use]
    pub fn about(subject: impl Into<String>) -> Self {
        Self {
            subject: subject.into(),
            purpose: None,
            limit: 10,
        }
    }

    #[must_use]
    pub fn for_purpose(mut self, purpose: impl Into<String>) -> Self {
        self.purpose = Some(purpose.into());
        self
    }

    #[must_use]
    pub const fn limit(mut self, n: usize) -> Self {
        self.limit = n;
        self
    }
}

/// Where a summary should land.
///
/// The parts of a memory a caller genuinely decides. Everything else about a
/// summary — its provenance, trust, sensitivity, and what it was made from — is
/// derived from the inputs, because those are not matters of opinion.
#[derive(Debug, Clone, PartialEq)]
pub struct Compaction {
    pub id: String,
    pub subject: String,
    pub purpose: String,
    pub at: Timestamp,
    /// What to tell the model to do with the memories.
    pub instruction: String,
    /// The highest sensitivity the summarising model may be shown.
    ///
    /// `Public` by default, which refuses to summarise anything above it. That
    /// is deliberate: compaction *sends the memories to a model*, so it is an
    /// egress decision and not a storage one. Without a ceiling here, summarising
    /// would be the way to move confidential content past a limit that stops
    /// every other path — and it would look like housekeeping.
    pub max_sensitivity: Sensitivity,
}

/// One selected memory, as the journal records it.
///
/// Ids and versions rather than content: this is what makes a replay reproduce
/// the *selection* without re-running the search, and it keeps the content out
/// of a chain that cannot be redacted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Selected {
    pub id: String,
    pub version: u64,
    /// What the immutable content and security metadata were when selected.
    ///
    /// Checked on replay: an item whose content, label inputs, scope, lineage,
    /// or attribution changed under a version that is supposed to be immutable
    /// is a store that cannot reproduce history. Lifecycle-only
    /// `superseded_at` is excluded so a later legitimate revision does not make
    /// an earlier run unreplayable.
    pub digest: Digest,
}

/// Why a memory operation could not be completed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MemoryError {
    /// A version named by the journal is no longer in the store.
    ///
    /// Distinguished from a plain miss because the two mean opposite things: a
    /// miss is an empty result, and this is a **history that can no longer be
    /// reproduced** — usually because the memory was deliberately forgotten.
    #[error(
        "memory '{id}' version {version} was recalled by this run and is no longer \
         stored — it was forgotten, so this history cannot be replayed as it happened"
    )]
    Forgotten { id: String, version: u64 },

    /// The stored content no longer hashes to what was recorded.
    #[error(
        "memory '{id}' version {version} has different content or security metadata \
            than when it was recalled — a version is supposed to be immutable, so this \
            store cannot reproduce its own history"
    )]
    Rewritten { id: String, version: u64 },

    #[error("the memory store could not be reached: {0}")]
    Unavailable(String),
}

impl From<StoreError> for MemoryError {
    fn from(e: StoreError) -> Self {
        Self::Unavailable(e.to_string())
    }
}

/// Where memories live.
#[async_trait]
pub trait MemoryStore: Send + Sync + Debug {
    /// Append a new version of a memory.
    ///
    /// Appends rather than replaces: the previous version is marked superseded
    /// and kept, so lineage survives and one bad write can be undone without
    /// guessing what it replaced.
    ///
    /// # Errors
    ///
    /// If the store cannot be reached.
    async fn remember(&self, item: &MemoryItem) -> Result<u64, StoreError>;

    /// The current versions matching a query, newest first.
    ///
    /// Superseded and forgotten versions are not returned.
    ///
    /// # Errors
    ///
    /// If the store cannot be reached.
    async fn recall(&self, query: &Recall) -> Result<Vec<MemoryItem>, StoreError>;

    /// One exact version, superseded or not.
    ///
    /// This is what replay uses: it names the version the run actually read, not
    /// whatever is current now.
    ///
    /// # Errors
    ///
    /// If the store cannot be reached.
    async fn version(&self, id: &str, version: u64) -> Result<Option<MemoryItem>, StoreError>;

    /// Forget a memory and every version of it.
    ///
    /// Selective by construction: one id, not a purge. A repair that can only
    /// drop everything is one nobody performs. The id remains reserved after
    /// erasure: recycling it could make an old journal selection or derivation
    /// edge refer to unrelated new content.
    ///
    /// # Errors
    ///
    /// If the store cannot be reached.
    async fn forget(&self, id: &str) -> Result<(), StoreError>;

    /// Forget everything about a subject.
    ///
    /// The unit an erasure request names — a person, an account, a matter.
    ///
    /// # Errors
    ///
    /// If the store cannot be reached.
    async fn forget_subject(&self, subject: &str) -> Result<usize, StoreError>;

    /// Memories derived from this one, directly.
    ///
    /// The repair path. A summary absorbs what it summarised, so a poisoned
    /// memory does not stop being a problem when it is forgotten — it stops
    /// being *visible* while its content continues to arrive in every summary
    /// that read it.
    ///
    /// # Errors
    ///
    /// If the store cannot be reached.
    async fn derivatives(&self, id: &str) -> Result<Vec<MemoryItem>, StoreError>;

    /// Forget a memory and everything derived from it, transitively.
    ///
    /// The form an **erasure** request needs. [`forget`](Self::forget) is the
    /// form a *correction* needs: a stale memory whose summaries are still
    /// legitimate should not take them with it. The two are separate calls
    /// because they answer different questions, and defaulting either way would
    /// be wrong half the time — silently.
    ///
    /// # Errors
    ///
    /// If the store cannot be reached.
    async fn forget_cascading(&self, id: &str) -> Result<usize, StoreError> {
        let mut removed = 0;
        let mut queue = vec![id.to_owned()];
        let mut seen = std::collections::BTreeSet::new();
        while let Some(next) = queue.pop() {
            if !seen.insert(next.clone()) {
                // A derivation cycle is not expressible by construction — a
                // summary names versions that already exist — but a store is a
                // store, and a repair that loops forever is worse than one that
                // stops.
                continue;
            }
            for derived in self.derivatives(&next).await? {
                queue.push(derived.id);
            }
            self.forget(&next).await?;
            removed += 1;
        }
        Ok(removed)
    }
}
