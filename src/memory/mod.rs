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
    /// When this version stops being eligible for fresh recall.
    ///
    /// Exact-version reads remain available for replay until an explicit
    /// lifecycle sweep erases the memory. The cutoff is evaluated against the
    /// journaled `Recall::as_of`, never an ambient store clock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Timestamp>,
    /// Sliding retention window refreshed only by an explicit journaled touch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_retention_seconds: Option<u64>,
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

/// Where a runtime memory write lands.
///
/// Security metadata is intentionally absent. [`StepCtx::remember`] derives
/// trust, provenance and sensitivity from the `Tainted<Value>` being stored, so
/// an untrusted model result cannot be promoted by constructing metadata that
/// says otherwise.
///
/// [`StepCtx::remember`]: crate::runtime::StepCtx::remember
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryWrite {
    pub id: String,
    pub subject: String,
    pub purpose: String,
    pub expires_at: Option<Timestamp>,
    pub access_retention_seconds: Option<u64>,
}

impl MemoryWrite {
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        subject: impl Into<String>,
        purpose: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            subject: subject.into(),
            purpose: purpose.into(),
            expires_at: None,
            access_retention_seconds: None,
        }
    }

    /// Expire this memory from fresh recall at a deterministic instant.
    #[must_use]
    pub const fn expires_at(mut self, at: Timestamp) -> Self {
        self.expires_at = Some(at);
        self
    }

    /// Keep the memory for this long after each explicitly journaled recall.
    #[must_use]
    pub const fn retain_after_access(mut self, seconds: u64) -> Self {
        self.access_retention_seconds = Some(seconds);
        self
    }
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
            "expires_at": self.expires_at,
            "access_retention_seconds": self.access_retention_seconds,
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
    /// Deterministic lifecycle cutoff. Set by [`StepCtx::recall`] from its
    /// journaled clock; direct store callers may choose one explicitly.
    ///
    /// [`StepCtx::recall`]: crate::runtime::StepCtx::recall
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub as_of: Option<Timestamp>,
    /// Refresh sliding retention for selected memories as a second effect.
    #[serde(default)]
    pub refresh_access: bool,
}

impl Recall {
    #[must_use]
    pub fn about(subject: impl Into<String>) -> Self {
        Self {
            subject: subject.into(),
            purpose: None,
            limit: 10,
            as_of: None,
            refresh_access: false,
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

    #[must_use]
    pub const fn at(mut self, at: Timestamp) -> Self {
        self.as_of = Some(at);
        self
    }

    #[must_use]
    pub const fn refresh_access(mut self) -> Self {
        self.refresh_access = true;
        self
    }
}

/// A semantic query whose exact vector and index identity are journalable.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SemanticQuery {
    pub subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    /// Human-readable query used to produce `embedding`.
    pub text: String,
    /// Exact query vector, obtained through
    /// [`StepCtx::embed`](crate::runtime::StepCtx::embed).
    ///
    /// It is in the retrieval effect's key, so a replay must reproduce it
    /// exactly — which is why producing it is itself a journaled effect rather
    /// than a call a skill makes on its own. An embedding API is a network
    /// observation: two calls with the same text are not obliged to return the
    /// same floats, and a model revision guarantees they will not. Computing one
    /// inside the deterministic zone therefore quarantines a healthy run at the
    /// next replay, for a reason nothing on the record explains.
    pub embedding: Vec<f32>,
    /// Stable embedding model and revision.
    pub embedding_model: String,
    /// Immutable vector-index snapshot searched by this query.
    pub index_snapshot: String,
    pub limit: usize,
    /// Highest sensitivity this retriever may receive.
    pub max_sensitivity: Sensitivity,
}

/// One ranked semantic selection as journaled.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SemanticHit {
    pub selected: Selected,
    pub score: f32,
}

/// Derived semantic index, never durable memory truth.
#[async_trait]
pub trait SemanticRetriever: Send + Sync + Debug {
    /// Stable non-secret implementation configuration for effect identity.
    fn profile(&self) -> Value;

    async fn search(&self, query: &SemanticQuery) -> Result<Vec<SemanticHit>, StoreError>;
}

/// Turns text into a vector.
///
/// # Why this is a seam and not a helper
///
/// [`SemanticQuery::embedding`] enters the retrieval effect's key, so a strict
/// replay has to arrive at the same floats. An embedding service is a network
/// call: batching, hardware and a silent model revision all move the last bits,
/// and nothing about *the same text* obliges the same answer. A skill that
/// computed its own vector would therefore be making a nondeterministic
/// observation inside the deterministic zone, which is the one thing the effect
/// protocol exists to forbid — and the symptom would be a quarantine on replay
/// with nothing on the record to explain it.
///
/// So embedding crosses the effect protocol like every other observation:
/// [`StepCtx::embed`](crate::runtime::StepCtx::embed) journals the vector, and a
/// replay reads it back rather than asking again. That also makes the cost
/// visible — an embedding call is metered like any other effect — and puts the
/// model revision on the record beside the vector it produced.
///
/// The crate ships no driver, for the reason it ships no policy evaluator:
/// picking one for the embedder is not its call.
#[async_trait]
pub trait Embedder: Send + Sync + Debug {
    /// Stable, non-secret identity of the model and revision producing vectors.
    ///
    /// It goes in the effect key beside the text, so a revision change is
    /// replay divergence rather than a silently different vector. Secrets never
    /// belong here.
    fn revision(&self) -> String;

    /// Embed one text.
    ///
    /// # Errors
    ///
    /// [`StoreError::Backend`] when the service cannot be reached or answers
    /// with something that is not a vector.
    async fn embed(&self, text: &str) -> Result<Vec<f32>, StoreError>;
}

/// One immutable vector record for [`InMemorySemanticRetriever`].
#[derive(Debug, Clone)]
pub struct SemanticVector {
    pub subject: String,
    pub purpose: String,
    pub selected: Selected,
    pub embedding: Vec<f32>,
}

/// Deterministic exact cosine retriever for tests and small corpora.
#[derive(Debug, Clone)]
pub struct InMemorySemanticRetriever {
    identity: String,
    snapshot: String,
    vectors: Vec<SemanticVector>,
}

impl InMemorySemanticRetriever {
    #[must_use]
    pub fn new(
        identity: impl Into<String>,
        snapshot: impl Into<String>,
        vectors: Vec<SemanticVector>,
    ) -> Self {
        Self {
            identity: identity.into(),
            snapshot: snapshot.into(),
            vectors,
        }
    }
}

#[async_trait]
impl SemanticRetriever for InMemorySemanticRetriever {
    fn profile(&self) -> Value {
        serde_json::json!({
            "driver": "in-memory-exact-cosine/v1",
            "identity": self.identity,
            "snapshot": self.snapshot,
        })
    }

    async fn search(&self, query: &SemanticQuery) -> Result<Vec<SemanticHit>, StoreError> {
        if query.index_snapshot != self.snapshot {
            return Err(StoreError::Backend(format!(
                "semantic query names index snapshot '{}' but retriever holds '{}'",
                query.index_snapshot, self.snapshot
            )));
        }
        validate_vector(&query.embedding)?;
        let mut hits = Vec::new();
        for candidate in &self.vectors {
            if candidate.subject != query.subject
                || query
                    .purpose
                    .as_ref()
                    .is_some_and(|purpose| purpose != &candidate.purpose)
            {
                continue;
            }
            validate_vector(&candidate.embedding)?;
            if candidate.embedding.len() != query.embedding.len() {
                return Err(StoreError::Backend(format!(
                    "semantic vector dimension {} does not match query dimension {}",
                    candidate.embedding.len(),
                    query.embedding.len()
                )));
            }
            let dot: f32 = candidate
                .embedding
                .iter()
                .zip(&query.embedding)
                .map(|(a, b)| *a * *b)
                .sum();
            let left = candidate
                .embedding
                .iter()
                .map(|value| value.powi(2))
                .sum::<f32>()
                .sqrt();
            let right = query
                .embedding
                .iter()
                .map(|value| value.powi(2))
                .sum::<f32>()
                .sqrt();
            let score = if left == 0.0 || right == 0.0 {
                0.0
            } else {
                dot / (left * right)
            };
            hits.push(SemanticHit {
                selected: candidate.selected.clone(),
                score,
            });
        }
        hits.sort_by(|a, b| {
            b.score
                .total_cmp(&a.score)
                .then_with(|| a.selected.id.cmp(&b.selected.id))
                .then_with(|| a.selected.version.cmp(&b.selected.version))
        });
        hits.truncate(query.limit);
        Ok(hits)
    }
}

fn validate_vector(vector: &[f32]) -> Result<(), StoreError> {
    if vector.is_empty() || vector.iter().any(|value| !value.is_finite()) {
        return Err(StoreError::Backend(
            "semantic vectors must be non-empty and finite".to_owned(),
        ));
    }
    Ok(())
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

/// Governed model-assisted formation of durable memories.
#[derive(Debug, Clone, PartialEq)]
pub struct Formation {
    pub subject: String,
    pub purpose: String,
    pub instruction: String,
    pub max_items: usize,
    pub expires_at: Option<Timestamp>,
    pub access_retention_seconds: Option<u64>,
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
    /// This is a required store operation rather than a default assembled from
    /// [`derivatives`](Self::derivatives) and [`forget`](Self::forget). Those
    /// calls are individually atomic but leave a gap in which another writer
    /// can add a derivative that the erasure never sees. Implementations must
    /// serialize derivative creation with the complete traversal and deletion.
    ///
    /// # Errors
    ///
    /// If the store cannot be reached.
    async fn forget_cascading(&self, id: &str) -> Result<usize, StoreError>;

    /// Place or release a legal hold. A held id cannot be forgotten, swept, or
    /// removed as part of subject/cascading erasure.
    async fn set_legal_hold(&self, id: &str, held: bool) -> Result<(), StoreError>;

    /// Whether an id is currently protected by legal hold.
    async fn legal_hold(&self, id: &str) -> Result<bool, StoreError>;

    /// Atomically erase current memories whose `expires_at <= at` unless held.
    /// Returns the number of memory ids erased.
    async fn sweep_expired(&self, at: Timestamp) -> Result<usize, StoreError>;

    /// Refresh sliding access retention for current ids at a journaled instant.
    async fn touch(&self, ids: &[String], at: Timestamp) -> Result<(), StoreError>;
}

#[cfg(test)]
mod write_tests {
    use super::*;

    /// The two lifecycle builders set their own field and no other.
    ///
    /// Fixed expiry and sliding retention answer opposite questions — "this
    /// stops being recallable on Thursday whatever happens" versus "this stays
    /// as long as it keeps being read" — and a memory carrying both by accident
    /// is one whose disposal date nobody can state. The store paths were tested
    /// through YAML and direct field assignment; the builders a caller reaches
    /// for had no test, so a swapped assignment would have been invisible.
    #[test]
    fn each_lifecycle_builder_sets_only_what_it_names() {
        let plain = MemoryWrite::new("m-1", "account-1", "support");
        assert_eq!(plain.expires_at, None, "neither is set by default");
        assert_eq!(plain.access_retention_seconds, None);

        let sliding = MemoryWrite::new("m-1", "account-1", "support").retain_after_access(600);
        assert_eq!(sliding.access_retention_seconds, Some(600));
        assert_eq!(
            sliding.expires_at, None,
            "a sliding window is not also a fixed expiry"
        );

        let at = Timestamp::UNIX_EPOCH;
        let fixed = MemoryWrite::new("m-1", "account-1", "support").expires_at(at);
        assert_eq!(fixed.expires_at, Some(at));
        assert_eq!(
            fixed.access_retention_seconds, None,
            "a fixed expiry is not also a sliding window"
        );

        // Identity is untouched by either: the id, subject and purpose are what
        // erasure and retrieval key on.
        for built in [&sliding, &fixed] {
            assert_eq!(built.id, plain.id);
            assert_eq!(built.subject, plain.subject);
            assert_eq!(built.purpose, plain.purpose);
        }
    }
}

#[cfg(test)]
mod semantic_tests {
    use super::*;

    fn selected(id: &str) -> Selected {
        Selected {
            id: id.to_owned(),
            version: 1,
            digest: Digest::of(id.as_bytes()),
        }
    }

    #[tokio::test]
    async fn exact_cosine_retrieval_is_scoped_ranked_and_snapshot_bound() {
        let retriever = InMemorySemanticRetriever::new(
            "reference",
            "snapshot-7",
            vec![
                SemanticVector {
                    subject: "account-1".to_owned(),
                    purpose: "support".to_owned(),
                    selected: selected("near"),
                    embedding: vec![1.0, 0.0],
                },
                SemanticVector {
                    subject: "account-1".to_owned(),
                    purpose: "support".to_owned(),
                    selected: selected("far"),
                    embedding: vec![0.0, 1.0],
                },
                SemanticVector {
                    subject: "account-2".to_owned(),
                    purpose: "support".to_owned(),
                    selected: selected("wrong-subject"),
                    embedding: vec![1.0, 0.0],
                },
            ],
        );
        let query = SemanticQuery {
            subject: "account-1".to_owned(),
            purpose: Some("support".to_owned()),
            text: "query".to_owned(),
            embedding: vec![1.0, 0.0],
            embedding_model: "embed-v3@2026-07-01".to_owned(),
            index_snapshot: "snapshot-7".to_owned(),
            limit: 2,
            max_sensitivity: Sensitivity::Internal,
        };
        let hits = retriever.search(&query).await.expect("semantic search");
        assert_eq!(
            hits.iter()
                .map(|hit| hit.selected.id.as_str())
                .collect::<Vec<_>>(),
            vec!["near", "far"]
        );
        assert!(hits[0].score > hits[1].score);

        let mut stale = query;
        stale.index_snapshot = "snapshot-8".to_owned();
        assert!(retriever.search(&stale).await.is_err());
    }
}
