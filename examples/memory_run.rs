//! Private/team memory without turning storage into an instruction backdoor.
//!
//! Run with:
//! `cargo run --example memory_run`

use std::sync::Arc;

use agentplane::core::{Outcome, Skill, SkillDescriptor, SkillError, SourceId, Tainted, Timestamp};
use agentplane::journal::JournalStore;
use agentplane::memory::{
    Embedder, InMemorySemanticRetriever, IndexIdentity, MemoryItem, MemoryStore, MemoryWrite,
    Recall, Selected, SemanticSearch, SemanticVector,
};
use agentplane::runtime::{Runtime, StepCtx};
use agentplane::store::RedbStore;
use serde_json::{Value, json};

#[derive(Debug)]
struct TeamMemory;

#[async_trait::async_trait]
impl Skill for TeamMemory {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("team_memory").provides("support.memory")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        if input.peek()["action"] == "remember" {
            // `map` keeps the caller's label. `remember` derives trust,
            // sensitivity and provenance from this value; there is no metadata
            // parameter with which model/user data can promote itself.
            let fact = input.map(|value| value["fact"].clone());
            cx.remember(
                MemoryWrite::new(
                    "team-support-language",
                    "team/support",
                    "customer-preferences",
                )
                .expires_at(
                    Timestamp::from_unix_timestamp(4_102_444_800)
                        .expect("2100-01-01 is representable"),
                ),
                fact,
            )
            .await?;
        }

        let recalled = cx
            .recall(
                Recall::about("team/support")
                    .for_purpose("customer-preferences")
                    .limit(5),
            )
            .await?;
        let values = recalled
            .into_iter()
            .map(|memory| memory.map(|item| item.content));
        Ok(Outcome::done(Tainted::array(values)))
    }
}

/// The space this example's index lives in. Both halves are one string on
/// purpose: anything that changes what the floats *mean* — the model, the
/// width, whether a query is embedded differently from a document — belongs in
/// the revision, because that is what `build` matches against the index.
const REVISION: &str = "example-embedding@2";

/// A stand-in for a real embedding service, deterministic so the example is.
#[derive(Debug)]
struct ExampleEmbedder;

#[async_trait::async_trait]
impl Embedder for ExampleEmbedder {
    fn revision(&self) -> String {
        REVISION.to_owned()
    }

    async fn embed(&self, text: &str) -> Result<Vec<f32>, agentplane::core::StoreError> {
        Ok(if text.contains("language") {
            vec![1.0, 0.0]
        } else {
            vec![0.0, 1.0]
        })
    }
}

#[derive(Debug)]
struct SemanticMemory;

#[async_trait::async_trait]
impl Skill for SemanticMemory {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("semantic_memory").provides("support.semantic-memory")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        // No vector, no model name, no snapshot: those come from the wiring,
        // which `build` already held to itself. A query embedded in the wrong
        // space would not fail — it would rank unrelated memories.
        let found = cx
            .semantic_recall(
                SemanticSearch::about("team/support")
                    .for_purpose("customer-preferences")
                    .limit(1)
                    .max_sensitivity(agentplane::core::Sensitivity::Internal),
                Tainted::trusted("preferred language".to_owned()),
            )
            .await?;
        Ok(Outcome::done(
            found
                .into_iter()
                .next()
                .expect("the example indexed one memory")
                .0
                .map(|item| item.content),
        ))
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(RedbStore::open_in_memory()?);
    let journal: Arc<dyn JournalStore> = store.clone();
    let memories: Arc<dyn MemoryStore> = store.clone();
    let runtime = Runtime::builder(journal)
        .memory(memories)
        .skill(TeamMemory)
        .build();

    let learned = runtime
        .run(
            "support.memory",
            Tainted::from_source(
                json!({"action": "remember", "fact": "Customer prefers German"}),
                SourceId::new("user:customer-7"),
            ),
        )
        .await?;
    assert_eq!(
        learned.output.as_ref().map(|o| o.peek().clone()),
        Some(json!(["Customer prefers German"]))
    );
    println!("1. remembered      → \"Customer prefers German\"");

    let recalled = runtime
        .run(
            "support.memory",
            Tainted::trusted(json!({"action": "recall"})),
        )
        .await?;
    assert_eq!(
        recalled.output.map(|o| o.peek().clone()),
        learned.output.map(|o| o.peek().clone())
    );
    println!(
        "2. recalled        → the same answer, on a later run, through the journaled recall effect"
    );

    let stored: MemoryItem = store
        .version("team-support-language", 1)
        .await?
        .expect("the first run wrote the memory");
    assert!(stored.label().is_untrusted());
    assert!(
        stored
            .label()
            .provenance
            .contains(&SourceId::new("user:customer-7"))
    );
    println!(
        "   its label      → untrusted, provenance {:?} — storage promoted nothing",
        stored
            .label()
            .provenance
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    );

    semantic_recall(&store, &stored).await?;

    store.set_legal_hold("team-support-language", true).await?;
    let after_expiry = Timestamp::from_unix_timestamp(4_102_444_801)?;
    let swept = store.sweep_expired(after_expiry).await?;
    println!(
        "4. legal hold      → a sweep past the expiry date removed {swept} — a hold outranks the calendar"
    );
    assert_eq!(swept, 0);
    store.set_legal_hold("team-support-language", false).await?;
    let swept = store.sweep_expired(after_expiry).await?;
    println!(
        "   hold released  → the same sweep removed {swept} — expiry is enforced, not advisory"
    );
    assert_eq!(swept, 1);
    Ok(())
}

/// A second plane, wired for semantic recall over the memory the first wrote.
async fn semantic_recall(
    store: &Arc<RedbStore>,
    stored: &MemoryItem,
) -> Result<(), Box<dyn std::error::Error>> {
    let retriever = Arc::new(InMemorySemanticRetriever::new(
        IndexIdentity {
            snapshot: "example-snapshot-1".to_owned(),
            query_revision: REVISION.to_owned(),
        },
        vec![SemanticVector {
            subject: stored.subject.clone(),
            purpose: stored.purpose.clone(),
            selected: Selected {
                id: stored.id.clone(),
                version: stored.version,
                digest: stored.selection_digest(),
            },
            embedding: vec![1.0, 0.0],
        }],
    ));
    let journal: Arc<dyn JournalStore> = store.clone();
    let memories: Arc<dyn MemoryStore> = store.clone();
    let semantic = Runtime::builder(journal)
        .memory(memories)
        .semantic_memory(Arc::new(ExampleEmbedder), retriever)
        .skill(SemanticMemory)
        .build();
    let ranked = semantic
        .run("support.semantic-memory", Tainted::trusted(json!({})))
        .await?;
    assert_eq!(
        ranked.output.map(|o| o.peek().clone()),
        Some(json!("Customer prefers German"))
    );
    println!(
        "3. semantic        → \"preferred language\" ranked it first, in the embedding space the wiring pinned"
    );
    Ok(())
}
