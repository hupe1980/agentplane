//! Private/team memory without turning storage into an instruction backdoor.
//!
//! Run with:
//! `cargo run --example memory_run`

use std::sync::Arc;

use agentplane::core::{Outcome, Skill, SkillDescriptor, SkillError, SourceId, Tainted, Timestamp};
use agentplane::journal::JournalStore;
use agentplane::memory::{
    InMemorySemanticRetriever, MemoryItem, MemoryStore, MemoryWrite, Recall, Selected,
    SemanticQuery, SemanticRetriever, SemanticVector,
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

#[derive(Debug)]
struct SemanticMemory(Arc<dyn SemanticRetriever>);

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
        let found = cx
            .semantic_recall(
                Arc::clone(&self.0),
                Tainted::trusted(SemanticQuery {
                    subject: "team/support".to_owned(),
                    purpose: Some("customer-preferences".to_owned()),
                    text: "preferred language".to_owned(),
                    embedding: vec![1.0, 0.0],
                    embedding_model: "example-embedding@1".to_owned(),
                    index_snapshot: "example-snapshot-1".to_owned(),
                    limit: 1,
                    max_sensitivity: agentplane::core::Sensitivity::Internal,
                }),
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
    let runtime = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .memory(Arc::clone(&store) as Arc<dyn MemoryStore>)
        .skill(TeamMemory)
        .build();

    let learned = runtime
        .run_tainted(
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

    let recalled = runtime
        .run("support.memory", json!({"action": "recall"}))
        .await?;
    assert_eq!(
        recalled.output.map(|o| o.peek().clone()),
        learned.output.map(|o| o.peek().clone())
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

    let retriever = Arc::new(InMemorySemanticRetriever::new(
        "example-index",
        "example-snapshot-1",
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
    )) as Arc<dyn SemanticRetriever>;
    let semantic = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .memory(Arc::clone(&store) as Arc<dyn MemoryStore>)
        .skill(SemanticMemory(retriever))
        .build();
    let ranked = semantic.run("support.semantic-memory", json!({})).await?;
    assert_eq!(
        ranked.output.map(|o| o.peek().clone()),
        Some(json!("Customer prefers German"))
    );

    store.set_legal_hold("team-support-language", true).await?;
    let after_expiry = Timestamp::from_unix_timestamp(4_102_444_801)?;
    assert_eq!(store.sweep_expired(after_expiry).await?, 0);
    store.set_legal_hold("team-support-language", false).await?;
    assert_eq!(store.sweep_expired(after_expiry).await?, 1);

    println!(
        "remembered, semantically recalled, held, and expired: {}",
        stored.content
    );
    Ok(())
}
