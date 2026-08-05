//! Private/team memory without turning storage into an instruction backdoor.
//!
//! Run with:
//! `cargo run --example memory_run`

use std::sync::Arc;

use agentplane::core::{Outcome, Skill, SkillDescriptor, SkillError, SourceId, Tainted};
use agentplane::journal::JournalStore;
use agentplane::memory::{MemoryItem, MemoryStore, MemoryWrite, Recall};
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
    assert_eq!(learned.output, Some(json!(["Customer prefers German"])));

    let recalled = runtime
        .run("support.memory", json!({"action": "recall"}))
        .await?;
    assert_eq!(recalled.output, learned.output);

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
        "remembered and recalled with provenance: {}",
        stored.content
    );
    Ok(())
}
