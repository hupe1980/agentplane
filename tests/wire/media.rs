//! Runtime-bound guarantees for governed remote media.

#![cfg(all(feature = "media", feature = "redb"))]
#![allow(clippy::disallowed_methods)]

use std::sync::Arc;

use agentplane::blob::{BlobStore, MemoryBlobs};
use agentplane::core::{
    Outcome, Sensitivity, Skill, SkillDescriptor, SkillError, SourceId, Tainted,
};
use agentplane::journal::JournalStore;
use agentplane::media::{GovernedMedia, MediaPolicy};
use agentplane::runtime::{RunStatus, Runtime, StepCtx};
use agentplane::store::RedbStore;
use serde_json::{Value, json};

#[derive(Debug)]
struct Fetches {
    media: GovernedMedia,
    untrusted_url: bool,
}

#[async_trait::async_trait]
impl Skill for Fetches {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("fetches-media").provides("fetches-media")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let url = if self.untrusted_url {
            Tainted::from_source(
                "https://media.example/a.png".to_owned(),
                SourceId::new("model.complete"),
            )
        } else {
            Tainted::trusted("https://media.example/a.png".to_owned())
        };
        let fetched = cx.fetch_media(&self.media, url).await?;
        Ok(Outcome::done(
            fetched.map(|artifact| json!(artifact.digest)),
        ))
    }
}

fn runtime(media: GovernedMedia, untrusted_url: bool) -> Arc<Runtime> {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let blobs: Arc<dyn BlobStore> = Arc::new(MemoryBlobs::new());
    Runtime::builder(store as Arc<dyn JournalStore>)
        .blobs(blobs)
        .skill(Fetches {
            media,
            untrusted_url,
        })
        .build()
}

fn policy() -> MediaPolicy {
    MediaPolicy::new()
        .allow_host("media.example")
        .allow_media_type("image/png")
}

#[tokio::test]
async fn an_untrusted_url_cannot_select_even_a_read_only_media_destination() {
    let out = runtime(
        GovernedMedia::new(
            policy()
                .max_url_sensitivity(Sensitivity::Internal)
                .external_retention("test/v1"),
        ),
        true,
    )
    .run("fetches-media", Tainted::trusted(json!({})))
    .await
    .unwrap();

    let RunStatus::Failed(reason) = out.status else {
        panic!("expected refusal, got {:?}", out.status);
    };
    assert!(
        reason.contains("untrusted data may not select protected field"),
        "{reason}"
    );
}

#[tokio::test]
async fn case_linked_media_is_refused_when_there_is_no_case_to_link() {
    let out = runtime(GovernedMedia::new(policy()), false)
        .run("fetches-media", Tainted::trusted(json!({})))
        .await
        .unwrap();

    let RunStatus::Failed(reason) = out.status else {
        panic!("expected refusal, got {:?}", out.status);
    };
    assert!(reason.contains("requires a case for retention"));
}
