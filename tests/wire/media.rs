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

/// Stores through the handle an externally retained fetch files into, and
/// reads back through both handles.
#[derive(Debug)]
struct ExternalHandle(GovernedMedia);

#[async_trait::async_trait]
impl Skill for ExternalHandle {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("external-handle").provides("external-handle")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let media = cx.media_blobs(&self.0)?;
        let digest = media.put(b"externally retained").await.expect("put");
        let through_media = media.get(digest).await.is_ok();
        let through_case = cx.blobs()?.get(digest).await.is_ok();
        Ok(Outcome::done(Tainted::trusted(
            json!({ "media": through_media, "case": through_case }),
        )))
    }
}

/// **Externally retained media is read through the policy's handle, not the
/// case's.**
///
/// Its bytes live under the policy's erasure unit, so the case-scoped store a
/// skill gets from `cx.blobs()` cannot address them; `cx.media_blobs` is the
/// handle that can.
#[tokio::test]
async fn externally_retained_media_has_its_own_handle() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let blobs: Arc<dyn BlobStore> = Arc::new(MemoryBlobs::new());
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .cases(store as Arc<dyn agentplane::case::CaseStore>)
        .blobs(blobs)
        .skill(ExternalHandle(GovernedMedia::new(
            policy().external_retention("test/v1"),
        )))
        .build();
    let out = rt
        .run_correlated(
            "external-handle",
            Tainted::trusted(json!({})),
            "matter",
            &[agentplane::core::CorrelationKey::new("doc", "D-1")],
        )
        .await
        .unwrap();
    assert_eq!(out.status, RunStatus::Succeeded, "{:?}", out.status);
    assert_eq!(
        out.output.expect("output").peek(),
        &json!({ "media": true, "case": false }),
        "the external handle and the case handle address the same unit"
    );
}
