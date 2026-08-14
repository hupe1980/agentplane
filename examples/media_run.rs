//! Digest-only multimodal dispatch and zero-I/O replay — no API key or network.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example media_run --features redb,testkit,media
//! ```
//!
//! The network fetch boundary is intentionally not mocked here: a fake
//! connector would not demonstrate DNS pinning or redirect re-authorization.
//! This example starts with the exact `FetchedMedia` capability that
//! `StepCtx::fetch_media` returns and demonstrates the rest of the contract:
//!
//! 1. provider-native remote media URLs are refused before provider dispatch;
//! 2. the journaled prompt carries a digest marker, never image bytes;
//! 3. live dispatch materializes only an explicitly granted artifact;
//! 4. model output remains untrusted; and
//! 5. strict replay reads neither blob storage nor the model.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use agentplane::blob::{BlobError, BlobStore, MemoryBlobs};
use agentplane::core::{
    Digest, Effect, Outcome, Sensitivity, Skill, SkillDescriptor, SkillError, SourceId, Tainted,
    Timestamp, Trust,
};
use agentplane::journal::JournalStore;
use agentplane::media::{FetchedMedia, MediaRetention};
use agentplane::model::{ModelCall, ModelId, ModelProvider};
use agentplane::runtime::{Mode, Runtime, StepCtx};
use agentplane::store::RedbStore;
use agentplane::testkit::FakeProvider;
use async_trait::async_trait;
use base64::Engine as _;
use serde_json::{Value, json};

#[derive(Debug)]
struct CountingBlobs {
    inner: MemoryBlobs,
    reads: AtomicUsize,
}

impl CountingBlobs {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: MemoryBlobs::new(),
            reads: AtomicUsize::new(0),
        })
    }

    fn reads(&self) -> usize {
        self.reads.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl BlobStore for CountingBlobs {
    async fn put(&self, bytes: &[u8]) -> Result<Digest, BlobError> {
        self.inner.put(bytes).await
    }

    async fn get(&self, digest: Digest) -> Result<Vec<u8>, BlobError> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.inner.get(digest).await
    }

    async fn put_at(&self, digest: Digest, bytes: &[u8]) -> Result<(), BlobError> {
        self.inner.put_at(digest, bytes).await
    }

    async fn get_raw(&self, digest: Digest) -> Result<Vec<u8>, BlobError> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.inner.get_raw(digest).await
    }

    async fn expire(&self, digest: Digest, at: Timestamp, reason: &str) -> Result<(), BlobError> {
        self.inner.expire(digest, at, reason).await
    }

    async fn has(&self, digest: Digest) -> Result<bool, BlobError> {
        self.inner.has(digest).await
    }
}

#[derive(Debug)]
struct DescribeImage {
    provider: Arc<FakeProvider>,
    blobs: Arc<CountingBlobs>,
    artifact: FetchedMedia,
}

#[async_trait]
impl Skill for DescribeImage {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("describe-image").provides("media.describe")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        // `from_source` preserves the fetch boundary's untrusted provenance.
        let prompt = Tainted::from_source(self.artifact.clone(), SourceId::new("media.fetch")).map(
            |artifact| {
                json!({
                    "input": [{
                        "role": "user",
                        "content": [
                            {"type": "input_text", "text": "Describe this image"},
                            artifact.openai_image()
                        ]
                    }]
                })
            },
        );
        let provider: Arc<dyn ModelProvider> = self.provider.clone();
        let blobs: Arc<dyn BlobStore> = self.blobs.clone();
        let completion = cx
            .sink_with(&prompt, |value| {
                ModelCall::new(provider, ModelId::new("fake", "vision-1"), value)
                    .with_max_sensitivity(Sensitivity::Internal)
                    .with_media(blobs, [&self.artifact])
            })
            .await?;
        assert_eq!(completion.label().trust, Trust::Untrusted);
        Ok(Outcome::done(
            completion.map(|answer| json!({ "description": answer.text })),
        ))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Provider-side URL dereferencing is an architectural egress bypass.
    let refused_provider = FakeProvider::new();
    let remote = ModelCall::new(
        refused_provider.clone(),
        ModelId::new("fake", "vision-1"),
        json!({
            "input": [{
                "content": [{
                    "type": "input_image",
                    "image_url": "https://cdn.example/chart.png"
                }]
            }]
        }),
    );
    let refusal = remote
        .perform()
        .await
        .expect_err("remote URL must be refused");
    assert_eq!(refused_provider.calls(), 0);
    println!("1. provider URL refused before dispatch → {refusal}");

    // This fixture is the capability returned by a successful governed fetch.
    // The bytes are content-addressed and kept out of the effect descriptor.
    let blobs = CountingBlobs::new();
    let image = b"\x89PNG\r\n\x1a\nagentplane-example";
    let digest = blobs.put(image).await?;
    let artifact = FetchedMedia {
        digest,
        media_type: "image/png".to_owned(),
        bytes: image.len(),
        source_url: "https://cdn.example/chart.png".to_owned(),
        final_url: "https://cdn.example/chart.png".to_owned(),
        redirects: 0,
        validated_by: Vec::new(),
        hops: Vec::new(),
        retention: MediaRetention::External {
            policy: "example/no-network-v1".to_owned(),
        },
    };

    let store: Arc<dyn JournalStore> = Arc::new(RedbStore::open_in_memory()?);
    let provider = FakeProvider::new();
    provider.will_say("a small status chart");
    let runtime = Runtime::builder(Arc::clone(&store))
        .owner("media-example")
        .skill(DescribeImage {
            provider: Arc::clone(&provider),
            blobs: Arc::clone(&blobs),
            artifact,
        })
        .build();

    let live = runtime
        .run("media.describe", Tainted::trusted(json!({})))
        .await?;
    assert_eq!(provider.calls(), 1);
    assert_eq!(blobs.reads(), 1);
    let history = format!("{:?}", store.read(live.run_id, 1).await?);
    let materialized = base64::engine::general_purpose::STANDARD.encode(image);
    assert!(
        !history.contains(&materialized),
        "input media bytes entered the append-only journal"
    );
    println!("2. live model dispatch                → {:?}", live.status);
    println!("   journaled media identity           → {digest}");
    println!("   blob reads / provider calls        → 1 / 1");

    let replay = runtime.replay(live.run_id, Mode::Strict).await?;
    assert_eq!(replay.output, live.output);
    assert_eq!(provider.calls(), 1, "strict replay called the model");
    assert_eq!(blobs.reads(), 1, "strict replay read the media blob");
    store.verify(live.run_id).await?;
    println!(
        "3. strict replay                      → {:?}",
        replay.status
    );
    println!("   blob reads / provider calls        → 1 / 1 (unchanged)");
    println!("4. journal verifies; input media bytes never entered it");

    Ok(())
}
