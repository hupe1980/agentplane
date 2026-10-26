//! A failed run names the effect it ended on, and the provider's code for the
//! refusal, live and on replay. Run against a local server, so nothing reaches
//! a provider.

#![cfg(all(feature = "providers", feature = "http", feature = "redb"))]
#![allow(clippy::disallowed_methods)]

use std::sync::Arc;

use agentplane::core::{Outcome, Skill, SkillDescriptor, SkillError, Tainted};
use agentplane::journal::JournalStore;
use agentplane::model::anthropic::Anthropic;
use agentplane::model::{ModelCall, ModelId, ModelProvider};
use agentplane::runtime::{Mode, RunStatus, Runtime, StepCtx};
use agentplane::store::RedbStore;
use axum::Router;
use axum::routing::post;
use serde_json::{Value, json};

/// A provider that answers every call with one HTTP error.
async fn refusing(status: u16, body: Value) -> String {
    let app = Router::new().route(
        "/v1/messages",
        post(move || {
            let body = body.clone();
            async move {
                (
                    axum::http::StatusCode::from_u16(status).unwrap(),
                    axum::Json(body),
                )
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

#[derive(Debug)]
struct Asks(Arc<dyn ModelProvider>);

#[async_trait::async_trait]
impl Skill for Asks {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("asks").provides("asks")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let call = ModelCall::new(
            Arc::clone(&self.0),
            ModelId::new("anthropic", "claude-x"),
            input.peek().clone(),
        );
        let answer = cx.sink(call, &input).await?;
        Ok(Outcome::done(answer.map(|c| json!(c.text))))
    }
}

async fn fail_with(
    status: u16,
    body: Value,
) -> (
    agentplane::runtime::RunOutcome,
    agentplane::runtime::RunOutcome,
) {
    let url = refusing(status, body).await;
    let driver = Anthropic::new("k").unwrap().base(url).buffered();
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .skill(Asks(Arc::new(driver)))
        .build();
    let live = rt
        .start("asks", Tainted::trusted(json!("balance?")))
        .run()
        .await
        .unwrap();
    let replayed = rt.replay(live.run_id, Mode::Strict).await.unwrap();
    (live, replayed)
}

/// An account refusal reaches the caller typed: the effect it ended on, the
/// provider's code, and the predicate that reads it — on the live run and on
/// its replay, which never asks the provider again.
#[tokio::test]
async fn a_failed_run_names_its_effect_and_the_providers_code() {
    let (live, replayed) = fail_with(
        401,
        json!({ "type": "error", "error": { "type": "authentication_error", "message": "invalid x-api-key" } }),
    )
    .await;
    assert!(
        matches!(live.status, RunStatus::Failed(_)),
        "{:?}",
        live.status
    );
    let failed = live
        .failed_effect
        .clone()
        .expect("the effect the run ended on");
    assert_eq!(failed.kind, "model.complete");
    assert!(failed.permanent, "a refusal no retry changes");
    assert_eq!(failed.code.as_deref(), Some("authentication_error"));
    assert!(failed.refuses_the_account());
    assert_eq!(
        replayed.failed_effect, live.failed_effect,
        "replay answered differently"
    );
}

/// A refusal of the request is told apart from one of the account.
#[tokio::test]
async fn a_bad_request_is_not_the_accounts() {
    let (live, _) = fail_with(
        400,
        json!({ "type": "error", "error": { "type": "invalid_request_error", "message": "max_tokens: too large" } }),
    )
    .await;
    let failed = live.failed_effect.expect("the effect the run ended on");
    assert_eq!(failed.code.as_deref(), Some("invalid_request_error"));
    assert!(!failed.refuses_the_account());
}
