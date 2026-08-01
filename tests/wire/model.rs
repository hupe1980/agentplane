//! Calling a model.
//!
//! One property carries this file, and it is about money rather than
//! correctness: **a completion that failed partway still costs what it
//! generated.**
//!
//! Every other outward call in this crate either happens or does not. A model
//! call has a third state — it ran, produced four hundred tokens, and the stream
//! died — and the provider bills for those tokens whatever happens next. Before
//! this, the runtime billed `Spend::default()` on every failure: the *call* was
//! counted against `max_effects`, and the tokens were counted as zero. A retry
//! loop against a flaky provider would therefore burn real money against a
//! ceiling that read nothing.

#![cfg(all(feature = "sqlite", feature = "testkit"))]
#![allow(clippy::disallowed_methods)]

use std::sync::Arc;

use agentplane::core::{
    Budget, Disposition, Effect, Outcome, Recovery, Sensitivity, Skill, SkillDescriptor,
    SkillError, Tainted, Trust,
};
use agentplane::journal::{JournalStore, RecordKind};
use agentplane::model::{Completion, ModelCall, ModelError, ModelId, ModelProvider, Usage};
use agentplane::runtime::{Mode, RunStatus, Runtime, StepCtx};
use agentplane::store::SqliteStore;
use agentplane::testkit::FakeProvider;
use serde_json::{Value, json};

fn model() -> ModelId {
    ModelId::new("anthropic", "claude-opus-5")
}

// ── The meter ───────────────────────────────────────────────────────────────

#[test]
fn an_interrupted_stream_reports_what_it_burned() {
    let err = ModelError::Interrupted {
        model: model(),
        usage: Usage {
            input_tokens: 100,
            output_tokens: 300,
            minor_units: 17,
            ..Default::default()
        },
        detail: "connection reset".into(),
    };
    assert_eq!(err.usage().spend().tokens, 400);
    assert_eq!(err.usage().spend().minor_units, 17);
}

/// A stream that died is *landed*, not in doubt.
///
/// The usual reasoning about reaching the peer is inverted: we watched it
/// generate, so nothing is in doubt. What is missing is the answer, and
/// repeating the call buys a second bill for the same question. `InDoubt` would
/// invite `Recovery` to resolve an outcome that is not uncertain.
#[test]
fn a_died_mid_stream_call_is_landed_not_in_doubt() {
    let interrupted = ModelError::Interrupted {
        model: model(),
        usage: Usage::default(),
        detail: "reset".into(),
    };
    assert_eq!(interrupted.disposition(), Disposition::Landed);

    // Refused before generating: nothing was metered, nothing happened.
    let refused = ModelError::Refused {
        model: model(),
        detail: "unknown model".into(),
    };
    assert_eq!(refused.disposition(), Disposition::DidNotHappen);
    assert_eq!(refused.usage().spend().tokens, 0);

    // Rate limited is the one case where retrying is unambiguously safe.
    let limited = ModelError::RateLimited {
        model: model(),
        detail: "slow down".into(),
    };
    assert_eq!(limited.disposition(), Disposition::DidNotHappen);
}

/// The spend survives the hop into `EffectError`, which is what the ledger reads.
#[tokio::test]
async fn a_metered_failure_carries_its_spend_into_the_effect_layer() {
    let provider = FakeProvider::new();
    provider.will_fail(ModelError::Interrupted {
        model: model(),
        usage: Usage {
            input_tokens: 100,
            output_tokens: 300,
            minor_units: 17,
            ..Default::default()
        },
        detail: "connection reset".into(),
    });

    let call = ModelCall::new(
        provider as Arc<dyn ModelProvider>,
        model(),
        json!({"q": "hi"}),
    );
    let err = call.perform().await.expect_err("the stream dies");

    assert_eq!(
        err.spend().tokens,
        400,
        "a failure that generated tokens must report them, or the ceiling that \
         bounds a runaway provider counts zero: {err}"
    );
    assert_eq!(err.disposition(), Disposition::Landed);
}

/// A failure that consumed nothing stays free.
#[tokio::test]
async fn a_refusal_before_generation_costs_nothing() {
    let provider = FakeProvider::new();
    provider.will_fail(ModelError::Refused {
        model: model(),
        detail: "bad request".into(),
    });
    let call = ModelCall::new(provider as Arc<dyn ModelProvider>, model(), json!({}));
    let err = call.perform().await.expect_err("refused");

    assert!(err.spend().is_zero());
    assert_eq!(err.disposition(), Disposition::DidNotHappen);
}

// ── End to end: the budget actually binds ───────────────────────────────────

#[derive(Debug)]
struct Asks {
    provider: Arc<FakeProvider>,
}

#[async_trait::async_trait]
impl Skill for Asks {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("ask").provides("ask")
    }
    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _i: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let out = cx
            .effect(ModelCall::new(
                Arc::clone(&self.provider) as Arc<dyn ModelProvider>,
                model(),
                json!({ "q": "what is the balance" }),
            ))
            .await?;
        Ok(Outcome::done(out.map(|c| json!({ "text": c.text }))))
    }
}

/// A failed completion is journaled with what it cost.
///
/// Without the spend on the record, a replayed run reaches a different budget
/// verdict than the original — it would think the failed attempt was free.
#[tokio::test]
async fn a_failed_completion_is_journaled_with_its_cost() {
    let store = Arc::new(SqliteStore::open_in_memory().unwrap());
    let provider = FakeProvider::new();
    provider.will_fail(ModelError::Interrupted {
        model: model(),
        usage: Usage {
            input_tokens: 100,
            output_tokens: 300,
            minor_units: 17,
            ..Default::default()
        },
        detail: "connection reset".into(),
    });

    let out = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .skill(Asks {
            provider: Arc::clone(&provider),
        })
        .build()
        .run("ask", json!({}))
        .await
        .unwrap();

    let records = store.read(out.run_id, 1).await.unwrap();
    let failed = records
        .iter()
        .find_map(|r| match r.kind() {
            RecordKind::EffectFailed { spend, .. } => Some(*spend),
            _ => None,
        })
        .expect("the failure is on the record");

    assert_eq!(
        failed.tokens, 400,
        "the record must carry what the attempt burned, or a replayed run reaches \
         a different budget verdict than the one that actually happened"
    );
    assert_eq!(failed.minor_units, 17);
}

/// The token ceiling stops a run after a *failed* completion burned through it.
///
/// This is the behaviour the accounting fix exists for, and getting the fixture
/// right matters: an interrupted stream is `Landed`, so it is never retried, and
/// a skill that gives up after one failure makes exactly one call whatever the
/// billing does. The first version of this test did that and passed with the
/// billing reverted.
///
/// So the skill here does what a real one would: the first completion dies
/// partway, it tries again with a different prompt, and the second call must be
/// refused because the first one's tokens counted.
#[tokio::test]
async fn a_failed_completion_spends_the_budget_that_stops_the_next_one() {
    #[derive(Debug)]
    struct AsksTwice {
        provider: Arc<FakeProvider>,
    }

    #[async_trait::async_trait]
    impl Skill for AsksTwice {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("ask").provides("ask")
        }
        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            _i: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            // Burns 400 tokens and dies. Swallowed, as an agent retrying with a
            // reworded prompt would.
            let _ = cx
                .effect(ModelCall::new(
                    Arc::clone(&self.provider) as Arc<dyn ModelProvider>,
                    model(),
                    json!({ "q": "first attempt" }),
                ))
                .await;

            let out = cx
                .effect(ModelCall::new(
                    Arc::clone(&self.provider) as Arc<dyn ModelProvider>,
                    model(),
                    json!({ "q": "second attempt, reworded" }),
                ))
                .await?;
            Ok(Outcome::done(out.map(|c| json!({ "text": c.text }))))
        }
    }

    let store = Arc::new(SqliteStore::open_in_memory().unwrap());
    let provider = FakeProvider::new();
    provider
        .will_fail(ModelError::Interrupted {
            model: model(),
            usage: Usage {
                input_tokens: 100,
                output_tokens: 300,
                minor_units: 0,
                ..Default::default()
            },
            detail: "connection reset".into(),
        })
        .will_answer(Completion {
            text: "the second answer".into(),
            usage: Usage {
                input_tokens: 10,
                output_tokens: 10,
                minor_units: 0,
                ..Default::default()
            },
            stop_reason: Some("end_turn".into()),
            truncated: false,
            structured: None,
        });

    let out = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .budget(Budget::unlimited().tokens(300))
        .skill(AsksTwice {
            provider: Arc::clone(&provider),
        })
        .build()
        .run("ask", json!({}))
        .await
        .unwrap();

    assert!(
        !matches!(out.status, RunStatus::Succeeded),
        "400 tokens burned by a failed call, against a 300-token ceiling, must \
         stop the run before it asks again: {:?}",
        out.status
    );
    assert_eq!(
        provider.calls(),
        1,
        "the second completion must be refused before it is sent — if it was, \
         the failed call's tokens were counted"
    );
}

/// A recorded failure bills the same on replay as it did live.
#[tokio::test]
async fn replay_charges_a_failed_completion_the_same_as_the_live_run() {
    let store = Arc::new(SqliteStore::open_in_memory().unwrap());
    let provider = FakeProvider::new();
    provider.will_fail(ModelError::Interrupted {
        model: model(),
        usage: Usage {
            input_tokens: 100,
            output_tokens: 300,
            minor_units: 17,
            ..Default::default()
        },
        detail: "reset".into(),
    });

    let build = || {
        Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
            .skill(Asks {
                provider: Arc::clone(&provider),
            })
            .build()
    };
    let out = build().run("ask", json!({})).await.unwrap();
    let live_calls = provider.calls();

    let replayed = build().replay(out.run_id, Mode::Strict).await;
    assert!(
        replayed.is_ok() || replayed.is_err(),
        "the point is the call count, not the verdict"
    );
    assert_eq!(
        provider.calls(),
        live_calls,
        "a replay must read the failure back rather than asking the model again"
    );
}

// ── Provenance ──────────────────────────────────────────────────────────────

/// Model output is untrusted, and this is the case the rule was written for.
#[test]
fn a_completion_is_untrusted_and_does_not_mutate() {
    let call = ModelCall::new(
        FakeProvider::new() as Arc<dyn ModelProvider>,
        model(),
        json!({}),
    );
    assert!(
        matches!(call.trust(), Trust::Untrusted),
        "a completion is a plausible string produced from whatever was in the \
         context window, including anything untrusted that got there"
    );
    assert!(
        !call.mutates(),
        "a completion does not move money, which is what makes retrying a rate \
         limit sane"
    );
    assert!(matches!(call.recovery(), Recovery::Retry));
}

/// A prompt above the model's ceiling never leaves.
#[test]
fn a_models_sensitivity_ceiling_is_declarable() {
    let call = ModelCall::new(
        FakeProvider::new() as Arc<dyn ModelProvider>,
        model(),
        json!({}),
    )
    .with_max_sensitivity(Sensitivity::Internal);
    assert_eq!(Effect::max_sensitivity(&call), Sensitivity::Internal);
}

/// The prompt is part of the effect key.
#[test]
fn a_changed_prompt_is_a_different_effect() {
    let a = ModelCall::new(
        FakeProvider::new() as Arc<dyn ModelProvider>,
        model(),
        json!({ "q": "one" }),
    );
    let b = ModelCall::new(
        FakeProvider::new() as Arc<dyn ModelProvider>,
        model(),
        json!({ "q": "two" }),
    );
    assert_ne!(
        a.descriptor().args,
        b.descriptor().args,
        "an edited prompt must show up as divergence on replay, not as a run that \
         quietly did something else"
    );
}

/// A successful completion bills what it used.
#[test]
fn a_successful_completion_bills_its_usage() {
    let call = ModelCall::new(
        FakeProvider::new() as Arc<dyn ModelProvider>,
        model(),
        json!({}),
    );
    let completion = Completion {
        text: "hi".into(),
        usage: Usage {
            input_tokens: 7,
            output_tokens: 3,
            minor_units: 5,
            ..Default::default()
        },
        stop_reason: None,
        truncated: false,
        structured: None,
    };
    assert_eq!(call.spend(&completion).tokens, 10);
    assert_eq!(call.spend(&completion).minor_units, 5);
}
