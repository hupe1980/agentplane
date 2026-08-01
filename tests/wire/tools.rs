//! Calling tools on other people's servers.
//!
//! One property matters more than the rest, and it is a security property:
//! **what a server says about its own tool must not change what this runtime
//! does with it.**
//!
//! The MCP specification is explicit — clients *MUST* treat tool annotations as
//! untrusted — and the reason it matters here is specific to how the effect
//! declarations compose:
//!
//! ```text
//! readOnlyHint: true   →  mutates() == false
//!                      →  Recovery defaults to Retry
//!                      →  a timed-out call is sent again
//! ```
//!
//! So a server that marks its own money-moving tool read-only would be choosing,
//! from the far side of the trust boundary, the one condition under which this
//! runtime performs an operation twice. Safety therefore comes from the
//! operator's catalogue, and the server's claims are recorded and compared but
//! never obeyed.

#![cfg(feature = "turso")]
#![allow(clippy::disallowed_methods)]

use std::sync::{Arc, Mutex};

use agentplane::core::{
    Disposition, Effect, Outcome, Recovery, Sensitivity, Skill, SkillDescriptor, SkillError,
    Tainted, Trust,
};
use agentplane::journal::JournalStore;
use agentplane::runtime::{RunStatus, Runtime, StepCtx};
use agentplane::store::TursoStore;
use agentplane::tools::{
    Advertised, ToolCall, ToolCatalog, ToolClient, ToolError, ToolId, ToolSafety,
};
use serde_json::{Value, json};

/// Records every call, and answers however the test says.
#[derive(Debug)]
struct Fake {
    calls: Arc<Mutex<Vec<String>>>,
    answer: Mutex<Vec<Result<Value, ToolError>>>,
}

impl Fake {
    fn new(answers: Vec<Result<Value, ToolError>>) -> Arc<Self> {
        Arc::new(Self {
            calls: Arc::default(),
            answer: Mutex::new(answers),
        })
    }
    fn ok() -> Arc<Self> {
        Self::new(vec![Ok(json!({ "result": "fine" }))])
    }
}

#[async_trait::async_trait]
impl ToolClient for Fake {
    async fn call(
        &self,
        tool: &ToolId,
        _args: &Value,
        _provenance: Option<&agentplane::core::Provenance>,
    ) -> Result<Value, ToolError> {
        self.calls.lock().unwrap().push(tool.to_string());
        self.answer
            .lock()
            .unwrap()
            .pop()
            .unwrap_or_else(|| Ok(json!({ "result": "fine" })))
    }
}

fn transfer() -> ToolId {
    ToolId::new("ledger", "transfer")
}

// ── The security property ───────────────────────────────────────────────────

/// A server calling its own tool read-only does not make it read-only.
///
/// This is the whole reason the catalogue exists. If the hint were obeyed,
/// `mutates` would be false, `Recovery` would default to `Retry`, and a timeout
/// would send the transfer a second time.
#[test]
fn a_servers_read_only_hint_does_not_make_a_tool_safe_to_repeat() {
    let catalog = ToolCatalog::new()
        .allow(transfer(), ToolSafety::default())
        .observed(
            &transfer(),
            Advertised {
                read_only: Some(true),
                idempotent: Some(true),
                destructive: Some(false),
            },
        );

    let call = ToolCall::prepare(&catalog, Fake::ok(), transfer(), json!({})).expect("permitted");

    assert!(
        call.mutates(),
        "the operator said this tool mutates; a server claiming otherwise must \
         not overrule that — the claim arrives from the far side of the trust \
         boundary"
    );
    assert!(
        matches!(call.recovery(), Recovery::RequiresOperator),
        "and the recovery posture must stay conservative, or a timeout retries \
         the transfer"
    );
}

/// The disagreement is visible rather than normalised away.
#[test]
fn a_server_claiming_more_safety_than_granted_is_reported() {
    let catalog = ToolCatalog::new()
        .allow(transfer(), ToolSafety::default())
        .allow(ToolId::new("ledger", "read"), ToolSafety::read_only())
        .observed(
            &transfer(),
            Advertised {
                read_only: Some(true),
                ..Advertised::default()
            },
        )
        .observed(
            &ToolId::new("ledger", "read"),
            Advertised {
                read_only: Some(true),
                ..Advertised::default()
            },
        );

    let flagged: Vec<String> = catalog.overclaiming().map(ToString::to_string).collect();
    assert_eq!(
        flagged,
        vec!["ledger/transfer".to_string()],
        "only the tool where the server claims more than the operator granted is \
         flagged — a server agreeing with the operator is not news"
    );
}

/// A tool nobody declared cannot be called at all.
#[test]
fn an_undeclared_tool_cannot_be_prepared() {
    let catalog = ToolCatalog::new();
    let err = ToolCall::prepare(&catalog, Fake::ok(), transfer(), json!({}))
        .expect_err("an undeclared tool must be refused");
    assert!(
        err.to_string().contains("ledger/transfer"),
        "the refusal names the tool: {err}"
    );
    assert_eq!(
        err.disposition(),
        Disposition::DidNotHappen,
        "nothing was attempted, so this is safe to treat as never having happened"
    );
}

// ── Disposition, which decides whether anything is repeated ─────────────────

#[test]
fn each_failure_says_what_it_knows_about_reaching_the_peer() {
    let t = transfer();
    let cases = [
        (
            ToolError::Unreachable {
                tool: t.clone(),
                detail: "connection refused".into(),
            },
            Disposition::DidNotHappen,
        ),
        (
            ToolError::Refused {
                tool: t.clone(),
                detail: "unknown method".into(),
            },
            Disposition::DidNotHappen,
        ),
        (
            ToolError::TimedOut {
                tool: t.clone(),
                detail: "no answer in 30s".into(),
            },
            Disposition::InDoubt,
        ),
        (
            ToolError::ToolFailed {
                tool: t.clone(),
                detail: "insufficient funds".into(),
            },
            Disposition::Landed,
        ),
        (
            ToolError::Malformed {
                tool: t,
                detail: "not a tool result".into(),
            },
            Disposition::Landed,
        ),
    ];
    for (err, expected) in cases {
        assert_eq!(err.disposition(), expected, "for {err}");
    }
}

/// A timeout must not be reported as something that did not happen.
///
/// The single most expensive mis-classification available: it turns "we do not
/// know whether the money moved" into "it definitely did not", and the runtime
/// then repeats the call.
#[tokio::test]
async fn a_timed_out_tool_call_is_in_doubt_when_it_reaches_the_runtime() {
    let catalog = ToolCatalog::new().allow(transfer(), ToolSafety::default());
    let client = Fake::new(vec![Err(ToolError::TimedOut {
        tool: transfer(),
        detail: "no answer in 30s".into(),
    })]);
    let call = ToolCall::prepare(&catalog, client, transfer(), json!({})).expect("permitted");

    let err = call.perform().await.expect_err("the call times out");
    assert_eq!(
        err.disposition(),
        Disposition::InDoubt,
        "the disposition must survive the hop from ToolError into EffectError, \
         because that is what the retry gate reads: {err}"
    );
}

/// A tool that ran and failed is never repeated.
#[tokio::test]
async fn a_tool_that_ran_and_failed_is_treated_as_having_landed() {
    let catalog = ToolCatalog::new().allow(transfer(), ToolSafety::default());
    let client = Fake::new(vec![Err(ToolError::ToolFailed {
        tool: transfer(),
        detail: "insufficient funds".into(),
    })]);
    let call = ToolCall::prepare(&catalog, client, transfer(), json!({})).expect("permitted");

    let err = call.perform().await.expect_err("the tool fails");
    assert_eq!(
        err.disposition(),
        Disposition::Landed,
        "the tool executed; repeating it would be a second invocation: {err}"
    );
}

// ── Provenance ──────────────────────────────────────────────────────────────

/// The catalogue governs authority, not provenance.
#[test]
fn a_tool_result_is_untrusted_whatever_the_catalogue_says() {
    let catalog = ToolCatalog::new().allow(
        ToolId::new("ledger", "read"),
        ToolSafety::read_only().output_sensitivity(Sensitivity::Secret),
    );
    let call = ToolCall::prepare(
        &catalog,
        Fake::ok(),
        ToolId::new("ledger", "read"),
        json!({}),
    )
    .expect("permitted");

    assert!(
        matches!(call.trust(), Trust::Untrusted),
        "no catalogue entry may make a tool result trusted — a tool the operator \
         trusts is still a tool whose output came from outside"
    );
    assert_eq!(call.output_sensitivity(), Sensitivity::Secret);
}

/// Two servers offering the same tool name are two different effects.
#[test]
fn the_server_is_part_of_the_effect_identity() {
    let catalog = ToolCatalog::new()
        .allow(ToolId::new("a", "transfer"), ToolSafety::default())
        .allow(ToolId::new("b", "transfer"), ToolSafety::default());

    let one = ToolCall::prepare(
        &catalog,
        Fake::ok(),
        ToolId::new("a", "transfer"),
        json!({}),
    )
    .expect("permitted");
    let two = ToolCall::prepare(
        &catalog,
        Fake::ok(),
        ToolId::new("b", "transfer"),
        json!({}),
    )
    .expect("permitted");

    assert_ne!(
        one.descriptor().args,
        two.descriptor().args,
        "the same tool name on two servers must not share an effect key, or one \
         server's recorded result replays as the other's"
    );
}

// ── End to end ──────────────────────────────────────────────────────────────

#[derive(Debug)]
struct Calls {
    catalog: ToolCatalog,
    client: Arc<Fake>,
}

#[async_trait::async_trait]
impl Skill for Calls {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("call").provides("call")
    }
    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _i: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let call = ToolCall::prepare(
            &self.catalog,
            Arc::clone(&self.client) as Arc<dyn ToolClient>,
            ToolId::new("ledger", "read"),
            json!({ "account": "1" }),
        )
        .map_err(|e| SkillError::Other(e.to_string()))?;
        let out = cx.effect(call).await?;
        Ok(Outcome::done(out))
    }
}

/// A tool call is an ordinary effect: journaled once, and read back on replay.
#[tokio::test]
async fn a_tool_call_is_performed_once_and_replayed_from_the_journal() {
    let store = Arc::new(TursoStore::open_in_memory().await.unwrap());
    let client = Fake::ok();
    let catalog = ToolCatalog::new().allow(ToolId::new("ledger", "read"), ToolSafety::read_only());

    let build = || {
        Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
            .skill(Calls {
                catalog: catalog.clone(),
                client: Arc::clone(&client),
            })
            .build()
    };

    let out = build().run("call", json!({})).await.unwrap();
    assert!(matches!(out.status, RunStatus::Succeeded));
    assert_eq!(client.calls.lock().unwrap().len(), 1);

    build()
        .replay(out.run_id, agentplane::runtime::Mode::Strict)
        .await
        .expect("a recorded tool call replays");

    assert_eq!(
        client.calls.lock().unwrap().len(),
        1,
        "replay must read the tool's answer back from the journal rather than \
         calling the server again"
    );
}

/// Tool output reaching a mutating sink is refused, without anyone remembering.
#[tokio::test]
async fn tool_output_cannot_steer_a_mutating_call() {
    #[derive(Debug)]
    struct Naive {
        catalog: ToolCatalog,
        client: Arc<Fake>,
    }

    #[async_trait::async_trait]
    impl Skill for Naive {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("naive").provides("naive")
        }
        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            _i: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            let read = ToolCall::prepare(
                &self.catalog,
                Arc::clone(&self.client) as Arc<dyn ToolClient>,
                ToolId::new("ledger", "read"),
                json!({}),
            )
            .map_err(|e| SkillError::Other(e.to_string()))?;
            let answer = cx.effect(read).await?;

            // Straight from a tool into a transfer.
            let write = ToolCall::prepare(
                &self.catalog,
                Arc::clone(&self.client) as Arc<dyn ToolClient>,
                transfer(),
                json!({}),
            )
            .map_err(|e| SkillError::Other(e.to_string()))?;
            let out = cx.sink(write, &answer).await?;
            Ok(Outcome::done(out))
        }
    }

    let store = Arc::new(TursoStore::open_in_memory().await.unwrap());
    let client = Fake::ok();
    let catalog = ToolCatalog::new()
        .allow(ToolId::new("ledger", "read"), ToolSafety::read_only())
        .allow(
            transfer(),
            ToolSafety::default().max_sensitivity(Sensitivity::Secret),
        );

    let out = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .skill(Naive {
            catalog,
            client: Arc::clone(&client),
        })
        .build()
        .run("naive", json!({}))
        .await
        .unwrap();

    assert!(
        matches!(out.status, RunStatus::Failed(_)),
        "status: {:?}",
        out.status
    );
    assert_eq!(
        client.calls.lock().unwrap().len(),
        1,
        "only the read happened; the transfer was refused before it was sent"
    );
}
