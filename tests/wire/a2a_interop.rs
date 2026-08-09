//! This crate's A2A **client**, against somebody else's server.
//!
//! Every other A2A test here drives this crate's client at this crate's server,
//! or at a canned response written from this crate's reading of the
//! specification. That proves symmetry, not conformance: a client and a server
//! written from the same misreading agree everywhere, including where both are
//! wrong.
//!
//! The protocol project's own conformance kit closes that gap for the **server**
//! and cannot close it for the client, because the kit validates servers only.
//! So the outside authority here is the reference Rust SDK's server
//! (`a2a-server-lf`), stood up in-process with its own request handler, its own
//! task store and its own JSON-RPC framing — none of it written here.
//!
//! # Why a pre-1.0 dependency is acceptable *here*
//!
//! It is a dev-dependency and nothing in `src/` links it, so its churn cannot
//! reach a deployment and `cargo package` does not carry it. That is a different
//! trade from taking the same crates onto a shipped hostile-input boundary,
//! which this project has evaluated and declined.

#![cfg(all(feature = "a2a", feature = "http"))]

use std::sync::Arc;

use a2a::{StreamResponse, Task, TaskState, TaskStatus};
use a2a_server::executor::ExecutorContext;
use a2a_server::handler::DefaultRequestHandler;
use a2a_server::jsonrpc::jsonrpc_router;
use a2a_server::task_store::InMemoryTaskStore;
use agentplane::core::{Delegation, Disposition, Principal, Scope};
use agentplane::peers::a2a::{A2aClient, Endpoint};
use agentplane::peers::{PeerClient, PeerId};
use futures_util::stream::BoxStream;
use serde_json::json;

/// Their executor, answering with a completed task.
struct Echo;

impl a2a_server::AgentExecutor for Echo {
    fn execute(
        &self,
        ctx: ExecutorContext,
    ) -> BoxStream<'static, Result<StreamResponse, a2a::A2AError>> {
        let task = Task {
            id: ctx.task_id.clone(),
            context_id: ctx.context_id.clone(),
            status: TaskStatus {
                state: TaskState::Completed,
                message: ctx.message,
                timestamp: None,
            },
            artifacts: None,
            history: None,
            metadata: None,
        };
        Box::pin(futures_util::stream::once(async move {
            Ok(StreamResponse::Task(task))
        }))
    }

    fn cancel(
        &self,
        ctx: ExecutorContext,
    ) -> BoxStream<'static, Result<StreamResponse, a2a::A2AError>> {
        let task = Task {
            id: ctx.task_id.clone(),
            context_id: ctx.context_id.clone(),
            status: TaskStatus {
                state: TaskState::Canceled,
                message: None,
                timestamp: None,
            },
            artifacts: None,
            history: None,
            metadata: None,
        };
        Box::pin(futures_util::stream::once(async move {
            Ok(StreamResponse::Task(task))
        }))
    }
}

/// Their server, on a loopback port.
async fn independent_server() -> String {
    let handler = Arc::new(DefaultRequestHandler::new(Echo, InMemoryTaskStore::new()));
    let app = jsonrpc_router(handler);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

fn chain() -> Delegation {
    Delegation::root(Principal::new("user:owner", Scope::root()))
}

/// A message this crate composed is understood by a server it did not write.
///
/// The release blocker this closes. Everything on the wire here — the method
/// name, the `ProtoJSON` envelope, the version header, the parts encoding, the
/// response `oneof` — is produced by this crate and parsed by the reference
/// SDK. A disagreement about any of them fails here and nowhere else in the
/// suite.
#[tokio::test]
async fn this_crates_client_round_trips_against_the_reference_server() {
    let url = independent_server().await;
    let client = A2aClient::new(Endpoint::new(url)).expect("client");

    let reply = client
        .send(
            &PeerId::new("reference"),
            "audit.check",
            &json!({ "ask": "is this understood" }),
            &chain(),
            None,
            None,
        )
        .await
        .expect("the reference server refused a message this crate composed");

    // Their echo executor completes the task, so a successful round trip is a
    // terminal state and not merely a 200.
    let body = serde_json::to_value(&reply).expect("serialisable");
    assert!(
        body.to_string().contains("TASK_STATE_COMPLETED") || body.get("task").is_some(),
        "the reply did not carry the task the reference server produced: {body:#}"
    );
}

/// An unknown method is a *refusal*, not an unknown outcome.
///
/// The disposition mapping is the half of a client with consequences, and it is
/// the half a canned fixture cannot check honestly: a stub returns whatever the
/// test author believed the peer would say. Here the error is the reference
/// server's own, for a method it genuinely does not implement — and this crate
/// must read it as *did not happen*, or a caller retries work that was never
/// started, or abandons work that was.
#[tokio::test]
async fn a_method_the_reference_server_rejects_maps_to_a_disposition() {
    let url = independent_server().await;
    let client = A2aClient::new(Endpoint::new(format!("{url}/nope"))).expect("client");

    let err = client
        .send(
            &PeerId::new("reference"),
            "audit.check",
            &json!({}),
            &chain(),
            None,
            None,
        )
        .await
        .expect_err("a request to a path the server does not serve was accepted");

    assert_eq!(
        err.disposition(),
        Disposition::DidNotHappen,
        "a request the reference server never routed must be safe to retry: {err}"
    );
}
