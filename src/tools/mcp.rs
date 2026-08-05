//! MCP as a transport for tool calls.
//!
//! The catalogue in [`super`] decides what a tool is *allowed* to do. This file
//! only carries the call, and its one hard job is to say — for every way a call
//! can fail — whether the request reached the far side.
//!
//! # Why the error mapping is the whole of it
//!
//! [`Disposition`] is what the retry gate reads. Classify a timeout as
//! `DidNotHappen` and a mutating tool gets called twice; classify a rejected
//! request as `InDoubt` and every malformed argument escalates to a human. The
//! transport is the only layer that knows which happened, so getting this table
//! right *is* the integration:
//!
//! | `ServiceError` | Disposition | Why |
//! |---|---|---|
//! | `McpError` (`METHOD_NOT_FOUND`, `INVALID_PARAMS`, parse) | `DidNotHappen` | the server parsed the request and declined it; the tool never ran |
//! | `McpError` (anything else) | `InDoubt` | the server errored, possibly mid-execution |
//! | `Timeout` | `InDoubt` | sent, no answer — a timeout is not evidence |
//! | `Cancelled` | `InDoubt` | *we* gave up; the server may still be running it |
//! | `TransportSend`, `TransportClosed` | `InDoubt` | a send that failed partway is indistinguishable from one that never left |
//! | `UnexpectedResponse` | `Landed` | it answered, so it processed |
//! | `SubscriptionLagged`, `InputRequiredRoundsExceeded` | `InDoubt` | the exchange was abandoned mid-flight |
//!
//! Two of those deserve their reasoning stated rather than assumed.
//!
//! **`Cancelled` is not `DidNotHappen`.** Cancelling a request cancels *our*
//! interest in the answer. Whether the server stops executing is entirely up to
//! the server, and for a tool that moves money the honest answer is that we do
//! not know.
//!
//! **`TransportSend` is not `DidNotHappen`.** It is tempting: the send failed, so
//! surely nothing left. But a framed message can fail *partway* through the
//! write, and from here a partial write and a refused connection are the same
//! error. The crate's rule for an error that does not say what it did is to treat
//! it as dangerous, and this is that rule applied.
//!
//! # Annotations are read, recorded, and disobeyed
//!
//! [`McpClient::discover`] returns what each server advertises so it can be put
//! beside the operator's catalogue. It deliberately does not build a catalogue:
//! that would be the server deciding what it is allowed to do, which is the one
//! thing this whole module exists to prevent.

use std::sync::Arc;

use async_trait::async_trait;
use rmcp::model::{CallToolRequestParams, ErrorCode};
use rmcp::service::{RoleClient, RunningService, ServiceError};
use serde_json::Value;

use super::{Advertised, ToolClient, ToolError, ToolId};

/// A connected MCP server.
#[derive(Debug)]
pub struct McpClient {
    /// The name this plane knows the server by.
    ///
    /// Local, not something the server chose: the catalogue keys on it, and a
    /// server able to rename itself could step into another's entry.
    server: String,
    service: Arc<RunningService<RoleClient, ()>>,
}

impl McpClient {
    /// Wrap an already-initialised rmcp client.
    ///
    /// Taking the running service rather than a connection string keeps every
    /// transport — stdio, a child process, streamable HTTP — a caller's choice.
    #[must_use]
    pub fn new(server: impl Into<String>, service: Arc<RunningService<RoleClient, ()>>) -> Self {
        Self {
            server: server.into(),
            service,
        }
    }

    /// What this server says its tools are.
    ///
    /// Returned for comparison against the operator's catalogue, never to build
    /// one. See the module docs.
    ///
    /// # Errors
    ///
    /// If the server cannot be listed.
    pub async fn discover(&self) -> Result<Vec<(ToolId, Advertised)>, ToolError> {
        let listed = self
            .service
            .list_all_tools()
            .await
            .map_err(|e| Self::classify(&ToolId::new(&self.server, "tools/list"), &e))?;

        Ok(listed
            .into_iter()
            .map(|t| {
                let annotations = t.annotations.as_ref();
                (
                    ToolId::new(&self.server, t.name.to_string()),
                    Advertised {
                        read_only: annotations.and_then(|a| a.read_only_hint),
                        destructive: annotations.and_then(|a| a.destructive_hint),
                        idempotent: annotations.and_then(|a| a.idempotent_hint),
                    },
                )
            })
            .collect())
    }

    /// Turn a transport failure into a statement about whether the call landed.
    //
    // The arms below are deliberately not merged, though several share a body.
    // Each is a separate judgement about what a failure implies, and they agree
    // today by coincidence rather than by definition — collapsing them would
    // delete the reasoning and make a future divergence a silent edit.
    #[allow(clippy::match_same_arms)]
    fn classify(tool: &ToolId, e: &ServiceError) -> ToolError {
        let detail = e.to_string();
        match e {
            // The server parsed the request and declined it without running
            // anything. The only genuinely safe-to-repeat class.
            ServiceError::McpError(err)
                if matches!(
                    err.code,
                    ErrorCode::METHOD_NOT_FOUND
                        | ErrorCode::INVALID_PARAMS
                        | ErrorCode::PARSE_ERROR
                ) =>
            {
                ToolError::Refused {
                    tool: tool.clone(),
                    detail,
                }
            }
            // Any other protocol error may have arrived mid-execution.
            ServiceError::McpError(_) => ToolError::TimedOut {
                tool: tool.clone(),
                detail,
            },
            ServiceError::Timeout { .. } => ToolError::TimedOut {
                tool: tool.clone(),
                detail,
            },
            // We stopped waiting. The server did not necessarily stop working.
            ServiceError::Cancelled { .. } => ToolError::TimedOut {
                tool: tool.clone(),
                detail,
            },
            // A send that failed partway is indistinguishable from one that
            // never left.
            ServiceError::TransportSend(_) | ServiceError::TransportClosed => ToolError::TimedOut {
                tool: tool.clone(),
                detail,
            },
            // It answered, so it processed; the answer was simply not usable.
            ServiceError::UnexpectedResponse => ToolError::Malformed {
                tool: tool.clone(),
                detail,
            },
            // Abandoned mid-exchange.
            _ => ToolError::TimedOut {
                tool: tool.clone(),
                detail,
            },
        }
    }
}

#[async_trait]
impl ToolClient for McpClient {
    async fn call(
        &self,
        tool: &ToolId,
        arguments: &Value,
        provenance: Option<&crate::core::Provenance>,
    ) -> Result<Value, ToolError> {
        // A `ToolId` names a server precisely so two servers offering
        // `transfer` stay two tools. This client speaks to exactly one, and
        // until it checked, it executed whatever name it was handed against
        // whatever it was connected to — so a plane granting `tool://ledger/read`
        // and wiring the `tickets` connection got an answer, from the wrong
        // server, under the ledger's operator safety. `Unreachable`, because
        // nothing was attempted and nothing could have been.
        if tool.server != self.server {
            return Err(ToolError::Unreachable {
                tool: tool.clone(),
                detail: format!(
                    "this client is connected to MCP server '{}', not '{}'",
                    self.server, tool.server
                ),
            });
        }
        let object = match arguments {
            Value::Object(map) => Some(map.clone()),
            Value::Null => None,
            other => {
                return Err(ToolError::Refused {
                    tool: tool.clone(),
                    detail: format!(
                        "MCP tool arguments must be a JSON object, got {}",
                        kind_of(other)
                    ),
                });
            }
        };

        let mut params = match object {
            Some(args) => CallToolRequestParams::new(tool.tool.clone()).with_arguments(args),
            None => CallToolRequestParams::new(tool.tool.clone()),
        };

        // `_meta` is where MCP puts caller context, and this is the whole reason
        // the block is signed: the fields let a server correlate, and the
        // signature is what lets it *check* them instead of believing whatever
        // the last hop wrote. Sent under a namespaced prefix because `_meta` is
        // shared with every other extension.
        if let Some(p) = provenance {
            use rmcp::model::RequestParamsMeta;
            params.set_meta(rmcp::model::RequestMetaObject(rmcp::model::MetaObject(
                p.to_meta(),
            )));
        }

        let result = self
            .service
            .call_tool(params)
            .await
            .map_err(|e| Self::classify(tool, &e))?;

        // `isError` means the server ran the tool and the tool failed. That is a
        // landed call: repeating it is a second invocation, whatever it did
        // before it failed.
        if result.is_error == Some(true) {
            return Err(ToolError::ToolFailed {
                tool: tool.clone(),
                detail: render(&result),
            });
        }

        // Structured content when the server provides it, otherwise preserve
        // every protocol block. Flattening to text silently discarded images,
        // audio and resources — a successful multimodal tool call became an
        // empty string, which is corruption rather than graceful degradation.
        // Both forms are labelled untrusted by the effect layer.
        if let Some(structured) = result.structured_content {
            return Ok(structured);
        }
        serde_json::to_value(&result.content).map_err(|error| ToolError::Malformed {
            tool: tool.clone(),
            detail: format!("MCP tool result content could not be represented: {error}"),
        })
    }
}

fn kind_of(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

fn render(result: &rmcp::model::CallToolResult) -> String {
    result
        .content
        .iter()
        .filter_map(|c| c.as_text().map(|t| t.text.clone()))
        .collect::<Vec<_>>()
        .join("\n")
}
