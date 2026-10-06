//! A page for trying an agent, on the author's own machine.
//!
//! `agentplane dev` serves one listener: a static page, the operator API under
//! `/api` exactly as a deployment serves it, and the routes in [`ROUTES`] under
//! `/dev` that an author needs while the process holds the store — start a
//! run, list runs, strict-replay, export, read the declaration, and read a
//! run and its history with their hidden characters shown. It is not a deployment
//! surface and not a reviewer page: it exists only in a build with the `dev`
//! feature, which no published image enables.
//!
//! # What runs before a route sees a request
//!
//! Outermost first:
//!
//! 1. **The headers.** Every response — every route, the page, its assets,
//!    the fallback and every refusal — carries [`CONTENT_SECURITY_POLICY`],
//!    `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` and
//!    `Cache-Control: no-store`. The policy requires Trusted Types and names
//!    no policy, so a sink that would parse HTML throws instead of running.
//! 2. **`Host` and `Origin`.** The `Host` must be the listener's own loopback
//!    authority, which refuses DNS rebinding; a request that changes state must
//!    name the page's own `Origin`, which refuses a cross-site form or fetch.
//! 3. **The gate.** Every `/dev` route authenticates with the session's one
//!    token and asks the plane's own engine its `api:dev.*` action, as every
//!    `/api` route asks its `api:` one. The page and its two assets carry no
//!    data and are served without the token, because a navigation cannot send
//!    a header.
//!
//! # Why the dev routes are a table of their own
//!
//! [`ROUTES`] is not part of [`openapi::ROUTES`](super::openapi::ROUTES): that
//! table is the published operator API, which every deployment build serves,
//! its document describes and its generated client calls. Starting a run over
//! HTTP must exist in no deployment, so these routes appear in no document,
//! and their actions are [`action::ALL`] here rather than in the operator
//! vocabulary a deployment's policy bundle is checked against.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{MethodFilter, MethodRouter, any, get, on};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tower::ServiceExt as _;

use super::openapi::Method;
use super::rebinding::{Rebinding, refuse_rebinding};
use super::{Api, ApiError, Authenticator, Session};
use crate::core::{
    ACTION_ADMIT, ACTION_PERFORM, ACTION_RELEASE, Digest, PolicyBundleIdentity, PolicyDecision,
    PolicyEngine, PolicyRequest,
};
use crate::runtime::Runtime;

/// The `api:dev.*` actions the dev routes ask the plane's engine.
pub mod action {
    /// Start a run.
    pub const RUN: &str = "api:dev.run";
    /// Strict-replay one run, or every run.
    pub const REPLAY: &str = "api:dev.replay";
    /// Export the store and verify the export.
    pub const EXPORT: &str = "api:dev.export";
    /// Read the declaration the plane runs.
    pub const MANIFEST: &str = "api:dev.manifest";
    /// Read a run's history as the page shows it.
    pub const HISTORY: &str = "api:dev.history";
    /// List every run the store holds.
    pub const RUNS: &str = "api:dev.runs";

    /// Every action a dev route asks.
    pub const ALL: &[&str] = &[RUN, REPLAY, EXPORT, MANIFEST, HISTORY, RUNS];
}

/// The tenant every dev plane runs as.
pub const TENANT: &str = "dev";

/// The content security policy on every response.
pub const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self'; \
     style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; \
     form-action 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'; \
     trusted-types 'none'";

/// The page and its assets: path, content type, body.
pub const SHELL: &[(&str, &str, &str)] = &[
    (
        "/",
        "text/html; charset=utf-8",
        include_str!("dev/index.html"),
    ),
    (
        "/assets/app.js",
        "text/javascript; charset=utf-8",
        include_str!("dev/app.js"),
    ),
    (
        "/assets/app.css",
        "text/css; charset=utf-8",
        include_str!("dev/app.css"),
    ),
];

/// What the page asks of the process that owns the plane.
///
/// The binary implements it, because building a plane from a manifest —
/// providers, tool servers, peers — is the binary's, and `run` and `dev` must
/// build it one way.
#[async_trait::async_trait]
pub trait Workbench: Send + Sync + 'static {
    /// The plane runs are admitted on now.
    async fn plane(&self) -> Arc<Runtime>;

    /// The declaration as the file holds it now, rebuilding the plane first
    /// when the file changed and parses.
    async fn declaration(&self) -> Declaration;

    /// Admit one run and drive it until it concludes or waits.
    ///
    /// # Errors
    ///
    /// A sentence the page shows when the run cannot be admitted.
    async fn start(&self, request: StartRequest) -> Result<Started, String>;

    /// Where the plane forwards its model calls' live output.
    fn streams(&self) -> Arc<StreamHub>;

    /// Strict-replay `run`, or every run in the store, against the
    /// declaration as the file holds it now.
    ///
    /// # Errors
    ///
    /// A sentence the page shows when nothing could be replayed.
    async fn replay(&self, run: Option<crate::core::RunId>) -> Result<Vec<Replayed>, String>;
}

/// Live model output from every run on the dev plane, fanned out to the
/// pages following it.
///
/// Advisory, as the observer it implements is: a page that falls behind
/// misses deltas, and the journal's completion stays the answer.
#[derive(Debug)]
pub struct StreamHub {
    sender: tokio::sync::broadcast::Sender<(String, Value)>,
    /// Set when the session ends, so every open stream closes and a graceful
    /// shutdown has no connection left to wait for.
    closed: tokio::sync::watch::Sender<bool>,
}

impl StreamHub {
    /// How many events a lagging page may fall behind before it misses some.
    const BACKLOG: usize = 1024;

    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            sender: tokio::sync::broadcast::channel(Self::BACKLOG).0,
            closed: tokio::sync::watch::channel(false).0,
        })
    }

    /// End every open stream.
    pub fn close(&self) {
        self.closed.send_replace(true);
    }
}

impl crate::runtime::RunStreamObserver for StreamHub {
    fn event(
        &self,
        run: crate::core::RunId,
        event: crate::core::Tainted<crate::model::ModelStreamEvent>,
    ) {
        let trust = event.label().trust;
        let line = match event.into_unlabelled() {
            crate::model::ModelStreamEvent::TextDelta(text) => {
                json!({ "type": "text_delta", "value": crate::core::visible::escape(&text).0, "trust": trust })
            }
            crate::model::ModelStreamEvent::Usage(usage) => {
                json!({ "type": "usage", "value": usage, "trust": trust })
            }
        };
        // No page following is not a failure: the hub drops what nobody reads.
        let _ = self.sender.send((run.to_string(), line));
    }
}

/// The declaration pane.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Declaration {
    /// The manifest file, as given on the command line.
    pub file: String,
    /// One entry per agent the running plane was built from.
    pub agents: Vec<DeclaredAgent>,
    /// Why the file as it is now was not loaded; the plane keeps running the
    /// last declaration that parsed.
    pub refused: Option<String>,
    /// Every transport that reaches a system outside this process.
    pub live: Vec<String>,
}

/// One agent the plane runs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeclaredAgent {
    pub name: String,
    pub version: String,
    pub digest: String,
    /// What its runs can cost, as `agentplane validate` reports it.
    pub bound: Vec<String>,
    /// The capabilities a run can be started under.
    #[serde(default)]
    pub provides: Vec<String>,
    /// The input the agent declares it takes, when it declares one.
    #[serde(default)]
    pub input_schema: Option<Value>,
}

/// What `POST /dev/runs` takes.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartRequest {
    /// The run's input.
    pub input: Value,
    /// Correlation keys, `namespace=value`; runs sharing one share a case.
    #[serde(default)]
    pub correlate: Vec<String>,
    /// The capability to start, where the file provides several.
    #[serde(default)]
    pub capability: Option<String>,
}

/// A run the page started.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Started {
    pub run: String,
    pub status: String,
}

/// One run's strict-replay verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Replayed {
    pub run: String,
    /// `reproduced`, `diverged`, `cannot_replay` or `unreadable`.
    pub verdict: String,
    /// The verdict in full, naming the first divergent effect.
    pub detail: String,
}

/// What `POST /dev/replay` takes.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayRequest {
    /// The run to replay; every run when absent.
    #[serde(default)]
    pub run: Option<String>,
}

/// One dev route.
#[derive(Debug, Clone, Copy)]
pub struct DevRoute {
    pub method: Method,
    pub path: &'static str,
    /// The `api:dev.*` action its gate asks.
    pub action: &'static str,
    serve: fn(MethodFilter) -> MethodRouter<Arc<Surface>>,
}

/// Every route under `/dev`.
pub const ROUTES: &[DevRoute] = &[
    DevRoute {
        method: Method::Get,
        path: "/dev/manifest",
        action: action::MANIFEST,
        serve: |m| on(m, declaration),
    },
    DevRoute {
        method: Method::Post,
        path: "/dev/runs",
        action: action::RUN,
        serve: |m| on(m, start),
    },
    DevRoute {
        method: Method::Get,
        path: "/dev/runs",
        action: action::RUNS,
        serve: |m| on(m, runs),
    },
    DevRoute {
        method: Method::Post,
        path: "/dev/replay",
        action: action::REPLAY,
        serve: |m| on(m, replay),
    },
    DevRoute {
        method: Method::Get,
        path: "/dev/export",
        action: action::EXPORT,
        serve: |m| on(m, export),
    },
    DevRoute {
        method: Method::Get,
        path: "/dev/runs/{run}",
        action: action::HISTORY,
        serve: |m| on(m, run_view),
    },
    DevRoute {
        method: Method::Get,
        path: "/dev/stream",
        action: action::RUNS,
        serve: |m| on(m, stream),
    },
    DevRoute {
        method: Method::Get,
        path: "/dev/runs/{run}/history",
        action: action::HISTORY,
        serve: |m| on(m, history),
    },
];

/// How many runs of each outcome one export reads.
const EXPORT_LIMIT: usize = 10_000;

/// The engine every dev plane runs under.
///
/// Permits the session's own actor every `api:` action on tenant `dev` and
/// nobody else anything there; permits admission and effects; refuses a
/// release, as `agentplane run` with no engine does. It exists only in the
/// process that built it: there is no text to copy into a deployment.
#[derive(Debug, Clone)]
pub struct DevPolicy {
    actor: String,
}

impl DevPolicy {
    /// The engine for one session's actor.
    #[must_use]
    pub fn new(actor: impl Into<String>) -> Self {
        Self {
            actor: actor.into(),
        }
    }
}

impl PolicyEngine for DevPolicy {
    fn authorize(&self, request: &PolicyRequest<'_>) -> PolicyDecision {
        if request.action.starts_with("api:") {
            let tenant = request.context.get("tenant").and_then(Value::as_str);
            if request.principal == self.actor && tenant == Some(TENANT) {
                return PolicyDecision::Permit;
            }
            return PolicyDecision::deny("only this dev session's own token reaches its plane");
        }
        match request.action {
            ACTION_ADMIT | ACTION_PERFORM => PolicyDecision::Permit,
            ACTION_RELEASE => PolicyDecision::deny(
                "`agentplane dev` permits no release, as `agentplane run` permits none: a \
                 release lowers a label only when a rule permits `data:release`",
            ),
            _ => PolicyDecision::deny("a dev plane permits admission and effects only"),
        }
    }

    fn bundle(&self) -> PolicyBundleIdentity {
        PolicyBundleIdentity::new(
            Digest::of(b"agentplane dev policy"),
            "agentplane/dev-policy-v1",
        )
    }
}

/// What every handler reads.
struct Surface {
    bench: Arc<dyn Workbench>,
    auth: Arc<dyn Authenticator>,
    /// The operator API over the plane it was built for.
    operator: Mutex<Option<(Arc<Runtime>, Api)>>,
}

impl std::fmt::Debug for Surface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Surface").finish_non_exhaustive()
    }
}

impl Surface {
    /// The operator API over the plane runs are admitted on now.
    async fn api(&self) -> Result<Api, ApiError> {
        let plane = self.bench.plane().await;
        let mut held = self
            .operator
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((built_for, api)) = held.as_ref()
            && Arc::ptr_eq(built_for, &plane)
        {
            return Ok(api.clone());
        }
        let api = Api::new(Arc::clone(&plane), Arc::clone(&self.auth))
            .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        *held = Some((plane, api.clone()));
        Ok(api)
    }

    /// Authenticate, then authorize against the plane's engine — the operator
    /// API's own gate, asked a dev action.
    async fn gate(
        &self,
        headers: &HeaderMap,
        action: &str,
        resource: &str,
    ) -> Result<Session, ApiError> {
        let api = self.api().await?;
        let caller = self.auth.authenticate(headers).await?;
        api.authorize(caller, action, resource)
    }
}

/// The dev listener's router, for a listener bound to loopback `port`.
pub fn router(bench: Arc<dyn Workbench>, auth: Arc<dyn Authenticator>, port: u16) -> Router {
    let surface = Arc::new(Surface {
        bench,
        auth,
        operator: Mutex::new(None),
    });
    let authorities = [
        format!("127.0.0.1:{port}"),
        format!("localhost:{port}"),
        format!("[::1]:{port}"),
    ];
    let rebinding = Rebinding::new(
        authorities.to_vec(),
        authorities.iter().map(|a| format!("http://{a}")).collect(),
    )
    .origin_on_writes();

    let mut routes = Router::new();
    for route in ROUTES {
        let filter = match route.method {
            Method::Get => MethodFilter::GET,
            Method::Post => MethodFilter::POST,
        };
        routes = routes.route(route.path, (route.serve)(filter));
    }
    for (path, content_type, body) in SHELL {
        routes = routes.route(
            path,
            get(move || async move { ([(header::CONTENT_TYPE, *content_type)], *body) }),
        );
    }
    routes
        .route("/api/{*rest}", any(operator))
        .fallback(not_found)
        .with_state(surface)
        .layer(axum::middleware::from_fn_with_state(
            rebinding,
            refuse_rebinding,
        ))
        .layer(axum::middleware::from_fn(security_headers))
}

/// Set the four headers on whatever the layers inside answered.
async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn not_found() -> Response {
    ApiError(StatusCode::NOT_FOUND, "no such page".to_owned()).into_response()
}

/// `/api/*`: the operator router over the current plane, unchanged.
async fn operator(State(surface): State<Arc<Surface>>, request: Request) -> Response {
    let api = match surface.api().await {
        Ok(api) => api,
        Err(refused) => return refused.into_response(),
    };
    // A request of its own rather than this one re-pointed: this router's
    // path parameters travel in the request's extensions, and the operator
    // router would read them as its own.
    let (parts, body) = request.into_parts();
    let path = parts
        .uri
        .path_and_query()
        .map_or("/", axum::http::uri::PathAndQuery::as_str);
    let Ok(uri) = path
        .strip_prefix("/api")
        .unwrap_or(path)
        .parse::<axum::http::Uri>()
    else {
        return not_found().await;
    };
    let mut inner = Request::new(body);
    *inner.method_mut() = parts.method;
    *inner.uri_mut() = uri;
    *inner.version_mut() = parts.version;
    *inner.headers_mut() = parts.headers;
    match api.router().oneshot(inner).await {
        Ok(response) => response,
        Err(never) => match never {},
    }
}

/// A body that is not this route's shape.
fn unreadable(e: &serde_json::Error) -> ApiError {
    ApiError(StatusCode::UNPROCESSABLE_ENTITY, e.to_string())
}

async fn declaration(
    State(surface): State<Arc<Surface>>,
    headers: HeaderMap,
) -> Result<Json<Declaration>, ApiError> {
    surface.gate(&headers, action::MANIFEST, "manifest").await?;
    Ok(Json(surface.bench.declaration().await))
}

async fn start(
    State(surface): State<Arc<Surface>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Started>, ApiError> {
    surface.gate(&headers, action::RUN, "run").await?;
    let request: StartRequest = serde_json::from_slice(&body).map_err(|e| unreadable(&e))?;
    surface
        .bench
        .start(request)
        .await
        .map(Json)
        .map_err(|why| ApiError(StatusCode::UNPROCESSABLE_ENTITY, why))
}

async fn replay(
    State(surface): State<Arc<Surface>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Vec<Replayed>>, ApiError> {
    surface.gate(&headers, action::REPLAY, "run").await?;
    let request: ReplayRequest = if body.is_empty() {
        ReplayRequest::default()
    } else {
        serde_json::from_slice(&body).map_err(|e| unreadable(&e))?
    };
    let run = request
        .run
        .as_deref()
        .map(crate::core::RunId::parse)
        .transpose()
        .map_err(|_| super::bad("run"))?;
    surface
        .bench
        .replay(run)
        .await
        .map(Json)
        .map_err(|why| ApiError(StatusCode::UNPROCESSABLE_ENTITY, why))
}

/// Every run the store holds, concluded or not, grouped by outcome as the
/// store lists them.
async fn runs(
    State(surface): State<Arc<Surface>>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let s = surface.gate(&headers, action::RUNS, "store").await?;
    let outcomes: Vec<String> = crate::runtime::OUTCOMES_OF_RECORD
        .iter()
        .map(|o| (*o).to_owned())
        .collect();
    let found = crate::export::runs_to_read(s.plane.journal(), &outcomes, true, EXPORT_LIMIT)
        .await
        .map_err(|_| super::store_failed())?;
    let runs: Vec<String> = found.runs.iter().map(ToString::to_string).collect();
    Ok(Json(
        json!({ "runs": runs, "partial": !found.reached.is_empty() }),
    ))
}

/// The store as an export, and that export's verification — over one buffer,
/// so the bytes the page offers are the bytes it verified.
async fn export(
    State(surface): State<Arc<Surface>>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let s = surface.gate(&headers, action::EXPORT, "store").await?;
    let journal = Arc::clone(s.plane.journal());
    let cases = s
        .plane
        .cases()
        .cloned()
        .ok_or_else(|| super::unavailable("case store"))?;
    let outcomes: Vec<String> = crate::runtime::OUTCOMES_OF_RECORD
        .iter()
        .map(|o| (*o).to_owned())
        .collect();
    let found = crate::export::runs_to_read(&journal, &outcomes, true, EXPORT_LIMIT)
        .await
        .map_err(|_| super::store_failed())?;
    let mut bytes = Vec::new();
    crate::export::to_jsonl(&journal, &cases, &found.runs, &mut bytes)
        .await
        .map_err(|_| super::store_failed())?;
    let report = crate::export::verify(&bytes[..], None, &[]).map_err(|_| super::store_failed())?;
    Ok(Json(json!({
        "export": String::from_utf8_lossy(&bytes),
        "partial": !found.reached.is_empty(),
        "report": report,
        "verify": [
            "agentplane verify export.jsonl",
            "python3 tools/verify_export.py export.jsonl",
        ],
    })))
}

/// A run's history as `GET /api/runs/{run}/history` serves it, with every
/// string in its records — object keys included — passed through
/// [`escape`](crate::core::visible::escape), as `agentplane history` prints
/// it.
async fn history(
    State(surface): State<Arc<Surface>>,
    Path(run): Path<String>,
    request: Request,
) -> Response {
    let (parts, _) = request.into_parts();
    let query = parts
        .uri
        .query()
        .map_or_else(String::new, |q| format!("?{q}"));
    escaped_read(
        &surface,
        &parts.headers,
        &run,
        &format!("/history{query}"),
        "records",
    )
    .await
}

/// Every run's live model output, one JSON object per line naming its run,
/// until the page stops reading.
///
/// One stream for the session rather than one per run, because a run the
/// page starts is driven before its id is answered: the page learns of it
/// from its first delta. Live only — nothing here is journaled, and a call
/// that finished before the page connected is read from the history.
async fn stream(State(surface): State<Arc<Surface>>, headers: HeaderMap) -> Response {
    if let Err(refused) = surface.gate(&headers, action::RUNS, "store").await {
        return refused.into_response();
    }
    let hub = surface.bench.streams();
    let state = (hub.sender.subscribe(), hub.closed.subscribe());
    let lines = futures_util::stream::unfold(state, |(mut receiver, mut closed)| async move {
        if *closed.borrow() {
            return None;
        }
        let line = tokio::select! {
            _ = closed.changed() => return None,
            next = receiver.recv() => match next {
                Ok((run, mut line)) => {
                    line["run"] = Value::String(run);
                    line
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(missed)) => {
                    json!({ "type": "lagged", "value": missed })
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
            },
        };
        let mut bytes = line.to_string().into_bytes();
        bytes.push(b'\n');
        Some((
            Ok::<_, std::convert::Infallible>(Bytes::from(bytes)),
            (receiver, closed),
        ))
    });
    (
        [(header::CONTENT_TYPE, "application/x-ndjson")],
        axum::body::Body::from_stream(lines),
    )
        .into_response()
}

/// A run's status as `GET /api/runs/{run}` serves it, every string escaped.
async fn run_view(
    State(surface): State<Arc<Surface>>,
    Path(run): Path<String>,
    headers: HeaderMap,
) -> Response {
    escaped_read(&surface, &headers, &run, "", "").await
}

/// `GET /runs/{run}{tail}` from the operator route, under its own gate,
/// with every string in `member` — the whole answer when empty — passed
/// through [`escape`](crate::core::visible::escape); `escaped` says whether
/// anything was.
///
/// The operator route answers, so the page reads what a deployment's reader
/// does and only the display differs.
async fn escaped_read(
    surface: &Surface,
    headers: &HeaderMap,
    run: &str,
    tail: &str,
    member: &str,
) -> Response {
    if let Err(refused) = surface.gate(headers, action::HISTORY, run).await {
        return refused.into_response();
    }
    let Ok(run) = crate::core::RunId::parse(run) else {
        return super::bad("run").into_response();
    };
    let api = match surface.api().await {
        Ok(api) => api,
        Err(refused) => return refused.into_response(),
    };
    let Ok(uri) = format!("/runs/{run}{tail}").parse::<axum::http::Uri>() else {
        return super::bad("from").into_response();
    };
    let mut inner = Request::new(axum::body::Body::empty());
    *inner.uri_mut() = uri;
    *inner.headers_mut() = headers.clone();
    let answer = match api.router().oneshot(inner).await {
        Ok(answer) => answer,
        Err(never) => match never {},
    };
    if answer.status() != StatusCode::OK {
        return answer;
    }
    let Ok(bytes) = axum::body::to_bytes(answer.into_body(), usize::MAX).await else {
        return super::store_failed().into_response();
    };
    let Ok(mut page) = serde_json::from_slice::<Value>(&bytes) else {
        return super::store_failed().into_response();
    };
    let mut escaped = false;
    if member.is_empty() {
        page = escape_strings(page, &mut escaped);
    } else if let Some(inner) = page.get_mut(member) {
        *inner = escape_strings(inner.take(), &mut escaped);
    }
    page["escaped"] = Value::Bool(escaped);
    Json(page).into_response()
}

/// `value` with every string and object key escaped; `escaped` is set when
/// any character was.
fn escape_strings(value: Value, escaped: &mut bool) -> Value {
    match value {
        Value::String(text) => {
            let (text, hit) = crate::core::visible::escape(&text);
            *escaped |= hit;
            Value::String(text)
        }
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(|item| escape_strings(item, escaped))
                .collect(),
        ),
        Value::Object(fields) => Value::Object(
            fields
                .into_iter()
                .map(|(key, item)| {
                    let (key, hit) = crate::core::visible::escape(&key);
                    *escaped |= hit;
                    (key, escape_strings(item, escaped))
                })
                .collect(),
        ),
        other => other,
    }
}
