//! Serving MCP over Streamable HTTP.
//!
//! The [`McpServer`] catalogue, reachable by a framework that holds a URL and
//! a bearer header — the way agent frameworks in every language consume a
//! remote tool.
//!
//! # What runs before the MCP layer sees a request
//!
//! In this order, each one refusing before the next is reached:
//!
//! 1. **`Host` and `Origin`.** `Host` must be an allowed authority — loopback
//!    unless the operator lists others — and an `Origin`, when present, must
//!    be listed: the DNS-rebinding guard the transport specification asks a
//!    server for. A request without `Origin` (every server-side framework)
//!    passes. Refused with `403`.
//! 2. **The [`Authenticator`], then the tenant.** One `401` for a missing
//!    credential, an unknown one and one for another tenant, so a prober
//!    learns nothing about which it held. The challenge is
//!    `WWW-Authenticate: Bearer`, carrying `resource_metadata` only when
//!    protected-resource metadata is configured.
//!
//!    An authenticator that cannot answer — its key store unreachable —
//!    answers as a refused credential does, since
//!    [`AuthError`](crate::api::AuthError) does not tell the two apart, and
//!    the reason is logged on this side.
//! 3. **The session's owner.** A `2025-11-25` session (`Mcp-Session-Id`)
//!    belongs to the caller whose `initialize` created it: a `GET`, `POST` or
//!    `DELETE` naming it from anyone else is answered `404`, as a session that
//!    does not exist is, so another caller can neither replay its stream, post
//!    into it, nor close it. One caller holds at most
//!    [`MAX_SESSIONS_PER_CALLER`] live sessions; an `initialize` past that is
//!    `429` and its session is closed.
//!
//! Authentication sits here rather than in each MCP method because a method
//! added later would otherwise be unauthenticated by default. The caller it
//! establishes travels on the request, and the server reads it per request:
//! the call is admitted as that caller, under its chain or none, with its
//! input labelled as coming from it, each action is asked of policy, and a
//! task is answered only to the caller whose key admitted it.
//!
//! # Protected-resource metadata
//!
//! Published only when [`HttpConfig::protected_resource`] names an
//! authorization server whose tokens the configured [`Authenticator`]
//! verifies. A document naming none, or naming one whose tokens nothing here
//! checks, would be a declared control enforced by nobody.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use rmcp::transport::streamable_http_server::session::SessionManager;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};

use super::serve::{McpServer, ServeError};
use crate::api::Authenticator;
use crate::api::rebinding::{Rebinding, refuse_rebinding};

/// The path the MCP endpoint is served at.
pub const MCP_PATH: &str = "/mcp";

/// The RFC 9728 well-known path, before any path is inserted.
const METADATA_PATH: &str = "/.well-known/oauth-protected-resource";

/// The one body every refused credential gets.
const UNAUTHENTICATED: &str = "this request was not authenticated";

/// The header a `2025-11-25` session is named by.
const SESSION_HEADER: &str = "mcp-session-id";

/// How many live `2025-11-25` sessions one caller may hold.
///
/// A session is server memory held until it is closed or idles out, so an
/// unbounded number per credential is a caller's to spend and the plane's to
/// pay for. A framework holds one per connection, and a handful covers a
/// reconnect racing its predecessor's idle eviction.
pub const MAX_SESSIONS_PER_CALLER: usize = 8;

/// Where the listener may be reached from.
#[derive(Debug, Clone, Default)]
pub struct HttpConfig {
    hosts: Vec<String>,
    origins: Vec<String>,
    protected_resource: Option<ProtectedResource>,
}

/// An RFC 9728 protected-resource document: the canonical URL of the MCP
/// endpoint and the authorization servers whose tokens it accepts.
#[derive(Debug, Clone, serde::Serialize)]
struct ProtectedResource {
    resource: String,
    authorization_servers: Vec<String>,
    bearer_methods_supported: [&'static str; 1],
}

/// The authorities a `Host` header may name when nobody lists any.
const LOOPBACK: [&str; 3] = ["localhost", "127.0.0.1", "::1"];

impl HttpConfig {
    /// Loopback only, no browser origin, no metadata.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Also accept this `Host` authority — `host` or `host:port`.
    #[must_use]
    pub fn allow_host(mut self, host: impl Into<String>) -> Self {
        self.hosts.push(host.into());
        self
    }

    /// Accept requests whose `Origin` is this one — `scheme://host[:port]`.
    #[must_use]
    pub fn allow_origin(mut self, origin: impl Into<String>) -> Self {
        self.origins.push(origin.into());
        self
    }

    /// Publish protected-resource metadata naming the authorization servers
    /// whose tokens the configured [`Authenticator`] verifies.
    ///
    /// # Errors
    ///
    /// [`ServeError::NoAuthorizationServer`] for an empty list: the
    /// specification requires at least one, and a document naming none tells
    /// a client nothing it can act on.
    pub fn protected_resource(
        mut self,
        resource: impl Into<String>,
        authorization_servers: Vec<String>,
    ) -> Result<Self, ServeError> {
        if authorization_servers.iter().all(|s| s.trim().is_empty()) {
            return Err(ServeError::NoAuthorizationServer);
        }
        self.protected_resource = Some(ProtectedResource {
            resource: resource.into(),
            authorization_servers,
            bearer_methods_supported: ["header"],
        });
        Ok(self)
    }

    /// The `Host` allow-list: loopback, plus whatever was listed.
    fn hosts(&self) -> Vec<String> {
        LOOPBACK
            .iter()
            .map(|h| (*h).to_owned())
            .chain(self.hosts.iter().cloned())
            .collect()
    }
}

/// The catalogue as an HTTP service.
#[derive(Clone)]
pub struct McpHttp {
    router: Router,
    stop: Arc<dyn Fn() + Send + Sync>,
}

impl std::fmt::Debug for McpHttp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpHttp").finish_non_exhaustive()
    }
}

/// What the authenticating layer reads.
#[derive(Clone)]
struct Guard {
    auth: Arc<dyn Authenticator>,
    tenant: crate::core::TenantId,
    challenge: HeaderValue,
    sessions: Arc<Sessions>,
}

/// Which caller each live session belongs to.
struct Sessions {
    manager: Arc<LocalSessionManager>,
    owners: Mutex<HashMap<String, String>>,
}

impl Sessions {
    /// The actor a session was created by, if this listener created it.
    fn owner(&self, id: &str) -> Option<String> {
        self.owners
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(id)
            .cloned()
    }

    /// Record a new session as `actor`'s, unless `actor` already holds the
    /// most it may. Sessions that have closed or idled out are forgotten
    /// first, so they do not count.
    async fn bind(&self, id: &str, actor: &str) -> bool {
        let live: std::collections::HashSet<String> = self
            .manager
            .sessions
            .read()
            .await
            .keys()
            .map(ToString::to_string)
            .collect();
        let mut owners = self
            .owners
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        owners.retain(|session, _| live.contains(session));
        let held = owners.values().filter(|owner| *owner == actor).count();
        if held >= MAX_SESSIONS_PER_CALLER {
            return false;
        }
        owners.insert(id.to_owned(), actor.to_owned());
        true
    }

    fn forget(&self, id: &str) {
        self.owners
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(id);
    }
}

impl McpHttp {
    /// Serve `server` behind `auth`.
    ///
    /// # Errors
    ///
    /// [`ServeError::PolicyUnevaluable`] when the policy set cannot evaluate a
    /// request this surface asks — a rule that cannot evaluate declines every
    /// caller and says nothing about why.
    pub fn new(
        server: McpServer,
        auth: Arc<dyn Authenticator>,
        config: &HttpConfig,
    ) -> Result<Self, ServeError> {
        let runtime = server.runtime();
        if let Some(policy) = runtime.policy() {
            let problems = super::serve::policy_problems(policy.as_ref());
            if !problems.is_empty() {
                return Err(ServeError::PolicyUnevaluable {
                    problems: problems.join("; "),
                });
            }
        }
        let tenant = runtime.tenant().clone();
        let server = server.authenticated();
        let transport = StreamableHttpServerConfig::default()
            .with_allowed_hosts(config.hosts())
            .with_allowed_origins(config.origins.clone())
            .enforce_origin_validation();
        let token = transport.cancellation_token.clone();
        let manager = Arc::new(LocalSessionManager::default());
        let service =
            StreamableHttpService::new(move || Ok(server.clone()), Arc::clone(&manager), transport);
        let challenge = config.protected_resource.as_ref().map_or_else(
            || HeaderValue::from_static("Bearer"),
            |pr| {
                HeaderValue::from_str(&format!(
                    "Bearer resource_metadata=\"{}\"",
                    metadata_url(&pr.resource)
                ))
                .unwrap_or_else(|_| HeaderValue::from_static("Bearer"))
            },
        );
        let rebinding = Rebinding::new(config.hosts(), config.origins.clone());
        let guard = Guard {
            auth,
            tenant,
            challenge,
            sessions: Arc::new(Sessions {
                manager,
                owners: Mutex::new(HashMap::new()),
            }),
        };
        let mut router = Router::new()
            .route_service(MCP_PATH, service)
            .layer(axum::middleware::from_fn_with_state(guard, authenticate));
        if let Some(document) = config.protected_resource.clone() {
            let document = Arc::new(document);
            let path = format!("{METADATA_PATH}{MCP_PATH}");
            let metadata = axum::routing::get(move || {
                let document = Arc::clone(&document);
                async move { axum::Json(document.as_ref().clone()) }
            });
            router = router
                .route(METADATA_PATH, metadata.clone())
                .route(&path, metadata);
        }
        let router = router.layer(axum::middleware::from_fn_with_state(
            rebinding,
            refuse_rebinding,
        ));
        Ok(Self {
            router,
            stop: Arc::new(move || token.cancel()),
        })
    }

    /// The service, to mount or serve.
    pub fn router(&self) -> Router {
        self.router.clone()
    }

    /// End every open stream and session, so a graceful shutdown is not held
    /// open by a host's idle event stream.
    pub fn close(&self) {
        (self.stop)();
    }
}

/// The well-known URL a resource's metadata is served at: the path inserted
/// after the origin, as RFC 9728 builds it.
fn metadata_url(resource: &str) -> String {
    match resource.parse::<axum::http::Uri>() {
        Ok(uri) if uri.scheme().is_some() && uri.authority().is_some() => {
            let path = uri.path().trim_end_matches('/');
            format!(
                "{}://{}{METADATA_PATH}{path}",
                uri.scheme_str().unwrap_or("https"),
                uri.authority()
                    .map_or("", axum::http::uri::Authority::as_str)
            )
        }
        _ => METADATA_PATH.to_owned(),
    }
}

/// Authenticate, check the tenant, hold a session to its owner, and put the
/// caller on the request.
async fn authenticate(State(guard): State<Guard>, mut request: Request, next: Next) -> Response {
    let caller = match guard.auth.authenticate(request.headers()).await {
        Ok(caller) if caller.tenant == guard.tenant => Some(caller),
        Ok(_) => {
            tracing::debug!(target: "agentplane::mcp", "MCP caller is another tenant's");
            None
        }
        Err(error) => {
            tracing::warn!(target: "agentplane::mcp", %error, "MCP request not authenticated");
            None
        }
    };
    let Some(caller) = caller else {
        let mut refused = (StatusCode::UNAUTHORIZED, UNAUTHENTICATED).into_response();
        refused
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, guard.challenge.clone());
        return refused;
    };
    let actor = caller.actor.clone();
    let session = request
        .headers()
        .get(SESSION_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    // Another caller's session answers as no session at all. One this
    // listener never bound is left to the transport, which answers `404` for
    // a session it does not hold.
    if let Some(id) = &session
        && guard.sessions.owner(id).is_some_and(|owner| owner != actor)
    {
        return (StatusCode::NOT_FOUND, "Not Found: Session not found").into_response();
    }
    let closing = request.method() == Method::DELETE;
    request.extensions_mut().insert(caller);
    let response = next.run(request).await;
    match session {
        Some(id) if closing && response.status().is_success() => guard.sessions.forget(&id),
        Some(_) => {}
        None => {
            let created = response
                .headers()
                .get(SESSION_HEADER)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            if let Some(id) = created
                && !guard.sessions.bind(&id, &actor).await
            {
                let _ = guard.sessions.manager.close_session(&id.into()).await;
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    "this caller holds as many MCP sessions as it may; close one first",
                )
                    .into_response();
            }
        }
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::rebinding::{host_allowed, origin_allowed};

    #[test]
    fn no_metadata_document_names_no_authorization_server() {
        assert!(matches!(
            HttpConfig::new().protected_resource("https://plane.example/mcp", vec![]),
            Err(ServeError::NoAuthorizationServer)
        ));
        assert!(matches!(
            HttpConfig::new().protected_resource("https://plane.example/mcp", vec![" ".into()]),
            Err(ServeError::NoAuthorizationServer)
        ));
    }

    #[test]
    fn the_metadata_url_inserts_the_resource_path() {
        assert_eq!(
            metadata_url("https://plane.example/mcp"),
            "https://plane.example/.well-known/oauth-protected-resource/mcp"
        );
    }

    #[test]
    fn hosts_and_origins_compare_by_authority() {
        let hosts = HttpConfig::new().allow_host("plane.example:8443").hosts();
        assert!(host_allowed("127.0.0.1:8081", &hosts));
        assert!(host_allowed("[::1]:8081", &hosts));
        assert!(host_allowed("plane.example:8443", &hosts));
        assert!(!host_allowed("plane.example:9000", &hosts));
        assert!(!host_allowed("evil.example", &hosts));
        let origins = ["https://app.example".to_owned()];
        assert!(origin_allowed("https://app.example:443", &origins));
        assert!(!origin_allowed("http://app.example", &origins));
        assert!(!origin_allowed("null", &origins));
    }
}
