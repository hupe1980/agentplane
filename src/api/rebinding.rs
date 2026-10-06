//! Where a request may come from: the `Host` and `Origin` checks a listener
//! runs before anything reads a credential.
//!
//! A server on a loopback port is reachable from every page the machine's
//! browser opens. DNS rebinding points a hostile name at `127.0.0.1`, so the
//! request arrives on the right socket naming the wrong `Host`; a cross-site
//! form or `fetch` arrives naming the right `Host` and a foreign `Origin`. One
//! layer refuses both, parameterised by what each listener's callers send: a
//! server-side framework sends no `Origin`, so the MCP listener lets its
//! absence through, while a browser always sends one with a request that
//! changes state, so the dev page refuses its absence there.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// The allow-lists one listener checks.
#[derive(Debug, Clone)]
pub(crate) struct Rebinding {
    hosts: Arc<[String]>,
    origins: Arc<[String]>,
    origin_on_writes: bool,
}

impl Rebinding {
    /// Accept a `Host` naming one of `hosts` (`host` or `host:port`; an entry
    /// without a port allows any port), and an `Origin`, when one is sent,
    /// naming one of `origins` (`scheme://host[:port]`).
    pub(crate) fn new(hosts: Vec<String>, origins: Vec<String>) -> Self {
        Self {
            hosts: hosts.into(),
            origins: origins.into(),
            origin_on_writes: false,
        }
    }

    /// Also refuse a request other than `GET`, `HEAD` or `OPTIONS` that
    /// names no `Origin`.
    #[cfg(feature = "dev")]
    pub(crate) const fn origin_on_writes(mut self) -> Self {
        self.origin_on_writes = true;
        self
    }
}

/// Refuse a request whose `Host` is not allowed, whose `Origin` is present and
/// not listed, or — where the listener asks for it — that changes state and
/// names no `Origin`. `403` in each case, before anything reads its credential.
pub(crate) async fn refuse_rebinding(
    State(guard): State<Rebinding>,
    request: Request,
    next: Next,
) -> Response {
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(str::to_owned)
        .or_else(|| request.uri().authority().map(|a| a.as_str().to_owned()));
    if !host
        .as_deref()
        .is_some_and(|h| host_allowed(h, &guard.hosts))
    {
        return (
            StatusCode::FORBIDDEN,
            "Forbidden: Host header is not allowed",
        )
            .into_response();
    }
    let origin = request.headers().get(header::ORIGIN);
    if let Some(origin) = origin
        && !origin
            .to_str()
            .is_ok_and(|o| origin_allowed(o, &guard.origins))
    {
        return (
            StatusCode::FORBIDDEN,
            "Forbidden: Origin header is not allowed",
        )
            .into_response();
    }
    if guard.origin_on_writes && origin.is_none() && !request.method().is_safe() {
        return (
            StatusCode::FORBIDDEN,
            "Forbidden: a request that changes state must name its Origin",
        )
            .into_response();
    }
    next.run(request).await
}

/// `host` or `host:port`, lowercased and without IPv6 brackets.
fn authority(value: &str) -> Option<(String, Option<u16>)> {
    // A bare IPv6 address is not an authority until bracketed.
    if let Ok(ip) = value.trim().parse::<std::net::Ipv6Addr>() {
        return Some((ip.to_string(), None));
    }
    let parsed = value.trim().parse::<axum::http::uri::Authority>().ok()?;
    let host = parsed
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    Some((host, parsed.port_u16()))
}

/// An allowed entry without a port allows that host on any port.
pub(crate) fn host_allowed(value: &str, allowed: &[String]) -> bool {
    let Some((host, port)) = authority(value) else {
        return false;
    };
    allowed
        .iter()
        .filter_map(|a| authority(a))
        .any(|(h, p)| h == host && p.is_none_or(|p| Some(p) == port))
}

/// `(scheme, host, port)`, the port defaulted from the scheme — RFC 6454's
/// comparison. `null` compares only to `null`.
fn origin(value: &str) -> Option<(String, String, Option<u16>)> {
    let value = value.trim();
    if value == "null" {
        return Some(("null".to_owned(), String::new(), None));
    }
    let uri = value.parse::<axum::http::Uri>().ok()?;
    let scheme = uri.scheme_str()?.to_ascii_lowercase();
    let (host, port) = authority(uri.authority()?.as_str())?;
    let port = port.or(match scheme.as_str() {
        "http" => Some(80),
        "https" => Some(443),
        _ => None,
    });
    Some((scheme, host, port))
}

pub(crate) fn origin_allowed(value: &str, allowed: &[String]) -> bool {
    origin(value).is_some_and(|o| allowed.iter().filter_map(|a| origin(a)).any(|a| a == o))
}
