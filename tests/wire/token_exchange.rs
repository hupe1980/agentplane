//! The shipped RFC 8693 client, against an issuer that answers like one.
//!
//! What the exchange posts is the whole contract with the deployment's
//! issuer, so the test reads the form the issuer received rather than the
//! client's own idea of it.

#![cfg(all(feature = "a2a", feature = "testkit", feature = "http"))]
#![allow(clippy::disallowed_methods)]

use std::sync::{Arc, Mutex};

use agentplane::core::Timestamp;
use agentplane::peers::{CredentialError, PeerId, TokenEndpoint, TokenExchange};
use axum::Router;
use axum::extract::State;
use axum::routing::post;

type Seen = Arc<Mutex<Vec<(Option<String>, String)>>>;

async fn issue(
    State((seen, status)): State<(Seen, u16)>,
    headers: axum::http::HeaderMap,
    body: String,
) -> (axum::http::StatusCode, String) {
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);
    seen.lock().unwrap().push((auth, body));
    let reply = if status == 200 {
        r#"{"access_token":"issued-for-alice","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":300}"#
    } else {
        r#"{"error":"invalid_target","error_description":"the reviewer is not a known resource"}"#
    };
    (
        axum::http::StatusCode::from_u16(status).unwrap(),
        reply.to_owned(),
    )
}

async fn issuer(status: u16) -> (String, Seen) {
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route("/token", post(issue))
        .with_state((Arc::clone(&seen), status));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}/token"), seen)
}

/// **The exchange carries the owner, the plane and the peer.** The issuer
/// receives the RFC 8693 grant with the run's owner as the subject assertion,
/// the plane's own credential as the actor, the peer as audience and its URI
/// as the RFC 8707 resource, and the plane authenticated as a client; what it
/// issues comes back bound to that peer and that person, expiring when it said.
#[tokio::test]
async fn the_exchange_request_carries_the_owner_and_the_actor() {
    let (url, seen) = issuer(200).await;
    let endpoint = TokenEndpoint::new(url, "urn:example:principal-id", "plane-actor-token")
        .expect("a loopback issuer in a testkit build")
        .client("agentplane", "client-secret")
        .resource(PeerId::new("reviewer"), "https://reviewer.example/a2a");

    let before = Timestamp::now_utc();
    let credential = endpoint
        .exchange(&PeerId::new("reviewer"), "user:alice")
        .await
        .expect("issued");
    assert_eq!(credential.expose(), "issued-for-alice");
    assert_eq!(credential.audience(), &PeerId::new("reviewer"));
    assert_eq!(credential.subject(), Some("user:alice"));
    let expiry = credential.expires_at().expect("the issuer said when");
    assert!(expiry > before && expiry <= Timestamp::now_utc() + time::Duration::seconds(300));

    let seen = seen.lock().unwrap();
    let (auth, form) = &seen[0];
    for pair in [
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange",
        "subject_token=user%3Aalice",
        "subject_token_type=urn%3Aexample%3Aprincipal-id",
        "actor_token=plane-actor-token",
        "audience=reviewer",
        "resource=https%3A%2F%2Freviewer.example%2Fa2a",
    ] {
        assert!(
            form.split('&').any(|p| p == pair),
            "the issuer did not receive {pair}: {form}"
        );
    }
    assert!(
        auth.as_deref().is_some_and(|a| a.starts_with("Basic ")),
        "the plane did not authenticate as a client: {auth:?}"
    );
}

/// **A refusal is final and names the OAuth error code, never the issuer's
/// prose** — the call it was for never left, and asking again would ask the
/// same rule.
#[tokio::test]
async fn an_issuer_refusal_is_final_and_names_only_its_code() {
    let (url, _seen) = issuer(400).await;
    let endpoint = TokenEndpoint::new(url, "urn:example:principal-id", "plane-actor-token")
        .expect("a loopback issuer in a testkit build");
    let err = endpoint
        .exchange(&PeerId::new("reviewer"), "user:alice")
        .await
        .expect_err("refused");
    let text = err.to_string();
    assert!(
        matches!(err, CredentialError::Refused { .. }) && text.contains("invalid_target"),
        "{text}"
    );
    assert!(
        !text.contains("not a known resource"),
        "the issuer's own description reached the error: {text}"
    );
}
