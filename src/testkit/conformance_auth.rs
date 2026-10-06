//! The contract an [`Authenticator`] a deployment writes has to keep.
//!
//! **Why this seam and not the credential ones.** The outbound seams —
//! [`TokenExchange`](crate::peers::TokenExchange) and
//! [`CredentialSource`](crate::peers::CredentialSource) — look like they need a
//! battery too, and they do not: the property that matters about a credential
//! this plane *sends* is that it is spent only at the audience it names and
//! names the subject it was asked for, and that is enforced at the boundary
//! every implementation crosses rather than asked of each one. Every credential
//! a source returns is checked for both before a peer effect presents it. A
//! battery asserting a property the runtime does not rely on the implementation
//! for would measure the boundary.
//!
//! Inbound is the other way round. An `Authenticator` *is* the decision: it
//! returns a [`Caller`] and the surface believes it, because establishing who
//! is calling is exactly what this crate does not know how to do for a
//! deployment. Nothing downstream can re-derive it, so what the trait asks for
//! has to be asked here.
//!
//! # The case an implementation gets wrong quietly
//!
//! A refusal must not say **why**: expired, unknown signer and wrong audience
//! are one sentence to whoever is probing. [`AuthError`] enforces most of that
//! by being two variants with fixed messages — an implementation cannot
//! elaborate even if it wants to. What it *can* still do is answer `Missing`
//! for a credential it looked at and refused, and that single bit separates
//! *the right shape* from *nothing here*, which is what a prober is reading
//! for. It is the kind of thing a first implementation gets wrong for the best
//! of reasons, and the kind nothing else notices, because every test a
//! deployment writes asserts that a bad credential is refused — which it is.

use std::panic::AssertUnwindSafe;

use axum::http::HeaderMap;
use futures_util::FutureExt as _;

use super::conformance::Report;
use crate::api::{AuthError, Authenticator, Caller};

/// The requests a deployment's own authenticator is asked about.
///
/// Supplied by the deployment because only it knows what a credential looks
/// like — this crate takes a whole [`HeaderMap`] precisely so a bearer token, a
/// mutual-TLS header and a gateway assertion are all expressible.
#[derive(Debug, Default)]
pub struct Requests {
    /// A request this deployment accepts, and the actor it names.
    ///
    /// Optional: an authenticator can be held to every refusal below without
    /// one. Supplying it is what also proves the battery is not passing because
    /// the implementation refuses everything.
    pub accepted: Option<(HeaderMap, String)>,
    /// Requests carrying a credential **in a form this server speaks** that it
    /// nevertheless does not accept — expired, unknown signer, wrong audience.
    ///
    /// Not a credential in some other scheme: *I cannot use what you sent* and
    /// *I used what you sent and refused it* are different answers and both are
    /// honest, because neither says which credentials exist. Every entry here
    /// must come back `Rejected`.
    pub rejected: Vec<(&'static str, HeaderMap)>,
}

/// Run the battery every authenticator answers, whatever it verifies.
///
/// # Panics
///
/// Never. A violated invariant is recorded on the report, and an implementation
/// that unwinds is recorded too — a panic on a malformed header is a refusal
/// spelled as a crash.
pub async fn check(auth: &dyn Authenticator, requests: &Requests, report: &mut Report) {
    no_credentials_is_missing_not_anonymous(auth, report).await;
    a_malformed_header_is_refused(auth, report).await;
    a_presented_credential_is_rejected_not_missing(auth, requests, report).await;
    an_accepted_request_names_its_actor(auth, requests, report).await;
}

/// Ask, recording an unwind as a violation of `rule` and returning `None`.
async fn ask(
    auth: &dyn Authenticator,
    headers: &HeaderMap,
    rule: &'static str,
    what: &str,
    r: &mut Report,
) -> Option<Result<Caller, AuthError>> {
    let answer = AssertUnwindSafe(auth.authenticate(headers))
        .catch_unwind()
        .await;
    if answer.is_err() {
        r.record(
            rule,
            format!(
                "authenticate panicked on {what} — a refusal spelled as a crash, taken \
                 down with it every request the process was serving"
            ),
        );
    }
    answer.ok()
}

/// A malformed credential is refused, not crashed on and not accepted.
///
/// `Bearer` with no token is what a client with an unset variable sends, and
/// the parse an implementation writes first splits it and indexes the half
/// that is not there.
async fn a_malformed_header_is_refused(auth: &dyn Authenticator, r: &mut Report) {
    const RULE: &str = "a malformed credential is refused";
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        axum::http::HeaderValue::from_static("Bearer"),
    );
    r.checked += 1;
    if let Some(Ok(caller)) = ask(auth, &headers, RULE, "`authorization: Bearer`", r).await {
        r.record(
            RULE,
            format!(
                "`authorization: Bearer` with no token was authenticated as `{}`",
                caller.actor
            ),
        );
    }
}

/// An empty request is [`AuthError::Missing`], and never a caller.
///
/// The arm worth checking rather than assuming: returning an anonymous caller
/// is the shortcut a first implementation reaches for, and it puts an unnamed
/// actor on an approval — which is the one place this design refuses to let a
/// name be absent.
async fn no_credentials_is_missing_not_anonymous(auth: &dyn Authenticator, r: &mut Report) {
    const RULE: &str = "no credentials is a refusal";
    r.checked += 1;
    let Some(answer) = ask(auth, &HeaderMap::new(), RULE, "an empty request", r).await else {
        return;
    };
    match answer {
        Err(AuthError::Missing) => {}
        Err(AuthError::Rejected) => r.record(
            RULE,
            "a request carrying nothing was `Rejected` rather than `Missing` — the two \
             are different answers, and only one of them means somebody tried",
        ),
        Ok(caller) => r.record(
            RULE,
            format!(
                "a request carrying no credentials was authenticated as `{}` — an \
                 unnamed actor on an approval is the one absence this design refuses",
                caller.actor
            ),
        ),
    }
}

/// A credential that was presented and refused is not an absent one.
///
/// **This is the whole of the oracle protection, because the type does the
/// rest.** [`AuthError`] has two variants and fixed messages, so two
/// `Rejected`s are identical by construction — expired, unknown signer and
/// wrong audience cannot be told apart even by an implementation that wants to
/// help. What an implementation *can* still do is answer `Missing` for a
/// credential it looked at and refused, and that single bit is the one a
/// prober reads: it separates *this token was the right shape* from *there was
/// nothing here*.
///
/// The legitimate `Missing` is the other direction — a scheme this server does
/// not speak, or no header at all. Neither says which credentials exist.
async fn a_presented_credential_is_rejected_not_missing(
    auth: &dyn Authenticator,
    requests: &Requests,
    r: &mut Report,
) {
    const RULE: &str = "a presented credential is rejected, not missing";
    for (what, headers) in &requests.rejected {
        r.checked += 1;
        let Some(answer) = ask(auth, headers, RULE, what, r).await else {
            continue;
        };
        match answer {
            Err(AuthError::Rejected) => {}
            Err(AuthError::Missing) => r.record(
                RULE,
                format!(
                    "`{what}` carries a credential this server speaks and was refused as \
                     `Missing` — that bit separates *the right shape* from *nothing at \
                     all*, which is what a prober is looking for"
                ),
            ),
            Ok(caller) => r.record(
                RULE,
                format!(
                    "`{what}` was accepted as `{}`, so this deployment's own example of \
                     a bad credential is one it admits",
                    caller.actor
                ),
            ),
        }
    }
}

/// An accepted request names the actor the deployment says it should.
///
/// The positive half, and it is why the refusals above mean anything: an
/// authenticator that refuses everything satisfies every check before this one.
async fn an_accepted_request_names_its_actor(
    auth: &dyn Authenticator,
    requests: &Requests,
    r: &mut Report,
) {
    const RULE: &str = "an accepted request names its actor";
    let Some((headers, principal)) = requests.accepted.as_ref() else {
        return;
    };
    r.checked += 1;
    let Some(answer) = ask(auth, headers, RULE, "the accepted request", r).await else {
        return;
    };
    match answer {
        Ok(Caller { actor, .. }) if &actor == principal => {}
        Ok(caller) => r.record(
            RULE,
            format!(
                "the accepted request named `{}` rather than `{principal}` — the \
                 actor is what every later authorization and every recorded act is \
                 attributed to",
                caller.actor
            ),
        ),
        Err(e) => r.record(
            RULE,
            format!(
                "the request this deployment supplied as accepted was refused ({e}), so \
                 the refusals above prove only that this authenticator refuses"
            ),
        ),
    }
}
