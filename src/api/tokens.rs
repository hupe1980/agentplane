//! Bearer tokens mapped to callers, from a file the operator writes.
//!
//! # Why this ships at all
//!
//! [`Authenticator`] is a seam, and the crate deliberately
//! shipped no implementation of it: authentication is a deployment's own
//! decision, and a runtime with an opinion about it is a runtime fighting
//! whatever the deployment already has.
//!
//! That held right up until the A2A server needed to be startable **without
//! writing Rust**. `agentplane serve` cannot ask its operator to implement a
//! trait — the whole premise of the declarative tier is that there is no Rust —
//! so the binary has to carry one authenticator, and the choice is between
//! shipping a real one and shipping none, which would mean the A2A 1.0 server
//! that passes the protocol project's own conformance kit can only be reached
//! by people who write Rust.
//!
//! # What it is, stated narrowly
//!
//! A **shared-secret lookup**. A token in the file names an actor, its roles and
//! its tenant; a request presenting that token is that caller. It is not a JWT
//! verifier, not OIDC, and it does not expire anything. Those belong in a
//! deployment's own `Authenticator`, which remains the supported path and is one
//! trait away.
//!
//! What it is *not* is the thing that grants authority. A caller's roles are an
//! input to the policy engine, which is what decides. An authenticator that
//! named every caller `admin` would still be refused by a policy that permits
//! nothing — which is why `serve` requires a policy file and has no permissive
//! default.
//!
//! # The properties that are not negotiable
//!
//! * **Constant-time comparison.** Tokens live in [`Secret`], whose `PartialEq`
//!   does not short-circuit on content. A `==` against a `String` leaks the
//!   matched prefix through timing, and this is the one code path in the crate
//!   where an attacker controls one side and can measure the answer.
//! * **No anonymous fallback.** An unparseable, missing or unknown credential is
//!   [`AuthError`], never a default caller. `Caller`'s own documentation makes
//!   the point: an approval with no name attached is not an approval.
//! * **An empty file is refused at load.** A token file that parsed to zero
//!   callers would start a server nobody can reach, which reads as a
//!   configuration problem long after it reads as an outage.
//! * **Duplicate tokens are refused at load.** Two entries sharing a token means
//!   one of them silently never applies, and which one depends on file order.

use std::collections::HashSet;

use axum::http::HeaderMap;

use super::{AuthError, Authenticator, Caller};
use crate::core::{Secret, TenantId};

/// Bearer tokens, each naming exactly one caller.
#[derive(Debug)]
pub struct TokenAuthenticator {
    entries: Vec<(Secret, Caller)>,
}

/// Why a token file was refused.
///
/// Every variant is a refusal to start. A server that came up with a token file
/// it could not fully honour would be answering requests under an authorization
/// model its operator did not write.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TokenFileError {
    #[error("the token file is not valid YAML: {0}")]
    Syntax(String),

    #[error(
        "the token file lists no callers — a server with no accepted credential \
         accepts nobody, which is an outage that reads like a configuration"
    )]
    Empty,

    #[error(
        "entry {index} has an empty token; a blank credential would be presented \
         by anyone who presented none"
    )]
    BlankToken { index: usize },

    #[error(
        "entry {index} has no actor; a decision recorded against an unnamed \
         caller is not a decision anybody can answer for"
    )]
    BlankActor { index: usize },

    #[error(
        "two entries share one token, so one of them silently never applies and \
         which depends on the order of the file"
    )]
    DuplicateToken,

    #[error("entry {index} names an invalid tenant: {detail}")]
    Tenant { index: usize, detail: String },
}

impl TokenAuthenticator {
    /// Build from parsed entries.
    ///
    /// # Errors
    ///
    /// [`TokenFileError`] if the set is empty, or an entry is unusable.
    pub fn new(entries: Vec<TokenEntry>) -> Result<Self, TokenFileError> {
        if entries.is_empty() {
            return Err(TokenFileError::Empty);
        }
        let mut seen: HashSet<String> = HashSet::new();
        let mut built = Vec::with_capacity(entries.len());
        for (index, entry) in entries.into_iter().enumerate() {
            if entry.token.trim().is_empty() {
                return Err(TokenFileError::BlankToken { index });
            }
            if entry.actor.trim().is_empty() {
                return Err(TokenFileError::BlankActor { index });
            }
            if !seen.insert(entry.token.clone()) {
                return Err(TokenFileError::DuplicateToken);
            }
            let mut caller = Caller::new(entry.actor, entry.roles);
            if let Some(tenant) = entry.tenant {
                let tenant = TenantId::new(tenant).map_err(|e| TokenFileError::Tenant {
                    index,
                    detail: e.to_string(),
                })?;
                caller = caller.in_tenant(tenant);
            }
            built.push((Secret::new(entry.token), caller));
        }
        Ok(Self { entries: built })
    }

    /// Read a token file.
    ///
    /// ```yaml
    /// - token: "a-long-random-string"
    ///   actor: peer-a
    ///   roles: [peer]
    ///   tenant: acme        # optional; the default tenant when absent
    /// ```
    ///
    /// # Errors
    ///
    /// [`TokenFileError`] if the document does not parse, or does not describe a
    /// usable set of callers.
    #[cfg(feature = "manifest")]
    pub fn from_yaml(source: &str) -> Result<Self, TokenFileError> {
        let entries: Vec<TokenEntry> =
            serde_yaml_ng::from_str(source).map_err(|e| TokenFileError::Syntax(e.to_string()))?;
        Self::new(entries)
    }
}

/// One line of a token file.
#[derive(Debug, Clone, serde::Deserialize)]
// An unknown field is refused for the same reason a manifest refuses one: a
// misspelled `tenant:` in a permissive parser silently serves the default
// tenant's data to a caller the operator meant to confine.
#[serde(deny_unknown_fields)]
pub struct TokenEntry {
    /// The bearer token presented in `Authorization: Bearer …`.
    pub token: String,
    /// The identity decisions are recorded under.
    pub actor: String,
    /// What this caller is eligible for. An input to policy, never a grant.
    #[serde(default)]
    pub roles: Vec<String>,
    /// Whose data this caller may reach. The default tenant when absent.
    #[serde(default)]
    pub tenant: Option<String>,
}

#[async_trait::async_trait]
impl Authenticator for TokenAuthenticator {
    async fn authenticate(&self, headers: &HeaderMap) -> Result<Caller, AuthError> {
        let raw = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(AuthError::Missing)?;
        // The scheme is matched case-insensitively because RFC 9110 §11.1
        // defines it that way, and the failure of getting this wrong is the
        // worst-shaped one an authenticator has: `bearer <token>` is a legal
        // request that would be answered `Missing`, which reads to its sender
        // as *you sent no credential*. The token itself keeps its exact bytes
        // and its constant-time comparison — only the scheme name is
        // case-folded, and only its first seven characters are examined.
        let (scheme, token) = raw.split_once(' ').ok_or(AuthError::Missing)?;
        if !scheme.eq_ignore_ascii_case("Bearer") {
            return Err(AuthError::Missing);
        }
        let presented = Secret::new(token);

        // Every entry is compared, and the loop does not break on a match.
        // Returning as soon as one matched would make the answer's *timing* a
        // function of the token's position in the file, which leaks how early a
        // guessed token sits — the same class of leak the constant-time
        // comparison inside `Secret` exists to close, reintroduced one level up.
        let mut found: Option<&Caller> = None;
        for (token, caller) in &self.entries {
            if *token == presented {
                found = Some(caller);
            }
        }
        found.cloned().ok_or(AuthError::Rejected)
    }
}

#[cfg(all(test, feature = "manifest"))]
mod scheme_tests {
    use super::*;

    fn ring() -> TokenAuthenticator {
        TokenAuthenticator::from_yaml(
            "- token: a-long-random-string\n  actor: peer-a\n  roles: [peer]\n",
        )
        .expect("one caller")
    }

    fn presenting(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            value.parse().expect("a header value"),
        );
        headers
    }

    /// **The scheme name is case-insensitive; the token is not.**
    ///
    /// RFC 9110 §11.1 defines the auth-scheme as case-insensitive, and the
    /// failure of reading it otherwise is the worst shape an authenticator
    /// has: `bearer <token>` is a legal request, and refusing it as `Missing`
    /// tells a conforming client it sent no credential at all — so the client
    /// retries the thing it already did.
    ///
    /// The second half is what keeps the first from being a weakening: the
    /// token's own bytes are still compared exactly, so case-folding the
    /// scheme cannot fold anything a caller had to guess.
    #[tokio::test]
    async fn the_scheme_is_case_insensitive_and_the_token_is_not() {
        let auth = ring();
        for spelling in ["Bearer", "bearer", "BEARER", "BeArEr"] {
            let caller = auth
                .authenticate(&presenting(&format!("{spelling} a-long-random-string")))
                .await
                .unwrap_or_else(|e| panic!("'{spelling}' is a legal auth-scheme spelling: {e}"));
            assert_eq!(caller.actor, "peer-a");
        }
        assert!(
            matches!(
                auth.authenticate(&presenting("Bearer A-LONG-RANDOM-STRING"))
                    .await,
                Err(AuthError::Rejected)
            ),
            "the token was matched case-insensitively, which silently shrinks \
             the space an attacker has to search"
        );
    }

    /// Anything that is not a bearer credential is absent, never a default
    /// caller — the property the module refuses to trade.
    #[tokio::test]
    async fn a_credential_that_is_not_a_bearer_token_names_nobody() {
        let auth = ring();
        for raw in [
            "Basic a-long-random-string",
            "Bearer",
            "a-long-random-string",
            "",
        ] {
            assert!(
                matches!(
                    auth.authenticate(&presenting(raw)).await,
                    Err(AuthError::Missing)
                ),
                "'{raw}' was read as a presented bearer credential"
            );
        }
    }
}
