//! OAuth 2.0 token exchange (RFC 8693) against the deployment's issuer.
//!
//! The shipped [`TokenExchange`]: one `POST` per (audience, subject) to the
//! token endpoint, naming the run's owner as `subject_token`, the plane's own
//! credential at the issuer as `actor_token`, and the peer as `audience` — and,
//! where the deployment maps one, as the RFC 8707 `resource` URI.
//!
//! **The subject token is an assertion, not a token the subject presented.**
//! It is the owner's principal id under a token type the deployment names, and
//! the issuer accepts it on the strength of the actor's authentication: the
//! plane admitted the run, and the issuer trusts it to name the subjects it
//! admitted. A resumed run has no inbound token to present, so nothing else
//! would work a day later.
//!
//! **What comes back is opaque.** The answer names neither the audience nor
//! the subject, so the credential is minted for the pair that was asked for;
//! the issuer is trusted to have bound it as asked, and a self-describing
//! token the peer can read says so to the peer, not to this plane.
//!
//! The endpoint is configured by the deployment, so it is reached wherever it
//! resolves — an in-cluster issuer has no public address — but only over
//! HTTPS, with no ambient proxy and no redirect, and its answer is read
//! against a ceiling.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::Secret;

use super::credentials::{CredentialError, TokenExchange};
use super::{PeerCredential, PeerId};

/// The RFC 8693 grant type.
pub const TOKEN_EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// The token type of an OAuth 2.0 access token, which is what is requested
/// and, by default, what the actor token is said to be.
pub const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

/// Exchanges at the deployment's token endpoint.
pub struct TokenEndpoint {
    url: String,
    http: reqwest::Client,
    subject_token_type: String,
    actor_token: Secret,
    actor_token_type: String,
    /// The plane's client credentials at the issuer, when it requires them.
    client: Option<(String, Secret)>,
    /// The RFC 8707 resource URI each peer is reached at.
    resources: BTreeMap<PeerId, String>,
}

/// Never renders a secret.
impl std::fmt::Debug for TokenEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenEndpoint")
            .field("url", &self.url)
            .field("subject_token_type", &self.subject_token_type)
            .field("actor_token_type", &self.actor_token_type)
            .field("client", &self.client.as_ref().map(|(id, _)| id))
            .field("resources", &self.resources)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct Issued {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
}

#[derive(Deserialize)]
struct Refused {
    error: String,
}

impl TokenEndpoint {
    /// How long one exchange may take in total.
    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    /// Exchange at `url`, naming subjects under `subject_token_type` and
    /// presenting `actor_token` as the plane.
    ///
    /// # Errors
    ///
    /// If `url` is not an HTTPS URL, or an HTTP client cannot be built.
    pub fn new(
        url: impl Into<String>,
        subject_token_type: impl Into<String>,
        actor_token: impl Into<String>,
    ) -> Result<Self, CredentialError> {
        let url = url.into();
        let refused = |detail: String| CredentialError::Unavailable {
            audience: PeerId::new("token-endpoint"),
            detail,
        };
        let parsed = reqwest::Url::parse(&url)
            .map_err(|e| refused(format!("the token endpoint is not a URL: {e}")))?;
        let local = cfg!(feature = "testkit")
            && parsed
                .host_str()
                .is_some_and(|h| crate::netguard::is_loopback_name(&h.to_ascii_lowercase()));
        if parsed.scheme() != "https" && !local {
            return Err(refused(format!(
                "the token endpoint on '{}' is not https — the plane's own credential \
                 and the issued tokens must not cross the network in cleartext",
                parsed.host_str().unwrap_or("")
            )));
        }
        let http = crate::netguard::guarded_client(crate::netguard::Reach::Configured)
            .timeout(Self::TIMEOUT)
            .build()
            .map_err(|e| refused(format!("could not build an HTTP client: {e}")))?;
        Ok(Self {
            url,
            http,
            subject_token_type: subject_token_type.into(),
            actor_token: Secret::new(actor_token),
            actor_token_type: ACCESS_TOKEN_TYPE.to_owned(),
            client: None,
            resources: BTreeMap::new(),
        })
    }

    /// Say what the actor token is, when it is not an access token.
    #[must_use]
    pub fn actor_token_type(mut self, token_type: impl Into<String>) -> Self {
        self.actor_token_type = token_type.into();
        self
    }

    /// Authenticate the plane to the issuer as a client, with HTTP Basic.
    #[must_use]
    pub fn client(mut self, id: impl Into<String>, secret: impl Into<String>) -> Self {
        self.client = Some((id.into(), Secret::new(secret)));
        self
    }

    /// Name the resource URI `peer` is reached at, sent as RFC 8707
    /// `resource` beside the `audience`.
    #[must_use]
    pub fn resource(mut self, peer: PeerId, uri: impl Into<String>) -> Self {
        self.resources.insert(peer, uri.into());
        self
    }

    /// The form the exchange posts for `audience` and `subject`.
    fn form(&self, audience: &PeerId, subject: &str) -> String {
        let mut pairs = vec![
            ("grant_type", TOKEN_EXCHANGE_GRANT),
            ("subject_token", subject),
            ("subject_token_type", self.subject_token_type.as_str()),
            ("actor_token", self.actor_token.expose()),
            ("actor_token_type", self.actor_token_type.as_str()),
            ("requested_token_type", ACCESS_TOKEN_TYPE),
            ("audience", audience.0.as_str()),
        ];
        if let Some(resource) = self.resources.get(audience) {
            pairs.push(("resource", resource.as_str()));
        }
        pairs
            .into_iter()
            .map(|(k, v)| format!("{}={}", form_encode(k), form_encode(v)))
            .collect::<Vec<_>>()
            .join("&")
    }
}

/// `application/x-www-form-urlencoded`, one component.
fn form_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'*' => {
                out.push(char::from(byte));
            }
            b' ' => out.push('+'),
            other => {
                let _ = write!(out, "%{other:02X}");
            }
        }
    }
    out
}

#[async_trait]
impl TokenExchange for TokenEndpoint {
    async fn exchange(
        &self,
        audience: &PeerId,
        subject: &str,
    ) -> Result<PeerCredential, CredentialError> {
        let unavailable = |detail: String| CredentialError::Unavailable {
            audience: audience.clone(),
            detail,
        };
        let mut request = self
            .http
            .post(&self.url)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .header(reqwest::header::ACCEPT, "application/json")
            .body(self.form(audience, subject));
        if let Some((id, secret)) = &self.client {
            request = request.basic_auth(form_encode(id), Some(form_encode(secret.expose())));
        }
        let response = request
            .send()
            .await
            .map_err(|e| unavailable(crate::netguard::transport_text(&e)))?;
        let status = response.status();
        let body = crate::netguard::intake::read(response, crate::netguard::intake::METADATA)
            .await
            .map_err(|e| unavailable(e.to_string()))?;
        if !status.is_success() {
            // The OAuth error code only: a description is the issuer's prose,
            // and this sentence reaches a journaled failure.
            let code = serde_json::from_slice::<Refused>(&body)
                .map_or_else(|_| "no error code".to_owned(), |r| r.error);
            let detail = format!("the token endpoint answered {status} ({code})");
            // A 4xx other than a timeout or a rate limit is the issuer's
            // answer about this request, which no retry changes.
            let answered = status.is_client_error()
                && status != reqwest::StatusCode::REQUEST_TIMEOUT
                && status != reqwest::StatusCode::TOO_MANY_REQUESTS;
            return Err(if answered {
                CredentialError::Refused {
                    audience: audience.clone(),
                    detail,
                }
            } else {
                unavailable(detail)
            });
        }
        let issued: Issued = serde_json::from_slice(&body)
            .map_err(|e| unavailable(format!("the token endpoint's answer is not a token: {e}")))?;
        let mut credential =
            PeerCredential::for_subject(audience.clone(), subject, issued.access_token);
        if let Some(seconds) = issued.expires_in {
            let lifetime = time::Duration::seconds(i64::try_from(seconds).unwrap_or(i64::MAX));
            if let Some(at) = super::credentials::now().checked_add(lifetime) {
                credential = credential.expiring_at(at);
            }
        }
        Ok(credential)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_form_names_the_owner_the_actor_and_the_peer() {
        let endpoint = TokenEndpoint::new(
            "https://issuer.example/token",
            "urn:example:principal",
            "plane secret",
        )
        .expect("an https endpoint")
        .resource(PeerId::new("reviewer"), "https://reviewer.example/a2a");
        let form = endpoint.form(&PeerId::new("reviewer"), "user:alice");
        for pair in [
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange",
            "subject_token=user%3Aalice",
            "subject_token_type=urn%3Aexample%3Aprincipal",
            "actor_token=plane+secret",
            "actor_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token",
            "audience=reviewer",
            "resource=https%3A%2F%2Freviewer.example%2Fa2a",
        ] {
            assert!(
                form.split('&').any(|p| p == pair),
                "the exchange did not post {pair}: {form}"
            );
        }
    }

    #[test]
    fn a_plaintext_token_endpoint_is_refused() {
        let err =
            TokenEndpoint::new("http://issuer.example/token", "t", "a").expect_err("plaintext");
        assert!(err.to_string().contains("not https"), "{err}");
    }
}
