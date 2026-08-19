//! A key ring that is somebody else: `HashiCorp` Vault's transit engine.
//!
//! [`MemoryKeyRing`](crate::testkit::MemoryKeyRing) proves the semantics and
//! protects nothing, because a key ring in the same process as the data is a
//! key ring an attacker already has. This is the one that earns the guarantee:
//! the wrapping key is created inside Vault and never leaves it, so destroying
//! it is something this crate can *ask for* and cannot undo.
//!
//! Transit is chosen over an SDK-shaped service for the same reason the SSE
//! parser is hand-rolled: it is four HTTP calls against a documented, stable
//! API, and a dependency tree to express that is a poor trade for a crate whose
//! argument is a small auditable substrate.
//!
//! # The mapping
//!
//! | This crate | Transit |
//! |---|---|
//! | erasure scope | a named key, `transit/keys/<scope>` |
//! | mint a data key | `POST transit/datakey/plaintext/<scope>` |
//! | open a data key | `POST transit/decrypt/<scope>` |
//! | erase | `DELETE transit/keys/<scope>` |
//!
//! Three endpoints Vault offers are deliberately not in that table.
//! `transit/keys/<scope>/rotate` is the operator's decision — on their
//! schedule, under their audit, with their approvals — and a runtime that
//! rotated somebody's key ring because it happened to be running would be
//! taking a decision that is not its own. `transit/rewrap` and
//! `transit/keys/<scope>/config` follow from the rule stated in the [module
//! documentation](crate::keyring): sealed bytes are rotation-immutable, so
//! there is nothing to rewrap, and the version floor that would make rewrapping
//! necessary is the one setting this crate must never move on an operator's
//! behalf.
//!
//! What this crate owns instead is *telling the operator when they have moved
//! it too far*. Raising `min_decryption_version` past a version a live envelope
//! names makes un-erased history unreadable, and Vault reports that with the
//! same 400 it uses for "you may not do that". Mapping it to
//! [`KeyError::Retired`] is what keeps a reversible configuration change from
//! reaching a report as data loss.
//!
//! # Erasure needs to be switched on
//!
//! A transit key cannot be deleted unless it was configured to allow it. That
//! is Vault protecting operators from themselves, and it means an erasure
//! request will fail against a default key — loudly, here, rather than silently
//! reporting success. Configure the scope's key with `deletion_allowed=true`
//! before promising anyone that erasure works:
//!
//! ```text
//! vault write transit/keys/<scope>/config deletion_allowed=true
//! ```
//!
//! [Transit HTTP API]: https://developer.hashicorp.com/vault/api-docs/secret/transit

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{Secret, Timestamp};

use super::{DataKey, KeyError, KeyRing, WrappedKey};

/// Vault's transit engine, reached over HTTP.
///
/// `Debug` derives safely because the only credential — the Vault token — is a
/// [`Secret`], which redacts itself and zeroizes on drop. A bare `String` here
/// would print verbatim, and `VaultTransit` is reachable through the derived
/// `Debug` of `Runtime`, `StepCtx` and `RuntimeBuilder`, so one `tracing::debug!`
/// would put the token in a log — the exact hole every other credential holder
/// in this crate hand-redacts against.
#[derive(Debug, Clone)]
pub struct VaultTransit {
    http: reqwest::Client,
    /// Base address, e.g. `https://vault.internal:8200`.
    address: String,
    /// Mount path of the transit engine, usually `transit`.
    mount: String,
    token: Secret,
}

#[derive(Deserialize)]
struct DataKeyReply {
    data: DataKeyData,
}

#[derive(Deserialize)]
struct DataKeyData {
    /// Base64, and the only thing in this exchange that must not be logged.
    plaintext: String,
    ciphertext: String,
}

#[derive(Deserialize)]
struct PlaintextReply {
    data: PlaintextData,
}

#[derive(Deserialize)]
struct PlaintextData {
    plaintext: String,
}

impl VaultTransit {
    /// Point at a Vault, with a token that may use the transit mount.
    ///
    /// # Errors
    ///
    /// If an HTTP client cannot be built.
    pub fn new(
        address: impl Into<String>,
        mount: impl Into<String>,
        token: impl Into<String>,
    ) -> Result<Self, KeyError> {
        // Bounded, like every other outbound call here. Sealing and opening go
        // through this client, so an unbounded one lets a key service that
        // stops answering hold every write that touches a sealed payload —
        // which with a keyring configured is most of them.
        let http = reqwest::Client::builder()
            .timeout(Self::TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| KeyError::Unavailable(format!("could not build an HTTP client: {e}")))?;
        Ok(Self {
            http,
            address: address.into().trim_end_matches('/').to_owned(),
            mount: mount.into().trim_matches('/').to_owned(),
            token: Secret::new(token),
        })
    }

    /// How long one key operation may take in total.
    ///
    /// Ten seconds: a transit wrap or unwrap is a small symmetric operation,
    /// and a service that cannot answer in that time is unavailable — which
    /// [`KeyError::Unavailable`] already says, and which a caller may retry.
    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    fn url(&self, tail: &str) -> String {
        format!("{}/v1/{}/{tail}", self.address, self.mount)
    }

    /// One request, with the status codes that mean something mapped.
    async fn call(
        &self,
        method: reqwest::Method,
        url: &str,
        body: Option<serde_json::Value>,
        scope: &str,
    ) -> Result<String, KeyError> {
        let mut req = self
            .http
            .request(method, url)
            .header("X-Vault-Token", self.token.expose());
        if let Some(b) = body {
            req = req.json(&b);
        }
        let response = req
            .send()
            .await
            .map_err(|e| KeyError::Unavailable(format!("{url}: {e}")))?;

        let status = response.status().as_u16();
        let text = response
            .text()
            .await
            .map_err(|e| KeyError::Unavailable(format!("{url}: reading the reply: {e}")))?;

        let reason = || first_error(&text).unwrap_or_else(|| text.trim().to_owned());
        match status {
            200 | 204 => Ok(text),
            // A missing key is the completed erasure, and Vault reports it as a
            // **400 with a message** rather than a 404 — which cost three
            // conformance failures to discover, because nothing but a real Vault
            // says so.
            //
            // Matching on that message is exactly the stringly-typed control
            // flow this codebase avoids, and there is no alternative here: the
            // status code does not distinguish "the key is gone" from "you may
            // not do that", and those are opposite answers. The match is kept
            // narrow for that reason — a false positive would report live data
            // as erased.
            //
            // Vault cannot say *when* or *why* it went; it keeps no tombstone.
            // The caller's own erasure record is the authority on that, so this
            // reports the fact rather than inventing a date.
            400 | 404 if is_missing_key(&reason()) => Err(KeyError::Destroyed {
                scope: scope.to_owned(),
                at: Timestamp::UNIX_EPOCH,
                reason: "the wrapping key no longer exists in Vault".to_owned(),
            }),
            // A refusal that retrying cannot fix: no permission, or a key whose
            // configuration forbids what was asked.
            400 | 403 | 404 => Err(KeyError::Refused(format!("{url}: {}", reason()))),
            // Sealed, standby, or over quota — all of which come back.
            412 | 429 | 500..=599 => Err(KeyError::Unavailable(format!(
                "{url}: status {status}: {}",
                text.trim()
            ))),
            other => Err(KeyError::Unavailable(format!(
                "{url}: unexpected status {other}: {}",
                text.trim()
            ))),
        }
    }
}

/// Whether a Vault refusal means the key is gone rather than forbidden.
///
/// Deliberately narrow. Vault phrases it differently per endpoint — `decrypt`
/// and `datakey` say *encryption key not found*, `DELETE keys/…` says *could
/// not delete key; not found* — and both are the same fact. Anything broader
/// risks reporting live data as erased, which is the one direction this must
/// not get wrong.
fn is_missing_key(reason: &str) -> bool {
    let r = reason.to_ascii_lowercase();
    r.contains("encryption key not found") || r.contains("could not delete key; not found")
}

/// Reclassify a decrypt refusal that is really a retired key version.
///
/// Applied at [`KeyRing::open`] rather than inside `call`, because this is the
/// one place the wrapped key's version is in hand, and a [`KeyError::Retired`]
/// that could not name the version would tell an operator a floor is too high
/// without saying what it must admit.
///
/// Narrow for the same reason [`is_missing_key`] is: Vault answers a retired
/// version with the same 400 it uses for a permission failure, and reading a
/// genuine refusal as a retirement would tell somebody to lower a floor that
/// was never the problem. What this does NOT cover is a key service that
/// phrases the condition differently — every implementation of [`KeyRing`] owes
/// its own mapping, and one that skips it degrades to [`KeyError::Refused`],
/// which is wrong in the safe direction: an operator investigates rather than
/// being told a reversible setting is unrecoverable loss.
fn as_retired(e: KeyError, scope: &str, key_id: &str) -> KeyError {
    let retired = match &e {
        KeyError::Refused(reason) => {
            let r = reason.to_ascii_lowercase();
            r.contains("ciphertext or signature version is disallowed by policy")
                || r.contains("ciphertext version is disallowed by policy")
        }
        _ => false,
    };
    if retired {
        KeyError::Retired {
            scope: scope.to_owned(),
            key_id: key_id.to_owned(),
        }
    } else {
        e
    }
}

/// Vault reports problems as `{"errors": ["..."]}`.
fn first_error(body: &str) -> Option<String> {
    #[derive(Deserialize)]
    struct Errors {
        errors: Vec<String>,
    }
    serde_json::from_str::<Errors>(body)
        .ok()?
        .errors
        .into_iter()
        .next()
}

/// RFC 4648 §4, which is what Vault speaks for key material.
fn unb64(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => u32::from(c - b'A'),
            b'a'..=b'z' => u32::from(c - b'a') + 26,
            b'0'..=b'9' => u32::from(c - b'0') + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        })
    };
    let raw: Vec<u8> = s.bytes().filter(|b| *b != b'=').collect();
    let mut out = Vec::with_capacity(raw.len() * 3 / 4);
    for chunk in raw.chunks(4) {
        let mut n = 0u32;
        for (i, c) in chunk.iter().enumerate() {
            n |= val(*c)? << (18 - 6 * i);
        }
        for i in 0..chunk.len() * 6 / 8 {
            out.push(((n >> (16 - 8 * i)) & 0xff) as u8);
        }
    }
    Some(out)
}

fn to_key(b64: &str, what: &str) -> Result<DataKey, KeyError> {
    let raw = unb64(b64).ok_or_else(|| KeyError::Refused(format!("{what} is not valid base64")))?;
    let bytes: [u8; 32] = raw.try_into().map_err(|_| {
        KeyError::Refused(format!(
            "{what} is not 32 bytes — ask transit for a 256-bit key"
        ))
    })?;
    Ok(DataKey::new(bytes))
}

#[async_trait]
impl KeyRing for VaultTransit {
    async fn data_key(&self, scope: &str) -> Result<(DataKey, WrappedKey), KeyError> {
        let url = self.url(&format!("datakey/plaintext/{scope}"));
        let body = self
            .call(
                reqwest::Method::POST,
                &url,
                Some(serde_json::json!({})),
                scope,
            )
            .await?;
        let reply: DataKeyReply = serde_json::from_str(&body)
            .map_err(|e| KeyError::Refused(format!("{url}: unreadable reply: {e}")))?;

        Ok((
            to_key(&reply.data.plaintext, "the data key transit returned")?,
            WrappedKey {
                scope: scope.to_owned(),
                // `vault:v1:…` — the version is in the ciphertext itself, which
                // is how transit knows what to decrypt with after a rotation.
                wrapped_by: reply
                    .data
                    .ciphertext
                    .split(':')
                    .take(2)
                    .collect::<Vec<_>>()
                    .join(":"),
                sealed: reply.data.ciphertext.into_bytes(),
            },
        ))
    }

    async fn open(&self, wrapped: &WrappedKey) -> Result<DataKey, KeyError> {
        let ciphertext = String::from_utf8(wrapped.sealed.clone())
            .map_err(|_| KeyError::Refused("a transit ciphertext must be text".to_owned()))?;
        let url = self.url(&format!("decrypt/{}", wrapped.scope));
        let body = self
            .call(
                reqwest::Method::POST,
                &url,
                Some(serde_json::json!({ "ciphertext": ciphertext })),
                &wrapped.scope,
            )
            .await
            .map_err(|e| as_retired(e, &wrapped.scope, &wrapped.wrapped_by))?;
        let reply: PlaintextReply = serde_json::from_str(&body)
            .map_err(|e| KeyError::Refused(format!("{url}: unreadable reply: {e}")))?;
        to_key(&reply.data.plaintext, "the data key transit returned")
    }

    async fn destroy(&self, scope: &str, _at: Timestamp, _reason: &str) -> Result<(), KeyError> {
        // Deleting the *key*, which is what makes every data key ever wrapped
        // under it unopenable. Vault refuses unless the key was configured with
        // `deletion_allowed=true`, and that refusal is surfaced rather than
        // swallowed: an erasure that quietly did not happen is worse than one
        // that failed.
        let url = self.url(&format!("keys/{scope}"));
        match self.call(reqwest::Method::DELETE, &url, None, scope).await {
            // `Destroyed` here means the key was already gone, and erasure is
            // idempotent: the caller's own record is the authority on when it
            // happened, so a second request succeeds rather than reporting a
            // failure for work that is done.
            Ok(_) | Err(KeyError::Destroyed { .. }) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A retired ciphertext version is reclassified; a real refusal is not.
    ///
    /// Both directions matter and they fail in opposite ways. Left as a bare
    /// `Refused`, an operator's reversible version floor reaches a drill as
    /// *neither opens nor was erased* — loss or tampering — and somebody hunts
    /// a fault that does not exist. Applied too broadly, a genuine permission
    /// failure would tell them to lower a floor that was never the problem,
    /// and the real refusal would go uninvestigated.
    #[test]
    fn a_retired_ciphertext_version_is_told_apart_from_a_refusal() {
        let refused = |m: &str| KeyError::Refused(m.to_owned());

        // Vault's wording for a ciphertext below `min_decryption_version`.
        match as_retired(
            refused("ciphertext or signature version is disallowed by policy (too old)"),
            "acme/case-1",
            "vault:v1",
        ) {
            KeyError::Retired { scope, key_id } => {
                assert_eq!(scope, "acme/case-1");
                assert_eq!(
                    key_id, "vault:v1",
                    "the error must name the version the floor has to readmit"
                );
            }
            other => panic!(
                "a retired version stayed a bare refusal ({other:?}), so a one-setting \
                 configuration change reaches an operator as unrecoverable data loss"
            ),
        }

        assert!(
            matches!(
                as_retired(refused("permission denied"), "acme/case-1", "vault:v1"),
                KeyError::Refused(_)
            ),
            "a permission failure was read as a retired key version, which sends an \
             operator to lower a floor that was never the problem and leaves the real \
             refusal uninvestigated"
        );

        assert!(
            matches!(
                as_retired(
                    KeyError::Unavailable("vault is sealed".to_owned()),
                    "acme/case-1",
                    "vault:v1"
                ),
                KeyError::Unavailable(_)
            ),
            "an outage was reclassified as a retired version, turning something that \
             comes back on its own into a configuration investigation"
        );
    }

    /// Base64 for key material, checked where the alphabets differ.
    ///
    /// `foobar`-style vectors never reach indices 62 and 63, so they pass
    /// identically under base64 and base64url — and transit speaks the former.
    /// A decoder that quietly accepted `-_` would produce the wrong key bytes
    /// from a well-formed reply.
    #[test]
    fn the_base64_decoder_reaches_the_bytes_that_differ() {
        assert_eq!(unb64("+/8=").expect("decodes"), vec![0xFB, 0xFF]);
        assert!(
            unb64("-_8=").is_none(),
            "the URL-safe alphabet was accepted, so a key would decode to the \
             wrong bytes without anything reporting it"
        );
    }

    /// A 32-byte key is required, and a shorter one is refused rather than padded.
    #[test]
    fn a_key_that_is_not_256_bits_is_refused() {
        // "AAAA" decodes to three bytes.
        let err = to_key("AAAA", "a test key").expect_err("must refuse");
        assert!(
            matches!(err, KeyError::Refused(ref m) if m.contains("32 bytes")),
            "wrong refusal: {err}"
        );
        let full = "A".repeat(43) + "=";
        assert!(
            to_key(&full, "a test key").is_ok(),
            "a 32-byte key was refused"
        );
    }

    /// Vault reports problems in a body, and the first one is the useful one.
    #[test]
    fn a_vault_error_body_is_read_rather_than_dumped() {
        let body =
            r#"{"errors":["1 error occurred:\n\t* deletion is not allowed for this key\n\n"]}"#;
        let first = first_error(body).expect("an error");
        assert!(
            first.contains("deletion is not allowed"),
            "the operator-facing reason was lost: {first}"
        );
        assert!(
            first_error("not json at all").is_none(),
            "a non-JSON body must fall through to the raw text rather than \
             producing a confident empty reason"
        );
    }

    /// The transit ciphertext carries its own key version.
    ///
    /// `vault:v1:…` is what lets Vault decrypt after a rotation without being
    /// told which version to use — so the version is recorded as the wrapping
    /// key id rather than invented here.
    #[test]
    fn the_wrapping_key_id_is_the_transit_key_version() {
        let ct = "vault:v3:abcdefGHIJ==";
        let id: String = ct.split(':').take(2).collect::<Vec<_>>().join(":");
        assert_eq!(id, "vault:v3");
    }
}
