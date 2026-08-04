//! Governed remote-media ingestion.
//!
//! A model-provider URL is an egress bypass: the provider, not this plane,
//! resolves and fetches it. This module makes dereferencing explicit and
//! replayable. A fetch is bound to the exact labelled URL, resolves every hop,
//! refuses any non-public answer, pins the checked addresses into the HTTP
//! client, validates each redirect, streams under a hard byte ceiling, refuses
//! content coding and ungranted media types, runs operator validators, and
//! stores only a content digest in the journal.
//!
//! The policy is deny-by-default. There is no wildcard host grant, no system
//! proxy, no cookie jar, no automatic redirect, no ambient credential, and no
//! switch that accepts private addresses. Network segmentation remains useful
//! defence in depth; application checks are not a firewall.

use std::collections::{BTreeSet, HashSet};
use std::fmt::Debug;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use futures_util::StreamExt;
use reqwest::header::{
    ACCEPT, ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, LOCATION,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::blob::BlobStore;
use crate::core::{
    CaseId, Digest, Effect, EffectDescriptor, EffectError, ProtectedField, Recovery, RetryPolicy,
    Sensitivity, Timestamp, Trust,
};

const DEFAULT_MAX_BYTES: usize = 10 * 1024 * 1024;
const DEFAULT_MAX_HEADER_BYTES: usize = 64 * 1024;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_URL_BYTES: usize = 8_192;

/// The complete, digest-covered policy for one media fetch.
///
/// Hosts and media types are exact allowlists. Defaults permit no destination
/// and no representation, so merely enabling the feature grants nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaPolicy {
    hosts: BTreeSet<String>,
    ports: BTreeSet<u16>,
    media_types: BTreeSet<String>,
    allow_http: bool,
    allow_query: bool,
    max_redirects: u8,
    max_bytes: usize,
    max_header_bytes: usize,
    timeout: Duration,
    retry: RetryPolicy,
    retention: MediaRetention,
    max_url_sensitivity: Sensitivity,
    output_sensitivity: Sensitivity,
}

impl Default for MediaPolicy {
    fn default() -> Self {
        Self {
            hosts: BTreeSet::new(),
            ports: BTreeSet::from([443]),
            media_types: BTreeSet::new(),
            allow_http: false,
            allow_query: false,
            max_redirects: 3,
            max_bytes: DEFAULT_MAX_BYTES,
            max_header_bytes: DEFAULT_MAX_HEADER_BYTES,
            timeout: DEFAULT_TIMEOUT,
            retry: RetryPolicy::never(),
            retention: MediaRetention::CaseLinked,
            max_url_sensitivity: Sensitivity::Public,
            output_sensitivity: Sensitivity::Public,
        }
    }
}

impl MediaPolicy {
    /// A policy that permits nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Permit one exact host. Wildcards and suffix grants are rejected.
    #[must_use]
    pub fn allow_host(mut self, host: impl AsRef<str>) -> Self {
        let host = normalize_host(host.as_ref());
        assert!(
            !host.is_empty() && !host.contains('*'),
            "media host grants must be non-empty exact hosts"
        );
        self.hosts.insert(host);
        self
    }

    /// Permit one exact response media type, without parameters.
    #[must_use]
    pub fn allow_media_type(mut self, media_type: impl AsRef<str>) -> Self {
        let media_type = normalize_media_type(media_type.as_ref());
        assert!(
            media_type.contains('/') && !media_type.contains('*'),
            "media type grants must be exact type/subtype values"
        );
        self.media_types.insert(media_type);
        self
    }

    /// Permit a destination port. HTTPS 443 is the only default.
    #[must_use]
    pub fn allow_port(mut self, port: u16) -> Self {
        assert_ne!(port, 0, "port zero is not a remote-media destination");
        self.ports.insert(port);
        self
    }

    /// Permit cleartext HTTP as well as HTTPS.
    ///
    /// This is intentionally conspicuous. It does not relax address, host,
    /// redirect, content, or size checks, but it does give up transport
    /// confidentiality and origin authentication.
    #[must_use]
    pub const fn allow_http(mut self) -> Self {
        self.allow_http = true;
        self
    }

    /// Permit URL query strings.
    ///
    /// The exact URL is journaled as effect identity, so signed URLs, bearer
    /// tokens, and personal identifiers must not be passed here. This grant is
    /// for public selectors such as immutable version or transform parameters.
    #[must_use]
    pub const fn allow_query(mut self) -> Self {
        self.allow_query = true;
        self
    }

    #[must_use]
    pub const fn max_redirects(mut self, redirects: u8) -> Self {
        self.max_redirects = redirects;
        self
    }

    #[must_use]
    pub const fn max_bytes(mut self, bytes: usize) -> Self {
        assert!(bytes > 0, "a media byte ceiling must be positive");
        self.max_bytes = bytes;
        self
    }

    #[must_use]
    pub const fn max_header_bytes(mut self, bytes: usize) -> Self {
        assert!(bytes > 0, "a media header ceiling must be positive");
        self.max_header_bytes = bytes;
        self
    }

    #[must_use]
    pub const fn timeout(mut self, timeout: Duration) -> Self {
        assert!(!timeout.is_zero(), "a media timeout must be positive");
        self.timeout = timeout;
        self
    }

    /// Set an explicit journaled retry policy. No repeat is the default.
    #[must_use]
    pub const fn retry(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    /// Name the retention regime for fetched bytes.
    ///
    /// The default requires a case so erasure can traverse from the business
    /// subject to the digest. An external regime is explicit and carries the
    /// policy identifier in the effect and output records.
    #[must_use]
    pub fn external_retention(mut self, policy: impl Into<String>) -> Self {
        let policy = policy.into();
        assert!(
            !policy.trim().is_empty(),
            "an external media retention policy must have an identity"
        );
        self.retention = MediaRetention::External { policy };
        self
    }

    /// Highest classification allowed on the URL itself.
    ///
    /// URLs are effect arguments and therefore journaled. Public is the safe
    /// default; credentials and personal data do not belong in a URL.
    #[must_use]
    pub const fn max_url_sensitivity(mut self, sensitivity: Sensitivity) -> Self {
        self.max_url_sensitivity = sensitivity;
        self
    }

    /// Classification assigned to the fetched artifact.
    #[must_use]
    pub const fn output_sensitivity(mut self, sensitivity: Sensitivity) -> Self {
        self.output_sensitivity = sensitivity;
        self
    }

    fn snapshot(&self) -> Value {
        json!({
            "hosts": self.hosts,
            "ports": self.ports,
            "media_types": self.media_types,
            "allow_http": self.allow_http,
            "allow_query": self.allow_query,
            "max_redirects": self.max_redirects,
            "max_bytes": self.max_bytes,
            "max_header_bytes": self.max_header_bytes,
            "timeout_ms": self.timeout.as_millis(),
            "retry": self.retry,
            "retention": self.retention,
            "max_url_sensitivity": self.max_url_sensitivity,
            "output_sensitivity": self.output_sensitivity,
        })
    }

    fn validate_url(&self, raw: &str) -> Result<reqwest::Url, MediaError> {
        if raw.len() > MAX_URL_BYTES {
            return Err(MediaError::Refused(format!(
                "media URL is {} bytes; limit is {MAX_URL_BYTES}",
                raw.len()
            )));
        }
        let url = reqwest::Url::parse(raw)
            .map_err(|error| MediaError::Refused(format!("invalid media URL: {error}")))?;
        match url.scheme() {
            "https" => {}
            "http" if self.allow_http => {}
            scheme => {
                return Err(MediaError::Refused(format!(
                    "media URL scheme '{scheme}' is not permitted"
                )));
            }
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(MediaError::Refused(
                "userinfo is forbidden in media URLs".to_owned(),
            ));
        }
        if url.fragment().is_some() {
            return Err(MediaError::Refused(
                "fragments are forbidden in media URLs".to_owned(),
            ));
        }
        if url.query().is_some() && !self.allow_query {
            return Err(MediaError::Refused(
                "query strings are forbidden in media URLs unless explicitly granted; the exact URL is journaled"
                    .to_owned(),
            ));
        }
        let host = url
            .host_str()
            .map(normalize_host)
            .ok_or_else(|| MediaError::Refused("media URL has no host".to_owned()))?;
        if !self.hosts.contains(&host) {
            return Err(MediaError::Refused(format!(
                "media host '{host}' is not exactly granted"
            )));
        }
        let port = url
            .port_or_known_default()
            .ok_or_else(|| MediaError::Refused("media URL has no effective port".to_owned()))?;
        if !self.ports.contains(&port) {
            return Err(MediaError::Refused(format!(
                "media port {port} is not granted"
            )));
        }
        Ok(url)
    }
}

/// How fetched media is made erasable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum MediaRetention {
    /// The runtime must be inside a case and links the digest to that case.
    CaseLinked,
    /// An external lifecycle controller owns expiry under the named policy.
    External { policy: String },
}

/// Metadata exposed to malware, file-format, and content-policy validators.
#[derive(Debug)]
pub struct MediaCandidate<'a> {
    pub source_url: &'a str,
    pub final_url: &'a str,
    pub media_type: &'a str,
    pub bytes: &'a [u8],
}

/// An operator-supplied content validator.
///
/// `identity` must include the validator and ruleset version. It is included in
/// the effect key and the resulting evidence, so changing scanner semantics is
/// a changed effect rather than an invisible deployment detail.
#[async_trait]
pub trait MediaValidator: Send + Sync + Debug {
    fn identity(&self) -> &str;
    async fn validate(&self, candidate: &MediaCandidate<'_>) -> Result<(), String>;
}

/// A configured governed-media fetcher.
#[derive(Debug, Clone)]
pub struct GovernedMedia {
    policy: MediaPolicy,
    validators: Vec<Arc<dyn MediaValidator>>,
}

impl GovernedMedia {
    #[must_use]
    pub fn new(policy: MediaPolicy) -> Self {
        Self {
            policy,
            validators: Vec::new(),
        }
    }

    #[must_use]
    pub fn validator(mut self, validator: Arc<dyn MediaValidator>) -> Self {
        assert!(
            !validator.identity().trim().is_empty(),
            "media validator identity must name a versioned ruleset"
        );
        self.validators.push(validator);
        self
    }

    pub(crate) fn requires_case(&self) -> bool {
        self.policy.retention == MediaRetention::CaseLinked
    }

    /// The unit that owns erasure for these bytes, when it is not the case.
    ///
    /// Named external retention means another lifecycle controller decides when
    /// these bytes go. That controller is still an erasure unit, so it is what a
    /// data key is scoped to — sealing under a case that does not exist, or not
    /// sealing at all, would both be wrong.
    pub(crate) fn external_scope(&self) -> Option<&str> {
        match &self.policy.retention {
            MediaRetention::External { policy } => Some(policy),
            MediaRetention::CaseLinked => None,
        }
    }

    pub(crate) fn effect(
        &self,
        blobs: Arc<dyn BlobStore>,
        url: &str,
        case_link: Option<MediaCaseLink>,
    ) -> GovernedFetch {
        GovernedFetch {
            fetcher: self.clone(),
            blobs,
            arguments: json!({ "url": url }),
            case_link,
        }
    }

    async fn fetch(&self, raw: &str) -> Result<FetchBody, MediaError> {
        match tokio::time::timeout(self.policy.timeout, self.fetch_loop(raw)).await {
            Ok(result) => result,
            Err(_) => Err(MediaError::TimedOut(self.policy.timeout)),
        }
    }

    async fn fetch_loop(&self, raw: &str) -> Result<FetchBody, MediaError> {
        let source = self.policy.validate_url(raw)?;
        let mut current = source.clone();
        let mut visited = HashSet::new();
        let mut hops = Vec::new();

        for redirects in 0..=self.policy.max_redirects {
            record_visit(&mut visited, &current)?;
            let (response, addresses) = self.request(&current).await?;
            enforce_header_limit(response.headers(), self.policy.max_header_bytes)?;
            hops.push(MediaHop {
                url: current.to_string(),
                addresses,
                status: response.status().as_u16(),
            });
            if is_redirect(response.status()) {
                if redirects == self.policy.max_redirects {
                    return Err(MediaError::Refused(format!(
                        "media redirect limit {} exceeded",
                        self.policy.max_redirects
                    )));
                }
                current = redirect_target(&current, &response)?;
                current = self.policy.validate_url(current.as_str())?;
                continue;
            }

            let (media_type, bytes) = self.read_body(response).await?;
            let has_signature_check = validate_media_signature(&media_type, &bytes)?;
            if !has_signature_check && self.validators.is_empty() {
                return Err(MediaError::Refused(format!(
                    "media type '{media_type}' has no built-in signature check; configure a versioned content validator"
                )));
            }
            let candidate = MediaCandidate {
                source_url: source.as_str(),
                final_url: current.as_str(),
                media_type: &media_type,
                bytes: &bytes,
            };
            let mut validated_by = Vec::with_capacity(self.validators.len());
            for validator in &self.validators {
                validator.validate(&candidate).await.map_err(|detail| {
                    MediaError::Refused(format!(
                        "media validator '{}' refused the artifact: {detail}",
                        validator.identity()
                    ))
                })?;
                validated_by.push(validator.identity().to_owned());
            }
            return Ok(FetchBody {
                source_url: source.to_string(),
                final_url: current.to_string(),
                media_type,
                bytes,
                redirects,
                validated_by,
                hops,
            });
        }
        unreachable!("the bounded redirect loop always returns")
    }

    async fn request(
        &self,
        url: &reqwest::Url,
    ) -> Result<(reqwest::Response, Vec<IpAddr>), MediaError> {
        let host = url
            .host_str()
            .ok_or_else(|| MediaError::Refused("media URL has no host".to_owned()))?;
        let port = url
            .port_or_known_default()
            .ok_or_else(|| MediaError::Refused("media URL has no effective port".to_owned()))?;
        let addrs = resolve_public(host, port).await?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .referer(false)
            .no_gzip()
            .no_brotli()
            .no_zstd()
            .no_deflate()
            .pool_max_idle_per_host(0)
            .connect_timeout(self.policy.timeout)
            .read_timeout(self.policy.timeout)
            .timeout(self.policy.timeout)
            .http2_max_header_list_size(
                u32::try_from(self.policy.max_header_bytes).unwrap_or(u32::MAX),
            )
            .https_only(!self.policy.allow_http)
            .resolve_to_addrs(host, &addrs)
            .build()
            .map_err(|error| MediaError::Unavailable(error.to_string()))?;
        let response = client
            .get(url.clone())
            .header(
                ACCEPT,
                self.policy
                    .media_types
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", "),
            )
            .header(ACCEPT_ENCODING, "identity")
            .send()
            .await
            .map_err(|error| {
                if error.is_timeout() {
                    MediaError::TimedOut(self.policy.timeout)
                } else if error.is_connect() {
                    MediaError::Unavailable(error.to_string())
                } else {
                    MediaError::Interrupted(error.to_string())
                }
            })?;
        Ok((
            response,
            addrs.into_iter().map(|address| address.ip()).collect(),
        ))
    }

    async fn read_body(
        &self,
        response: reqwest::Response,
    ) -> Result<(String, Vec<u8>), MediaError> {
        if response.status() != reqwest::StatusCode::OK {
            return Err(MediaError::Refused(format!(
                "media origin returned HTTP {}",
                response.status()
            )));
        }
        if let Some(length) = response
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            && length > self.policy.max_bytes as u64
        {
            return Err(MediaError::Refused(format!(
                "media Content-Length {length} exceeds {} bytes",
                self.policy.max_bytes
            )));
        }
        if let Some(encoding) = response.headers().get(CONTENT_ENCODING) {
            let encoding = encoding.to_str().unwrap_or("<invalid>");
            if !encoding.eq_ignore_ascii_case("identity") {
                return Err(MediaError::Refused(format!(
                    "media Content-Encoding '{encoding}' is forbidden; only identity is accepted"
                )));
            }
        }
        let media_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(normalize_media_type)
            .ok_or_else(|| {
                MediaError::Refused("media response has no valid Content-Type".to_owned())
            })?;
        if !self.policy.media_types.contains(&media_type) {
            return Err(MediaError::Refused(format!(
                "media type '{media_type}' is not granted"
            )));
        }

        let mut bytes = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|error| MediaError::Interrupted(error.to_string()))?;
            let next = bytes.len().checked_add(chunk.len()).ok_or_else(|| {
                MediaError::Refused("media response length overflowed".to_owned())
            })?;
            if next > self.policy.max_bytes {
                return Err(MediaError::Refused(format!(
                    "media body exceeds {} bytes",
                    self.policy.max_bytes
                )));
            }
            bytes.extend_from_slice(&chunk);
        }
        if bytes.is_empty() {
            return Err(MediaError::Refused(
                "media response body is empty".to_owned(),
            ));
        }
        Ok((media_type, bytes))
    }
}

/// A fetched immutable artifact. The journal carries this metadata and digest,
/// while the potentially erasable bytes live in the configured blob store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchedMedia {
    pub digest: Digest,
    pub media_type: String,
    pub bytes: usize,
    pub source_url: String,
    pub final_url: String,
    pub redirects: u8,
    pub validated_by: Vec<String>,
    pub hops: Vec<MediaHop>,
    pub retention: MediaRetention,
}

/// Auditable transport provenance for one origin or redirect hop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaHop {
    pub url: String,
    pub addresses: Vec<IpAddr>,
    pub status: u16,
}

impl FetchedMedia {
    /// An Anthropic image block whose bytes are materialized only inside a live
    /// [`ModelCall`](crate::model::ModelCall).
    #[must_use]
    pub fn anthropic_image(&self) -> Value {
        json!({
            "type": "image",
            "source": {
                "type": "base64",
                "media_type": self.media_type,
                "data": self.materialization("base64"),
            }
        })
    }

    /// An `OpenAI` Responses image block whose data URL is materialized only
    /// inside a live [`ModelCall`](crate::model::ModelCall).
    #[must_use]
    pub fn openai_image(&self) -> Value {
        json!({
            "type": "input_image",
            "image_url": self.materialization("data_url"),
        })
    }

    fn materialization(&self, encoding: &str) -> Value {
        json!({
            "$agentplane_media": {
                "digest": self.digest,
                "media_type": self.media_type,
                "encoding": encoding,
            }
        })
    }
}

#[derive(Debug)]
struct FetchBody {
    source_url: String,
    final_url: String,
    media_type: String,
    bytes: Vec<u8>,
    redirects: u8,
    validated_by: Vec<String>,
    hops: Vec<MediaHop>,
}

/// The effect used internally by [`StepCtx::fetch_media`](crate::runtime::StepCtx::fetch_media).
#[derive(Debug, Clone)]
pub struct GovernedFetch {
    fetcher: GovernedMedia,
    blobs: Arc<dyn BlobStore>,
    arguments: Value,
    case_link: Option<MediaCaseLink>,
}

#[derive(Debug, Clone)]
pub(crate) struct MediaCaseLink {
    pub(crate) cases: Arc<dyn crate::case::CaseStore>,
    pub(crate) case: CaseId,
    pub(crate) at: Timestamp,
}

#[async_trait]
impl Effect for GovernedFetch {
    type Output = FetchedMedia;

    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new(
            "media.fetch",
            json!({
                "request": self.arguments,
                "policy": self.fetcher.policy.snapshot(),
                "validators": self.fetcher.validators.iter()
                    .map(|validator| validator.identity())
                    .collect::<Vec<_>>(),
            }),
        )
    }

    fn mutates(&self) -> bool {
        false
    }

    fn recovery(&self) -> Recovery {
        Recovery::Retry
    }

    fn retry(&self) -> RetryPolicy {
        self.fetcher.policy.retry
    }

    fn max_sensitivity(&self) -> Sensitivity {
        self.fetcher.policy.max_url_sensitivity
    }

    fn output_sensitivity(&self) -> Sensitivity {
        self.fetcher.policy.output_sensitivity
    }

    fn trust(&self) -> Trust {
        Trust::Untrusted
    }

    fn sink_arguments(&self) -> Option<&Value> {
        Some(&self.arguments)
    }

    fn protected_fields(&self) -> &[ProtectedField] {
        static URL: OnceLock<Vec<ProtectedField>> = OnceLock::new();
        URL.get_or_init(|| vec![ProtectedField::trusted("/url")])
    }

    async fn perform(&self) -> Result<FetchedMedia, EffectError> {
        let raw = self
            .arguments
            .get("url")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                EffectError::Rejected("media URL argument is not a string".to_owned())
            })?;
        let fetched = self.fetcher.fetch(raw).await.map_err(EffectError::from)?;
        let digest = Digest::of(&fetched.bytes);
        // Link before put. A crash may leave a harmless dangling link, which a
        // retry repairs, but it must never leave durable bytes outside the
        // case traversal used for erasure.
        if let Some(link) = &self.case_link {
            link.cases
                .link_blob(link.case, digest, link.at)
                .await
                .map_err(|error| EffectError::Unavailable {
                    driver: "case.store".to_owned(),
                    detail: error.to_string(),
                })?;
        }
        let digest =
            self.blobs
                .put(&fetched.bytes)
                .await
                .map_err(|error| EffectError::Unavailable {
                    driver: "blob.store".to_owned(),
                    detail: error.to_string(),
                })?;
        Ok(FetchedMedia {
            digest,
            media_type: fetched.media_type,
            bytes: fetched.bytes.len(),
            source_url: fetched.source_url,
            final_url: fetched.final_url,
            redirects: fetched.redirects,
            validated_by: fetched.validated_by,
            hops: fetched.hops,
            retention: self.fetcher.policy.retention.clone(),
        })
    }
}

#[derive(Debug, thiserror::Error)]
enum MediaError {
    #[error("{0}")]
    Refused(String),
    #[error("{0}")]
    Unavailable(String),
    #[error("timed out after {}ms", .0.as_millis())]
    TimedOut(Duration),
    #[error("{0}")]
    Interrupted(String),
}

impl From<MediaError> for EffectError {
    fn from(error: MediaError) -> Self {
        match error {
            MediaError::Refused(detail) => Self::Rejected(detail),
            MediaError::Unavailable(detail) => Self::Unavailable {
                driver: "media.fetch".to_owned(),
                detail,
            },
            MediaError::TimedOut(waited) => Self::Timeout {
                driver: "media.fetch".to_owned(),
                waited_ms: u64::try_from(waited.as_millis()).unwrap_or(u64::MAX),
            },
            MediaError::Interrupted(detail) => Self::Interrupted {
                driver: "media.fetch".to_owned(),
                detail,
            },
        }
    }
}

fn redirect_target(
    current: &reqwest::Url,
    response: &reqwest::Response,
) -> Result<reqwest::Url, MediaError> {
    let location = response
        .headers()
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| MediaError::Refused("media redirect has no valid Location".to_owned()))?;
    current
        .join(location)
        .map_err(|error| MediaError::Refused(format!("invalid media redirect: {error}")))
}

fn record_visit(visited: &mut HashSet<String>, url: &reqwest::Url) -> Result<(), MediaError> {
    if visited.insert(url.as_str().to_owned()) {
        Ok(())
    } else {
        Err(MediaError::Refused(
            "media redirect cycle detected".to_owned(),
        ))
    }
}

fn is_redirect(status: reqwest::StatusCode) -> bool {
    matches!(
        status,
        reqwest::StatusCode::MOVED_PERMANENTLY
            | reqwest::StatusCode::FOUND
            | reqwest::StatusCode::SEE_OTHER
            | reqwest::StatusCode::TEMPORARY_REDIRECT
            | reqwest::StatusCode::PERMANENT_REDIRECT
    )
}

async fn resolve_public(host: &str, port: u16) -> Result<Vec<SocketAddr>, MediaError> {
    let addresses = if let Ok(ip) = host.parse::<IpAddr>() {
        vec![SocketAddr::new(ip, port)]
    } else {
        tokio::net::lookup_host((host, port))
            .await
            .map_err(|error| MediaError::Unavailable(format!("DNS for '{host}': {error}")))?
            .collect::<Vec<_>>()
    };
    validate_resolved(host, addresses)
}

/// Which addresses this fetch may connect to.
///
/// The classification is [`crate::netguard`], shared with push
/// notification delivery — the other feature that dereferences a URL somebody
/// else chose. Two copies of this rule would diverge, and the copy that diverges
/// is whichever nobody probed at the boundary.
fn validate_resolved(
    host: &str,
    addresses: impl IntoIterator<Item = SocketAddr>,
) -> Result<Vec<SocketAddr>, MediaError> {
    crate::netguard::all_public(host, addresses).map_err(|detail| {
        // An empty resolution is an outage; a private answer is a refusal. The
        // two call for different responses, so they keep different variants.
        if detail.contains("no addresses") {
            MediaError::Unavailable(detail)
        } else {
            MediaError::Refused(format!("media {detail}"))
        }
    })
}

fn enforce_header_limit(
    headers: &reqwest::header::HeaderMap,
    limit: usize,
) -> Result<(), MediaError> {
    let bytes = headers.iter().try_fold(0usize, |total, (name, value)| {
        total
            .checked_add(name.as_str().len())?
            .checked_add(value.as_bytes().len())?
            .checked_add(4)
    });
    if bytes.is_none_or(|bytes| bytes > limit) {
        return Err(MediaError::Refused(format!(
            "media response headers exceed {limit} bytes"
        )));
    }
    Ok(())
}

/// Validate common passive media formats from bytes rather than trusting the
/// origin's `Content-Type`. Unknown exact types require an operator validator.
fn validate_media_signature(media_type: &str, bytes: &[u8]) -> Result<bool, MediaError> {
    let valid = match media_type {
        "image/png" => bytes.starts_with(b"\x89PNG\r\n\x1a\n"),
        "image/jpeg" => bytes.starts_with(b"\xff\xd8\xff"),
        "image/gif" => bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a"),
        "image/webp" => bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP",
        "application/pdf" => bytes.starts_with(b"%PDF-"),
        "application/json" => serde_json::from_slice::<Value>(bytes).is_ok(),
        "text/plain" => std::str::from_utf8(bytes).is_ok() && !bytes.contains(&0),
        "audio/mpeg" => {
            bytes.starts_with(b"ID3")
                || (bytes.len() >= 2 && bytes[0] == 0xff && bytes[1] & 0xe0 == 0xe0)
        }
        "audio/wav" => bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WAVE",
        "video/mp4" => bytes.len() >= 12 && &bytes[4..8] == b"ftyp",
        _ => return Ok(false),
    };
    if !valid {
        return Err(MediaError::Refused(format!(
            "media bytes do not match declared type '{media_type}'"
        )));
    }
    Ok(true)
}

pub(crate) fn verify_materialized(media_type: &str, bytes: &[u8]) -> Result<(), String> {
    match validate_media_signature(media_type, bytes) {
        Ok(true) => Ok(()),
        Ok(false) => Err(format!(
            "media type '{media_type}' cannot be safely materialized without its fetch validator"
        )),
        Err(error) => Err(error.to_string()),
    }
}

fn normalize_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn normalize_media_type(media_type: &str) -> String {
    media_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> MediaPolicy {
        MediaPolicy::new()
            .allow_host("media.example")
            .allow_media_type("image/png")
    }

    #[test]
    fn policy_is_exact_and_deny_by_default() {
        assert!(
            MediaPolicy::new()
                .validate_url("https://media.example/a.png")
                .is_err()
        );
        assert!(policy().validate_url("https://media.example/a.png").is_ok());
        assert!(
            policy()
                .validate_url("https://evil.media.example/a.png")
                .is_err()
        );
        assert!(
            policy()
                .validate_url("https://media.example.evil/a.png")
                .is_err()
        );
    }

    #[test]
    fn unsafe_url_components_are_refused() {
        let policy = policy();
        assert!(policy.validate_url("file:///etc/passwd").is_err());
        assert!(
            policy
                .validate_url("https://user:pass@media.example/a.png")
                .is_err()
        );
        assert!(
            policy
                .validate_url("https://media.example/a.png#secret")
                .is_err()
        );
        assert!(
            policy
                .validate_url("https://media.example/a.png?token=secret")
                .is_err()
        );
        assert!(
            policy
                .clone()
                .allow_query()
                .validate_url("https://media.example/a.png?v=1")
                .is_ok()
        );
        assert!(
            policy
                .validate_url("https://media.example:8443/a.png")
                .is_err()
        );
        assert!(policy.validate_url("http://media.example/a.png").is_err());
    }

    #[test]
    fn only_uri_redirect_statuses_are_followed() {
        for status in [301, 302, 303, 307, 308] {
            assert!(is_redirect(reqwest::StatusCode::from_u16(status).unwrap()));
        }
        for status in [300, 304, 305, 306] {
            assert!(!is_redirect(reqwest::StatusCode::from_u16(status).unwrap()));
        }
    }

    #[test]
    fn every_redirect_target_is_reparsed_and_reauthorized() {
        let current = reqwest::Url::parse("https://media.example/a.png").unwrap();
        let response: reqwest::Response = http::Response::builder()
            .status(302)
            .header(LOCATION, "https://evil.example/steal")
            .body(Vec::new())
            .unwrap()
            .into();
        let target = redirect_target(&current, &response).unwrap();
        assert!(policy().validate_url(target.as_str()).is_err());

        let mut visited = HashSet::new();
        record_visit(&mut visited, &current).unwrap();
        assert!(record_visit(&mut visited, &current).is_err());
    }

    #[tokio::test]
    async fn an_exact_grant_cannot_make_a_metadata_ip_public() {
        let policy = MediaPolicy::new()
            .allow_host("169.254.169.254")
            .allow_media_type("image/png");
        let url = policy
            .validate_url("https://169.254.169.254/latest/meta-data")
            .unwrap();
        let error = resolve_public(url.host_str().unwrap(), 443)
            .await
            .unwrap_err();
        assert!(matches!(error, MediaError::Refused(_)));
    }

    #[test]
    fn cleartext_and_nonstandard_ports_require_separate_explicit_grants() {
        let policy = policy().allow_http().allow_port(80);
        assert!(policy.validate_url("http://media.example/a.png").is_ok());
        assert!(
            policy
                .validate_url("http://media.example:8080/a.png")
                .is_err()
        );
    }

    /// A public answer does not launder a private one.
    ///
    /// The classification itself is `core::netguard`, shared with webhook
    /// delivery and tested there. What this pins is *this* module's use of it:
    /// that a forbidden address is a `Refused` — an operator's decision — rather
    /// than an `Unavailable`, which would invite a retry of something that can
    /// never work.
    #[test]
    fn one_private_dns_answer_refuses_the_entire_resolution() {
        let result = validate_resolved(
            "media.example",
            [
                SocketAddr::from(([1, 1, 1, 1], 443)),
                SocketAddr::from(([169, 254, 169, 254], 443)),
            ],
        );
        assert!(
            matches!(result, Err(MediaError::Refused(_))),
            "a public answer laundered a private one, or the refusal was \
             reported as a transient outage: {result:?}"
        );
    }

    #[test]
    fn content_type_is_not_trusted_without_matching_bytes() {
        assert!(validate_media_signature("image/png", b"not a png").is_err());
        assert!(validate_media_signature("image/png", b"\x89PNG\r\n\x1a\nbody").unwrap());
        assert!(!validate_media_signature("image/svg+xml", b"<svg/>").unwrap());
    }

    #[test]
    fn aggregate_response_headers_have_a_hard_ceiling() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("x-one", "1234".parse().unwrap());
        headers.insert("x-two", "5678".parse().unwrap());
        assert!(enforce_header_limit(&headers, 100).is_ok());
        assert!(enforce_header_limit(&headers, 10).is_err());
    }

    #[tokio::test]
    async fn declared_and_streamed_body_sizes_are_both_bounded() {
        let fetcher = GovernedMedia::new(policy().max_bytes(8));
        let declared: reqwest::Response = http::Response::builder()
            .status(200)
            .header(CONTENT_TYPE, "image/png")
            .header(CONTENT_LENGTH, "9")
            .body(Vec::new())
            .unwrap()
            .into();
        assert!(fetcher.read_body(declared).await.is_err());

        let streamed: reqwest::Response = http::Response::builder()
            .status(200)
            .header(CONTENT_TYPE, "image/png")
            .body(b"\x89PNG\r\n\x1a\nX".to_vec())
            .unwrap()
            .into();
        assert!(fetcher.read_body(streamed).await.is_err());
    }

    #[tokio::test]
    async fn compressed_responses_are_refused_before_body_use() {
        let fetcher = GovernedMedia::new(policy());
        let response: reqwest::Response = http::Response::builder()
            .status(200)
            .header(CONTENT_TYPE, "image/png")
            .header(CONTENT_ENCODING, "gzip")
            .body(b"not actually gzip".to_vec())
            .unwrap()
            .into();
        assert!(fetcher.read_body(response).await.is_err());
    }

    #[test]
    fn policy_and_validator_identity_are_in_the_effect_key() {
        #[derive(Debug)]
        struct Scanner(String);
        #[async_trait]
        impl MediaValidator for Scanner {
            fn identity(&self) -> &str {
                &self.0
            }
            async fn validate(&self, _: &MediaCandidate<'_>) -> Result<(), String> {
                Ok(())
            }
        }

        let fetcher =
            GovernedMedia::new(policy()).validator(Arc::new(Scanner("clamav:rules-42".to_owned())));
        let effect = fetcher.effect(
            Arc::new(crate::blob::MemoryBlobs::new()),
            "https://media.example/a.png",
            None,
        );
        let descriptor = effect.descriptor();
        assert_eq!(descriptor.kind, "media.fetch");
        assert_eq!(effect.trust(), Trust::Untrusted);
        assert_eq!(descriptor.args["validators"][0], "clamav:rules-42");
        assert_eq!(descriptor.args["policy"]["max_bytes"], DEFAULT_MAX_BYTES);
    }
}
