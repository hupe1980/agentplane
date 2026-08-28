//! Embedding drivers, for the seam semantic retrieval needs.
//!
//! Three, chosen by which wire a provider speaks:
//!
//! * `OpenAiEmbedder` — `POST /v1/embeddings`, which reaches `OpenAI`, Voyage
//!   AI, Ollama, vLLM, TGI, LM Studio and Hugging Face's router. One driver, as
//!   `chat-completions` is one driver for completions.
//! * `GeminiEmbedder` — Google's `:embedContent`, a different wire.
//! * `BedrockEmbedder` — Titan and Cohere on Bedrock, for a plane whose data
//!   may not leave one AWS account.
//!
//! Anthropic has no embeddings API and recommends Voyage, which the first driver
//! reaches by base URL alone.
//!
//! # What is deliberately absent
//!
//! **Batching.** The seam embeds one text, because the vector goes into an
//! effect key and one effect is one observation. Batching would have to decide
//! how a partial failure maps onto several effects.
//!
//! **A default model.** [`Embedder::revision`](crate::memory::Embedder::revision)
//! is in the effect key, so a guessed default would put a guess in the identity
//! of every vector.

#[cfg(feature = "providers")]
use crate::core::Secret;
use crate::core::StoreError;
use crate::memory::Embedder;

/// One embedding component, as `f32`.
///
/// Vectors are `f32` by the seam's own contract — that is what an index stores
/// and what cosine is computed in. JSON carries `f64`, so narrowing is not a
/// loss of information the caller had: it is the wire's precision meeting the
/// type the whole retrieval path already uses.
///
/// # The narrowing has to be checked, not merely declared safe
///
/// `1e39` is an ordinary JSON number — `serde_json` refuses only what no `f64`
/// can hold — and `1e39 as f32` is `inf`. The obvious one-liner therefore
/// returns `Some(inf)`, the caller's `len()` check passes because nothing was
/// dropped, and an infinite component goes into the vector.
///
/// What it does downstream is the reason this is a check rather than a
/// tidy-up. The query vector is part of the retrieval effect's identity, and
/// `serde_json::to_value` turns a non-finite float into `null` — so `+inf`,
/// `-inf` and every out-of-range component journal as the same value and
/// therefore share an effect key. [`core::canon`](crate::core::canon) states
/// the rule this breaks: two *different* values must never hash identically,
/// because replay then hands one effect the other's recorded output.
///
/// Returning `None` puts it back on the length check, which refuses the whole
/// reply and names the driver — a provider answering with a component no
/// embedding index can rank against is not speaking this wire.
#[allow(clippy::cast_possible_truncation)]
fn json_f32(value: &serde_json::Value) -> Option<f32> {
    let narrowed = value.as_f64()? as f32;
    narrowed.is_finite().then_some(narrowed)
}

/// Embeddings over the `OpenAI`-compatible wire.
#[cfg(feature = "providers")]
#[derive(Debug, Clone)]
pub struct OpenAiEmbedder {
    http: reqwest::Client,
    key: Option<Secret>,
    base: String,
    model: String,
    dimensions: Option<u32>,
    input_type: Option<String>,
    egress: Option<crate::core::Egress>,
    timeout: std::time::Duration,
}

#[cfg(feature = "providers")]
impl OpenAiEmbedder {
    /// Five minutes, matching the model drivers.
    pub const DEFAULT_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(5);

    /// A driver for one embedding model.
    ///
    /// The model is required and has no default: it is `revision()`, which sits
    /// in the retrieval effect's key, and a guessed default would put a guess
    /// into the identity of every vector this ever produced.
    ///
    /// # Errors
    ///
    /// If the HTTP client cannot be built.
    pub fn new(model: impl Into<String>) -> Result<Self, StoreError> {
        let http = reqwest::Client::builder()
            .build()
            .map_err(|e| StoreError::Backend(format!("could not build an HTTP client: {e}")))?;
        Ok(Self {
            http,
            key: None,
            base: "https://api.openai.com".to_owned(),
            model: model.into(),
            dimensions: None,
            input_type: None,
            egress: None,
            timeout: Self::DEFAULT_TIMEOUT,
        })
    }

    /// The bearer token, when the server wants one.
    ///
    /// Optional because the common local server does not, which is the same
    /// shape `chat-completions` has.
    #[must_use]
    pub fn key(mut self, key: impl Into<String>) -> Self {
        self.key = Some(Secret::new(key));
        self
    }

    /// Point at a different host — a local server, a gateway, or a test double.
    #[must_use]
    pub fn base(mut self, base: impl Into<String>) -> Self {
        self.base = base.into();
        self
    }

    /// Ask for a shortened vector, where the model supports it.
    ///
    /// In [`revision`](Embedder::revision), because a 1536-dimension vector and
    /// a 256-dimension one from the same model are not comparable and must not
    /// share an index — nor an effect identity.
    #[must_use]
    pub const fn dimensions(mut self, dimensions: u32) -> Self {
        self.dimensions = Some(dimensions);
        self
    }

    /// Tell an asymmetric model that this text is a **query**.
    ///
    /// Some models embed questions and documents into deliberately different
    /// regions, and rank badly when the two are swapped. Voyage prepends a
    /// prompt when told (`"query"`); Cohere's direct API takes the same field
    /// (`"search_query"`). `OpenAI`'s own models are symmetric and take no such
    /// parameter, which is why this is opt-in rather than defaulted — sending an
    /// unknown field to a server that does not want it is a 400.
    ///
    /// **Nothing in a reply says you got this wrong.** The vectors come back the
    /// right shape and rank slightly worse forever, which is why it is a typed
    /// option here rather than something a caller is left to discover.
    ///
    /// It goes into [`revision`](Embedder::revision): a query embedded with the
    /// hint and one without are not comparable, so they must not share an
    /// effect identity.
    #[must_use]
    pub fn input_type(mut self, input_type: impl Into<String>) -> Self {
        self.input_type = Some(input_type.into());
        self
    }

    /// Restrict where this driver may connect.
    ///
    /// Deny-by-default once set, refused **before the request is built**, so
    /// nothing leaves. An embedding call sends the query text to a third party;
    /// that it is short does not make it uninteresting.
    #[must_use]
    pub fn egress(mut self, egress: crate::core::Egress) -> Self {
        self.egress = Some(egress);
        self
    }

    /// Bound connection and response as one operation.
    #[must_use]
    pub const fn timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn check_egress(&self) -> Result<(), StoreError> {
        let Some(egress) = &self.egress else {
            return Ok(());
        };
        let host = reqwest::Url::parse(&self.base)
            .ok()
            .and_then(|u| u.host_str().map(ToOwned::to_owned));
        egress
            .permits(host.as_deref())
            .map_err(|e| StoreError::Backend(e.to_string()))
    }
}

#[cfg(feature = "providers")]
#[derive(serde::Deserialize)]
struct EmbeddingsReply {
    data: Vec<EmbeddingDatum>,
}

#[cfg(feature = "providers")]
#[derive(serde::Deserialize)]
struct EmbeddingDatum {
    /// Raw JSON numbers, not `f32`: serde's float path reads `1e39` as `inf`
    /// without complaint, and a non-finite component is exactly what
    /// [`json_f32`] exists to refuse.
    embedding: Vec<serde_json::Value>,
}

#[cfg(feature = "providers")]
#[async_trait::async_trait]
impl Embedder for OpenAiEmbedder {
    /// Model **and** dimension count.
    ///
    /// Both, because both change the vector. Two runs whose queries were
    /// embedded at different widths would rank against different geometry, and
    /// the effect key is what stops a replay reading one as the other.
    fn revision(&self) -> String {
        use std::fmt::Write as _;
        let mut revision = self.model.clone();
        if let Some(d) = self.dimensions {
            let _ = write!(revision, "@{d}");
        }
        if let Some(input_type) = &self.input_type {
            let _ = write!(revision, "/{input_type}");
        }
        revision
    }

    async fn embed(&self, text: &str) -> Result<Vec<f32>, StoreError> {
        self.check_egress()?;

        let mut body = serde_json::json!({ "model": self.model, "input": text });
        if let Some(dimensions) = self.dimensions {
            body["dimensions"] = serde_json::json!(dimensions);
        }
        if let Some(input_type) = &self.input_type {
            body["input_type"] = serde_json::json!(input_type);
        }

        let url = format!("{}/v1/embeddings", self.base.trim_end_matches('/'));
        let mut request = self.http.post(&url).timeout(self.timeout).json(&body);
        if let Some(key) = &self.key {
            request = request.bearer_auth(key.expose());
        }

        let response = request
            .send()
            .await
            .map_err(|e| StoreError::Backend(format!("{url}: {e}")))?;
        let status = response.status();
        let text_body = response
            .text()
            .await
            .map_err(|e| StoreError::Backend(format!("{url}: unreadable reply: {e}")))?;
        if !status.is_success() {
            // The body, not only the code: an embeddings 400 is almost always
            // "that model does not exist" or "input too long", and a bare status
            // sends somebody to check their key.
            return Err(StoreError::Backend(format!(
                "{url}: embeddings returned {status}: {text_body}"
            )));
        }

        let reply: EmbeddingsReply = serde_json::from_str(&text_body)
            .map_err(|e| StoreError::Backend(format!("{url}: unreadable reply: {e}")))?;

        // Exactly one, because exactly one text was sent. A server answering
        // with more — or none — is not speaking this wire, and returning the
        // first of several would silently pick a vector for somebody else's
        // input.
        let [datum] = reply.data.as_slice() else {
            return Err(StoreError::Backend(format!(
                "{url}: one input was sent and {} embeddings came back",
                reply.data.len()
            )));
        };
        if datum.embedding.is_empty() {
            return Err(StoreError::Backend(format!(
                "{url}: the embedding is empty, which no index can rank against"
            )));
        }
        let vector: Vec<f32> = datum.embedding.iter().filter_map(json_f32).collect();
        if vector.len() != datum.embedding.len() {
            return Err(StoreError::Backend(format!(
                "{url}: the embedding carries a component that is not a finite number"
            )));
        }
        Ok(vector)
    }
}

/// How a Bedrock embedding family spells a request.
///
/// Bedrock's `InvokeModel` is a **passthrough**: the body is the vendor's own,
/// and the vendors do not agree. Titan takes `{"inputText": …}` and answers
/// `{"embedding": […]}`; Cohere takes `{"texts": […], "input_type": …}` and
/// answers `{"embeddings": [[…]]}`. There is no shape this driver can derive
/// from the model id, so it is **declared, never sniffed** — the same decision
/// [`ReasoningDialect`](super::bedrock::ReasoningDialect) makes, and for the
/// same reason: cross-region inference profiles prefix the id
/// (`us.amazon.titan-…`), so a substring match would bind behaviour to a naming
/// convention AWS owns and can change.
///
/// An undeclared dialect refuses rather than guessing. Sending Titan's body to
/// Cohere does not fail cleanly — it is a 400 whose text blames the caller — and
/// guessing wrong on the *response* would be worse: `embeddings[0]` read as
/// `embedding` yields a vector of the wrong rank that ranks against nothing.
#[cfg(feature = "bedrock")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EmbeddingDialect {
    /// Amazon Titan Embed: `inputText`, answering `embedding`.
    Titan,
    /// Cohere Embed: `texts` plus `input_type`, answering `embeddings`.
    Cohere,
}

/// The request body for one Bedrock embedding dialect.
///
/// A free function rather than a method, so the vendor mapping — the part that
/// is easy to get silently wrong and impossible to test against AWS without
/// credentials — is exercisable on its own.
///
/// # Errors
///
/// If a parameter is set that the dialect has no place for.
#[cfg(feature = "bedrock")]
fn bedrock_body(
    dialect: EmbeddingDialect,
    text: &str,
    dimensions: Option<u32>,
) -> Result<serde_json::Value, StoreError> {
    match dialect {
        EmbeddingDialect::Titan => {
            let mut body = serde_json::json!({ "inputText": text });
            if let Some(dimensions) = dimensions {
                body["dimensions"] = serde_json::json!(dimensions);
            }
            Ok(body)
        }
        EmbeddingDialect::Cohere => {
            if dimensions.is_some() {
                return Err(StoreError::Backend(
                    "Cohere Embed takes no `dimensions`; the width is the model's. \
                     Drop `.dimensions(..)` or choose a Titan model — a knob that \
                     silently did nothing would put a width in the effect key that \
                     never reached the wire"
                        .to_owned(),
                ));
            }
            // `search_query`, not `search_document`: this embeds the thing being
            // looked *for*. Cohere's asymmetric models rank badly when the two
            // are swapped, and nothing in the reply says so.
            Ok(serde_json::json!({ "texts": [text], "input_type": "search_query" }))
        }
    }
}

/// Embeddings through Amazon Bedrock's `InvokeModel`.
///
/// # Why this exists beside the `OpenAI`-compatible one
///
/// Bedrock is the deployment that cannot reach the other driver: a plane chosen
/// for Bedrock was usually chosen because its data may not leave a particular
/// account, and telling it to call `api.openai.com` for the *query text* is the
/// one thing it cannot do. Without this, semantic retrieval was unavailable to
/// exactly the regulated deployments this crate is built for — the AWS SDK
/// already being paid for by the `bedrock` feature.
#[cfg(feature = "bedrock")]
#[derive(Debug, Clone)]
pub struct BedrockEmbedder {
    client: aws_sdk_bedrockruntime::Client,
    model: String,
    region: String,
    dialect: EmbeddingDialect,
    dimensions: Option<u32>,
}

#[cfg(feature = "bedrock")]
impl BedrockEmbedder {
    /// Load the standard AWS credential chain for this region.
    ///
    /// The same chain [`Bedrock::from_env`](super::bedrock::Bedrock::from_env)
    /// documents, Bedrock API keys included — they cover `InvokeModel`.
    ///
    /// # Errors
    ///
    /// If the region is blank.
    pub async fn from_env(
        region: impl Into<String>,
        model: impl Into<String>,
        dialect: EmbeddingDialect,
    ) -> Result<Self, StoreError> {
        let region = region.into();
        if region.trim().is_empty() {
            return Err(StoreError::Backend(
                "an AWS region is required for Bedrock embeddings".to_owned(),
            ));
        }
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(region.clone()))
            .load()
            .await;
        Self::from_client(aws_sdk_bedrockruntime::Client::new(&config), model, dialect)
    }

    /// Build from an already configured AWS client.
    ///
    /// The region is read **from the client**, not accepted beside it. It is
    /// half of [`Embedder::revision`], which decides whether a stored vector
    /// belongs to the index being queried — so a region taken as a separate
    /// argument is a second copy of a fact the client already holds, free to
    /// disagree with the service the vectors actually came from. Two indexes
    /// built in different regions would then share one revision and be treated
    /// as comparable.
    ///
    /// # Errors
    ///
    /// If the client carries no region, or a blank one.
    pub fn from_client(
        client: aws_sdk_bedrockruntime::Client,
        model: impl Into<String>,
        dialect: EmbeddingDialect,
    ) -> Result<Self, StoreError> {
        let region = client
            .config()
            .region()
            .map(|region| region.as_ref().trim().to_owned())
            .filter(|region| !region.is_empty())
            .ok_or_else(|| {
                StoreError::Backend(
                    "the Bedrock client carries no region, so an embedding revision cannot name \
                     the service its vectors came from — build it from a config with `.region(..)` \
                     set"
                    .to_owned(),
                )
            })?;
        Ok(Self {
            client,
            model: model.into(),
            region,
            dialect,
            dimensions: None,
        })
    }

    /// Ask Titan for a shortened vector.
    ///
    /// Titan v2 accepts 256, 512 or 1024. Cohere does not take the parameter at
    /// all, so setting it there is refused rather than ignored — a ceiling that
    /// silently does nothing is the shape this crate refuses everywhere else.
    #[must_use]
    pub const fn dimensions(mut self, dimensions: u32) -> Self {
        self.dimensions = Some(dimensions);
        self
    }
}

#[cfg(feature = "bedrock")]
#[async_trait::async_trait]
impl Embedder for BedrockEmbedder {
    /// Region, model and width.
    ///
    /// The **region** is in it because a Bedrock model id names a model, not a
    /// deployment: the same id in two regions is two services, and a vector from
    /// one has no standing in an index built from the other. It is also the fact
    /// a compliance reader most wants on the record.
    fn revision(&self) -> String {
        let base = format!("bedrock:{}/{}", self.region, self.model);
        self.dimensions
            .map_or(base.clone(), |d| format!("{base}@{d}"))
    }

    async fn embed(&self, text: &str) -> Result<Vec<f32>, StoreError> {
        let body = bedrock_body(self.dialect, text, self.dimensions)?;

        let reply = self
            .client
            .invoke_model()
            .model_id(&self.model)
            .content_type("application/json")
            .accept("application/json")
            // `canon`, not `serde_json::to_vec`: the layering guard funnels every
            // byte-producing path through the canonical writer, and canonical
            // JSON is still JSON — sorting the keys costs nothing on the wire
            // and makes this driver's request bytes reproducible, which is the
            // property the rest of the crate already depends on.
            .body(aws_smithy_types::Blob::new(
                crate::core::canon::value_bytes(&body),
            ))
            .send()
            .await
            .map_err(|e| StoreError::Backend(format!("bedrock embeddings: {e}")))?;

        let parsed: serde_json::Value = serde_json::from_slice(reply.body().as_ref())
            .map_err(|e| StoreError::Backend(format!("bedrock embeddings: unreadable: {e}")))?;

        let vector = match self.dialect {
            EmbeddingDialect::Titan => parsed.get("embedding").cloned(),
            // One text was sent, so one row comes back. Taking the first of
            // several would rank this query against somebody else's vector.
            EmbeddingDialect::Cohere => {
                match parsed
                    .get("embeddings")
                    .and_then(|e| e.as_array())
                    .map(Vec::as_slice)
                {
                    Some([only]) => Some(only.clone()),
                    _ => None,
                }
            }
        };
        let Some(serde_json::Value::Array(values)) = vector else {
            return Err(StoreError::Backend(format!(
                "bedrock embeddings: the reply carried no single vector in the \
                 {:?} shape — a declared dialect that does not match the model is \
                 the usual cause: {parsed}",
                self.dialect
            )));
        };
        let vector: Vec<f32> = values.iter().filter_map(json_f32).collect();
        if vector.len() != values.len() || vector.is_empty() {
            return Err(StoreError::Backend(
                "bedrock embeddings: the vector is empty or not all numbers".to_owned(),
            ));
        }
        Ok(vector)
    }
}

/// Embeddings through Google's Gemini API.
///
/// `POST /v1beta/models/{model}:embedContent`, which is not the `OpenAI` wire —
/// different path, different body, different reply — so it gets a driver rather
/// than a base-URL override.
///
/// # Two details that are easy to get silently wrong
///
/// **`taskType` is fixed to `RETRIEVAL_QUERY`, not offered as a knob.** This
/// seam only ever embeds the thing being looked *for*: `SemanticQuery::embedding`
/// is a query by construction, and the documents were embedded by whoever built
/// the index, which is outside this crate. Exposing the choice would let a
/// caller embed a query as a document, which ranks worse and reports nothing.
///
/// **A truncated vector is re-normalised.** `outputDimensionality` uses
/// Matryoshka truncation — the tail is cut off — and the result is no longer
/// unit length. Cosine similarity against a normalised index would then be
/// scaled by whatever magnitude survived, quietly biasing every score. The
/// native width is already normalised and is left alone.
#[cfg(feature = "providers")]
#[derive(Debug, Clone)]
pub struct GeminiEmbedder {
    http: reqwest::Client,
    key: Secret,
    base: String,
    model: String,
    dimensions: Option<u32>,
    egress: Option<crate::core::Egress>,
    timeout: std::time::Duration,
}

#[cfg(feature = "providers")]
impl GeminiEmbedder {
    /// Google's public endpoint.
    pub const DEFAULT_BASE: &'static str = "https://generativelanguage.googleapis.com";

    /// A driver for one Gemini embedding model.
    ///
    /// # Errors
    ///
    /// If the HTTP client cannot be built.
    pub fn new(key: impl Into<String>, model: impl Into<String>) -> Result<Self, StoreError> {
        let http = reqwest::Client::builder()
            .build()
            .map_err(|e| StoreError::Backend(format!("could not build an HTTP client: {e}")))?;
        Ok(Self {
            http,
            key: Secret::new(key),
            base: Self::DEFAULT_BASE.to_owned(),
            model: model.into(),
            dimensions: None,
            egress: None,
            timeout: OpenAiEmbedder::DEFAULT_TIMEOUT,
        })
    }

    /// `GEMINI_API_KEY`, falling back to `GOOGLE_API_KEY`.
    ///
    /// Both are in wide use, and a deployment that exported the other one would
    /// otherwise meet an authentication failure naming neither.
    ///
    /// # Errors
    ///
    /// If neither variable is set.
    pub fn from_env(model: impl Into<String>) -> Result<Self, StoreError> {
        let key = std::env::var("GEMINI_API_KEY")
            .or_else(|_| std::env::var("GOOGLE_API_KEY"))
            .map_err(|_| {
                StoreError::Backend("neither GEMINI_API_KEY nor GOOGLE_API_KEY is set".to_owned())
            })?;
        Self::new(key, model)
    }

    /// Point at a different host — a gateway, or a test server.
    #[must_use]
    pub fn base(mut self, base: impl Into<String>) -> Self {
        self.base = base.into();
        self
    }

    /// Ask for a shortened vector, re-normalised.
    #[must_use]
    pub const fn dimensions(mut self, dimensions: u32) -> Self {
        self.dimensions = Some(dimensions);
        self
    }

    /// Restrict where this driver may connect.
    #[must_use]
    pub fn egress(mut self, egress: crate::core::Egress) -> Self {
        self.egress = Some(egress);
        self
    }

    /// Bound connection and response as one operation.
    #[must_use]
    pub const fn timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

#[cfg(feature = "providers")]
#[async_trait::async_trait]
impl Embedder for GeminiEmbedder {
    fn revision(&self) -> String {
        let base = format!("gemini:{}", self.model);
        self.dimensions
            .map_or(base.clone(), |d| format!("{base}@{d}"))
    }

    async fn embed(&self, text: &str) -> Result<Vec<f32>, StoreError> {
        if let Some(egress) = &self.egress {
            let host = reqwest::Url::parse(&self.base)
                .ok()
                .and_then(|u| u.host_str().map(ToOwned::to_owned));
            egress
                .permits(host.as_deref())
                .map_err(|e| StoreError::Backend(e.to_string()))?;
        }

        let mut body = serde_json::json!({
            "content": { "parts": [{ "text": text }] },
            "taskType": "RETRIEVAL_QUERY",
        });
        if let Some(dimensions) = self.dimensions {
            body["outputDimensionality"] = serde_json::json!(dimensions);
        }

        let url = format!(
            "{}/v1beta/models/{}:embedContent",
            self.base.trim_end_matches('/'),
            self.model
        );
        // The header form rather than a `?key=` query parameter: a URL reaches
        // proxy logs and crash reports, and a key in one is a key disclosed.
        let response = self
            .http
            .post(&url)
            .timeout(self.timeout)
            .header("x-goog-api-key", self.key.expose())
            .json(&body)
            .send()
            .await
            .map_err(|e| StoreError::Backend(format!("{url}: {e}")))?;
        let status = response.status();
        let text_body = response
            .text()
            .await
            .map_err(|e| StoreError::Backend(format!("{url}: unreadable reply: {e}")))?;
        if !status.is_success() {
            return Err(StoreError::Backend(format!(
                "{url}: embedContent returned {status}: {text_body}"
            )));
        }

        let parsed: serde_json::Value = serde_json::from_str(&text_body)
            .map_err(|e| StoreError::Backend(format!("{url}: unreadable reply: {e}")))?;
        let Some(serde_json::Value::Array(values)) = parsed
            .get("embedding")
            .and_then(|e| e.get("values"))
            .cloned()
        else {
            return Err(StoreError::Backend(format!(
                "{url}: the reply carried no embedding.values: {parsed}"
            )));
        };
        let mut vector: Vec<f32> = values.iter().filter_map(json_f32).collect();
        if vector.len() != values.len() || vector.is_empty() {
            return Err(StoreError::Backend(format!(
                "{url}: the vector is empty or not all numbers"
            )));
        }

        // Matryoshka truncation cuts the tail, so a shortened vector is no
        // longer unit length and cosine against a normalised index would be
        // scaled by whatever magnitude happened to survive. The native width
        // arrives normalised and is left exactly as it came.
        if self.dimensions.is_some() {
            let norm = vector.iter().map(|v| v * v).sum::<f32>().sqrt();
            // Refused rather than skipped. A zero-magnitude vector has no
            // direction, so cosine against it is `0/0` — and a guard that
            // merely skipped normalisation would hand one straight back, to
            // fail several layers away as "the retriever returned a non-finite
            // score", naming the retriever for the driver's answer. Refusing
            // also makes the guard falsifiable: skipping is indistinguishable
            // from dividing by zero unless something produces the zero vector.
            //
            // `is_finite` as well as `> 0.0`: every component is finite by
            // `json_f32`, but a sum of squares is not, and dividing by an
            // infinite norm would answer with a vector of zeros — the same
            // directionless value, arrived at silently.
            if !norm.is_finite() || norm <= 0.0 {
                return Err(StoreError::Backend(format!(
                    "{url}: the vector has no usable magnitude ({norm}), so there \
                     is no direction to rank against"
                )));
            }
            for v in &mut vector {
                *v /= norm;
            }
        }
        Ok(vector)
    }
}

#[cfg(all(test, feature = "bedrock"))]
mod bedrock_dialect_tests {
    use super::{EmbeddingDialect, bedrock_body};

    /// Each dialect sends the body its vendor actually takes.
    ///
    /// The mapping is declared rather than sniffed from the model id, so nothing
    /// downstream can notice it being wrong: Titan's `inputText` sent to Cohere
    /// is a 400 blaming the caller, and — worse — Cohere's `embeddings[0]` read
    /// as Titan's `embedding` would yield a vector of the wrong rank that ranks
    /// against nothing.
    #[test]
    fn each_dialect_sends_its_own_shape() {
        let titan = bedrock_body(EmbeddingDialect::Titan, "refund policy", Some(512))
            .expect("titan takes a width");
        assert_eq!(titan["inputText"], "refund policy");
        assert_eq!(titan["dimensions"], 512);

        let cohere = bedrock_body(EmbeddingDialect::Cohere, "refund policy", None).expect("cohere");
        assert_eq!(cohere["texts"][0], "refund policy");
        assert_eq!(
            cohere["input_type"], "search_query",
            "this seam embeds the thing being looked *for*; embedding it as a \
             document ranks worse and reports nothing"
        );
    }

    /// A width Cohere has no place for is refused, not dropped.
    ///
    /// It would otherwise reach `revision()` — and therefore the effect key —
    /// while never reaching the wire, so two runs with different declared widths
    /// would have different identities and identical vectors.
    #[test]
    fn cohere_refuses_a_width_it_cannot_send() {
        let err = bedrock_body(EmbeddingDialect::Cohere, "x", Some(512))
            .expect_err("a width Cohere cannot send was accepted");
        assert!(err.to_string().contains("no `dimensions`"), "{err}");
    }
}

#[cfg(test)]
mod narrowing_tests {
    use super::json_f32;

    /// A component `f32` cannot hold is refused, not turned into infinity.
    ///
    /// Both halves, because a `None`-for-everything change would satisfy the
    /// negative one perfectly and reject every real embedding: the ordinary
    /// values must still narrow, including one that loses precision, since
    /// precision loss *is* the contract and range loss is not.
    #[test]
    fn a_component_no_f32_can_hold_is_refused_rather_than_infinite() {
        // `1e39` is an ordinary JSON number — `serde_json` refuses only what no
        // `f64` can hold — and `1e39 as f32` is `inf`. The obvious narrowing
        // returned `Some(inf)`, which the caller's length check cannot see.
        for out_of_range in ["1e39", "-1e39", "1e300"] {
            let value: serde_json::Value = serde_json::from_str(out_of_range).expect("valid JSON");
            assert_eq!(
                json_f32(&value),
                None,
                "{out_of_range} narrowed to a non-finite component; journaled as \
                 `null` it would share an effect key with every other one"
            );
        }

        assert_eq!(json_f32(&serde_json::json!(1.0)), Some(1.0));
        assert_eq!(json_f32(&serde_json::json!(-0.0321)), Some(-0.0321));
        assert_eq!(
            json_f32(&serde_json::json!(0.123_456_789_012_345_68_f64)),
            Some(0.123_456_79),
            "precision loss is the contract; range loss is the defect"
        );
        assert_eq!(json_f32(&serde_json::json!("0.5")), None);
    }
}

#[cfg(all(test, feature = "bedrock"))]
mod bedrock_reply_tests {
    use super::{BedrockEmbedder, EmbeddingDialect};
    use crate::memory::Embedder as _;

    /// A Bedrock client whose one answer is `body`.
    ///
    /// The request builder had a test and the **response reader** had none, so a
    /// mutation sweep replaced the whole of `embed` with `Ok(vec![1.0])` and the
    /// suite stayed green. That is the shape the media-block work already named:
    /// a producer and a consumer each tested against hand-written JSON, with
    /// nothing feeding one to the other, so a renamed key breaks the driver and
    /// no test.
    fn embedder(dialect: EmbeddingDialect, body: &'static str) -> BedrockEmbedder {
        let config = aws_sdk_bedrockruntime::Config::builder()
            .region(aws_config::Region::new("eu-central-1"))
            .credentials_provider(aws_sdk_bedrockruntime::config::Credentials::for_tests())
            .behavior_version_latest()
            .http_client(aws_smithy_http_client::test_util::infallible_client_fn(
                move |_req| {
                    http::Response::builder()
                        .status(200)
                        .header("content-type", "application/json")
                        .body(body)
                        .unwrap()
                },
            ))
            .build();
        BedrockEmbedder::from_client(
            aws_sdk_bedrockruntime::Client::from_conf(config),
            "amazon.titan-embed-text-v2:0",
            dialect,
        )
        .expect("a client with a region")
    }

    /// Each dialect reads the shape its vendor answers with.
    #[tokio::test]
    async fn each_dialect_reads_its_own_reply() {
        let titan = embedder(EmbeddingDialect::Titan, r#"{"embedding":[0.25,-0.5,0.75]}"#)
            .embed("refund policy")
            .await
            .expect("titan reply");
        assert_eq!(titan, vec![0.25, -0.5, 0.75]);

        let cohere = embedder(EmbeddingDialect::Cohere, r#"{"embeddings":[[1.0,0.0]]}"#)
            .embed("refund policy")
            .await
            .expect("cohere reply");
        assert_eq!(cohere, vec![1.0, 0.0]);
    }

    /// Every reply this driver cannot honestly read is refused.
    ///
    /// Each row is a different way to be wrong, and each is one a downstream
    /// index would not notice: a vector of the wrong rank ranks against
    /// nothing, a component that is not a number silently disappears from a
    /// `filter_map`, and more than one row means the query was ranked against
    /// somebody else's text.
    #[tokio::test]
    async fn a_reply_this_dialect_cannot_read_is_refused() {
        for (dialect, body, what) in [
            (
                EmbeddingDialect::Titan,
                r#"{"embeddings":[[1.0]]}"#,
                "Cohere's shape read as Titan's",
            ),
            (
                EmbeddingDialect::Cohere,
                r#"{"embedding":[1.0]}"#,
                "Titan's shape read as Cohere's",
            ),
            (
                EmbeddingDialect::Cohere,
                r#"{"embeddings":[[1.0],[2.0]]}"#,
                "two rows for one text",
            ),
            (
                EmbeddingDialect::Titan,
                r#"{"embedding":[]}"#,
                "an empty vector, which no index can rank against",
            ),
            (
                EmbeddingDialect::Titan,
                r#"{"embedding":[1.0,"nan",2.0]}"#,
                "a component that is not a number",
            ),
            (
                EmbeddingDialect::Titan,
                r#"{"embedding":[1.0,1e39]}"#,
                "a component no f32 can hold, which narrows to infinity",
            ),
        ] {
            let err = embedder(dialect, body)
                .embed("x")
                .await
                .expect_err(&format!("accepted {what}"));
            assert!(
                matches!(err, crate::core::StoreError::Backend(_)),
                "{what}: {err}"
            );
        }
    }

    /// The revision names the region, and that is not decoration.
    ///
    /// A Bedrock model id names a model, not a deployment: the same id in two
    /// regions is two services, and a vector from one has no standing in an
    /// index built from the other. It sits in the retrieval effect's key, so a
    /// revision that dropped the region would let a replay read one region's
    /// vector as the other's — and it is the fact a compliance reader most
    /// wants on the record.
    #[test]
    fn the_revision_names_the_region_the_model_and_the_width() {
        let base = |region| {
            let config = aws_sdk_bedrockruntime::Config::builder()
                .region(aws_config::Region::new(region))
                .behavior_version_latest()
                .http_client(aws_smithy_http_client::test_util::infallible_client_fn(
                    |_req| http::Response::builder().status(200).body("").unwrap(),
                ))
                .build();
            BedrockEmbedder::from_client(
                aws_sdk_bedrockruntime::Client::from_conf(config),
                "amazon.titan-embed-text-v2:0",
                EmbeddingDialect::Titan,
            )
            .expect("a client with a region")
        };

        assert_eq!(
            base("eu-central-1").revision(),
            "bedrock:eu-central-1/amazon.titan-embed-text-v2:0"
        );
        assert_ne!(
            base("eu-central-1").revision(),
            base("us-east-1").revision(),
            "two regions are two services and shared one effect identity"
        );
        assert_eq!(
            base("eu-central-1").dimensions(256).revision(),
            "bedrock:eu-central-1/amazon.titan-embed-text-v2:0@256",
            "a width that does not reach the revision lets two geometries share an index"
        );
    }

    /// A client that cannot name its region cannot revision its vectors.
    ///
    /// The assertions above are the positive half: each revision names the
    /// region its client resolves against, because there is no other place for
    /// it to come from. This is the half that refuses the client which would
    /// otherwise revision every vector under an empty region — one index name
    /// shared by every deployment that forgot to configure one.
    #[test]
    fn a_client_without_a_region_cannot_build_an_embedder() {
        let stub = |region: Option<&str>| {
            let mut config = aws_sdk_bedrockruntime::Config::builder()
                .behavior_version_latest()
                .http_client(aws_smithy_http_client::test_util::infallible_client_fn(
                    |_req| http::Response::builder().status(200).body("").unwrap(),
                ));
            if let Some(region) = region {
                config = config.region(aws_config::Region::new(region.to_owned()));
            }
            BedrockEmbedder::from_client(
                aws_sdk_bedrockruntime::Client::from_conf(config.build()),
                "amazon.titan-embed-text-v2:0",
                EmbeddingDialect::Titan,
            )
        };

        for absent in [None, Some("   ")] {
            let err = stub(absent).expect_err("an embedder with no region was built");
            assert!(
                err.to_string().contains("region"),
                "the refusal must name the missing region, got: {err}"
            );
        }
        stub(Some("eu-central-1")).expect("a client carrying a region was refused");
    }
}
