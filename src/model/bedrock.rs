//! Amazon Bedrock Runtime through the provider-neutral Converse API.
//!
//! `ConverseStream` is the default so partial generation can be classified and
//! metered. Buffered mode is an explicit opt-out.

use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use aws_sdk_bedrockruntime::Client;
use aws_sdk_bedrockruntime::config::Region;
use aws_sdk_bedrockruntime::operation::converse::ConverseError;
use aws_sdk_bedrockruntime::types::{
    ContentBlock, ConversationRole, DocumentBlock, DocumentFormat, DocumentSource, ImageBlock,
    ImageFormat, ImageSource, InferenceConfiguration, JsonSchemaDefinition, Message, OutputConfig,
    OutputFormat, OutputFormatStructure, OutputFormatType, ReasoningContentBlock,
    ReasoningTextBlock, SpecificToolChoice, SystemContentBlock, Tool, ToolChoice,
    ToolConfiguration, ToolInputSchema, ToolResultBlock, ToolResultContentBlock, ToolResultStatus,
    ToolSpecification, ToolUseBlock,
};
use aws_smithy_types::{Blob, Document, Number};
use base64::Engine as _;
use serde_json::{Value, json};

use super::{
    Completion, ModelError, ModelId, ModelProvider, ProviderContinuation, Request, SchemaMode,
    ToolDeclaration, ToolExchange, Usage,
};

const RESPOND_TOOL: &str = "__agentplane_respond";

fn decoded_media(
    block: &Value,
    expected_type: &str,
    model: &ModelId,
) -> Result<(String, Vec<u8>), ModelError> {
    let actual = block
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if actual != expected_type {
        return Err(Bedrock::refused(
            model,
            format!("unsupported Bedrock content block '{actual}'"),
        ));
    }
    let media_type = block
        .get("media_type")
        .and_then(Value::as_str)
        .ok_or_else(|| Bedrock::refused(model, "Bedrock media block has no media_type"))?;
    let data = block
        .get("data")
        .and_then(Value::as_str)
        .ok_or_else(|| Bedrock::refused(model, "Bedrock media block has no inline base64 data"))?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(data)
        .map_err(|error| {
            Bedrock::refused(model, format!("invalid Bedrock media base64: {error}"))
        })?;
    Ok((media_type.to_owned(), bytes))
}

pub(crate) fn content_from_prompt_json(
    block: &Value,
    model: &ModelId,
) -> Result<ContentBlock, ModelError> {
    if let Some(text) = block.get("text").and_then(Value::as_str) {
        return Ok(ContentBlock::Text(text.to_owned()));
    }
    match block.get("type").and_then(Value::as_str) {
        Some("image") => {
            let (media_type, bytes) = decoded_media(block, "image", model)?;
            let format = match media_type.as_str() {
                "image/gif" => ImageFormat::Gif,
                "image/jpeg" => ImageFormat::Jpeg,
                "image/png" => ImageFormat::Png,
                "image/webp" => ImageFormat::Webp,
                other => {
                    return Err(Bedrock::refused(
                        model,
                        format!("Bedrock does not support image media type '{other}'"),
                    ));
                }
            };
            ImageBlock::builder()
                .format(format)
                .source(ImageSource::Bytes(Blob::new(bytes)))
                .build()
                .map(ContentBlock::Image)
                .map_err(|error| Bedrock::refused(model, error.to_string()))
        }
        Some("document") => {
            let (media_type, bytes) = decoded_media(block, "document", model)?;
            let format = match media_type.as_str() {
                "text/csv" => DocumentFormat::Csv,
                "application/msword" => DocumentFormat::Doc,
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => {
                    DocumentFormat::Docx
                }
                "text/html" => DocumentFormat::Html,
                "text/markdown" => DocumentFormat::Md,
                "application/pdf" => DocumentFormat::Pdf,
                "text/plain" => DocumentFormat::Txt,
                "application/vnd.ms-excel" => DocumentFormat::Xls,
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" => {
                    DocumentFormat::Xlsx
                }
                other => {
                    return Err(Bedrock::refused(
                        model,
                        format!("Bedrock does not support document media type '{other}'"),
                    ));
                }
            };
            DocumentBlock::builder()
                .format(format)
                // Neutral and constant: Bedrock warns that document names are
                // prompt-injection-bearing model input.
                .name("document")
                .source(DocumentSource::Bytes(Blob::new(bytes)))
                .build()
                .map(ContentBlock::Document)
                .map_err(|error| Bedrock::refused(model, error.to_string()))
        }
        Some(other) => Err(Bedrock::refused(
            model,
            format!("unsupported Bedrock content block '{other}'"),
        )),
        None => Err(Bedrock::refused(
            model,
            "Bedrock content block has neither text nor a supported type",
        )),
    }
}

/// Amazon Bedrock Runtime's Converse driver.
///
/// # This driver has no egress allowlist, and that is a gap rather than a design
///
/// Every other model driver here takes an [`Egress`](crate::core::Egress) and
/// refuses a base URL the deployment never granted. This one cannot: it is
/// handed a built AWS `Client`, and the SDK exposes no way to read back the
/// endpoint that client will actually reach. A check against the endpoint
/// *derived* from the region would pass while an endpoint override sent every
/// call somewhere else — a control that looks like one and is not, which is the
/// same reason this crate ships no `Egress::allow_all`.
///
/// What stands in its place is narrower and worth knowing exactly: the region
/// is on the record. It is read from the client rather than accepted beside it,
/// and it enters [`ModelProvider::request_profile`], so it is digest-covered
/// and a change of region is replay divergence. That says *which service the
/// client was configured for*. It does not say the call went there, and nothing
/// in this driver does. A deployment that needs the destination constrained
/// constrains it where the SDK does — a VPC endpoint, an egress proxy, or an
/// IAM policy — not here.
#[derive(Clone)]
pub struct Bedrock {
    client: Client,
    region: String,
    timeout: Duration,
    schema_mode: SchemaMode,
    stream: bool,
    /// The deployment's Bedrock guardrail, when it has one.
    ///
    /// Passed through rather than reimplemented. Content classification is a
    /// specialist's job — this crate ships no policy evaluator and no tracing
    /// exporter for the same reason — and a deployment on Bedrock already owns
    /// a guardrail, versioned and administered where its compliance people can
    /// see it. What the runtime owns is everything *around* it: the choice is
    /// in the request profile, so it is digest-covered and replay-visible, and
    /// an intervention is a **metered refusal** rather than an answer.
    guardrail: Option<Guardrail>,
    /// Which model family's reasoning dialect this driver instance speaks.
    ///
    /// Absent by default, and absent means *refuse* — see
    /// [`ReasoningDialect`].
    reasoning: Option<ReasoningDialect>,
}

/// How a Bedrock model family spells "think harder".
///
/// Converse is a **provider-neutral** envelope over a model zoo that does not
/// agree on this: Anthropic takes adaptive thinking, Nova 2 takes a
/// `reasoningConfig` in `additionalModelRequestFields`, and several families
/// have no such control at all. There is therefore no mapping this driver can
/// derive from a Converse request, which is why an undeclared dialect refuses
/// rather than guessing — silently sending a different effort than the one the
/// manifest declared would make a digest-covered control advisory.
///
/// It is **declared, never sniffed from the model id**. Cross-region inference
/// profiles prefix the id (`us.amazon.nova-2-lite-v1:0`), a substring match
/// would bind behaviour to a naming convention AWS owns, and this crate already
/// refuses to decide a control by matching on a string elsewhere. One driver
/// instance therefore serves one family, exactly as a guardrail does.
///
/// The choice is in the **request profile**, so it is effect identity: moving a
/// deployment from one dialect to another is replay divergence rather than a
/// quiet change in what governed the call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReasoningDialect {
    /// Amazon Nova 2's extended thinking.
    ///
    /// Rendered as `additionalModelRequestFields.reasoningConfig`, with
    /// `type: "enabled"` and `maxReasoningEffort` of `low`, `medium` or `high`
    /// — the three levels AWS documents and the only three it accepts.
    ///
    /// [`ReasoningEffort::None`](crate::model::ReasoningEffort::None) sends
    /// `type: "disabled"`, which is Nova's own default and is *not* the same as
    /// sending nothing: it is a deployment stating that this call must not
    /// reason, and stating it puts the fact in the journal.
    ///
    /// `Minimal`, `XHigh` and `Max` are **refused**, because Nova has no
    /// counterpart and collapsing them into `low` or `high` is the silent
    /// substitution this seam exists to prevent. That is the same rule the
    /// Anthropic driver follows for the levels adaptive thinking cannot
    /// express.
    ///
    /// One constraint AWS documents is satisfied here by construction: Nova
    /// refuses `temperature`, `topP` and `topK` alongside `maxReasoningEffort:
    /// "high"`, and this driver has never sent any of them — sampling
    /// parameters are absent from the request profile, so they cannot be part
    /// of effect identity, so they are not sent.
    Nova,
}

/// Which Bedrock guardrail to apply, and whether to ask for its trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Guardrail {
    pub identifier: String,
    /// Pinned, never `DRAFT`-by-default: a guardrail version is part of what
    /// governed this call, and a floating pointer would make two runs under
    /// "the same" configuration mean different things.
    pub version: String,
    /// Ask Bedrock to return why it intervened.
    ///
    /// Off by default. The trace names the policy and the matched category,
    /// which is exactly the classification the gate protects — useful in a
    /// journal an operator reads, and a map for a prober if it ever reaches a
    /// model. It never does: an intervention leaves this driver as an error.
    pub trace: bool,
}

impl Guardrail {
    #[must_use]
    pub fn new(identifier: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            identifier: identifier.into(),
            version: version.into(),
            trace: false,
        }
    }

    /// Ask for the intervention trace, which is journaled and never shown to a
    /// model.
    #[must_use]
    pub const fn with_trace(mut self) -> Self {
        self.trace = true;
        self
    }

    /// The streaming form.
    ///
    /// `SYNCHRONOUS` deliberately, which is Bedrock's *blocking* mode: the
    /// service assesses each chunk before releasing it. The alternative,
    /// `ASYNCHRONOUS`, streams first and intervenes afterwards — lower
    /// latency, and it means blocked content has already reached the caller
    /// by the time the guardrail objects. A control that arrives after the
    /// thing it was installed to prevent is not one.
    fn stream_config(&self) -> aws_sdk_bedrockruntime::types::GuardrailStreamConfiguration {
        use aws_sdk_bedrockruntime::types::{
            GuardrailStreamConfiguration, GuardrailStreamProcessingMode, GuardrailTrace,
        };
        GuardrailStreamConfiguration::builder()
            .guardrail_identifier(&self.identifier)
            .guardrail_version(&self.version)
            .trace(if self.trace {
                GuardrailTrace::Enabled
            } else {
                GuardrailTrace::Disabled
            })
            .stream_processing_mode(GuardrailStreamProcessingMode::Sync)
            .build()
    }

    fn config(&self) -> aws_sdk_bedrockruntime::types::GuardrailConfiguration {
        use aws_sdk_bedrockruntime::types::{GuardrailConfiguration, GuardrailTrace};
        GuardrailConfiguration::builder()
            .guardrail_identifier(&self.identifier)
            .guardrail_version(&self.version)
            .trace(if self.trace {
                GuardrailTrace::Enabled
            } else {
                GuardrailTrace::Disabled
            })
            .build()
    }
}

impl std::fmt::Debug for Bedrock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bedrock")
            .field("region", &self.region)
            .field("timeout", &self.timeout)
            .field("schema_mode", &self.schema_mode)
            .field("stream", &self.stream)
            .field("guardrail", &self.guardrail)
            .finish_non_exhaustive()
    }
}

impl Bedrock {
    /// Load the standard AWS credential chain for this region.
    ///
    /// # Errors
    ///
    /// If the region is blank, or the client it builds carries none.
    pub async fn from_env(region: impl Into<String>) -> Result<Self, String> {
        let region = region.into();
        if region.trim().is_empty() {
            return Err("an AWS region is required for Bedrock".to_owned());
        }
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(Region::new(region))
            .load()
            .await;
        Self::from_client(Client::new(&config))
    }

    /// Build from an already configured AWS client.
    ///
    /// The region is read **from the client**, not accepted beside it. It is
    /// what [`ModelProvider::request_profile`] attests, and that profile is
    /// effect identity — so a region taken as a separate argument is a second
    /// copy of a fact the client already holds, free to disagree with the
    /// endpoint the SDK actually reaches. The journal would then attest a
    /// destination the calls never went to, and a replay would compare against
    /// it, with nothing anywhere able to notice.
    ///
    /// # Errors
    ///
    /// If the client carries no region, or a blank one. A client that cannot
    /// name its region cannot resolve a Bedrock endpoint either, so this is a
    /// wiring mistake refused where it is written rather than at the far end of
    /// a run — and recording an empty region would put a fiction on the record
    /// instead.
    pub fn from_client(client: Client) -> Result<Self, String> {
        let region = client
            .config()
            .region()
            .map(|region| region.as_ref().trim().to_owned())
            .filter(|region| !region.is_empty())
            .ok_or_else(|| {
                "the Bedrock client carries no region, so there is nothing true to put in the \
                 request profile — build it from a config with `.region(..)` set"
                    .to_owned()
            })?;
        Ok(Self {
            client,
            region,
            timeout: Duration::from_mins(5),
            schema_mode: SchemaMode::Native,
            stream: true,
            guardrail: None,
            reasoning: None,
        })
    }

    /// Apply a Bedrock guardrail to every call this driver makes.
    ///
    /// Passed through rather than reimplemented: content classification is a
    /// specialist's job, and a deployment on Bedrock already owns a guardrail
    /// administered where its compliance people can see it. What the runtime
    /// owns is everything around it — the choice enters
    /// [`ModelProvider::request_profile`], so it is digest-covered and
    /// replay-visible, and an intervention is a **metered refusal** rather
    /// than an answer.
    #[must_use]
    pub fn guardrail(mut self, guardrail: Guardrail) -> Self {
        self.guardrail = Some(guardrail);
        self
    }

    /// Declare which model family's reasoning dialect this driver speaks.
    ///
    /// Without it, a request carrying a `reasoning_effort` is **refused**:
    /// Converse is one envelope over families that spell reasoning differently
    /// or not at all, so there is nothing for this driver to derive. See
    /// [`ReasoningDialect`] for why it is declared rather than read off the
    /// model id, and for which efforts each dialect can carry faithfully.
    ///
    /// The dialect enters [`ModelProvider::request_profile`], so changing it is
    /// replay divergence rather than a quiet change in what governed the call.
    #[must_use]
    pub const fn reasoning(mut self, dialect: ReasoningDialect) -> Self {
        self.reasoning = Some(dialect);
        self
    }

    /// The `additionalModelRequestFields` this call's reasoning effort needs.
    ///
    /// `None` when the request asked for no reasoning at all, which is the
    /// ordinary case and must send nothing — an empty `reasoningConfig` is not
    /// the same request as no `reasoningConfig`.
    ///
    /// Built once and handed to **both** request paths. The guardrail above is
    /// the precedent and the reason: a control rendered separately on the
    /// buffered and streaming paths is one where only the half nobody exercises
    /// is wrong, and a `stream: true` deployment loses it silently.
    ///
    /// # Errors
    ///
    /// If no dialect is declared, or the declared one cannot carry this effort
    /// faithfully.
    fn reasoning_config(
        &self,
        model: &ModelId,
        effort: Option<super::ReasoningEffort>,
    ) -> Result<Option<Document>, ModelError> {
        use super::ReasoningEffort as E;

        let Some(effort) = effort else {
            return Ok(None);
        };
        let Some(dialect) = self.reasoning else {
            return Err(Self::refused(
                model,
                "Bedrock Converse has no provider-neutral reasoning-effort mapping, because one \
                 envelope covers families that spell reasoning differently or not at all. \
                 Declare which one this driver speaks — `Bedrock::from_client(..).reasoning(\
                 ReasoningDialect::Nova)` — rather than having the driver guess and silently \
                 change the effort the manifest declared",
            ));
        };
        match dialect {
            ReasoningDialect::Nova => {
                // Refused rather than collapsed. Nova documents exactly three
                // levels, and folding `Max` into `high` would answer a request
                // for the most thorough reasoning available with the third of
                // three — a substitution nothing downstream could see, on a
                // value that is digest-covered and therefore claims to describe
                // what actually governed the call.
                let level = match effort {
                    E::None => {
                        return Ok(Some(document_from_json(
                            &json!({ "reasoningConfig": { "type": "disabled" } }),
                        )));
                    }
                    E::Low => "low",
                    E::Medium => "medium",
                    E::High => "high",
                    E::Minimal | E::XHigh | E::Max => {
                        return Err(Self::refused(
                            model,
                            format!(
                                "Amazon Nova extended thinking has no counterpart for reasoning \
                                 effort '{}' — it accepts low, medium and high. Declare one of \
                                 those, or none to disable reasoning explicitly",
                                effort.as_str()
                            ),
                        ));
                    }
                };
                Ok(Some(document_from_json(&json!({
                    "reasoningConfig": { "type": "enabled", "maxReasoningEffort": level },
                }))))
            }
        }
    }

    /// Bound the complete Converse operation.
    #[must_use]
    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Choose native constrained output or the forced-tool compatibility path.
    #[must_use]
    pub const fn structured_via(mut self, mode: SchemaMode) -> Self {
        self.schema_mode = mode;
        self
    }

    /// Use buffered Converse instead of `ConverseStream`.
    #[must_use]
    pub const fn buffered(mut self) -> Self {
        self.stream = false;
        self
    }

    fn refused(model: &ModelId, detail: impl Into<String>) -> ModelError {
        ModelError::Refused {
            model: model.clone(),
            detail: detail.into(),
        }
    }

    fn messages(
        model: &ModelId,
        prompt: &Value,
        exchanges: &[ToolExchange],
        continuation: Option<&ProviderContinuation>,
    ) -> Result<Vec<Message>, ModelError> {
        let source = prompt
            .get("messages")
            .unwrap_or_else(|| prompt.get("input").unwrap_or(prompt));
        let mut messages = match source {
            Value::Array(items) => items
                .iter()
                .map(|item| Self::message_from_value(model, item))
                .collect::<Result<Vec<_>, _>>()?,
            Value::String(text) => vec![Self::text_message(ConversationRole::User, text, model)?],
            other => vec![Self::text_message(
                ConversationRole::User,
                &other.to_string(),
                model,
            )?],
        };

        if exchanges.is_empty() {
            return Ok(messages);
        }

        if let Some(state) = continuation {
            if state.provider != "bedrock" {
                return Err(Self::refused(
                    model,
                    format!(
                        "a '{}' continuation cannot be sent to Bedrock",
                        state.provider
                    ),
                ));
            }
            let transcript = state
                .state
                .as_array()
                .ok_or_else(|| Self::refused(model, "the Bedrock continuation is not an array"))?
                .iter()
                .map(|message| continuation_message_from_json(message, model))
                .collect::<Result<Vec<_>, _>>()?;
            messages.extend(transcript);
        } else {
            let assistant = exchanges
                .iter()
                .map(|exchange| {
                    Ok(ContentBlock::ToolUse(
                        ToolUseBlock::builder()
                            .tool_use_id(exchange.call.id.clone())
                            .name(exchange.call.name.clone())
                            .input(document_from_json(&exchange.call.arguments))
                            .build()
                            .map_err(|error| Self::refused(model, error.to_string()))?,
                    ))
                })
                .collect::<Result<Vec<_>, ModelError>>()?;
            messages.push(
                Message::builder()
                    .role(ConversationRole::Assistant)
                    .set_content(Some(assistant))
                    .build()
                    .map_err(|error| Self::refused(model, error.to_string()))?,
            );
        }

        messages.push(tool_results_message(exchanges, model)?);
        Ok(messages)
    }

    fn message_from_value(model: &ModelId, value: &Value) -> Result<Message, ModelError> {
        let object = value
            .as_object()
            .ok_or_else(|| Self::refused(model, "a Bedrock message must be an object"))?;
        let role = match object.get("role").and_then(Value::as_str) {
            Some("user") => ConversationRole::User,
            Some("assistant") => ConversationRole::Assistant,
            Some(other) => {
                return Err(Self::refused(
                    model,
                    format!("unsupported Bedrock message role '{other}'"),
                ));
            }
            None => return Err(Self::refused(model, "a Bedrock message has no role")),
        };
        let content = object
            .get("content")
            .ok_or_else(|| Self::refused(model, "a Bedrock message has no content"))?;
        match content {
            Value::String(text) => Self::text_message(role, text, model),
            Value::Array(blocks) => {
                let blocks = blocks
                    .iter()
                    .map(|block| content_from_prompt_json(block, model))
                    .collect::<Result<Vec<_>, ModelError>>()?;
                Message::builder()
                    .role(role)
                    .set_content(Some(blocks))
                    .build()
                    .map_err(|error| Self::refused(model, error.to_string()))
            }
            _ => Err(Self::refused(
                model,
                "Bedrock message content must be text or text blocks",
            )),
        }
    }

    fn text_message(
        role: ConversationRole,
        text: &str,
        model: &ModelId,
    ) -> Result<Message, ModelError> {
        Message::builder()
            .role(role)
            .content(ContentBlock::Text(text.to_owned()))
            .build()
            .map_err(|error| Self::refused(model, error.to_string()))
    }

    fn tool_config(
        model: &ModelId,
        schema: Option<&Value>,
        tools: &[ToolDeclaration],
        mode: SchemaMode,
    ) -> Result<Option<ToolConfiguration>, ModelError> {
        if schema.is_some() && mode == SchemaMode::ForcedTool && !tools.is_empty() {
            return Err(Self::refused(
                model,
                "Bedrock Converse obtains structured output by forcing a synthetic tool, so a \
                 response schema cannot be combined with callable tools",
            ));
        }
        let mut builder = ToolConfiguration::builder();
        if let Some(schema) = schema.filter(|_| mode == SchemaMode::ForcedTool) {
            builder = builder
                .tools(tool(
                    RESPOND_TOOL,
                    "Return the answer in the required shape.",
                    schema,
                    model,
                )?)
                .tool_choice(ToolChoice::Tool(
                    SpecificToolChoice::builder()
                        .name(RESPOND_TOOL)
                        .build()
                        .map_err(|error| Self::refused(model, error.to_string()))?,
                ));
        } else {
            for declaration in tools {
                builder = builder.tools(tool(
                    &declaration.name,
                    &declaration.description,
                    &declaration.parameters,
                    model,
                )?);
            }
        }
        if (schema.is_none() || mode == SchemaMode::Native) && tools.is_empty() {
            Ok(None)
        } else {
            builder
                .build()
                .map(Some)
                .map_err(|error| Self::refused(model, error.to_string()))
        }
    }

    fn output_config(
        model: &ModelId,
        schema: Option<&Value>,
        mode: SchemaMode,
    ) -> Result<Option<OutputConfig>, ModelError> {
        let Some(schema) = schema.filter(|_| mode == SchemaMode::Native) else {
            return Ok(None);
        };
        let definition = JsonSchemaDefinition::builder()
            .schema(schema.to_string())
            .name("agentplane_response")
            .build()
            .map_err(|error| Self::refused(model, error.to_string()))?;
        let format = OutputFormat::builder()
            .r#type(OutputFormatType::JsonSchema)
            .structure(OutputFormatStructure::JsonSchema(definition))
            .build()
            .map_err(|error| Self::refused(model, error.to_string()))?;
        Ok(Some(OutputConfig::builder().text_format(format).build()))
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn complete_streamed(
        &self,
        model: &ModelId,
        prompt: &Value,
        messages: Vec<Message>,
        max_tokens: i32,
        tools: Option<ToolConfiguration>,
        output_config: Option<OutputConfig>,
        reasoning_config: Option<Document>,
        schema: Option<&Value>,
        observer: Option<(&dyn super::ModelStreamObserver, &crate::core::Label)>,
    ) -> Result<Completion, ModelError> {
        let deadline = tokio::time::Instant::now() + self.timeout;
        let mut operation = self
            .client
            .converse_stream()
            .model_id(&model.model)
            .set_messages(Some(messages))
            .inference_config(
                InferenceConfiguration::builder()
                    .max_tokens(max_tokens)
                    .build(),
            )
            .set_tool_config(tools)
            .set_output_config(output_config)
            // Both paths, or the control is one a `stream: true` deployment
            // silently loses — the same rule written twice is the shape where
            // only the half nobody exercises is wrong.
            .set_guardrail_config(self.guardrail.as_ref().map(Guardrail::stream_config))
            .set_additional_model_request_fields(reasoning_config);
        if let Some(system) = prompt.get("system") {
            let text = system.as_str().ok_or_else(|| {
                Self::refused(model, "Bedrock's system instruction must be a string")
            })?;
            operation = operation.system(SystemContentBlock::Text(text.to_owned()));
        }
        let output = tokio::time::timeout_at(deadline, operation.send())
            .await
            .map_err(|_| ModelError::Unavailable {
                model: model.clone(),
                detail: "Bedrock did not start the stream before the request deadline".to_owned(),
            })?
            .map_err(|error| {
                error.as_service_error().map_or_else(
                    || ModelError::Unreachable {
                        model: model.clone(),
                        detail: error.to_string(),
                    },
                    |service| classify_stream_start(model, service),
                )
            })?;

        let mut stream = output.stream;
        let mut accumulator = super::bedrock_stream::Accumulator::new();
        loop {
            let event = tokio::time::timeout_at(deadline, stream.recv())
                .await
                .map_err(|_| severed_stream(model, &accumulator, "the request deadline elapsed"))?
                .map_err(|error| {
                    let detail = error.to_string();
                    classify_stream_event(model, &accumulator, error.as_service_error(), &detail)
                })?;
            let Some(event) = event else {
                break;
            };
            if let aws_sdk_bedrockruntime::types::ConverseStreamOutput::ContentBlockDelta(delta) =
                &event
                && let Some(aws_sdk_bedrockruntime::types::ContentBlockDelta::Text(text)) =
                    delta.delta()
                && let Some((observer, label)) = observer
            {
                observer.event(crate::core::Tainted::with_label(
                    super::ModelStreamEvent::TextDelta(text.clone()),
                    label.clone(),
                ));
            }
            accumulator.event(event);
        }

        if accumulator.stop_reason()
            == Some(&aws_sdk_bedrockruntime::types::StopReason::GuardrailIntervened)
        {
            // Metered and landed, exactly as on the buffered path: the model
            // was invoked and the assessment was billed. A streamed
            // intervention has usually already emitted deltas to a live
            // observer — advisory by contract, and the journal keeps the
            // refusal that is canonical.
            return Err(ModelError::Unusable {
                model: model.clone(),
                // Whatever the stream reported before it was stopped. A
                // guardrail assessed the call, and an assessment is billed —
                // reporting zero would tell the ceiling it was free.
                usage: accumulator.usage().unwrap_or_default(),
                detail: "a Bedrock guardrail intervened on this call".to_owned(),
            });
        }
        let Some(stop_reason) = accumulator.stop_reason().cloned() else {
            return Err(severed_stream(
                model,
                &accumulator,
                "the stream ended before messageStop",
            ));
        };
        let Some(usage) = accumulator.usage() else {
            return Err(severed_stream(
                model,
                &accumulator,
                "the stream ended without usage metadata",
            ));
        };
        if let Some((observer, label)) = observer {
            observer.event(crate::core::Tainted::with_label(
                super::ModelStreamEvent::Usage(usage),
                label.clone(),
            ));
        }
        let blocks = accumulator
            .finish()
            .map_err(|detail| ModelError::Unusable {
                model: model.clone(),
                usage,
                detail,
            })?;
        let message = Message::builder()
            .role(ConversationRole::Assistant)
            .set_content(Some(blocks))
            .build()
            .map_err(|error| ModelError::Unusable {
                model: model.clone(),
                usage,
                detail: error.to_string(),
            })?;
        let token_usage = aws_sdk_bedrockruntime::types::TokenUsage::builder()
            .input_tokens(i32::try_from(usage.input_tokens).unwrap_or(i32::MAX))
            .output_tokens(i32::try_from(usage.output_tokens).unwrap_or(i32::MAX))
            .total_tokens(
                i32::try_from(usage.input_tokens.saturating_add(usage.output_tokens))
                    .unwrap_or(i32::MAX),
            )
            .cache_write_input_tokens(i32::try_from(usage.cache_write_tokens).unwrap_or(i32::MAX))
            .cache_read_input_tokens(i32::try_from(usage.cache_read_tokens).unwrap_or(i32::MAX))
            .build()
            .map_err(|error| ModelError::Unusable {
                model: model.clone(),
                usage,
                detail: error.to_string(),
            })?;
        let assembled = aws_sdk_bedrockruntime::operation::converse::ConverseOutput::builder()
            .output(aws_sdk_bedrockruntime::types::ConverseOutput::Message(
                message,
            ))
            .stop_reason(stop_reason)
            .usage(token_usage)
            .build()
            .map_err(|error| ModelError::Unusable {
                model: model.clone(),
                usage,
                detail: error.to_string(),
            })?;
        Self::interpret(model, schema, self.schema_mode, &assembled)
    }

    #[allow(clippy::too_many_lines)]
    fn interpret(
        model: &ModelId,
        schema: Option<&Value>,
        mode: SchemaMode,
        output: &aws_sdk_bedrockruntime::operation::converse::ConverseOutput,
    ) -> Result<Completion, ModelError> {
        let usage = output.usage().map_or_else(Usage::default, |usage| Usage {
            input_tokens: u64::try_from(usage.input_tokens()).unwrap_or_default(),
            output_tokens: u64::try_from(usage.output_tokens()).unwrap_or_default(),
            cache_write_tokens: u64::try_from(usage.cache_write_input_tokens().unwrap_or_default())
                .unwrap_or_default(),
            cache_read_tokens: u64::try_from(usage.cache_read_input_tokens().unwrap_or_default())
                .unwrap_or_default(),
            minor_units: 0,
        });
        let message = output
            .output()
            .and_then(|value| value.as_message().ok())
            .ok_or_else(|| ModelError::Unusable {
                model: model.clone(),
                usage,
                detail: "Bedrock returned no message output".to_owned(),
            })?;

        let mut text = String::new();
        let mut calls = Vec::new();
        let mut state = Vec::new();
        let mut forced = None;
        for block in message.content() {
            state.push(content_to_json(block, model, usage)?);
            match block {
                ContentBlock::Text(value) => text.push_str(value),
                ContentBlock::ToolUse(value) if value.name() == RESPOND_TOOL => {
                    forced = Some(json_from_document(value.input()));
                }
                ContentBlock::ToolUse(value) => calls.push(super::ToolCall {
                    id: value.tool_use_id().to_owned(),
                    name: value.name().to_owned(),
                    arguments: json_from_document(value.input()),
                }),
                ContentBlock::ReasoningContent(_) => {}
                _ => {
                    return Err(ModelError::Unusable {
                        model: model.clone(),
                        usage,
                        detail: "Bedrock returned a content block this driver cannot preserve"
                            .to_owned(),
                    });
                }
            }
        }

        let emulating = schema.is_some() && mode == SchemaMode::ForcedTool;
        let structured = if emulating {
            let value = forced.ok_or_else(|| ModelError::Unusable {
                model: model.clone(),
                usage,
                detail: "Bedrock did not honor the forced structured-output tool".to_owned(),
            })?;
            if let Some(schema) = schema {
                super::validate_schema(schema, &value).map_err(|detail| ModelError::Unusable {
                    model: model.clone(),
                    usage,
                    detail,
                })?;
            }
            text = value.to_string();
            Some(value)
        } else if schema.is_some() && calls.is_empty() {
            let value = serde_json::from_str(&text).map_err(|error| ModelError::Unusable {
                model: model.clone(),
                usage,
                detail: format!("Bedrock native structured output was not JSON: {error}"),
            })?;
            super::validate_schema(schema.expect("checked above"), &value).map_err(|detail| {
                ModelError::Unusable {
                    model: model.clone(),
                    usage,
                    detail,
                }
            })?;
            Some(value)
        } else {
            None
        };
        if text.is_empty() && calls.is_empty() && structured.is_none() {
            return Err(ModelError::Unusable {
                model: model.clone(),
                usage,
                detail: "Bedrock returned neither text nor a tool call".to_owned(),
            });
        }
        let stop_reason = output.stop_reason().as_str().to_owned();
        let truncated = matches!(
            output.stop_reason(),
            aws_sdk_bedrockruntime::types::StopReason::MaxTokens
                | aws_sdk_bedrockruntime::types::StopReason::ModelContextWindowExceeded
        );
        let continuation = (!calls.is_empty()).then(|| {
            ProviderContinuation::new(
                "bedrock",
                json!([{ "role": "assistant", "content": state }]),
            )
        });
        Ok(Completion {
            text,
            tool_calls: calls,
            usage,
            stop_reason: Some(stop_reason),
            truncated,
            structured,
            continuation,
        })
    }
}

#[async_trait]
impl ModelProvider for Bedrock {
    fn request_profile(&self, _model: &ModelId) -> Value {
        json!({
            "driver": "aws-bedrock-converse/v1",
            "region": self.region,
            "stream": self.stream,
            "schema_mode": match self.schema_mode {
                SchemaMode::Native => "native",
                SchemaMode::ForcedTool => "forced-tool",
            },
            "timeout_ms": self.timeout.as_millis(),
            // Identity, not decoration: turning a guardrail on, off, or to
            // another version changes what governed the call, so a replay of
            // history written under the old configuration reports divergence
            // rather than answering under the new one. The identifier and
            // version only — a guardrail id is configuration, not a secret,
            // and the trace flag changes no request semantics.
            "guardrail": self.guardrail.as_ref().map(|g| json!({
                "id": g.identifier,
                "version": g.version,
            })),
            // Identity for the same reason the guardrail is. The dialect
            // decides how a declared `reasoning_effort` is rendered, so moving
            // a deployment from one to another changes what governed the call
            // — and a replay of history written under the old one reports
            // divergence rather than answering under the new.
            "reasoning_dialect": self.reasoning.map(|d| match d {
                ReasoningDialect::Nova => "nova",
            }),
        })
    }

    async fn complete(&self, request: Request<'_>) -> Result<Completion, ModelError> {
        let Request {
            model,
            prompt,
            max_output_tokens,
            reasoning_effort,
            schema,
            tools,
            exchanges,
            continuation,
            stream,
        } = request;
        super::refuse_provider_side_media(prompt, model)?;
        let reasoning_config = self.reasoning_config(model, reasoning_effort)?;
        let max_tokens = i32::try_from(max_output_tokens)
            .map_err(|_| Self::refused(model, "max_output_tokens exceeds Bedrock's i32 limit"))?;
        let messages = Self::messages(model, prompt, exchanges, continuation)?;
        let tools = Self::tool_config(model, schema, tools, self.schema_mode)?;
        let output_config = Self::output_config(model, schema, self.schema_mode)?;
        if self.stream {
            let streamed = self
                .complete_streamed(
                    model,
                    prompt,
                    messages,
                    max_tokens,
                    tools,
                    output_config,
                    reasoning_config,
                    schema,
                    stream,
                )
                .await?;
            let mut completion = streamed;
            accumulate_continuation(&mut completion, continuation, exchanges);
            return Ok(completion);
        }
        let mut operation = self
            .client
            .converse()
            .model_id(&model.model)
            .set_messages(Some(messages))
            .inference_config(
                InferenceConfiguration::builder()
                    .max_tokens(max_tokens)
                    .build(),
            )
            .set_tool_config(tools)
            .set_output_config(output_config)
            // Both paths, or the control is one a `stream: true` deployment
            // silently loses — the same rule written twice is the shape where
            // only the half nobody exercises is wrong.
            .set_guardrail_config(self.guardrail.as_ref().map(Guardrail::config))
            .set_additional_model_request_fields(reasoning_config);
        if let Some(system) = prompt.get("system") {
            let text = system.as_str().ok_or_else(|| {
                Self::refused(model, "Bedrock's system instruction must be a string")
            })?;
            operation = operation.system(SystemContentBlock::Text(text.to_owned()));
        }

        let result = tokio::time::timeout(self.timeout, operation.send())
            .await
            .map_err(|_| ModelError::Unavailable {
                model: model.clone(),
                detail: format!("Bedrock did not complete within {:?}", self.timeout),
            })?;
        let output = result.map_err(|error| {
            if let Some(service) = error.as_service_error() {
                classify_service(model, service)
            } else {
                ModelError::Unreachable {
                    model: model.clone(),
                    detail: error.to_string(),
                }
            }
        })?;
        let mut completion = Self::interpret(model, schema, self.schema_mode, &output)?;
        if let Some((observer, label)) = stream {
            observer.event(crate::core::Tainted::with_label(
                super::ModelStreamEvent::Usage(completion.usage),
                label.clone(),
            ));
        }
        accumulate_continuation(&mut completion, continuation, exchanges);
        Ok(completion)
    }
}

fn tool_result_json(exchange: &ToolExchange) -> Value {
    json!({
        "type": "tool_result",
        "tool_use_id": exchange.call.id,
        "output": exchange.output,
        "failed": exchange.failed,
    })
}

fn tool_results_message(
    exchanges: &[ToolExchange],
    model: &ModelId,
) -> Result<Message, ModelError> {
    let content = exchanges
        .iter()
        .map(|exchange| tool_result_from_json(&tool_result_json(exchange), model))
        .collect::<Result<Vec<_>, _>>()?;
    Message::builder()
        .role(ConversationRole::User)
        .set_content(Some(content))
        .build()
        .map_err(|error| Bedrock::refused(model, error.to_string()))
}

fn accumulate_continuation(
    completion: &mut Completion,
    prior: Option<&ProviderContinuation>,
    exchanges: &[ToolExchange],
) {
    let Some(current) = completion.continuation.as_mut() else {
        return;
    };
    let mut transcript = prior
        .and_then(|value| value.state.as_array())
        .cloned()
        .unwrap_or_default();
    if !exchanges.is_empty() {
        transcript.push(json!({
            "role": "user",
            "content": exchanges.iter().map(tool_result_json).collect::<Vec<_>>(),
        }));
    }
    if let Some(messages) = current.state.as_array() {
        transcript.extend(messages.iter().cloned());
    }
    current.state = Value::Array(transcript);
}

fn tool(
    name: &str,
    description: &str,
    schema: &Value,
    model: &ModelId,
) -> Result<Tool, ModelError> {
    let specification = ToolSpecification::builder()
        .name(name)
        .description(description)
        .input_schema(ToolInputSchema::Json(document_from_json(schema)))
        .strict(true)
        .build()
        .map_err(|error| Bedrock::refused(model, error.to_string()))?;
    Ok(Tool::ToolSpec(specification))
}

fn classify_service(model: &ModelId, error: &ConverseError) -> ModelError {
    let detail = error.to_string();
    if error.is_throttling_exception() || error.is_model_not_ready_exception() {
        ModelError::RateLimited {
            model: model.clone(),
            detail,
            // The SDK models a throttle as a typed error and does not surface
            // the response headers at this seam, so there is no window to read.
            // Nothing is lost that the caller could have used: the AWS client
            // applies its own adaptive retry beneath this call, and a second
            // schedule stacked on it would multiply rather than add.
            retry_after: None,
        }
    } else if error.is_access_denied_exception()
        || error.is_resource_not_found_exception()
        || error.is_validation_exception()
    {
        ModelError::Refused {
            model: model.clone(),
            detail,
        }
    } else {
        // Buffered Converse does not expose partial usage for timeout, model,
        // service, or unknown failures. It may have generated, so do not claim
        // the request was free or definitely absent.
        ModelError::Unavailable {
            model: model.clone(),
            detail,
        }
    }
}

fn classify_stream_start(
    model: &ModelId,
    error: &aws_sdk_bedrockruntime::operation::converse_stream::ConverseStreamError,
) -> ModelError {
    let detail = error.to_string();
    if error.is_throttling_exception() || error.is_model_not_ready_exception() {
        ModelError::RateLimited {
            model: model.clone(),
            detail,
            // The SDK models a throttle as a typed error and does not surface
            // the response headers at this seam, so there is no window to read.
            // Nothing is lost that the caller could have used: the AWS client
            // applies its own adaptive retry beneath this call, and a second
            // schedule stacked on it would multiply rather than add.
            retry_after: None,
        }
    } else if error.is_access_denied_exception()
        || error.is_resource_not_found_exception()
        || error.is_validation_exception()
    {
        ModelError::Refused {
            model: model.clone(),
            detail,
        }
    } else {
        ModelError::Unavailable {
            model: model.clone(),
            detail,
        }
    }
}

fn severed_stream(
    model: &ModelId,
    accumulator: &super::bedrock_stream::Accumulator,
    detail: &str,
) -> ModelError {
    if let Some(usage) = accumulator.usage() {
        return ModelError::Interrupted {
            model: model.clone(),
            usage,
            detail: detail.to_owned(),
        };
    }
    if accumulator.generated() {
        return ModelError::Unaccounted {
            model: model.clone(),
            detail: detail.to_owned(),
        };
    }
    ModelError::Unavailable {
        model: model.clone(),
        detail: detail.to_owned(),
    }
}

fn classify_stream_event(
    model: &ModelId,
    accumulator: &super::bedrock_stream::Accumulator,
    error: Option<&aws_sdk_bedrockruntime::types::error::ConverseStreamOutputError>,
    detail: &str,
) -> ModelError {
    if accumulator.started() || accumulator.generated() {
        return severed_stream(model, accumulator, detail);
    }
    if error.is_some_and(
        aws_sdk_bedrockruntime::types::error::ConverseStreamOutputError::is_throttling_exception,
    ) {
        ModelError::RateLimited {
            model: model.clone(),
            detail: detail.to_owned(),
            // See `classify_service`: the SDK does not surface response
            // headers here, and it retries throttles itself beneath this call.
            retry_after: None,
        }
    } else if error.is_some_and(
        aws_sdk_bedrockruntime::types::error::ConverseStreamOutputError::is_validation_exception,
    ) {
        ModelError::Refused {
            model: model.clone(),
            detail: detail.to_owned(),
        }
    } else {
        ModelError::Unavailable {
            model: model.clone(),
            detail: detail.to_owned(),
        }
    }
}

pub(super) fn document_from_json(value: &Value) -> Document {
    match value {
        Value::Null => Document::Null,
        Value::Bool(value) => Document::Bool(*value),
        Value::String(value) => Document::String(value.clone()),
        Value::Array(values) => Document::Array(values.iter().map(document_from_json).collect()),
        Value::Object(values) => Document::Object(
            values
                .iter()
                .map(|(key, value)| (key.clone(), document_from_json(value)))
                .collect::<HashMap<_, _>>(),
        ),
        Value::Number(value) => {
            if let Some(value) = value.as_u64() {
                Document::Number(Number::PosInt(value))
            } else if let Some(value) = value.as_i64() {
                Document::Number(Number::NegInt(value))
            } else {
                Document::Number(Number::Float(
                    value.as_f64().expect("JSON number is finite"),
                ))
            }
        }
    }
}

pub(super) fn json_from_document(value: &Document) -> Value {
    match value {
        Document::Null => Value::Null,
        Document::Bool(value) => Value::Bool(*value),
        Document::String(value) => Value::String(value.clone()),
        Document::Array(values) => Value::Array(values.iter().map(json_from_document).collect()),
        Document::Object(values) => Value::Object(
            values
                .iter()
                .map(|(key, value)| (key.clone(), json_from_document(value)))
                .collect(),
        ),
        Document::Number(Number::PosInt(value)) => json!(value),
        Document::Number(Number::NegInt(value)) => json!(value),
        Document::Number(Number::Float(value)) => json!(value),
    }
}

fn content_to_json(
    block: &ContentBlock,
    model: &ModelId,
    usage: Usage,
) -> Result<Value, ModelError> {
    match block {
        ContentBlock::Text(text) => Ok(json!({"type": "text", "text": text})),
        ContentBlock::ToolUse(tool) => Ok(json!({
            "type": "tool_use",
            "id": tool.tool_use_id(),
            "name": tool.name(),
            "input": json_from_document(tool.input()),
        })),
        ContentBlock::ReasoningContent(ReasoningContentBlock::ReasoningText(reasoning)) => {
            Ok(json!({
                "type": "reasoning",
                "text": reasoning.text(),
                "signature": reasoning.signature(),
            }))
        }
        ContentBlock::ReasoningContent(ReasoningContentBlock::RedactedContent(bytes)) => {
            Ok(json!({
                "type": "redacted_reasoning",
                "data": base64::engine::general_purpose::STANDARD.encode(bytes.as_ref()),
            }))
        }
        _ => Err(ModelError::Unusable {
            model: model.clone(),
            usage,
            detail: "Bedrock returned an unknown or unsupported continuation content block"
                .to_owned(),
        }),
    }
}

fn content_from_json(value: &Value, model: &ModelId) -> Result<ContentBlock, ModelError> {
    let kind = value
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| Bedrock::refused(model, "a Bedrock continuation block has no type"))?;
    match kind {
        "text" => Ok(ContentBlock::Text(
            value
                .get("text")
                .and_then(Value::as_str)
                .ok_or_else(|| Bedrock::refused(model, "a text block has no text"))?
                .to_owned(),
        )),
        "tool_use" => Ok(ContentBlock::ToolUse(
            ToolUseBlock::builder()
                .tool_use_id(
                    value
                        .get("id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| Bedrock::refused(model, "a tool block has no id"))?,
                )
                .name(
                    value
                        .get("name")
                        .and_then(Value::as_str)
                        .ok_or_else(|| Bedrock::refused(model, "a tool block has no name"))?,
                )
                .input(document_from_json(
                    value.get("input").unwrap_or(&Value::Null),
                ))
                .build()
                .map_err(|error| Bedrock::refused(model, error.to_string()))?,
        )),
        "reasoning" => {
            let mut builder = ReasoningTextBlock::builder().text(
                value
                    .get("text")
                    .and_then(Value::as_str)
                    .ok_or_else(|| Bedrock::refused(model, "a reasoning block has no text"))?,
            );
            if let Some(signature) = value.get("signature").and_then(Value::as_str) {
                builder = builder.signature(signature);
            }
            Ok(ContentBlock::ReasoningContent(
                ReasoningContentBlock::ReasoningText(
                    builder
                        .build()
                        .map_err(|error| Bedrock::refused(model, error.to_string()))?,
                ),
            ))
        }
        "redacted_reasoning" => {
            let encoded = value
                .get("data")
                .and_then(Value::as_str)
                .ok_or_else(|| Bedrock::refused(model, "redacted reasoning has no data"))?;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|error| Bedrock::refused(model, error.to_string()))?;
            Ok(ContentBlock::ReasoningContent(
                ReasoningContentBlock::RedactedContent(Blob::new(bytes)),
            ))
        }
        other => Err(Bedrock::refused(
            model,
            format!("unsupported Bedrock continuation block '{other}'"),
        )),
    }
}

fn tool_result_from_json(value: &Value, model: &ModelId) -> Result<ContentBlock, ModelError> {
    let id = value
        .get("tool_use_id")
        .and_then(Value::as_str)
        .ok_or_else(|| Bedrock::refused(model, "a tool result has no tool_use_id"))?;
    let status = if value.get("failed").and_then(Value::as_bool) == Some(true) {
        ToolResultStatus::Error
    } else {
        ToolResultStatus::Success
    };
    Ok(ContentBlock::ToolResult(
        ToolResultBlock::builder()
            .tool_use_id(id)
            .content(ToolResultContentBlock::Json(document_from_json(
                value.get("output").unwrap_or(&Value::Null),
            )))
            .status(status)
            .build()
            .map_err(|error| Bedrock::refused(model, error.to_string()))?,
    ))
}

fn continuation_message_from_json(value: &Value, model: &ModelId) -> Result<Message, ModelError> {
    let role = value
        .get("role")
        .and_then(Value::as_str)
        .ok_or_else(|| Bedrock::refused(model, "a continuation message has no role"))?;
    let blocks = value
        .get("content")
        .and_then(Value::as_array)
        .ok_or_else(|| Bedrock::refused(model, "a continuation message has no content array"))?;
    let (role, content) = match role {
        "assistant" => (
            ConversationRole::Assistant,
            blocks
                .iter()
                .map(|block| content_from_json(block, model))
                .collect::<Result<Vec<_>, _>>()?,
        ),
        "user" => (
            ConversationRole::User,
            blocks
                .iter()
                .map(|block| tool_result_from_json(block, model))
                .collect::<Result<Vec<_>, _>>()?,
        ),
        other => {
            return Err(Bedrock::refused(
                model,
                format!("unsupported continuation role '{other}'"),
            ));
        }
    };
    Message::builder()
        .role(role)
        .set_content(Some(content))
        .build()
        .map_err(|error| Bedrock::refused(model, error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smithy_documents_round_trip_json() {
        let value = json!({"s": "x", "n": -2, "u": 3, "f": 1.5, "a": [true, null]});
        assert_eq!(json_from_document(&document_from_json(&value)), value);
    }

    #[test]
    fn governed_images_and_documents_become_inline_bedrock_blocks() {
        let model = ModelId::new("bedrock", "test");
        let image = content_from_prompt_json(
            &json!({
                "type": "image",
                "media_type": "image/png",
                "data": base64::engine::general_purpose::STANDARD.encode(b"png")
            }),
            &model,
        )
        .expect("image");
        assert_eq!(
            image.as_image().expect("image block").format(),
            &ImageFormat::Png
        );

        let document = content_from_prompt_json(
            &json!({
                "type": "document",
                "media_type": "application/pdf",
                "data": base64::engine::general_purpose::STANDARD.encode(b"pdf")
            }),
            &model,
        )
        .expect("document");
        let document = document.as_document().expect("document block");
        assert_eq!(document.format(), &DocumentFormat::Pdf);
        assert_eq!(document.name(), "document");
    }

    #[test]
    fn bedrock_media_never_accepts_a_remote_source() {
        let model = ModelId::new("bedrock", "test");
        assert!(
            content_from_prompt_json(
                &json!({
                    "type": "image",
                    "media_type": "image/png",
                    "url": "https://example.test/image.png"
                }),
                &model,
            )
            .is_err()
        );
    }

    #[test]
    fn signed_and_redacted_reasoning_round_trip() {
        let model = ModelId::new("bedrock", "test");
        for value in [
            json!({"type": "reasoning", "text": "private", "signature": "sig"}),
            json!({"type": "redacted_reasoning", "data": "AQID"}),
        ] {
            let block = content_from_json(&value, &model).expect("decode block");
            assert_eq!(
                content_to_json(&block, &model, Usage::default()).unwrap(),
                value
            );
        }
    }

    /// A guardrail is part of what governed the call, so it is part of
    /// identity — and its two forms agree about which guardrail they name.
    #[test]
    fn a_guardrail_is_effect_identity_and_both_paths_send_the_same_one() {
        let config = aws_sdk_bedrockruntime::Config::builder()
            .region(Region::new("eu-west-1"))
            .behavior_version_latest()
            .http_client(aws_smithy_http_client::test_util::infallible_client_fn(
                |_req| http::Response::builder().status(200).body("").unwrap(),
            ))
            .build();
        let client = Client::from_conf(config);
        let plain = Bedrock::from_client(client.clone()).expect("a client with a region");
        let model = ModelId::new("bedrock", "m");
        let guarded = Bedrock::from_client(client)
            .expect("a client with a region")
            .guardrail(Guardrail::new("gr-7", "3"));

        assert_eq!(plain.request_profile(&model)["guardrail"], Value::Null);
        assert_eq!(
            guarded.request_profile(&model)["guardrail"],
            json!({ "id": "gr-7", "version": "3" }),
            "a guardrail that does not enter the request profile can be turned \
             off between a run and its replay with nothing on the record"
        );
        assert_ne!(
            plain.request_profile(&model),
            guarded.request_profile(&model),
            "guarded and unguarded calls shared one effect identity"
        );

        // The buffered and streaming forms must name the same guardrail: a
        // control applied on one path only is one a `stream: true` deployment
        // silently loses.
        let g = Guardrail::new("gr-7", "3");
        assert_eq!(g.config().guardrail_identifier(), "gr-7");
        assert_eq!(g.stream_config().guardrail_identifier(), "gr-7");
        assert_eq!(g.config().guardrail_version(), "3");
        assert_eq!(g.stream_config().guardrail_version(), "3");
        // Synchronous: the alternative streams blocked content to the caller
        // and objects afterwards, which is a control arriving after the thing
        // it exists to prevent.
        assert_eq!(
            g.stream_config().stream_processing_mode().as_str(),
            "sync",
            "an asynchronous guardrail releases content before assessing it"
        );

        // Trace is off by default and reaches both request forms when asked for,
        // because the intervention reason it returns is journaled — and a
        // control the streaming path drops is one a `stream: true` deployment
        // loses.
        assert_eq!(g.config().trace().as_str(), "disabled");
        assert_eq!(g.stream_config().trace().as_str(), "disabled");
        let traced = Guardrail::new("gr-7", "3").with_trace();
        assert_eq!(traced.config().trace().as_str(), "enabled");
        assert_eq!(
            traced.stream_config().trace().as_str(),
            "enabled",
            "with_trace must reach the streaming path too"
        );
    }

    #[test]
    fn request_profile_commits_to_region_and_buffering() {
        let config = aws_sdk_bedrockruntime::Config::builder()
            .region(Region::new("eu-west-1"))
            .behavior_version_latest()
            // A stub client, so no TLS provider is built: the default one
            // eagerly reads the OS trust store, and under a fully parallel
            // suite the macOS keychain read can transiently yield zero roots
            // — a panic inside aws-smithy, in a test that asserts a JSON
            // profile and never opens a connection.
            .http_client(aws_smithy_http_client::test_util::infallible_client_fn(
                |_req| http::Response::builder().status(200).body("").unwrap(),
            ))
            .build();
        let driver =
            Bedrock::from_client(Client::from_conf(config)).expect("a client with a region");
        assert_eq!(
            driver.request_profile(&ModelId::new("bedrock", "m")),
            json!({
                "driver": "aws-bedrock-converse/v1",
                "region": "eu-west-1",
                "stream": true,
                "schema_mode": "native",
                "timeout_ms": 300_000,
                // Present and null when unguarded: an absent key and a null
                // one are the same to a reader and different to a digest, so
                // the profile states the answer rather than omitting it.
                "guardrail": Value::Null,
                "reasoning_dialect": Value::Null,
            })
        );

        assert_ne!(
            driver.request_profile(&ModelId::new("bedrock", "m")),
            driver
                .buffered()
                .request_profile(&ModelId::new("bedrock", "m")),
            "buffered and streamed Bedrock requests reused one effect identity"
        );
    }

    /// **The attested region is the client's, and there is no second copy of it
    /// to disagree.**
    ///
    /// `region` is what `request_profile` puts on the record, and that profile
    /// is effect identity — so a replay is judged against it. Taken as an
    /// argument beside the client it is a fact stored twice, and the copy the
    /// journal attests is the one nothing checks: a driver built with a
    /// `us-east-1` client and the string `"eu-west-1"` would send every call to
    /// Virginia and swear to Ireland, on a record built to be evidence.
    ///
    /// The positive half is what does the work here. That a blank region is
    /// refused proves only that a constructor validates its input; that the
    /// profile *follows the client* is the property, and it is the half that
    /// fails if the parameter ever comes back.
    #[test]
    fn the_attested_region_is_the_one_the_client_will_reach() {
        let stub = |region: Option<&str>| {
            let mut config = aws_sdk_bedrockruntime::Config::builder()
                .behavior_version_latest()
                .http_client(aws_smithy_http_client::test_util::infallible_client_fn(
                    |_req| http::Response::builder().status(200).body("").unwrap(),
                ));
            if let Some(region) = region {
                config = config.region(Region::new(region.to_owned()));
            }
            Bedrock::from_client(Client::from_conf(config.build()))
        };

        for region in ["us-east-1", "eu-west-1"] {
            let driver = stub(Some(region)).expect("a client carrying a region");
            assert_eq!(
                driver.request_profile(&ModelId::new("bedrock", "m"))["region"],
                json!(region),
                "the profile attested a region other than the one the client \
                 resolves its endpoint from"
            );
        }

        // A client with no region cannot name where it went, and an empty
        // string on the record is worse than a refusal: it is a destination
        // that reads as answered.
        let err = stub(None).expect_err("a client with no region was accepted");
        assert!(
            err.contains("region"),
            "the refusal must name the missing region, got: {err}"
        );
        let err = stub(Some("   ")).expect_err("a blank region was accepted");
        assert!(
            err.contains("region"),
            "the refusal must name the blank region, got: {err}"
        );
    }

    fn stub_driver() -> Bedrock {
        let config = aws_sdk_bedrockruntime::Config::builder()
            .region(Region::new("eu-west-1"))
            .behavior_version_latest()
            .http_client(aws_smithy_http_client::test_util::infallible_client_fn(
                |_req| http::Response::builder().status(200).body("").unwrap(),
            ))
            .build();
        Bedrock::from_client(Client::from_conf(config)).expect("a client with a region")
    }

    /// **Nova's reasoning dialect, rendered exactly as AWS documents it.**
    ///
    /// The shape is a known answer taken from Amazon's own Nova 2 extended-thinking
    /// page, not from a round trip through this driver: `reasoningConfig` with a
    /// `type` and a `maxReasoningEffort` of `low`, `medium` or `high`. A round
    /// trip would agree with itself under any spelling at all, including a wrong
    /// one, and Bedrock answers a misspelled `additionalModelRequestFields` key
    /// by **ignoring it** — so the failure mode this pins is a deployment that
    /// declared `high` effort, was billed for none, and had nothing on the record
    /// to say so.
    #[test]
    fn nova_reasoning_effort_is_rendered_the_way_aws_documents_it() {
        use super::super::ReasoningEffort as E;

        let nova = stub_driver().reasoning(ReasoningDialect::Nova);
        let model = ModelId::new("bedrock", "us.amazon.nova-2-lite-v1:0");

        for (effort, expected) in [(E::Low, "low"), (E::Medium, "medium"), (E::High, "high")] {
            let document = nova
                .reasoning_config(&model, Some(effort))
                .expect("a documented level maps")
                .expect("an effort produces a config");
            assert_eq!(
                json_from_document(&document),
                json!({ "reasoningConfig": { "type": "enabled", "maxReasoningEffort": expected } }),
                "the {} level did not render as AWS documents it",
                effort.as_str()
            );
        }

        // `None` is a *statement*, not an omission: a deployment saying this
        // call must not reason. Sending `disabled` puts that on the wire and in
        // the journal; sending nothing would be indistinguishable from a
        // deployment that never considered the question.
        assert_eq!(
            json_from_document(
                &nova
                    .reasoning_config(&model, Some(E::None))
                    .expect("none maps")
                    .expect("none is still a config")
            ),
            json!({ "reasoningConfig": { "type": "disabled" } })
        );

        // No effort asked for sends nothing at all. An empty `reasoningConfig`
        // is a different request from no `reasoningConfig`.
        assert!(
            nova.reasoning_config(&model, None)
                .expect("no effort is not an error")
                .is_none()
        );
    }

    /// **An effort Nova cannot carry is refused, never collapsed.**
    ///
    /// The positive half above would pass with a mapping that folded every
    /// unknown level into `high` — and that mapping is the defect, because
    /// `reasoning_effort` is digest-covered: it claims to describe what governed
    /// the call. Answering a request for `max` with the third of three levels is
    /// a substitution nothing downstream can see, on the one value that exists
    /// to be seen.
    ///
    /// Same rule as the Anthropic driver, which refuses the levels adaptive
    /// thinking cannot express rather than approximating them.
    #[test]
    fn nova_refuses_an_effort_it_has_no_counterpart_for() {
        use super::super::ReasoningEffort as E;

        let nova = stub_driver().reasoning(ReasoningDialect::Nova);
        let model = ModelId::new("bedrock", "us.amazon.nova-2-lite-v1:0");

        for effort in [E::Minimal, E::XHigh, E::Max] {
            let error = nova
                .reasoning_config(&model, Some(effort))
                .expect_err("an effort Nova cannot express must be refused");
            let text = error.to_string();
            assert!(
                text.contains(effort.as_str()) && text.contains("low, medium and high"),
                "the refusal must name the effort and the levels that exist: {text}"
            );
        }
    }

    /// **An undeclared dialect still refuses, and the message says what to do.**
    ///
    /// The blanket refusal is the pre-existing behaviour and must survive:
    /// Converse is one envelope over families that spell reasoning differently
    /// or not at all, so a driver with no declared dialect has nothing to derive
    /// and guessing is the failure. What changed is only that there is now a way
    /// to answer it, and the message names that way.
    #[test]
    fn an_undeclared_dialect_refuses_rather_than_guessing() {
        let plain = stub_driver();
        let model = ModelId::new("bedrock", "m");
        let text = plain
            .reasoning_config(&model, Some(super::super::ReasoningEffort::Medium))
            .expect_err("no dialect must refuse")
            .to_string();
        assert!(
            text.contains("ReasoningDialect::Nova"),
            "a refusal that does not name the remedy leaves the reader stuck: {text}"
        );
    }

    /// **The dialect is effect identity, on both request paths.**
    ///
    /// Two properties, and the guardrail above is the precedent for each. The
    /// dialect decides how a declared effort is rendered, so switching it
    /// changes what governed the call and a replay of older history must report
    /// divergence rather than answering under the new rendering. And the config
    /// is built once and handed to `converse` and `converse_stream` alike,
    /// because a control applied on one path only is one a `stream: true`
    /// deployment silently loses.
    #[test]
    fn the_reasoning_dialect_is_effect_identity_and_reaches_both_paths() {
        let model = ModelId::new("bedrock", "us.amazon.nova-2-lite-v1:0");
        let plain = stub_driver();
        let nova = stub_driver().reasoning(ReasoningDialect::Nova);

        assert_eq!(
            plain.request_profile(&model)["reasoning_dialect"],
            Value::Null
        );
        assert_eq!(nova.request_profile(&model)["reasoning_dialect"], "nova");
        assert_ne!(
            plain.request_profile(&model),
            nova.request_profile(&model),
            "a driver that renders reasoning differently shared one effect identity"
        );

        // Buffered and streamed differ only in `stream`, so the dialect must
        // survive that difference — the streaming path takes the config as an
        // argument rather than rebuilding it, and this is what says so.
        assert_eq!(
            nova.clone().buffered().request_profile(&model)["reasoning_dialect"],
            nova.request_profile(&model)["reasoning_dialect"],
        );
    }

    #[test]
    fn native_schema_can_coexist_with_tools_but_forced_fallback_cannot() {
        let model = ModelId::new("bedrock", "test");
        let schema = json!({"type": "object"});
        let tools = vec![ToolDeclaration::new(
            "lookup",
            "Look something up.",
            json!({"type": "object"}),
        )];
        assert!(
            Bedrock::tool_config(&model, Some(&schema), &tools, SchemaMode::Native)
                .expect("native schema and tools")
                .is_some()
        );
        assert!(
            Bedrock::tool_config(&model, Some(&schema), &tools, SchemaMode::ForcedTool).is_err(),
            "forced-tool structured output consumed the same tool channel as caller tools"
        );
    }

    /// Reasoning + `toolUse` + no sibling text is a working tool turn.
    ///
    /// With extended thinking on, choosing a tool IS the answer: Converse
    /// returns `reasoningContent` and `toolUse` blocks with no text beside
    /// them. This test pins two things at once. First, that the emptiness
    /// guard in `interpret` requires *both* no text and no tool call before
    /// declaring the answer unusable — weaken it to text alone and this fails.
    /// Second, that the continuation carries the reasoning block byte-for-byte
    /// beside the tool call, signature included, because Bedrock rejects a
    /// follow-up turn whose reasoning does not return its signature and a
    /// driver that rebuilt the turn from the fields it understands cannot
    /// return what it never kept. What this does NOT cover is the streaming
    /// accumulator's reassembly of those blocks — that has its own tests in
    /// `bedrock_stream.rs`; both paths funnel into this same `interpret`.
    #[test]
    fn a_reasoning_tool_turn_with_no_text_is_an_answer_not_an_empty_one() {
        let model = ModelId::new("bedrock", "test");
        let message = Message::builder()
            .role(ConversationRole::Assistant)
            .content(ContentBlock::ReasoningContent(
                ReasoningContentBlock::ReasoningText(
                    ReasoningTextBlock::builder()
                        .text("private reasoning")
                        .signature("sig-bytes")
                        .build()
                        .expect("reasoning block"),
                ),
            ))
            .content(ContentBlock::ToolUse(
                ToolUseBlock::builder()
                    .tool_use_id("tool_1")
                    .name("lookup")
                    .input(document_from_json(&json!({ "id": "AC-1" })))
                    .build()
                    .expect("tool block"),
            ))
            .build()
            .expect("assistant message");
        let output = aws_sdk_bedrockruntime::operation::converse::ConverseOutput::builder()
            .output(aws_sdk_bedrockruntime::types::ConverseOutput::Message(
                message,
            ))
            .stop_reason(aws_sdk_bedrockruntime::types::StopReason::ToolUse)
            .build()
            .expect("converse output");

        let completion = Bedrock::interpret(&model, None, SchemaMode::Native, &output)
            .expect("a tool call with empty sibling text is a normal tool turn");
        assert_eq!(completion.tool_calls.len(), 1);
        assert_eq!(completion.tool_calls[0].name, "lookup");
        let state = completion
            .continuation
            .expect("a tool turn must carry its provider continuation")
            .state;
        assert_eq!(
            state,
            json!([{ "role": "assistant", "content": [
                { "type": "reasoning", "text": "private reasoning", "signature": "sig-bytes" },
                { "type": "tool_use", "id": "tool_1", "name": "lookup", "input": { "id": "AC-1" } },
            ]}]),
            "the continuation must carry the provider turn verbatim, reasoning \
             block and signature included"
        );
    }

    /// The twin of the test above: no text AND no tool call stays unusable.
    ///
    /// Together the pair pins the guard to exactly `text.is_empty() &&
    /// calls.is_empty()` (with no structured answer either) — remove either
    /// conjunct and one of the two fails.
    #[test]
    fn an_answer_with_neither_text_nor_tool_calls_is_unusable() {
        let model = ModelId::new("bedrock", "test");
        let message = Message::builder()
            .role(ConversationRole::Assistant)
            .content(ContentBlock::ReasoningContent(
                ReasoningContentBlock::ReasoningText(
                    ReasoningTextBlock::builder()
                        .text("reasoned and then said nothing")
                        .build()
                        .expect("reasoning block"),
                ),
            ))
            .build()
            .expect("assistant message");
        let output = aws_sdk_bedrockruntime::operation::converse::ConverseOutput::builder()
            .output(aws_sdk_bedrockruntime::types::ConverseOutput::Message(
                message,
            ))
            .stop_reason(aws_sdk_bedrockruntime::types::StopReason::EndTurn)
            .build()
            .expect("converse output");
        let error = Bedrock::interpret(&model, None, SchemaMode::Native, &output)
            .expect_err("reasoning with neither text nor a tool call is not usable");
        assert!(
            matches!(error, ModelError::Unusable { .. }),
            "wrong classification: {error}"
        );
    }

    #[test]
    fn cumulative_bedrock_transcript_decodes_every_prior_turn() {
        let model = ModelId::new("bedrock", "test");
        let continuation = ProviderContinuation::new(
            "bedrock",
            json!([
                {"role": "assistant", "content": [
                    {"type": "reasoning", "text": "private", "signature": "sig"},
                    {"type": "tool_use", "id": "tool_1", "name": "lookup", "input": {}}
                ]},
                {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "tool_1", "output": {"v": 1}, "failed": false}
                ]}
            ]),
        );
        let messages = Bedrock::messages(
            &model,
            &json!({"input": "question"}),
            &[ToolExchange::ok(
                super::super::ToolCall {
                    id: "tool_2".to_owned(),
                    name: "lookup".to_owned(),
                    arguments: json!({}),
                },
                json!({"v": 2}),
            )],
            Some(&continuation),
        )
        .expect("decode cumulative transcript");
        assert_eq!(messages.len(), 4, "question plus three continuation turns");
        assert!(messages[1].content()[0].is_reasoning_content());
        assert!(messages[2].content()[0].is_tool_result());
        assert!(messages[3].content()[0].is_tool_result());
    }
}
