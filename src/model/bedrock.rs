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
#[derive(Clone)]
pub struct Bedrock {
    client: Client,
    region: String,
    timeout: Duration,
    schema_mode: SchemaMode,
    stream: bool,
}

impl std::fmt::Debug for Bedrock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bedrock")
            .field("region", &self.region)
            .field("timeout", &self.timeout)
            .field("schema_mode", &self.schema_mode)
            .field("stream", &self.stream)
            .finish_non_exhaustive()
    }
}

impl Bedrock {
    /// Load the standard AWS credential chain for this region.
    pub async fn from_env(region: impl Into<String>) -> Result<Self, String> {
        let region = region.into();
        if region.trim().is_empty() {
            return Err("an AWS region is required for Bedrock".to_owned());
        }
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(Region::new(region.clone()))
            .load()
            .await;
        Ok(Self::from_client(Client::new(&config), region))
    }

    /// Build from an already configured AWS client.
    #[must_use]
    pub fn from_client(client: Client, region: impl Into<String>) -> Self {
        Self {
            client,
            region: region.into(),
            timeout: Duration::from_mins(5),
            schema_mode: SchemaMode::Native,
            stream: true,
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
            .set_output_config(output_config);
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
        if reasoning_effort.is_some() {
            return Err(Self::refused(
                model,
                "Bedrock Converse has no provider-neutral reasoning-effort mapping; configure a \
                 model-specific Bedrock driver rather than silently changing the requested effort",
            ));
        }
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
            .set_output_config(output_config);
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

    #[test]
    fn request_profile_commits_to_region_and_buffering() {
        let config = aws_sdk_bedrockruntime::Config::builder()
            .region(Region::new("eu-west-1"))
            .behavior_version_latest()
            .build();
        let driver = Bedrock::from_client(Client::from_conf(config), "eu-west-1");
        assert_eq!(
            driver.request_profile(&ModelId::new("bedrock", "m")),
            json!({
                "driver": "aws-bedrock-converse/v1",
                "region": "eu-west-1",
                "stream": true,
                "schema_mode": "native",
                "timeout_ms": 300_000,
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
