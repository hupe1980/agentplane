//! Amazon Bedrock Runtime through the provider-neutral Converse API.
//!
//! This driver is deliberately buffered. Converse returns usage with the whole
//! response; claiming streaming support before every event-stream failure can
//! be classified and metered would weaken the runtime's spend guarantees.

use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use aws_sdk_bedrockruntime::Client;
use aws_sdk_bedrockruntime::config::Region;
use aws_sdk_bedrockruntime::operation::converse::ConverseError;
use aws_sdk_bedrockruntime::types::{
    ContentBlock, ConversationRole, InferenceConfiguration, Message, ReasoningContentBlock,
    ReasoningTextBlock, SpecificToolChoice, SystemContentBlock, Tool, ToolChoice,
    ToolConfiguration, ToolInputSchema, ToolResultBlock, ToolResultContentBlock, ToolResultStatus,
    ToolSpecification, ToolUseBlock,
};
use aws_smithy_types::{Blob, Document, Number};
use base64::Engine as _;
use serde_json::{Value, json};

use super::{
    Completion, ModelError, ModelId, ModelProvider, ProviderContinuation, Request, ToolDeclaration,
    ToolExchange, Usage,
};

const RESPOND_TOOL: &str = "__agentplane_respond";

/// Amazon Bedrock Runtime's Converse driver.
#[derive(Clone)]
pub struct Bedrock {
    client: Client,
    region: String,
    timeout: Duration,
}

impl std::fmt::Debug for Bedrock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bedrock")
            .field("region", &self.region)
            .field("timeout", &self.timeout)
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
        }
    }

    /// Bound the complete Converse operation.
    #[must_use]
    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
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
                    .map(|block| {
                        let text = block.get("text").and_then(Value::as_str).ok_or_else(|| {
                            Self::refused(
                                model,
                                "initial Bedrock messages support text content blocks only",
                            )
                        })?;
                        Ok(ContentBlock::Text(text.to_owned()))
                    })
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
    ) -> Result<Option<ToolConfiguration>, ModelError> {
        if schema.is_some() && !tools.is_empty() {
            return Err(Self::refused(
                model,
                "Bedrock Converse obtains structured output by forcing a synthetic tool, so a \
                 response schema cannot be combined with callable tools",
            ));
        }
        let mut builder = ToolConfiguration::builder();
        if let Some(schema) = schema {
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
        if schema.is_none() && tools.is_empty() {
            Ok(None)
        } else {
            builder
                .build()
                .map(Some)
                .map_err(|error| Self::refused(model, error.to_string()))
        }
    }

    fn interpret(
        model: &ModelId,
        schema: Option<&Value>,
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

        let structured = if schema.is_some() {
            let value = forced.ok_or_else(|| ModelError::Unusable {
                model: model.clone(),
                usage,
                detail: "Bedrock did not honor the forced structured-output tool".to_owned(),
            })?;
            text = value.to_string();
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
            "stream": false,
            "structured_output": "forced-tool",
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
        let tools = Self::tool_config(model, schema, tools)?;
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
            .set_tool_config(tools);
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
        let mut completion = Self::interpret(model, schema, &output)?;
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

fn document_from_json(value: &Value) -> Document {
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

fn json_from_document(value: &Document) -> Value {
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
                "stream": false,
                "structured_output": "forced-tool",
                "timeout_ms": 300_000,
            })
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
