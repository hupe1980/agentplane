//! Reassemble Amazon Bedrock `ConverseStream` events without exposing partial answers.

use std::collections::BTreeMap;

use aws_sdk_bedrockruntime::types::{
    ContentBlock, ContentBlockDelta, ContentBlockStart, ConverseStreamOutput,
    ReasoningContentBlock, ReasoningContentBlockDelta, ReasoningTextBlock, StopReason,
    ToolUseBlock,
};
use aws_smithy_types::Blob;

use super::Usage;

#[derive(Debug, Default)]
enum Block {
    #[default]
    Empty,
    Text(String),
    Tool {
        id: String,
        name: String,
        input: String,
    },
    Reasoning {
        text: String,
        signature: String,
        redacted: Vec<u8>,
    },
}

/// One streamed Bedrock message under construction.
#[derive(Debug, Default)]
pub struct Accumulator {
    blocks: BTreeMap<i32, Block>,
    usage: Option<Usage>,
    stop_reason: Option<StopReason>,
    started: bool,
    generated: bool,
}

impl Accumulator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn started(&self) -> bool {
        self.started
    }

    #[must_use]
    pub const fn generated(&self) -> bool {
        self.generated
    }

    #[must_use]
    pub const fn usage(&self) -> Option<Usage> {
        self.usage
    }

    #[must_use]
    pub fn stop_reason(&self) -> Option<&StopReason> {
        self.stop_reason.as_ref()
    }

    pub fn event(&mut self, event: ConverseStreamOutput) {
        match event {
            ConverseStreamOutput::MessageStart(_) => self.started = true,
            ConverseStreamOutput::ContentBlockStart(event) => {
                let index = event.content_block_index();
                if let Some(ContentBlockStart::ToolUse(tool)) = event.start() {
                    self.blocks.insert(
                        index,
                        Block::Tool {
                            id: tool.tool_use_id().to_owned(),
                            name: tool.name().to_owned(),
                            input: String::new(),
                        },
                    );
                }
            }
            ConverseStreamOutput::ContentBlockDelta(event) => {
                self.generated = true;
                let index = event.content_block_index();
                let Some(delta) = event.delta() else {
                    return;
                };
                match delta {
                    ContentBlockDelta::Text(text) => {
                        let block = self
                            .blocks
                            .entry(index)
                            .or_insert_with(|| Block::Text(String::new()));
                        if let Block::Text(value) = block {
                            value.push_str(text);
                        }
                    }
                    ContentBlockDelta::ToolUse(delta) => {
                        if let Some(Block::Tool { input, .. }) = self.blocks.get_mut(&index) {
                            input.push_str(delta.input());
                        }
                    }
                    ContentBlockDelta::ReasoningContent(delta) => {
                        let block = self
                            .blocks
                            .entry(index)
                            .or_insert_with(|| Block::Reasoning {
                                text: String::new(),
                                signature: String::new(),
                                redacted: Vec::new(),
                            });
                        if let Block::Reasoning {
                            text,
                            signature,
                            redacted,
                        } = block
                        {
                            match delta {
                                ReasoningContentBlockDelta::Text(value) => text.push_str(value),
                                ReasoningContentBlockDelta::Signature(value) => {
                                    signature.push_str(value);
                                }
                                ReasoningContentBlockDelta::RedactedContent(value) => {
                                    redacted.extend_from_slice(value.as_ref());
                                }
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
            }
            ConverseStreamOutput::MessageStop(event) => {
                self.stop_reason = Some(event.stop_reason().clone());
            }
            ConverseStreamOutput::Metadata(event) => {
                // The same beside-the-input fold as the buffered path — the
                // cache counters are not inside `inputTokens` on this wire.
                self.usage = event.usage().map(|usage| {
                    Usage::with_cache_beside_input(
                        u64::try_from(usage.input_tokens()).unwrap_or_default(),
                        u64::try_from(usage.output_tokens()).unwrap_or_default(),
                        u64::try_from(usage.cache_write_input_tokens().unwrap_or_default())
                            .unwrap_or_default(),
                        u64::try_from(usage.cache_read_input_tokens().unwrap_or_default())
                            .unwrap_or_default(),
                    )
                });
            }
            _ => {}
        }
    }

    pub fn finish(self) -> Result<Vec<ContentBlock>, String> {
        self.blocks
            .into_values()
            .map(|block| match block {
                Block::Text(text) => Ok(ContentBlock::Text(text)),
                Block::Tool { id, name, input } => {
                    // No input deltas is a zero-argument call, which the
                    // buffered path reads as `{}` — not a parse failure.
                    let input = if input.is_empty() {
                        serde_json::Value::Object(serde_json::Map::new())
                    } else {
                        serde_json::from_str(&input)
                            .map_err(|error| format!("streamed tool input was not JSON: {error}"))?
                    };
                    Ok(ContentBlock::ToolUse(
                        ToolUseBlock::builder()
                            .tool_use_id(id)
                            .name(name)
                            .input(super::bedrock::document_from_json(&input))
                            .build()
                            .map_err(|error| error.to_string())?,
                    ))
                }
                Block::Reasoning {
                    text: _,
                    signature: _,
                    redacted,
                } if !redacted.is_empty() => Ok(ContentBlock::ReasoningContent(
                    ReasoningContentBlock::RedactedContent(Blob::new(redacted)),
                )),
                Block::Reasoning {
                    text, signature, ..
                } => {
                    let mut builder = ReasoningTextBlock::builder().text(text);
                    if !signature.is_empty() {
                        builder = builder.signature(signature);
                    }
                    Ok(ContentBlock::ReasoningContent(
                        ReasoningContentBlock::ReasoningText(
                            builder.build().map_err(|error| error.to_string())?,
                        ),
                    ))
                }
                Block::Empty => Err("streamed content block had no supported content".to_owned()),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_bedrockruntime::types::{
        ContentBlockDeltaEvent, ContentBlockStartEvent, ConverseStreamMetadataEvent,
        MessageStartEvent, MessageStopEvent, TokenUsage, ToolUseBlockDelta, ToolUseBlockStart,
    };

    #[test]
    fn text_tools_reasoning_and_usage_are_reassembled() {
        let mut acc = Accumulator::new();
        acc.event(ConverseStreamOutput::MessageStart(
            MessageStartEvent::builder()
                .role(aws_sdk_bedrockruntime::types::ConversationRole::Assistant)
                .build()
                .unwrap(),
        ));
        acc.event(ConverseStreamOutput::ContentBlockDelta(
            ContentBlockDeltaEvent::builder()
                .content_block_index(0)
                .delta(ContentBlockDelta::Text("answer".to_owned()))
                .build()
                .unwrap(),
        ));
        acc.event(ConverseStreamOutput::ContentBlockStart(
            ContentBlockStartEvent::builder()
                .content_block_index(1)
                .start(ContentBlockStart::ToolUse(
                    ToolUseBlockStart::builder()
                        .tool_use_id("tool-1")
                        .name("lookup")
                        .build()
                        .unwrap(),
                ))
                .build()
                .unwrap(),
        ));
        acc.event(ConverseStreamOutput::ContentBlockDelta(
            ContentBlockDeltaEvent::builder()
                .content_block_index(1)
                .delta(ContentBlockDelta::ToolUse(
                    ToolUseBlockDelta::builder()
                        .input("{\"id\":1}")
                        .build()
                        .unwrap(),
                ))
                .build()
                .unwrap(),
        ));
        acc.event(ConverseStreamOutput::Metadata(
            ConverseStreamMetadataEvent::builder()
                .usage(
                    TokenUsage::builder()
                        .input_tokens(10)
                        .output_tokens(4)
                        .total_tokens(14)
                        .build()
                        .unwrap(),
                )
                .build(),
        ));
        acc.event(ConverseStreamOutput::MessageStop(
            MessageStopEvent::builder()
                .stop_reason(StopReason::ToolUse)
                .build()
                .unwrap(),
        ));

        assert!(acc.started());
        assert!(acc.generated());
        assert_eq!(acc.usage().unwrap().output_tokens, 4);
        assert_eq!(acc.stop_reason(), Some(&StopReason::ToolUse));
        let blocks = acc.finish().unwrap();
        assert_eq!(blocks[0].as_text().unwrap(), "answer");
        assert_eq!(
            super::super::bedrock::json_from_document(blocks[1].as_tool_use().unwrap().input()),
            serde_json::json!({"id": 1})
        );
    }
}
