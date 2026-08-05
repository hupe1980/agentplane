//! One real Amazon Bedrock Converse call, explicitly gated to avoid accidental spend.
//!
//! ```sh
//! AGENTPLANE_LIVE=1 AWS_REGION=eu-west-1 \
//! AGENTPLANE_BEDROCK_MODEL=anthropic.claude-3-5-sonnet-20241022-v2:0 \
//! cargo run --example bedrock_live --features bedrock
//! ```

use agentplane::model::{ModelCall, ModelId, ModelProvider, Request};
use serde_json::json;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("AGENTPLANE_LIVE").as_deref() != Ok("1") {
        println!("skipping: set AGENTPLANE_LIVE=1 to authorize provider spend");
        return Ok(());
    }
    let region = std::env::var("AWS_REGION")?;
    let model = std::env::var("AGENTPLANE_BEDROCK_MODEL")?;
    let provider = agentplane::model::bedrock::Bedrock::from_env(region).await?;
    let model = ModelId::new("bedrock", model);
    let prompt = json!({
        "system": "Answer concisely.",
        "input": "Reply with the word durable."
    });
    let completion = provider
        .complete(Request {
            model: &model,
            prompt: &prompt,
            max_output_tokens: ModelCall::DEFAULT_MAX_OUTPUT_TOKENS,
            reasoning_effort: None,
            schema: None,
            tools: &[],
            exchanges: &[],
            continuation: None,
        })
        .await?;
    println!("{}", completion.text);
    eprintln!(
        "input={} output={} stop={:?}",
        completion.usage.input_tokens, completion.usage.output_tokens, completion.stop_reason
    );
    Ok(())
}
