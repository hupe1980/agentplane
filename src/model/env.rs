//! A shipped driver, by its provider name, configured from the environment.
//!
//! The conventions the CLI uses, for an embedder that wants the same ones:
//! `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY` (or
//! `GOOGLE_API_KEY`), `AWS_REGION` with the AWS credential chain, and
//! `CHAT_COMPLETIONS_BASE_URL` with an optional `CHAT_COMPLETIONS_API_KEY`.

use std::sync::Arc;

use super::ModelProvider;

/// The driver for `provider`, from the environment.
///
/// # Errors
///
/// A provider this build ships no driver for, a variable it needs that is
/// not set, or a client that cannot be built. The message names the
/// variable, never its value.
#[allow(
    clippy::unused_async,
    reason = "async for Bedrock, whose credential chain resolves over the network"
)]
pub async fn from_env(provider: &str) -> Result<Arc<dyn ModelProvider>, String> {
    match provider {
        #[cfg(feature = "providers")]
        "anthropic" => Ok(Arc::new(
            super::anthropic::Anthropic::new(var(provider, "ANTHROPIC_API_KEY")?)
                .map_err(|e| e.to_string())?,
        )),
        #[cfg(feature = "bedrock")]
        "bedrock" => Ok(Arc::new(
            super::bedrock::Bedrock::from_env(var(provider, "AWS_REGION")?).await?,
        )),
        #[cfg(feature = "providers")]
        "gemini" => Ok(Arc::new(
            super::gemini::Gemini::from_env().map_err(|e| e.to_string())?,
        )),
        #[cfg(feature = "providers")]
        "openai" => Ok(Arc::new(
            super::openai::OpenAi::new(var(provider, "OPENAI_API_KEY")?)
                .map_err(|e| e.to_string())?,
        )),
        // The OpenAI-compatible wire every self-hosted server speaks — TGI,
        // vLLM, Ollama, llama.cpp, and Hugging Face's hosted router. The token
        // is optional because the common local server needs none.
        #[cfg(feature = "providers")]
        "chat-completions" => {
            let base = var(provider, "CHAT_COMPLETIONS_BASE_URL").map_err(|e| {
                format!(
                    "{e}. Point it at the server: Ollama is http://localhost:11434, vLLM \
                     http://localhost:8000, TGI http://localhost:8080, Hugging Face's router \
                     https://router.huggingface.co/v1"
                )
            })?;
            let mut driver =
                super::chat_completions::ChatCompletions::new(base).map_err(|e| e.to_string())?;
            if let Ok(token) = std::env::var("CHAT_COMPLETIONS_API_KEY") {
                driver = driver.bearer(token);
            }
            Ok(Arc::new(driver))
        }
        #[cfg(feature = "fake-model")]
        "fake" => {
            let fake = super::fake::FakeProvider::new();
            // Its deltas reach an observer only where one listens.
            fake.streaming();
            Ok(fake)
        }
        other => Err(format!(
            "no driver for provider '{other}'. This build ships {}; anything else is an \
             embedder's own driver, registered through RuntimeBuilder::provider",
            shipped().join(", "),
        )),
    }
}

/// Every provider name [`from_env`] can construct in this build.
///
/// Assembled from the same `cfg`s as the dispatch, so it cannot claim a
/// driver the build left out.
#[must_use]
pub fn shipped() -> Vec<&'static str> {
    let mut names = vec![
        #[cfg(feature = "providers")]
        "anthropic",
        #[cfg(feature = "providers")]
        "chat-completions",
        #[cfg(feature = "providers")]
        "gemini",
        #[cfg(feature = "providers")]
        "openai",
        #[cfg(feature = "bedrock")]
        "bedrock",
        #[cfg(feature = "fake-model")]
        "fake",
    ];
    names.sort_unstable();
    names
}

#[cfg(any(feature = "providers", feature = "bedrock"))]
fn var(provider: &str, name: &str) -> Result<String, String> {
    std::env::var(name)
        .map_err(|_| format!("{name} is not set, and provider '{provider}' needs it"))
}
