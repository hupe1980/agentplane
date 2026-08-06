//! Run an agent that is only a file.
//!
//! ```sh
//! agentplane run agent.yaml --input '{"ticket": "printer on fire"}'
//! agentplane validate agent.yaml
//! agentplane digest agent.yaml
//! ```
//!
//! This binary is the last step of the declarative tier. A manifest with
//! `spec.execution` already needs no skill, but it still needed a `main` to
//! build a runtime and hand it a driver — and Rust is the thing the tier exists
//! to remove. With this, a YAML file and an API key are the whole agent.
//!
//! That is also what makes the digest claim exact rather than nearly true:
//! everything the agent does is in the file, so there is no accompanying program
//! that could diverge from it.
//!
//! # Why the arguments are parsed by hand
//!
//! The surface is three verbs and five flags. A dependency that grows feature
//! flags and a derive macro to express that is a poor trade for a crate whose
//! argument is a small, auditable substrate — the same reason the SSE parser is
//! hand-rolled.

use std::process::ExitCode;
use std::sync::Arc;

use agentplane::journal::JournalStore;
use agentplane::manifest::Manifest;
use agentplane::model::ModelProvider;
use agentplane::runtime::{Mode, RunStatus, Runtime, RuntimeBuilder};
use agentplane::store::RedbStore;

const USAGE: &str = "\
agentplane — run an agent that is only a file

USAGE
    agentplane run <manifest.yaml> [OPTIONS]
    agentplane validate <manifest.yaml>
    agentplane digest <manifest.yaml>

OPTIONS
    --input <JSON>       the run's input; defaults to {}
    --input-file <PATH>  read the input from a file instead
    --store <PATH>       journal on disk; defaults to memory, which keeps nothing
    --replay <RUN_ID>    re-execute a recorded run instead of starting one
    --strict             with --replay: verify rather than resume

PROVIDERS
    The manifest names a provider; the key comes from the environment, never
    from the file — an agent's declaration must not change when its key does.

      anthropic         ANTHROPIC_API_KEY
      bedrock           AWS_REGION plus the standard AWS credential chain
      openai            OPENAI_API_KEY
      chat-completions  CHAT_COMPLETIONS_BASE_URL, pointing at any
                        OpenAI-compatible server — TGI, vLLM, Ollama,
                        llama.cpp, or Hugging Face's hosted router — plus
                        CHAT_COMPLETIONS_API_KEY when the server wants one.
                        This is how a local or Hugging Face model runs under
                        a governed manifest.
      fake              no key. Answers deterministically without a network,
                        so a manifest can be exercised before anyone pays
                        for it.
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("agentplane: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<ExitCode, String> {
    let Some(verb) = args.first().map(String::as_str) else {
        print!("{USAGE}");
        return Ok(ExitCode::FAILURE);
    };
    if matches!(verb, "-h" | "--help" | "help") {
        print!("{USAGE}");
        return Ok(ExitCode::SUCCESS);
    }

    let path = args
        .get(1)
        .ok_or_else(|| format!("`{verb}` needs a manifest path. See --help"))?;
    let text = std::fs::read_to_string(path).map_err(|e| format!("reading {path}: {e}"))?;

    // Parsed before anything else, for every verb. A manifest that does not
    // validate is not a thing to run, digest, or reason about.
    let manifest = Manifest::parse(&text).map_err(|e| e.to_string())?;

    match verb {
        "validate" => {
            println!(
                "ok: {} {}",
                manifest.metadata.name, manifest.metadata.version
            );
            Ok(ExitCode::SUCCESS)
        }
        "digest" => {
            println!("{}", manifest.digest().map_err(|e| e.to_string())?.to_hex());
            Ok(ExitCode::SUCCESS)
        }
        "run" => execute(&manifest, &Options::parse(&args[2..])?),
        other => Err(format!("unknown command `{other}`. See --help")),
    }
}

#[derive(Default)]
struct Options {
    input: Option<String>,
    input_file: Option<String>,
    store: Option<String>,
    replay: Option<String>,
    strict: bool,
}

impl Options {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut o = Self::default();
        let mut it = args.iter();
        while let Some(flag) = it.next() {
            // A flag needing a value and not getting one is an error, never a
            // default. Silently running with `{}` because `--input` was last on
            // the line is the kind of mistake that only shows up in the output.
            let mut value = || {
                it.next()
                    .cloned()
                    .ok_or_else(|| format!("{flag} needs a value"))
            };
            match flag.as_str() {
                "--input" => o.input = Some(value()?),
                "--input-file" => o.input_file = Some(value()?),
                "--store" => o.store = Some(value()?),
                "--replay" => o.replay = Some(value()?),
                "--strict" => o.strict = true,
                other => return Err(format!("unknown option `{other}`. See --help")),
            }
        }
        if o.input.is_some() && o.input_file.is_some() {
            return Err("--input and --input-file both given; which one did you mean?".into());
        }
        Ok(o)
    }

    fn read_input(&self) -> Result<serde_json::Value, String> {
        let text = match (&self.input, &self.input_file) {
            (Some(s), _) => s.clone(),
            (_, Some(p)) => std::fs::read_to_string(p).map_err(|e| format!("reading {p}: {e}"))?,
            _ => "{}".into(),
        };
        serde_json::from_str(&text).map_err(|e| format!("the input is not valid JSON: {e}"))
    }
}

fn execute(manifest: &Manifest, opts: &Options) -> Result<ExitCode, String> {
    if manifest.spec.execution.is_none() {
        return Err(format!(
            "manifest '{}' declares no `spec.execution`, so its behaviour is a skill somebody \
             wrote and there is nothing here for this binary to run. Register it in your own \
             binary with `RuntimeBuilder::agent(Agent::new(&manifest).skill(YourSkill))` instead",
            manifest.metadata.name
        ));
    }

    // Current-thread on purpose. A CLI runs one agent and exits, so a work
    // stealing pool buys nothing and would mean pulling `rt-multi-thread` into
    // a crate that has so far needed four tokio features.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the async runtime: {e}"))?;

    rt.block_on(async {
        let store: Arc<dyn JournalStore> = if let Some(path) = &opts.store {
            Arc::new(RedbStore::open(path).map_err(|e| e.to_string())?)
        } else {
            // Said out loud rather than assumed: a run whose journal disappears
            // is the opposite of what this crate is for.
            eprintln!("note: journaling to memory; this run will not survive the process");
            Arc::new(RedbStore::open_in_memory().map_err(|e| e.to_string())?)
        };

        let builder = with_providers(Runtime::builder(Arc::clone(&store)), manifest).await?;
        let agent = builder
            .agent(agentplane::runtime::Agent::new(manifest))
            .build();

        let outcome = if let Some(id) = &opts.replay {
            let run = agentplane::core::RunId::parse(id)
                .map_err(|e| format!("`{id}` is not a run id: {e}"))?;
            let mode = if opts.strict {
                Mode::Strict
            } else {
                Mode::Resume
            };
            agent.replay(run, mode).await
        } else {
            let capability = manifest
                .spec
                .capabilities
                .provides
                .first()
                .ok_or("the manifest provides no capability to run")?;
            agent.run(capability, opts.read_input()?).await
        }
        .map_err(|e| e.to_string())?;

        eprintln!("run {} — {:?}", outcome.run_id, outcome.status);
        if let Some(output) = &outcome.output {
            // The answer on stdout and everything else on stderr, so this
            // composes with a pipe instead of needing a flag to be quiet.
            println!("{output}");
        }

        // A refused, exhausted or failed run must not exit zero: whoever scripts
        // this needs the shell's own answer to "did it work".
        Ok(if matches!(outcome.status, RunStatus::Succeeded) {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        })
    })
}

/// Register a driver for each provider the manifest names — and only those.
///
/// Registering every driver whose key happens to be set would make the agent
/// runnable on a model its declaration does not name, the moment somebody
/// exports the wrong variable.
async fn with_providers(
    builder: RuntimeBuilder,
    manifest: &Manifest,
) -> Result<RuntimeBuilder, String> {
    let Some(models) = &manifest.spec.models else {
        return Ok(builder);
    };
    let mut builder = builder;
    let mut seen: Vec<String> = Vec::new();

    for m in [models.privileged.as_ref(), models.quarantined.as_ref()]
        .into_iter()
        .flatten()
    {
        if seen.contains(&m.provider) {
            continue;
        }
        seen.push(m.provider.clone());
        builder = builder.provider(m.provider.clone(), driver(&m.provider).await?);
    }
    Ok(builder)
}

async fn driver(name: &str) -> Result<Arc<dyn ModelProvider>, String> {
    match name {
        #[cfg(feature = "providers")]
        "anthropic" => Ok(Arc::new(
            agentplane::model::anthropic::Anthropic::new(key("ANTHROPIC_API_KEY")?)
                .map_err(|e| e.to_string())?,
        )),
        #[cfg(feature = "bedrock")]
        "bedrock" => Ok(Arc::new(
            agentplane::model::bedrock::Bedrock::from_env(
                std::env::var("AWS_REGION").map_err(|_| {
                    "AWS_REGION is not set, and the manifest names Bedrock".to_owned()
                })?,
            )
            .await?,
        )),
        #[cfg(feature = "providers")]
        "openai" => Ok(Arc::new(
            agentplane::model::openai::OpenAi::new(key("OPENAI_API_KEY")?)
                .map_err(|e| e.to_string())?,
        )),
        // The OpenAI-compatible wire every self-hosted server speaks — TGI,
        // vLLM, Ollama, llama.cpp, and Hugging Face's hosted router. The base
        // URL is deployment wiring, so it comes from the environment like a
        // key does; the token is optional because the common local server
        // needs none.
        #[cfg(feature = "providers")]
        "chat-completions" => {
            let base = key("CHAT_COMPLETIONS_BASE_URL").map_err(|_| {
                "CHAT_COMPLETIONS_BASE_URL is not set, and the manifest names the \
                 chat-completions provider. Point it at the server: Ollama is \
                 http://localhost:11434, vLLM http://localhost:8000, TGI \
                 http://localhost:8080, Hugging Face's router \
                 https://router.huggingface.co/v1"
                    .to_owned()
            })?;
            let mut driver = agentplane::model::chat_completions::ChatCompletions::new(base)
                .map_err(|e| e.to_string())?;
            if let Ok(token) = std::env::var("CHAT_COMPLETIONS_API_KEY") {
                driver = driver.bearer(token);
            }
            Ok(Arc::new(driver))
        }
        #[cfg(feature = "testkit")]
        "fake" => Ok(agentplane::testkit::FakeProvider::new()),
        other => Err(format!(
            "no driver for provider '{other}'. This binary ships anthropic, bedrock, openai, \
             chat-completions and fake; anything else is an embedder's own driver, registered \
             through RuntimeBuilder::provider"
        )),
    }
}

#[cfg(feature = "providers")]
fn key(var: &str) -> Result<String, String> {
    std::env::var(var)
        .map_err(|_| format!("{var} is not set, and the manifest names a provider that needs it"))
}
