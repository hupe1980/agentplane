//! Run an agent that is only a file.
//!
//! ```sh
//! agentplane run agent.yaml --input '{"ticket": "printer on fire"}'
//! agentplane run room.yaml  --input '{"topic": "durable execution"}'
//! agentplane validate room.yaml
//! agentplane digest room.yaml
//! ```
//!
//! A file may hold **several** manifests separated by `---`, the Kubernetes
//! packaging convention — so a multi-agent room deploys as one file with no
//! Rust anywhere. The file is packaging: each agent keeps its own digest.
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
//! # Why the arguments are *not* parsed by hand any more
//!
//! They were, and the reason was written down: *the surface is three verbs and
//! five flags, and a dependency that grows feature flags and a derive macro to
//! express that is a poor trade*. That was true. It stopped being true without
//! anybody noticing — `serve` and its wiring took the binary to **four verbs and
//! fourteen flags**, and the comment justifying the decision went on describing
//! the surface it was written against.
//!
//! The cost was not tidiness. A hand-rolled parser reads one flag table for
//! every verb, so a flag belonging to one was **silently accepted** by another:
//!
//! ```sh
//! agentplane run agent.yaml --push-host evil.example.com --tokens /nonexistent
//! # ran happily; both flags did nothing, and one of them is a security control
//! ```
//!
//! That is a declaration that does nothing, at the command line, and
//! I12 says a declared control must be enforced or rejected by the parser. What
//! a derive buys is that the bad state stops being representable: a flag lives on
//! its subcommand's struct, and `run --push-host` fails to parse by
//! construction. `--strict` `requires` `--replay` in the same way, and `--help`
//! is generated from the structs that enforce the flags rather than being prose
//! that can describe an option nobody implemented.
//!
//! It costs 9 crates on `cli` and **nothing on the library**, which is what
//! settled it: `cli` produces a binary and already carries three hundred.
//! Re-derive with `cargo tree --no-default-features --features cli -e normal
//! --prefix none | sort -u | wc -l` — a number in a comment nobody can check is
//! exactly how the sentence above this one went stale.

use std::process::ExitCode;
use std::sync::Arc;

use agentplane::core::Tainted;
use agentplane::journal::JournalStore;
use agentplane::manifest::Manifest;
use agentplane::model::ModelProvider;
use agentplane::runtime::{Mode, RunStatus, Runtime, RuntimeBuilder};
use agentplane::store::RedbStore;

fn install_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("warn,agentplane=info"));
    // `try_init` rather than `init`: failing to install a subscriber must not
    // take down a run that would otherwise have worked.
    let _ = fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

/// The command line.
///
/// One struct per verb, which is the whole point: a flag is reachable only from
/// the subcommand that uses it, so the parser refuses what the old hand-rolled
/// table silently accepted.
#[derive(clap::Parser, Debug)]
#[command(
    name = "agentplane",
    version,
    about = "Run an agent that is only a file",
    long_about = "Run, host and pin agents declared entirely in YAML.\n\n\
                  A file may hold several manifests separated by `---` (the \
                  Kubernetes convention), so a whole multi-agent room deploys as \
                  one file. Each document keeps its own digest — the file is \
                  packaging, not identity.",
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    verb: Verb,
}

#[derive(clap::Subcommand, Debug)]
enum Verb {
    /// Execute an agent once and print its answer.
    Run(RunArgs),
    /// Host an agent as an A2A 1.0 peer.
    Serve(Box<ServeArgs>),
    /// Check every document in a file, and say what is in it.
    Validate(FileArgs),
    /// Print the identity a registry pins.
    Digest(FileArgs),
    /// Check a journal's history and print what could not be checked.
    Audit(AuditArgs),
    /// Write a journal's records out as JSON Lines.
    Export(StoreArgs),
    /// Recompute an export and check it against its own checkpoint.
    Verify(VerifyArgs),
    /// Rebuild a store from an export, and prove it by its own checkpoint.
    Restore(RestoreArgs),
}

/// Rebuild a journal from an export.
#[derive(clap::Args, Debug)]
struct RestoreArgs {
    /// The export to read.
    file: String,

    /// Where to write the rebuilt journal. Must not already hold these runs —
    /// this rebuilds a history rather than merging one.
    #[arg(long, env = "AGENTPLANE_STORE")]
    store: String,
}

/// The restore drill: an export, and nothing else.
///
/// Takes a *file* rather than a store on purpose. This is the one verb that
/// needs neither the runtime that wrote the data nor the store it came from —
/// which is what makes it usable by somebody who was handed a copy and asked
/// whether it is the whole of it.
#[derive(clap::Args, Debug)]
struct VerifyArgs {
    /// The export to check. `-` reads standard input.
    file: String,

    /// Trust records signed by this key, as `<key-id>=<64 hex chars>`.
    /// Repeatable. With a key supplied, an unsigned record is a finding —
    /// that is the auditor's posture, since an unsigned record inside a
    /// signed history is the one an attacker who cannot sign would add.
    #[arg(long)]
    key: Vec<String>,
}

/// What `audit` takes beyond the shared store arguments: the evidence.
///
/// These flags exist because the library call has taken this evidence all
/// along, while the verb hardcoded none of it — so the signature check and the
/// deletion check were real and unreachable without writing Rust, which is the
/// dependency these verbs exist to remove. A control that must be linked
/// against is not one an independent party holds.
#[derive(clap::Args, Debug)]
struct AuditArgs {
    #[command(flatten)]
    store: StoreArgs,

    /// Trust records signed by this key, as `<key-id>=<64 hex chars>`.
    /// Repeatable. Without one, the report says signatures went unchecked.
    #[arg(long)]
    key: Vec<String>,

    /// A checkpoint saved earlier, as JSON — the `current` field of a previous
    /// audit report. This is the deletion check: a log that shrank or forked
    /// since that checkpoint is a finding, and without one the report says
    /// deletion went unchecked.
    #[arg(long)]
    prior: Option<String>,

    /// Treat an unsigned record as a failure.
    ///
    /// Off by default because history written before signing was configured is
    /// legitimately unsigned, and a wall of failures over a healthy plane
    /// teaches the reader to ignore the report.
    #[arg(long)]
    require_signatures: bool,
}

/// The arguments the two journal verbs share.
///
/// Both read a store and neither reads a manifest, which is the point: an
/// auditor holds a database file and a checkpoint somebody gave them, not the
/// deployment's source tree.
#[derive(clap::Args, Debug)]
struct StoreArgs {
    /// The journal to read. Required — there is nothing to audit or export in
    /// a memory store that this process did not itself write.
    #[arg(long, env = "AGENTPLANE_STORE")]
    store: String,

    /// Which runs, by outcome. Repeatable. Defaults to every sealed outcome.
    #[arg(long)]
    outcome: Vec<String>,

    /// How many runs to consider per outcome.
    #[arg(long, default_value_t = 1000)]
    limit: usize,
}

/// Build a verifier from repeated `--key <key-id>=<hex>` flags.
///
/// `None` when no key was given, so the report's `not_checked` half can say
/// signatures went unchecked — which is a different statement from checked and
/// clean, and the difference is the whole reason the field exists.
fn verifier_from(keys: &[String]) -> Result<Option<agentplane::policy::Ed25519Verifier>, String> {
    if keys.is_empty() {
        return Ok(None);
    }
    let mut verifier = agentplane::policy::Ed25519Verifier::new();
    for entry in keys {
        let Some((id, hex_key)) = entry.split_once('=') else {
            return Err(format!(
                "--key takes <key-id>=<64 hex chars>, got '{entry}' — the id is what records \
                 name as their signer, and the hex is the Ed25519 public key"
            ));
        };
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(hex_key, &mut bytes)
            .map_err(|e| format!("--key {id}: not 64 hex characters: {e}"))?;
        verifier = verifier
            .trust(id, &bytes)
            .map_err(|e| format!("--key {id}: not a valid Ed25519 public key: {e}"))?;
    }
    Ok(Some(verifier))
}

#[derive(clap::Args, Debug)]
struct FileArgs {
    /// The manifest, or a `---`-separated file of them.
    manifest: String,
}

#[derive(clap::Args, Debug)]
struct RunArgs {
    /// The manifest, or a `---`-separated file of them.
    manifest: String,

    /// The run's input, as JSON. Defaults to `{}`.
    #[arg(long, conflicts_with = "input_file")]
    input: Option<String>,

    /// Read the run's input from a file instead.
    #[arg(long)]
    input_file: Option<String>,

    /// Which capability to run. Optional when the file leaves no doubt.
    #[arg(long)]
    capability: Option<String>,

    /// Journal on disk. Defaults to memory, which keeps nothing.
    #[arg(long, env = "AGENTPLANE_STORE")]
    store: Option<String>,

    /// Re-execute a recorded run instead of starting one.
    #[arg(long)]
    replay: Option<String>,

    /// With --replay: verify rather than resume.
    #[arg(long, requires = "replay")]
    strict: bool,

    /// Run an MCP server as a child process and reach it as `tool://NAME/...`.
    ///
    /// Repeatable, one per server. The manifest grants the tools; this says only
    /// which transport reaches the server offering them, because an agent's
    /// digest must not change when it moves between a laptop and a cluster.
    /// Needs the `mcp-stdio` feature.
    #[arg(long, value_name = "NAME=COMMAND")]
    mcp: Vec<String>,
}

#[derive(clap::Args, Debug)]
struct ServeArgs {
    /// The manifest. `serve` hosts exactly one agent.
    manifest: String,

    /// Where callers reach this plane. Goes on the Agent Card, so it is the
    /// public URL rather than what you bind.
    #[arg(long, env = "AGENTPLANE_URL")]
    url: Option<String>,

    /// What to bind the peer surface to.
    #[arg(long, env = "AGENTPLANE_ADDR", default_value = "127.0.0.1:8080")]
    addr: String,

    /// A Cedar policy set. No default: a permissive engine and no engine are the
    /// same behaviour, and only one of them looks governed.
    #[arg(long, env = "AGENTPLANE_POLICY")]
    policy: Option<String>,

    /// Bearer tokens naming the callers this plane accepts.
    #[arg(long, env = "AGENTPLANE_TOKENS")]
    tokens: Option<String>,

    /// Journal on disk. Required: a served task's id is a promise it can be
    /// fetched again.
    #[arg(long, env = "AGENTPLANE_STORE")]
    store: Option<String>,

    /// Also serve the operator surface — the worklist, task decisions and
    /// `GET /runs?outcome=quarantined` — on its own listener.
    #[arg(long, env = "AGENTPLANE_OPERATOR_ADDR")]
    operator_addr: Option<String>,

    /// How often deadlines, task expiry, dead letters and due timers are swept.
    /// `0` runs the sweep from your own scheduler instead.
    #[arg(long, value_name = "SECS", env = "AGENTPLANE_SWEEP_EVERY")]
    sweep_every: Option<u32>,

    /// Permit A2A push notifications to this exact host. Repeatable.
    ///
    /// Without one, push is not wired and the Agent Card advertises it as
    /// absent rather than claiming a capability nothing serves.
    #[arg(long, value_name = "HOST")]
    push_host: Vec<String>,

    /// Run an MCP server as a child process and reach it as `tool://NAME/...`.
    #[arg(long, value_name = "NAME=COMMAND")]
    mcp: Vec<String>,
}

/// The two verbs that read a journal instead of a manifest.
///
/// One function because they differ only in what they do with the run list, and
/// the half that is easy to get wrong — *which* runs, and saying so when the
/// limit truncated — is the half they share. `audit` is `None` for an export,
/// and carries the evidence flags for an audit.
fn journal_verb(opts: &StoreArgs, audit: Option<&AuditArgs>) -> Result<ExitCode, String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the async runtime: {e}"))?;

    rt.block_on(async {
        let redb = Arc::new(RedbStore::open(&opts.store).map_err(|e| e.to_string())?);
        let store: Arc<dyn JournalStore> = redb.clone();
        // The same file holds the case layer, so the export always carries it.
        // An optional flag here would be a way to quietly produce the file the
        // verifier flags — the matters the journal names, missing.
        let cases: Arc<dyn agentplane::case::CaseStore> = redb;

        // The library's own list, not literals restated here: the store indexes
        // runs *by* outcome and has no "all runs" query, so an export has to
        // name every sealed outcome — and a copy of that list in a binary is
        // where a new sealing outcome would be silently dropped from exactly
        // the artifact an auditor asks for.
        let wanted: Vec<String> = if opts.outcome.is_empty() {
            agentplane::runtime::SEALED_OUTCOMES
                .iter()
                .map(|s| (*s).to_owned())
                .collect()
        } else {
            opts.outcome.clone()
        };

        let mut runs = Vec::new();
        let mut truncated = Vec::new();
        for outcome in &wanted {
            let found = store
                .runs_by_outcome(outcome, opts.limit + 1)
                .await
                .map_err(|e| e.to_string())?;
            // One more than asked for, so a full page and an overflowing one are
            // distinguishable. An export that quietly stopped at the limit is
            // shaped exactly like a complete one.
            if found.len() > opts.limit {
                truncated.push(outcome.clone());
            }
            runs.extend(found.into_iter().take(opts.limit));
        }

        // Said on stderr so it survives `> out.jsonl`, and said before the work
        // rather than after: an operator who pipes this somewhere is not going
        // to re-read the tail.
        if !truncated.is_empty() {
            eprintln!(
                "warning: --limit {} was reached for: {}. This is a partial view; \
                 raise --limit or narrow --outcome",
                opts.limit,
                truncated.join(", ")
            );
        }

        let Some(audit) = audit else {
            let stdout = std::io::stdout();
            let trailer = agentplane::export::to_jsonl(
                &store,
                Some(&cases),
                &runs,
                std::io::BufWriter::new(stdout.lock()),
            )
            .await
            .map_err(|e| e.to_string())?;
            eprintln!(
                "exported {} record(s) from {}/{} run(s) and {} case(s)",
                trailer.records, trailer.runs_exported, trailer.runs_requested, trailer.cases
            );
            if !trailer.unreadable.is_empty() {
                for u in &trailer.unreadable {
                    eprintln!("unreadable: {} — {}", u.run, u.reason);
                }
                return Ok(ExitCode::FAILURE);
            }
            return Ok(ExitCode::SUCCESS);
        };

        // An audit with no prior checkpoint and no key still checks every
        // chain, and reports the two things it could not do. That is the
        // honest default for somebody who has just been handed a database —
        // and the flags are how they narrow it on the second pass, with the
        // key the operator published and the checkpoint the first pass printed.
        let verifier = verifier_from(&audit.key)?;
        let prior: Option<agentplane::journal::Checkpoint> = match &audit.prior {
            Some(path) => Some(
                std::fs::read_to_string(path)
                    .map_err(|e| format!("reading --prior {path}: {e}"))
                    .and_then(|text| {
                        serde_json::from_str(&text).map_err(|e| {
                            format!(
                                "--prior {path} is not a checkpoint — expected the `current` \
                                 field of an earlier audit report: {e}"
                            )
                        })
                    })?,
            ),
            None => None,
        };
        let evidence = agentplane::audit::Evidence {
            prior: prior.as_ref(),
            verifier: verifier
                .as_ref()
                .map(|v| v as &dyn agentplane::core::Verifier),
            require_signatures: audit.require_signatures,
        };
        let report = agentplane::audit::audit(&store, &runs, &evidence)
            .await
            .map_err(|e| e.to_string())?;
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
        // Findings are a failure; `not_checked` is not. An auditor who supplied
        // nothing gets a clean exit and a populated `not_checked`, and it is
        // their call whether that is enough.
        Ok(if report.is_sound() {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        })
    })
}

/// Read and validate the manifests, for every verb.
///
/// A manifest that does not validate is not a thing to run, digest, or reason
/// about — and in a multi-document file every document is held to that, because
/// deploying two thirds of a room is worse than deploying none of it.
fn manifests_at(path: &str) -> Result<Vec<Manifest>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("reading {path}: {e}"))?;
    Manifest::parse_all(&text).map_err(|e| e.to_string())
}

fn dispatch(cli: Cli) -> Result<ExitCode, String> {
    match cli.verb {
        Verb::Validate(a) => {
            for m in &manifests_at(&a.manifest)? {
                println!("ok: {} {}", m.metadata.name, m.metadata.version);
            }
            Ok(ExitCode::SUCCESS)
        }
        Verb::Digest(a) => {
            let manifests = manifests_at(&a.manifest)?;
            // One document prints the bare digest, so scripts that pin a single
            // agent keep working; a room prints one line per agent, because a
            // bundle digest would make one agent's edit move its neighbours'
            // identities.
            if let [only] = manifests.as_slice() {
                println!("{}", only.digest().map_err(|e| e.to_string())?.to_hex());
            } else {
                for m in &manifests {
                    println!(
                        "{}  {} {}",
                        m.digest().map_err(|e| e.to_string())?.to_hex(),
                        m.metadata.name,
                        m.metadata.version
                    );
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Verb::Audit(a) => journal_verb(&a.store, Some(&a)),
        Verb::Export(a) => journal_verb(&a, None),
        Verb::Restore(a) => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| format!("could not start the async runtime: {e}"))?;
            rt.block_on(async {
                let redb = Arc::new(RedbStore::open(&a.store).map_err(|e| e.to_string())?);
                let store: Arc<dyn JournalStore> = redb.clone();
                let cases: Arc<dyn agentplane::case::CaseStore> = redb;
                let file =
                    std::fs::File::open(&a.file).map_err(|e| format!("reading {}: {e}", a.file))?;
                let report = agentplane::export::from_jsonl(
                    &store,
                    Some(&cases),
                    std::io::BufReader::new(file),
                )
                .await
                .map_err(|e| e.to_string())?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
                );
                // The result is the comparison, not the loading. Equal roots at
                // equal size means every record, in every run, in the order the
                // log recorded them, rebuilt to the same commitment.
                Ok(if report.is_faithful() {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::FAILURE
                })
            })
        }
        Verb::Verify(a) => {
            let verifier = verifier_from(&a.key)?;
            let verifier = verifier
                .as_ref()
                .map(|v| v as &dyn agentplane::core::Verifier);
            let report = if a.file == "-" {
                agentplane::export::verify(std::io::stdin().lock(), verifier)
            } else {
                std::fs::File::open(&a.file)
                    .map_err(|e| format!("reading {}: {e}", a.file))
                    .and_then(|f| {
                        agentplane::export::verify(std::io::BufReader::new(f), verifier)
                            .map_err(|e| e.to_string())
                    })
                    .map_err(std::io::Error::other)
            }
            .map_err(|e| e.to_string())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
            );
            // Findings fail; `not_checked` does not. A pass with no key has
            // established less, and saying so is different from failing.
            Ok(if report.is_sound() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }
        Verb::Run(a) => {
            let manifests = manifests_at(&a.manifest)?;
            execute(&manifests, &a)
        }
        Verb::Serve(a) => {
            let manifests = manifests_at(&a.manifest)?;
            serve(&manifests, &a)
        }
    }
}

fn main() -> ExitCode {
    install_tracing();
    // `clap` prints its own diagnostics and exits; everything past the parse is
    // this binary's own vocabulary.
    let cli = <Cli as clap::Parser>::parse();
    match dispatch(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("agentplane: {e}");
            ExitCode::FAILURE
        }
    }
}

impl RunArgs {
    fn read_input(&self) -> Result<serde_json::Value, String> {
        let text = match (&self.input, &self.input_file) {
            (Some(s), _) => s.clone(),
            (_, Some(p)) => std::fs::read_to_string(p).map_err(|e| format!("reading {p}: {e}"))?,
            _ => "{}".into(),
        };
        serde_json::from_str(&text).map_err(|e| format!("the input is not valid JSON: {e}"))
    }
}

/// How many due webhook registrations one push tick delivers.
///
/// Bounded, and the report says when it came back full — a worker still draining
/// a backlog is one not delivering the next notification, and a capped result
/// shaped like a complete one is the silent-truncation shape.
#[cfg(all(feature = "a2a-server", feature = "cedar"))]
const PUSH_BATCH: usize = 64;

/// How often a served plane sweeps, when nobody says otherwise.
///
/// Short enough that a breached deadline is noticed in the same minute, long
/// enough that an idle plane is not doing constant store reads.
/// `--sweep-every 0` turns it off, for a deployment running the sweep from its
/// own scheduler.
#[cfg(all(feature = "a2a-server", feature = "cedar"))]
const DEFAULT_SWEEP_SECONDS: u32 = 30;

/// Host this agent as an A2A 1.0 peer.
///
/// The A2A server, the Agent Card and the conformance work behind them all
/// existed already and could only be reached by writing Rust — which is the one
/// thing the declarative tier exists to remove. A manifest that can be *run*
/// from a file but not *hosted* from one leaves the interoperability half of
/// this crate behind a language barrier.
///
/// # Everything here fails closed, and each refusal says why
///
/// Both `--policy` and `--tokens` are required with no default. That is the
/// whole design and not an inconvenience to be smoothed away later: a permissive
/// engine and no engine are the same behaviour, and a server that authenticates
/// nobody has no actor to record a decision against. `A2aServer::new` already
/// refuses a runtime with no policy engine and no case layer; this wires both
/// rather than working around either.
#[cfg(all(feature = "a2a-server", feature = "cedar"))]
fn serve(manifests: &[Manifest], opts: &ServeArgs) -> Result<ExitCode, String> {
    use agentplane::api::a2a::A2aServer;
    use agentplane::api::tokens::TokenAuthenticator;

    // One card, one agent. A room is several manifests and A2A's well-known
    // card path is singular, so serving a bundle would have to pick one and
    // silently not serve the others.
    let [manifest] = manifests else {
        return Err(format!(
            "`serve` hosts one agent and this file holds {}. A2A's card path is \
             well-known and singular, so a room would have to advertise one \
             document and quietly not serve the rest — split the file, or run \
             one process per agent",
            manifests.len()
        ));
    };

    let url = opts.url.as_deref().ok_or(
        "`serve` needs --url: the address callers reach this plane on. It goes on the \
         Agent Card, so it is the public URL rather than what you bind — an agent's \
         declaration must not change when its address does",
    )?;
    let policy_path = opts.policy.as_deref().ok_or(
        "`serve` needs --policy: a Cedar policy set. There is deliberately no default — \
         a permissive engine and no engine are the same behaviour, and only one of them \
         looks governed",
    )?;
    let tokens_path = opts.tokens.as_deref().ok_or(
        "`serve` needs --tokens: bearer tokens naming the callers this plane accepts. \
         There is deliberately no default — a server that authenticates nobody has no \
         actor to record a decision against",
    )?;
    let addr = opts.addr.as_str();

    let policy_src = std::fs::read_to_string(policy_path)
        .map_err(|e| format!("reading the policy set {policy_path}: {e}"))?;
    let policy = agentplane::policy::CedarEngine::new(&policy_src)
        .map_err(|e| format!("the policy set {policy_path} was refused: {e}"))?;
    let tokens_src = std::fs::read_to_string(tokens_path)
        .map_err(|e| format!("reading the token file {tokens_path}: {e}"))?;
    // One `Arc`, two surfaces: the same accepted credentials govern both, so a
    // token added for a peer is not silently also an operator credential —
    // that separation is policy's job, on `a2a:*` versus `api:*` actions.
    let auth: Arc<dyn agentplane::api::Authenticator> = Arc::new(
        TokenAuthenticator::from_yaml(&tokens_src)
            .map_err(|e| format!("the token file {tokens_path} was refused: {e}"))?,
    );
    let operator_auth = Arc::clone(&auth);

    // Multi-threaded here and current-thread in `execute`, because these are
    // different programs wearing one binary: a run does one agent's work and
    // exits, a server takes concurrent requests for as long as it is up.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the async runtime: {e}"))?;

    rt.block_on(async move {
        // A journal in memory would make every served task disappear on
        // restart, which is the opposite of what a peer promises when it hands
        // back a task id. Refused rather than defaulted.
        let path = opts.store.as_deref().ok_or(
            "`serve` needs --store: a served task's id is a promise that it can be \
             fetched again, and an in-memory journal breaks that promise at the next \
             restart. `run` may journal to memory because it exits with its answer",
        )?;
        let store = Arc::new(RedbStore::open(path).map_err(|e| e.to_string())?);

        let mut builder = with_providers(
            Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>),
            std::slice::from_ref(manifest),
        )
        .await?;
        // **The whole plane, not a corner of it.** One redb file backs every
        // store this runtime has, and a server that wired only the journal and
        // the case layer would accept an agent that waits, sleeps or opens a
        // human task and then never make progress on any of them — a suspended
        // run is a row, and something has to come back for it.
        for (name, client) in connect_mcp_servers(&opts.mcp).await? {
            builder = builder.tool_server(name, client);
        }
        builder = builder
            .cases(Arc::clone(&store) as Arc<dyn agentplane::case::CaseStore>)
            .tasks(Arc::clone(&store) as Arc<dyn agentplane::case::TaskStore>)
            .events(Arc::clone(&store) as Arc<dyn agentplane::case::EventStore>)
            .timers(Arc::clone(&store) as Arc<dyn agentplane::case::TimerStore>)
            .memory(Arc::clone(&store) as Arc<dyn agentplane::memory::MemoryStore>)
            .policy(Arc::new(policy) as Arc<dyn agentplane::core::PolicyEngine>)
            .agent(agentplane::runtime::Agent::new(manifest));
        let runtime = builder.try_build().map_err(|e| e.to_string())?;

        let security = agentplane::peers::CardSecurity::bearer("bearer", Vec::<String>::new());
        let mut server = A2aServer::new(Arc::clone(&runtime), auth, &security, manifest, url)
            .map_err(|e| e.to_string())?;

        server = wire_push(server, &opts.push_host, &store)?;
        if let Some(worker) = server.push_worker() {
            spawn_push_worker(worker, opts.sweep_every.unwrap_or(DEFAULT_SWEEP_SECONDS));
        }

        spawn_sweeper(&runtime, opts.sweep_every.unwrap_or(DEFAULT_SWEEP_SECONDS));

        if let Some(operator_addr) = opts.operator_addr.as_deref() {
            spawn_operator_surface(&runtime, operator_auth, operator_addr).await?;
        }

        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| format!("could not bind {addr}: {e}"))?;
        // stderr, so the answer stream stays clean for whatever pipes this.
        eprintln!(
            "serving {} {} on {addr} as {url}",
            manifest.metadata.name, manifest.metadata.version
        );
        eprintln!("  card: {url}/.well-known/agent-card.json");
        axum::serve(listener, server.router())
            .await
            .map_err(|e| format!("the server stopped: {e}"))?;
        Ok(ExitCode::SUCCESS)
    })
}

/// Sweep on a clock, because nothing else will.
///
/// Deadlines warn and breach, tasks expire, dead letters accumulate, and a run
/// suspended on `cx.sleep` or a correlated event is a **row** waiting for a
/// sweep — not a task waiting on a timer. Without this a served plane accepts
/// all of that and silently never progresses any of it, which is worse than
/// refusing it: the agent looks like it is working.
///
/// `sweep` is idempotent by contract, so a tick overlapping the last one, or a
/// second instance sweeping the same store, is safe. `0` turns it off for a
/// deployment driving the sweep from its own scheduler.
#[cfg(all(feature = "a2a-server", feature = "cedar"))]
fn spawn_sweeper(runtime: &Arc<Runtime>, every: u32) {
    if every == 0 {
        return;
    }
    let sweeper = Arc::clone(runtime);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(u64::from(every)));
        loop {
            tick.tick().await;
            // The sweeper's clock is the wall clock by design: it decides *when*
            // an obligation is late, which is not a journaled observation of a
            // run. Every transition it makes is journaled by the sweep's own
            // sealed run.
            #[allow(clippy::disallowed_methods)]
            let now = time::OffsetDateTime::now_utc();
            match sweeper.fire_timers(now).await {
                Ok(w) if w.failed > 0 => {
                    tracing::warn!(fired = w.fired, failed = w.failed, "timer wakes failed");
                }
                Ok(w) if w.fired > 0 => tracing::info!(fired = w.fired, "timers fired"),
                Ok(_) => {}
                Err(error) => tracing::error!(%error, "firing timers failed"),
            }
            match sweeper
                .sweep(now, std::time::Duration::from_secs(3600))
                .await
            {
                // A sweep that decided something, hit its cap, or lost its own
                // evidence is a finding an operator must clear rather than a
                // line in a log — I13 applies to the sweeper's own report.
                Ok(report) if report.needs_attention() => {
                    tracing::warn!(?report, "the sweep needs attention");
                }
                Ok(report) if !report.is_quiet() => tracing::info!(?report, "swept"),
                Ok(_) => {}
                Err(error) => tracing::error!(%error, "the sweep failed"),
            }
        }
    });
}

/// The operator surface, on its **own listener**.
///
/// Off unless asked for, and deliberately not the peer's port. Sharing it would
/// put the worklist, task decisions and `GET /runs?outcome=quarantined` behind
/// the public address an A2A peer is handed — one policy mistake away from a
/// peer reading every run on the plane. A separate binding lets an operator keep
/// this on loopback or a private interface while the card stays public.
///
/// The real separation is **policy**, not the port: both surfaces authenticate
/// against the same token file, and a peer token permitted only `a2a:*` is
/// refused `api:run.list` even when it reaches this socket. The port is defence
/// in depth.
///
/// # Errors
///
/// If the plane has no policy engine, or the address cannot be bound.
#[cfg(all(feature = "a2a-server", feature = "cedar"))]
async fn spawn_operator_surface(
    runtime: &Arc<Runtime>,
    auth: Arc<dyn agentplane::api::Authenticator>,
    addr: &str,
) -> Result<(), String> {
    let api = agentplane::api::Api::new(Arc::clone(runtime), auth).map_err(|e| e.to_string())?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("could not bind the operator surface {addr}: {e}"))?;
    eprintln!("  operator: http://{addr}/runs?outcome=failed");
    tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, api.router()).await {
            tracing::error!(%error, "the operator surface stopped");
        }
    });
    Ok(())
}

/// Connect the MCP servers named on the command line.
///
/// # Why the command line and not the manifest
///
/// The manifest grants `tool://tickets/read`; **which transport reaches
/// `tickets`** is deployment wiring, exactly as a model's base URL and an API
/// key are. Putting it in the reviewed file would mean an agent's declaration —
/// and therefore its digest — changed when it moved between a laptop and a
/// cluster, and the whole point of the digest is that it does not.
///
/// # The trust boundary, stated
///
/// This **executes a command**. That is not an escalation over what the caller
/// already had: the operator typed it on the same command line as the manifest
/// path, the policy set and the token file, and anyone who can choose this
/// process's arguments can run their own process instead. It is emphatically
/// *not* a capability the manifest, a model, or an A2A peer can reach — nothing
/// in a run's data path chooses a server, only the operator's argv does.
///
/// The command is split on whitespace, which covers `npx -y @scope/server` and
/// `python server.py` and stops short of a shell: no globbing, no pipelines, no
/// `$(...)`. A path containing spaces needs a wrapper script, and that is the
/// right trade for not embedding a shell in a governed runtime.
#[cfg(feature = "mcp-stdio")]
async fn connect_mcp_servers(
    specs: &[String],
) -> Result<Vec<(String, Arc<dyn agentplane::tools::ToolClient>)>, String> {
    use rmcp::ServiceExt as _;

    let mut wired = Vec::with_capacity(specs.len());
    for spec in specs {
        let (name, command) = spec.split_once('=').ok_or_else(|| {
            format!(
                "--mcp wants `<server>=<command>`, got `{spec}`. The server name is the \
                 one your manifest's grants use: a grant `tool://tickets/read` needs \
                 `--mcp tickets=...`"
            )
        })?;
        if name.trim().is_empty() {
            return Err(format!("--mcp `{spec}` names no server"));
        }
        let mut parts = command.split_whitespace();
        let program = parts
            .next()
            .ok_or_else(|| format!("--mcp `{spec}` names server `{name}` but no command"))?;
        let mut process = tokio::process::Command::new(program);
        process.args(parts);
        let transport = rmcp::transport::TokioChildProcess::new(process)
            .map_err(|e| format!("could not start the MCP server `{name}` (`{command}`): {e}"))?;
        // `host_info` is the crate's own client declaration — it negotiates
        // Tasks and deliberately omits elicitation, sampling, roots and
        // subscriptions, none of which has a governed runtime callback path.
        let service = agentplane::tools::McpClient::host_info()
            .serve(transport)
            .await
            .map_err(|e| format!("the MCP server `{name}` did not initialise: {e}"))?;
        eprintln!("  mcp: {name} <- {command}");
        wired.push((
            name.to_owned(),
            Arc::new(agentplane::tools::McpClient::new(name, Arc::new(service)))
                as Arc<dyn agentplane::tools::ToolClient>,
        ));
    }
    Ok(wired)
}

/// The same, in a build without the transport.
///
/// Naming the feature rather than ignoring the flag: a `--mcp` that silently did
/// nothing would produce a plane whose build then refuses for a *different*
/// reason — no tool catalogue — and send a reader looking at their manifest for
/// a mistake that is in their build.
#[cfg(not(feature = "mcp-stdio"))]
#[allow(clippy::unused_async)]
async fn connect_mcp_servers(
    specs: &[String],
) -> Result<Vec<(String, Arc<dyn agentplane::tools::ToolClient>)>, String> {
    if specs.is_empty() {
        return Ok(Vec::new());
    }
    Err(
        "this build cannot run an MCP server: `--mcp` needs the `mcp-stdio` feature. \
         Reinstall with `--features cli,mcp-stdio`, or use the `:full` container \
         image, which is built with it"
            .to_owned(),
    )
}

/// Turn on A2A push, if the operator granted anywhere to send it.
///
/// `--push-host` is the *whole* configuration, and that is the point:
/// [`PushSender`](agentplane::push::PushSender) already owns HTTPS-only, the
/// all-answer public-IP check, DNS pinning, manual per-hop redirects, the
/// timeout and secret redaction. What an operator supplies is **where**, which
/// is the one thing the crate cannot decide for them.
///
/// No host means push is not wired **and the card says so** — advertising a
/// capability nothing serves is worse than not having it, because a peer that
/// registers a webhook and never hears back has a worse day than one told up
/// front.
///
/// # Errors
///
/// If the card has already been signed, since push changes what the signature
/// covers.
#[cfg(all(feature = "a2a-server", feature = "cedar"))]
fn wire_push(
    server: agentplane::api::a2a::A2aServer,
    hosts: &[String],
    store: &Arc<RedbStore>,
) -> Result<agentplane::api::a2a::A2aServer, String> {
    if hosts.is_empty() {
        return Ok(server);
    }
    let policy = hosts
        .iter()
        .fold(agentplane::push::PushPolicy::new(), |policy, host| {
            policy.allow_host(host)
        });
    let server = server
        .with_push(
            Arc::clone(store) as Arc<dyn agentplane::push::PushStore>,
            Arc::new(agentplane::push::PushSender::new(policy))
                as Arc<dyn agentplane::push::PushTransport>,
        )
        .map_err(|e| e.to_string())?;
    for host in hosts {
        eprintln!("  push: https://{host}");
    }
    Ok(server)
}

/// Deliver due webhooks on a clock.
///
/// The task journal is the outbox: each receiver stores its first unacknowledged
/// sequence and the cursor advances only after HTTP 2xx, so a crash after the
/// POST but before persistence **repeats** an event rather than losing it —
/// which is the right way round, and which A2A receivers are required to
/// tolerate.
///
/// Shares the sweeper's cadence because it is the same job: the operator's
/// scheduler running the plane's periodic work. Several instances may race and
/// produce duplicates; cursors advance monotonically, so none can regress.
#[cfg(all(feature = "a2a-server", feature = "cedar"))]
fn spawn_push_worker(worker: agentplane::api::a2a::A2aPushWorker, every: u32) {
    if every == 0 {
        return;
    }
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(u64::from(every)));
        loop {
            tick.tick().await;
            #[allow(clippy::disallowed_methods)]
            let at = time::OffsetDateTime::now_utc().unix_timestamp();
            let Ok(at) = u64::try_from(at) else { continue };
            match worker.run_once(at, PUSH_BATCH).await {
                // A batch that came back full is a backlog, and a registration
                // given up on is a peer that will never hear back. Neither may
                // produce the same numbers — or the same log level — as a quiet
                // plane, which is I13 applied to this worker's own report.
                Ok(report) if report.needs_attention() => {
                    tracing::warn!(?report, "push delivery needs attention");
                }
                Ok(report) if report.registrations > 0 => {
                    tracing::info!(?report, "push delivered");
                }
                Ok(_) => {}
                Err(error) => tracing::error!(%error, "push delivery failed"),
            }
        }
    });
}

/// The same verb, in a build that cannot answer it.
///
/// A binary that met `serve` with *unknown command* would be telling a reader
/// the feature does not exist, when it does and is one build flag away. Naming
/// the flag is the difference between a dead end and a next step — the same
/// reason the provider list is derived from the build rather than written out.
#[cfg(not(all(feature = "a2a-server", feature = "cedar")))]
#[allow(clippy::unnecessary_wraps)]
fn serve(_manifests: &[Manifest], _opts: &ServeArgs) -> Result<ExitCode, String> {
    Err(
        "this build cannot serve: `serve` needs the `a2a-server` and `cedar` features. \
         Reinstall with `--features cli,a2a-server,cedar`, or use the `:full` \
         container image, which is built with them"
            .to_owned(),
    )
}

fn execute(manifests: &[Manifest], opts: &RunArgs) -> Result<ExitCode, String> {
    for manifest in manifests {
        if manifest.spec.execution.is_none() {
            return Err(format!(
                "manifest '{}' declares no `spec.execution`, so its behaviour is a skill somebody \
                 wrote and there is nothing here for this binary to run. Register it in your own \
                 binary with `RuntimeBuilder::agent(Agent::new(&manifest).skill(YourSkill))` instead",
                manifest.metadata.name
            ));
        }
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

        let mut builder = with_providers(Runtime::builder(Arc::clone(&store)), manifests).await?;
        for (name, client) in connect_mcp_servers(&opts.mcp).await? {
            builder = builder.tool_server(name, client);
        }
        for manifest in manifests {
            builder = builder.agent(agentplane::runtime::Agent::new(manifest));
        }
        // `try_build`, because everything on this plane arrived as input: a
        // wiring mistake in a file somebody handed us is a refusal with a
        // sentence, not a programmer error worth a crash.
        let agent = builder.try_build().map_err(|e| e.to_string())?;

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
            let capability = entry_capability(manifests, opts.capability.as_deref())?;
            agent
                .run(&capability, Tainted::trusted(opts.read_input()?))
                .await
        }
        .map_err(|e| e.to_string())?;

        eprintln!("run {} — {:?}", outcome.run_id, outcome.status);
        if let Some(output) = &outcome.output {
            // The answer on stdout and everything else on stderr, so this
            // composes with a pipe instead of needing a flag to be quiet.
            println!("{}", output.peek());
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
    manifests: &[Manifest],
) -> Result<RuntimeBuilder, String> {
    let mut builder = builder;
    let mut seen: Vec<String> = Vec::new();

    for manifest in manifests {
        let Some(models) = &manifest.spec.models else {
            continue;
        };
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
    }
    Ok(builder)
}

/// Which capability a `run` starts, when the file holds a room.
///
/// Explicit beats implicit, and implicit is allowed only where the file leaves
/// no doubt: `--capability` always wins; a file providing exactly one
/// capability runs it; and a room with exactly one agent declaring
/// `topology.role: orchestrator` — whose declaration provides exactly one
/// capability — starts there, because the topology *is* the file saying where
/// the room begins. Anything else is a refusal that lists the candidates,
/// never a guess.
fn entry_capability(manifests: &[Manifest], asked: Option<&str>) -> Result<String, String> {
    let all: Vec<(&str, &str)> = manifests
        .iter()
        .flat_map(|m| {
            m.spec
                .capabilities
                .provides
                .iter()
                .map(move |c| (m.metadata.name.as_str(), c.as_str()))
        })
        .collect();

    if let Some(asked) = asked {
        if all.iter().any(|(_, c)| *c == asked) {
            return Ok(asked.to_owned());
        }
        return Err(format!(
            "no agent in this file provides '{asked}'. It provides: {}",
            all.iter().map(|(_, c)| *c).collect::<Vec<_>>().join(", ")
        ));
    }
    if let [(_, only)] = all.as_slice() {
        return Ok((*only).to_owned());
    }
    let orchestrators: Vec<&Manifest> = manifests
        .iter()
        .filter(|m| {
            m.spec
                .topology
                .as_ref()
                .is_some_and(|t| t.role == agentplane::manifest::Role::Orchestrator)
        })
        .collect();
    if let [desk] = orchestrators.as_slice()
        && let [only] = desk.spec.capabilities.provides.as_slice()
    {
        return Ok(only.clone());
    }
    Err(format!(
        "this file provides several capabilities and no single orchestrator to \
         start at — say which one with --capability. It provides: {}",
        all.iter()
            .map(|(agent, c)| format!("{c} ({agent})"))
            .collect::<Vec<_>>()
            .join(", ")
    ))
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
        // `GEMINI_API_KEY`, falling back to `GOOGLE_API_KEY`: both are in wide
        // use, and a deployment that exported the other one would otherwise
        // meet an authentication failure naming neither.
        #[cfg(feature = "providers")]
        "gemini" => Ok(Arc::new(
            agentplane::model::gemini::Gemini::from_env().map_err(|e| e.to_string())?,
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
            "no driver for provider '{other}'. This binary ships {}; anything else is an \
             embedder's own driver, registered through RuntimeBuilder::provider",
            shipped_providers().join(", "),
        )),
    }
}

/// Every provider name *this* binary can construct.
///
/// Assembled from the same `cfg`s as the dispatch above. It used to be a
/// hand-written sentence — "this binary ships anthropic, bedrock, gemini,
/// openai, chat-completions and fake" — which was true only because the `cli`
/// feature happened to force every one of them on. The moment `bedrock` became
/// opt-in, that sentence started telling a reader their build had a driver it
/// did not have, and the compiler has nothing to say about a string. A list
/// derived from the build cannot disagree with the build.
fn shipped_providers() -> Vec<&'static str> {
    #[allow(unused_mut)]
    let mut names: Vec<&'static str> = Vec::new();
    #[cfg(feature = "providers")]
    names.extend(["anthropic", "chat-completions", "gemini", "openai"]);
    #[cfg(feature = "bedrock")]
    names.push("bedrock");
    #[cfg(feature = "testkit")]
    names.push("fake");
    names.sort_unstable();
    names
}

#[cfg(feature = "providers")]
fn key(var: &str) -> Result<String, String> {
    std::env::var(var)
        .map_err(|_| format!("{var} is not set, and the manifest names a provider that needs it"))
}
