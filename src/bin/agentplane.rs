//! Run an agent that is only a file.
//!
//! ```sh
//! agentplane run agent.yaml --input '{"ticket": "printer on fire"}'
//! agentplane run room.yaml  --input '{"topic": "durable execution"}'
//! echo '{"ticket": "…"}' | agentplane run agent.yaml --input -
//! agentplane replay 01J… --store runs.redb --manifest agent.yaml --strict
//! agentplane card agent.yaml --url https://agents.example.com
//! agentplane validate room.yaml
//! agentplane digest room.yaml
//! ```
//!
//! A file may hold **several** manifests separated by `---`, the Kubernetes
//! packaging convention — so a multi-agent room deploys as one file with no
//! Rust anywhere. The file is packaging: each agent keeps its own digest.
//!
//! This binary completes the declarative tier. A manifest with
//! `spec.execution` needs no skill, and this is the `main` that builds a
//! runtime and hands it a driver — Rust being the thing the tier exists to
//! remove. A YAML file and an API key are the whole agent.
//!
//! That is also what makes the digest claim exact rather than nearly true:
//! everything the agent does is in the file, so there is no accompanying program
//! that could diverge from it.
//!
//! # Why the arguments are parsed by a derive
//!
//! A hand-rolled parser reads one flag table for every verb, so a flag
//! belonging to one is **silently accepted** by another:
//!
//! ```sh
//! agentplane run agent.yaml --push-host evil.example.com --tokens /nonexistent
//! # both flags do nothing, and one of them is a security control
//! ```
//!
//! That is a declaration that does nothing, at the command line, and a declared
//! control must be enforced or rejected by the parser rather than accepted and
//! ignored. A derive makes the bad state unrepresentable: a flag lives on its
//! subcommand's struct, so `run --push-host` fails to parse by construction, and
//! `--strict` belongs to `replay` and fails on `run` the same way. `--help` is
//! generated from the structs that enforce the flags rather than being prose
//! that can describe an option nobody implemented.
//!
//! It costs crates on `cli` and **nothing on the library**, which is what
//! settles the trade: `cli` produces a binary and already carries hundreds.
//! Count them with `cargo tree --no-default-features --features cli -e normal
//! --prefix none | sort -u | wc -l` rather than reading a figure here — a number
//! in a comment is one nobody re-derives.

use std::process::ExitCode;
use std::sync::Arc;

use agentplane::core::Tainted;
use agentplane::journal::JournalStore;
use agentplane::manifest::Manifest;
use agentplane::model::ModelProvider;
use agentplane::runtime::{Mode, RunStatus, Runtime, RuntimeBuilder};
use agentplane::store::RedbStore;

/// Install the log subscriber, deciding whether metric events are part of the
/// output.
///
/// **Metrics carry their own `tracing` target so that a subscriber can filter
/// them out cheaply**, and this binary is a subscriber. A one-shot verb has
/// nobody collecting a counter: printing two metric events per run buries the
/// two lines the run is actually about, on the first command a new reader
/// types. A serving plane is the case where somebody is collecting, and there
/// the stream is the fallback export when no collector is wired.
///
/// `RUST_LOG` overrides the whole decision, so a one-shot run that *is* being
/// measured stays reachable.
///
/// A strict replay's divergence is its report, printed as the verdict; the
/// executor's own divergence and quarantine events would say the same thing
/// twice, louder, and call a verification that wrote nothing a quarantine.
fn install_tracing(metrics: bool, verifying: bool, format: LogFormat) {
    use tracing_subscriber::{EnvFilter, fmt};
    let mut default = if metrics {
        "warn,agentplane=info".to_owned()
    } else {
        "warn,agentplane=info,agentplane.metric=off".to_owned()
    };
    if verifying {
        for target in [
            agentplane::runtime::telemetry::NONDETERMINISM,
            agentplane::runtime::telemetry::QUARANTINED,
        ] {
            default.push(',');
            default.push_str(target);
            default.push_str("=off");
        }
    }
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));
    // `try_init` rather than `init`: failing to install a subscriber must not
    // take down a run that would otherwise have worked.
    let builder = fmt().with_env_filter(filter).with_writer(std::io::stderr);
    let _ = match format {
        LogFormat::Text => builder.try_init(),
        // One JSON object per line, for a collector that would otherwise parse
        // the human format with a regular expression.
        LogFormat::Json => builder.json().try_init(),
    };
}

/// How a log line is written.
#[derive(clap::ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
enum LogFormat {
    /// For a person at a terminal.
    #[default]
    Text,
    /// One JSON object per line, for a log collector.
    Json,
}

#[cfg(feature = "dev")]
#[path = "agentplane/dev.rs"]
mod dev;

/// The exit statuses, one table for every verb.
///
/// A scheduler reads the status and nothing else, so each number means one
/// thing whichever verb returned it: a finding and an outage are different
/// pages, and a partial answer is neither a pass nor a failure.
mod exit {
    /// The command did what it was asked, and the answer is yes.
    pub const OK: u8 = 0;
    /// A finding, or a negative answer: a run that failed, an audit finding,
    /// something that needs attention, a lift that found nothing standing.
    pub const FINDING: u8 = 1;
    /// The command as typed cannot be carried out: a flag, an argument or an
    /// input file this binary refuses. `clap`'s own parse errors use it too.
    pub const USAGE: u8 = 2;
    /// A run stopped to wait — for a person, a timer or an event.
    pub const SUSPENDED: u8 = 3;
    /// Something this command depends on failed: a store, a witness, the
    /// network, the filesystem.
    pub const OPERATIONAL: u8 = 4;
    /// The answer is incomplete: a `--limit` truncated what was read, or a
    /// strict replay met a run it could not replay.
    pub const PARTIAL: u8 = 5;
    /// An export under a canon this build does not implement: `verify` cannot
    /// check it and `restore` cannot rebuild it, and neither is damage.
    pub const UNVERIFIABLE: u8 = 6;
}

/// The same table, as `--help` prints it.
const EXIT_STATUS_HELP: &str = "Exit status:
  0  ok
  1  a finding or a negative answer (a failed run, an audit or drill finding, an
     unused grant, needs attention)
  2  usage: the command as typed cannot be carried out
  3  a run is suspended, waiting for a person, a timer or an event
  4  operational: a store, witness, network or file could not be used
  5  partial: --limit truncated the answer, a strict replay could not replay a run,
     policy check evaluated nothing, grants met an incomplete export or unreadable
     calls, or subject a cut scan or an unreadable run
  6  unverifiable: verify or restore met an export under a canon this build does not
     implement";

/// Why a verb could not answer, which decides its exit status.
///
/// A plain `String` is an operational fault — most refusals arrive as one from
/// a store or a file — so `?` on the library's errors lands there, and a
/// refusal of the command line itself is said with [`usage`].
#[derive(Debug)]
enum Fault {
    Usage(String),
    Operational(String),
}

impl Fault {
    const fn status(&self) -> u8 {
        match self {
            Self::Usage(_) => exit::USAGE,
            Self::Operational(_) => exit::OPERATIONAL,
        }
    }
}

impl std::fmt::Display for Fault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage(m) | Self::Operational(m) => f.write_str(m),
        }
    }
}

impl From<String> for Fault {
    fn from(message: String) -> Self {
        Self::Operational(message)
    }
}

/// A refusal of the command as typed.
fn usage(message: impl Into<String>) -> Fault {
    Fault::Usage(message.into())
}

/// A refused admission, as the exit status reports it: an input the agent
/// cannot read its data subject from is the command as typed, and every other
/// refusal is the plane's.
fn admission_fault(e: agentplane::core::RuntimeError) -> Fault {
    match e {
        e @ agentplane::core::RuntimeError::SubjectUnbound { .. } => usage(e.to_string()),
        e => e.to_string().into(),
    }
}

/// What `--version` prints: the version and the features compiled in.
///
/// A binary's feature set decides which verbs, stores and drivers exist, and
/// an operator debugging "this build cannot serve" needs it without a
/// toolchain. Derived from the same `cfg`s the code is, so it cannot claim a
/// feature the build lacks.
fn build_description() -> &'static str {
    static TEXT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    TEXT.get_or_init(|| {
        format!(
            "{}\nfeatures: {}",
            env!("CARGO_PKG_VERSION"),
            compiled_features().join(", ")
        )
    })
}

/// Every feature this binary was built with, by its Cargo name.
fn compiled_features() -> Vec<&'static str> {
    let all = [
        ("a2a", cfg!(feature = "a2a")),
        ("a2a-server", cfg!(feature = "a2a-server")),
        ("acp", cfg!(feature = "acp")),
        ("bedrock", cfg!(feature = "bedrock")),
        ("cedar", cfg!(feature = "cedar")),
        ("cli", cfg!(feature = "cli")),
        ("dev", cfg!(feature = "dev")),
        ("fake-model", cfg!(feature = "fake-model")),
        ("http", cfg!(feature = "http")),
        ("keyring", cfg!(feature = "keyring")),
        ("keyring-vault", cfg!(feature = "keyring-vault")),
        ("manifest", cfg!(feature = "manifest")),
        ("mcp", cfg!(feature = "mcp")),
        ("mcp-http", cfg!(feature = "mcp-http")),
        ("mcp-server", cfg!(feature = "mcp-server")),
        ("mcp-stdio", cfg!(feature = "mcp-stdio")),
        ("media", cfg!(feature = "media")),
        ("opendal", cfg!(feature = "opendal")),
        ("postgres", cfg!(feature = "postgres")),
        ("providers", cfg!(feature = "providers")),
        ("push", cfg!(feature = "push")),
        ("redb", cfg!(feature = "redb")),
        ("signing", cfg!(feature = "signing")),
        ("testkit", cfg!(feature = "testkit")),
        ("witness-http", cfg!(feature = "witness-http")),
    ];
    all.iter()
        .filter(|(_, on)| *on)
        .map(|(name, _)| *name)
        .collect()
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
    long_version = build_description(),
    after_help = EXIT_STATUS_HELP,
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
    /// Write a starter manifest that validates and runs.
    Init(InitArgs),
    /// Execute an agent once and print its answer.
    Run(RunArgs),
    /// Re-execute a recorded run: resume it, or verify it with --strict.
    Replay(ReplayArgs),
    /// Print the Agent Card a served manifest would advertise.
    Card(CardArgs),
    /// Host an agent as an A2A 1.0 peer.
    Serve(Box<ServeArgs>),
    /// Check every document in a file, and say what is in it.
    Validate(ValidateArgs),
    /// Print the manifest format as a JSON Schema, for editors and CI linters.
    Schema,
    /// Print the operator API's published description, for client generators.
    Openapi,
    /// Print the identity a registry pins.
    Digest(DigestArgs),
    /// Check a journal's history and print what could not be checked.
    Audit(AuditArgs),
    /// Write a journal's records out as JSON Lines.
    Export(ExportArgs),
    /// List what left the plane about a case or a run: the disclosure register.
    Disclosures(DisclosuresArgs),
    /// Recompute an export and check it against its own checkpoint.
    Verify(VerifyArgs),
    /// Bind a grader's verdict to the records it judged, as an unsigned sidecar.
    Bind(BindArgs),
    /// Re-derive an export's policy verdicts, or measure a candidate bundle.
    Policy(PolicyArgs),
    /// Try a manifest's content rules on a value, offline.
    Content(ContentArgs),
    /// Report the tool grants an export shows no run used, with a narrower proposal.
    Grants(GrantsArgs),
    /// Report where a subject's data went, and what the report cannot trace.
    Subject(SubjectArgs),
    /// Rebuild a store from an export, and prove it by its own checkpoint.
    Restore(RestoreArgs),
    /// Walk the case layer and tell erasure from loss, against the live stores.
    Drill(DrillArgs),
    /// Retire admission keys older than a window you choose.
    ForgetAdmissions(ForgetArgs),
    /// Plan retention: list the closed cases a pass would erase.
    Retention(RetentionArgs),
    /// Throw or lift the emergency stop; `halt list` shows every one standing.
    Halt(HaltArgs),
    /// List the runs that are waiting, and what each one waits for.
    Waiting(WaitingArgs),
    /// Ask whether anything on this plane needs a person right now.
    Attention(WaitingArgs),
    /// Place or lift a legal hold; `hold list` shows every one standing.
    Hold(HoldArgs),
    /// Establish what happened to an effect the runtime could not decide.
    Reconcile(ReconcileArgs),
    /// Answer a quarantine: hand the run back, or close it where it stands.
    Quarantine(QuarantineArgs),
    /// List the open tasks on the worklist, or show one with --show.
    Tasks(TasksArgs),
    /// Decide a task on the worklist, as the person named.
    Decide(DecideArgs),
    /// Account for a breached obligation so it leaves the backlog.
    Acknowledge(AcknowledgeArgs),
    /// Re-arm a push registration that was parked after a failed delivery.
    #[cfg(feature = "push")]
    Rearm(RearmArgs),
    /// Stop a run and unwind what it did.
    Cancel(CancelArgs),
    /// Print one run's journal as a timeline, record by record.
    History(HistoryArgs),
    /// Serve a page on this machine for trying an agent.
    #[cfg(feature = "dev")]
    Dev(DevArgs),
}

/// The operator behind a verb a terminal carries.
///
/// `--actor` is required on every one of these, and recorded as
/// [`Basis::Asserted`](agentplane::core::Basis::Asserted): nothing here
/// verified the name, and the honest record of a terminal act says so. The
/// HTTP surface records the same acts as `authenticated`, because an
/// `Authenticator` ran before the route did.
#[derive(clap::Args, Debug)]
struct ActingAs {
    /// Who is doing this. Recorded permanently, as asserted.
    #[arg(long)]
    actor: String,
}

impl ActingAs {
    fn operator(&self) -> Result<agentplane::core::Operator, Fault> {
        agentplane::core::Operator::asserted(&self.actor).map_err(|e| usage(e.to_string()))
    }
}

/// Establish what happened to an undecided effect.
#[derive(clap::Args, Debug)]
struct ReconcileArgs {
    /// The run holding it.
    run_id: String,

    #[command(flatten)]
    at: StoreRef,

    /// The effect key, as `audit` and the run's history print it.
    #[arg(long)]
    effect: String,

    /// What was established: `landed` or `did-not-happen`.
    ///
    /// No default. A person is asserting a fact the runtime could not
    /// establish, and a default would pick the answer for them.
    #[arg(long)]
    outcome: String,

    /// The result the run reads back, as JSON. Only with `--outcome landed`,
    /// and recorded untrusted: nothing here produced it.
    #[arg(long)]
    output: Option<String>,

    /// What was checked, and how. Required and recorded.
    #[arg(long)]
    note: String,

    #[command(flatten)]
    who: ActingAs,
}

/// Answer a quarantine.
#[derive(clap::Args, Debug)]
struct QuarantineArgs {
    /// The run to answer for.
    run_id: String,

    #[command(flatten)]
    at: StoreRef,

    /// `reopen` to hand the run back to the executor, `abandon` to close it
    /// where it stands, unwinding nothing.
    #[arg(long)]
    decision: String,

    /// What was looked at, and what was found. Required and recorded.
    #[arg(long)]
    reason: String,

    #[command(flatten)]
    who: ActingAs,
}

/// A verdict, said in so many words.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    /// Let the proposed action happen.
    Approve,
    /// Refuse it.
    Reject,
}

/// One run's journal, as a timeline.
#[derive(clap::Args, Debug)]
struct HistoryArgs {
    /// The run.
    run: String,

    #[command(flatten)]
    at: StoreRef,

    /// Start at this sequence number rather than the run's first record.
    #[arg(long, value_name = "SEQ")]
    from: Option<u64>,

    /// One JSON object per record, in the shape the operator API's history
    /// route serves. Machine output: JSON escapes only U+0000–U+001F, so DEL,
    /// the C1 controls and the bidirectional and invisible characters print
    /// raw; read the text form on a terminal.
    #[arg(long)]
    json: bool,
}

/// A page on this machine for trying an agent.
#[cfg(feature = "dev")]
#[derive(clap::Args, Debug)]
struct DevArgs {
    /// The manifest, or a `---`-separated file of them. Saving it rebuilds the
    /// plane over the same store.
    manifest: String,

    /// The loopback port to listen on; `0` picks a free one. The page is
    /// never bound anywhere but loopback.
    #[arg(long, default_value_t = 0)]
    port: u16,

    /// Keep the journal in a redb file in this directory: an empty one, which
    /// this mode marks as its own, or one it marked before. Defaults to
    /// memory, which keeps nothing.
    #[arg(long, value_name = "DIR")]
    scratch: Option<String>,

    /// Refused unless `dev`, the only tenant a dev plane runs as — so a
    /// deployment's tenant in the environment is a refusal, not a plane.
    #[arg(long, env = "AGENTPLANE_TENANT")]
    tenant: Option<String>,

    /// Run an MCP server as a child process and reach it as `tool://NAME/...`.
    /// Needs `--allow-live`.
    #[arg(long, value_name = "NAME=COMMAND")]
    mcp: Vec<String>,

    /// Reach an A2A peer at URL as `tool://NAME/...`. Needs `--allow-live` and
    /// `--acting-as`.
    #[arg(long, value_name = "NAME=URL", requires = "acting_as")]
    peer: Vec<String>,

    /// Say that the systems `--mcp` and `--peer` reach are yours to act on: an
    /// approval on the page performs a real effect through them. The page
    /// names every such transport for the whole session.
    #[arg(long)]
    allow_live: bool,

    /// Who the page's runs act on behalf of, as with `run`.
    #[arg(long, value_name = "SUBJECT")]
    acting_as: Option<String>,
}

/// The worklist, as a verb.
#[derive(clap::Args, Debug)]
struct TasksArgs {
    #[command(flatten)]
    at: StoreRef,

    /// Show one task whole — its proposed action and evidence — instead of
    /// listing. Takes the id as the listing prints it.
    #[arg(long, value_name = "TASK")]
    show: Option<String>,

    /// A role you hold. Repeatable. The listing is the worklist as these roles
    /// see it — a task naming candidate roles is shown only to one of them,
    /// exactly as `decide` would admit — and a task naming none is anyone's.
    #[arg(long = "role")]
    roles: Vec<String>,

    /// How many to list, highest priority and oldest first.
    #[arg(long, default_value_t = 100)]
    limit: usize,
}

/// Decide a task on the worklist.
#[derive(clap::Args, Debug)]
struct DecideArgs {
    /// The task, as `tasks` and `attention` print it.
    task_id: String,

    /// `approve` or `reject`. No default: a decision with no verdict is not
    /// one.
    #[arg(value_enum)]
    verdict: Verdict,

    #[command(flatten)]
    at: StoreRef,

    /// The words that go on the record beside the verdict. Required.
    #[arg(long)]
    reason: String,

    /// A role this decider holds. Repeatable; the store checks eligibility
    /// and four-eyes against them, exactly as the HTTP route does.
    #[arg(long = "role")]
    roles: Vec<String>,

    /// The version of the task this decision was made against, as `tasks`
    /// prints it. A task that changed since is refused, exit 1, with nothing
    /// recorded.
    #[arg(long, value_name = "HEX")]
    digest: Option<String>,

    #[command(flatten)]
    who: ActingAs,
}

/// Account for a breached obligation.
#[derive(clap::Args, Debug)]
struct AcknowledgeArgs {
    /// The case the obligation belongs to.
    case_id: String,

    #[command(flatten)]
    at: StoreRef,

    /// The obligation's declared name.
    #[arg(long)]
    obligation: String,

    /// What happened, and what was done about it. Required and recorded.
    #[arg(long)]
    note: String,

    #[command(flatten)]
    who: ActingAs,
}

/// Stop a run.
#[derive(clap::Args, Debug)]
struct CancelArgs {
    /// The run to stop.
    run_id: String,

    #[command(flatten)]
    at: StoreRef,

    /// Why, recorded permanently beside who asked. Required: the next person
    /// to read this run is somebody else.
    #[arg(long)]
    reason: String,

    #[command(flatten)]
    who: ActingAs,
}

/// Re-arm a parked push registration.
#[cfg(feature = "push")]
#[derive(clap::Args, Debug)]
struct RearmArgs {
    /// The run the registration belongs to.
    run_id: String,

    #[command(flatten)]
    at: StoreRef,

    /// The registration's id — the part after the `/` in an `attention`
    /// `push.parked` subject.
    #[arg(long)]
    id: String,
}

/// Retention, as a verb, for the tier that is a manifest and this binary.
///
/// Only `plan` exists, and that is the honest shape: this binary wires **no
/// blob store and no key ring**, so nothing here can make a byte unreadable.
/// Erasing is `Runtime::retain` on a plane built with both.
#[derive(clap::Args, Debug)]
struct RetentionArgs {
    #[command(subcommand)]
    act: RetentionAct,
}

#[derive(clap::Subcommand, Debug)]
enum RetentionAct {
    /// List the closed cases a retention pass would erase.
    Plan(RetentionPlanArgs),
}

/// `--older-than-days` is **required and has no default**, for the reason
/// [`ForgetArgs`]'s window is: a retention period is a legal and business
/// decision, and a crate that picked one would be choosing somebody else's.
#[derive(clap::Args, Debug)]
struct RetentionPlanArgs {
    /// The store holding the case layer, and whose. Blob addresses and key
    /// scopes derive from the tenant, so a plan under the wrong one lists
    /// nothing.
    #[command(flatten)]
    at: StoreRef,

    /// Closed cases opened longer ago than this, in days. Required.
    #[arg(long)]
    older_than_days: u32,
}

/// The hold listing, for a verb whose default act changes something.
#[derive(clap::Subcommand, Debug)]
enum HoldListing {
    /// List every hold standing on this tenant, or every recorded release.
    List(HoldListArgs),
}

#[derive(clap::Args, Debug)]
struct HoldListArgs {
    /// The store, and whose to read.
    #[command(flatten)]
    at: StoreRef,

    /// List the recorded releases instead, newest first: who released each
    /// hold, when, and who had placed it.
    #[arg(long)]
    released: bool,

    /// How many releases to list with `--released`, newest first.
    #[arg(long, default_value_t = 100)]
    limit: usize,
}

/// The halt listing, for a verb whose default act changes something.
#[derive(clap::Subcommand, Debug)]
enum HaltListing {
    /// List every halt standing on this tenant, or every recorded lift.
    List(HaltListArgs),
}

#[derive(clap::Args, Debug)]
struct HaltListArgs {
    /// The store, and whose to read.
    #[command(flatten)]
    at: StoreRef,

    /// List the recorded lifts instead, newest first: who lifted each halt,
    /// when, and the halt it ended.
    #[arg(long)]
    lifted: bool,

    /// How many lifts to list with `--lifted`, newest first.
    #[arg(long, default_value_t = 100)]
    limit: usize,
}

/// Preservation, as a verb.
///
/// The counterpart of `retention plan`: that verb says what a sweep would
/// destroy, this one says what it may not. `hold list` reads every hold
/// standing — a hold that can only be read by somebody who already knows
/// which matter to ask about delivers nothing to the person whose job is to
/// find out what is still being preserved and why.
#[derive(clap::Args, Debug)]
#[command(args_conflicts_with_subcommands = true, subcommand_negates_reqs = true)]
struct HoldArgs {
    #[command(subcommand)]
    list: Option<HoldListing>,

    /// The store holding the case layer, and whose.
    #[command(flatten)]
    at: Option<StoreRef>,

    /// The matter to place or lift a hold on.
    #[arg(long, required = true)]
    case: Option<String>,

    /// Why this matter may not be destroyed. Required to place one: the person
    /// reviewing this listing in two years has only this sentence to act on.
    #[arg(long)]
    reason: Option<String>,

    /// Who is placing or releasing it. Required either way.
    ///
    /// Recorded as **asserted**: nothing here verified it, and what it proves
    /// is that whoever ran this command could open the store. The operator API
    /// records the same field from the credential its authenticator checked,
    /// and the row or the release record says which of the two it was.
    #[arg(long)]
    actor: Option<String>,

    /// Release the hold instead of placing it. The release is journaled under
    /// `--actor` before the hold is removed; `hold list --released` reads the
    /// releases back.
    #[arg(long, conflicts_with = "reason")]
    lift: bool,
}

/// The emergency stop, as a verb: an incident is the worst time to discover
/// that the brake needs a compiler.
///
/// `--reason` and `--actor` are required to halt: the next person to look will
/// be somebody else, possibly at three in the morning, and *why* and *who* are
/// the whole question. `--actor` is required to lift too, and `--reason` is
/// refused: the lift is journaled under that name before the row goes, and
/// `halt list --lifted` reads the lifts back.
#[derive(clap::Args, Debug)]
#[command(args_conflicts_with_subcommands = true, subcommand_negates_reqs = true)]
struct HaltArgs {
    #[command(subcommand)]
    list: Option<HaltListing>,

    /// The store holding the halt, and which tenant to stop.
    #[command(flatten)]
    at: Option<StoreRef>,

    /// What to stop: `tenant`, `agent:<metadata.name>`,
    /// `revision:<manifest digest>`, or `subject:<principal on the chain>` —
    /// any principal on the run's delegation chain.
    ///
    /// `revision:` is the one to reach for when a bad deploy is the incident:
    /// it names the exact reviewed bytes, so a fix published as a new version
    /// runs while the broken revision stays stopped.
    #[arg(long, default_value = "tenant")]
    scope: String,

    /// Why. Required unless `--lift`.
    #[arg(long)]
    reason: Option<String>,

    /// Who is throwing or lifting it. Required either way.
    ///
    /// It goes on the row or the lift record, and it is recorded as **asserted** rather than
    /// authenticated: nothing here verified it, and what it proves is that
    /// whoever ran this command could open the store. The operator API records
    /// the same field from the credential its authenticator checked, and the
    /// two are told apart on the row rather than guessed at from the surface.
    ///
    /// Required rather than defaulted from the shell, because a name taken from
    /// `$USER` reads on the record exactly like one somebody chose to put
    /// there, and only one of those is true.
    #[arg(long)]
    actor: Option<String>,

    /// Lift this halt instead of setting it.
    #[arg(long, conflicts_with = "reason")]
    lift: bool,

    /// Print one JSON document on stdout instead of text — `halt list` too.
    #[arg(long, global = true)]
    json: bool,
}

/// The runs that are waiting, as a verb.
///
/// The recovery runbook's last step is *re-arm the suspended runs*, and until
/// this existed that step named a verb with no argument an operator could
/// obtain: a run waiting on a person is in the worklist, and a run waiting on a
/// timer or an event was in no listing at all.
///
/// Answered from the journal rather than from the timer and subscription
/// tables, which is the difference that matters here: an export carries
/// neither, so on a plane restored from one the registrations are exactly what
/// is missing and these runs are exactly what is inert.
#[derive(clap::Args, Debug)]
struct WaitingArgs {
    /// The store holding the runs, and whose to read.
    #[command(flatten)]
    at: StoreRef,
    /// How many to list. Soonest due first, so a smaller page is the most
    /// overdue work rather than an arbitrary slice.
    #[arg(long, default_value_t = 100)]
    limit: usize,
}

/// Retention for the admission index, as a verb.
///
/// The same reasoning [`DrillArgs`] carries: `JournalStore::forget_admissions`
/// could only be reached by writing Rust, and a deployment that is only a YAML
/// file has an index that grows and no way to trim it.
///
/// `--older-than` is **required and has no default**. Retiring a key reopens
/// the door it closed, so a window shorter than the emitter's retry horizon
/// admits a second run on a timer — which is the failure the key exists to
/// prevent. A default here would be this crate choosing somebody else's retry
/// horizon for them.
#[derive(clap::Args, Debug)]
struct ForgetArgs {
    /// The store holding the admission index, and whose.
    #[command(flatten)]
    at: StoreRef,

    /// Retire keys claimed longer ago than this, as days. Required.
    ///
    /// It must exceed how long your emitter keeps retrying a delivery it has
    /// not seen a 2xx for.
    #[arg(long)]
    older_than_days: u32,
}

/// The live half of the case-layer drill, as a verb.
///
/// `Runtime::drill` reachable without writing Rust, which is the dependency the
/// declarative tier exists to remove: a deployment that is only a YAML file
/// still has to be able to rehearse its own recovery. The verb opens the same
/// store file the other journal verbs do; the case layer lives in it, so
/// `--store` is the whole wiring.
///
/// What this verb does NOT check: blob bytes and sealed-state keys. A redb
/// file holds no blob store, and this binary has no key-ring wiring — both
/// are named as unchecked in the report rather than silently passed, which is
/// the same honesty the library's own report shape enforces. An embedder
/// whose plane has those stores runs `Runtime::drill` with them wired.
#[derive(clap::Args, Debug)]
struct DrillArgs {
    /// The store holding the case layer to drill. Required — the drill walks
    /// cases, and a memory store this process did not write holds none.
    #[command(flatten)]
    at: StoreRef,

    /// Read the last rehearsal's verdict instead of running one.
    ///
    /// The question an audit asks — *when did you last rehearse, and did it
    /// pass* — answered from the plane rather than from whatever scheduled
    /// the verb. Exits non-zero when the recorded verdict was not sound, and
    /// when no rehearsal has ever run: *nobody has drilled this plane* is a
    /// finding, not a clean answer.
    #[arg(long)]
    last: bool,
}

/// Rebuild a journal from an export.
#[derive(clap::Args, Debug)]
struct RestoreArgs {
    /// The export to read.
    file: String,

    /// Where to write the rebuilt journal, and under which tenant. Must not
    /// already hold these runs — this rebuilds a history rather than merging
    /// one. The tenant matters as much as the path: a restore into the unnamed
    /// default of a store whose plane serves `acme` rebuilds a history nobody
    /// serves.
    #[command(flatten)]
    at: StoreRef,
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

    /// The checkpoint this export is supposed to be a copy of, as a
    /// `tlog-checkpoint` note or as the JSON an audit report prints.
    ///
    /// This is the deletion check, and without it there is none. The Merkle
    /// root rebuilt from the file can otherwise only be compared with the
    /// file's own header — which an editor who dropped a run rewrites too —
    /// so the report says deletion went unchecked. Supply the checkpoint an
    /// earlier audit printed, or fetch one with `--witness`: the point is that
    /// it comes from somewhere other than the file being checked.
    #[arg(long)]
    checkpoint: Option<String>,

    /// Fetch the anchoring checkpoint from a witness, at its monitoring
    /// prefix. Repeatable.
    ///
    /// The deletion check needs a checkpoint from **outside** the store, and
    /// this is the only way to get one that the operator did not hand over.
    /// A witness keeps the last checkpoint it cosigned for a log and will only
    /// cosign one that provably extends it, so a run removed from the store is
    /// a size the witness still remembers.
    ///
    /// Two or more witnesses are worth naming: a split view is precisely two
    /// witnesses holding one size with different roots, and that is a finding
    /// no single anchor produces.
    #[arg(long = "witness")]
    witness: Vec<String>,

    /// A witness key to trust, as `<name>=<base64 Ed25519 public key>` —
    /// repeatable, and required by `--witness`.
    ///
    /// Without one a fetch could only report what a URL served. The whole
    /// argument for an outside anchor is that an independent party signed it,
    /// and a signature nobody checks makes that an argument about a status
    /// code.
    #[arg(long = "witness-key")]
    witness_key: Vec<String>,

    /// The log's origin line, when it is not this store's own.
    ///
    /// Defaults to what the store reports, which is right for an auditor
    /// holding the database. Naming it explicitly is for the case where the
    /// store's own answer is the thing under suspicion.
    #[arg(long)]
    origin: Option<String>,

    /// A grader-verdict sidecar to check against this export. Repeatable.
    /// Each is reported bound, refused or not checked; a refused one fails.
    #[arg(long = "grader-verdict", value_name = "FILE")]
    grader_verdict: Vec<String>,

    /// A grader key a sidecar's signature may verify under, as
    /// `<key-id>=<64 hex chars>`. Repeatable; separate from `--key`.
    #[arg(long = "grader-key", value_name = "KEY_ID=HEX")]
    grader_key: Vec<String>,
}

/// Bind a grader's verdict to a prefix of one run in an export.
#[derive(clap::Args, Debug)]
struct BindArgs {
    /// The export, or `-` for standard input.
    export: String,

    /// The run the verdict is about.
    #[arg(long)]
    run: String,

    /// The last record of the bound prefix. Defaults to the run's last record.
    #[arg(long = "last-seq")]
    last_seq: Option<u64>,

    /// The verdict, as a file of bytes this binary never interprets.
    #[arg(long)]
    content: String,

    /// Where to write the unsigned sidecar.
    #[arg(long)]
    out: String,
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

    /// Fetch the anchoring checkpoint from a witness, at its monitoring
    /// prefix. Repeatable.
    ///
    /// The deletion check needs a checkpoint from **outside** the store, and
    /// this is the only way to get one that the operator did not hand over.
    /// A witness keeps the last checkpoint it cosigned for a log and will only
    /// cosign one that provably extends it, so a run removed from the store is
    /// a size the witness still remembers.
    ///
    /// Two or more witnesses are worth naming: a split view is precisely two
    /// witnesses holding one size with different roots, and that is a finding
    /// no single anchor produces.
    #[arg(long = "witness")]
    witness: Vec<String>,

    /// A witness key to trust, as `<name>=<base64 Ed25519 public key>` —
    /// repeatable, and required by `--witness`.
    ///
    /// Without one a fetch could only report what a URL served. The whole
    /// argument for an outside anchor is that an independent party signed it,
    /// and a signature nobody checks makes that an argument about a status
    /// code.
    #[arg(long = "witness-key")]
    witness_key: Vec<String>,

    /// The log's origin line, when it is not this store's own.
    ///
    /// Defaults to what the store reports, which is right for an auditor
    /// holding the database. Naming it explicitly is for the case where the
    /// store's own answer is the thing under suspicion.
    #[arg(long)]
    origin: Option<String>,

    /// The oldest, in seconds, each witness key's latest signed timestamp may
    /// be at this machine's clock. A key older than this — or ahead of it by
    /// more — is a finding. Without it freshness is not judged.
    #[arg(long = "max-checkpoint-age", value_name = "SECS")]
    max_checkpoint_age: Option<u64>,
}

/// The arguments the two journal verbs share.
///
/// Both read a store and neither reads a manifest, which is the point: an
/// auditor holds a database file and a checkpoint somebody gave them, not the
/// deployment's source tree.
#[derive(clap::Args, Debug)]
struct StoreArgs {
    /// The journal to read, and whose. Required — there is nothing to audit or
    /// export in a memory store that this process did not itself write.
    #[command(flatten)]
    at: StoreRef,

    /// Which runs, by outcome. Repeatable. Defaults to every sealed outcome.
    #[arg(long)]
    outcome: Vec<String>,

    /// How many runs to consider per outcome.
    #[arg(long, default_value_t = 1000)]
    limit: usize,
}

/// What `export` takes beyond the shared store arguments.
#[derive(clap::Args, Debug)]
struct ExportArgs {
    #[command(flatten)]
    store: StoreArgs,

    /// Write the export even when `--limit` truncated it, and exit 5.
    ///
    /// Without it a truncated export is refused and nothing is written: a file
    /// that stopped at the limit is framed exactly like a complete one, and
    /// it is the artifact an auditor is handed.
    #[arg(long)]
    allow_partial: bool,

    /// Disclose one matter instead: the runs this case holds now, each sealed
    /// run with its inclusion path, and the case's whole block — its state,
    /// deadlines, blob digests, hold reason and the ids of every run it holds,
    /// including runs not carried. Repeatable.
    ///
    /// The disclosure is recorded in the plane's register — recipient, runs,
    /// package digest, actor — before any byte reaches the destination, so a
    /// later erasure names the copy. One recorded and then not delivered (a
    /// closed standard output) stays recorded.
    #[arg(long = "case", conflicts_with_all = ["outcome", "allow_partial"])]
    cases: Vec<String>,

    /// Disclose this run. Repeatable, and combines with `--case`.
    #[arg(long = "run", conflicts_with_all = ["outcome", "allow_partial"])]
    runs: Vec<String>,

    /// Who receives the package. Required with `--case` or `--run`.
    #[arg(long)]
    to: Option<String>,

    /// Who is disclosing it, recorded as asserted. Required with `--case` or
    /// `--run`.
    #[arg(long)]
    actor: Option<String>,

    /// Where to deliver the package. Standard output when omitted.
    #[arg(long)]
    output: Option<String>,
}

/// What `disclosures` takes.
#[derive(clap::Args, Debug)]
struct DisclosuresArgs {
    #[command(flatten)]
    at: StoreRef,

    /// List the disclosures carrying this case. Repeatable.
    #[arg(long = "case")]
    cases: Vec<String>,

    /// List the disclosures carrying this run. Repeatable.
    #[arg(long = "run")]
    runs: Vec<String>,
}

/// Where a plane's state is, and whose.
///
/// One type rather than a `--store`/`--tenant` pair written out per verb, so no
/// verb can name a store without taking whose it is. A verb missing `--tenant`
/// would read the unnamed tenant and hand an operator an artifact about a
/// different plane — empty, well-formed and exit zero.
#[derive(clap::Args, Debug, Clone)]
struct StoreRef {
    /// The plane's store: a redb file, or a `postgres://` connection string.
    #[arg(long, env = "AGENTPLANE_STORE")]
    store: String,

    /// Which tenant's plane. Defaults to the unnamed single-tenant plane.
    ///
    /// Every key in both backends leads with the tenant, so naming the wrong
    /// one is a *miss* rather than an error: the verb answers about a plane
    /// nobody runs and reports success.
    #[arg(long, env = "AGENTPLANE_TENANT")]
    tenant: Option<String>,
}

impl StoreRef {
    async fn open(&self) -> Result<Backend, Fault> {
        Backend::open(&self.store, self.tenant.as_deref()).await
    }
}

/// [`StoreRef`] for the verbs a store is genuinely optional for.
///
/// `run` may journal to memory because it exits with its answer; `replay
/// --strict` may read `--from` exports instead; `serve` refuses without one and
/// says why in its own words rather than clap's.
#[derive(clap::Args, Debug, Clone)]
struct MaybeStoreRef {
    /// The plane's store: a redb file, or a `postgres://` connection string.
    #[arg(long, env = "AGENTPLANE_STORE")]
    store: Option<String>,

    /// Which tenant's plane. Defaults to the unnamed single-tenant plane.
    #[arg(long, env = "AGENTPLANE_TENANT")]
    tenant: Option<String>,
}

impl MaybeStoreRef {
    /// Open the named store, or say nothing was named.
    ///
    /// `Ok(None)` rather than a default, so each caller decides what an absent
    /// store means: `run` journals to memory and says so, `serve` refuses.
    async fn open(&self) -> Result<Option<Backend>, Fault> {
        match &self.store {
            Some(spec) => Backend::open(spec, self.tenant.as_deref()).await.map(Some),
            None => Ok(None),
        }
    }
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

/// A starter manifest, written where you say.
#[derive(clap::Args, Debug)]
struct InitArgs {
    /// Where to write it. Refused when the file exists.
    #[arg(default_value = "agent.yaml")]
    path: String,

    /// Start from a tool-calling agent that reads from an MCP server, rather
    /// than a single completion.
    #[arg(long)]
    tools: bool,

    /// The agent's `metadata.name`, and the capability it provides.
    #[arg(long, default_value = "my-agent")]
    name: String,

    /// Write a plane ready to serve into DIR instead: a manifest, the shipped
    /// policy, freshly generated tokens, the framework caller's token alone,
    /// a generated Postgres password, the plane's store connection, and a
    /// compose file. Refused when any of the seven exists.
    #[arg(long, value_name = "DIR", conflicts_with_all = ["tools", "name", "path"])]
    serve: Option<String>,

    #[command(flatten)]
    out: JsonFlag,
}

/// Machine-readable output, for the verbs whose answer is a sentence.
///
/// One convention: those verbs print text for a person, and with `--json` one
/// JSON document on stdout instead. The verbs whose answer is a report —
/// `audit`, `verify`, `attention`, `tasks` and the rest — print JSON always.
#[derive(clap::Args, Debug, Clone, Copy)]
struct JsonFlag {
    /// Print one JSON document on stdout instead of text.
    #[arg(long)]
    json: bool,
}

#[derive(clap::Args, Debug)]
struct DigestArgs {
    /// The manifest, or a `---`-separated file of them.
    manifest: String,

    #[command(flatten)]
    out: JsonFlag,
}

#[derive(clap::Args, Debug)]
struct ValidateArgs {
    /// The manifest, or a `---`-separated file of them.
    manifest: String,

    /// Require this annotation key to be present and non-empty. Repeatable.
    ///
    /// The runtime never reads `metadata.annotations` — that is what makes them
    /// safe to carry, and it is why nothing can notice a production agent that
    /// shipped without an owner. A control nobody checks is a convention.
    ///
    /// This does not change that: the check lives in review, the keys stay the
    /// deployment's own vocabulary, and no interpretation crosses the trust
    /// boundary. It is the division `--policy` already draws — the rule is
    /// yours, the enforcement is a job you run.
    #[arg(long = "require-annotation", value_name = "KEY")]
    require_annotation: Vec<String>,

    /// Print one JSON document on stdout instead of text.
    #[arg(long)]
    json: bool,
}

#[derive(clap::Args, Debug)]
struct RunArgs {
    /// The manifest, or a `---`-separated file of them.
    manifest: String,

    /// The run's input, as JSON. `-` reads standard input. Defaults to `{}`.
    #[arg(long, conflicts_with = "input_file")]
    input: Option<String>,

    /// Read the run's input from a file instead.
    #[arg(long)]
    input_file: Option<String>,

    /// Which capability to run. Optional when the file leaves no doubt.
    #[arg(long)]
    capability: Option<String>,

    /// Journal on disk, and whose. Defaults to memory, which keeps nothing.
    #[command(flatten)]
    at: MaybeStoreRef,

    /// Run an MCP server as a child process and reach it as `tool://NAME/...`.
    ///
    /// Repeatable, one per server. The manifest grants the tools; this says only
    /// which transport reaches the server offering them, because an agent's
    /// digest must not change when it moves between a laptop and a cluster.
    /// Needs the `mcp-stdio` feature.
    #[arg(long, value_name = "NAME=COMMAND")]
    mcp: Vec<String>,

    /// Reach an A2A peer at URL as `tool://NAME/...`.
    ///
    /// Repeatable, one per peer. The manifest grants the capabilities; this
    /// says where the peer is. Its bearer token, when it needs one, comes from
    /// the environment as `AGENTPLANE_PEER_TOKEN_<NAME>` (upper-cased, `.`
    /// and `-` as `_`), never from the command line. Needs the `a2a` feature,
    /// and `--acting-as`: a peer call is made on somebody's behalf.
    #[arg(long, value_name = "NAME=URL", requires = "acting_as")]
    peer: Vec<String>,

    /// Who this run acts on behalf of: the owner of its delegation chain.
    ///
    /// The chain is rooted at this subject and scoped to exactly what the
    /// file declares — the capabilities its agents provide and the ones they
    /// grant under a peer's name — so a peer receives the chain plus one link
    /// naming it, and nothing wider. Required by `--peer`.
    #[arg(long, value_name = "SUBJECT")]
    acting_as: Option<String>,

    /// A correlation key for the run's case, as `NAMESPACE=VALUE`. Repeatable.
    ///
    /// Every run opens or joins a case, because oversight, obligations and
    /// `$correlation/<namespace>` memory subjects all live on one. Without this
    /// the run gets a case of its own, keyed `invocation=<fresh id>`; name a
    /// key (`--correlate customer=C-7`) to join the open case that key already
    /// belongs to, or to resolve a `$correlation/customer` subject.
    #[arg(long, value_name = "NAMESPACE=VALUE")]
    correlate: Vec<String>,

    /// Admit only if the declaration governing the capability has this digest
    /// (hex, as `agentplane digest` prints it). Another revision is refused
    /// before anything is recorded.
    #[arg(long, value_name = "DIGEST")]
    expect_digest: Option<String>,
}

/// Re-execute a recorded run.
///
/// Its own verb rather than a `run --replay` flag, because the two share
/// almost nothing: a replay has no input, no capability choice and no default
/// store — the journal *is* the subject — and a flag table where half the
/// flags are meaningless under another flag is the silently-accepted-option
/// defect this parser exists to remove.
#[derive(clap::Args, Debug)]
#[command(after_help = REPLAY_EXIT_HELP)]
struct ReplayArgs {
    /// The run to re-execute. With `--strict --from`, leave it out to replay
    /// every run the exports hold.
    run_id: Option<String>,

    /// The journal holding the run, and whose. Required unless `--strict`
    /// reads `--from` an export: there is nothing to replay in a memory store
    /// this process did not itself write.
    #[command(flatten)]
    at: MaybeStoreRef,

    /// Replay from an export file instead of a store. Repeatable; `--strict`
    /// only. Each file is rebuilt in memory and checked against its own
    /// checkpoint — nothing is written to disk.
    #[arg(long, value_name = "EXPORT", requires = "strict")]
    from: Vec<String>,

    /// The manifest (or `---`-separated room) to replay under.
    ///
    /// A resume under a different declaration than the run was admitted
    /// under is refused before anything replays, and the run is quarantined
    /// with both digests named. A strict verification runs under whatever it
    /// is handed — that is how an edited manifest is checked against the runs
    /// it would have made — and its report names both digests.
    #[arg(long)]
    manifest: String,

    /// Verify rather than resume: read every effect back and report whether
    /// this build does the same work, different work, or cannot be compared.
    ///
    /// Calls no model, starts no tool server, dials no peer and writes
    /// nothing, so it needs no provider credential.
    #[arg(long)]
    strict: bool,

    /// Run an MCP server as a child process, as `run` takes it. A resume that
    /// continues past its recorded history dispatches live and may need one.
    /// Refused with `--strict`, which dispatches nothing.
    #[arg(long, value_name = "NAME=COMMAND")]
    mcp: Vec<String>,

    /// Reach an A2A peer, as `run` takes it. Refused with `--strict`.
    #[arg(long, value_name = "NAME=URL")]
    peer: Vec<String>,
}

/// What `replay --strict` exits with, beside the table every verb shares.
const REPLAY_EXIT_HELP: &str = "Exit status of `--strict`:
  0  every run replayed was verified
  1  a run diverged from its record
  4  a store, file or journal could not be used
  5  partial: a run could not be replayed (named in the report), and none diverged";

/// Print the Agent Card a served manifest would advertise.
#[derive(clap::Args, Debug)]
struct CardArgs {
    /// The manifest. A card names one agent, exactly as `serve` hosts one.
    manifest: String,

    /// The public base URL the card advertises — what `serve --url` would be
    /// handed, without serving anything.
    #[arg(long, env = "AGENTPLANE_URL")]
    url: String,
}

/// Content rules, tried before they are deployed.
#[derive(clap::Args, Debug)]
struct ContentArgs {
    #[command(subcommand)]
    act: ContentAct,
}

#[derive(clap::Subcommand, Debug)]
enum ContentAct {
    /// Judge one JSON value with a manifest's content rules.
    Check(ContentCheckArgs),
}

/// Runs the runtime's own evaluator over one value. Reads the manifest and the
/// value; opens no store and calls no checker.
#[derive(clap::Args, Debug)]
struct ContentCheckArgs {
    /// The manifest declaring the rules: one agent.
    manifest: String,
    /// Where the value is judged: `admission`, `source:<kind>` or
    /// `sink:<kind>`.
    #[arg(long)]
    at: String,
    /// The JSON value to judge. Standard input when absent.
    #[arg(long)]
    value: Option<String>,
}

/// Policy over recorded history.
#[derive(clap::Args, Debug)]
struct PolicyArgs {
    #[command(subcommand)]
    act: PolicyAct,
}

#[derive(clap::Subcommand, Debug)]
enum PolicyAct {
    /// Rebuild every gated request an export records and evaluate it offline.
    Check(PolicyCheckArgs),
}

/// Re-derive recorded verdicts from an export.
///
/// Reads one file, opens no store, writes nothing and calls no network. It
/// checks agreement between a bundle and the record, not the record's
/// integrity — run `verify` on the same file for that.
#[derive(clap::Args, Debug)]
#[cfg_attr(not(feature = "cedar"), allow(dead_code))]
struct PolicyCheckArgs {
    /// The bundle the runs recorded: a `.cedar` file, or a directory holding
    /// `policy.cedar` and optionally `schema.json` and `entities.json`. Read
    /// by the loader `serve --policy` uses, so its digest is the one a served
    /// plane records. A run that recorded another bundle is a mismatch and is
    /// not evaluated.
    #[arg(long)]
    bundle: String,

    /// The export to read. `-` reads standard input.
    #[arg(long)]
    from: String,

    /// A bundle to measure against what happened: every recorded permit it
    /// would refuse, per run.
    #[arg(long)]
    candidate: Option<String>,

    /// The tenant the runs belong to. Every request carries it and no record
    /// does, so the report says whether it was supplied or assumed.
    #[arg(long, env = "AGENTPLANE_TENANT")]
    tenant: Option<String>,

    #[command(flatten)]
    out: JsonFlag,
}

/// Measure an export against the manifests its runs name.
///
/// Reads one file and the manifests given, opens no store and calls no
/// network. A sealed export's arguments are not opened here, so its grants are
/// reported as not established.
#[derive(clap::Args, Debug)]
struct GrantsArgs {
    /// The export to read. `-` reads standard input.
    #[arg(long)]
    from: String,

    /// A manifest the runs may name by digest. Repeatable.
    #[arg(long, required = true)]
    manifest: Vec<String>,

    /// Write each proposed manifest to `<dir>/<digest>.yaml`. Never applied,
    /// signed or published.
    #[arg(long)]
    propose: Option<String>,

    #[command(flatten)]
    out: JsonFlag,
}

/// Where one memory subject's data went.
///
/// Read-only: appends nothing and changes no store. Sealed arguments and
/// recall outputs are not opened here.
#[derive(clap::Args, Debug)]
struct SubjectArgs {
    /// The subject, as governed memory and run bindings name it.
    subject: String,

    #[command(flatten)]
    at: StoreRef,

    /// How many runs to scan per outcome, and in flight.
    #[arg(long, default_value_t = 1000)]
    limit: usize,

    #[command(flatten)]
    out: JsonFlag,
}

#[derive(clap::Args, Debug)]
struct ServeArgs {
    /// The manifest, or a room file. A2A serves its one agent, or the room's
    /// one `topology.role: orchestrator`; `--mcp-addr` serves every agent in it.
    manifest: String,

    /// The A2A endpoint callers reach this plane at — `/a2a` under its public
    /// address, as `http://localhost:8080/a2a`. Goes on the Agent Card, so it
    /// is the public URL rather than what you bind; refused unless it ends in
    /// `/a2a`.
    #[arg(long, env = "AGENTPLANE_URL")]
    url: Option<String>,

    /// What to bind the peer surface to.
    #[arg(long, env = "AGENTPLANE_ADDR", default_value = "127.0.0.1:8080")]
    addr: String,

    /// A Cedar policy bundle: one `.cedar` file, or a directory holding
    /// `policy.cedar` and optionally `schema.json` and `entities.json` — the
    /// same loader `policy check --bundle` reads. No default: a permissive
    /// engine and no engine are the same behaviour, and only one of them
    /// looks governed.
    #[arg(long, env = "AGENTPLANE_POLICY")]
    policy: Option<String>,

    /// Bearer tokens naming the callers this plane accepts.
    #[arg(long, env = "AGENTPLANE_TOKENS")]
    tokens: Option<String>,

    /// Journal on disk, and which tenant this plane serves. Required: a served
    /// task's id is a promise it can be fetched again.
    #[command(flatten)]
    at: MaybeStoreRef,

    /// Also serve the operator surface — the worklist, task decisions and
    /// `GET /runs?outcome=quarantined` — on its own listener.
    #[arg(long, env = "AGENTPLANE_OPERATOR_ADDR")]
    operator_addr: Option<String>,

    /// Also serve every agent in the file as MCP tools, over Streamable HTTP
    /// at `/mcp` on its own listener — under the same `--policy` and
    /// `--tokens`, asked as `mcp:*` actions.
    #[arg(long, env = "AGENTPLANE_MCP_ADDR")]
    mcp_addr: Option<String>,

    /// Serve only this agent on `--mcp-addr`, by `metadata.name`. Repeatable;
    /// without it every agent in the file is served, and each must declare
    /// `spec.input`.
    #[arg(long, value_name = "NAME")]
    mcp_agent: Vec<String>,

    /// A `Host` authority the MCP listener answers besides loopback, as
    /// `host` or `host:port`. Repeatable; required for a non-loopback bind.
    #[arg(long, value_name = "HOST")]
    mcp_allowed_host: Vec<String>,

    /// A browser `Origin` the MCP listener accepts, as `scheme://host[:port]`.
    /// Repeatable. A request carrying any other `Origin` is refused; one
    /// carrying none — every server-side framework — is not.
    #[arg(long, value_name = "ORIGIN")]
    mcp_allowed_origin: Vec<String>,

    /// How often deadlines, task expiry, dead letters and due timers are swept.
    /// `0` runs the sweep from your own scheduler instead.
    #[arg(long, value_name = "SECS", env = "AGENTPLANE_SWEEP_EVERY")]
    sweep_every: Option<u32>,

    /// How often the recovery drill runs, in seconds. Off unless you say.
    ///
    /// `Runtime::drill` walks every case and holds its blob and sealed-state
    /// references against the live stores, telling *intact* from *erased by
    /// design* from *lost*. Nothing invoked it on a schedule, and a control
    /// that exists and is never exercised is one an audit cannot count — the
    /// rehearsal was left as something an operator would arrange, and the
    /// deployments that most need it are the ones that write no Rust.
    ///
    /// **Off by default, deliberately.** A drill is a full walk of the case
    /// layer, so its cost grows with the case layer and this crate does not
    /// know how large yours is or when your quiet hour is. Daily (`86400`) is
    /// the shape most deployments want; a finding is logged at `error` with
    /// the report attached, which is what an alert rule keys on.
    #[arg(long, value_name = "SECS", env = "AGENTPLANE_DRILL_EVERY")]
    drill_every: Option<u32>,

    /// Permit A2A push notifications to this exact host. Repeatable.
    ///
    /// Without one, push is not wired and the Agent Card advertises it as
    /// absent rather than claiming a capability nothing serves.
    #[arg(long, value_name = "HOST")]
    push_host: Vec<String>,

    /// Run an MCP server as a child process and reach it as `tool://NAME/...`.
    #[arg(long, value_name = "NAME=COMMAND")]
    mcp: Vec<String>,

    /// Reach an A2A peer at URL as `tool://NAME/...`, as `run` takes it.
    #[arg(long, value_name = "NAME=URL")]
    peer: Vec<String>,

    /// Submit this plane's checkpoints to the witness at this submission
    /// prefix, on the sweep. Repeatable; needs `--witness-key` and `--log-key`.
    #[arg(long = "witness-submit", value_name = "URL")]
    witness_submit: Vec<String>,

    /// A submission witness's key to trust, as `<name>=<base64 Ed25519 public
    /// key>`. Repeatable.
    #[arg(long = "witness-key", value_name = "NAME=BASE64")]
    witness_key: Vec<String>,

    /// How many witnesses must cosign each round. Defaults to all of them.
    #[arg(long = "witness-quorum", value_name = "N")]
    witness_quorum: Option<usize>,

    /// This log's note key: its `signed-note` name and a file holding the
    /// 32-byte Ed25519 seed as 64 hex characters.
    #[arg(long = "log-key", value_name = "NAME=PATH")]
    log_key: Option<String>,

    /// Re-submit an unchanged checkpoint to every witness at least this
    /// often, in seconds, so an idle plane still carries a fresh witness
    /// time. Refused if shorter than `--sweep-every`.
    #[arg(long = "witness-interval", value_name = "SECS")]
    witness_interval: Option<u64>,

    /// How long to keep working after a stop signal, in seconds.
    ///
    /// On `SIGTERM` or `SIGINT` this process stops accepting connections,
    /// finishes the requests already in hand, lets the periodic passes complete
    /// the tick they are in, and waits this long for the runs it started in the
    /// background to reach a journaled resting point.
    ///
    /// **It has to fit inside the supervisor's own grace period**, which is what
    /// sends `SIGKILL` afterwards — 30 seconds on Kubernetes and Docker unless
    /// raised. The default leaves margin under that. `0` exits as soon as the
    /// listeners are closed.
    ///
    /// What it buys: a run killed inside a tool call leaves an announced effect
    /// with no outcome, and no later reader can tell whether that call reached
    /// the world — so the effect's declared recovery decides, which for anything
    /// not safe to repeat means waiting for a person. Draining turns the
    /// ordinary case of a deploy back into an ordinary conclusion.
    #[arg(
        long,
        value_name = "SECS",
        env = "AGENTPLANE_DRAIN_SECS",
        default_value_t = 25
    )]
    drain_secs: u64,

    /// How the server logs: `text` for a terminal, `json` for a collector.
    #[arg(
        long,
        value_enum,
        env = "AGENTPLANE_LOG_FORMAT",
        default_value_t = LogFormat::Text
    )]
    log_format: LogFormat,
}

/// The anchoring checkpoint an audit was given, and **how it was obtained**.
///
/// The basis of a fact is part of the fact. A checkpoint fetched from two
/// independent witnesses and verified against keys the reader supplied, and one
/// typed out of a ticket, are different grounds for the same verdict — and an
/// artifact that records only the checkpoint lets the second be read as the
/// first. That is trust laundering by omission, and it happens at a shell
/// redirect: the report goes to stdout, and a basis printed only to stderr is
/// gone the moment somebody writes `> report.json`.
///
/// So the basis travels with the report. What it records is what **this
/// command** established, never what the library verified — the audit checks
/// that a checkpoint *extends*, and cannot check who vouched for it.
#[derive(Debug, Default, serde::Serialize)]
struct Anchor {
    /// Every checkpoint obtained, held for the caller and **not serialized**.
    ///
    /// The report already names them — `held_to` on an audit, the header
    /// comparison on a verify — and one document carrying one checkpoint in
    /// two fields is two answers waiting to disagree. What this object adds is
    /// the half the report cannot have: how each was obtained.
    ///
    /// **All of them, not the highest.** The append-only check is run against
    /// each one, because they are independent observations of the same log: an
    /// operator that forks and feeds the fork to a fresh witness holds the
    /// *longest* history anybody has, so keeping only the largest keeps
    /// exactly the observation a fork is invisible from and drops the one it
    /// is visible from.
    #[serde(skip)]
    checkpoints: Vec<agentplane::audit::Anchor>,
    /// The witness keys whose cosignatures verified, by monitoring prefix or
    /// by the signed-note file that carried them.
    ///
    /// Absent for a checkpoint nobody trusted cosigned — a plain note, a JSON
    /// file, or a signed note with no line verifying under a `--witness-key`:
    /// it is an asserted fact, and saying nothing is how that is said.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    cosigned_by: Vec<String>,
    /// Witnesses that were asked and gave no anchor, with why.
    ///
    /// Kept because a clean report over one witness's anchor and a clean report
    /// over three are different statements, and the difference is only visible
    /// here.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    unreached: Vec<String>,
    /// Two witnesses holding one tree size with two different roots.
    ///
    /// The event witnessing exists to detect. It fails the command: a finding
    /// that only prints is one nobody files.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    split_view: Vec<String>,
}

/// What `audit` prints: the library's report, and what this command
/// established about the evidence it fed in.
///
/// One document rather than two streams, so the basis cannot be separated from
/// the verdict by a redirect.
#[derive(serde::Serialize)]
struct AuditDocument<'a> {
    anchor: &'a Anchor,
    /// Which run lists `--limit` cut short. Travels in the report, because a
    /// warning on stderr is gone the moment somebody writes `> report.json`,
    /// and a clean report over a truncated list reads as a clean plane.
    truncated: &'a Truncation,
    #[serde(flatten)]
    report: &'a agentplane::audit::AuditReport,
}

/// Where a journal verb's run list stopped short of the store.
#[derive(Debug, Default, serde::Serialize)]
struct Truncation {
    /// The `--limit` in force.
    limit: usize,
    /// The outcomes, and `in-flight runs`, whose list reached it — so runs
    /// past it were not read.
    reached: Vec<String>,
}

impl Truncation {
    const fn is_partial(&self) -> bool {
        !self.reached.is_empty()
    }
}

/// What `verify` prints: the file's report, and the anchor it was held to.
#[derive(serde::Serialize)]
struct VerifyDocument<'a> {
    anchor: &'a Anchor,
    #[serde(flatten)]
    report: &'a agentplane::export::VerifyReport,
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    grader_verdicts: &'a [agentplane::grader_verdict::SidecarReport],
}

/// The two verbs that read a journal instead of a manifest.
///
/// One function because they differ only in what they do with the run list, and
/// the half that is easy to get wrong — *which* runs, and saying so when the
/// limit truncated — is the half they share. `audit` is `None` for an export,
/// and carries the evidence flags for an audit.
/// The trusted witness keys an auditor named, as the reader takes them.
fn witness_keys(keys: &[String]) -> Result<Vec<agentplane::journal::TrustedWitness>, String> {
    let mut out = Vec::new();
    for entry in keys {
        let Some((name, encoded)) = entry.split_once('=') else {
            return Err(format!(
                "--witness-key takes <name>=<base64 Ed25519 public key>, got '{entry}' — \
                 the name is the one the witness signs its lines with, and the key is \
                 what makes a cosignature checkable rather than a string"
            ));
        };
        // Base64 where the sibling `--key` takes hex, and the difference is
        // whose key it is. A record-signing key id is this deployment's own,
        // so an operator can publish it in whatever form the flag wants; a
        // witness key arrives from a third party, published in base64 by
        // every witness in the existing network. Making an auditor re-encode
        // it by hand adds a step where a typo reads as "the witness is down".
        let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
            .map_err(|e| format!("--witness-key {name}: not base64: {e}"))?;
        let key: [u8; 32] = bytes.try_into().map_err(|b: Vec<u8>| {
            format!(
                "--witness-key {name}: an Ed25519 public key is 32 bytes, this is {}",
                b.len()
            )
        })?;
        out.push(agentplane::journal::TrustedWitness::ed25519(name, key));
    }
    Ok(out)
}

/// Wire `serve`'s submission witnesses and checkpoint interval into the plane.
///
/// An interval shorter than a non-zero `--sweep-every` is refused: the sweep is
/// what re-submits, so it could not be kept.
#[cfg(all(feature = "a2a-server", feature = "cedar"))]
fn with_submission_witnesses(
    builder: agentplane::runtime::RuntimeBuilder,
    opts: &ServeArgs,
) -> Result<agentplane::runtime::RuntimeBuilder, String> {
    if opts.witness_submit.is_empty() {
        if !opts.witness_key.is_empty()
            || opts.witness_quorum.is_some()
            || opts.log_key.is_some()
            || opts.witness_interval.is_some()
        {
            return Err(
                "--witness-key, --witness-quorum, --log-key and --witness-interval need \
                 --witness-submit: there is no witness to submit to"
                    .to_owned(),
            );
        }
        return Ok(builder);
    }
    let trusted = witness_keys(&opts.witness_key)?;
    if trusted.is_empty() {
        return Err("--witness-submit needs at least one --witness-key".to_owned());
    }
    let Some((name, path)) = opts.log_key.as_deref().and_then(|k| k.split_once('=')) else {
        return Err(
            "--witness-submit needs --log-key <name>=<path to a 64-hex-character seed>: \
             a witness recognises a log by its signed note"
                .to_owned(),
        );
    };
    let seed_hex = std::fs::read_to_string(path).map_err(|e| format!("--log-key {path}: {e}"))?;
    let seed: [u8; 32] = hex::decode(seed_hex.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| format!("--log-key {path}: not a 32-byte seed as 64 hex characters"))?;
    let signer = agentplane::policy::Ed25519Signer::new(name, &seed);
    let public = signer.verifying_key();
    let log = agentplane::journal::LogKey::ed25519(name, public, Arc::new(signer))
        .map_err(|e| format!("--log-key {name}: {e}"))?;
    let mut witnesses: Vec<Arc<dyn agentplane::journal::Witness>> = Vec::new();
    for prefix in &opts.witness_submit {
        let witness = agentplane::journal::HttpWitness::new(prefix, log.clone(), trusted.clone())
            .map_err(|e| format!("--witness-submit {prefix}: {e}"))?;
        witnesses.push(Arc::new(witness));
    }
    let required = opts.witness_quorum.unwrap_or(witnesses.len());
    if required > witnesses.len() {
        return Err(format!(
            "--witness-quorum {required} is above the {} witness(es) given",
            witnesses.len()
        ));
    }
    let quorum = agentplane::journal::WitnessQuorum::of(required)
        .map_err(|e| format!("--witness-quorum {required}: {e}"))?;
    let mut builder = builder.witnesses(witnesses, quorum);
    if let Some(secs) = opts.witness_interval {
        let sweep = opts.sweep_every.unwrap_or(DEFAULT_SWEEP_SECONDS);
        if sweep != 0 && secs < u64::from(sweep) {
            return Err(format!(
                "--witness-interval {secs} is shorter than --sweep-every {sweep}: the sweep \
                 re-submits, so an interval shorter than it cannot be kept"
            ));
        }
        if sweep == 0 {
            eprintln!(
                "--witness-interval {secs} with --sweep-every 0: the interval is kept only as \
                 often as your own scheduler sweeps"
            );
        }
        builder = builder.witness_interval(std::time::Duration::from_secs(secs));
    }
    Ok(builder)
}

/// What the named witnesses hold for `origin`, and whether they agree.
///
/// The **anchor** an auditor needs is one checkpoint from outside the store.
/// Naming several witnesses buys something a single one cannot: a split view
/// is exactly two witnesses holding one size with different roots, and no
/// single anchor exhibits it. So this returns every checkpoint the witnesses
/// cosigned — each one an anchor the audit is held to — and reports a
/// disagreement on stderr as what it is: the event witnessing exists to
/// detect, found by the party it exists to protect.
///
/// `Ok(None)` when no witness was named. A named witness that has never seen
/// this log is said out loud and is not an anchor: an auditor holding a clean
/// report has to know that the check they asked for did not happen.
async fn anchor_from_witnesses(
    prefixes: &[String],
    keys: &[String],
    origin: &str,
) -> Result<Anchor, String> {
    let mut anchor = Anchor::default();
    if prefixes.is_empty() {
        if !keys.is_empty() {
            return Err("--witness-key was given with no --witness to use it against".to_owned());
        }
        return Ok(anchor);
    }
    let trusted = witness_keys(keys)?;
    if trusted.is_empty() {
        return Err(
            "--witness needs at least one --witness-key: a checkpoint fetched from a URL \
             nobody's signature covers is a stranger's claim presented as an independent \
             anchor"
                .to_owned(),
        );
    }

    let mut held: Vec<(String, agentplane::journal::Checkpoint)> = Vec::new();
    for prefix in prefixes {
        let reader = agentplane::journal::WitnessReader::new(prefix, trusted.clone())
            .map_err(|e| format!("--witness {prefix}: {e}"))?;
        match reader.latest(origin).await {
            Ok(Some(cosigned)) => {
                eprintln!(
                    "witness {prefix}: log '{}' at size {} with root {}, {} cosignature(s)",
                    cosigned.checkpoint.origin,
                    cosigned.checkpoint.size,
                    cosigned.checkpoint.root.to_hex(),
                    cosigned.cosignatures.len(),
                );
                // **Kept, not compared.** Every witness answer is an
                // independent observation, and the audit is held to all of
                // them: dropping the lower ones would drop the only
                // observation a fork is visible from, since the history an
                // equivocating operator feeds a fresh witness is the longest
                // one anybody holds. The cosignature keys are taken from the
                // same answer, never assembled separately — a basis describing
                // a checkpoint other than the one used would be the laundering
                // these records exist to prevent.
                anchor
                    .checkpoints
                    .push(agentplane::audit::Anchor::from_cosigned(
                        &cosigned,
                        format!("witness {prefix}"),
                    ));
                anchor.cosigned_by.extend(
                    cosigned
                        .cosignatures
                        .iter()
                        .map(|c| format!("{prefix}:{}", c.key_id)),
                );
                held.push((prefix.clone(), cosigned.checkpoint));
            }
            // An answer, and one an auditor acts on: submission never reached
            // this witness, so the anchor they asked for does not exist.
            Ok(None) => {
                let said = format!(
                    "witness {prefix}: has never cosigned log '{origin}' — no anchor from \
                     this one, and nothing here is evidence about deletion"
                );
                eprintln!("{said}");
                anchor.unreached.push(said);
            }
            // Not fatal: one unreachable witness among several still leaves an
            // anchor, and failing the command over it would make an auditor's
            // check depend on every witness being up at once.
            Err(e) => {
                let said = format!("witness {prefix}: {e}");
                eprintln!("{said}");
                anchor.unreached.push(said);
            }
        }
    }

    // The rule lives in the library, where it can be tested and where an
    // embedder auditing with several witnesses gets it too. Said before the
    // report so it is not lost in the scroll — and **kept**, because a
    // finding delivered only to a terminal is a finding nobody files.
    for split in agentplane::journal::split_views(&held) {
        eprintln!("{split}");
        anchor.split_view.push(split.to_string());
    }
    Ok(anchor)
}

/// The audit half of `journal_verb`, printed and turned into an exit code.
///
/// Its own function because the export half and this one share only the run
/// list, and because assembling the evidence — a key, a saved checkpoint, an
/// anchor fetched from witnesses — is the part with rules in it.
async fn audit_report(
    store: &Arc<dyn JournalStore>,
    runs: &[agentplane::RunId],
    audit: &AuditArgs,
    truncated: &Truncation,
) -> Result<ExitCode, Fault> {
    // An audit with no prior checkpoint and no key still checks every
    // chain, and reports the two things it could not do. That is the
    // honest default for somebody who has just been handed a database —
    // and the flags are how they narrow it on the second pass, with the
    // key the operator published and the checkpoint the first pass printed.
    let verifier = verifier_from(&audit.key).map_err(usage)?;
    // The store's own origin, unless the auditor named one — which they do
    // exactly when the store's answer is the thing under suspicion.
    let origin = match &audit.origin {
        Some(o) => o.clone(),
        None => store.checkpoint().await.map_err(|e| e.to_string())?.origin,
    };
    let fetched = anchor_from_witnesses(&audit.witness, &audit.witness_key, &origin)
        .await
        .map_err(usage)?;
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
    // A checkpoint from a file and one from a witness are the same kind of
    // evidence, and the higher one establishes more: the append-only check
    // is *since when*, so the later anchor is the stronger claim. Both
    // named is not a conflict to resolve — a witness holding a size the
    // saved checkpoint has passed is ordinary, and the reverse is a
    // finding the check below produces on its own.
    // A checkpoint read from a file joins the witnesses' rather than competing
    // with them. They are answers to the same question from different
    // observers, and the audit is held to each: a saved checkpoint an earlier
    // audit printed is exactly the observation that exposes a store which has
    // since been rewritten, and dropping it because a witness answered higher
    // would drop the evidence for the reason it is evidence.
    let mut anchor = fetched;
    if let Some(saved) = prior {
        anchor.checkpoints.push(agentplane::audit::Anchor::new(
            saved,
            match &audit.prior {
                Some(path) => format!("file {path}"),
                None => "file".to_owned(),
            },
        ));
    }

    // The auditor's own clock is what a freshness bound is judged against.
    #[allow(clippy::disallowed_methods)]
    let now = agentplane::core::Timestamp::now_utc();
    let evidence = agentplane::audit::Evidence {
        anchors: &anchor.checkpoints,
        verifier: verifier
            .as_ref()
            .map(|v| v as &dyn agentplane::core::Verifier),
        require_signatures: audit.require_signatures,
        freshness: audit
            .max_checkpoint_age
            .map(|secs| agentplane::audit::Freshness {
                now,
                max_age: std::time::Duration::from_secs(secs),
            }),
    };
    let report = agentplane::audit::audit(store, runs, &evidence)
        .await
        .map_err(|e| e.to_string())?;
    println!(
        "{}",
        serde_json::to_string_pretty(&AuditDocument {
            anchor: &anchor,
            truncated,
            report: &report,
        })
        .map_err(|e| e.to_string())?
    );
    // Findings are a failure; `not_checked` is not. An auditor who supplied
    // nothing gets a clean exit and a populated `not_checked`, and it is
    // their call whether that is enough.
    //
    // A split view fails too, and it is not the library's to report: two
    // witnesses holding one size with two different roots is the event
    // witnessing exists to detect, and only this command — which asked more
    // than one witness — is in a position to see it.
    //
    // A sound audit over a truncated run list is a partial answer, not a pass:
    // the runs past `--limit` were never read.
    Ok(ExitCode::from(audit_status(
        report.is_sound() && anchor.split_view.is_empty(),
        truncated,
    )))
}

/// Whether an export stops before writing: truncated, and nobody said a partial
/// file is what they want.
const fn refuses_partial_export(truncated: &Truncation, allow_partial: bool) -> bool {
    truncated.is_partial() && !allow_partial
}

/// How an audit exits: a finding outranks a partial view, and a partial view
/// is never a pass.
const fn audit_status(sound: bool, truncated: &Truncation) -> u8 {
    if !sound {
        exit::FINDING
    } else if truncated.is_partial() {
        exit::PARTIAL
    } else {
        exit::OK
    }
}

/// The export half of `journal_verb`: write the runs out, or refuse a partial
/// file nobody asked for.
async fn export_runs(
    store: &Arc<dyn JournalStore>,
    cases: &Arc<dyn agentplane::case::CaseStore>,
    runs: &[agentplane::RunId],
    truncation: &Truncation,
    allow_partial: bool,
) -> Result<ExitCode, Fault> {
    // Refused before a byte is written: a truncated export is framed
    // exactly like a complete one, so the only place the difference
    // can live is the decision to write it at all.
    if refuses_partial_export(truncation, allow_partial) {
        eprintln!(
            "agentplane: refusing a partial export; raise --limit, narrow \
             --outcome, or pass --allow-partial to write it anyway"
        );
        return Ok(ExitCode::from(exit::PARTIAL));
    }
    let stdout = std::io::stdout();
    let trailer =
        agentplane::export::to_jsonl(store, cases, runs, std::io::BufWriter::new(stdout.lock()))
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
        return Ok(ExitCode::from(exit::FINDING));
    }
    Ok(ExitCode::from(if truncation.is_partial() {
        exit::PARTIAL
    } else {
        exit::OK
    }))
}

/// The grant exercise report, from an export and the manifests it names.
fn grants_verb(opts: &GrantsArgs) -> Result<ExitCode, Fault> {
    let manifests = opts
        .manifest
        .iter()
        .map(|path| {
            let text =
                std::fs::read_to_string(path).map_err(|e| usage(format!("reading {path}: {e}")))?;
            Manifest::parse(&text).map_err(|e| usage(format!("{path}: {e}")))
        })
        .collect::<Result<Vec<_>, Fault>>()?;
    let grants = agentplane::grants::Grants::new(&manifests);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the async runtime: {e}"))?;
    let report = if opts.from == "-" {
        rt.block_on(grants.run(std::io::stdin().lock()))
    } else {
        let file =
            std::fs::File::open(&opts.from).map_err(|e| format!("reading {}: {e}", opts.from))?;
        rt.block_on(grants.run(std::io::BufReader::new(file)))
    }
    .map_err(|e| match e {
        agentplane::grants::GrantsError::NotAnExport(_)
        | agentplane::grants::GrantsError::Manifest(_) => usage(format!("{}: {e}", opts.from)),
        _ => Fault::Operational(e.to_string()),
    })?;

    if let Some(dir) = &opts.propose {
        std::fs::create_dir_all(dir).map_err(|e| format!("creating {dir}: {e}"))?;
        for row in &report.digests {
            let (Some(digest), Some(proposal)) = (&row.digest, &row.proposal) else {
                continue;
            };
            let yaml = agentplane::manifest::registry::to_yaml(&proposal.manifest)
                .map_err(|e| e.to_string())?;
            let header = format!(
                "# Proposed by `agentplane grants` from {}: unsigned, not published.\n\
                 # Equal to the input after parsing except for the removed grants: {:?}.\n\
                 # Comments and key order are not kept. Export {}.\n",
                opts.from,
                proposal.removed,
                if report.window.complete() {
                    "complete"
                } else {
                    "INCOMPLETE"
                },
            );
            let path = std::path::Path::new(dir).join(format!("{digest}.yaml"));
            std::fs::write(&path, header + &yaml)
                .map_err(|e| format!("writing {}: {e}", path.display()))?;
        }
    }

    if opts.out.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    } else {
        print!("{report}");
    }
    Ok(if report.has_unused() {
        ExitCode::from(exit::FINDING)
    } else if report.partial() {
        ExitCode::from(exit::PARTIAL)
    } else {
        ExitCode::SUCCESS
    })
}

/// Where a subject's data went, read from a store and changing nothing.
fn subject_verb(opts: &SubjectArgs) -> Result<ExitCode, Fault> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the async runtime: {e}"))?;
    rt.block_on(async {
        let backend = opts.at.open().await?;
        let tenant = backend.tenant();
        let report = agentplane::subject::Trace::new(tenant.as_str())
            .report(
                &backend.journal(),
                backend.memory().as_ref(),
                &opts.subject,
                opts.limit,
            )
            .await
            .map_err(|e| Fault::Operational(e.to_string()))?;
        if opts.out.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
            );
        } else {
            print!("{report}");
        }
        Ok(if report.partial() {
            ExitCode::from(exit::PARTIAL)
        } else {
            ExitCode::SUCCESS
        })
    })
}

fn journal_verb(
    opts: &StoreArgs,
    audit: Option<&AuditArgs>,
    allow_partial: bool,
) -> Result<ExitCode, Fault> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the async runtime: {e}"))?;

    rt.block_on(async {
        let backend = opts.at.open().await?;
        let store = backend.journal();
        // The same store holds the case layer, so the export always carries it.
        // An optional flag here would be a way to quietly produce the file the
        // verifier flags — the matters the journal names, missing.
        let cases = backend.cases();

        // The library's own list, not literals restated here: the store indexes
        // runs *by* outcome and has no "all runs" query, so an offline verb has
        // to name every outcome it wants — and a copy of that list in a binary
        // is where a new one would be silently dropped from exactly the
        // artifact an auditor asks for.
        let wanted: Vec<String> = if opts.outcome.is_empty() {
            agentplane::runtime::OUTCOMES_OF_RECORD
                .iter()
                .map(|s| (*s).to_owned())
                .collect()
        } else {
            opts.outcome.clone()
        };

        // In-flight runs are skipped when the caller narrowed to specific
        // outcomes, because that is a request for exactly those conclusions.
        let found =
            agentplane::export::runs_to_read(&store, &wanted, opts.outcome.is_empty(), opts.limit)
                .await
                .map_err(|e| e.to_string())?;
        let runs = found.runs;
        let truncated = found.reached;
        for (run, why) in &found.unreadable {
            eprintln!("warning: in-flight run {run} could not be read: {why}");
        }
        if found.in_flight > 0 {
            eprintln!(
                "including {} run(s) still in flight — sleeping, awaiting a message, \
                 or waiting on a person. The Merkle log commits to sealed runs only, \
                 so these are carried and the checkpoint does not cover them",
                found.in_flight
            );
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
            let truncation = Truncation {
                limit: opts.limit,
                reached: truncated,
            };
            return export_runs(&store, &cases, &runs, &truncation, allow_partial).await;
        };

        audit_report(
            &store,
            &runs,
            audit,
            &Truncation {
                limit: opts.limit,
                reached: truncated,
            },
        )
        .await
    })
}

/// The recovery rehearsal, from the command line.
///
/// The exit code carries the drill's load-bearing property: **only a loss
/// finding fails the command.** Erasure — tombstoned blobs, destroyed keys —
/// is retention working and lands in the report's counters, never in
/// `findings`, so a plane that erased everything it was asked to exits zero.
/// A drill whose exit code could not tell the two apart would teach whoever
/// scripts it to ignore the nonzero that means bytes are missing with no
/// tombstone to explain them.
fn drill_verb(opts: &DrillArgs) -> Result<ExitCode, Fault> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the async runtime: {e}"))?;

    rt.block_on(async {
        let backend = opts.at.open().await?;
        // The same store the other journal verbs open holds the case layer —
        // that is the wiring, whole. Blobs and keys are not in it, and the
        // report says so instead of this verb pretending otherwise.
        let cases = backend.cases();

        if opts.last {
            let record = cases.last_drill().await.map_err(|e| e.to_string())?;
            let Some(record) = record else {
                // Not an error and not a pass. *Nobody has rehearsed this
                // plane* is the finding an auditor came for, and it is
                // exactly what a missing CI log cannot tell from a rotated
                // one — so it exits non-zero and says which it is.
                println!("{}", serde_json::json!({ "drilled": false }));
                return Ok(ExitCode::from(exit::FINDING));
            };
            let sound = record.sound;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "drilled": true,
                    "at": record.at.to_string(),
                    "sound": sound,
                    "cases": record.cases,
                    "findings": record.findings,
                    "not_checked": record.not_checked,
                    // Which store, so a rehearsal against a restored copy
                    // cannot be read as one against production.
                    "origin": record.origin,
                    "log_size": record.size,
                }))
                .map_err(|e| e.to_string())?
            );
            return Ok(if sound {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(exit::FINDING)
            });
        }
        // The tenant scopes blob addresses and key scopes. This verb wires
        // neither store, so it reaches neither — but the value is the one the
        // operator named, not a default nobody chose.
        let tenant = opts
            .at
            .tenant
            .as_deref()
            .map(|name| {
                agentplane::core::TenantId::new(name).map_err(|e| usage(format!("--tenant: {e}")))
            })
            .transpose()?
            .unwrap_or_default();
        let stores = agentplane::drill::Stores {
            cases: &cases,
            blobs: None,
            #[cfg(feature = "keyring")]
            keys: None,
            tenant: &tenant,
        };
        let report = agentplane::drill::drill(&stores)
            .await
            .map_err(|e| e.to_string())?;

        // Recorded here as well as on `Runtime::drill`, because otherwise the
        // plane's answer to *when did you last rehearse* would depend on
        // which surface ran it. This verb reaches neither the blob store nor
        // the key ring, so its `not_checked` is large — and writing that
        // honestly is right even though it replaces a richer scheduled
        // drill's verdict: it *is* the last rehearsal, and it *was*
        // incomplete.
        #[allow(clippy::disallowed_methods)]
        let at = agentplane::core::Timestamp::now_utc();
        let checkpoint = backend
            .journal()
            .checkpoint()
            .await
            .map_err(|e| e.to_string())?;
        cases
            .record_drill(&agentplane::case::DrillRecord {
                at,
                sound: report.is_sound(),
                cases: report.cases as u64,
                findings: report.findings.len() as u64,
                not_checked: report.not_checked.len() as u64,
                origin: checkpoint.origin.clone(),
                size: checkpoint.size,
            })
            .await
            .map_err(|e| e.to_string())?;

        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
        Ok(if report.is_sound() {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(exit::FINDING)
        })
    })
}

/// The instant a retention window of `days` reaches back to.
///
/// Checked, and the refusal is the point: subtracting a duration from an
/// instant **panics** in `time` when the result leaves the representable range,
/// so a typed-in day count large enough would abort the command rather than
/// explain itself. The two verbs that take such a window share this so they
/// cannot come to disagree about where the edge is.
fn cutoff_before(
    now: agentplane::core::Timestamp,
    days: u32,
) -> Result<agentplane::core::Timestamp, String> {
    now.checked_sub(time::Duration::days(i64::from(days)))
        .ok_or_else(|| {
            format!(
                "--older-than-days {days} reaches back past the first instant this \
                 runtime can name"
            )
        })
}

/// Retire admission keys past a window the operator chose.
///
/// Prints the count, because a retention pass that says nothing is
/// indistinguishable from one that found nothing — and the two call for
/// different responses when the index keeps growing.
fn forget_admissions_verb(opts: &ForgetArgs) -> Result<ExitCode, Fault> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the async runtime: {e}"))?;

    rt.block_on(async {
        let store = opts.at.open().await?.journal();
        // Wall clock by design, like the sweeper's: a retention window is a
        // question about how long ago something was claimed, not a journaled
        // observation of a run.
        #[allow(clippy::disallowed_methods)]
        let now = time::OffsetDateTime::now_utc();
        let cutoff = cutoff_before(now, opts.older_than_days).map_err(usage)?;
        let retired = store
            .forget_admissions(cutoff)
            .await
            .map_err(|e| e.to_string())?;
        println!(
            "{}",
            serde_json::json!({
                "retired": retired,
                "older_than_days": opts.older_than_days,
                "cutoff": cutoff.unix_timestamp(),
            })
        );
        Ok(ExitCode::SUCCESS)
    })
}

/// Plan a retention pass.
///
/// This binary wires **no blob store and no key ring** — a redb file is a
/// journal and a case layer, not a bucket and not a KMS — so nothing here can
/// make a byte unreadable. A verb that walked the cases, erased nothing, and
/// printed `erased: 0` beside a clean exit code would be a control that reads
/// as having run. So the verb is named for the half it performs — *what a pass
/// would erase* — through the same selection rule `Runtime::retain` uses.
fn retention_plan_verb(opts: &RetentionPlanArgs) -> Result<ExitCode, Fault> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the async runtime: {e}"))?;

    rt.block_on(async {
        let cases = opts.at.open().await?.cases();

        // Wall clock by design, like the sweeper's: a retention window is a
        // question about how long ago a matter opened, not a journaled
        // observation of a run.
        #[allow(clippy::disallowed_methods)]
        let now = time::OffsetDateTime::now_utc();
        let cutoff = cutoff_before(now, opts.older_than_days).map_err(usage)?;
        let plan = agentplane::retention::plan(cases.as_ref(), cutoff)
            .await
            .map_err(|e| e.to_string())?;
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "cutoff": cutoff.unix_timestamp(),
                "scanned": plan.scanned,
                "would_erase": plan.due,
            }))
            .map_err(|e| e.to_string())?
        );
        Ok(ExitCode::SUCCESS)
    })
}

/// What a verb whose store is optional in the parser says when none was named.
///
/// `halt` and `hold` take a `list` subcommand, and clap cannot make `--store`
/// required on the verb and optional on its subcommand at once — so the one
/// requirement it would have enforced is enforced here, in its words.
fn missing_store() -> String {
    "--store is required (or set AGENTPLANE_STORE): the plane's store, a redb file or a \
     `postgres://` connection string"
        .to_owned()
}

/// Every standing legal hold; or, with `released`, up to that many recorded
/// releases, newest first.
fn holds_verb(at: &StoreRef, released: Option<usize>) -> Result<ExitCode, Fault> {
    blocking(async {
        let backend = at.open().await?;
        if let Some(limit) = released {
            let plane = backend.plane().build();
            let mut records = plane
                .released_holds(limit.saturating_add(1))
                .await
                .map_err(|e| e.to_string())?;
            let truncated = records.len() > limit;
            records.truncate(limit);
            let rows: Vec<serde_json::Value> = records.iter().filter_map(release_row).collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "released": rows,
                    "truncated": truncated,
                }))
                .map_err(|e| e.to_string())?
            );
            return Ok(listed_status(truncated));
        }
        let cases = backend.cases();
        let mut standing = Vec::new();
        let mut after = None;
        loop {
            let page = cases.holds(after, 256).await.map_err(|e| e.to_string())?;
            if page.is_empty() {
                break;
            }
            after = page.last().map(|(c, _)| *c);
            for (id, hold) in page {
                standing.push(serde_json::json!({
                    "case": id.to_string(),
                    "placed_at": hold.placed_at.unix_timestamp(),
                    "reason": hold.reason,
                    "by": hold.by.actor(),
                    "basis": hold.by.basis().as_str(),
                }));
            }
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({ "holds": standing }))
                .map_err(|e| e.to_string())?
        );
        Ok(ExitCode::SUCCESS)
    })
}

/// Place or lift a legal hold.
///
/// Prints what it did for the reason `halt` does: an operator who cannot see
/// the control move has not been told whether they moved it.
fn hold_verb(opts: &HoldArgs) -> Result<ExitCode, Fault> {
    let (at, case) = match (&opts.list, &opts.at, &opts.case) {
        (Some(HoldListing::List(list)), ..) => {
            return holds_verb(&list.at, list.released.then_some(list.limit));
        }
        (None, Some(at), Some(case)) => (at, case.as_str()),
        (None, None, _) => return Err(usage(missing_store())),
        (None, Some(_), None) => {
            return Err(usage(
                "name the matter with --case, or run `hold list` to list every \
                        hold standing"
                    .to_owned(),
            ));
        }
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the async runtime: {e}"))?;

    if opts.lift {
        let by = lifter(opts.actor.as_deref(), "release a hold")?;
        let case =
            agentplane::core::CaseId::parse(case).map_err(|e| usage(format!("--case: {e}")))?;
        return rt.block_on(async {
            let plane = at.open().await?.plane().build();
            // Wall clock by design: when a hold was released is a fact about
            // the outside world, not a journaled observation.
            #[allow(clippy::disallowed_methods)]
            let now = time::OffsetDateTime::now_utc();
            let record = plane
                .release_hold(case, &by, now)
                .await
                .map_err(|e| e.to_string())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "case": case.to_string(),
                    "lifted": record.is_some(),
                    "removed": record.is_some_and(|r| r.removed),
                    "by": by.actor(),
                    "basis": by.basis().as_str(),
                    "record": record.map(|r| r.record.to_string()),
                }))
                .map_err(|e| e.to_string())?
            );
            Ok(lift_status(record.is_some()))
        });
    }

    rt.block_on(async {
        let cases = at.open().await?.cases();

        let case =
            agentplane::core::CaseId::parse(case).map_err(|e| usage(format!("--case: {e}")))?;

        let Some(reason) = opts.reason.as_deref() else {
            return Err(usage(
                concat!(
                    "--reason is required to place a hold: a preservation nobody can account for ",
                    "is indistinguishable from a sweep that quietly stopped working. ",
                    "Use --lift to release one"
                )
                .to_owned(),
            ));
        };
        let Some(actor) = opts.actor.as_deref() else {
            return Err(usage(
                concat!(
                    "--actor is required to place a hold: a preservation order the runtime ",
                    "cannot check is worth the name beside it, and the row records that this ",
                    "one was asserted rather than authenticated"
                )
                .to_owned(),
            ));
        };
        let by = agentplane::core::Operator::asserted(actor).map_err(|e| usage(e.to_string()))?;
        // Wall clock by design, like the retention cutoff: when a hold was placed
        // is a fact about the outside world, not a journaled observation.
        #[allow(clippy::disallowed_methods)]
        let now = time::OffsetDateTime::now_utc();
        let placed = cases
            .place_hold(
                case,
                &agentplane::core::LegalHold {
                    placed_at: now,
                    reason: reason.to_owned(),
                    by,
                },
            )
            .await
            .map_err(|e| e.to_string())?;
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "case": case.to_string(),
                "placed": placed,
                // False means one was already standing, and the first placement
                // is the one that counts — so say what is actually in force
                // rather than leaving the operator to assume it is theirs.
                "in_force": cases.hold(case).await.map_err(|e| e.to_string())?
                    .map(|h| serde_json::json!({
                        "placed_at": h.placed_at.unix_timestamp(),
                        "reason": h.reason,
                        "by": h.by.actor(),
                        "basis": h.by.basis().as_str(),
                    })),
            }))
            .map_err(|e| e.to_string())?
        );
        Ok(ExitCode::SUCCESS)
    })
}

/// Throw or lift one emergency stop.
///
/// Prints what it did, because an operator who cannot see the switch move has
/// not been told whether they threw it.
fn halt_verb(opts: &HaltArgs) -> Result<ExitCode, Fault> {
    let at = match (&opts.list, &opts.at) {
        (Some(HaltListing::List(list)), _) => {
            return halts_verb(&list.at, list.lifted.then_some(list.limit), opts.json);
        }
        (None, Some(at)) => at,
        (None, None) => return Err(usage(missing_store())),
    };
    let scope = agentplane::quota::HaltScope::parse(&opts.scope).ok_or_else(|| {
        usage(format!(
            "'{}' is not a scope: use {}",
            opts.scope,
            agentplane::quota::HaltScope::forms()
        ))
    })?;
    if opts.lift {
        let by = lifter(opts.actor.as_deref(), "lift a halt")?;
        return lift_one_halt(at, &scope, &by, opts.json);
    }
    let thrown = {
        let reason = opts.reason.as_deref().ok_or_else(|| {
            usage(concat!(
                "--reason is required to halt: the next person to look will be somebody else, ",
                "possibly at three in the morning, and why is the whole question. ",
                "Use --lift to clear a halt"
            ))
        })?;
        let actor = opts.actor.as_deref().ok_or_else(|| {
            usage(concat!(
                "--actor is required to halt: the runtime cannot check an emergency stop, ",
                "so the name beside it is the whole of its evidence. It is recorded as ",
                "asserted — nothing here verified it"
            ))
        })?;
        let by = agentplane::core::Operator::asserted(actor).map_err(|e| usage(e.to_string()))?;
        (by, reason)
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the async runtime: {e}"))?;

    let (by, reason) = &thrown;
    rt.block_on(async {
        let quotas = at.open().await?.quotas();
        // Wall clock by design, like the retention cutoff and a hold's
        // instant: when a person threw a stop is a fact about the outside
        // world, not a journaled observation.
        #[allow(clippy::disallowed_methods)]
        let now = time::OffsetDateTime::now_utc();
        quotas
            .set_halt(&scope, by, now, reason)
            .await
            .map_err(|e| e.to_string())?;
        if opts.json {
            println!(
                "{}",
                serde_json::json!({
                    "scope": scope.key(),
                    "halted": true,
                    "reason": reason,
                    "by": by.actor(),
                    "basis": by.basis().as_str(),
                })
            );
        } else {
            println!(
                "halted {}: {reason} (by {}, {})",
                scope.key(),
                by.actor(),
                by.basis().as_str()
            );
        }
        Ok(ExitCode::SUCCESS)
    })
}

/// Lift the halt at `scope`, journaled under `by` before the row goes.
///
/// Whether one was standing is the answer to *did I clear the right scope*,
/// which is the question during an incident. A lift that found nothing must not
/// read as success, so it exits as a negative answer.
fn lift_one_halt(
    at: &StoreRef,
    scope: &agentplane::quota::HaltScope,
    by: &agentplane::core::Operator,
    json: bool,
) -> Result<ExitCode, Fault> {
    blocking(async {
        let plane = at.open().await?.plane().build();
        // Wall clock by design, as the throw's instant is.
        #[allow(clippy::disallowed_methods)]
        let now = time::OffsetDateTime::now_utc();
        let record = plane
            .lift_halt(scope, by, now)
            .await
            .map_err(|e| e.to_string())?;
        if json {
            println!(
                "{}",
                serde_json::json!({
                    "scope": scope.key(),
                    "halted": false,
                    "was_standing": record.is_some(),
                    "removed": record.is_some_and(|r| r.removed),
                    "by": by.actor(),
                    "basis": by.basis().as_str(),
                    "record": record.map(|r| r.record.to_string()),
                })
            );
        } else if let Some(lifted) = record {
            let removal = if lifted.removed {
                ""
            } else {
                "; another lift removed the row first"
            };
            println!(
                "lifted {} (by {}, {}; recorded in run {}{removal})",
                scope.key(),
                by.actor(),
                by.basis().as_str(),
                lifted.record
            );
        } else {
            println!("no halt was standing on {}; nothing lifted", scope.key());
        }
        Ok(lift_status(record.is_some()))
    })
}

/// The operator a terminal lift is recorded under, refused before any store is
/// opened when `--actor` is absent: the lift is journaled under this name, and
/// a lift nobody can account for is the gap the record exists to close.
fn lifter(actor: Option<&str>, act: &str) -> Result<agentplane::core::Operator, Fault> {
    let Some(actor) = actor else {
        return Err(usage(format!(
            "--actor is required to {act}: the lift is recorded under that name, and the \
             record says it was asserted rather than authenticated"
        )));
    };
    agentplane::core::Operator::asserted(actor).map_err(|e| usage(e.to_string()))
}

/// How a lift exits: a lift that found nothing standing is a negative answer.
fn lift_status(was_standing: bool) -> ExitCode {
    ExitCode::from(if was_standing {
        exit::OK
    } else {
        exit::FINDING
    })
}

/// One recorded release as `hold list --released` prints it.
fn release_row(record: &agentplane::journal::Record) -> Option<serde_json::Value> {
    let agentplane::journal::RecordKind::HoldReleased {
        by,
        at,
        placed_by,
        placed_at,
    } = record.kind()
    else {
        return None;
    };
    Some(serde_json::json!({
        "case": record.body.case.map(|c| c.to_string()),
        "by": by.actor(),
        "basis": by.basis().as_str(),
        "released_at": at.unix_timestamp(),
        "placed_by": placed_by.actor(),
        "placed_basis": placed_by.basis().as_str(),
        "placed_at": placed_at.unix_timestamp(),
        "record": record.body.run.to_string(),
    }))
}

/// One recorded lift as `halt list --lifted` prints it.
fn lift_row(record: &agentplane::journal::Record) -> Option<serde_json::Value> {
    let agentplane::journal::RecordKind::HaltLifted {
        scope,
        by,
        at,
        reason,
        thrown_by,
        thrown_at,
    } = record.kind()
    else {
        return None;
    };
    Some(serde_json::json!({
        "scope": scope,
        "by": by.actor(),
        "basis": by.basis().as_str(),
        "lifted_at": at.unix_timestamp(),
        "reason": reason,
        "thrown_by": thrown_by.actor(),
        "thrown_basis": thrown_by.basis().as_str(),
        "thrown_at": thrown_at.unix_timestamp(),
        "record": record.body.run.to_string(),
    }))
}

/// Every standing halt, so an operator can see what an incident left behind;
/// or, with `lifted`, up to that many recorded lifts, newest first.
fn halts_verb(at: &StoreRef, lifted: Option<usize>, json: bool) -> Result<ExitCode, Fault> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the async runtime: {e}"))?;

    rt.block_on(async {
        let backend = at.open().await?;
        if let Some(limit) = lifted {
            let plane = backend.plane().build();
            let mut records = plane
                .lifted_halts(limit.saturating_add(1))
                .await
                .map_err(|e| e.to_string())?;
            let truncated = records.len() > limit;
            records.truncate(limit);
            let rows: Vec<serde_json::Value> = records.iter().filter_map(lift_row).collect();
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "lifted": rows,
                        "truncated": truncated,
                    }))
                    .map_err(|e| e.to_string())?
                );
            } else if rows.is_empty() {
                println!("no lifts recorded");
            } else {
                for row in &rows {
                    println!(
                        "{}\tlifted {} by {} ({}); thrown {} by {} ({}): {}\trun {}",
                        row["scope"].as_str().unwrap_or_default(),
                        row["lifted_at"],
                        row["by"].as_str().unwrap_or_default(),
                        row["basis"].as_str().unwrap_or_default(),
                        row["thrown_at"],
                        row["thrown_by"].as_str().unwrap_or_default(),
                        row["thrown_basis"].as_str().unwrap_or_default(),
                        row["reason"].as_str().unwrap_or_default(),
                        row["record"].as_str().unwrap_or_default(),
                    );
                }
                if truncated {
                    println!("truncated: --limit {limit} cut the listing short");
                }
            }
            return Ok(listed_status(truncated));
        }
        let quotas = backend.quotas();
        let halts = quotas.halts().await.map_err(|e| e.to_string())?;
        let rows: Vec<serde_json::Value> = halts
            .iter()
            .map(|h| {
                serde_json::json!({
                    "scope": h.scope.key(),
                    "reason": h.reason,
                    "by": h.by.actor(),
                    "basis": h.by.basis().as_str(),
                    "thrown_at": h.at.unix_timestamp(),
                })
            })
            .collect();
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({ "halts": rows }))
                    .map_err(|e| e.to_string())?
            );
        } else if halts.is_empty() {
            println!("no halts standing");
        } else {
            for h in &halts {
                println!(
                    "{}\tthrown {} by {} ({}): {}",
                    h.scope.key(),
                    h.at.unix_timestamp(),
                    h.by.actor(),
                    h.by.basis().as_str(),
                    h.reason
                );
            }
        }
        Ok(ExitCode::SUCCESS)
    })
}

/// List the runs whose last record is a suspension.
fn waiting_verb(opts: &WaitingArgs) -> Result<ExitCode, Fault> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the async runtime: {e}"))?;

    rt.block_on(async {
        let store = opts.at.open().await?.journal();
        let mut waiting = store
            .waiting_runs(opts.limit.saturating_add(1))
            .await
            .map_err(|e| e.to_string())?;
        let truncated = waiting.len() > opts.limit;
        waiting.truncate(opts.limit);
        let rows: Vec<serde_json::Value> = waiting
            .iter()
            .map(|w| {
                serde_json::json!({
                    "run": w.run.to_string(),
                    // The tagged reason, so a script tells a timer from a
                    // correlation without parsing prose: the two fail
                    // differently and only one of them is a defect.
                    "waiting_for": w.reason,
                    "until": w.reason.until().to_string(),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "waiting": rows,
                "truncated": truncated,
            }))
            .map_err(|e| e.to_string())?
        );
        Ok(listed_status(truncated))
    })
}

/// One async runtime, for the verbs that only touch stores.
fn blocking<T, E: From<String>>(
    f: impl std::future::Future<Output = Result<T, E>>,
) -> Result<T, E> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| E::from(format!("could not start the async runtime: {e}")))?
        .block_on(f)
}

/// Establish what happened to an effect the runtime could not decide.
///
/// The first of the remedies `attention` names for a quarantine, and the one
/// that has to come first: reopening a run whose doubt is unanswered
/// quarantines it again, correctly, on the same effect.
fn reconcile_verb(opts: &ReconcileArgs) -> Result<ExitCode, Fault> {
    let assertion = match opts.outcome.as_str() {
        "landed" => {
            let raw = opts.output.as_deref().unwrap_or("null");
            agentplane::core::Assertion::Landed(
                serde_json::from_str(raw)
                    .map_err(|e| usage(format!("--output is not JSON: {e}")))?,
            )
        }
        "did-not-happen" => {
            if opts.output.is_some() {
                return Err(usage(
                    "--output belongs to `--outcome landed`: an effect that did not happen \
                     produced no result to read back"
                        .to_owned(),
                ));
            }
            agentplane::core::Assertion::DidNotHappen
        }
        other => {
            return Err(usage(format!(
                "'{other}' is not an outcome: use `landed` or `did-not-happen`"
            )));
        }
    };
    let by = opts.who.operator()?;
    let run = agentplane::core::RunId::parse(&opts.run_id).map_err(|e| usage(e.to_string()))?;
    let effect =
        agentplane::core::EffectKey::from_hex(&opts.effect).map_err(|e| usage(e.to_string()))?;

    blocking(async move {
        let backend = opts.at.open().await?;
        let plane = backend.plane().build();
        plane
            .reconcile_effect(run, effect, assertion, &by, &opts.note)
            .await
            .map_err(|e| e.to_string())?;
        println!(
            "{}",
            serde_json::json!({
                "run": run.to_string(),
                "effect": opts.effect,
                "outcome": opts.outcome,
                "by": by.actor(),
                "basis": by.basis().as_str(),
            })
        );
        Ok(ExitCode::SUCCESS)
    })
}

/// Answer a quarantine, recording the instruction where the run will find it.
///
/// **It does not drive the run, and says so.** A terminal holds the journal
/// and not the agent — a declarative run's program is a manifest this process
/// was not handed — so the decision is recorded and the next resume applies
/// it. Reporting the run as moved would be the one dishonest thing available
/// here.
fn quarantine_verb(opts: &QuarantineArgs) -> Result<ExitCode, Fault> {
    use agentplane::core::QuarantineDecision;

    let decision = match opts.decision.as_str() {
        "reopen" => QuarantineDecision::Reopen,
        "abandon" => QuarantineDecision::Abandon,
        other => {
            return Err(usage(format!(
                "'{other}' is not a decision: use `reopen` or `abandon`"
            )));
        }
    };
    let by = opts.who.operator()?;
    let run = agentplane::core::RunId::parse(&opts.run_id).map_err(|e| usage(e.to_string()))?;

    blocking(async move {
        let backend = opts.at.open().await?;
        let plane = backend.plane().build();
        plane
            .record_quarantine_decision(run, &by, &opts.reason, decision)
            .await
            .map_err(|e| e.to_string())?;
        println!(
            "{}",
            serde_json::json!({
                "run": run.to_string(),
                "decision": opts.decision,
                "by": by.actor(),
                "basis": by.basis().as_str(),
                // The half an operator has to be told, rather than left to
                // infer from a silent success.
                "applied": false,
                "next": "recorded; the next resume of this run applies it",
            })
        );
        Ok(ExitCode::SUCCESS)
    })
}

/// One task, as a terminal shows it.
///
/// The rendering every surface shows ([`Task::rendering`]): hidden and
/// direction-changing code points escaped in place, words mixing scripts
/// listed beside the text, and a proposal this binary cannot open — it holds
/// no key ring — shown as withheld, with the reason, rather than as an
/// envelope a person might read as the arguments.
///
/// [`Task::rendering`]: agentplane::core::Task::rendering
fn task_json(task: &agentplane::core::Task, whole: bool) -> serde_json::Value {
    let j = &task.justification;
    let shown = task.rendering();
    let mut out = serde_json::json!({
        "task": task.id.to_string(),
        "run": task.run.to_string(),
        "case": task.case.map(|c| c.to_string()),
        "kind": task.kind,
        "state": task.state.as_str(),
        "priority": task.priority.as_str(),
        "summary": shown.summary,
        "proposed_action": shown.proposed_action,
        "withheld": shown.withheld.map(|w| format!("{} — {w}", w.as_str())),
        "candidate_roles": task.candidate_roles,
        "assignee": task.assignee,
        "due_at": task.due_at.map(|d| d.to_string()),
        // Whether a sentence above was written by something the run does not
        // trust — the distinction a reviewer must be shown, not left to infer.
        "has_untrusted_prose": j.has_untrusted_prose(),
        // Whether anything above had a code point escaped that would have
        // rendered as nothing or reordered the text around it.
        "escaped": shown.escaped,
        "mixed_script": shown.mixed_script,
        // The version of the stored row, which `decide --digest` names back.
        "digest": j.digest().to_hex(),
    });
    if whole {
        out["confidence"] = serde_json::json!(j.confidence);
        out["cost"] = serde_json::json!(shown.cost);
        out["evidence"] = serde_json::json!(shown.evidence);
        out["excluded_actors"] = serde_json::json!(task.excluded_actors);
        out["on_expiry"] = serde_json::json!(task.on_expiry.as_str());
        out["escalate_to"] = serde_json::json!(task.escalate_to);
    }
    out
}

/// The worklist, or one task on it.
///
/// Read through [`TaskStore::queue`](agentplane::case::TaskStore::queue) with
/// the roles named, which is the listing the HTTP worklist serves a caller —
/// so a terminal shows the same tasks `decide` would admit, and no others.
fn tasks_verb(opts: &TasksArgs) -> Result<ExitCode, Fault> {
    blocking(async move {
        let tasks = opts.at.open().await?.tasks();
        if let Some(show) = &opts.show {
            let id = agentplane::core::TaskId::parse(show)
                .map_err(|e| usage(format!("`{show}` is not a task id: {e}")))?;
            let task = tasks
                .task(id)
                .await
                .map_err(|e| e.to_string())?
                .ok_or_else(|| format!("no task {id} on this plane"))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&task_json(&task, true)).map_err(|e| e.to_string())?
            );
            return Ok(ExitCode::SUCCESS);
        }
        let mut queued = tasks
            .queue(&opts.roles, opts.limit.saturating_add(1))
            .await
            .map_err(|e| e.to_string())?;
        // One past the page, so *there is more* is a fact rather than an
        // inference from a full page.
        let truncated = queued.len() > opts.limit;
        queued.truncate(opts.limit);
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "tasks": queued.iter().map(|t| task_json(t, false)).collect::<Vec<_>>(),
                "truncated": truncated,
            }))
            .map_err(|e| e.to_string())?
        );
        Ok(listed_status(truncated))
    })
}

/// How a listing exits: one that `--limit` cut short is a partial answer.
fn listed_status(truncated: bool) -> ExitCode {
    ExitCode::from(if truncated { exit::PARTIAL } else { exit::OK })
}

/// Decide a task on the worklist.
///
/// The claim, the eligibility check and four-eyes all run in the task store,
/// which is why `--role` is taken: the exclusion this enforces is the reason
/// an approval is worth anything, and a terminal that skipped it would be a
/// second door into the control the HTTP route goes through.
fn decide_verb(opts: &DecideArgs) -> Result<ExitCode, Fault> {
    let by = opts.who.operator()?;
    let id = agentplane::core::TaskId::parse(&opts.task_id)
        .map_err(|e| usage(format!("`{}` is not a task id: {e}", opts.task_id)))?;
    let expected = opts
        .digest
        .as_deref()
        .map(|hex| {
            agentplane::core::Digest::from_hex(hex)
                .map_err(|e| usage(format!("--digest `{hex}` is not a digest: {e}")))
        })
        .transpose()?;
    let approved = opts.verdict == Verdict::Approve;
    let decision = if approved {
        agentplane::core::Decision::approve(by.clone(), opts.reason.clone())
    } else {
        agentplane::core::Decision::reject(by.clone(), opts.reason.clone())
    };

    blocking(async move {
        let backend = opts.at.open().await?;
        // The shortest lease the store can renew: this plane holds no agent,
        // so a resume after the decision keeps its lease for recovery to find
        // the run, and the operator's `replay` should not wait long for it.
        let plane = backend
            .plane()
            .lease_ttl(std::time::Duration::from_secs(2))
            .build();
        let delivery = match plane
            .decide_task_at(id, &decision, &opts.roles, expected)
            .await
        {
            Ok(delivery) => delivery,
            Err(e @ agentplane::core::RuntimeError::TaskChanged { .. }) => {
                eprintln!(
                    "{e}\n  agentplane tasks --show {id}{}",
                    where_flags(Some(&opts.at.store), opts.at.tenant.as_deref())
                );
                return Ok(ExitCode::from(exit::FINDING));
            }
            // A refusal, not an outage: nothing was recorded and the task is
            // still open, and the person at this terminal is owed the way on.
            Err(agentplane::core::RuntimeError::ProposalWithheld { reason, .. }) => {
                eprintln!("{}", withheld_refusal(id, reason));
                return Ok(ExitCode::from(exit::FINDING));
            }
            Err(e) => return Err(e.to_string().into()),
        };
        println!(
            "{}",
            serde_json::json!({
                "task": id.to_string(),
                "approved": approved,
                "by": by.actor(),
                "basis": by.basis().as_str(),
                // Buffered rather than resumed is the ordinary answer here: a
                // terminal holds no agent to run the waiting run with, and the
                // decision is durable either way.
                "delivery": format!("{delivery:?}"),
            })
        );
        if delivery.resumed_run().is_none()
            && let Some(task) = backend.tasks().task(id).await.map_err(|e| e.to_string())?
        {
            eprintln!(
                "recorded. Run {} reads it when it resumes:\n  agentplane replay {} \
                 --manifest <file>{}",
                task.run,
                task.run,
                where_flags(Some(&opts.at.store), opts.at.tenant.as_deref())
            );
        }
        Ok(ExitCode::SUCCESS)
    })
}

/// Why this terminal will not record an approval, in words its operator can
/// act on.
fn withheld_refusal(id: agentplane::core::TaskId, reason: agentplane::core::Withheld) -> String {
    use agentplane::core::Withheld;
    let why = match reason {
        Withheld::Sealed => {
            "its proposal is sealed at rest and this terminal holds no key ring, so it \
             cannot show you what you would be approving. Approve it on the plane that \
             holds the key ring, or reject it here — a rejection needs no proposal"
        }
        Withheld::Erased => {
            "its proposal was erased — the key it was sealed under is destroyed — so \
             nobody can be shown what an approval would approve. Reject it"
        }
        Withheld::Undecodable => {
            "its sealed proposal opened and does not decode, so what it holds cannot be \
             shown. Reject it, or restore the row from a backup and decide it then"
        }
    };
    format!("task {id} was not approved: {why}. Nothing was recorded; the task is still open.")
}

/// Account for a breached obligation so it leaves the backlog.
fn acknowledge_verb(opts: &AcknowledgeArgs) -> Result<ExitCode, Fault> {
    let by = opts.who.operator()?;
    let case = agentplane::core::CaseId::parse(&opts.case_id).map_err(|e| usage(e.to_string()))?;

    blocking(async move {
        let backend = opts.at.open().await?;
        // Wall clock by design, as a halt's instant is: when somebody
        // accounted for a breach is a fact about the outside world.
        #[allow(clippy::disallowed_methods)]
        let at = agentplane::core::Timestamp::now_utc();
        let note = agentplane::core::BreachNote {
            by: by.clone(),
            note: opts.note.clone(),
            at,
        };
        let recorded = backend
            .cases()
            .acknowledge_breach(case, &opts.obligation, &note)
            .await
            .map_err(|e| e.to_string())?;
        println!(
            "{}",
            serde_json::json!({
                "case": opts.case_id,
                "obligation": opts.obligation,
                // Whether *this* call recorded it: acknowledging is
                // idempotent and first note wins, so a second one must not
                // read as having replaced the first.
                "recorded": recorded,
                "by": by.actor(),
            })
        );
        Ok(ExitCode::SUCCESS)
    })
}

/// Stop a run, and unwind what it did.
///
/// The remedy for the two conclusions a quarantine decision cannot answer: an
/// exhausted run whose ceiling nobody will raise, and a run paused under a
/// withdrawn credential that is not coming back. `quarantine --decision
/// abandon` is refused for both — it answers a doubt, and neither is one.
///
/// A request, not an interruption: the run reads it at its next step
/// boundary, so an effect between announcing and recording is never cut in
/// half.
fn cancel_verb(opts: &CancelArgs) -> Result<ExitCode, Fault> {
    let by = opts.who.operator()?;
    let run = agentplane::core::RunId::parse(&opts.run_id).map_err(|e| usage(e.to_string()))?;
    blocking(async move {
        let backend = opts.at.open().await?;
        let plane = backend.plane().build();
        let first = plane
            .request_cancel(run, &by, &opts.reason)
            .await
            .map_err(|e| e.to_string())?;
        println!(
            "{}",
            serde_json::json!({
                "run": run.to_string(),
                "by": by.actor(),
                "basis": by.basis().as_str(),
                // A second asker does not take the first one's place, and must
                // not be told they did.
                "requested": first,
            })
        );
        Ok(ExitCode::SUCCESS)
    })
}

/// Re-arm a parked push registration.
#[cfg(feature = "push")]
fn rearm_verb(opts: &RearmArgs) -> Result<ExitCode, Fault> {
    let run = agentplane::core::RunId::parse(&opts.run_id).map_err(|e| usage(e.to_string()))?;
    blocking(async move {
        let backend = opts.at.open().await?;
        let plane = backend.plane().push(backend.push()).build();
        let rearmed = plane
            .rearm_push(run, &opts.id)
            .await
            .map_err(|e| e.to_string())?;
        println!(
            "{}",
            serde_json::json!({
                "run": run.to_string(),
                "id": opts.id,
                // Whether one was parked to re-arm. A re-arm that found
                // nothing must not read as success, for the reason lifting a
                // halt that was not standing must not.
                "rearmed": rearmed,
            })
        );
        Ok(lift_status(rearmed))
    })
}

/// Ask the plane whether anything needs a person, and exit non-zero if so.
///
/// **The exit code is the point.** This is a verb a scheduler runs, and a check
/// that always exits zero is a check nobody notices has stopped working — the
/// same reason `drill` and `verify` report through their status rather than
/// only on stdout.
fn attention_verb(opts: &WaitingArgs) -> Result<ExitCode, Fault> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the async runtime: {e}"))?;

    rt.block_on(async {
        let backend = opts.at.open().await?;
        // The quota store is wired for its reservations only: which stopped
        // runs hold the tenant's period is a condition, and no ceiling this
        // verb could state is consulted.
        let plane = backend.plane().build();
        // The clock is this verb's, which is what makes the runtime's own
        // escapes stay at three: a binary reading the wall clock to ask "what
        // is overdue right now" is not the deterministic zone reaching for it.
        #[allow(clippy::disallowed_methods)]
        let now = agentplane::core::Timestamp::now_utc();
        let found = plane
            .attention(now, opts.limit)
            .await
            .map_err(|e| e.to_string())?;
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "needs_attention": found.any(),
                "conditions": found
                    .conditions
                    .iter()
                    .map(|c| serde_json::json!({
                        "condition": c.kind,
                        "found": c.found,
                        "at_least": c.at_least,
                        // The ids the remedy's verb takes, so the next command
                        // can be typed from this output alone.
                        "subjects": c.subjects,
                        "unlisted": c.unlisted,
                        "remedy": c.remedy.cli,
                    }))
                    .collect::<Vec<_>>(),
                "not_checked": found.not_checked,
            }))
            .map_err(|e| e.to_string())?
        );
        Ok(if found.any() {
            ExitCode::from(exit::FINDING)
        } else {
            ExitCode::SUCCESS
        })
    })
}

/// How many records `history` reads from the store at a time.
const HISTORY_PAGE: usize = 500;

/// `history`: one run's journal, one line per record.
fn history_verb(opts: &HistoryArgs) -> Result<ExitCode, Fault> {
    let run = agentplane::core::RunId::parse(&opts.run)
        .map_err(|e| usage(format!("`{}` is not a run id: {e}", opts.run)))?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the async runtime: {e}"))?;
    rt.block_on(async {
        let backend = opts.at.open().await?;
        let lines = history_lines(&backend.journal(), run, opts.from, opts.json).await?;
        let Some(lines) = lines else {
            eprintln!(
                "no run {run} in {}{}",
                without_password(&opts.at.store),
                opts.at
                    .tenant
                    .as_deref()
                    .map_or_else(String::new, |t| format!(" (tenant {t})"))
            );
            return Ok(ExitCode::from(exit::FINDING));
        };
        let mut out = std::io::stdout().lock();
        for line in lines {
            std::io::Write::write_all(&mut out, line.as_bytes())
                .and_then(|()| std::io::Write::write_all(&mut out, b"\n"))
                .map_err(|e| format!("could not write the timeline: {e}"))?;
        }
        Ok(ExitCode::SUCCESS)
    })
}

/// The lines `history` prints, or `None` for a run the store does not hold.
///
/// `--json` prints each record as the history route serves it. The text form
/// is built from the same view, and every line passes through the plane's
/// hidden-code-point escaping: a recorded string is somebody's input, and an
/// escape sequence in it would otherwise drive the terminal reading it.
async fn history_lines(
    journal: &Arc<dyn JournalStore>,
    run: agentplane::core::RunId,
    from: Option<u64>,
    json: bool,
) -> Result<Option<Vec<String>>, Fault> {
    let start = from.unwrap_or(1).max(1);
    let mut next = start;
    let mut lines = Vec::new();
    loop {
        let page = journal
            .read_page(run, next, HISTORY_PAGE)
            .await
            .map_err(|e| e.to_string())?;
        for record in &page {
            let view = agentplane::journal::view::record_view(record);
            lines.push(if json {
                serde_json::to_string(&view).map_err(|e| e.to_string())?
            } else {
                timeline_line(&view)
            });
            next = record.seq() + 1;
        }
        if page.len() < HISTORY_PAGE {
            break;
        }
    }
    // A run with no first record is a run nobody has heard of, whatever
    // `from` asked; an empty page from further along a run that exists is a
    // reader who has caught up.
    if lines.is_empty()
        && (start == 1
            || journal
                .read_page(run, 1, 1)
                .await
                .map_err(|e| e.to_string())?
                .is_empty())
    {
        return Ok(None);
    }
    Ok(Some(lines))
}

/// One record as a terminal line: sequence, kind, step, phase, then the
/// payload — escaped.
fn timeline_line(view: &agentplane::journal::view::RecordView) -> String {
    use std::fmt::Write as _;
    let mut payload = view.record.clone();
    if let Some(fields) = payload.as_object_mut() {
        fields.remove("kind");
    }
    let mut line = format!("{:>5}  {}", view.seq, view.kind);
    if let Some(step) = &view.step {
        let _ = write!(line, "  step {step}");
    }
    if view.phase != "forward" {
        let _ = write!(line, "  {}", view.phase);
    }
    line.push_str("  ");
    line.push_str(&serde_json::to_string(&payload).unwrap_or_default());
    agentplane::core::visible::escape(&line).0
}

/// The file beside a scratch store that says `dev` created it.
#[cfg(feature = "dev")]
const DEV_MARKER: &str = ".agentplane-dev";

/// The marker's exact contents.
#[cfg(feature = "dev")]
const DEV_MARKER_TEXT: &str = "created by `agentplane dev`; not a deployment's store\n";

/// The scratch store's file name.
#[cfg(feature = "dev")]
const DEV_STORE: &str = "dev.redb";

/// The store a dev plane runs on: memory, or a scratch directory this mode
/// created.
///
/// Refused before anything is opened: a `PostgreSQL` connection string, a
/// file, a symbolic link, a directory holding anything without the marker's
/// exact bytes, a `dev.redb` that is not a regular file, and a tenant other
/// than `dev`. A deployment's store is never one of these, so a page that
/// starts runs over HTTP cannot write to one.
#[cfg(feature = "dev")]
fn dev_store(scratch: Option<&str>, tenant: Option<&str>) -> Result<Backend, Fault> {
    if let Some(other) = tenant.filter(|t| *t != agentplane::api::dev::TENANT) {
        return Err(usage(format!(
            "`agentplane dev` runs as tenant `{}` only, and `{other}` was named (by --tenant or \
             AGENTPLANE_TENANT) — a deployment's tenant is not a scratch plane",
            agentplane::api::dev::TENANT
        )));
    }
    let tenant =
        agentplane::core::TenantId::new(agentplane::api::dev::TENANT).map_err(|e| e.to_string())?;
    let Some(dir) = scratch else {
        let store = RedbStore::open_in_memory().map_err(|e| e.to_string())?;
        return Ok(Backend::Embedded(
            Arc::new(store.for_tenant(tenant.clone())),
            tenant,
        ));
    };
    if is_connection_string(dir) {
        return Err(usage(
            "--scratch names a database; `agentplane dev` opens only a directory it created",
        ));
    }
    let dir = std::path::Path::new(dir);
    // Nothing here follows a link: a link is a path into a store this mode
    // did not create.
    let kind = |path: &std::path::Path| std::fs::symlink_metadata(path).map(|m| m.file_type());
    if let Ok(found) = kind(dir) {
        if found.is_symlink() {
            return Err(usage(format!(
                "--scratch {} is a symbolic link; `agentplane dev` opens only a directory it \
                 created, and a link can name any other",
                dir.display()
            )));
        }
        if !found.is_dir() {
            return Err(usage(format!(
                "--scratch {} is a file; `agentplane dev` opens only a directory it created, so \
                 no deployment's store is one it writes to",
                dir.display()
            )));
        }
    }
    std::fs::create_dir_all(dir).map_err(|e| format!("could not create {}: {e}", dir.display()))?;
    let held: Vec<String> = std::fs::read_dir(dir)
        .map_err(|e| format!("could not read {}: {e}", dir.display()))?
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    let marker = dir.join(DEV_MARKER);
    let ours = kind(&marker).is_ok_and(|k| k.is_file())
        && std::fs::read(&marker).is_ok_and(|bytes| bytes == DEV_MARKER_TEXT.as_bytes());
    if held.is_empty() {
        std::fs::write(&marker, DEV_MARKER_TEXT)
            .map_err(|e| format!("could not mark {}: {e}", dir.display()))?;
    } else if !ours {
        return Err(usage(format!(
            "--scratch {} holds files and no dev marker; `agentplane dev` opens only an empty \
             directory or one it marked",
            dir.display()
        )));
    } else if let Some(other) = held.iter().find(|n| *n != DEV_MARKER && *n != DEV_STORE) {
        return Err(usage(format!(
            "--scratch {} holds `{other}` beside its dev store; `agentplane dev` opens only a \
             directory holding nothing else",
            dir.display()
        )));
    } else if kind(&dir.join(DEV_STORE)).is_ok_and(|k| !k.is_file()) {
        return Err(usage(format!(
            "--scratch {}/{DEV_STORE} is not a regular file; `agentplane dev` opens only the \
             store it created there",
            dir.display()
        )));
    }
    let path = dir.join(DEV_STORE);
    let store = RedbStore::open(&path).map_err(|e| Fault::from(held_by_a_plane(&e.to_string())))?;
    Ok(Backend::Embedded(
        Arc::new(store.for_tenant(tenant.clone())),
        tenant,
    ))
}

/// `--mcp` and `--peer` reach systems outside this process, so an approval on
/// the page performs a real effect: refused until the author says they own
/// them.
#[cfg(feature = "dev")]
fn refuse_live_without_consent(opts: &DevArgs) -> Result<(), Fault> {
    if !opts.allow_live && (!opts.mcp.is_empty() || !opts.peer.is_empty()) {
        return Err(usage(
            "--mcp and --peer reach real systems, and approving a task on the page performs \
             a real effect through them; add --allow-live to say they are yours to act on",
        ));
    }
    Ok(())
}

/// The dev listener: loopback, on `port`.
#[cfg(feature = "dev")]
async fn bind_dev(port: u16) -> Result<tokio::net::TcpListener, Fault> {
    tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
        .await
        .map_err(|e| usage(format!("could not listen on 127.0.0.1:{port}: {e}")))
}

/// Who the dev session's decisions are recorded under.
#[cfg(feature = "dev")]
fn dev_actor() -> String {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .ok()
        .filter(|u| {
            !u.trim().is_empty()
                && u.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
        })
        .unwrap_or_else(|| "author".to_owned());
    format!("dev:{user}")
}

/// `dev`: serve the page until interrupted.
#[cfg(feature = "dev")]
fn dev_verb(opts: &DevArgs) -> Result<ExitCode, Fault> {
    refuse_live_without_consent(opts)?;
    let manifests = manifests_at(&opts.manifest).map_err(usage)?;
    require_declarative(&manifests).map_err(usage)?;
    let token = fresh_token()?;
    let actor = dev_actor();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the async runtime: {e}"))?;
    rt.block_on(async {
        let backend = dev_store(opts.scratch.as_deref(), opts.tenant.as_deref())?;
        let bench = dev::Bench::start(
            backend,
            dev::Wiring {
                file: opts.manifest.clone(),
                mcp: opts.mcp.clone(),
                peer: opts.peer.clone(),
                acting_as: opts.acting_as.clone(),
                policy: Arc::new(agentplane::api::dev::DevPolicy::new(&actor)),
            },
            manifests,
        )
        .await?;
        let auth = agentplane::api::tokens::TokenAuthenticator::new(vec![
            agentplane::api::tokens::TokenEntry {
                token: token.clone(),
                actor,
                roles: Vec::new(),
                tenant: Some(agentplane::api::dev::TENANT.to_owned()),
                scope: None,
                not_after: None,
            },
        ])
        .map_err(|e| e.to_string())?;
        let listener = bind_dev(opts.port).await?;
        let port = listener
            .local_addr()
            .map_err(|e| format!("the listener has no address: {e}"))?
            .port();
        println!("http://127.0.0.1:{port}/#t={token}");
        let streams = agentplane::api::dev::Workbench::streams(&bench);
        axum::serve(
            listener,
            agentplane::api::dev::router(Arc::new(bench), Arc::new(auth), port),
        )
        .with_graceful_shutdown(async move {
            let _ = tokio::signal::ctrl_c().await;
            // An open page holds its stream open; graceful shutdown would
            // wait on it for ever.
            streams.close();
        })
        .await
        .map_err(|e| format!("the dev page stopped: {e}"))?;
        Ok(ExitCode::SUCCESS)
    })
}

/// Whichever backend `--store` names.
///
/// One flag rather than `--store` plus `--database-url`: two flags are mutually
/// exclusive in prose and simultaneously settable in fact, which is a refusal
/// somebody has to remember to write.
///
/// The choice is not cosmetic. redb admits a single writer **process**, so every
/// verb here is one a serving plane locks out; the shared store has no such
/// rule, which is what makes `halt` reachable during the incident it exists for.
enum Backend {
    /// A redb file. One writer process, so these verbs run between serving
    /// sessions rather than beside one.
    Embedded(Arc<RedbStore>, agentplane::core::TenantId),
    /// A shared `PostgreSQL` database. Several processes, so an operator verb
    /// and a serving plane coexist.
    #[cfg(feature = "postgres")]
    Shared(
        Arc<agentplane::store::PostgresStore>,
        agentplane::core::TenantId,
    ),
}

impl Backend {
    /// Open whichever backend `--store` names, scoped to `--tenant`.
    ///
    /// **Both arguments, always.** Every key in both backends leads with the
    /// tenant, so a cross-tenant read is a *miss* rather than a filtered row: a
    /// verb that opened a store without deciding whose would answer about the
    /// unnamed default and exit zero.
    // `async` in every configuration and awaiting nothing in one: connecting is
    // a network call, opening a file is not. One signature so no caller has to
    // know which feature set it was built with.
    #[allow(clippy::unused_async, clippy::unused_async_trait_impl)]
    async fn open(spec: &str, tenant: Option<&str>) -> Result<Self, Fault> {
        let tenant = tenant
            .map(|name| {
                agentplane::core::TenantId::new(name).map_err(|e| usage(format!("--tenant: {e}")))
            })
            .transpose()?;
        if is_connection_string(spec) {
            // The refusal names the flag rather than saying "not a file": the
            // feature exists, it is one rebuild away, and "no such file or
            // directory" would send somebody to look at their path.
            #[cfg(not(feature = "postgres"))]
            return Err(usage(
                "--store names a PostgreSQL database and this build cannot open one. \
                 Reinstall with `--features cli,postgres`, or use the `:full` container \
                 image, which is built with it",
            ));
            #[cfg(feature = "postgres")]
            return Self::shared(spec, tenant).await;
        }
        let store =
            RedbStore::open(spec).map_err(|e| Fault::from(held_by_a_plane(&e.to_string())))?;
        let tenant = tenant.unwrap_or_default();
        Ok(Self::Embedded(
            Arc::new(store.for_tenant(tenant.clone())),
            tenant,
        ))
    }

    #[cfg(feature = "postgres")]
    async fn shared(url: &str, tenant: Option<agentplane::core::TenantId>) -> Result<Self, Fault> {
        let store = agentplane::store::PostgresStore::connect(url)
            .await
            .map_err(|e| e.to_string())?;
        let tenant = tenant.unwrap_or_default();
        Ok(Self::Shared(
            Arc::new(store.for_tenant(tenant.clone())),
            tenant,
        ))
    }

    /// A plane on this backend, as every verb here builds one.
    ///
    /// **The only door to a runtime in this binary**, so no verb wires its
    /// stores or tenant differently from another.
    fn plane(&self) -> RuntimeBuilder {
        Runtime::builder_with(self.stores()).tenant(self.tenant())
    }

    /// A backend held in this process's memory, for a `run` with no `--store`.
    fn in_memory() -> Result<Self, Fault> {
        let tenant = agentplane::core::TenantId::default();
        let store = RedbStore::open_in_memory().map_err(|e| e.to_string())?;
        Ok(Self::Embedded(
            Arc::new(store.for_tenant(tenant.clone())),
            tenant,
        ))
    }

    /// The stores a plane runs on.
    fn stores(&self) -> agentplane::runtime::Stores {
        match self {
            Self::Embedded(s, _) => agentplane::runtime::Stores::on(Arc::clone(s)),
            #[cfg(feature = "postgres")]
            Self::Shared(s, _) => agentplane::runtime::Stores::on(Arc::clone(s)),
        }
    }

    fn journal(&self) -> Arc<dyn JournalStore> {
        match self {
            Self::Embedded(s, _) => Arc::clone(s) as _,
            #[cfg(feature = "postgres")]
            Self::Shared(s, _) => Arc::clone(s) as _,
        }
    }

    fn disclosures(&self) -> Arc<dyn agentplane::disclosure::DisclosureRegister> {
        match self {
            Self::Embedded(s, _) => Arc::clone(s) as _,
            #[cfg(feature = "postgres")]
            Self::Shared(s, _) => Arc::clone(s) as _,
        }
    }

    fn cases(&self) -> Arc<dyn agentplane::case::CaseStore> {
        match self {
            Self::Embedded(s, _) => Arc::clone(s) as _,
            #[cfg(feature = "postgres")]
            Self::Shared(s, _) => Arc::clone(s) as _,
        }
    }

    fn tasks(&self) -> Arc<dyn agentplane::case::TaskStore> {
        match self {
            Self::Embedded(s, _) => Arc::clone(s) as _,
            #[cfg(feature = "postgres")]
            Self::Shared(s, _) => Arc::clone(s) as _,
        }
    }

    fn memory(&self) -> Arc<dyn agentplane::memory::MemoryStore> {
        match self {
            Self::Embedded(s, _) => Arc::clone(s) as _,
            #[cfg(feature = "postgres")]
            Self::Shared(s, _) => Arc::clone(s) as _,
        }
    }

    fn quotas(&self) -> Arc<dyn agentplane::quota::QuotaStore> {
        match self {
            Self::Embedded(s, _) => Arc::clone(s) as _,
            #[cfg(feature = "postgres")]
            Self::Shared(s, _) => Arc::clone(s) as _,
        }
    }

    #[cfg(feature = "push")]
    fn push(&self) -> Arc<dyn agentplane::push::PushStore> {
        match self {
            Self::Embedded(s, _) => Arc::clone(s) as _,
            #[cfg(feature = "postgres")]
            Self::Shared(s, _) => Arc::clone(s) as _,
        }
    }

    /// Whose plane this store was opened as.
    ///
    /// The store is scoped by `for_tenant` and the runtime carries a tenant of
    /// its own, and **they are two halves of one decision**: a plane running as
    /// the default against a store scoped to `acme` writes runs into one
    /// keyspace while naming the other in every policy request and every
    /// erasure. `try_build` refuses that, which is how this was found — so the
    /// tenant travels with the backend rather than being passed twice.
    fn tenant(&self) -> agentplane::core::TenantId {
        match self {
            Self::Embedded(_, t) => t.clone(),
            #[cfg(feature = "postgres")]
            Self::Shared(_, t) => t.clone(),
        }
    }

    /// What this is, for a message an operator reads.
    #[cfg(all(feature = "a2a-server", feature = "cedar"))]
    const fn describe(&self) -> &'static str {
        match self {
            Self::Embedded(..) => "embedded redb file",
            #[cfg(feature = "postgres")]
            Self::Shared(..) => "shared PostgreSQL store",
        }
    }
}

/// Say what a locked embedded store means, in the words of the situation.
///
/// redb admits one writer **process**, so the ordinary way to meet this is to
/// run an operator verb against the file a `serve` is holding — which is to say,
/// during an incident, which is when the message matters most. *Database already
/// open* is true and tells nobody what to do about it.
fn held_by_a_plane(detail: &str) -> String {
    if !detail.contains("already open") {
        return detail.to_owned();
    }
    format!(
        "{detail}\n\nAn embedded redb store admits one writer process, and something \
         else is holding this one — most likely `agentplane serve`. Either stop that \
         process and run this again, or put the plane on a shared store \
         (`--store postgres://…`), where an operator verb and a serving plane \
         coexist. To act on a *running* embedded plane meanwhile, the operator API \
         is the surface that reaches it."
    )
}

/// Whether `--store` names a database rather than a file.
///
/// The two schemes `libpq` accepts, and nothing else. A prefix test rather than
/// a URL parse because the alternative treats every path containing `://` as a
/// connection string and every malformed URL as a filename.
fn is_connection_string(spec: &str) -> bool {
    spec.starts_with("postgres://") || spec.starts_with("postgresql://")
}

/// Read and validate the manifests, for every verb.
///
/// A manifest that does not validate is not a thing to run, digest, or reason
/// about — and in a multi-document file every document is held to that, because
/// deploying two thirds of a room is worse than deploying none of it.
/// Judge one value with a manifest's content rules, through the evaluator the
/// runtime uses.
///
/// Exit 1 when a rule would refuse it. Names rules and pointers, never what
/// matched. A declared check is reported as not evaluable here: it needs the
/// checker, and the checker is the deployment's.
fn content_check_verb(a: &ContentCheckArgs) -> Result<ExitCode, Fault> {
    use agentplane::content::At;
    use std::io::Read as _;

    let at = match a.at.split_once(':') {
        None if a.at == "admission" => At::Admission,
        Some(("source", kind)) => At::Source(kind),
        Some(("sink", kind)) => At::Sink(kind),
        _ => {
            return Err(usage(format!(
                "--at '{}': use admission, source:<kind> or sink:<kind>",
                a.at
            )));
        }
    };
    let manifests = manifests_at(&a.manifest).map_err(usage)?;
    let [manifest] = manifests.as_slice() else {
        return Err(usage(format!(
            "{} holds {} agents; content check reads one",
            a.manifest,
            manifests.len()
        )));
    };
    let text = if let Some(path) = &a.value {
        std::fs::read_to_string(path).map_err(|e| usage(format!("reading {path}: {e}")))?
    } else {
        let mut text = String::new();
        std::io::stdin()
            .read_to_string(&mut text)
            .map_err(|e| usage(format!("reading standard input: {e}")))?;
        text
    };
    let value: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| usage(format!("the value is not JSON: {e}")))?;
    let Some(content) = manifest.spec.security.content.as_ref() else {
        println!("{}", serde_json::json!({ "evaluated": [] }));
        return Ok(ExitCode::SUCCESS);
    };
    let outcome = content.rules().map_err(usage)?.at(at, &value);
    let hits = |hits: &[agentplane::content::Hit]| {
        hits.iter()
            .map(|h| serde_json::json!({ "rule": h.rule, "pointer": h.pointer }))
            .collect::<Vec<_>>()
    };
    let not_evaluable: Vec<&str> = content.checks_at(at).map(|c| c.id.as_str()).collect();
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "evaluated": outcome.evaluated,
            "refused": hits(&outcome.refused),
            "redacted": hits(&outcome.redactions),
            "classified": outcome.classified,
            "sensitivity": outcome.sensitivity,
            "checks_not_evaluable": not_evaluable,
        }))
        .map_err(|e| e.to_string())?
    );
    Ok(if outcome.refused.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(exit::FINDING)
    })
}

fn manifests_at(path: &str) -> Result<Vec<Manifest>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("reading {path}: {e}"))?;
    Manifest::parse_all(&text).map_err(|e| e.to_string())
}

/// Print the identity a registry pins, per agent.
fn digest_verb(a: &DigestArgs) -> Result<ExitCode, Fault> {
    let manifests = manifests_at(&a.manifest).map_err(usage)?;
    // One document prints the bare digest, so scripts that pin a single
    // agent keep working; a room prints one line per agent, because a
    // bundle digest would make one agent's edit move its neighbours'
    // identities.
    if a.out.json {
        let rows = manifests
            .iter()
            .map(|m| {
                Ok(serde_json::json!({
                    "name": m.metadata.name,
                    "version": m.metadata.version,
                    "digest": m.digest().map_err(|e| e.to_string())?.to_hex(),
                }))
            })
            .collect::<Result<Vec<_>, String>>()?;
        println!("{}", serde_json::json!({ "digests": rows }));
    } else if let [only] = manifests.as_slice() {
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

fn dispatch(cli: Cli) -> Result<ExitCode, Fault> {
    match cli.verb {
        Verb::Validate(a) => validate(&a),
        Verb::Schema => {
            // The parser stays authoritative: the schema is the format's
            // *shape*, and the semantic refusals run only in `validate`. The
            // document says so itself, so a copy pasted into a repo carries
            // the caveat along.
            let schema = Manifest::json_schema();
            println!(
                "{}",
                serde_json::to_string_pretty(&schema).expect("a generated schema serializes")
            );
            Ok(ExitCode::SUCCESS)
        }
        Verb::Openapi => openapi_verb(),
        Verb::Digest(a) => digest_verb(&a),
        Verb::Audit(a) => journal_verb(&a.store, Some(&a), false),
        Verb::Export(a) if !a.cases.is_empty() || !a.runs.is_empty() => disclose_verb(&a),
        Verb::Export(a) => journal_verb(&a.store, None, a.allow_partial),
        Verb::Disclosures(a) => disclosures_verb(&a),
        Verb::Drill(a) => drill_verb(&a),
        Verb::ForgetAdmissions(a) => forget_admissions_verb(&a),
        Verb::Retention(RetentionArgs {
            act: RetentionAct::Plan(a),
        }) => retention_plan_verb(&a),
        Verb::Halt(a) => halt_verb(&a),
        Verb::Hold(a) => hold_verb(&a),
        Verb::Reconcile(a) => reconcile_verb(&a),
        Verb::Quarantine(a) => quarantine_verb(&a),
        Verb::Tasks(a) => tasks_verb(&a),
        Verb::Decide(a) => decide_verb(&a),
        Verb::Init(a) => init_verb(&a),
        Verb::Acknowledge(a) => acknowledge_verb(&a),
        #[cfg(feature = "push")]
        Verb::Rearm(a) => rearm_verb(&a),
        Verb::Cancel(a) => cancel_verb(&a),
        Verb::History(a) => history_verb(&a),
        #[cfg(feature = "dev")]
        Verb::Dev(a) => dev_verb(&a),
        Verb::Waiting(a) => waiting_verb(&a),
        Verb::Attention(a) => attention_verb(&a),
        Verb::Restore(a) => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| format!("could not start the async runtime: {e}"))?;
            rt.block_on(async {
                let open = || {
                    std::fs::File::open(&a.file)
                        .map(std::io::BufReader::new)
                        .map_err(|e| format!("reading {}: {e}", a.file))
                };
                if let Some(why) = restore_unverifiable(open()?) {
                    eprintln!("restore: {why}");
                    return Ok(ExitCode::from(exit::UNVERIFIABLE));
                }
                let backend = a.at.open().await?;
                let store = backend.journal();
                let cases = backend.cases();
                let file = open()?;
                let report = agentplane::export::from_jsonl(&store, Some(&cases), file)
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
                    ExitCode::from(exit::FINDING)
                })
            })
        }
        Verb::Verify(a) => verify_verb(&a),
        Verb::Bind(a) => bind_verb(&a),
        Verb::Policy(PolicyArgs {
            act: PolicyAct::Check(a),
        }) => policy_check_verb(&a),
        Verb::Content(ContentArgs {
            act: ContentAct::Check(a),
        }) => content_check_verb(&a),
        Verb::Grants(a) => grants_verb(&a),
        Verb::Subject(a) => subject_verb(&a),
        Verb::Run(a) => {
            let manifests = manifests_at(&a.manifest).map_err(usage)?;
            execute(&manifests, &a)
        }
        Verb::Replay(a) => {
            let manifests = manifests_at(&a.manifest).map_err(usage)?;
            replay(&manifests, &a)
        }
        Verb::Card(a) => card(&a),
        Verb::Serve(a) => {
            let manifests = manifests_at(&a.manifest).map_err(usage)?;
            serve(&manifests, &a)
        }
    }
}

/// The starter a single-completion agent begins from.
///
/// Every line is one the parser accepts and the schema describes, and the
/// budget is stated: the format refuses a document that leaves spend unbounded
/// by omission, so a starter without one would fail the first `validate`.
const STARTER: &str = r#"# yaml-language-server: $schema=https://hupe1980.github.io/agentplane/agent.schema.json
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: NAME, version: "0.1.0" }
spec:
  execution: { kind: completion }
  identity:
    role: "Summarise the input in one sentence"
    constraints: "No speculation."
  capabilities: { provides: [NAME] }
  models:
    # No key yet? `provider: fake` answers with a value of the output schema.
    privileged: { provider: anthropic, model: claude-sonnet-5 }
  output:
    schema:
      type: object
      additionalProperties: false
      required: [summary]
      properties: { summary: { type: string } }
  budgets: { max_tokens: 20000, max_steps: 4 }
"#;

/// The starter a tool-calling agent begins from.
///
/// The grant names a server; which process serves it is `--mcp` on the command
/// line, so moving the agent between machines does not change its digest.
const STARTER_TOOLS: &str = r#"# yaml-language-server: $schema=https://hupe1980.github.io/agentplane/agent.schema.json
#
#   agentplane run FILE --input '{"ticket": "T-1"}' \
#     --mcp "tickets=python3 examples/mcp-server.py"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: NAME, version: "0.1.0" }
spec:
  execution: { kind: tool-calling, max_turns: 4 }
  identity:
    role: "Answer a support question using the ticket tool"
    constraints: "One sentence. Cite the ticket id."
  capabilities: { provides: [NAME] }
  models:
    # No key yet? `provider: fake` answers with a value of the output schema.
    privileged: { provider: anthropic, model: claude-sonnet-5 }
  tools:
    - ref: "tool://tickets/read"
      mutates: false
      description: "Read a ticket by id"
      arguments:
        type: object
        additionalProperties: false
        required: [id]
        properties: { id: { type: string } }
  budgets: { max_tokens: 20000, max_steps: 8 }
"#;

/// Write a starter manifest, and prove it parses before saying so.
///
/// Refuses to overwrite: a starter is a first file, and replacing a reviewed
/// one with it is the kind of mistake nothing downstream would notice.
fn init_verb(opts: &InitArgs) -> Result<ExitCode, Fault> {
    if let Some(dir) = &opts.serve {
        return init_serve_verb(dir, opts.out);
    }
    let template = if opts.tools { STARTER_TOOLS } else { STARTER };
    let text = template
        .replace("NAME", &opts.name)
        .replace("FILE", &opts.path);
    // Parsed before it is written, so a name the format refuses is a message
    // here rather than a file that fails its first `validate`.
    let parsed =
        Manifest::parse_all(&text).map_err(|e| usage(format!("--name {}: {e}", opts.name)))?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&opts.path)
        .map_err(|e| format!("writing {}: {e}", opts.path))?;
    std::io::Write::write_all(&mut file, text.as_bytes())
        .map_err(|e| format!("writing {}: {e}", opts.path))?;
    let digest = parsed
        .first()
        .map(|m| m.digest().map(agentplane::Digest::to_hex))
        .transpose()
        .map_err(|e| e.to_string())?
        .unwrap_or_default();
    if opts.out.json {
        println!(
            "{}",
            serde_json::json!({ "wrote": opts.path, "digest": digest })
        );
    } else {
        println!("wrote {} ({digest})", opts.path);
    }
    eprintln!(
        "next:\n  agentplane validate {path}\n  agentplane run {path} --input '{{}}'{mcp}",
        path = opts.path,
        mcp = if opts.tools {
            " --mcp \"tickets=<command>\""
        } else {
            ""
        }
    );
    Ok(ExitCode::SUCCESS)
}

/// The files `init --serve` writes, in the order it reports them.
const SERVED_FILES: [&str; 7] = [
    "agent.yaml",
    "policy.cedar",
    "tokens.yaml",
    "framework.token",
    "postgres.password",
    "store.env",
    "compose.yaml",
];

/// The served starter, embedded from the files CI brings up, so what an
/// adopter is handed and what is tested are one set of bytes.
#[cfg(all(feature = "a2a-server", feature = "cedar", feature = "mcp-server-http"))]
const SERVED_MANIFEST: &str = include_str!("../../examples/served-starter.yaml");
#[cfg(all(feature = "a2a-server", feature = "cedar", feature = "mcp-server-http"))]
const SERVED_POLICY: &str = include_str!("../../examples/serve-policy.cedar");
#[cfg(all(feature = "a2a-server", feature = "cedar", feature = "mcp-server-http"))]
const SERVED_COMPOSE: &str = include_str!("../../examples/compose.yaml");

/// What `init --serve` wrote: each path, and the manifest's digest.
#[cfg(all(feature = "a2a-server", feature = "cedar", feature = "mcp-server-http"))]
#[derive(Debug)]
struct Served {
    paths: Vec<String>,
    digest: String,
}

/// 32 bytes from the operating system's random source, as hex.
#[cfg(any(
    feature = "dev",
    all(feature = "a2a-server", feature = "cedar", feature = "mcp-server-http")
))]
fn fresh_token() -> Result<String, Fault> {
    use rand::TryRng as _;
    let mut bytes = [0_u8; agentplane::api::tokens::MIN_TOKEN_BYTES];
    rand::rngs::SysRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| format!("the operating system's random source failed: {e}"))?;
    Ok(bytes.iter().fold(String::new(), |mut hex, b| {
        let _ = std::fmt::Write::write_fmt(&mut hex, format_args!("{b:02x}"));
        hex
    }))
}

/// The files one `init --serve` has created, removed again unless it finishes.
///
/// Each is opened `create_new`, so every path here is one this call made; a
/// failure partway leaves the directory as it was and a re-run is not refused
/// over the files of the attempt that failed.
#[cfg(all(feature = "a2a-server", feature = "cedar", feature = "mcp-server-http"))]
#[derive(Default)]
struct Written {
    paths: Vec<std::path::PathBuf>,
    kept: bool,
}

#[cfg(all(feature = "a2a-server", feature = "cedar", feature = "mcp-server-http"))]
impl Written {
    /// Create `dir/name` holding `text`, mode 0600 when `secret`.
    fn create(
        &mut self,
        dir: &std::path::Path,
        name: &str,
        text: &str,
        secret: bool,
    ) -> Result<(), Fault> {
        let path = dir.join(name);
        let mut open = std::fs::OpenOptions::new();
        open.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            open.mode(if secret { 0o600 } else { 0o644 });
        }
        #[cfg(not(unix))]
        let _ = secret;
        let mut file = open
            .open(&path)
            .map_err(|e| format!("writing {}: {e}", path.display()))?;
        self.paths.push(path.clone());
        std::io::Write::write_all(&mut file, text.as_bytes())
            .map_err(|e| format!("writing {}: {e}", path.display()).into())
    }

    /// Keep every file, and report their paths.
    fn keep(mut self) -> Vec<String> {
        self.kept = true;
        self.paths.iter().map(|p| p.display().to_string()).collect()
    }
}

#[cfg(all(feature = "a2a-server", feature = "cedar", feature = "mcp-server-http"))]
impl Drop for Written {
    fn drop(&mut self) {
        if !self.kept {
            for path in &self.paths {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

/// The compose `user:` the plane runs as: the owner of the token file it reads.
///
/// The file is mode 0600, so only its owner can read it. Root is refused: a
/// plane started under `sudo` would run its container as root.
#[cfg(all(feature = "a2a-server", feature = "cedar", feature = "mcp-server-http"))]
fn plane_user(uid: u32, gid: u32) -> Result<String, Fault> {
    if uid == 0 {
        return Err(usage(
            "init --serve ran as root, so the token file is root's and the plane would run \
             as root to read it; run it as the user the plane should run as (in a container, \
             `docker run --user \"$(id -u):$(id -g)\"`), so nothing was written",
        ));
    }
    Ok(format!("{uid}:{gid}"))
}

/// Write the served starter into `dir`, every file checked by the loader that
/// will read it before any is written.
///
/// Refuses before generating anything when any target exists: a token file
/// replaced under a running plane locks out every caller holding the old one,
/// and half a starter written over a reviewed directory is a mistake nothing
/// downstream notices. A failure after the first file is written removes what
/// this call wrote.
#[cfg(all(feature = "a2a-server", feature = "cedar", feature = "mcp-server-http"))]
fn init_serve(dir: &std::path::Path) -> Result<Served, Fault> {
    std::fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    if let Some(existing) = SERVED_FILES
        .iter()
        .find(|name| dir.join(name).symlink_metadata().is_ok())
    {
        return Err(usage(format!(
            "{} exists; init --serve writes nothing over a file, so nothing was written",
            dir.join(existing).display()
        )));
    }

    let [peer, framework, operator] = [fresh_token()?, fresh_token()?, fresh_token()?];
    let tokens = format!(
        "# The callers this plane accepts, generated by `agentplane init --serve`.\n\
         # Keep this file secret; `serve` reads it from a mounted file, never from\n\
         # the environment. Roles are inputs to policy.cedar, not grants.\n\
         - token: \"{peer}\"\n  actor: peer-1\n  roles: [peer]\n\n\
         - token: \"{framework}\"\n  actor: framework-1\n  roles: [framework]\n\n\
         - token: \"{operator}\"\n  actor: ops-1\n  roles: [operator]\n"
    );
    let password = fresh_token()?;
    let store = format!(
        "# The plane's journal, read by `serve` as AGENTPLANE_STORE. Keep this file\n\
         # secret: it holds the Postgres password.\n\
         AGENTPLANE_STORE=postgres://agentplane:{password}@postgres:5432/agentplane?sslmode=disable\n"
    );

    let parsed = Manifest::parse_all(SERVED_MANIFEST)
        .map_err(|e| format!("the served starter does not parse: {e}"))?;
    agentplane::policy::CedarEngine::from_bundle(SERVED_POLICY, None, None)
        .map_err(|e| format!("the shipped policy was refused: {e}"))?;
    agentplane::api::tokens::TokenAuthenticator::from_yaml(&tokens)
        .map_err(|e| format!("the generated tokens were refused: {e}"))?;
    let digest = parsed
        .first()
        .map(|m| m.digest().map(agentplane::Digest::to_hex))
        .transpose()
        .map_err(|e| e.to_string())?
        .unwrap_or_default();

    let mut written = Written::default();
    written.create(dir, SERVED_FILES[0], SERVED_MANIFEST, false)?;
    written.create(dir, SERVED_FILES[1], SERVED_POLICY, false)?;
    written.create(dir, SERVED_FILES[2], &tokens, true)?;
    written.create(dir, SERVED_FILES[3], &framework, true)?;
    written.create(dir, SERVED_FILES[4], &format!("{password}\n"), true)?;
    written.create(dir, SERVED_FILES[5], &store, true)?;

    #[cfg(unix)]
    let owner = {
        use std::os::unix::fs::MetadataExt as _;
        let token_file = dir.join(SERVED_FILES[2]);
        let meta = std::fs::metadata(&token_file)
            .map_err(|e| format!("reading {}: {e}", token_file.display()))?;
        plane_user(meta.uid(), meta.gid())?
    };
    #[cfg(not(unix))]
    let owner = "65532:65532".to_owned();
    let compose = SERVED_COMPOSE
        .replace("AGENTPLANE_VERSION", env!("CARGO_PKG_VERSION"))
        .replace("PLANE_USER", &owner);
    written.create(dir, SERVED_FILES[6], &compose, false)?;
    Ok(Served {
        paths: written.keep(),
        digest,
    })
}

/// What `init --serve` prints on stdout: paths and the digest, never a token.
#[cfg(all(feature = "a2a-server", feature = "cedar", feature = "mcp-server-http"))]
fn served_report(served: &Served, json: bool) -> String {
    if json {
        return serde_json::json!({ "wrote": served.paths, "digest": served.digest }).to_string();
    }
    let mut out = String::new();
    for (index, path) in served.paths.iter().enumerate() {
        out.push_str("wrote ");
        out.push_str(path);
        if index == 0 {
            let _ = std::fmt::Write::write_fmt(&mut out, format_args!(" ({})", served.digest));
        }
        out.push('\n');
    }
    out
}

/// `init --serve`: the served starter, and the two commands after it.
#[cfg(all(feature = "a2a-server", feature = "cedar", feature = "mcp-server-http"))]
fn init_serve_verb(dir: &str, out: JsonFlag) -> Result<ExitCode, Fault> {
    let served = init_serve(std::path::Path::new(dir))?;
    print!("{}", served_report(&served, out.json));
    if out.json {
        println!();
    }
    eprintln!(
        "next:\n  docker compose -f {dir}/compose.yaml up --wait\n  \
         then a framework quickstart: \
         https://hupe1980.github.io/agentplane/docs/getting-started/#zero-to-governed"
    );
    Ok(ExitCode::SUCCESS)
}

/// The `--url` the Agent Card publishes, refused unless it ends in `/a2a`.
///
/// The card carries the URL verbatim and a client follows it, while the plane
/// serves A2A at `/a2a` only; a bare host would publish an endpoint that answers
/// every client with `404`.
#[cfg(all(feature = "a2a-server", feature = "cedar"))]
fn a2a_endpoint(url: &str) -> Result<&str, Fault> {
    if url.ends_with("/a2a") {
        return Ok(url);
    }
    let base = url.trim_end_matches('/');
    let fix = if base.ends_with("/a2a") {
        base.to_owned()
    } else {
        format!("{base}/a2a")
    };
    Err(usage(format!(
        "--url {url} does not end in /a2a: the Agent Card publishes it verbatim and this \
         plane serves A2A at /a2a only, so a client following the card would be answered \
         404. Pass --url {fix}"
    )))
}

/// `init --serve` in a build that cannot serve what it would write.
#[cfg(not(all(feature = "a2a-server", feature = "cedar", feature = "mcp-server-http")))]
#[allow(clippy::unnecessary_wraps)]
fn init_serve_verb(_dir: &str, _out: JsonFlag) -> Result<ExitCode, Fault> {
    Err(usage(format!(
        "this build cannot write a served plane: `init --serve` writes for `serve --mcp-addr`, \
         which needs the `a2a-server`, `cedar` and `mcp-server-http` features. Use the \
         `:full` container image, or reinstall with `--features \
         cli,a2a-server,cedar,mcp-server-http`; it would have written {}",
        SERVED_FILES.join(", ")
    )))
}

/// Read a checkpoint an auditor was handed, in either form they hold it in.
///
/// Two forms because two things produce one: `audit` prints JSON, and a
/// witness cosigns a `tlog-checkpoint` note. Requiring a conversion between
/// them would put a step between the auditor and the check, and the steps
/// between an auditor and a check are what this crate keeps removing.
fn read_checkpoint(
    path: &str,
) -> Result<
    (
        agentplane::journal::Checkpoint,
        Option<agentplane::journal::SignedNote>,
    ),
    String,
> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("reading --checkpoint {path}: {e}"))?;
    // The note first: it is the form that travels, and it is unambiguous —
    // JSON never parses as three newline-terminated lines.
    if let Ok(cp) = agentplane::journal::Checkpoint::from_note(&text) {
        return Ok((cp, None));
    }
    // A signed note carries the checkpoint as its body, and its lines are the
    // cosignatures a `--witness-key` checks.
    if let Ok(note) = agentplane::journal::SignedNote::parse(&text)
        && let Ok(cp) = agentplane::journal::Checkpoint::from_note(&note.text)
    {
        return Ok((cp, Some(note)));
    }
    serde_json::from_str(&text)
        .map(|cp| (cp, None))
        .map_err(|e| {
            format!(
                "--checkpoint {path} is neither a tlog-checkpoint note nor the `current` \
                 field of an audit report: {e}"
            )
        })
}

/// The anchor a `--checkpoint` file gives, and who cosigned it.
struct FileAnchor {
    anchor: agentplane::audit::Anchor,
    /// `<path>:<witness name>` per cosignature that verified.
    cosigned_by: Vec<String>,
    /// Whether the file is a signed note, which a `--witness-key` checks.
    signed_note: bool,
}

/// Read a `--checkpoint` file. A signed note's lines are checked under
/// `witness_keys`, through the rule a witness fetch uses, and each one that
/// verifies contributes its signed time; any other file carries no signature
/// to check.
fn checkpoint_anchor(path: &str, keys: &[String]) -> Result<FileAnchor, String> {
    let (checkpoint, note) = read_checkpoint(path)?;
    let from = format!("file {path}");
    let signed_note = note.is_some();
    let Some(note) = note.filter(|_| !keys.is_empty()) else {
        return Ok(FileAnchor {
            anchor: agentplane::audit::Anchor::new(checkpoint, from),
            cosigned_by: Vec::new(),
            signed_note,
        });
    };
    let trusted = witness_keys(keys)?;
    let cosignatures = agentplane::journal::cosignatures_in(&note, &trusted);
    let cosigned_by = cosignatures
        .iter()
        .map(|c| format!("{path}:{}", c.key_id))
        .collect();
    let anchor = if cosignatures.is_empty() {
        agentplane::audit::Anchor::new(checkpoint, from)
    } else {
        agentplane::audit::Anchor::from_cosigned(
            &agentplane::journal::CosignedCheckpoint {
                checkpoint,
                cosignatures,
            },
            from,
        )
    };
    Ok(FileAnchor {
        anchor,
        cosigned_by,
        signed_note,
    })
}

/// `verify`: recompute an export from its own bytes, against a checkpoint from
/// somewhere else.
/// The files a policy bundle directory holds, and nothing else.
#[cfg(feature = "cedar")]
const BUNDLE_FILES: [&str; 3] = ["policy.cedar", "schema.json", "entities.json"];

/// Load a Cedar policy bundle: one rules file, or a directory of rules,
/// schema and static entities.
///
/// The one loader, for `serve --policy` and `policy check --bundle` alike, so a
/// checked bundle is byte for byte the served one and its digest is the one a
/// served run records. A directory holding any other file is refused rather
/// than read around: a rule in a file the loader skipped is a rule the bundle
/// identity does not cover, and an author would believe it checked.
#[cfg(feature = "cedar")]
fn load_policy_bundle(path: &str) -> Result<agentplane::policy::CedarEngine, Fault> {
    let at = std::path::Path::new(path);
    let meta =
        std::fs::metadata(at).map_err(|e| format!("reading the policy bundle {path}: {e}"))?;
    let read = |file: &std::path::Path| {
        std::fs::read_to_string(file).map_err(|e| format!("reading {}: {e}", file.display()))
    };
    let (rules, schema, entities) = if meta.is_dir() {
        let entries = std::fs::read_dir(at).map_err(|e| format!("reading {path}: {e}"))?;
        for entry in entries {
            let name = entry
                .map_err(|e| format!("reading {path}: {e}"))?
                .file_name()
                .to_string_lossy()
                .into_owned();
            if !name.starts_with('.') && !BUNDLE_FILES.contains(&name.as_str()) {
                return Err(usage(format!(
                    "the policy bundle {path} holds `{name}`, which no bundle reads: a bundle \
                     directory holds {} and nothing else, so a rule cannot sit in a file \
                     the bundle's identity does not cover",
                    BUNDLE_FILES.join(", ")
                )));
            }
        }
        let rules = at.join(BUNDLE_FILES[0]);
        if !rules.is_file() {
            return Err(usage(format!(
                "the policy bundle {path} has no {}",
                BUNDLE_FILES[0]
            )));
        }
        let optional = |name: &str| {
            let file = at.join(name);
            if file.is_file() {
                read(&file).map(Some)
            } else {
                Ok(None)
            }
        };
        (
            read(&rules)?,
            optional(BUNDLE_FILES[1])?,
            optional(BUNDLE_FILES[2])?,
        )
    } else {
        (read(at)?, None, None)
    };
    agentplane::policy::CedarEngine::from_bundle(&rules, schema.as_deref(), entities.as_deref())
        .map_err(|e| usage(format!("the policy bundle {path} was refused: {e}")))
}

/// `policy check`: an export's gated requests, rebuilt and evaluated offline.
#[cfg(feature = "cedar")]
fn policy_check_verb(opts: &PolicyCheckArgs) -> Result<ExitCode, Fault> {
    use agentplane::policy::check::{Check, CheckError, TenantSource, Verdict};

    let bundle = load_policy_bundle(&opts.bundle)?;
    let candidate = opts
        .candidate
        .as_deref()
        .map(load_policy_bundle)
        .transpose()?;
    let (tenant, source) = match &opts.tenant {
        Some(name) => (
            agentplane::core::TenantId::new(name).map_err(|e| usage(format!("--tenant: {e}")))?,
            TenantSource::Supplied,
        ),
        None => (agentplane::core::TenantId::default(), TenantSource::Default),
    };
    let check = Check::new(tenant.as_str(), source);
    let candidate = candidate
        .as_ref()
        .map(|c| c as &dyn agentplane::core::PolicyEngine);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the async runtime: {e}"))?;
    let report = if opts.from == "-" {
        rt.block_on(check.run(std::io::stdin().lock(), &bundle, candidate))
    } else {
        let file =
            std::fs::File::open(&opts.from).map_err(|e| format!("reading {}: {e}", opts.from))?;
        rt.block_on(check.run(std::io::BufReader::new(file), &bundle, candidate))
    }
    .map_err(|e| match e {
        CheckError::NotAnExport(_) => usage(format!("{}: {e}", opts.from)),
        CheckError::Io(_) | CheckError::Keys(_) => Fault::Operational(e.to_string()),
    })?;

    if opts.out.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    } else {
        print!("{}", policy_report_text(&report));
    }
    Ok(match report.verdict() {
        Verdict::Clean => ExitCode::SUCCESS,
        Verdict::Findings => ExitCode::from(exit::FINDING),
        Verdict::Partial => ExitCode::from(exit::PARTIAL),
    })
}

/// The report, for a person.
#[cfg(feature = "cedar")]
fn policy_report_text(report: &agentplane::policy::check::Report) -> String {
    use agentplane::policy::check::{Finding, Mode};
    use std::fmt::Write as _;

    let line = |f: &Finding| {
        let mut at = String::new();
        if let Some(step) = f.step {
            let _ = write!(at, "step {step} ");
        }
        if let Some(key) = f.effect_key {
            let _ = write!(at, "effect {} ", key.to_hex());
        }
        format!("{at}{} on {}: {}", f.action, f.resource, f.reason)
    };
    let mut out = String::new();
    let _ = write!(out, "bundle {}", report.bundle.to_hex());
    if let Some(candidate) = report.candidate {
        let _ = write!(out, ", candidate {}", candidate.to_hex());
    }
    let _ = writeln!(
        out,
        "; tenant {} ({})",
        report.tenant.value,
        match report.tenant.source {
            agentplane::policy::check::TenantSource::Supplied => "supplied",
            agentplane::policy::check::TenantSource::Default => "assumed: none was supplied",
        }
    );
    for run in &report.runs {
        match run.mode {
            Mode::Recorded => {
                let _ = writeln!(
                    out,
                    "run {}: {} evaluated, {} finding(s)",
                    run.run,
                    run.evaluated,
                    run.findings.len()
                );
            }
            Mode::Mismatch => {
                let _ = writeln!(
                    out,
                    "run {}: recorded bundle {} is not the one supplied — not evaluated",
                    run.run,
                    run.recorded_bundle
                        .map(agentplane::core::Digest::to_hex)
                        .unwrap_or_default()
                );
            }
            Mode::Ungoverned => {
                let _ = writeln!(
                    out,
                    "run {}: ungoverned — no bundle is on its record, so no gate ran",
                    run.run
                );
            }
        }
        for f in &run.findings {
            let _ = writeln!(out, "  finding: {}", line(f));
        }
        if let Some(diff) = &run.diff {
            for f in &diff.newly_denied {
                let _ = writeln!(out, "  newly denied: {}", line(f));
            }
            for f in &diff.malformed_under_candidate {
                let _ = writeln!(out, "  malformed under candidate: {}", line(f));
            }
        }
        let mut reasons = std::collections::BTreeMap::new();
        for n in &run.not_evaluable {
            *reasons.entry(n.reason).or_insert(0usize) += 1;
        }
        for (reason, count) in reasons {
            let _ = writeln!(
                out,
                "  not evaluable: {count} {}",
                serde_json::to_value(reason)
                    .ok()
                    .and_then(|v| v.as_str().map(ToOwned::to_owned))
                    .unwrap_or_default()
            );
        }
    }
    for run in &report.unreadable {
        let _ = writeln!(out, "run {run}: the export could not read it");
    }
    let _ = writeln!(out, "not in any export: {}", report.outside_export);
    out
}

fn verify_verb(opts: &VerifyArgs) -> Result<ExitCode, Fault> {
    let verifier = verifier_from(&opts.key).map_err(usage)?;
    let saved = match &opts.checkpoint {
        Some(path) => Some(checkpoint_anchor(path, &opts.witness_key).map_err(usage)?),
        None => None,
    };
    let note_checked = saved.as_ref().is_some_and(|file| file.signed_note);
    // The origin an export is *supposed* to be of. Read from the file would
    // defeat the purpose — the header is written by whoever wrote the file —
    // so `--origin` is required to fetch an anchor here, where `audit` can ask
    // its own store. `verify` runs against a file the auditor was handed, and
    // the name of the log is the one thing they have to know already.
    let fetched = match (&opts.origin, opts.witness.is_empty()) {
        (Some(origin), false) => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| format!("could not start the async runtime: {e}"))?;
            rt.block_on(anchor_from_witnesses(
                &opts.witness,
                &opts.witness_key,
                origin,
            ))
            .map_err(usage)?
        }
        (None, false) => {
            return Err(usage(
                "--witness needs --origin: the log's name cannot come from the file being \
                 checked, because that header is written by whoever wrote the file"
                    .to_owned(),
            ));
        }
        // No witness named. A `--witness-key` with neither a witness nor a
        // signed-note checkpoint to use it against is a refusal rather than a
        // flag that did nothing.
        (_, true) => {
            if !opts.witness_key.is_empty() && !note_checked {
                return Err(usage(
                    "--witness-key was given with no --witness and no signed-note \
                     --checkpoint to use it against"
                        .to_owned(),
                ));
            }
            Anchor::default()
        }
    };
    // The same rule `audit` applies, for the same reason: the file is held to
    // every observation the reader could obtain, and each says how it was
    // obtained.
    let mut anchor = fetched;
    if let Some(saved) = saved {
        anchor.checkpoints.push(saved.anchor);
        anchor.cosigned_by.extend(saved.cosigned_by);
    }
    let verifier = verifier
        .as_ref()
        .map(|v| v as &dyn agentplane::core::Verifier);
    if opts.grader_verdict.is_empty() && !opts.grader_key.is_empty() {
        return Err(usage(
            "--grader-key was given with no --grader-verdict to use it against".to_owned(),
        ));
    }
    let graders =
        verifier_from(&opts.grader_key).map_err(|e| usage(e.replace("--key", "--grader-key")))?;
    let sidecars = opts
        .grader_verdict
        .iter()
        .map(|path| std::fs::read(path).map_err(|e| format!("reading {path}: {e}")))
        .collect::<Result<Vec<_>, _>>()?;
    let input: Box<dyn std::io::BufRead> = if opts.file == "-" {
        Box::new(std::io::stdin().lock())
    } else {
        let file =
            std::fs::File::open(&opts.file).map_err(|e| format!("reading {}: {e}", opts.file))?;
        Box::new(std::io::BufReader::new(file))
    };
    let checked = agentplane::grader_verdict::check(
        input,
        verifier,
        &anchor.checkpoints,
        &sidecars,
        graders
            .as_ref()
            .map(|v| v as &dyn agentplane::core::Verifier),
    )
    .map_err(|e| e.to_string())?;
    let report = &checked.export;
    println!(
        "{}",
        serde_json::to_string_pretty(&VerifyDocument {
            anchor: &anchor,
            report,
            grader_verdicts: &checked.sidecars,
        })
        .map_err(|e| e.to_string())?
    );
    if checked.any_refused() {
        return Ok(ExitCode::from(exit::FINDING));
    }
    // Findings fail; `not_checked` does not. A pass with no key — or with no
    // checkpoint — has established less, and saying so is different from
    // failing.
    // A split view fails here too. Only a caller that asked more than one
    // witness can see it, so neither the library's report nor the file can.
    Ok(verify_status(report, anchor.split_view.is_empty()))
}

/// The selection `--case` and `--run` name, refused as usage when an id does
/// not parse.
fn selection_of(cases: &[String], runs: &[String]) -> Result<agentplane::export::Selection, Fault> {
    Ok(agentplane::export::Selection {
        cases: cases
            .iter()
            .map(|c| {
                agentplane::core::CaseId::parse(c).map_err(|e| usage(format!("--case {c}: {e}")))
            })
            .collect::<Result<_, _>>()?,
        runs: runs
            .iter()
            .map(|r| {
                agentplane::core::RunId::parse(r).map_err(|e| usage(format!("--run {r}: {e}")))
            })
            .collect::<Result<_, _>>()?,
    })
}

/// The sentence every surface naming a disclosure carries.
const REGISTER_RUNG: &str = "read from the operator's disclosure register — an unchained row \
     whoever administers the store can edit or delete, so an empty list does not show that \
     nothing left the plane";

/// Write a disclosure package of one matter, recording the act first.
fn disclose_verb(opts: &ExportArgs) -> Result<ExitCode, Fault> {
    let selection = selection_of(&opts.cases, &opts.runs)?;
    let Some(to) = opts.to.as_deref().filter(|t| !t.trim().is_empty()) else {
        return Err(usage(
            "--to is required to disclose: an erasure names a copy by who received it".to_owned(),
        ));
    };
    let Some(actor) = opts.actor.as_deref() else {
        return Err(usage(
            "--actor is required to disclose: the register records who made the copy".to_owned(),
        ));
    };
    let by = agentplane::core::Operator::asserted(actor).map_err(|e| usage(e.to_string()))?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the async runtime: {e}"))?;
    rt.block_on(async {
        let backend = opts.store.at.open().await?;
        // Wall clock by design, as for a hold: when a copy left is a fact about
        // the outside world, not a journaled observation.
        #[allow(clippy::disallowed_methods)]
        let at = time::OffsetDateTime::now_utc();
        let request = agentplane::disclosure::Request {
            selection,
            recipient: to.to_owned(),
            by,
            at,
        };
        // Standard output gets the bytes only once the act is recorded, so they
        // are staged in a private directory first.
        let staging = match &opts.output {
            Some(_) => None,
            None => Some(private_dir()?),
        };
        let destination = staging.as_ref().map_or_else(
            || std::path::PathBuf::from(opts.output.as_deref().unwrap_or_default()),
            |dir| dir.join("package.jsonl"),
        );
        let disclosed = agentplane::disclosure::disclose(
            &backend.journal(),
            &backend.cases(),
            backend.disclosures().as_ref(),
            &request,
            &destination,
        )
        .await;
        let delivered = match disclosed {
            Ok(act) => {
                if staging.is_some() {
                    let bytes = std::fs::read(&destination).map_err(|e| e.to_string());
                    let written = bytes.and_then(|b| {
                        use std::io::Write as _;
                        std::io::stdout().lock().write_all(&b).map_err(|e| {
                            format!(
                                "disclosure {} is recorded and was not delivered: {e}",
                                act.id
                            )
                        })
                    });
                    written.map(|()| act).map_err(Fault::from)
                } else {
                    Ok(act)
                }
            }
            Err(agentplane::disclosure::DiscloseError::Write(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::InvalidInput
                ) =>
            {
                Err(usage(e.to_string()))
            }
            Err(e) => Err(Fault::from(e.to_string())),
        };
        if let Some(dir) = &staging {
            let _ = std::fs::remove_dir_all(dir);
        }
        let act = delivered?;
        eprintln!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "disclosure": act,
                "register": REGISTER_RUNG,
            }))
            .map_err(|e| e.to_string())?
        );
        Ok(ExitCode::SUCCESS)
    })
}

/// A directory only this user can read, for a package on its way to stdout.
fn private_dir() -> Result<std::path::PathBuf, Fault> {
    let dir = std::env::temp_dir().join(format!(
        "agentplane-disclosure-{}-{}",
        std::process::id(),
        agentplane::core::RunId::generate()
    ));
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder
        .create(&dir)
        .map_err(|e| format!("staging {}: {e}", dir.display()))?;
    Ok(dir)
}

/// List the disclosure register for a case or a run.
fn disclosures_verb(opts: &DisclosuresArgs) -> Result<ExitCode, Fault> {
    if opts.cases.is_empty() && opts.runs.is_empty() {
        return Err(usage("name a matter with --case or --run".to_owned()));
    }
    let selection = selection_of(&opts.cases, &opts.runs)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the async runtime: {e}"))?;
    rt.block_on(async {
        let acts = opts
            .at
            .open()
            .await?
            .disclosures()
            .disclosures(&selection.cases, &selection.runs)
            .await
            .map_err(|e| e.to_string())?;
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "disclosures": acts,
                "register": REGISTER_RUNG,
            }))
            .map_err(|e| e.to_string())?
        );
        Ok(ExitCode::SUCCESS)
    })
}

/// Write an unsigned grader-verdict sidecar and print the digest to sign.
///
/// The binary holds no grader key: the grader signs the printed digest with
/// its own tool and adds the `signature` member.
fn bind_verb(opts: &BindArgs) -> Result<ExitCode, Fault> {
    let run = agentplane::core::RunId::parse(&opts.run)
        .map_err(|e| usage(format!("--run {}: {e}", opts.run)))?;
    let content =
        std::fs::read(&opts.content).map_err(|e| format!("reading {}: {e}", opts.content))?;
    let input: Box<dyn std::io::BufRead> = if opts.export == "-" {
        Box::new(std::io::stdin().lock())
    } else {
        let file = std::fs::File::open(&opts.export)
            .map_err(|e| format!("reading {}: {e}", opts.export))?;
        Box::new(std::io::BufReader::new(file))
    };
    let sidecar = agentplane::grader_verdict::bind(input, run, opts.last_seq, content)
        .map_err(|e| e.to_string())?;
    let json = serde_json::to_string_pretty(&sidecar).map_err(|e| e.to_string())?;
    std::fs::write(&opts.out, json + "\n").map_err(|e| format!("writing {}: {e}", opts.out))?;
    println!("{}", sidecar.signing_digest().to_hex());
    Ok(ExitCode::SUCCESS)
}

/// Why `restore` cannot rebuild the export `input` holds, when its header names
/// a canon this build does not implement: checked before any store is opened.
fn restore_unverifiable(input: impl std::io::BufRead) -> Option<String> {
    let header = input.lines().next()?.ok()?;
    agentplane::export::foreign_canon(&header)
}

/// What `verify` exits with: a finding or a split view fails, and a file under
/// a canon this build does not implement is neither sound nor damaged — this
/// reader could not answer, which is its own status.
fn verify_status(report: &agentplane::export::VerifyReport, one_view: bool) -> ExitCode {
    ExitCode::from(if !report.findings.is_empty() || !one_view {
        exit::FINDING
    } else if report.unverifiable.is_some() {
        exit::UNVERIFIABLE
    } else if report.is_sound() {
        exit::OK
    } else {
        exit::FINDING
    })
}

/// Print the Agent Card a served manifest would advertise.
fn card(opts: &CardArgs) -> Result<ExitCode, Fault> {
    // One card, one agent — the same rule `serve` applies, because this verb
    // prints exactly what `serve` would advertise.
    let manifests = manifests_at(&opts.manifest).map_err(usage)?;
    let [manifest] = manifests.as_slice() else {
        return Err(usage(format!(
            "`card` describes one agent and this file holds {}. A2A's card \
             path is well-known and singular — split the file, or point this \
             at the document you would serve",
            manifests.len()
        )));
    };
    let card =
        agentplane::peers::AgentCard::derive(manifest, &opts.url).map_err(|e| e.to_string())?;
    println!(
        "{}",
        serde_json::to_string_pretty(&card).map_err(|e| e.to_string())?
    );
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    // `clap` prints its own diagnostics and exits; everything past the parse is
    // this binary's own vocabulary. Parsed before the subscriber is installed
    // because which verb this is decides what belongs in the output.
    let cli = <Cli as clap::Parser>::parse();
    let (metrics, format) = match &cli.verb {
        Verb::Serve(serve) => (true, serve.log_format),
        _ => (false, LogFormat::Text),
    };
    let verifying = matches!(&cli.verb, Verb::Replay(replay) if replay.strict);
    install_tracing(metrics, verifying, format);
    match dispatch(cli) {
        Ok(code) => code,
        Err(fault) => {
            eprintln!("agentplane: {fault}");
            ExitCode::from(fault.status())
        }
    }
}

impl RunArgs {
    fn read_input(&self) -> Result<serde_json::Value, String> {
        let text = match (&self.input, &self.input_file) {
            // `-` is stdin, the convention every pipe-shaped tool honours and
            // `verify` here already does. It belongs to `--input`, not
            // `--input-file`: a file literally named `-` is reachable as
            // `./-`, and a pipe is not reachable any other way.
            (Some(s), _) if s == "-" => {
                use std::io::Read as _;
                let mut text = String::new();
                std::io::stdin()
                    .read_to_string(&mut text)
                    .map_err(|e| format!("reading standard input: {e}"))?;
                text
            }
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
fn serve(manifests: &[Manifest], opts: &ServeArgs) -> Result<ExitCode, Fault> {
    use agentplane::api::a2a::A2aServer;
    use agentplane::api::tokens::TokenAuthenticator;

    let manifest = a2a_agent(manifests)?;
    refuse_mcp_listener(opts)?;

    let url = opts.url.as_deref().ok_or_else(|| {
        usage(
            "`serve` needs --url: the A2A endpoint callers reach this plane at, `/a2a` under \
         its public address. It goes on the Agent Card, so it is the public URL rather \
         than what you bind — an agent's declaration must not change when its address does",
        )
    })?;
    let url = a2a_endpoint(url)?;
    let policy_path = opts.policy.as_deref().ok_or_else(|| {
        usage(
            "`serve` needs --policy: a Cedar policy set. There is deliberately no default — \
         a permissive engine and no engine are the same behaviour, and only one of them \
         looks governed",
        )
    })?;
    let tokens_path = opts.tokens.as_deref().ok_or_else(|| {
        usage(
            "`serve` needs --tokens: bearer tokens naming the callers this plane accepts. \
         There is deliberately no default — a server that authenticates nobody has no \
         actor to record a decision against",
        )
    })?;

    let policy = load_policy_bundle(policy_path)?;
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
        let backend = opts.at.open().await?.ok_or_else(|| {
            usage(
                "`serve` needs --store: a served task's id is a promise that it can be \
             fetched again, and an in-memory journal breaks that promise at the next \
             restart. `run` may journal to memory because it exits with its answer",
            )
        })?;

        // **The whole plane, not a corner of it.** One store backs every store
        // this runtime has, and a server that wired only the journal and the
        // case layer would accept an agent that waits, sleeps or opens a human
        // task and then never make progress on any of them — a suspended run is
        // a row, and something has to come back for it.
        let mut builder = with_providers(backend.plane(), manifests).await?;
        for (name, client) in connect_mcp_servers(&opts.mcp, manifests).await? {
            builder = builder.tool_server(name, client);
        }
        if let Some((registry, client)) = connect_peers(&opts.peer, manifests).map_err(usage)? {
            builder = builder.peers(registry, client);
        }
        builder = builder.policy(Arc::new(policy) as Arc<dyn agentplane::core::PolicyEngine>);
        for m in manifests {
            builder = builder.agent(agentplane::runtime::Agent::new(m));
        }
        // The same handle `wire_push` gives the A2A server below. The plane
        // holds it because the registrations that stop being delivered are a
        // backlog, and the operator surface is where a backlog is answered —
        // the delivery worker that parked one has nothing more to say about it.
        if !opts.push_host.is_empty() {
            builder = builder.push(backend.push());
        }
        let builder = with_submission_witnesses(builder, opts).map_err(usage)?;
        let runtime = builder.try_build().map_err(|e| e.to_string())?;

        let mcp = mcp_surface(&runtime, Arc::clone(&auth), manifests, opts)?;
        let security = agentplane::peers::CardSecurity::bearer("bearer", Vec::<String>::new());
        let mut server = A2aServer::new(Arc::clone(&runtime), auth, &security, manifest, url)
            .map_err(|e| e.to_string())?;

        server = wire_push(server, &opts.push_host, &backend)?;
        serve_until_stopped(
            &runtime,
            server,
            mcp,
            operator_auth,
            opts,
            manifest,
            url,
            &backend,
        )
        .await?;
        Ok(ExitCode::SUCCESS)
    })
}

/// Serve until a supervisor says stop, then stop everything this process owns.
///
/// Split from `serve` because wiring a plane and running one are different jobs
/// with different failure modes, and because the shutdown order below is the
/// part worth reading on its own.
#[cfg(all(feature = "a2a-server", feature = "cedar"))]
#[allow(clippy::too_many_arguments)]
async fn serve_until_stopped(
    runtime: &Arc<Runtime>,
    server: agentplane::api::a2a::A2aServer,
    mcp: Option<McpSurface>,
    operator_auth: Arc<dyn agentplane::api::Authenticator>,
    opts: &ServeArgs,
    manifest: &Manifest,
    url: &str,
    backend: &Backend,
) -> Result<(), String> {
    let addr = opts.addr.as_str();
    // One signal, every listener. Raised by the signal watcher below, and
    // by `serve` itself returning for any other reason — a bind that dies
    // under a running plane must not leave the periodic passes sweeping a
    // store nothing is serving from.
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let mut background: Vec<Task> = Vec::new();
    if let Some(worker) = server.push_worker() {
        background.extend(spawn_push_worker(
            worker,
            opts.sweep_every.unwrap_or(DEFAULT_SWEEP_SECONDS),
            stop_rx.clone(),
        ));
    }

    background.extend(spawn_sweeper(
        runtime,
        opts.sweep_every.unwrap_or(DEFAULT_SWEEP_SECONDS),
        stop_rx.clone(),
    ));
    background.extend(spawn_drill(
        runtime,
        opts.drill_every.unwrap_or(0),
        stop_rx.clone(),
    ));

    if let Some(operator_addr) = opts.operator_addr.as_deref() {
        background.push(
            spawn_operator_surface(runtime, operator_auth, operator_addr, stop_rx.clone()).await?,
        );
    }
    if let Some(mcp) = mcp {
        background.push(spawn_mcp_surface(mcp, stop_rx.clone()).await?);
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
    // Which backend, never the connection string: a `postgres://` URL carries a
    // password, and a startup banner is the most-copied text a deployment has.
    // It matters to an operator because it decides whether the CLI verbs work
    // beside this process or only after it stops.
    eprintln!("  store: {}", backend.describe());
    eprintln!("  stop: SIGTERM drains for up to {}s", opts.drain_secs);

    let mut peer = tokio::spawn(async move {
        axum::serve(listener, server.router())
            .with_graceful_shutdown(stopping(stop_rx))
            .await
    });

    // Whichever comes first. A server that ends on its own — an accept loop that
    // died — must still stop the rest of this process, or the periodic passes go
    // on sweeping a store nothing is serving from.
    let mut ended = tokio::select! {
        () = stop_requested() => None,
        joined = &mut peer => Some(joined),
    };
    let still_serving = ended.is_none();
    let _ = stop_tx.send(true);
    let grace = std::time::Duration::from_secs(opts.drain_secs);
    let deadline = tokio::time::Instant::now() + grace;

    // **Concurrently, and that is the design.** The two waits are for different
    // things — the connections still being served, and the runs this process put
    // on a task of its own — and `Runtime::drain` closes admission on its first
    // poll, which is what lets an open subscription end rather than hold the
    // graceful shutdown open for as long as the run it is watching.
    let (report, closed) = tokio::join!(
        runtime.drain(grace),
        stop_serving(&mut peer, background, still_serving, deadline),
    );
    ended = ended.or(closed);
    report_drain(&report);
    match ended {
        Some(Ok(listening)) => listening.map_err(|e| format!("the server stopped: {e}")),
        Some(Err(e)) => Err(format!("the server task failed: {e}")),
        None => Ok(()),
    }
}

/// Wait out the listeners and the periodic passes, bounded by one deadline.
///
/// Everything here is abandoned rather than waited for once the deadline
/// passes. A periodic pass holds no lease of its own and every write in it is
/// idempotent, so the next instance's first tick repeats whatever it did not
/// finish; a connection still open is a client that reconnects. What must not be
/// abandoned early is a *run*, and that is the other half of the join this is
/// called from.
#[cfg(all(feature = "a2a-server", feature = "cedar"))]
async fn stop_serving(
    peer: &mut tokio::task::JoinHandle<std::io::Result<()>>,
    background: Vec<Task>,
    still_serving: bool,
    deadline: tokio::time::Instant,
) -> Option<Result<std::io::Result<()>, tokio::task::JoinError>> {
    let mut ended = None;
    if still_serving {
        match tokio::time::timeout_at(deadline, peer).await {
            Ok(joined) => ended = Some(joined),
            Err(_) => eprintln!("  stop: connections were still open at the grace period"),
        }
    }
    for task in background {
        if tokio::time::timeout_at(deadline, task).await.is_err() {
            break;
        }
    }
    ended
}

/// Say what the stop cost, and to whom.
#[cfg(all(feature = "a2a-server", feature = "cedar"))]
fn report_drain(report: &agentplane::runtime::DrainReport) {
    if report.is_complete() {
        eprintln!(
            "stopped; {} background runs finished first",
            report.settled()
        );
        return;
    }
    // Named, at `warn`, and on stderr: these are runs whose leases this process
    // is about to stop renewing, so each expires unreleased and the next
    // instance's recovery sweep takes it over — the same path a crash takes.
    // Nothing is lost, and the number is what an operator sizing `--drain-secs`
    // against their supervisor's grace period has to see.
    let unfinished: Vec<String> = report.unfinished.iter().map(ToString::to_string).collect();
    tracing::warn!(
        settled = report.settled(),
        unfinished = ?unfinished,
        "the grace period ended with runs still executing; they are left for the recovery sweep"
    );
    eprintln!(
        "stopped; {} background runs finished, {} left to the recovery sweep: {}",
        report.settled(),
        unfinished.len(),
        unfinished.join(" ")
    );
}

/// A stop signal, broadcast to everything this process started.
///
/// `watch` rather than a one-shot because there are several listeners and none
/// of them owns the signal: two HTTP servers and up to three periodic passes all
/// have to hear the same thing, and a channel that only one can take would make
/// the order they were started in decide which ones stop.
#[cfg(all(feature = "a2a-server", feature = "cedar"))]
type Stop = tokio::sync::watch::Receiver<bool>;

/// A background pass this process must see the end of before it exits.
#[cfg(all(feature = "a2a-server", feature = "cedar"))]
type Task = tokio::task::JoinHandle<()>;

/// Wait for the next tick, or for the stop signal. `false` means stop.
///
/// The check is here and not around the work, so a pass that is *mid-tick* when
/// the signal arrives finishes that tick and stops before the next one. A sweep
/// abandoned halfway is not a fault — every write in it is idempotent and the
/// next instance repeats it — but finishing costs milliseconds and leaves less
/// for somebody else to redo.
#[cfg(all(feature = "a2a-server", feature = "cedar"))]
async fn next_tick(tick: &mut tokio::time::Interval, stop: &mut Stop) -> bool {
    tokio::select! {
        _ = tick.tick() => true,
        _ = stop.changed() => false,
    }
}

/// Resolve when the stop signal is raised, or when the last sender is dropped.
///
/// A dropped sender is treated as a stop rather than as a hang: the sender lives
/// in `serve`, so its absence means `serve` has already returned.
#[cfg(all(feature = "a2a-server", feature = "cedar"))]
async fn stopping(mut stop: Stop) {
    let _ = stop.changed().await;
}

/// The signals a supervisor stops a process with.
///
/// `SIGTERM` is what Kubernetes, Docker and systemd send; `SIGINT` is a person
/// at a terminal. They mean the same thing here and are handled the same way —
/// a second one is *not* special-cased into an immediate exit, because the whole
/// point of the drain is that the grace period belongs to the supervisor, which
/// already holds a `SIGKILL` for a process that overstays it.
#[cfg(all(feature = "a2a-server", feature = "cedar"))]
async fn stop_requested() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let term = match signal(SignalKind::terminate()) {
            Ok(s) => Some(s),
            // A process that cannot install the handler must not silently become
            // one that ignores the signal. Said out loud, and `SIGTERM` keeps
            // its default disposition — which kills this process without a
            // drain, exactly as it would have before the handler was attempted.
            Err(error) => {
                tracing::error!(%error, "could not listen for SIGTERM; this process will not drain");
                None
            }
        };
        let terminated = async move {
            match term {
                Some(mut term) => {
                    term.recv().await;
                }
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            () = terminated => {}
            r = tokio::signal::ctrl_c() => {
                if let Err(error) = r {
                    tracing::error!(%error, "could not listen for SIGINT");
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "could not listen for an interrupt");
        }
    }
}

/// Rehearse recovery on a timer, because a control nobody exercises is one an
/// audit cannot count.
///
/// The three-way verdict — *intact*, *erased by design*, *lost* — is the whole
/// value: an erasure that worked and a byte that went missing look identical
/// to a store, and telling them apart is what a rehearsal establishes.
///
/// A finding is an `error` with the report attached, not a panic: a drill
/// reports on the past and stopping a serving plane because yesterday's bytes
/// are gone helps nobody. `not_checked` is logged whenever it is non-empty,
/// because the difference between *sound* and *nothing I looked at was wrong*
/// is exactly that list — the same reason the report carries it at all.
#[cfg(all(feature = "a2a-server", feature = "cedar"))]
fn spawn_drill(runtime: &Arc<Runtime>, every: u32, stop: Stop) -> Option<Task> {
    if every == 0 {
        return None;
    }
    if runtime.cases().is_none() {
        eprintln!(
            "  drill: --drill-every was given but this plane has no case store, \
             so there are no cases to walk"
        );
        return None;
    }
    let plane = Arc::clone(runtime);
    Some(tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(u64::from(every)));
        let mut stop = stop;
        loop {
            if !next_tick(&mut tick, &mut stop).await {
                break;
            }
            // The scheduler's clock, as the sweep's is: the runtime takes the
            // instant rather than reaching for one, so its deterministic zone
            // keeps the escapes it already argued for.
            #[allow(clippy::disallowed_methods)]
            let at = agentplane::core::Timestamp::now_utc();
            match plane.drill(at).await {
                Ok(report) if !report.is_sound() => {
                    tracing::error!(?report, "the recovery drill found unrecoverable references");
                }
                Ok(report) if !report.not_checked.is_empty() => {
                    tracing::warn!(
                        ?report,
                        "the recovery drill passed, but could not check everything"
                    );
                }
                Ok(report) => tracing::info!(cases = report.cases, "the recovery drill passed"),
                Err(error) => tracing::error!(%error, "the recovery drill could not run"),
            }
        }
    }))
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
fn spawn_sweeper(runtime: &Arc<Runtime>, every: u32, stop: Stop) -> Option<Task> {
    if every == 0 {
        return None;
    }
    let sweeper = Arc::clone(runtime);
    Some(tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(u64::from(every)));
        let mut stop = stop;
        loop {
            if !next_tick(&mut tick, &mut stop).await {
                break;
            }
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
    }))
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
    stop: Stop,
) -> Result<Task, String> {
    let api = agentplane::api::Api::new(Arc::clone(runtime), auth).map_err(|e| e.to_string())?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("could not bind the operator surface {addr}: {e}"))?;
    eprintln!("  operator: http://{addr}/runs?outcome=failed");
    Ok(tokio::spawn(async move {
        let served = axum::serve(listener, api.router())
            .with_graceful_shutdown(stopping(stop))
            .await;
        if let Err(error) = served {
            tracing::error!(%error, "the operator surface stopped");
        }
    }))
}

/// Which agent A2A serves: the file's one agent, or a room's one
/// `topology.role: orchestrator`. A2A's card path is well-known and singular,
/// so a room with no single entry would have to advertise one document and
/// quietly not serve the rest.
#[cfg(all(feature = "a2a-server", feature = "cedar"))]
fn a2a_agent(manifests: &[Manifest]) -> Result<&Manifest, Fault> {
    if let [only] = manifests {
        return Ok(only);
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
    match orchestrators.as_slice() {
        [desk] => Ok(desk),
        found => Err(usage(format!(
            "`serve` hosts a room on A2A through its one orchestrator, and this file holds \
             {} agents of which {} declare `topology.role: orchestrator`. A2A's card path \
             is well-known and singular — declare exactly one orchestrator, or split the file",
            manifests.len(),
            found.len()
        ))),
    }
}

/// The MCP listener's startup refusals, before anything is opened.
#[cfg(all(feature = "a2a-server", feature = "cedar"))]
fn refuse_mcp_listener(opts: &ServeArgs) -> Result<(), Fault> {
    let Some(addr) = opts.mcp_addr.as_deref() else {
        if opts.mcp_agent.is_empty() {
            return Ok(());
        }
        return Err(usage(
            "--mcp-agent names an agent to serve on the MCP listener, and no \
             --mcp-addr opens one",
        ));
    };
    if !cfg!(feature = "mcp-server-http") {
        return Err(usage(
            "this build cannot serve MCP over HTTP: `--mcp-addr` needs the \
             `mcp-server-http` feature. Reinstall with \
             `--features cli,a2a-server,cedar,mcp-server-http`, or use the `:full` \
             container image, which is built with it",
        ));
    }
    if addr == opts.addr || opts.operator_addr.as_deref() == Some(addr) {
        return Err(usage(format!(
            "--mcp-addr {addr} is another listener's address. Each surface has its own \
             socket and its own action vocabulary — give MCP a port of its own"
        )));
    }
    if !loopback_bind(addr) && opts.mcp_allowed_host.is_empty() {
        return Err(usage(format!(
            "--mcp-addr {addr} is not a loopback address and no --mcp-allowed-host names \
             the host callers reach it by, so every request would be refused at its \
             `Host` header. Name it, as `host` or `host:port`"
        )));
    }
    Ok(())
}

/// Whether a bind address is reachable only from this host.
#[cfg(all(feature = "a2a-server", feature = "cedar"))]
fn loopback_bind(addr: &str) -> bool {
    addr.parse::<std::net::SocketAddr>().map_or_else(
        |_| {
            addr.rsplit_once(':')
                .is_some_and(|(host, _)| host == "localhost")
        },
        |a| a.ip().is_loopback(),
    )
}

/// The MCP listener, built and not yet bound: the service and its address.
#[cfg(all(feature = "a2a-server", feature = "cedar", feature = "mcp-server-http"))]
type McpSurface = (agentplane::tools::serve_http::McpHttp, String);

/// No MCP listener in this build; `refuse_mcp_listener` said so.
#[cfg(all(
    feature = "a2a-server",
    feature = "cedar",
    not(feature = "mcp-server-http")
))]
type McpSurface = std::convert::Infallible;

/// Every agent in the file, as one MCP catalogue, behind the same tokens and
/// policy as the other listeners.
#[cfg(all(feature = "a2a-server", feature = "cedar", feature = "mcp-server-http"))]
fn mcp_surface(
    runtime: &Arc<Runtime>,
    auth: Arc<dyn agentplane::api::Authenticator>,
    manifests: &[Manifest],
    opts: &ServeArgs,
) -> Result<Option<McpSurface>, String> {
    use agentplane::tools::serve::McpServer;
    use agentplane::tools::serve_http::{HttpConfig, McpHttp};

    let Some(addr) = opts.mcp_addr.clone() else {
        return Ok(None);
    };
    let chosen = mcp_served(manifests, &opts.mcp_agent)?;
    let server = McpServer::new(Arc::clone(runtime), &chosen).map_err(|e| mcp_refusal(&e))?;
    let mut config = HttpConfig::new();
    for host in &opts.mcp_allowed_host {
        config = config.allow_host(host.clone());
    }
    for origin in &opts.mcp_allowed_origin {
        config = config.allow_origin(origin.clone());
    }
    let http = McpHttp::new(server, auth, &config).map_err(|e| format!("--mcp-addr: {e}"))?;
    Ok(Some((http, addr)))
}

#[cfg(all(
    feature = "a2a-server",
    feature = "cedar",
    not(feature = "mcp-server-http")
))]
#[allow(clippy::unnecessary_wraps)]
fn mcp_surface(
    _runtime: &Arc<Runtime>,
    _auth: Arc<dyn agentplane::api::Authenticator>,
    _manifests: &[Manifest],
    _opts: &ServeArgs,
) -> Result<Option<McpSurface>, String> {
    Ok(None)
}

/// The agents `--mcp-addr` serves: those `--mcp-agent` names, or every one.
#[cfg(all(feature = "a2a-server", feature = "cedar", feature = "mcp-server-http"))]
fn mcp_served(manifests: &[Manifest], named: &[String]) -> Result<Vec<Manifest>, String> {
    if named.is_empty() {
        return Ok(manifests.to_vec());
    }
    if let Some(unknown) = named
        .iter()
        .find(|name| !manifests.iter().any(|m| &m.metadata.name == *name))
    {
        return Err(format!(
            "--mcp-agent {unknown}: no agent in the file is named that"
        ));
    }
    Ok(manifests
        .iter()
        .filter(|m| named.contains(&m.metadata.name))
        .cloned()
        .collect())
}

/// Why the MCP catalogue could not be built, with what this command can do
/// about it.
#[cfg(all(feature = "a2a-server", feature = "cedar", feature = "mcp-server-http"))]
fn mcp_refusal(error: &agentplane::tools::serve::ServeError) -> String {
    match error {
        agentplane::tools::serve::ServeError::NoInputSchema { .. } => {
            format!("--mcp-addr: {error} — `--mcp-agent NAME` serves only the agents it names")
        }
        _ => format!("--mcp-addr: {error}"),
    }
}

/// Bind the MCP listener and serve it until the stop signal, then end its
/// open streams so the graceful shutdown is not held open by an idle host.
#[cfg(all(feature = "a2a-server", feature = "cedar", feature = "mcp-server-http"))]
async fn spawn_mcp_surface((http, addr): McpSurface, stop: Stop) -> Result<Task, String> {
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("could not bind the MCP surface {addr}: {e}"))?;
    eprintln!(
        "  mcp: http://{addr}{}",
        agentplane::tools::serve_http::MCP_PATH
    );
    let router = http.router();
    Ok(tokio::spawn(async move {
        let served = axum::serve(listener, router)
            .with_graceful_shutdown(async move {
                stopping(stop).await;
                http.close();
            })
            .await;
        if let Err(error) = served {
            tracing::error!(%error, "the MCP surface stopped");
        }
    }))
}

#[cfg(all(
    feature = "a2a-server",
    feature = "cedar",
    not(feature = "mcp-server-http")
))]
#[allow(clippy::unused_async)]
async fn spawn_mcp_surface(surface: McpSurface, _stop: Stop) -> Result<Task, String> {
    match surface {}
}

/// A peer registry and the transport that reaches every peer in it.
type WiredPeers = (
    agentplane::peers::PeerRegistry,
    Arc<dyn agentplane::peers::PeerClient>,
);

/// Wire the A2A peers `--peer` names, granted what the manifests grant them.
///
/// The registry scope for a peer is exactly the set of capabilities some
/// manifest grants under `tool://<name>/…`: the reviewed documents are what
/// say what this plane may ask a peer for, and a peer nothing grants is a
/// flag naming nobody. The token rides in the environment, because a command
/// line is visible to every process on the host.
#[cfg(feature = "a2a")]
fn connect_peers(specs: &[String], manifests: &[Manifest]) -> Result<Option<WiredPeers>, String> {
    use agentplane::core::Scope;
    use agentplane::peers::a2a::{A2aClient, Endpoint};
    use agentplane::peers::{PeerCredential, PeerGrant, PeerId, PeerRegistry, PeerRouter};

    if specs.is_empty() {
        return Ok(None);
    }
    refuse_ambiguous_peers(specs)?;
    let mut registry = PeerRegistry::new();
    let mut router = PeerRouter::new();
    for spec in specs {
        let (name, url) = spec.split_once('=').ok_or_else(|| {
            format!(
                "--peer wants `<name>=<url>`, got `{spec}`. The name is the one your \
                 manifest's grants use: a grant `tool://reviewer/audit.check` needs \
                 `--peer reviewer=https://...`"
            )
        })?;
        if name.trim().is_empty() || url.trim().is_empty() {
            return Err(format!("--peer `{spec}` names no peer or no URL"));
        }
        let grants: Vec<(String, bool)> = manifests
            .iter()
            .flat_map(|m| &m.spec.tools)
            .filter_map(|g| {
                agentplane::tools::ToolId::parse(&g.reference).map(|id| (id, g.mutates))
            })
            .filter(|(id, _)| id.server == name)
            .map(|(id, mutates)| (id.tool, mutates))
            .collect();
        let granted: Vec<String> = grants.iter().map(|(tool, _)| tool.clone()).collect();
        if granted.is_empty() {
            return Err(format!(
                "--peer `{name}` is wired but no manifest grants a `tool://{name}/…` \
                 capability, so nothing could ever call it"
            ));
        }
        let peer = PeerId::new(name);
        let mut grant = PeerGrant::new(Scope::of(granted.iter().cloned()));
        // Read-only when every grant naming this peer says `mutates: false`,
        // for the reason the scope is the grants': the reviewed documents say
        // what a call to this peer does. One mutating grant keeps the whole
        // registration mutating, which is the cautious reading.
        if grants.iter().all(|(_, mutates)| !mutates) {
            grant = grant.read_only();
        }
        let token_var = peer_token_var(name);
        if let Ok(token) = std::env::var(&token_var)
            && !token.is_empty()
        {
            grant = grant.with_credential(&peer, PeerCredential::for_audience(peer.clone(), token));
        }
        registry = registry.allow(peer.clone(), grant);
        // Refused here rather than at the first call, because the two failures
        // read nothing alike: a plaintext peer wired at boot fails much later,
        // once, inside whichever run happened to reach it, as a peer refusal
        // that names no cause a person can act on.
        //
        // This build cannot lift it. The exception for `http://` to this machine
        // is `testkit`, which the released binary does not carry — see the `cli`
        // feature — and reaching a local peer from a development build means
        // `--features cli,a2a,testkit`.
        let local = cfg!(feature = "testkit")
            && ["http://localhost:", "http://127.0.0.1:", "http://[::1]:"]
                .iter()
                .any(|prefix| url.starts_with(prefix));
        if !url.starts_with("https://") && !local {
            return Err(format!(
                "--peer `{name}` is `{url}`, and a peer is reached over HTTPS. A card or a \
                 peer answer steers the calls that follow it, so a plaintext hop would let \
                 the network choose them. For a peer on this machine, build with \
                 `--features cli,a2a,testkit`."
            ));
        }
        let client = A2aClient::new(Endpoint::new(url))
            .map_err(|e| format!("could not build a client for peer `{name}`: {e}"))?;
        #[cfg(feature = "testkit")]
        let client = if local {
            client.allow_loopback()
        } else {
            client
        };
        router = router.peer(
            peer,
            Arc::new(client) as Arc<dyn agentplane::peers::PeerClient>,
        );
        eprintln!("  peer: {name} <- {url} ({})", granted.join(", "));
    }
    Ok(Some((
        registry,
        Arc::new(router) as Arc<dyn agentplane::peers::PeerClient>,
    )))
}

/// The environment variable a peer's bearer token is read from.
///
/// Upper-cased, with `.` and `-` as `_`, because a shell variable name admits
/// neither — which is also why two names can meet here.
#[cfg_attr(not(feature = "a2a"), allow(dead_code))]
fn peer_token_var(name: &str) -> String {
    format!(
        "AGENTPLANE_PEER_TOKEN_{}",
        name.to_ascii_uppercase().replace(['.', '-'], "_")
    )
}

/// Refuse `--peer` names that would read one token variable.
///
/// `a.b`, `a-b`, `a_b` and `A_B` all become `AGENTPLANE_PEER_TOKEN_A_B`, so two
/// of them wired together would each present the other's credential — the
/// token meant for one peer sent to another. Refused at boot, naming both, and
/// a name given twice is refused with them.
#[cfg_attr(not(feature = "a2a"), allow(dead_code))]
fn refuse_ambiguous_peers(specs: &[String]) -> Result<(), String> {
    let mut seen: std::collections::HashMap<String, &str> = std::collections::HashMap::new();
    for spec in specs {
        let name = spec.split_once('=').map_or(spec.as_str(), |(name, _)| name);
        let var = peer_token_var(name);
        if let Some(earlier) = seen.insert(var.clone(), name) {
            return Err(format!(
                "--peer `{earlier}` and --peer `{name}` both read their token from {var}, \
                 so one would present the other's credential — rename one of them"
            ));
        }
    }
    Ok(())
}

/// Parse every manifest in the file, and hold each to the annotations a
/// deployment requires.
///
/// Why this lives in review rather than in the runtime is on
/// `ValidateArgs::require_annotation`.
///
/// # Errors
///
/// If a manifest will not parse, or a required annotation is absent.
fn validate(a: &ValidateArgs) -> Result<ExitCode, Fault> {
    let text = std::fs::read_to_string(&a.manifest)
        .map_err(|e| usage(format!("reading {}: {e}", a.manifest)))?;
    // A document the parser refuses is this verb's negative answer, not a
    // fault of the command: `validate` was asked *is this valid*, and no is an
    // answer a CI job acts on.
    let manifests = match Manifest::parse_all(&text) {
        Ok(manifests) => manifests,
        Err(e) => {
            if a.json {
                println!(
                    "{}",
                    serde_json::json!({ "valid": false, "error": e.to_string() })
                );
            } else {
                eprintln!("invalid: {e}");
            }
            return Ok(ExitCode::from(exit::FINDING));
        }
    };
    let mut documents = Vec::new();
    let mut missing = Vec::new();
    for m in &manifests {
        // Checked per agent, because a file may hold a room and "one of them
        // has an owner" is not the rule anybody meant.
        //
        // Presence only: an annotation *present and empty* never reaches here,
        // because the parser refuses it — a key that answers nothing reads to a
        // reviewer like a question that was answered.
        let absent: Vec<&String> = a
            .require_annotation
            .iter()
            .filter(|key| !m.metadata.annotations.contains_key(*key))
            .collect();
        let bound = declared_bound(m);
        if !a.json {
            if absent.is_empty() {
                println!("ok: {} {}", m.metadata.name, m.metadata.version);
            }
            for key in &absent {
                println!("MISSING: {} — annotation '{key}'", m.metadata.name);
            }
            for line in &bound.lines {
                println!("  {line}");
            }
        }
        missing.extend(
            absent
                .iter()
                .map(|key| format!("{}: {key}", m.metadata.name)),
        );
        documents.push(serde_json::json!({
            "name": m.metadata.name,
            "version": m.metadata.version,
            "missing_annotations": absent,
            "bound": bound.json,
        }));
    }
    if a.json {
        println!(
            "{}",
            serde_json::json!({ "valid": missing.is_empty(), "documents": documents })
        );
    } else if !missing.is_empty() {
        eprintln!(
            "{} required annotation(s) absent: {}",
            missing.len(),
            missing.join(", ")
        );
    }
    Ok(ExitCode::from(if missing.is_empty() {
        exit::OK
    } else {
        exit::FINDING
    }))
}

/// What one agent's declaration says its runs can cost, and nothing else.
struct DeclaredBound {
    lines: Vec<String>,
    json: serde_json::Value,
}

/// The worst case a declaration implies, per unit: the run ceiling plus one
/// call past it per step in flight — the figure a tenant's spend quota
/// reserves at admission.
///
/// **Derived, never forecast.** Every number is read off the manifest: the
/// ceilings, each model role's `max_input_tokens` and output ceiling at its
/// declared price, `max_parallel_steps`, `max_turns`. A term the manifest
/// leaves unbounded is named, and no total is printed beside it — a figure
/// that assumed a value for it would be a guess wearing a bound's name.
///
/// Width is `max_parallel_steps`, or one: a run started by name is one step,
/// and a multi-step plan is held to its own width, which no manifest states.
#[allow(clippy::too_many_lines)]
fn declared_bound(m: &Manifest) -> DeclaredBound {
    let budget = m.budget();
    let width = budget.max_parallel_steps.unwrap_or(1) as u64;
    let mut lines = Vec::new();

    let roles: Vec<(&str, &agentplane::manifest::ModelRef)> = m
        .spec
        .models
        .as_ref()
        .map(|models| {
            [
                ("privileged", models.privileged.as_ref()),
                ("quarantined", models.quarantined.as_ref()),
            ]
            .into_iter()
            .filter_map(|(name, r)| r.map(|r| (name, r)))
            .collect()
        })
        .unwrap_or_default();
    let mut role_json = Vec::new();
    for (name, r) in &roles {
        let line = match r.call_bound() {
            Some(call) => format!(
                "one call, {name} {}/{}: {} tokens, {} minor units",
                r.provider, r.model, call.tokens, call.minor_units
            ),
            None => format!(
                "one call, {name} {}/{}: unbounded — spec.models.{name}.max_input_tokens is \
                 not declared",
                r.provider, r.model
            ),
        };
        lines.push(line);
        role_json.push(serde_json::json!({
            "role": name,
            "call": r.call_bound().map(|c| serde_json::json!({
                "tokens": c.tokens,
                "minor_units": c.minor_units,
            })),
        }));
    }
    let call = m.call_bound();
    // The fields that leave the per-call term unbounded, by name.
    let call_gaps: Vec<String> = if roles.is_empty() {
        vec!["spec.models (no model role states what one call can cost)".to_owned()]
    } else {
        roles
            .iter()
            .filter(|(_, r)| r.call_bound().is_none())
            .map(|(name, _)| format!("spec.models.{name}.max_input_tokens"))
            .collect()
    };

    let mut units = serde_json::Map::new();
    for (unit, ceiling, field, per_call) in [
        (
            "tokens",
            budget.max_tokens,
            "spec.budgets.max_tokens",
            call.map(|c| c.tokens),
        ),
        (
            "minor units",
            budget.max_minor_units,
            "spec.budgets.max_minor_units",
            call.map(|c| c.minor_units),
        ),
    ] {
        let mut unbounded: Vec<String> = Vec::new();
        if ceiling.is_none() {
            unbounded.push(field.to_owned());
        }
        if per_call.is_none() {
            unbounded.extend(call_gaps.iter().cloned());
        }
        let total = match (ceiling, per_call) {
            (Some(c), Some(p)) => Some(c.saturating_add(width.saturating_mul(p))),
            _ => None,
        };
        let shown = |v: Option<u64>| v.map_or_else(|| "?".to_owned(), |v| v.to_string());
        lines.push(match total {
            Some(total) => format!(
                "worst case, {unit}: {total} = ceiling {} + width {width} × one call {}",
                shown(ceiling),
                shown(per_call)
            ),
            None => format!(
                "worst case, {unit}: no total — unbounded: {}",
                unbounded.join(", ")
            ),
        });
        units.insert(
            unit.replace(' ', "_"),
            serde_json::json!({
                "ceiling": ceiling,
                "per_call": per_call,
                "width": width,
                "total": total,
                "unbounded": unbounded,
            }),
        );
    }

    // A tool-calling agent's model calls are also bounded by its turns: a
    // second figure, independent of the ceiling, and only as bounded as one
    // call is.
    let turns = m
        .spec
        .execution
        .as_ref()
        .filter(|e| e.kind == agentplane::manifest::ExecutionKind::ToolCalling)
        .map(|e| e.max_turns);
    if let Some(turns) = turns {
        lines.push(match call {
            Some(c) => format!(
                "model calls: at most {turns} turns × one call = {} tokens, {} minor units",
                u64::from(turns).saturating_mul(c.tokens),
                u64::from(turns).saturating_mul(c.minor_units)
            ),
            None => format!(
                "model calls: at most {turns} turns, no total — unbounded: {}",
                call_gaps.join(", ")
            ),
        });
    }

    DeclaredBound {
        lines,
        json: serde_json::json!({
            "roles": role_json,
            "units": units,
            "turns": turns,
        }),
    }
}

/// Naming the feature rather than ignoring the flag, as `--mcp` does.
#[cfg(not(feature = "a2a"))]
fn connect_peers(specs: &[String], _manifests: &[Manifest]) -> Result<Option<WiredPeers>, String> {
    if specs.is_empty() {
        return Ok(None);
    }
    Err(
        "this build cannot call an A2A peer: `--peer` needs the `a2a` feature. Reinstall \
         with `--features cli,a2a`, or use the `:full` container image"
            .to_owned(),
    )
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
    manifests: &[Manifest],
) -> Result<Vec<(String, Arc<dyn agentplane::tools::ToolClient>)>, String> {
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
        // A child process over stdio: this plane opens no socket for it, so
        // there is no host for an egress allowlist to judge. That is not a
        // claim about what the server itself reaches — the same residual a
        // compromised allowlisted endpoint carries — and it is the honest
        // answer to the only question an allowlist can decide.
        let client = agentplane::tools::McpClient::connect(
            name,
            transport,
            agentplane::tools::Destination::Local,
        )
        .await
        .map_err(|e| format!("the MCP server `{name}` cannot be used: {e}"))?;
        // The negotiated version, not the offered one. MCP negotiation is a
        // designed downgrade, and a server that answered with an older version
        // still serves `tools/call` — it simply never returns a task, so a
        // long-running tool behaves synchronously and nothing says why. This
        // tier has no Rust in which to ask, so the line says it.
        match client.negotiated_version() {
            Some(version) => eprintln!("  mcp: {name} <- {command} (MCP {version})"),
            None => eprintln!("  mcp: {name} <- {command}"),
        }
        // What the server advertises, put beside what the operator granted.
        // The grant rules either way; what the operator is being told is that
        // the server now *wants* more than they gave it — the first observable
        // move of a server going bad, or having been swapped. Comparison, not
        // configuration: a listing failure costs the warning, never the plane.
        match client.discover().await {
            Ok(advertised) => {
                for manifest in manifests {
                    let mut catalog = agentplane::tools::ToolCatalog::from_manifest(manifest);
                    for (id, adv) in &advertised {
                        catalog = catalog.observed(id, *adv);
                    }
                    for id in catalog.overclaiming() {
                        eprintln!(
                            "  mcp: {name}: warning: `{id}` advertises more safety than \
                             manifest `{}` grants; the grant still rules",
                            manifest.metadata.name
                        );
                    }
                }
            }
            Err(e) => {
                eprintln!("  mcp: {name}: tools/list failed, advertisements not compared: {e}");
            }
        }
        wired.push((
            name.to_owned(),
            Arc::new(client) as Arc<dyn agentplane::tools::ToolClient>,
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
    _manifests: &[Manifest],
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
    backend: &Backend,
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
            backend.push(),
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
fn spawn_push_worker(
    worker: agentplane::api::a2a::A2aPushWorker,
    every: u32,
    stop: Stop,
) -> Option<Task> {
    if every == 0 {
        return None;
    }
    Some(tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(u64::from(every)));
        let mut stop = stop;
        loop {
            if !next_tick(&mut tick, &mut stop).await {
                break;
            }
            #[allow(clippy::disallowed_methods)]
            let at = time::OffsetDateTime::now_utc().unix_timestamp();
            let Ok(at) = u64::try_from(at) else { continue };
            match worker.run_once(at, PUSH_BATCH).await {
                // A batch that came back full is a backlog, and a parked
                // registration is a peer that will hear nothing until an
                // operator re-arms it. Neither may produce the same numbers —
                // or the same log level — as a quiet plane, which is I13
                // applied to this worker's own report.
                Ok(report) if report.needs_attention() => {
                    tracing::warn!(?report, "push delivery needs attention");
                }
                // On deliveries, not registrations: an idle plane re-reads
                // its registrations every tick, and that is not a delivery.
                Ok(report) if report.deliveries > 0 => {
                    tracing::info!(?report, "push delivered");
                }
                Ok(_) => {}
                Err(error) => tracing::error!(%error, "push delivery failed"),
            }
        }
    }))
}

/// The same verb, in a build that cannot answer it.
///
/// A binary that met `serve` with *unknown command* would be telling a reader
/// the feature does not exist, when it does and is one build flag away. Naming
/// the flag is the difference between a dead end and a next step — the same
/// reason the provider list is derived from the build rather than written out.
#[cfg(not(all(feature = "a2a-server", feature = "cedar")))]
#[allow(clippy::unnecessary_wraps)]
fn serve(_manifests: &[Manifest], _opts: &ServeArgs) -> Result<ExitCode, Fault> {
    Err(usage(
        "this build cannot serve: `serve` needs the `a2a-server` and `cedar` features. \
         Reinstall with `--features cli,a2a-server,cedar`, or use the `:full` \
         container image, which is built with them",
    ))
}

/// The operator API's description, as the site publishes it.
#[cfg(feature = "http")]
fn openapi_text() -> String {
    serde_json::to_string_pretty(&agentplane::api::openapi::document())
        .expect("a generated document serializes")
}

#[cfg(feature = "http")]
#[allow(clippy::unnecessary_wraps)]
fn openapi_verb() -> Result<ExitCode, Fault> {
    println!("{}", openapi_text());
    Ok(ExitCode::SUCCESS)
}

/// `openapi` in a build without the operator API it would describe.
#[cfg(not(feature = "http"))]
#[allow(clippy::unnecessary_wraps)]
fn openapi_verb() -> Result<ExitCode, Fault> {
    Err(usage(
        "this build cannot describe the operator API: `openapi` needs the `http` feature. \
         Reinstall with `--features cli,http`, or read the published document at \
         https://hupe1980.github.io/agentplane/openapi.json",
    ))
}

/// `policy check` in a build without the evaluator it would run.
///
/// Said in words rather than left to the parser, so a reader is told the verb
/// exists and which feature it needs rather than that it does not exist.
#[cfg(not(feature = "cedar"))]
#[allow(clippy::unnecessary_wraps)]
fn policy_check_verb(_opts: &PolicyCheckArgs) -> Result<ExitCode, Fault> {
    Err(usage(
        "this build cannot check policy: `policy check` evaluates a Cedar bundle and needs \
         the `cedar` feature. Reinstall with `--features cli,cedar`, or use the `:full` \
         container image",
    ))
}

/// Refuse a file whose behaviour is not in the file.
fn require_declarative(manifests: &[Manifest]) -> Result<(), String> {
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
    Ok(())
}

/// Where the run was, so the next command a person types can be printed whole.
struct Resume<'a> {
    manifest: &'a str,
    store: Option<&'a str>,
    /// Whose plane: a printed command that dropped it would resume against the
    /// unnamed default, find nothing, and say so as if the run were gone.
    tenant: Option<&'a str>,
}

/// Quote a word for a POSIX shell, so a printed command pastes back as the
/// same arguments.
fn shell_quote(word: &str) -> String {
    let safe = !word.is_empty()
        && word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-./:@%+=,".contains(c));
    if safe {
        word.to_owned()
    } else {
        format!("'{}'", word.replace('\'', r"'\''"))
    }
}

/// A connection string with its password taken out, for printing.
///
/// Both places libpq accepts one: the userinfo of the URL, and a `password=`
/// parameter. What is left still names the database; libpq finds the password
/// in `PGPASSWORD` or `~/.pgpass`, which is where one belongs.
fn without_password(spec: &str) -> String {
    let Some((scheme, rest)) = spec.split_once("://") else {
        return spec.to_owned();
    };
    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(authority_end);
    let authority = match authority.rsplit_once('@') {
        Some((userinfo, host)) => {
            let user = userinfo.split_once(':').map_or(userinfo, |(user, _)| user);
            format!("{user}@{host}")
        }
        None => authority.to_owned(),
    };
    let tail = match tail.split_once('?') {
        Some((path, query)) => {
            let kept: Vec<&str> = query
                .split('&')
                .filter(|pair| !pair.to_ascii_lowercase().starts_with("password="))
                .collect();
            if kept.is_empty() {
                path.to_owned()
            } else {
                format!("{path}?{}", kept.join("&"))
            }
        }
        None => tail.to_owned(),
    };
    format!("{scheme}://{authority}{tail}")
}

/// The `--store` and `--tenant` a printed next step carries.
///
/// A store named by `AGENTPLANE_STORE` is printed as that variable, and a
/// connection string named on the command line loses its password: stderr is
/// pasted into tickets and scrollback is shared, and a hint is not the place a
/// database credential should travel.
fn where_flags(store: Option<&str>, tenant: Option<&str>) -> String {
    let from_env = std::env::var("AGENTPLANE_STORE").ok();
    let store = match store {
        None => " --store <file>".to_owned(),
        Some(s) if from_env.as_deref() == Some(s) => r#" --store "$AGENTPLANE_STORE""#.to_owned(),
        Some(s) if is_connection_string(s) => {
            format!(" --store {}", shell_quote(&without_password(s)))
        }
        Some(s) => format!(" --store {}", shell_quote(s)),
    };
    match tenant {
        Some(t) => format!("{store} --tenant {}", shell_quote(t)),
        None => store,
    }
}

/// The verbs' shared tail: report the run, print the answer, exit honestly.
fn conclude(outcome: &agentplane::runtime::RunOutcome, resume: &Resume<'_>) -> ExitCode {
    if let RunStatus::Suspended(reason) = &outcome.status {
        suspended(outcome.run_id, reason, resume);
        // Not a failure and not an answer: the run is durable and waiting,
        // and a script needs to tell that apart from both.
        return ExitCode::from(exit::SUSPENDED);
    }
    eprintln!("run {} — {:?}", outcome.run_id, outcome.status);
    if let Some(output) = &outcome.output {
        // The answer on stdout and everything else on stderr, so this
        // composes with a pipe instead of needing a flag to be quiet.
        println!("{}", output.peek());
    }
    // A refused, exhausted or failed run must not exit zero: whoever scripts
    // this needs the shell's own answer to "did it work".
    if matches!(outcome.status, RunStatus::Succeeded) {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(exit::FINDING)
    }
}

/// Say what a suspended run waits for, and the commands that move it on.
fn suspended(
    run: agentplane::core::RunId,
    reason: &agentplane::core::SuspendReason,
    at: &Resume<'_>,
) {
    use agentplane::core::SuspendReason;

    let store = where_flags(at.store, at.tenant);
    let replay = format!(
        "agentplane replay {run} --manifest {}{store}",
        shell_quote(at.manifest)
    );
    match reason {
        SuspendReason::AwaitingEvent {
            kind, correlation, ..
        } => {
            let task = correlation
                .iter()
                .find(|k| k.namespace == "task")
                .and_then(|k| agentplane::core::TaskId::parse(&k.value).ok());
            if let Some(task) = task {
                eprintln!("run {run} is waiting for a person to decide {task}");
                eprintln!("next:");
                eprintln!("  agentplane tasks --show {task}{store}");
                eprintln!("  agentplane decide {task} approve --reason '…' --actor <you>{store}");
                eprintln!("  {replay}");
            } else {
                eprintln!("run {run} is waiting for a `{kind}` event ({reason})");
                eprintln!("next: deliver it, then\n  {replay}");
            }
        }
        SuspendReason::AwaitingTime { until } => {
            eprintln!("run {run} is waiting until {until}");
            eprintln!("next, once that instant has passed:\n  {replay}");
        }
        other => {
            eprintln!("run {run} is waiting: {other}");
            eprintln!("next:\n  {replay}");
        }
    }
    if at.store.is_none() {
        eprintln!(
            "note: this run journaled to memory and ended with the process — run it \
             again with --store to keep it"
        );
    }
}

/// Parse `--correlate NAMESPACE=VALUE` flags, or mint the run a case of its
/// own.
///
/// A fresh key rather than no case: oversight, obligations and case-bound
/// memory are declarative features, and a run without a case refuses each of
/// them at the first step that needs one.
fn correlation(flags: &[String]) -> Result<Vec<agentplane::core::CorrelationKey>, String> {
    if flags.is_empty() {
        return Ok(vec![agentplane::core::CorrelationKey::new(
            "invocation",
            agentplane::core::RunId::generate().to_string(),
        )]);
    }
    flags
        .iter()
        .map(|flag| {
            let (namespace, value) = flag
                .split_once('=')
                .filter(|(n, v)| !n.trim().is_empty() && !v.trim().is_empty())
                .ok_or_else(|| {
                    format!(
                        "--correlate wants `<namespace>=<value>`, got `{flag}` — a \
                         `$correlation/customer` subject needs `--correlate customer=C-7`"
                    )
                })?;
            Ok(agentplane::core::CorrelationKey::new(namespace, value))
        })
        .collect()
}

/// The chain `--acting-as` names: rooted at that subject, scoped to what the
/// file declares.
///
/// Exactly the file's own reach — the capabilities its agents provide, and the
/// ones they grant under a peer's name — because the chain is what a peer
/// receives, and a root wider than the declaration would hand a peer
/// authority no reviewer saw.
fn chain_for(
    subject: &str,
    manifests: &[Manifest],
    peers: &[String],
) -> Result<agentplane::core::Delegation, String> {
    let peer_names: Vec<&str> = peers
        .iter()
        .filter_map(|p| p.split_once('=').map(|(n, _)| n))
        .collect();
    let mut scope: Vec<String> = manifests
        .iter()
        .flat_map(|m| m.spec.capabilities.provides.iter().cloned())
        .collect();
    scope.extend(
        manifests
            .iter()
            .flat_map(|m| &m.spec.tools)
            .filter_map(|g| agentplane::tools::ToolId::parse(&g.reference))
            .filter(|id| peer_names.contains(&id.server.as_str()))
            .map(|id| id.tool),
    );
    if subject.trim().is_empty() {
        return Err("--acting-as names nobody".to_owned());
    }
    Ok(agentplane::core::Delegation::root(
        agentplane::core::Principal::new(subject, agentplane::core::Scope::of(scope)),
    ))
}

/// Say a build refusal in this binary's vocabulary.
///
/// The library's messages name the Rust call that fixes a wiring mistake,
/// which is right for an embedder and useless to somebody holding a YAML file
/// and this binary. The refusals a command line can reach are rewritten to
/// name the flag that fixes them; the rest pass through.
fn in_cli_terms(error: &agentplane::runtime::BuildError, manifests: &[Manifest]) -> String {
    use agentplane::runtime::BuildError;
    match error {
        BuildError::DeclarativeToolsUnreachable { agent, kind, .. } => {
            let servers: Vec<String> = manifests
                .iter()
                .filter(|m| &m.metadata.name == agent)
                .flat_map(|m| &m.spec.tools)
                .filter_map(|g| agentplane::tools::ToolId::parse(&g.reference))
                .map(|id| id.server)
                .filter(|s| s != "agent")
                .fold(Vec::new(), |mut acc, s| {
                    if !acc.contains(&s) {
                        acc.push(s);
                    }
                    acc
                });
            format!(
                "agent '{agent}' declares `execution.kind: {kind}` and grants tools on {}, \
                 but nothing reaches them. Name the process that serves each one: \
                 `--mcp {}=<command>` for an MCP server, or `--peer <name>=<url>` for an \
                 A2A peer",
                servers.join(", "),
                servers.first().map_or("<server>", String::as_str),
            )
        }
        BuildError::PeerIsAlsoAToolServer { server } => format!(
            "'{server}' is named by both --mcp and --peer; a grant `tool://{server}/…` \
             cannot mean both a tool call and a delegating hop — drop one of the two flags"
        ),
        BuildError::UnknownProvider { agent, provider } => format!(
            "agent '{agent}' names provider '{provider}', and this binary ships {}",
            shipped_providers().join(", ")
        ),
        other => other.to_string(),
    }
}

/// The plane `run` and `dev` admit runs on, built one way: the manifest's
/// providers, its MCP servers and peers, the chain `--acting-as` names, and
/// `policy` where the verb has one.
async fn build_plane(
    backend: &Backend,
    manifests: &[Manifest],
    mcp: &[String],
    peers: &[String],
    chain: Option<agentplane::core::Delegation>,
    policy: Option<Arc<dyn agentplane::core::PolicyEngine>>,
    streams: Option<Arc<dyn agentplane::runtime::RunStreamObserver>>,
) -> Result<Arc<Runtime>, Fault> {
    let mut builder = with_providers(backend.plane(), manifests).await?;
    if let Some(streams) = streams {
        builder = builder.observe_model_streams(streams);
    }
    for (name, client) in connect_mcp_servers(mcp, manifests).await? {
        builder = builder.tool_server(name, client);
    }
    if let Some((registry, client)) = connect_peers(peers, manifests).map_err(usage)? {
        builder = builder.peers(registry, client);
    }
    if let Some(chain) = chain {
        builder = builder.acting_as(chain);
    }
    if let Some(policy) = policy {
        builder = builder.policy(policy);
    }
    for manifest in manifests {
        builder = builder.agent(agentplane::runtime::Agent::new(manifest));
    }
    // `try_build`, because everything on this plane arrived as input: a
    // wiring mistake in a file somebody handed us is a refusal with a
    // sentence, not a programmer error worth a crash.
    builder
        .try_build()
        .map_err(|e| Fault::from(in_cli_terms(&e, manifests)))
}

fn execute(manifests: &[Manifest], opts: &RunArgs) -> Result<ExitCode, Fault> {
    require_declarative(manifests).map_err(usage)?;
    // Before anything is started: a peer call is made on somebody's behalf,
    // and a run with no chain would reach the model, offer it the peer, and
    // refuse the call as a tool failure the run then answers around — exit
    // zero, and the peer never asked.
    let chain = opts
        .acting_as
        .as_deref()
        .map(|subject| chain_for(subject, manifests, &opts.peer))
        .transpose()
        .map_err(usage)?;
    let keys = correlation(&opts.correlate).map_err(usage)?;
    let pinned = opts
        .expect_digest
        .as_deref()
        .map(|hex| {
            agentplane::core::Digest::from_hex(hex)
                .map_err(|e| usage(format!("--expect-digest `{hex}` is not a digest: {e}")))
        })
        .transpose()?;

    // Current-thread on purpose. A CLI runs one agent and exits, so a work
    // stealing pool buys nothing and would mean pulling `rt-multi-thread` into
    // a crate that has so far needed four tokio features.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the async runtime: {e}"))?;

    rt.block_on(async {
        // **The whole plane, not the journal alone**, as `serve` wires it: a
        // declaration naming memory or a wait is not a different declaration
        // because of which verb reached it.
        let backend = if let Some(backend) = opts.at.open().await? {
            backend
        } else {
            // Said out loud rather than assumed: a run whose journal disappears
            // is the opposite of what this crate is for.
            eprintln!("note: journaling to memory; this run will not survive the process");
            Backend::in_memory()?
        };
        let agent = build_plane(
            &backend, manifests, &opts.mcp, &opts.peer, chain, None, None,
        )
        .await?;

        let capability = entry_capability(manifests, opts.capability.as_deref()).map_err(usage)?;
        // The case kind is the capability: a case is a matter, and the matter
        // a terminal run belongs to is the thing it was asked to do.
        let mut terms = agentplane::runtime::RunTerms::default().correlated(&capability, &keys);
        if let Some(digest) = pinned {
            terms = terms.expect_declaration(digest);
        }
        // No admission key, so the admission is always fresh.
        let agentplane::runtime::Admission::Fresh(outcome) = agent
            .run_under(
                &capability,
                Tainted::trusted(opts.read_input().map_err(usage)?),
                terms,
            )
            .await
            .map_err(admission_fault)?
        else {
            return Err("an unkeyed run was answered as a keyed one"
                .to_owned()
                .into());
        };

        Ok(conclude(
            &outcome,
            &Resume {
                manifest: &opts.manifest,
                store: opts.at.store.as_deref(),
                tenant: opts.at.tenant.as_deref(),
            },
        ))
    })
}

/// Re-execute a recorded run against the same declaration.
///
/// The plane is rebuilt exactly as `run` builds it — same providers, same MCP
/// wiring, same agents — plus the whole case layer, because a **resume** may
/// continue past its recorded history and dispatch live: a run that suspended
/// on a task or a timer needs the stores those live in. `--strict` is
/// [`verify_replay`]: it dispatches nothing and reports a verdict.
fn replay(manifests: &[Manifest], opts: &ReplayArgs) -> Result<ExitCode, Fault> {
    require_declarative(manifests).map_err(usage)?;
    if opts.strict {
        return verify_replay(manifests, opts);
    }
    let run_id = opts.run_id.as_deref().ok_or_else(|| {
        usage("a resume needs the run to resume: `agentplane replay <run> --manifest …`")
    })?;
    let store = opts.at.store.as_deref().ok_or_else(|| {
        usage("a resume needs the store the run lives in: --store <file|postgres://…>")
    })?;
    let run = agentplane::core::RunId::parse(run_id)
        .map_err(|e| usage(format!("`{run_id}` is not a run id: {e}")))?;
    let mode = Mode::Resume;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the async runtime: {e}"))?;

    rt.block_on(async {
        let backend = Backend::open(store, opts.at.tenant.as_deref()).await?;
        let mut builder = with_providers(backend.plane(), manifests).await?;
        for (name, client) in connect_mcp_servers(&opts.mcp, manifests).await? {
            builder = builder.tool_server(name, client);
        }
        if let Some((registry, client)) = connect_peers(&opts.peer, manifests).map_err(usage)? {
            builder = builder.peers(registry, client);
        }
        for manifest in manifests {
            builder = builder.agent(agentplane::runtime::Agent::new(manifest));
        }
        let agent = builder
            .try_build()
            .map_err(|e| in_cli_terms(&e, manifests))?;

        let outcome = match agent.replay(run, mode).await {
            // A terminal that recorded a decision and could not run the agent
            // keeps its short lease, so the run stays findable. The replay the
            // operator runs next waits that lease out rather than failing on it;
            // a longer hold is somebody else's live work and is reported.
            Err(agentplane::core::RuntimeError::LeaseHeld { remaining_secs, .. })
                if remaining_secs <= 5 =>
            {
                tokio::time::sleep(std::time::Duration::from_secs(remaining_secs + 1)).await;
                agent.replay(run, mode).await
            }
            other => other,
        }
        .map_err(|e| e.to_string())?;
        Ok(conclude(
            &outcome,
            &Resume {
                manifest: &opts.manifest,
                store: Some(store),
                tenant: opts.at.tenant.as_deref(),
            },
        ))
    })
}

/// What one replayed run contributes to the process's exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Replayed {
    Verified,
    CannotReplay,
    Diverged,
    Unreadable,
}

impl Replayed {
    fn of(verdict: &agentplane::runtime::Verdict) -> Self {
        use agentplane::runtime::Finding;
        match verdict.finding {
            Finding::Verified { .. } => Self::Verified,
            Finding::CannotReplay(_) => Self::CannotReplay,
            _ => Self::Diverged,
        }
    }
}

/// The exit a strict replay of several runs owes, from the worst of them.
///
/// Worst is an outage (the answer is unreliable), then a divergence (the
/// finding the verb exists for), then a run that could not be replayed (a
/// partial answer), then verified. A corpus with one diverged run fails as
/// diverged whatever else it holds, so CI reads one status.
fn replay_exit(runs: &[Replayed]) -> u8 {
    match runs.iter().max() {
        None | Some(Replayed::Verified) => exit::OK,
        Some(Replayed::CannotReplay) => exit::PARTIAL,
        Some(Replayed::Diverged) => exit::FINDING,
        Some(Replayed::Unreadable) => exit::OPERATIONAL,
    }
}

/// `replay --strict`: replay recorded runs under the manifest in hand and
/// report a verdict per run.
///
/// Every driver is replay-only: a provider that answers with the recorded
/// request profile and refuses to complete, a tool transport and a peer
/// transport that refuse every call. A strict replay serves every call from
/// the record, so none of them is reached, and none needs a credential or a
/// process. `--mcp` and `--peer` are refused rather than ignored: under
/// `--strict` one could only start a server and the other only dial one.
fn verify_replay(manifests: &[Manifest], opts: &ReplayArgs) -> Result<ExitCode, Fault> {
    if !opts.mcp.is_empty() || !opts.peer.is_empty() {
        return Err(usage(
            "--strict dispatches nothing, so --mcp could only start a server and --peer only \
             dial one; drop them — every tool result and peer reply is read from the record",
        ));
    }
    if !opts.from.is_empty() && opts.at.store.is_some() {
        return Err(usage(
            "--from and --store name two sources; replay one of them (AGENTPLANE_STORE counts \
             as --store)",
        ));
    }
    let wanted = opts
        .run_id
        .as_deref()
        .map(|id| {
            agentplane::core::RunId::parse(id)
                .map_err(|e| usage(format!("`{id}` is not a run id: {e}")))
        })
        .transpose()?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the async runtime: {e}"))?;

    rt.block_on(async {
        // Each source is a set of stores and the runs to replay from it.
        let mut sources: Vec<(Backend, Vec<agentplane::core::RunId>)> = Vec::new();
        if opts.from.is_empty() {
            let store = opts.at.store.as_deref().ok_or_else(|| {
                usage("--strict needs a source: --store <file|postgres://…> or --from <export>")
            })?;
            let run = wanted.ok_or_else(|| {
                usage("a strict replay of a store names its run; replay every run of an export with --from")
            })?;
            let backend = Backend::open(store, opts.at.tenant.as_deref()).await?;
            sources.push((backend, vec![run]));
        } else {
            for path in &opts.from {
                let file = std::fs::File::open(path)
                    .map_err(|e| format!("could not read the export {path}: {e}"))?;
                let source =
                    agentplane::export::open_for_replay(std::io::BufReader::new(file))
                        .await
                        .map_err(|e| format!("{path}: {e}"))?;
                let runs = match wanted {
                    Some(run) if source.runs.contains(&run) => vec![run],
                    Some(_) => continue,
                    None => source.runs.clone(),
                };
                sources.push((
                    Backend::Embedded(source.store, agentplane::core::TenantId::default()),
                    runs,
                ));
            }
            if let Some(run) = wanted
                && sources.is_empty()
            {
                return Err(format!("no export named holds run {run}").into());
            }
        }

        let mut results = Vec::new();
        for (backend, runs) in sources {
            for run in runs {
                results.push(verify_one(manifests, &backend, run).await?);
            }
        }
        Ok(ExitCode::from(replay_exit(&results)))
    })
}

/// Replay one run strictly and print its verdict.
async fn verify_one(
    manifests: &[Manifest],
    backend: &Backend,
    run: agentplane::core::RunId,
) -> Result<Replayed, Fault> {
    match strict_verdict(manifests, backend, run).await? {
        Ok(verdict) => {
            eprint!("{verdict}");
            Ok(Replayed::of(&verdict))
        }
        Err(e) => {
            eprintln!("run {run} — cannot be read: {e}");
            Ok(Replayed::Unreadable)
        }
    }
}

/// One run's strict-replay verdict under `manifests`, or why the run could
/// not be read. Every driver is replay-only: nothing is dispatched.
async fn strict_verdict(
    manifests: &[Manifest],
    backend: &Backend,
    run: agentplane::core::RunId,
) -> Result<Result<agentplane::runtime::Verdict, String>, Fault> {
    let history = match backend.journal().read(run, 1).await {
        Ok(history) => history,
        Err(e) => return Ok(Err(e.to_string())),
    };
    let mut builder = agentplane::runtime::replay_only::wire(backend.plane(), manifests, &history);
    for manifest in manifests {
        builder = builder.agent(agentplane::runtime::Agent::new(manifest));
    }
    let plane = builder
        .try_build()
        .map_err(|e| usage(in_cli_terms(&e, manifests)))?;
    Ok(plane.verify(run).await.map_err(|e| e.to_string()))
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
        #[cfg(feature = "fake-model")]
        "fake" => {
            let fake = agentplane::model::fake::FakeProvider::new();
            // Its deltas reach an observer only where one listens.
            fake.streaming();
            Ok(fake)
        }
        other => Err(format!(
            "no driver for provider '{other}'. This binary ships {}; anything else is an \
             embedder's own driver, registered through RuntimeBuilder::provider",
            shipped_providers().join(", "),
        )),
    }
}

/// Every provider name *this* binary can construct.
///
/// Assembled from the same `cfg`s as the dispatch above, rather than written
/// out as prose. A hand-written list is true only for whichever feature set
/// the author had in mind: the moment a driver becomes opt-in, the sentence
/// starts telling a reader their build has something it does not, and the
/// compiler has nothing to say about a string. A list derived from the build
/// cannot disagree with the build.
fn shipped_providers() -> Vec<&'static str> {
    #[allow(unused_mut)]
    let mut names: Vec<&'static str> = Vec::new();
    #[cfg(feature = "providers")]
    names.extend(["anthropic", "chat-completions", "gemini", "openai"]);
    #[cfg(feature = "bedrock")]
    names.push("bedrock");
    #[cfg(feature = "fake-model")]
    names.push("fake");
    names.sort_unstable();
    names
}

#[cfg(feature = "providers")]
fn key(var: &str) -> Result<String, String> {
    std::env::var(var)
        .map_err(|_| format!("{var} is not set, and the manifest names a provider that needs it"))
}

#[cfg(test)]
mod tests {
    /// **An input the agent cannot read its data subject from is a usage
    /// error**, not an outage: the same input is refused again, so a caller
    /// told to retry would retry forever.
    #[test]
    fn an_unbound_subject_exits_as_usage() {
        let unbound = agentplane::core::RuntimeError::SubjectUnbound {
            binding: "$input/customer/id".to_owned(),
            reason: "it selects nothing in the run's input".to_owned(),
        };
        assert_eq!(super::admission_fault(unbound).status(), super::exit::USAGE);
        assert_eq!(
            super::admission_fault(agentplane::core::RuntimeError::Draining).status(),
            super::exit::OPERATIONAL
        );
    }

    /// **`verify` checks the cosignature on a note it was handed as a file.**
    /// The golden cosigned checkpoint, read with the golden witness key, names
    /// its witness and carries the time the witness signed; without the key it
    /// names nobody, and a key that is not the witness's names nobody either.
    #[test]
    fn a_cosigned_note_file_names_its_witness_in_verify() {
        let golden = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden");
        let note = golden
            .join("checkpoint.cosigned.note")
            .display()
            .to_string();
        let keys = std::fs::read_to_string(golden.join("keys.txt")).expect("keys.txt");
        let witness = keys
            .lines()
            .find_map(|l| l.strip_prefix("--witness-key "))
            .expect("a witness key")
            .to_owned();

        let file = super::checkpoint_anchor(&note, std::slice::from_ref(&witness))
            .expect("the note reads");
        assert!(file.signed_note);
        assert_eq!(file.cosigned_by, vec![format!("{note}:golden-witness")]);
        assert_eq!(
            file.anchor
                .witnessed
                .iter()
                .map(|t| (t.key_id.as_str(), t.timestamp))
                .collect::<Vec<_>>(),
            vec![("golden-witness", 1_700_000_600)],
            "the witness's signed time travels with the anchor, for `audit`'s freshness rule"
        );

        let unkeyed = super::checkpoint_anchor(&note, &[]).expect("the note reads");
        assert!(unkeyed.cosigned_by.is_empty() && unkeyed.anchor.witnessed.is_empty());
        let stranger = format!(
            "golden-witness={}",
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                agentplane::policy::Ed25519Signer::new("x", &[3u8; 32]).verifying_key()
            )
        );
        let wrong = super::checkpoint_anchor(&note, &[stranger]).expect("the note reads");
        assert!(
            wrong.cosigned_by.is_empty(),
            "a line is a cosignature only under the key that made it"
        );
    }

    use super::{
        EXIT_STATUS_HELP, Fault, Truncation, audit_status, cutoff_before, declared_bound, exit,
        lift_status, refuse_ambiguous_peers, refuses_partial_export, restore_unverifiable,
        shell_quote, verify_status, where_flags, without_password,
    };
    use std::sync::Arc;

    /// **The verb prints the document the site publishes.** Regenerate the file
    /// with `cargo run --features cli,http -- openapi > site/static/openapi.json`.
    #[cfg(feature = "http")]
    #[test]
    fn the_openapi_verb_prints_the_published_document() {
        let published = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/site/static/openapi.json"
        ))
        .expect("site/static/openapi.json exists");
        assert_eq!(
            super::openapi_text().trim_end(),
            published.trim_end(),
            "`agentplane openapi` and site/static/openapi.json disagree"
        );
    }

    /// **A build without the operator API says which feature describes it.**
    #[cfg(not(feature = "http"))]
    #[test]
    fn the_openapi_verb_names_the_feature_it_needs() {
        match super::openapi_verb() {
            Err(fault @ Fault::Usage(_)) => {
                assert_eq!(fault.status(), super::exit::USAGE);
                assert!(fault.to_string().contains("`http`"), "{fault}");
            }
            other => panic!("a build without `http` described the operator API: {other:?}"),
        }
    }

    /// A fresh directory under the system temp dir, unique to this test.
    #[cfg(feature = "cedar")]
    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "agentplane-bundle-{name}-{}",
            agentplane::core::RunId::generate()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    /// **A bundle directory and the rules file it holds are one bundle.**
    ///
    /// `serve --policy` and `policy check --bundle` read through one loader, so
    /// a served file and the directory an auditor is handed name the same
    /// identity — the one `RunAdmitted.policy_bundle` records and the check
    /// compares against. With a schema beside the rules, it is another bundle.
    #[cfg(feature = "cedar")]
    #[test]
    fn a_bundle_directory_and_its_rules_file_have_one_identity() {
        use agentplane::core::PolicyEngine as _;

        let rules = "permit(principal, action, resource);";
        let dir = scratch("same");
        std::fs::write(dir.join("policy.cedar"), rules).unwrap();
        let single = scratch("single").join("served.cedar");
        std::fs::write(&single, rules).unwrap();

        let from_dir = super::load_policy_bundle(dir.to_str().unwrap()).expect("dir");
        let from_file = super::load_policy_bundle(single.to_str().unwrap()).expect("file");
        assert_eq!(from_dir.bundle(), from_file.bundle());
        assert_eq!(
            from_dir.bundle(),
            agentplane::policy::CedarEngine::new(rules)
                .unwrap()
                .bundle(),
            "the loader is not the engine `serve` used to build"
        );

        std::fs::write(dir.join("entities.json"), "[]").unwrap();
        let with_entities = super::load_policy_bundle(dir.to_str().unwrap()).expect("dir");
        assert_ne!(
            with_entities.bundle(),
            from_file.bundle(),
            "the entities beside the rules did not reach the bundle identity"
        );
    }

    /// **A file the loader would skip is refused**, so no rule sits where the
    /// bundle's identity does not reach.
    #[cfg(feature = "cedar")]
    #[test]
    fn a_bundle_directory_holding_another_file_is_refused() {
        let dir = scratch("stray");
        std::fs::write(
            dir.join("policy.cedar"),
            "permit(principal, action, resource);",
        )
        .unwrap();
        std::fs::write(
            dir.join("extra.cedar"),
            "forbid(principal, action, resource);",
        )
        .unwrap();
        match super::load_policy_bundle(dir.to_str().unwrap()) {
            Err(Fault::Usage(why)) => assert!(why.contains("extra.cedar"), "{why}"),
            Err(other) => panic!("refused as the wrong kind of fault: {other}"),
            Ok(_) => panic!("a rule in a file the bundle does not read was accepted"),
        }
    }

    fn agent(models: &str, budgets: &str) -> agentplane::manifest::Manifest {
        agentplane::manifest::Manifest::parse(&format!(
            "apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: {{ name: bounded, version: \"1.0.0\" }}
spec:
  execution: {{ kind: tool-calling, max_turns: 4 }}
  capabilities: {{ provides: [bounded.answer] }}
  models:
{models}
  budgets: {budgets}
"
        ))
        .expect("the fixture parses")
    }

    const PRICE: &str =
        "pricing: { input: 1000000, output: 2000000, cache_read: 100000, cache_write: 1250000 }";

    /// Every term bounded: the figure is the formula, from the declaration.
    #[test]
    fn validate_derives_the_worst_case_from_the_declaration() {
        let m = agent(
            &format!(
                "    privileged: {{ provider: fake, model: m, max_tokens: 100, max_input_tokens: 900, {PRICE} }}"
            ),
            "{ max_tokens: 10000, max_minor_units: 50000, max_parallel_steps: 2 }",
        );
        let bound = declared_bound(&m);
        let tokens = &bound.json["units"]["tokens"];
        // 1000 per call; 10000 + 2 × 1000.
        assert_eq!(tokens["per_call"], 1000);
        assert_eq!(tokens["total"], 12_000);
        // 900 input at the dearest input rate (1.25/token) + 100 output at 2.
        let money = &bound.json["units"]["minor_units"];
        assert_eq!(money["per_call"], 1325);
        assert_eq!(money["total"], 50_000 + 2 * 1325);
        assert_eq!(bound.json["turns"], 4);
        assert!(
            bound
                .lines
                .iter()
                .any(|l| l.contains("12000 = ceiling 10000 + width 2 × one call 1000")),
            "{:?}",
            bound.lines
        );
    }

    /// An unbounded term is named, and no total stands beside it.
    #[test]
    fn validate_names_every_unbounded_term() {
        let m = agent(
            &format!("    privileged: {{ provider: fake, model: m, max_tokens: 100, {PRICE} }}"),
            "{ max_tokens: 10000 }",
        );
        let bound = declared_bound(&m);
        for unit in ["tokens", "minor_units"] {
            assert!(
                bound.json["units"][unit]["total"].is_null(),
                "a total was printed for {unit} although a term is unbounded: {}",
                bound.json
            );
        }
        let tokens: Vec<String> =
            serde_json::from_value(bound.json["units"]["tokens"]["unbounded"].clone())
                .expect("names");
        assert_eq!(tokens, vec!["spec.models.privileged.max_input_tokens"]);
        let money: Vec<String> =
            serde_json::from_value(bound.json["units"]["minor_units"]["unbounded"].clone())
                .expect("names");
        assert_eq!(
            money,
            vec![
                "spec.budgets.max_minor_units",
                "spec.models.privileged.max_input_tokens"
            ]
        );
        assert!(
            bound.lines.iter().any(|l| l.contains("no total")),
            "{:?}",
            bound.lines
        );
    }
    use std::process::ExitCode;

    fn truncation(reached: &[&str]) -> Truncation {
        Truncation {
            limit: 10,
            reached: reached.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    /// **One table of exit statuses, and `--help` prints the same one.**
    ///
    /// A scheduler reads the status and nothing else, so a finding and an
    /// outage must not share a number, and a partial answer must be neither a
    /// pass nor a failure.
    #[test]
    fn the_exit_statuses_are_one_table() {
        use clap::CommandFactory as _;

        assert_eq!(usage_status(), exit::USAGE);
        assert_eq!(
            Fault::from("store down".to_owned()).status(),
            exit::OPERATIONAL
        );
        assert_ne!(exit::FINDING, exit::OPERATIONAL);

        // An audit: a finding outranks a partial view; a partial view is not a pass.
        assert_eq!(audit_status(true, &truncation(&[])), exit::OK);
        assert_eq!(
            audit_status(true, &truncation(&["succeeded"])),
            exit::PARTIAL
        );
        assert_eq!(
            audit_status(false, &truncation(&["succeeded"])),
            exit::FINDING
        );

        // A lift that found nothing standing is a negative answer.
        assert_eq!(lift_status(true), ExitCode::SUCCESS);
        assert_eq!(lift_status(false), ExitCode::from(exit::FINDING));

        // An export this build cannot verify is partial, not damaged; a finding
        // beside it still fails.
        let mut report = agentplane::export::VerifyReport {
            checkpoint: agentplane::journal::Checkpoint {
                origin: String::new(),
                size: 0,
                root: agentplane::core::Digest::ZERO,
            },
            sound: Vec::new(),
            findings: Vec::new(),
            not_checked: Vec::new(),
            records: 0,
            cases: 0,
            complete: true,
            unverifiable: None,
            selection: None,
        };
        assert_eq!(verify_status(&report, true), ExitCode::SUCCESS);
        report.unverifiable = Some("unknown canon".to_owned());
        assert_eq!(
            verify_status(&report, true),
            ExitCode::from(exit::UNVERIFIABLE)
        );
        let version = agentplane::export::FORMAT_VERSION;
        let foreign =
            format!("{{\"kind\":\"agentplane.export\",\"version\":{version},\"canon\":999}}\n");
        assert!(restore_unverifiable(foreign.as_bytes()).is_some());
        let native = format!(
            "{{\"kind\":\"agentplane.export\",\"version\":{version},\"canon\":{}}}\n",
            agentplane::core::canon::VERSION
        );
        assert!(restore_unverifiable(native.as_bytes()).is_none());
        // Kind and version before canon, in `verify`'s order: neither of these
        // is an export this build could hold to its digests under any canon.
        let not_an_export = "{\"kind\":\"RunAdmitted\",\"canon\":999}\n";
        assert!(restore_unverifiable(not_an_export.as_bytes()).is_none());
        let other_version = format!(
            "{{\"kind\":\"agentplane.export\",\"version\":{},\"canon\":999}}\n",
            version + 1
        );
        assert!(restore_unverifiable(other_version.as_bytes()).is_none());
        report.findings.push("damage".to_owned());
        assert_eq!(verify_status(&report, true), ExitCode::from(exit::FINDING));

        for (code, word) in [
            (exit::OK, "ok"),
            (exit::FINDING, "finding"),
            (exit::USAGE, "usage"),
            (exit::SUSPENDED, "suspended"),
            (exit::OPERATIONAL, "operational"),
            (exit::PARTIAL, "partial"),
            (exit::UNVERIFIABLE, "unverifiable"),
        ] {
            assert!(
                EXIT_STATUS_HELP
                    .lines()
                    .any(|l| l.trim_start().starts_with(&format!("{code}  ")) && l.contains(word)),
                "--help does not say that {code} means {word}: {EXIT_STATUS_HELP}"
            );
        }
        let help = super::Cli::command()
            .get_after_help()
            .map(ToString::to_string)
            .unwrap_or_default();
        assert_eq!(help, EXIT_STATUS_HELP, "--help prints another table");
    }

    fn usage_status() -> u8 {
        super::usage("bad flag").status()
    }

    /// **A truncated export is refused unless a partial file was asked for.**
    #[test]
    fn a_truncated_export_is_refused_without_allow_partial() {
        assert!(refuses_partial_export(
            &truncation(&["in-flight runs"]),
            false
        ));
        assert!(!refuses_partial_export(
            &truncation(&["in-flight runs"]),
            true
        ));
        assert!(!refuses_partial_export(&truncation(&[]), false));
    }

    /// **A printed next step names the tenant and carries no password.**
    ///
    /// The hint `run` and `replay` print is pasted into tickets: `--store`
    /// verbatim would carry a `postgres://` password, and a hint with no
    /// `--tenant` resumes against the default tenant and finds nothing.
    #[test]
    fn a_printed_next_step_carries_the_tenant_and_no_password() {
        let flags = where_flags(
            Some("postgres://ada:s3cret@db.internal:5432/plane?password=hunter2&sslmode=require"),
            Some("acme corp"),
        );
        assert!(
            !flags.contains("s3cret"),
            "the URL's password was printed: {flags}"
        );
        assert!(
            !flags.contains("hunter2"),
            "the password parameter was printed: {flags}"
        );
        assert!(flags.contains("ada@db.internal:5432/plane"), "{flags}");
        assert!(flags.contains("sslmode=require"), "{flags}");
        assert!(
            flags.ends_with(" --tenant 'acme corp'"),
            "the tenant is missing or unquoted: {flags}"
        );
        assert_eq!(
            without_password("postgres://db/plane"),
            "postgres://db/plane",
            "a URL with no password is printed as it is"
        );
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
        assert_eq!(where_flags(Some("runs.redb"), None), " --store runs.redb");
    }

    /// **Two `--peer` names that read one token variable are refused.**
    ///
    /// `a.b`, `a-b` and `a_b` all read `AGENTPLANE_PEER_TOKEN_A_B`, so wiring
    /// two of them would send one peer's bearer token to the other.
    #[test]
    fn ambiguous_peer_names_are_refused_at_boot() {
        let specs = |names: &[&str]| -> Vec<String> {
            names
                .iter()
                .map(|n| format!("{n}=https://peer.example"))
                .collect()
        };
        let err = refuse_ambiguous_peers(&specs(&["billing.eu", "billing-eu"]))
            .expect_err("both read AGENTPLANE_PEER_TOKEN_BILLING_EU");
        assert!(
            err.contains("billing.eu") && err.contains("billing-eu"),
            "{err}"
        );
        assert!(refuse_ambiguous_peers(&specs(&["billing", "reviewer"])).is_ok());
    }

    /// A window a person could type is answered; one that reaches past the
    /// calendar is a message rather than an abort.
    ///
    /// The subtraction `time` performs panics on underflow, so the unchecked
    /// form ended a retention command with `overflow subtracting duration from
    /// date` and no mention of the flag that caused it.
    #[test]
    fn a_retention_window_past_the_calendar_is_a_message_not_an_abort() {
        let now = time::macros::datetime!(2026-09-13 12:00:00 UTC);
        assert!(cutoff_before(now, 90).is_ok());
        let err = cutoff_before(now, u32::MAX).expect_err("a window of 11m years");
        assert!(err.contains("--older-than-days"), "{err}");
    }

    /// **A corpus exits with its worst verdict, and each verdict has one
    /// status.**
    ///
    /// A CI job reads the status and nothing else: a divergence anywhere fails
    /// the job as a finding whatever else the corpus holds, a run that could
    /// not be replayed is a partial answer rather than a pass, and an outage
    /// outranks both because it leaves the answer unknown.
    #[test]
    fn a_corpus_exits_with_its_worst_verdict() {
        use super::{Replayed, replay_exit};

        assert_eq!(replay_exit(&[]), exit::OK);
        assert_eq!(replay_exit(&[Replayed::Verified]), exit::OK);
        assert_eq!(
            replay_exit(&[Replayed::Verified, Replayed::CannotReplay]),
            exit::PARTIAL
        );
        assert_eq!(
            replay_exit(&[
                Replayed::CannotReplay,
                Replayed::Diverged,
                Replayed::Verified
            ]),
            exit::FINDING
        );
        assert_eq!(
            replay_exit(&[Replayed::Diverged, Replayed::Unreadable]),
            exit::OPERATIONAL
        );
    }

    /// **A strict replay needs no provider this binary could build.**
    ///
    /// The run was recorded under a provider name no driver here answers to —
    /// the shape of a CI job holding no credential for the provider its
    /// manifest names. Every call is served from the record, so the verdict
    /// must still come back; a strict path that registered the manifest's
    /// live drivers would refuse before replaying anything.
    #[test]
    fn strict_replay_wires_only_replay_only_drivers() {
        use agentplane::journal::JournalStore;

        const ACME: &str = r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: summariser, version: "1.0.0" }
spec:
  execution: { kind: completion }
  identity: { role: "Summarise a support ticket" }
  capabilities: { provides: [support.summarise] }
  models:
    privileged: { provider: acme, model: sum-1 }
  budgets: { max_tokens: 10000 }
"#;
        let manifests = vec![agentplane::manifest::Manifest::parse(ACME).expect("parses")];
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(async {
                let store = std::sync::Arc::new(
                    agentplane::store::RedbStore::open_in_memory().expect("store"),
                );
                let recorded = agentplane::runtime::Runtime::builder(
                    std::sync::Arc::clone(&store) as std::sync::Arc<dyn JournalStore>
                )
                .provider("acme", agentplane::model::fake::FakeProvider::new())
                .agent(agentplane::runtime::Agent::new(&manifests[0]))
                .build()
                .run(
                    "support.summarise",
                    agentplane::core::Tainted::trusted(serde_json::json!({ "t": 1 })),
                )
                .await
                .expect("recorded");

                let replayed = super::verify_one(
                    &manifests,
                    &super::Backend::Embedded(store, agentplane::core::TenantId::default()),
                    recorded.run_id,
                )
                .await
                .expect("a strict replay needs no driver this binary can build");
                assert_eq!(replayed, super::Replayed::Verified);
            });
    }

    /// `serve`'s arguments for the witness tests: one submission witness at a
    /// port nothing listens on, a trusted key, and a log key on disk.
    #[cfg(all(feature = "a2a-server", feature = "cedar"))]
    fn serve_witness_args(extra: &[&str]) -> super::ServeArgs {
        let dir = std::env::temp_dir().join(format!(
            "agentplane-logkey-{}",
            agentplane::core::RunId::generate()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let seed = dir.join("log.seed");
        std::fs::write(&seed, "07".repeat(32)).expect("seed");
        let witness_key = format!(
            "w={}",
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                agentplane::policy::Ed25519Signer::new("w", &[9u8; 32]).verifying_key()
            )
        );
        let log_key = format!("log.example/plane={}", seed.display());
        let mut args = vec![
            "agentplane",
            "serve",
            "agent.yaml",
            "--witness-submit",
            "http://127.0.0.1:9",
            "--witness-key",
            &witness_key,
            "--log-key",
            &log_key,
        ];
        args.extend_from_slice(extra);
        match <super::Cli as clap::Parser>::try_parse_from(args)
            .expect("parses")
            .verb
        {
            super::Verb::Serve(opts) => *opts,
            _ => unreachable!("a serve line"),
        }
    }

    /// An interval shorter than the sweep that keeps it is refused, naming
    /// both; an externally run sweep owns the cadence.
    #[test]
    #[cfg(all(feature = "a2a-server", feature = "cedar"))]
    fn serve_refuses_an_interval_shorter_than_its_sweep() {
        let builder = || {
            agentplane::runtime::Runtime::builder(std::sync::Arc::new(
                agentplane::store::RedbStore::open_in_memory().expect("store"),
            )
                as std::sync::Arc<dyn agentplane::journal::JournalStore>)
        };
        let short = serve_witness_args(&["--sweep-every", "60", "--witness-interval", "30"]);
        let refused = super::with_submission_witnesses(builder(), &short)
            .expect_err("an interval the sweep cannot keep");
        assert!(
            refused.contains("30") && refused.contains("60"),
            "the refusal does not name both values: {refused}"
        );
        let external = serve_witness_args(&["--sweep-every", "0", "--witness-interval", "30"]);
        assert!(super::with_submission_witnesses(builder(), &external).is_ok());
    }

    /// A `serve`-built plane submits its checkpoint to its `--witness-submit`
    /// witnesses on the sweep: an unreachable one is a shortfall, not silence.
    #[test]
    #[cfg(all(feature = "a2a-server", feature = "cedar"))]
    fn serve_wires_its_submission_witnesses_into_the_sweep() {
        use agentplane::journal::JournalStore;

        const AGENT: &str = r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: summariser, version: "1.0.0" }
spec:
  execution: { kind: completion }
  identity: { role: "Summarise a support ticket" }
  capabilities: { provides: [support.summarise] }
  models:
    privileged: { provider: acme, model: sum-1 }
  budgets: { max_tokens: 10000 }
"#;
        let manifest = agentplane::manifest::Manifest::parse(AGENT).expect("parses");
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(async {
                let store = std::sync::Arc::new(
                    agentplane::store::RedbStore::open_in_memory().expect("store"),
                );
                agentplane::runtime::Runtime::builder(
                    std::sync::Arc::clone(&store) as std::sync::Arc<dyn JournalStore>
                )
                .provider("acme", agentplane::model::fake::FakeProvider::new())
                .agent(agentplane::runtime::Agent::new(&manifest))
                .build()
                .run(
                    "support.summarise",
                    agentplane::core::Tainted::trusted(serde_json::json!({ "t": 1 })),
                )
                .await
                .expect("a sealed run");

                let plane = super::with_submission_witnesses(
                    agentplane::runtime::Runtime::builder(
                        std::sync::Arc::clone(&store) as std::sync::Arc<dyn JournalStore>
                    ),
                    &serve_witness_args(&[]),
                )
                .expect("wired")
                .build();
                #[allow(clippy::disallowed_methods)]
                let now = agentplane::core::Timestamp::now_utc();
                let report = plane
                    .sweep(now, std::time::Duration::from_secs(60))
                    .await
                    .expect("a sweep");
                assert_eq!(
                    report.witness_shortfall, 1,
                    "serve's witnesses never reached the sweep: {report:?}"
                );
            });
    }

    /// Run one command line through this binary's own dispatch.
    fn cli(args: &[&str]) -> Result<std::process::ExitCode, Fault> {
        super::dispatch(<super::Cli as clap::Parser>::try_parse_from(args).expect("parses"))
    }

    /// **A halt thrown at the terminal stops a plane this binary builds.**
    ///
    /// `halt --store` writes to the quota store; a `run`, `serve` or resume
    /// that built its plane without that store admits straight past it.
    #[test]
    fn a_halt_thrown_at_the_terminal_refuses_a_run_on_the_same_store() {
        let dir = std::env::temp_dir().join(format!(
            "agentplane-halt-{}",
            agentplane::core::RunId::generate()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let store = dir.join("plane.redb");
        let store = store.to_str().expect("utf-8 path");
        let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/summariser.yaml");
        let input = r#"{"ticket":"printer on fire"}"#;

        cli(&[
            "agentplane",
            "run",
            manifest,
            "--input",
            input,
            "--store",
            store,
        ])
        .expect("an unhalted plane runs the example");
        cli(&[
            "agentplane",
            "halt",
            "--store",
            store,
            "--reason",
            "incident 7",
            "--actor",
            "ops",
        ])
        .expect("the halt is thrown");
        let refused = cli(&[
            "agentplane",
            "run",
            manifest,
            "--input",
            input,
            "--store",
            store,
        ])
        .expect_err("a run under a standing tenant halt must be refused at admission");
        assert!(
            refused.to_string().contains("halt"),
            "the refusal must name the halt: {refused}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A scratch store holding one case, and that case's id.
    fn store_with_a_case(tag: &str) -> (std::path::PathBuf, String, String) {
        use agentplane::case::CaseStore;

        let dir = std::env::temp_dir().join(format!(
            "agentplane-{tag}-{}",
            agentplane::core::RunId::generate()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let path = dir.join("plane.redb");
        let store = path.to_str().expect("utf-8 path").to_owned();
        let case = {
            let cases = agentplane::store::RedbStore::open(&store).expect("store");
            tokio::runtime::Builder::new_current_thread()
                .build()
                .expect("runtime")
                .block_on(
                    cases.correlate_or_open(
                        "matter",
                        &[agentplane::core::CorrelationKey::new("matter", "M-1")],
                        agentplane::core::Timestamp::from_unix_timestamp(1_700_000_000)
                            .expect("an instant"),
                    ),
                )
                .expect("a case")
                .case_id()
                .to_string()
        };
        (dir, store, case)
    }

    /// The first record of every run sealed under `outcome` in `store`.
    fn lift_records(store: &str, outcome: &str) -> Vec<agentplane::journal::RecordKind> {
        use agentplane::journal::JournalStore;

        let journal = agentplane::store::RedbStore::open(store).expect("store");
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime")
            .block_on(async {
                let mut kinds = Vec::new();
                for run in journal.runs_by_outcome(outcome, 100).await.expect("index") {
                    let page = journal.read_page(run, 1, 1).await.expect("records");
                    kinds.extend(page.into_iter().map(|r| r.kind().clone()));
                }
                kinds
            })
    }

    /// **A lift at the terminal is recorded under `--actor`, as asserted**, and
    /// the history listings read it back.
    #[test]
    fn a_terminal_lift_is_recorded_as_asserted() {
        let (dir, store, case) = store_with_a_case("lift");
        let store = store.as_str();
        cli(&[
            "agentplane",
            "halt",
            "--store",
            store,
            "--reason",
            "incident 7",
            "--actor",
            "ops",
        ])
        .expect("the halt is thrown");
        cli(&[
            "agentplane",
            "hold",
            "--store",
            store,
            "--case",
            &case,
            "--reason",
            "order 9",
            "--actor",
            "ops",
        ])
        .expect("the hold is placed");

        assert_eq!(
            cli(&[
                "agentplane",
                "halt",
                "--store",
                store,
                "--lift",
                "--actor",
                "ops-erin"
            ])
            .expect("the halt is lifted"),
            std::process::ExitCode::SUCCESS
        );
        assert_eq!(
            cli(&[
                "agentplane",
                "hold",
                "--store",
                store,
                "--case",
                &case,
                "--lift",
                "--actor",
                "ops-erin",
            ])
            .expect("the hold is released"),
            std::process::ExitCode::SUCCESS
        );

        let lifts = lift_records(store, "halt-lifted");
        assert_eq!(lifts.len(), 1, "{lifts:?}");
        let agentplane::journal::RecordKind::HaltLifted { by, thrown_by, .. } = &lifts[0] else {
            panic!("a lift run holds a lift record: {lifts:?}");
        };
        assert_eq!((by.actor(), by.basis().as_str()), ("ops-erin", "asserted"));
        assert_eq!(thrown_by.actor(), "ops");
        let releases = lift_records(store, "hold-released");
        assert_eq!(releases.len(), 1, "{releases:?}");
        let agentplane::journal::RecordKind::HoldReleased { by, .. } = &releases[0] else {
            panic!("a release run holds a release record: {releases:?}");
        };
        assert_eq!((by.actor(), by.basis().as_str()), ("ops-erin", "asserted"));

        the_histories_list(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Both histories list in full under the default page, and exit partial
    /// under a page shorter than the one lift and one release `store` holds.
    fn the_histories_list(store: &str) {
        for args in [
            &["agentplane", "halt", "list", "--store", store, "--lifted"][..],
            &[
                "agentplane",
                "halt",
                "list",
                "--store",
                store,
                "--lifted",
                "--json",
            ][..],
            &["agentplane", "hold", "list", "--store", store, "--released"][..],
        ] {
            assert_eq!(
                cli(args).expect("the history lists"),
                std::process::ExitCode::SUCCESS,
                "{args:?}"
            );
        }
        // A page shorter than the history is a partial answer.
        for args in [
            &[
                "agentplane",
                "halt",
                "list",
                "--store",
                store,
                "--lifted",
                "--limit",
                "0",
            ][..],
            &[
                "agentplane",
                "hold",
                "list",
                "--store",
                store,
                "--released",
                "--limit",
                "0",
            ][..],
        ] {
            assert_eq!(
                cli(args).expect("the history lists"),
                std::process::ExitCode::from(exit::PARTIAL),
                "{args:?}"
            );
        }
    }

    /// **A lift at the terminal with no `--actor` is refused** before the
    /// store is touched: the halt and the hold still stand, and nothing is
    /// recorded.
    #[test]
    fn a_terminal_lift_without_an_actor_is_refused() {
        use agentplane::case::CaseStore;
        use agentplane::quota::QuotaStore;

        let (dir, store, case) = store_with_a_case("unattributed");
        let store = store.as_str();
        cli(&[
            "agentplane",
            "halt",
            "--store",
            store,
            "--reason",
            "incident 7",
            "--actor",
            "ops",
        ])
        .expect("the halt is thrown");
        cli(&[
            "agentplane",
            "hold",
            "--store",
            store,
            "--case",
            &case,
            "--reason",
            "order 9",
            "--actor",
            "ops",
        ])
        .expect("the hold is placed");

        for args in [
            &["agentplane", "halt", "--store", store, "--lift"][..],
            &[
                "agentplane",
                "hold",
                "--store",
                store,
                "--case",
                &case,
                "--lift",
            ][..],
        ] {
            let refused = cli(args).expect_err("a lift nobody is named for");
            assert!(
                matches!(refused, Fault::Usage(_)) && refused.to_string().contains("--actor"),
                "{args:?}: {refused}"
            );
        }

        let plane = agentplane::store::RedbStore::open(store).expect("store");
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime")
            .block_on(async {
                assert_eq!(
                    plane.halts().await.expect("halts").len(),
                    1,
                    "the halt stands"
                );
                let id = agentplane::core::CaseId::parse(&case).expect("case id");
                assert!(
                    plane.hold(id).await.expect("hold").is_some(),
                    "the hold stands"
                );
            });
        drop(plane);
        assert!(lift_records(store, "halt-lifted").is_empty());
        assert!(lift_records(store, "hold-released").is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **`content check` answers with the runtime's own evaluator**: exit 1
    /// when a rule would refuse the value, 0 when none would, and a usage
    /// error for a boundary it cannot name.
    #[test]
    fn content_check_exits_on_what_a_rule_would_refuse() {
        let dir = std::env::temp_dir().join(format!(
            "agentplane-content-{}",
            agentplane::core::RunId::generate()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let manifest = dir.join("agent.yaml");
        std::fs::write(
            &manifest,
            "apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: ruled, version: \"1.0.0\" }
spec:
  capabilities: { provides: [work.do] }
  budgets: {}
  security:
    content:
      rules:
        - id: codename
          match: {contains: [falcon], case: fold}
          at: {sinks: [model.complete]}
          then: refuse
",
        )
        .expect("manifest");
        let check = |value: &str, at: &str| {
            let path = dir.join("value.json");
            std::fs::write(&path, value).expect("value");
            cli(&[
                "agentplane",
                "content",
                "check",
                manifest.to_str().expect("utf-8"),
                "--at",
                at,
                "--value",
                path.to_str().expect("utf-8"),
            ])
        };
        assert_eq!(
            check(r#"{"q": "Falcon"}"#, "sink:model.complete").expect("judged"),
            std::process::ExitCode::from(exit::FINDING)
        );
        assert_eq!(
            check(r#"{"q": "Falcon"}"#, "sink:tool.call").expect("judged"),
            std::process::ExitCode::SUCCESS,
            "a rule applies only where it is declared"
        );
        assert!(matches!(
            check(r#"{"q": "x"}"#, "outbound"),
            Err(Fault::Usage(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **A listing cut short by `--limit` exits partial.** The help table says
    /// 5 means exactly this, and a script reading exit 0 takes the page for
    /// the whole worklist.
    #[test]
    fn a_listing_cut_short_by_its_limit_exits_partial() {
        use agentplane::case::TaskStore;

        let dir = std::env::temp_dir().join(format!(
            "agentplane-listing-{}",
            agentplane::core::RunId::generate()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let path = dir.join("plane.redb");
        let store = path.to_str().expect("utf-8 path");
        {
            let tasks = agentplane::store::RedbStore::open(store).expect("store");
            tokio::runtime::Builder::new_current_thread()
                .build()
                .expect("runtime")
                .block_on(async {
                    for summary in ["first", "second"] {
                        tasks
                            .open(&listed(summary, serde_json::json!({}), None))
                            .await
                            .expect("opened");
                    }
                });
        }
        let status = |limit: &str| {
            cli(&["agentplane", "tasks", "--store", store, "--limit", limit]).expect("listed")
        };
        assert_eq!(
            status("1"),
            std::process::ExitCode::from(exit::PARTIAL),
            "a page of one over two tasks is a partial answer"
        );
        assert_eq!(status("2"), std::process::ExitCode::SUCCESS);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **A decision naming a version the task no longer holds is refused at
    /// the terminal**: exit 1, and the task is still open. A digest that is
    /// not one is a usage error.
    #[test]
    fn a_stale_digest_at_the_terminal_is_refused() {
        use agentplane::case::TaskStore;

        let dir = std::env::temp_dir().join(format!(
            "agentplane-stale-{}",
            agentplane::core::RunId::generate()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let path = dir.join("plane.redb");
        let store = path.to_str().expect("utf-8 path");
        let task = listed("Refund the invoice", serde_json::json!({}), None);
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        {
            let tasks = agentplane::store::RedbStore::open(store).expect("store");
            rt.block_on(tasks.open(&task)).expect("opened");
        }
        let id = task.id.to_string();
        let decide = |digest: &str| {
            cli(&[
                "agentplane",
                "decide",
                &id,
                "reject",
                "--reason",
                "no",
                "--actor",
                "ops",
                "--store",
                store,
                "--digest",
                digest,
            ])
        };

        let stale = agentplane::core::Digest::of(b"another version").to_hex();
        assert_eq!(
            decide(&stale).expect("a refusal, not a fault"),
            std::process::ExitCode::from(exit::FINDING)
        );
        let tasks = agentplane::store::RedbStore::open(store).expect("store");
        let after = rt.block_on(tasks.task(task.id)).unwrap().unwrap();
        assert!(
            after.state.is_pending() && after.assignee.is_none(),
            "{after:?}"
        );
        drop(tasks);

        assert!(matches!(decide("not-hex"), Err(Fault::Usage(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **Every plane this binary builds comes from one door.**
    ///
    /// [`super::Backend::plane`] is what binds a plane to the operator's
    /// backend and tenant. A second builder in this file is a verb whose plane
    /// can sit on other stores or another tenant — or, started from the
    /// journal alone, on no quota store, where the operator's halts do not
    /// reach.
    #[test]
    fn every_plane_this_binary_builds_comes_through_backend_plane() {
        let source = include_str!("agentplane.rs");
        let body = source
            .split("#[cfg(test)]\nmod tests {")
            .next()
            .expect("the file has a body");
        assert_eq!(
            body.matches("Runtime::builder_with(").count(),
            1,
            "only Backend::plane may start a runtime builder"
        );
        for other in ["Runtime::builder(", "Runtime::builder_on("] {
            assert_eq!(
                body.matches(other).count(),
                0,
                "only Backend::plane may start a runtime builder, and {other} does"
            );
        }
    }

    /// A task for the terminal tests, proposing `proposed` under `summary`.
    fn listed(
        summary: &str,
        proposed: serde_json::Value,
        withheld: Option<agentplane::core::Withheld>,
    ) -> agentplane::core::Task {
        use agentplane::core::{
            EffectDescriptor, EffectKey, Justification, OnExpiry, Phase, Priority, RunId, StepId,
            Tainted, Task, TaskId, TaskState,
        };
        let run = RunId::generate();
        Task {
            id: TaskId::derive(
                run,
                EffectKey::for_effect(
                    StepId(0),
                    Phase::Forward,
                    0,
                    1,
                    &EffectDescriptor::new("approval", serde_json::json!({})),
                ),
            ),
            run,
            case: None,
            kind: "approval".into(),
            justification: Justification::new(Tainted::trusted(summary.to_owned()), proposed),
            candidate_roles: Vec::new(),
            escalate_to: Vec::new(),
            assignee: None,
            priority: Priority::Normal,
            state: TaskState::Open,
            on_expiry: OnExpiry::Deny,
            excluded_actors: Vec::new(),
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            due_at: None,
            withheld,
        }
    }

    /// **The terminal shows a withheld proposal as withheld.**
    ///
    /// This binary holds no key ring, so on a sealed plane every proposal it
    /// reads is an envelope. Printing that as `proposed_action` hands the
    /// person at the terminal a value that is not the arguments; the reason
    /// is printed instead.
    #[test]
    fn the_terminal_shows_a_withheld_proposal_as_withheld() {
        let task = listed(
            "Refund the invoice",
            serde_json::json!({ "$sealed": "AAECAwQFBgc=" }),
            Some(agentplane::core::Withheld::Sealed),
        );
        let shown = super::task_json(&task, true);
        assert_eq!(shown["proposed_action"], serde_json::Value::Null, "{shown}");
        // The version of the stored row, not of what is shown.
        assert_eq!(
            shown["digest"],
            task.justification.digest().to_hex(),
            "{shown}"
        );
        assert!(
            shown["withheld"]
                .as_str()
                .is_some_and(|w| w.starts_with("sealed") && w.contains("no key ring")),
            "{shown}"
        );
        assert!(!shown.to_string().contains("$sealed"), "{shown}");
    }

    /// **The terminal escapes what a reviewer cannot see.**
    ///
    /// A JSON printer passes a right-to-left override through verbatim, and
    /// the terminal then reverses the digits after it. The terminal prints
    /// the same rendering the HTTP worklist serves.
    #[test]
    fn the_terminal_escapes_what_a_reviewer_cannot_see() {
        let task = listed(
            "Pay\u{200B} the vendor",
            serde_json::json!({ "amount": "\u{202E}0001" }),
            None,
        );
        let shown = super::task_json(&task, false);
        assert_eq!(shown["escaped"], true, "{shown}");
        assert_eq!(
            shown["proposed_action"]["amount"], "\\u{202E}0001",
            "{shown}"
        );
        let printed = shown.to_string();
        assert!(
            !printed.contains('\u{202E}') && !printed.contains('\u{200B}'),
            "{printed}"
        );
    }

    /// **`--mcp-agent` chooses what the MCP listener serves**, so one agent
    /// with no `spec.input` in the file is left off rather than failing the
    /// whole listener — and a name that matches nothing is refused, never an
    /// empty catalogue.
    #[cfg(all(feature = "a2a-server", feature = "cedar", feature = "mcp-server-http"))]
    #[test]
    fn mcp_agent_serves_only_the_agents_it_names() {
        let agent = |name: &str| {
            agentplane::manifest::Manifest::parse(&format!(
                "apiVersion: agentplane.hupe1980.github.io/v1alpha1\n\
                 kind: Agent\n\
                 metadata: {{ name: {name}, version: \"1.0.0\" }}\n\
                 spec:\n  identity: {{ role: r }}\n  capabilities: {{ provides: [{name}.do] }}\n  budgets: {{}}\n"
            ))
            .expect("manifest")
        };
        let file = [agent("triage"), agent("specialist")];
        let all = super::mcp_served(&file, &[]).expect("every agent");
        assert_eq!(all.len(), 2, "no --mcp-agent must serve every agent");
        let one = super::mcp_served(&file, &["triage".to_owned()]).expect("one agent");
        assert_eq!(
            one.iter()
                .map(|m| m.metadata.name.as_str())
                .collect::<Vec<_>>(),
            ["triage"],
            "--mcp-agent served an agent it did not name"
        );
        let unknown = super::mcp_served(&file, &["nobody".to_owned()]);
        assert!(
            unknown.is_err_and(|e| e.contains("nobody")),
            "a name matching no agent was not refused"
        );
        let refusal = super::mcp_refusal(&agentplane::tools::serve::ServeError::NoInputSchema {
            agent: "specialist".into(),
            capability: "specialist.do".into(),
        });
        assert!(
            refusal.contains("--mcp-agent"),
            "the refusal does not name what this command can do: {refusal}"
        );
    }

    /// A fresh, empty directory for `init --serve` to write into.
    #[cfg(all(feature = "a2a-server", feature = "cedar", feature = "mcp-server-http"))]
    fn served_dir(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "agentplane-served-{name}-{}",
            agentplane::core::RunId::generate()
        ))
    }

    /// The tokens a token file holds, in file order.
    #[cfg(all(feature = "a2a-server", feature = "cedar", feature = "mcp-server-http"))]
    fn tokens_in(file: &str) -> Vec<(String, String)> {
        let entries: Vec<serde_json::Value> = serde_yaml_ng::from_str(file).expect("yaml");
        entries
            .iter()
            .map(|e| {
                (
                    e["actor"].as_str().expect("actor").to_owned(),
                    e["token"].as_str().expect("token").to_owned(),
                )
            })
            .collect()
    }

    /// **The starter's credentials are fresh, distinct, accepted, and private.**
    ///
    /// A token this project printed is a token every reader holds, so each run
    /// generates its own from the operating system; and the file is not
    /// world-readable, because the token file is the plane's whole notion of
    /// who is calling.
    #[cfg(all(feature = "a2a-server", feature = "cedar", feature = "mcp-server-http"))]
    #[test]
    fn init_serve_writes_three_distinct_accepted_tokens() {
        let dir = served_dir("tokens");
        let served = super::init_serve(&dir).expect("an empty directory");
        let again = super::init_serve(&served_dir("again")).expect("a second plane");
        for name in super::SERVED_FILES {
            assert!(dir.join(name).is_file(), "{name} was not written");
        }
        let file = std::fs::read_to_string(dir.join("tokens.yaml")).unwrap();
        agentplane::api::tokens::TokenAuthenticator::from_yaml(&file).expect("serve accepts it");
        let tokens = tokens_in(&file);
        let actors: Vec<&str> = tokens.iter().map(|(a, _)| a.as_str()).collect();
        assert_eq!(actors, ["peer-1", "framework-1", "ops-1"]);
        assert!(tokens.iter().all(|(_, t)| t.len() >= 64), "{tokens:?}");
        let other = std::fs::read_to_string(
            again
                .paths
                .iter()
                .find(|p| p.ends_with("tokens.yaml"))
                .unwrap(),
        )
        .unwrap();
        let distinct: std::collections::BTreeSet<String> = tokens
            .iter()
            .chain(&tokens_in(&other))
            .map(|(_, t)| t.clone())
            .collect();
        assert_eq!(distinct.len(), 6, "a token repeats across two planes");
        assert_eq!(
            std::fs::read_to_string(dir.join("framework.token")).unwrap(),
            tokens[1].1,
            "framework.token is not the framework caller's token"
        );
        #[cfg(unix)]
        for name in [
            "tokens.yaml",
            "framework.token",
            "postgres.password",
            "store.env",
        ] {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(dir.join(name))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{name} is mode {mode:o}");
        }
        for json in [false, true] {
            let printed = super::served_report(&served, json);
            assert!(printed.contains(&served.digest) && printed.contains("compose.yaml"));
            for (_, token) in &tokens {
                assert!(!printed.contains(token.as_str()), "a token was printed");
            }
        }
    }

    /// **`init --serve` writes nothing when any of its files exists.**
    ///
    /// Each target is pre-created in turn; the refusal names it, its bytes are
    /// untouched, and no other file appears.
    #[cfg(all(feature = "a2a-server", feature = "cedar", feature = "mcp-server-http"))]
    #[test]
    fn init_serve_refuses_and_writes_nothing_when_a_file_exists() {
        for name in super::SERVED_FILES {
            let dir = served_dir("refused");
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(name), "reviewed\n").unwrap();
            let err = super::init_serve(&dir).expect_err("an existing file");
            assert!(err.to_string().contains(name), "{err}");
            // Refused before anything is generated, and told so.
            assert!(err.to_string().contains("so nothing was written"), "{err}");
            assert_eq!(
                std::fs::read_to_string(dir.join(name)).unwrap(),
                "reviewed\n"
            );
            let present: Vec<String> = std::fs::read_dir(&dir)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            assert_eq!(present, [name], "a refused init --serve wrote {present:?}");
        }
    }

    /// **The written policy is the shipped file**, not a second bundle beside
    /// it; the manifest validates; the compose file runs this version.
    #[cfg(all(feature = "a2a-server", feature = "cedar", feature = "mcp-server-http"))]
    #[test]
    fn init_serve_writes_the_shipped_policy() {
        let dir = served_dir("policy");
        super::init_serve(&dir).expect("an empty directory");
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        assert_eq!(
            std::fs::read(dir.join("policy.cedar")).unwrap(),
            std::fs::read(root.join("examples/serve-policy.cedar")).unwrap(),
            "init --serve wrote a policy that is not the shipped bundle"
        );
        let manifest = std::fs::read_to_string(dir.join("agent.yaml")).unwrap();
        let parsed = agentplane::manifest::Manifest::parse_all(&manifest).expect("it parses");
        super::mcp_served(&parsed, &[]).expect("the MCP listener serves it");
        let compose = std::fs::read_to_string(dir.join("compose.yaml")).unwrap();
        assert!(
            compose.contains(&format!("agentplane:{}-full", env!("CARGO_PKG_VERSION"))),
            "the compose file does not run this version"
        );
        assert!(!compose.contains("PLANE_USER") && !compose.contains("AGENTPLANE_VERSION"));
    }

    /// **The starter's Postgres takes a generated password, carried by files.**
    ///
    /// A network marked internal still gives a Linux host an address on its
    /// bridge, so a passwordless Postgres is one any local process reaches as
    /// the superuser. The password is in no command line and the compose file
    /// holds no secret; every port is published on loopback.
    #[cfg(all(feature = "a2a-server", feature = "cedar", feature = "mcp-server-http"))]
    #[test]
    fn init_serve_gives_postgres_a_password_off_the_command_line() {
        let dir = served_dir("password");
        super::init_serve(&dir).expect("an empty directory");
        let password = std::fs::read_to_string(dir.join("postgres.password")).unwrap();
        let password = password.trim();
        assert!(password.len() >= 64, "{password:?}");
        let store = std::fs::read_to_string(dir.join("store.env")).unwrap();
        assert!(
            store.contains(&format!(
                "AGENTPLANE_STORE=postgres://agentplane:{password}@postgres:5432/"
            )),
            "store.env does not connect with the generated password: {store}"
        );
        let compose = std::fs::read_to_string(dir.join("compose.yaml")).unwrap();
        let yaml: serde_json::Value = serde_yaml_ng::from_str(&compose).expect("yaml");
        let postgres = &yaml["services"]["postgres"];
        assert_eq!(
            postgres["environment"]["POSTGRES_PASSWORD_FILE"], "/run/secrets/postgres_password",
            "{postgres}"
        );
        assert!(
            postgres["environment"]["POSTGRES_HOST_AUTH_METHOD"].is_null(),
            "{postgres}"
        );
        assert_eq!(
            yaml["secrets"]["postgres_password"]["file"], "./postgres.password",
            "{yaml}"
        );
        let plane = &yaml["services"]["plane"];
        assert_eq!(plane["env_file"][0], "./store.env", "{plane}");
        let command = plane["command"].to_string();
        assert!(
            !command.contains("--store") && !command.contains("postgres://"),
            "{command}"
        );
        assert!(
            !compose.contains(password),
            "the compose file holds the password"
        );
        for port in plane["ports"].as_array().expect("published ports") {
            let port = port.as_str().expect("a short-syntax port");
            assert!(
                port.starts_with("127.0.0.1:"),
                "{port} is published beyond loopback"
            );
        }
    }

    /// **The plane runs as the token file's owner, and never as root.**
    ///
    /// The token file is mode 0600, so the container must run as its owner to
    /// read it; root would read it, and run the plane as root.
    #[cfg(all(feature = "a2a-server", feature = "cedar", feature = "mcp-server-http"))]
    #[test]
    fn init_serve_runs_the_plane_as_the_token_files_owner_and_never_root() {
        let err = super::plane_user(0, 0).expect_err("root");
        assert!(err.to_string().contains("--user"), "{err}");
        assert_eq!(super::plane_user(1000, 1000).unwrap(), "1000:1000");
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let dir = served_dir("owner");
            super::init_serve(&dir).expect("an empty directory");
            let meta = std::fs::metadata(dir.join("tokens.yaml")).unwrap();
            let compose = std::fs::read_to_string(dir.join("compose.yaml")).unwrap();
            let user = format!("user: \"{}:{}\"", meta.uid(), meta.gid());
            assert!(
                compose.contains(&user),
                "the compose file does not hold {user}"
            );
        }
    }

    /// **A failed `init --serve` leaves nothing behind.**
    ///
    /// Files written before the failure are removed, so a re-run is not refused
    /// over the remains of the attempt that failed.
    #[cfg(all(feature = "a2a-server", feature = "cedar", feature = "mcp-server-http"))]
    #[test]
    fn a_failed_init_serve_removes_what_it_wrote() {
        let dir = served_dir("partial");
        std::fs::create_dir_all(&dir).unwrap();
        {
            let mut written = super::Written::default();
            written
                .create(&dir, "agent.yaml", "a\n", false)
                .expect("the first file");
            written
                .create(&dir, "tokens.yaml", "t\n", true)
                .expect("the second file");
            written
                .create(&dir, "no-such-dir/compose.yaml", "c\n", false)
                .expect_err("a file under a missing directory");
        }
        let present: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
        assert!(present.is_empty(), "a failed init --serve left {present:?}");
        super::init_serve(&dir).expect("a re-run after the failure");
    }

    /// **`serve` refuses a `--url` that is not the A2A endpoint.**
    ///
    /// The card publishes the URL verbatim and A2A is served at `/a2a` only, so
    /// a bare host would answer every client that follows the card with `404`.
    #[cfg(all(feature = "a2a-server", feature = "cedar"))]
    #[test]
    fn serve_refuses_a_url_that_is_not_the_a2a_endpoint() {
        for (bare, fix) in [
            ("https://agent.example.com", "https://agent.example.com/a2a"),
            (
                "https://agent.example.com/",
                "https://agent.example.com/a2a",
            ),
            ("http://h:8080/a2a/", "http://h:8080/a2a"),
        ] {
            let err = super::a2a_endpoint(bare).expect_err(bare);
            assert!(err.to_string().ends_with(&format!("--url {fix}")), "{err}");
        }
        assert_eq!(
            super::a2a_endpoint("http://localhost:8080/a2a").unwrap(),
            "http://localhost:8080/a2a"
        );
    }

    /// A fresh directory under the system temp dir.
    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "agentplane-{name}-{}",
            agentplane::core::RunId::generate()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    /// The runs a store concluded as `succeeded`.
    fn succeeded_in(store: &str) -> Vec<agentplane::core::RunId> {
        let journal = agentplane::store::RedbStore::open(store).expect("store");
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime")
            .block_on(agentplane::journal::JournalStore::runs_by_outcome(
                &journal,
                "succeeded",
                10,
            ))
            .expect("listed")
    }

    /// **`history` prints a recorded string escaped**, one line per record
    /// in sequence order; `--from` starts there; an unknown run exits 1
    /// whatever `--from` names.
    #[test]
    fn history_prints_a_hostile_record_escaped() {
        let dir = temp_dir("history");
        let path = dir.join("plane.redb");
        let store = path.to_str().expect("utf-8 path");
        let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/summariser.yaml");
        let hostile =
            "\u{1b}]52;c;ZXZpbA==\u{7}\u{9b}31m<img src=x onerror=alert(1)>\u{202E}gnp.exe";
        let input = serde_json::json!({ "ticket": hostile }).to_string();
        cli(&[
            "agentplane",
            "run",
            manifest,
            "--input",
            &input,
            "--store",
            store,
        ])
        .expect("the example runs");
        let run = succeeded_in(store)[0];

        let journal: Arc<dyn agentplane::journal::JournalStore> =
            Arc::new(agentplane::store::RedbStore::open(store).expect("store"));
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        let lines = rt
            .block_on(super::history_lines(&journal, run, None, false))
            .expect("read")
            .expect("the run exists");
        assert!(lines.len() >= 2, "{lines:?}");
        let seqs: Vec<u64> = lines
            .iter()
            .map(|l| l.split_whitespace().next().unwrap().parse().unwrap())
            .collect();
        assert!(seqs.windows(2).all(|w| w[1] == w[0] + 1), "{seqs:?}");
        let printed = lines.join("\n");
        assert!(
            printed.contains("\\u{202E}gnp.exe"),
            "the bidi override was not shown escaped: {printed}"
        );
        for raw in ['\u{1b}', '\u{7}', '\u{9b}', '\u{202E}'] {
            assert!(
                !printed.contains(raw),
                "U+{:04X} reached the terminal raw",
                raw as u32
            );
        }

        let later = rt
            .block_on(super::history_lines(&journal, run, Some(2), false))
            .expect("read")
            .expect("the run exists");
        assert!(later[0].trim_start().starts_with("2 "), "{later:?}");
        let unknown = agentplane::core::RunId::generate();
        for from in [None, Some(2)] {
            assert!(
                rt.block_on(super::history_lines(&journal, unknown, from, false))
                    .expect("read")
                    .is_none(),
                "an unknown run read from {from:?} was answered as one that exists"
            );
        }
        assert!(
            rt.block_on(super::history_lines(&journal, run, Some(1_000), false))
                .expect("read")
                .is_some_and(|lines| lines.is_empty()),
            "a reader past the end of a run that exists was told it does not"
        );
        drop(journal);
        assert_eq!(
            cli(&[
                "agentplane",
                "history",
                &unknown.to_string(),
                "--store",
                store
            ])
            .expect("an answer"),
            std::process::ExitCode::from(exit::FINDING)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **`dev` opens only memory or a directory it created**, following no
    /// link and trusting no marker but its own exact bytes.
    #[cfg(feature = "dev")]
    #[test]
    fn dev_refuses_a_store_it_did_not_create() {
        let refused = |scratch: Option<&str>, tenant: Option<&str>| {
            matches!(super::dev_store(scratch, tenant), Err(Fault::Usage(_)))
        };
        assert!(refused(Some("postgres://ops@db/plane"), None));
        assert!(refused(None, Some("acme")));

        let deployed = temp_dir("dev-deployed");
        // Named as a dev store would be, so only the missing marker refuses it.
        let file = deployed.join("dev.redb");
        drop(agentplane::store::RedbStore::open(&file).expect("a deployment's store"));
        assert!(refused(file.to_str(), None), "a redb file was opened");
        assert!(
            refused(deployed.to_str(), None),
            "an unmarked directory was opened"
        );
        assert_eq!(
            std::fs::read_dir(&deployed).unwrap().count(),
            1,
            "a refused directory was written to"
        );

        let scratch = temp_dir("dev-scratch");
        let scratch = scratch.to_str().expect("utf-8 path");
        drop(super::dev_store(Some(scratch), Some("dev")).expect("an empty directory opens"));
        drop(super::dev_store(Some(scratch), None).expect("a marked directory reopens"));
        #[cfg(unix)]
        {
            let linked = temp_dir("dev-linked");
            let link = linked.join("scratch");
            std::os::unix::fs::symlink(scratch, &link).expect("a link");
            assert!(
                refused(link.to_str(), None),
                "a symbolic link to a marked directory was followed"
            );
            let store = std::path::Path::new(scratch).join("dev.redb");
            std::fs::remove_file(&store).expect("the dev store");
            std::os::unix::fs::symlink(&file, &store).expect("a link");
            assert!(
                refused(Some(scratch), None),
                "a dev.redb linking to a deployment's store was opened"
            );
            std::fs::remove_file(&store).expect("the link");
            let _ = std::fs::remove_dir_all(&linked);
        }
        let marker = std::path::Path::new(scratch).join(".agentplane-dev");
        std::fs::write(&marker, "").expect("an empty marker");
        assert!(
            refused(Some(scratch), None),
            "a marker without the exact bytes dev writes was accepted"
        );
        std::fs::write(&marker, super::DEV_MARKER_TEXT).expect("the marker");
        drop(super::dev_store(Some(scratch), None).expect("a marked directory reopens"));
        std::fs::write(std::path::Path::new(scratch).join("other"), "x").unwrap();
        assert!(
            refused(Some(scratch), None),
            "a marked directory holding more was opened"
        );
        let _ = std::fs::remove_dir_all(&deployed);
        let _ = std::fs::remove_dir_all(scratch);
    }

    /// **`--mcp` and `--peer` are refused without `--allow-live`.**
    #[cfg(feature = "dev")]
    #[test]
    fn dev_refuses_live_transports_without_consent() {
        let args = |extra: &[&str]| {
            let mut line = vec!["agentplane", "dev", "agent.yaml"];
            line.extend_from_slice(extra);
            match <super::Cli as clap::Parser>::try_parse_from(line)
                .expect("parses")
                .verb
            {
                super::Verb::Dev(args) => args,
                other => panic!("parsed as {other:?}"),
            }
        };
        for extra in [
            &["--mcp", "files=mcp-files"][..],
            &[
                "--peer",
                "billing=https://billing.example/a2a",
                "--acting-as",
                "ada",
            ][..],
        ] {
            let refused = super::refuse_live_without_consent(&args(extra))
                .expect_err("a live transport without consent");
            assert!(refused.to_string().contains("--allow-live"), "{refused}");
            let mut consented = extra.to_vec();
            consented.push("--allow-live");
            super::refuse_live_without_consent(&args(&consented)).expect("consented");
        }
        super::refuse_live_without_consent(&args(&[])).expect("nothing live");
    }

    /// **The dev listener is bound to loopback.**
    #[cfg(feature = "dev")]
    #[test]
    fn the_dev_listener_binds_loopback_only() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let listener = rt.block_on(super::bind_dev(0)).expect("bound");
        let addr = listener.local_addr().expect("an address");
        assert!(addr.ip().is_loopback(), "the dev page listens on {addr}");
        assert_ne!(addr.port(), 0);
    }

    #[cfg(feature = "dev")]
    const DEV_PORT: u16 = 47_312;
    #[cfg(feature = "dev")]
    const DEV_TOKEN: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    /// A dev session over memory, as `dev` builds it.
    #[cfg(feature = "dev")]
    async fn dev_session(
        manifest: &str,
    ) -> (axum::Router, Arc<dyn agentplane::journal::JournalStore>) {
        dev_session_as(manifest, None).await
    }

    /// A dev session over memory, acting as `acting_as` when one is named.
    #[cfg(feature = "dev")]
    async fn dev_session_as(
        manifest: &str,
        acting_as: Option<&str>,
    ) -> (axum::Router, Arc<dyn agentplane::journal::JournalStore>) {
        let backend = super::dev_store(None, None).expect("memory");
        let journal = backend.journal();
        let manifests = super::manifests_at(manifest).expect("the manifest");
        let bench = super::dev::Bench::start(
            backend,
            super::dev::Wiring {
                file: manifest.to_owned(),
                mcp: Vec::new(),
                peer: Vec::new(),
                acting_as: acting_as.map(str::to_owned),
                policy: Arc::new(agentplane::api::dev::DevPolicy::new("dev:author")),
            },
            manifests,
        )
        .await
        .expect("the plane builds");
        let auth = agentplane::api::tokens::TokenAuthenticator::new(vec![
            agentplane::api::tokens::TokenEntry {
                token: DEV_TOKEN.to_owned(),
                actor: "dev:author".to_owned(),
                roles: Vec::new(),
                tenant: Some("dev".to_owned()),
                scope: None,
                not_after: None,
            },
        ])
        .expect("tokens");
        (
            agentplane::api::dev::router(Arc::new(bench), Arc::new(auth), DEV_PORT),
            journal,
        )
    }

    /// One request from the page's own tab, and its JSON answer.
    #[cfg(feature = "dev")]
    async fn page(
        router: &axum::Router,
        method: &str,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> (u16, serde_json::Value) {
        use tower::ServiceExt as _;
        let request = axum::http::Request::builder()
            .method(method)
            .uri(path)
            .header("host", format!("127.0.0.1:{DEV_PORT}"))
            .header("origin", format!("http://127.0.0.1:{DEV_PORT}"))
            .header("authorization", format!("Bearer {DEV_TOKEN}"))
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                body.map(|b| b.to_string()).unwrap_or_default(),
            ))
            .expect("a request");
        let response = router.clone().oneshot(request).await.expect("an answer");
        let status = response.status().as_u16();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("a body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    /// Every record the history route serves for `run`, paged with `?from=`.
    #[cfg(feature = "dev")]
    async fn served_history(router: &axum::Router, run: &str) -> Vec<serde_json::Value> {
        let mut records = Vec::new();
        let mut from = 1;
        loop {
            let (status, page_) = page(
                router,
                "GET",
                &format!("/api/runs/{run}/history?from={from}"),
                None,
            )
            .await;
            assert_eq!(status, 200, "{page_}");
            for record in page_["records"].as_array().expect("records") {
                records.push(record.clone());
            }
            match page_["next_from"].as_u64() {
                Some(next) => from = next,
                None => return records,
            }
        }
    }

    /// **`history --json` prints what the history route serves.**
    #[cfg(feature = "dev")]
    #[test]
    fn history_json_is_the_history_routes_records() {
        let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/summariser.yaml");
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(async {
                let (router, journal) = dev_session(manifest).await;
                let (status, started) = page(
                    &router,
                    "POST",
                    "/dev/runs",
                    Some(serde_json::json!({ "input": { "ticket": "printer\u{202E} on fire" } })),
                )
                .await;
                assert_eq!(status, 200, "{started}");
                let run_text = started["run"].as_str().expect("a run").to_owned();
                let run = agentplane::core::RunId::parse(&run_text).expect("a run id");
                let served = served_history(&router, &run_text).await;
                let printed: Vec<serde_json::Value> =
                    super::history_lines(&journal, run, None, true)
                        .await
                        .expect("read")
                        .expect("the run exists")
                        .iter()
                        .map(|l| serde_json::from_str(l).expect("one JSON object per line"))
                        .collect();
                assert!(!printed.is_empty());
                assert_eq!(printed, served);
            });
    }

    /// **The page's timeline shows a hidden character escaped**, as
    /// `history` prints it, and otherwise the records the history route
    /// serves.
    #[cfg(feature = "dev")]
    #[test]
    fn the_dev_timeline_escapes_hidden_characters() {
        let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/summariser.yaml");
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(async {
                let (router, _) = dev_session(manifest).await;
                let (_, started) = page(
                    &router,
                    "POST",
                    "/dev/runs",
                    Some(serde_json::json!({ "input": { "printer\u{202E}": "on\u{200B} fire" } })),
                )
                .await;
                let run = started["run"].as_str().expect("a run").to_owned();
                let (status, shown) =
                    page(&router, "GET", &format!("/dev/runs/{run}/history"), None).await;
                assert_eq!(status, 200, "{shown}");
                let text = shown["records"].to_string();
                assert!(
                    !text.contains('\u{202E}') && !text.contains('\u{200B}'),
                    "{text}"
                );
                assert!(
                    text.contains("printer\\\\u{202E}"),
                    "a key was not escaped: {text}"
                );
                assert!(text.contains("on\\\\u{200B} fire"), "{text}");
                assert_eq!(shown["escaped"], true);
                let served = served_history(&router, &run).await;
                assert_eq!(
                    shown["records"].as_array().expect("records").len(),
                    served.len()
                );

                let (status, _) = page(&router, "GET", "/dev/runs/not-a-run/history", None).await;
                assert_eq!(status, 400);
            });
    }

    /// The `governed_by` a run's admission recorded.
    #[cfg(feature = "dev")]
    async fn governed_by(
        journal: &Arc<dyn agentplane::journal::JournalStore>,
        run: agentplane::core::RunId,
    ) -> serde_json::Value {
        super::history_lines(journal, run, None, true)
            .await
            .expect("read")
            .expect("the run exists")
            .iter()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).expect("JSON"))
            .find(|r| r["kind"] == "RunAdmitted")
            .expect("an admission")["record"]["governed_by"]
            .clone()
    }

    /// **`run` and `dev` admit a run under the same declaration.**
    #[cfg(feature = "dev")]
    #[test]
    fn dev_and_run_admit_the_same_declaration() {
        let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/summariser.yaml");
        let dir = temp_dir("dev-same");
        let path = dir.join("plane.redb");
        let store = path.to_str().expect("utf-8 path");
        cli(&[
            "agentplane",
            "run",
            manifest,
            "--input",
            "{\"ticket\":\"t\"}",
            "--store",
            store,
        ])
        .expect("run");
        let ran = succeeded_in(store)[0];
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let by_run = rt.block_on(async {
            let journal: Arc<dyn agentplane::journal::JournalStore> =
                Arc::new(agentplane::store::RedbStore::open(store).expect("store"));
            governed_by(&journal, ran).await
        });
        let by_dev = rt.block_on(async {
            let (router, journal) = dev_session(manifest).await;
            let (_, started) = page(
                &router,
                "POST",
                "/dev/runs",
                Some(serde_json::json!({ "input": { "ticket": "t" } })),
            )
            .await;
            let run = agentplane::core::RunId::parse(started["run"].as_str().expect("a run"))
                .expect("a run id");
            governed_by(&journal, run).await
        });
        assert!(by_run.is_object(), "{by_run}");
        assert_eq!(by_run, by_dev);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **A saved file widens the `--acting-as` chain**: a capability added
    /// to the file is in scope after the rebuild, not refused until restart.
    #[cfg(feature = "dev")]
    #[test]
    fn a_rebuild_scopes_the_acting_as_chain_to_the_saved_file() {
        let dir = temp_dir("dev-chain");
        let file = dir.join("agent.yaml");
        let original = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/summariser.yaml"
        ))
        .expect("the example");
        std::fs::write(&file, &original).expect("written");
        let manifest = file.to_str().expect("utf-8 path").to_owned();
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(async {
                let (router, _) = dev_session_as(&manifest, Some("ada")).await;
                let start = |capability: &str| {
                    serde_json::json!({
                        "input": { "ticket": "t" },
                        "capability": capability,
                    })
                };
                let (status, ran) = page(
                    &router,
                    "POST",
                    "/dev/runs",
                    Some(start("support.summarise")),
                )
                .await;
                assert_eq!(status, 200, "{ran}");
                assert_eq!(ran["status"], "succeeded", "{ran}");

                let triager = original
                    .replace("name: summariser", "name: triager")
                    .replace("support.summarise", "support.triage");
                std::fs::write(&file, format!("{original}---\n{triager}")).expect("edited");
                let (status, declared) = page(&router, "GET", "/dev/manifest", None).await;
                assert_eq!(status, 200, "{declared}");
                assert!(declared["refused"].is_null(), "{declared}");
                let (status, ran) =
                    page(&router, "POST", "/dev/runs", Some(start("support.triage"))).await;
                assert_eq!(status, 200, "{ran}");
                assert_eq!(ran["status"], "succeeded", "{ran}");
            });
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **The page's loop, end to end**: start a run that waits on an
    /// approval, page its history, decide the task with the served digest
    /// (a stale one is 412), strict-replay to reproduced, see an edited
    /// manifest diverge, and export a store that verifies.
    #[cfg(feature = "dev")]
    #[test]
    #[allow(clippy::too_many_lines)]
    fn a_run_started_on_the_dev_page_is_decided_replayed_and_exported() {
        let dir = temp_dir("dev-loop");
        let file = dir.join("agent.yaml");
        let original = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/approval.yaml"
        ))
        .expect("the example");
        std::fs::write(&file, &original).expect("written");
        let manifest = file.to_str().expect("utf-8 path").to_owned();
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(async {
                let (router, journal) = dev_session(&manifest).await;
                let (status, declared) = page(&router, "GET", "/dev/manifest", None).await;
                assert_eq!(status, 200);
                assert_eq!(
                    declared["agents"][0]["name"], "approved-summary",
                    "{declared}"
                );

                let start = |ticket: &str| {
                    serde_json::json!({
                        "input": { "ticket": ticket },
                        "correlate": ["customer=C-7"],
                    })
                };
                let (status, started) =
                    page(&router, "POST", "/dev/runs", Some(start("T-1"))).await;
                assert_eq!(status, 200, "{started}");
                assert_eq!(started["status"], "suspended", "{started}");
                let run = started["run"].as_str().expect("a run").to_owned();
                let run_id = agentplane::core::RunId::parse(&run).expect("a run id");

                let served = served_history(&router, &run).await;
                let held = journal.read(run_id, 1).await.expect("the journal");
                assert_eq!(served.len(), held.len());
                assert_eq!(
                    served.last().expect("records")["seq"],
                    held.last().expect("records").seq()
                );

                // A second run on the same key joins the same case.
                let (_, second) = page(&router, "POST", "/dev/runs", Some(start("T-2"))).await;
                let second_history =
                    served_history(&router, second["run"].as_str().expect("a run")).await;
                assert_eq!(served[0]["case"], second_history[0]["case"]);
                assert!(served[0]["case"].is_string());

                let (status, worklist) = page(&router, "GET", "/api/tasks", None).await;
                assert_eq!(status, 200, "{worklist}");
                let task = worklist["tasks"]
                    .as_array()
                    .expect("tasks")
                    .iter()
                    .find(|t| t["run"] == run.as_str())
                    .expect("the run's task")
                    .clone();
                assert!(task["rendering"]["summary"].is_string(), "{task}");
                let decide = format!("/api/tasks/{}/decide", task["id"].as_str().expect("an id"));
                let stale = agentplane::core::Digest::of(b"another version").to_hex();
                let (status, _) = page(
                    &router,
                    "POST",
                    &decide,
                    Some(serde_json::json!({ "approved": true, "reason": "ok", "digest": stale })),
                )
                .await;
                assert_eq!(status, 412, "a stale digest was not refused");
                let (status, decided) = page(
                    &router,
                    "POST",
                    &decide,
                    Some(serde_json::json!({
                        "approved": true,
                        "reason": "checked",
                        "digest": task["digest"],
                    })),
                )
                .await;
                assert_eq!(status, 200, "{decided}");
                assert_eq!(decided["decided_by"], "dev:author");

                let mut concluded = false;
                for _ in 0..50 {
                    let (_, view) = page(&router, "GET", &format!("/api/runs/{run}"), None).await;
                    if view["status"] == "succeeded" {
                        concluded = true;
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                assert!(
                    concluded,
                    "the decided run did not resume to its conclusion"
                );

                let (status, verdicts) = page(
                    &router,
                    "POST",
                    "/dev/replay",
                    Some(serde_json::json!({ "run": run })),
                )
                .await;
                assert_eq!(status, 200, "{verdicts}");
                assert_eq!(verdicts[0]["verdict"], "reproduced", "{verdicts}");

                let (status, export) = page(&router, "GET", "/dev/export", None).await;
                assert_eq!(status, 200, "{export}");
                let report = &export["report"];
                assert_eq!(report["findings"], serde_json::json!([]), "{report}");
                let reverified = agentplane::export::verify(
                    export["export"].as_str().expect("the export").as_bytes(),
                    None,
                    &[],
                )
                .expect("readable");
                assert_eq!(
                    serde_json::to_value(&reverified).expect("a report"),
                    *report,
                    "the bytes offered are not the bytes verified"
                );

                std::fs::write(&file, original.replace("One sentence.", "Two sentences."))
                    .expect("edited");
                let (status, verdicts) = page(
                    &router,
                    "POST",
                    "/dev/replay",
                    Some(serde_json::json!({ "run": run })),
                )
                .await;
                assert_eq!(status, 200, "{verdicts}");
                assert_eq!(verdicts[0]["verdict"], "diverged", "{verdicts}");
            });
        let _ = std::fs::remove_dir_all(&dir);
    }
}
