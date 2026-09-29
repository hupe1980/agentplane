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
}

/// The same table, as `--help` prints it.
const EXIT_STATUS_HELP: &str = "Exit status:
  0  ok
  1  a finding or a negative answer (a failed run, an audit finding, needs attention)
  2  usage: the command as typed cannot be carried out
  3  a run is suspended, waiting for a person, a timer or an event
  4  operational: a store, witness, network or file could not be used
  5  partial: --limit truncated the answer, or a strict replay could not replay a run";

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
    /// Print the identity a registry pins.
    Digest(DigestArgs),
    /// Check a journal's history and print what could not be checked.
    Audit(AuditArgs),
    /// Write a journal's records out as JSON Lines.
    Export(ExportArgs),
    /// Recompute an export and check it against its own checkpoint.
    Verify(VerifyArgs),
    /// Re-derive an export's policy verdicts, or measure a candidate bundle.
    Policy(PolicyArgs),
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

/// A listing, for the verbs whose default act changes something.
#[derive(clap::Subcommand, Debug)]
enum Listing {
    /// List every one standing on this tenant.
    List(ListArgs),
}

#[derive(clap::Args, Debug)]
struct ListArgs {
    /// The store, and whose to read.
    #[command(flatten)]
    at: StoreRef,
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
    list: Option<Listing>,

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

    /// Who is placing it. Required to place one.
    ///
    /// Recorded as **asserted**: nothing here verified it, and what it proves
    /// is that whoever ran this command could open the store. The operator API
    /// records the same field from the credential its authenticator checked,
    /// and the row says which of the two it was.
    #[arg(long)]
    actor: Option<String>,

    /// Lift the hold instead of placing it.
    #[arg(long, conflicts_with_all = ["reason", "actor"])]
    lift: bool,
}

/// The emergency stop, as a verb: an incident is the worst time to discover
/// that the brake needs a compiler.
///
/// `--reason` and `--actor` are required to halt and refused to lift: the next
/// person to look will be somebody else, possibly at three in the morning, and
/// *why* and *who* are the whole question. A lift needs neither, because it
/// restores the default and the row it clears is gone.
#[derive(clap::Args, Debug)]
#[command(args_conflicts_with_subcommands = true, subcommand_negates_reqs = true)]
struct HaltArgs {
    #[command(subcommand)]
    list: Option<Listing>,

    /// The store holding the halt, and which tenant to stop.
    #[command(flatten)]
    at: Option<StoreRef>,

    /// What to stop: `tenant`, `agent:<metadata.name>`,
    /// `revision:<manifest digest>`, or `subject:<delegation subject>`.
    ///
    /// `revision:` is the one to reach for when a bad deploy is the incident:
    /// it names the exact reviewed bytes, so a fix published as a new version
    /// runs while the broken revision stays stopped.
    #[arg(long, default_value = "tenant")]
    scope: String,

    /// Why. Required unless `--lift`.
    #[arg(long)]
    reason: Option<String>,

    /// Who is throwing it. Required unless `--lift`.
    ///
    /// It goes on the row, and it is recorded as **asserted** rather than
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
    #[arg(long, conflicts_with_all = ["reason", "actor"])]
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
    /// The witness keys whose cosignatures verified, by monitoring prefix.
    ///
    /// Absent for a checkpoint read from a file: a file carries no signature
    /// this command can check, so it is an asserted fact and saying nothing is
    /// how that is said.
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
                anchor.checkpoints.push(agentplane::audit::Anchor::new(
                    cosigned.checkpoint.clone(),
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

    let evidence = agentplane::audit::Evidence {
        anchors: &anchor.checkpoints,
        verifier: verifier
            .as_ref()
            .map(|v| v as &dyn agentplane::core::Verifier),
        require_signatures: audit.require_signatures,
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
    let trailer = agentplane::export::to_jsonl(
        store,
        Some(cases),
        runs,
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
        return Ok(ExitCode::from(exit::FINDING));
    }
    Ok(ExitCode::from(if truncation.is_partial() {
        exit::PARTIAL
    } else {
        exit::OK
    }))
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

        // The runs no outcome names. Skipped when the caller narrowed to
        // specific outcomes, because that is a request for exactly those
        // conclusions — and an in-flight run is not one.
        if opts.outcome.is_empty() {
            let flight = agentplane::export::runs_in_flight(&store, opts.limit)
                .await
                .map_err(|e| e.to_string())?;
            if flight.truncated {
                truncated.push("in-flight runs".to_owned());
            }
            for (run, why) in &flight.unreadable {
                eprintln!("warning: in-flight run {run} could not be read: {why}");
            }
            if !flight.runs.is_empty() {
                eprintln!(
                    "including {} run(s) still in flight — sleeping, awaiting a message, \
                     or waiting on a person. The Merkle log commits to sealed runs only, \
                     so these are carried and the checkpoint does not cover them",
                    flight.runs.len()
                );
            }
            runs.extend(flight.runs);
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

/// Every standing legal hold.
fn holds_verb(at: &StoreRef) -> Result<ExitCode, Fault> {
    blocking(async {
        let cases = at.open().await?.cases();
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
        (Some(Listing::List(list)), ..) => return holds_verb(&list.at),
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

    rt.block_on(async {
        let cases = at.open().await?.cases();

        let case =
            agentplane::core::CaseId::parse(case).map_err(|e| usage(format!("--case: {e}")))?;
        if opts.lift {
            let lifted = cases.release_hold(case).await.map_err(|e| e.to_string())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "case": case.to_string(),
                    "lifted": lifted,
                }))
                .map_err(|e| e.to_string())?
            );
            return Ok(lift_status(lifted));
        }

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
        (Some(Listing::List(list)), _) => return halts_verb(&list.at, opts.json),
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
    let thrown = if opts.lift {
        None
    } else {
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
        Some((by, reason))
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the async runtime: {e}"))?;

    rt.block_on(async {
        let quotas = at.open().await?.quotas();
        let printed = if let Some((by, reason)) = &thrown {
            {
                // Wall clock by design, like the retention cutoff and a hold's
                // instant: when a person threw a stop is a fact about the
                // outside world, not a journaled observation.
                #[allow(clippy::disallowed_methods)]
                let now = time::OffsetDateTime::now_utc();
                quotas
                    .set_halt(&scope, by, now, reason)
                    .await
                    .map_err(|e| e.to_string())?;
                if !opts.json {
                    println!(
                        "halted {}: {reason} (by {}, {})",
                        scope.key(),
                        by.actor(),
                        by.basis().as_str()
                    );
                    return Ok(ExitCode::SUCCESS);
                }
                serde_json::json!({
                    "scope": scope.key(),
                    "halted": true,
                    "reason": reason,
                    "by": by.actor(),
                    "basis": by.basis().as_str(),
                })
            }
        } else {
            {
                let was_standing = quotas.lift_halt(&scope).await.map_err(|e| e.to_string())?;
                // Whether one was standing is the answer to *did I clear the
                // right scope*, which is the question during an incident. A lift
                // that found nothing must not read as success, so it exits as a
                // negative answer.
                if opts.json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "scope": scope.key(),
                            "halted": false,
                            "was_standing": was_standing,
                        })
                    );
                } else if was_standing {
                    println!("lifted {}", scope.key());
                } else {
                    println!("no halt was standing on {}; nothing lifted", scope.key());
                }
                return Ok(lift_status(was_standing));
            }
        };
        println!("{printed}");
        Ok(ExitCode::SUCCESS)
    })
}

/// How a lift exits: a lift that found nothing standing is a negative answer.
fn lift_status(was_standing: bool) -> ExitCode {
    ExitCode::from(if was_standing {
        exit::OK
    } else {
        exit::FINDING
    })
}

/// Every standing halt, so an operator can see what an incident left behind.
fn halts_verb(at: &StoreRef, json: bool) -> Result<ExitCode, Fault> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the async runtime: {e}"))?;

    rt.block_on(async {
        let quotas = at.open().await?.quotas();
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
        let waiting = store
            .waiting_runs(opts.limit)
            .await
            .map_err(|e| e.to_string())?;
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
            serde_json::to_string_pretty(&serde_json::json!({ "waiting": rows }))
                .map_err(|e| e.to_string())?
        );
        Ok(ExitCode::SUCCESS)
    })
}

/// Ask the plane whether anything needs a person, and exit non-zero if so.
///
/// **The exit code is the point.** This is a verb a scheduler runs, and a check
/// that always exits zero is a check nobody notices has stopped working — the
/// same reason `drill` and `verify` report through their status rather than
/// only on stdout.
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
        let plane = Runtime::builder_with(backend.stores())
            .tenant(backend.tenant())
            .build();
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
        let plane = Runtime::builder_with(backend.stores())
            .tenant(backend.tenant())
            .build();
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
        Ok(ExitCode::SUCCESS)
    })
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
        let plane = Runtime::builder_with(backend.stores())
            .tenant(backend.tenant())
            .lease_ttl(std::time::Duration::from_secs(2))
            .build();
        let delivery = match plane.decide_task(id, &decision, &opts.roles).await {
            Ok(delivery) => delivery,
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
        let plane = Runtime::builder_with(backend.stores())
            .tenant(backend.tenant())
            .build();
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
        let plane = Runtime::builder_with(backend.stores())
            .tenant(backend.tenant())
            .push(backend.push())
            .build();
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
        let plane = Runtime::builder_with(backend.stores())
            .tenant(backend.tenant())
            .quota(backend.quotas(), agentplane::quota::TenantQuota::default())
            .build();
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
        Verb::Digest(a) => digest_verb(&a),
        Verb::Audit(a) => journal_verb(&a.store, Some(&a), false),
        Verb::Export(a) => journal_verb(&a.store, None, a.allow_partial),
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
        Verb::Waiting(a) => waiting_verb(&a),
        Verb::Attention(a) => attention_verb(&a),
        Verb::Restore(a) => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| format!("could not start the async runtime: {e}"))?;
            rt.block_on(async {
                let backend = a.at.open().await?;
                let store = backend.journal();
                let cases = backend.cases();
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
                    ExitCode::from(exit::FINDING)
                })
            })
        }
        Verb::Verify(a) => verify_verb(&a),
        Verb::Policy(PolicyArgs {
            act: PolicyAct::Check(a),
        }) => policy_check_verb(&a),
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

/// Read a checkpoint an auditor was handed, in either form they hold it in.
///
/// Two forms because two things produce one: `audit` prints JSON, and a
/// witness cosigns a `tlog-checkpoint` note. Requiring a conversion between
/// them would put a step between the auditor and the check, and the steps
/// between an auditor and a check are what this crate keeps removing.
fn read_checkpoint(path: &str) -> Result<agentplane::journal::Checkpoint, String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("reading --checkpoint {path}: {e}"))?;
    // The note first: it is the form that travels, and it is unambiguous —
    // JSON never parses as three newline-terminated lines.
    if let Ok(cp) = agentplane::journal::Checkpoint::from_note(&text) {
        return Ok(cp);
    }
    // A signed note carries the checkpoint as its body, so a reader who was
    // handed the cosigned artifact does not have to cut the signatures off.
    if let Ok(note) = agentplane::journal::SignedNote::parse(&text)
        && let Ok(cp) = agentplane::journal::Checkpoint::from_note(&note.text)
    {
        return Ok(cp);
    }
    serde_json::from_str(&text).map_err(|e| {
        format!(
            "--checkpoint {path} is neither a tlog-checkpoint note nor the `current` \
             field of an audit report: {e}"
        )
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
        Some(path) => Some(read_checkpoint(path).map_err(usage)?),
        None => None,
    };
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
        // No witness named. The key check still has to happen, so a
        // `--witness-key` with nothing to use it against is a refusal rather
        // than a flag that did nothing.
        (_, true) => {
            if !opts.witness_key.is_empty() {
                return Err(usage(
                    "--witness-key was given with no --witness to use it against".to_owned(),
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
        anchor.checkpoints.push(agentplane::audit::Anchor::new(
            saved,
            match &opts.checkpoint {
                Some(path) => format!("file {path}"),
                None => "file".to_owned(),
            },
        ));
    }
    let verifier = verifier
        .as_ref()
        .map(|v| v as &dyn agentplane::core::Verifier);
    let report = if opts.file == "-" {
        agentplane::export::verify(std::io::stdin().lock(), verifier, &anchor.checkpoints)
            .map_err(|e| e.to_string())
    } else {
        let file =
            std::fs::File::open(&opts.file).map_err(|e| format!("reading {}: {e}", opts.file))?;
        agentplane::export::verify(std::io::BufReader::new(file), verifier, &anchor.checkpoints)
            .map_err(|e| e.to_string())
    }?;
    println!(
        "{}",
        serde_json::to_string_pretty(&VerifyDocument {
            anchor: &anchor,
            report: &report,
        })
        .map_err(|e| e.to_string())?
    );
    // Findings fail; `not_checked` does not. A pass with no key — or with no
    // checkpoint — has established less, and saying so is different from
    // failing.
    // A split view fails here too. Only a caller that asked more than one
    // witness can see it, so neither the library's report nor the file can.
    Ok(if report.is_sound() && anchor.split_view.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(exit::FINDING)
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

    // One card, one agent. A room is several manifests and A2A's well-known
    // card path is singular, so serving a bundle would have to pick one and
    // silently not serve the others.
    let [manifest] = manifests else {
        return Err(usage(format!(
            "`serve` hosts one agent and this file holds {}. A2A's card path is \
             well-known and singular, so a room would have to advertise one \
             document and quietly not serve the rest — split the file, or run \
             one process per agent",
            manifests.len()
        )));
    };

    let url = opts.url.as_deref().ok_or_else(|| {
        usage(
            "`serve` needs --url: the address callers reach this plane on. It goes on the \
         Agent Card, so it is the public URL rather than what you bind — an agent's \
         declaration must not change when its address does",
        )
    })?;
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
        let mut builder = with_providers(
            Runtime::builder_with(backend.stores()).tenant(backend.tenant()),
            std::slice::from_ref(manifest),
        )
        .await?;
        for (name, client) in connect_mcp_servers(&opts.mcp, std::slice::from_ref(manifest)).await?
        {
            builder = builder.tool_server(name, client);
        }
        if let Some((registry, client)) =
            connect_peers(&opts.peer, std::slice::from_ref(manifest)).map_err(usage)?
        {
            builder = builder.peers(registry, client);
        }
        builder = builder
            .policy(Arc::new(policy) as Arc<dyn agentplane::core::PolicyEngine>)
            .agent(agentplane::runtime::Agent::new(manifest));
        // The same handle `wire_push` gives the A2A server below. The plane
        // holds it because the registrations that stop being delivered are a
        // backlog, and the operator surface is where a backlog is answered —
        // the delivery worker that parked one has nothing more to say about it.
        if !opts.push_host.is_empty() {
            builder = builder.push(backend.push());
        }
        let runtime = builder.try_build().map_err(|e| e.to_string())?;

        let security = agentplane::peers::CardSecurity::bearer("bearer", Vec::<String>::new());
        let mut server = A2aServer::new(Arc::clone(&runtime), auth, &security, manifest, url)
            .map_err(|e| e.to_string())?;

        server = wire_push(server, &opts.push_host, &backend)?;
        serve_until_stopped(
            &runtime,
            server,
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
async fn serve_until_stopped(
    runtime: &Arc<Runtime>,
    server: agentplane::api::a2a::A2aServer,
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
        let (stores, tenant) = if let Some(backend) = opts.at.open().await? {
            (backend.stores(), backend.tenant())
        } else {
            // Said out loud rather than assumed: a run whose journal disappears
            // is the opposite of what this crate is for.
            eprintln!("note: journaling to memory; this run will not survive the process");
            (
                agentplane::runtime::Stores::on(Arc::new(
                    RedbStore::open_in_memory().map_err(|e| e.to_string())?,
                )),
                agentplane::core::TenantId::default(),
            )
        };
        let mut builder =
            with_providers(Runtime::builder_with(stores).tenant(tenant), manifests).await?;
        for (name, client) in connect_mcp_servers(&opts.mcp, manifests).await? {
            builder = builder.tool_server(name, client);
        }
        if let Some((registry, client)) = connect_peers(&opts.peer, manifests).map_err(usage)? {
            builder = builder.peers(registry, client);
        }
        if let Some(chain) = chain {
            builder = builder.acting_as(chain);
        }
        for manifest in manifests {
            builder = builder.agent(agentplane::runtime::Agent::new(manifest));
        }
        // `try_build`, because everything on this plane arrived as input: a
        // wiring mistake in a file somebody handed us is a refusal with a
        // sentence, not a programmer error worth a crash.
        let agent = builder
            .try_build()
            .map_err(|e| in_cli_terms(&e, manifests))?;

        let capability = entry_capability(manifests, opts.capability.as_deref()).map_err(usage)?;
        // The case kind is the capability: a case is a matter, and the matter
        // a terminal run belongs to is the thing it was asked to do.
        let outcome = agent
            .run_correlated(
                &capability,
                Tainted::trusted(opts.read_input().map_err(usage)?),
                &capability,
                &keys,
            )
            .await
            .map_err(|e| e.to_string())?;

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
        let mut builder = with_providers(
            Runtime::builder_with(backend.stores()).tenant(backend.tenant()),
            manifests,
        )
        .await?;
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
        let mut sources: Vec<(
            agentplane::runtime::Stores,
            agentplane::core::TenantId,
            Vec<agentplane::core::RunId>,
        )> = Vec::new();
        if opts.from.is_empty() {
            let store = opts.at.store.as_deref().ok_or_else(|| {
                usage("--strict needs a source: --store <file|postgres://…> or --from <export>")
            })?;
            let run = wanted.ok_or_else(|| {
                usage("a strict replay of a store names its run; replay every run of an export with --from")
            })?;
            let backend = Backend::open(store, opts.at.tenant.as_deref()).await?;
            sources.push((backend.stores(), backend.tenant(), vec![run]));
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
                    agentplane::runtime::Stores::on(source.store),
                    agentplane::core::TenantId::default(),
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
        for (stores, tenant, runs) in sources {
            for run in runs {
                results.push(verify_one(manifests, &stores, &tenant, run).await?);
            }
        }
        Ok(ExitCode::from(replay_exit(&results)))
    })
}

/// Replay one run strictly and print its verdict.
async fn verify_one(
    manifests: &[Manifest],
    stores: &agentplane::runtime::Stores,
    tenant: &agentplane::core::TenantId,
    run: agentplane::core::RunId,
) -> Result<Replayed, Fault> {
    let history = match stores.journal.read(run, 1).await {
        Ok(history) => history,
        Err(e) => {
            eprintln!("run {run} — cannot be read: {e}");
            return Ok(Replayed::Unreadable);
        }
    };
    let mut builder = agentplane::runtime::replay_only::wire(
        Runtime::builder_with(stores.clone()).tenant(tenant.clone()),
        manifests,
        &history,
    );
    for manifest in manifests {
        builder = builder.agent(agentplane::runtime::Agent::new(manifest));
    }
    let plane = builder
        .try_build()
        .map_err(|e| usage(in_cli_terms(&e, manifests)))?;
    match plane.verify(run).await {
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
        "fake" => Ok(agentplane::model::fake::FakeProvider::new()),
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
    use super::{
        EXIT_STATUS_HELP, Fault, Truncation, audit_status, cutoff_before, declared_bound, exit,
        lift_status, refuse_ambiguous_peers, refuses_partial_export, shell_quote, where_flags,
        without_password,
    };

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

        for (code, word) in [
            (exit::OK, "ok"),
            (exit::FINDING, "finding"),
            (exit::USAGE, "usage"),
            (exit::SUSPENDED, "suspended"),
            (exit::OPERATIONAL, "operational"),
            (exit::PARTIAL, "partial"),
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
                    &agentplane::runtime::Stores::on(store),
                    &agentplane::core::TenantId::default(),
                    recorded.run_id,
                )
                .await
                .expect("a strict replay needs no driver this binary can build");
                assert_eq!(replayed, super::Replayed::Verified);
            });
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
}
