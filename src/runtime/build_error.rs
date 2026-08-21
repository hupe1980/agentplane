//! Why a plane could not be assembled.
//!
//! Every variant here is a wiring mistake with a fix and no recovery: the
//! embedder's code, or the declaration beside it, says two contradictory things
//! and the runtime cannot pick one. They are refused at
//! [`RuntimeBuilder::try_build`] rather than at dispatch, because the cost of
//! finding out at dispatch is a run that has already begun.
//!
//! # Why this is a `Result` and also a panic
//!
//! [`build`] keeps panicking, and that is deliberate. For the ordinary case —
//! a binary wiring its own skills against manifests it ships — every one of
//! these is a bug in code the author is looking at, and `?`-propagating it to a
//! `main` that prints it is ceremony around an abort.
//!
//! But a manifest is a **file**, and a plane that loads one at runtime is a
//! legitimate shape this crate encourages: `Registry` pins digests, the CLI
//! reads YAML from disk, and a multi-tenant host may assemble a plane per
//! tenant from declarations it did not write. There, a bad file is an input,
//! not a bug, and a panic takes down every other tenant in the process to
//! report it. [`try_build`] is for that caller.
//!
//! One implementation, two entry points: `build` is `try_build` with an
//! `expect`, so the two cannot diverge about what is refused.
//!
//! [`RuntimeBuilder::try_build`]: crate::runtime::RuntimeBuilder::try_build
//! [`build`]: crate::runtime::RuntimeBuilder::build
//! [`try_build`]: crate::runtime::RuntimeBuilder::try_build

/// A plane this crate will not assemble.
#[derive(Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BuildError {
    /// The plane and its blob store are scoped to different tenants.
    #[error(
        "this plane runs as tenant '{plane}' but its blob store serves '{store}'. \
         Blobs are content-addressed, so a shared store means two tenants' \
         identical bytes are one object — and erasing it for one destroys it for \
         the other while reporting both requests discharged"
    )]
    BlobStoreTenant { plane: String, store: String },

    /// The plane and its journal store are scoped to different tenants.
    ///
    /// The dangerous one, because it *works*. Runs are written into another
    /// tenant's keyspace while every key-scoped erasure and every policy request
    /// names the right one, so nothing at runtime looks wrong.
    #[error(
        "this plane runs as tenant '{plane}' but its journal store is scoped to \
         '{store}'. The mismatch does not surface at runtime: runs are written \
         into the other tenant's keyspace while every erasure and every policy \
         request names this one"
    )]
    JournalStoreTenant { plane: String, store: String },

    /// The plane and one of its state stores are scoped to different tenants.
    ///
    /// One variant for the five stores whose consequence is the same, with the
    /// store named as data rather than as five messages that differ only in a
    /// noun. When a key ring is wired, the plane seals this state under **its**
    /// tenant while the store writes rows under the store's, and the two scopes
    /// are both real — so nothing fails, nothing leaks, and the state sits
    /// under a scope the tenant's erasure does not name.
    ///
    /// That is the failure a deletion guarantee may not have: `erase` destroys
    /// the key it was asked for, reports success, and the sealed rows remain
    /// readable under the other scope. It is invisible at runtime because
    /// nothing about it is wrong except which of two correct scopes was used.
    #[error(
        "this plane runs as tenant '{plane}' but its {store} store serves \
         '{tenant}'. With a key ring wired the plane seals that state under \
         '{plane}' while the store keeps it under '{tenant}' — both scopes are \
         real, so nothing fails at runtime and an erasure for either tenant \
         destroys a key that does not reach these rows"
    )]
    StateStoreTenant {
        /// Which store disagreed: `case`, `event`, `task`, `memory` or `push`.
        store: &'static str,
        plane: String,
        tenant: String,
    },

    /// A tool server took the name reserved for agents on this plane.
    #[error(
        "tool server 'agent' is reserved: `tool://agent/<capability>` names an \
         agent on this plane and dispatches through `commission`. A transport \
         under that name would let a deployment change whether a grant means \
         \"an agent here\" or \"somebody's server\" without changing any \
         reviewed document — rename the server"
    )]
    ReservedToolServer,

    /// A declarative agent needs a tool catalogue and the plane has none.
    ///
    /// Refused at build because it is knowable at build: the manifest says the
    /// agent runs a tool loop, and the plane says nothing reaches a tool server.
    /// Deferring it to the run would report a wiring mistake once per request
    /// instead of once, on a plane that assembled cleanly. The one shape that is
    /// legitimately catalogue-free is an agent whose grants are *all*
    /// `tool://agent/…`: those dispatch through `commission` and their
    /// catalogue is derived from the declaration.
    #[error(
        "agent '{agent}' declares `execution.kind: {kind}` with {grants}, but this \
         plane has no tool catalogue, so every run would fail identically. Wire one \
         with `RuntimeBuilder::toolbox(..)` — which derives it from this very \
         declaration — or state it with `.tools(catalog, client)`. Grants of the \
         form `tool://agent/<capability>` need neither, because they dispatch \
         through `commission` rather than a transport"
    )]
    DeclarativeToolsUnreachable {
        agent: String,
        kind: &'static str,
        grants: String,
    },

    /// A process-local erasure lock beside a store two instances can write.
    #[error(
        "this plane's journal store is shared between instances, and its \
         governed memory is sealed with a **process-local** erasure lock — so \
         the window between an erasure's legal-hold check and its key \
         destruction is open to the other instance, which can write an item \
         that ends up sealed under a scope about to stop existing. The erasure \
         would report success. Wire a coordinator that spans instances: \
         `EncryptedMemoryStore::new(..).coordinated_by(Arc::new(store.erasure_coordinator()))`"
    )]
    ErasureCoordinatorNotShared,

    /// An agent declares oversight on a plane that cannot ask anybody.
    ///
    /// The same shape as [`DeclarativeToolsUnreachable`](Self::DeclarativeToolsUnreachable),
    /// and both facts are in hand at `build`: the manifest says a human must
    /// decide, and the plane says there is nowhere to put the decision. Left to
    /// run time it surfaces on the one code path a test suite is least likely
    /// to reach — the first real approval — with the person already waiting.
    #[error(
        "agent '{agent}' declares {declared}, so a run must be able to open a \
         task and suspend until somebody decides it — but this plane has no \
         {missing}. Wire it with `RuntimeBuilder::{remedy}(..)`, or drop the \
         oversight declaration. A run admitted through plain `run(..)` also has \
         no case, so give it correlation keys with `run_correlated(..)` or name \
         one with `run_in_case(..)`"
    )]
    OversightUnreachable {
        agent: String,
        declared: String,
        missing: &'static str,
        remedy: &'static str,
    },

    /// An agent reads or writes memories on a plane that has nowhere to keep
    /// them.
    ///
    /// Knowable at build, and expensive at run time in a way most wiring
    /// mistakes are not: formation happens **after** the answer, so the run has
    /// already paid for its model calls, opened its approval task and waited for
    /// a person before failing on a store nobody wired.
    #[error(
        "agent '{agent}' declares `{declared}`, so its runs reach durable memory — but \
         this plane has no memory store. Wire one with `RuntimeBuilder::memory(..)`, or \
         drop the declaration. Left to run time, formation fails only once the run has \
         already paid for its model calls"
    )]
    MemoryWithoutStore {
        agent: String,
        /// The declaration that needs a store: `spec.memory.recall` or
        /// `spec.memory.formation`.
        declared: &'static str,
    },

    /// The plane's embedder and its index speak different languages.
    ///
    /// The one wiring mistake in this list that would otherwise never fail —
    /// see [`IndexIdentity`](crate::memory::IndexIdentity). The two strings
    /// differing is not itself the mistake: an index built from
    /// `…/search_document` asks for `…/search_query` here.
    #[error(
        "this plane embeds with '{embedder}' but its index accepts query vectors from \
         '{index}'. Two embedding revisions produce vectors of the same width that \
         compare with the same cosine and mean nothing to each other, so this pairing \
         would not fail — it would rank unrelated memories confidently on every search. \
         Wire the embedder the index names, or re-index"
    )]
    EmbeddingSpaceMismatch { embedder: String, index: String },

    /// A semantic index on a plane with no authoritative memory.
    ///
    /// Every search would fail at its last step, having already paid for an
    /// embedding call and a retrieval.
    #[error(
        "this plane wires a semantic index but no memory store. An index holds only \
         `(id, version, digest)` commitments — the content is materialised from \
         authoritative memory and re-checked before anything is exposed — so wire one \
         with `RuntimeBuilder::memory(..)`"
    )]
    SemanticMemoryWithoutStore,

    /// A memory subject binds to a case on a plane with no cases.
    ///
    /// The failure this prevents is worse than an error, which is why it is one:
    /// a binding that cannot resolve leaves the operator's fallback options as
    /// *fail the run* or *file everybody's memories under one key*, and the
    /// second is the defect bindings exist to remove.
    #[error(
        "agent '{agent}' files memories under '{subject}', which resolves from the run's \
         case — and this plane has no case store, so nothing could ever resolve it. Wire \
         one with `RuntimeBuilder::cases(..)` and admit runs with `run_correlated(..)`, or \
         declare a literal subject and accept that every subject's facts share one key"
    )]
    MemorySubjectUnbindable { agent: String, subject: String },

    /// An agent grant names a capability no agent on this plane provides.
    #[error(
        "agent '{agent}' grants 'tool://agent/{capability}', and no agent on \
         this plane provides '{capability}' — the model would be offered a \
         consultation that fails when chosen"
    )]
    AgentToolUnknownCapability { agent: String, capability: String },

    /// An agent grant names the granting agent's own capability.
    #[error(
        "agent '{agent}' grants 'tool://agent/{capability}', which it provides \
         itself — an agent consulting itself is a loop wearing a grant, and \
         the delegation ceiling would only bound how long it spins"
    )]
    AgentToolSelfReference { agent: String, capability: String },

    /// The policy set cannot be evaluated against a request this plane makes.
    ///
    /// Every rule is evaluated against every request, so a rule reading an
    /// attribute a request does not carry does not merely fail to match — it
    /// **errors**, and an unevaluable rule may be the `forbid` that would have
    /// stopped the call, so the gate refuses. A rule guarded on nothing
    /// therefore denies every effect of every run, from a policy set that
    /// compiled cleanly and validated against its schema.
    ///
    /// Some context attributes are conditional by design: `delegation_depth`,
    /// `owner` and `scope` exist only where a delegation chain does, and
    /// `label` only where a value is being sinked. A rule that reads one
    /// unconditionally is correct exactly until the first request without it.
    /// The remedy is Cedar's `has`: `context has delegation_depth &&
    /// context.delegation_depth >= 1`.
    ///
    /// Found at build by evaluating the compiled set against a canonical
    /// request of each shape the runtime issues — cheap, because evaluation is
    /// total and side-effect free — rather than at the first effect of the
    /// first run, which is where a deployment discovered it as a plane that
    /// denied everything.
    #[error(
        "this plane's policy set cannot be evaluated: {problems} — every rule is \
         evaluated against every request, so a rule reading an attribute the \
         request does not carry errors rather than not matching, and the gate \
         refuses because the rule that failed may be the one that would have \
         forbidden the call. Attributes that are conditional by design: \
         `delegation_depth`, `owner` and `scope` (a delegation chain only), \
         `label` (sinks only). Guard them — `context has delegation_depth && \
         context.delegation_depth >= 1`"
    )]
    PolicyUnevaluable { problems: String },

    /// A ceiling set to zero, which permits nothing at all.
    ///
    /// Zero is not a small budget; it is a budget already spent. These
    /// ceilings are checked before the work and against every effect of every
    /// kind, so a plane carrying one refuses its first operation on every run
    /// it will ever make — including a read-only tool call by an agent that
    /// declares no model.
    ///
    /// The manifest refuses this at parse, and a plane wired in Rust reaches
    /// the same budget without passing a parser: one rule, both doors.
    #[error(
        "the budget's `{field}` is 0, which permits nothing at all — not merely \
         no model spend. This ceiling is checked before every step and every \
         effect, so at 0 it is already reached and the run is refused its first \
         operation of any kind: a read-only tool call, a local lookup, an agent \
         that declares no models. Such a plane does not run once and stop, it \
         fails identically on every run it will ever make. Leave the field \
         `None` to mean 'no limit'. To stop a tenant doing work, use the \
         operator's emergency stop (`QuotaStore::set_halt`), which refuses new \
         runs with a reason attached — a halt says somebody is dealing with an \
         incident, where a ceiling only says not right now"
    )]
    BudgetPermitsNothing { field: &'static str },

    /// A lease TTL shorter than the store's expiry granularity.
    ///
    /// Both stores keep lease expiry in whole seconds and treat
    /// `expires_at <= now` as lapsed, so anything under the minimum is expired
    /// for part of every second it exists — no renewal frequency saves it.
    /// A plane built with one would have every run takeable by another
    /// instance while still working, and only under load.
    #[error(
        "a lease of {ttl:?} cannot be renewed: the store keeps expiry in whole \
         seconds and treats `expires_at <= now` as lapsed, so anything under \
         {minimum:?} expires between renewals however often they run — and a \
         run that cannot hold its lease can be taken over while it is still \
         working"
    )]
    LeaseUnrenewable {
        ttl: std::time::Duration,
        minimum: std::time::Duration,
    },

    /// One tool server name was registered twice.
    #[error(
        "tool server '{server}' is registered twice — registration order would \
         decide which transport carries a call"
    )]
    DuplicateToolServer { server: String },

    /// Both `tools(..)` and `toolbox(..)` were wired.
    ///
    /// Not a merge, and it must not silently become one: the stated catalogue is
    /// the operator saying something deliberate, the derived one is the agent's
    /// declaration, and overwriting either runs a plane under grants nobody
    /// chose.
    #[error(
        "this plane wires tools twice — `tools(..)` states the catalogue \
         explicitly and `toolbox(..)` derives it from the agents, so one of them \
         would silently replace the other's grants"
    )]
    ToolsWiredTwice,

    /// The tools this binary implements and a reviewed manifest disagree.
    #[error(
        "the tools this binary implements and the manifest of agent '{agent}' \
         disagree — the declaration a reviewer approved no longer describes the \
         agent:\n  {}", problems.join("\n  ")
    )]
    ToolDrift {
        agent: String,
        problems: Vec<String>,
    },

    /// Two agents grant one tool and declare it differently.
    #[error(
        "agents '{first}' and '{second}' both grant '{tool}' and declare it \
         differently — a plane has one catalogue, so one of the two reviewed \
         declarations would silently not be the one enforced"
    )]
    ToolDeclaredTwoWays {
        tool: String,
        first: String,
        second: String,
    },

    /// Tools were wired to a plane whose agents declare none.
    #[error(
        "tools were wired to a plane with no declared agent — a grant is an \
         agent's declaration, so there is nothing here that admits them"
    )]
    ToolsWithoutDeclaration,

    /// A stated catalogue is laxer than a reviewed grant.
    ///
    /// The one direction nobody can be right about: a read-only entry exempts
    /// the tool from the whole-value taint gate *and* carries `Recovery::Retry`,
    /// so a timed-out money-moving call is sent again.
    #[error(
        "the stated tool catalogue is laxer than a reviewed manifest grant — a \
         read-only entry exempts the tool from the whole-value taint gate and \
         makes a timed-out call retryable:\n  {}", problems.join("\n  ")
    )]
    CatalogueLaxerThanGrant { problems: Vec<String> },

    /// Two distinct skills share one name.
    #[error(
        "two skills on this plane are both named '{name}'. A skill name is how a \
         capability resolves to an implementation and how a run names what it \
         dispatched, so two of them make both answers arbitrary — rename one"
    )]
    DuplicateSkillName { name: String },

    /// Two agents claim one capability.
    #[error(
        "capability '{capability}' is claimed by two agents on this plane: \
         '{first}' and '{second}'. Dispatch resolves a capability to one skill \
         and to the manifest governing it, so the second claim would silently \
         take the first's work out from under the first's budget and grants. \
         Give them distinct capabilities, or put them on separate planes"
    )]
    CapabilityClaimedTwice {
        capability: String,
        first: String,
        second: String,
    },

    /// A skill answers a capability its agent's declaration never names.
    ///
    /// The manifest is the artifact that gets reviewed, digested and pinned,
    /// and the A2A card is built from it — so a capability served but not
    /// advertised is a door in a reviewed surface that the review could not
    /// see. The skill is still governed by the manifest, which is what makes
    /// this quiet rather than broken: budgets and grants apply, the run
    /// journals correctly, and nothing anywhere says the agent answers more
    /// than its file claims.
    #[error(
        "agent '{agent}' registers skills answering {undeclared:?}, which \
         `spec.capabilities.provides` does not name — the declaration is what \
         gets reviewed, digested and advertised, so a capability added in code \
         is a surface no reviewer of that file can see. Add it to `provides`, \
         or register the skill on its own agent"
    )]
    ProvidesWhatItDoesNotAdvertise {
        agent: String,
        undeclared: Vec<String>,
    },

    /// A declarative agent has no model to call.
    #[error(
        "agent '{agent}' declares execution but no privileged model — a \
         declarative agent has nothing to call"
    )]
    DeclarativeWithoutModel { agent: String },

    /// A declarative agent names a provider no driver is registered for.
    ///
    /// Named rather than defaulted: falling back to some other registered driver
    /// would run the agent on a model its own declaration does not name.
    #[error(
        "agent '{agent}' names provider '{provider}', which no driver is \
         registered for. Call RuntimeBuilder::provider(\"{provider}\", ..)"
    )]
    UnknownProvider { agent: String, provider: String },

    /// A declarative agent provides no capability.
    #[error(
        "agent '{agent}' declares execution but provides no capability — a \
         declarative agent nothing can call is a file that does nothing"
    )]
    DeclarativeProvidesNothing { agent: String },

    /// A manifest advertises capabilities none of its own skills provide.
    #[error(
        "agent '{agent}' advertises capabilities none of its own skills provide: \
         {missing:?}. A skill wired with `RuntimeBuilder::skill` is not governed \
         by any agent — it runs under the plane's budget and no manifest gate. \
         Register it on the agent instead: \
         `.agent(Agent::new(&manifest).skill(MySkill))`"
    )]
    AdvertisesWhatItCannotProvide { agent: String, missing: Vec<String> },
}

crate::core::error::debug_is_display!(BuildError);
