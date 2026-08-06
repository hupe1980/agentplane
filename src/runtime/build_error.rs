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
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
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
