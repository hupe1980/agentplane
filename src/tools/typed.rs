//! Defining a tool once, as one thing.
//!
//! # One artifact, because three cannot be kept in step
//!
//! The shape this avoids splits a tool across three artifacts that nothing
//! reconciles:
//!
//! * an argument schema hand-written in the manifest;
//! * a client implementation that matches on the tool's **name** and reads
//!   arguments out of a `Value` by hand — `arguments["id"].as_str()`;
//! * whatever JSON the model actually sends.
//!
//! Nothing can check that the three agree. A field renamed in the manifest and
//! not in the code yields `None`, and a `.unwrap_or(default)` turns that into a
//! plausible wrong answer rather than an error. Dispatching on the name is also
//! [stringly-typed control flow] — the shape this codebase rejects everywhere
//! else.
//!
//! [stringly-typed control flow]: crate::tools
//!
//! # The shape every other ecosystem converged on
//!
//! Python's `@tool`, Pydantic AI, the `OpenAI` Agents SDK and Rust's Rig all
//! arrived at the same three rules, and they are right:
//!
//! 1. **The schema comes from the type**, never from a second document.
//! 2. **The body receives that type**, rather than indexing a second untyped
//!    representation by hand.
//! 3. **Model-steering prose stays in the manifest.** Unlike ordinary agent
//!    SDKs, this runtime has a digest-covered review artifact; changing what the
//!    model is told a tool does must change that artifact's identity.
//!
//! ```no_run
//! # use agentplane::tools::{Tool, ToolFailure};
//! # use serde::Deserialize;
//! # use serde_json::{Value, json};
//! /// Read a ledger account's balance.
//! #[derive(Debug, Deserialize, schemars::JsonSchema)]
//! struct ReadBalance {
//!     /// The account to read.
//!     account: String,
//! }
//!
//! #[async_trait::async_trait]
//! impl Tool for ReadBalance {
//!     const SERVER: &'static str = "ledger";
//!     const NAME: &'static str = "read";
//!
//!     async fn call(self) -> Result<Value, ToolFailure> {
//!         Ok(json!({ "account": self.account, "balance": 42 }))
//!     }
//! }
//! ```
//!
//! # What this design adds that the others do not need
//!
//! None of those frameworks has a security boundary to reconcile. This one does:
//! the **manifest** is the reviewable declaration of what an agent may reach, and
//! it stays the authority. So a typed tool does not replace the grant — it
//! supplies the *shape*, and [`ToolBox::check_against`] refuses a deployment
//! where the two disagree.
//!
//! That check is the point. Deriving a schema is ergonomics; noticing that the
//! code and the reviewed declaration have drifted apart is a control.

use std::collections::BTreeMap;
use std::fmt::Debug;

use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde_json::Value;

use super::{Disposition, ToolClient, ToolError, ToolId};

/// What a tool body knows about whether the world changed.
///
/// Named by **disposition** rather than by transport, because that is the only
/// thing the runtime does anything with — it decides whether a retry is a
/// correction or a second real invocation. A body writing its own logic has no
/// `TimedOut` to report; it has an answer, a refusal, or a genuine uncertainty,
/// and asking it to translate that into a wire vocabulary is asking it to guess
/// at a mapping it cannot see.
///
/// The [`ToolId`] is attached by the box that dispatched the call, so a body
/// cannot name a tool other than itself, and there is no boilerplate identity to
/// repeat on every error path.
///
/// There is deliberately no `Default` and no catch-all constructor: every
/// variant is a claim about the outside world, and the one that is safe to
/// assume does not exist.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ToolFailure {
    /// Nothing was done and nothing will have been. Safe to repeat.
    ///
    /// The right answer for a validation refusal, an unknown identifier, or any
    /// path that returns before touching anything. **Not** the right answer for
    /// "the call I made returned an error", because the far side may have acted
    /// before it failed.
    #[error("did not happen: {0}")]
    DidNotHappen(String),

    /// It may or may not have happened, and this code cannot tell.
    ///
    /// The honest answer whenever a request left this process and no
    /// acknowledgement came back. Repeating it is a coin flip with the outside
    /// world, so the runtime escalates instead — which is the point.
    #[error("outcome unknown: {0}")]
    InDoubt(String),

    /// It happened, and it failed.
    ///
    /// Distinct from [`DidNotHappen`](Self::DidNotHappen) because the work was
    /// done: repeating it would be a second real invocation, whatever it did
    /// before reporting failure.
    #[error("landed and failed: {0}")]
    Landed(String),
}

impl ToolFailure {
    /// What this says about whether the call reached the world.
    #[must_use]
    pub const fn disposition(&self) -> Disposition {
        match self {
            Self::DidNotHappen(_) => Disposition::DidNotHappen,
            Self::InDoubt(_) => Disposition::InDoubt,
            Self::Landed(_) => Disposition::Landed,
        }
    }

    /// Attach the identity of the tool that produced it.
    fn at(self, tool: ToolId) -> ToolError {
        let detail = match &self {
            Self::DidNotHappen(d) | Self::InDoubt(d) | Self::Landed(d) => d.clone(),
        };
        match self {
            // `Refused` rather than `Unreachable`: the tool ran its own logic
            // and declined. Both are `DidNotHappen`, and this one is true.
            Self::DidNotHappen(_) => ToolError::Refused { tool, detail },
            Self::InDoubt(_) => ToolError::TimedOut { tool, detail },
            Self::Landed(_) => ToolError::ToolFailed { tool, detail },
        }
    }
}

/// One tool: its name, its arguments, and what it does.
///
/// Implemented on the **argument type**, so the arguments are the tool. That is
/// what makes the schema derivable and the body typed — a `call` that received a
/// `Value` would be back to reading fields by hand.
#[async_trait]
pub trait Tool: DeserializeOwned + schemars::JsonSchema + Send + Sync + 'static {
    /// Which server offers it, as the transport names it.
    const SERVER: &'static str;
    /// Its name on that server.
    const NAME: &'static str;
    /// Whether calling it changes the world.
    ///
    /// Defaults to **true**, the same direction every other default here
    /// points: a tool nobody thought about gets the treatment that makes the
    /// runtime cautious.
    ///
    /// A *claim by the author about their own code*, not a grant — and it is
    /// load-bearing rather than decorative. [`ToolBox::check_against`] refuses a
    /// manifest that grants a self-declared mutating tool as read-only, because
    /// that exemption lets model-chosen arguments reach something that changes
    /// the world. The other direction is allowed: an operator may be stricter
    /// than the author, and often knows something the author forgot.
    fn mutates() -> bool {
        true
    }

    /// Do the thing.
    ///
    /// Takes `self` because the arguments **are** the tool: by the time this
    /// runs, the model's JSON has been deserialized into this type or the call
    /// was refused. There is no `Value` left to index into and no field to
    /// misspell.
    ///
    /// # Errors
    ///
    /// A [`ToolFailure`], which asks the author the **one** question that
    /// decides what the runtime may safely do next: did the world change?
    ///
    /// Deliberately **not** [`ToolError`], the transport vocabulary, which is
    /// the wrong shape for a body. That would make the author name their own
    /// [`ToolId`] on every error — boilerplate, and a foot-gun, since nothing
    /// would stop them naming a *different* tool. Worse, it would ask them to
    /// pick between `Unreachable`, `Refused`, `TimedOut`, `ToolFailed` and
    /// `Malformed`, which are facts about a wire that a body implementing its
    /// own logic does not have. The mapping from those to a disposition lives
    /// in this crate's head, and getting it wrong in the `DidNotHappen`
    /// direction is how a payment happens twice.
    async fn call(self) -> Result<Value, ToolFailure>;
}

/// Everything a registered tool exposes without being instantiated.
///
/// A trait object cannot carry associated constants or construct `Self`, so the
/// registry holds this instead: the same facts, resolved at registration.
struct Registered {
    description: String,
    schema: Value,
    mutates: bool,
    #[allow(clippy::type_complexity)]
    invoke: Box<
        dyn Fn(Value) -> futures_core::future::BoxFuture<'static, Result<Value, ToolError>>
            + Send
            + Sync,
    >,
}

/// A set of typed tools, dispatched by name **once, here**.
///
/// The name-to-implementation match still has to happen; the difference is that
/// it happens in one place inside this crate instead of in an `if` at the top of
/// every user's `ToolClient`. A tool added to the box cannot be forgotten in a
/// match arm, because there is no match arm.
#[derive(Default)]
pub struct ToolBox {
    tools: BTreeMap<ToolId, Registered>,
}

impl Debug for ToolBox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolBox")
            .field("tools", &self.tools.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl ToolBox {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a tool.
    ///
    /// Its schema is generated from the type, so the arguments a model is shown
    /// and the arguments the body receives are the same declaration.
    #[must_use]
    pub fn with<T: Tool>(mut self) -> Self {
        let schema = serde_json::to_value(schemars::schema_for!(T))
            .expect("a schemars-generated schema must serialize to JSON");
        // Keep the type's description for inspection and for deployments with
        // no manifest presentation. A declarative agent deliberately uses the
        // manifest's description instead: it is model-steering text, so a
        // change must be visible in the digest-covered review artifact.
        let description = schema
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let id = ToolId::new(T::SERVER, T::NAME);
        assert!(
            !self.tools.contains_key(&id),
            "typed tool '{id}' was registered twice — silently replacing one body with \
             another makes registration order decide which implementation runs"
        );
        self.tools.insert(
            id,
            Registered {
                description,
                schema,
                mutates: T::mutates(),
                invoke: Box::new(|args: Value| {
                    Box::pin(async move {
                        // The model's JSON becomes the tool's type here, or the
                        // call is refused. `Malformed`, because nothing reached
                        // the far side: arguments that do not fit the declared
                        // shape are a question the tool never saw.
                        //
                        // There is deliberately no mutation for this. The
                        // guarantee is structural — `from_value::<T>` yields a
                        // `T` or an error, and there is no branch to break — so
                        // a mutation would have to stop using the type at all,
                        // which is the old design rather than a defect in this
                        // one. An attempt to write one came back WEAK, which is
                        // the honest answer and the reason it is not here.
                        let parsed: T =
                            serde_json::from_value(args).map_err(|e| ToolError::Malformed {
                                tool: ToolId::new(T::SERVER, T::NAME),
                                detail: format!("arguments do not match the declared shape: {e}"),
                            })?;
                        // The id is attached here, where it is known for
                        // certain, rather than repeated in every error path of
                        // every body — which is also what stops a body naming
                        // some other tool.
                        parsed
                            .call()
                            .await
                            .map_err(|failure| failure.at(ToolId::new(T::SERVER, T::NAME)))
                    })
                }),
            },
        );
        self
    }

    /// The tools in this box, for a catalogue or a manifest to be checked
    /// against.
    pub fn ids(&self) -> impl Iterator<Item = &ToolId> {
        self.tools.keys()
    }

    /// The distinct servers these tools name.
    ///
    /// What [`ToolRouter::toolbox`](super::ToolRouter::toolbox) registers the
    /// box under, so the servers a box answers for are stated once — by the
    /// tools themselves — rather than repeated at the wiring call.
    pub fn servers(&self) -> impl Iterator<Item = &str> {
        // `BTreeMap` iterates in key order and `ToolId` orders by server first,
        // so equal servers are adjacent and skipping repeats is enough.
        let mut seen: Option<&str> = None;
        self.tools.keys().filter_map(move |id| {
            let server = id.server.as_str();
            if seen == Some(server) {
                return None;
            }
            seen = Some(server);
            Some(server)
        })
    }

    /// Refuse a deployment where the code and the reviewed declaration disagree.
    ///
    /// This is the part the other ecosystems do not need. Deriving a schema from
    /// a type is ergonomics; noticing that the manifest a reviewer approved and
    /// the tools this binary actually implements have drifted apart is a
    /// control.
    ///
    /// Two directions, and both are defects:
    ///
    /// * a tool in the box the manifest never granted — the binary can do
    ///   something the declaration does not admit, so the declaration stops
    ///   describing the agent;
    /// * a grant with no implementation — the manifest advertises a capability
    ///   to the model that will fail when chosen, which reads to the model as
    ///   the tool being broken rather than absent.
    ///
    /// Neither is caught by the dispatch gates: those refuse a *call*, and by
    /// then the disagreement has already shaped what the model was offered.
    ///
    /// `remote_servers` names the servers reached by some *other* path on the
    /// same plane — a tool transport, or a registered peer. A grant on one of
    /// those is somebody else's to implement, so this box neither claims it
    /// nor reports it missing — without that, a plane could never mix typed
    /// tools with an MCP server, because every MCP grant read as "granted but
    /// nothing implements it".
    ///
    /// # Errors
    ///
    /// Every disagreement found, so one run of this fixes all of them rather
    /// than the first.
    #[cfg(feature = "manifest")]
    pub fn check_against(
        &self,
        manifest: &crate::manifest::Manifest,
        remote_servers: &std::collections::BTreeSet<String>,
    ) -> Result<(), Vec<String>> {
        let granted: BTreeMap<ToolId, &crate::manifest::ToolGrant> = manifest
            .spec
            .tools
            .iter()
            .filter_map(|g| ToolId::parse(&g.reference).map(|id| (id, g)))
            .collect();

        let mut problems = Vec::new();
        for (id, registered) in &self.tools {
            // A manifest may be **stricter** than a tool claims and not laxer.
            //
            // The type's `mutates` is the author's statement about their own
            // code; the manifest is the deployment's. An operator being more
            // cautious is fine — they may know about a side effect the author
            // forgot, and the call is simply treated carefully. An operator
            // being *less* cautious is not: marking a self-declared mutating
            // tool read-only exempts it from the whole-value taint gate, so
            // model-chosen arguments reach something that changes the world.
            if registered.mutates && granted.get(id).is_some_and(|g| !g.mutates) {
                problems.push(format!(
                    "'{id}' declares that it mutates and the manifest grants it as \
                     read-only — that exemption lets model-chosen arguments reach \
                     something that changes the world"
                ));
            }
            if let Some(grant) = granted.get(id)
                && grant.arguments.is_some()
            {
                problems.push(format!(
                    "'{id}' repeats its argument schema in the manifest — typed tools \
                     derive it from the Rust argument type, so the second copy can only \
                     drift; remove `arguments` from this grant"
                ));
            }
        }
        for id in self.tools.keys() {
            if !granted.contains_key(id) {
                problems.push(format!(
                    "'{id}' is implemented but the manifest grants no such tool — \
                     this binary can do something its declaration does not admit"
                ));
            }
        }
        for id in granted.keys() {
            // Agent grants have no implementation *here* by design: dispatch is
            // `commission`, and whether the capability exists is checked at
            // build against the plane's registered agents.
            if id.server == super::AGENT_SERVER {
                continue;
            }
            if !self.tools.contains_key(id) && !remote_servers.contains(&id.server) {
                problems.push(format!(
                    "'{id}' is granted but nothing implements it and no transport is \
                     wired for server '{}' — the model will be offered a tool that \
                     fails when chosen",
                    id.server
                ));
            }
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(problems)
        }
    }

    /// What a tool declares about itself: description, schema, and whether it
    /// mutates.
    #[must_use]
    pub fn declared(&self, id: &ToolId) -> Option<(&str, &Value, bool)> {
        self.tools
            .get(id)
            .map(|t| (t.description.as_str(), &t.schema, t.mutates))
    }
}

#[async_trait]
impl ToolClient for ToolBox {
    async fn call(
        &self,
        tool: &ToolId,
        arguments: &Value,
        _provenance: Option<&crate::core::Provenance>,
    ) -> Result<Value, ToolError> {
        let Some(registered) = self.tools.get(tool) else {
            // `Refused`, not a transport failure: this box does not offer that
            // tool, and nothing was attempted. Saying so plainly beats a
            // timeout against nothing.
            return Err(ToolError::Refused {
                tool: tool.clone(),
                detail: "this box offers no such tool".to_owned(),
            });
        };
        (registered.invoke)(arguments.clone()).await
    }
}

#[cfg(test)]
mod tests {
    use super::{Disposition, Tool, ToolBox, ToolClient, ToolFailure, ToolId};
    use serde_json::{Value, json};

    /// Refuses on its own terms, before touching anything.
    #[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
    /// Read a ledger account's balance.
    struct Refuses {
        /// The account to read.
        account: String,
    }

    #[async_trait::async_trait]
    impl Tool for Refuses {
        const SERVER: &'static str = "ledger";
        const NAME: &'static str = "read";
        fn mutates() -> bool {
            false
        }
        async fn call(self) -> Result<Value, ToolFailure> {
            Err(ToolFailure::DidNotHappen(format!(
                "no account {}",
                self.account
            )))
        }
    }

    /// Each failure keeps its disposition, and gains the right identity.
    ///
    /// Both halves matter. The disposition is what the retry gate reads, so a
    /// mapping that collapsed `InDoubt` into `DidNotHappen` would make a
    /// timed-out mutating call retryable — the one direction nobody can be right
    /// about. And the id is attached by the box rather than repeated in the
    /// body, so a body physically cannot name a tool other than itself.
    #[test]
    fn a_failure_keeps_its_disposition_and_gains_the_calling_tools_identity() {
        for (failure, expected) in [
            (
                ToolFailure::DidNotHappen("nope".into()),
                Disposition::DidNotHappen,
            ),
            (ToolFailure::InDoubt("unknown".into()), Disposition::InDoubt),
            (ToolFailure::Landed("failed".into()), Disposition::Landed),
        ] {
            assert_eq!(failure.disposition(), expected);
            let id = ToolId::new("ledger", "read");
            let error = failure.clone().at(id.clone());
            assert_eq!(
                error.disposition(),
                expected,
                "attaching an identity changed what the runtime concludes about \
                 {failure:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_body_that_refuses_is_reported_as_not_having_happened() {
        let box_ = ToolBox::new().with::<Refuses>();
        let error = box_
            .call(
                &ToolId::new("ledger", "read"),
                &json!({ "account": "AC-9" }),
                None,
            )
            .await
            .expect_err("the body refused");

        assert_eq!(error.disposition(), Disposition::DidNotHappen);
        assert!(
            error.to_string().contains("AC-9"),
            "the body's own detail did not survive: {error}"
        );
    }
}
