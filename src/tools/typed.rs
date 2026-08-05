//! Defining a tool once, as one thing.
//!
//! # What this replaces, and why it was wrong
//!
//! A tool used to be three artifacts that nothing reconciled:
//!
//! * an argument schema hand-written in the manifest;
//! * a `ToolClient` implementation that matched on the tool's **name** and read
//!   arguments out of a `Value` by hand — `arguments["id"].as_str()`;
//! * whatever JSON the model actually sent.
//!
//! Nothing checked that the three agreed. A field renamed in the manifest and
//! not in the code produced `None`, and a `.unwrap_or(default)` turned that into
//! a plausible wrong answer rather than an error. Dispatching on the name is
//! also [stringly-typed control flow] — the shape this codebase rejects
//! everywhere else.
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
//! # use agentplane::tools::{Tool, ToolError};
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
//!     async fn call(self) -> Result<Value, ToolError> {
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

use super::{ToolClient, ToolError, ToolId};

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
    /// A [`ToolError`] whose variant states what is known about whether the call
    /// reached the far side.
    async fn call(self) -> Result<Value, ToolError>;
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
                        parsed.call().await
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
    /// # Errors
    ///
    /// Every disagreement found, so one run of this fixes all of them rather
    /// than the first.
    #[cfg(feature = "manifest")]
    pub fn check_against(&self, manifest: &crate::manifest::Manifest) -> Result<(), Vec<String>> {
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
            if !self.tools.contains_key(id) {
                problems.push(format!(
                    "'{id}' is granted but nothing implements it — the model will \
                     be offered a tool that fails when chosen"
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
