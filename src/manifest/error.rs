//! Why a manifest was refused.

/// A manifest this crate will not run.
///
/// Every variant is a refusal rather than a warning. A manifest is the document
/// that says what an agent may do; running a version of it the crate had to
/// guess at would make the declaration worth less than the code it replaced.
#[derive(thiserror::Error)]
pub enum ManifestError {
    /// Not well-formed — which includes an **unknown field**.
    ///
    /// Worth being blunt about why that is fatal rather than ignorable:
    /// `max_tokns: 100` in a permissive parser means *no token ceiling*, and
    /// the run that discovers it is the expensive one. A field this crate does
    /// not recognise in a security document is a mistake, not an extension.
    #[error("manifest is not well-formed: {0}")]
    Syntax(String),

    /// A different schema, or a different kind of object.
    #[error(
        "this is a '{kind}' at '{api_version}' — expected an 'Agent' at \
         'agentplane.hupe1980.github.io/v1alpha1'. A manifest whose meaning the \
         runtime has to guess is worse than no manifest"
    )]
    WrongDocument { api_version: String, kind: String },

    /// A field is present and says nothing.
    #[error("{0} is empty — declare it or remove it, but do not leave it blank")]
    Empty(&'static str),

    /// `spec.output.schema` is not a JSON object.
    #[error(
        "spec.output.schema is {found}, not a JSON Schema object — a result \
         contract the runtime cannot hand to a provider is a contract in name only"
    )]
    NotASchema { found: &'static str },

    /// The declared arrangement contradicts itself.
    ///
    /// Kept separate from a bad *value* because the fields are individually
    /// fine: it is the combination that describes nothing. A manifest whose
    /// topology is incoherent would pass review looking like one that governs an
    /// arrangement, which is worse than one that never claimed to.
    #[error("spec.topology declares {detail}")]
    IncoherentTopology { detail: &'static str },

    /// A field was declared where nothing could enforce it.
    ///
    /// The binding rule as an error. A manifest naming a control the runtime
    /// will not apply is worse than one that stays quiet, because the reviewer
    /// who approved it believes the control exists.
    #[error("{field} cannot be enforced here: {detail}")]
    Unenforceable {
        field: &'static str,
        detail: &'static str,
    },

    /// No budget at all.
    ///
    /// Refused because "unbounded" is a decision somebody should make on
    /// purpose. An agent with no ceiling is exactly the one that runs up a bill
    /// nobody authorised, and silence in a config file is how that happens
    /// without anyone choosing it. `budgets: {}` says it deliberately.
    #[error(
        "no budgets declared. An agent with no ceiling is the one that runs up a \
         bill nobody authorised — write `budgets: {{}}` if you mean unbounded, so \
         that the decision is in the file rather than in its absence"
    )]
    Unbounded,
}

crate::core::error::debug_is_display!(ManifestError);
