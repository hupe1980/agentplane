//! Values a declaration names rather than states.
//!
//! A manifest is a constant document: it is reviewed once, digested, and then
//! governs every run. That is exactly right for a grant, a ceiling or a prompt,
//! and exactly wrong for the one thing a *durable memory* needs — the scope it
//! is filed under.
//!
//! # The gap a literal subject leaves
//!
//! A declared subject decides which pile a fact lands in — and, for a declared
//! recall, which pile is read back — and the pile is the unit
//! [`MemoryStore::forget_subject`] erases. A literal subject
//! therefore pools every customer, every meter and every matter the agent ever
//! reasoned about under one key — so one subject's facts are recalled into
//! another subject's run, and an erasure request naming one person cannot be
//! satisfied without destroying everybody's. Under a data-protection regime
//! that is not a caveat to document; it is a defect.
//!
//! A **coded** skill never had this problem: [`MemoryWrite::new`] takes the
//! subject as a runtime value. Only the declarative tier was stuck with a
//! compile-time literal, and the declarative tier is the one this crate
//! otherwise pushes people toward.
//!
//! [`MemoryStore::forget_subject`]: crate::memory::MemoryStore::forget_subject
//! [`MemoryWrite::new`]: crate::memory::MemoryWrite::new
//!
//! # Why the sources are these three and not "any expression"
//!
//! A binding resolves against something the **run** already established, and
//! each source here is one a reviewer can name and the runtime can prove:
//!
//! * `$correlation/<namespace>` — a business key the run was admitted with.
//!   Correlation is a deterministic lookup performed before planning, from keys
//!   an operator's edge supplied; no model ever touches it.
//! * `$case` — the case id itself, for an agent whose memory scope *is* the
//!   matter rather than a party to it.
//! * `$input/<pointer>` — a field of the run's input, by RFC 6901 pointer, and
//!   **only if that field is trusted**. A subject taken from untrusted input is
//!   an attacker choosing whose file to write into, which is a worse failure
//!   than the pooling this feature exists to fix.
//!
//! There is deliberately no arithmetic, no concatenation and no default. Each
//! would be a small step toward a template language inside a security document,
//! and the value of the document is that a reviewer can read a line and know
//! what it will be.
//!
//! # `$$` escapes
//!
//! A literal subject that genuinely begins with `$` is written `$$`. An
//! unrecognised `$`-prefixed value is **refused**, never taken as a literal:
//! `$correlaton/malo` is a typo, and reading it as the constant string
//! `"$correlaton/malo"` would file every customer's memories under the typo.

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

/// Which memory scope a declaration names, as the manifest spells it.
///
/// One type for both halves of `spec.memory`: the pile a formation writes to
/// and the pile a recall reads from are the same kind of thing, and an agent
/// whose two halves could spell a scope differently would file facts it could
/// never read.
///
/// Serialises as the string it was written as, so the manifest digest covers
/// the binding exactly as authored and a round-trip cannot normalise one form
/// into another.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MemorySubject {
    /// A constant, exactly as written.
    ///
    /// Still the right answer for a genuinely global scope — an operator's
    /// reference corpus, a team-wide policy digest — and it stays the default
    /// spelling because a subject with no `$` in it means what it says.
    Literal(String),
    /// The value of one of the run's correlation keys, by namespace.
    Correlation(String),
    /// The case this run belongs to.
    Case,
    /// A field of the run's input, by RFC 6901 pointer. Empty means the whole
    /// input.
    Input(String),
}

impl MemorySubject {
    /// Parse the manifest spelling.
    ///
    /// # Errors
    ///
    /// A message naming the spelling and what was expected, for any `$`-prefixed
    /// value that is not one of the three bindings — because the alternative is
    /// filing memories under a typo.
    pub fn parse(raw: &str) -> Result<Self, String> {
        if let Some(rest) = raw.strip_prefix("$$") {
            return Ok(Self::Literal(format!("${rest}")));
        }
        let Some(binding) = raw.strip_prefix('$') else {
            return Ok(Self::Literal(raw.to_owned()));
        };
        if binding == "case" {
            return Ok(Self::Case);
        }
        if let Some(namespace) = binding.strip_prefix("correlation/") {
            if namespace.is_empty() {
                return Err(
                    "'$correlation/' names no namespace — write the correlation key's \
                     namespace after the slash, e.g. '$correlation/meter'"
                        .to_owned(),
                );
            }
            return Ok(Self::Correlation(namespace.to_owned()));
        }
        if let Some(pointer) = binding.strip_prefix("input") {
            if !pointer.is_empty() && !pointer.starts_with('/') {
                return Err(format!(
                    "'{raw}' is not an input reference — a pointer after '$input' is \
                     RFC 6901 and begins with '/', e.g. '$input/customer/id'"
                ));
            }
            return Ok(Self::Input(pointer.to_owned()));
        }
        Err(format!(
            "'{raw}' is not a binding this crate understands. Use \
             '$correlation/<namespace>', '$case', '$input/<pointer>', or write '$$' \
             for a literal that really begins with a dollar sign — an unrecognised \
             binding is not read as a constant, because a typo would file every \
             subject's memories under the typo"
        ))
    }

    /// The manifest spelling, exactly as it would be written.
    ///
    /// The inverse of [`parse`](Self::parse) — pinned by a round-trip test,
    /// because this is what the digest is taken over.
    #[must_use]
    pub fn as_written(&self) -> String {
        match self {
            Self::Literal(value) if value.starts_with('$') => format!("${value}"),
            Self::Literal(value) => value.clone(),
            Self::Correlation(namespace) => format!("$correlation/{namespace}"),
            Self::Case => "$case".to_owned(),
            Self::Input(pointer) => format!("$input{pointer}"),
        }
    }

    /// Whether this is resolved at run time rather than read off the file.
    #[must_use]
    pub const fn is_bound(&self) -> bool {
        !matches!(self, Self::Literal(_))
    }

    /// Whether resolving this needs the run to belong to a case.
    #[must_use]
    pub const fn needs_case(&self) -> bool {
        matches!(self, Self::Correlation(_) | Self::Case)
    }
}

impl std::fmt::Display for MemorySubject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.as_written())
    }
}

impl Serialize for MemorySubject {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.as_written())
    }
}

impl<'de> Deserialize<'de> for MemorySubject {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every spelling round-trips, because the written form is what the digest
    /// covers.
    ///
    /// A normalising parser would make two files that a reviewer reads as
    /// different documents share one identity — or, worse, make one file's
    /// digest depend on which direction it was last converted.
    #[test]
    fn every_binding_round_trips_through_its_written_form() {
        for written in [
            "agent:triage",
            "$correlation/malo",
            "$correlation/document-number",
            "$case",
            "$input",
            "$input/customer/id",
            "$$literal-dollar",
        ] {
            let parsed = MemorySubject::parse(written).expect("a valid binding");
            assert_eq!(parsed.as_written(), written, "round trip of {written}");
        }
    }

    /// `$$x` is the literal `$x`, and `$x` is a refusal.
    #[test]
    fn an_unrecognised_binding_is_refused_rather_than_taken_as_a_constant() {
        assert_eq!(
            MemorySubject::parse("$$agent:triage"),
            Ok(MemorySubject::Literal("$agent:triage".to_owned()))
        );
        // The typo that motivated the rule.
        let refused = MemorySubject::parse("$correlaton/malo").expect_err("a typo is refused");
        assert!(refused.contains("$correlation/<namespace>"), "{refused}");
        // A binding head with no namespace says so specifically.
        assert!(
            MemorySubject::parse("$correlation/")
                .expect_err("an empty namespace is refused")
                .contains("names no namespace")
        );
        // A pointer that is not a pointer.
        assert!(
            MemorySubject::parse("$inputcustomer")
                .expect_err("a malformed pointer is refused")
                .contains("RFC 6901")
        );
    }

    /// The two questions the runtime asks a binding before resolving it.
    #[test]
    fn a_binding_states_whether_it_is_dynamic_and_whether_it_needs_a_case() {
        let literal = MemorySubject::parse("team:billing").expect("literal");
        assert!(!literal.is_bound());
        assert!(!literal.needs_case());

        for written in ["$correlation/malo", "$case"] {
            let bound = MemorySubject::parse(written).expect("binding");
            assert!(bound.is_bound(), "{written}");
            assert!(bound.needs_case(), "{written}");
        }

        let from_input = MemorySubject::parse("$input/malo").expect("binding");
        assert!(from_input.is_bound());
        assert!(
            !from_input.needs_case(),
            "an input binding reads the run's own input and needs no case"
        );
    }
}
