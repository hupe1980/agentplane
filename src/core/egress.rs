//! Where this plane is permitted to connect.
//!
//! The sensitivity lattice controls *what* may leave; this controls
//! *where it may leave to*. They are different holes. A value can be perfectly
//! within its ceiling and still be posted to a host nobody granted.
//!
//! # The channel this closes
//!
//! An MCP server can advertise new tools at any time, and a model provider's
//! base URL is a string in a config file. Both are places where a *destination*
//! can appear without anybody deciding it should. That is a self-service egress
//! channel: discovery of a new capability quietly becomes permission to reach a
//! new host.
//!
//! So destinations are **granted, not discovered**. Discovering that a tool
//! exists stays fine; reaching a host nobody listed does not.
//!
//! # Deny by default, once configured
//!
//! An [`Egress`] permits nothing until told otherwise, which is the only default
//! that fails safe. But the *seam* is optional in exactly the way the policy
//! engine is: a runtime with no egress policy has none, and that is spelled
//! `None` rather than as a permissive allowlist. There is deliberately no
//! `Egress::allow_all()`, for the reason `core::policy` gives for having no
//! `AllowAll` — a deployment that wants no control should have to say so by
//! configuring nothing, not by configuring something that looks like a control
//! and is not.
//!
//! # Host, not URL
//!
//! Matching is on the **host**, and this type never parses a URL. URL parsing is
//! where allowlists are broken: `https://evil.example/#@allowed.example` and its
//! many cousins read one way to a careless splitter and another to a real
//! parser. The callers here already link a correct parser, so they hand over a
//! parsed host and this type does set membership on it.

use std::collections::BTreeSet;

/// The hosts this plane may connect to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Egress {
    hosts: BTreeSet<String>,
}

impl Egress {
    /// An allowlist that permits nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Grant one host.
    ///
    /// Hosts are compared case-insensitively, because DNS is, and an allowlist
    /// that can be bypassed by capitalising a letter is not one.
    #[must_use]
    pub fn allow(mut self, host: impl AsRef<str>) -> Self {
        self.hosts.insert(host.as_ref().to_ascii_lowercase());
        self
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.hosts.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }

    /// Every granted host, in a stable order.
    pub fn hosts(&self) -> impl Iterator<Item = &str> {
        self.hosts.iter().map(String::as_str)
    }

    /// Whether a connection to `host` is permitted.
    ///
    /// No wildcards, and that is deliberate. `*.example.com` reads as a
    /// convenience and is a grant of every host anybody can register under a
    /// domain — including one an attacker controls the moment a subdomain is
    /// dangling. A deployment that genuinely needs many hosts lists them.
    ///
    /// # Errors
    ///
    /// [`EgressError::NotGranted`], naming the host, so an operator reading the
    /// journal can see what was attempted rather than only that something was.
    pub fn permits(&self, host: Option<&str>) -> Result<(), EgressError> {
        // A destination with no host — a relative URL, a unix socket, a
        // malformed string — cannot be checked against an allowlist, and
        // "cannot be checked" resolves to "not permitted".
        let Some(host) = host else {
            return Err(EgressError::NoHost);
        };
        if self.hosts.contains(&host.to_ascii_lowercase()) {
            return Ok(());
        }
        Err(EgressError::NotGranted {
            host: host.to_owned(),
        })
    }
}

/// Why a connection was refused before it was made.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EgressError {
    #[error(
        "'{host}' is not a granted destination; a host reachable without being \
         listed is a self-service egress channel"
    )]
    NotGranted { host: String },

    #[error("the destination has no host, so it cannot be checked against the allowlist")]
    NoHost,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_allowlist_permits_nothing() {
        let e = Egress::new();
        assert!(e.permits(Some("api.anthropic.com")).is_err());
        assert!(e.is_empty());
    }

    #[test]
    fn a_granted_host_is_permitted() {
        let e = Egress::new().allow("api.anthropic.com");
        assert!(e.permits(Some("api.anthropic.com")).is_ok());
    }

    #[test]
    fn an_ungranted_host_is_refused_and_named() {
        let e = Egress::new().allow("api.anthropic.com");
        let err = e.permits(Some("evil.example")).expect_err("not granted");
        assert_eq!(
            err,
            EgressError::NotGranted {
                host: "evil.example".to_owned()
            }
        );
        assert!(err.to_string().contains("evil.example"));
    }

    /// DNS is case-insensitive; an allowlist that is not can be walked past.
    #[test]
    fn matching_is_case_insensitive() {
        let e = Egress::new().allow("API.Anthropic.COM");
        assert!(e.permits(Some("api.anthropic.com")).is_ok());
        assert!(e.permits(Some("API.ANTHROPIC.COM")).is_ok());
    }

    /// A grant is exactly one host. No wildcards, no suffix matching.
    #[test]
    fn a_grant_does_not_extend_to_subdomains() {
        let e = Egress::new().allow("example.com");
        assert!(e.permits(Some("evil.example.com")).is_err());
        assert!(e.permits(Some("example.com.evil.test")).is_err());
        assert!(
            e.permits(Some("notexample.com")).is_err(),
            "a suffix comparison would have let this through"
        );
    }

    /// Unparseable means unpermitted.
    #[test]
    fn a_destination_with_no_host_is_refused() {
        let e = Egress::new().allow("example.com");
        assert_eq!(e.permits(None), Err(EgressError::NoHost));
    }

    #[test]
    fn grants_are_listable_for_an_operator() {
        let e = Egress::new().allow("b.example").allow("a.example");
        assert_eq!(
            e.hosts().collect::<Vec<_>>(),
            vec!["a.example", "b.example"]
        );
        assert_eq!(e.len(), 2);
    }
}
