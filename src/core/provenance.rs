//! What a run tells a callee about itself, and why it has to be signed.
//!
//! A tool call carries a little context — which run, which case, which effect,
//! which agent — so a server can correlate, deduplicate, and log something more
//! useful than "somebody called me". MCP has a place for it (`_meta`) and so
//! does A2A.
//!
//! # Asserted provenance is a debugging aid, not an input
//!
//! Sent as plain fields, every one of them is a claim the callee cannot check.
//! A compromised intermediary — a proxy, a gateway, a sidecar, another agent in
//! the chain — writes whatever it likes, and a receiving tool has no way to tell
//! a real `run_id` from an invented one. That is fine for a log line and
//! disqualifying for a decision: the moment a callee *authorizes* on this, it is
//! trusting whatever the last hop wrote.
//!
//! So the block is **attested**. The fields are hashed canonically and signed by
//! the run's workload identity, and a callee that holds the corresponding public
//! key can check the claim rather than believe it.
//!
//! # What the signature covers, and why it is more than the fields
//!
//! Signing the identifiers alone would be worse than useless — it would be
//! *convincing* and wrong. An attestation over `{run, case, effect, agent}` is
//! valid for those identifiers no matter what request it rides on, so anybody
//! who observes one legitimate call can lift the block and attach it to a
//! different one. The provenance would verify perfectly on a request the run
//! never made.
//!
//! The payload therefore binds the **call**: the tool being invoked and a digest
//! of its arguments. Move the block to another tool, or change one argument, and
//! the signature no longer verifies. That is the difference between "this run
//! exists" and "this run asked for exactly this".
//!
//! # What it is still not
//!
//! Not authorization. A verified attestation says *who is calling and what they
//! asked for*; whether they may is the callee's decision, made against its own
//! policy and the delegation chain. Provenance that authorizes by
//! existing is a bearer token with extra steps.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::core::{Attestation, CaseId, Digest, EffectKey, RunId, Signer, Verifier, canon};

/// The `_meta` key prefix this crate writes under.
///
/// Namespaced because `_meta` is shared: MCP reserves the space and other
/// extensions write into the same object, so an unprefixed `run_id` is a
/// collision waiting for the first server that has its own.
///
/// Under a domain the project controls. These keys travel to other people's
/// servers, so a prefix nobody here registered is a collision waiting for
/// whoever registers it later.
///
/// **Reverse DNS**, which is where MCP is going rather than where it has been.
/// The released specification expresses no preference and its reserved prefixes
/// read left to right (`modelcontextprotocol.io/`); the draft adds "SHOULD use
/// reverse DNS notation", names `example.com/` as the form not to use, and
/// re-spells MCP's own keys as `io.modelcontextprotocol/`. Both directions are
/// valid key names under either version, so adopting the destination early
/// costs nothing and saves a rename on a wire identifier later.
///
/// `io.github.<user>` is the namespace GitHub Pages ownership establishes — the
/// same derivation Maven Central grants GitHub users — so a reader can check
/// who holds it. The second label is `github`, so this does not fall in the
/// space MCP reserves (`modelcontextprotocol` or `mcp`).
pub const NS: &str = "io.github.hupe1980.agentplane/";

/// Who is calling, on whose behalf, for which piece of work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    pub run: RunId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub case: Option<CaseId>,
    /// Which effect within the run — unique per run *and per attempt*.
    pub effect: EffectKey,
    /// The logical dispatch, stable across retries of the same call.
    ///
    /// [`effect`](Self::effect) hashes the attempt number, and it must: without
    /// it a retry would collide with the recorded failure of the attempt before
    /// it, and replay would read back the failure instead of the retry.
    ///
    /// That makes it the wrong thing to hand a callee for **duplicate
    /// detection**, which is the opposite question — "have I already done this
    /// work?" — and must answer *yes* for a retry. A peer given the effect key
    /// sees two unrelated messages and may act twice, which is precisely the
    /// outcome deduplication exists to prevent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dispatch: Option<EffectKey>,
    /// The agent, as the deployment names it.
    pub agent: String,
    /// The signature over [`payload`](Self::payload), if the plane has a signer.
    ///
    /// `None` is honest rather than convenient: a plane with no workload
    /// identity cannot attest, and a self-signed block would look attested and
    /// prove nothing — the same reasoning that keeps unsigned journal records
    /// unsigned rather than self-signed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<Attestation>,
}

impl Provenance {
    #[must_use]
    pub fn new(run: RunId, effect: EffectKey, agent: impl Into<String>) -> Self {
        Self {
            run,
            case: None,
            effect,
            dispatch: None,
            agent: agent.into(),
            attestation: None,
        }
    }

    /// Name the logical dispatch this call belongs to.
    ///
    /// See [`Provenance::dispatch`] for why it is not the effect key.
    #[must_use]
    pub const fn dispatching(mut self, dispatch: EffectKey) -> Self {
        self.dispatch = Some(dispatch);
        self
    }

    /// The identity a callee should deduplicate on.
    ///
    /// Falls back to the effect key when no dispatch id was supplied, which is
    /// wrong across retries and right for everything else — and is what a
    /// transport gets if the runtime did not set one.
    #[must_use]
    pub fn dedupe_key(&self) -> EffectKey {
        self.dispatch.unwrap_or(self.effect)
    }

    #[must_use]
    pub const fn in_case(mut self, case: Option<CaseId>) -> Self {
        self.case = case;
        self
    }

    /// The bytes a signature covers.
    ///
    /// Canonical — the same map always hashes the same way — because the callee
    /// recomputes this from the wire form and the two must agree byte for byte.
    /// Uses this crate's own canonical writer rather than `serde_json`'s
    /// ordering, for the reason recorded against `core::canon`: map order is not
    /// something to inherit from a dependency's feature flags.
    ///
    /// `target` and `arguments` are what bind the attestation to *this call*.
    #[must_use]
    pub fn payload(&self, target: &str, arguments: &Value) -> Digest {
        let claim = json!({
            "run": self.run.to_string(),
            "case": self.case.map(|c| c.to_string()),
            "effect": self.effect.to_string(),
            "agent": self.agent,
            "target": target,
            // The arguments by digest rather than by value: a payload that
            // embedded them would grow without bound and would put the caller's
            // data into anything that logs the signature's input.
            "arguments": Digest::of(canon::value_bytes(arguments).as_slice()).to_string(),
        });
        Digest::of(canon::value_bytes(&claim).as_slice())
    }

    /// Sign this block for one specific call.
    #[must_use]
    pub fn seal(mut self, signer: &dyn Signer, target: &str, arguments: &Value) -> Self {
        self.attestation = Some(signer.attest(&self.payload(target, arguments)));
        self
    }

    /// Whether this block was signed for exactly this call.
    ///
    /// The callee's side. Returns `false` for an unsigned block, an unknown key,
    /// and a signature made for a different call alike — they are the same
    /// answer to the only question being asked, which is *may I act on this*.
    #[must_use]
    pub fn verify(&self, verifier: &dyn Verifier, target: &str, arguments: &Value) -> bool {
        let Some(a) = &self.attestation else {
            return false;
        };
        verifier.verify(&a.key_id, &self.payload(target, arguments), &a.signature)
    }

    /// The wire form: a `_meta`-shaped object.
    #[must_use]
    pub fn to_meta(&self) -> serde_json::Map<String, Value> {
        let mut m = serde_json::Map::new();
        m.insert(format!("{NS}run_id"), json!(self.run.to_string()));
        if let Some(case) = self.case {
            m.insert(format!("{NS}case_id"), json!(case.to_string()));
        }
        m.insert(format!("{NS}effect_key"), json!(self.effect.to_string()));
        m.insert(format!("{NS}agent"), json!(self.agent));
        if let Some(a) = &self.attestation {
            m.insert(
                format!("{NS}attestation"),
                serde_json::to_value(a).unwrap_or(Value::Null),
            );
        }
        m
    }

    /// Read a block back off the wire.
    ///
    /// For a callee, and for the tests that stand in for one. Returns `None`
    /// when the required fields are absent or malformed — a partially parsed
    /// block is not something to act on.
    #[must_use]
    pub fn from_meta(meta: &serde_json::Map<String, Value>) -> Option<Self> {
        let s = |k: &str| meta.get(&format!("{NS}{k}"))?.as_str().map(str::to_owned);
        Some(Self {
            run: RunId::parse(&s("run_id")?).ok()?,
            // Not carried on the wire yet: a callee deduplicates on the id the
            // transport hands it, and this block is the *caller's* record of
            // what it sent.
            dispatch: None,
            case: match s("case_id") {
                Some(c) => Some(CaseId::parse(&c).ok()?),
                None => None,
            },
            // `Display` writes `ek:<hex>`; strip the tag the same way the
            // id types do, so a caller can paste either form back.
            effect: {
                let raw = s("effect_key")?;
                EffectKey::from_hex(raw.strip_prefix("ek:").unwrap_or(&raw)).ok()?
            },
            agent: s("agent")?,
            attestation: meta
                .get(&format!("{NS}attestation"))
                .and_then(|v| serde_json::from_value(v.clone()).ok()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{Phase, StepId};

    fn key(n: u32) -> EffectKey {
        EffectKey::derive(StepId(0), Phase::Forward, n, 1, "tool.call", b"{}")
    }

    /// Deliberately forgeable, and that is fine here: what these tests check is
    /// *what the signature covers*, not how hard it is to forge.
    #[derive(Debug)]
    struct Stub;

    impl Signer for Stub {
        fn key_id(&self) -> crate::core::KeyId {
            "spiffe://example.org/plane/a".to_owned()
        }
        fn sign(&self, hash: &Digest) -> Vec<u8> {
            hash.to_hex().into_bytes()
        }
    }

    impl Verifier for Stub {
        fn verify(&self, key_id: &str, hash: &Digest, signature: &[u8]) -> bool {
            key_id == self.key_id() && signature == self.sign(hash)
        }
    }

    fn block() -> Provenance {
        Provenance::new(RunId::generate(), key(0), "auditor@2.0.0")
    }

    #[test]
    fn a_sealed_block_verifies_for_the_call_it_was_sealed_for() {
        let args = json!({ "target_id": "ID-88219-A" });
        let p = block().seal(&Stub, "data.fetch", &args);
        assert!(p.verify(&Stub, "data.fetch", &args));
    }

    /// **The property the whole design turns on.**
    ///
    /// An attestation over the identifiers alone would be valid on any request,
    /// so anybody observing one legitimate call could lift the block onto a
    /// different tool. Binding the target is what stops that.
    #[test]
    fn an_attestation_cannot_be_lifted_onto_another_tool() {
        let args = json!({ "amount": 1 });
        let p = block().seal(&Stub, "reports.read", &args);
        assert!(
            !p.verify(&Stub, "billing.transfer", &args),
            "a block sealed for one tool verified on another — provenance that \
             travels is provenance that proves nothing about the call carrying it"
        );
    }

    /// And the arguments, for the same reason one step further in.
    #[test]
    fn an_attestation_cannot_be_lifted_onto_other_arguments() {
        let p = block().seal(&Stub, "billing.transfer", &json!({ "amount": 1 }));
        assert!(
            !p.verify(&Stub, "billing.transfer", &json!({ "amount": 1_000_000 })),
            "the amount changed and the attestation still verified"
        );
    }

    /// Argument order must not change the digest, or a callee that reserialises
    /// before checking gets a false negative on a legitimate call.
    #[test]
    fn argument_key_order_does_not_change_the_payload() {
        let p = block();
        let a = json!({ "a": 1, "b": 2 });
        let b = json!({ "b": 2, "a": 1 });
        assert_eq!(p.payload("t", &a), p.payload("t", &b));
    }

    #[test]
    fn a_different_run_is_a_different_payload() {
        let args = json!({});
        let one = block().seal(&Stub, "t", &args);
        let two =
            Provenance::new(RunId::generate(), key(0), "auditor@2.0.0").seal(&Stub, "t", &args);
        assert_ne!(one.attestation, two.attestation);
    }

    #[test]
    fn an_unsigned_block_never_verifies() {
        assert!(
            !block().verify(&Stub, "t", &json!({})),
            "an unsigned block must not pass — a plane with no identity cannot \
             attest, and treating absence as assent is how a compromised \
             intermediary gets believed"
        );
    }

    #[test]
    fn a_tampered_field_is_caught() {
        let args = json!({});
        let mut p = block().seal(&Stub, "t", &args);
        p.agent = "someone-else@9.9.9".to_owned();
        assert!(!p.verify(&Stub, "t", &args));
    }

    #[test]
    fn the_wire_form_round_trips() {
        let args = json!({ "x": 1 });
        let p = block()
            .in_case(Some(crate::core::CaseId::generate()))
            .seal(&Stub, "t", &args);
        let meta = p.to_meta();
        let back = Provenance::from_meta(&meta).expect("round trip");
        assert_eq!(back, p);
        assert!(back.verify(&Stub, "t", &args), "and it still verifies");
    }

    /// `_meta` is shared, so the keys have to be namespaced.
    #[test]
    fn every_wire_key_is_namespaced() {
        let meta = block().seal(&Stub, "t", &json!({})).to_meta();
        assert!(meta.keys().all(|k| k.starts_with(NS)), "{meta:?}");
        assert!(meta.contains_key("io.github.hupe1980.agentplane/run_id"));
    }

    /// A block whose signature was stripped in transit must not read as absent.
    #[test]
    fn a_stripped_attestation_does_not_verify() {
        let args = json!({});
        let p = block().seal(&Stub, "t", &args);
        let mut meta = p.to_meta();
        meta.remove("io.github.hupe1980.agentplane/attestation");
        let back = Provenance::from_meta(&meta).expect("still parses");
        assert!(back.attestation.is_none());
        assert!(!back.verify(&Stub, "t", &args));
    }
}
