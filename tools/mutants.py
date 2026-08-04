#!/usr/bin/env python3
"""Break a guarantee on purpose, and check that a test notices.

`spec/mutations.py` does this for the specs: each spec is re-run against
deliberately broken copies of itself, and every mutant must trip the invariant
written to catch it. The reasoning was that a spec which passes with its own bug
present proves nothing.

The same reasoning applies to the code, and for a long time it was not applied
there — mutations were run by hand, once, when a feature was written, and never
again. That gap is not theoretical. `cx.effect()` used to return an unlabelled
value, so the runtime's own fixtures wrapped tool results in
`Tainted::trusted(..)`; the refusal to replan on untrusted data was therefore
implemented, tested, and **unfalsifiable** — deleting it would have failed no
test. It was found by accident. This file is so the next one is not.

Each mutation names the ONE test that must fail. Tripping *some* test proves only
that something broke; it does not prove the test written to catch this bug is the
one that caught it, and a mutation caught by an unrelated test usually means the
guarantee has no test of its own.

A mutation whose anchor no longer matches is an **error**, not a skip: the code
moved and the mutation is silently testing nothing.

Usage:  mutants.py --list           (tab-separated: name, file, test, description)
        mutants.py <name> --apply   (rewrite the file in place)
        mutants.py <name> --revert  (restore from the .orig backup)
"""

from __future__ import annotations

import os
import pathlib
import shutil
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent

# name -> (file, test that must fail, description, find, replace)
#
# `find` must appear verbatim, exactly once.
MUTANTS: dict[str, tuple[str, str, str, str, str]] = {
    # ── Exactly-once ────────────────────────────────────────────────────────
    "ReplayRePerforms": (
        "src/runtime/ctx.rs",
        "a_committed_but_lost_effect_record_is_not_performed_again",
        "replay re-performs a completed effect instead of reading it back",
        """                        self.replayed_done(&descriptor.kind, attempt, spend);
                        return Ok(serde_json::from_value(output)?);""",
        """                        self.replayed_done(&descriptor.kind, attempt, spend);
                        let _ = output;""",
    ),
    "MediaReplayRePerforms": (
        "src/runtime/ctx.rs",
        "strict_replay_does_not_read_media_blobs_or_call_the_model",
        "strict replay re-materializes a media blob and calls the model again",
        """                        self.replayed_done(&descriptor.kind, attempt, spend);
                        return Ok(serde_json::from_value(output)?);""",
        """                        self.replayed_done(&descriptor.kind, attempt, spend);
                        if descriptor.kind == "model.complete" {
                            let _ = effect.perform().await;
                        }
                        return Ok(serde_json::from_value(output)?);""",
    ),
    "NoReplayCursor": (
        "src/journal/replay.rs",
        "no_crash_point_breaks_a_successful_run",
        "the replay cursor is empty, so nothing is ever read back",
        "        Self { by_step }",
        "        let _ = by_step;\n        Self {\n            by_step: BTreeMap::new(),\n        }",
    ),
    # ── Divergence ──────────────────────────────────────────────────────────
    "IgnoreKeyMismatch": (
        "src/journal/replay.rs",
        "resume_refuses_a_journal_written_by_different_code",
        "a recomputed effect key that differs from history is accepted",
        """        if *expected != recomputed {
            return Err(StepError::NonDeterminism {
                seq: *seq,
                expected: *expected,
                actual: recomputed,
            });
        }
        self.pos += 1;""",
        """        let _ = expected;
        self.pos += 1;""",
    ),
    # ── Retry safety ────────────────────────────────────────────────────────
    "RetryWhatLanded": (
        "src/runtime/ctx.rs",
        "an_effect_that_landed_is_never_repeated",
        "an effect that definitely landed is retried anyway",
        """            Disposition::Landed => {
                return Some(StepError::Effect(crate::core::EffectError::Other(format!(
                    "effect {key} took effect and its response could not be used ({message}); \\
                     repeating it would perform it a second time"
                ))));
            }""",
        """            Disposition::Landed => {
                let _ = (&key, &message);
                return None;
            }""",
    ),
    # ── Sagas ───────────────────────────────────────────────────────────────
    "UnwindForwards": (
        "src/runtime/executor.rs",
        "a_failing_step_unwinds_the_completed_ones_in_reverse",
        "completed steps are undone in the order they ran",
        "        for (step, capability) in completed.iter().rev().cloned() {",
        "        for (step, capability) in completed.iter().cloned() {",
    ),
    "UnwindPastPivot": (
        "src/runtime/executor.rs",
        "a_pivot_stops_the_unwind",
        "the unwind continues past the point of no return",
        "                crate::core::Compensation::Pivot => break,",
        "                crate::core::Compensation::Pivot => continue,",
    ),
    "UnwindUnderDoubt": (
        "src/runtime/executor.rs",
        "a_quarantined_run_is_never_unwound",
        "a run holding an unknown outcome is unwound anyway",
        "            RunStatus::Failed(_) | RunStatus::Exhausted(_) | RunStatus::Cancelled { .. } => {}",
        "            RunStatus::Failed(_)\n            | RunStatus::Exhausted(_)\n            | RunStatus::Cancelled { .. }\n            | RunStatus::Quarantined(_) => {}",
    ),
    # ── Information flow ────────────────────────────────────────────────────
    "TrustToolOutput": (
        "src/core/effect.rs",
        "an_effect_output_is_untrusted_by_default",
        "effect output defaults to trusted",
        """    fn trust(&self) -> Trust {
        Trust::Untrusted
    }""",
        """    fn trust(&self) -> Trust {
        Trust::Trusted
    }""",
    ),
    "NoTaintGate": (
        "src/runtime/ctx.rs",
        "tool_output_cannot_reach_a_mutating_sink",
        "untrusted data may reach a mutating sink",
        """        if protected.is_empty() {
            if effect.mutates() && label.is_untrusted() {
                return Err(PolicyError::TaintGate { sink: sink_name }.into());
            }
            return Ok(());
        }""",
        """        if protected.is_empty() {
            let _ = label;
            return Ok(());
        }""",
    ),
    "ReadOnlyProtectedFieldsIgnored": (
        "src/runtime/ctx.rs",
        "untrusted_data_cannot_select_a_protected_read_only_argument",
        "a read-only effect skips its declared authority-bearing field checks",
        "        if protected.is_empty() {",
        "        if !effect.mutates() || protected.is_empty() {",
    ),
    "ReleaseWithoutPolicy": (
        "src/runtime/ctx.rs",
        "policy_can_refuse_a_release_before_the_label_is_improved",
        "a typed release improves a label without authorization",
        "        self.authorize_release(key, &release, &label).await?;",
        "        let _ = (key, &release, &label);",
    ),
    "ReleaseReplayDriftIgnored": (
        "src/runtime/ctx.rs",
        "changing_release_evidence_is_replay_divergence",
        "strict replay accepts a release with different scope or evidence from history",
        """        if self.mode.is_replaying() {
            match self.cursor.next(key)? {
                Some(EffectReplay::Done { .. }) => return Ok(released),""",
        """        if false {
            match self.cursor.next(key)? {
                Some(EffectReplay::Done { .. }) => return Ok(released),""",
    ),
    "SinkViaEffect": (
        "src/runtime/ctx.rs",
        "a_tool_call_cannot_bypass_sink_gates_through_effect",
        "an effect carrying outbound arguments bypasses the mandatory sink path",
        "        if effect.sink_arguments().is_some() {",
        "        if false && effect.sink_arguments().is_some() {",
    ),
    "SinkArgumentSubstitution": (
        "src/runtime/ctx.rs",
        "a_sink_cannot_check_one_argument_value_and_send_another",
        "a sink validates one labelled value and dispatches different arguments",
        "        if canon::value_bytes(bound) != canon::value_bytes(args.peek()) {",
        "        if false && canon::value_bytes(bound) != canon::value_bytes(args.peek()) {",
    ),
    "ModelPromptIsNotASinkArgument": (
        "src/model/mod.rs",
        "a_models_sensitivity_ceiling_is_declarable",
        "a model prompt is not bound to the labelled value checked by the egress ceiling",
        """    fn sink_arguments(&self) -> Option<&Value> {
        Some(&self.prompt)
    }""",
        """    fn sink_arguments(&self) -> Option<&Value> {
        None
    }""",
    ),
    "ProtectedFieldTaintIgnored": (
        "src/runtime/ctx.rs",
        "untrusted_data_cannot_select_a_protected_tool_argument",
        "untrusted data may select an authority-bearing protected field",
        "            if field.requires_trusted() && field_label.is_untrusted() {",
        "            if false && field.requires_trusted() && field_label.is_untrusted() {",
    ),
    "ProtectedFieldSourceIgnored": (
        "src/runtime/ctx.rs",
        "a_protected_tool_argument_must_derive_only_from_allowed_sources",
        "a protected field may derive from provenance outside its source allowlist",
        "            if !field.allowed_sources().is_empty() {",
        "            if false && !field.allowed_sources().is_empty() {",
    ),
    "ProtectedFieldSensitivityIgnored": (
        "src/runtime/ctx.rs",
        "a_protected_tool_argument_honours_its_own_sensitivity_ceiling",
        "a protected field may exceed its field-specific sensitivity ceiling",
        "            if let Some(field_ceiling) = field.sensitivity_ceiling()\n"
        "                && field_label.sensitivity > field_ceiling",
        "            if let Some(field_ceiling) = field.sensitivity_ceiling()\n"
        "                && false\n"
        "                && field_label.sensitivity > field_ceiling",
    ),
    "PlanFieldLabelsFlattened": (
        "src/runtime/executor.rs",
        "plan_argument_assembly_preserves_field_level_provenance",
        "plan argument assembly flattens every field into one joined label",
        "    Ok(Tainted::object(fields))",
        """    let mut value = serde_json::Map::new();
    let mut label = crate::core::Label::trusted();
    for (name, field) in fields {
        label = label.join(field.label());
        value.insert(name, field.peek().clone());
    }
    Ok(Tainted::with_label(Value::Object(value), label))""",
    ),
    "ManifestProtectedFieldsIgnored": (
        "src/runtime/ctx.rs",
        "protected_tool_fields_must_match_the_live_catalogue",
        "a live tool catalogue may disagree with digest-covered protected fields",
        """                    Some(grant)
                        if serde_json::to_value(crate::tools::sorted_fields(
                            &grant.protected_fields,
                        ))
                        .ok()
                            != descriptor.args.get("protected_fields").cloned() =>""",
        """                    Some(grant)
                        if false =>"""
    ),
    "NoEgressCeiling": (
        "src/runtime/ctx.rs",
        "a_sink_refuses_data_above_its_ceiling",
        "a value above the sink's ceiling is sent anyway",
        "        if label.sensitivity > ceiling {",
        "        if false && label.sensitivity > ceiling {",
    ),
    "SensitivityCanLower": (
        "src/runtime/ctx.rs",
        "an_undeclared_effect_keeps_the_sensitivity_its_provenance_implies",
        "an effect may declare its output less sensitive than its provenance",
        "        let sensitivity = labelled.label().sensitivity.max(declared);",
        "        let sensitivity = declared;",
    ),
    # ── Authorization ───────────────────────────────────────────────────────
    "PolicyOnReplay": (
        "src/runtime/ctx.rs",
        "strict_replay_never_asks_the_policy_engine",
        "policy is re-evaluated while replaying a recorded run",
        "            if self.mode.is_replaying() {",
        "            self.gate(key, &descriptor, effect.mutates()).await?;\n            if self.mode.is_replaying() {",
    ),
    "DenialNotJournaled": (
        "src/runtime/ctx.rs",
        "a_denial_is_journaled_like_a_budget_refusal",
        "a policy denial stops the run without recording it",
        """        self.append_effect(
            key,
            RecordKind::PolicyDenied {
                reason: reason.clone(),
                action: crate::core::ACTION_PERFORM.to_owned(),
                resource: descriptor.kind.clone(),
            },
        )
        .await?;""",
        "",
    ),
    "NoScopeGate": (
        "src/runtime/executor.rs",
        "a_plan_outside_the_chain_s_authority_never_starts",
        "a plan naming a capability outside the chain's scope runs anyway",
        "        self.authorize_scope(&plan)?;\n",
        "",
    ),
    "DelegationCanWiden": (
        "src/core/identity.rs",
        "a_delegate_cannot_widen_its_delegator_s_authority",
        "a delegate is granted authority its delegator does not hold",
        "        if !from.scope.contains(&to.scope) {",
        "        if false {",
    ),
    "ScopePrefixMatch": (
        "src/core/identity.rs",
        "a_wildcard_does_not_leak_across_a_segment_boundary",
        "scope matching ignores segment boundaries",
        """        capability == prefix
            || (capability.starts_with(prefix)
                && capability.as_bytes().get(prefix.len()) == Some(&b'.'))""",
        "        capability.starts_with(prefix)",
    ),
    "TrustStoredChain": (
        "src/core/identity.rs",
        "a_rehydrated_chain_is_rechecked_for_widening",
        "a chain loaded from storage is trusted rather than re-checked",
        """        let mut chain = Self::root(root);
        for link in it {
            chain = chain.delegate(link)?;
        }
        Ok(chain)""",
        """        let mut chain = Self::root(root);
        for link in it {
            chain.links.push(link);
        }
        Ok(chain)""",
    ),
    # ── Tool calls ──────────────────────────────────────────────────────────
    # Obeying a server's `readOnlyHint`. The MCP spec says clients MUST treat
    # annotations as untrusted, and here the consequence is concrete: a
    # non-mutating effect defaults to Recovery::Retry, so a server could arrange
    # for its own money-moving tool to be sent twice after a timeout.
    "ObeyServerHints": (
        "src/tools/mod.rs",
        "a_servers_read_only_hint_does_not_make_a_tool_safe_to_repeat",
        "the catalogue lets a server's read-only hint overwrite the operator's "
        "declaration, so a mutating tool becomes safe to repeat on the far side's say-so",
        '''        Ok(Self {
            safety: safety.clone(),''',
        '''        let mut safety = safety.clone();
        if let Some(adv) = catalog.advertised(&id)
            && adv.read_only == Some(true)
        {
            safety.mutates = false;
            safety.recovery = Recovery::Retry;
        }
        Ok(Self {
            safety,''',
    ),
    # A timeout classified as "nothing happened" is the single most expensive
    # mis-classification available: it turns "we do not know whether the money
    # moved" into "it definitely did not", and the runtime repeats the call.
    "TimeoutIsNotInDoubt": (
        "src/tools/mod.rs",
        "a_timed_out_tool_call_is_in_doubt_when_it_reaches_the_runtime",
        "a timed-out tool call is reported as never having happened",
        "            Self::TimedOut { .. } => Disposition::InDoubt,",
        "            Self::TimedOut { .. } => Disposition::DidNotHappen,",
    ),
    # ── Metering ────────────────────────────────────────────────────────────
    # A failed call billed as free. Every other outward call either happens or
    # does not; a model call can generate four hundred tokens and then die, and
    # the provider bills for them. This was the behaviour before the model layer
    # existed: `max_effects` counted the call, and the token and cost ceilings
    # counted nothing.
    "FailedCallsAreFree": (
        "src/runtime/ctx.rs",
        "a_failed_completion_spends_the_budget_that_stops_the_next_one",
        "a failed effect is billed as costing nothing",
        "                let spend = e.spend();\n                self.bill(spend);",
        "                let spend = crate::core::Spend::default();\n                self.bill(spend);",
    ),
    # A stream that died reported as never having happened. It reached the
    # provider — we watched it generate — so repeating buys a second bill for the
    # same question.
    "InterruptedStreamDidNotHappen": (
        "src/model/mod.rs",
        "a_died_mid_stream_call_is_landed_not_in_doubt",
        "a completion that died mid-stream is reported as never having happened",
        "            Self::Interrupted { .. } | Self::Unusable { .. } | Self::Unaccounted { .. } => {\n                Disposition::Landed\n            }",
        "            Self::Unusable { .. } | Self::Unaccounted { .. } => Disposition::Landed,\n            Self::Interrupted { .. } => Disposition::DidNotHappen,",
    ),
    # ── Credentials ─────────────────────────────────────────────────────────
    # A bearer token written into the journal. The worst leak this crate can
    # produce: the log is append-only and hash-chained, so the secret cannot be
    # redacted afterwards — the record's hash covers it — only discovered.
    "CredentialReachesTheJournal": (
        "src/peers/mod.rs",
        "a_credential_is_presented_to_the_peer_and_never_written_to_the_journal",
        "a bearer token is written into the effect descriptor, and so into history",
        """                "payload": self.payload,
            }),""",
        """                "payload": self.payload,
                "auth": self.credential.as_ref().map(|c| c.expose()),
            }),""",
    ),
    # An issuer that ignores the RFC 8707 `resource` parameter hands back a token
    # the peer can spend elsewhere. Taking the issuer at its word about the
    # audience defeats the binding entirely.
    "IssuerAudienceTrusted": (
        "src/peers/credentials.rs",
        "a_token_bound_to_the_wrong_audience_is_refused",
        "the issuer is trusted about which audience it bound a token to",
        "        if fresh.audience() != audience {",
        "        if false && fresh.audience() != audience {",
    ),
    # ── Peer hops ───────────────────────────────────────────────────────────
    # Handing a peer a credential minted for someone else. The peer can then
    # replay it at the audience it was actually for — the whole token-confusion
    # class, and the reason RFC 8707 exists.
    "CredentialAudienceIgnored": (
        "src/peers/mod.rs",
        "a_credential_bound_to_one_peer_is_not_spent_at_another",
        "a credential is sent to a peer it was not minted for",
        "            Some(c) if c.audience() == peer => Ok(Some(c)),",
        "            Some(c) if true => Ok(Some(c)),",
    ),
    # A hop that does not attenuate hands the peer the caller's own authority,
    # and stops capping how far a request can travel from the human who
    # authorised it.
    "HopDoesNotAttenuate": (
        "src/peers/mod.rs",
        "a_grant_wider_than_the_caller_is_refused",
        "a peer hop passes the caller's authority through unchanged",
        """        let acting_as = caller
            .delegate(Principal::new(peer.to_string(), grant.scope.clone()))
            .map_err(|source| PeerError::Delegation {
                peer: peer.clone(),
                source,
            })?;""",
        "        let acting_as = caller.clone();",
    ),
    "A2aInvalidResponseLooksLikeRefusal": (
        "src/peers/a2a.rs",
        "an_invalid_agent_response_is_in_doubt",
        "A2A InvalidAgentResponseError is treated as proof that no work happened",
        "        -32006 => PeerError::InvalidResponse {",
        "        -32006 => PeerError::Refused {",
    ),
    # ── MCP transport ───────────────────────────────────────────────────────
    # Collapsing every protocol error into "the server declined". Only
    # METHOD_NOT_FOUND / INVALID_PARAMS / PARSE_ERROR mean nothing ran; an
    # INTERNAL_ERROR may have arrived after the tool did some of its work, and
    # treating it as a clean rejection is how a partial transfer is sent again.
    #
    # This one initially passed: the tests exercised only invalid_params, which
    # is legitimately a rejection, so the dangerous branch had no coverage.
    "McpErrorsAllLookLikeRejections": (
        "src/tools/mcp.rs",
        "a_server_error_during_execution_is_in_doubt_not_a_rejection",
        "every MCP protocol error is treated as a clean rejection",
        """            // Any other protocol error may have arrived mid-execution.
            ServiceError::McpError(_) => ToolError::TimedOut {""",
        """            // Any other protocol error may have arrived mid-execution.
            ServiceError::McpError(_) => ToolError::Refused {""",
    ),
    "McpToolFailureIsNotLanded": (
        "src/tools/mcp.rs",
        "a_tool_that_reports_failure_is_landed_not_did_not_happen",
        "a tool that ran and failed is reported as a rejected request",
        "            return Err(ToolError::ToolFailed {",
        "            return Err(ToolError::Refused {",
    ),
    # ── Store conformance ───────────────────────────────────────────────────
    # The battery itself. If it cannot reject a store that permits a duplicate
    # effect start, then every backend "passing" it means nothing — which is the
    # failure mode a conformance suite is uniquely good at hiding.
    "ConformanceIgnoresDuplicates": (
        "src/testkit/conformance.rs",
        "the_battery_rejects_a_store_that_drops_exactly_once",
        "the conformance battery stops checking exactly-once",
        """        Ok(_) => r.record(
            "exactly-once",
            "a second EffectStarted for one effect key was accepted.""",
        """        Ok(_) => r.record(
            "ignored",
            "a second EffectStarted for one effect key was accepted.""",
    ),
    # ── Canonical form ──────────────────────────────────────────────────────
    # Object keys unsorted. With `preserve_order` on — which cedar enables —
    # this makes an effect key depend on the order a caller happened to build a
    # JSON object, so two runs performing the same call derive different keys
    # and exactly-once stops holding. Silent, and expensive.
    "CanonicalOrderIgnored": (
        "src/core/canon.rs",
        "sorted_keys_guard",
        "canonical form follows insertion order instead of sorting keys",
        "            keys.sort_unstable();\n",
        "",
    ),
    # ── Cedar adapter ───────────────────────────────────────────────────────
    "CedarErrorsReadAsRefusals": (
        "src/policy/cedar.rs",
        "a_policy_that_fails_to_evaluate_is_reported_as_broken_not_as_a_refusal",
        "a policy that cannot evaluate is reported as an ordinary refusal",
        "            cedar_policy::Decision::Deny if !errors.is_empty() => PolicyDecision::deny(format!(",
        "            cedar_policy::Decision::Deny if false => PolicyDecision::deny(format!(",
    ),
    "CedarBundleIgnoresRules": (
        "src/policy/cedar.rs",
        "the_digest_follows_the_policy_text",
        "the policy bundle identity does not depend on the rules",
        "PolicyBundleIdentity::new(Digest::of(source.as_bytes()), EVALUATOR_SEMANTICS)",
        "PolicyBundleIdentity::new(Digest::ZERO, EVALUATOR_SEMANTICS)",
    ),
    "CedarBundleIgnoresSchema": (
        "src/policy/cedar.rs",
        "the_bundle_identity_covers_every_static_policy_input",
        "the policy bundle identity does not depend on its schema",
        "            bundle = bundle.with_schema(digest);",
        "            let _ = digest;",
    ),
    "CedarBundleIgnoresEntities": (
        "src/policy/cedar.rs",
        "the_bundle_identity_covers_every_static_policy_input",
        "the policy bundle identity does not depend on static entities",
        "            bundle = bundle.with_entities(digest);",
        "            let _ = digest;",
    ),
    "CedarBundleIgnoresConfiguration": (
        "src/policy/cedar.rs",
        "the_bundle_identity_covers_every_static_policy_input",
        "the policy bundle identity does not depend on adapter configuration",
        "                .with_configuration(Digest::of(ADAPTER_CONFIGURATION));",
        ";",
    ),
    "CedarBundleEvaluatorVersionDrifts": (
        "src/policy/cedar.rs",
        "the_evaluator_identity_tracks_the_pinned_cedar_version",
        "the bundle claims evaluator semantics unrelated to the pinned Cedar version",
        "PolicyBundleIdentity::new(Digest::of(source.as_bytes()), EVALUATOR_SEMANTICS)",
        "PolicyBundleIdentity::new(Digest::of(source.as_bytes()), \"cedar-policy/unversioned\")",
    ),
    "ResumeIgnoresPolicyBundleDrift": (
        "src/runtime/executor.rs",
        "an_open_run_refuses_to_resume_under_a_different_policy_bundle",
        "an open run resumes under policy semantics other than those recorded at admission",
        "        if recorded != configured {",
        "        if false && recorded != configured {",
    ),
    # ── Budgets ─────────────────────────────────────────────────────────────
    "RefusalNotJournaled": (
        "src/runtime/ctx.rs",
        "an_exhausted_run_replays_as_exhausted",
        "a budget refusal stops the run without recording it",
        """        self.append_effect(
            key,
            RecordKind::BudgetRefused {
                limit: exceeded.to_string(),
                used: format!("{:?}", self.budget()),
            },
        )
        .await?;""",
        "",
    ),
    # ── Replanning ──────────────────────────────────────────────────────────
    "ReplanOnUntrusted": (
        "src/runtime/executor.rs",
        "a_run_holding_tool_output_may_not_replan",
        "a run holding untrusted data is allowed to change its plan",
        "        if let Some(source) = untrusted_in(outputs) {",
        "        if let Some(source) = None::<String> {",
    ),
    "ReuseCompletedStepId": (
        "src/runtime/executor.rs",
        "a_successor_may_not_reuse_a_completed_step_id_for_other_work",
        "a successor plan reuses a completed step's id for different work",
        "                    \"the successor plan reuses step {step} — which already ran \\",
        "                    \"UNREACHABLE {step} \\",
    ),
    # ── HTTP surface ────────────────────────────────────────────────────────
    #
    # There is deliberately no mutant for the `Send` bound on the executor's
    # closures. The guarantee is held by a compile-time assertion in
    # `tests/guards/layering.rs`, and removing it stops the tree building — which this
    # harness reports as ERROR (a mutation that does not compile tests nothing)
    # rather than as a catch. A guarantee the compiler enforces does not need a
    # test that can falsify it; it has one that cannot be bypassed.
    "BodyMayCarryAnActor": (
        "src/api/mod.rs",
        "a_body_that_names_an_actor_is_refused_rather_than_ignored",
        "a decision body carrying an actor is accepted and silently ignored",
        "#[serde(deny_unknown_fields)]\npub struct DecisionRequest {",
        "pub struct DecisionRequest {",
    ),
    "GatePermitsWithoutAsking": (
        "src/api/mod.rs",
        "a_denying_policy_stops_every_route_before_it_touches_anything",
        "the routes authenticate but never authorize",
        """        match decision {
            PolicyDecision::Permit => Ok(Session {
                caller,
                plane: Arc::clone(plane),
            }),
            PolicyDecision::Deny { reason } => Err(ApiError(StatusCode::FORBIDDEN, reason)),
        }""",
        """        let _ = decision;
        Ok(Session {
            caller,
            plane: Arc::clone(plane),
        })""",
    ),
    "GateRunsAfterParsing": (
        "src/api/mod.rs",
        "a_denying_policy_stops_every_route_before_it_touches_anything",
        "a route parses its path before asking whether the caller may look",
        """    let s = api.gate(&headers, action::RUN_READ, &run).await?;
    let id = RunId::parse(&run).map_err(|_| bad("run"))?;""",
        """    let id = RunId::parse(&run).map_err(|_| bad("run"))?;
    let s = api.gate(&headers, action::RUN_READ, &run).await?;""",
    ),
    "SurfaceStartsWithoutPolicy": (
        "src/api/mod.rs",
        "the_surface_refuses_to_build_without_a_policy_engine",
        "the HTTP surface opens against a runtime with no authorization layer",
        """        for plane in planes.by_tenant.values() {
            if plane.policy().is_none() {
                return Err(ApiSetupError::NoPolicy);
            }
        }""",
        "",
    ),
    "TruncationIsSilent": (
        "src/api/mod.rs",
        "a_truncated_worklist_says_it_was_truncated",
        "a worklist page that was cut off reports itself as the whole queue",
        "    let truncated = queued.len() > api.limit;",
        "    let truncated = false;",
    ),
    "WorklistIgnoresCallerRoles": (
        "src/api/mod.rs",
        "a_caller_sees_only_the_queue_their_roles_entitle_them_to",
        "the worklist is filtered by a role the caller need not hold",
        "        .queue(&s.caller.roles, api.limit + 1)",
        '        .queue(&["compliance-officer".to_owned()], api.limit + 1)',
    ),
    "DecidableIgnoresExclusion": (
        "src/api/mod.rs",
        "the_worklist_says_which_items_this_caller_may_decide",
        "every worklist item claims this caller may decide it",
        "            decidable_by_you: task.may_decide(&caller.actor, &caller.roles),",
        "            decidable_by_you: true,",
    ),
    # ── Attestation ─────────────────────────────────────────────────────────
    "AnAuditHidesWhatItSkipped": (
        "src/audit.rs",
        "an_audit_reports_what_it_could_not_look_at",
        "an audit that checked nothing reports itself as sound",
        "    if evidence.prior.is_none() {",
        "    if false {",
    ),
    "TheAuditIgnoresThePriorCheckpoint": (
        "src/audit.rs",
        "only_an_outside_checkpoint_detects_a_deletion",
        "an audit ignores the checkpoint the auditor brought, so deletion goes unseen",
        "    if let Some(prior) = evidence.prior {",
        "    if let Some(prior) = None::<&Checkpoint> {",
    ),
    "TheTreeIndexIsTheStoredIndex": (
        "src/store/redb.rs",
        "only_an_outside_checkpoint_detects_a_deletion",
        "a removed run still advances the tree position, so every later run's inclusion proof is off by one",
        "                let Some(seal) = seals.get(run_id.value()).map_err(|e| be(&e))? else {\n                    continue;\n                };\n                if run_id.value() == key {",
        "                let Some(seal) = seals.get(run_id.value()).map_err(|e| be(&e))? else {\n                    rank += 1;\n                    continue;\n                };\n                if run_id.value() == key {",
    ),
    "ConsistencyProofsAreVacuous": (
        "src/core/merkle.rs",
        "a_forged_old_root_is_rejected",
        "a consistency proof verifies against an old root the log never had",
        "    old == *old_root && new == *new_root && fed == proof.len()",
        "    new == *new_root && fed == proof.len()",
    ),
    "TheLogDoesNotGrowInTheBattery": (
        "src/store/redb.rs",
        "redb_satisfies_the_journal_store_contract",
        "consistency proofs are answered from the wrong prefix",
        "        Ok(crate::core::merkle::consistency_proof(&leaves, old))",
        "        Ok(crate::core::merkle::consistency_proof(&leaves, old.min(1)))",
    ),
    "SealsNeverEnterTheLog": (
        "src/store/redb.rs",
        "a_sealed_run_is_committed_to",
        "a sealed run is never added to the Merkle log, so the checkpoint commits to nothing",
        "                    w.open_table(SEAL_LOG)\n                        .map_err(|e| be(&e))?\n                        .insert((tenant.as_str(), next), key.as_str())\n                        .map_err(|e| be(&e))?;",
        "                    let _ = &SEAL_LOG;",
    ),
    "TheLogIndexIsReused": (
        "src/store/redb.rs",
        "a_new_run_is_appended_after_the_survivors",
        "log positions stop advancing, so a new run is dropped into a slot an earlier one already holds",
        "                    counters\n                        .insert(counter.as_str(), next + 1)\n                        .map_err(|e| be(&e))?;",
        "                    let _ = (&mut counters, next);",
    ),
    "MerkleLeavesAreNotDomainSeparated": (
        "src/core/merkle.rs",
        "leaves_and_nodes_are_domain_separated",
        "a leaf hash omits its prefix, so a leaf can stand in for an interior node",
        "    bytes.push(LEAF);\n",
        "",
    ),
    "AProofCanBePadded": (
        "src/core/merkle.rs",
        "a_padded_proof_is_rejected",
        "a proof with trailing junk still verifies",
        "    if went_left.len() != proof.len() {",
        "    if went_left.len() > proof.len() {",
    ),
    "SignaturesAreNotChecked": (
        "src/journal/record.rs",
        "a_signature_from_the_wrong_key_is_refused",
        "a record signed by the wrong key is accepted",
        "                Some(a) if verifier.verify(&a.key_id, &r.hash, &a.signature) => {}",
        "                Some(_) => {}",
    ),
    "StrictVerificationTakesUnsigned": (
        "src/journal/record.rs",
        "stripping_the_signatures_is_not_a_way_to_pass",
        "stripping the signatures passes a strict verification",
        "                None if require_signature => {",
        "                None if false => {",
    ),
    "ModelCallsAreNotGenAiOperations": (
        "src/model/mod.rs",
        "a_model_call_is_reported_as_a_gen_ai_chat",
        "a completion emits a span with no gen_ai.operation.name, so tracing "
        "shows the agent invocation and nothing about the model call inside it",
        "        Some(crate::runtime::telemetry::GEN_AI_CHAT)",
        "        None",
    ),
    "CustomProvidersReceiveRemoteMediaUrls": (
        "src/model/mod.rs",
        "a_model_call_refuses_provider_side_media_before_any_provider",
        "the runtime hands a provider-native media URL to a custom provider, so "
        "that provider can fetch outside the plane's egress policy and journal",
        """        refuse_provider_side_media(&prompt, &self.model)
            .map_err(|error| EffectError::Rejected(error.to_string()))?;""",
        "        let _ = (&prompt, &self.model);",
    ),
    "MediaDigestIsAmbientAuthority": (
        "src/model/mod.rs",
        "knowing_a_media_digest_is_not_authority_to_materialize_its_blob",
        "knowing a content digest grants ambient authority to read and disclose that blob",
        "        if !grants.contains(&(reference.digest, reference.media_type.clone())) {",
        "        if false {",
    ),
    "MediaAcceptsPrivateDnsAnswers": (
        "src/media/mod.rs",
        "one_private_dns_answer_refuses_the_entire_resolution",
        "a public DNS answer launders a private or metadata address in the same response",
        "        if !is_public_ip(address.ip()) {",
        "        if false {",
    ),
    "MediaDoesNotPinValidatedDns": (
        "src/media/mod.rs",
        "governed_media_pins_every_validated_dns_answer_into_the_connection",
        "the connector resolves a checked hostname again and permits DNS rebinding",
        "            .resolve_to_addrs(host, &addrs)",
        "            .resolve_to_addrs(host, &[])",
    ),
    "MediaFollowsAutomaticRedirects": (
        "src/media/mod.rs",
        "governed_media_keeps_automatic_redirects_disabled",
        "reqwest follows a redirect without reapplying host and address policy",
        "            .redirect(reqwest::redirect::Policy::none())",
        "            .redirect(reqwest::redirect::Policy::limited(10))",
    ),
    "MediaRedirectTargetNotRevalidated": (
        "src/media/mod.rs",
        "governed_media_revalidates_every_redirect_target",
        "a redirect may leave the granted scheme, host, or port before the next request",
        "                current = self.policy.validate_url(current.as_str())?;",
        "                current = current.clone();",
    ),
    "MediaStreamLimitIgnored": (
        "src/media/mod.rs",
        "declared_and_streamed_body_sizes_are_both_bounded",
        "a chunked response can cross the media byte ceiling after its headers passed",
        "            if next > self.policy.max_bytes {",
        "            if false {",
    ),
    "MediaSignatureIgnored": (
        "src/media/mod.rs",
        "content_type_is_not_trusted_without_matching_bytes",
        "an origin can label arbitrary bytes as an allowed media type",
        "    if !valid {",
        "    if false {",
    ),
    "GovernedMediaIsTrusted": (
        "src/media/mod.rs",
        "policy_and_validator_identity_are_in_the_effect_key",
        "fetched multimodal content is treated as trusted instructions",
        """    fn trust(&self) -> Trust {
        Trust::Untrusted
    }""",
        """    fn trust(&self) -> Trust {
        Trust::Trusted
    }""",
    ),
    "MediaBlobDurableBeforeCaseLink": (
        "src/media/mod.rs",
        "case_retention_links_are_durable_before_blob_bytes",
        "a crash can leave fetched media durable but unreachable from case erasure",
        """        if let Some(link) = &self.case_link {
            link.cases
                .link_blob(link.case, digest, link.at)
                .await
                .map_err(|error| EffectError::Unavailable {
                    driver: "case.store".to_owned(),
                    detail: error.to_string(),
                })?;
        }
        let digest =
            self.blobs
                .put(&fetched.bytes)
                .await
                .map_err(|error| EffectError::Unavailable {
                    driver: "blob.store".to_owned(),
                    detail: error.to_string(),
                })?;""",
        """        let digest =
            self.blobs
                .put(&fetched.bytes)
                .await
                .map_err(|error| EffectError::Unavailable {
                    driver: "blob.store".to_owned(),
                    detail: error.to_string(),
                })?;
        if let Some(link) = &self.case_link {
            link.cases
                .link_blob(link.case, digest, link.at)
                .await
                .map_err(|error| EffectError::Unavailable {
                    driver: "case.store".to_owned(),
                    detail: error.to_string(),
                })?;
        }""",
    ),
    "BlobDurableBeforeCaseLink": (
        "src/runtime/ctx.rs",
        "case_retention_links_are_durable_before_blob_bytes",
        "a crash can leave arbitrary stored bytes unreachable from case erasure",
        """        cx.cases
            .link_blob(cx.case_id, digest, at)
            .await
            .map_err(StepError::Store)?;
        let stored = blobs
            .put(bytes)
            .await
            .map_err(|e| StepError::Store(crate::core::StoreError::Backend(e.to_string())))?;""",
        """        let stored = blobs
            .put(bytes)
            .await
            .map_err(|e| StepError::Store(crate::core::StoreError::Backend(e.to_string())))?;
        cx.cases
            .link_blob(cx.case_id, digest, at)
            .await
            .map_err(StepError::Store)?;""",
    ),
    "AnthropicReceivesRemoteMediaUrls": (
        "src/model/anthropic.rs",
        "anthropic_never_receives_a_provider_fetched_media_url",
        "an Anthropic image/document URL crosses the model boundary, letting the "
        "provider fetch bytes the plane never governed or recorded",
        """        super::refuse_provider_side_media(prompt, model)?;

        // Before the request is built: a refused destination must cost nothing""",
        """        let _ = (prompt, model);

        // Before the request is built: a refused destination must cost nothing""",
    ),
    "OpenAiReceivesRemoteMediaUrls": (
        "src/model/openai.rs",
        "openai_never_receives_a_provider_fetched_media_url",
        "an OpenAI image/file URL crosses the model boundary, letting the provider "
        "fetch bytes the plane never governed or recorded",
        """        super::refuse_provider_side_media(prompt, model)?;

        self.check_egress(model)?;""",
        """        let _ = (prompt, model);

        self.check_egress(model)?;""",
    ),
    "AWitnessSignsAnyHistory": (
        "src/journal/witness.rs",
        "a_forked_history_is_refused",
        "a witness cosigns a checkpoint that does not extend what it saw, so an "
        "operator can have two contradictory histories both vouched for",
        "                if !merkle::verify_consistency(old, &old_root, new, &checkpoint.root, proof) {",
        "                if false {",
    ),
    "ErasureIsNotScopedToTheCase": (
        "src/store/redb_cases.rs",
        "erasing_a_case_leaves_other_cases_alone",
        "a case's blob list returns every case's blobs, so answering one erasure "
        "request destroys unrelated subjects' data",
        "                    (tenant.as_str(), key.as_str(), i64::MIN, [].as_slice())\n"
        "                        ..=(\n"
        "                            tenant.as_str(),\n"
        "                            key.as_str(),\n"
        "                            i64::MAX,\n"
        "                            [0xffu8; 32].as_slice(),\n"
        "                        ),",
        "                    (tenant.as_str(), \"\", i64::MIN, [].as_slice())\n"
        "                        ..=(\n"
        "                            tenant.as_str(),\n"
        "                            MAX_STR,\n"
        "                            i64::MAX,\n"
        "                            [0xffu8; 32].as_slice(),\n"
        "                        ),",
    ),
    "ErasureLooksLikeDataLoss": (
        "src/blob/memory.rs",
        "an_expired_blob_is_not_reported_as_missing",
        "a deliberate erasure is reported as a missing blob, so an operator "
        "cannot tell retention doing its job from data nobody can account for",
        "        match stone {\n            Some((at, reason)) => Err(BlobError::Expired {",
        "        match None::<(i64, String)> {\n            Some((at, reason)) => Err(BlobError::Expired {",
    ),
    "AManifestTypoDisablesACeiling": (
        "src/manifest/mod.rs",
        "a_misspelled_field_is_refused",
        "a manifest's unknown fields are ignored rather than refused, so "
        "`max_tokns: 100` reads as no token ceiling at all and the file that "
        "was supposed to make the limit reviewable hides its absence",
        "#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]\n#[serde(deny_unknown_fields)]\npub struct Budgets {",
        "#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]\npub struct Budgets {",
    ),
    "ThePromptIsNotPartOfTheDeclaration": (
        "src/manifest/mod.rs",
        "rewording_a_prompt_changes_the_manifest_identity",
        "the declared prompt is left out of the manifest's digest, so a reworded "
        "instruction ships under an unchanged version and nothing pinning that "
        "version notices",
        "    #[serde(default, skip_serializing_if = \"Option::is_none\")]\n    pub identity: Option<Identity>,",
        "    #[serde(default, skip_serializing_if = \"Option::is_none\", skip_serializing)]\n    pub identity: Option<Identity>,",
    ),
    "EveryInstanceSharesALeaseOwner": (
        "src/runtime/executor.rs",
        "two_runtimes_do_not_share_a_lease_owner",
        "every runtime instance uses one lease owner, so two replicas each read "
        "the other's lease as their own and renew it without a fencing bump — "
        "two writers on one run, under one epoch",
        "    format!(\"agentplane-{seed:016x}-{n}\")",
        "    \"agentplane\".to_owned()",
    ),
    "AManifestSignatureIsNotDomainSeparated": (
        "src/manifest/registry.rs",
        "a_manifest_signature_is_bound_to_being_a_manifest",
        "a manifest is signed over its bare digest, so a signature made in any "
        "other context over the same digest — a record attestation — is accepted "
        "as approval of the manifest",
        "        let attestation = signer.attest(&signing_hash(DOMAIN_MANIFEST, &digest));",
        "        let attestation = signer.attest(&digest);",
    ),
    "AnUnsignedManifestPassesAVerifyingResolve": (
        "src/manifest/registry.rs",
        "a_signed_manifest_names_who_published_it",
        "a resolve that required a signature accepts a manifest nobody signed, "
        "so 'who published this' has no answer and nothing says so",
        """        let Some(a) = attestation else {
            return Err(RegistryError::Unsigned {
                name: name.to_owned(),
                version: version.to_owned(),
            });
        };""",
        """        let Some(a) = attestation else {
            return Ok((manifest, String::from("unverified")));
        };""",
    ),
    "SigningAnExistingManifestRecordsNothing": (
        "src/manifest/registry.rs",
        "signing_an_existing_unsigned_manifest_records_the_publisher",
        "publish_signed reports success for an existing unsigned artifact but "
        "does not record the publisher, so every verifying resolve still says unsigned",
        "                    (None, Some(signed)) => existing.attestation = Some(signed),",
        "                    (None, Some(_)) => {},",
    ),
    "AManifestPublisherCanBeReassigned": (
        "src/manifest/registry.rs",
        "republishing_with_another_signer_cannot_reassign_the_publisher",
        "identical artifact bytes can be republished by another identity without a refusal, "
        "so publication reports success while changing who approved the version",
        "                    (Some(recorded), Some(offered)) if recorded.key_id != offered.key_id => {",
        "                    (Some(recorded), Some(offered)) if false && recorded.key_id != offered.key_id => {",
    ),
    "OversightMayBeDeclaredWhereNothingAppliesIt": (
        "src/manifest/mod.rs",
        "oversight_without_a_declarative_agent_is_refused",
        "oversight is accepted beside an agent whose behaviour is code, so the "
        "file claims a human is in the loop and no human ever is",
        "        if self.spec.execution.is_none() {",
        "        if false {",
    ),
    "ADeclarativeAgentTakesAnyDriver": (
        "src/runtime/executor.rs",
        "a_declarative_agent_refuses_an_unnamed_provider",
        "a declarative agent falls back to whatever driver is registered when "
        "the one its manifest names is absent, running the agent on a model its "
        "own declaration never mentioned",
        "            let Some(provider) = self.providers.get(&model.provider).map(Arc::clone) else {",
        "            let Some(provider) = self.providers.values().next().map(Arc::clone) else {",
    ),
    "AFencedCallerCanReleaseTheLease": (
        "src/store/redb.rs",
        "redb_satisfies_the_journal_store_contract",
        "a lease release ignores the caller's epoch, so a fenced instance "
        "shutting down frees the lease of whoever replaced it — handing the run "
        "to a third party while its rightful owner is mid-write",
        "                if held == Some(epoch) {",
        "                if held.is_some() {",
    ),
    "TheManifestIsOnlyAComment": (
        "src/runtime/ctx.rs",
        "a_model_the_manifest_never_declared_is_refused",
        "an effect is dispatched without checking it against the agent's own "
        "manifest, so a reviewer approves one model and the code calls another "
        "with nothing anywhere disagreeing",
        "        self.declared(key, descriptor).await?;",
        "        let _ = self.declared(key, descriptor);",
    ),
    "CaseStateLaundersTaint": (
        "src/runtime/ctx.rs",
        "case_state_does_not_launder_untrusted_data",
        "case state is handed back trusted, so a skill can write a model "
        "completion into it and read it back clean in a later step or a later "
        "run — an exit from the lattice that passes no policy check and leaves "
        "no record that a declassification happened",
        """        let label = crate::core::Label::untrusted(crate::core::SourceId::new(format!(
            "case:{}",
            cx.case_id
        )));""",
        """        let label = crate::core::Label::trusted();""",
    ),
    "ReleasingALeaseForgetsTheEpoch": (
        "src/store/redb.rs",
        "redb_satisfies_the_journal_store_contract",
        "releasing a lease deletes the row the epoch lives in, so append has "
        "nothing to fence against and the next acquire restarts at 1 — a writer "
        "already fenced at 2 then outranks the legitimate owner and the fence "
        "inverts",
        """                    leases
                        .insert(key.as_str(), ("", epoch, 0))
                        .map_err(|e| be(&e))?;""",
        """                    leases.remove(key.as_str()).map_err(|e| be(&e))?;""",
    ),
    "TheForcedToolIsFoundByPosition": (
        "src/model/anthropic.rs",
        "the_forced_tool_is_found_by_name_not_by_position",
        "the structured answer is taken from whichever tool block came first, "
        "so a caller's own tool call emitted ahead of the forced one is "
        "returned as the schema-shaped answer — a wrong answer that parses",
        """            .find(|b| b.kind == "tool_use" && b.name.as_deref() == Some(RESPOND_TOOL))""",
        """            .find(|b| b.kind == "tool_use")""",
    ),
    "StreamedToolArgumentsAreMixed": (
        "src/model/anthropic_stream.rs",
        "concurrent_tool_calls_keep_their_own_arguments",
        "fragments of concurrently streamed tool calls are appended to one "
        "buffer, so they reassemble into JSON that parses — into the wrong "
        "arguments. A refund dispatched with another call's amount is a failure "
        "that succeeds",
        """                if let Some(index) = value.get("index").and_then(Value::as_u64)
                    && let Some(p) = delta.get("partial_json").and_then(Value::as_str)
                    && let Some(block) = self.tools.get_mut(&index)
                {
                    block.json.push_str(p);
                }""",
        """                if let Some(p) = delta.get("partial_json").and_then(Value::as_str)
                    && let Some((_, block)) = self.tools.iter_mut().next()
                {
                    block.json.push_str(p);
                }""",
    ),
    "TheProofsStartingSizeIsGuessed": (
        "src/journal/witness_http.rs",
        "the_request_body_follows_the_protocol",
        "the size a consistency proof starts from is inferred from the proof's "
        "length, but an RFC 6962 proof is O(log n) hashes — so a 50 to 100 "
        "submission claims to start at 93 and every witness refuses it",
        "        let url = format!(\"{}/add-checkpoint\", self.prefix);",
        "        let old_size = checkpoint.size.saturating_sub(proof.len() as u64);\n        let url = format!(\"{}/add-checkpoint\", self.prefix);",
    ),
    "AStaleWitnessCursorIsCalledAFork": (
        "src/journal/witness_http.rs",
        "a_stale_cursor_is_not_a_fork",
        "a witness answering 409 — 'your proof starts from a size I have moved "
        "past' — is reported as a forked history, so a routine retry pages "
        "somebody for an integrity incident and the alert that matters stops "
        "being believed",
        """            409 => Err(WitnessError::Stale {
                origin: checkpoint.origin.clone(),
                witness_size: text.trim().parse().unwrap_or_default(),
            }),""",
        """            409 => Err(WitnessError::Forked {
                origin: checkpoint.origin.clone(),
                seen: old_size,
                offered: checkpoint.size,
            }),""",
    ),
    "ANoteUsesTheWrongDash": (
        "src/journal/note.rs",
        "a_hyphen_is_not_a_signature_line",
        "a signature line is written with a hyphen instead of the em dash the "
        "note format specifies, producing checkpoints that look right in every "
        "terminal and diff and that no witness will accept",
        "const EM_DASH: char = '\\u{2014}';",
        "const EM_DASH: char = '-';",
    ),
    "ANotePayloadIsUrlSafeBase64": (
        "src/journal/note.rs",
        "the_note_payload_is_rfc4648_base64",
        "the note payload is encoded with the URL-safe alphabet, which differs "
        "from the specified one in exactly two positions — so most checkpoints "
        "encode identically and the ones that do not are rejected by every "
        "verifier",
        "0123456789+/",
        "0123456789-_",
    ),
    "ANoteBodyAbsorbsItsSeparator": (
        "src/journal/note.rs",
        "a_body_without_its_trailing_newline_is_refused",
        "the blank line separating a note body from its signatures is treated "
        "as part of the body, so every signature covers bytes the verifier does "
        "not hash",
        "        let text = format!(\"{text}\\n\");",
        "        let text = format!(\"{text}\\n\\n\");",
    ),
    "AWitnessSwallowsASigningFailure": (
        "src/journal/witness.rs",
        "a_witness_that_cannot_sign_reports_it",
        "a signing failure yields an empty signature instead of an error, so a "
        "cosignature that never happened is indistinguishable to an auditor "
        "from a witness that vouched",
        """            .map_err(|e| match e {
                SignError::Unavailable(d) => WitnessError::Unavailable(d),
                SignError::Refused { key_id, detail } => {
                    WitnessError::Unavailable(format!("key '{key_id}' refused: {detail}"))
                }
            })?;""",
        """            .unwrap_or_default();""",
    ),
    "ASpecialistMayHandOff": (
        "src/manifest/mod.rs",
        "a_specialist_that_may_delegate_is_refused",
        "an agent declared a specialist may still delegate, so the role that "
        "bounds a handoff chain bounds nothing and A->B->C->A stays reachable",
        "        if t.role == Role::Specialist",
        "        if false && t.role == Role::Specialist",
    ),
    "CollaborationNeedsNoJustification": (
        "src/manifest/mod.rs",
        "collaboration_requires_a_reason_and_nothing_else_may_carry_one",
        "a manifest may declare collaboration without saying why, so the mode "
        "with the whole inter-agent failure surface is the one nobody had to "
        "argue for",
        "            (TopologyMode::Collaborative, None) => {",
        "            (TopologyMode::Collaborative, None) if false => {",
    ),
    "ManifestEgressCeilingIsIgnored": (
        "src/runtime/ctx.rs",
        "the_manifest_egress_ceiling_binds_every_sink",
        "a sink uses only its local egress ceiling and ignores the stricter "
        "ceiling in the reviewed manifest",
        "                        effect_ceiling.min(manifest_ceiling)",
        "                        effect_ceiling.max(manifest_ceiling)",
    ),
    "ManifestDelegationCeilingIsIgnored": (
        "src/runtime/ctx.rs",
        "the_manifest_delegation_ceiling_binds_every_handoff",
        "a handoff may exceed the reviewed manifest's delegation-depth ceiling",
        "        ) && actual > usize::from(ceiling)",
        "        ) && false",
    ),
    "PeerCallHidesItsDelegationDepth": (
        "src/peers/mod.rs",
        "a_hop_appends_a_link_and_narrows",
        "a peer call hides the chain depth it will put on the wire, bypassing "
        "the manifest's handoff ceiling",
        "        Some(self.acting_as.depth())",
        "        None",
    ),
    "AnOutputContractMayPromiseNothing": (
        "src/manifest/mod.rs",
        "an_output_schema_that_permits_anything_is_refused",
        "`output.schema: {}` is accepted, so a result contract that permits "
        "anything reads in review as one that was declared",
        "            serde_json::Value::Object(m) if !m.is_empty() => {}",
        "            serde_json::Value::Object(_) => {}",
    ),
    "AVersionCanBeRepublished": (
        "src/manifest/registry.rs",
        "a_published_version_cannot_be_rewritten",
        "a published manifest version is overwritten rather than refused, so a "
        "widened tool grant reaches every consumer that pinned the version they "
        "reviewed",
        """            Some(existing) => Err(RegistryError::Immutable {
                name,
                version,
                existing: existing.digest.to_hex(),
                offered: digest.to_hex(),
            }),
            None => {""",
        """            _ => {""",
    ),
    "APinnedResolveAcceptsAnything": (
        "src/manifest/registry.rs",
        "a_pinned_resolve_refuses_substituted_content",
        "a pinned resolve returns whatever the registry served, so the one check "
        "that survives a compromised registry checks nothing",
        "        if actual == expected {",
        "        if true {",
    ),
    "BlobsAreServedUnverified": (
        "src/blob/mod.rs",
        "altered_bytes_are_detected_rather_than_served",
        "storage is trusted, so bytes edited after the fact are served as the "
        "ones the hash chain vouched for",
        "    let actual = Digest::of(&bytes);\n    if actual == digest {",
        "    let actual = Digest::of(&bytes);\n    if actual == actual {",
    ),
    "TheJournalTakesAnySizeRecord": (
        "src/journal/record.rs",
        "a_record_larger_than_the_limit_is_refused",
        "an unbounded record is written into an append-only chain, where it "
        "cannot be pruned, rewritten, or skipped on read",
        "        if raw.len() > Self::MAX_RECORD_BYTES {",
        "        if raw.len() > usize::MAX {",
    ),
    "TheSweepForgetsToDeindexAClaim": (
        "src/store/redb_events.rs",
        "redb_satisfies_the_case_layer_contracts",
        "a delivered message is left sweepable, so the run resumes on it and the "
        "dead-letter queue reports it as never claimed",
        "                        drop(events);\n                        // No longer sweepable: the index moves with the row it\n                        // describes, in the row's transaction.\n                        w.open_table(EVENTS_LIVE)\n                            .map_err(|e| be(&e))?\n                            .remove((tenant.as_str(), received, id.as_str()))\n                            .map_err(|e| be(&e))?;",
        "                        drop(events);",
    ),
    "TheBacklogDropsClaimedWork": (
        "src/store/redb_tasks.rs",
        "redb_satisfies_the_case_layer_contracts",
        "the backlog counts only unclaimed work, so it falls the moment a "
        "reviewer opens an item and reports progress that has not happened",
        "            let pending = r.open_table(PENDING).map_err(|e| be(&e))?;",
        "            let pending = r.open_table(TASKS).map_err(|e| be(&e))?;",
    ),
    "TheStoreDropsTheSignature": (
        "src/store/redb.rs",
        "redb_satisfies_the_journal_store_contract",
        "the store writes records and silently discards who signed them",
        "                        key_id: record.attestation.as_ref().map(|a| a.key_id.clone()),",
        "                        key_id: None,",
    ),
    # ── Cancellation ────────────────────────────────────────────────────────
    "StopDoesNotUnwind": (
        "src/runtime/executor.rs",
        "stopping_a_suspended_run_undoes_what_it_did",
        "a stopped run seals without undoing what it already did",
        "            RunStatus::Failed(_) | RunStatus::Exhausted(_) | RunStatus::Cancelled { .. } => {}",
        "            RunStatus::Failed(_) | RunStatus::Exhausted(_) => {}\n            RunStatus::Cancelled { .. } => return Ok(status),",
    ),
    "StopUnwindsAroundDoubt": (
        "src/runtime/executor.rs",
        "a_stop_will_not_unwind_around_an_unknown_outcome",
        "a stop compensates around an effect whose outcome is unknown",
        "        if let Some(step) = self.undecided_effect(run).await? {",
        "        if let Some(step) = None::<StepId> {",
    ),
    "StopLeavesTheInterruptedStep": (
        "src/runtime/executor.rs",
        "stopping_a_suspended_run_undoes_what_it_did",
        "a stop unwinds only completed steps, leaving the suspended one's effects",
        "        let mut out = completed.to_vec();",
        "        return completed.to_vec();\n        #[allow(unreachable_code)]\n        let mut out = completed.to_vec();",
    ),
    "AStoppedRunResumes": (
        "src/runtime/executor.rs",
        "a_stopped_run_is_not_resumed_by_a_later_event",
        "a stopped run is resumed by the next event and carries on",
        '        "cancelled" => Some(RunStatus::Cancelled {',
        '        "cancelled" if false => Some(RunStatus::Cancelled {',
    ),
    "AStopRequestOverwritesTheAsker": (
        "src/store/redb.rs",
        "redb_satisfies_the_journal_store_contract",
        "a second stop request overwrites the first asker",
        "                if t.get(key.as_str()).map_err(|e| be(&e))?.is_some() {\n                    false",
        "                if false {\n                    false",
    ),
    # ── Wire drivers ────────────────────────────────────────────────────────
    "PeerInternalErrorIsARefusal": (
        "src/peers/a2a.rs",
        "an_internal_error_is_in_doubt_not_a_refusal",
        "a peer's internal error is read as a clean refusal",
        "        -32700 | -32600 | -32601 | -32602 | -32005..=-32001 | -32009..=-32007 => {",
        "        -32700 | -32600 | -32601 | -32602 | -32603 | -32005..=-32001 | -32009..=-32007 => {",
    ),
    "FailedPeerTaskIsInDoubt": (
        "src/peers/a2a.rs",
        "a_failed_task_landed",
        "a peer task that reported failure is treated as an unknown outcome",
        '        "TASK_STATE_FAILED" | "TASK_STATE_CANCELED" | "TASK_STATE_REJECTED" => {',
        '        "TASK_STATE_FAILED" | "TASK_STATE_CANCELED" | "TASK_STATE_REJECTED" if false => {',
    ),
    "CachedTokensAreDropped": (
        "src/model/anthropic.rs",
        "anthropic_cached_tokens_are_added_back",
        "cached tokens are dropped, so a cached run bills a fraction of its cost",
        "            input_tokens: u.map_or(0, |u| u.input_tokens) + write + read,",
        "            input_tokens: u.map_or(0, |u| u.input_tokens),",
    ),
    "CachedTokensAreDoubleCounted": (
        "src/model/openai.rs",
        "openai_cached_tokens_are_not_double_counted",
        "cached tokens are added to a count that already contains them",
        "            input_tokens: u.map_or(0, |u| u.input_tokens),\n            output_tokens: u.map_or(0, |u| u.output_tokens),\n            // Responses reports no cache-write counter",
        "            input_tokens: u.map_or(0, |u| u.input_tokens) + u.and_then(|u| u.input_tokens_details.as_ref()).map_or(0, |d| d.cached_tokens),\n            output_tokens: u.map_or(0, |u| u.output_tokens),\n            // Responses reports no cache-write counter",
    ),
    "SchemaModeIgnoresTheModel": (
        "src/model/anthropic.rs",
        "the_schema_mode_is_chosen_per_model",
        "a per-model schema mode is ignored, so one driver cannot serve mixed models",
        "        self.schema_modes\n            .get(&model.model)\n            .copied()\n            .unwrap_or(self.default_schema_mode)",
        "        let _ = &self.schema_modes;\n        self.default_schema_mode",
    ),
    "EmulationOffersRatherThanForces": (
        "src/model/anthropic.rs",
        "anthropic_can_emulate_a_schema_with_a_forced_tool",
        "the emulation tool is offered rather than forced, so the model may answer in prose",
        '                    body["tool_choice"] = json!({ "type": "tool", "name": RESPOND_TOOL });',
        '                    body["tool_choice"] = json!({ "type": "auto" });',
    ),
    "AnIgnoredForcedToolIsSilent": (
        "src/model/anthropic.rs",
        "a_model_that_ignores_the_forced_tool_is_caught",
        "a model that ignored the forced tool returns an empty success",
        """        let Some(value) = forced else {
            return Err(ModelError::Unusable {""",
        """        let Some(value) = forced.or(Some(Value::Null)) else {
            return Err(ModelError::Unusable {""",
    ),
    "IncompatibleSchemasReachTheWire": (
        "src/model/openai.rs",
        "an_incompatible_schema_is_refused_with_the_reason",
        "a schema strict mode cannot accept is sent anyway, for an opaque 400",
        "        if let Some(problem) = strict_schema_problem(schema) {",
        "        if let Some(problem) = None::<String> {",
    ),
    "TheSchemaIsRewrittenOnTheWayOut": (
        "src/model/wire.rs",
        "a_conformant_schema_is_not_rewritten",
        "a conformant schema is rejected, making structured output unusable",
        "    let mut problems = Vec::new();\n    walk(schema, \"schema\", &mut problems);",
        "    let mut problems = vec![\"synthetic\".to_owned()];\n    walk(schema, \"schema\", &mut problems);",
    ),
    "SchemaIsASuggestion": (
        "src/model/openai.rs",
        "a_schema_is_sent_as_a_strict_constraint",
        "a declared schema goes out without strict mode, so the model may ignore it",
        '''                        "type": "json_schema",
                        "name": RESPOND_TOOL,
                        "strict": true,''',
        '''                        "type": "json_schema",
                        "name": RESPOND_TOOL,
                        "strict": false,''',
    ),
    "MalformedStructuredOutputIsFree": (
        "src/model/wire.rs",
        "an_unparseable_structured_answer_is_billed_and_loud",
        "an answer that broke its own schema is billed as free",
        "        .map_err(|e| ModelError::Unusable {\n            model: model.clone(),\n            usage,",
        "        .map_err(|e| ModelError::Unusable {\n            model: model.clone(),\n            usage: super::Usage::default(),",
    ),
    "TruncationIsNotReported": (
        "src/model/openai.rs",
        "a_cut_off_answer_says_so",
        "a cut-off answer is returned looking whole",
        '        let truncated = parsed.status == "incomplete";',
        "        let truncated = false;",
    ),
    "ReasoningTokensAreNotBilled": (
        "src/model/openai.rs",
        "a_response_bills_reasoning_tokens_too",
        "reasoning tokens are dropped, so a reasoning-heavy run bills a fraction of its cost",
        "            output_tokens: u.map_or(0, |u| u.output_tokens),\n            // Responses reports no cache-write counter;",
        "            output_tokens: u.map_or(0, |u| u.output_tokens.saturating_sub(u.output_tokens_details.as_ref().map_or(0, |d| d.reasoning_tokens))),\n            // Responses reports no cache-write counter;",
    ),
    "ProviderErrorBodiesAreLoggedWhole": (
        "src/model/wire.rs",
        "a_huge_error_body_is_trimmed_before_it_reaches_a_log",
        "a provider's error body reaches the log at full length, echoed prompt and all",
        "    if body.len() <= LIMIT {\n        return body.to_owned();\n    }",
        "    if true {\n        return body.to_owned();\n    }",
    ),
    # Quorum. Neither mutation stops a panel running; both let it decide when it
    # should have escalated.
    "ASplitPanelPicksTheMajority": (
        "src/core/quorum.rs",
        "a_split_panel_decides_nothing",
        "a panel that failed to reach its threshold reports whichever side had "
        "more votes, turning 'we do not know' into a decision",
        """        if tally.passed >= self.need {
            return Outcome::Reached(Verdict::Pass, tally);
        }
        if tally.failed >= self.need {
            return Outcome::Reached(Verdict::Fail, tally);
        }""",
        """        if tally.passed >= self.need || tally.passed > tally.failed {
            return Outcome::Reached(Verdict::Pass, tally);
        }
        if tally.failed >= self.need {
            return Outcome::Reached(Verdict::Fail, tally);
        }""",
    ),
    "IdenticalJudgesArePermitted": (
        "src/core/quorum.rs",
        "repeating_a_lens_is_refused",
        "a panel may repeat one lens, so three identical judgements share their "
        "blind spots and look like diversity",
        """        let unique: BTreeSet<&String> = lenses.iter().collect();
        if unique.len() != lenses.len() {
            return Err(QuorumError::RepeatedLens);
        }""",
        "",
    ),
    "AQuorumNeedsNoSubject": (
        "src/plan/mod.rs",
        "a_quorum_on_a_node_that_judges_nothing_is_refused",
        "a panel may be declared on a node that judges nothing, so it repeats "
        "the work instead of reviewing it",
        """    for n in plan.nodes.iter().filter(|n| n.quorum.is_some()) {
        if n.depends_on.is_empty() {
            return Err(PlanError::QuorumWithoutSubject { step: n.id });
        }
    }""",
        "",
    ),
    # Network egress. Neither mutation breaks a working deployment; both turn a
    # granted-destinations list back into a suggestion.
    "EgressGrantsBySuffix": (
        "src/core/egress.rs",
        "a_grant_does_not_extend_to_subdomains",
        "a grant matches by suffix, so listing example.com hands over every host "
        "anybody can register under it",
        "        if self.hosts.contains(&host.to_ascii_lowercase()) {",
        "        if self\n            .hosts\n            .iter()\n            .any(|h| host.to_ascii_lowercase().ends_with(h.as_str()))\n        {",
    ),
    "AnUncheckableDestinationIsAllowed": (
        "src/core/egress.rs",
        "a_destination_with_no_host_is_refused",
        "a destination with no host is permitted, so anything the parser cannot "
        "read is reachable",
        """        let Some(host) = host else {
            return Err(EgressError::NoHost);
        };""",
        """        let Some(host) = host else {
            return Ok(());
        };""",
    ),
    "EgressIsCheckedAfterSending": (
        "src/model/anthropic.rs",
        "a_model_call_to_an_ungranted_host_is_refused",
        "the destination is never checked, so an ungranted host is reached",
        "        self.check_egress(model)?;",
        "        let _ = self.check_egress(model);",
    ),
    # Attested provenance. Neither mutation stops a call working; both turn a
    # claim a callee can *check* back into one it has to believe.
    "ProvenanceIsNotBoundToTheCall": (
        "src/core/provenance.rs",
        "an_attestation_cannot_be_lifted_onto_another_tool",
        "the signature covers the identifiers but not the call, so a block "
        "observed on one request verifies on any other",
        '''            "target": target,''',
        '''            "target": "",''',
    ),
    "ProvenanceIgnoresTheArguments": (
        "src/core/provenance.rs",
        "an_attestation_cannot_be_lifted_onto_other_arguments",
        "the signature ignores the arguments, so the amount can be changed under "
        "a block that still verifies",
        '''            "arguments": Digest::of(canon::value_bytes(arguments).as_slice()).to_string(),''',
        '''            "arguments": "",''',
    ),
    "AnUnsignedBlockIsAccepted": (
        "src/core/provenance.rs",
        "an_unsigned_block_never_verifies",
        "a block with no signature verifies, so anything that strips the "
        "attestation in transit is believed",
        """        let Some(a) = &self.attestation else {
            return false;
        };""",
        """        let Some(a) = &self.attestation else {
            return true;
        };""",
    ),
    "ProvenanceIsNeverSent": (
        "src/tools/mcp.rs",
        "a_tool_call_carries_signed_provenance",
        "the MCP client drops the provenance block, so a server has nothing to "
        "correlate on and nothing to check",
        "        if let Some(p) = provenance {",
        "        if let Some(p) = None::<&crate::core::Provenance> {",
    ),
    # Case state is the one piece of mutable storage a step touches directly, and
    # it went unjournaled for a long time. Both mutations below restore that: the
    # run keeps working, and replay quietly stops being replay.
    "CaseStateReadsSkipTheJournal": (
        "src/runtime/ctx.rs",
        "a_strict_replay_reads_case_state_from_the_journal_not_the_store",
        "a case-state read goes straight to the store, so a replayed run sees "
        "whatever the case holds now and reaches a different answer from the "
        "same journal",
        '''        let snapshot = self
            .effect(crate::runtime::effects::ReadCaseState {
                cases: Arc::clone(&cx.cases),
                case: cx.case_id,
            })
            .await?;
        let snapshot = snapshot.into_unlabelled();''',
        '''        let live = cx
            .cases
            .case(cx.case_id)
            .await?
            .ok_or_else(|| StepError::Store(crate::core::StoreError::NotFound(String::new())))?;
        let snapshot = crate::runtime::effects::CaseSnapshot {
            state: live.state,
            version: live.version,
        };''',
    ),
    "CaseStateWritesAreBlind": (
        "src/store/redb_cases.rs",
        "a_write_against_a_stale_read_is_refused",
        "the version check is dropped from the state write, so two runs on "
        "one case silently lose each other's work",
        "                    Some((kind, status, _, ver, at)) if ver == expected.0 => {",
        "                    Some((kind, status, _, ver, at)) if ver != u64::MAX => {",
    ),
    "AMissingCaseLooksLikeAConflict": (
        "src/store/redb_cases.rs",
        "a_write_to_a_missing_case_is_not_found",
        "a write to a case that does not exist reports a conflict, sending the "
        "caller into a re-read loop against nothing",
        "                    None => Err(StoreError::NotFound(key.clone())),",
        "                    None => Err(StoreError::CaseConflict { case: key.clone(), expected: expected.0, current: 0 }),",
    ),
    # The denial channel. Neither mutation changes what the policy decides — only
    # how much an attacker learns from asking repeatedly.
    "DenialReasonsReachTheModel": (
        "src/core/error.rs",
        "a_model_is_told_the_same_thing_whatever_the_reason",
        "the model-facing refusal carries the operator-facing detail, turning "
        "the policy into an oracle that reports the sensitivity of data the run "
        "was never allowed to reveal",
        "pub const REFUSED: &str = \"this action was not permitted\";",
        "pub const REFUSED: &str = \"denied: Secret exceeds the sink ceiling\";",
    ),
    "TheDenialCeilingIsCheckedTooLate": (
        "src/runtime/ctx.rs",
        "a_run_that_keeps_being_refused_stops_learning",
        "the denial ceiling is checked after the policy rather than before, so "
        "every attempt still journals a refusal and still yields its bit",
        '''        if let Err(exceeded) = self
            .ledger
            .lock()
            .expect("budget mutex")
            .admit_policy_check()
        {
            return Err(StepError::Budget(exceeded));
        }''',
        "        let _ = &self.ledger;",
    ),
    # Streaming exists for exactly one reason — a severed call can still say what
    # it burned — and every mutation below silently restores the behaviour that
    # reason describes as broken. None of them fails to compile; all of them make
    # a budget ceiling stop binding.
    "ASeveredStreamReportsNothing": (
        "src/model/anthropic.rs",
        "a_severed_stream_reports_what_it_burned",
        "a stream that generated and then died reports 'cost unknown', so the "
        "tokens it burned are billed as zero and it is retried for free",
        "    if acc.started() {\n        return ModelError::Interrupted {\n"
        "            model: model.clone(),\n            usage: acc.billed(),\n"
        "            detail: detail.to_owned(),\n        };\n    }",
        "    if false {\n        return ModelError::Interrupted {\n"
        "            model: model.clone(),\n            usage: acc.billed(),\n"
        "            detail: detail.to_owned(),\n        };\n    }",
    ),
    "AnUnfinishedStreamIsReturnedWhole": (
        "src/model/anthropic.rs",
        "a_stream_that_ends_without_message_stop_is_not_an_answer",
        "a stream that ended before `message_stop` is returned as a complete "
        "answer — the silent truncation this crate refuses everywhere else",
        "        if !acc.complete() {",
        "        if false {",
    ),
    "CumulativeOutputTokensAreSummed": (
        "src/model/anthropic_stream.rs",
        "cumulative_output_counts_are_not_summed",
        "cumulative per-event counts are added instead of replaced, over-billing "
        "an answer in proportion to how many events it took to deliver",
        "        if let Some(v) = w.output_tokens {\n            self.usage.output_tokens = v;\n        }",
        "        if let Some(v) = w.output_tokens {\n            self.usage.output_tokens += v;\n        }",
    ),
    "APartialUsageEventErasesTheInputCount": (
        "src/model/anthropic_stream.rs",
        "a_partial_usage_object_does_not_zero_what_is_already_known",
        "a `message_delta` carrying only output tokens zeroes the input count "
        "`message_start` already reported",
        "        if let Some(v) = w.input_tokens {",
        "        {\n            let v = w.input_tokens.unwrap_or(0);",
    ),
    "ASeveredOpenAiStreamIsSafeToRepeat": (
        "src/model/openai.rs",
        "a_severed_openai_stream_is_landed_but_unaccounted",
        "an OpenAI stream that generated and then died is reported as possibly "
        "never having run, so the runtime asks again and pays twice",
        "    if acc.generated() {\n        return ModelError::Unaccounted {",
        "    if false {\n        return ModelError::Unaccounted {",
    ),
    "GenerationIsAssumedFromTheHandshake": (
        "src/model/openai_stream.rs",
        "generation_is_not_claimed_before_any_output",
        "a response id is treated as evidence that tokens were produced, so every "
        "failed handshake becomes an un-retryable landed call",
        '            "response.created" => {\n                self.id = value',
        '            "response.created" => {\n                self.generated = true;\n                self.id = value',
    ),
    "SseIgnoresChunkBoundaries": (
        "src/model/sse.rs",
        "an_event_split_across_chunks_is_reassembled",
        "the decoder drops whatever did not arrive on a line boundary, losing "
        "every event TCP happened to split",
        "        self.partial.push_str(&String::from_utf8_lossy(chunk));",
        "        self.partial = String::from_utf8_lossy(chunk).into_owned();",
    ),
    # The two ways a fake provider makes the suite *worse* than having none. A
    # broken fake does not fail loudly; it makes the tests that depend on it pass
    # for the wrong reason, which is the exact failure mode this whole file
    # exists to catch. So the fake gets mutated like anything else.
    "TheFakeAnswersForFree": (
        "src/testkit/fake_model.rs",
        "an_answer_is_never_free",
        "the fake reports zero usage, so every token and cost ceiling test passes "
        "over a runtime that has stopped counting",
        "        input_tokens: (len / 4).max(1),\n        output_tokens: (len / 8).max(1),",
        "        input_tokens: 0,\n        output_tokens: 0,",
    ),
    "TheFakeIsNotDeterministic": (
        "src/testkit/fake_model.rs",
        "the_same_question_gets_the_same_answer",
        "the fake answers differently each call, so every replay test becomes a "
        "coin-toss that mostly passes",
        '        let scripted = self.scripted.lock().expect("fake").pop_front();\n'
        "        scripted.unwrap_or_else(|| Ok(echo(&request)))",
        '        let scripted = self.scripted.lock().expect("fake").pop_front();\n'
        "        let n = self.calls();\n"
        "        scripted.unwrap_or_else(|| {\n"
        "            let mut c = echo(&request);\n"
        '            c.text = format!("{} #{n}", c.text);\n'
        "            Ok(c)\n"
        "        })",
    ),
    "TheFakeScriptRunsBackwards": (
        "src/testkit/fake_model.rs",
        "scripted_answers_come_back_in_order_then_the_default_takes_over",
        "scripted answers are handed out in reverse, so a test arranging "
        "failure-then-success exercises success-then-failure",
        '        let scripted = self.scripted.lock().expect("fake").pop_front();',
        '        let scripted = self.scripted.lock().expect("fake").pop_back();',
    ),
    "GeneratedRefusalIsFree": (
        "src/model/anthropic.rs",
        "a_generated_refusal_is_billed",
        "a model that generated and then declined is billed as free",
        """        return Err(ModelError::Unusable {
            model: model.clone(),
            usage,
            detail: "the model declined to answer".to_owned(),
        });""",
        """        return Err(ModelError::Refused {
            model: model.clone(),
            detail: "the model declined to answer".to_owned(),
        });""",
    ),
    # ── One plane, several agents ───────────────────────────────────────────
    "TwoAgentsShareACapability": (
        "src/runtime/executor.rs",
        "two_agents_may_not_claim_the_same_capability",
        "a second agent's claim on a capability silently displaces the first, "
        "moving its work out from under its own budget and grants",
        "            caps.get(&cap).is_none_or(|first| first == &d.name),",
        "            true,",
    ),
    "TwoSkillsShareAName": (
        "src/runtime/executor.rs",
        "two_skills_on_one_plane_may_not_share_a_name",
        "two skills share a name, so the second inherits the first's manifest",
        "    if let Some(existing) = skills.get(&d.name) {",
        "    if let Some(existing) = None::<&Arc<dyn Skill>> {",
    ),
    "TheJournalForgetsWhoGoverned": (
        "src/runtime/executor.rs",
        "the_journal_records_which_declaration_governed_a_run",
        "a run records no governing declaration, so which manifest governed it "
        "depends on somebody still having the file",
        "        let governed_by = self.identity_for(&agent);",
        "        let governed_by = self.identity_for(&agent).filter(|_| false);",
    ),
    "AdmissionHidesTheDeclaration": (
        "src/runtime/executor.rs",
        "admission_policy_sees_the_agent_apart_from_the_capability",
        "the governing declaration never reaches policy, so a rule can only bind "
        "to a self-asserted name instead of the digest that pins what it said",
        "        if let Some(id) = governed_by {",
        "        if let Some(id) = None::<&crate::journal::AgentIdentity> {",
    ),
    "ThePublisherNeverReachesPolicy": (
        "src/runtime/executor.rs",
        "a_policy_can_bind_to_the_publisher_that_vouched_for_an_agent",
        "the publisher who vouched for a declaration is dropped, leaving a rule "
        "nothing to bind to but a name any file can claim",
        "            publisher: self.published_by.get(&m.metadata.name).cloned(),",
        "            publisher: None,",
    ),
    "InternalSectionRefsAreAllowedToShip": (
        "tests/guards/docs.rs",
        "shipped_source_cites_no_internal_section_numbers",
        "rustdoc may cite sections of the internal design document, which a "
        "docs.rs reader cannot resolve and which go stale silently",
        "    if before.contains(\"RFC\") || before.contains(\"C2SP\") {",
        "    if true {",
    ),
    # ── Envelope encryption and cryptographic erasure ───────────────────────
    "AnErasedScopeMintsAFreshKey": (
        "src/testkit/memory_keyring.rs",
        "an_erased_scope_cannot_be_recreated",
        "an erased scope mints a new data key, so a late write lands in a unit "
        "already reported as erased",
        "        if let Some(gone) = Self::tombstone(&state, scope) {\n            return Err(gone);\n        }\n        let generation = state.generation;",
        "        let generation = state.generation;",
    ),
    "ErasingACaseSparesItsKey": (
        "src/blob/mod.rs",
        "erasing_a_case_destroys_its_key_and_the_backup_with_it",
        "erasing a case writes tombstones but leaves the data key alive, so the "
        "erasure reaches the live store and no backup",
        "    if let Some(keys) = keyring {",
        "    if let Some(keys) = None::<&dyn crate::keyring::KeyRing> {",
    ),
    "SealedRunsWriteInTheClear": (
        "src/runtime/ctx.rs",
        "erasing_a_case_destroys_its_key_and_the_backup_with_it",
        "a configured key ring is ignored on the write path, so payload bytes "
        "reach disk unsealed and erasing the case cannot reach them",
        "        if let Some(keys) = self.keyring.clone() {",
        "        if let Some(keys) = None::<Arc<dyn crate::keyring::KeyRing>> {",
    ),
    "MediaBytesBypassTheSeal": (
        "src/runtime/ctx.rs",
        "only_the_sealed_accessor_reads_the_raw_blob_store",
        "the media path reads the raw blob store directly, so a sealed "
        "deployment writes those payload bytes in the clear",
        "        let blobs = self.blobs_scoped(fetcher.external_scope())?;",
        "        let blobs = self.blobs.clone().expect(\"a blob store\");",
    ),
    "AVaultOutageIsReadAsAnErasure": (
        "src/keyring/vault.rs",
        "a_vault_error_body_is_read_rather_than_dumped",
        "a Vault error body is dumped raw instead of read, so the operator-facing "
        "reason an erasure was refused is buried in JSON",
        "    serde_json::from_str::<Errors>(body)\n        .ok()?\n        .errors\n        .into_iter()\n        .next()",
        "    let _ = body;\n    None",
    ),
    "TransitKeysMayBeAnySize": (
        "src/keyring/vault.rs",
        "a_key_that_is_not_256_bits_is_refused",
        "a data key shorter than 256 bits is accepted, so a misconfigured transit "
        "key silently weakens every payload it seals",
        "    let bytes: [u8; 32] = raw.try_into().map_err(|_| {",
        "    let mut padded = raw.clone();\n    padded.resize(32, 0);\n    let bytes: [u8; 32] = padded.try_into().map_err(|_: Vec<u8>| {",
    ),
    "AVaultErasureLooksLikeARefusal": (
        "src/keyring/vault.rs",
        "vault_transit_satisfies_the_key_ring_contract",
        "a destroyed Vault key is read as an ordinary refusal, so a caller "
        "cannot tell a completed erasure from a permission problem",
        "            400 | 404 if is_missing_key(&reason()) => Err(KeyError::Destroyed {",
        "            400 | 404 if false => Err(KeyError::Destroyed {",
    ),
    # ── Tenant isolation ────────────────────────────────────────────────────
    "TenantsShareAKeyScope": (
        "src/keyring/mod.rs",
        "erasing_one_tenants_key_leaves_another_tenant_readable",
        "the key scope drops the tenant, so two tenants using one case name "
        "share a key and either can erase the other's data",
        "    format!(\"{tenant}/{unit}\")",
        "    let _ = tenant;\n    unit.to_owned()",
    ),
    "ATenantNameMayContainASeparator": (
        "src/core/tenant.rs",
        "erasing_one_tenants_key_leaves_another_tenant_readable",
        "a tenant name may contain '/', so tenant `acme/prod` and tenant `acme` "
        "unit `prod` produce one indistinguishable scope",
        "            .find(|c| matches!(c, '/' | ':' | '\\0' | '\\n') || c.is_control())",
        "            .find(|c| matches!(c, '\\0' | '\\n') || c.is_control())",
    ),
    "AStoreKeyDropsTheTenant": (
        "src/store/redb.rs",
        "a_tenant_cannot_read_another_tenants_run_even_holding_its_id",
        "a run's storage key drops the tenant, so any tenant holding a run id "
        "reads another tenant's journal",
        "        format!(\"{}/{run}\", self.tenant)",
        "        run.to_string()",
    ),
    # ── Tool declarations ───────────────────────────────────────────────────
    "AForcedSchemaSilentlyEatsTheTools": (
        "src/model/anthropic.rs",
        "a_forced_schema_and_declared_tools_are_refused_together",
        "a forced-tool schema overwrites the caller's declared tools, so the "
        "model is offered none and nothing says so",
        "                    if !tools.is_empty() {\n                        return Err(ModelError::Refused {",
        "                    if false {\n                        return Err(ModelError::Refused {",
    ),
    "OpenAiToolsAreNotStrict": (
        "src/model/openai.rs",
        "a_declared_tool_is_rendered_in_openais_shape",
        "declared tools drop strict mode, so arguments are checked after the "
        "tokens are paid for rather than enforced during generation",
        "                                \"strict\": true,",
        "                                \"strict\": false,",
    ),
    "AModelsToolNameResolvesApproximately": (
        "src/tools/mod.rs",
        "a_model_chosen_tool_name_is_matched_exactly_or_refused",
        "a model's chosen tool name is matched loosely, so it can reach a granted "
        "tool by describing it rather than by naming it",
        "            .find(|id| id.wire_name() == name)",
        "            .find(|id| id.wire_name().eq_ignore_ascii_case(name.trim()))",
    ),
    "AContinuationSendsResultsWithoutTheirCalls": (
        "src/model/anthropic.rs",
        "a_continuation_echoes_the_call_beside_its_result",
        "a continuation sends tool results without the calls that asked for "
        "them, which every provider rejects",
        '        "role": "assistant",',
        '        "role": "user",',
    ),
    "AFailedToolLooksLikeAnAnswer": (
        "src/model/anthropic.rs",
        "a_failed_tool_is_marked_is_error",
        "a failed tool is reported as an ordinary result, so the model is taught "
        "the operation succeeded and returned something strange",
        '                "is_error": e.failed,',
        '                "is_error": false,',
    ),
    "AToolCallingAgentRunsForever": (
        "src/runtime/declarative.rs",
        "a_tool_calling_agent_stops_when_it_will_not_converge",
        "a tool-calling agent has no turn ceiling, so a model that keeps asking "
        "runs until the budget stops it — after paying for every turn",
        "        for _turn in 0..self.max_turns {",
        "        for _turn in 0..u32::MAX {",
    ),
    "AToolCallingAgentAnswersFromAnUnfinishedTurn": (
        "src/runtime/declarative.rs",
        "a_tool_calling_agent_stops_when_it_will_not_converge",
        "an agent out of turns returns its half-formed reasoning as the answer "
        "instead of failing",
        '        Ok(Outcome::fail(format!(\n            "\'{}\' did not finish within {} model turns',
        '        return Ok(Outcome::done(crate::core::Tainted::trusted(json!({}))));\n        #[allow(unreachable_code)]\n        Ok(Outcome::fail(format!(\n            "\'{}\' did not finish within {} model turns',
    ),
    "AToolMayBeOfferedWithoutADescription": (
        "src/manifest/mod.rs",
        "a_tool_calling_agent_must_describe_its_tools",
        "a tool-calling agent may grant a tool with no description, so the model "
        "guesses and the guess is refused after the tokens are paid for",
        "            if grant\n                .description\n                .as_ref()\n                .is_none_or(|d| d.trim().is_empty())\n            {",
        "            if false {",
    ),
    "ACardAdvertisesWhatIsNotBuilt": (
        "src/peers/card.rs",
        "an_agent_card_is_derived_from_the_manifest",
        "the published card advertises streaming and push notifications that do "
        "not exist, so a caller waits for events nobody will send",
        "            capabilities: CardCapabilities::implemented(),",
        "            capabilities: CardCapabilities {\n                streaming: true,\n                push_notifications: true,\n                extended_agent_card: true,\n            },",
    ),
    "ACardsSkillsAreNotTheDeclaredCapabilities": (
        "src/peers/card.rs",
        "an_agent_card_is_derived_from_the_manifest",
        "the card's skills are not the declared capabilities, so a peer is told "
        "about work the plane would refuse to dispatch",
        "            .provides\n            .iter()",
        "            .requires\n            .iter()",
    ),
    "TheExtendedCardLeaksTheModel": (
        "src/peers/card.rs",
        "the_extended_card_discloses_more_but_not_the_model",
        "the authenticated card discloses which model an agent runs on, which "
        "is a fact about a supply chain rather than something a caller needs",
        "            topology,\n        })",
        "            topology: manifest\n                .spec\n                .models\n                .as_ref()\n                .and_then(|m| m.privileged.as_ref())\n                .map(|r| format!(\"{}/{}\", r.provider, r.model)),\n        })",
    ),
    "EventsDeduplicateOnIdAlone": (
        "src/core/event.rs",
        "two_producers_sharing_an_id_are_not_one_event",
        "events deduplicate on id alone, so two producers sharing an id swallow "
        "each other's messages with nothing reporting it",
        '        format!("{}\\u{1f}{}", self.source, self.id)',
        "        self.id.clone()",
    ),
    "ADeliveredEventChoosesItsOwnSource": (
        "src/api/mod.rs",
        "a_delivered_events_source_is_the_authenticated_caller",
        "a caller names the source of the event it delivers, so it controls both "
        "halves of the dedup identity and can deduplicate against another party",
        "    let mut event = InboundEvent::new(s.caller.actor.clone(), body.id, body.kind, body.payload);",
        "    let mut event = InboundEvent::new(\"urn:anonymous\", body.id, body.kind, body.payload);\n    let _ = &s;",
    ),
    "AnAwaitedEventsSenderIsNotJournaled": (
        "src/runtime/executor.rs",
        "an_awaited_events_sender_is_in_its_provenance_and_survives_replay",
        "a delivered event's sender is not journaled, so a replayed run labels "
        "the value differently from the live one",
        "                            source: Some(event.source.clone()),",
        "                            source: None,",
    ),
    "ASweepClaimsAnotherTenantsTimer": (
        "src/store/redb_timers.rs",
        "a_sweep_does_not_claim_another_tenants_timers",
        "a timer's key drops the tenant, so a sweep claims another tenant's "
        "timer and wakes that tenant's run under this plane's identity",
        "                        .get((tenant.as_str(), run.as_str(), effect.as_str()))",
        "                        .get((\"\", run.as_str(), effect.as_str()))",
    ),
    "AnEventMatchesAnotherTenantsWaiter": (
        "src/store/redb_events.rs",
        "one_tenants_event_does_not_resume_another_tenants_run",
        "the subscription match index drops the tenant, so one tenant's event "
        "resumes another tenant's waiting run",
        "                .get((tenant, run, effect, ns, val))",
        "                .get((\"\", run, effect, ns, val))",
    ),
    "APlaneMayRunOverAnotherTenantsStore": (
        "src/runtime/executor.rs",
        "a_plane_will_not_start_over_another_tenants_store",
        "a plane starts over a store scoped to a different tenant, so its runs "
        "land in another tenant's keyspace while every key-scoped erasure and "
        "policy request names the right one",
        "        store.tenant() == tenant.as_str(),",
        "        store.tenant() != \"never\",",
    ),
    "TheCardMisspellsItsBinding": (
        "src/peers/card.rs",
        "the_card_uses_the_spec_field_names",
        "the published card names its protocol binding with this crate's own "
        "field name, so a conforming A2A client cannot tell what the URL speaks",
        "#[serde(rename_all = \"camelCase\")]\npub struct CardInterface {",
        "pub struct CardInterface {",
    ),
    "OneTenantsErasureDestroysAnothersBlobs": (
        "src/blob/opendal_store.rs",
        "erasing_one_tenants_blob_leaves_another_tenants_alone",
        "blob paths drop the tenant, so two tenants writing identical bytes "
        "share one object and erasing it for one destroys the other's data "
        "while reporting both requests discharged",
        "        format!(\n"
        "            \"{}/{}/{}/{}/{hex}\",\n"
        "            self.prefix,\n"
        "            self.tenant,\n"
        "            &hex[0..2],\n"
        "            &hex[2..4]\n"
        "        )",
        "        format!(\"{}/{}/{}/{hex}\", self.prefix, &hex[0..2], &hex[2..4])",
    ),
    "APlaneMayShareAnotherTenantsBlobs": (
        "src/runtime/executor.rs",
        "a_plane_will_not_start_over_another_tenants_blobs",
        "a plane starts over a blob store scoped to a different tenant, so its "
        "artifacts land in another tenant's erasure unit",
        "        assert!(\n            blobs.tenant() == tenant.as_str(),",
        "        assert!(\n            blobs.tenant() != \"never\",",
    ),
    "APeerCanNameAnyTenant": (
        "src/api/a2a.rs",
        "a_peer_cannot_name_a_tenant_its_credential_does_not_hold",
        "the A2A surface checks the request's tenant against the card but never "
        "against the credential, so a peer holding a valid credential for any "
        "tenant is served from another's runs by naming it in a field",
        "        if caller.tenant != *self.runtime.tenant() {",
        "        if false {",
    ),
    "AnUnservedTenantFallsBackToAPlane": (
        "src/api/mod.rs",
        "an_unregistered_tenant_is_refused_rather_than_defaulted",
        "a caller whose tenant has no plane is served by some other tenant's "
        "plane instead of refused, which turns an unregistered tenant into "
        "somebody else's data and looks like working software",
        "        let plane = self.planes.get(&caller.tenant).ok_or_else(|| {",
        "        let plane = self\n"
        "            .planes\n"
        "            .get(&caller.tenant)\n"
        "            .or_else(|| self.planes.by_tenant.values().next())\n"
        "            .ok_or_else(|| {",
    ),
    "TheServingTenantComesFromTheRequest": (
        "src/api/mod.rs",
        "a_caller_cannot_read_another_tenants_run",
        "the plane is chosen without reference to the caller's tenant, so any "
        "authenticated caller reads any tenant's runs while holding nothing but "
        "a valid id",
        "        let plane = self.planes.get(&caller.tenant).ok_or_else(|| {",
        "        let plane = self\n"
        "            .planes\n"
        "            .by_tenant\n"
        "            .iter()\n"
        "            .find(|(t, _)| *t != &caller.tenant)\n"
        "            .map(|(_, p)| p)\n"
        "            .or_else(|| self.planes.get(&caller.tenant))\n"
        "            .ok_or_else(|| {",
    ),
    "ANonBlockingSendBlocksAnyway": (
        "src/api/a2a.rs",
        "a_non_blocking_send_returns_a_task_that_already_exists",
        "`returnImmediately` is ignored, so the connection is held open for the "
        "whole run while the response looks exactly like compliance",
        "    if params\n"
        "        .configuration\n"
        "        .as_ref()\n"
        "        .is_some_and(|c| c.return_immediately)\n"
        "    {",
        "    if false {",
    ),
    "AnUnconfiguredSendDoesNotBlock": (
        "src/api/a2a.rs",
        "an_unconfigured_send_blocks",
        "a send with no configuration returns before the run finishes, so a "
        "caller expecting a completed task is handed an unfinished one",
        "        .is_some_and(|c| c.return_immediately)",
        "        .is_none_or(|c| !c.return_immediately)",
    ),
    "ALongRunLosesItsLease": (
        "src/runtime/executor.rs",
        "a_long_run_keeps_its_lease",
        "a run's lease is never renewed while it executes, so a run that "
        "outlives its TTL looks crashed, is taken over by another instance, and "
        "is fenced mid-flight having already done real work",
        "        let _heartbeat = self.heartbeat(a.run, a.epoch);",
        "",
    ),
    "AnUnrenewableLeaseIsAccepted": (
        "src/runtime/executor.rs",
        "a_lease_too_short_to_renew_is_refused",
        "a lease shorter than the store's whole-second expiry granularity is "
        "accepted, so a live run cannot hold it and any instance may take the "
        "run away while it is still working",
        "            ttl >= MIN_LEASE_TTL,",
        "            ttl >= Duration::ZERO,",
    ),
    "TheServerSpeaksTheOldProtocolVersion": (
        "src/api/a2a.rs",
        "this_planes_client_can_call_this_planes_server",
        "the server answers the 0.3 method name, so this plane's own client "
        "cannot call it and any 1.0 peer gets method-not-found",
        "    pub const SEND_MESSAGE: &str = \"SendMessage\";",
        "    pub const SEND_MESSAGE: &str = \"message/send\";",
    ),
    "ADeclineIsReportedAsAnOutage": (
        "src/api/a2a.rs",
        "a_policy_denial_is_a_decline_not_a_server_fault",
        "a policy denial comes back as an internal error, so the caller reads a "
        "permanent refusal as a transient fault and retries a decision that "
        "will never change",
        "        Err(crate::core::RuntimeError::PolicyDenied(_)) => {\n"
        "            return Ok(json!({ \"message\": declined(&skill) }));\n"
        "        }",
        "",
    ),
    "ADeclineRepeatsThePolicysReason": (
        "src/api/a2a.rs",
        "a_policy_denial_is_a_decline_not_a_server_fault",
        "the decline sent to a peer carries the runtime's own denial, naming "
        "the action and resource the gate keyed on — enough to map this "
        "plane's authorization vocabulary by probing it",
        "        Err(crate::core::RuntimeError::PolicyDenied(_)) => {\n"
        "            return Ok(json!({ \"message\": declined(&skill) }));\n"
        "        }",
        "        Err(crate::core::RuntimeError::PolicyDenied(why)) => {\n"
        "            return Ok(json!({ \"message\": declined(&why.to_string()) }));\n"
        "        }",
    ),
    "APeersMessageArrivesTrusted": (
        "src/api/a2a.rs",
        "a_peers_message_is_untrusted_and_carries_its_sender",
        "a message from another agent is admitted as trusted input, so a value "
        "that arrived over the network wears the runtime's own authority and "
        "every protected sink field downstream checks nothing",
        "    let input = Tainted::from_source(\n"
        "        message.to_input(),\n"
        "        SourceId::new(format!(\"peer:{}\", caller.actor)),\n"
        "    );",
        "    let input = Tainted::trusted(message.to_input());",
    ),
    "TheCardIsNotAtTheWellKnownPath": (
        "src/api/a2a.rs",
        "the_agent_card_is_public",
        "the agent card is served somewhere other than the well-known path, so "
        "the server works, nothing errors, and no conforming client ever "
        "discovers this agent",
        "            .route(WELL_KNOWN_PATH, get(agent_card))",
        "            .route(\"/agent-card.json\", get(agent_card))",
    ),
    "TheSkillIsInferredFromTheMessage": (
        "src/api/a2a.rs",
        "an_ambiguous_message_is_refused_rather_than_guessed",
        "an unnamed skill is guessed from the message instead of refused, so "
        "the sender picks which capability runs by writing text",
        "        many => Err(RpcError::new(",
        "        [first, ..] => return Ok(first.clone()),\n        many => Err(RpcError::new(",
    ),
    "AnAbsentVersionIsTreatedAsCurrent": (
        "src/api/a2a.rs",
        "a_request_without_a_version_is_refused_as_zero_three",
        "a request with no A2A-Version header is answered with 1.0 semantics "
        "rather than refused as the 0.3 client the spec says it is",
        "        if major_minor(claimed) == major_minor(crate::peers::PROTOCOL_VERSION) {",
        "        if claimed.is_empty()\n"
        "            || major_minor(claimed) == major_minor(crate::peers::PROTOCOL_VERSION)\n"
        "        {",
    ),
    "ARunJoinsAnotherTenantsCase": (
        "src/store/redb_cases.rs",
        "one_tenants_run_does_not_join_another_tenants_case",
        "the correlation index drops the tenant, so a run joins another tenant's "
        "case on a shared business key and they share a history and an erasure unit",
        "                                (tenant.as_str(), k.namespace.as_str(), k.value.as_str()),\n                                case.as_str(),",
        "                                (\"\", k.namespace.as_str(), k.value.as_str()),\n                                case.as_str(),",
    ),
    # ── The worklist contract ───────────────────────────────────────────────
    "TaskIdIgnoresTheRun": (
        "src/core/task.rs",
        "two_runs_of_one_plan_do_not_share_one_task",
        "a task id is derived from the effect key alone, so two runs share one decision",
        "        let mut bytes = run.to_string().into_bytes();",
        "        let mut bytes = Vec::new();\n        let _ = run;",
    ),
    "ContentionOutranksIneligibility": (
        "src/store/redb_tasks.rs",
        "redb_satisfies_the_case_layer_contracts",
        "a barred reviewer is told the task is held rather than that it is not theirs",
        "                        if task.excluded_actors.iter().any(|a| a == &actor) {",
        "                        if task.assignee.is_none()\n                            && task.excluded_actors.iter().any(|a| a == &actor)\n                        {",
    ),
    "AnyoneCanReleaseAClaim": (
        "src/store/redb_tasks.rs",
        "redb_satisfies_the_case_layer_contracts",
        "a claim can be released by somebody who does not hold it",
        "                    t.state == TaskState::Claimed && t.assignee.as_deref() == Some(actor.as_str())",
        "                    t.state == TaskState::Claimed",
    ),
    "SuspensionScansHistory": (
        "src/api/mod.rs",
        "a_resumed_run_is_not_still_reported_as_suspended",
        "run status comes from any suspension in history, not from the last record",
        "    let Some(last) = records.last() else {",
        """    let Some(last) = records
        .iter()
        .find(|r| matches!(r.kind(), RecordKind::RunSuspended { .. }))
        .or_else(|| records.last())
    else {""",
    ),
}


def _touch(path: pathlib.Path) -> None:
    """Move the file's mtime forward.

    `shutil.move` preserves the backup's *original* timestamp, so a reverted file
    can look older than the object compiled from the mutated source — and cargo,
    which decides by mtime, reuses it. The working tree is then correct while the
    build is not.

    That is not merely untidy. During a sweep it means a later mutation can be
    judged against a stale binary, so a guarantee could be reported as
    unfalsifiable when it is fine, or worse, as fine when it is not. Found the
    hard way: a clean checkout failed a test whose mutated text appeared nowhere
    in the source.
    """
    now = time.time()
    os.utime(path, (now, now))


def _target(name: str) -> tuple[pathlib.Path, str, str]:
    path, _test, _desc, find, replace = MUTANTS[name]
    return ROOT / path, find, replace


def apply(name: str) -> int:
    path, find, replace = _target(name)
    src = path.read_text()
    n = src.count(find)
    if n != 1:
        print(
            f"mutant '{name}' anchors {n} times in {path.name} (expected 1) — "
            f"the code moved and this mutation is testing nothing",
            file=sys.stderr,
        )
        return 1
    shutil.copy(path, path.with_suffix(path.suffix + ".orig"))
    path.write_text(src.replace(find, replace, 1))
    _touch(path)
    return 0


def revert(name: str) -> int:
    path, _, _ = _target(name)
    backup = path.with_suffix(path.suffix + ".orig")
    if backup.exists():
        shutil.move(backup, path)
        _touch(path)
    return 0


def check() -> int:
    """Report every mutation whose anchor no longer matches exactly once.

    Anchor drift is silent until a sweep runs, and a sweep is the expensive way
    to learn it: the guarantee is simply unverified in the meantime, which looks
    identical to being verified. Refactoring the code a mutation points at is
    routine — rewriting the model drivers for streaming broke seven at once — so
    this is a text-only check something cheap can run.
    """
    # A sweep mutates source in place and restores it afterwards, leaving a
    # `.orig` beside whatever it currently holds. Anchor results are meaningless
    # in that window — the file genuinely does not contain its anchor — and
    # reporting them as failures sends someone hunting a defect that will
    # disappear on its own. Refuse to answer rather than answer wrongly.
    held = sorted(p.relative_to(ROOT) for p in ROOT.glob("src/**/*.rs.orig"))
    if held:
        print("a mutation sweep is running; these files are mutated right now:")
        for f in held:
            print(f"  {f.with_suffix('')}")
        print("anchor results would be false. Re-run when the sweep finishes.")
        return 2

    bad = 0
    for name, (path, _test, _desc, find, _replace) in MUTANTS.items():
        target = ROOT / path
        if not target.exists():
            print(f"{name}: {path} does not exist")
            bad += 1
            continue
        n = target.read_text().count(find)
        if n != 1:
            print(f"{name}: anchors {n} times in {path} (expected 1)")
            bad += 1
    print(f"checked {len(MUTANTS)} mutations, {bad} broken")
    return 1 if bad else 0


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--check":
        return check()
    if len(sys.argv) == 2 and sys.argv[1] == "--list":
        for name, (path, test, desc, _, _) in MUTANTS.items():
            print(f"{name}\t{path}\t{test}\t{desc}")
        return 0
    if len(sys.argv) != 3 or sys.argv[1] not in MUTANTS:
        print(__doc__, file=sys.stderr)
        return 2
    name, action = sys.argv[1], sys.argv[2]
    if action == "--apply":
        return apply(name)
    if action == "--revert":
        return revert(name)
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
