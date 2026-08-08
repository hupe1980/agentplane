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
        mutants.py <name> --verify  (apply, run the test it names, restore)

`--check` proves a mutation still *matches* the code. Only `--verify` proves it
still *kills*: a mutation whose test was rewritten around it passes quietly, and
a guarantee that stopped being checked looks exactly like one that is. The
feature set comes from the test's own `cfg` gates rather than a second list, so
there is nothing to keep in step.
"""

from __future__ import annotations

import os
import pathlib
import re
import subprocess
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
                return Some(StepError::Effect(crate::core::EffectError::Final {
                    detail: format!(
                        "effect {key} took effect and its response could not be used \\
                         ({message}); repeating it would perform it a second time"
                    ),
                    disposition,
                }));
            }""",
        """            Disposition::Landed => {
                let _ = (&key, &message, &disposition);
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
            if mutates && label.is_untrusted() {
                return Err(PolicyError::TaintGate { sink: sink_name }.into());
            }
            return Ok(());
        }""",
        """        if protected.is_empty() {
            let _ = label;
            return Ok(());
        }""",
    ),
    "RefusalsTeachTheModel": (
        "src/runtime/declarative.rs",
        "a_refusal_tells_the_model_nothing_it_can_differentiate",
        "the tool-calling loop hands the model the precise policy refusal, "
        "turning the policy into a queryable service",
        "        crate::core::StepError::Policy(p) => Some(p.for_model().to_owned()),",
        "        crate::core::StepError::Policy(p) => Some(p.to_string()),",
    ),
    "AnUnknownOutcomeBecomesAChatMessage": (
        "src/runtime/declarative.rs",
        "an_undecidable_tool_call_quarantines_rather_than_answering_the_model",
        "every error the tool-calling loop meets is stringified back to the "
        "model, so an undecidable outcome never reaches the executor and the "
        "run ends Succeeded instead of quarantined",
        "        _ => None,\n    }\n}",
        "        _ => Some(e.to_string()),\n    }\n}",
    ),
    "AnInDoubtEffectIsAnApology": (
        "src/runtime/declarative.rs",
        "an_in_doubt_tool_call_does_not_become_a_chat_message",
        "an in-doubt effect error is reported to the model as a failed call, so "
        "the loop invites it to reach the same effect another way while the "
        "first may still be in flight",
        """        crate::core::StepError::Effect(inner)
            if inner.disposition() != crate::core::Disposition::InDoubt =>
        {
            Some(inner.to_string())
        }""",
        """        crate::core::StepError::Effect(inner) => Some(inner.to_string()),""",
    ),
    "EveryFailureLooksLikeARefusal": (
        "src/runtime/declarative.rs",
        "a_tool_that_ran_and_failed_reports_its_own_words",
        "the far side's own answer is replaced by the uniform refusal, blinding "
        "the model to the one thing it can act on",
        """        crate::core::StepError::Effect(inner)
            if inner.disposition() != crate::core::Disposition::InDoubt =>
        {
            Some(inner.to_string())
        }""",
        """        crate::core::StepError::Effect(inner)
            if inner.disposition() != crate::core::Disposition::InDoubt =>
        {
            Some(crate::core::REFUSED.to_owned())
        }""",
    ),
    "TheTaintGateTakesTheCatalogueAtItsWord": (
        "src/runtime/ctx.rs",
        "the_taint_gate_takes_the_stricter_of_catalogue_and_grant",
        "the sink gate reads `mutates` from the catalogue alone, so a catalogue "
        "calling a reviewed-mutating tool read-only exempts it from the "
        "whole-value taint gate",
        """        let mutates = effect.mutates()
            || (manifest_gates
                && self
                    .tool_grant_for(&effect.descriptor())
                    .is_some_and(|g| g.mutates));""",
        """        let mutates = effect.mutates();""",
    ),
    "TheQuarantineListKeepsTheOldest": (
        "src/store/redb.rs",
        "redb_satisfies_the_journal_store_contract",
        "the outcome index pages in ascending order, so a backlog past one page "
        "never surfaces the quarantine that just happened",
        """                .map_err(|e| be(&e))?
                .rev()
            {
                if out.len() >= limit {""",
        """                .map_err(|e| be(&e))?
            {
                if out.len() >= limit {""",
    ),
    "OneToolTwoDeclarationsLastWins": (
        "src/runtime/executor.rs",
        "two_agents_may_not_declare_one_tool_differently",
        "two agents declaring one tool differently merge by registration order "
        "instead of being refused",
        """                if let Some((first, existing)) = source.get(&id) {
                    if existing != &safety {""",
        """                if let Some((first, existing)) = source.get(&id) {
                    if false {""",
    ),
    "AStatedCatalogueMayRelaxAGrant": (
        "src/runtime/executor.rs",
        "a_stated_catalogue_may_not_relax_a_reviewed_mutating_grant",
        "a hand-written catalogue laxer than the reviewed manifest builds anyway",
        "        self.check_catalogue_not_laxer_than_grants()",
        "        let _ = Self::check_catalogue_not_laxer_than_grants;\n        Ok(())",
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
        "            self.gate(key, &descriptor, effect.mutates(), outbound).await?;\n            if self.mode.is_replaying() {",
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
        "            keys.sort_unstable_by(|a, b| utf16_order(a, b));\n",
        "",
    ),
    # ── Cedar adapter ───────────────────────────────────────────────────────
    "ANullDeniesEverything": (
        "src/policy/cedar.rs",
        "a_null_inside_caller_arguments_does_not_deny_everything",
        "the Cedar adapter hands the context straight to Cedar, which refuses "
        "any document containing a JSON null — not the field, the whole record "
        "— so every request carrying an unset optional is reported as malformed "
        "and denied, while an operator reading 'denied' hunts for the rule",
        "            without_nulls(r.context.clone()),",
        "            r.context.clone(),",
    ),
    "AnAbsentPublisherIsNull": (
        "src/runtime/executor.rs",
        "a_declared_agent_sends_no_null_either",
        "an unpublished manifest's absent publisher is sent as a JSON null "
        "rather than omitted, which is the shape the adapter's own "
        "documentation calls 'absent' and the shape Cedar cannot parse",
        '            if let Some(publisher) = id.publisher.as_ref() {\n'
        '                agent["publisher"] = serde_json::to_value(publisher)?;\n'
        "            }",
        '            agent["publisher"] = serde_json::to_value(&id.publisher)?;',
    ),
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
    "AnAuditNeverSaysWhatAuthorized": (
        "src/audit.rs",
        "an_audit_reports_what_authorized_each_run",
        "the offline audit reports history as sound without ever saying what "
        "warranted it, so a run that executed with no policy engine configured "
        "at all verifies exactly as soundly as a governed one and an auditor "
        "reading `sound` concludes it was governed",
        "        warrants.extend(warrant_in(run, &records));",
        "        let _ = warrant_in;",
    ),
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
        """                Some(a)
                    if verifier.verify(&a.key_id, &record_signing_input(r.hash), &a.signature) => {}""",
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
        "src/netguard/mod.rs",
        "one_private_dns_answer_refuses_the_entire_resolution",
        "a public DNS answer launders a private or metadata address in the same "
        "response — one rule, so this breaks governed media and webhook delivery "
        "together",
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
        "        // the decoration the binding rule exists to refuse.\n        if self.spec.execution.is_none() {",
        "        // the decoration the binding rule exists to refuse.\n        if false {",
    ),
    "ADeclarativeAgentTakesAnyDriver": (
        "src/runtime/executor.rs",
        "a_declarative_agent_refuses_an_unnamed_provider",
        "a declarative agent falls back to whatever driver is registered when "
        "the one its manifest names is absent, running the agent on a model its "
        "own declaration never mentioned",
        "                let provider = self\n                    .providers\n                    .get(&model.provider)",
        "                let provider = self\n                    .providers\n                    .values()\n                    .next()\n                    .map(|p| p)",
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
        """            .find(|b| {
                b.get("type").and_then(Value::as_str) == Some("tool_use")
                    && b.get("name").and_then(Value::as_str) == Some(RESPOND_TOOL)
            })""",
        """            .find(|b| {
                b.get("type").and_then(Value::as_str) == Some("tool_use")
            })""",
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
        "            && actual > usize::from(ceiling)",
        "            && false",
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
    # ── How a failure reads ─────────────────────────────────────────────────
    #
    # A diagnostic is a control here for the same reason a refusal is: I13 asks
    # whether a finding reaches somebody who can act on it, and a message nobody
    # is shown fails that test as completely as one nobody wrote.
    "ADerivedDebugHidesEveryMessage": (
        "src/core/error.rs",
        "a_failure_debugs_as_the_message_it_carries",
        "the user-facing error types report through a structural Debug again, "
        "so `fn main() -> Result<_, E>` — which prints Debug, not Display — "
        "shows `NoProvider(\"demo.greet\")` and every message in the taxonomy "
        "becomes unreachable on the first path a newcomer takes",
        "                ::core::fmt::Display::fmt(self, f)",
        '                f.write_str("RuntimeError")',
    ),
    "AnUnknownCapabilityListsNothing": (
        "src/core/error.rs",
        "an_unknown_capability_is_told_what_exists",
        "the unknown-capability refusal stops naming what the plane does "
        "provide, sending a reader back to their own source to reconstruct a "
        "list the error was already holding",
        "    if available.is_empty() {",
        "    if true {",
    ),
    "ACappedListLooksComplete": (
        "src/core/error.rs",
        "a_capped_capability_list_admits_the_cap",
        "a capped capability list stops saying it was capped, so a reader who "
        "scans it and does not find theirs cannot tell 'it is not here' from "
        "'the message stopped' — shape 12, in a diagnostic",
        '        format!(", and {rest} more")',
        '        String::new()',
    ),

    # ── Wire drivers ────────────────────────────────────────────────────────
    "ATruncatedVectorStaysUnnormalised": (
        "src/model/embeddings.rs",
        "gemini_embeds_a_query_and_renormalises_a_truncated_vector",
        "a Matryoshka-truncated vector is returned without re-normalising, so "
        "cosine against a normalised index is scaled by whatever magnitude "
        "survived the truncation and every score is quietly biased",
        "        if self.dimensions.is_some() {\n            let norm = vector.iter().map(|v| v * v).sum::<f32>().sqrt();",
        "        if false {\n            let norm = vector.iter().map(|v| v * v).sum::<f32>().sqrt();",
    ),
    "AQueryIsEmbeddedAsADocument": (
        "src/model/embeddings.rs",
        "gemini_embeds_a_query_and_renormalises_a_truncated_vector",
        "the query is embedded under the document task type, which an "
        "asymmetric model ranks badly and no reply reports",
        '            "taskType": "RETRIEVAL_QUERY",',
        '            "taskType": "RETRIEVAL_DOCUMENT",',
    ),
    "AnAsymmetryHintNeverLeaves": (
        "src/model/embeddings.rs",
        "an_input_type_reaches_the_wire_and_the_revision",
        "the declared input type never reaches the wire, so an asymmetric model "
        "embeds a query symmetrically — right shape, worse ranking, nothing in "
        "the reply saying so",
        '            body["input_type"] = serde_json::json!(input_type);',
        "            let _ = input_type;",
    ),
    "AnEmbedderTakesWhateverCameBack": (
        "src/model/embeddings.rs",
        "an_embedder_refuses_an_answer_that_is_not_one_vector",
        "the embedder takes the first vector of however many came back, so a "
        "server answering with several ranks a query against a vector produced "
        "for somebody else's input — and the effect key records it as this "
        "query's",
        "        let [datum] = reply.data.as_slice() else {",
        "        let [datum, ..] = reply.data.as_slice() else {",
    ),
    "AnEmbedderRevisionForgetsItsWidth": (
        "src/model/embeddings.rs",
        "an_embedder_sends_the_wire_and_names_its_revision",
        "the embedding revision names the model but not the dimension count, so "
        "vectors of two widths share one effect identity and a replay reads one "
        "as the other",
        '            let _ = write!(revision, "@{d}");',
        "            let _ = d;",
    ),
    "AnyProviderAnswerSatisfiesItsSchema": (
        "src/model/mod.rs",
        "a_provider_answer_that_defies_its_schema_is_a_metered_failure",
        "the effect boundary takes any provider's structured answer on trust",
        "    let Some(schema) = schema else {\n        return Ok(());\n    };\n    if !completion.tool_calls.is_empty() {",
        "    let Some(schema) = schema else {\n        return Ok(());\n    };\n    if true || !completion.tool_calls.is_empty() {",
    ),
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
        "        serde_json::from_str(text).map_err(|e| ModelError::Unusable {\n            model: model.clone(),\n            usage,",
        "        serde_json::from_str(text).map_err(|e| ModelError::Unusable {\n            model: model.clone(),\n            usage: super::Usage::default(),",
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
    # ── Standing authority ──────────────────────────────────────────────────
    #
    # A ceiling that spans runs and can be revoked. Every one of these failures
    # is silent in the ordinary case and only shows up under retry, after
    # revocation, or on replay — which is why each gets a mutation rather than
    # trusting the happy path to have covered it.
    "ADrawIsNotIdempotent": (
        "src/store/redb_authority.rs",
        "a_repeated_draw_under_one_key_consumes_once",
        "a retried draw takes the authority a second time, so one purchase "
        "spends a customer's authorization twice — and only under retry, which "
        "is the condition hardest to notice in testing",
        """    if let Some(prior) = receipts
        .get((tenant, name, key))
        .map_err(|e| be(&e))?
        .map(|v| v.value())
    {""",
        # `ReceiptRow`, not the tuple spelled out: this mutation stopped
        # compiling when money went unsigned, so the guarantee it names went
        # unverified while `--check` still reported the anchor present. Naming
        # the alias makes the row's shape the store's business, not this table's.
        """    if let Some(prior) = None::<ReceiptRow> {""",
    ),
    "OnlyOneAxisOfTheCeilingIsBounded": (
        "src/authority/mod.rs",
        "draws_accumulate_across_calls_until_the_ceiling_refuses",
        "the ceiling is enforced on tokens and not on money, so an authority "
        "issued in minor units bounds nothing at all — the failure is invisible "
        "in any test whose amounts happen to be token-shaped",
        "    if amount.tokens > remaining.tokens || amount.minor_units > remaining.minor_units {",
        "    if amount.tokens > remaining.tokens {",
    ),
    "ARevokedAuthorityStillDraws": (
        "src/authority/mod.rs",
        "a_landed_draw_survives_a_later_revocation_on_retry",
        "revocation is recorded and never consulted, so withdrawing an "
        "authorization changes a stored field and nothing else — a control that "
        "reads as enforced while permitting every later draw",
        "    if let Some(reason) = revoked {",
        "    if let Some(reason) = None::<&str> {",
    ),
    "AnExpiredAuthorityStillDraws": (
        "src/authority/mod.rs",
        "each_refusal_is_distinguishable_from_the_others",
        "expiry is never checked, so an authority that ran out of time keeps "
        "spending against a ceiling nobody is watching any more",
        """    if let Some(expires) = authority.expires_at
        && now >= expires.unix_timestamp()
    {""",
        """    if let Some(expires) = authority.expires_at
        && false
    {""",
    ),
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
    "TheFakeIsExemptFromTheMediaRefusal": (
        "src/testkit/fake_model.rs",
        "the_fake_refuses_a_provider_side_media_url_like_every_driver",
        "the fake skips the provider-side media refusal every real driver makes, "
        "so a test proving that a caller-named URL never reaches a provider "
        "passes without the refusal existing — and an embedder concludes the "
        "plane permits what production refuses",
        "        crate::model::refuse_provider_side_media(request.prompt, request.model)?;",
        "        let _ = &request.prompt;",
    ),
    "TheFakeIgnoresADeclaredSchema": (
        "src/testkit/fake_model.rs",
        "a_declared_schema_binds_the_fake_the_way_it_binds_a_driver",
        "the fake records `output.schema` and ignores it, so a run scripted with "
        "prose completes and yields Null where every real driver answers "
        "Unusable — a stub passing tests no provider could pass",
        "            .and_then(|completion| honour_schema(completion, request.schema, request.model));",
        "            .map(|completion| completion);",
    ),
    "TheFakeIsNotDeterministic": (
        "src/testkit/fake_model.rs",
        "the_same_question_gets_the_same_answer",
        "the fake answers differently each call, so every replay test becomes a "
        "coin-toss that mostly passes",
        '        let scripted = self.scripted.lock().expect("fake").pop_front();\n'
        "        let answer = scripted\n"
        "            .unwrap_or_else(|| Ok(echo(&request)))\n"
        "            .and_then(|completion| honour_schema(completion, request.schema, request.model));",
        '        let scripted = self.scripted.lock().expect("fake").pop_front();\n'
        "        let n = self.calls();\n"
        "        let answer = scripted.unwrap_or_else(|| {\n"
        "            let mut c = echo(&request);\n"
        '            c.text = format!("{} #{n}", c.text);\n'
        "            Ok(c)\n"
        "        });",
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
    "AToolLoopWithNothingToReachBuilds": (
        "src/runtime/executor.rs",
        "a_tool_calling_agent_with_no_catalogue_refuses_the_build",
        "a declarative tool loop with no tool catalogue assembles cleanly and "
        "then fails identically on every single run — a wiring mistake known at "
        "build, reported once per request instead of once",
        "                if tools.is_none() {",
        "                if false {",
    ),
    "TwoAgentsShareACapability": (
        "src/runtime/executor.rs",
        "two_agents_may_not_claim_the_same_capability",
        "a second agent's claim on a capability silently displaces the first, "
        "moving its work out from under its own budget and grants",
        "        if let Some(first) = caps.get(&cap)\n            && first != &d.name\n        {",
        "        if let Some(first) = caps.get(&cap)\n            && false\n        {",
    ),
    "TwoSkillsShareAName": (
        "src/runtime/executor.rs",
        "two_skills_on_one_plane_may_not_share_a_name",
        "two skills share a name, so the second inherits the first's manifest",
        "    if let Some(existing) = skills.get(&d.name)",
        "    if let Some(existing) = None::<&Arc<dyn Skill>>",
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
        "nothing_a_reader_sees_cites_an_internal_section_number",
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
    "AnInertQuarantinedModelParses": (
        "src/manifest/mod.rs",
        "a_quarantined_model_nothing_selects_is_refused",
        "a quarantined model nothing in the declaration can select is accepted, "
        "so a tool-calling agent reads as dual-model isolation while every call "
        "goes to the privileged model — a declared control governing nothing",
        "            if !selectable {",
        "            if false {",
    ),
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
        "                        let strict = strict_schema_problem(&t.parameters).is_none();",
        "                        let strict = false;",
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
        '                "is_error": exchange.failed,',
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
        "                let mut capabilities = CardCapabilities::implemented();",
        "                let mut capabilities = CardCapabilities {\n                    streaming: true,\n                    push_notifications: true,\n                    extended_agent_card: true,\n                    extensions: Vec::new(),\n                };",
    ),
    "ACardsSkillsAreNotTheDeclaredCapabilities": (
        "src/peers/card.rs",
        "an_agent_card_is_derived_from_the_manifest",
        "the card's skills are not the declared capabilities, so a peer is told "
        "about work the plane would refuse to dispatch",
        # This used to swap `.provides` for `.requires`, and stopped compiling
        # when `Capabilities` lost every field but `provides` — so the guarantee
        # went unverified while `--check` still found the anchor, which is the
        # exact gap `--verify` exists to close. The mutation now advertises a
        # capability the manifest never declared: same guarantee removed, and it
        # cannot rot into a non-compiling edit again, because the field it
        # writes is the one the test reads.
        "                id: capability.clone(),\n                name: capability.clone(),",
        "                id: format!(\"{capability}.undeclared\"),\n                name: capability.clone(),",
    ),
    "TheExtendedCardLeaksTheModel": (
        "src/peers/card.rs",
        "the_extended_card_discloses_more_but_not_the_model",
        "the authenticated card discloses which model an agent runs on, which "
        "is a fact about a supply chain rather than something a caller needs",
        "        if let Some(topology) = topology {\n            params.insert(\"topology\".to_owned(), serde_json::Value::String(topology));\n        }",
        "        if let Some(topology) = topology {\n            params.insert(\"topology\".to_owned(), serde_json::Value::String(topology));\n        }\n        if let Some(model) = manifest\n            .spec\n            .models\n            .as_ref()\n            .and_then(|m| m.privileged.as_ref())\n            .map(|r| format!(\"{}/{}\", r.provider, r.model))\n        {\n            params.insert(\"model\".to_owned(), serde_json::Value::String(model));\n        }",
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
        "    if store.tenant() != tenant.as_str() {",
        "    if store.tenant() == \"never\" {",
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
        "    if let Some(blobs) = blobs\n        && blobs.tenant() != tenant.as_str()",
        "    if let Some(blobs) = blobs\n        && blobs.tenant() == \"never\"",
    ),
    "ASummaryDropsItsSensitivity": (
        "src/runtime/ctx.rs",
        "a_summary_inherits_the_join_of_what_it_summarised",
        "a summary takes a lower sensitivity than its most sensitive input, so "
        "summarising is a declassification nobody authorised",
        "            sensitivity = sensitivity.max(l.sensitivity);",
        "",
    ),
    "CompactionIgnoresTheCeiling": (
        "src/runtime/ctx.rs",
        "compaction_cannot_exceed_the_sensitivity_ceiling",
        "compaction does not bound what the summarising model may be shown, so "
        "summarising becomes the route by which confidential memories reach a "
        "model that may not see them — while looking like housekeeping",
        "        let call = crate::model::ModelCall::new(provider, model, prompt.peek().clone())\n            .with_max_sensitivity(into.max_sensitivity);",
        "        let call = crate::model::ModelCall::new(provider, model, prompt.peek().clone())\n            .with_max_sensitivity(crate::core::Sensitivity::Secret);",
    ),
    "ASummaryForgetsWhatItWasMadeFrom": (
        "src/store/redb_memory.rs",
        "forgetting_a_source_can_reach_what_was_derived_from_it",
        "derivation edges are not written, so a poisoned memory can be forgotten "
        "while every summary that absorbed it stays readable — the attack "
        "outliving its own remedy",
        "                for source in &item.derived_from {\n"
        "                    derived\n"
        "                        .insert((tenant.as_str(), source.id.as_str(), id.as_str()), ())\n"
        "                        .map_err(|e| be(&e))?;\n"
        "                }",
        "",
    ),
    # ── Transactional effect groups ─────────────────────────────────────────
    "AGroupCommitsByBeingForgotten": (
        "src/runtime/executor.rs",
        "a_group_left_open_is_reversed_rather_than_committed",
        "a step that returns without settling its group leaves the members "
        "standing, so the most consequential thing a group does is what happens "
        "when the author writes nothing at all",
        "    let Some(name) = cx.open_group().map(|g| g.name.clone()) else {\n        return result;\n    };",
        "    let Some(name) = cx.open_group().map(|g| g.name.clone()) else {\n        return result;\n    };\n    let _ = &name;\n    if true {\n        return result;\n    }",
    ),
    "AGroupReversesThroughDoubt": (
        "src/runtime/executor.rs",
        "a_group_in_doubt_is_quarantined_rather_than_reversed",
        "a group unwinds around a member whose outcome nobody can establish — "
        "undoing a call that may or may not have landed, which is a coin flip "
        "with the outside world's money on it",
        "    let doubt = match &result {\n        Err(SkillError::Step(e)) => crate::runtime::group::may_have_externalised(e),\n        _ => false,\n    };",
        "    let doubt = false;",
    ),
    "ReversalsRunForwards": (
        "src/runtime/group.rs",
        "reversals_run_in_the_opposite_order_to_the_members",
        "members are taken back in the order they landed, so a reversal that "
        "depends on an earlier member still being in place runs after it is gone",
        "        for (done, member) in reversals.into_iter().rev().enumerate() {",
        "        for (done, member) in reversals.into_iter().enumerate() {",
    ),
    "TheGateOpensBeforeTheInvariants": (
        "src/runtime/group.rs",
        "a_broken_invariant_reverses_the_group_and_names_itself",
        "deferred members are released without checking the invariants, so the "
        "irreversible send goes out for a group that should never have committed",
        "        if let Some(broken) = invariants.iter().find(|i| !i.holds) {",
        "        if let Some(broken) = invariants.iter().find(|_| false) {",
    ),
    "AnUndeclaredResourceIsAdmitted": (
        "src/runtime/group.rs",
        "a_member_outside_the_footprint_is_refused_before_it_runs",
        "a member may touch a resource the group never declared, which makes the "
        "footprint a comment and the frontier a boundary around nothing",
        "        if open.resources.iter().any(|r| r == resource) {\n            return Ok(());\n        }",
        "        if true {\n            let _ = resource;\n            return Ok(());\n        }",
    ),
    "AnAtomicCommitIsForgottenByTheAbortPath": (
        "src/runtime/group.rs",
        "a_deferred_failure_after_an_atomic_commit_is_not_an_abort",
        "a deferred member failing after the atomic members committed takes the "
        "cheap abort path, so the journal settles the group as taken back whole "
        "while the transaction's writes stand with no reversal registered and "
        "none possible",
        "                Err(e) if outputs.is_empty() && !atomic_committed && !may_have_externalised(&e) => {",
        "                Err(e) if outputs.is_empty() && !may_have_externalised(&e) => {",
    ),
    "AMutatingEffectPassesAsARead": (
        "src/runtime/group.rs",
        "a_mutating_effect_cannot_be_declared_a_group_read",
        "an effect that mutates is admitted as a group read, taking the exemption "
        "from declaring a reversal while leaving something standing",
        "        if effect.mutates() {",
        "        if false {",
    ),
    "AGuardrailIsNotEffectIdentity": (
        "src/model/bedrock.rs",
        "a_guardrail_is_effect_identity_and_both_paths_send_the_same_one",
        "the guardrail a call ran under is left out of the request profile, so "
        "it can be turned off, or moved to another version, between a run and "
        "its replay with nothing on the record — the one control a deployment "
        "installed to stop something, silently absent from what governed the call",
        '            "guardrail": self.guardrail.as_ref().map(|g| json!({\n'
        '                "id": g.identifier,\n'
        '                "version": g.version,\n'
        '            })),',
        '            "guardrail": Value::Null,',
    ),
    "AnUntrustedAnswerMayChooseItsEnvelope": (
        "src/api/a2a.rs",
        "a_peer_cannot_smuggle_a_reply_envelope_through_untrusted_output",
        "an A2A reply projection is honoured from untrusted output, so a peer "
        "that puts the marker in its own message and has an ordinary echoing "
        "skill return it chooses the envelope its reply arrives in — a file "
        "URL of the attacker's naming, presented as the agent's answer",
        "        if output.label().is_untrusted() {\n            return None;\n        }",
        "",
    ),
    "ARoomMayDeclareOneAgentTwice": (
        "src/manifest/mod.rs",
        "a_bundle_declaring_one_agent_twice_is_refused",
        "one file declaring the same agent twice parses as a room, so which "
        "declaration governs is decided by registration order — a reviewed "
        "disagreement resolved by accident",
        "            if let Some(twin) = manifests\n"
        "                .iter()\n"
        "                .find(|prior| prior.metadata.name == m.metadata.name)\n"
        "            {",
        "            if let Some(twin) = manifests\n"
        "                .iter()\n"
        "                .find(|_prior| false)\n"
        "            {",
    ),
    "AnAgentGrantNobodyProvidesIsAccepted": (
        "src/runtime/executor.rs",
        "an_agent_grant_naming_no_capability_refuses_the_build",
        "an agent grant naming a capability no agent provides builds anyway, so "
        "the model is offered a consultation that fails when chosen — paid for "
        "and refused, on every run, instead of refused once at build",
        "                    if !by_capability.contains_key(&Capability::new(id.tool.as_str())) {\n"
        "                        return Err(BuildError::AgentToolUnknownCapability {\n"
        "                            agent: m.metadata.name.clone(),\n"
        "                            capability: id.tool,\n"
        "                        });\n"
        "                    }",
        "",
    ),
    "ASeveredLocalStreamIsCalledFree": (
        "src/model/chat_completions.rs",
        "chat_completions_a_stream_severed_after_generation_is_not_free_to_retry",
        "a chat-completions stream severed after visible deltas is reported as "
        "safe to repeat, so a retry loop against a flaky local server buys a "
        "second generation for every question while the ceiling reads zero",
        "    if acc.generated() {\n        return ModelError::Unaccounted {",
        "    if false {\n        return ModelError::Unaccounted {",
    ),
    "ARefusalBecomesDoubt": (
        "src/runtime/ctx.rs",
        "exhausting_the_attempts_keeps_the_driver_s_verdict",
        "exhausting the attempts flattens the driver's verdict into an untyped "
        "error, which reads as in-doubt — so a call that was provably refused is "
        "reported as one that may have happened, and everything that acts on "
        "doubt acts on a fabrication",
        "            StepError::Effect(crate::core::EffectError::Final {\n"
        "                detail: format!(\n"
        "                    \"effect {key} failed on attempt {attempt} of {}: {message}\",\n"
        "                    policy.max_attempts\n"
        "                ),\n"
        "                disposition,\n"
        "            })",
        "            StepError::Effect(crate::core::EffectError::Other(format!(\n"
        "                \"effect {key} failed on attempt {attempt} of {}: {message}\",\n"
        "                policy.max_attempts\n"
        "            )))",
    ),
    "AReversalCannotAffordItself": (
        "src/runtime/ctx.rs",
        "a_group_is_taken_back_even_when_the_budget_is_exhausted",
        "a group reversal is gated like a forward call, so a run that reaches "
        "its ceiling mid-group cannot release the hold it already placed — a "
        "charged card and no order, reached through the budget rather than "
        "through a bug",
        "        if !self.phase.is_forward() || self.reversing {",
        "        if !self.phase.is_forward() {",
    ),
    "AReportedFailureIsCalledSuccess": (
        "src/runtime/executor.rs",
        "a_step_that_reports_failure_keeps_its_own_reason",
        "a step that reports a failure has its reason replaced by a message "
        "about groups, so the operator reading the run is told the step returned "
        "successfully and never learns why it actually stopped",
        "            failed @ Ok(Outcome::Fail { .. }) => failed,",
        "",
    ),
    "ReversalLeavesTheGateOpen": (
        "src/runtime/group.rs",
        "the_gate_exemption_ends_with_the_reversal",
        "the gate exemption is never cleared after a reversal, so every effect "
        "the step performs afterwards skips the manifest check, policy and the "
        "budget — a security hole that looks like a missing line",
        "        let reversed = self.reverse_each(reversals).await;\n        self.set_reversing(false);",
        "        let reversed = self.reverse_each(reversals).await;",
    ),
    "PolicyCannotSeeProvenance": (
        "src/runtime/ctx.rs",
        "a_rule_can_refuse_an_effect_for_where_its_arguments_came_from",
        "the label never reaches the authorization request, so provenance and "
        "authorization are two graphs that only meet in checks written in this "
        "crate — a deployment can say 'amounts over 5000 need approval' but not "
        "'not with data that passed through that peer'",
        "        if let Some(label) = outbound {\n            context[\"label\"] = serde_json::to_value(label).unwrap_or(Value::Null);\n        }",
        "",
    ),
    "ASinkBoundMemberIsAcceptedSilently": (
        "src/runtime/group.rs",
        "a_member_that_binds_outbound_arguments_is_refused_at_registration",
        "a member that binds its outbound arguments is registered without "
        "complaint, so the refusal arrives during an abort — about the undo "
        "rather than about the member that was wrong — or, for a reversal, the "
        "group settles as aborted with nothing registered to take the hold back",
        "        effect.sink_arguments().is_some().then(|| {",
        "        effect.sink_arguments().is_none().then(|| {",
    ),
    "AnUntrustedInstructionIsObeyed": (
        "src/model/mod.rs",
        "an_untrusted_instruction_is_refused_before_the_model_sees_it",
        "the instruction slot is not protected, so text that arrived as *data* "
        "can be handed to the model as the order it reasons under — and the "
        "agent follows instructions written by whoever authored the page it read",
        "        self.protected = if self.prompt.get(\"system\").is_some_and(|s| !s.is_null()) {\n"
        "            vec![crate::core::ProtectedField::trusted(\"/system\")]\n"
        "        } else {\n"
        "            Vec::new()\n"
        "        };",
        "        self.protected = Vec::new();",
    ),
    "AToolLoopInstructionIsTaintedByItsCaller": (
        "src/runtime/declarative.rs",
        "a_declared_instruction_survives_an_untrusted_input_in_the_tool_loop",
        "the tool-calling loop builds its prompt by mapping over the caller's "
        "input, so the manifest's reviewed instruction inherits the caller's "
        "label — and this is the tier where it matters most, because the "
        "model's answer chooses which granted tool runs",
        "        let prompt = Tainted::object([\n"
        "            (\"system\".to_owned(), Tainted::trusted(json!(system))),\n"
        "            (\"input\".to_owned(), input),\n"
        "        ]);",
        "        let prompt = input.map(|input| json!({ \"system\": system, \"input\": input }));",
    ),
    "ADeclaredInstructionIsTaintedByItsCaller": (
        "src/runtime/declarative.rs",
        "a_declared_instruction_survives_an_untrusted_input",
        "a declarative agent builds its prompt by mapping over the caller's "
        "input, so the manifest's own reviewed, digest-pinned instruction "
        "inherits the caller's label — the declared order becomes "
        "indistinguishable from the data, and an agent reachable over A2A is "
        "refused as though the peer had written its prompt",
        "                let prompt = Tainted::object([\n"
        "                    (\"system\".to_owned(), Tainted::trusted(json!(system))),\n"
        "                    (\"input\".to_owned(), input),\n"
        "                ]);",
        "                let prompt = input.map(|input| json!({ \"system\": system, \"input\": input }));",
    ),
    # ── Committing with the journal ─────────────────────────────────────────
    "AtomicMembersRunBeforeTheFrontier": (
        "src/runtime/group.rs",
        "an_atomic_member_commits_with_the_journal",
        "atomic members are never applied, so a group reports committed while "
        "the ledger it was supposed to post to never moved — the quietest "
        "possible failure, because nothing errors",
        "        if atomic_committed && let Err(e) = self.cx.commit_atomic(&name, atomic).await {",
        "        if false && let Err(e) = self.cx.commit_atomic(&name, atomic).await {",
    ),
    "AFailedTransactionQuarantines": (
        "src/runtime/group.rs",
        "a_refused_atomic_member_leaves_nothing_behind",
        "a transaction that did not commit is treated as damage rather than as "
        "nothing happening, so the group quarantines instead of being taken "
        "back — throwing away the one property this class exists for",
        "            self.cx.abort_open_group(&what).await?;\n            return Err(StepError::GroupAborted { what });\n        }\n\n        let mut outputs = Vec::with_capacity(deferred.len());",
        "            self.cx\n                .settle_open_group(GroupOutcome::Quarantined, Some(&what))\n                .await?;\n            return Err(StepError::GroupUnsettled { group: name, detail: what });\n        }\n\n        let mut outputs = Vec::with_capacity(deferred.len());",
    ),
    "AReplayedTransactionRuns": (
        "src/runtime/group.rs",
        "a_replayed_atomic_member_is_not_applied_again",
        "a replayed run applies the transaction again, so replaying a committed "
        "group posts to the ledger twice — reliably, because it is transactional",
        "            if self.replaying() {",
        "            if false {",
    ),
    "AnAbsentTransactionIsDiscoveredAtTheFrontier": (
        "src/runtime/group.rs",
        "an_atomic_member_is_refused_by_a_store_that_cannot_enlist",
        "a store that cannot lend a transaction is discovered at commit instead "
        "of at registration, by which time every eager member has already run",
        "        if !self.cx.store_is_atomic() {",
        "        if false {",
    ),
    "CaseStatusIsWrittenOutsideTheJournal": (
        "src/runtime/ctx.rs",
        "changing_a_case_status_is_journaled_and_not_repeated_on_replay",
        "a case's status is written straight to the store, so the change is "
        "unattributable *and* performed again on every replay — replaying last "
        "quarter's history to answer a question closes a case that has since "
        "been reopened",
        "        self.effect(crate::runtime::effects::SetCaseStatus {\n"
        "            cases: Arc::clone(&cx.cases),\n"
        "            case: cx.case_id,\n"
        "            status,\n"
        "        })\n"
        "        .await?;",
        "        cx.cases.set_status(cx.case_id, status).await?;",
    ),
    "ADeadlineTransitionIsWrittenOutsideTheJournal": (
        "src/runtime/ctx.rs",
        "changing_a_case_status_is_journaled_and_not_repeated_on_replay",
        "a deadline transition is written straight to the store and journaled "
        "afterwards, so a crash between the two marks an obligation met with "
        "nothing saying who met it — and a replay meets it a second time",
        "        let before = self\n"
        "            .effect(crate::runtime::effects::TransitionDeadline {\n"
        "                cases: Arc::clone(&cx.cases),\n"
        "                case: cx.case_id,\n"
        "                name: name.to_owned(),\n"
        "                to,\n"
        "            })\n"
        "            .await?\n"
        "            .into_unlabelled();",
        "        let before = {\n"
        "            let seen = cx\n"
        "                .cases\n"
        "                .deadlines(cx.case_id)\n"
        "                .await?\n"
        "                .into_iter()\n"
        "                .find(|d| d.name == name)\n"
        "                .map_or(DeadlineState::Pending, |d| d.state);\n"
        "            cx.cases.set_deadline_state(cx.case_id, name, to).await?;\n"
        "            seen\n"
        "        };",
    ),
    "AnAtomicMemberSkipsTheGate": (
        "src/runtime/group.rs",
        "an_atomic_member_is_authorized_before_it_commits",
        "an atomic member commits without passing the gate, so the one mutating "
        "path that *commits* is the only one policy, the manifest and the budget "
        "all miss — and being wrapped in a transaction makes it reliable rather "
        "than authorised",
        "            self.gate(key, &descriptor, true, None).await?;",
        "",
    ),
    "ACappedSweepLooksOrdinary": (
        "src/runtime/sweeper.rs",
        "a_sweep_that_hits_its_cap_says_so",
        "a sweep that handled its full batch reports an ordinary tick, so a "
        "growing backlog and a quiet plane produce the same numbers — and the "
        "one an operator needs to see is the one that looks normal",
        "        if due.len() >= DEADLINE_BATCH {\n            report.saturated.deadlines = true;\n        }",
        "",
    ),
    "ASweepLeavesNoRecord": (
        "src/runtime/sweeper.rs",
        "a_sweep_records_what_it_did_in_a_sealed_run",
        "the sweeper breaches obligations and escalates cases without recording "
        "that it did, so *why is this case escalated* is answerable only from "
        "the resulting state — which cannot tell 'the sweep breached this at "
        "02:00' from 'somebody set it', and no human was there to remember",
        "        match ledger.seal(self.store()).await {\n            SweepRecord::Quiet => {}\n            SweepRecord::Recorded(run) => report.record = Some(run),\n            SweepRecord::EvidenceLost => report.evidence_lost = true,\n        }",
        "        let _ = ledger;",
    ),
    "AQuietSweepOpensARun": (
        "src/runtime/sweeper.rs",
        "a_sweep_records_what_it_did_in_a_sealed_run",
        "a tick that decided nothing still opens and seals a run, so the Merkle "
        "log fills with evidence of inactivity — and a log of nothings is where "
        "the somethings hide",
        "    const fn new() -> Self {\n        Self {\n            run: None,\n            entries: Vec::new(),\n        }\n    }",
        "    fn new() -> Self {\n        Self {\n            run: Some(RunId::generate()),\n            entries: Vec::new(),\n        }\n    }",
    ),
    "ASweepRecordIsNotReachableFromItsCase": (
        "src/runtime/sweeper.rs",
        "a_case_s_history_includes_a_sweep_that_escalated_it",
        "a sweep's records are written without the case they are about, so the "
        "record explaining *why this case is escalated* is unreachable from the "
        "case — which is the only reason for writing it down",
        "        if let Some(case) = case {\n            entry = entry.case(case);\n        }",
        "",
    ),
    "ACaseScanReturnsEveryMatter": (
        "src/store/redb.rs",
        "a_case_s_history_includes_a_sweep_that_escalated_it",
        "the case index is written without the case in its key, so one matter's "
        "history returns another's — the worst possible answer to a question "
        "asked by a regulator",
        "                    if let Some(case) = record.body.case {",
        "                    if false && let Some(case) = record.body.case {",
    ),
    "AQuarantineIsUnfindable": (
        "src/store/redb.rs",
        "a_quarantined_run_can_be_found_afterwards",
        "a concluded run is not indexed by how it ended, so the most serious "
        "conclusion this runtime reaches leaves a status, a log line and a "
        "counter — and no way to ask what is quarantined right now",
        """                        by_outcome
                            .insert((tenant.as_str(), outcome.as_str(), next), key.as_str())
                            .map_err(|e| be(&e))?;""",
        """                        let _ = &outcome;""",
    ),
    "TheGateReadsWhatTheRecordDoesNot": (
        "src/runtime/ctx.rs",
        "the_label_authorization_consulted_is_journaled",
        "authorization consults the outbound label and the journal does not "
        "record it, so the decision cannot be re-derived by anyone who was not "
        "there — an auditor must take the runtime's word that the right label "
        "was presented",
        "                    outbound_label: outbound.cloned(),",
        "                    outbound_label: None,",
    ),
    "InPlaneHandoffIsUngoverned": (
        "src/runtime/ctx.rs",
        "a_specialist_cannot_commission_another_agent",
        "the delegation ceiling is not consulted on the path `cx.commission` "
        "takes, so it governs the A2A peer call and not the function call — a "
        "specialist hands work off inside one process, and A->B->C->A is "
        "reachable with no peer boundary to cross and no allowlist to notice",
        "        self.check_delegation_depth(&effect)?;",
        "",
    ),
    "ADerivedCatalogueRelaxesAGrant": (
        "src/tools/mod.rs",
        "a_catalogue_derived_from_a_manifest_keeps_its_security_fields",
        "a catalogue derived from a manifest drops the grant's protected "
        "fields, so a reviewer's field rules vanish on the way to the runtime — "
        "worse than the duplication it replaced, because the operator believes "
        "they declared something they did not",
        "                protected_fields: grant.protected_fields.clone(),",
        "                protected_fields: Vec::new(),",
    ),
    "CodeAndDeclarationMayDisagree": (
        "src/tools/typed.rs",
        "a_box_that_disagrees_with_its_manifest_is_refused",
        "a binary may implement tools its manifest never granted, so the "
        "reviewed declaration stops describing the agent — and the dispatch "
        "gates cannot catch it, because by then the disagreement has already "
        "shaped what the model was offered",
        "        if problems.is_empty() {",
        "        if true {",
    ),
    "TheCoherenceCheckIsAdvisory": (
        "src/runtime/executor.rs",
        "a_plane_will_not_build_with_tools_its_manifest_does_not_grant",
        "the tool/manifest coherence check exists but nothing runs it, so a "
        "deployer must remember to call it — and a control a caller may forget "
        "is advice that reads like a control, which is the one thing I12 says a "
        "declared control may never be",
        "        self.settle_toolbox()?;\n        self.check_catalogue_not_laxer_than_grants()",
        "        Ok(())",
    ),
    "OnlyTheFirstAgentIsChecked": (
        "src/runtime/executor.rs",
        "every_agent_on_a_plane_is_checked_against_the_tools",
        "coherence is checked against the first declared agent and no other, so "
        "a plane hosting several agents enforces one declaration and ignores the "
        "rest — and the ignored ones are exactly where a second team's manifest "
        "drifts unnoticed",
        "            tools\n                .check_against(manifest, &remote_servers)",
        "            if declared > 1 {\n                continue;\n            }\n"
        "            tools\n                .check_against(manifest, &remote_servers)",
    ),
    "EmbeddingIsComputedNotObserved": (
        "src/runtime/ctx.rs",
        "a_replayed_run_reads_its_embedding_back_rather_than_asking_again",
        "the embedding service is called directly instead of through the effect "
        "protocol, so a replay asks again and gets different floats — and since "
        "the query vector is in the semantic-retrieval effect key, the run "
        "quarantines itself with nothing on the record explaining why",
        "        self.sink(\n            crate::runtime::effects::Embed {",
        "        if true {\n            let v = embedder.embed(&plain).await"
        ".map_err(StepError::Store)?;\n            return Ok(crate::core::Tainted"
        "::trusted(v));\n        }\n"
        "        self.sink(\n            crate::runtime::effects::Embed {",
    ),
    "MemoryFormsBeforeTheHumanDecides": (
        "src/runtime/declarative.rs",
        "a_refused_answer_is_not_written_into_memory",
        "an answer is written into durable memory before oversight decides, so "
        "a reviewer's refusal fails the run while the refused answer stays a "
        "standing fact the next run reads as established",
        "        if let Some(spec) = oversight.filter(Proposal::gates_the_answer) {",
        "        self.form_answer(cx, formation, formed_source.clone(), model)\n"
        "            .await?;\n"
        "        if let Some(spec) = oversight.filter(Proposal::gates_the_answer) {",
    ),
    "ToolCallingSkipsOversight": (
        "src/runtime/declarative.rs",
        "a_tool_calling_agent_still_asks_a_human",
        "a tool-calling agent returns its answer without asking anyone, so a "
        "declared `oversight.approval: required` is a control the runtime "
        "silently does not apply — on the execution kind that has already "
        "touched the world by the time it answers",
        "                return self\n                    .settle(",
        "                if true {\n                    return Ok(Outcome::done(answer));\n                }\n"
        "                return self\n                    .settle(",
    ),
    "OversightNeverRegistersItsObligation": (
        "src/runtime/declarative.rs",
        "a_refused_answer_is_not_written_into_memory",
        "the obligation bounding an oversight wait is never registered, so a "
        "declarative agent — which writes no code and therefore cannot register "
        "it either — fails outright in the one configuration the declarative "
        "tier exists for",
        "            cx.deadline(spec.deadline.name.clone(), &spec.deadline.spec(), None)\n                .await?;",
        "",
    ),
    "TheMediaBuilderAndItsDriverDrift": (
        "src/media/mod.rs",
        "the_bedrock_driver_accepts_the_bedrock_builders_own_block",
        "the Bedrock media block builder emits a key its own driver does not "
        "read, so multimodal dispatch to that provider silently stops working "
        "while both sides' hand-written tests still pass",
        "    pub fn bedrock_image(&self) -> Value {\n        json!({\n            \"type\": \"image\",\n            \"media_type\": self.media_type,",
        "    pub fn bedrock_image(&self) -> Value {\n        json!({\n            \"type\": \"image\",\n            \"mime_type\": self.media_type,",
    ),
    "AnObligationCannotBeWithdrawn": (
        "src/runtime/ctx.rs",
        "a_cancelled_obligation_no_longer_blocks_closing_the_case",
        "withdrawing an obligation does nothing, so a case whose matter went "
        "away can never be closed — the obligation that exists to stop a "
        "premature close instead makes the close impossible",
        "        self.transition_deadline(name, DeadlineState::Cancelled)\n            .await\n    }",
        "        let _ = name;\n        Ok(())\n    }",
    ),
    "RecencyOutranksTrustInRecall": (
        "src/store/redb_memory.rs",
        "newer_untrusted_memories_cannot_evict_a_trusted_one",
        "recall truncates by recency alone, so anything able to write an "
        "untrusted memory writes `limit` of them and evicts every trusted one "
        "from the window — silently, because each item is honestly labelled and "
        "the caller gets exactly the number it asked for",
        "                if rank == 0 {\n                    trusted.push(item);\n                } else {\n                    untrusted.push(item);\n                }",
        "                trusted.push(item);",
    ),
    "AHaltDoesNotStopAnUnlimitedTenant": (
        "src/runtime/executor.rs",
        "a_halt_refuses_new_runs_on_every_instance_and_names_the_reason",
        "the emergency stop is checked after the no-ceilings shortcut, so a "
        "tenant with no quotas configured cannot be halted at all — which is "
        "the tenant an operator is most likely to need to stop",
        "        match quotas.halted().await {",
        "        if self.quota.is_unlimited() {\n            return Ok(());\n        }\n        match quotas.halted().await {",
    ),
    "AHighImpactCallSkipsItsApproval": (
        "src/runtime/declarative.rs",
        "a_call_needing_approval_does_not_happen_until_it_is_approved",
        "a tool grant asking for a human is dispatched without asking, so the "
        "mutation happens and the only review left is of the answer — which "
        "arrives after the money moved",
        """                // not the answer they will produce.
                if grant.requires_approval {""",
        """                // not the answer they will produce.
                if false && grant.requires_approval {""",
    ),
    "APlannedCallSkipsItsApproval": (
        "src/runtime/declarative.rs",
        "a_planned_step_waits_for_its_approval",
        "a planned step whose grant asks for a human dispatches without asking "
        "— the plan was reviewed by nobody and the call by nobody either",
        """                    // report it to.
                    if grant.requires_approval {""",
        """                    // report it to.
                    if false && grant.requires_approval {""",
    ),
    "TheAuditIsSilentAboutReleases": (
        "src/audit.rs",
        "the_audit_reports_who_raised_a_label_and_on_what_evidence",
        "the offline audit reports no label-raising decision, so an auditor "
        "verifies that history is intact while never seeing the only "
        "discretionary act in it — who decided untrusted data could be treated "
        "as trusted, toward what destination, on what evidence",
        "        releases.extend(releases_in(run, &records));",
        "",
    ),
    "AReleaseValidatorThatAcceptsAnything": (
        "src/core/label.rs",
        "a_release_with_no_usable_evidence_is_refused",
        "the gate on a request to raise a label accepts every request, so an "
        "evidence-free, destination-free, no-op release is journaled as a "
        "decision — the one operation that turns untrusted data into trusted "
        "data, unchecked",
        "        if !self.scope.trust && self.scope.sensitivity.is_none() {",
        "        return Ok(());\n        #[allow(unreachable_code)]\n        if !self.scope.trust && self.scope.sensitivity.is_none() {",
    ),
    "AnUngovernedSkillSatisfiesADeclaration": (
        "src/runtime/executor.rs",
        "a_coded_skill_reads_its_prompt_from_the_digested_manifest",
        "an agent's declaration is checked against every skill on the plane "
        "rather than its own, so a skill wired with `RuntimeBuilder::skill` "
        "satisfies the check while being governed by no manifest — it runs "
        "under the plane's default budget and no manifest gate, and the plane "
        "builds cleanly",
        "                mine.extend(s.descriptor().provides);",
        "",
    ),
    "ACaseWriteReachesPolicyAsARead": (
        "src/runtime/effects.rs",
        "policy_sees_a_case_read_as_a_read_and_a_case_write_as_a_mutation",
        "a versioned case-state write declares that it does not mutate, so it "
        "reaches the policy engine as a read and every rule keyed on "
        "`context.mutates` silently stops applying to it — including the taint "
        "gate published on the security page",
        "    /// It changes state other runs can observe. That is what mutating means.\n    fn mutates(&self) -> bool {\n        true\n    }",
        "    fn mutates(&self) -> bool {\n        false\n    }",
    ),
    "ADeadlineTransitionReadsAnotherDeadline": (
        "src/runtime/effects.rs",
        "a_deadline_transition_records_the_state_that_deadline_moved_from",
        "a deadline transition looks up some other obligation's state and "
        "journals that as the one it moved from, so the record says a deadline "
        "moved from a state it was never in",
        "            .find(|d| d.name == self.name)",
        "            .find(|d| d.name != self.name)",
    ),
    "ACaseStatusChangeReachesPolicyAsARead": (
        "src/runtime/effects.rs",
        "policy_sees_a_case_read_as_a_read_and_a_case_write_as_a_mutation",
        "closing a case reaches the policy engine as a read, so a rule that "
        "gates mutations of shared state does not apply to the one that ends "
        "the matter",
        "    /// It changes state other runs observe.\n    fn mutates(&self) -> bool {\n        true\n    }",
        "    fn mutates(&self) -> bool {\n        false\n    }",
    ),
    "McpDispatchesAnyServersTool": (
        "src/tools/mcp.rs",
        "a_tool_from_another_server_is_refused_rather_than_run_here",
        "an MCP client runs a tool id belonging to a different server against "
        "its own connection, so a plane granting one server's tool and wiring "
        "another's gets a successful answer from the wrong server under the "
        "first one's operator safety",
        "        if tool.server != self.server {",
        "        if false && tool.server != self.server {",
    ),
    "TheRouterIgnoresTheServer": (
        "src/tools/mod.rs",
        "a_router_sends_each_server_to_its_own_transport",
        "the router hands every tool id to whichever transport it holds first, "
        "so the server component that exists to tell two servers' identically "
        "named tools apart decides nothing",
        "        let Some(client) = self.routes.get(&tool.server) else {",
        "        let Some(client) = self.routes.values().next() else {",
    ),
    "TwoCataloguesSilentlyMerge": (
        "src/runtime/executor.rs",
        "a_plane_may_not_state_its_catalogue_and_derive_it",
        "a plane that wires tools twice takes one silently — the derived "
        "catalogue replaces the operator's explicit one, so the plane runs under "
        "grants nobody chose and nothing says which won",
        "        if self.tools.is_some() {",
        "        if false {",
    ),
    "AToolboxNeedsNoDeclaration": (
        "src/runtime/executor.rs",
        "tools_wired_to_a_plane_with_no_declaration_are_refused",
        "tools may be wired to a plane with no declared agent, so the coherence "
        "check passes by having nothing to compare against — enforcement that is "
        "satisfied by the absence of the thing it enforces against",
        "        if declared == 0 {",
        "        if false {",
    ),
    "MetricsLeakTheTenantByDefault": (
        "src/runtime/metrics.rs",
        "metrics_carry_no_tenant_unless_asked",
        "a plane puts its tenant on every metric without being asked, so "
        "customer names reach whatever backend the deployment happens to point "
        "at — usually the least protected system it runs",
        "    #[default]\n    Omitted,",
        "    Omitted,\n    #[default]",
    ),
    "AMemoryIsTrustedByWhatItSays": (
        "src/memory/mod.rs",
        "a_memory_cannot_promote_itself_by_what_it_says",
        "a recalled memory's trust is read from its content, so text asserting "
        "its own reliability is believed — one poisoned write becomes a standing "
        "instruction on every later session",
        "        let mut label = if self.trust == Trust::Trusted {",
        "        let mut label = if self.trust == Trust::Trusted\n"
        "            || self.content.get(\"trusted\") == Some(&serde_json::Value::Bool(true))\n"
        "        {",
    ),
    "ARecalledMemoryDropsItsProvenance": (
        "src/memory/mod.rs",
        "a_memory_cannot_promote_itself_by_what_it_says",
        "a recalled memory arrives without the sources it declared, so nothing "
        "downstream can require a named source and a protected field has "
        "nothing to check",
        "        for source in &self.provenance {\n            label.provenance.insert(source.clone());\n        }",
        "",
    ),
    "ARecallIsNotAnEffect": (
        "src/runtime/ctx.rs",
        "a_replayed_recall_does_not_search_again",
        "a recall queries the store directly instead of through the effect "
        "protocol, so a replayed run retrieves whatever the corpus holds now and "
        "produces a history that disagrees with itself",
        "        let selected = self\n"
        "            .effect(crate::runtime::effects::RecallMemory {\n"
        "                memories: Arc::clone(&memories),\n"
        "                query,\n"
        "            })\n"
        "            .await?\n"
        "            .into_unlabelled();",
        "        let selected: Vec<crate::memory::Selected> = memories\n"
        "            .recall(&query)\n"
        "            .await\n"
        "            .map_err(StepError::Store)?\n"
        "            .iter()\n"
        "            .map(|i| crate::memory::Selected {\n"
        "                id: i.id.clone(),\n"
        "                version: i.version,\n"
        "                digest: i.digest(),\n"
        "            })\n"
        "            .collect();",
    ),
    "AForgottenMemoryLeavesItsHistory": (
        "src/store/redb_memory.rs",
        "forgetting_one_memory_reaches_all_its_versions_and_spares_the_rest",
        "forgetting removes only the current version, so an erasure is reported "
        "discharged while every superseded version is still readable by id",
        "                for version in doomed {\n"
        "                    items\n"
        "                        .remove((tenant.as_str(), id.as_str(), version))\n"
        "                        .map_err(|e| be(&e))?;\n"
        "                }",
        "                if let Some(version) = doomed.last() {\n"
        "                    items\n"
        "                        .remove((tenant.as_str(), id.as_str(), *version))\n"
        "                        .map_err(|e| be(&e))?;\n"
        "                }",
    ),
    "OneTenantRecallsAnothersMemories": (
        "src/store/redb_memory.rs",
        "one_tenants_memories_are_not_another_tenants",
        "reading a memory by id drops the tenant, so one tenant reads another's "
        "memory while holding nothing but an id — and a memory is read into a "
        "context window as established fact",
        "            let Some(raw) = items\n"
        "                .get((tenant.as_str(), id.as_str(), version))\n"
        "                .map_err(|e| be(&e))?",
        "            let Some(raw) = items\n"
        "                .range((\"\", id.as_str(), version)..=(MAX_STR, id.as_str(), version))\n"
        "                .map_err(|e| be(&e))?\n"
        "                .next()\n"
        "                .transpose()\n"
        "                .map_err(|e| be(&e))?\n"
        "                .map(|(_, v)| v)",
    ),
    "OpenAiNestsItsToolDeclarations": (
        "src/model/openai.rs",
        "a_declared_tool_is_rendered_in_openais_shape",
        "tool declarations are nested under `function`, which is the Chat "
        "Completions shape — Responses answers `Missing required parameter: "
        "tools[0].name` and the call never reaches a model",
        "                        json!({\n"
        "                            \"type\": \"function\",\n"
        "                            \"name\": t.name,\n"
        "                            \"description\": t.description,\n"
        "                            \"parameters\": t.parameters,\n"
        "                            \"strict\": strict,\n"
        "                        })",
        "                        json!({\n"
        "                            \"type\": \"function\",\n"
        "                            \"function\": {\n"
        "                                \"name\": t.name,\n"
        "                                \"description\": t.description,\n"
        "                                \"parameters\": t.parameters,\n"
        "                                \"strict\": strict,\n"
        "                            }\n"
        "                        })",
    ),
    "AToolCallReadsAsAnEmptyAnswer": (
        "src/model/openai.rs",
        "a_tool_call_with_no_text_is_a_usable_answer",
        "a tool call with no text is rejected as an empty answer, so every "
        "declared-tool loop against OpenAI fails on a response that worked — and "
        "is billed for it",
        "        if text.is_empty() && calls.is_empty() && !truncated && !emulating {",
        "        if text.is_empty() && !truncated && !emulating {",
    ),
    "AWebhookHostIsMatchedBySuffix": (
        "src/push/mod.rs",
        "a_webhook_host_must_be_granted",
        "webhook hosts are matched by suffix, so `hooks.acme.example.evil.example` "
        "satisfies a grant for `hooks.acme.example` and the allowlist is bypassed "
        "by registering a domain",
        "        if !self.hosts.contains(&host) {",
        "        if !self.hosts.iter().any(|h| host.ends_with(h.as_str())) {",
    ),
    "AWebhookMayBePlaintext": (
        "src/push/mod.rs",
        "a_webhook_must_be_https",
        "a webhook may be plain http, so a payload describing somebody's task "
        "crosses the network in clear to an address the recipient chose",
        "        if parsed.scheme() != \"https\" {\n            return Err(PushError::NotHttps);\n        }",
        "",
    ),
    "DeliveryTrustsTheRegistrationTimeCheck": (
        "src/push/mod.rs",
        "a_revoked_host_stops_receiving_notifications",
        "the grant is checked only when a webhook is registered, so a host "
        "removed from the allowlist keeps receiving notifications for every task "
        "registered while it was still granted",
        "        self.policy.check(&config.url)?;",
        "",
    ),
    "AWebhookMayResolveInward": (
        "src/push/mod.rs",
        "a_webhook_resolving_to_a_private_address_is_refused",
        "resolved webhook addresses are not checked, so a granted hostname "
        "pointing at loopback or a metadata service is connected to",
        "        let addrs = crate::netguard::all_public(&host, resolved)\n            .map_err(|e| PushError::Unroutable(e.to_string()))?;",
        "        let addrs: Vec<std::net::SocketAddr> = resolved.collect();",
    ),
    "AWebhookTokenIsEchoedBack": (
        "src/push/mod.rs",
        "a_configuration_read_back_does_not_carry_its_token",
        "a configuration read back carries its token, so a caller learns the "
        "correlation secret for somebody else's webhook",
        "            \"url\": self.url,\n            \"authentication\": self.authentication.as_ref().map(|auth| serde_json::json!({",
        "            \"url\": self.url,\n            \"token\": self.token.as_ref().map(crate::core::Secret::expose),\n            \"authentication\": self.authentication.as_ref().map(|auth| serde_json::json!({",
    ),
    "OneTenantReadsAnothersWebhooks": (
        "src/store/redb_push.rs",
        "one_tenants_webhooks_are_not_another_tenants",
        "webhook registrations drop the tenant from their key, so any tenant "
        "holding a valid task id reads another's destination and bearer token",
        "                .get((tenant.as_str(), task_key.as_str(), id.as_str()))",
        "                .get((\"\", task_key.as_str(), id.as_str()))",
    ),
    "AnUnsignedCardPassesVerification": (
        "src/peers/discovery.rs",
        "discovery_refuses_an_unsigned_card_when_verification_is_required",
        "verification is skipped when a card carries no signature, so an "
        "attacker downgrades it by removing the signature rather than forging one",
        "        if let Some(verifier) = &self.verifier {",
        "        if let Some(verifier) = &self.verifier\n            && !card.signatures.is_empty()\n        {",
    ),
    "InterfaceSelectionIgnoresTheTenant": (
        "src/peers/discovery.rs",
        "a_client_discovers_verifies_and_calls_a_tenant_scoped_agent",
        "the endpoint built from a card drops the interface's tenant, so a "
        "client can only ever reach an agent serving the default tenant",
        "        Ok(match &iface.tenant {\n            Some(t) => endpoint.for_tenant(t.clone()),\n            None => endpoint,\n        })",
        "        Ok(endpoint)",
    ),
    "InterfaceSelectionIgnoresTheVersion": (
        "src/peers/discovery.rs",
        "an_interface_is_selected_by_binding_and_version",
        "interface selection ignores the protocol version, so a client picks an "
        "endpoint speaking a protocol it does not",
        "        self.supported_interfaces.iter().find(|i| {\n"
        "            i.protocol_binding == binding\n"
        "                && super::protocol_major_minor(&i.protocol_version) == Some(want)\n"
        "        })",
        "        self.supported_interfaces\n"
        "            .iter()\n"
        "            .find(|i| i.protocol_binding == binding)",
    ),
    "ACardSignatureCoversItself": (
        "src/peers/card_sig.rs",
        "a_signed_card_verifies_and_a_changed_one_does_not",
        "the signed payload keeps the signatures field, so signing twice signs a "
        "different document each time and no verifier can reproduce the bytes",
        "    if let Some(obj) = value.as_object_mut() {\n        obj.remove(\"signatures\");\n    }",
        "",
    ),
    "ACardVerifierBelievesTheHeader": (
        "src/peers/card_sig.rs",
        "a_card_naming_its_own_algorithm_is_refused",
        "the verifier takes the algorithm from the card it is checking, so a "
        "card naming `none` is accepted without a key",
        "            if alg != ALG {\n                wrong_alg = Some(alg.to_owned());\n                continue;\n            }",
        "",
    ),
    "ACardIsSignedOverItsHash": (
        "src/peers/card_sig.rs",
        "a_signed_card_verifies_and_a_changed_one_does_not",
        "the signature is made over a hash of the JWS signing input rather than "
        "the input itself, which verifies here and nowhere else — every "
        "conforming verifier rejects it",
        "        let signature = B64.encode(signer.sign_bytes(&input));",
        "        let signature =\n            B64.encode(signer.sign_bytes(crate::core::Digest::of(&input).as_bytes()));",
    ),
    "CanonicalOrderIsUtf8NotUtf16": (
        "src/core/canon.rs",
        "keys_sort_by_utf16_code_unit_not_utf8_byte",
        "object keys sort by UTF-8 byte order instead of RFC 8785's UTF-16 code "
        "unit order, so canonical bytes are rejected by any conforming verifier "
        "while every ASCII test still passes",
        "            keys.sort_unstable_by(|a, b| utf16_order(a, b));",
        "            keys.sort_unstable();",
    ),
    "AStreamNeverClosesOnAFinishedTask": (
        "src/api/a2a_stream.rs",
        "a_stream_on_an_already_finished_task_ends",
        "a stream opened on an already-finished task polls forever: the record "
        "that ended the run was consumed before the subscriber existed, so the "
        "loop never sees it — which is every client reconnecting after a drop",
        "        if already_over {\n            return;\n        }",
        "",
    ),
    "AStreamRunsPastItsTerminalState": (
        "src/api/a2a_stream.rs",
        "a_streaming_send_opens_with_the_task_and_closes_when_it_finishes",
        "the stream does not close when the task reaches a terminal state, so a "
        "client waits on a connection that will never say anything again",
        "            if done {\n                return;\n            }",
        "",
    ),
    "AStreamDoesNotOpenWithTheTask": (
        "src/api/a2a_stream.rs",
        "a_streaming_send_opens_with_the_task_and_closes_when_it_finishes",
        "the stream omits the opening Task, so a subscriber that was not present "
        "when the run started cannot learn its current state",
        "        yield Ok(stream_response(&id, &json!({ \"task\": first })));",
        "        let _ = &first;",
    ),
    "AZeroCeilingAdmitsEverything": (
        "src/store/redb_quota.rs",
        "redb_satisfies_the_quota_store_contract",
        "the concurrency ceiling is compared inside the counting loop, so a "
        "ceiling of zero never compares anything and admits every run — the "
        "value an operator sets to stop a tenant dead",
        "                        if n >= limit {\n                            refused = Some(n);\n                        }",
        "                        if n > limit {\n                            refused = Some(n);\n                        }",
    ),
    "AQuotaCeilingIsSharedAcrossTenants": (
        "src/store/redb_quota.rs",
        "one_tenants_ceiling_does_not_throttle_another",
        "the running-run count spans every tenant, so one busy tenant throttles "
        "everybody — a shared ceiling wearing a per-tenant name",
        "                            .range((tenant.as_str(), \"\")..=(tenant.as_str(), MAX_STR))\n"
        "                            .map_err(|e| be(&e))?\n"
        "                            .take(limit as usize)",
        "                            .range((\"\", \"\")..=(MAX_STR, MAX_STR))\n"
        "                            .map_err(|e| be(&e))?\n"
        "                            .take(limit as usize)",
    ),
    "AnAdmittedRunSkipsItsQuota": (
        "src/runtime/executor.rs",
        "a_refused_run_writes_nothing",
        "admission never consults the tenant's ceiling, so a caller that can "
        "start runs can start a thousand of them, each within its own budget",
        "        self.check_quota(run).await?;",
        "",
    ),
    "AFinishedRunKeepsItsSlot": (
        "src/runtime/executor.rs",
        "a_finished_run_frees_its_slot",
        "a run never gives its concurrency slot back, so a ceiling of N permits "
        "N runs per process lifetime rather than N at a time",
        "        self.settle_quota(run, spend).await;",
        "",
    ),
    "ReplayReChecksTheQuota": (
        "src/runtime/executor.rs",
        "replay_does_not_consult_the_quota",
        "replay consults the tenant's live ceiling, so re-reading a run that "
        "genuinely happened can refuse — history says something different on "
        "the second reading",
        "        // Strict verification never writes, so it holds no lease to renew.\n"
        "        let _heartbeat = (mode != Mode::Strict).then(|| self.heartbeat(run, epoch));",
        "        self.check_quota(run).await?;\n"
        "        // Strict verification never writes, so it holds no lease to renew.\n"
        "        let _heartbeat = (mode != Mode::Strict).then(|| self.heartbeat(run, epoch));",
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
        "        if claimed_version == crate::peers::protocol_major_minor(crate::peers::PROTOCOL_VERSION)\n"
        "            && claimed_version.is_some()\n"
        "        {",
        "        if claimed.is_empty()\n"
        "            || claimed_version == crate::peers::protocol_major_minor(crate::peers::PROTOCOL_VERSION)\n"
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
    "ADeclarativeAgentAnswersToTwoNames": (
        "src/manifest/mod.rs",
        "a_declarative_agent_provides_exactly_one_capability",
        "a declarative agent accepts several capabilities — a distinction "
        "nothing executes, refused later at build under the agent's own name",
        "        if self.spec.execution.is_some() && self.spec.capabilities.provides.len() > 1 {",
        "        if false {",
    ),
    "GeminiFileUriReachesTheProvider": (
        "src/model/mod.rs",
        "gemini_refuses_a_provider_side_file_uri",
        "a Gemini `fileData.fileUri` is not recognised as a provider-side fetch, "
        "so Google dereferences a caller-named URL from its own network — "
        "outside this plane's egress allowlist, DNS pinning, size and type "
        "ceilings, and journal, which is the whole of what governed media replaces",
        '            for key in ["fileData", "file_data"] {',
        '            for key in [] as [&str; 0] {',
    ),
    "GeminiStreamsWithoutAltSse": (
        "src/model/gemini.rs",
        "gemini_streams_reassemble_and_keep_the_signature",
        "the streaming path drops `alt=sse`, so Gemini answers with a chunked "
        "JSON array the SSE decoder reads as no events at all — every streamed "
        "call reported as never having generated, and retried forever against a "
        "provider that answered correctly every time",
        '            "streamGenerateContent?alt=sse"',
        '            "streamGenerateContent"',
    ),
    "GeminiStreamMergesEverySignedPart": (
        "src/model/gemini_stream.rs",
        "gemini_streams_reassemble_and_keep_the_signature",
        "reassembly merges every part as text rather than only the text-only "
        "ones, so a `thoughtSignature` arriving on a function-call part is "
        "flattened away and the next turn is a 400 — the failure appears on the "
        "second tool turn, never the first",
        "        .is_some_and(|object| object.len() == 1 && object.contains_key(\"text\"))",
        "        .is_some_and(|object| object.contains_key(\"text\"))",
    ),
    "GeminiSafetyIsNotEffectIdentity": (
        "src/model/gemini.rs",
        "gemini_passes_the_deployments_safety_thresholds_and_puts_them_in_identity",
        "the declared safety thresholds stay out of the request profile, so "
        "loosening one to BLOCK_NONE between a run and its replay is a silent "
        "change in what governed the call rather than divergence",
        '            "safety": (!self.safety.is_empty()).then(|| self.safety.profile()),',
        '            "safety": Value::Null,',
    ),
    "GeminiRebuildsTheModelsTurn": (
        "src/model/gemini.rs",
        "gemini_returns_the_models_turn_verbatim_including_its_thought_signature",
        "the model's turn is rebuilt from the function calls this driver parsed "
        "instead of being carried verbatim, so the `thoughtSignature` Gemini 3 "
        "requires back is dropped — a 400 on the second tool turn, and the exact "
        "bug the ecosystem worked around by smuggling signatures into tool-call ids",
        "            Some(state) if state.provider == PROVIDER => array.push(state.state.clone()),",
        "            Some(state) if state.provider == PROVIDER => {\n"
        "                let _ = &state;\n"
        "                array.push(json!({ \"role\": \"model\", \"parts\": [] }));\n"
        "            }",
    ),
    "GeminiThinkingTokensAreFree": (
        "src/model/gemini.rs",
        "gemini_maps_the_request_shape_usage_and_the_system_instruction",
        "thinking tokens are dropped from the output count, so a reasoning-heavy "
        "run under-reports most of its bill — Gemini reports them beside the "
        "candidate count rather than inside it, so omitting them is silent",
        '            output_tokens: count("candidatesTokenCount") + count("thoughtsTokenCount"),',
        '            output_tokens: count("candidatesTokenCount"),',
    ),
    "GeminiEffortIsCollapsedNotRefused": (
        "src/model/gemini.rs",
        "gemini_maps_the_thinking_levels_it_has_and_refuses_the_rest",
        "an effort Gemini cannot express is folded into the nearest level it "
        "can, so a run declaring `max` is answered at `high` — a substitution on "
        "a digest-covered value that exists to say what governed the call",
        "            ReasoningEffort::None | ReasoningEffort::XHigh | ReasoningEffort::Max => {",
        '            ReasoningEffort::XHigh | ReasoningEffort::Max => "high",\n'
        "            ReasoningEffort::None => {",
    ),
    "TheStreamedToolCallLosesItsExtension": (
        "src/model/chat_completions_stream.rs",
        "chat_completions_streaming_carries_an_unknown_tool_call_field_too",
        "reassembling a stream drops every tool-call field this driver does not "
        "itself understand, so a `thought_signature` is lost on the **default** "
        "path while the buffered one keeps it — a fix that holds exactly where "
        "nobody runs it",
        '                if !matches!(key.as_str(), "index" | "id" | "type" | "function") {',
        '                if false {',
    ),
    "TheAssistantTurnIsRebuiltNotCarried": (
        "src/model/chat_completions.rs",
        "chat_completions_carries_an_unknown_tool_call_field_into_the_continuation",
        "the continuation is rebuilt from the fields this driver understands "
        "rather than carried verbatim, so anything an OpenAI-compatible server "
        "attached is dropped — including the `thought_signature` Gemini 3 "
        "requires back and rejects the turn without",
        "            let mut message = choice.message.raw.clone();",
        "            let mut message = Value::Null;",
    ),
    "NovaEffortIsCollapsedNotRefused": (
        "src/model/bedrock.rs",
        "nova_refuses_an_effort_it_has_no_counterpart_for",
        "an effort Nova cannot express is folded into the nearest level it can, "
        "so a run declaring `max` is answered at `high` — a substitution on a "
        "digest-covered value whose whole purpose is to describe what governed "
        "the call, and which nothing downstream can see",
        '                    E::Minimal | E::XHigh | E::Max => {',
        '                    E::Minimal => "low",\n'
        '                    E::XHigh | E::Max => "high",\n'
        '                    #[allow(unreachable_patterns)]\n'
        '                    _ => {',
    ),
    "NovaReasoningNeverReachesTheWire": (
        "src/model/bedrock.rs",
        "nova_reasoning_effort_is_rendered_the_way_aws_documents_it",
        "a declared reasoning effort is accepted and then dropped, so Bedrock "
        "answers without extended thinking while the journal records the effort "
        "as applied — the manifest's control becoming advisory, silently",
        '                Ok(Some(document_from_json(&json!({\n'
        '                    "reasoningConfig": { "type": "enabled", "maxReasoningEffort": level },\n'
        "                }))))",
        "                {\n"
        "                    let _ = level;\n"
        "                    Ok(None)\n"
        "                }",
    ),
    "ASealedRunMayResume": (
        "src/runtime/executor.rs",
        "a_sealing_conclusion_is_never_resumable",
        "a conclusion that froze the journal and published a Merkle leaf is "
        "treated as resumable, so its resume grows the history past the leaf "
        "every later checkpoint attests — the failure the 'a conclusion is not "
        "a closure' work removed for `failed`, reachable again the moment the "
        "sealing set and the resumable set disagree",
        '        "quarantined" => Some(RunStatus::Quarantined(\n'
        '            "recorded as quarantined; a human must resolve it before it can run again".into(),\n'
        "        )),",
        '        "quarantined" => None,',
    ),
    "TheLiveAnswerHasItsOwnStateMapping": (
        "src/api/a2a.rs",
        "the_live_answer_and_the_read_back_answer_are_the_same_state",
        "the immediate SendMessage response derives its A2A state from its own "
        "match instead of the one every read-back path uses, so the same task "
        "reports one state to the client holding the response and another to the "
        "client that polled for it",
        "        RunStatus::Succeeded => TaskState::Completed,",
        "        RunStatus::Succeeded => TaskState::Working,",
    ),
    "TheSealedAnswerHasItsOwnStateMapping": (
        "src/api/a2a.rs",
        "a_live_status_and_its_sealed_outcome_agree",
        "the read-back paths derive their A2A state from a string match that has "
        "drifted from the enum match the immediate response uses, so the same "
        "task reports one state to the client that polled and another to the "
        "client holding the response",
        '        "cancelled" => TaskState::Canceled,',
        '        "cancelled" => TaskState::Failed,',
    ),
    "TwoSpellingsOfTerminal": (
        "src/api/a2a.rs",
        "subscribing_to_a_finished_task_is_unsupported",
        "the SubscribeToTask refusal keeps its own list of terminal states "
        "instead of asking `closes`, so the rule deciding whether a stream ends "
        "and the rule deciding whether a subscription is refused can disagree",
        "    if req.method == method::SUBSCRIBE && super::a2a_stream::closes(task.status.state) {",
        "    if req.method == method::SUBSCRIBE\n"
        "        && matches!(task.status.state, TaskState::Canceled | TaskState::Rejected)\n"
        "    {",
    ),
    "A2aReplyNeverApplies": (
        "src/api/a2a.rs",
        "a_skill_declares_several_artifacts_and_they_arrive_as_several",
        "a skill's declared reply is never honoured, so `A2aReply` silently "
        "stops shaping the answer — and every test that existed asserted a "
        "*refusal* to honour one, so the whole feature could go missing with a "
        "green suite",
        "        if output.label().is_untrusted() {",
        "        if true {",
    ),
    "ATaskProposalIsNotSealed": (
        "src/keyring/tasks.rs",
        "a_task_proposal_is_sealed_in_the_worklist",
        "a task proposal is written to the worklist in the clear, so the exact "
        "amount and account a reviewer approves stay readable in the copy an "
        "operator queries",
        "        sealed.justification.proposed_action = payload::wrap(&envelope);",
        "        let _ = &envelope;",
    ),
    "AKeyRingSealsOnlyBlobs": (
        "src/runtime/executor.rs",
        "configuring_a_key_ring_seals_every_store",
        "a configured key ring seals blob payloads and leaves the journal, "
        "case store, worklist and event buffer in the clear — a plane that "
        "reads as encrypted and is one fifth encrypted",
        "        self.seal_stores();",
        "",
    ),
    "AnEventPayloadIsNotSealed": (
        "src/keyring/events.rs",
        "a_buffered_event_payload_is_sealed_and_erasable_on_its_own",
        "a buffered event payload is written in the clear, so a counterparty's "
        "message stays readable in the dead-letter list that keeps it "
        "indefinitely",
        "        sealed.payload = payload::wrap(&envelope);",
        "        let _ = &envelope;",
    ),
    "SealedCasesUseADifferentScope": (
        "src/keyring/cases.rs",
        "one_erasure_reaches_every_copy_and_the_chain_still_verifies",
        "case state is sealed under a scope `erase_case` does not destroy, so "
        "an erasure reports success and leaves the case's own state readable "
        "— the two-mechanisms-disagreeing failure, silent by construction",
        "        super::scope(&self.tenant, &case.to_string())",
        "        super::scope(&self.tenant, &format!(\"cases/{case}\"))",
    ),
    "CaseStateIsNotSealed": (
        "src/keyring/cases.rs",
        "case_state_is_sealed_and_erasing_the_case_takes_it",
        "case state is written to the case store in the clear, so the copy an "
        "operator reads first survives an erasure that destroyed the journal's",
        """        self.inner
            .put_state(case, expected, payload::wrap(&envelope))
            .await""",
        """        let _ = &envelope;
        self.inner.put_state(case, expected, state).await""",
    ),
    "TheJournalIsNotSealed": (
        "src/keyring/journal.rs",
        "a_sealed_journal_hides_payloads_and_still_verifies_without_keys",
        "a sealed journal writes its payloads in the clear, so the prompts and "
        "arguments a deployment sealed reach the store readable",
        "                *field = payload::wrap(&envelope);",
        "                let _ = &envelope;",
    ),
    "ADestroyedKeyStillOpens": (
        "src/journal/payload.rs",
        "erasing_the_key_leaves_the_chain_verifiable",
        "a sealed payload is not recognised as sealed, so an erased record "
        "reads as though its key still existed",
        """    value
        .as_object()
        .is_some_and(|o| o.len() == 1 && o.get(SEALED).is_some_and(serde_json::Value::is_string))""",
        """    let _ = value;
    false""",
    ),
    "TheJournalCeilingIsAdvisory": (
        "src/runtime/ctx.rs",
        "data_above_the_journal_ceiling_is_refused_before_it_is_recorded",
        "a declared journal ceiling does not refuse, so data the deployment "
        "said must stay erasable is written into an append-only chain that "
        "cannot forget it",
        """            && label.sensitivity > journal_ceiling
        {""",
        """            && label.sensitivity > journal_ceiling
            && false
        {""",
    ),
    "BreakGlassLeavesNoRecord": (
        "src/runtime/executor.rs",
        "break_glass_is_recorded_in_the_crossed_tenants_journal",
        "an operator crosses the tenant boundary and the crossing is not "
        "sealed into that tenant's journal, so the designed exception is "
        "indistinguishable from the breach it is meant to be",
        """        self.store
            .seal(run, epoch, BREAK_GLASS_OUTCOME)
            .await
            .map_err(RuntimeError::from_store)?;""",
        """        let _ = BREAK_GLASS_OUTCOME;""",
    ),
    "AnUnexplainedCrossingIsRecorded": (
        "src/runtime/executor.rs",
        "break_glass_without_a_reason_is_refused",
        "a break-glass with no stated reason is accepted, recording an "
        "exception that explains nothing",
        "        if reason.trim().is_empty() {",
        "        if false {",
    ),
    "AmbientMutationBesideAGroup": (
        "src/runtime/ctx.rs",
        "a_mutating_effect_beside_an_open_group_is_refused",
        "a mutating effect performed beside an open group is admitted, so it "
        "survives an abort that settles `Aborted` — the world taken back whole "
        "over a write that is still standing",
        """        if let Some(open) = self.open_group.as_ref()
            && !self.member_dispatch
            && effect.mutates()
        {""",
        """        if let Some(open) = self.open_group.as_ref()
            && !self.member_dispatch
            && effect.mutates()
            && false
        {""",
    ),
    "AMetQuorumSilencesAFork": (
        "src/journal/witness.rs",
        "a_fork_report_survives_a_met_quorum",
        "a met quorum silences an integrity refusal, so the one witness that "
        "remembers a different history is outvoted by witnesses that never saw "
        "it",
        """    pub fn needs_attention(&self) -> bool {
        !self.met() || !self.integrity.is_empty()
    }""",
        """    pub fn needs_attention(&self) -> bool {
        !self.met()
    }""",
    ),
    # ── Seals and conclusions ───────────────────────────────────────────────
    "SealedRunAcceptsAppends": (
        "src/store/redb.rs",
        "redb_satisfies_the_journal_store_contract",
        "a sealed run accepts appends, so the true head moves past the leaf "
        "every checkpoint attests",
        """                    if let Some(seal) = seals.get(key.as_str()).map_err(|e| be(&e))? {
                        let (outcome, _, _) = seal.value();
                        return Err(StoreError::RunSealed {
                            run: key.clone(),
                            outcome: outcome.to_owned(),
                        });
                    }""",
        """                    if let Some(seal) = seals.get(key.as_str()).map_err(|e| be(&e))? {
                        let (outcome, _, _) = seal.value();
                        let _ = (outcome, &key);
                    }""",
    ),
    "OutcomeIndexKeepsFirstConclusion": (
        "src/store/redb.rs",
        "redb_satisfies_the_journal_store_contract",
        "a re-conclusion accumulates a second index row instead of replacing "
        "the first, so a resumed run stays listed as failed forever",
        """                            by_outcome
                                .remove((tenant.as_str(), prior.0.as_str(), prior.1))
                                .map_err(|e| be(&e))?;""",
        """                            let _ = &prior;""",
    ),
    "FailedRunSeals": (
        "src/runtime/executor.rs",
        "a_failed_run_is_findable_open_and_moves_on_resume",
        "a failed run seals and enters the Merkle log, so its own resume grows "
        "the history past the leaf a checkpoint attests",
        """        matches!(
            self,
            Self::Succeeded | Self::Quarantined(_) | Self::Cancelled { .. }
        )""",
        """        matches!(
            self,
            Self::Succeeded | Self::Quarantined(_) | Self::Cancelled { .. } | Self::Failed(_)
        )""",
    ),
    "UnknownOutcomeResumes": (
        "src/runtime/executor.rs",
        "an_unrecognised_recorded_outcome_refuses_resume",
        "a recorded ending this build does not recognise is treated as "
        "resumable — fail open instead of fail closed",
        """        other => Some(RunStatus::Quarantined(format!(
            "recorded as '{other}', which this build does not recognise as resumable"
        ))),""",
        """        _ => None,""",
    ),
    "FormationIgnoresQuarantined": (
        "src/runtime/declarative.rs",
        "formation_runs_on_the_quarantined_model_when_declared",
        "untrusted contact runs on the privileged model even when a quarantined "
        "one is declared, so the role designated for it governs nothing in the "
        "declarative tier",
        """    m.spec
        .models
        .as_ref()
        .and_then(|models| models.quarantined.as_ref())
        .map_or_else(|| fallback.clone(), |r| ModelId::new(&r.provider, &r.model))""",
        """    let _ = m;
    fallback.clone()""",
    ),
    "PlannedAcceptsUntrustedInput": (
        "src/runtime/declarative.rs",
        "a_planned_agent_refuses_untrusted_input",
        "a planned agent plans over untrusted input, so the attacker authors "
        "the authorization order",
        "        if input.label().trust != crate::core::Trust::Trusted {",
        "        if false {",
    ),
    "AReferenceIsRetyped": (
        "src/runtime/declarative.rs",
        "a_reference_keeps_provenance_a_literal_does_not",
        "a plan reference is retyped under the plan's own label, so binding a "
        "trusted value strips the provenance the reference exists to carry",
        "        Value::String(s) if s.starts_with('$') => resolve_reference(s, input, outputs),",
        """        Value::String(s) if s.starts_with('$') => resolve_reference(s, input, outputs)
            .map(|v| Tainted::with_label(v.peek().clone(), plan_label.clone())),""",
    ),
    "AShortfallAnswersAnyway": (
        "src/runtime/declarative.rs",
        "a_parse_shortfall_fails_the_run_rather_than_guessing",
        "a parse that declared it lacked information answers anyway, producing "
        "wrong data nothing downstream can detect",
        """                    let enough = value
                        .get("have_enough_information")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    if !enough {""",
        """                    let enough = value
                        .get("have_enough_information")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    if !enough && false {""",
    ),
    "LostAckCheapAborts": (
        "src/runtime/group.rs",
        "a_lost_commit_acknowledgement_quarantines_the_group",
        "a commit whose acknowledgement was lost takes the cheap abort, so the "
        "journal settles 'taken back whole' over a write that may stand",
        """            if matches!(
                &e,
                StepError::Store(crate::core::StoreError::CommitUnknown { .. })
            ) {""",
        """            if false {""",
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



def _locate(test: str) -> tuple[str | None, set[str] | None] | None:
    """Where `test` lives, and which features it needs to build and exist.

    Returns `(target, features)`, with `target = None` for a unit test in the
    library — those run under `--lib`, and looking for them only under `tests/`
    reported *no such test* for four that plainly existed. A tool that says a
    guarantee is untested when it is tested is worse than one that says nothing.

    Read from the source rather than configured, because a second list of
    feature sets is a second thing to keep in step — and the one that rots is
    always the one nobody runs.

    Two unions, for different reasons. Cargo compiles an integration target as
    one binary, so **every** module in it must compile: the features come from
    every file's `#![cfg(...)]`, not just the one holding the test. And the
    function may carry its own `#[cfg(...)]`, which decides whether it exists
    inside a module that already compiled. Missing either produces a run
    reporting `0 passed`, which looks exactly like a mutation that was caught.
    """
    root = pathlib.Path(__file__).resolve().parent.parent

    # Integration tests first: they are the common case and name their target.
    tests = root / "tests"
    for path in sorted(tests.rglob("*.rs")):
        src = path.read_text()
        at = src.find(f"fn {test}(")
        if at < 0:
            continue
        target = path.relative_to(tests).parts[0]
        feats: set[str] = set()
        for sibling in sorted((tests / target).rglob("*.rs")):
            for line in sibling.read_text().splitlines():
                if line.startswith("#!["):
                    feats.update(re.findall(r'feature\s*=\s*"([a-z0-9-]+)"', line))
        feats.update(
            re.findall(r'feature\s*=\s*"([a-z0-9-]+)"', src[max(0, at - 400) : at])
        )
        return target, feats

    # A unit test inside the library.
    #
    # `None` for the features, meaning *all of them*. A module's gate lives on
    # its `mod` declaration in the parent — `#[cfg(feature = "providers")] mod
    # anthropic;` — not inside the file holding the test, so reading the file
    # finds nothing and the run silently matches no tests. Walking parents to
    # reconstruct the gate would be a second model of cargo's; building the
    # whole library is one command and cannot disagree with it.
    for path in sorted((root / "src").rglob("*.rs")):
        if f"fn {test}(" in path.read_text():
            return None, None
    return None


def verify(name: str) -> int:
    """Apply one mutation, run the test it names, and classify what happened.

    The single implementation of *did this guarantee hold*. `verify-mutants.sh`
    loops over it and owns only the sweep's concerns — locking, strays,
    progress, a summary — so there is one classifier rather than two that can
    disagree about the same mutation.

    Four verdicts, and the middle two are why this is not a boolean:

    * `0` **killed** — the named test failed. The guarantee is pinned by the
      test written for it.
    * `1` **weak** — something else failed, but not the named test. The
      mutation was caught, and the row's claim about *which* test does the
      catching is wrong. Tripping some other assertion proves only that
      something broke.
    * `1` **survived** — nothing failed at all. The guarantee has no test that
      can falsify it, which is the failure this whole harness exists to find.
    * `2` **error** — it did not compile, or the named test never ran. A
      mutation must remove the *guarantee*, not break the file.

    Two-speed on purpose. A mutation changes one source file, so the library
    rebuilds and every test binary relinks — expensive to learn one bit. The
    named test's own target runs first, and the full suite runs **only** when
    that comes back clean, which is the rare and interesting case. `killed` is
    the one verdict the fast path may produce, and it is the one needing no
    knowledge of any other test.

    Restores the file on every path, including a failure to build.
    """
    path, test, _desc, _find, _replace = MUTANTS[name]
    found = _locate(test)
    if not found:
        print(f"{name}: no test named '{test}' anywhere in src/ or tests/")
        return 2
    target, feats = found
    if feats is None:
        # A library unit test: build everything, because the gate that decides
        # whether this test exists is not in the file it lives in.
        selector = ["--all-features", "--lib"]
        features = "all"
    else:
        # `redb` and `testkit` are what a test needs to stand up a plane at all.
        feats |= {"redb", "testkit"}
        features = ",".join(sorted(feats))
        selector = ["--features", features, "--test", target]

    def run(args: list[str]) -> str:
        proc = subprocess.run(
            ["cargo", "test", *args], capture_output=True, text=True, cwd=ROOT, check=False
        )
        return proc.stdout + proc.stderr

    if apply(name) != 0:
        return 2
    try:
        out = run([*selector, test])
        if not _named_test_failed(out, test):
            # Slow path, and only here: the named test held, so the question is
            # now whether *anything* did.
            out = run(["--all-features", "--no-fail-fast"])
    finally:
        revert(name)

    # Order matters. A failing test makes cargo print `error: test failed, to
    # rerun pass ...`, so a naive `^error:` check reads every successful
    # mutation as a compile failure.
    if _named_test_failed(out, test):
        print(f"{name}: KILLED by {test}")
        return 0
    if re.search(r"^error\[|could not compile", out, re.M):
        print(f"{name}: ERROR — did not compile; a mutation must remove the "
              f"guarantee, not break the file")
        print("\n".join(out.splitlines()[-6:]))
        return 2
    if "test result: FAILED" in out:
        others = re.findall(r"^test ([a-z_:]+) \.\.\. FAILED", out, re.M)[:3]
        print(f"{name}: WEAK — {test} did not fail; caught only by "
              f"{', '.join(others) or 'something unnamed'}")
        return 1
    if not re.search(r"test result: \w+\. \d+ passed", out):
        print(f"{name}: ERROR — '{test}' never ran in {target or 'lib'} ({features})")
        return 2
    print(f"{name}: SURVIVED — nothing failed, so this guarantee has no test "
          f"that can falsify it ({path})")
    return 1


def _named_test_failed(out: str, test: str) -> bool:
    """Whether cargo reported *this* test failing.

    `- should panic` is optional because cargo prints it for a `#[should_panic]`
    test. Without it the classifier cannot see those failing at all, and every
    such mutation reads as a guarantee nothing can falsify — which would send
    somebody hunting for a missing test that exists and works.
    """
    return bool(
        re.search(rf"^test .*{re.escape(test)}( - should panic)? \.\.\. FAILED", out, re.M)
    )


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
    if action == "--verify":
        return verify(name)
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
