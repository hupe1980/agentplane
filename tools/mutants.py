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
        """        if effect.mutates() && label.is_untrusted() {
            return Err(PolicyError::TaintGate { sink: sink_name }.into());
        }""",
        "",
    ),
    "NoEgressCeiling": (
        "src/runtime/ctx.rs",
        "a_sink_refuses_data_above_its_ceiling",
        "a value above the sink's ceiling is sent anyway",
        """        let ceiling = effect.max_sensitivity();
        if label.sensitivity > ceiling {""",
        """        let ceiling = effect.max_sensitivity();
        if false && label.sensitivity > ceiling {""",
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
    "CedarDigestIgnoresRules": (
        "src/policy/cedar.rs",
        "the_digest_follows_the_policy_text",
        "the policy digest does not depend on the rules",
        "        framed.extend_from_slice(source.as_bytes());\n",
        "",
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
            PolicyDecision::Permit => Ok(caller),
            PolicyDecision::Deny { reason } => Err(ApiError(StatusCode::FORBIDDEN, reason)),
        }""",
        """        let _ = decision;
        Ok(caller)""",
    ),
    "GateRunsAfterParsing": (
        "src/api/mod.rs",
        "a_denying_policy_stops_every_route_before_it_touches_anything",
        "a route parses its path before asking whether the caller may look",
        """    api.gate(&headers, action::RUN_READ, &run).await?;
    let id = RunId::parse(&run).map_err(|_| bad("run"))?;""",
        """    let id = RunId::parse(&run).map_err(|_| bad("run"))?;
    api.gate(&headers, action::RUN_READ, &run).await?;""",
    ),
    "SurfaceStartsWithoutPolicy": (
        "src/api/mod.rs",
        "the_surface_refuses_to_build_without_a_policy_engine",
        "the HTTP surface opens against a runtime with no authorization layer",
        "        let policy = runtime.policy().ok_or(ApiSetupError::NoPolicy)?.clone();",
        """        let policy = runtime.policy().cloned().unwrap_or_else(|| {
            Arc::new(crate::core::DenyAll) as Arc<dyn crate::core::PolicyEngine>
        });""",
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
        "        .queue(&caller.roles, api.limit + 1)",
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
        "                    w.open_table(SEAL_LOG)\n                        .map_err(|e| be(&e))?\n                        .insert(next, key.as_str())\n                        .map_err(|e| be(&e))?;",
        "                    let _ = &SEAL_LOG;",
    ),
    "TheLogIndexIsReused": (
        "src/store/redb.rs",
        "a_new_run_is_appended_after_the_survivors",
        "log positions stop advancing, so a new run is dropped into a slot an earlier one already holds",
        "                    counters\n                        .insert(NEXT_LOG_INDEX, next + 1)\n                        .map_err(|e| be(&e))?;",
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
    "TheSweepForgetsToDeindexAClaim": (
        "src/store/redb_events.rs",
        "redb_satisfies_the_case_layer_contracts",
        "a delivered message is left sweepable, so the run resumes on it and the "
        "dead-letter queue reports it as never claimed",
        "                        drop(events);\n                        // No longer sweepable: the index moves with the row it\n                        // describes, in the row's transaction.\n                        w.open_table(EVENTS_LIVE)\n                            .map_err(|e| be(&e))?\n                            .remove((received, id.as_str()))\n                            .map_err(|e| be(&e))?;",
        "                        drop(events);",
    ),
    "TheBacklogDropsClaimedWork": (
        "src/store/redb_tasks.rs",
        "redb_satisfies_the_case_layer_contracts",
        "the backlog counts only unclaimed work, so it falls the moment a "
        "reviewer opens an item and reports progress that has not happened",
        "            r.open_table(PENDING)",
        "            r.open_table(QUEUE)",
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
        "        -32700 | -32600 | -32601 | -32602 | -32006..=-32001 => PeerError::Refused {",
        "        -32700 | -32600 | -32601 | -32602 | -32006..=-32001 | -32603 => PeerError::Refused {",
    ),
    "FailedPeerTaskIsInDoubt": (
        "src/peers/a2a.rs",
        "a_failed_task_landed",
        "a peer task that reported failure is treated as an unknown outcome",
        '        "failed" => Some(PeerError::Failed {',
        '        "failed" if false => Some(PeerError::Failed {',
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
