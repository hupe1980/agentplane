#!/usr/bin/env python3
"""Break a guarantee on purpose, and check that a test notices.

`tla/mutations.py` does this for the specs: each spec is re-run against
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

`--check` reads only the *find* half, so it cannot see a *replace* half that
stopped compiling. A replacement calling a function whose signature has since
gained a parameter is an ERROR the moment it runs and invisible until then —
which means green anchors in `just ci`, and the failure only in the sweep,
which `ci` does not run. After changing any signature, grep this table for the
function's name and `--verify` what it finds.
"""

from __future__ import annotations

import functools
import os
import pathlib
import re
import signal
import subprocess
import shutil
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent

# How long one cargo invocation may take before it is killed as hung.
#
# Generous, because a cold feature set builds the dependency graph before it
# runs anything and the whole-suite fallback runs every test in the crate. It is
# a bound on *infinite*, not a performance budget: the slowest measured group is
# under three minutes per mutation.
TIMEOUT_SECONDS = int(os.environ.get("MUTANTS_TIMEOUT_SECS", "900"))

# name -> (file, test that must fail, description, find, replace)
#
# `find` must appear verbatim, exactly once.
MUTANTS: dict[str, tuple[str, str, str, str, str]] = {
    # ── Exactly-once ────────────────────────────────────────────────────────
    "ARecordReadsPastAFieldItDoesNotKnow": (
        "src/journal/record.rs",
        "a_record_with_a_field_this_build_does_not_know_is_refused",
        "a record carrying a field this build does not know is read anyway, so "
        "every field it could not see takes a serde default and the decisions "
        "downstream are made over a record nobody fully read",
        r"""#[serde(tag = "kind", rename_all = "PascalCase", deny_unknown_fields)]""",
        r"""#[serde(tag = "kind", rename_all = "PascalCase")]""",
    ),
    "ANestedPayloadReadsPastAFieldItDoesNotKnow": (
        "src/core/effect.rs",
        "a_member_nobody_knows_is_refused_inside_the_payload",
        "an effect descriptor carrying a member this build does not know is "
        "read anyway — the record's top level refuses one, the structs it "
        "holds do not — so a verdict about the effect is reached over a "
        "descriptor nobody fully read",
        """#[serde(deny_unknown_fields)]
pub struct EffectDescriptor {""",
        """pub struct EffectDescriptor {""",
    ),
    "ANestedLabelReadsPastAFieldItDoesNotKnow": (
        "src/core/label.rs",
        "a_member_nobody_knows_is_refused_inside_the_payload",
        "a label inside a record carrying a member this build does not know is "
        "read anyway, so the trust and sensitivity verdicts that route on it "
        "are reached over a label nobody fully read",
        """#[serde(deny_unknown_fields)]
pub struct Label {""",
        """pub struct Label {""",
    ),
    "ADeclarativeAgentNeedsItsNameSpelledOut": (
        "src/manifest/mod.rs",
        "the_shorthands_have_the_longhands_digest",
        "a declarative agent that names no capability provides nothing instead "
        "of its own name, so the file that omits the line and the one that "
        "writes it are different agents",
        "        if self.spec.execution.is_some() && self.spec.capabilities.provides.is_empty() {",
        "        if false && self.spec.capabilities.provides.is_empty() {",
    ),
    "ATerminalDecisionIsReportedLost": (
        "src/runtime/executor.rs",
        "a_decision_recorded_by_a_plane_without_the_agent_completes_the_task",
        "a decision recorded by a plane holding no agent for the run (an "
        "operator's terminal) fails after the record, so the task stays claimed "
        "and the decider is told the answer was lost",
        """                RuntimeError::NoProvider { .. }
                | RuntimeError::NoCaseStore { .. }
                | RuntimeError::PayloadsSealed { .. },
            ) => {
                return Ok(Delivery::Buffered);""",
        """                e @ (RuntimeError::NoProvider { .. }
                | RuntimeError::NoCaseStore { .. }
                | RuntimeError::PayloadsSealed { .. }),
            ) => {
                return Err(e);""",
    ),
    "APlaneThatCannotDriveARunJudgesIt": (
        "src/runtime/executor.rs",
        "a_decision_from_a_plane_without_the_agent_does_not_quarantine_a_governed_run",
        "a plane holding no provider for a run (an operator's terminal) compares "
        "its own empty policy with the run's before finding it cannot drive the "
        "run, and quarantines a governed run it could never have continued",
        "            self.refuse_undrivable(std::iter::once(&plan).chain(&successors))?;",
        "            let _ = self.refuse_undrivable(std::iter::once(&plan).chain(&successors));",
    ),
    "ATerminalStopIsReportedAsAFailure": (
        "src/runtime/executor.rs",
        "a_stop_from_a_plane_without_the_agent_is_recorded_and_not_judged",
        "a stop recorded by a plane holding no provider for the run is reported "
        "as an error after the request is durable, so the operator is told a "
        "standing stop failed",
        """                    RuntimeError::LeaseHeld { .. }
                    | RuntimeError::NoProvider { .. }
                    | RuntimeError::NoCaseStore { .. }""",
        """                    RuntimeError::LeaseHeld { .. }
                    | RuntimeError::NoCaseStore { .. }""",
    ),
    "ATaskIdRefusesItsOwnDisplayForm": (
        "src/core/task.rs",
        "a_task_id_parses_from_its_own_display_form",
        "a task id copied from a listing (`task_<hex>`) is refused by the parser "
        "that decide and the operator API read it with",
        r"""        Digest::from_hex(s.strip_prefix("task_").unwrap_or(s)).map(Self)""",
        r"""        Digest::from_hex(s).map(Self)""",
    ),
    "OriginKeyIsForgeable": (
        "src/core/event.rs",
        "one_emitter_cannot_spell_anothers_pair",
        "a producer can spell another producer's (source, id) pair, so its next "
        "message is swallowed as an apparent retry",
        r"""    format!("{}\u{1f}{source}\u{1f}{id}", source.len())""",
        r"""    format!("{source}\u{1f}{id}")""",
    ),
    "ReplayRePerforms": (
        "src/runtime/ctx.rs",
        "a_committed_but_lost_effect_record_is_not_performed_again",
        "replay re-performs a completed effect instead of reading it back",
        """                self.arrival_refusal(content.as_ref())?;
                declared.sensitivity =
                    crate::core::ContentVerdict::raise(content.as_ref(), declared.sensitivity);
                Ok(Replayed::Answered(
                    serde_json::from_value(output)?,
                    declared,
                ))""",
        """                let _ = (output, declared, content);
                Ok(Replayed::Live)""",
    ),
    "MediaReplayRePerforms": (
        "src/runtime/ctx.rs",
        "strict_replay_does_not_read_media_blobs_or_call_the_model",
        "strict replay re-materializes a media blob and calls the model again",
        """                    crate::core::ContentVerdict::raise(content.as_ref(), declared.sensitivity);
                Ok(Replayed::Answered(""",
        """                    crate::core::ContentVerdict::raise(content.as_ref(), declared.sensitivity);
                if descriptor.kind == "model.complete" {
                    let _ = effect.perform().await;
                }
                Ok(Replayed::Answered(""",
    ),
    "NoReplayCursor": (
        "src/journal/replay.rs",
        "no_crash_point_breaks_a_successful_run",
        "the replay cursor is empty, so nothing is ever read back",
        "            by_step,\n            noted: None,",
        "            by_step: {\n                let _ = by_step;\n                BTreeMap::new()\n            },\n            noted: None,",
    ),
    # ── Divergence ──────────────────────────────────────────────────────────
    "ADivergenceNamesNoRevision": (
        "src/runtime/verdict.rs",
        "a_strict_replay_under_an_edited_instruction_names_both_revisions_and_the_step",
        "a strict replay's report drops the declaration it replayed under, so a "
        "divergence reads as a verdict on the recorded revision alone",
        """                revision(f, "candidate", c)?;""",
        """                let _ = c;""",
    ),
    "ANoDivergenceReadsAsTheSameRevision": (
        "src/runtime/verdict.rs",
        "an_edit_no_effect_reaches_verifies_with_both_digests_named",
        "a replay that reached nothing an edit touched is reported like one under "
        "the recorded revision, so a reviewer reads the edit as inert",
        """            Finding::Verified { outcome } if self.same_revision() => {""",
        """            Finding::Verified { outcome } if true => {""",
    ),
    "AStrictDivergenceIsFlattened": (
        "src/runtime/executor.rs",
        "a_strict_replay_under_an_edited_instruction_names_both_revisions_and_the_step",
        "the first divergence is left behind in a quarantine sentence, so the "
        "verdict cannot name the step or either effect key",
        """        .inspect(|_| *divergence = cursor.divergence().cloned())""",
        """        .inspect(|_| *divergence = None)""",
    ),
    "StrictReplayConcludesInTheJournal": (
        "src/runtime/executor.rs",
        "a_strict_replay_under_an_edited_declaration_leaves_the_store_unchanged",
        "a strict replay writes as a live pass does, so verifying an edit appends "
        "a quarantine for a divergence nobody ran into the run's history",
        """        let writing = !matches!(mode, Mode::Strict);""",
        """        let writing = true;""",
    ),
    "AFaithfulFailureIsAFailure": (
        "src/runtime/executor.rs",
        "a_faithful_replay_of_a_failed_run_is_verified",
        "a strict replay that reproduces a recorded failure is not verified, so "
        "CI reads a faithfully replayed refusal as a regression",
        """            (Ok(outcome), None) if outcome.status.as_str() == ending => {""",
        """            (Ok(outcome), None) if matches!(outcome.status, RunStatus::Succeeded) => {""",
    ),
    "AMissingKeyReadsAsAnErasure": (
        "src/runtime/executor.rs",
        "a_sealed_run_without_its_key_is_not_reported_as_erased",
        "a plane holding no key ring reports every sealed run as erased, so a "
        "verifier handed no key is told intact data is gone",
        """            RuntimeError::PayloadsErased { run } if !self.holds_key_ring() => {""",
        """            RuntimeError::PayloadsErased { run } if false => {""",
    ),
    "ACanonicalizationChangeIsNotNamed": (
        "src/runtime/executor.rs",
        "a_run_under_another_canonicalization_rule_cannot_be_replayed",
        "history under another canonicalization rule is not named as such by a "
        "strict replay's verdict, so a rule change reads as some other answer",
        """        }) = ensure_replayable_canon(&records)""",
        """        }) = Ok::<(), RuntimeError>(())""",
    ),
    "ARemovedEntryPointIsAnError": (
        "src/runtime/executor.rs",
        "a_manifest_that_no_longer_provides_the_capability_cannot_replay_it",
        "an edit that removed the run's capability ends the replay in an error "
        "rather than a verdict naming what the edit removed",
        """            (Err(RuntimeError::NoProvider { target, .. }), _) => {""",
        """            (Err(RuntimeError::NoProvider { target, .. }), _) if false => {""",
    ),
    "AnExportSourceListsNoRuns": (
        "src/export.rs",
        "a_run_replays_from_an_export_with_no_store_path",
        "an export restored for replay names none of the runs it holds, so a "
        "corpus replay reports every file verified having replayed nothing",
        """    let runs = parsed.runs.iter().map(|r| r.run).collect();""",
        """    let runs = Vec::new();""",
    ),
    "ACorpusHidesADivergence": (
        "src/bin/agentplane.rs",
        "a_corpus_exits_with_its_worst_verdict",
        "a corpus with a diverged run exits partial, so CI reads a regression as "
        "an incomplete answer",
        """        Some(Replayed::Diverged) => exit::FINDING,""",
        """        Some(Replayed::Diverged) => exit::PARTIAL,""",
    ),
    "StrictReplayRegistersLiveProviders": (
        "src/bin/agentplane.rs",
        "strict_replay_wires_only_replay_only_drivers",
        "`replay --strict` builds the manifest's live drivers, so a CI job with "
        "no provider credential cannot verify a pass that calls no provider",
        """    let mut builder = agentplane::runtime::replay_only::wire(backend.plane(), manifests, &history);""",
        """    let _ = &history;
    let mut builder = with_providers(backend.plane(), manifests).await?;""",
    ),
    "AVerbBuildsItsOwnPlane": (
        "src/bin/agentplane.rs",
        "every_plane_this_binary_builds_comes_through_backend_plane",
        "a verb starts its runtime builder itself, so whether it wires the quota "
        "store the operator's halts live in is that verb's choice to forget",
        """        let plane = backend.plane().build();
        let first = plane""",
        """        let plane = Runtime::builder_with(backend.stores())
            .tenant(backend.tenant())
            .build();
        let first = plane""",
    ),
    "AContinuationSkipsTheKindGate": (
        "src/api/a2a.rs",
        "a_continuation_is_refused_the_kind_policy_refuses",
        "an A2A continuation delivers whatever kind its task awaits without "
        "asking whether the peer may supply that kind, so a rule `POST /events` "
        "enforces is bypassed by addressing the task instead",
        "    server.authorize(caller, action::EVENT_DELIVER, &kind, Some(&caller.actor))?;",
        "    let _ = action::EVENT_DELIVER;",
    ),
    "TheReleaseRouteBypassesTheRuntime": (
        "src/api/mod.rs",
        "a_hold_release_and_a_halt_lift_name_who_made_them",
        "the release route removes the hold through the case store directly, so "
        "a release over the wire answers with a record that was never written",
        """    let record = s
        .plane
        .release_hold(case, &by, now_for_account())
        .await""",
        """    let record = s
        .plane
        .cases()
        .ok_or_else(|| unavailable("case"))?
        .release_hold(case)
        .await
        .map(|lifted| {
            lifted.then(|| crate::runtime::ControlLifted {
                record: crate::core::RunId::generate(),
                removed: true,
            })
        })
        .map_err(crate::core::RuntimeError::Store)""",
    ),
    "APushRegistrationIsUnbounded": (
        "src/api/a2a.rs",
        "push_registrations_are_bounded_per_task_and_by_id_length",
        "a peer registers push configurations on its task without limit, each "
        "one a delivery per record, multiplying the plane's outbound traffic",
        "    if held.len() >= MAX_PUSH_CONFIGS_PER_TASK && !held.contains(&config.id) {",
        "    if held.len() >= usize::MAX && !held.contains(&config.id) {",
    ),
    "APushIdIsUnbounded": (
        "src/api/a2a.rs",
        "push_registrations_are_bounded_per_task_and_by_id_length",
        "a push configuration id of any length is stored and echoed back",
        "            .is_some_and(|id| id.len() > MAX_PUSH_ID_LEN)",
        "            .is_some_and(|id| id.len() > usize::MAX - 1)",
    ),
    "ATruncatedListingExitsZero": (
        "src/bin/agentplane.rs",
        "a_listing_cut_short_by_its_limit_exits_partial",
        "`tasks` and `waiting` exit 0 on a page `--limit` cut short, so a "
        "script takes the page for the whole worklist",
        "    ExitCode::from(if truncated { exit::PARTIAL } else { exit::OK })",
        "    ExitCode::from(if truncated { exit::OK } else { exit::OK })",
    ),
    "AnUnauthenticatedPeerIsToldItsRequestWasMalformed": (
        "src/api/a2a.rs",
        "every_method_is_authenticated",
        "a refused credential answers HTTP 200 with INVALID_REQUEST, so an A2A "
        "client is told its body was malformed rather than to authenticate",
        "        if self.unauthenticated {",
        "        if !self.unauthenticated && self.code == i32::MIN {",
    ),
    "TheOperatorApiEchoesAnUnevaluablePolicy": (
        "src/api/mod.rs",
        "an_unevaluable_policy_set_is_a_fixed_sentence_to_the_caller",
        "a policy set that cannot evaluate hands the caller the engine's reason, "
        "naming the policy ids and attributes it keys on",
        "                    POLICY_UNEVALUABLE.to_owned(),",
        "                    reason,",
    ),
    "AnUnwiredQuotaStoreIsAServerFault": (
        "src/api/mod.rs",
        "a_missing_store_does_not_describe_the_plane",
        "the halt and live-run routes on a plane with no quota store answer "
        "500, the status of an outage, instead of 501 naming what is not wired",
        """        .ok_or_else(|| unavailable("quota"))""",
        """        .or(Some(()))
        .ok_or_else(|| unavailable("quota"))""",
    ),
    "APlaintextRefusalQuotesTheUrl": (
        "src/peers/a2a.rs",
        "a_plaintext_peer_endpoint_and_card_url_are_refused",
        "the plaintext-peer refusal quotes the endpoint URL, carrying whatever "
        "credential its path or query holds into logs and records",
        """                    "the peer endpoint on '{host}' is not https — a bearer credential and \\
                     the run's payload must not cross the network in cleartext"
                ),""",
        """                    "the peer endpoint on '{host}' ({}) is not https — a bearer credential and \\
                     the run's payload must not cross the network in cleartext",
                    self.endpoint.url
                ),""",
    ),
    "IgnoreKeyMismatch": (
        "src/journal/replay.rs",
        "resume_refuses_a_journal_written_by_different_code",
        "a recomputed effect key that differs from history is accepted",
        """        if entry.key != recomputed {
            return Err(StepError::NonDeterminism {
                seq: entry.seq,
                expected: entry.key,
                actual: recomputed,
                detail: entry.diverged_from(asked, attempt),
            });
        }
        self.pos += 1;""",
        """        let _ = (asked, attempt);
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
        # The companion `a_quarantined_run_is_never_unwound` cannot kill this:
        # its quarantine comes from a mutating effect in doubt, which the
        # unwind's own doubt check refuses independently of the status arm.
        # This one quarantines on a *non-mutating* undecidable effect, where
        # the arm is the only control standing.
        "a_quarantined_run_is_never_unwound_without_a_mutating_doubt",
        "a run holding an unknown outcome is unwound anyway",
        "            RunStatus::Failed(_) | RunStatus::Cancelled { .. } => {}",
        "            RunStatus::Failed(_)\n            | RunStatus::Cancelled { .. }\n            | RunStatus::Quarantined(_) => {}",
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
            if mutates && args.effective_label(sink_id).is_untrusted() {
                if let Some(mark) = misdirected_release(args, sink_id, "") {
                    return Err(PolicyError::ReleaseDestination {
                        sink: sink_name,
                        granted: mark.destination().to_owned(),
                        actual: sink_id.to_owned(),
                    }
                    .into());
                }
                return Err(PolicyError::TaintGate { sink: sink_name }.into());
            }
            return Ok(());
        }""",
        """        if protected.is_empty() {
            return Ok(());
        }""",
    ),
    "AReviewersAmendmentIsAdvisory": (
        "src/runtime/declarative.rs",
        "a_reviewers_amendment_is_the_call_that_runs",
        "the loop records the reviewer's amendment and dispatches the model's "
        "original arguments anyway — a declared answer the runtime silently "
        "ignores, on the one surface whose point is that a person's answer "
        "governs",
        "                    args = match approved_arguments(&decision, &declaration.parameters, args) {\n"
        "                        Ok(args) => args,",
        "                    args = match Ok::<_, String>(args) {\n"
        "                        Ok(args) => args,",
    ),
    "AnAmendmentIsAsUntrustedAsTheValueItReplaces": (
        "src/runtime/declarative.rs",
        "a_reviewers_amendment_is_the_call_that_runs",
        "a reviewer's substitute arguments inherit the model completion's "
        "label, so the authenticated decision channel confers nothing and "
        "every field rule that demands a trusted author still refuses the "
        "value a person wrote",
        "    let mut label = crate::core::Label::trusted();",
        "    let mut label = original.label().clone();",
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
            match self.cursor.next(key, &descriptor, 1)? {
                Some(EffectReplay::Done { .. }) => return Ok(released),""",
        """        if false {
            match self.cursor.next(key, &descriptor, 1)? {
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
        "        if bound_bytes != sent_bytes {",
        "        if false && bound_bytes != sent_bytes {",
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
        "        if live_dispatch && label.sensitivity > ceiling {",
        "        if false && label.sensitivity > ceiling {",
    ),
    "DeclarationFromCatalogue": (
        "src/runtime/ctx.rs",
        "lowering_a_declared_sensitivity_does_not_declassify_history",
        "a replayed value is relabelled from today's catalogue instead of its record",
        "                Ok(Replayed::Answered(\n                    serde_json::from_value(output)?,\n                    declared,\n                ))",
        "                Ok(Replayed::Answered(\n                    serde_json::from_value(output)?,\n                    crate::core::DeclaredOutput::of(effect),\n                ))",
    ),
    "EmbedHasNoCeiling": (
        "src/runtime/effects.rs",
        "an_embedding_above_its_declared_ceiling_is_refused",
        "the embedding sink accepts anything, whatever ceiling was declared",
        "    fn max_sensitivity(&self) -> Sensitivity {\n        self.max_sensitivity\n    }\n\n    fn sink_arguments(&self) -> Option<&serde_json::Value> {\n        Some(&self.arguments)\n    }\n\n    async fn perform(&self) -> Result<Self::Output, EffectError> {\n        // The revision",
        "    fn max_sensitivity(&self) -> Sensitivity {\n        Sensitivity::Secret\n    }\n\n    fn sink_arguments(&self) -> Option<&serde_json::Value> {\n        Some(&self.arguments)\n    }\n\n    async fn perform(&self) -> Result<Self::Output, EffectError> {\n        // The revision",
    ),
    "SensitivityCanLower": (
        "src/runtime/ctx.rs",
        "an_undeclared_effect_keeps_the_sensitivity_its_provenance_implies",
        "an effect may declare its output less sensitive than its provenance",
        "    let sensitivity = base.sensitivity.max(declared.sensitivity);",
        "    let sensitivity = declared.sensitivity;",
    ),
    "ALandedReadIsNeverRetried": (
        "src/runtime/ctx.rs",
        "a_stream_that_died_after_generating_is_retried_and_billed",
        "a non-mutating effect that landed and failed is final whatever its "
        "policy says, so one mid-stream provider overload fails the step",
        "            Disposition::Landed if !mutates && !permanent => {}",
        "            Disposition::Landed if false => {}",
    ),
    "APermanentLandedFailureIsRetried": (
        "src/runtime/ctx.rs",
        "a_tool_that_ran_and_failed_is_retried_only_when_declared",
        "a non-mutating effect whose landed failure is permanent falls through "
        "to its retry policy, so a tool's reported failure is asked again for "
        "the same answer",
        "            Disposition::Landed if !mutates && !permanent => {}",
        "            Disposition::Landed if !mutates => {}",
    ),
    "AToolsReportedFailureIsNotPermanent": (
        "src/runtime/ctx.rs",
        "a_tool_that_ran_and_failed_is_retried_only_when_declared",
        "a tool that ran and reported failure is recorded as a transient fault "
        "unless it declared otherwise, so its retry policy asks it again",
        "        || (failure.disposition() == crate::core::Disposition::Landed && !effect.retries_landed())",
        "        || (failure.disposition() == crate::core::Disposition::Landed && false)",
    ),
    "AFailureCarriesNoLabel": (
        "src/runtime/ctx.rs",
        "a_tool_failure_above_the_model_ceiling_never_reenters_the_provider",
        "a failed effect records no output label, so a confidential tool's "
        "error text reaches a model cleared below it",
        "                    self.failed_output = Some(failure_label);",
        "                    let _ = failure_label;",
    ),
    "ARelayedFailureKeepsTheConversationLabel": (
        "src/runtime/declarative.rs",
        "a_tool_failure_above_the_model_ceiling_never_reenters_the_provider",
        "the tool loop relays a failure's text to the model without joining its "
        "label, so the next turn's sink gate judges a conversation the model "
        "does not read",
        "        *conversation_label = conversation_label.join(&failed);",
        "        let _ = failed;",
    ),
    # ── The offline re-derivation (`policy check`) ──────────────────────────
    "TheEffectGateAddsAKeyOutsideTheBuilder": (
        "src/runtime/ctx.rs",
        "a_rebuilt_request_equals_the_one_the_gate_was_asked",
        "the effect gate adds a context key after the shared builder returns, so "
        "the live gate asks a question the record cannot rebuild and an offline "
        "verdict is about a request nobody asked",
        "        let decision = engine.authorize(&request.as_request());",
        """        let decision = engine.authorize(
            &{
                let mut asked = request.clone();
                asked.context["smuggled"] = Value::Bool(true);
                asked
            }
            .as_request(),
        );""",
    ),
    "TheReleaseGateAddsAKeyOutsideTheBuilder": (
        "src/runtime/ctx.rs",
        "a_rebuilt_request_equals_the_one_the_gate_was_asked",
        "the release gate adds a context key after the shared builder returns, so "
        "a release's verdict cannot be re-derived from `Released`",
        "            |engine| engine.authorize(&request.as_request()),",
        """            |engine| {
                let mut asked = request.clone();
                asked.context["smuggled"] = Value::Bool(true);
                engine.authorize(&asked.as_request())
            },""",
    ),
    "TheAdmissionGateAddsAKeyOutsideTheBuilder": (
        "src/runtime/executor.rs",
        "a_rebuilt_request_equals_the_one_the_gate_was_asked",
        "admission adds a context key after the shared builder returns, so the "
        "run's admission cannot be re-derived from `RunAdmitted`",
        "        let decision = engine.authorize(&request.as_request());",
        """        let decision = engine.authorize(
            &{
                let mut asked = request.clone();
                asked.context["smuggled"] = serde_json::Value::Bool(true);
                asked
            }
            .as_request(),
        );""",
    ),
    "TheRecordKeepsTheEffectsOwnMutates": (
        "src/runtime/ctx.rs",
        "a_rebuilt_request_equals_the_one_the_gate_was_asked",
        "`EffectStarted.mutates` records the effect's own claim while the gate "
        "was asked with the grant-widened value, so a tool a reviewed grant "
        "declares mutating is re-derived as a read",
        "            let mutates = self.gated_mutates(&descriptor, effect.mutates());",
        "            let mutates = effect.mutates();",
    ),
    "TheGateSkipsOneEffectKind": (
        "src/runtime/ctx.rs",
        "an_export_checked_against_its_own_bundle_has_no_findings",
        "the effect gate lets one kind past the bundle, so a transfer the bundle "
        "forbids reaches the world — and the offline check over the export is "
        "what reports it",
        """        self.authorize(key, descriptor, mutates, outbound.map(|o| o.label))
            .await?;""",
        """        if descriptor.kind != "ledger.transfer" {
            self.authorize(key, descriptor, mutates, outbound.map(|o| o.label))
                .await?;
        }""",
    ),
    "TheCheckSkipsEffectStarted": (
        "src/policy/check.rs",
        "a_permit_the_recorded_bundle_refuses_is_a_finding",
        "the offline check rebuilds no `EffectStarted`, so every recorded effect "
        "the bundle refuses passes as agreement",
        "                } => requests::effect(",
        "                } if false => requests::effect(",
    ),
    "AMismatchedRunIsEvaluatedAsRecorded": (
        "src/policy/check.rs",
        "a_mismatched_bundle_is_reported_not_evaluated",
        "a run that recorded another bundle is judged by the supplied one, so a "
        "bundle edit reads as the runtime having broken its own rules",
        "        Some(_) => Mode::Mismatch,",
        "        Some(_) => Mode::Recorded,",
    ),
    "ACompensationIsJudged": (
        "src/policy/check.rs",
        "a_compensation_is_not_judged",
        "a compensating effect, which never passes the gate, is judged, so an "
        "undo the bundle refuses is reported as a verdict the runtime never gave",
        "                    if !body.phase.is_forward() {",
        "                    if false {",
    ),
    "AManifestRefusalIsJudged": (
        "src/policy/check.rs",
        "a_manifest_or_sink_refusal_is_not_judged",
        "a manifest or sink refusal — the same record, no bundle's decision — is "
        "reported as a policy verdict the check could not rebuild",
        "                } if ACTIONS.contains(&action.as_str()) => {",
        "                } if !action.is_empty() => {",
    ),
    "AnAbortedGroupsMembersAreJudged": (
        "src/policy/check.rs",
        "a_record_the_gate_may_have_skipped_is_not_judged",
        "a member of a group that did not commit is judged, so a reversal that "
        "skipped the gate — and that nothing on the record marks — is a finding",
        "                    if *outcome == GroupOutcome::Committed {",
        "                    if *outcome != GroupOutcome::Quarantined {",
    ),
    "AWaitIsJudged": (
        "src/policy/check.rs",
        "a_record_the_gate_may_have_skipped_is_not_judged",
        "a record of a durable wait's kind is judged, so a wait — announced "
        "without passing the gate — is a finding",
        "                    } else if WAIT_KINDS.contains(&descriptor.kind.as_str()) {",
        "                    } else if WAIT_KINDS.is_empty() {",
    ),
    "TheCheckImportsAStore": (
        "src/policy/check.rs",
        "the_policy_check_imports_no_store_or_client",
        "the offline check names a store type, which is the first step to one "
        "that writes, takes a lease or is pointed at a live plane",
        "use std::io::BufRead;\n",
        "use std::io::BufRead;\n#[allow(unused_imports)]\nuse crate::journal::JournalStore;\n",
    ),
    "TheExecutorCallsTheCheck": (
        "src/runtime/executor.rs",
        "the_policy_check_is_reachable_from_no_executor_path",
        "the executor can reach the offline check, so a policy edit could "
        "re-judge history on resume",
        "use super::ctx::{CaseContext, Mode, StepCtx};\n",
        "use super::ctx::{CaseContext, Mode, StepCtx};\n#[allow(unused_imports)]\nuse crate::policy::check::Check;\n",
    ),
    "ACheckThatReadNothingPasses": (
        "src/policy/check.rs",
        "an_export_with_nothing_evaluable_fails_the_check",
        "a check that evaluated nothing reports a clean bill — it found nothing "
        "because it read nothing",
        "            return Verdict::Partial;",
        "            return Verdict::Clean;",
    ),
    "ACandidateIsComparedWithTheRecordedBundle": (
        "src/policy/check.rs",
        "a_candidate_diff_is_against_the_recorded_outcome",
        "a candidate is diffed against the supplied bundle re-evaluated instead "
        "of against what happened, so a mismatched run's changes vanish",
        "            if let Some(finding) = disagreement(rebuilt, &decision) {",
        "            if let Some(finding) = disagreement(rebuilt, &decision)\n"
        "                .filter(|_| bundle.authorize(&rebuilt.request.as_request()).is_permit())\n"
        "            {",
    ),
    "AMalformedCandidateReadsAsADenial": (
        "src/policy/check.rs",
        "a_candidate_that_errors_is_malformed_not_denied",
        "a candidate that cannot evaluate a request is reported as a rule "
        "refusing it, so a broken bundle reads as a strict one",
        "        malformed: decision.is_malformed(),",
        "        malformed: false,",
    ),
    "AnErasedArgumentReadsAsSealed": (
        "src/keyring/journal.rs",
        "a_sealed_and_an_erased_run_are_not_evaluable_for_their_own_reasons",
        "the shared opener stops counting a destroyed key, so an erased payload reads as one merely sealed and an auditor is told to find a key that no longer exists",
        "                        *field = serde_json::from_slice(&plain)?;\n                        found.opened += 1;\n                    }\n                    None => found.erased += 1,",
        "                        *field = serde_json::from_slice(&plain)?;\n                        found.opened += 1;\n                    }\n                    None => {}",
    ),
    "ABundleDirectoryReadsAroundAStrayFile": (
        "src/bin/agentplane.rs",
        "a_bundle_directory_holding_another_file_is_refused",
        "a bundle directory holding a rules file the loader does not read is "
        "accepted, so a rule sits where the bundle identity does not reach",
        "            if !name.starts_with('.') && !BUNDLE_FILES.contains(&name.as_str()) {",
        "            if name.is_empty() {",
    ),
    # ── Authorization ───────────────────────────────────────────────────────
    "PolicyOnReplay": (
        "src/runtime/ctx.rs",
        "strict_replay_never_asks_the_policy_engine",
        "policy is re-evaluated while replaying a recorded run",
        "            if self.mode.is_replaying() {",
        "            self.gate(key, dispatch, &descriptor, effect.mutates(), outbound, "
        "Some(DeclaredCeilings::of(&effect)), Self::outbound_size(&effect))\n"
        "                .await?;\n"
        "            if self.mode.is_replaying() {",
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
        "            terms.acting_as.ceiling(self.identity.as_ref()),",
        "            None,",
    ),
    "DelegationCanWiden": (
        "src/core/identity.rs",
        "a_delegate_cannot_widen_its_delegator_s_authority",
        "a delegate is granted authority its delegator does not hold",
        "        if !from.scope.contains(&to.scope) {",
        "        if false {",
    ),
    "ValidityCanWiden": (
        "src/core/identity.rs",
        "a_delegate_cannot_outlive_its_delegator",
        "a delegate outlives its delegator, so a short-lived credential buys a "
        "long-lived one",
        "            && delegate_until > delegator_until\n",
        "            && false\n",
    ),
    "AudienceCanWiden": (
        "src/core/identity.rs",
        "a_delegate_cannot_change_its_delegators_audience",
        "a delegate carries its delegator's authority to a plane the delegator "
        "was never issued for",
        "            && delegate_audience != delegator_audience\n",
        "            && false\n",
    ),
    "AnExpiredChainIsAdmitted": (
        "src/core/identity.rs",
        "an_expired_chain_is_refused_at_admission",
        "a chain past its validity still admits runs — the time bound is a note",
        "            && at >= not_after\n",
        "            && false\n",
    ),
    "AChainForAnotherPlaneIsAdmitted": (
        "src/core/identity.rs",
        "a_chain_bound_to_another_plane_is_refused_at_admission",
        "a credential minted for another plane is spendable here — the audience "
        "bound is a note",
        "            && audience != plane\n",
        "            && false\n",
    ),
    "NoAdmissionBoundsCheck": (
        "src/runtime/executor.rs",
        "an_expired_chain_is_refused_at_admission",
        "admission checks the chain's scope and never its validity or audience",
        "        chain.admissible(self.tenant.as_str(), now_for_admission())?;\n",
        "",
    ),
    # The plane's chain reaching a run whose terms carried the caller's: every
    # served run would act as the owner, and the journal would say so.
    "ThePlanesChainOutranksTheCallers": (
        "src/runtime/executor.rs",
        "a_run_acts_under_the_terms_chain_not_the_planes",
        "the plane's own chain gates a run whose terms carried the caller's",
        "            Self::Plane | Self::Nobody => plane,\n            Self::Caller(chain) => Some(chain),",
        "            Self::Plane | Self::Nobody | Self::Caller(_) => plane,",
    ),
    "ThePlanesChainIsRecordedForTheCaller": (
        "src/runtime/executor.rs",
        "a_run_acts_under_the_terms_chain_not_the_planes",
        "the journal names the plane's chain on a run admitted for a caller",
        "        let chain = acting_as.resolve(self.identity.as_ref());",
        "        let chain = self.identity.as_ref().or(acting_as.resolve(None));",
    ),
    "ACallerWithoutAChainBorrowsThePlanes": (
        "src/runtime/executor.rs",
        "a_caller_without_a_chain_does_not_act_under_the_planes",
        "a served caller whose credential carried no chain is admitted under the "
        "plane's own, so every authenticated peer acts with the operator's "
        "authority and the journal names the operator for it",
        "            Self::Nobody => None,",
        "            Self::Nobody => plane,",
    ),
    "AStepActsAsThePlane": (
        "src/runtime/executor.rs",
        "a_steps_policy_context_names_the_runs_chain_live_and_on_replay",
        "every step's policy context carries the plane's chain rather than the "
        "run's, so a served run's effects are judged as the operator's",
        "                identity: identity.cloned(),\n                subjects: subjects.clone(),\n                agent: agent.to_owned(),",
        "                identity: self.identity.clone(),\n                subjects: subjects.clone(),\n                agent: agent.to_owned(),",
    ),
    "AResumedRunActsAsThePlane": (
        "src/runtime/executor.rs",
        "a_replayed_step_reads_the_recorded_chain_not_the_configured_one",
        "a replayed run acts under the chain the plane is configured with now "
        "instead of the one its journal records",
        "                identity: recorded_chain(&records)?,",
        "                identity: self.identity.clone(),",
    ),
    "AStepHidesItsChain": (
        "src/runtime/ctx.rs",
        "a_replayed_step_reads_the_recorded_chain_not_the_configured_one",
        "a skill cannot read the chain its run acts under, so the only chain it "
        "can extend toward a peer is one it holds ambiently",
        "    pub fn acting_as(&self) -> Option<&crate::core::Delegation> {\n        self.identity.as_ref()",
        "    pub fn acting_as(&self) -> Option<&crate::core::Delegation> {\n        None",
    ),
    "ACommissionDropsTheChain": (
        "src/runtime/ctx.rs",
        "a_commissioned_run_acts_under_the_orderers_chain_plus_one_link",
        "a commissioned sub-run is admitted under the plane's chain, so the "
        "orderer's owner, expiry and audience stop at the hand-off",
        "            (Some(chain), _) => super::RunTerms::default().acting_as(chain.clone()),",
        "            (Some(_), _) => super::RunTerms::default(),",
    ),
    "APlanesCommissionIsServed": (
        "src/runtime/ctx.rs",
        "a_planes_own_commission_draws_as_the_plane",
        "the plane's own chainless run commissions its sub-run as a "
        "chainless served caller, so the sub-run journals served_unchained "
        "and cannot draw the tenant mandate its parent holds",
        "            (None, false) => super::RunTerms::default(),",
        "            (None, false) => super::RunTerms::default().served(None),",
    ),
    "AServedCommissionActsAsThePlane": (
        "src/runtime/ctx.rs",
        "a_planes_own_commission_draws_as_the_plane",
        "a chainless served caller's commission admits its sub-run as the "
        "plane's own, so a peer that holds nothing draws the tenant's "
        "mandate one hand-off down",
        "            (None, true) => super::RunTerms::default().served(None),",
        "            (None, true) => super::RunTerms::default(),",
    ),
    "ARepairedSealKeepsTheRunsWaits": (
        "src/runtime/executor.rs",
        "a_repaired_seal_retires_the_runs_waits",
        "the seal resume writes to repair a crash between conclusion and "
        "seal leaves the run's waits registered, so its wait stays the "
        "oldest waiter on its key and takes the next event from a live run",
        """            // retired the run's waits; retiring twice is harmless.
            self.retire_waits(run).await;""",
        "            // retired the run's waits; retiring twice is harmless.",
    ),
    "ATrimKeepsTheVersionsKey": (
        "src/keyring/memory.rs",
        "a_trimmed_versions_backup_no_longer_opens",
        "a cascade that trims a superseded version destroys no key for it, "
        "so a backup taken before the cascade still opens the version the "
        "erasure claimed to remove",
        "            self.destroy_erased(&cascade.trimmed, at, &reason).await?;",
        "            let _ = &cascade.trimmed;",
    ),
    "ATrimNamesTheWrongVersion": (
        "src/store/redb_memory.rs",
        "redb_satisfies_the_memory_store_contract",
        "the cascade names a trimmed id with a version it did not remove, "
        "so a sealing wrapper destroys the wrong key \u2014 the removed version "
        "stays readable in backups and a live one goes dark",
        "                        partly.entry(memory_id.as_str()).or_default().push(*version);",
        "                        partly.entry(memory_id.as_str()).or_default().push(version + 1);",
    ),
    "AChainlessRunDelegatesFromTheOwner": (
        "src/runtime/ctx.rs",
        "a_chainless_run_delegates_from_the_planes_depth",
        "a run acting under no chain counts its hand-offs from the owner rather "
        "than from the plane that bounds it, so a chainless caller delegates "
        "further than the plane itself may",
        "            || plane.upgrade().map_or(0, |p| p.own_depth()),",
        "            || 0,",
    ),
    "AServedRunActsAsThePlane": (
        "src/api/a2a.rs",
        "a_served_run_acts_as_its_caller_not_as_the_plane",
        "the A2A server admits every peer's run under the plane's own chain — an "
        "ambient credential with the caller's name on the message and the "
        "owner's on the record",
        """        .served(caller.acting_as.clone())
        .admitted_by(&caller.actor);""",
        """        .admitted_by(&caller.actor);""",
    ),
    "AChainlessCallerEscapesThePlanesCeiling": (
        "src/runtime/executor.rs",
        "a_chainless_caller_is_bounded_by_the_planes_chain",
        "a served caller that presented no chain is checked against no scope "
        "at all, so the plane's own chain bounds the operator's runs and "
        "nobody else's",
        "            Self::Plane | Self::Nobody => plane,",
        "            Self::Plane => plane,\n            Self::Nobody => None,",
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
            chain.rest.push(link);
        }
        Ok(chain)""",
    ),
    # The door nobody reads as a door. A chain reaches the runtime from a
    # credential an `Authenticator` parsed, from a journal record and from a
    # peer — all `serde`, none of them a call to `delegate`. A derived
    # `Deserialize` would reach the fields directly and be the
    # `Delegation::new(links)` the type declines to offer.
    "ADeserializedChainSkipsRehydration": (
        "src/core/identity.rs",
        "a_deserialized_chain_cannot_widen_skip_the_depth_cap_or_be_empty",
        "a chain built by `serde` skips the attenuation and depth re-check, so "
        "presenting a credential is how a delegate holds authority its "
        "delegator never had",
        "        Self::rehydrate(wire.links)",
        """        let mut it = wire.links.into_iter();
        let root = it.next().ok_or(DelegationError::Empty)?;
        Ok(Self {
            root,
            rest: it.collect(),
        })""",
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
        "                let spend = e.spend();\n                self.bill_live(spend);",
        "                let spend = crate::core::Spend::default();\n                self.bill_live(spend);",
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
        "the token a hop presented is returned in its result, and so written into history",
        """                credential.as_ref(),
                self.provenance.as_ref(),
            )
            .await
            .map_err(""",
        """                credential.as_ref(),
                self.provenance.as_ref(),
            )
            .await
            .map(|reply| serde_json::json!({
                "reply": reply,
                "auth": credential.as_ref().map(|c| c.expose()),
            }))
            .map_err(""",
    ),
    # An issuer that ignores the RFC 8707 `resource` parameter hands back a token
    # the peer can spend elsewhere. Taking the issuer at its word about the
    # audience defeats the binding entirely.
    "IssuerAudienceTrusted": (
        "src/peers/credentials.rs",
        "a_token_bound_to_the_wrong_audience_is_refused",
        "the issuer is trusted about which audience it bound a token to",
        "    if credential.audience() != audience {",
        "    if false && credential.audience() != audience {",
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
    "APeerCallSkipsTheGrantScope": (
        "src/peers/mod.rs",
        "a_capability_outside_the_peers_grant_never_leaves",
        "a call for a capability the registry never granted the peer leaves "
        "anyway, to be refused by the peer's admission after a round trip",
        "        if !grant.scope.permits(&Capability::new(capability.as_str())) {",
        "        if false {",
    ),
    "APeerRouterDialsAnyPeer": (
        "src/peers/mod.rs",
        "a_peer_router_reaches_only_the_peers_it_routes",
        "an unrouted peer is sent to whichever endpoint the router holds first",
        "        self.routes.get(peer).ok_or_else(|| PeerError::Unreachable {",
        "        self.routes.values().next().ok_or_else(|| PeerError::Unreachable {",
    ),
    "ADeclaredPeerGrantIgnoresItsFields": (
        "src/runtime/ctx.rs",
        "a_declared_peer_grants_protected_fields_govern_the_hop",
        "the manifest grant's protected fields and ceiling never reach the peer "
        "call, so a model-chosen value fills an authority-bearing field on a hop",
        "                Some(safety) => call.governed_by(safety),",
        "                Some(_) => call,",
    ),
    "ADeclaredPeerGrantGoesToTheRouter": (
        "src/runtime/declarative.rs",
        "a_declared_peer_grant_dispatches_to_the_peer_and_replay_calls_nobody",
        "a grant naming a registered peer is dispatched as a tool call, which "
        "extends no chain, counts against no delegation ceiling, and reaches "
        "a router that knows no such server",
        "                if let Some(peer) = cx.peer_named(&id.server) {\n"
        "                    match cx.call_peer(&peer, &id.tool, &args).await {",
        "                if let Some(peer) = cx.peer_named(&id.server).filter(|_| false) {\n"
        "                    match cx.call_peer(&peer, &id.tool, &args).await {",
    ),
    "AGovernedSkillCallsAnyPeer": (
        "src/runtime/ctx.rs",
        "a_governed_skill_cannot_call_a_peer_its_manifest_never_granted",
        "a governed skill may call a peer its manifest never granted — the "
        "registry alone decides, and the reviewed document says nothing",
        "                manifest.tool_grant(&reference).is_none().then(|| {",
        "                manifest.tool_grant(&reference).is_none().then(|| None::<String>).flatten().map(|_| {",
    ),
    "APeerGrantOutsideScopeBuilds": (
        "src/runtime/executor.rs",
        "a_peer_grant_the_plane_cannot_honour_refuses_the_build",
        "a manifest grant naming a capability the registry never gave the peer "
        "builds, and is refused by the peer's admission on every run",
        "                        if !peer_grant.scope.permits(&Capability::new(id.tool.as_str())) {",
        "                        if false {",
    ),
    "APeerNamedLikeAToolServerBuilds": (
        "src/runtime/executor.rs",
        "a_peer_grant_the_plane_cannot_honour_refuses_the_build",
        "one name is both a peer and a tool server, and a grant on it means "
        "whichever the runtime checks first",
        "            if servers.iter().any(|(server, _)| server == name)\n"
        "                || tools\n"
        "                    .as_ref()\n"
        "                    .is_some_and(|t| t.servers().any(|s| s == name))\n"
        "            {",
        "            if false {",
    ),
    "HopDoesNotAttenuate": (
        "src/peers/mod.rs",
        "a_grant_wider_than_the_caller_is_refused",
        "a peer hop passes the caller's authority through unchanged",
        """        let acting_as = caller
            .delegate(Principal::new(peer.to_string(), grant.scope.clone()))
            .map_err(|source| PeerError::Delegation {
                peer: peer.clone(),
                source: Box::new(source),
            })?;""",
        "        let acting_as = caller.clone();",
    ),
    # Publishing the caller's chain in the message metadata. A receiver cannot
    # verify a chain it reads from a body, so the only correct use of the field
    # is to discard it — and a field published under this crate's own extension
    # whose correct use is to be discarded is one a third-party implementer
    # authorizes on instead. The chain crosses in the credential.
    "TheChainIsPublishedOnTheWire": (
        "src/peers/a2a.rs",
        "the_chain_does_not_travel_in_the_message",
        "the caller's delegation chain is published in the message metadata, where no receiver can verify it and a careless one will authorize on the sender's own claim about its authority",
        '        governance.insert("capability".into(), json!(capability));',
        '        governance.insert("capability".into(), json!(capability));\n        governance.insert("chain".into(), json!(acting_as));',
    ),
    # One sentence for every halt scope. Three scopes name a workload and close
    # admission; `subject:` names an authority and pauses runs already
    # executing. Collapsing them tells somebody who withdrew a credential to
    # cancel, which unwinds the completed work the withdrawal preserved — the
    # predicate exists on the type precisely so this is derived, not restated.
    "AWithdrawalRepeatsTheWorkloadSentence": (
        "src/api/mod.rs",
        "a_withdrawal_says_it_reaches_the_work_a_workload_halt_leaves_running",
        "every halt scope reads back the same sentence about its reach, so an operator who withdrew a credential is told the stop does not reach running work and to cancel instead — unwinding a week of correct work the withdrawal deliberately left standing",
        "    let reach = if scope.withdrawn_subject().is_some() {",
        "    let reach = if scope.withdrawn_subject().is_none() {",
    ),
    # The audit reports warrants and drops the runs that have none. A run with
    # no `RunAdmitted` then appears in neither list, so *what authorized this*
    # is a question the report silently leaves some runs out of — and the runs
    # it leaves out are exactly the ones nothing authorized.
    "UnadmittedRunsAreNotReported": (
        "src/audit.rs",
        "every_verified_run_is_warranted_or_reported_as_unadmitted",
        "an audit lists the runs it found a warrant for and says nothing about the rest, so a verified run that nothing admitted is indistinguishable from one the report simply did not reach",
        "        unadmitted,\n",
        "        unadmitted: Vec::new(),\n",
    ),
    # A protected field's path stops resolving — a renamed field, a catalogue
    # written against a shape the tool moved on from. The rule still parses and
    # matches nothing, so the gate either refuses or waves the call through with
    # the authority-bearing argument ungoverned. Removing the resolution check
    # makes an unresolvable path inherit the nearest ancestor's label instead.
    "AnUnresolvableProtectedPathGuardsNothing": (
        "src/core/label.rs",
        "a_protected_path_that_matches_no_field_refuses_the_call",
        "a protected field whose path matches nothing in the value is treated as present and inherits a label from an ancestor, so a rule that named a renamed field silently guards nothing and the call goes out ungoverned",
        "        self.value.pointer(path)?;",
        "        // self.value.pointer(path)?;",
    ),
    # The same path question on the release side. Without field lineage the
    # runtime cannot improve one field, so falling back would let a narrow
    # reviewed release launder the whole model-produced body.
    "AReleaseWithoutFieldLineageIsAccepted": (
        "src/core/label.rs",
        "a_release_naming_a_field_the_value_lacks_is_refused",
        "a field-scoped release whose path matches nothing is accepted, so a release granted over one reviewed field claims precision the runtime does not have and improves a value it never tracked",
        "            .any(|path| !self.fields.contains_key(path) || self.value.pointer(path).is_none())",
        "            .any(|_path| false)",
    ),
    # The runtime reads the peer's window, schedules from it, and writes none of
    # it down. `EffectFailed` then says a call was throttled without saying
    # whether the peer wanted forty milliseconds or two hours — the difference
    # between a run worth resuming shortly and one that should be parked.
    "TheNamedRetryWindowIsNotRecorded": (
        "src/core/error.rs",
        "the_window_a_peer_named_is_on_the_record",
        "a throttled effect records that it was rate limited and not the window the peer named, so the one fact that decides whether the run is worth resuming soon is consumed by the schedule and never written down",
        '''            format!("effect rate limited: {detail} (the peer asked for {window:?})")''',
        '''            format!("effect rate limited: {detail}")''',
    ),
    # The acting declaration never reaches a step, so no effect gate can name
    # the revision. Admission refuses the agent's name as a principal and tells
    # rules to bind to `context.agent.digest`; at an effect that name *is* the
    # principal, so without this a deployment can say which revision may start
    # and not which may reach a sink.
    "AnEffectGateCannotNameTheRevision": (
        "src/runtime/executor.rs",
        "an_effect_rule_can_bind_to_the_acting_revision",
        "the declaration never reaches a step, so every effect gate authorizes under an agent name any manifest can claim and no rule can bind to the revision that is actually acting",
        "            declaration: manifest.as_deref().and_then(|m| self.identity_of(m)),",
        "            declaration: None,",
    ),
    # The export stops saying what it never carries. A restored plane's runs and
    # cases come back and the operational rows beside them do not, so an operator
    # reading a clean report with no statement concludes the restore was total —
    # and goes looking for a webhook subscriber's missing deliveries as a fault.
    "TheExportHidesWhatItCannotCarry": (
        "src/export.rs",
        "an_export_names_the_operational_state_it_cannot_carry",
        "a verified export says nothing about the operational state it structurally cannot carry, so a clean report reads as a total restore and the rows that did not survive are discovered as faults later",
        "        .extend(UNCARRIED.iter().map(|limit| (*limit).to_owned()));",
        "        .extend(UNCARRIED.iter().take(0).map(|limit| (*limit).to_owned()));",
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
    # Doubles fall back to serde_json's formatting — `1e30` where RFC 8785
    # says `1e+30` — so a signed Agent Card carrying a number verifies against
    # this crate and is rejected by every conforming verifier. The divergence
    # is invisible to any test whose numbers happen to agree under both rules,
    # which is most of them.
    "DoublesFallBackToSerde": (
        "src/core/canon.rs",
        "canonical_bytes_carry_rfc_8785_numbers",
        "doubles are written by serde_json instead of ECMAScript's rules, so "
        "canonical bytes disagree with every conforming JCS implementation "
        "exactly where the two formatters differ",
        """    if let Value::Number(n) = value
        && n.is_f64()
    {""",
        """    if let Value::Number(n) = value
        && n.is_f64()
        && false
    {""",
    ),
    # The exponent loses its mandatory sign — which is serde_json's own form,
    # so the mutated output is precisely the plausible-looking wrong answer
    # that survived here for as long as the number rules went unimplemented.
    "AnExponentDropsItsSign": (
        "src/core/canon.rs",
        "doubles_format_per_rfc_8785",
        "a positive exponent is written without the sign ECMAScript mandates, "
        "producing serde_json's `1e21` where the standard and every "
        "conforming verifier write `1e+21`",
        """        out.push(if e < 0 { b'-' } else { b'+' });""",
        """        if e < 0 {
            out.push(b'-');
        }""",
    ),
    # Card signing stops walking the payload for integers no double can hold,
    # so a deployment's extension params can put 2^53+1 into a signed card —
    # this crate signs exact bytes, a conforming verifier recomputes rounded
    # ones, and each side is correct under its own reading.
    "AnUnrepresentableIntegerIsSigned": (
        "src/peers/card_sig.rs",
        "a_card_with_an_integer_beyond_double_precision_is_refused_at_signing",
        "the card signer no longer refuses integers outside ±2^53, so a "
        "signature is taken over bytes a conforming JCS verifier will not "
        "reproduce",
        """    representable(&value, "")?;""",
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
        "        let stripped = without_nulls(r.context.clone(), &mut removed);",
        "        let stripped = r.context.clone();",
    ),
    "AnAbsentPublisherIsNull": (
        "src/policy/requests.rs",
        "a_declared_agent_sends_no_null_either",
        "an unpublished manifest's absent publisher is sent as a JSON null "
        "rather than omitted, which is the shape the adapter's own "
        "documentation calls 'absent' and the shape Cedar cannot parse",
        '    if let Some(value) = id\n'
        '        .publisher\n'
        '        .as_ref()\n'
        '        .and_then(|p| serde_json::to_value(p).ok())\n'
        '    {\n'
        '        agent["publisher"] = value;\n'
        "    }",
        '    agent["publisher"] =\n'
        '        serde_json::to_value(&id.publisher).unwrap_or(serde_json::Value::Null);',
    ),
    "CedarErrorsReadAsRefusals": (
        "src/policy/cedar.rs",
        "a_policy_that_fails_to_evaluate_is_reported_as_broken_not_as_a_refusal",
        "a policy that cannot evaluate is reported as an ordinary refusal",
        "            cedar_policy::Decision::Deny if !errors.is_empty() => {",
        "            cedar_policy::Decision::Deny if false => {",
    ),
    "CapabilityReadsAsSubject": (
        "src/policy/cedar.rs",
        "a_subject_rule_does_not_match_a_capability_of_the_same_name",
        "a chainless run's capability and a chain subject share one Cedar entity "
        "type, so a rule granting the person `alice` admits every run of a "
        "capability someone named `alice`",
        "        let principal = uid(r.principal_kind.entity_type(), r.principal)?;",
        '        let principal = uid("Subject", r.principal)?;',
    ),
    "RatePruneFollowsTheReservation": (
        "src/quota/mod.rs",
        "redb_satisfies_the_quota_store_contract",
        'the reservation prunes rate rows older than one minute instead of older than the widest window any declaration may state, so the rows an hourly ceiling counts are deleted after sixty seconds and it admits like a per-minute one',
        '    rate_window_start(at.unix_timestamp(), MAX_RATE_WINDOW_SECONDS)',
        '    rate_window_start(at.unix_timestamp(), 60)',
    ),
    "ACodeBuiltRateWindowOutlivesItsRows": (
        "src/quota/mod.rs",
        "redb_satisfies_the_quota_store_contract",
        'a ceiling built in code with a window wider than a store keeps its rows is counted, so it sees only what retention left and admits more than it states',
        '        .find(|c| c.window_seconds == 0 || c.window_seconds > MAX_RATE_WINDOW_SECONDS)',
        '        .find(|c| c.window_seconds == 0)',
    ),
    "ARateWindowOutlivesItsRows": (
        "src/manifest/mod.rs",
        "a_rate_ceiling_that_admits_nothing_is_refused",
        'a rate window longer than a store keeps the count parses, so the ceiling counts only the rows retention left and admits more than it states',
        '                || rate.window_seconds > crate::quota::MAX_RATE_WINDOW_SECONDS',
        '                || rate.window_seconds > crate::core::MAX_WINDOW_SECONDS',
    ),
    "ABroadcastIgnoresTheWaitsSender": (
        "src/store/redb_events.rs",
        "redb_satisfies_the_case_layer_contracts",
        "an arriving event is matched to a wait that names another sender, so any producer knowing the kind and the correlation key consumes another run's wait",
        '                if from.is_some_and(|from| from != source) {',
        '                if false {',
    ),
    "ABufferedEventIgnoresTheWaitsSender": (
        "src/store/redb_events.rs",
        "redb_satisfies_the_case_layer_contracts",
        'a registering wait claims a buffered event from a sender it does not accept, so a producer that answers first consumes the wait',
        '                            && wait.accepts_source(&row.5)',
        '                            && true',
    ),
    "ATargetedEventIgnoresTheWaitsSender": (
        "src/store/redb_events.rs",
        "redb_satisfies_the_case_layer_contracts",
        'a targeted delivery resumes a wait that names another sender, so the one path that names the run bypasses the sender the run asked for',
        '                        && from.is_none_or(|from| from == source)',
        '                        && true',
    ),
    "ABufferedEventNeverReachesANamedWait": (
        "src/store/redb_events.rs",
        "redb_satisfies_the_case_layer_contracts",
        'a wait naming its sender never claims a buffered event, even the sender\'s own, so a reply that arrived first leaves the run waiting for something that already happened',
        '                            && wait.accepts_source(&row.5)',
        '                            && wait.from.is_none()',
    ),
    "ATargetedEventNeverReachesANamedWait": (
        "src/store/redb_events.rs",
        "redb_satisfies_the_case_layer_contracts",
        'a targeted delivery never resumes a wait naming its sender, even from that sender, so every sender-named A2A continuation is refused as not waiting',
        '                        && from.is_none_or(|from| from == source)',
        '                        && from.is_none()',
    ),
    "PostgresBroadcastIgnoresTheWaitsSender": (
        "src/store/postgres_cases.rs",
        "postgres_satisfies_the_case_layer_contracts",
        "an arriving event is matched to a wait that names another sender, so any producer knowing the kind and the correlation key consumes another run's wait",
        '                        AND (from_source IS NULL OR from_source = $5)',
        '                        AND (from_source IS NULL OR TRUE)',
    ),
    "PostgresBufferedEventIgnoresTheWaitsSender": (
        "src/store/postgres_cases.rs",
        "postgres_satisfies_the_case_layer_contracts",
        'a registering wait claims a buffered event from a sender it does not accept, so a producer that answers first consumes the wait',
        '                             AND ($7::TEXT IS NULL OR e.source = $7)',
        '                             AND ($7::TEXT IS NULL OR TRUE)',
    ),
    "PostgresTargetedEventIgnoresTheWaitsSender": (
        "src/store/postgres_cases.rs",
        "postgres_satisfies_the_case_layer_contracts",
        'a targeted delivery resumes a wait that names another sender, so the one path that names the run bypasses the sender the run asked for',
        '                    AND (from_source IS NULL OR from_source = $4)',
        '                    AND (from_source IS NULL OR TRUE)',
    ),
    "AnOlderSubscriptionsTableLacksTheSender": (
        "src/store/postgres_cases.rs",
        "postgres_an_older_subscriptions_table_gains_the_sender_at_open",
        'a subscriptions table an older build created opens without from_source, and the first wait that names its sender fails at the database instead of at open',
        'ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS from_source TEXT;',
        '-- no from_source column',
    ),
    "AnOldSubscriptionRowOpens": (
        "src/store/redb_events.rs",
        "a_store_with_the_old_subscription_row_refuses_to_open",
        'the subscriptions table is not opened at store open, so a file holding the older row shape opens and fails only at the first wait or delivery',
        '    w.open_table(SUBS).map_err(|e| be(&e))?;',
        '    let _ = SUBS;',
    ),
    "ADeadlineOfNoTimeResolves": (
        "src/core/calendar.rs",
        "the_built_in_calendar_satisfies_the_contract",
        'a count of zero or less resolves to the registration instant or before it, so an obligation is breached before anybody is warned',
        '            .filter(|n| *n > 0)',
        '            .filter(|n| *n > i64::MIN)',
    ),
    "AnOversightDeadlineOfNoTimeParses": (
        "src/manifest/mod.rs",
        "an_oversight_deadline_counts_at_least_one_unit",
        'a declared deadline of zero or negative units parses, and every run registers an obligation already due',
        '            Some(n) if n.as_i64().is_none_or(|n| n <= 0) => Err(ManifestError::Syntax(format!(',
        '            Some(n) if false && n.as_i64().is_none_or(|n| n <= 0) => Err(ManifestError::Syntax(format!(',
    ),
    "AJudgeCountsTwice": (
        "src/core/quorum.rs",
        "a_lens_judged_twice_is_refused",
        "one lens's verdict is counted as often as it is repeated, so a single judge reaches a quorum meant for three",
        '            if !seen.insert(*lens) {',
        '            if !seen.insert(*lens) && false {',
    ),
    "ADeserializedReleaseSkipsValidation": (
        "src/core/label.rs",
        "a_deserialized_release_is_validated",
        'a release read from a journal or a wire is not validated, so one with no fields reads as a successful no-op and one with no evidence is recorded as a decision',
        '        release.validate().map(|()| release)',
        '        Ok(release)',
    ),
    "AnErasureLeavesTheIndex": (
        "src/memory/indexed.rs",
        "an_erasure_reaches_the_semantic_index",
        'forgetting a subject leaves its embeddings in the semantic index, where a vector hidden from search is still reconstructible content',
        '        self.tell(vec![Forgotten::Subject(subject.to_owned())])\n            .await?;',
        '        let _ = Forgotten::Subject(subject.to_owned());',
    ),
    "AForgottenIdLeavesTheIndex": (
        "src/memory/indexed.rs",
        "an_erasure_reaches_the_semantic_index",
        'forgetting one memory leaves its embedding in the semantic index, where a vector hidden from search is still reconstructible content',
        '        self.tell(vec![Forgotten::Ids(vec![id.to_owned()])]).await',
        '        Ok(())',
    ),
    "ACascadeLeavesTheIndex": (
        "src/memory/indexed.rs",
        "an_erasure_the_index_missed_is_delivered_by_the_next_one",
        'a cascading erasure removes rows and never tells the index, so every derivative it erased keeps its embedding',
        '        self.tell(forgotten).await?;\n        Ok(cascade)',
        '        let _ = forgotten;\n        Ok(cascade)',
    ),
    "AnExpirySweepLeavesTheIndex": (
        "src/memory/indexed.rs",
        "the_expiry_sweep_reaches_the_semantic_index",
        'the expiry sweep removes rows and never tells the index, so every expired memory keeps its embedding',
        '        self.tell(forgotten).await?;\n        Ok(swept)',
        '        let _ = forgotten;\n        Ok(swept)',
    ),
    "WhatTheIndexMissedIsDropped": (
        "src/memory/indexed.rs",
        "an_erasure_the_index_missed_is_delivered_by_the_next_one",
        'an erasure the index refused is forgotten with the call, and since the rows are gone no retry finds it again, so the embedding stays for good',
        '        let mut owed = self.owed.lock().await;',
        '        let mut owed = Vec::new();',
    ),
    "TheSweepLeavesTheIndex": (
        "src/runtime/executor.rs",
        "the_expiry_sweep_reaches_the_semantic_index",
        "the plane's memory is not wrapped when a semantic index is wired, so the expiry sweep erases items and leaves their vectors",
        "                None => Arc::new(crate::memory::IndexedMemoryStore::new(\n                    Arc::clone(&memories),\n                    Arc::clone(&semantic.retriever),\n                )),",
        "                None => memories,",
    ),
    "AnEmbeddingIsFree": (
        "src/runtime/effects.rs",
        "an_embedding_counts_against_the_token_ceiling",
        'an embedding reports no spend, so no token or money ceiling binds on the calls a semantic tier makes',
        '        output.usage.spend()',
        '        crate::core::Spend::default()',
    ),
    "AnUnpricedEmbedderUnderAMoneyCeiling": (
        "src/runtime/executor.rs",
        "an_unpriced_embedder_is_refused_beside_a_money_ceiling",
        'a plane caps money beside an embedder with no price, so every embedding reports no cost and the ceiling never binds on them',
        '            if semantic.embedder.pricing().is_none() && self.states_a_money_ceiling() {',
        '            if semantic.embedder.pricing().is_none() && self.states_a_money_ceiling() && false {',
    ),
    "AGeminiIntakeRefusalIsFree": (
        "src/model/gemini.rs",
        "gemini_a_stream_past_the_ceiling_reports_what_it_burned",
        'a stream refused at the intake ceiling drops the usage its chunks already reported, so a token ceiling counts nothing for a call that generated',
        '                return Err(super::wire::classify_intake(model, usage, &e));',
        '                return Err(super::wire::classify_intake(model, Usage::default(), &e));',
    ),
    "AGeminiResultLosesItsCallId": (
        "src/model/gemini.rs",
        "gemini_answers_a_provider_identified_call_under_its_id",
        'a function result omits the id of the call the provider issued, so parallel calls to one function cannot be told apart',
        '                    if !is_synthesized_id(&e.call.name, &e.call.id) {',
        '                    if false {',
    ),
    "TheAuthBatteryUnwindsWithIt": (
        "src/testkit/conformance_auth.rs",
        "the_auth_battery_records_a_panicking_authenticator",
        "an authenticator that panics is not recorded, so the battery's doc claims a check it never makes",
        '    if answer.is_err() {',
        '    if false {',
    ),
    "TheAuthBatterySendsNoMalformedHeader": (
        "src/testkit/conformance_auth.rs",
        "the_auth_battery_records_a_panicking_authenticator",
        'the battery never sends a malformed credential, so an authenticator that indexes a missing token passes it',
        '    a_malformed_header_is_refused(auth, report).await;',
        '    let _ = a_malformed_header_is_refused;',
    ),
    "CedarBundleIgnoresRules": (
        "src/policy/cedar.rs",
        "the_digest_follows_the_policy_text",
        "the policy bundle identity does not depend on the rules",
        "PolicyBundleIdentity::new(Digest::of(source.as_bytes()), evaluator_semantics())",
        "PolicyBundleIdentity::new(Digest::ZERO, evaluator_semantics())",
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
    "CedarBundleEvaluatorIsCopiedNotRead": (
        "src/policy/cedar.rs",
        "the_evaluator_identity_is_the_linked_cedar_language_version",
        "a journaled bundle names an evaluator the build is not running",
        "PolicyBundleIdentity::new(Digest::of(source.as_bytes()), evaluator_semantics())",
        "PolicyBundleIdentity::new(Digest::of(source.as_bytes()), \"cedar-lang/4.4.0;agentplane-adapter/4;extensions=all-available\")",
    ),
    "AnUnreachableRuleCompiles": (
        "src/policy/cedar.rs",
        "a_rule_that_can_never_fire_is_refused_at_construction",
        "a forbid no request can satisfy compiles into a bundle an operator reads as a limit",
        "                if let Some(rule) = first_unreachable(&policies, &validation) {",
        "                if let Some(rule) = Option::<String>::None {",
    ),
    "ADurableDigestDomainLeavesTheEnumeration": (
        "src/core/calendar.rs",
        "every_versioned_crypto_domain_is_enumerated_and_at_version_one",
        "a versioned digest domain on a record moves with nothing naming the list it left",
        "Digest::of(b\"agentplane.calendar.wallclock.v1\")",
        "Digest::of(b\"agentplane.calendar.wallclock.v2\")",
    ),
    "ResumeIgnoresPolicyBundleDrift": (
        "src/runtime/executor.rs",
        "an_open_run_refuses_to_resume_under_a_different_policy_bundle",
        "an open run resumes under policy semantics other than those recorded at admission",
        "        if recorded != configured {",
        "        if false && recorded != configured {",
    ),
    "DeclarationDriftResumes": (
        "src/runtime/executor.rs",
        "an_edited_declaration_is_refused_before_the_resume_replays",
        "an open run resumes under an edited declaration, so one program "
        "continues another's journal and the difference surfaces, if at all, "
        "as two digests several effects in",
        "        if configured != recorded.digest {",
        "        if false && configured != recorded.digest {",
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
    "AnEffectRefusalReplaysVerbatimOnResume": (
        "src/runtime/ctx.rs",
        "an_effect_limited_run_resumes_under_a_raised_ceiling_and_not_under_the_same_one",
        "a recorded effect-level budget refusal is re-raised verbatim on resume "
        "instead of being re-asked against the ledger now in force, so a run "
        "exhausted by max_effects stays exhausted under a ceiling that now "
        "admits it — the step-level twin resumes, this tier never does",
        """        if !self.writes_enabled() {
            return Err(recorded_refusal(EffectReplay::Refused { limit, used }));
        }""",
        """        if true {
            return Err(recorded_refusal(EffectReplay::Refused { limit, used }));
        }""",
    ),
    "AMidPrefixRefusalIsReadmitted": (
        "src/runtime/ctx.rs",
        "a_refusal_a_group_abort_already_answered_is_not_readmitted",
        "a budget refusal inside the replayed prefix — one a group abort "
        "already answered, with the reversals and settlement recorded after "
        "it — is re-admitted under a raised ceiling, dispatching the member "
        "where history holds the abort: divergence and a quarantine "
        "manufactured out of an operator's raise",
        """        if !self.writes_enabled() {
            return Err(recorded_refusal(EffectReplay::Refused { limit, used }));
        }
        // Asked without taking the slot""",
        """        if self.mode == Mode::Strict {
            return Err(recorded_refusal(EffectReplay::Refused { limit, used }));
        }
        // Asked without taking the slot""",
    ),
    "AReadmittedRefusalStillStopsAStrictReplay": (
        "src/journal/replay.rs",
        "an_effect_limited_run_resumes_under_a_raised_ceiling_and_not_under_the_same_one",
        "a recorded re-admission no longer supersedes the refusal beside it, so "
        "a strict replay of the resumed history stops at the stale refusal and "
        "reports Exhausted about a run whose own later records show it "
        "finishing — refusal-then-continuation read as divergence",
        """            RecordKind::BudgetReadmitted { .. } => {
                if let Some(pos) = self
                    .effects
                    .iter()
                    .rposition(|e| e.key == key && matches!(e.replay, EffectReplay::Refused { .. }))
                {
                    self.effects.remove(pos);
                }
            }""",
        """            RecordKind::BudgetReadmitted { .. } => {}""",
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
    "ARedeclaredStepCountsAsDone": (
        "src/runtime/executor.rs",
        "a_successor_may_not_redeclare_a_completed_step",
        "a successor may keep a completed step's capability under new "
        "arguments, dependencies or flags, and since `done` is by id the new "
        "node counts as done — a terminal verifier moved behind new work "
        "completes the run without ever seeing what it verifies",
        "            if node != node_ran {",
        "            if false {",
    ),
    "AStartedStepIdIsReused": (
        "src/runtime/executor.rs",
        "a_successor_may_not_reuse_the_id_of_a_step_that_started",
        "the reuse check covers only completed steps, so a successor puts other "
        "work at the id of a step that charged and then asked to replan — the "
        "new work runs over the charge's keys and the charge is never undone",
        "            if resolved.as_deref() != Some(skill.as_str()) {",
        "            if false {",
    ),
    "AnInterruptedStepIsNotUndoneAsWhatRan": (
        "src/runtime/executor.rs",
        "a_charge_that_asked_to_replan_is_undone_when_the_successor_drops_it",
        "a step that landed a mutation and asked to replan is not resolved from "
        "the skill its StepStarted names, so when the successor drops it the "
        "unwind finds nothing to undo and the charge stays standing",
        "            if let Some(skill) = started.get(step) {",
        "            if let Some(skill) = started.get(step).filter(|_| false) {",
    ),
    "ASuccessorWithoutAReasonIsFrozen": (
        "src/runtime/executor.rs",
        "a_successor_without_a_reason_is_rejected",
        "a successor carrying no reason is frozen into the journal — a plan "
        "that replaced another with nothing on the record saying why, losing "
        "the half of an incident versioned replanning exists to keep",
        "        if next.reason.as_deref().is_none_or(str::is_empty) {",
        "        if next.reason.as_deref().is_none_or(str::is_empty) && false {",
    ),
    # ── Blob erasure units ──────────────────────────────────────────────────
    "AnErasureUnitDoesNotLeadTheAddress": (
        "src/blob/scoped.rs",
        "erasing_a_case_leaves_other_cases_alone",
        "the storage address drops the erasure unit, so two cases of one "
        "tenant holding identical bytes hold one object — and one case's "
        "erasure tombstones the other's data while the drill reads the loss "
        "as erased by design, the verdict that pages nobody",
        """    bytes.extend_from_slice(&(scope.len() as u64).to_be_bytes());
    bytes.extend_from_slice(scope.as_bytes());""",
        """    let _ = scope;""",
    ),
    "AnUnknownCaseErasesToZero": (
        "src/blob/mod.rs",
        "erasing_an_unknown_case_is_not_found",
        "an erasure naming a case this plane never held answers `Ok(0)` — the "
        "same answer as a matter that stored nothing and was erased — so a "
        "mistyped id closes the request while the real matter stays untouched",
        """    if found.is_none() {""",
        """    if false {""",
    ),
    "AnErasureExpiresTheBareDigest": (
        "src/blob/mod.rs",
        "erasing_a_case_leaves_other_cases_alone",
        "case erasure tombstones the bare content digest instead of the "
        "case's own unit address, so the tombstones land where nothing was "
        "written — the erasure reports success and this case's copies stay "
        "readable",
        """            blobs
                .expire(unit_address(&scope, digest), at, reason)
                .await?;""",
        """            blobs.expire(digest, at, reason).await?;""",
    ),
    "TheDrillReadsBesideTheDeployment": (
        "src/drill.rs",
        "the_drill_tells_erasure_from_loss",
        "the drill reads the bare store at bare content digests instead of "
        "the per-case handle the plane wrote through, so on a sealed "
        "deployment every intact artifact reports as missing or corrupt — "
        "false alarms that teach operators the real one is noise",
        """                let scope = crate::core::erasure_scope(stores.tenant, &case.id.to_string());
                let scoped: Arc<dyn BlobStore> = Arc::new(crate::blob::ScopedBlobs::new(
                    Arc::clone(blobs),
                    scope.clone(),
                ));""",
        """                let scope = crate::core::erasure_scope(stores.tenant, &case.id.to_string());
                let _ = &scope;
                let scoped: Arc<dyn BlobStore> = Arc::clone(blobs);""",
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
            // Refused, and it is the plane that is broken rather than the
            // request: 500 rather than 403, because 403 tells an operator to
            // fix their credentials and this one is fixed in the policy set.
            PolicyDecision::Malformed { reason } => {
                // The engine's reason names rules, attributes and entity
                // types; it is the operator's, and the caller gets a sentence.
                tracing::error!(target: "agentplane::api", policy_error = true, reason, "the policy set could not be evaluated");
                Err(ApiError(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    POLICY_UNEVALUABLE.to_owned(),
                ))
            }
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
        """            let Some(policy) = plane.policy() else {
                return Err(ApiSetupError::NoPolicy);
            };""",
        """            let Some(policy) = plane.policy() else {
                continue;
            };""",
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
        "        .queue(&s.caller.roles, api.limit.saturating_add(1))",
        '        .queue(&["compliance-officer".to_owned()], api.limit.saturating_add(1))',
    ),
    "DecidableIgnoresExclusion": (
        "src/api/mod.rs",
        "the_worklist_says_which_items_this_caller_may_decide",
        "every worklist item claims this caller may decide it",
        "            decidable_by_you: task.may_decide(&caller.actor, &caller.roles),",
        "            decidable_by_you: true,",
    ),
    "AMistypedRunReadsAsAConflict": (
        "src/api/mod.rs",
        "a_mistyped_id_is_a_404_not_a_conflict",
        "cancelling a run id that names nothing answers 409 instead of 404, so "
        "an operator with a typo is told somebody else got there first and goes "
        "hunting for an interventionist who does not exist",
        """            crate::core::RuntimeError::Store(crate::core::StoreError::NotFound(_)) => {
                not_found("run")
            }""",
        """            crate::core::RuntimeError::Store(crate::core::StoreError::NotFound(e)) => {
                ApiError(StatusCode::CONFLICT, e)
            }""",
    ),
    "TheApiClaimsABasisItDidNotEstablish": (
        "src/api/mod.rs",
        "the_decision_is_recorded_under_the_authenticated_caller",
        "every decision is journaled as merely asserted, so the one surface "
        "that verified a credential records the same claim a terminal makes — "
        "an auditor reading an approval can no longer tell a name an identity "
        "provider vouched for from one somebody typed",
        """            crate::core::Operator::authenticated(s.caller.actor.clone())""",
        """            crate::core::Operator::asserted(s.caller.actor.clone())""",
    ),
    "AnExpiryIsFiledAsAPersonsAnswer": (
        "src/runtime/sweeper.rs",
        "an_expiry_may_not_be_filed_as_a_persons_answer",
        "the person's door accepts the policy's answer by inventing a name for "
        "it, so a claim, an eligibility check and a four-eyes exclusion all run "
        "against `system:expiry` — every control passes by having nothing to "
        "test, and the worklist records a decider who does not exist",
        """        let Some(by) = decision.decided.operator() else {""",
        """        let fabricated = crate::core::Operator::asserted("system:expiry")
            .expect("a constant name");
        let Some(by) = decision.decided.operator().or(Some(&fabricated)) else {""",
    ),
    "ADecideRefusalLosesItsClass": (
        "src/runtime/sweeper.rs",
        "a_mistyped_id_is_a_404_not_a_conflict",
        "the decide path flattens the claim protocol's refusals into a policy "
        "denial, so a task id that names nothing reads as 'you are not "
        "allowed' — the permanent answer for the transient mistake — and no "
        "surface downstream can tell a typo from a four-eyes exclusion",
        """        let claimed = tasks.claim(id, by.actor(), roles).await?;""",
        """        let claimed = tasks.claim(id, by.actor(), roles).await.map_err(|e| {
            RuntimeError::PolicyDenied(crate::core::PolicyError::Denied {
                principal: by.actor().to_owned(),
                action: "task/decide".into(),
                resource: format!("{id}: {e}"),
            })
        })?;""",
    ),
    "AnApprovalOfAnEditedTaskAuthorizes": (
        "src/runtime/ctx.rs",
        "an_approval_of_an_edited_task_does_not_authorize_the_original",
        "a decision is accepted whatever the reviewer was shown, so a task edited "
        "in the store between proposal and decision authorizes arguments nobody "
        "reviewed",
        """            && decision.reviewed != Some(spec_digest)""",
        """            && false""",
    ),
    "TheInitiatorMayApproveTheirOwnRun": (
        "src/runtime/ctx.rs",
        "the_caller_who_started_a_run_cannot_approve_it",
        "the caller who started a run is not excluded from deciding its tasks, so "
        "one person holding the approver role both asks and approves",
        """        let parties = self
            .initiator()
            .await?
            .into_iter()""",
        """        let parties = None::<String>
            .into_iter()""",
    ),
    "AnyRunMayDrawAnyAuthority": (
        "src/runtime/effects.rs",
        "a_run_acting_for_someone_else_cannot_draw",
        "a standing authority is drawn by any run that knows its id, so one "
        "customer's mandate pays for another's work",
        """                if self.holder.as_ref() == Some(&state.authority.holder) {""",
        """                if true {""",
    ),
    "AChainlessServedCallerDrawsTheTenantsMandate": (
        "src/authority/mod.rs",
        "a_tenant_mandate_is_drawn_only_by_the_planes_own_runs",
        "a run admitted for a served caller that presented no chain draws as "
        "the tenant, so any authenticated peer spends the deployment's own "
        "mandates",
        """        None if served_unchained => None,""",
        """        None if served_unchained => Some(Holder::Tenant),""",
    ),
    "AChainlessServedRunIsRecordedAsThePlanes": (
        "src/runtime/executor.rs",
        "a_tenant_mandate_is_drawn_only_by_the_planes_own_runs",
        "a run admitted for a chainless served caller is recorded like one the "
        "plane started for itself, so it draws on the tenant's mandates",
        """            served_unchained: matches!(acting_as, Acting::Nobody),""",
        """            served_unchained: false,""",
    ),
    "AnUntrustedAuthorityIdIsDrawn": (
        "src/runtime/ctx.rs",
        "an_authority_id_from_untrusted_data_is_refused",
        "an authority id taken from model or peer text is drawn like one the "
        "run's own code chose, so injected text picks whose money is spent",
        """        if id.label().is_untrusted() {""",
        """        if false {""",
    ),
    "ABatchItemIsTrustedByDefault": (
        "src/batch/mod.rs",
        "a_batch_item_is_admitted_untrusted_unless_its_source_vouches",
        "a batch item from a paged API or a file is admitted trusted, so an "
        "external row can steer control flow and fill trusted-only fields",
        """            Label::untrusted(crate::core::SourceId::new(format!("batch:{batch}")))""",
        """            Label::trusted()""",
    ),
    "AnUngovernedPlaneReleases": (
        "src/runtime/ctx.rs",
        "an_ungoverned_plane_refuses_a_release",
        "a plane with no policy engine permits every release, so any skill can "
        "lower a label below a ceiling nobody agreed to lift",
        """        let decision = self.policy.as_ref().map_or_else(
            || {
                crate::core::PolicyDecision::deny(
                    "this plane has no policy engine, and a release lowers a label \\
                     only when a rule permits it — wire one that permits `data:release`",
                )
            },
            |engine| engine.authorize(&request.as_request()),
        );""",
        """        let Some(engine) = self.policy.as_ref() else {
            return Ok(());
        };
        let decision = engine.authorize(&request.as_request());""",
    ),
    "PreflightAsksOnlyAReadWithoutALabel": (
        "src/runtime/executor.rs",
        "the_preflight_asks_a_mutating_call_without_a_label",
        "the build probes only a read with no label, so a rule that reads the "
        "label behind `context.mutates &&` passes the build and fails every "
        "mutating call it was written for",
        """            for (mutates, labelled) in [(false, false), (true, false), (false, true), (true, true)]""",
        """            for (mutates, labelled) in [(false, false)]""",
    ),
    "AnUnevaluablePolicyIsServedOverA2a": (
        "src/api/a2a.rs",
        "a_policy_set_this_surface_cannot_evaluate_is_not_served",
        "the A2A surface opens over a policy set that errors on its own "
        "requests, so every peer call is refused as malformed in production",
        """        if !problems.is_empty() {""",
        """        if false {""",
    ),
    "AChainlessPeersRunIsNeverProbed": (
        "src/api/a2a.rs",
        "a_rule_a_chainless_peers_run_cannot_evaluate_is_not_served",
        "the A2A surface opens over a policy set that cannot evaluate the "
        "runtime's requests for a peer acting under no chain, so every such "
        "peer is declined as malformed in production",
        """        problems.extend(runtime.served_policy_problems());""",
        """        problems.extend(Vec::<String>::new());""",
    ),
    "ATaskActionIsProbedWithoutItsOwner": (
        "src/api/a2a.rs",
        "a_rule_reading_the_owner_of_a_task_action_is_served",
        "the A2A preflight asks a cancel without the owner every cancel "
        "carries, so a rule set reading context.owner is refused at startup "
        "for a shape no request takes",
        """        (action::TASK_CANCEL, &owned),""",
        """        (action::TASK_CANCEL, &bare),""",
    ),
    "AnUnevaluablePolicyIsServedToOperators": (
        "src/api/mod.rs",
        "a_depth_cap_with_no_action_scope_is_refused_by_the_operator_api",
        "the operator API opens over a policy set that errors on its own "
        "requests, so every operator call is a 500 during the incident it was "
        "needed for",
        """            if !problems.is_empty() {""",
        """            if false {""",
    ),
    "AWithheldItemIsCountedAsExhausted": (
        "src/store/redb_batches.rs",
        "a_withheld_item_is_counted_as_withheld_and_keeps_the_batch_running",
        "a batch item paused under a withdrawn authority is tallied as an "
        "exhaustion, so the census sends an operator to raise a budget that is "
        "not why it stopped",
        "                        ItemOutcome::Withheld(_) => c.withheld += 1,",
        "                        ItemOutcome::Withheld(_) => c.exhausted += 1,",
    ),
    "AnEffectKeyIsNotDomainSeparated": (
        "src/core/id.rs",
        "effect_key_derivation_is_pinned_to_its_bytes",
        "the effect key is hashed with no domain tag, so the same bytes hashed "
        "for another purpose are indistinguishable from an effect's identity",
        "        h.update(EFFECT_KEY_DOMAIN);",
        "",
    ),
    "AStatuslessToolUpdateRegresses": (
        "src/observe/acp.rs",
        "a_tool_update_without_a_status_does_not_record_a_regression",
        "a tool call update carrying no status is recorded as pending, so a call "
        "the agent reported completed reads on the record as having gone back",
        """            if update.session_update == "tool_call_update" && update.status.is_none() {""",
        """            if false {""",
    ),
    "AnUndecodableProposalReadsAsErased": (
        "src/keyring/tasks.rs",
        "an_undecodable_proposal_is_not_reported_as_erased",
        "a sealed row whose bytes do not decode is reported as erased, so damage "
        "reads as an erasure somebody asked for",
        """                return Ok(Opening::Undecodable);""",
        """                return Ok(Opening::Erased);""",
    ),
    "ASealedRowIsJudgedByItsShape": (
        "src/keyring/tasks.rs",
        "an_undecodable_proposal_is_not_reported_as_erased",
        "the worklist opens every value shaped like an envelope, so clear "
        "arguments spelled like the marker read back withheld",
        """        if task.withheld != Some(Withheld::Sealed) {""",
        """        if false {""",
    ),
    "TheWorklistServesTheEnvelopeAsTheValue": (
        "src/core/task.rs",
        "a_withheld_proposal_is_served_as_withheld",
        "the worklist serves a withheld proposal's envelope as its "
        "`proposed_action`, a value a client renders as the arguments",
        """        if self.withheld.is_some() {
            shown.proposed_action = Value::Null;""",
        """        if false {
            shown.proposed_action = Value::Null;""",
    ),
    "TheRenderingShowsTheEnvelope": (
        "src/core/task.rs",
        "a_withheld_proposal_is_served_as_withheld",
        "the rendering a person reads shows a withheld proposal's envelope as if "
        "it were the arguments",
        """        let (proposed_action, evidence) = if self.withheld.is_some() {""",
        """        let (proposed_action, evidence) = if false {""",
    ),
    "TheTerminalPrintsTheEnvelope": (
        "src/bin/agentplane.rs",
        "the_terminal_shows_a_withheld_proposal_as_withheld",
        "`agentplane tasks` prints a sealed proposal's envelope as the arguments "
        "on a terminal that holds no key ring",
        """        "proposed_action": shown.proposed_action,""",
        """        "proposed_action": j.proposed_action,""",
    ),
    "AWithheldRefusalIsAConflict": (
        "src/api/mod.rs",
        "a_withheld_proposal_refuses_an_approval_with_its_own_status",
        "an approval refused because the proposal cannot be shown is answered 409, "
        "telling the decider they lost a race nobody ran",
        """            crate::core::RuntimeError::ProposalWithheld { .. } => {""",
        """            crate::core::RuntimeError::ProposalWithheld { .. } if false => {""",
    ),
    "AMarkerShapedArgumentIsWithheld": (
        "src/runtime/sweeper.rs",
        "an_argument_spelled_like_the_marker_is_approvable",
        "whether a proposal is withheld is read from its shape, so untrusted "
        "input spelling `{\"$sealed\": …}` makes a task nobody can approve",
        """            && let Some(reason) = current.as_ref().and_then(|task| task.withheld)""",
        """            && let Some(reason) = current.as_ref().and_then(|task| {
                task.withheld.or_else(|| {
                    crate::journal::payload::is_sealed(&task.justification.proposed_action)
                        .then_some(crate::core::Withheld::Sealed)
                })
            })""",
    ),
    "ASealedRunsTerminalDecisionIsLost": (
        "src/runtime/executor.rs",
        "a_proposal_this_plane_cannot_open_is_not_approved",
        "a decision recorded on a terminal holding no key ring for a sealed run "
        "fails after the record, so a rejection that needed no proposal is "
        "reported lost",
        """                RuntimeError::NoProvider { .. }
                | RuntimeError::NoCaseStore { .. }
                | RuntimeError::PayloadsSealed { .. },
            ) => {
                return Ok(Delivery::Buffered);""",
        """                RuntimeError::NoProvider { .. }
                | RuntimeError::NoCaseStore { .. },
            ) => {
                return Ok(Delivery::Buffered);""",
    ),
    "TheRenderingPassesInvisibleCodePoints": (
        "src/core/visible.rs",
        "every_surface_escapes_what_a_reviewer_cannot_see",
        "a right-to-left override or a tag character reaches the reviewer's "
        "rendering raw, so what they approve is not what they read",
        """        if is_hidden(c) {""",
        """        if false && is_hidden(c) {""",
    ),
    "AnEscapedTaskIsNotFlagged": (
        "src/core/task.rs",
        "the_terminal_escapes_what_a_reviewer_cannot_see",
        "a task whose text needed escaping does not say so, so a reviewer reads "
        "an escape sequence as the value's own text",
        """        self.escaped |= escaped;""",
        """        let _ = escaped;""",
    ),
    "AMixedScriptWordIsNotFlagged": (
        "src/core/visible.rs",
        "a_word_mixing_scripts_is_flagged",
        "a Latin payee with a Cyrillic letter in it is shown with no flag, so the "
        "homoglyph passes a reviewer unmarked",
        """    (seen.len() > 1).then_some(seen)""",
        """    (seen.len() > usize::MAX - 1).then_some(seen)""",
    ),
    "AnUnreadableProposalIsApproved": (
        "src/runtime/sweeper.rs",
        "a_proposal_this_plane_cannot_open_is_not_approved",
        "a plane that cannot open a sealed proposal records an approval of it "
        "anyway, so a terminal with no key approves arguments nobody was shown",
        """        if decision.approved
            && let Some(reason) = current.as_ref().and_then(|task| task.withheld)""",
        """        if false
            && let Some(reason) = current.as_ref().and_then(|task| task.withheld)""",
    ),
    "ACaseHistoryPageCannotSeePastItself": (
        "src/api/mod.rs",
        "a_case_history_of_exactly_the_limit_is_not_called_truncated",
        "the case view fetches exactly the limit instead of one more, so "
        "truncation is inferred from a full page and a matter one record past "
        "the limit reads as complete — records fell off the end and the "
        "response swears nothing did",
        """        .case_history(id, api.history.saturating_add(1))""",
        """        .case_history(id, api.history)""",
    ),
    "ACompleteCaseHistoryReadsAsTruncated": (
        "src/api/mod.rs",
        "a_case_history_of_exactly_the_limit_is_not_called_truncated",
        "a history of exactly the limit is reported truncated, so a complete "
        "record reads as a shortened one and whoever is reconstructing the "
        "matter goes looking for records that do not exist",
        """    let history_truncated = history.len() > api.history;""",
        """    let history_truncated = history.len() >= api.history;""",
    ),
    # ── KeySignature ─────────────────────────────────────────────────────────
    "AnAuditNeverSaysWhatAuthorized": (
        "src/audit.rs",
        "an_audit_reports_what_authorized_each_run",
        "the offline audit reports history as sound without ever saying what "
        "warranted it, so a run that executed with no policy engine configured "
        "at all verifies exactly as soundly as a governed one and an auditor "
        "reading `sound` concludes it was governed",
        "            Some(warrant) => warrants.push(warrant),",
        "            Some(_warrant) => {}",
    ),
    "AnAuditHidesWhatItSkipped": (
        "src/audit.rs",
        "an_audit_reports_what_it_could_not_look_at",
        "an audit that checked nothing reports itself as sound",
        "    if evidence.anchors.is_empty() {",
        "    if false {",
    ),
    "AnOpenRunAuditsAsDeleted": (
        "src/audit.rs",
        "a_missing_leaf_is_a_finding_only_for_a_sealed_conclusion",
        "any conclusion — including failed, which stays open for resume — is "
        "treated as sealed, so every healthy resumable run audits as an "
        "integrity finding: a false alarm on every pass, which is how the true "
        "alarm stops being believed",
        """    concluded_outcome(records).is_some_and(|o| crate::runtime::SEALED_OUTCOMES.contains(&o))""",
        """    concluded_outcome(records).is_some()""",
    ),
    "AMissingLeafAuditsAsSound": (
        "src/audit.rs",
        "a_missing_leaf_is_a_finding_only_for_a_sealed_conclusion",
        "a run whose own records carry a sealing conclusion but which the log "
        "holds no leaf for is reported sound — history the log no longer "
        "commits to, waved through by the audit that exists to name it",
        """    concluded_outcome(records).is_some_and(|o| crate::runtime::SEALED_OUTCOMES.contains(&o))""",
        """    concluded_outcome(records).is_some_and(|_| false)""",
    ),
    "AGroupUnsettledUnderASealIsNotAFinding": (
        "src/audit.rs",
        "a_sealed_run_with_an_unsettled_group_is_a_finding",
        "a sealed run holding an opened, never-settled group audits as sound — "
        "nothing may resume it, so whether the members were taken or taken "
        "back is permanently undecided, under a conclusion that claims the "
        "history is complete",
        """    if !has_sealing_conclusion(records) {
        return Vec::new();
    }""",
        """    if !records.is_empty() {
        return Vec::new();
    }""",
    ),
    "AnOpenRunsCrashShapeFlagsAsAFinding": (
        "src/audit.rs",
        "a_sealed_run_with_an_unsettled_group_is_a_finding",
        "an open run's unsettled group — the ordinary crash shape a resume "
        "repairs — is flagged beside the sealed one, a false alarm on every "
        "healthy resumable run, which is how the true alarm stops being "
        "believed",
        """    if !has_sealing_conclusion(records) {
        return Vec::new();
    }""",
        """    if records.is_empty() {
        return Vec::new();
    }""",
    ),
    "TheAuditIgnoresThePriorCheckpoint": (
        "src/audit.rs",
        "only_an_outside_checkpoint_detects_a_deletion",
        "an audit ignores the checkpoints the auditor brought, so deletion goes unseen",
        "    for anchor in evidence.anchors {",
        "    for anchor in std::iter::empty::<&Anchor>() {",
    ),
    "TheTreeIndexIsTheStoredIndex": (
        "src/store/redb.rs",
        "only_an_outside_checkpoint_detects_a_deletion",
        "a removed run still advances the tree position, so every later run's inclusion proof is off by one",
        "                let Some(seal) = seals.get(run_id.value()).map_err(|e| be(&e))? else {\n                    continue;\n                };\n                if let Some(slot) = wanted.get_mut(run_id.value()) {",
        "                let Some(seal) = seals.get(run_id.value()).map_err(|e| be(&e))? else {\n                    rank += 1;\n                    continue;\n                };\n                if let Some(slot) = wanted.get_mut(run_id.value()) {",
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
    "TheEmptyLogAcceptsAnyRoot": (
        "src/core/merkle.rs",
        "growth_from_the_empty_log_still_names_the_empty_root",
        "consistency from size 0 ignores the root it was given, so a "
        "checkpoint no log ever had verifies as the ancestor of one that "
        "does — and a witness cosigns growth from a tree it never saw",
        "        return proof.is_empty() && *old_root == empty_root();",
        "        return proof.is_empty();",
    ),
    "TheEmptyLogHashesToZero": (
        "src/core/merkle.rs",
        "an_empty_log_hashes_the_way_rfc_6962_says",
        "the empty tree's root is thirty-two zero bytes instead of "
        "RFC 6962's SHA-256 of the empty string — a value no conforming "
        "witness or verifier computes, and one an uninitialised buffer, a "
        "default-constructed struct and a truncated read all produce by "
        "accident",
        """        return empty_root();""",
        """        return Digest::ZERO;""",
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
    "AModelCallIsMeasuredByItsPrompt": (
        "src/model/mod.rs",
        "a_model_calls_tool_results_count_against_the_egress_ceiling",
        "the egress ceiling counts a model call's prompt alone, so every tool "
        "result, declaration and continuation it carries leaves uncounted",
        "        let request = crate::core::canon::to_bytes(&self.descriptor().args)",
        "        let request = crate::core::canon::to_bytes(&self.prompt)",
    ),
    "GrantedMediaCountsAsItsMarker": (
        "src/model/mod.rs",
        "a_granted_image_counts_at_its_encoded_size",
        "a granted image counts against the egress ceiling as the few dozen "
        "bytes of its marker, so a megabyte leaves under a kilobyte limit",
        "            let encoded = size.div_ceil(3).saturating_mul(4);",
        "            let encoded = size * 0;",
    ),
    "APricedModelReportsNoMoney": (
        "src/model/mod.rs",
        "a_money_ceiling_binds_on_a_priced_model",
        "a role's declared price is never applied, so every completion reports "
        "zero minor units and a money ceiling never binds on a model",
        "            usage.minor_units = pricing.price(&usage);",
        "            let _ = pricing;",
    ),
    "APriceRoundsDown": (
        "src/model/mod.rs",
        "pricing_splits_cached_input_and_rounds_up",
        "a price is rounded down, so a run of sub-cent calls is free against a "
        "money ceiling it exceeded",
        "        u64::try_from(micro.div_ceil(1_000_000)).unwrap_or(u64::MAX)",
        "        u64::try_from(micro / 1_000_000).unwrap_or(u64::MAX)",
    ),
    "AnUnpricedRoleCarriesAMoneyCeiling": (
        "src/manifest/mod.rs",
        "a_money_ceiling_beside_an_unpriced_model_is_refused",
        "a money ceiling is accepted beside a model role that states no price, "
        "so the reviewer approves a control that never binds on the agent's "
        "largest cost",
        "            if declared.as_ref().is_some_and(|r| r.pricing.is_none()) {",
        "            if declared.as_ref().is_some_and(|r| r.pricing.is_none() && false) {",
    ),
    "ADriversTimeoutRekeysEveryModelCall": (
        "src/model/anthropic.rs",
        "a_drivers_timeout_is_not_part_of_the_effect_identity",
        "how long the plane waits enters the effect key, so two deployments "
        "differing only in a timeout report divergence on every model call",
        """            "schema_mode": schema_mode,
            "stream": self.stream,
        })""",
        """            "schema_mode": schema_mode,
            "stream": self.stream,
            "timeout_ms": self.timeout.as_millis(),
        })""",
    ),
    "ARecallCutoffWindsBackRetention": (
        "src/runtime/ctx.rs",
        "a_recall_cutoff_in_the_past_does_not_resurrect_an_expired_memory",
        "a step that names a recall cutoff in the past reads memories whose "
        "retention has lapsed but that the sweep has not reached yet, so a "
        "retention period is a suggestion any skill can wind back",
        """        query.as_of = Some(query.as_of.map_or(now, |cutoff| cutoff.max(now)));""",
        """        query.as_of = Some(query.as_of.unwrap_or(now));""",
    ),
    "AMediaTimeoutRekeysEveryFetch": (
        "src/media/mod.rs",
        "policy_and_validator_identity_are_in_the_effect_key",
        "a media fetcher's timeout enters the effect key, so a patience change "
        "reports divergence on every replayed fetch",
        """            "max_header_bytes": self.max_header_bytes,""",
        """            "max_header_bytes": self.max_header_bytes,
            "timeout_ms": self.timeout.as_millis(),""",
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
        "        if !grants.contains_key(&(reference.digest, reference.media_type.clone())) {",
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
    "ATransportErrorQuotesItsUrl": (
        "src/netguard/mod.rs",
        "an_unreachable_delivery_does_not_quote_its_url",
        "a transport failure is rendered with reqwest's whole request URL, so a "
        "webhook's bearer secret is parked beside its registration, logged, and "
        "served back by the operator API",
        "    if let Some(url) = error.url() {",
        "    if let Some(url) = error.url().filter(|_| false) {",
    ),
    "APeerErrorQuotesItsUrl": (
        "src/peers/a2a.rs",
        "an_unreachable_peer_is_not_quoted_by_url",
        "an unreachable peer's error carries reqwest's rendering, URL and all, "
        "into the effect's failure, the log and the operator's reading — and a "
        "peer endpoint can carry its credential in the path",
        """            detail: format!("could not connect: {}", crate::netguard::transport_text(e)),""",
        """            detail: format!("could not connect: {e}"),""",
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
        "src/netguard/intake.rs",
        "declared_and_streamed_body_sizes_are_both_bounded",
        "a chunked response can cross the media byte ceiling after its headers "
        "passed. On the shared rule since media stopped carrying its own copy: "
        "this and `AnOversizedAnswerIsRead` are the same line answering to two "
        "batteries, which is what collapsing two implementations into one is for",
        "        if self.seen > self.limit {",
        "        if self.seen > usize::MAX {",
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
    "ExternalMediaIsLinkedToTheCase": (
        "src/media/mod.rs",
        "externally_retained_media_is_not_linked_to_the_case",
        "media under a named external retention policy, fetched inside a case, "
        "is linked to the case while its bytes live under the policy's unit — "
        "a drill reports the digest lost and `erase_case` tombstones an empty "
        "address and counts it as erased",
        """            case_link: case_link.filter(|_| self.requires_case()),""",
        """            case_link,""",
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
        let stored = self.blobs.put(&fetched.bytes).await.map_err(blob_failure)?;
""",
        """        let stored = self.blobs.put(&fetched.bytes).await.map_err(blob_failure)?;
        if let Some(link) = &self.case_link {
            link.cases
                .link_blob(link.case, digest, link.at)
                .await
                .map_err(|error| EffectError::Unavailable {
                    driver: "case.store".to_owned(),
                    detail: error.to_string(),
                })?;
        }
""",
    ),
    "BlobDurableBeforeCaseLink": (
        "src/runtime/ctx.rs",
        "case_retention_links_are_durable_before_blob_bytes",
        "a crash can leave arbitrary stored bytes unreachable from case erasure",
        """        cx.cases
            .link_blob(cx.case_id, digest, at)
            .await
            .map_err(StepError::Store)?;
        // An erased address refuses as itself rather than as a backend string:
        // a run re-producing bytes an operator had removed is a rule this
        // runtime enforces, not a store that is having a bad day.
        let stored = blobs
            .put(bytes)
            .await
            .map_err(|e| StepError::Store(crate::blob::refusal(e)))?;
""",
        """        // An erased address refuses as itself rather than as a backend string:
        // a run re-producing bytes an operator had removed is a rule this
        // runtime enforces, not a store that is having a bad day.
        let stored = blobs
            .put(bytes)
            .await
            .map_err(|e| StepError::Store(crate::blob::refusal(e)))?;
        cx.cases
            .link_blob(cx.case_id, digest, at)
            .await
            .map_err(StepError::Store)?;
""",
    ),
    "AnthropicReceivesRemoteMediaUrls": (
        "src/model/anthropic.rs",
        "anthropic_never_receives_a_provider_fetched_media_url",
        "an Anthropic image/document URL crosses the model boundary, letting the "
        "provider fetch bytes the plane never governed or recorded",
        """        super::refuse_provider_side_media(prompt, model)?;
        super::refuse_in_thread_instructions(prompt, model)?;

        // Before the request is built: a refused destination must cost nothing""",
        """        let _ = (prompt, model);
        super::refuse_in_thread_instructions(prompt, model)?;

        // Before the request is built: a refused destination must cost nothing""",
    ),
    "OpenAiReceivesRemoteMediaUrls": (
        "src/model/openai.rs",
        "openai_never_receives_a_provider_fetched_media_url",
        "an OpenAI image/file URL crosses the model boundary, letting the provider "
        "fetch bytes the plane never governed or recorded",
        """        super::refuse_provider_side_media(prompt, model)?;
        super::refuse_in_thread_instructions(prompt, model)?;

        self.check_egress(model)?;""",
        """        let _ = (prompt, model);
        super::refuse_in_thread_instructions(prompt, model)?;

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
    "PostgresBlobListsIgnoreTheCase": (
        "src/store/postgres_cases.rs",
        "postgres_satisfies_the_case_layer_contracts",
        "the blob list a case answers with drops its own case predicate, so an "
        "erasure request walks every matter's artifacts — tombstones written "
        "across matters, and a count reporting more discharged than the case "
        "ever held. The redb twin of this had an anchor and this backend had "
        "none, which is the asymmetry that lets one store enforce a rule its "
        "sibling quietly does not",
        """                  WHERE case_id = $1 AND tenant = $2 ORDER BY written_at, digest",""",
        """                  WHERE (case_id = $1 OR TRUE) AND tenant = $2 ORDER BY written_at, digest",""",
    ),
    "AClosureRefusalWearsAFaultsType": (
        "src/store/redb_cases.rs",
        "redb_satisfies_the_case_layer_contracts",
        "the open-obligation refusal is reported as a generic backend fault, so "
        "a store outage is indistinguishable from the rule firing — and the "
        "operator surface files a business refusal as an internal error",
        "                    return Err(StoreError::ObligationsOutstanding {\n"
        "                        case: case.to_string(),\n"
        "                        outstanding,\n"
        "                    });",
        "                    return Err(StoreError::Backend(format!(\n"
        "                        \"case {case} has {outstanding} open deadline(s)\"\n"
        "                    )));",
    ),
    "APostgresClosureRefusalWearsAFaultsType": (
        "src/store/postgres_cases.rs",
        "postgres_satisfies_the_case_layer_contracts",
        "the open-obligation refusal is reported as a generic backend fault on "
        "this backend alone — the two stores then disagree about what kind of "
        "answer one rule gives, which is the asymmetry the battery exists to "
        "refuse",
        "            return Err(StoreError::ObligationsOutstanding {\n"
        "                case: case.to_string(),\n"
        "                outstanding: usize::try_from(open).unwrap_or(usize::MAX),\n"
        "            });",
        "            return Err(StoreError::Backend(format!(\n"
        "                \"case {case} has {open} unmet obligation(s)\"\n"
        "            )));",
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
        "#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, schemars::JsonSchema)]\n#[serde(deny_unknown_fields)]\npub struct Budgets {",
        "#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, schemars::JsonSchema)]\npub struct Budgets {",
    ),
    "ADeclarativeAgentNeedsNoModelAtParse": (
        "src/manifest/mod.rs",
        "a_declarative_agent_without_a_model_is_refused_at_parse",
        "a manifest declaring `spec.execution` with no privileged model parses "
        "clean, so `agentplane validate` approves a document that can never "
        "assemble a plane — and the refusal arrives from whichever process "
        "first tried to build one, after the review it should have failed",
        "            .is_some_and(|e| e.kind != ExecutionKind::Call)",
        "            .is_some_and(|_| false)",
    ),
    "AnUndeclaredCapabilityIsServed": (
        "src/runtime/executor.rs",
        "a_capability_served_must_also_be_advertised",
        "a skill may answer a capability its agent's manifest never names, so "
        "the declaration that gets reviewed, digested and advertised as an A2A "
        "card describes a smaller surface than the plane actually serves — and "
        "the extra door is governed, journaled and invisible",
        """    if !undeclared.is_empty() {
        return Err(BuildError::ProvidesWhatItDoesNotAdvertise {""",
        """    if false {
        return Err(BuildError::ProvidesWhatItDoesNotAdvertise {""",
    ),
    "AnAgentMayGrantItselfAtParse": (
        "src/manifest/mod.rs",
        "an_agent_granting_its_own_capability_is_refused_at_parse",
        "a manifest granting `tool://agent/<a capability it itself provides>` "
        "parses clean, so `agentplane validate` approves a document whose "
        "grant is a call to itself — a regress that terminates only if a model "
        "decides it should, and both halves are on the same page",
        """            if self.spec.capabilities.provides.iter().any(|c| c == rest) {""",
        """            if false {""",
    ),
    "AZeroCeilingIsAccepted": (
        "src/manifest/mod.rs",
        "a_zero_ceiling_is_refused_at_parse",
        "a ceiling of 0 is accepted, so `max_tokens: 0` written to mean 'no "
        "permission to spend' instead refuses the run's first effect of any "
        "kind — a read-only tool call on an agent with no models — and the "
        "agent fails identically on every run it will ever make",
        """        let Some(field) = self.budget().bricked_ceiling() else {
            return Ok(());
        };""",
        """        let Some(field) = None::<&'static str> else {
            return Ok(());
        };""",
    ),
    "AZeroCeilingIsAcceptedByTheBuilder": (
        "src/runtime/executor.rs",
        "a_zero_ceiling_is_refused_however_the_budget_arrives",
        "a ceiling of 0 wired in Rust is accepted, so a plane built by an "
        "embedder — who never passes a manifest parser — refuses its first "
        "effect on every run it will ever make, while the identical budget "
        "written in YAML is refused at parse",
        """        if let Some(field) = self.budget.bricked_ceiling() {
            return Err(BuildError::BudgetPermitsNothing { field });
        }""",
        """        if false {
            return Err(BuildError::BudgetPermitsNothing { field: "max_steps" });
        }""",
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
        "other context over the same digest — a record signature — is accepted "
        "as approval of the manifest",
        """    Ok((
        digest,
        signer.signature_over(&signing_hash(DOMAIN_MANIFEST, &digest)),
    ))""",
        """    Ok((digest, signer.signature_over(&digest)))""",
    ),
    "AnUnsignedManifestPassesAVerifyingResolve": (
        "src/manifest/registry.rs",
        "a_signed_manifest_names_who_published_it",
        "a resolve that required a signature accepts a manifest nobody signed, "
        "so 'who published this' has no answer and nothing says so",
        """    let Some(a) = signature else {
        return Err(RegistryError::Unsigned {
            name: name.to_owned(),
            version: version.to_owned(),
        });
    };""",
        """    let Some(a) = signature else {
        return Ok(String::from("unverified"));
    };""",
    ),
    "SigningAnExistingManifestRecordsNothing": (
        "src/manifest/registry.rs",
        "signing_an_existing_unsigned_manifest_records_the_publisher",
        "publish_signed reports success for an existing unsigned artifact but "
        "does not record the publisher, so every verifying resolve still says unsigned",
        "        (None, Some(_)) => Ok(PublishVerdict::AdoptSignature),",
        "        (None, Some(_)) => Ok(PublishVerdict::Unchanged),",
    ),
    "AManifestPublisherCanBeReassigned": (
        "src/manifest/registry.rs",
        "republishing_with_another_signer_cannot_reassign_the_publisher",
        "identical artifact bytes can be republished by another identity without a refusal, "
        "so publication reports success while changing who approved the version",
        "        (Some(recorded), Some(offered)) if recorded.key_id != offered.key_id => {",
        "        (Some(recorded), Some(offered)) if false && recorded.key_id != offered.key_id => {",
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
        "        providers\n            .get(&model.provider)",
        "        providers\n            .values()\n            .next()\n            .map(|p| p)",
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
        "        self.declared(key, descriptor, ceilings).await?;",
        "        let _ = self.declared(key, descriptor, ceilings);",
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
    "AGenAiSpanNamesNoModel": (
        "src/runtime/ctx.rs",
        "a_model_call_is_reported_as_a_gen_ai_chat",
        "a completion's span carries the operation name and nothing else, so "
        "which model of which provider answered is invisible to the convention "
        "the attribute set exists for — and a panel keyed on it reads blank as "
        "*no model* rather than *nothing reports it*",
        """            if let Some(request) = effect.gen_ai_request() {""",
        """            if false && let Some(request) = effect.gen_ai_request() {""",
    ),
    "AGenAiSpanNamesNoCost": (
        "src/runtime/ctx.rs",
        "a_model_call_is_reported_as_a_gen_ai_chat",
        "what the provider said about its own answer never reaches the span, so "
        "a completion's cost, its stop reason and the model that served it are "
        "absent from the attributes the convention defines for exactly them",
        """                if let Some(reply) = effect.gen_ai_response(answer) {""",
        """                if false && let Some(reply) = effect.gen_ai_response(answer) {""",
    ),
    "AFailedAttemptNamesNoFault": (
        "src/runtime/ctx.rs",
        "a_failed_attempt_names_the_class_of_fault",
        "a failed attempt's span says only that something went wrong, so every "
        "panel keyed on `error.type` reports a plane with no failures at all — "
        "the one claim this runtime exists not to make",
        """                span.record(telemetry::ERROR_TYPE, failure.class());""",
        """                let _ = failure;""",
    ),
    "APostgresPageIsAdvisory": (
        "src/store/postgres.rs",
        "postgres_satisfies_the_journal_store_contract",
        "the shared backend ignores the page's bound — the redb mutation cannot "
        "reach this copy of the rule, and SQL is where a forgotten LIMIT looks "
        "most like a complete query",
        """                  WHERE tenant = $1 AND run_id = $2 AND seq >= $3 ORDER BY seq ASC
                  LIMIT $4""",
        """                  WHERE tenant = $1 AND run_id = $2 AND seq >= $3 ORDER BY seq ASC""",
    ),
    "ATenantLabelStopsAtTheMetrics": (
        "src/runtime/executor.rs",
        "the_tenant_label_reaches_the_run_span_too",
        "the tenant policy is honoured on the metrics and not on the traces, so "
        "a deployment that asked which tenant a run belongs to is answered on "
        "one signal and left guessing on the other",
        """        if !self.meter.tenant().is_empty() {
            span.record(telemetry::TENANT, self.meter.tenant());
        }""",
        """        let _ = &self.meter;""",
    ),
    "ALeaseForgetsWhatTheHistoryRecords": (
        "src/store/redb.rs",
        "redb_satisfies_the_journal_store_contract",
        "a run with no lease row is leased at epoch 1 whatever its history "
        "already reached, so a restore — which carries no lease table — hands a "
        "run that had changed hands a second ownership period wearing the "
        "number of its first, and quota settlement matches passes to spend by "
        "exactly that number",
        """                        None => epoch_after_history(&w, key.as_str(), upcaster.as_ref())?,""",
        """                        None => 1,""",
    ),
    "APostgresLeaseForgetsTheHistory": (
        "src/store/postgres.rs",
        "postgres_satisfies_the_journal_store_contract",
        "the shared backend's first lease ignores the run's journal, so the "
        "fencing token restarts below the epochs the history already carries — "
        "the redb mutation cannot reach this copy of the rule",
        """                         COALESCE((SELECT MAX(epoch) FROM journal
                                    WHERE tenant = $1 AND run_id = $2), 0) + 1,""",
        """                         1,""",
    ),
    "APostgresSealTakesAPositionOutOfOrder": (
        "src/store/postgres.rs",
        "postgres_merkle_log_only_grows_at_its_end_under_concurrent_seals",
        "two instances sealing at once read the log's end without the tenant's "
        "seal lock, so both take one position and the second seal fails — and "
        "any allocation that does not wait lets a position commit behind one "
        "already checkpointed, which a witness reports as a fork",
        """            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            &[&format!("run-seal:{}", self.tenant_name())],""",
        """            "SELECT hashtextextended($1, 0)",
            &[&format!("run-seal:{}", self.tenant_name())],""",
    ),
    "APostgresRowHoldsHalfASignature": (
        "src/store/postgres.rs",
        "postgres_half_a_signature_is_refused_not_read_as_unsigned",
        "the journal table accepts a key id without its signature, so a row "
        "edited around the application loses its authorship and reads back as "
        "a record written before signing was configured",
        """    CONSTRAINT journal_signature_whole CHECK ((key_id IS NULL) = (signature IS NULL))""",
        """    CONSTRAINT journal_signature_whole CHECK (true)""",
    ),
    "APostgresHalfSignatureReadsAsUnsigned": (
        "src/store/postgres.rs",
        "postgres_half_a_signature_is_refused_not_read_as_unsigned",
        "a row carrying half a signature is read as an unsigned record, so a "
        "table created without the constraint strips authorship silently on "
        "every read",
        """        (None, None) => Ok(None),""",
        """        (None, _) | (_, None) => Ok(None),""",
    ),
    "ARedbSignatureFlagIsAnyByte": (
        "src/store/redb.rs",
        "a_signature_flag_other_than_zero_or_one_is_corrupt",
        "a journal row's signature flag other than 0 or 1 reads as unsigned, "
        "so one damaged byte strips a record's authorship without a word",
        """            _ => return Err(corrupt("the signature flag")),""",
        """            _ => false,""",
    ),
    "ARedbRowIgnoresTrailingBytes": (
        "src/store/redb.rs",
        "trailing_bytes_after_a_journal_row_are_corrupt",
        "bytes after a journal row's body are ignored, so a damaged or "
        "appended-to row decodes as whole",
        """        if end != raw.len() {""",
        """        if false {""",
    ),
    "AJournalPageIsAdvisory": (
        "src/store/redb.rs",
        "redb_satisfies_the_journal_store_contract",
        "the store ignores the page's bound and reads a run's whole remaining "
        "history, which the one surface that pages then truncates — so the "
        "answers are byte-identical and the only difference is that every page "
        "of a long run costs the length of the run",
        """                .range((key.as_str(), from)..=(key.as_str(), u64::MAX))
                .map_err(|e| be(&e))?
                .take(limit)""",
        """                .range((key.as_str(), from)..=(key.as_str(), u64::MAX))
                .map_err(|e| be(&e))?
                .take(usize::MAX)""",
    ),
    "ARecordArrivesWithoutItsEnvelope": (
        "src/journal/view.rs",
        "a_runs_journal_is_readable_and_pages_from_a_cursor",
        "an operator surface serves a record's payload and drops the identity "
        "it belongs to, so a reader sees that an effect started and not which "
        "one, and cannot pair a start with its outcome",
        """        effect_key: r.effect_key().map(|k| k.to_string()),""",
        """        effect_key: None,""",
    ),
    "AnErasedEffectLosesItsTarget": (
        "src/core/effect.rs",
        "an_erased_effect_reports_what_a_typed_one_does",
        "an effect dispatched through the erasure answers the trait's defaults "
        "for the GenAI seams, so the same call opens a span naming a model when "
        "typed and naming nothing when boxed — while the module doc promises "
        "the two travel the same path",
        """    fn gen_ai_request(&self) -> Option<GenAiRequest> {
        (**self).gen_ai_request()
    }""",
        """    fn gen_ai_request(&self) -> Option<GenAiRequest> {
        None
    }""",
    ),
    "AnAttemptDoesNotChangeAnEffectsIdentity": (
        "src/core/id.rs",
        "effect_key_separates_step_phase_ordinal_and_attempt",
        "the attempt number leaves the effect key, so a retry reuses the "
        "identity of the attempt before it — a replay reads back the earlier "
        "outcome as though it were this call's, and two dispatches share one "
        "record (I3)",
        """        h.update(attempt.to_be_bytes());""",
        """        h.update(0u32.to_be_bytes());""",
    ),
    "TwoEffectsInAStepCollideOnOneKey": (
        "src/core/id.rs",
        "effect_key_separates_step_phase_ordinal_and_attempt",
        "the ordinal leaves the effect key, so two effects of the same kind "
        "in one step derive the same identity and the second reads back the "
        "first's outcome instead of being performed (I3)",
        """        h.update(ordinal.to_be_bytes());""",
        """        h.update(0u32.to_be_bytes());""",
    ),
    "AMutatingDoubtUnwindsInsteadOfAsking": (
        "src/runtime/ctx.rs",
        "a_mutating_effect_that_ends_in_doubt_quarantines",
        "a mutating call whose attempts run out with the outcome still unknown "
        "is classified as an ordinary failure, so the unwind compensates every "
        "step around a call that may have landed — the refund for money nobody "
        "took, issued because the retry policy gave up (I5)",
        """                    if mutates && !policy.permits(attempt) {""",
        """                    if false && mutates && !policy.permits(attempt) {""",
    ),
    "AnAnnouncementWithNoOutcomeIsAssumedHarmless": (
        "src/runtime/executor.rs",
        "a_failed_steps_landed_mutation_is_undone_and_its_rejected_one_is_not",
        "an `EffectStarted` with no terminal record is treated as having "
        "changed nothing, so the unwind skips the one call it cannot account "
        "for — which is the whole reason the announcement is durable before "
        "dispatch (I2)",
        """                        touching.insert(key, (step, true));""",
        """                        touching.insert(key, (step, false));""",
    ),
    "TheModelsSpellingOfAToolIsUnchecked": (
        "src/manifest/mod.rs",
        "a_prompt_naming_an_ungranted_tool_is_refused",
        "a reviewed prompt may name a tool in the spelling the model is "
        "actually offered — `server__tool` — without that name being granted, "
        "so the model is told of no such tool, improvises, and the instruction "
        "silently does not happen",
        """            for wire in wire_names_in(text) {
                if !offered.contains(&wire) {""",
        """            for wire in wire_names_in(text) {
                if false && !offered.contains(&wire) {""",
    ),
    "ADanglingContinuationIsHonoured": (
        "src/model/mod.rs",
        "a_continuation_with_no_exchanges_behind_it_is_refused",
        "a continuation with no tool exchanges behind it is sent, so the "
        "effect key records a continuation the wire never carried and the "
        "provider is asked to continue a turn that never happened",
        """    if continuation.is_some() && exchanges.is_empty() {""",
        """    if false && continuation.is_some() && exchanges.is_empty() {""",
    ),
    "TheStandInEnforcesAnySchema": (
        "src/model/fake.rs",
        "a_schema_no_provider_could_enforce_is_refused_offline",
        "the stand-in accepts a schema no provider with constrained decoding "
        "would, so an agent whose result contract or plan format cannot be "
        "asked for passes every offline test and is refused on its first real "
        "call — the gap that let `planned` ship unable to run at all",
        """        if *self.constrained.lock().expect("fake")
            && let Some(schema) = request.schema""",
        """        if false
            && let Some(schema) = request.schema""",
    ),
    "AnOpenObjectSchemaIsAccepted": (
        "src/manifest/mod.rs",
        "an_object_schema_a_model_may_add_to_is_refused",
        "a declarative agent may declare an object schema the model can add "
        "fields to — the vacuous `schema: {}` one level down, and the one "
        "constrained decoding cannot bind, so the reviewed contract stops "
        "holding at the moment it is supposed to",
        """        if is_object && schema.get("additionalProperties") != Some(&serde_json::Value::Bool(false))
        {""",
        """        if false && is_object {""",
    ),
    "TheOpenObjectRuleStopsAtTheSurface": (
        "src/manifest/mod.rs",
        "an_object_schema_a_model_may_add_to_is_refused",
        "only the outermost object is checked, so a nested one the model also "
        "fills in stays open — and a reviewer reading a closed top level has "
        "no way to see it",
        """        if let Some(properties) = schema.get("properties").and_then(|p| p.as_object()) {
            for (name, nested) in properties {
                Self::refuse_open_objects(nested, &format!("{at}.{name}"))?;
            }
        }""",
        """        if false && let Some(properties) = schema.get("properties").and_then(|p| p.as_object()) {
            for (name, nested) in properties {
                Self::refuse_open_objects(nested, &format!("{at}.{name}"))?;
            }
        }""",
    ),
    "ASensitivityRendersAsRustRatherThanAsWritten": (
        "src/core/label.rs",
        "a_sensitivity_reads_back_as_the_name_a_manifest_writes",
        "a policy refusal names a level in a spelling no manifest uses, so an "
        "operator matching the refusal against the file that caused it has to "
        "know that `Internal` and `internal` are one level",
        """            Self::Confidential => "confidential",""",
        """            Self::Confidential => "Confidential",""",
    ),
    "APlanFormatNoProviderWillAccept": (
        "src/runtime/declarative.rs",
        "the_plan_format_survives_constrained_decoding",
        "the plan a privileged model is asked for falls back outside the "
        "subset constrained decoding accepts, so `planned` — the dual-model "
        "execution kind — is refused by the driver before it is sent and can "
        "only ever run against a fake",
        """                        "args": {
                            "type": ["string", "null"],""",
        """                        "args": {
                            "type": "object",""",
    ),
    "AParseStepAcceptsProseArguments": (
        "src/runtime/declarative.rs",
        "a_parse_step_carrying_args_is_refused",
        "a plan step that is a parse silently ignores the `args` it carries — "
        "a field that parses and is never read, manufacturing confidence in "
        "arguments nothing executes, in the artifact whose whole point is that "
        "what is accepted is what runs",
        """                        Ok(args) if args.is_empty() => {}""",
        """                        Ok(_) => {}""",
    ),
    "ATakeOverDisplacesWhoeverHoldsIt": (
        "src/store/redb_tasks.rs",
        "redb_satisfies_the_case_layer_contracts",
        "the take-over ignores which holder the caller named, so a decision "
        "made from a stale queue view displaces whoever holds the task now — "
        "and an unheld task is 'taken over' where the honest verb is claim",
        """                        } else if task.assignee.as_deref() != Some(from.as_str()) {""",
        """                        } else if task.assignee.is_none()
                            && task.assignee.as_deref() != Some(from.as_str())
                        {""",
    ),
    "ATakeOverThinsTheLadder": (
        "src/store/redb_tasks.rs",
        "redb_satisfies_the_case_layer_contracts",
        "a take-over skips the eligibility ladder, so the four-eyes exclusion "
        "thins the moment a reviewer leaves — the proposer acquires the "
        "decision on their own action by displacing its reviewer",
        """                        // A take-over is a claim: the ladder does not thin
                        // because the previous reviewer left.
                        if let Err(refused) = eligible(&task, id, &actor, &roles) {
                            Err(refused)
                        } else if task.assignee.as_deref() != Some(from.as_str()) {""",
        """                        // A take-over is a claim: the ladder does not thin
                        // because the previous reviewer left.
                        if let Err(refused) = eligible(&task, id, &actor, &roles).or(Ok::<(), ClaimError>(())) {
                            Err(refused)
                        } else if task.assignee.as_deref() != Some(from.as_str()) {""",
    ),
    "AHostGrantSkipsIdnaCanonicalisation": (
        "src/netguard/mod.rs",
        "a_host_grant_is_canonicalised_like_the_url_it_guards",
        "a host grant is returned only lowercased, not put through the URL "
        "parser both fetch and push paths use — so an internationalised grant "
        "is stored in its Unicode form and never matches the punycode a URL "
        "host carries, silently refusing every request it was meant to permit",
        """    Some(url.host_str()?.trim_end_matches('.').to_ascii_lowercase())""",
        """    Some(raw.trim().trim_end_matches('.').to_ascii_lowercase())""",
    ),
    "AnErasedEventStaysClaimable": (
        "src/store/redb_events.rs",
        "redb_event_buffer_erases_payloads",
        "erasing an event nobody had claimed nulls its payload and leaves "
        "the row live, so the next matching waiter claims it and is handed "
        "`null` as though the counterparty had sent it",
        "                    if (!claimed && !dead) || undelivered_claim {",
        "                    if (false && !claimed && !dead) || undelivered_claim {",
    ),
    "AnErasedClaimStaysClaimed": (
        "src/store/redb_events.rs",
        "redb_satisfies_the_case_layer_contracts",
        "erasing a message a run claimed and never journaled leaves the "
        "claim standing, so the crashed delivery's recovery or a redelivery "
        "hands the run the emptied row as the counterparty's word",
        "                    if (!claimed && !dead) || undelivered_claim {",
        "                    if !claimed && !dead {",
    ),
    "PostgresAnErasedClaimStaysClaimed": (
        "src/store/postgres_cases.rs",
        "postgres_satisfies_the_case_layer_contracts",
        "the Postgres erasure of a claimed, undelivered message keeps its "
        "claim, so the recovery hands the run an emptied row or the message "
        "never reaches the dead-letter list",
        "        let undelivered = claimed_by.is_none() || standing;",
        "        let undelivered = claimed_by.is_none() || (standing && false);",
    ),
    "AnErasedClaimKeepsItsWaitParked": (
        "src/store/redb_events.rs",
        "redb_satisfies_the_case_layer_contracts",
        "erasing a claimed message releases the claim but leaves the wait "
        "parked, so it is matchable by nothing and tried by the redelivery "
        "pass every tick until its deadline",
        "                        unpark_for(&w, &tenant, &claimant, &key)?;",
        "                        let _ = (&w, &claimant);",
    ),
    "ASatisfiedWaiterKeepsMatching": (
        "src/store/redb_events.rs",
        "redb_satisfies_the_case_layer_contracts",
        "the broadcast match claims the event but leaves the subscription "
        "registered until the run's own unsubscribe, so a second event matches "
        "the same satisfied waiter — sequentially, no race required — and is "
        "parked under a claim nobody consumes, invisible to dead-lettering "
        "and to every listing an operator reads",
        """                            w.open_table(PARKED)
                                .map_err(|e| be(&e))?
                                .insert((tenant.as_str(), run.as_str(), effect.as_str()), ts(at))
                                .map_err(|e| be(&e))?;""",
        """                            let _ = at;""",
    ),
    "AParkedWaitIsMatchedAgain": (
        "src/store/redb_events.rs",
        "redb_satisfies_the_case_layer_contracts",
        "a parked wait stays in the match path, so a second matching event "
        "is claimed for a wait its first event already satisfied \u2014 and a "
        "claimed event never dead-letters, so the second stays claimed for "
        "ever",
        "            if is_parked(w, tenant, run, effect)? {",
        "            if false && is_parked(w, tenant, run, effect)? {",
    ),
    "PostgresAParkedWaitIsMatchedAgain": (
        "src/store/postgres_cases.rs",
        "postgres_satisfies_the_case_layer_contracts",
        "the Postgres match path elects a parked wait, so a second matching "
        "event is claimed for a wait its first event already satisfied and "
        "stays claimed for ever",
        "                        AND parked_at IS NULL",
        "                        AND TRUE",
    ),
    "ASealedRunsParkedWaitIsListed": (
        "src/store/redb_events.rs",
        "redb_satisfies_the_case_layer_contracts",
        "a sealed run's parked wait is listed for redelivery, so the pass "
        "tries a delivery no sealed run can record, fails, and finds it "
        "again every tick",
        "                if is_sealed(&w, &tenant, &run)? {",
        "                if false && is_sealed(&w, &tenant, &run)? {",
    ),
    "PostgresASealedRunsParkedWaitIsListed": (
        "src/store/postgres_cases.rs",
        "postgres_satisfies_the_case_layer_contracts",
        "the Postgres redelivery listing keeps a sealed run's parked wait, "
        "so the pass tries a delivery no sealed run can record every tick",
        "                  WHERE s.tenant = $1 AND s.parked_at IS NOT NULL",
        "                  WHERE s.tenant = $1 AND s.parked_at IS NOT NULL AND FALSE",
    ),
    "AClaimedEventHidesFromItsOwnRun": (
        "src/store/redb_events.rs",
        "redb_satisfies_the_case_layer_contracts",
        "claim_for filters to unclaimed events only, so a crash between "
        "match_waiter's durable claim and the run's resume leaves the "
        "message claimed for a run that can never see it \u2014 the "
        "counterparty's retry is answered Duplicate, the resumed wait finds "
        "nothing, and a message that arrived in time is lost to a deadline "
        "breach",
        "                            && ((row.3 == 0 && !parked_here) || own_claim)",
        "                            && (row.3 == 0 && !parked_here)",
    ),
    "ARevokedDrawReadsAsADoubt": (
        "src/runtime/effects.rs",
        "a_revoked_draw_is_answered_once_and_never_retried",
        "every authority refusal flattens to an error that reads as in-doubt, "
        "so a draw against a revoked mandate — 'not retryable, ever', per its "
        "own docs — is retried under the full policy, reported as a call that "
        "may have landed, and quarantines any group it was deferred in where "
        "the cheap abort was the truthful settlement",
        """            _ => EffectError::Refused(error.to_string()),""",
        """            _ => EffectError::Other(error.to_string()),""",
    ),
    "ACatalogueOffersWhatNothingProvides": (
        "src/tools/serve.rs",
        "a_capability_the_plane_does_not_provide_is_not_offered",
        "a manifest's declared capability is offered as a tool without asking "
        "whether this plane has a skill for it, so a model is handed a verb "
        "that is refused at admission every time it is called — and the error "
        "names the plane rather than the catalogue that advertised it",
        """                if !runtime.provides(capability) {""",
        """                if false {""",
    ),
    "ASuspendedRunIsNotATask": (
        "src/tools/serve.rs",
        "a_suspended_run_is_a_task_that_reads_from_the_journal",
        "a run that suspends answers the calling host as a failed tool call "
        "rather than as a task handle, so a governed wait — an approval, a "
        "timer, an event — reads to the caller as work that did not happen, "
        "and the run it abandoned goes on holding its lease",
        """            RunStatus::Suspended(ref why) => {""",
        """            RunStatus::Suspended(ref why) if false => {""",
    ),
    "AnUngovernedPlaneIsServedOverMcp": (
        "src/tools/serve.rs",
        "a_plane_without_a_policy_engine_is_not_served",
        "the MCP catalogue is built for a plane with no policy engine, so any "
        "connecting host admits runs under no rule at all",
        "        if runtime.policy().is_none() {",
        "        if runtime.policy().is_none() && false {",
    ),
    "TheMcpListenerSkipsTheAuthenticator": (
        "src/tools/serve_http.rs",
        "an_unauthenticated_mcp_request_is_refused_and_admits_nothing",
        "the HTTP listener lets a request with no valid credential through as "
        "somebody, so anyone who can reach the port lists and calls tools",
        "    let Some(caller) = caller else {",
        "    let Some(caller) = caller.or_else(|| Some(crate::api::Caller::new(\"anyone\", vec![]))) else {",
    ),
    "AnHttpCallIsAdmittedAsNobody": (
        "src/tools/serve.rs",
        "an_http_tool_call_is_admitted_as_its_caller",
        "a call over HTTP is admitted under no chain and names no admitter, so "
        "the journal cannot say who started the run and the caller's own "
        "authority never bounds it",
        """            Some(caller) => RunTerms::default()
                .once(&key)
                .served(caller.acting_as.clone())
                .admitted_by(&caller.actor),""",
        """            Some(_) => RunTerms::default().once(&key).served(None),""",
    ),
    "AnHttpCallIsKeyedAsNobody": (
        "src/tools/serve.rs",
        "an_http_tool_call_is_admitted_as_its_caller",
        "every HTTP caller's admissions are keyed under the anonymous stdio "
        "source, so ownership of a task cannot be read back from the run",
        """                admission: format!("{CALLER_NAMESPACE}{}", caller.source),""",
        """                admission: ADMISSION_SOURCE.to_owned(),""",
    ),
    "AnyCallerReadsAnHttpTask": (
        "src/tools/serve.rs",
        "another_callers_task_is_no_such_task",
        "any authenticated caller reads and cancels any other caller's task by "
        "its id, because ownership is checked against the surface, not the caller",
        "            != Some(asker.admission.as_str())",
        "            .is_none_or(|s| !s.starts_with(\"mcp/\"))",
    ),
    "TheHttpKeyIsScopedToTheSession": (
        "src/tools/serve.rs",
        "an_http_retry_with_the_same_key_is_one_run",
        "an HTTP caller's idempotency key is scoped to the transport session, "
        "which is fresh per request, so every retry is a second run",
        """            Some(key) if asker.caller.is_some() => format!("host:{key}"),""",
        """            Some(key) if asker.caller.is_some() => format!("host:{}/{key}", self.session),""",
    ),
    "TheMcpGateAlwaysPermits": (
        "src/tools/serve.rs",
        "a_tool_call_the_policy_does_not_permit_is_declined_and_admits_nothing",
        "no MCP action is asked of policy, so a caller the rules refuse lists, "
        "calls and reads whatever is served",
        "        let Some(caller) = asker.caller.as_ref() else {",
        "        let Some(caller) = asker.caller.as_ref().filter(|_| false) else {",
    ),
    "OriginValidationIsLeftAtTheCrateDefault": (
        "src/api/rebinding.rs",
        "a_foreign_origin_is_refused_before_authentication",
        "a request carrying a foreign Origin reaches the credential check, so a "
        "browser page on another site can drive the listener through DNS "
        "rebinding with whatever credential the browser holds",
        "    if let Some(origin) = origin\n",
        "    if let Some(origin) = origin.filter(|_| false)\n",
    ),
    "AForeignHostIsServed": (
        "src/api/rebinding.rs",
        "a_foreign_origin_is_refused_before_authentication",
        "a request naming a foreign Host reaches the credential check — the "
        "DNS-rebinding shape the Host allow-list exists to refuse",
        "    if !host\n        .as_deref()",
        "    if false && !host\n        .as_deref()",
    ),
    "TheServerSpeaksOneRevision": (
        "src/tools/serve.rs",
        "a_host_without_tasks_is_offered_only_tools_that_cannot_suspend",
        "the served revisions drift from the spoken ones, and every host on "
        "2025-11-25 — most frameworks — is refused at the handshake",
        "        Cow::Owned(crate::tools::McpClient::SPOKEN_REVISIONS.to_vec())",
        "        Cow::Owned(vec![crate::tools::MCP_REVISION])",
    ),
    "EverythingIsSafeWithoutTasks": (
        "src/manifest/mod.rs",
        "a_host_without_tasks_is_offered_only_tools_that_cannot_suspend",
        "every tool is judged unable to suspend, so a host that cannot hold a "
        "task is offered calls that will wait on a person with no way to say so",
        "    pub fn may_suspend(&self, is_peer: impl Fn(&str) -> bool) -> bool {",
        "    pub fn may_suspend(&self, is_peer: impl Fn(&str) -> bool) -> bool {\n        if !self.spec.tools.is_empty() || self.spec.tools.is_empty() { return false; }",
    ),
    "AMaySuspendCallIsAdmittedWithoutTasks": (
        "src/tools/serve.rs",
        "a_host_without_tasks_is_offered_only_tools_that_cannot_suspend",
        "a host without the Tasks extension that names a tool it was not "
        "offered gets a run admitted anyway",
        "        if served.may_suspend && !tasks {",
        "        if false && served.may_suspend && !tasks {",
    ),
    "ASuspensionWithoutTasksReadsAsSuccess": (
        "src/tools/serve.rs",
        "a_suspension_for_a_host_without_tasks_is_an_error_naming_the_run",
        "a run that waits for a host that cannot hold a task is answered as a "
        "success, so the host reports a call that has not happened",
        "fn waiting_without_tasks(run: RunId) -> CallToolResult {",
        "fn waiting_without_tasks(run: RunId) -> CallToolResult {\n    if run.to_string().is_empty() || !run.to_string().is_empty() { return CallToolResult::structured(serde_json::json!({ \"run\": run.to_string() })); }",
    ),
    "ACallAgentAsksAModel": (
        "src/runtime/declarative.rs",
        "a_call_agent_dispatches_its_one_grant_and_no_model",
        "a `call` agent is run as a completion, so it needs a model it does not "
        "declare and never dispatches its one grant",
        "        match self.kind {\n            ExecutionKind::Completion => {",
        "        match if self.kind == ExecutionKind::Call { ExecutionKind::Completion } else { self.kind } {\n            ExecutionKind::Completion => {",
    ),
    "ACallSkipsItsInputSchema": (
        "src/runtime/declarative.rs",
        "a_call_whose_input_fails_its_schema_performs_nothing",
        "a `call` dispatches input its declared `spec.input` refuses, so the "
        "reviewed argument shape is offered and enforced by nobody",
        "        if let Err(detail) = crate::model::validate_schema(&schema, input.peek()) {",
        "        if let Err(detail) = crate::model::validate_schema(&json!({}), input.peek()) {",
    ),
    "ACallSkipsItsToolsDeclaration": (
        "src/runtime/declarative.rs",
        "a_call_holds_its_arguments_to_the_tools_declaration",
        "a `call` holds its input to `spec.input` only, so a caller adds an "
        "argument the tool's reviewed declaration leaves out — a fee waiver on "
        "a transfer — and it is dispatched as written",
        "                if let Err(detail) = crate::model::validate_schema(declared, input.peek()) {",
        "                if let Err(detail) = crate::model::validate_schema(&json!({}), input.peek()) {",
    ),
    "ACallAcceptsAnOpenInput": (
        "src/manifest/mod.rs",
        "a_call_agent_with_an_open_input_is_refused",
        "a `call` agent parses with an open `spec.input`, so its caller-facing "
        "shape admits arguments nobody reviewed and validating against it "
        "refuses none of them",
        """            Self::refuse_open_objects(&input.schema, "spec.input.schema")""",
        """            Self::refuse_open_objects(&serde_json::Value::Null, "spec.input.schema")""",
    ),
    # ── The dev page ────────────────────────────────────────────────────────
    "ADevRouteSkipsTheToken": (
        "src/api/dev.rs",
        "every_dev_route_refuses_a_request_without_the_token",
        "a dev route answers a request that carries no token, so any page the "
        "author's browser opens starts runs and exports the store",
        "        let caller = self.auth.authenticate(headers).await?;",
        "        let caller = crate::api::Caller::new(\"dev:anyone\", Vec::new()).in_tenant(crate::core::TenantId::new(TENANT).expect(\"a tenant\"));",
    ),
    "TheDevPageServesAForeignHost": (
        "src/api/dev.rs",
        "a_request_naming_a_foreign_host_is_refused",
        "the dev page's own allow-list names a host other than loopback, so a "
        "hostile name rebound to 127.0.0.1 reaches its token check from "
        "another site",
        "    let authorities = [\n        format!(\"127.0.0.1:{port}\"),",
        "    let authorities = [\n        format!(\"evil.example:{port}\"),\n        format!(\"127.0.0.1:{port}\"),",
    ),
    "ACrossOriginPostIsServed": (
        "src/api/rebinding.rs",
        "a_cross_origin_post_is_refused",
        "a dev request that changes state is served without naming its Origin, "
        "so the page's one check against a cross-site write is the token alone",
        "    if guard.origin_on_writes && origin.is_none() && !request.method().is_safe() {",
        "    if false && guard.origin_on_writes && origin.is_none() && !request.method().is_safe() {",
    ),
    "TheFallbackCarriesNoPolicy": (
        "src/api/dev.rs",
        "every_dev_response_carries_the_content_security_policy",
        "the security headers wrap matched routes only, so the fallback's "
        "answer to a path no route serves carries no content security policy",
        "        .layer(axum::middleware::from_fn(security_headers))",
        "        .route_layer(axum::middleware::from_fn(security_headers))",
    ),
    "TheDevListenerBindsEverywhere": (
        "src/bin/agentplane.rs",
        "the_dev_listener_binds_loopback_only",
        "the dev page listens on every interface, so another host on the "
        "author's network reaches a page that starts runs",
        "    tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))",
        "    tokio::net::TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, port))",
    ),
    "ThePageParsesHtml": (
        "src/api/dev/app.js",
        "the_dev_page_script_inserts_text_only",
        "the dev page inserts plane data through an HTML sink: under the "
        "page's policy Trusted Types make it throw and the page renders "
        "nothing, and with the policy gone a recorded `<img onerror>` becomes "
        "an element whose handler only script-src still blocks",
        "  if (text !== undefined && text !== null) node.textContent = String(text);",
        "  if (text !== undefined && text !== null) node.innerHTML = String(text);",
    ),
    "AnUnmarkedStoreIsOpened": (
        "src/bin/agentplane.rs",
        "dev_refuses_a_store_it_did_not_create",
        "dev opens a directory it did not create, so a deployment's store is "
        "one a page that starts runs over HTTP writes to",
        "    } else if !ours {",
        "    } else if false {",
    ),
    "AScratchLinkIsFollowed": (
        "src/bin/agentplane.rs",
        "dev_refuses_a_store_it_did_not_create",
        "dev follows a symbolic link named as --scratch, so a link into any "
        "marked-looking directory is a store a page that starts runs writes to",
        "    if let Ok(found) = kind(dir) {",
        "    if let Ok(found) = std::fs::metadata(dir).map(|m| m.file_type()) {",
    ),
    "ALinkedDevStoreIsOpened": (
        "src/bin/agentplane.rs",
        "dev_refuses_a_store_it_did_not_create",
        "dev opens a dev.redb that is a link, so a marked directory points the "
        "page's runs at a deployment's store",
        "    } else if kind(&dir.join(DEV_STORE)).is_ok_and(|k| !k.is_file()) {",
        "    } else if false {",
    ),
    "AnyMarkerIsTrusted": (
        "src/bin/agentplane.rs",
        "dev_refuses_a_store_it_did_not_create",
        "dev trusts any file named as its marker, so a directory somebody else "
        "marked is one it writes to",
        "        && std::fs::read(&marker).is_ok_and(|bytes| bytes == DEV_MARKER_TEXT.as_bytes());",
        "        && std::fs::read(&marker).is_ok();",
    ),
    "TheActingAsChainIsNotTheSavedFiles": (
        "src/bin/agentplane/dev.rs",
        "a_rebuild_scopes_the_acting_as_chain_to_the_saved_file",
        "the --acting-as chain is scoped to less than the file the plane was "
        "rebuilt from, so a capability added on save is refused as out of "
        "scope until the process restarts",
        "            .map(|subject| super::chain_for(subject, manifests, &wiring.peer))",
        "            .map(|subject| super::chain_for(subject, &manifests[..1], &wiring.peer))",
    ),
    "TheTimelineShowsHiddenCharactersRaw": (
        "src/api/dev.rs",
        "the_dev_timeline_escapes_hidden_characters",
        "the page's timeline serves records unescaped, so a bidi override or "
        "zero-width character recorded by a model reorders or hides what the "
        "author reads",
        "        *inner = escape_strings(inner.take(), &mut escaped);",
        "        *inner = inner.take();",
    ),
    "TheTimelineShowsAKeyRaw": (
        "src/api/dev.rs",
        "the_dev_timeline_escapes_hidden_characters",
        "the page's timeline escapes values but not object keys, so a hidden "
        "character in a recorded key reaches the author raw",
        "                    let (key, hit) = crate::core::visible::escape(&key);",
        "                    let (key, hit) = (key, false);",
    ),
    "AnUnknownRunReadFromLaterExists": (
        "src/bin/agentplane.rs",
        "history_prints_a_hostile_record_escaped",
        "`history --from N` on a run the store does not hold prints nothing "
        "and exits 0, so a mistyped run id reads as one that has caught up",
        "        && (start == 1\n            || journal",
        "        && (start == 1\n            || false && journal",
    ),
    "APublishedImageServesTheDevPage": (
        ".github/workflows/release.yml",
        "no_published_image_enables_dev",
        "a published image is built with `dev`, so a deployment ships the page "
        "that starts runs over HTTP",
        "            features: cli\n",
        "            features: cli,dev\n",
    ),
    "LiveTransportsNeedNoConsent": (
        "src/bin/agentplane.rs",
        "dev_refuses_live_transports_without_consent",
        "dev wires real tool servers and peers unasked, so an approval on the "
        "page performs a real effect on a system nobody said was the author's",
        "    if !opts.allow_live && (!opts.mcp.is_empty() || !opts.peer.is_empty()) {",
        "    if false && !opts.allow_live && (!opts.mcp.is_empty() || !opts.peer.is_empty()) {",
    ),
    "TheDevPolicyPermitsAnyone": (
        "src/api/dev.rs",
        "the_dev_policy_permits_only_its_own_actor",
        "the dev engine permits any actor on tenant dev, so any credential "
        "that reaches the plane decides its tasks",
        "            if request.principal == self.actor && tenant == Some(TENANT) {",
        "            if tenant == Some(TENANT) {",
    ),
    "TheTimelinePrintsRawText": (
        "src/bin/agentplane.rs",
        "history_prints_a_hostile_record_escaped",
        "history prints recorded strings raw, so a bidi override or an escape "
        "sequence in a run's input drives the terminal reading it",
        "    agentplane::core::visible::escape(&line).0",
        "    line",
    ),
    "AnyCallerUsesAnHttpSession": (
        "src/tools/serve_http.rs",
        "another_callers_session_is_no_session",
        "a 2025-11-25 session answers whoever names its id, so another caller "
        "replays its stream, posts into it, or closes it",
        "        && guard.sessions.owner(id).is_some_and(|owner| owner != actor)",
        "        && guard.sessions.owner(id).is_some_and(|_| false)",
    ),
    "HttpSessionsAreUnbounded": (
        "src/tools/serve_http.rs",
        "a_caller_holds_a_bounded_number_of_sessions",
        "one credential opens sessions without bound, each server memory held "
        "until it idles out, so a caller spends the plane's memory at will",
        "        if held >= MAX_SESSIONS_PER_CALLER {",
        "        if held >= usize::MAX {",
    ),
    "AnUnguardedHttpRequestIsTheStdioHost": (
        "src/tools/serve.rs",
        "a_catalogue_mounted_over_http_without_its_guard_admits_nothing",
        "a catalogue mounted over HTTP without its guard treats every request "
        "as the anonymous stdio host, so anyone who reaches the port calls "
        "tools with no policy asked",
        "        if self.authenticated || over_http {",
        "        if self.authenticated || (over_http && false) {",
    ),
    "OneKeyServesEveryTool": (
        "src/tools/serve.rs",
        "one_key_sent_to_two_tools_is_two_calls",
        "an idempotency key is not bound to the tool, so the same key sent to a "
        "second tool is answered with a replay of the first tool's run",
        "        let id = crate::core::origin_key(capability, &id);",
        "        let id = crate::core::origin_key(&capability[..0], &id);",
    ),
    "APromptIsListedPerCapability": (
        "src/tools/serve.rs",
        "an_agent_serving_two_capabilities_is_one_prompt",
        "an agent serving two capabilities is listed as two prompts under one "
        "name, the same reviewed instruction offered twice",
        "                    .filter(|s| listed.insert(s.agent.clone()))",
        "                    .filter(|s| listed.insert(s.capability.clone()))",
    ),
    "McpAgentServesEveryAgent": (
        "src/bin/agentplane.rs",
        "mcp_agent_serves_only_the_agents_it_names",
        "`--mcp-agent` selects nothing, so one agent without `spec.input` in "
        "the file still fails the whole MCP listener at startup",
        "        .filter(|m| named.contains(&m.metadata.name))",
        "        .filter(|_| true)",
    ),
    "ServedInputIsTrusted": (
        "src/tools/serve.rs",
        "a_served_caller_cannot_fill_a_trusted_field",
        "a served caller's arguments arrive trusted, so they fill fields a "
        "reviewer reserved for trusted input and the field gate admits anyone",
        """        let input = Tainted::from_source(
            serde_json::Value::Object(request.arguments.unwrap_or_default()),
            SourceId::new(asker.input.clone()),
        );""",
        """        let input = Tainted::trusted(serde_json::Value::Object(
            request.arguments.unwrap_or_default(),
        ));""",
    ),
    "ACallMayDeclareAnUngatedMutation": (
        "src/manifest/mod.rs",
        "a_call_with_an_ungated_mutating_grant_is_refused",
        "a `call` agent's mutating grant with no field rules parses, and every "
        "served call to it is refused by the taint gate — a grant that reads as "
        "a capability and is decoration",
        """        if !matches!(
            execution.kind,
            ExecutionKind::ToolCalling | ExecutionKind::Call
        ) {""",
        """        if !matches!(execution.kind, ExecutionKind::ToolCalling) {""",
    ),
    "AnMcpTaskIdReachesAnyRun": (
        "src/tools/serve.rs",
        "a_run_this_surface_did_not_admit_is_no_task_of_its_own",
        "tasks/get and tasks/cancel act on whatever run the id names, so a host "
        "reads and stops the embedder's runs and other surfaces' tasks",
        "            != Some(asker.admission.as_str())",
        "            == Some(\"nobody\")",
    ),
    "AnMcpRetryIsASecondRun": (
        "src/tools/serve.rs",
        "a_retried_call_with_the_same_key_is_one_run",
        "tools/call admits under no key, so a host that resends a call after "
        "losing the response runs the agent twice",
        "            None => RunTerms::default().once(&key).served(None),",
        "            None => RunTerms::default().served(None),",
    ),
    "AnMcpCloneSharesItsSession": (
        "src/tools/serve.rs",
        "two_sessions_with_the_same_request_id_and_key_are_two_runs",
        "a server cloned per session keeps one session id, so two hosts' calls "
        "under the same request id are keyed into one run and the second host "
        "is handed the first one's output",
        """            served: self.served.clone(),
            session: RunId::generate().to_string(),""",
        """            served: self.served.clone(),
            session: self.session.clone(),""",
    ),
    "AnMcpHostKeySpansSessions": (
        "src/tools/serve.rs",
        "two_sessions_with_the_same_request_id_and_key_are_two_runs",
        "a host's idempotency key is honoured across sessions, so any host that "
        "guesses another's key is handed that host's run",
        """            Some(key) => format!("host:{}/{key}", self.session),""",
        """            Some(key) => format!("host:{key}"),""",
    ),
    "ACompletedMcpTaskLosesItsResult": (
        "src/tools/serve.rs",
        "a_completed_task_returns_the_calls_result",
        "a completed task answers tasks/get with an empty result, so a host "
        "that suspended for an answer is handed nothing when it comes",
        "                    result: result.as_object().cloned().unwrap_or_default(),",
        "                    result: result.as_object().map(|_| serde_json::Map::new()).unwrap_or_default(),",
    ),
    "ACancelledMcpTaskReadsAsFailed": (
        "src/tools/serve.rs",
        "a_suspended_run_is_a_task_that_reads_from_the_journal",
        "a cancelled run reads as failed, so a host reports an operator's stop "
        "as the agent breaking",
        "            Some(RunStatus::Cancelled { .. }) => TaskPayload::Cancelled,",
        "            Some(RunStatus::Cancelled { .. }) => TaskPayload::Failed { error: error_object(\"cancelled\") },",
    ),
    "ADroppedLeaseReleasesNothing": (
        "src/keyring/coordinator.rs",
        "a_dropped_lease_frees_the_scope",
        "the lock lives beside the lease rather than inside it, so a lease "
        "dropped instead of released — a cancelled erasure, a `timeout` around "
        "a memory write — leaves the scope held by a lease that no longer "
        "exists, and every later erasure of that subject blocks forever with "
        "no error anywhere",
        """        Ok(Lease::holding(scope, token, client))""",
        """        std::mem::forget(client);
        Ok(Lease::new(scope, token))""",
    ),
    "AProviderCanReportItsWayUnderACeiling": (
        "src/model/mod.rs",
        "usage_a_provider_invented_cannot_wrap_a_ceiling",
        "the usage a provider reported is summed with a plain `+`, so a "
        "response claiming `u64::MAX` input tokens wraps to a spend of zero in "
        "a release build — the token ceiling is defeated by the counterparty "
        "whose consumption it exists to bound, and the run reads as free",
        """            tokens: self.input_tokens.saturating_add(self.output_tokens),""",
        """            tokens: self.input_tokens.wrapping_add(self.output_tokens),""",
    ),
    "CacheCountsBesideInputWrap": (
        "src/model/mod.rs",
        "usage_a_provider_invented_cannot_wrap_a_ceiling",
        "cache counts reported beside the prompt count are summed with "
        "wrapping arithmetic, so a hostile count bills a huge call as tiny",
        "                .saturating_add(cache_write_tokens)",
        "                .wrapping_add(cache_write_tokens)",
    ),
    "GeminiThoughtsWrapTheOutputCount": (
        "src/model/gemini.rs",
        "gemini_output_and_thought_counts_saturate",
        "visible and thinking tokens are summed with wrapping arithmetic, so a "
        "hostile count bills a huge call as tiny",
        """                .saturating_add(count("thoughtsTokenCount")),""",
        """                .wrapping_add(count("thoughtsTokenCount")),""",
    ),
    "AForgetSeversItsIncomingLineage": (
        "src/store/redb_memory.rs",
        "redb_satisfies_the_memory_store_contract",
        "an individual forget deletes the edges pointing at the memory it "
        "tombstones, so a later cascade from further upstream cannot route "
        "through it — a summary-of-a-summary is sheltered from its poisoned "
        "root's erasure by the correction that was supposed to help",
        """                // Edges deliberately stay — **both directions**. Outgoing,""",
        """                {
                    let mut edges = w.open_table(DERIVED).map_err(|e| be(&e))?;
                    let mut edges_rev = w.open_table(DERIVED_BY_TARGET).map_err(|e| be(&e))?;
                    let stale: Vec<(String, u64, u64)> = edges_rev
                        .range(
                            (tenant.as_str(), id.as_str(), 0, "", 0)
                                ..=(tenant.as_str(), id.as_str(), u64::MAX, MAX_STR, u64::MAX),
                        )
                        .map_err(|e| be(&e))?
                        .map(|entry| {
                            entry
                                .map(|(key, _)| {
                                    let (_, _, dv, sid, sv) = key.value();
                                    (sid.to_owned(), sv, dv)
                                })
                                .map_err(|error| be(&error))
                        })
                        .collect::<Result<_, StoreError>>()?;
                    for (source_id, source_version, derived_version) in stale {
                        edges
                            .remove((
                                tenant.as_str(),
                                source_id.as_str(),
                                source_version,
                                id.as_str(),
                                derived_version,
                            ))
                            .map_err(|e| be(&e))?;
                        edges_rev
                            .remove((
                                tenant.as_str(),
                                id.as_str(),
                                derived_version,
                                source_id.as_str(),
                                source_version,
                            ))
                            .map_err(|e| be(&e))?;
                    }
                }
                // Edges deliberately stay — **both directions**. Outgoing,""",
    ),
    "ACascadeCountsItsTombstones": (
        "src/store/redb_memory.rs",
        "redb_satisfies_the_memory_store_contract",
        "the cascade reports every node it visited as erased, tombstones "
        "included, so the count an erasure request is answered with claims "
        "removals this call did not perform",
        "                    if previous.is_some() || !versions.is_empty() {",
        "                    if true {",
    ),
    "AnAnswerIsRetriedAsAFault": (
        "src/runtime/ctx.rs",
        "a_refusal_that_is_an_answer_is_not_retried",
        "a refusal the peer meant as an answer — unknown model, malformed "
        "request — is retried under the full policy with backoff, burning "
        "every permitted attempt asking the same rule the same question and "
        "teaching the operator that retries are noise",
        """                if permanent {""",
        """                if permanent && false {""",
    ),
    "ARefusalsPermanenceIsNotRecorded": (
        "src/runtime/ctx.rs",
        "a_refusal_that_is_an_answer_is_not_retried",
        "the permanence of a refusal is dropped from the failure record, so "
        "the live run stops after one attempt while a strict replay — which "
        "recomputes the retry decision from history — expects the retry the "
        "live run never made and reports divergence over a faithful history",
        """                            // An answer, not a fault — recorded so the replayed
                            // retry decision stops where the live one did.
                            permanent: permanent_failure(effect, &e),""",
        """                            // An answer, not a fault — recorded so the replayed
                            // retry decision stops where the live one did.
                            permanent: false,""",
    ),
    "ATransientTimeoutIsAJudgement": (
        "src/model/wire.rs",
        "the_transient_4xx_are_not_judgements",
        "HTTP 408 and 425 — the server timing out or declining to process "
        "early — are classed as the provider judging the request wrong, so a "
        "hiccup becomes terminal: the retry loop spends no attempt on a "
        "refusal, and the two 4xx codes whose documented remedy is the retry "
        "are the two that never get one",
        """        408 | 425 => ModelError::Unavailable {
            model: model.clone(),
            detail,
        },""",
        """        408 | 425 => ModelError::Refused {
            model: model.clone(),
            detail,
        },""",
    ),
    "AShrunkenLogIsReportedAsRoutine": (
        "src/journal/witness_http.rs",
        "a_shrunken_log_is_an_integrity_finding_not_a_routine_one",
        "a witness answering 400 — 'the log you offer is smaller than where I "
        "am' — is reported as routine unavailability rather than a shrink, so "
        "runs deleted from a log the witness already cosigned never reach the "
        "integrity bucket and nobody is paged for the one event a witness exists "
        "to catch",
        """            400 if old_size > checkpoint.size => Err(WitnessError::Shrank {
                origin: checkpoint.origin.clone(),
                seen: old_size,
                offered: checkpoint.size,
            }),""",
        """            400 if old_size > checkpoint.size => {
                Err(WitnessError::Unavailable(format!("{url}: refused")))
            }""",
    ),
    "AConfusedWitnessInventsAShrink": (
        "src/journal/witness_http.rs",
        "an_off_spec_400_cannot_invent_a_shrink",
        "the guard on the 400 arm is dropped, so a witness answering 400 for a "
        "request whose own numbers show no shrink — an off-spec reply, a "
        "mis-parse, a proxy's error page — manufactures a fork-class alert, and "
        "an alert a counterparty can manufacture is one an operator learns to "
        "ignore",
        """            400 if old_size > checkpoint.size => Err(WitnessError::Shrank {""",
        """            400 if old_size <= u64::MAX => Err(WitnessError::Shrank {""",
    ),
    "AStaleWitnessCursorIsCalledAFork": (
        "src/journal/witness_http.rs",
        "a_stale_cursor_is_not_a_fork",
        "a witness answering 409 — 'your proof starts from a size I have moved "
        "past' — is reported as a forked history, so a routine retry pages "
        "somebody for an integrity incident and the alert that matters stops "
        "being believed",
        """                Ok(witness_size) => Err(WitnessError::Stale {
                    origin: checkpoint.origin.clone(),
                    witness_size,
                }),""",
        """                Ok(_) => Err(WitnessError::Forked {
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
        "src/core/b64.rs",
        "the_note_payload_is_rfc4648_base64",
        "the standard dialect is encoded with the URL-safe alphabet, which "
        "differs from the specified one in exactly two positions — so most "
        "checkpoints encode identically and the ones that do not are rejected "
        "by every verifier",
        "    base64::engine::general_purpose::STANDARD.encode(bytes)",
        "    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)",
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
        "a declared schema that permits everything is accepted, so a contract "
        "that constrains nothing reads in review as one that was declared — for "
        "the result shape and, since they are one rule, for the argument shape "
        "a model is offered",
        "            serde_json::Value::Object(m) if !m.is_empty() => Ok(()),",
        "            serde_json::Value::Object(_) => Ok(()),",
    ),
    "AVersionCanBeRepublished": (
        "src/manifest/registry.rs",
        "a_published_version_cannot_be_rewritten",
        "a published manifest version is overwritten rather than refused, so a "
        "widened tool grant reaches every consumer that pinned the version they "
        "reviewed",
        "    if existing != offered {",
        "    if false {",
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
        "                        key_id: record.signature.as_ref().map(|a| a.key_id.clone()),",
        "                        key_id: None,",
    ),
    # ── Cancellation ────────────────────────────────────────────────────────
    "StopDoesNotUnwind": (
        "src/runtime/executor.rs",
        "stopping_a_suspended_run_undoes_what_it_did",
        "a stopped run seals without undoing what it already did",
        "            RunStatus::Failed(_) | RunStatus::Cancelled { .. } => {}",
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
        "a stop unwinds only completed steps, leaving the suspended one's "
        "effects",
        """        mutated: &BTreeSet<StepId>,
    ) -> Vec<(StepId, Capability)> {
        let mut out = completed.to_vec();""",
        """        mutated: &BTreeSet<StepId>,
    ) -> Vec<(StepId, Capability)> {
        return completed.to_vec();
        #[allow(unreachable_code)]
        let mut out = completed.to_vec();""",
    ),
    "AStoppedRunResumes": (
        "src/runtime/executor.rs",
        "a_stopped_run_is_not_resumed_by_a_later_event",
        "a stopped run is resumed by the next event and carries on",
        '        "cancelled" => Some(recorded_cancellation(records).map_or_else(',
        '        "cancelled" if false => Some(recorded_cancellation(records).map_or_else(',
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
    "AnUnreportedEmbeddingIsFree": (
        "src/model/embeddings.rs",
        "a_priced_reply_without_a_token_count_is_refused",
        "a priced embedder whose reply reports no input tokens meters the call "
        "as zero, so it passes a money ceiling for free",
        "        (None, None) => 0,",
        "        (None, _) => 0,",
    ),
    "OpenAiEmbeddingUsageIgnoresPricing": (
        "src/model/embeddings.rs",
        "a_priced_embedder_refuses_a_reply_without_usage",
        "the OpenAI-wire embedder meters as if unpriced, so a reply with no "
        "usage costs nothing against a money ceiling",
        "                reply.usage.and_then(|u| u.prompt_tokens),\n                self.pricing,",
        "                reply.usage.and_then(|u| u.prompt_tokens),\n                None,",
    ),
    "GeminiEmbeddingUsageIgnoresPricing": (
        "src/model/embeddings.rs",
        "a_priced_embedder_refuses_a_reply_without_usage",
        "the Gemini embedder meters as if unpriced, so a reply with no "
        "usageMetadata costs nothing against a money ceiling",
        "            usage: metered(tokens, self.pricing, &url)?,",
        "            usage: metered(tokens, None, &url)?,",
    ),
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
        "src/model/mod.rs",
        "anthropic_cached_tokens_are_added_back",
        "a provider that reports cached counts beside the prompt count has them "
        "dropped rather than added back, so a cached run bills a fraction of "
        "its cost — on the buffered and streaming paths at once, because both "
        "reach this one arithmetic",
        """            input_tokens: input_tokens
                .saturating_add(cache_write_tokens)
                .saturating_add(cache_read_tokens),""",
        "            input_tokens,",
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
        "src/model/mod.rs",
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
        '            ("incomplete", Some("max_output_tokens")) => true,',
        '            ("incomplete", Some("max_output_tokens")) => false,',
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
            return Ok(PanelOutcome::Reached(Verdict::Pass, tally));
        }
        if tally.failed >= self.need {
            return Ok(PanelOutcome::Reached(Verdict::Fail, tally));
        }""",
        """        if tally.passed >= self.need || tally.passed > tally.failed {
            return Ok(PanelOutcome::Reached(Verdict::Pass, tally));
        }
        if tally.failed >= self.need {
            return Ok(PanelOutcome::Reached(Verdict::Fail, tally));
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
    # A plan is deserialized far more often than it is built — from a store,
    # from a journal, from a replanner parsing a model's proposal. That last one
    # is untrusted output, and a panel is exactly the control a hijacked plan
    # wants weakened: `need: 0` reports `Pass` having judged nothing.
    "ADeserializedQuorumIsUnchecked": (
        "src/core/quorum.rs",
        "a_deserialized_quorum_cannot_dodge_the_rules_the_constructor_enforces",
        "a quorum built by `serde` skips construction, so a panel needing "
        "nobody passes and a non-majority threshold resolves by tally order",
        "        Self::new(d.need, d.lenses)",
        """        Ok(Self {
            need: d.need,
            lenses: d.lenses,
        })""",
    ),
    # Arithmetic on a number the runtime did not choose. `time`'s duration
    # constructors multiply and its instant operators add, and **both panic**
    # rather than return — so the unchecked form of each of these turned a
    # typo in somebody's YAML into a process abort, in a plane hosting every
    # other tenant's in-flight run.
    "ARestoreIsJudgedByItsLabel": (
        "src/export.rs",
        "a_restore_writes_only_into_the_tenant_it_was_pointed_at",
        "a restore's verdict compares the log's *name* beside its commitment, so "
        "the recovery everybody actually performs — one tenant's history put "
        "back beside another's, in the database that survived — reports a "
        "byte-perfect restore as a failed one, and `agentplane restore` exits on it",
        "        self.expected.size == self.rebuilt.size && self.expected.root == self.rebuilt.root",
        "        self.expected == self.rebuilt",
    ),
    "AGraceWindowIsSubtractedUnchecked": (
        "src/runtime/executor.rs",
        "a_grace_window_past_the_calendar_retires_nothing",
        "the dead-letter cutoff subtracts its grace window from the clock "
        "without a check, so a caller asking to hold events indefinitely ends "
        "the tick that also breaches obligations and recovers abandoned runs",
        """        let cutoff = now_for_admission()
            .checked_sub(grace)
            .unwrap_or_else(crate::core::first_instant);""",
        "        let cutoff = now_for_admission() - grace;",
    ),
    "ACappedRedeliveryReadsAsAnOrdinaryTick": (
        "src/runtime/sweeper.rs",
        "a_capped_redelivery_pass_says_so",
        "the one backlog whose entries block their own retries is the one "
        "capped sweep that cannot say it is behind, so it drains a batch a "
        "tick while every counter reads normal",
        "                report.saturated.redeliveries = again.examined >= EVENT_BATCH;",
        "                report.saturated.redeliveries = false;",
    ),
    # Content-addressed erasure. The address is the content, so every one of
    # these turns "this was erased" into "this was erased, until somebody
    # produced the same bytes again".
    "ATombstoneIsGuessedAt": (
        "src/blob/opendal_store.rs",
        "a_tombstone_that_does_not_read_is_a_finding_not_an_erasure",
        "an unreadable tombstone is answered with a made-up date and reason, so "
        "a drill counts a completed erasure nobody can vouch for — the one "
        "verdict in that report that pages nobody",
        """        let stone: Tombstone = match serde_json::from_slice(&raw) {
            Ok(stone) => stone,
            Err(e) => return unreadable(e.to_string()),
        };""",
        """        let stone: Tombstone = serde_json::from_slice(&raw).unwrap_or(Tombstone {
            v: TOMBSTONE_FORMAT_VERSION,
            at: 0,
            reason: "expired".to_owned(),
        });""",
    ),
    "ATombstoneFromAnotherFormatIsRead": (
        "src/blob/opendal_store.rs",
        "a_tombstone_that_does_not_read_is_a_finding_not_an_erasure",
        "a tombstone written under a format this build does not implement is "
        "read field by field anyway, which is a verdict over evidence the "
        "reader did not understand",
        """        if stone.v != TOMBSTONE_FORMAT_VERSION {""",
        """        if false {""",
    ),
    "AnUnlimitedTaskRetentionReadsAsUnstated": (
        "src/tools/mcp.rs",
        "an_unlimited_retention_is_not_an_unstated_one",
        "`ttlMs: null` — the tasks extension's way of saying *no deadline* — is "
        "reported as *the server did not say*, which is the opposite "
        "instruction to a poll loop choosing how cautious to be",
        """            Some(Value::Null) => TaskRetention::Unlimited,""",
        """            Some(Value::Null) => TaskRetention::Unstated,""",
    ),
    "AWriteUndoesAnErasure": (
        "src/blob/memory.rs",
        "every_blob_store_satisfies_the_contract",
        "a write to an erased address is taken, so an Article 17 request "
        "reported as discharged is reversed by the next run that produces the "
        "same bytes — under a tombstone that still says when they went",
        """    async fn put_at(&self, digest: Digest, bytes: &[u8]) -> Result<(), BlobError> {
        // An expired address stays expired: the address is the content, so
        // writing the same bytes again lands on the erased object and puts the
        // data back under a tombstone that still says when it went.
        self.tombstone(digest)?;""",
        """    async fn put_at(&self, digest: Digest, bytes: &[u8]) -> Result<(), BlobError> {""",
    ),
    "AnObjectStoreWriteUndoesAnErasure": (
        "src/blob/opendal_store.rs",
        "every_blob_store_satisfies_the_contract",
        "the object-store backend takes a write to an erased address — the "
        "embedded one's refusal says nothing about the backend a deployment "
        "actually erases in",
        """        match self.absent(digest).await {
            // Nothing has been erased here, which is what "no tombstone" means
            // on the read path and the only answer that licenses a write.
            BlobError::NotFound(_) => {}
            refusal => return Err(refusal),
        }""",
        "",
    ),
    "AnErasedWriteIsAStoreFault": (
        "src/blob/mod.rs",
        "a_run_cannot_put_back_what_an_erasure_removed",
        "a refusal to resurrect erased bytes is classified as a backend "
        "failure, so every caller that tells an outage from a rule reads an "
        "enforced erasure as a store having a bad day",
        """        BlobError::Expired { digest, at, reason } => {
            crate::core::StoreError::BlobErased { digest, at, reason }
        }""",
        "",
    ),
    "ACalendarCountIsMultipliedUnchecked": (
        "src/core/calendar.rs",
        "a_count_that_cannot_be_a_duration_is_refused_not_a_panic",
        "a deadline's count is multiplied into a duration without a check, so "
        "`{kind: hours, params: {n: <large>}}` in a manifest aborts the process "
        "from inside the calendar instead of refusing the document",
        """        let seconds = match spec.kind.as_str() {
            "hours" => n.checked_mul(3_600),
            "days" => n.checked_mul(86_400),
            "minutes" => n.checked_mul(60),""",
        """        let seconds = match spec.kind.as_str() {
            "hours" => Some(time::Duration::hours(n).whole_seconds()),
            "days" => Some(time::Duration::days(n).whole_seconds()),
            "minutes" => Some(time::Duration::minutes(n).whole_seconds()),""",
    ),
    "AWindowIsAddedToAnInstantUnchecked": (
        "src/core/id.rs",
        "a_window_no_instant_can_carry_is_none_not_a_panic",
        "the one conversion from a window of seconds to an instant adds without "
        "a check, so every caller that believed it was refused instead aborts",
        """        .map(time::Duration::seconds)
        .and_then(|delta| from.checked_add(delta))""",
        """        .map(time::Duration::seconds)
        .map(|delta| from + delta)""",
    ),
    "ARetentionWindowIsUnbounded": (
        "src/manifest/mod.rs",
        "a_retention_window_no_instant_can_carry_is_refused_at_parse",
        "a declared retention window is bounded below and not above, so a "
        "document naming a window no instant can carry parses and fails later, "
        "at the step that forms memory",
        "            if seconds.is_some_and(|s| s > crate::core::MAX_WINDOW_SECONDS) {",
        "            if seconds.is_some_and(|s| s > u64::MAX) {",
    ),
    "ARetentionFlagIsSubtractedUnchecked": (
        "src/bin/agentplane.rs",
        "a_retention_window_past_the_calendar_is_a_message_not_an_abort",
        "a retention verb subtracts its operator's day count from the clock "
        "without a check, so a mistyped flag ends the command with `overflow "
        "subtracting duration from date` and no mention of the flag",
        """    now.checked_sub(time::Duration::days(i64::from(days)))
        .ok_or_else(|| {""",
        """    Some(now - time::Duration::days(i64::from(days)))
        .ok_or_else(|| {""",
    ),
    "AnAuditOverATruncatedListPasses": (
        "src/bin/agentplane.rs",
        "the_exit_statuses_are_one_table",
        "an audit whose run list `--limit` cut short exits zero when nothing it "
        "read was wrong, so a scheduler reads a partial view as a clean plane",
        "    } else if truncated.is_partial() {",
        "    } else if false {",
    ),
    "ALiftThatFoundNothingPasses": (
        "src/bin/agentplane.rs",
        "the_exit_statuses_are_one_table",
        "`halt --lift` on a scope with no halt standing exits zero, so an operator "
        "who cleared the wrong scope during an incident is told it worked",
        "    ExitCode::from(if was_standing {",
        "    ExitCode::from(if true {",
    ),
    "AUsageErrorExitsAsAnOutage": (
        "src/bin/agentplane.rs",
        "the_exit_statuses_are_one_table",
        "a refused flag exits with the outage status, so a scheduler pages "
        "somebody about the network for a typo in its own command",
        "            Self::Usage(_) => exit::USAGE,",
        "            Self::Usage(_) => exit::OPERATIONAL,",
    ),
    "APartialExportIsWritten": (
        "src/bin/agentplane.rs",
        "a_truncated_export_is_refused_without_allow_partial",
        "an export that `--limit` truncated is written anyway, framed exactly "
        "like a complete one, and handed to an auditor as the whole history",
        "    truncated.is_partial() && !allow_partial",
        "    false && !allow_partial",
    ),
    "APrintedHintCarriesThePassword": (
        "src/bin/agentplane.rs",
        "a_printed_next_step_carries_the_tenant_and_no_password",
        "the next step `run` prints repeats a `postgres://` password into "
        "stderr, where it is pasted into tickets and shared scrollback",
        "            let user = userinfo.split_once(':').map_or(userinfo, |(user, _)| user);",
        "            let user = userinfo;",
    ),
    "APrintedHintDropsTheTenant": (
        "src/bin/agentplane.rs",
        "a_printed_next_step_carries_the_tenant_and_no_password",
        "the next step `run` prints names no tenant, so pasting it resumes "
        "against the default plane and finds nothing",
        """        Some(t) => format!("{store} --tenant {}", shell_quote(t)),""",
        """        Some(_) => store,""",
    ),
    "AmbiguousPeerNamesShareAToken": (
        "src/bin/agentplane.rs",
        "ambiguous_peer_names_are_refused_at_boot",
        "two `--peer` names that normalise to one token variable are wired "
        "together, so one peer is sent the other's bearer token",
        "        if let Some(earlier) = seen.insert(var.clone(), name) {",
        "        if let Some(earlier) = seen.insert(var.clone(), name).filter(|_| false) {",
    ),
    "AJudgeNeedsASubject": (
        "src/plan/mod.rs",
        "a_panel_is_judges_over_a_subject_and_an_aggregator_over_the_judges",
        "a judge may be declared on a node that checks nothing, so a panel "
        "repeats the work instead of reviewing it — and for a mutating step, "
        "repeats it on the world",
        """    for n in plan.nodes.iter().filter(|n| n.verifies) {
        if n.depends_on.is_empty() {
            return Err(PlanError::VerifierWithoutSubject { step: n.id });
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
        "a_signature_cannot_be_lifted_onto_another_tool",
        "the signature covers the identifiers but not the call, so a block "
        "observed on one request verifies on any other",
        '''            "target": target,''',
        '''            "target": "",''',
    ),
    "ProvenanceIgnoresTheArguments": (
        "src/core/provenance.rs",
        "a_signature_cannot_be_lifted_onto_other_arguments",
        "the signature ignores the arguments, so the amount can be changed under "
        "a block that still verifies",
        '''            "arguments": Digest::of(canon::value_bytes(arguments).as_slice()).to_string(),''',
        '''            "arguments": "",''',
    ),
    "AnUnsignedBlockIsAccepted": (
        "src/core/provenance.rs",
        "an_unsigned_block_never_verifies",
        "a block with no signature verifies, so anything that strips the "
        "signature in transit is believed",
        """        let Some(a) = &self.signature else {
            return false;
        };""",
        """        let Some(a) = &self.signature else {
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
            && !undoing
        {
            return Err(StepError::Budget(exceeded));
        }''',
        "        let _ = (&self.ledger, undoing);",
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
        "        self.partial.push_str(&text);",
        "        self.partial = text;",
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
        "src/model/fake.rs",
        "an_answer_is_never_free",
        "the fake reports zero usage, so every token and cost ceiling test passes "
        "over a runtime that has stopped counting",
        "        input_tokens: (len / 4).max(1),\n        output_tokens: (len / 8).max(1),",
        "        input_tokens: 0,\n        output_tokens: 0,",
    ),
    "TheFakeIsExemptFromTheMediaRefusal": (
        "src/model/fake.rs",
        "the_fake_refuses_a_provider_side_media_url_like_every_driver",
        "the fake skips the provider-side media refusal every real driver makes, "
        "so a test proving that a caller-named URL never reaches a provider "
        "passes without the refusal existing — and an embedder concludes the "
        "plane permits what production refuses",
        "        crate::model::refuse_provider_side_media(request.prompt, request.model)?;",
        "        let _ = &request.prompt;",
    ),
    "TheFakeIgnoresADeclaredSchema": (
        "src/model/fake.rs",
        "a_declared_schema_binds_the_fake_the_way_it_binds_a_driver",
        "the fake records `output.schema` and ignores it, so a run scripted with "
        "prose completes and yields Null where every real driver answers "
        "Unusable — a stub passing tests no provider could pass",
        "            .and_then(|completion| honour_schema(completion, request.schema, request.model))",
        "            .map(|completion| completion)",
    ),
    "TheFakeIsNotDeterministic": (
        "src/model/fake.rs",
        "the_same_question_gets_the_same_answer",
        "the fake answers differently each call, so every replay test becomes a "
        "coin-toss that mostly passes",
        '        let scripted = self.scripted.lock().expect("fake").pop_front();\n'
        "        let answer = scripted\n"
        "            .unwrap_or_else(|| Ok(echo(&request)))",
        '        let scripted = self.scripted.lock().expect("fake").pop_front();\n'
        "        let n = self.calls();\n"
        "        let answer = scripted\n"
        "            .unwrap_or_else(|| {\n"
        "                let mut c = echo(&request);\n"
        '                c.text = format!("{} #{n}", c.text);\n'
        "                Ok(c)\n"
        "            })",
    ),
    "TheFakeScriptRunsBackwards": (
        "src/model/fake.rs",
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
            detail,
        });
    }""",
        """        return Err(ModelError::Refused {
            model: model.clone(),
            detail,
        });
    }""",
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
        "                agent: governed_by,",
        "                agent: None,",
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
        "the_internal_reference_detectors_recognise_what_they_are_for",
        "rustdoc may cite sections of the internal design document, which a "
        "docs.rs reader cannot resolve and which go stale silently",
        "    if NAMED_EXTERNAL.iter().any(|doc| before.contains(doc)) {",
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
    "LiftingAHoldNeedsOnlyThePowerToPlaceOne": (
        "src/api/mod.rs",
        "a_denying_policy_stops_every_route_before_it_touches_anything",
        "lifting a legal hold is authorized by the capability that places one, so "
        "every principal who can preserve a matter can also authorise its "
        "destruction — the one direction this pair must not be symmetric in",
        "    let s = api.gate(&headers, action::HOLD_RELEASE, &body.case).await?;",
        "    let s = api.gate(&headers, action::HOLD_PLACE, &body.case).await?;",
    ),
    "AServedResultInvitesASharedCache": (
        "src/tools/serve.rs",
        "every_cacheable_result_refuses_a_shared_cache_and_a_freshness_window",
        "served results carry the protocol's default cache scope, so a shared "
        "intermediary may hold a governed declaration and serve it to another "
        "principal — a copy no erasure reaches",
        "const CACHE_SCOPE: CacheScope = CacheScope::Private;",
        "const CACHE_SCOPE: CacheScope = CacheScope::Public;",
    ),
    "ARetentionSweepIgnoresALegalHold": (
        "src/blob/mod.rs",
        "erasing_a_held_case_directly_is_refused_before_anything_is_destroyed",
        "erase_case destroys a matter that is under a legal hold, so an automatic "
        "retention pass erases the one thing somebody was ordered to preserve",
        "    if let Some(hold) = cases.hold(case).await? {",
        "    if let Some(hold) = None::<crate::core::LegalHold> {",
    ),
    "AHeldMatterIsNotReported": (
        "src/retention.rs",
        "a_legal_hold_stops_the_retention_sweep_and_lifting_it_lets_the_sweep_through",
        "a retention pass preserves a held matter and says nothing about it, so the "
        "report reads as a clean sweep and nobody learns what is still being kept",
        "    for case in &selected.held {",
        "    for case in std::iter::empty::<&crate::core::CaseId>() {",
    ),
    "MediaBytesBypassTheSeal": (
        "src/runtime/ctx.rs",
        "only_the_sealed_accessor_reads_the_raw_blob_store",
        "the media path reads the raw blob store directly, so a sealed "
        "deployment writes those payload bytes in the clear",
        "        let blobs = self.blobs_scoped(fetcher.external_scope().as_deref())?;",
        "        let blobs = self.blobs.clone().expect(\"a blob store\");",
    ),
    "AVaultScopeReachesTheUrlRaw": (
        "src/keyring/vault.rs",
        "a_scope_maps_to_one_legal_transit_key_name",
        "a scope is written into the transit URL as it is, so an event scope "
        "carrying a counterparty's `?` or `#` truncates onto another message's "
        "key — erasing one erases both — and `..` walks the plane's token to "
        "another Vault path",
        """        self.url(&format!("{op}/{}", Self::key_name(scope)))""",
        """        self.url(&format!("{op}/{scope}"))""",
    ),
    "ASealedBlobIsBoundToItsAddressAlone": (
        "src/keyring/sealed.rs",
        "an_envelope_read_under_another_scope_does_not_open",
        "a sealed blob's associated data names the address and not the erasure "
        "unit, so an envelope read at the same address through another unit's "
        "handle opens as that unit's data — and survives the erasure of the unit "
        "it was sealed for wherever another unit's key still lives",
        """        format!("blob:{}:{}", self.scope, digest.to_hex())""",
        """        format!("blob:{}", digest.to_hex())""",
    ),
    "ARetiredBlobKeyReadsAsAnOutage": (
        "src/keyring/sealed.rs",
        "a_retired_key_version_reads_as_unopened",
        "a blob whose wrapping-key version an operator retired is reported as a "
        "backend outage, so a reversible configuration change reads as "
        "something retrying will clear rather than as intact bytes a setting "
        "keeps shut",
        """        e @ (KeyError::Retired { .. }""",
        """        KeyError::Retired { scope, .. } => BlobError::Backend(scope),
        e @ (KeyError::Retired { .. }""",
    ),
    "AnErasedEventReachesItsWaiterSealed": (
        "src/keyring/events.rs",
        "a_failed_cleanup_is_reported_and_the_erased_message_is_not_delivered",
        "a message whose key was destroyed but whose row was still claimable is "
        "delivered with its `$sealed` wrapper in place of the payload, so a run "
        "journals ciphertext nobody can open as the counterparty's reply",
        """        let Some(payload) = self.payload(&buffered.event).await? else {""",
        """        let Some(payload) = Some(self.payload(&buffered.event).await?.unwrap_or_else(|| buffered.event.payload.clone())) else {""",
    ),
    "AnEventCleanupFailureReadsAsDone": (
        "src/keyring/events.rs",
        "a_failed_cleanup_is_reported_and_the_erased_message_is_not_delivered",
        "an event erasure whose ciphertext cleanup failed after the key's "
        "destruction is reported as clean, so the request is closed over a live "
        "row a retry of the same call would have removed",
        """                    cleanup_failed: Some(error.to_string()),""",
        """                    cleanup_failed: None,""",
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
        "src/core/tenant.rs",
        "erasing_one_tenants_key_leaves_another_tenant_readable",
        "the erasure scope drops the tenant, so two tenants using one case "
        "name share a key scope and a blob address, and either can erase the "
        "other's data",
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
    # The rule above, reached through the door that skips it. A `TenantId`
    # arrives from a credential claim, a store row and a journal record far more
    # often than from a call to `new`, and units already carry separators
    # (`event/{source}/{id}`) — so a name holding one lands on another tenant's
    # scope exactly, and either tenant's erasure destroys the other's key.
    "ADeserializedTenantNameIsUnchecked": (
        "src/core/tenant.rs",
        "a_deserialized_tenant_name_cannot_carry_a_scope_separator",
        "a tenant name arriving through `serde` skips the newtype's validation, "
        "so a name carrying '/' derives another tenant's key scope",
        "        Self::new(name)",
        "        Ok(Self(name))",
    ),
    "AStoreKeyDropsTheTenant": (
        "src/store/redb.rs",
        "a_tenant_cannot_read_another_tenants_run_even_holding_its_id",
        "a run's storage key drops the tenant, so any tenant holding a run id "
        "reads another tenant's journal",
        "    format!(\"{tenant}/{run}\")",
        "    run.to_owned()",
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
        "        origin_key(&self.source, &self.id)",
        "        self.id.clone()",
    ),
    "ADeliveredEventChoosesItsOwnSource": (
        "src/api/mod.rs",
        "a_delivered_events_source_is_the_authenticated_caller",
        "a caller names the source of the event it delivers, so it controls both "
        "halves of the dedup identity and can deduplicate against another party",
        "    let event = input.into_event(peer_source(&s.caller.actor));",
        "    let event = input.into_event(\"urn:anonymous\".to_owned());",
    ),
    "ACloudEventDedupesOnIdAlone": (
        "src/core/cloudevent.rs",
        "two_producers_behind_one_gateway_do_not_collide",
        "an arriving CloudEvent is deduplicated on `id` alone rather than on "
        "CloudEvents' `(source, id)` pair, so a gateway relaying two "
        "counterparties that both number their messages from one swallows the "
        "second as a retry of the first, silently",
        "        crate::core::origin_key(&self.source, &self.id)",
        "        self.id.clone()",
    ),
    "AnUnknownEnvelopeIsGuessedAt": (
        "src/core/cloudevent.rs",
        "what_is_refused_and_why",
        "an envelope naming a spec version this plane was not written against "
        "is accepted anyway, so a payload nobody here has understood is handed "
        "to a run as if it had been",
        "        if wire.specversion != SPEC_VERSION {\n"
        "            return Err(CloudEventError::UnknownSpecVersion(wire.specversion));\n"
        "        }",
        "        if false {\n"
        "            return Err(CloudEventError::UnknownSpecVersion(wire.specversion));\n"
        "        }",
    ),
    "AnAwaitedEventsSenderIsNotJournaled": (
        "src/runtime/executor.rs",
        "an_awaited_events_sender_is_in_its_provenance_and_survives_replay",
        "a delivered event's sender is not journaled, so a replayed run labels "
        "the value differently from the live one",
        "                            source: Some(event.source.clone()),",
        "                            source: None,",
    ),
    "AClosedRunKeepsItsWaits": (
        "src/runtime/executor.rs",
        "a_cancelled_sleeping_run_leaves_no_timer_armed",
        "a run that concludes closed keeps its timers, subscriptions and awaited "
        "tasks, so every sweep claims and fails a sealed run's timer, the next "
        "event on its key goes to a run that cannot consume it, and its task "
        "stays in the worklist",
        "                self.retire_waits(run).await;",
        "",
    ),
    "ASealedRunsTimerIsFired": (
        "src/store/redb_timers.rs",
        "a_sealed_runs_leftover_timer_is_retired_not_fired",
        "a sealed run's leftover timer is claimed and fired, fails to append on "
        "the sealed journal, and is claimed again every lease period for ever",
        "                        if is_sealed(&w, &tenant, &run)? {",
        "                        if false {",
    ),
    "AHeldTimerFillsThePage": (
        "src/store/redb_timers.rs",
        "redb_satisfies_the_case_layer_contracts",
        "the due scan takes `limit` candidates before skipping the ones another "
        "sweeper holds, so a page of held timers at the head of the due order "
        "hides every due timer behind it — silently, a short page reading as a "
        "quiet plane",
        "                    let Some(last) = candidates.last().cloned() else {\n                        break;\n                    };\n                    after = Some(last);",
        "                    let Some(last) = candidates.last().cloned() else {\n                        break;\n                    };\n                    if after.is_some() {\n                        break;\n                    }\n                    after = Some(last);\n                    let candidates: Vec<_> = candidates.into_iter().take(limit).collect();",
    ),
    "ASealedRunTakesTheEvent": (
        "src/store/redb_events.rs",
        "a_sealed_runs_leftover_wait_does_not_take_the_event",
        "a sealed run's leftover wait is still the oldest waiter on its key, so "
        "the event is claimed for a run that cannot consume it and the live "
        "waiter behind it starves",
        "            if is_sealed(w, tenant, run)? {",
        "            if false {",
    ),
    "ARedeliveryReadsEveryWait": (
        "src/runtime/executor.rs",
        "a_parked_delivery_behind_a_page_of_long_waits_is_redelivered",
        "the redelivery pass pages every registered wait oldest first, so a "
        "plane's long legitimate waits fill the page and a delivery parked "
        "after them is never finished",
        "            .parked_waits(limit)",
        "            .waiting(limit)",
    ),
    "AClosedRunsTaskStaysOpen": (
        "src/store/redb_tasks.rs",
        "a_cancelled_runs_open_task_is_withdrawn",
        "a cancelled run's awaited task stays open, offered for a decision no "
        "answer can reach and counted in the backlog",
        "                    && settle(&w, &tenant, &key, &task, TaskState::Withdrawn)?",
        "                    && false",
    ),
    "AnAnsweredTaskIsWithdrawn": (
        "src/runtime/executor.rs",
        "a_decision_resumes_the_run_and_names_the_decider",
        "a run's conclusion withdraws the task whose answer it just consumed, "
        "landing before the decider's own settlement — so an approved task "
        "reads `withdrawn` and the worklist loses who decided it",
        "        .filter(|k| !settled.contains(k))",
        "",
    ),
    "ASettledTaskIsSettledAgain": (
        "src/store/redb_tasks.rs",
        "redb_satisfies_the_case_layer_contracts",
        "a task's settlement is unconditional, so the expiry that lost the race "
        "to a decision overwrites it and the worklist contradicts the answer "
        "the run consumed",
        "    if !task.state.is_pending() {\n        return Ok(false);",
        "    if false {\n        return Ok(false);",
    ),
    "AnExpiryOverwritesADecision": (
        "src/runtime/sweeper.rs",
        "an_expiry_that_lost_to_a_decision_does_not_settle_the_task",
        "the sweep settles a task whose run already consumed a reviewer's "
        "answer, so the worklist says the window lapsed over a run that acted "
        "on a person's approval",
        "                    if delivery == crate::core::Delivery::Duplicate {",
        "                    if false {",
    ),
    "ALosingDecisionIsReported": (
        "src/runtime/sweeper.rs",
        "a_decision_that_lost_to_an_expiry_is_refused",
        "a decision the run never consumed is reported delivered and recorded "
        "as completed, so the worklist names a decider whose approval nothing "
        "acted on",
        "        if matches!(delivery, crate::core::Delivery::Duplicate) {",
        "        if false {",
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
        "        summary_label.sensitivity = sensitivity;",
        "        summary_label.sensitivity = crate::core::Sensitivity::Public;",
    ),
    "CompactionIgnoresTheCeiling": (
        "src/runtime/ctx.rs",
        "compaction_cannot_exceed_the_sensitivity_ceiling",
        "compaction does not bound what the summarising model may be shown, so "
        "summarising becomes the route by which confidential memories reach a "
        "model that may not see them — while looking like housekeeping",
        "                    .observed_by(stream.clone())\n                    .with_max_sensitivity(max_sensitivity)",
        "                    .observed_by(stream.clone())\n                    .with_max_sensitivity(crate::core::Sensitivity::Secret)",
    ),
    "ASummaryForgetsWhatItWasMadeFrom": (
        "src/store/redb_memory.rs",
        "forgetting_a_source_can_reach_what_was_derived_from_it",
        "derivation edges are not written, so a poisoned memory can be forgotten "
        "while every summary that absorbed it stays readable — the attack "
        "outliving its own remedy",
        "                for source in &item.derived_from {\n"
        "                    derived\n"
        "                        .insert(\n"
        "                            (\n"
        "                                tenant.as_str(),\n"
        "                                source.id.as_str(),\n"
        "                                source.version,\n"
        "                                id.as_str(),\n"
        "                                version,\n"
        "                            ),\n"
        "                            (),\n"
        "                        )\n"
        "                        .map_err(|e| be(&e))?;\n"
        "                    derived_rev\n"
        "                        .insert(\n"
        "                            (\n"
        "                                tenant.as_str(),\n"
        "                                id.as_str(),\n"
        "                                version,\n"
        "                                source.id.as_str(),\n"
        "                                source.version,\n"
        "                            ),\n"
        "                            (),\n"
        "                        )\n"
        "                        .map_err(|e| be(&e))?;\n"
        "                }",
        "",
    ),
    "ANoteFailureDoesNotStopTheTakeover": (
        "src/runtime/sweeper.rs",
        "a_takeover_whose_note_cannot_be_written_is_not_taken",
        "a takeover note that cannot be written no longer stops the takeover, "
        "so the sweep fences and resumes a run whose account no journal "
        "carries — and the resume releases the lease, so no later tick can "
        "re-select the run and write it",
        """                .await?;
            match self.recover_abandoned_run(run).await {""",
        """                .await.ok();
            match self.recover_abandoned_run(run).await {""",
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
    "AnAbortedGroupStillMarksItsStep": (
        "src/runtime/executor.rs",
        "a_cleanly_aborted_group_leaves_its_step_nothing_to_unwind",
        "the unwind evidence ignores a group's Aborted settlement, so a step "
        "whose group was taken back whole reads as having changed the world — "
        "quarantined when it declares no compensation, undone twice when it does",
        "                    if *outcome == crate::core::GroupOutcome::Aborted {",
        "                    if *outcome == crate::core::GroupOutcome::Committed {",
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
    "AnUnrecordedOutcomeTakesTheCheapAbort": (
        "src/runtime/group.rs",
        "a_send_whose_outcome_could_not_be_recorded_is_not_reported_taken_back",
        "a member that landed but whose terminal record was refused reads as "
        "never dispatched, so the group settles Aborted — the journal claiming "
        "taken back whole over a send already delivered, whose orphaned "
        "announcement the next resume re-performs",
        """        StepError::Unrecorded { disposition, .. } => {
            *disposition != crate::core::Disposition::DidNotHappen
        }""",
        """        StepError::Unrecorded { .. } => false,""",
    ),
    "ALandedCallIsRecordedAsNotHappened": (
        "src/runtime/ctx.rs",
        "a_send_whose_outcome_could_not_be_recorded_is_not_reported_taken_back",
        "a call that returned successfully before its record was refused is "
        "classified as never having happened, so everything that branches on "
        "whether it reached the world — the group's cheap abort first — acts "
        "on a fabrication",
        """                let unrecorded = |key, detail: String| StepError::Unrecorded {
                    key,
                    disposition: crate::core::Disposition::Landed,
                    detail,
                };""",
        """                let unrecorded = |key, detail: String| StepError::Unrecorded {
                    key,
                    disposition: crate::core::Disposition::DidNotHappen,
                    detail,
                };""",
    ),
    "ARecordedDenialIsReDecidedOnResume": (
        "src/runtime/group.rs",
        "a_resumed_atomic_member_consumes_its_recorded_denial",
        "the atomic-member path consumes a recorded gate refusal and then runs "
        "the gate fresh, so a resume under a gate that has since relented "
        "dispatches — and commits — a member the recorded run was refused, "
        "appending a second history under the same key",
        """                    Some(
                        refusal @ (crate::journal::EffectReplay::Refused { .. }
                        | crate::journal::EffectReplay::Denied { .. }),
                    ) => {
                        self.replayed_refusal(key, &descriptor, refusal, 0).await?;
                    }""",
        """                    Some(
                        refusal @ (crate::journal::EffectReplay::Refused { .. }
                        | crate::journal::EffectReplay::Denied { .. }),
                    ) => {
                        let _ = refusal;
                    }""",
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
        "        !self.phase.is_forward() || self.reversing",
        "        !self.phase.is_forward()",
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
        "src/policy/requests.rs",
        "a_rule_can_refuse_an_effect_for_where_its_arguments_came_from",
        "the label never reaches the authorization request, so provenance and "
        "authorization are two graphs that only meet in checks written in this "
        "crate — a deployment can say 'amounts over 5000 need approval' but not "
        "'not with data that passed through that peer'",
        "    if let Some(label) = label {\n        context[\"label\"] = serde_json::to_value(label.for_policy()).unwrap_or(Value::Null);\n    }",
        "    let _ = label;",
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
        "        if prompt.get(\"system\").is_some_and(|s| !s.is_null()) {\n"
        "            vec![crate::core::ProtectedField::trusted(\"/system\")]\n"
        "        } else {\n"
        "            Vec::new()\n"
        "        }",
        "        let _ = prompt;\n        Vec::new()",
    ),
    "ARecalledMemoryEntersThePromptTrusted": (
        "src/runtime/declarative.rs",
        "a_recalled_memory_reaches_the_prompt_with_its_own_label",
        "a declared recall relabels every memory it reads as trusted on the way "
        "into the prompt, so a fact a model wrote last week is believed this "
        "week — the cross-session laundering the whole memory tier is shaped to "
        "refuse, performed by the tier that reads it",
        "        parts.push((\"memory\".to_owned(), remembered));",
        "        parts.push((\"memory\".to_owned(), Tainted::trusted(remembered.peek().clone())));",
    ),
    "ADeclaredInstructionIsTaintedByItsCaller": (
        "src/runtime/declarative.rs",
        "a_declared_instruction_survives_an_untrusted_input",
        "a declarative agent builds its prompt by mapping over the caller's "
        "input, so the manifest's own reviewed, digest-pinned instruction "
        "inherits the caller's label — the declared order becomes "
        "indistinguishable from the data, and an agent reachable over A2A is "
        "refused as though the peer had written its prompt",
        "    let mut parts = vec![\n"
        "        (\"system\".to_owned(), Tainted::trusted(json!(system))),",
        "    let mut parts = vec![\n"
        "        (\"system\".to_owned(), input.clone().map(|_| json!(system))),",
    ),
    "ASemanticLimitIsAdvisory": (
        "src/runtime/effects.rs",
        "a_retriever_that_overruns_the_limit_is_refused",
        "a retriever may return more hits than the caller's declared limit, so "
        "the ceiling is advisory: the selection's membership ends up decided by "
        "the seam's iteration order, and every extra hit costs a store read and "
        "a slot in whatever window the caller was sizing",
        "        if hits.len() > self.query.limit {",
        "        if false {",
    ),
    "AStaleSemanticHitIsServed": (
        "src/runtime/effects.rs",
        "a_stale_semantic_index_is_screened_not_served_and_not_fatal",
        "the lifecycle screen keeps every hit the index names, so a superseded "
        "version is served after its correction, an expired one past its "
        "stated disposal date, and an erased one fails the whole query — "
        "routine retention arriving as a semantic-search outage",
        "            if current.is_some_and(|item| item.version == hit.selected.version) {",
        "            if true {",
    ),
    "TheEmbeddingSpaceIsNotChecked": (
        "src/runtime/executor.rs",
        "an_embedder_that_does_not_speak_the_indexs_language_is_refused_at_build",
        "the plane accepts an embedder whose revision is not the one the index "
        "declares it takes queries in — cosine similarity is defined between "
        "any two equal-width vectors, so every search then ranks unrelated "
        "memories confidently and nothing ever throws",
        "            if embedder != index {\n"
        "                return Err(BuildError::EmbeddingSpaceMismatch { embedder, index });\n"
        "            }",
        "            let _ = (&embedder, &index);",
    ),
    "APlannedAgentMayRecall": (
        "src/manifest/mod.rs",
        "a_planned_agent_may_not_declare_a_recall",
        "a `planned` agent may declare `memory.recall`, so memories written by "
        "a model reach the planner that compiles the run's authorization order "
        "— the untrusted-input refusal that kind exists for, walked around "
        "through the store",
        "        if self.spec.execution.as_ref().map(|e| e.kind) == Some(ExecutionKind::Planned) {",
        "        if false {",
    ),
    "ARecallMayReadNothing": (
        "src/manifest/mod.rs",
        "a_recall_limit_outside_the_declared_band_is_refused",
        "a recall may declare `limit: 0`, which reads in review as a ceiling "
        "and behaves as an agent that remembers nothing",
        "        if !(1..=50).contains(&recall.limit) {",
        "        if false {",
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
        "            self.gate(key, key, &descriptor, true, None, None, 0)\n"
        "                .await?;",
        "",
    ),
    "ARewrittenMemoryIsOnlyAFailure": (
        "src/runtime/executor.rs",
        "a_memory_rewritten_under_a_run_quarantines_it",
        "a run whose pinned read came back different is filed as `Failed` — an "
        "ordinary, resumable outcome sharing a bucket with a store that was "
        "briefly unreachable — so the one conclusion meaning *the durable record "
        "is not trustworthy* never reaches the quarantine backlog",
        "                        | StepError::Unreproducible { .. }",
        "",
    ),
    "ABreachIgnoresAMetObligation": (
        "src/store/redb_cases.rs",
        "an_obligation_met_during_the_sweep_is_not_breached",
        "the conditional breach no longer checks the obligation is still owed, "
        "so a run that met it and closed the case after the sweep's read loses "
        "to a stale decision — a met duty reported as missed, a closed matter "
        "reopened, and the refusal ends the tick",
        "            if !is_outstanding(&row.4) || row.0 > now {",
        "            if row.0 > now {",
    ),
    "AMootWarningEndsTheTick": (
        "src/runtime/sweeper.rs",
        "an_obligation_met_during_the_sweep_is_not_breached",
        "a warning for an obligation a run met since the read is treated as a "
        "failure, so a race the sweep lost correctly aborts every later phase "
        "of the tick",
        "                    Err(StoreError::DeadlineFinal { .. }) => {",
        "                    Err(e @ StoreError::DeadlineFinal { .. }) => return Err(RuntimeError::from_store(e)),\n                    Err(StoreError::DeadlineFinal { .. }) => {",
    ),
    "ALostBreachIsLeftStanding": (
        "src/runtime/sweeper.rs",
        "an_obligation_met_during_the_sweep_is_not_breached",
        "a breach the store refused because a run met the obligation first "
        "is noted anyway, so the sweep's journal claims a breach of a duty "
        "that was met",
        "                if applied {",
        "                if true || applied {",
    ),
    "AnOwedBreachIsNeverNoted": (
        "src/runtime/sweeper.rs",
        "a_breach_whose_notes_were_lost_is_noted_by_the_next_tick_once",
        "the tick never drains the breaches a crashed tick applied without "
        "noting, so a breach that left due before its notes landed has no "
        "account on the journal at all",
        "        for deadline in owed {",
        "        for deadline in owed.into_iter().take(0) {",
    ),
    "ABreachOwesNoAccount": (
        "src/store/redb_cases.rs",
        "redb_satisfies_the_case_layer_contracts",
        "an applied breach is not marked as owing its account, so a crash "
        "between the breach and its notes leaves a breach no tick will ever "
        "note",
        "                .insert((tenant.as_str(), key.as_str(), name.as_str()), ())",
        "                .remove((tenant.as_str(), key.as_str(), name.as_str()))",
    ),
    "PostgresABreachOwesNoAccount": (
        "src/store/postgres_cases.rs",
        "postgres_satisfies_the_case_layer_contracts",
        "the Postgres breach does not mark the obligation as owing its "
        "account, so a crash between the breach and its notes leaves a "
        "breach no tick will ever note",
        "SET state = $4, breach_unnoted = TRUE",
        "SET state = $4, breach_unnoted = FALSE",
    ),
    "AMootWarningIsLeftStanding": (
        "src/runtime/sweeper.rs",
        "an_obligation_met_during_the_sweep_is_not_breached",
        "a warning the store refused because the obligation was already met "
        "is not corrected on the record, so the sweep's journal ends on a "
        "'warned' note about a settled duty",
        "                                deadline.case.to_string(),\n                                SweptAction::NotApplied,",
        "                                deadline.case.to_string(),\n                                SweptAction::DeadlineWarned,",
    ),
    "AnExpiryMeetingAnAnswerNeverSettles": (
        "src/runtime/sweeper.rs",
        "an_expiry_meeting_a_given_answer_settles_the_task_once",
        "an expiry that meets an answer already on record skips the task "
        "without settling it, so it stays overdue and every tick writes a "
        "fresh expiry note for an expiry that never applied",
        "                        match self.settle_answered(task.id).await? {",
        "                        match None::<crate::case::Minter> {",
    ),
    "AResubmittedAnswerIsRefused": (
        "src/runtime/sweeper.rs",
        "a_resubmitted_decision_is_not_a_second_answer",
        "a decider resubmitting their own answer after its settlement was "
        "lost is refused as already answered, so the task their answer "
        "decided stays pending with no door left to settle it",
        "            if own {",
        "            if false && own {",
    ),
    "AWarnedObligationKeepsItsWarningKey": (
        "src/store/redb_cases.rs",
        "a_warned_obligation_does_not_hide_an_overdue_one",
        "a warned obligation stays keyed at its warning instant, so a page of "
        "them sorts ahead of an obligation already past due and the breach the "
        "sweep exists for waits behind obligations that are not due",
        "    if state == DeadlineState::Warned.as_str() {",
        "    if false {",
    ),
    "AConditionalReleaseIgnoresTheReadHold": (
        "src/store/redb_cases.rs",
        "redb_satisfies_the_case_layer_contracts",
        "a release naming the hold it read removes whatever stands, so a hold "
        "placed since that read is lifted under a record naming the old one and "
        "the matter it preserves is open to erasure",
        "                        same.then_some(at)",
        "                        Some(at)",
    ),
    "ABreachedObligationIsNotListed": (
        "src/store/redb_cases.rs",
        "redb_satisfies_the_case_layer_contracts",
        "the breach listing answers empty, so a missed obligation is reachable "
        "only through the case that produced it — and `close` retires that "
        "handle at the moment people stop looking",
        "    DeadlineState::parse(state).is_some_and(|s| s.is_unaccounted(has_ack != 0))",
        "    DeadlineState::parse(state).is_some_and(|s| s.is_unaccounted(true))",
    ),
    "AnAcknowledgedBreachStaysListed": (
        "src/core/case.rs",
        "redb_satisfies_the_case_layer_contracts",
        "an answered breach stays on the listing, so the page is ordered "
        "oldest-first over entries nothing removes — its head is permanent and "
        "every later breach is unreachable",
        "        matches!(self, Self::Breached) && !accounted",
        "        matches!(self, Self::Breached)",
    ),
    "AnObligationLandsOnAClosedCase": (
        "src/store/redb_cases.rs",
        "redb_satisfies_the_case_layer_contracts",
        "an obligation is registered on a closed case, so `close` refusing an "
        "outstanding one is a check at an instant rather than a property of the "
        "store — the sweep breaches the late obligation and escalates a matter "
        "audited as settled",
        "                    .is_some_and(|v| v.value().1 == CaseStatus::Closed.as_str());",
        "                    .is_some_and(|v| v.value().1 == CaseStatus::AwaitingExternal.as_str());",
    ),
    "AReopenedCaseStaysUncorrelatable": (
        "src/store/redb_cases.rs",
        "redb_satisfies_the_case_layer_contracts",
        "a case that leaves `Closed` does not take back its correlation keys, "
        "so it comes back live-looking and unreachable — no inbound message can "
        "ever correlate to the matter the sweep just reopened",
        "                if was == CaseStatus::Closed.as_str() {",
        "                if was == CaseStatus::Escalated.as_str() {",
    ),
    "AnOversizedAnswerIsRead": (
        "src/netguard/intake.rs",
        "an_oversized_answer_is_refused_rather_than_read",
        "an answer is read to end-of-stream, so a model endpoint, a peer, a "
        "witness or a key service decides how much of this process's memory its "
        "reply costs — and one OOM takes down every run on the instance",
        "        if self.seen > self.limit {",
        "        if self.seen > usize::MAX {",
    ),
    "ADeclaredOversizeIsRead": (
        "src/netguard/intake.rs",
        "a_declared_oversize_is_refused_before_a_byte_is_read",
        "a counterparty that says how big its answer will be is read anyway, so "
        "the cheap refusal never fires and the honest large answer costs a full "
        "read before it is rejected",
        "    if let Some(declared) = declared\n        && declared > limit as u64",
        "    if let Some(declared) = declared\n        && declared > u64::MAX",
    ),
    "AnOversizedStreamIsAccumulated": (
        "src/model/anthropic.rs",
        "an_oversized_stream_is_refused_rather_than_accumulated",
        "a stream is accumulated without a ceiling: `sse::Decoder` bounds one "
        "event, so well-formed hundred-byte deltas pass every check it makes "
        "while the accumulator grows until the process dies",
        "            if let Err(e) = meter.charge(chunk.len()) {",
        "            if let Err(e) = meter.charge(0) {",
    ),
    "ABreachIsEditedAway": (
        "src/store/redb_cases.rs",
        "redb_satisfies_the_case_layer_contracts",
        "an obligation can be moved out of `breached`, so a run answering late "
        "takes the miss off the operator's listing and out of the row at once — "
        "the only record that the window closed unmet, erased rather than stale",
        "    if !from.may_become(state) {",
        "    if false {",
    ),
    "APostgresObligationLandsOnAClosedCase": (
        "src/store/postgres_cases.rs",
        "postgres_satisfies_the_case_layer_contracts",
        "the SQL backend accepts an obligation on a closed case; the redb "
        "mutation cannot reach this copy of the rule, and a rule enforced by "
        "one backend of two is a deployment-shaped hole",
        "        if status == CaseStatus::Closed.as_str() {",
        "        if status == CaseStatus::AwaitingExternal.as_str() {",
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
        # Both gates in one edit, because either alone is caught by the other:
        # a quiet tick has no run *and* has written nothing, so a mutation that
        # removes only one of them changes no outcome and reports a guarantee
        # as verified that nothing checked.
        "        let Some(run) = self.run else {\n            return SweepRecord::Quiet;\n        };\n        if !self.wrote {",
        "        let run = self.run.unwrap_or_else(RunId::generate);\n        if false {",
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
        "                    outbound_label: outbound.map(|o| o.label.clone()),",
        "                    outbound_label: None,",
    ),
    "InPlaneHandoffIsUngoverned": (
        "src/runtime/ctx.rs",
        "a_specialist_cannot_commission_another_agent",
        "the delegation ceiling is not consulted on the path `cx.commission` "
        "takes, so it governs the A2A peer call and not the function call — a "
        "specialist hands work off inside one process, and A->B->C->A is "
        "reachable with no peer boundary to cross and no allowlist to notice",
        "        self.refuse_excess_delegation(&effect, &descriptor).await?;",
        "",
    ),
    "ADerivedCatalogueRelaxesAGrant": (
        "src/tools/mod.rs",
        "a_catalogue_derived_from_a_manifest_keeps_its_security_fields",
        "a catalogue derived from a manifest drops the grant's protected "
        "fields, so a reviewer's field rules vanish on the way to the runtime — "
        "worse than the duplication it replaced, because the operator believes "
        "they declared something they did not",
        "            protected_fields: grant.protected_fields.clone(),",
        "            protected_fields: Vec::new(),",
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
        "            tools\n                .check_against(manifest, &reachable_elsewhere)",
        "            if declared > 1 {\n                continue;\n            }\n"
        "            tools\n                .check_against(manifest, &reachable_elsewhere)",
    ),
    "EmbeddingIsComputedNotObserved": (
        "src/runtime/ctx.rs",
        "a_replayed_run_reads_its_embedding_back_rather_than_asking_again",
        "the embedding service is called directly instead of through the effect "
        "protocol, so a replay asks again and gets different floats — and since "
        "the query vector is in the semantic-retrieval effect key, the run "
        "quarantines itself with nothing on the record explaining why",
        "        self.sink_with(&arguments, |value| crate::runtime::effects::Embed {",
        "        {\n"
        "            let crate::memory::Embedded { vector, usage } =\n"
        "                embedder.embed(&plain).await.map_err(StepError::Store)?;\n"
        "            let revision = embedder.revision();\n"
        "            return Ok(Tainted::trusted(crate::memory::Embedding { vector, revision, usage }));\n"
        "        }\n"
        "        #[allow(unreachable_code)]\n"
        "        self.sink_with(&arguments, |value| crate::runtime::effects::Embed {",
    ),
    "MemoryFormsBeforeTheHumanDecides": (
        "src/runtime/declarative.rs",
        "a_refused_answer_is_not_written_into_memory",
        "an answer is written into durable memory before oversight decides, so "
        "a reviewer's refusal fails the run while the refused answer stays a "
        "standing fact the next run reads as established",
        "        if let Some(spec) = oversight.as_ref().filter(|s| s.gates_the_answer()) {",
        "        self.form_answer(cx, formation, formed_source.clone(), input, role)\n"
        "            .await?;\n"
        "        if let Some(spec) = oversight.as_ref().filter(|s| s.gates_the_answer()) {",
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
        "            keys.sort_unstable_by(|a, b| (a.0, a.1, a.2.as_str()).cmp(&(b.0, b.1, b.2.as_str())));",
        "            keys.sort_unstable_by(|a, b| (a.1, a.2.as_str()).cmp(&(b.1, b.2.as_str())));",
    ),
    "AHaltDoesNotStopAnUnlimitedTenant": (
        "src/runtime/executor.rs",
        "a_halt_refuses_new_runs_on_every_instance_and_names_the_reason",
        "the emergency stop is checked after the no-ceilings shortcut, so a "
        "tenant with no quotas configured cannot be halted at all — which is "
        "the tenant an operator is most likely to need to stop",
        "        match quotas.halts().await {",
        "        if self.quota.is_unlimited() {\n            return Ok(pass);\n        }\n        match quotas.halts().await {",
    ),
    "APreviewIsNeverComputed": (
        "src/runtime/declarative.rs",
        "a_declared_preview_shows_the_reviewer_what_the_call_will_touch",
        "a grant naming a dry run opens its approval task without one, so a "
        "reviewer approves the instruction while the file says they were shown "
        "its consequences",
        "                    approved = reach;\n                    // Consequences beside the instruction, when the grant names",
        "                    approved = reach;\n                    let grant = &crate::manifest::ToolGrant { preview: None, ..grant.clone() };\n                    // Consequences beside the instruction, when the grant names",
    ),
    "AHighImpactCallSkipsItsApproval": (
        "src/runtime/declarative.rs",
        "a_call_needing_approval_does_not_happen_until_it_is_approved",
        "a tool grant asking for a human is dispatched without asking, so the "
        "mutation happens and the only review left is of the answer — which "
        "arrives after the money moved",
        """                let mut approved: Option<crate::core::Reach> = None;
                if grant.requires_approval {""",
        """                let mut approved: Option<crate::core::Reach> = None;
                if false && grant.requires_approval {""",
    ),
    "APlannedCallSkipsItsApproval": (
        "src/runtime/declarative.rs",
        "a_planned_step_waits_for_its_approval",
        "a planned step whose grant asks for a human dispatches without asking "
        "— the plan was reviewed by nobody and the call by nobody either",
        """    let mut approved: Option<crate::core::Reach> = None;
    if grant.requires_approval {""",
        """    let mut approved: Option<crate::core::Reach> = None;
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
    "AReleaseCoversEverySink": (
        "src/core/label.rs",
        "a_release_for_one_destination_is_refused_at_another_sink",
        "the effective label ignores the destination a release named, so a "
        "value released for one sink arrives improved at every sink — the "
        "declared control the marks exist to enforce",
        "            if mark.destination() == destination && mark.covers(path) {",
        "            if mark.covers(path) {",
    ),
    "ADependencyJoinCarriesAReleaseAcrossValues": (
        "src/core/label.rs",
        "a_dependency_join_drops_release_marks",
        "a release mark survives the join that mixes an untrusted dependency "
        "into the value, so a sink honours a grant that was priced against "
        "the bare value and not against the history now folded into it",
        "            label: self.label.join(other),\n"
        "            fields: self.fields.clone(),\n"
        "            releases: BTreeSet::new(),",
        "            label: self.label.join(other),\n"
        "            fields: self.fields.clone(),\n"
        "            releases: self.releases.clone(),",
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
        "                mine.extend(s.descriptor().capabilities());",
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
    "APlaneCeilingDoesNotBoundWhatIsWrittenDown": (
        "src/runtime/ctx.rs",
        "a_plane_without_a_manifest_can_bound_what_it_writes_down",
        "a plane's own journal ceiling is ignored, so a plane of hand-written "
        "skills cannot bound what enters an append-only chain and the default "
        "stays the unerasable one",
        "        let journal_ceiling = match (self.journal_ceiling, declared) {",
        "        let journal_ceiling = match (None, declared) {",
    ),
    "AnAnnotationNameIsUnchecked": (
        "src/manifest/mod.rs",
        "annotation_keys_follow_the_kubernetes_grammar",
        "an annotation name of any length or charset is accepted, so an entry "
        "the manifest reviewed cannot be carried into a Kubernetes object and "
        "the grammar the docs promise is prose",
        "            if !is_annotation_name(name) {",
        "            if false {",
    ),
    "AnnotationsAreUnbounded": (
        "src/manifest/mod.rs",
        "annotations_are_capped_in_total_size",
        "a manifest may carry a document as an annotation, so the digest, the "
        "registry row and every copy of the reviewed file carry it too",
        "        if total > MAX_ANNOTATIONS_BYTES {",
        "        if false {",
    ),
    "AnMcpClientStartsWithTheLegacyHandshake": (
        "src/tools/mcp.rs",
        "the_negotiated_protocol_version_is_pinned_to_2026_07_28",
        "the client opens every MCP server with the initialize handshake, which "
        "2026-07-28 replaced with server/discover, so every connection negotiates "
        "down to a legacy dialect and the tasks extension silently never appears",
        """                ClientLifecycleMode::Auto {
                    preferred_versions: vec![crate::tools::MCP_REVISION],
                    legacy_version: Some(Self::LEGACY_REVISION),
                },""",
        """                ClientLifecycleMode::Initialize,""",
    ),
    "AnUnorderedPageIsRun": (
        "src/runtime/batch.rs",
        "a_source_paging_out_of_byte_order_is_refused",
        "a source paging out of byte order is run as given, so the resume "
        "cursor skips items that never ran or re-offers ones that did, and the "
        "batch reports complete either way",
        "    in_cursor_order(after, &page)?;",
        "    let _ = after;",
    ),
    "ARefusedBatchAdmissionIsRecordedAsFailed": (
        "src/runtime/batch.rs",
        "a_halt_mid_batch_stops_the_pass_without_failing_the_items",
        "an admission the plane refused — a halt, a ceiling, a store outage — "
        "is written over the item as a terminal Failed, so when the halt lifts "
        "every item behind it stays failed forever",
        "        let out = outcome?;",
        "        let out = match outcome {\n            Ok(out) => out,\n            Err(e) => {\n                let result = ItemOutcome::Failed(e.to_string());\n                store.record(id, &item.key, &result, Spend::default()).await.map_err(RuntimeError::from_store)?;\n                return Ok(result);\n            }\n        };",
    ),
    "AHaltWearsTheBackPressureCode": (
        "src/api/a2a.rs",
        "a_halted_agent_is_not_back_pressure",
        "a halted agent answers a peer with QUOTA_EXHAUSTED, so every compliant "
        "peer backs off and retries the one refusal that means stop",
        "        crate::quota::QuotaError::Halted { .. } => RpcError::new(code::HALTED, HALTED_MESSAGE),",
        "        crate::quota::QuotaError::Halted { .. } => RpcError::new(code::QUOTA_EXHAUSTED, QUOTA_EXHAUSTED_MESSAGE),",
    ),
    "ADrainingPlaneStillAdmits": (
        "src/runtime/executor.rs",
        "a_draining_instance_admits_nothing_and_writes_nothing",
        "the admission gate a drain closes is never consulted, so an instance "
        "that has announced it is going away keeps taking on runs it will not "
        "finish — and the drain report it hands back is true for an instant",
        "        if entry == Entry::Outside && self.inflight.is_draining() {",
        "        if false && entry == Entry::Outside && self.inflight.is_draining() {",
    ),
    "ADrainRefusesACommission": (
        "src/runtime/executor.rs",
        "a_drain_does_not_refuse_the_commission_of_a_run_it_is_waiting_for",
        "the drain gate sees commissions as well as callers, so a run the drain "
        "is waiting for fails its own delegating step — and that failure is "
        "in-doubt, so the drain manufactures the state it exists to prevent",
        "        if entry == Entry::Outside && self.inflight.is_draining() {",
        "        if self.inflight.is_draining() {",
    ),
    "ADrainForgetsWhatItDidNotFinish": (
        "src/runtime/drain.rs",
        "a_run_the_grace_period_did_not_cover_is_named_and_keeps_its_lease",
        "a drain that ran out of time reports an empty unfinished list, so a "
        "deploy that cut runs short looks exactly like one that did not and "
        "nobody learns the grace period is too short",
        "            unfinished: self.snapshot(),",
        "            unfinished: Vec::new(),",
    ),
    "AStrandedSlotReadsAsLiveWork": (
        "src/runtime/executor.rs",
        "the_live_listing_attributes_each_run_and_marks_a_stranded_slot",
        "the live listing stops distinguishing a slot whose lease has lapsed "
        "from a run something is actually executing, so an operator cancels "
        "what the recovery sweep was about to resume — which unwinds work that "
        "was going to finish",
        "                stranded: stranded.contains(&run),",
        "                stranded: false,",
    ),
    "LiftingAHaltIsTheAuthorityToThrowOne": (
        "src/api/mod.rs",
        "throwing_a_halt_and_lifting_one_are_separate_authorities",
        "lifting the emergency stop is gated on the capability to throw it, so "
        "a deployment that granted somebody the power to stop the plane has "
        "silently granted them the power to start it again",
        "    let s = api.gate(&headers, action::HALT_LIFT, &body.scope).await?;",
        "    let s = api.gate(&headers, action::HALT_PLACE, &body.scope).await?;",
    ),
    "ADrainDoesNotWait": (
        "src/runtime/drain.rs",
        "a_drain_waits_for_a_background_run_to_reach_its_conclusion",
        "a drain closes admission and returns without waiting, so every run in "
        "flight is cut at the same point a crash would cut it — the whole "
        "difference between a scheduled stop and an accident",
        "            if crate::core::poison::recover(&self.running).is_empty() {\n                break;\n            }",
        "            if true {\n                break;\n            }",
    ),
    "ADrainWearsTheBackPressureCode": (
        "src/api/a2a.rs",
        "a_draining_instance_is_neither_a_ceiling_nor_a_halt",
        "a draining instance answers a peer with QUOTA_EXHAUSTED, so a caller "
        "waits out a back-off window for a refusal a retry now would pass",
        "        Err(crate::core::RuntimeError::Draining) => {\n            return Err(RpcError::new(code::DRAINING, DRAINING_MESSAGE));\n        }",
        "        Err(crate::core::RuntimeError::Draining) => {\n            return Err(RpcError::new(code::QUOTA_EXHAUSTED, QUOTA_EXHAUSTED_MESSAGE));\n        }",
    ),
    "AStreamOutlivesTheInstanceServingIt": (
        "src/api/a2a_stream.rs",
        "a_stream_ends_when_the_instance_is_draining",
        "a subscription goes on polling while this instance is stopping, so a "
        "graceful shutdown waits for a connection that lasts as long as the run "
        "it watches — and an ordinary deploy hangs until the supervisor kills "
        "it, which is the one stop nothing can drain",
        "            if runtime.is_draining() {\n                return;\n            }",
        "            if false {\n                return;\n            }",
    ),
    "ADrainingPeerIsAnUnknownFault": (
        "src/peers/a2a.rs",
        "a_draining_peer_is_refused_rather_than_left_in_doubt",
        "the client does not recognise a peer's marked drain, so it falls to "
        "the unknown-fault arm as InDoubt — and a mutating call that never "
        "left is treated as one that may have landed",
        "        -32031 if e.names_reason(super::ERROR_DOMAIN, super::DRAINING_REASON) => {",
        "        -32031 if false && e.names_reason(super::ERROR_DOMAIN, super::DRAINING_REASON) => {",
    ),
    "APeersHaltIsAnUnknownFault": (
        "src/peers/a2a.rs",
        "a_peers_halt_is_a_refusal_that_says_do_not_retry",
        "the client does not recognise a peer's marked halt, so it falls to the "
        "unknown-fault arm as InDoubt — a clean pre-admission refusal reported "
        "as a peer that may have acted",
        "        -32030 if e.names_reason(super::ERROR_DOMAIN, super::HALTED_REASON) => PeerError::Refused {",
        "        -32030 if false && e.names_reason(super::ERROR_DOMAIN, super::HALTED_REASON) => PeerError::Refused {",
    ),
    "ARetentionReportOmitsWhatNoCaseReaches": (
        "src/retention.rs",
        "a_retention_pass_names_what_a_case_walk_does_not_reach",
        "a retention pass reports its coverage without the copies whose erasure "
        "unit is not the case — memory keyed to the matter, the event buffer, "
        "externally retained media, semantic-index vectors — so a clean report "
        "reads as a discharged obligation while all four survive",
        """        .extend(OUTSIDE_THE_CASE.iter().map(|line| (*line).to_owned()));""",
        """        .extend(OUTSIDE_THE_CASE.iter().skip(4).map(|line| (*line).to_owned()));""",
    ),
    "RetentionSkipsASealedCaseWithNoBlobStore": (
        "src/retention.rs",
        "retention_without_a_blob_store_still_destroys_the_case_key",
        "a retention pass returns before erasing anything when no blob store is "
        "wired, so a plane that seals its journal and stores no blobs never has "
        "a key destroyed — the one act that reaches every copy, skipped for want "
        "of a lesser one",
        "    if stores.blobs.is_none() {",
        "    if stores.blobs.is_none() {\n        return Ok(finish(report));\n    }\n    if false {",
    ),
    "APreviewIsUnbounded": (
        "src/runtime/declarative.rs",
        "a_preview_larger_than_the_bound_is_truncated_and_says_so",
        "a preview's whole answer is copied into the reviewer's evidence, so a "
        "dry run listing four thousand records produces a worklist row nobody "
        "can open",
        "    if rendered.len() <= PREVIEW_EVIDENCE_BYTES {",
        "    if true {",
    ),
    "RetentionErasesALiveCase": (
        "src/retention.rs",
        "retention_erases_closed_cases_past_the_window_and_nothing_else",
        "a retention pass erases matters that are still open or still inside "
        "their window, so retention becomes an outage and data goes early",
        "            if case.status == CaseStatus::Closed && case.opened_at < older_than {",
        "            if true {",
    ),
    "APostgresPublishRacesWithoutALock": (
        "src/store/postgres_registry.rs",
        "postgres_refuses_the_loser_of_a_concurrent_publish",
        "the registry reads and decides without serialising on the key, so two "
        "publishes of different content both find no row and the primary key "
        "conflict — not the immutability rule — decides who wins, wearing a "
        "backend fault's type",
        """        tx.execute(
            "SELECT pg_advisory_xact_lock(hashtext($1 || E'\\\\x1f' || $2 || E'\\\\x1f' || $3))",
            &[&tenant, &name, &version],
        )
        .await
        .map_err(|e| be(&e))?;""",
        """        let _ = (&tenant, &name, &version);""",
    ),
    "ACedarDenialNamesANumberNotTheRule": (
        "src/policy/cedar.rs",
        "a_named_rule_is_named_in_the_denial_rather_than_numbered",
        "a Cedar denial reports the generated policy id instead of the rule's "
        "@id, so forty rules produce forty reasons that each name a number and "
        "the required reason answers nothing",
        """    policies
        .annotation(id, RULE_NAME_ANNOTATION)
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map_or_else(|| id.to_string(), ToOwned::to_owned)""",
        """    id.to_string()""",
    ),
    "AToolTransportReachesAnUngrantedHost": (
        "src/tools/mod.rs",
        "a_tool_transport_reaching_an_ungranted_host_is_refused",
        "the plane's egress allowlist is not applied to the tool path, so the "
        "most-used outbound path is the one destination control does not reach",
        "        if let Some(egress) = egress",
        "        if let Some(egress) = None::<&crate::core::Egress>",
    ),
    "TheRouterIgnoresTheServer": (
        "src/tools/mod.rs",
        "a_router_sends_each_server_to_its_own_transport",
        "the router hands every tool id to whichever transport it holds first, "
        "so the server component that exists to tell two servers' identically "
        "named tools apart decides nothing",
        "    fn route(&self, tool: &ToolId) -> Option<&Arc<dyn ToolClient>> {\n        self.routes.get(&tool.server)\n    }",
        "    fn route(&self, tool: &ToolId) -> Option<&Arc<dyn ToolClient>> {\n        let _ = tool;\n        self.routes.values().next()\n    }",
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
        "src/runtime/telemetry.rs",
        "metrics_carry_no_tenant_unless_asked",
        "a plane puts its tenant on everything it reports without being asked, "
        "so customer names reach whatever backend the deployment happens to "
        "point at — usually the least protected system it runs",
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
    "AnEmbeddingCallSkipsTheEgressCeiling": (
        "src/model/embeddings.rs",
        "an_embedder_refuses_a_host_nobody_granted",
        "the embedding driver's egress ceiling is not consulted, so the query "
        "text — the thing a user typed — is posted to whatever base URL a config "
        "names, with no operator grant behind it",
        "    fn check_egress(&self) -> Result<(), StoreError> {\n        let Some(egress) = &self.egress else {\n            return Ok(());\n        };",
        "    fn check_egress(&self) -> Result<(), StoreError> {\n        return Ok(());\n        #[allow(unreachable_code)]\n        let Some(egress) = &self.egress else {\n            return Ok(());\n        };",
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
        "        if parsed.scheme() != \"https\"\n            && !(allow_loopback && crate::netguard::is_loopback_name(&host))\n        {\n            return Err(PushError::NotHttps);\n        }",
        "",
    ),
    "DeliveryTrustsTheRegistrationTimeCheck": (
        "src/push/mod.rs",
        "a_revoked_host_stops_receiving_notifications",
        "the grant is checked only when a webhook is registered, so a host "
        "removed from the allowlist keeps receiving notifications for every task "
        "registered while it was still granted",
        "            self.policy\n                .check_allowing_loopback(&config.url, self.loopback_allowed())?;",
        "",
    ),
    "AnUnresolvableSubjectFallsBackToTheLiteral": (
        "src/runtime/declarative.rs",
        "an_unresolvable_binding_fails_the_run",
        "a memory subject binding that cannot resolve falls back to the "
        "declaration's literal text, so every party's durable facts are pooled "
        "under one key — one party's history recalled into another's run, and "
        "an erasure request naming one person unsatisfiable without destroying "
        "everybody's",
        "        MemorySubject::Correlation(namespace) => cx\n            .correlation_value(namespace)\n            .map(ToOwned::to_owned)\n            .ok_or_else(|| {",
        "        MemorySubject::Correlation(namespace) => cx\n            .correlation_value(namespace)\n            .map(ToOwned::to_owned)\n            .or_else(|| Some(format!(\"$correlation/{namespace}\")))\n            .ok_or_else(|| {",
    ),
    "AnUntrustedInputMayChooseTheSubject": (
        "src/runtime/declarative.rs",
        "an_untrusted_input_may_not_choose_the_subject",
        "a memory subject bound to `$input` is accepted from an untrusted "
        "field, so whoever supplied the input chooses whose durable memories "
        "this run writes into — strictly worse than the pooling the binding "
        "exists to fix, and invisible at the time",
        "            if selected.label().trust != crate::core::Trust::Trusted {",
        "            if false && selected.label().trust != crate::core::Trust::Trusted {",
    ),
    "APromptMayNameAnUngrantedTool": (
        "src/manifest/mod.rs",
        "a_prompt_naming_an_ungranted_tool_is_refused",
        "a prompt instructs the agent to use a tool `spec.tools` never granted, "
        "so the model asks, is refused, improvises, and the step silently does "
        "not happen — with nothing in the journal saying the instruction was "
        "unfollowable",
        "                if !granted.contains(reference.as_str()) {",
        "                if false && !granted.contains(reference.as_str()) {",
    ),
    "ATriageRuleIsNotTypedAgainstTheAnswer": (
        "src/manifest/mod.rs",
        "a_triage_rule_is_checked_against_the_declared_output",
        "a triage condition naming a field the declared output schema provably "
        "cannot carry is accepted, so a compliance alert that can never fire "
        "reads in review exactly like one that does",
        "                condition.check_against(schema).map_err(|detail| {",
        "                Ok::<(), String>(()).map_err(|detail| {",
    ),
    "AnOperatorWorkerServesACallersWebhook": (
        # The trait *default*: since both backends grew native overrides, the
        # runtime path no longer runs this code over a real store, and the
        # test that kills it is the conformance pin that forces the default
        # over redb and compares — a worker-level test would pass with this
        # mutation applied, because the worker reads the (unmutated) override.
        "src/push/mod.rs",
        "redb_due_in_matches_the_paging_default",
        "the paging default stops filtering by namespace, so any backend "
        "without a native override hands every worker every registration and "
        "the deployment's own event is POSTed to a peer's A2A webhook — a "
        "disclosure to a party that registered for something else",
        "                if namespace.owns_id(&registration.config.id) {",
        "                if true {",
    ),
    "RedbDueInServesEveryNamespace": (
        # The native override the workers actually run over the embedded
        # store. Killed by the worker-level test, because the disclosure it
        # names — an operator event on a caller's webhook — is the one this
        # filter exists to prevent.
        "src/store/redb_push.rs",
        "an_operator_worker_leaves_a_callers_webhook_alone",
        "the embedded store's native due filter serves every namespace, so "
        "every worker claims every registration and the deployment's own "
        "event is POSTed to a peer's A2A webhook",
        "                if !namespace.owns_id(id) {",
        "                if false {",
    ),
    "AnUnfireableMutatingGrantParses": (
        "src/manifest/mod.rs",
        "a_mutating_grant_a_tool_loop_cannot_dispatch_is_refused",
        "a `mutates: true` grant with no `protected_fields` parses on a "
        "tool-calling agent, so a grant the taint gate refuses on every run "
        "reads to a reviewer as a live capability — and the run succeeds "
        "having quietly done nothing the model asked for",
        "            if grant.mutates && grant.protected_fields.is_empty() {",
        "            if false && grant.mutates && grant.protected_fields.is_empty() {",
    ),
    "OversightNeedsNoWorklist": (
        "src/runtime/executor.rs",
        "oversight_on_a_plane_with_no_worklist_is_refused",
        "an agent declaring oversight builds on a plane with no case store, "
        "worklist or timers, so the refusal arrives at the first real approval "
        "with a person already waiting",
        "                    if let Some((missing, remedy)) = missing {",
        "                    if let Some((missing, remedy)) = None::<(&'static str, &'static str)>.or(missing).filter(|_| false) {",
    ),
    "TwoAgentsMayShareOneSkill": (
        "src/api/a2a.rs",
        "two_agents_claiming_one_skill_are_refused",
        "two agents on one plane may advertise the same skill id, so a request "
        "naming it resolves to whichever agent was registered first — a routing "
        "decision the caller did not make, on a surface whose whole rule is that "
        "dispatch is named and never inferred",
        "                if let Some(other) = owner_of_skill.insert(skill.id.clone(), name.clone())\n                    && other != name\n                {",
        "                if let Some(other) = owner_of_skill.insert(skill.id.clone(), name.clone())\n                    && other != name\n                    && false\n                {",
    ),
    "AnAbsentTenantIsSentAsNull": (
        "src/peers/a2a.rs",
        "this_crates_client_round_trips_against_the_reference_server",
        "an absent `tenant` is emitted as JSON `null` rather than omitted, which "
        "ProtoJSON reads as a type error where a string belongs — this crate's "
        "own server accepts it because `serde` reads null into an `Option`, so "
        "every in-repo test agrees with the bug and only a foreign server sees it",
        "    if let Some(tenant) = tenant {\n        params.insert(\"tenant\".into(), json!(tenant));\n    }",
        "    params.insert(\"tenant\".into(), json!(tenant));",
    ),
    "ACanonRuleChangeReadsAsDivergence": (
        "src/runtime/executor.rs",
        "history_under_an_older_canonicalization_rule_is_unverifiable_not_divergent",
        "replay does not check which canonicalization rule wrote a run, so "
        "history written under the old UTF-8 key ordering recomputes different "
        "effect keys and is quarantined as non-determinism — the most serious "
        "conclusion this runtime reaches, reported for a healthy run",
        "    if let Some(recorded) = records.iter().find_map(recorded_canon)\n        && recorded != crate::core::canon::VERSION\n    {",
        "    if let Some(recorded) = records.iter().find_map(recorded_canon)\n        && recorded != crate::core::canon::VERSION\n        && false\n    {",
    ),
    "ALocalErasureLockBesideASharedStoreBuilds": (
        "src/runtime/executor.rs",
        "a_local_erasure_lock_beside_a_shared_store_is_refused",
        "a plane pairs a shared journal with a process-local erasure lock and "
        "builds, so the window between an erasure's hold check and its key "
        "destruction is open to the other instance — and the erasure reports "
        "success over an item sealed to a scope that no longer exists",
        "    if store.is_shared() && memories.is_some_and(|m| m.erasure_is_distributed() == Some(false)) {",
        "    if false && store.is_shared() && memories.is_some_and(|m| m.erasure_is_distributed() == Some(false)) {",
    ),
    "AForgottenMemoryKeepsItsKey": (
        "src/keyring/memory.rs",
        "forgetting_one_memory_makes_its_backup_unreadable",
        "`forget` removes a sealed memory's rows and leaves its key alive, "
        "so the live store forgets while every backup taken before still "
        "opens it",
        "                Self::every_version(self.highest_versions(&[id.to_owned()]).await?)",
        "                Self::every_version(Vec::new())",
    ),
    "ASweptMemoryKeepsItsKey": (
        "src/keyring/memory.rs",
        "forgetting_one_memory_makes_its_backup_unreadable",
        "the expiry sweep removes a sealed memory's rows and destroys no "
        "key, so a retention period ends in the live store and never in a "
        "backup",
        "                &Self::every_version(swept.clone()),",
        "                &Self::every_version(Vec::new()),",
    ),
    "ACascadedMemoryKeepsItsKey": (
        "src/keyring/memory.rs",
        "forgetting_one_memory_makes_its_backup_unreadable",
        "a cascading erasure \u2014 the form an erasure request takes \u2014 removes "
        "the source and its derivatives from the live store and destroys "
        "none of their keys, so backups keep opening all of them",
        "            self.destroy_erased(&Self::every_version(cascade.erased.clone()), at, &reason)",
        "            self.destroy_erased(&Self::every_version(Vec::new()), at, &reason)",
    ),
    "AMemoryKeyCoversMoreThanItsItem": (
        "src/keyring/memory.rs",
        "forgetting_one_memory_makes_its_backup_unreadable",
        "memories share a key wider than one item, so forgetting one "
        "destroys the key of every other memory sealed under it \u2014 or, kept "
        "alive to spare them, reaches no backup at all",
        """        super::scope(&self.tenant, &format!("memory-item/{id}@{version}"))""",
        """        super::scope(&self.tenant, &format!("memory-item/{}@{version}", id.is_empty()))""",
    ),
    "AMemoryEnvelopeIgnoresItsRow": (
        "src/keyring/memory.rs",
        "a_sealed_memory_moved_to_another_row_does_not_open",
        "a sealed memory is not bound to its id, so an envelope copied into "
        "another row opens as that row's content — whoever can write rows can "
        "re-attribute a memory to another id",
        """            item.id.as_str(),""",
        """            "",""",
    ),
    "AHeldMemoryRefusesUntyped": (
        "src/keyring/memory.rs",
        "memory_subject_erasure_makes_backup_ciphertext_unreadable",
        "a subject erasure blocked by a legal hold refuses as a backend string, "
        "so the caller cannot tell a preservation order from an outage and "
        "retries an erasure that the hold will refuse every time",
        """                return Err(StoreError::UnderLegalHold { id: id.clone() });""",
        """                return Err(StoreError::Backend(format!("memory '{id}' is under legal hold")));""",
    ),
    "ASubjectCleanupFailureReadsAsDone": (
        "src/keyring/memory.rs",
        "a_subject_erasure_whose_cleanup_failed_is_not_reported_clean",
        "a subject erasure whose row cleanup failed after its keys were "
        "destroyed is reported clean, closing the request over live ciphertext "
        "a retry would have removed",
        """                        cleanup_failed: Some(error.to_string()),""",
        """                        cleanup_failed: None,""",
    ),
    "TheErasureLockIsNotTaken": (
        "src/keyring/memory.rs",
        "the_encrypted_memory_store_takes_the_lifecycle_lock",
        "subject erasure runs without the lifecycle lock, so a write on another "
        "instance lands under a scope this one is destroying and the erasure "
        "reports success over a row sealed to a key that no longer exists",
        "        super::under_lock(self.lifecycle.as_ref(), &self.lifecycle_scope(), || async {\n"
        "            // The subject's ids, enumerated by the dedicated erasure-path",
        "        (async {\n"
        "            // The subject's ids, enumerated by the dedicated erasure-path",
    ),
    "AnUnknownA2aParameterIsIgnored": (
        "src/api/a2a.rs",
        "a_parameter_that_belongs_to_another_method_is_refused",
        "an A2A parameter this method does not take is silently ignored rather "
        "than refused, so a `ListTasks` whose `contextId` is misspelled drops "
        "the filter and answers with every task the caller may see — shaped "
        "exactly like the scoped list that was asked for",
        "    if let Some((_, allowed)) = FIELDS_BY_METHOD.iter().find(|(m, _)| *m == method)\n        && let Some(stray) = object.keys().find(|k| !allowed.contains(&k.as_str()))\n    {",
        "    if false\n        && let Some((_, allowed)) = FIELDS_BY_METHOD.iter().find(|(m, _)| *m == method)\n        && let Some(stray) = object.keys().find(|k| !allowed.contains(&k.as_str()))\n    {",
    ),
    "APermanentRefusalIsRetriedForever": (
        "src/push/delivery.rs",
        "a_permanently_refused_webhook_is_abandoned_rather_than_retried_forever",
        "a webhook refusal no backoff can change — a host taken off the "
        "allowlist, a URL that is not https — is rescheduled instead of given "
        "up on, so the registration is retried until the journal is deleted and "
        "the operator sees the same info line a rebooting receiver produces",
        "        let exhausted = attempts.saturating_add(1) >= self.max_attempts;\n        if failure.permanent || exhausted {",
        "        let exhausted = attempts.saturating_add(1) >= self.max_attempts;\n        if exhausted {",
    ),
    "AFailureReasonIsDroppedAtTheBusDoor": (
        "src/push/outbox.rs",
        "a_failed_runs_event_carries_the_reason_the_seal_records",
        "the completion event drops the seal's reason, so a receiver of "
        "io.agentplane.run.completed gets the word 'failed' and nothing else — "
        "the state the field exists to end, one delivery further out",
        """        if let Some(reason) = reason {
            data["reason"] = json!(reason);
        }""",
        """        let _ = reason;""",
    ),
    "ASuccessCarriesANullReason": (
        "src/push/outbox.rs",
        "a_cloudevents_delivery_announces_its_media_type_and_its_identity",
        "every completion event carries a reason key, null on success — so a "
        "receiver keying on the field's presence reads every success as a "
        "failure that had no explanation",
        """        if let Some(reason) = reason {
            data["reason"] = json!(reason);
        }""",
        """        data["reason"] = json!(reason);""",
    ),
    "ARotationSecretNeedsNoPrimary": (
        "src/push/outbox.rs",
        "a_rotation_secret_is_refused_without_a_panic_in_reach",
        "a rotation secret with no primary configured is accepted as the "
        "primary instead of refused, so which key every receiver must hold is "
        "decided by whichever half of the configuration loaded first",
        """        let signing = self
            .signing
            .take()
            .ok_or(super::SigningKeyError::NoPrimary)?;
        self.signing = Some(signing.try_also_with(secret)?);""",
        """        let signing = match self.signing.take() {
            Some(signing) => signing.try_also_with(secret)?,
            None => BodySigning::try_new(secret)?,
        };
        self.signing = Some(signing);""",
    ),
    "AFailureReasonIsDroppedAtTheOperatorView": (
        "src/api/mod.rs",
        "a_failed_runs_view_carries_the_reason_the_seal_records",
        "the run view drops the seal's reason, so an operator asking what "
        "happened is answered 'failed' and sent into the journal for the one "
        "sentence the record already carries",
        """    let reason = match &observed {
        Some(RunStatus::Suspended(_)) | None => None,
        Some(s) => s.reason().map(std::borrow::Cow::into_owned),
    };""",
        """    let reason: Option<String> = None;""",
    ),
    "APushDeliveryAnnouncesOneMediaType": (
        "src/push/mod.rs",
        "a_cloudevents_delivery_announces_its_media_type_and_its_identity",
        "every delivery is labelled with A2A's media type whatever it carries, "
        "so an operator's structured-mode CloudEvent is posted under a type no "
        "CloudEvents receiver routes on — the body is well formed, the POST is "
        "accepted, and nothing reports that the envelope was not recognised",
        "        let content_type = reqwest::header::HeaderValue::from_str(&message.content_type)",
        "        let content_type = reqwest::header::HeaderValue::from_str(\"application/a2a+json\")",
    ),
    "AGoneReceiverIsRetriedForTheFullCeiling": (
        "src/push/mod.rs",
        "a_gone_receiver_is_parked_at_once_and_a_failing_one_is_not",
        "a receiver answering 410 Gone — the status that means this endpoint is "
        "retired — is retried for the whole ceiling like one that is rebooting, "
        "so the one rejection an operator could have acted on is buried under "
        "two hours of identical retry lines",
        "        matches!(self, Self::Rejected { status: 410, .. })",
        "        matches!(self, Self::Rejected { status: 0, .. })",
    ),
    "ARetryAfterIsDiscarded": (
        "src/push/delivery.rs",
        "a_receivers_retry_after_is_honoured_and_bounded",
        "a receiver naming its own recovery through Retry-After is ignored in "
        "favour of a fixed schedule, so a rate-limited receiver is hammered on "
        "the sender's cadence and told twice what it already said once",
        "        if let Some(seconds) = advice {\n"
        "            return at.saturating_add(seconds.clamp(1, Self::MAX_RETRY_AFTER));\n"
        "        }",
        "        if let Some(_seconds) = advice {}",
    ),
    "APushBackoffHasNoSpread": (
        "src/push/delivery.rs",
        "registrations_that_failed_together_do_not_come_back_together",
        "every registration that failed against one receiver is scheduled to "
        "return at the same instant, so the moment that receiver recovers it is "
        "hit by its entire backlog at once — a recovering service knocked over "
        "by the sender that had been waiting politely for it",
        "        let offset = spread(registration, attempts) % (half.saturating_add(1));",
        "        let offset = 0 * spread(registration, attempts);",
    ),
    "AnExhaustedRegistrationLosesItsCursor": (
        "src/push/delivery.rs",
        "a_parked_registration_keeps_its_cursor_and_can_be_re_armed",
        "a registration that answered permanently or outlasted the ceiling is "
        "deleted rather than parked, discarding the cursor that is the only "
        "record of how far its receiver got — the undelivered tail of that run "
        "becomes unrecoverable without a scan nobody schedules",
        "            self.store\n"
        "                .park(\n"
        "                    registration.config.task,\n"
        "                    &registration.config.id,\n"
        "                    &failure.error,\n"
        "                )\n"
        "                .await?;",
        "            self.store\n"
        "                .delete(registration.config.task, &registration.config.id)\n"
        "                .await?;",
    ),
    "APushCeilingAbandonsOnTheFirstHiccup": (
        "src/push/delivery.rs",
        "an_unreachable_receiver_is_retried_up_to_the_ceiling_and_then_abandoned",
        "every transient delivery failure abandons the registration, so a "
        "receiver that was merely rebooting loses every notification it had not "
        "yet acknowledged",
        "        let exhausted = attempts.saturating_add(1) >= self.max_attempts;",
        "        let exhausted = true;",
    ),
    "AWebhookMayResolveInward": (
        "src/push/mod.rs",
        "a_webhook_resolving_to_a_private_address_is_refused",
        "the pre-flight address check is skipped, so a granted hostname pointing "
        "at loopback or a metadata service is dispatched to rather than refused "
        "— and the caller is told a receiver is down instead of that a "
        "destination is forbidden",
        "        crate::netguard::judge(self.reach(), &host, resolved)\n            .map_err(|e| PushError::Unroutable(e.to_string()))?;",
        "        let _ = resolved;",
    ),
    "ANamedRetryWindowIsIgnored": (
        "src/core/retry.rs",
        "a_named_retry_window_is_waited_rather_than_a_computed_one",
        "a peer's own `Retry-After` is discarded in favour of the computed "
        "schedule, so a run meets a sixty-second rate-limit window three times "
        "inside a second, exhausts its attempts and reports the provider as "
        "down",
        "            Some(named) if !named.is_zero() => named.min(self.max_advice),",
        "            Some(_) => self.backoff(run, key, attempt),",
    ),
    "ARetryWindowIsObeyedUnbounded": (
        "src/core/retry.rs",
        "a_window_longer_than_the_policy_allows_is_clamped_not_obeyed",
        "advice is obeyed without a ceiling, so a hostile or broken "
        "`Retry-After` holds a worker for as long as the peer cares to name",
        "            Some(named) if !named.is_zero() => named.min(self.max_advice),",
        "            Some(named) if !named.is_zero() => named,",
    ),
    # NOTE: `advice.take()` at the read site is deliberately *not* mutated. Every
    # live iteration reassigns `advice` at the foot of the loop, and the replay
    # arms that skip that assignment run only while it is still None — so
    # dropping the `take` is an equivalent mutant, not a gap. What is pinned
    # instead is that the window leaves the failure at all.
    "AWindowNeverLeavesTheFailure": (
        "src/runtime/ctx.rs",
        "a_named_retry_window_is_waited_rather_than_a_computed_one",
        "the window a refusal named is never carried to the attempt it is "
        "supposed to schedule, so every driver reads `Retry-After` correctly "
        "and the retry loop still computes a schedule in ignorance of it",
        "            advice = failure.retry_after();",
        "            advice = None;",
    ),
    "AProviderWindowIsDroppedAtTheWire": (
        "src/model/wire.rs",
        "a_named_rate_limit_window_survives_classification",
        "the provider's `Retry-After` is dropped as the response is classified, "
        "so the one number that makes retrying a rate limit useful never leaves "
        "the driver",
        "            retry_after: retry_after(headers),",
        "            retry_after: None,",
    ),
    "ASweepServesOneReceiverAtATime": (
        "src/push/delivery.rs",
        "one_stalled_receiver_does_not_hold_up_the_others",
        "a delivery sweep serves its registrations strictly in order, so one "
        "receiver sitting on its timeout decides when every other receiver gets "
        "its events and a plane with a backlog falls permanently behind on all "
        "of them",
        "        .buffer_unordered(self.max_in_flight)",
        "        .buffered(1)",
    ),
    "ASweepOpensASocketPerRow": (
        "src/push/delivery.rs",
        "a_sweep_opens_no_more_connections_than_its_ceiling",
        "a delivery sweep ignores its concurrency ceiling, so a large backlog "
        "is answered by opening a connection for every due row at once",
        "        .buffer_unordered(self.max_in_flight)",
        "        .buffer_unordered(usize::MAX)",
    ),
    "APooledClientReachesAnything": (
        "src/netguard/resolver.rs",
        "a_guarded_client_does_not_reach_a_live_server_on_this_machine",
        "every pooled outbound client is built without its address rule, so the "
        "connections its pool opens after a caller's pre-flight returned reach "
        "whatever DNS answers with — the rebinding window a one-shot check "
        "cannot close",
        "        .dns_resolver(GuardedResolver::shared(reach))",
        "",
    ),
    "ACallerFacingReachIsTheOperatorsOwn": (
        "src/netguard/resolver.rs",
        "a_reach_rule_is_one_rule_for_the_preflight_and_the_socket",
        "a caller-facing reach is exempted like the deployment's own, so the "
        "address rule applies to nothing an untrusted party ever names",
        "        Reach::Public => false,",
        "        Reach::Public => true,",
    ),
    "ALoopbackExemptionIsKeyedOnTheAnswer": (
        "src/netguard/resolver.rs",
        "a_name_that_is_not_loopback_gets_no_exemption_from_its_answers",
        "the loopback exemption stops being keyed on the name, so any host an "
        "attacker can point inward is exempted by the answer it arranged — the "
        "rebinding attack, admitted by the control meant to refuse it",
        "        Reach::PublicOrLoopbackName => super::is_loopback_name(host),",
        "        Reach::PublicOrLoopbackName => true,",
    ),
    "AWebhookTokenIsEchoedBack": (
        "src/push/mod.rs",
        "a_configuration_read_back_does_not_carry_its_token",
        "a configuration read back carries its token, so a caller learns the "
        "correlation secret for somebody else's webhook",
        "            \"url\": self.url,\n            \"authentication\": self.authentication.as_ref().map(|auth| serde_json::json!({",
        "            \"url\": self.url,\n            \"token\": self.token.as_ref().map(crate::core::Secret::expose),\n            \"authentication\": self.authentication.as_ref().map(|auth| serde_json::json!({",
    ),
    "ADeliverySignatureCoversNothing": (
        "src/push/sign.rs",
        "a_signed_destination_carries_a_standard_webhooks_signature_over_what_it_posted",
        "the body signature is computed over a constant instead of the body, so "
        "every delivery carries the same valid-looking MAC and a receiver "
        "verifying it accepts any body at all — the header says the payload was "
        "written by a holder of the secret, and it no longer says anything about "
        "the payload",
        "                let mac = hmac_sha256(key, &content);",
        "                let mac = hmac_sha256(key, b\"\");",
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
        "        let signature = crate::core::b64::encode_url(signer.sign_bytes(&input));",
        "        let signature = crate::core::b64::encode_url(\n            signer.sign_bytes(crate::core::Digest::of(&input).as_bytes()),\n        );",
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
        "                        if n >= limit {\n                            refused = Some(QuotaError::TooManyRuns {",
        "                        if n > limit {\n                            refused = Some(QuotaError::TooManyRuns {",
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
    "AWithdrawnAuthorityDoesNotStopWorkInFlight": (
        "src/runtime/executor.rs",
        "a_withdrawn_authority_pauses_a_running_run_without_unwinding_it",
        "a withdrawal never reaches a running run, so work carries on under a "
        "credential somebody withdrew — which is the harm the subject scope "
        "exists to stop, not a side effect of it",
        "                let standing = self.withdrawn_authority(identity.as_ref()).await?;",
        "                let standing: Option<Withdrawal> = None;",
    ),
    "AWithdrawalUnwindsTheWorkItPaused": (
        "src/runtime/executor.rs",
        "a_withdrawn_authority_pauses_a_running_run_without_unwinding_it",
        "a withheld run is unwound like a cancelled one, so a withdrawn "
        "credential reverses correct, completed work for a reason unrelated to "
        "it — a week of a six-week matter undone because somebody lost a laptop",
        "            RunStatus::Failed(_) | RunStatus::Cancelled { .. } => {}",
        "            RunStatus::Failed(_) | RunStatus::Cancelled { .. } | RunStatus::Withheld { .. } => {}",
    ),
    "AWithdrawalIsCheckedAgainstThePlanesOwnChain": (
        "src/runtime/executor.rs",
        "a_halt_can_name_the_authority_a_run_acts_for",
        "a halt scoped to an authority is matched against the *plane's* chain "
        "rather than the caller's, so a withdrawn credential is compared with "
        "the operator's own subject and never matches — a refusal that does not "
        "happen, writing no record and raising no error",
        """            terms.acting_as.resolve(self.identity.as_ref()),""",
        """            self.identity.as_ref(),""",
    ),
    "AnAdmittedRunSkipsItsQuota": (
        "src/runtime/executor.rs",
        "a_refused_run_writes_nothing",
        "admission never consults the tenant's ceiling, so a caller that can "
        "start runs can start a thousand of them, each within its own budget",
        """        let quota = match Box::pin(self.check_quota(
            run,
            governed_by.as_ref(),
            // **The chain this run acts under, not the plane's.** A served
            // surface admits each run under its caller's chain, so reading
            // the plane's here would check a withdrawal against the
            // operator's own subject and never match the caller's — a
            // refusal that does not happen, which leaves no trace anywhere.
            terms.acting_as.resolve(self.identity.as_ref()),
            now_for_admission(),
            (&budget, reserved_width(&budget, &plan)),
        ))
        .await
        {""",
        "        let quota = match Ok::<_, RuntimeError>(QuotaPass::disabled()) {",
    ),
    "AFinishedRunKeepsItsSlot": (
        "src/runtime/executor.rs",
        "a_finished_run_frees_its_slot",
        "a run never gives its concurrency slot back, so a ceiling of N permits "
        "N runs per process lifetime rather than N at a time",
        "            self.settle_quota(run, epoch, live_spend, quota, status.seals())\n                .await?;",
        "",
    ),
    # ── A tool's rate ceiling, across runs ─────────────────────────────────
    "AZeroRateCeilingParses": (
        "src/manifest/mod.rs",
        "a_rate_ceiling_that_admits_nothing_is_refused",
        "a rate_limit of zero calls parses, so a reviewer reads a grant that "
        "forbids its own tool as a grant",
        "        if rate.count == 0 {",
        "        if rate.count == u32::MAX {",
    ),
    "ARateCeilingOnAnAgentGrantParses": (
        "src/manifest/mod.rs",
        "a_rate_ceiling_on_an_agent_grant_is_refused",
        "a rate ceiling on an agent grant parses, though the consultation "
        "dispatches through commission where nothing counts it — a reviewed "
        "control that never binds",
        "            if grant.rate_limit.is_some() {",
        "            if false {",
    ),
    "ARateWindowIsAFixedBucket": (
        "src/quota/mod.rs",
        "redb_satisfies_the_quota_store_contract",
        "the rate window restarts at a bucket boundary, so twenty an hour "
        "admits forty in the two minutes around the hour",
        "    at.saturating_sub(i64::try_from(window_seconds).unwrap_or(i64::MAX))",
        "    at - at.rem_euclid(i64::try_from(window_seconds).unwrap_or(i64::MAX))",
    ),
    "ARateCountIgnoresTheTenant": (
        "src/store/redb_quota.rs",
        "one_tenants_rate_count_does_not_throttle_another",
        "the rate count reads every tenant's reservations, so one busy tenant "
        "throttles another's calls to the same tool",
        '        .range((tenant, grant, "", "")..=(tenant, grant, MAX_STR, MAX_STR))',
        '        .range(("", grant, "", "")..=(MAX_STR, grant, MAX_STR, MAX_STR))',
    ),
    "ARateCeilingWithoutACounterBuilds": (
        "src/runtime/executor.rs",
        "a_rate_ceiling_on_a_plane_with_no_quota_store_is_refused_at_build",
        "a plane with a declared rate ceiling and no quota store builds, and "
        "the ceiling a reviewer approved is never counted",
        "            if ceilings.is_empty() {",
        "            if ceilings.is_empty() || self.quotas.is_none() {",
    ),
    "ARateReservationReadsThenWrites": (
        "src/store/postgres_quota.rs",
        "postgres_rate_ceiling_holds_under_concurrent_dispatch",
        "the rate count and the insert are not serialised, so two instances "
        "each read a window with one place left and both land",
        '            "SELECT pg_advisory_xact_lock(hashtextextended($1, 1))",',
        '            "SELECT hashtextextended($1, 1)",',
    ),
    "AnUnreachableRateCounterAdmits": (
        "src/runtime/ctx.rs",
        "an_unreachable_rate_counter_refuses",
        "an unreachable rate counter admits the call, so the ceiling is "
        "removed by taking its store down",
        "            },\n            Err(other) => return Err(rate_counter_unreachable(&other)),",
        "            },\n            Err(_) => return Ok(()),",
    ),
    "ACompensationIsRateRefused": (
        "src/runtime/ctx.rs",
        "a_compensation_is_counted_and_never_rate_refused",
        "an undo is judged by the rate ceiling instead of counted, so a window "
        "the forward call filled leaves the undo uncounted",
        "            exempt: true,",
        "            exempt: false,",
    ),
    "APeerCallEscapesItsRateCeiling": (
        "src/runtime/ctx.rs",
        "a_peer_call_is_held_to_its_grant_s_rate_ceiling",
        "the rate lookup answers only tool calls, so a ceiling declared on a "
        "peer grant is reviewed and never counted",
        '            "a2a.peer/call" => ("peer", "capability"),',
        '            "a2a.peer/never" => ("peer", "capability"),',
    ),
    "ARateRefusalTakesALedgerSlot": (
        "src/runtime/ctx.rs",
        "a_rate_refusal_does_not_spend_the_run_budget",
        "the run's budget slot is taken before the rate ceiling refuses, so a "
        "live pass bills a call that never happened and exhausts before its "
        "own replay",
        "            self.admit(key, &descriptor.kind, outbound_bytes, false)",
        "            self.admit(key, &descriptor.kind, outbound_bytes, true)",
    ),
    "ARateKeyNamesTheAttempt": (
        "src/runtime/ctx.rs",
        "a_retried_dispatch_reserves_once",
        "the rate reservation is keyed on each attempt, so a retry spends a "
        "second call and a flaky server closes the ceiling",
        "                FIRST_ATTEMPT,",
        "                attempt,",
    ),
    "ARateReservationIgnoresItsKey": (
        "src/store/redb_quota.rs",
        "a_dispatch_recovered_after_its_reservation_reserves_once",
        "re-reserving a present dispatch does not find its row, so a recovered "
        "dispatch is refused against its own reservation",
        "                        .get((tenant.as_str(), grant, run.as_str(), dispatch.as_str()))",
        '                        .get((tenant.as_str(), grant, run.as_str(), ""))',
    ),
    "ARateKeyOmitsTheRun": (
        "src/store/redb_quota.rs",
        "two_runs_making_the_same_call_each_count",
        "the rate reservation omits the run, so two runs making the identical "
        "call share one row and the ceiling admits every such run",
        "                    let run = reservation.run.to_string();",
        "                    let run = String::new();",
    ),
    "ARateRefusalIsNotJournaled": (
        "src/runtime/ctx.rs",
        "a_strict_replay_reads_a_rate_refusal_back_without_the_counter",
        "a rate refusal stops the run without recording it, so a replay finds "
        "no history where the run stopped",
        "        self.append_effect(key, rate_refusal).await?;",
        "        let _ = rate_refusal;",
    ),
    "AResumeIgnoresTheRateCounter": (
        "src/runtime/ctx.rs",
        "a_resume_inside_a_full_window_stays_refused_without_a_second_record",
        "a resume re-asks only the ledger, so inside a still-full window it "
        "re-admits, is refused again, and stacks a second refusal",
        "                    Err(crate::quota::QuotaError::RateLimited { .. }) => Err(()),",
        "                    Err(crate::quota::QuotaError::RateLimited { .. }) => Ok(()),",
    ),
    "ARateStopIsNotListed": (
        "src/runtime/attention.rs",
        "a_rate_refused_run_is_listed_with_its_remedy",
        "the exhausted remedy tells an operator to raise a ceiling, which a "
        "rate-stopped run's is not raised by — the remedy is to wait",
        "                    cli: \"raise the ceiling — or, stopped by a tool's rate ceiling, wait for \\\n",
        "                    cli: \"raise the ceiling — or, stopped by a tool's ceiling, wait for \\\n",
    ),
    "ATightestCeilingBindsOnlyItsAgent": (
        "src/runtime/ctx.rs",
        "the_tightest_ceiling_binds_every_agent",
        "each dispatch is judged against its own declaration's ceiling, so a "
        "looser agent fills the shared count past the tightest one",
        "        let ceilings = rates.ceilings.get(&reference)?.clone();",
        "        let ceilings = vec![self.manifest.as_ref()?.tool_grant(&reference)?.rate_limit?.into()];",
    ),
    "ReplayReChecksTheQuota": (
        "src/runtime/executor.rs",
        "replay_does_not_consult_the_quota",
        "replay consults the tenant's live ceiling, so re-reading a run that "
        "genuinely happened can refuse — history says something different on "
        "the second reading",
        "        // Strict verification never writes, so it holds no lease to renew.\n"
        "        let _heartbeat = lease.map(|l| self.heartbeat(run, l.epoch));",
        "        let _ = self\n"
        "            .check_quota(run, None, None, now_for_admission(), (&Budget::unlimited(), 1))\n"
        "            .await?;\n"
        "        // Strict verification never writes, so it holds no lease to renew.\n"
        "        let _heartbeat = lease.map(|l| self.heartbeat(run, l.epoch));",
    ),
    "AnUnlimitedQuotaHidesItsRunningWork": (
        "src/runtime/executor.rs",
        "an_unlimited_wired_quota_tracks_active_runs",
        "the runtime skips reservation when every ceiling is unlimited, so "
        "the operator's running count is false and a newly-added ceiling starts "
        "from an empty ledger while work is already active",
        "        // What the run can cost at most, held against the period in the same\n",
        "        if self.quota.is_unlimited() {\n            return Ok(pass);\n        }\n        // What the run can cost at most, held against the period in the same\n",
    ),
    "AQuotaPassMovesToTheCompletionPeriod": (
        "src/runtime/executor.rs",
        "a_quota_pass_keeps_the_period_it_started_in",
        "the accounting period is read from the clock instead of the pass's "
        "start instant, so work crossing midnight is authorized against one "
        "ledger and charged to another",
        "            period: quota.bounds_spend().then(|| quota.period.key_for(at)),",
        "            period: quota\n                .bounds_spend()\n                .then(|| quota.period.key_for(now_for_admission())),",
    ),
    "AQuotaPassStartsAfterItsEffects": (
        "src/runtime/executor.rs",
        "a_failed_quota_settlement_is_recovered_exactly_once",
        "the pass marker is omitted from admission, so a crash leaves durable "
        "effect spend with no period or receipt identity recovery can derive",
        """        if let Some(started) = quota.started() {
            records.push(Append::new(run, started));
        }""",
        "",
    ),
    "AQuotaSettlementRetryBillsTwice": (
        "src/store/redb_quota.rs",
        "redb_satisfies_the_quota_store_contract",
        "an existing receipt falls through to accrual again, so a lost "
        "acknowledgement charges one pass twice",
        "            if !fresh {",
        "            if false && !fresh {",
    ),
    "ASettlementFailureReleasesItsRetryLease": (
        "src/runtime/executor.rs",
        "a_failed_recovery_keeps_the_run_in_the_retry_queue",
        "a failed settlement releases the run lease, removing the only queue "
        "that can discover and retry the missing receipt",
        "            Err(RuntimeError::QuotaSettlementPending { .. }) => false,",
        "            Err(RuntimeError::QuotaSettlementPending { .. }) => true,",
    ),
    "AFailedResumeReleasesTheOnlyLeaseListingIt": (
        "src/runtime/executor.rs",
        "a_resume_that_fails_mid_flight_is_left_for_recovery",
        "a resume that fails after its wake was recorded releases its lease, so "
        "the run is off the waiting listing, has no conclusion, and is invisible "
        "to the abandonment sweep, which lists only leases that lapse owned",
        "            Err(_) => claim == Claim::Standing && !dispatched,",
        "            Err(_) => true,",
    ),

    "RecoverySkipsRecordedQuotaPasses": (
        "src/runtime/executor.rs",
        "a_failed_quota_settlement_is_recovered_exactly_once",
        "resume never replays the journal's quota intents, so the run seals "
        "while the failed charge and admission slot remain missing",
        "        self.settle_recorded_quota_passes(run, records).await?;",
        "",
    ),
    "AccountingRecoveryRetriesBusinessFailure": (
        "src/runtime/executor.rs",
        "settlement_recovery_preserves_an_open_failure",
        "the abandonment sweep repairs accounting and then treats that repair "
        "as permission to start a second execution pass over failed work",
        "        if !recovering {\n            return Ok(None);\n        }",
        "        if true {\n            return Ok(None);\n        }",
    ),
    "AQuotaStoreCanServeAnotherTenant": (
        "src/runtime/executor.rs",
        "a_plane_refuses_another_tenants_quota_store",
        "the builder omits the quota store from tenant checks, so one tenant's "
        "runs reserve and bill another tenant's ledger while their journals "
        "remain correctly isolated",
        "                (\"quota\", self.quotas.as_ref().map(|s| s.tenant())),",
        "                (\"quota\", None),",
    ),
    "ATimerStoreCanServeAnotherTenant": (
        "src/runtime/executor.rs",
        "a_plane_refuses_mismatched_timer_batch_and_authority_stores",
        "the timer store is omitted from tenant checks, so a sweep can claim "
        "another tenant's timer and try to execute its run under this plane",
        "                (\"timer\", self.timers.as_ref().map(|s| s.tenant())),",
        "                (\"timer\", None),",
    ),
    "ABatchStoreCanServeAnotherTenant": (
        "src/runtime/executor.rs",
        "a_plane_refuses_mismatched_timer_batch_and_authority_stores",
        "the batch store is omitted from tenant checks, so item reservations "
        "and outcomes are written into another tenant's batch",
        "                (\"batch\", self.batches.as_ref().map(|s| s.tenant())),",
        "                (\"batch\", None),",
    ),
    "AnAuthorityStoreCanServeAnotherTenant": (
        "src/runtime/executor.rs",
        "a_plane_refuses_mismatched_timer_batch_and_authority_stores",
        "the authority store is omitted from tenant checks, so one tenant's "
        "run draws against another tenant's standing authorization",
        "                (\"authority\", self.authorities.as_ref().map(|s| s.tenant())),",
        "                (\"authority\", None),",
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
        "        let plane = self.planes.get(&caller).ok_or_else(|| {",
        "        let plane = self\n"
        "            .planes\n"
        "            .get(&caller)\n"
        "            .or_else(|| self.planes.by_tenant.values().next())\n"
        "            .ok_or_else(|| {",
    ),
    "TheServingTenantComesFromTheRequest": (
        "src/api/mod.rs",
        "a_caller_cannot_read_another_tenants_run",
        "the plane is chosen without reference to the caller's tenant, so any "
        "authenticated caller reads any tenant's runs while holding nothing but "
        "a valid id",
        "        let plane = self.planes.get(&caller).ok_or_else(|| {",
        "        let plane = self\n"
        "            .planes\n"
        "            .by_tenant\n"
        "            .iter()\n"
        "            .find(|(t, _)| *t != &caller.tenant)\n"
        "            .map(|(_, p)| p)\n"
        "            .or_else(|| self.planes.get(&caller))\n"
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
        "        if self.lease_ttl < MIN_LEASE_TTL {",
        "        if self.lease_ttl < Duration::ZERO {",
    ),
    "TheClientSpeaksEveryRevisionTheSdkKnows": (
        "src/tools/mcp.rs",
        "a_revision_the_sdk_knows_but_this_host_is_not_held_to_is_refused",
        "the host proceeds on a revision nobody ran it against, because the SDK can parse it",
        """    pub const SPOKEN_REVISIONS: [ProtocolVersion; 2] =
        [crate::tools::MCP_REVISION, Self::LEGACY_REVISION];""",
        """    pub const SPOKEN_REVISIONS: [ProtocolVersion; 3] =
        [crate::tools::MCP_REVISION, Self::LEGACY_REVISION, ProtocolVersion::V_2025_06_18];""",
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
        "        Err(\n"
        "            crate::core::RuntimeError::PolicyDenied(_) | crate::core::RuntimeError::Delegation(_),\n"
        "        ) => {\n"
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
        "        Err(\n"
        "            crate::core::RuntimeError::PolicyDenied(_) | crate::core::RuntimeError::Delegation(_),\n"
        "        ) => {\n"
        "            return Ok(json!({ \"message\": declined(&skill) }));\n"
        "        }",
        "        Err(why @ crate::core::RuntimeError::PolicyDenied(_))\n"
        "        | Err(why @ crate::core::RuntimeError::Delegation(_)) => {\n"
        "            return Ok(json!({ \"message\": declined(&why.to_string()) }));\n"
        "        }",
    ),
    "APeersMessageArrivesTrusted": (
        "src/api/a2a.rs",
        "a_peers_message_is_untrusted_and_carries_its_sender",
        "a message from another agent is admitted as trusted input, so a value "
        "that arrived over the network wears the runtime's own authority and "
        "every protected sink field downstream checks nothing",
        "    let source = super::peer_source(&caller.actor);\n"
        "    let input = Tainted::from_source(message.to_input(), SourceId::new(&source));",
        "    let source = super::peer_source(&caller.actor);\n"
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
    "APostedEventDecidesATask": (
        "src/core/event.rs",
        "a_decision_posted_as_an_event_is_forbidden",
        "the plane's own event namespace is open at the intake, so anyone who "
        "may post an event decides a human task — no claim, no role, no "
        "four-eyes — with the kind and task id `GET /tasks` serves",
        '    kind.starts_with("agentplane.")',
        '    false && kind.starts_with("agentplane.")',
    ),
    "ATargetedEventDecidesATask": (
        "src/runtime/executor.rs",
        "a_decision_addressed_to_its_run_is_refused",
        "targeted delivery skips the namespace refusal, so a peer continuing a "
        "task by run id delivers the approval the run is waiting for",
        "        refuse_reserved_kind(event)?;\n        let events = self.events",
        "        let events = self.events",
    ),
    "ATaskTakesAnAnswerFromAnywhere": (
        "src/runtime/ctx.rs",
        "a_task_answer_that_did_not_come_from_the_worklist_is_not_a_decision",
        "a task takes any claimed answer of its kind as the decision, so one "
        "door that forgets the intake refusal is an approval from outside",
        "    if !from_worklist || decision.decided.operator() != answer.by.as_ref() {",
        "    if false || decision.decided.operator() != answer.by.as_ref() {",
    ),
    "ATaskTakesAnAnswerUnderAnotherDecider": (
        "src/runtime/ctx.rs",
        "a_task_answer_that_did_not_come_from_the_worklist_is_not_a_decision",
        "a task takes an answer whose decider is not the operator it was "
        "delivered under, so the name on the approval is the payload's claim",
        "    if !from_worklist || decision.decided.operator() != answer.by.as_ref() {",
        "    if !from_worklist || false {",
    ),
    "ContentionOutranksIneligibility": (
        "src/store/redb_tasks.rs",
        "redb_satisfies_the_case_layer_contracts",
        "a barred reviewer is told the task is held rather than that it is not theirs",
        "    if task.excluded_actors.iter().any(|a| a == actor) {",
        "    if task.assignee.is_none() && task.excluded_actors.iter().any(|a| a == actor) {",
    ),
    "AnyoneCanReleaseAClaim": (
        "src/store/redb_tasks.rs",
        "redb_satisfies_the_case_layer_contracts",
        "a claim can be released by somebody who does not hold it",
        "                    t.state == TaskState::Claimed && t.assignee.as_deref() == Some(actor.as_str())",
        "                    t.state == TaskState::Claimed",
    ),
    "SuspensionScansHistory": (
        "src/runtime/executor.rs",
        "a_resumed_run_is_not_still_reported_as_suspended",
        "run status comes from any suspension in history, not from the last "
        "record, so every run that ever waited reads as stuck forever — on the "
        "operator view and on idempotent admission alike, which is the point of "
        "there being one reader",
        "    Some(match records.last()?.kind() {",
        """    Some(match records
        .iter()
        .find(|r| matches!(r.kind(), RecordKind::RunSuspended { .. }))
        .or_else(|| records.last())?
        .kind()
    {""",
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
        "                Some(turns) => array.extend(turns.iter().cloned()),",
        "                Some(turns) => {\n"
        "                    let _ = &turns;\n"
        "                    array.push(json!({ \"role\": \"model\", \"parts\": [] }));\n"
        "                }",
    ),
    "GeminiThinkingTokensAreFree": (
        "src/model/gemini.rs",
        "gemini_maps_the_request_shape_usage_and_the_system_instruction",
        "thinking tokens are dropped from the output count, so a reasoning-heavy "
        "run under-reports most of its bill — Gemini reports them beside the "
        "candidate count rather than inside it, so omitting them is silent",
        '''            output_tokens: count("candidatesTokenCount")
                .saturating_add(count("thoughtsTokenCount")),''',
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
        '        "abandoned" => Some(recorded_abandonment(records).map_or_else(\n'
        "            || RunStatus::Quarantined(UNATTRIBUTED.to_owned()),\n"
        "            |(actor, reason)| RunStatus::Abandoned { actor, reason },\n"
        "        )),",
        '        "abandoned" => None,',
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
        "    if req.method == method::SUBSCRIBE && super::a2a_stream::closes(state) {",
        "    if req.method == method::SUBSCRIBE\n"
        "        && matches!(state, TaskState::Canceled | TaskState::Rejected)\n"
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
    "AnEventScopeIsASlashJoin": (
        "src/keyring/mod.rs",
        "erasing_one_event_leaves_a_lookalike_pair_readable",
        "an event's erasure scope joins source and id with `/`, so erasing "
        "('bus/x', '1') destroys the key of ('bus', 'x/1') and reports success",
        r"""        &format!("event/{}", crate::core::origin_key(source, id)),""",
        r"""        &format!("event/{source}/{id}"),""",
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
        "                        *field = payload::wrap(&envelope);",
        "                        let _ = &envelope;",
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
        """            && stored > journal_ceiling
        {""",
        """            && stored > journal_ceiling
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
            .seal(run, epoch, outcome)
            .await
            .map_err(RuntimeError::from_store)?;""",
        """        let _ = (outcome, epoch);""",
    ),
    "AnUnexplainedCrossingIsRecorded": (
        "src/runtime/executor.rs",
        "break_glass_without_a_reason_is_refused",
        "a break-glass with no stated reason is accepted, recording an "
        "exception that explains nothing",
        "    ) -> Result<RunId, RuntimeError> {\n        if reason.trim().is_empty() {",
        "    ) -> Result<RunId, RuntimeError> {\n        if false {",
    ),
    "AnEndingIsGivenAName": (
        "src/runtime/executor.rs",
        "an_ending_with_no_attribution_record_is_not_given_a_name",
        "a conclusion whose attribution record is missing is served under a "
        "fabricated operator name instead of being quarantined — and a "
        "fabricated actor is indistinguishable from a real operator with that "
        "name on the surface an incident review reads",
        '        "cancelled" => recorded_cancellation(records).map_or_else(\n'
        "            || RunStatus::Quarantined(UNATTRIBUTED.to_owned()),\n"
        "            |(actor, reason)| RunStatus::Cancelled { actor, reason },",
        '        "cancelled" => recorded_cancellation(records).map_or_else(\n'
        '            || RunStatus::Cancelled {\n'
        '                actor: crate::core::Operator::asserted("unknown").expect("a name"),\n'
        '                reason: "unattributed".to_owned(),\n'
        "            },\n"
        "            |(actor, reason)| RunStatus::Cancelled { actor, reason },",
    ),
    "AHaltForgetsHowItsOperatorWasNamed": (
        "src/store/redb_quota.rs",
        "redb_satisfies_the_quota_store_contract",
        "every emergency stop is stored as though the name on it had been "
        "typed at a terminal, so a halt an authenticator attributed and one "
        "somebody with the database URL asserted read back identically — the "
        "distinction the row exists to keep",
        "            by: by.clone(),",
        '            by: crate::core::Operator::asserted(by.actor()).expect("a name"),',
    ),
    "ACheckpointNoteIsReadLineByLine": (
        "src/journal/store.rs",
        "a_checkpoint_has_exactly_one_spelling",
        "a checkpoint note is read with `lines()`, which accepts a missing "
        "final newline, eats a carriage return before it, and ignores "
        "everything after the third line — so several different signed texts "
        "parse to one checkpoint, and an operator can hand two auditors "
        "different bytes that both verify",
        """        if parts.next().is_some() {""",
        """        if false {""",
    ),
    "ABase64PaddingBitsAreIgnored": (
        "src/core/b64.rs",
        "a_checkpoint_has_exactly_one_spelling",
        "the unused trailing bits of a base64 tail are not required to be "
        "zero, so every 32-byte root has sixteen spellings — each a distinct "
        "note text, each signable, all naming one history",
        "    base64::engine::general_purpose::STANDARD.decode(text).ok()",
        """    base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::general_purpose::GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true),
    )
    .decode(text)
    .ok()""",
    ),
    "ABase64PayloadNeedNotBePadded": (
        "src/core/b64.rs",
        "a_checkpoint_has_exactly_one_spelling",
        "base64 input is decoded without requiring canonical padding, so an "
        "unpadded tail is a second spelling of one value — one root with two "
        "note texts, both signable",
        "    base64::engine::general_purpose::STANDARD.decode(text).ok()",
        """    base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::general_purpose::GeneralPurposeConfig::new()
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
    )
    .decode(text)
    .ok()""",
    ),
    "AKeyNameIsFreeText": (
        "src/journal/note.rs",
        "a_key_name_that_would_break_the_line_is_refused",
        "a note signature's key name is written out unchecked, so a name "
        "carrying a space, a newline or an em dash produces a line that reads "
        "back as a different name, a truncated payload, or an extra signature "
        "line nobody wrote",
        """        Self::validate_name(&signature.name)?;""",
        """        let _ = Self::validate_name(&signature.name);""",
    ),
    "AnExportIsCheckedAgainstItsOwnHeader": (
        "src/export.rs",
        "an_export_with_a_rewritten_header_needs_an_outside_checkpoint",
        "the Merkle root rebuilt from an export is held to the checkpoint in "
        "the file's own header rather than to the one the reader was given, so "
        "an editor who drops a run and rewrites the header produces a file "
        "that verifies clean — the same 'it agrees with itself' the record "
        "rehash exists to refuse, one level up",
        """        if given.origin != report.checkpoint.origin || given.size > report.checkpoint.size {""",
        """        if false {""",
    ),
    "AnIncoherentCheckpointIsRemembered": (
        "src/journal/witness.rs",
        "an_incoherent_checkpoint_is_refused_before_it_is_remembered",
        "a checkpoint claiming size 0 beside a root the empty tree does not "
        "have is remembered rather than refused, and a witness holds every "
        "later checkpoint to its first — so one malformed submission makes "
        "every honest checkpoint for that origin report as forked, forever",
        """            if !checkpoint.is_coherent() {""",
        """            if false {""",
    ),
    "ACheckpointIsSignedOverItsHash": (
        "src/journal/witness.rs",
        "a_cosignature_verifies_as_cosignature_v1_over_the_note_text",
        "a cosignature is produced over SHA-256 of its message rather than "
        "over the message text — sixty-four bytes of the right algorithm "
        "under the right key that verify against no witness, no auditor and "
        "no tool outside this crate",
        """            .sign(message.as_bytes())""",
        """            .sign(crate::core::Digest::of(message.as_bytes()).as_bytes())""",
    ),
    "ACosignatureSignsTheBareNote": (
        "src/journal/witness.rs",
        "a_cosignature_verifies_as_cosignature_v1_over_the_note_text",
        "the cosignature/v1 header and timestamp line are dropped from the "
        "signed message, leaving a signature over the bare note text — the "
        "shape of a log's *own* signature, so the log's claim about itself "
        "and a witness's observation of it become interchangeable, which is "
        "the confusion the domain separation exists to rule out",
        r'''pub(crate) fn cosignature_message(timestamp: u64, note_text: &str) -> String {
    format!("cosignature/v1\ntime {timestamp}\n{note_text}")
}''',
        r'''pub(crate) fn cosignature_message(timestamp: u64, note_text: &str) -> String {
    let _ = timestamp;
    note_text.to_owned()
}''',
    ),
    "ABareSignatureIsReadAsATimestampedOne": (
        "src/journal/witness.rs",
        "a_payload_without_a_timestamp_is_not_a_cosignature",
        "a 64-byte payload is read as a cosignature with no timestamp instead "
        "of being refused, so a bare signature — which covers a message nobody "
        "constructed — reaches the verifier, and the payload layout the spec "
        "publishes stops being enforced",
        """    if blob.len() != 8 + 64 {
        return None;
    }""",
        """    if blob.len() != 8 + 64 && blob.len() != 64 {
        return None;
    }""",
    ),
    "ACosignatureTimestampIsUnbounded": (
        "src/journal/witness.rs",
        "a_timestamp_past_two_to_the_sixty_three_is_not_a_cosignature",
        "a cosignature whose timestamp reads above 2^63 − 1 is accepted, "
        "though the cosignature format bounds it there — an instant no "
        "conforming witness can state is counted as a witness's observation",
        """    if timestamp > i64::MAX.cast_unsigned() {""",
        """    if false {""",
    ),
    "ACosignatureIsNotVerified": (
        "src/journal/witness_http.rs",
        "a_cosignature_is_counted_only_if_it_verifies",
        "the signature on a 200 is parsed and never checked, so any endpoint "
        "answering with a well-formed base64 string is counted toward a "
        "quorum — and every guarantee resting on 'an independent party saw "
        "this log' becomes a guarantee about string formatting",
        """    verifying.verify(message.as_bytes(), &signature).ok()?;""",
        """    let _ = (&verifying, &signature);""",
    ),
    "ACosignatureIsMatchedOnNameAlone": (
        "src/journal/witness_http.rs",
        "a_cosignature_is_counted_only_if_it_verifies",
        "a signature line is matched to a trusted key by name only, dropping "
        "`signed-note`'s conjunction — so a server that picks the name it "
        "sends can wear the identity of any witness the operator registered, "
        "and a rotated-away key keeps counting",
        """        .find(|k| k.name == line.name && k.note_key_id == line.key_id)?;""",
        """        .find(|k| k.name == line.name)?;""",
    ),
    "OnlyTheFirstSignatureLineIsRead": (
        "src/journal/witness_http.rs",
        "a_cosignature_is_counted_only_if_it_verifies",
        "only the first signature line of a 200 is considered, so which "
        "cosignature counts is decided by the answering server's ordering and "
        "a real one behind an unknown key's line is discarded",
        """    for line in &note.signatures {
        if let Some(cosignature) = verify_line(line, &note_text, trusted) {""",
        """    for line in note.signatures.iter().take(1) {
        if let Some(cosignature) = verify_line(line, &note_text, trusted) {""",
    ),
    "AWitnessKeyIdNamesAPlainSignature": (
        "src/journal/witness_http.rs",
        "a_cosignature_is_counted_only_if_it_verifies",
        "a trusted witness key id is derived with 0x01 — signed-note's plain "
        "Ed25519 type — instead of 0x04, tlog-cosignature's algorithm byte, so "
        "the id matches no line a conforming witness sends and every real "
        "cosignature is skipped as an unknown key: a client that can only ever "
        "verify a fake",
        """        let note_key_id = super::note::key_id(&name, 0x04, &public_key);""",
        """        let note_key_id = super::note::key_id(&name, 0x01, &public_key);""",
    ),
    "ACheckpointIsSignedOnceAtConfiguration": (
        "src/journal/witness_http.rs",
        "every_checkpoint_is_signed_over_its_own_note",
        "the log's own signature over a checkpoint is taken from configuration "
        "rather than made over this checkpoint's note body — so it is correct "
        "for exactly one checkpoint and every conformant witness answers 403 "
        "Forbidden for every one after it, while the client's message says the "
        "log's key is not registered",
        """        let signature = self.log.sign(&body).await?;""",
        """        let signature = self.log.sign("plane-a\\n0\\nAA==\\n").await?;""",
    ),
    "AnUnverifiableProofIsAFork": (
        "src/journal/witness_http.rs",
        "a_422_is_a_fork_only_where_the_witness_removed_the_ambiguity",
        "a 422 is reported as a forked history whatever its cause, but the "
        "specification gives it three and only equal-sizes-unequal-roots is "
        "evidence about the log — so a consistency proof this plane built "
        "wrongly pages an operator for a split view, which is the alert this "
        "module's own 409 handling exists to keep believable",
        """            422 if old_size == checkpoint.size => Err(WitnessError::Forked {""",
        """            422 if old_size <= checkpoint.size => Err(WitnessError::Forked {""",
    ),
    "ACosignatureNeedsNoObservationTime": (
        "src/journal/witness_http.rs",
        "a_cosignature_without_an_observation_time_is_not_counted",
        "a cosignature with a zero timestamp is counted, which `tlog-witness` "
        "forbids in as many words — and the observation instant is half of "
        "what a cosignature is: it is what separates a witness that is "
        "watching from one that answered once and stopped",
        """    if timestamp == 0 {
        return None;
    }""",
        """    if false {
        return None;
    }""",
    ),
    "AnOpenRunsTailReadsAsPinned": (
        "src/export.rs",
        "an_open_runs_tail_is_reported_as_unpinned",
        "an offline verification of a file carrying in-flight runs says nothing "
        "about the one thing its root cannot prove — a run with no position in "
        "the Merkle log has an unpinned tail, so records cut from it before the "
        "export was taken are undetectable — while `audit` states exactly that "
        "about the same history, leaving the reader an independent auditor "
        "holds as the laxer of the two",
        """    if open_runs > 0 {""",
        """    if false {""",
    ),
    "APrefixAnchorIsNeverRebuilt": (
        "src/export.rs",
        "a_run_dropped_below_a_prefix_anchor_is_a_finding",
        "a checkpoint smaller than the export is filed as unanswerable though "
        "the file carries every leaf it commits to, so an editor who drops an "
        "early run, renumbers the rest and rewrites the header verifies "
        "against a witness's checkpoint that the dropped run was part of",
        """        } else if prefix_root(leaves, given.size) != Some(given.root) {""",
        """        } else if false {""",
    ),
    "AnEditedRecordReadsAsBuildSkew": (
        "src/export.rs",
        "an_unparseable_record_that_fails_its_hash_is_an_edit_not_a_skew",
        "the body is parsed before the hash is checked, so replaced bytes that "
        "happen not to parse are excused as a newer writer's record rather "
        "than reported as edited — a tampering verdict spent as a build skew",
        """    if crate::core::Digest::chain(pass.prev, raw_bytes) != claimed {""",
        """    if false {""",
    ),
    "ARestoreReplaysBytesItsHashDoesNotCover": (
        "src/export.rs",
        "a_record_whose_hash_does_not_cover_its_bytes_refuses_to_restore",
        "a restore replays a record line without holding its bytes to its "
        "claimed hash, so an edited record is rebuilt into the store — which "
        "re-derives every hash from what it is handed — before anything "
        "compares the result with the export",
        """    crate::journal::Record::from_stored_with(upcaster, raw.to_vec(), prev, claimed, None).map_err(""",
        """    crate::journal::Record::from_stored_with(upcaster, raw.to_vec(), prev, crate::core::Digest::chain(prev, raw), None).map_err(""",
    ),
    "ARestoreRewritesAForeignVersion": (
        "src/export.rs",
        "a_record_at_a_foreign_version_refuses_to_restore_before_any_write",
        "a restore replays a record at a version no upcaster reaches, so the "
        "store is handed bytes it cannot read back — written before anything "
        "compares the result with the export",
        """    crate::journal::Record::from_stored_with(upcaster, raw.to_vec(), prev, claimed, None).map_err(""",
        """    serde_json::from_slice::<crate::journal::RecordBody>(raw)
        .map_err(StoreError::Encoding)
        .and_then(|body| {
            let _ = (claimed, upcaster);
            crate::journal::Record::seal(body, prev)
        })
        .map_err(""",
    ),
    "RedbReadsThroughTheIdentity": (
        "src/store/redb.rs",
        "redb_satisfies_the_journal_store_contract",
        "the embedded store reads every record through this build's own shapes "
        "whatever upcaster it was built with, so the first shape change makes a "
        "store refuse the history it holds — a migration that is also the "
        "mechanism's first exercise",
        """        Record::from_stored_with(
            upcaster,
            self.body,""",
        """        Record::from_stored_with(
            {
                let _ = upcaster;
                &crate::journal::Identity
            },
            self.body,""",
    ),
    "PostgresReadsThroughTheIdentity": (
        "src/store/postgres.rs",
        "postgres_satisfies_the_journal_store_contract",
        "the shared backend's run read ignores its upcaster, so a store written "
        "at an older shape refuses its own history on the first read after the "
        "upgrade — the redb mutation cannot reach this copy of the read",
        """            let signature = signature_of(seq.cast_unsigned(), key_id, signature)?;
            out.push(Record::from_stored_with(
                self.upcaster.as_ref(),""",
        """            let signature = signature_of(seq.cast_unsigned(), key_id, signature)?;
            out.push(Record::from_stored_with(
                &crate::journal::Identity,""",
    ),
    "PostgresCaseReadsThroughTheIdentity": (
        "src/store/postgres.rs",
        "postgres_satisfies_the_journal_store_contract",
        "the shared backend's case read ignores its upcaster, so a matter's "
        "history written at an older shape reads by run and is refused by case",
        """            let signature = signature_of(0, key_id, signature)?;
            out.push(Record::from_stored_with(
                self.upcaster.as_ref(),""",
        """            let signature = signature_of(0, key_id, signature)?;
            out.push(Record::from_stored_with(
                &crate::journal::Identity,""",
    ),
    "VerifyParsesBeforeTheVersion": (
        "src/export.rs",
        "an_export_at_an_older_record_shape_verifies_under_an_upcaster",
        "the verifier parses a record into this build's struct before its "
        "version is compared, so a record at an older shape is filed as "
        "malformed before the upcaster that reads it is ever asked",
        """    let record = match crate::journal::Record::from_stored_with(""",
        """    if let Err(parse) = serde_json::from_slice::<crate::journal::RecordBody>(raw_bytes) {
        return unread_record(raw_bytes, &crate::core::StoreError::Encoding(parse), pass, report);
    }
    let record = match crate::journal::Record::from_stored_with(""",
    ),
    "VerifyReadsThroughTheIdentity": (
        "src/export.rs",
        "an_export_at_an_older_record_shape_verifies_under_an_upcaster",
        "the verifier ignores the upcaster it is handed and reads through this "
        "build's own shapes, so every export written before a shape change "
        "reports a build skew on every record it carries",
        """    let record = match crate::journal::Record::from_stored_with(
        upcaster,""",
        """    let record = match crate::journal::Record::from_stored_with(
        {
            let _ = upcaster;
            &crate::journal::Identity
        },""",
    ),
    "ARestoreResealsALiftedBody": (
        "src/journal/record.rs",
        "a_restored_chain_hashes_as_the_exported_one_under_an_upcaster",
        "a restore hands the store the lifted body without the bytes it was "
        "written with, so the store re-seals this build's serialization of it — "
        "new bytes and a new hash, and the restored chain is not the exported one",
        """            written: Some(record.raw),""",
        """            written: {
                let _ = record.raw;
                None
            },""",
    ),
    "AnExportWritesOnlyThisBuildsShape": (
        "src/export.rs",
        "two_builds_rehearse_the_upgrade_and_the_rollback_window",
        "the export writer parses every record into this build's shape for its "
        "display copy, so a store holding an older shape cannot be exported by "
        "the build that reads it — the upgrade's own first step fails",
        """            _ => DisplayBody::Written(serde_json::from_slice(r.raw()).map_err(unparsed)?),""",
        """            Ok(body) => DisplayBody::Current(Box::new(body)),
            Err(e) => return Err(unparsed(e)),""",
    ),
    "AnAuditKeepsOnlyTheHighestAnchor": (
        "src/audit.rs",
        "a_fork_is_caught_by_the_shorter_anchor_the_highest_would_have_hidden",
        "the append-only check runs against the tallest checkpoint the auditor "
        "brought instead of against each one, so an operator who forks and has "
        "a fresh witness cosign the fork is audited against the fork — the "
        "shorter, honest observation being exactly the one dropped",
        "    for anchor in evidence.anchors {",
        "    for anchor in evidence.anchors.iter().max_by_key(|a| a.checkpoint.size) {",
    ),
    "AnAuditDoesNotNameItsAnchor": (
        "src/audit.rs",
        "an_audit_names_the_checkpoint_it_was_held_to",
        "the report does not record which checkpoint the append-only check ran "
        "against, so a clean verdict against an outside anchor is "
        "indistinguishable from a clean verdict that compared the store with "
        "itself — to a SIEM, a ticket attachment and a compliance reviewer "
        "alike, which are the three readers of this JSON",
        """        held_to: evidence.anchors.to_vec(),""",
        """        held_to: Vec::new(),""",
    ),
    "ARestoreDropsALegalHold": (
        "src/export.rs",
        "a_legal_hold_survives_export_and_restore",
        "a restore rebuilds a held matter without its hold, so the next "
        "retention pass on the recovered plane finds a closed, old, unheld case "
        "and erases exactly the matter somebody was ordered to preserve",
        """                if let Some(hold) = &block.hold {""",
        """                if let Some(hold) = None::<&crate::core::LegalHold> {""",
    ),
    "AConcludedRunCountsAsInFlight": (
        "src/export.rs",
        "a_run_still_in_flight_is_named_by_nothing_the_outcome_indexes_hold",
        "a concluded run is selected as in flight, so an export carries every "
        "sealed run twice — and the arm that decides it is the one that must "
        "fail closed, because a conclusion this build cannot interpret is "
        "still a conclusion",
        """                        Some(_) => false,""",
        """                        Some(_) => true,""",
    ),
    "AnInFlightRunIsNotSelected": (
        "src/export.rs",
        "a_run_still_in_flight_is_named_by_nothing_the_outcome_indexes_hold",
        "a run that has not concluded is left out of the selection, so an "
        "export taken for disaster recovery carries no run that was sleeping, "
        "awaiting a message or waiting on a person — and the loss is invisible "
        "in the result, because the Merkle log commits to sealed runs only and "
        "the restore still reports itself faithful",
        """                    if in_flight {
                        found.runs.push(run);
                    }""",
        """                    if in_flight {
                        let _ = run;
                    }""",
    ),
    "ARestoredWaitIsNotNamed": (
        "src/export.rs",
        "a_restored_wait_is_armed_by_nothing_until_the_run_is_resumed",
        "a restore does not name the runs that came back waiting, so the one "
        "thing an operator must act on is absent from the report — and a "
        "restored wait is armed by nothing: no timer fires, no subscription "
        "matches, and the run released its lease cleanly when it suspended, so "
        "recovery does not see it either",
        """            awaiting.push(run.run);""",
        """            let _ = run;""",
    ),
    "AnyWitnessDisagreementIsASplitView": (
        "src/journal/witness.rs",
        "a_split_view_is_equal_sizes_with_unequal_roots_and_nothing_else",
        "two witnesses at different tree sizes are reported as a split view, so "
        "the ordinary case — witnesses that observed at different times — pages "
        "an operator for the system working, and the one alert this crate "
        "cannot raise any other way stops being believed",
        """            if a.size == b.size && a.root != b.root {""",
        """            if a.root != b.root {""",
    ),
    "TheSweepNeverAsksAWitness": (
        "src/runtime/sweeper.rs",
        "a_plane_with_witnesses_anchors_its_history_on_the_sweep",
        "the periodic pass never submits a checkpoint, so a plane configured "
        "with witnesses is anchored nowhere outside itself while every report "
        "it prints stays clean — the shape this whole tier had before there "
        "was a door: the mechanism exists, so the requirement reads as met",
        """            self.cosign_checkpoint(now, &mut report).await?;""",
        """            let _ = (now, &mut report);""",
    ),
    "AWitnessShortfallIsAQuietTick": (
        "src/runtime/sweeper.rs",
        "a_witness_that_cannot_be_reached_is_a_shortfall_on_the_report",
        "a plane anchored by fewer independent parties than the deployment "
        "declared it required does not reach `needs_attention`, so witnessing "
        "silently stops and the sweep that says so looks like every other "
        "quiet tick",
        """            || self.witness_shortfall > 0""",
        """            || false""",
    ),
    "AWitnessReaderNeedsNoKeys": (
        "src/journal/witness_http.rs",
        "a_reader_with_no_keys_cannot_report_an_anchor",
        "a reader is constructible with no trusted key, so it reports whatever "
        "a URL served as an independent anchor — the sibling of the client's "
        "own refusal, on the direction an auditor actually uses",
        """        if trusted.is_empty() {
            return Err(WitnessError::Unavailable(
                "a witness reader needs at least one trusted key""",
        """        if false {
            return Err(WitnessError::Unavailable(
                "a witness reader needs at least one trusted key""",
    ),
    "AnUncosignedCheckpointIsAnAnchor": (
        "src/journal/witness_http.rs",
        "an_uncosigned_checkpoint_is_not_an_anchor",
        "a monitoring endpoint's answer is returned whether or not any trusted "
        "key covers it, so an auditor is handed the plane's own checkpoint "
        "under the name of an independent party's — and then runs the deletion "
        "check against the history it is supposed to be checking",
        """        if cosignatures.is_empty() {""",
        """        if false {""",
    ),
    "AWitnessClientNeedsNoKeys": (
        "src/journal/witness_http.rs",
        "a_witness_client_with_no_keys_is_not_a_witness_client",
        "a witness client is constructible with an empty trusted set, which "
        "verifies nothing and refuses everything — a misconfiguration that "
        "reads as a witness being down rather than as never having been "
        "configured",
        """        if trusted.is_empty() {
            return Err(WitnessError::Unavailable(
                "a witness needs at least one trusted key""",
        """        if false {
            return Err(WitnessError::Unavailable(
                "a witness needs at least one trusted key""",
    ),
    "AnUnreadableStaleSizeBecomesZero": (
        "src/journal/witness_http.rs",
        "a_stale_reply_without_a_size_is_not_an_integrity_event",
        "a 409 whose body is not a tree size is read as the witness being at "
        "size 0 — a claim it never made, which the caller acts on by "
        "resubmitting a proof from 0 that comes back classified as a fork, so "
        "an unreadable reply manufactures an integrity page",
        """            409 => match text.trim().parse::<u64>() {
                Ok(witness_size) => Err(WitnessError::Stale {
                    origin: checkpoint.origin.clone(),
                    witness_size,
                }),""",
        """            409 => match text.trim().parse::<u64>().or(Ok::<u64, ()>(0)) {
                Ok(witness_size) => Err(WitnessError::Stale {
                    origin: checkpoint.origin.clone(),
                    witness_size,
                }),""",
    ),
    "TheActionListOmitsTheQuarantineVerb": (
        "src/api/mod.rs",
        "a_denying_policy_stops_every_route_before_it_touches_anything",
        "`api:run.list` is missing from the enumerated action vocabulary, so a "
        "deployment writing rules from it never grants the verb behind *what is "
        "quarantined right now* — and a default-deny engine then refuses the "
        "backlog that exists so a quarantine reaches somebody",
        """        RUN_READ,
        RUN_HISTORY,
        RUN_LIST,
        RUN_LIVE,
        RUN_WAITING,
        ATTENTION,
        DRILL_READ,
        RUN_CANCEL,""",
        """        RUN_READ,
        RUN_HISTORY,
        RUN_LIVE,
        RUN_WAITING,
        ATTENTION,
        DRILL_READ,
        RUN_CANCEL,""",
    ),
    "EscalatedCasesAreNotListable": (
        "src/api/mod.rs",
        "escalated_cases_are_listable_without_knowing_the_case_id",
        "the case listing answers with whatever status was asked but ignores "
        "the store's index, returning nothing — so an escalated case is "
        "findable only by somebody who already knows its id, which is the group "
        "that does not need to ask",
        """    let mut found = cases
        .by_status(status, api.limit.saturating_add(1))
        .await
        .map_err(|_| store_failed())?;""",
        """    let mut found = cases
        .by_status(status, api.limit.saturating_add(1))
        .await
        .map_err(|_| store_failed())?;
    found.clear();""",
    ),
    "APlanDigestIgnoresItsTopology": (
        "src/core/plan.rs",
        "every_identity_bearing_field_of_a_plan_changes_its_digest",
        "the plan's content address is taken over its nodes alone, so topology "
        "— which decides whether sub-tasks may run on overlapping inputs and "
        "with what authority — is outside the identity that admission journals "
        "and binds the run to",
        """        let value = serde_json::to_value(self)
            .expect("a plan holds only strings, integers, enums, digests and JSON values");""",
        """        let value = serde_json::to_value(&self.nodes)
            .expect("a plan holds only strings, integers, enums, digests and JSON values");""",
    ),
    "TheDiscoveryIndexIgnoresItsCursor": (
        "src/store/redb.rs",
        "redb_satisfies_the_journal_store_contract",
        "the discovery index ignores the cursor it was given and restarts from "
        "the newest run every time, so a paged listing serves page one forever "
        "and every run past the first page is unreachable",
        """            let rows = match &end {
                Some((updated, key)) => activity
                    .range((tenant.as_str(), 0, "")..(tenant.as_str(), *updated, key.as_str()))
                    .map_err(|e| be(&e))?,""",
        """            let rows = match &None::<(u64, String)> {
                Some((updated, key)) => activity
                    .range((tenant.as_str(), 0, "")..(tenant.as_str(), *updated, key.as_str()))
                    .map_err(|e| be(&e))?,""",
    ),
    "TheFilterScanHasNoCeiling": (
        "src/api/a2a.rs",
        "a_listing_past_its_scan_budget_is_refused_naming_the_lever",
        "a ListTasks reads a record of every candidate in the tenant with no "
        "ceiling to count its exact total, so any authenticated peer buys a "
        "scan of the whole store per request — the cost the paged index exists "
        "to remove, reintroduced through the count",
        """            if examined > server.filter_scan_budget {""",
        """            if examined > usize::MAX {""",
    ),
    "APeersListingIsChargedForTheTenantsRuns": (
        "src/api/a2a.rs",
        "a_listing_reads_only_the_callers_runs",
        "ListTasks finds the caller's runs in the tenant's whole index, so "
        "one peer's listing reads every other peer's runs and every run the "
        "embedder started",
        "            .recent_runs_from(&source, cursor_pos, TASK_SCAN)",
        "            .recent_runs({ let _ = &source; cursor_pos }, TASK_SCAN)",
    ),
    "ATimestampCutoffScansOn": (
        "src/api/a2a.rs",
        "a_timestamp_cutoff_ends_the_listing_scan",
        "a run older than statusTimestampAfter is skipped rather than "
        "ending the scan, so a listing narrowed to recent work pages "
        "through the caller's whole history on a newest-first index to find "
        "nothing",
        "                break 'scan;",
        "                continue;",
    ),
    "AnInterruptedSiblingIsNotAsked": (
        "src/runtime/executor.rs",
        "an_interrupted_siblings_landed_work_is_unwound_with_nothing_completed",
        "whether a failure unwinds is asked of completed steps alone, so a "
        "failure with nothing completed leaves an interrupted sibling's "
        "landed mutation in the world",
        "        let candidates = Self::with_interrupted_siblings(completed, &evidence);",
        "        let candidates = completed.to_vec();",
    ),
    "TheFailingStepIsUnwoundToo": (
        "src/runtime/executor.rs",
        "a_failed_run_standing_on_landed_work_is_on_the_attention_roll_up",
        "the failing step counts as an interrupted sibling, so a failure "
        "whose only landed work is its own closes the run by compensating "
        "it instead of leaving it resumable",
        "            .filter(|s| !done.contains(s) && !evidence.failed.contains(s))",
        "            .filter(|s| !done.contains(s))",
    ),
    "AFailedRunOnLandedWorkIsQuiet": (
        "src/runtime/attention.rs",
        "a_failed_run_standing_on_landed_work_is_on_the_attention_roll_up",
        "a failed run standing on landed work nothing undid is left off the "
        "attention roll-up, so the work stays in the world with nothing "
        "naming it",
        "            if self.holds_landed_work(*run).await? {",
        "            if false && self.holds_landed_work(*run).await? {",
    ),
    "TheTaskTotalCountsHiddenTasks": (
        "src/api/a2a.rs",
        "list_tasks_omits_tasks_the_caller_cannot_read",
        "`totalSize` is counted before the permission check, so the reply "
        "discloses how many tasks exist that the caller was just refused — the "
        "listing hides the rows and the number reports them",
        """            if !server.permits(&caller, action::TASK_READ, &run.to_string(), owner) {
                continue;
            }""",
        """            if !server.permits(&caller, action::TASK_READ, &run.to_string(), owner) {
                matched += 1;
                continue;
            }""",
    ),
    "ListTasksCountsOtherPeersTasks": (
        "src/api/a2a.rs",
        "a_task_belongs_to_the_peer_that_admitted_it",
        "ListTasks reads the tenant's whole index rather than the caller's "
        "range of it, so a peer lists and counts other peers' task ids and "
        "the runs the embedder started in-process",
        "            .recent_runs_from(&source, cursor_pos, TASK_SCAN)",
        "            .recent_runs({ let _ = &source; cursor_pos }, TASK_SCAN)",
    ),
    "TheSourceIndexKeepsStaleRows": (
        "src/store/redb.rs",
        "redb_satisfies_the_journal_store_contract",
        "the per-producer run index gains a row on every append instead of "
        "moving one, so a producer's listing names each of its runs once "
        "per append",
        "                            .remove((tenant.as_str(), source.as_str(), previous, key.as_str()))",
        "                            .remove((tenant.as_str(), source.as_str(), previous.wrapping_add(7), key.as_str()))",
    ),
    "PostgresTheSourceIndexForgetsTheProducer": (
        "src/store/postgres.rs",
        "postgres_satisfies_the_journal_store_contract",
        "every append after the admission clears the run's admitting "
        "producer, so a run leaves its producer's listing the moment it "
        "makes progress",
        "                 admission_source = COALESCE(run_activity.admission_source,",
        "                 admission_source = COALESCE(NULL,",
    ),
    "ATaskIdIsABearerToken": (
        "src/api/a2a.rs",
        "a_task_belongs_to_the_peer_that_admitted_it",
        "every task method acts on whatever run the id names, so a peer holding "
        "another peer's task id reads its history, cancels it, continues it, "
        "subscribes to it and redirects its webhook",
        """        let owner = task_owner(&records);
        if owner != Some(caller.actor.as_str()) {""",
        """        let owner = task_owner(&records);
        if owner.is_some_and(|_| false) {""",
    ),
    "APeerJoinsAnotherPeersContext": (
        "src/api/a2a.rs",
        "a_task_belongs_to_the_peer_that_admitted_it",
        "a contextId is honoured whoever opened it, so a peer that learns "
        "another's context id seats its own run inside that case",
        "            && crate::core::origin_source(&key.value) == Some(ours.as_str())",
        "            && crate::core::origin_source(&key.value).is_some_and(|_| !ours.is_empty())",
    ),
    "TheTaskRuleCannotNameItsOwner": (
        "src/api/a2a.rs",
        "a_task_belongs_to_the_peer_that_admitted_it",
        "a task action's policy context omits whose task it is, so a rule set "
        "cannot say that a peer reads its own tasks in its own words",
        """            context["owner"] = json!(owner);""",
        """            let _ = owner;""",
    ),
    "AStoreFaultIsRelayedToThePeer": (
        "src/api/a2a.rs",
        "an_internal_fault_names_nothing_about_the_plane",
        "an internal fault is answered with the error's own text, so a store's "
        "DSN, host or table reaches whoever sent the request",
        """        crate::core::withheld_fault("a2a", doing, error),""",
        """        error.to_string(),""",
    ),
    "AFilteredLiveListingHidesItsTruncation": (
        "src/api/mod.rs",
        "a_filtered_live_listing_reports_the_truncation_of_its_page",
        "the subject filter runs before truncation is decided, so a responder "
        "asking what still acts under a withdrawn authority is told nothing is "
        "when the runs past the page were never read",
        """    let truncated = found.len() > api.limit;
    found.truncate(api.limit);
    if let Some(subject) = q.subject.as_deref() {
        found.retain(|live| live.subject.as_deref() == Some(subject));
    }""",
        """    if let Some(subject) = q.subject.as_deref() {
        found.retain(|live| live.subject.as_deref() == Some(subject));
    }
    let truncated = found.len() > api.limit;
    found.truncate(api.limit);""",
    ),
    "StreamsPerCallerAreUnbounded": (
        "src/api/a2a.rs",
        "open_streams_per_caller_are_bounded_and_given_back",
        "a peer may hold any number of streams open, each a connection and a "
        "journal poll for as long as its run lives",
        "        if *held >= self.limit {",
        "        if *held >= usize::MAX {",
    ),
    "ARestoreSealsInFileOrder": (
        "src/export.rs",
        "a_restored_store_rebuilds_the_same_checkpoint",
        "a restore seals runs in whatever order the export listed them rather "
        "than in the log's own order, so the Merkle tree is rebuilt over the "
        "same leaves in a different sequence — a store holding identical history "
        "under a root no checkpoint or witness cosignature matches",
        """    sealed.sort_by_key(|r| r.index);""",
        """    sealed.reverse();""",
    ),
    "ARestoreFlattensTheEpoch": (
        "src/export.rs",
        "a_run_that_changed_hands_restores_with_its_epochs",
        "a restore writes every record under one epoch instead of the epoch it was sealed with, so any run that ever changed hands rehashes — and those are exactly the runs a failover produced, which is the history a disaster recovery is most likely to be carrying",
        "            for (written, want) in store.append(epoch, appends).await?.iter().zip(&mut claimed) {",
        "            for (written, want) in store.append(1, appends).await?.iter().zip(&mut claimed) {",
    ),
    "AnExportOmitsItsLogPositions": (
        "src/export.rs",
        "a_run_removed_from_the_middle_is_caught_by_the_rebuilt_root",
        "the export carries no Merkle log position for a sealed run, so a verifier can walk every chain and still not notice a whole run deleted from the middle — each surviving chain is internally consistent, and only the rebuilt tree can see the gap",
        "    let positions = store\n        .log_positions(runs)\n        .await\n        .unwrap_or_else(|_| vec![None; runs.len()]);",
        "    let positions: Vec<Option<(u64, crate::core::Digest)>> = vec![None; runs.len()];",
    ),
    "AVerifiedExportSkipsTheRehash": (
        "src/export.rs",
        "an_edited_record_fails_to_recompute",
        "verification trusts the hash a record carries instead of recomputing "
        "it, so an export edited after it was written verifies clean — the "
        "chain becomes a claim the file makes about itself",
        """    if crate::core::Digest::chain(pass.prev, raw_bytes) != claimed {""",
        """    if claimed != claimed {""",
    ),
    "AnExportDropsAnUnreadableRun": (
        "src/export.rs",
        "a_run_that_cannot_be_read_is_named_in_the_trailer",
        "a run the export could not read is skipped without being named, so a "
        "partial export is shaped exactly like a complete one — and the run "
        "that fails to read is not a random one",
        """            Err(e) => unreadable.push(Unreadable {
                run,
                reason: e.to_string(),
            }),""",
        """            Err(_) => {}""",
    ),
    "AForeignFormatVersionVerifiesAnyway": (
        "src/export.rs",
        "an_export_of_a_foreign_format_version_is_named_not_guessed_at",
        "the verifier never looks at the header's format version, so a future "
        "format is parsed as far as its lines happen to look familiar and the "
        "report describes a file this build never understood — the version a "
        "reader was told to pin, consulted by nobody",
        """    if version != Some(u64::from(FORMAT_VERSION)) {""",
        """    if version != Some(u64::from(FORMAT_VERSION)) && false {""",
    ),
    "ARestoreRebuildsAForeignFormat": (
        "src/export.rs",
        "an_export_of_a_foreign_format_version_is_named_not_guessed_at",
        "a restore accepts a format version this build does not read, and "
        "`parse` skips what it does not recognise — so it rebuilds whatever "
        "subset happened to look familiar and calls it a history",
        """    if parsed.version != Some(u64::from(FORMAT_VERSION)) {""",
        """    if parsed.version != Some(u64::from(FORMAT_VERSION)) && false {""",
    ),
    "ADuplicatedLogPositionIsARootMismatch": (
        "src/export.rs",
        "a_duplicated_log_position_is_named_rather_than_left_as_a_root_mismatch",
        "the verifier stops holding run blocks' log positions to the "
        "contiguous 0..N the checkpoint commits to, so an export spliced from "
        "two histories rebuilds a tree over duplicated positions and reports "
        "a bare root mismatch — true, and useless to the auditor asking which "
        "runs to distrust",
        """        let contiguous = leaves
            .iter()
            .enumerate()
            .all(|(at, (index, _))| u64::try_from(at) == Ok(*index));""",
        """        let contiguous = true;""",
    ),
    "ARelabelledRunBlockVerifies": (
        "src/export.rs",
        "a_relabelled_run_block_is_caught_by_its_own_records",
        "the verifier never compares a record's own run id against the block it "
        "sits under, so an export that files run B's records and B's leaf under "
        "run A's id passes every check — chain, leaf and Merkle all verify B's "
        "bytes, and only the label lied, which is what a reader looks a run up "
        "by",
        """    if body.run != current {""",
        """    if false && body.run != current {""",
    ),
    "AnExportStampsALeafPastItsCheckpoint": (
        "src/export.rs",
        "a_run_sealed_after_the_checkpoint_exports_as_still_open",
        "a run sealed after the export's checkpoint was taken is stamped with a log position the header does not commit to, so the export disagrees with its own first line and the verifier reports tampering where there was only time — a race every busy plane hits",
        "        let placed = placed.filter(|&(index, _)| index < log_size);",
        "        let placed = placed.filter(|&(index, _)| index <= u64::MAX);",
    ),
    "AnOpenRunsFindingsNeverReachItsVerdict": (
        "src/export.rs",
        "an_edited_record_in_an_open_run_is_not_sound",
        "per-record findings never reach the run's verdict, so an edited record "
        "in an open run — which has no leaf to catch it — produces a finding "
        "and leaves the run listed sound, two halves of one report "
        "contradicting each other",
        """    let mut ok = pass.clean;""",
        """    let mut ok = true;""",
    ),
    "ASealedOutcomeFallsOffTheExportList": (
        "src/runtime/executor.rs",
        "the_sealed_outcome_list_agrees_with_the_sealing_rule",
        "a sealing outcome is dropped from SEALED_OUTCOMES, so the export CLI's "
        "default sweep silently omits every run sealed with it — and the runs "
        "dropped are quarantined ones, exactly the runs an auditor came for",
        """pub const SEALED_OUTCOMES: &[&str] = &[
    "succeeded",
    "cancelled",""",
        """pub const SEALED_OUTCOMES: &[&str] = &[
    "succeeded",""",
    ),
    "AnExportHasNoTrailer": (
        "src/export.rs",
        "an_interrupted_export_is_missing_its_trailer",
        "the export is written without its closing trailer, so a file cut short "
        "by a full disk or a killed pipe is indistinguishable from a whole one "
        "to a reader who does not have the source to count against",
        """    writeln!(out, "{}", to_line(&trailer)?)?;
    out.flush()?;""",
        """    out.flush()?;""",
    ),
    "TheOrdinaryLookupCrossesTenants": (
        "src/api/mod.rs",
        "crossing_to_another_tenant_records_before_it_serves",
        "the ordinary plane lookup serves whatever tenant is asked for rather "
        "than the caller's own, so a handler reaches another tenant's store "
        "without the crossing ever being recorded — which leaves `Planes::cross` "
        "a step somebody has to remember rather than the door it claims to be",
        "        self.by_tenant.get(&caller.tenant)",
        "        self.by_tenant\n"
        "            .get(&caller.tenant)\n"
        "            .or_else(|| self.by_tenant.values().next())",
    ),
    "CrossingServesBeforeItRecords": (
        "src/api/mod.rs",
        "crossing_to_another_tenant_records_before_it_serves",
        "the break-glass gate hands back another tenant's plane whether or not "
        "the crossing was recorded, so a failure to write the evidence stops "
        "being a failure to access — which is the whole of the control",
        """        // The record first, and the plane only if it landed.
        plane
            .record_break_glass(
                &crate::core::Operator::authenticated(caller.actor.clone()).map_err(|e| {
                    crate::core::RuntimeError::Store(crate::core::StoreError::Backend(
                        e.to_string(),
                    ))
                })?,
                &caller.roles,
                reason,
            )
            .await?;
        Ok(plane)""",
        """        let _ = plane
            .record_break_glass(
                &crate::core::Operator::authenticated(caller.actor.clone()).map_err(|e| {
                    crate::core::RuntimeError::Store(crate::core::StoreError::Backend(
                        e.to_string(),
                    ))
                })?,
                &caller.roles,
                reason,
            )
            .await;
        Ok(plane)""",
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
            Self::Succeeded
                | Self::Cancelled { .. }
                | Self::Abandoned { .. }
                | Self::Swept
                | Self::BrokeGlass { .. }
                | Self::HaltLifted { .. }
                | Self::HoldReleased { .. }
                | Self::Observed
        )""",
        """        matches!(
            self,
            Self::Succeeded
                | Self::Cancelled { .. }
                | Self::Abandoned { .. }
                | Self::Swept
                | Self::BrokeGlass { .. }
                | Self::HaltLifted { .. }
                | Self::HoldReleased { .. }
                | Self::Failed(_)
        )""",
    ),
    "ARunsJournalRidesTheStatusVerb": (
        "src/api/mod.rs",
        "a_denying_policy_stops_every_route_before_it_touches_anything",
        "reading a run's whole journal is authorized under the status view's "
        "verb, so every deployment that granted an on-call rota `run.read` "
        "silently also granted them every input, model exchange and argument "
        "the run sent",
        """    let s = api.gate(&headers, action::RUN_HISTORY, &run).await?;""",
        """    let s = api.gate(&headers, action::RUN_READ, &run).await?;""",
    ),
    "AnEgressCeilingOvershoots": (
        "src/core/budget.rs",
        "an_egress_ceiling_refuses_the_call_that_would_cross_it",
        "the egress ceiling is compared like a metered one — against what has "
        "already been sent rather than what this call would reach — so the "
        "effect that crosses it is sent and only the next one is refused, "
        "which is an overshoot the size being known in advance makes avoidable",
        """            && self.consumed.egress_bytes.saturating_add(outbound) > max""",
        """            && self.consumed.egress_bytes >= max""",
    ),
    "AReplayForgetsWhatItSent": (
        "src/core/budget.rs",
        "a_strict_replay_reaches_the_same_egress_tally",
        "a replayed attempt bills its slot and not its outbound size, so a "
        "resumed run has room under an egress ceiling its own history had "
        "already reached — the divergence journaled figures exist to prevent",
        """    pub fn replay_effect(&mut self, spend: Spend, outbound: u64) {
        self.consumed.effects += 1;
        self.consumed.spend += spend;
        self.consumed.egress_bytes = self.consumed.egress_bytes.saturating_add(outbound);""",
        """    pub fn replay_effect(&mut self, spend: Spend, outbound: u64) {
        let _ = outbound;
        self.consumed.effects += 1;
        self.consumed.spend += spend;""",
    ),
    "AReadCostsEgress": (
        "src/core/effect.rs",
        "a_zero_egress_ceiling_still_permits_a_read",
        "an effect that binds no outbound value is counted as having sent "
        "something, so a run of pure reads exhausts an egress ceiling and the "
        "one shape the ceiling exists to permit — look but do not send — "
        "cannot run at all",
        """        self.sink_arguments().map_or(0, |args| {""",
        """        self.sink_arguments().map_or(1, |args| {""",
    ),
    "ARehearsalDoesNotSayWhichStore": (
        "src/runtime/executor.rs",
        "a_rehearsal_leaves_a_record_the_plane_can_be_asked_for",
        "the rehearsal's record does not say which store it ran against, so a "
        "drill over a restored copy reads exactly like one over production — "
        "the obvious mistake, and the one an auditor most needs the record to "
        "make impossible",
        """                origin: checkpoint.origin.clone(),""",
        """                origin: String::new(),""",
    ),
    "AnIncidentVerbIsAbsentFromTheExampleBundle": (
        "examples/serve-policy.cedar",
        "the_example_bundle_names_every_action_the_crate_asks_about",
        "the only policy bundle this project ships — the one getting-started "
        "hands a newcomer and docker-smoke runs — stops naming an action the "
        "crate asks about, while its comment still claims to be the complete "
        "vocabulary; Cedar denies what no rule permits, so a deployment that "
        "copied the list finds the verb refused at the point of use, and for "
        "a halt that point is the incident",
        """//   api:halt.list     api:halt.place  api:halt.lift""",
        """//   api:halt.list     api:halt.lift""",
    ),
    "AStatusIsMissingFromTheAgreementList": (
        "src/runtime/executor.rs",
        "every_run_status_variant_is_listed",
        "a run status the enum declares is absent from the one list every "
        "agreement test walks, so nothing decides whether it seals, whether a "
        "resume may continue from it, or which A2A state it surfaces as — and "
        "the length assertions beside that list stay green, because they fire "
        "when somebody edits it rather than when somebody forgets to",
        """        RunStatus::Swept,""",
        """        RunStatus::Quarantined("a second".into()),""",
    ),
    "ATasksEvidenceIsLeftUnsealed": (
        "src/keyring/tasks.rs",
        "a_tasks_evidence_is_sealed_but_its_provenance_is_not",
        "the trail behind a proposal is written to the worklist in the clear, "
        "so a dry-run preview — a tool's answer quoting the caller's data — "
        "outlives the case erasure that reached the journal's copy, in the "
        "one store an operator browses by hand",
        """            *item = item.clone().map(|_| payload::wrap_text(&wrapped));""",
        """            let _ = &wrapped;""",
    ),
    "APreviewIsShownAsTheRuntimesOwnWord": (
        "src/runtime/declarative.rs",
        "a_declared_preview_shows_the_reviewer_what_the_call_will_touch",
        "a dry run's answer reaches the worklist as a sentence the run "
        "vouches for, indistinguishable from the runtime's own notes beside "
        "it — so the most persuasive line on the task, and the one a "
        "compromised tool writes, is the one a reviewer has no reason to "
        "doubt",
        """            answer.map(|_| rendered)""",
        """            crate::core::Tainted::trusted(rendered)""",
    ),
    "TheApproverIsSealedWithWhatTheySaid": (
        "src/core/event.rs",
        "the_approver_outlives_an_erasure_of_what_they_said",
        "the decider is left inside the decision payload, so the only record "
        "of who approved an action sits in a sealed field — a lawful erasure "
        "of the run's payloads destroys the approver's name while leaving the "
        "chain readable, verifiable and auditable, and nothing reports the loss",
        """        self.by = Some(by);""",
        """        let _: crate::core::Operator = by;""",
    ),
    "TheInitiatorIsSealedWithTheInput": (
        "src/journal/payload.rs",
        "the_initiator_outlives_an_erasure",
        "who asked for a run is sealed beside its input, so erasing the case "
        "destroys the name the four-eyes exclusion reads on every task the "
        "run opens, and the chain stays verifiable with the initiator gone",
        """            admitted_by: _,
            // Clear: which holder a run draws as is control-plane.
            served_unchained: _,
            plane_chain: _,
        } => vec![SealedField::Value(input)],""",
        """            admitted_by,
            served_unchained: _,
            plane_chain: _,
        } => {
            let mut v = vec![SealedField::Value(input)];
            v.extend(admitted_by.iter_mut().map(SealedField::Text));
            v
        }""",
    ),
    "AnAdmissionKeyIsUndocumented": (
        "src/policy/requests.rs",
        "the_security_page_documents_every_runtime_gate_s_context",
        "the admission gate asks with an attribute the security page never "
        "names, so the page a rule author writes from describes a request the "
        "plane does not send",
        """    let context = serde_json::json!({ "input": input, "tenant": acting.tenant });""",
        """    let context = serde_json::json!({ "input": input, "tenant": acting.tenant, "capability": acting.capability });""",
    ),
    "AdmissionIgnoresThePinnedDigest": (
        "src/runtime/executor.rs",
        "a_pinned_admission_refuses_another_digest",
        "a run pinned to the revision its scheduler reviewed is admitted under "
        "whichever revision this plane holds, so an edited declaration runs "
        "work that was approved against another one",
        """            if found != Some(expected) {""",
        """            if found.is_none() {""",
    ),
    "ADecisionIsNotComparedToTheRow": (
        "src/runtime/sweeper.rs",
        "a_stale_digest_is_refused_and_nothing_is_recorded",
        "a decision naming a version of its task the row no longer holds is "
        "recorded anyway, so a client deciding on a row that changed since it "
        "read it is answered as if it had read the current one",
        """    expected.is_some_and(|digest| digest != row.justification.digest())""",
        """    let _ = (expected, row);
    false""",
    ),
    "ARowChangedUnderTheClaimKeepsTheClaim": (
        "src/runtime/sweeper.rs",
        "a_row_changed_under_the_claim_is_refused_and_released",
        "a decision refused because the row changed under its claim leaves the "
        "claim behind, so the task sits assigned to somebody whose decision "
        "was never recorded — or a claim the decider already held is taken away",
        """            if !held && let Err(error) = tasks.release(id, by.actor()).await {""",
        """            if held && let Err(error) = tasks.release(id, by.actor()).await {""",
    ),
    "TheServedDigestIsOfTheShownJustification": (
        "src/api/mod.rs",
        "a_served_digest_is_of_the_stored_row",
        "the served digest is of the withheld view rather than the stored row, "
        "so every decision naming it on a proposal this plane cannot open is "
        "refused as stale",
        """            digest: task.justification.digest(),""",
        """            digest: task.shown_justification().digest(),""",
    ),
    "TheDecideRouteDropsTheDigest": (
        "src/api/mod.rs",
        "a_stale_digest_is_refused_with_412",
        "the decide route accepts a digest and never passes it on, so a "
        "decision on a stale version is recorded while the client believes it "
        "was conditional",
        """        .decide_task_at(id, &decision, &s.caller.roles, body.digest)""",
        """        .decide_task_at(id, &decision, &s.caller.roles, None)""",
    ),
    "TheTerminalDropsTheDigest": (
        "src/bin/agentplane.rs",
        "a_stale_digest_at_the_terminal_is_refused",
        "`decide --digest` parses the digest and never passes it on, so a "
        "decision on a stale version is recorded from the terminal",
        """            .decide_task_at(id, &decision, &opts.roles, expected)""",
        """            .decide_task_at(id, &decision, &opts.roles, { let _ = expected; None })""",
    ),
    "TheReleaseDigestHidesItsValue": (
        "src/runtime/ctx.rs",
        "an_erased_low_entropy_value_is_recoverable_from_the_export",
        "the release digest stops being the public unkeyed derivation the "
        "erasure guide describes, so the page states a residual the runtime "
        "no longer leaves and nothing asks for the page to change",
        """        let value_digest = crate::core::Digest::of(&value_bytes);""",
        """        let value_digest = crate::core::Digest::of(&[b"salt".as_slice(), &value_bytes].concat());""",
    ),
    "TheEffectKeyHidesItsArguments": (
        "src/runtime/ctx.rs",
        "an_erased_low_entropy_value_is_recoverable_from_the_export",
        "an effect's key stops being the public unkeyed derivation over its "
        "arguments, so the erasure guide states a residual the runtime no "
        "longer leaves and nothing asks for the page to change",
        """            let key = EffectKey::derive(
                self.step,
                self.phase,
                ordinal,
                attempt,
                &descriptor.kind,
                &canon::value_bytes(&descriptor.args),
            );""",
        """            let key = EffectKey::derive(
                self.step,
                self.phase,
                ordinal,
                attempt,
                &descriptor.kind,
                &[canon::value_bytes(&descriptor.args), b"salt".to_vec()].concat(),
            );""",
    ),
    "TheErasureStatementOmitsARecordKind": (
        "site/content/docs/erasure.md",
        "every_record_kind_is_placed_in_the_erasure_digest_statement",
        "a record kind the erasure guide's digest statement does not place, so "
        "an operator deciding what to seal cannot tell whether it leaves a "
        "digest of erased content in the clear",
        """`HoldReleased`,
`Swept` and `Observed` carry""",
        """`HoldReleased`,
`Observed` carry""",
    ),
    "TheErasureStatementOmitsAStore": (
        "site/content/docs/erasure.md",
        "every_record_kind_is_placed_in_the_erasure_digest_statement",
        "the erasure guide drops the logs' reason digest, so a deployment "
        "believes an erased failure reason is gone from everywhere",
        """| reason digest | every loud event in the deployment's logs, unkeyed and truncated | a failure, quarantine or compensation reason the journal seals |
""",
        "",
    ),
    "AWithdrawalIsUnrecognised": (
        "src/runtime/executor.rs",
        "every_outcome_this_build_writes_is_one_it_can_read_back",
        "the reader loses the arm for a withdrawal, so a run this plane paused "
        "under a withdrawn credential reads back as quarantined with 'this "
        "build does not recognise it' — and the operator deciding whether to "
        "lift the halt or cancel is told the runtime cannot say what happened",
        """        WITHHELD_OUTCOME => recorded_withholding(records).map_or_else(""",
        """        "never-written-by-this-build" => recorded_withholding(records).map_or_else(""",
    ),
    "AnEndingRepeatsTheReasonItsRecordHolds": (
        "src/runtime/executor.rs",
        "the_conclusion_does_not_repeat_a_reason_its_own_record_holds",
        "the conclusion copies the reason an operator gave, so one sentence "
        "becomes two facts — and the copy is a sealed payload while the "
        "original is clear, so after a lawful erasure the chain says both that "
        "the reason is knowable and that it is not",
        """            | Self::Exhausted(_) => None,""",
        """            | Self::Exhausted(_) => self.reason(),""",
    ),
    "ABreakGlassCrossingIsUnrecognised": (
        "src/runtime/executor.rs",
        "every_outcome_this_build_writes_is_one_it_can_read_back",
        "the reader loses the arm for a crossing, so a run this plane sealed "
        "itself reads back as quarantined with 'this build does not recognise "
        "it' in place of the operator's reason — on the one surface the docs "
        "send an incident review to",
        """        BREAK_GLASS_OUTCOME => recorded_crossing(records).map_or_else(""",
        """        "never-written-by-this-build" => recorded_crossing(records).map_or_else(""",
    ),
    "ACrossingIsAnonymous": (
        "src/runtime/executor.rs",
        "a_break_glass_crossing_names_who_crossed",
        "the crossing's actor is not read back from the chain, so the control "
        "whose whole content is who crossed and why answers with the reason and "
        "nobody's name against it",
        """        RecordKind::BreakGlass { actor, reason, .. } => Some((actor.clone(), reason.clone())),""",
        """        RecordKind::BreakGlass { .. } => None,""",
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
    "AFormedMemoryLaundersItsSource": (
        "src/runtime/ctx.rs",
        "a_formed_memory_names_the_sources_of_what_it_was_formed_from",
        "a memory formed from untrusted material names only the model that "
        "phrased it, so the sources it was formed from are absent from the "
        "record a protected field's allowed_sources would have refused",
        "        let label = completion.label().join(&source_label);",
        "        let label = completion.label().clone();",
    ),
    "FormationIgnoresQuarantined": (
        "src/runtime/declarative.rs",
        "formation_runs_on_the_quarantined_model_when_declared",
        "untrusted contact runs on the privileged model even when a quarantined "
        "one is declared, so the role designated for it governs nothing in the "
        "declarative tier",
        "    m.quarantined_role().unwrap_or_else(|| fallback.clone())",
        "    let _ = m;\n    fallback.clone()",
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
    "TheRecoverySweepNeverRuns": (
        "src/runtime/sweeper.rs",
        "the_sweep_recovers_a_run_its_owner_died_holding",
        "the sweep stops taking over the runs an instance died holding, so a "
        "crashed run with no pending timer and no inbound event has no driver "
        "— it appears in no backlog and waits forever while looking exactly "
        "like work in progress",
        "            self.recover_abandoned(&mut report, &mut ledger).await?;",
        "",
    ),
    "ARefusedResumeIsListedNowhere": (
        "src/runtime/executor.rs",
        "a_wake_refused_by_an_edited_declaration_stays_findable",
        "a resume refused for a moved declaration or bundle concludes as an "
        "ordinary failure, which no roll-up lists and every later resume meets "
        "again — the unattended wake that met it tells nobody",
        "            RunStatus::Quarantined(refusal.to_string()),",
        "            RunStatus::Failed(refusal.to_string()),",
    ),
    "AnUnrecoverableRunIsRecoveredForEver": (
        "src/runtime/executor.rs",
        "a_recovery_that_cannot_succeed_is_quarantined_not_retried",
        "a recovery refused by the journal itself keeps its lease and lapses "
        "owned, so the sweep retries it — and writes a note — every lease "
        "period for ever, and nobody is asked to decide it",
        """            Err(error) if recurs_on_every_resume(&error) => {""",
        """            Err(error) if false && recurs_on_every_resume(&error) => {""",
    ),
    "ALostRecoveryRaceIsAFailure": (
        "src/runtime/sweeper.rs",
        "a_recovery_that_loses_the_race_is_not_a_failure",
        "a takeover lost to a live instance matches no arm but the failure one, "
        "so the mechanism working pages an operator as a recovery failure",
        "                Err(RuntimeError::LeaseHeld { .. } | RuntimeError::Fenced { .. }) => {}",
        "                Err(RuntimeError::Store(StoreError::LeaseHeld { .. })) => {}",
    ),
    "AFencedDeliveryReportsAFailure": (
        "src/runtime/executor.rs",
        "a_wake_whose_resume_was_fenced_still_happened",
        "a delivery whose event is recorded reports failure when another "
        "instance claims the run mid-resume, so the sender retries into a "
        "duplicate of a message that was delivered",
        "            Ok(_) | Err(RuntimeError::Fenced { .. }) => {}",
        "            Ok(_) | Err(RuntimeError::LeaseHeld { .. }) => {}",
    ),
    "AFencedWakeReportsAFailure": (
        "src/runtime/sweeper.rs",
        "a_wake_whose_resume_was_fenced_still_happened",
        "a timer whose wake is recorded counts as failed when another instance "
        "claims the run mid-resume, though the wake happened",
        "            Ok(_) | Err(RuntimeError::Fenced { .. }) => Ok(()),",
        "            Ok(_) | Err(RuntimeError::LeaseHeld { .. }) => Ok(()),",
    ),
    "AReleasedLeaseReadsAsAbandoned": (
        "src/store/redb.rs",
        "an_expired_unreleased_lease_marks_a_run_abandoned",
        "the abandonment scan stops distinguishing a released lease from a "
        "lapsed one, so every run that ever exited cleanly is 'recovered' on "
        "every tick — an epoch bump and a replay per run per tick, forever, "
        "reported as healing",
        "                if owner.is_empty() || expires_at > now {",
        "                if expires_at > now {",
    ),
    "SweepEvidenceLeavesWithTheError": (
        "src/runtime/sweeper.rs",
        "sweep_evidence_survives_a_later_phase_failure",
        "the ledger is sealed only after every phase succeeds, so a later "
        "phase's error drops the account of decisions the earlier phases "
        "already applied to state — the exact failure the ledger exists to "
        "prevent, reintroduced by control flow",
        "        match ledger.seal(self.store()).await {\n            SweepRecord::Quiet => {}\n            SweepRecord::Recorded(run) => report.record = Some(run),\n            SweepRecord::EvidenceLost => report.evidence_lost = true,\n        }\n        phases?;",
        "        phases?;\n        match ledger.seal(self.store()).await {\n            SweepRecord::Quiet => {}\n            SweepRecord::Recorded(run) => report.record = Some(run),\n            SweepRecord::EvidenceLost => report.evidence_lost = true,\n        }",
    ),
    "ARefiredWakeIsRecordedTwice": (
        "src/runtime/sweeper.rs",
        "a_refired_timer_does_not_duplicate_the_recorded_wake",
        "a timer re-fired after a crash between append and disarm writes its "
        "wake into the journal a second time — and the journal is the one "
        "place a retry must never show up twice",
        "        if !already_recorded && !closed {",
        "        if !closed {",
    ),
    "ACutCaseLayerReadsAsComplete": (
        "src/export.rs",
        "a_dropped_case_layer_is_a_finding_not_a_quiet_file",
        "the verifier stops comparing the trailer's case count against the "
        "blocks it read, so an export stripped of its whole case layer reads "
        "as a complete, sound file from a plane that simply had no cases — "
        "while its own trailer says otherwise",
        "    if let Some(declared) = value.get(\"cases\").and_then(serde_json::Value::as_u64)\n        && declared != report.cases as u64",
        "    if let Some(declared) = value.get(\"cases\").and_then(serde_json::Value::as_u64)\n        && false && declared != report.cases as u64",
    ),
    "AnImportForgetsCorrelation": (
        "src/store/redb_cases.rs",
        "redb_satisfies_the_case_layer_contracts",
        "import_case rebuilds every index except the open-correlation half, so "
        "a restored matter is invisible to correlation and the next inbound "
        "message about it opens a duplicate case — the index-drift failure the "
        "read-path battery exists to catch",
        "                    if case.status != CaseStatus::Closed {\n                        let prior = corr_open",
        "                    if false && case.status != CaseStatus::Closed {\n                        let prior = corr_open",
    ),
    "CaseEnumerationServesAPageTwice": (
        "src/store/redb_cases.rs",
        "redb_satisfies_the_case_layer_contracts",
        "the enumeration cursor stops excluding the id the caller already saw, "
        "so consecutive pages overlap and an export carries a matter twice — "
        "which the verifier then reads as a duplicate",
        "                    if Some(id) == cursor.as_deref() {\n                        continue;\n                    }",
        "",
    ),
    "ErasureReadsAsIntact": (
        "src/drill.rs",
        "the_drill_tells_erasure_from_loss",
        "the drill counts a tombstoned blob as present, so the erased and the "
        "intact collapse into one number and an erasure can no longer be shown "
        "to have happened — the three-way distinction is the pass's entire value",
        "            Err(BlobError::Expired { .. }) => report.blobs_erased += 1,",
        "            Err(BlobError::Expired { .. }) => report.blobs_present += 1,",
    ),
    "ALostBlobIsSilent": (
        "src/drill.rs",
        "the_drill_tells_erasure_from_loss",
        "bytes gone with no tombstone produce no finding, so unexplained loss "
        "passes the drill silently — the exact state the tombstone vocabulary "
        "exists to make loud, muted by the checker written for it",
        "            Err(BlobError::NotFound(_)) => report.findings.push(format!(",
        "            Err(BlobError::NotFound(_)) => drop(format!(",
    ),
    "RetirementReadsAsErasure": (
        "src/drill.rs",
        "a_retired_key_version_is_not_reported_as_loss_or_as_erasure",
        "a key version retired by an operator's version floor is counted as a "
        "completed erasure, so the drill reports an obligation discharged that "
        "nobody requested and writes off data that is intact and one setting "
        "away from readable",
        """        Some(Err(e @ KeyError::Retired { .. })) => report.findings.push(format!(""",
        """        Some(Err(KeyError::Retired { .. })) => report.sealed_erased += 1,
        #[allow(unreachable_patterns)]
        Some(Err(e @ KeyError::Refused(_))) => report.findings.push(format!(""",
    ),
    "RetiredCollapsesIntoRefused": (
        "src/keyring/vault.rs",
        "a_retired_ciphertext_version_is_told_apart_from_a_refusal",
        "a Vault refusal naming a retired ciphertext version is left as a bare "
        "Refused, so a reversible version floor reaches a drill as loss or "
        "tampering and an operator hunts a fault that does not exist",
        """    if retired {
        KeyError::Retired {
            scope: scope.to_owned(),
            key_id: key_id.to_owned(),
        }
    } else {
        e
    }""",
        """    let _ = (retired, scope, key_id);
    e""",
    ),
    "AnEnvelopeCarriesNoFormatVersion": (
        "src/keyring/envelope.rs",
        "an_envelope_leads_with_the_format_version_it_claims",
        "sealed envelopes are written without a leading format version, so a "
        "build meeting a construction it does not know walks its own layout "
        "over somebody else's and reaches the AEAD — reporting a version skew "
        "as a payload that did not authenticate, which is the signature of "
        "tampering",
        "    envelope.push(FORMAT_VERSION);\n",
        "",
    ),
    "AnUnknownEnvelopeVersionReadsAsTampering": (
        "src/keyring/envelope.rs",
        "a_version_this_build_does_not_read_is_not_reported_as_tampering",
        "an envelope naming a format version this build does not read is left "
        "to fail at the cipher, so a mixed-version fleet, a rollback or a "
        "restore from a newer plane pages somebody to hunt corruption that "
        "does not exist",
        """    if version != FORMAT_VERSION {
        return Err(KeyError::UnknownFormat {
            version,
            supported: FORMAT_VERSION,
        });
    }""",
        "    let _ = version;",
    ),
    "AnUnreadableSealedStateIsSkipped": (
        "src/keyring/cases.rs",
        "sealed_state_this_build_cannot_read_is_answered_not_skipped",
        "state marked sealed whose envelope will not parse answers 'nothing to "
        "check', so the drill counts the case as carrying no sealed state and "
        "reports that everything opens over state it never opened — detection "
        "withheld by the pass whose only job is detection",
        """    let scope = match super::envelope::wrapped_scope(&envelope) {
        Ok(scope) => scope,
        Err(e) => return Some(Err(e)),
    };""",
        "    let scope = super::envelope::wrapped_scope(&envelope).ok()?;",
    ),
    "AForeignEnvelopeIsNotThisCasesProblem": (
        "src/keyring/cases.rs",
        "sealed_state_this_build_cannot_read_is_answered_not_skipped",
        "a case whose sealed state names another case's erasure scope is "
        "silently skipped, so an envelope this case's erasure would not reach "
        "is never reported — the bytes survive the deletion request and the "
        "drill says the case is clean",
        """    let Some(tenant) = scope.strip_suffix(&format!("/{case}")) else {
        return Some(Err(super::KeyError::Refused(format!(
            "this case's sealed state names erasure scope '{scope}', which is not this \\
             case — the envelope was written for a different matter, so erasing this \\
             case would leave it readable"
        ))));
    };""",
        """    let tenant = scope.strip_suffix(&format!("/{case}"))?;""",
    ),
    "AnUnreadableVersionPagesForTampering": (
        "src/drill.rs",
        "a_version_this_build_cannot_read_is_not_reported_as_loss_or_tampering",
        "a format version this build cannot read is folded into the loss arm, "
        "so a build skew whose remedy is which binary is running reaches an "
        "operator as suspected loss or tampering",
        """        Some(Err(e @ KeyError::UnknownFormat { .. })) => report.findings.push(format!(
            "case {case}: {e}. Run the plane on a build that reads this version, or restore \\
             this case from an export written by one — nothing here needs a key operation"
        )),""",
        "",
    ),
    "APeerEndpointIsConnectedToUnchecked": (
        "src/peers/a2a.rs",
        "a_peer_endpoint_that_resolves_inward_is_refused_before_the_request",
        "a peer endpoint is connected to without checking where it resolves, so "
        "a discovered card that advertises an internal address gets this run's "
        "payload and a bearer credential posted to it",
        """        crate::netguard::judge(self.reach(), host, resolved).map_err(|error| {
            PeerError::Refused {
                peer: peer.clone(),
                detail: error.to_string(),
            }
        })?;""",
        """        let _ = resolved;""",
    ),
    "CardDiscoveryReachesInward": (
        "src/peers/discovery.rs",
        "card_discovery_refuses_an_inward_address_a_redirect_and_a_hang",
        "a card URL is fetched without checking where it resolves, so the first "
        "attacker-influenced string a deployment handles reaches the cloud "
        "metadata service, a database or an internal health endpoint",
        """        crate::netguard::judge(self.reach(), &host, resolved).map_err(|e| match e {
            crate::netguard::NetGuardError::NoAddresses { .. } => {
                DiscoveryError::Unreachable(e.to_string())
            }
            crate::netguard::NetGuardError::Forbidden { .. } => {
                DiscoveryError::Refused(e.to_string())
            }
        })?;""",
        """        let _ = resolved;""",
    ),
    "AGuardedClientFollowsARedirect": (
        "src/netguard/resolver.rs",
        "card_discovery_refuses_an_inward_address_a_redirect_and_a_hang",
        "every guarded client follows redirects, so the address and host checks "
        "apply only to the first hop and an allowed server forwards this plane "
        "wherever it likes — every outbound door at once, because they share one "
        "constructor: card discovery, webhook delivery, peer calls, four model "
        "drivers, both embedders, the key ring and the witness client",
        "        .redirect(reqwest::redirect::Policy::none())",
        "        .redirect(reqwest::redirect::Policy::limited(10))",
    ),
    "AModelDriverBuildsItsOwnClient": (
        "src/model/anthropic.rs",
        "a_provider_that_redirects_does_not_move_this_plane",
        "a model driver builds its own `reqwest` client rather than the guarded "
        "one, so it follows up to ten redirects and honours an ambient proxy — "
        "and since `reqwest` strips only `Authorization`, `Cookie` and "
        "`Proxy-Authorization` across origins, the `x-api-key` header and the "
        "prompt body arrive at whatever host the endpoint's `Location` names",
        "        let http = crate::netguard::guarded_client(crate::netguard::Reach::Configured)",
        "        let http = reqwest::Client::builder()",
    ),
    "ARefusedRedirectIsAProviderOutage": (
        "src/model/wire.rs",
        "a_provider_that_redirects_does_not_move_this_plane",
        "a 3xx is classified as the provider being unavailable rather than as "
        "this plane declining to follow it, so the retry ladder spends every "
        "attempt on an answer that cannot change and the operator is sent to a "
        "vendor status page instead of to their own gateway configuration",
        "        300..=399 => ModelError::Egress {",
        "        300..=399 => ModelError::Unavailable {",
    ),
    "ACardFetchIsUnbounded": (
        "src/peers/discovery.rs",
        "card_discovery_refuses_an_inward_address_a_redirect_and_a_hang",
        "a card fetch has no whole-request timeout, so an unknown host that "
        "accepts the connection and never answers holds a task open for as "
        "long as it likes",
        "            .timeout(self.timeout)",
        "",
    ),
    "ATruncatedTurnIsRunAsAnInstruction": (
        "src/runtime/declarative.rs",
        "a_truncated_turn_asking_for_tools_never_runs_them",
        "a turn the provider cut off mid-output is executed anyway, so the last "
        "tool call's arguments are whatever survived the cut — a side effect "
        "performed on a request the model never finished writing",
        """            if completion.peek().truncated {""",
        """            if false && completion.peek().truncated {""",
    ),
    "ATruncatedAnswerSettlesAsTheAnswer": (
        "src/runtime/declarative.rs",
        "a_truncated_answer_is_not_settled_as_the_runs_output",
        "a cut-off answer is settled as the run's output with nothing marking "
        "it partial, which is the silent truncation this crate refuses "
        "everywhere else",
        """                let reason = if completion.peek().tool_calls.is_empty() {""",
        """                let reason = if !completion.peek().tool_calls.is_empty() {""",
    ),
    "ASeveredGeminiStreamBillsNothing": (
        "src/model/gemini.rs",
        "gemini_a_severed_stream_reports_what_it_burned",
        "a severed Gemini stream drops the usage the provider already reported "
        "and bills zero, so the token ceiling that exists to bound a runaway "
        "provider counts nothing during exactly the failure it was bought for",
        """    if let Some(envelope) = acc.usage_envelope() {
        return ModelError::Interrupted {
            model: model.clone(),
            usage: Gemini::usage(&envelope),
            detail: detail.to_owned(),
        };
    }""",
        "",
    ),
    "TheMcpClientReportsWhatItOffered": (
        "src/tools/mcp.rs",
        "the_client_reports_the_version_the_handshake_settled_on",
        "the MCP client reports the protocol version it offered rather than the "
        "one the handshake settled on, so a server that negotiated the "
        "connection down — losing the tasks extension, and with it every "
        "governed suspension a long-running tool would have produced — looks "
        "identical to one that did not",
        """        self.service
            .peer_info()
            .map(|info| info.protocol_version.as_str().to_owned())""",
        """        let _ = &self.service;
        Some(rmcp::model::ProtocolVersion::V_2026_07_28.as_str().to_owned())""",
    ),
    "TheStreamKeepsItsOwnTaskStateMapping": (
        "src/api/a2a.rs",
        "every_read_back_surface_reports_the_same_state",
        "the event stream derives an A2A task state from its own copy of the "
        "history mapping rather than the shared one, so a client that polled "
        "and a client that subscribed can be told different states for one run "
        "with no way to discover the disagreement",
        "    let Some((state, detail)) = state_from_history(&records) else {",
        """    let Some((state, detail)) = records.last().map(|last| match last.kind() {
        RecordKind::RunConcluded { outcome, .. } => (sealed_state(outcome), outcome.clone()),
        _ => (TaskState::Working, "running".to_owned()),
    }) else {""",
    ),
    "TheAuthSchemeIsMatchedCaseSensitively": (
        "src/api/tokens.rs",
        "the_scheme_is_case_insensitive_and_the_token_is_not",
        "the bearer auth-scheme is compared case-sensitively against RFC 9110 "
        "§11.1, so a conforming client sending `bearer <token>` is told it "
        "presented no credential at all and retries the thing it already did",
        """        if !scheme.eq_ignore_ascii_case("Bearer") {""",
        """        if scheme != "Bearer" {""",
    ),
    "AShortTokenIsAccepted": (
        "src/api/tokens.rs",
        "a_short_or_published_token_is_refused_at_load",
        "a token file may carry a credential short enough to guess at the rate "
        "the server answers, and `serve` starts on it",
        "            if entry.token.len() < MIN_TOKEN_BYTES {",
        "            if entry.token.len() < 1 {",
    ),
    "APublishedTokenIsAccepted": (
        "src/api/tokens.rs",
        "a_short_or_published_token_is_refused_at_load",
        "`serve` starts on the example file's placeholders, so a plane accepts "
        "a credential every reader of the repository holds",
        "            if PUBLISHED_TOKENS.contains(&entry.token.as_str()) {",
        "            if false {",
    ),
    "ADamagedPhaseColumnDecodesAsForward": (
        "src/store/postgres_cases.rs",
        "an_unreadable_column_is_refused_rather_than_defaulted",
        "a step phase this store cannot read decodes to `Forward` instead of "
        "refusing, so a compensating record comes back wearing the forward "
        "half of the saga and the unwind logic acts on a value the store "
        "invented for a row nobody could read",
        """    decoded("step phase", s, crate::core::Phase::parse(s))""",
        """    Ok(crate::core::Phase::parse(s).unwrap_or_default())""",
    ),
    "AFailedEffectIsAlwaysFree": (
        "src/core/error.rs",
        "a_metered_failure_carries_its_spend_into_the_effect_layer",
        "a failed effect's spend falls back to zero for every variant that is "
        "not the metered one, so a variant added later that burned tokens "
        "before dying costs the run nothing and the ceilings that exist to "
        "bound a flaky provider stop counting",
        "            Self::Metered { spend, .. } => *spend,",
        "            Self::Metered { .. } => Spend::default(),",
    ),
    "TamperedBytesPassTheDrill": (
        "src/drill.rs",
        "altered_bytes_are_a_finding_not_a_presence",
        "altered bytes are reported as presence, so the one state somebody must "
        "be paged about is the one the drill waves through",
        "            Err(e @ BlobError::Corrupt { .. }) => report.findings.push(format!(",
        "            Err(e @ BlobError::Corrupt { .. }) => drop(format!(",
    ),
    # ── At-most-once admission ──────────────────────────────────────────────
    "AdmissionKeyNotClaimed": (
        "src/store/redb.rs",
        "redb_satisfies_the_journal_store_contract",
        "the store accepts a second run under an admission key it already issued",
        """                        if let Some(held) = admissions
                            .get((tenant.as_str(), k.as_str()))
                            .map_err(|e| be(&e))?
                            .map(|v| v.value().0.to_owned())
                        {
                            return Err(StoreError::DuplicateAdmission { key: k, run: held });
                        }""",
        """                        let _ = &admissions;""",
    ),
    "DuplicateAdmissionStartsASecondRun": (
        "src/runtime/executor.rs",
        "a_duplicate_the_read_missed_is_still_answered_with_the_original",
        "a duplicate admission is reported as fresh, so a redelivery runs the work again",
        """                run, ..
            })) => self.answer_with(parse_holder(&run)?).await,""",
        """                run, ..
            })) => Ok(Admission::InFlight(parse_holder(&run)?)),""",
    ),
    "SuspendedRunIsNotAnAnswer": (
        "src/runtime/executor.rs",
        "a_run_waiting_for_a_human_answers_its_own_redelivery",
        "a suspension stops counting as a resting point, so a redelivery of a run "
        "parked on a four-eyes decision opens a second approval",
        """        RecordKind::RunSuspended { reason } => RunStatus::Suspended(reason.clone()),""",
        """        RecordKind::RunSuspended { .. } => return None,""",
    ),
    "EmptyAdmissionKeyAccepted": (
        "src/runtime/executor.rs",
        "an_empty_admission_key_is_refused",
        "an empty admission key is accepted, so every message after the first is "
        "answered with the first one's run",
        """    if key.trim().is_empty() {""",
        """    if false {""",
    ),
    "ConclusionReasonNotSealed": (
        "src/journal/payload.rs",
        "a_conclusions_reason_is_sealed_and_its_outcome_stays_readable",
        "a run's conclusion reason reaches the store in the clear",
        """        } => reason.as_mut().map(SealedField::Text).into_iter().collect(),""",
        """        } => {
            let _ = reason;
            Vec::new()
        }""",
    ),
    "ACompensationsOutcomeIsNotSealed": (
        "src/journal/payload.rs",
        "a_compensations_outcome_is_sealed_and_erased_with_the_case",
        "a compensation's outcome — its error text, quoting the charge it was "
        "asked to reverse — reaches the store in the clear and survives the "
        "erasure of its case",
        """        } => vec![SealedField::Text(outcome)],""",
        """        } => {
            let _ = outcome;
            Vec::new()
        }""",
    ),
    "RetiringAKeyDoesNotFreeIt": (
        "src/store/redb.rs",
        "redb_satisfies_the_journal_store_contract",
        "retirement reports a count without releasing the keys it counted",
        """                for key in &stale {
                    admissions
                        .remove((tenant.as_str(), key.as_str()))
                        .map_err(|e| be(&e))?;
                }""",
        """                let _ = &mut admissions;""",
    ),
    # ── The stored vocabulary ──────────────────────────────────────────────
    "ANonTerminalOutcomeCloses": (
        "src/store/redb_batches.rs",
        "redb_satisfies_the_case_layer_contracts",
        "an item with any recorded outcome is treated as settled, so the resume "
        "cursor steps over a suspended one and the batch reports complete with "
        "work still waiting on an event, a person or a raised ceiling",
        """    has_outcome != 1 || ItemOutcome::parse(outcome, String::new()).is_none_or(|o| !o.is_terminal())""",
        """    has_outcome != 1""",
    ),
    "PostgresCursorStepsOverAnUnsettledItem": (
        "src/store/postgres_cases.rs",
        "postgres_satisfies_the_case_layer_contracts",
        "the shared store's resume cursor counts every outcome as terminal, so "
        "a suspended item is stepped over and the batch resumes past work that "
        "never settled — the failure a hand-listed terminal set produces",
        """                    &ItemOutcome::terminal_tags(),""",
        """                    &ItemOutcome::all(String::new())
                        .iter()
                        .map(ItemOutcome::as_str)
                        .collect::<Vec<_>>(),""",
    ),
    "APriorityRankHasATie": (
        "src/core/task.rs",
        "the_queue_serves_priority_before_age",
        "two priorities share a rank, so the worklist index cannot order them "
        "and an urgent decision sorts among the routine ones — the failure a "
        "table with a fallback arm produces the day a priority is added",
        """            Self::Urgent => 0,
            Self::High => 1,""",
        """            Self::Urgent => 1,
            Self::High => 1,""",
    ),
    "AQueuedTaskIsAnyPendingOne": (
        "src/core/task.rs",
        "redb_satisfies_the_case_layer_contracts",
        "a claimed task is offered to the queue again, so two reviewers are "
        "shown one decision and the second finds it already held",
        """    pub const fn is_queued(self) -> bool {
        match self {
            Self::Open | Self::Escalated => true,
            Self::Claimed | Self::Completed | Self::Expired | Self::Withdrawn => false,
        }
    }""",
        """    pub const fn is_queued(self) -> bool {
        self.is_pending()
    }""",
    ),
    "AnUnreadableObligationLeavesTheIndex": (
        "src/store/redb_cases.rs",
        "an_unreadable_obligation_is_still_outstanding",
        "an obligation whose state will not parse is treated as settled, so a "
        "damaged row drops out of the sweep and out of what `close` counts — "
        "and a matter is audited as closed with a duty nobody can see",
        """    DeadlineState::parse(state).is_none_or(DeadlineState::is_open)""",
        """    DeadlineState::parse(state).is_some_and(DeadlineState::is_open)""",
    ),
    "AStoredStatusIsMatchedByHand": (
        "src/core/case.rs",
        "every_stored_spelling_round_trips_and_nothing_else_parses",
        "the reader is a hand-written match beside the writer rather than the "
        "writer read backwards, so a variant added later is a spelling the "
        "crate emits and refuses — the second implementation `parse` exists to "
        "make impossible",
        """    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|c| c.as_str() == s)
    }

    /// Every status, so a caller can enumerate them without matching.""",
        """    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "open" => Some(Self::Open),
            "awaiting_external" => Some(Self::AwaitingExternal),
            "awaiting_human" => Some(Self::AwaitingHuman),
            "closed" => Some(Self::Closed),
            _ => None,
        }
    }

    /// Every status, so a caller can enumerate them without matching.""",
    ),
    # ── The oversight surface ───────────────────────────────────────────────
    "AnEscalatedTaskNeverLeavesTheOverdueScan": (
        "src/core/task.rs",
        "redb_satisfies_the_case_layer_contracts",
        "the overdue scan keeps returning escalated tasks, whose expiry policy "
        "has already fired; they accumulate at the head of the bounded "
        "oldest-first batch until it holds nothing else, and the deny/proceed "
        "policies of every task behind them silently stop firing",
        """    pub const fn awaits_expiry(self) -> bool {
        match self {
            Self::Open | Self::Claimed => true,
            Self::Completed | Self::Expired | Self::Escalated | Self::Withdrawn => false,
        }
    }""",
        """    pub const fn awaits_expiry(self) -> bool {
        self.is_pending()
    }""",
    ),
    "PostgresKeepsEscalatedTasksOverdue": (
        "src/store/postgres_cases.rs",
        "postgres_satisfies_the_case_layer_contracts",
        "the shared-store overdue scan keeps returning escalated tasks — the "
        "same starvation as the embedded store's, on the backend the redb "
        "mutation cannot reach",
        """                    &task_states(TaskState::awaits_expiry),""",
        """                    &task_states(TaskState::is_pending),""",
    ),
    "EscalationKeepsTheStaleReservation": (
        "src/core/task.rs",
        "redb_satisfies_the_case_layer_contracts",
        "escalation leaves the task assigned to whoever sat on it, so the "
        "widened audience is shown a row only the absent holder can claim",
        """        self.state = TaskState::Escalated;
        self.assignee = None;""",
        """        self.state = TaskState::Escalated;""",
    ),
    "EscalationWidensNobody": (
        "src/core/task.rs",
        "an_escalating_task_is_escalated_once",
        "escalation flips the state flag and adds nobody, so the widening the "
        "manifest promised is back to being a word",
        """        if !self.candidate_roles.is_empty() {
            for role in &self.escalate_to {
                if !self.candidate_roles.contains(role) {
                    self.candidate_roles.push(role.clone());
                }
            }
        }""",
        """        let _ = &self.escalate_to;""",
    ),
    "AnEscalationNamingNobodyIsAccepted": (
        "src/runtime/ctx.rs",
        "an_escalation_naming_nobody_is_refused",
        "the coded tier accepts Expiry::Escalate with no escalation audience, "
        "so the window closes on a promise the sweep cannot keep",
        """        if to.is_empty() {""",
        """        if false && to.is_empty() {""",
    ),
    "ManifestEscalationNeedsNoAudience": (
        "src/manifest/mod.rs",
        "escalation_must_name_its_audience",
        "the manifest accepts 'escalate' with no escalate_to, so a reviewer "
        "signs an oversight declaration whose one enforceable meaning is absent",
        """            if o.escalate_to.is_empty() {""",
        """            if false {""",
    ),
    # ── Batch honesty ───────────────────────────────────────────────────────
    "ABatchReopensUnderAnEditedPlan": (
        "src/store/redb_batches.rs",
        "a_batch_resumed_under_an_edited_plan_is_refused",
        "a batch reopened under a different plan digest is accepted, so items "
        "from the resume onward settle under a plan the batch's record does "
        "not name — several acts wearing one audit identity",
        """                    // One batch runs one frozen plan; a resume offering an
                    // edited one is a second act wearing this batch's name.
                    Some(stored) => {
                        return Err(StoreError::BatchPlanChanged {
                            batch: key.clone(),
                            stored,
                            offered: digest.clone(),
                        });
                    }""",
        """                    Some(_) => {}""",
    ),
    "PostgresBatchReopensUnderAnEditedPlan": (
        "src/store/postgres_cases.rs",
        "postgres_satisfies_the_case_layer_contracts",
        "the shared-store backend accepts a batch reopened under a different "
        "plan digest — the same plan swap, on the backend the redb mutation "
        "cannot reach",
        """        if stored != plan_digest {
            return Err(StoreError::BatchPlanChanged {""",
        """        if false {
            return Err(StoreError::BatchPlanChanged {""",
    ),
    "AMarkOnAMissingBatchReportsRecorded": (
        "src/store/redb_batches.rs",
        "redb_satisfies_the_case_layer_contracts",
        "marking an unknown batch exhausted reports success while writing "
        "nothing — the one bit that lets a census read as finished, lost with "
        "no symptom",
        """                let Some(digest) = digest else {
                    return Err(StoreError::NotFound(key.clone()));
                };""",
        """                let Some(digest) = digest else {
                    return Ok(());
                };""",
    ),
    "ADamagedItemOutcomeReadsAsNeverRan": (
        "src/store/redb_batches.rs",
        "an_unreadable_item_outcome_is_refused_rather_than_defaulted",
        "an outcome string the store cannot read decodes as 'no outcome yet', "
        "so a damaged row reads as an item that never ran and the census "
        "carries it as in-flight forever",
        """    decoded("item outcome", s, ItemOutcome::parse(s, detail.to_owned())).map(Some)""",
        """    Ok(ItemOutcome::parse(s, detail.to_owned()))""",
    ),
    "ADamagedTimerPhaseDecodesAsForward": (
        "src/store/redb_timers.rs",
        "an_unreadable_timer_phase_is_refused_rather_than_defaulted",
        "a timer phase the store cannot read decodes to Forward, handing the "
        "unwind logic a compensating record wearing the wrong half of the "
        "saga — the refusal the shared-store backend already makes, absent "
        "from the embedded one",
        """    decoded("step phase", s, Phase::parse(s))""",
        """    Ok(Phase::parse(s).unwrap_or_default())""",
    ),
    "AnUnknownBatchReportsAsRunning": (
        "src/runtime/batch.rs",
        "a_report_on_an_unknown_batch_is_not_an_empty_batch",
        "a report on a batch that does not exist answers an empty Running "
        "batch, so a mistyped id reads as healthy work that never starts",
        """        if store
            .plan_digest(id)
            .await
            .map_err(RuntimeError::from_store)?
            .is_none()
        {""",
        """        if store
            .plan_digest(id)
            .await
            .map_err(RuntimeError::from_store)?
            .is_none()
            && false
        {""",
    ),
    # ── The interop seams (0.21.0 audit round) ─────────────────────────────
    "ASchemaFailsEveryToolTurn": (
        "src/model/wire.rs",
        "a_schema_and_a_tool_calling_turn_coexist_on_every_driver",
        "the schema exemption for tool-asking turns is gone, so every "
        "schema-bearing tool-calling agent fails on its first tool turn with "
        "'the answer is not JSON' — and the error path carries no "
        "continuation, so the signed reasoning blocks are dropped from the "
        "retry, which the provider then rejects",
        """    if !tool_calls.is_empty() {
        return Ok(None);
    }""",
        "",
    ),
    "GeminiForgetsPriorRounds": (
        "src/model/gemini.rs",
        "gemini_two_tool_turns_accumulate_the_transcript_exactly_once",
        "the accumulated continuation starts empty each turn instead of from "
        "the prior state, so round three's request carries only round two — "
        "round one's signed turn is gone and the model re-asks for the same "
        "tools with amnesia, silently",
        """        let mut state = prior
            .and_then(|value| value.state.as_array())
            .cloned()
            .unwrap_or_default();
        if !exchanges.is_empty() {
            state.push(Self::tool_responses(exchanges));
        }""",
        """        let mut state = Vec::new();
        let _ = prior;
        if !exchanges.is_empty() {
            state.push(Self::tool_responses(exchanges));
        }""",
    ),
    "AnUnstoredResponseLosesItsReasoning": (
        "src/model/openai.rs",
        "provider_retention_is_private_by_default_and_replay_visible_when_enabled",
        "an unstored request no longer asks for the encrypted reasoning "
        "payload, so reasoning items come back as bare ids the provider will "
        "not resolve next turn — the stateless multi-turn pattern fails "
        "against the live API while every local round trip passes",
        """            body["include"] = json!(["reasoning.encrypted_content"]);""",
        "",
    ),
    "BedrockCacheTokensAreFree": (
        "src/model/bedrock.rs",
        "cache_tokens_are_folded_into_the_input_count",
        "the cache counters are recorded but no longer folded into "
        "`input_tokens`, so the count under-reports by the whole cached "
        "prefix and the token ceiling reads a fraction of the real spend — a "
        "bill nobody can reconcile rather than a failure",
        """        let usage = output.usage().map_or_else(Usage::default, |usage| {
            Usage::with_cache_beside_input(
                u64::try_from(usage.input_tokens()).unwrap_or_default(),""",
        """        let usage = output.usage().map_or_else(Usage::default, |usage| {
            Usage::with_cache_beside_input(
                u64::try_from(usage.input_tokens()).unwrap_or_default() * 0,""",
    ),
    "AGuardrailInterventionIsAnAnswer": (
        "src/model/bedrock.rs",
        "a_buffered_guardrail_intervention_is_a_refusal_not_an_answer",
        "the buffered path's stop-reason allowlist admits a guardrail "
        "intervention as an answer, so the canned refusal message comes back "
        "as a successful completion — on exactly the path a "
        "streaming-by-default deployment never exercises",
        """            StopReason::EndTurn | StopReason::ToolUse | StopReason::StopSequence => false,""",
        """            StopReason::EndTurn
            | StopReason::ToolUse
            | StopReason::StopSequence
            | StopReason::GuardrailIntervened => false,""",
    ),
    "TheAsyncPathDeclassifies": (
        "src/tools/mcp.rs",
        "an_async_tool_returns_a_task_that_can_be_polled_as_an_effect",
        "the task poll's snapshot ignores the ceiling it was constructed "
        "with and arrives at the trait default, so the asynchronous path "
        "quietly declassifies the same payload the synchronous tool call "
        "protects",
        """        self.output_sensitivity
    }""",
        """        let _ = self.output_sensitivity;
        Sensitivity::Public
    }""",
    ),
    "APushTokenNeverRides": (
        "src/push/mod.rs",
        "the_push_token_rides_the_delivery_as_its_own_header",
        "the A2A per-task token is stored, sealed, redacted — and never "
        "attached to a delivery, so a receiver that validates it rejects "
        "every push while this plane retries thirty-two times and parks",
        """            request = request.header(HEADER_A2A_TOKEN, value);""",
        """            let _ = value;""",
    ),
    "AControlCharacterForgesAPair": (
        "src/core/cloudevent.rs",
        "a_control_character_cannot_forge_another_producers_pair",
        "control characters pass into `source` and `id`, so a producer can "
        "embed the U+001F joiner and spell another producer's `(source, id)` "
        "pair — the victim's real event later reads as a duplicate and is "
        "silently swallowed",
        """                return Err(CloudEventError::ControlCharacter(name));""",
        """                let _ = name;""",
    ),
    "AMessageIdIsSharedBetweenPeers": (
        "src/api/a2a.rs",
        "two_peers_sharing_a_message_id_are_two_runs",
        "the admission key drops its producer, so one peer replaying "
        "another's messageId is treated as that peer's retry — it is handed "
        "the victim's task id and a seat inside the victim's case",
        "    let keyed = crate::core::origin_key(&admission_source(&caller.actor), &message.message_id);",
        "    let keyed = message.message_id.clone();",
    ),
    "HistoryDefaultsToNothing": (
        "src/api/a2a.rs",
        "history_rides_by_default_and_zero_suppresses_it",
        "an unset historyLength reads as zero instead of the protocol's "
        "full-history default, so a conformant client expecting its "
        "conversation back gets nothing",
        """    let limit = history_length.unwrap_or(HISTORY_CAP);""",
        """    let limit = history_length.unwrap_or(0);""",
    ),
    "SseSplitsACodepoint": (
        "src/model/sse.rs",
        "a_codepoint_split_across_chunks_survives",
        "the front half of a codepoint is decoded lossily instead of held "
        "for the next chunk, so every multi-byte character TCP happens to "
        "split becomes two replacement chars — silently, because the JSON "
        "around it still parses",
        """                    } else {
                        // The front half of a codepoint. Kept for the next chunk.
                        start += valid;
                        break;
                    }""",
        """                    } else {
                        // The front half of a codepoint. Kept for the next chunk.
                        text.push('\\u{FFFD}');
                        start = self.pending.len();
                        break;
                    }""",
    ),
    "SseScanSkipsAHeldCarriageReturn": (
        "src/model/sse.rs",
        "a_crlf_split_across_chunks_is_still_one_terminator",
        "the next search starts past a trailing carriage return held for its "
        "line feed, so a CRLF split across chunks is read as a bare LF and the "
        "CR stays in the line",
        "        self.scanned = self.partial.len() - usize::from(self.partial.ends_with('\\r'));",
        "        self.scanned = self.partial.len();",
    ),
    "AClientNeverNamesItsSkill": (
        "src/peers/a2a.rs",
        "this_planes_client_names_its_skill_on_a_multi_skill_plane",
        "the client's capability never reaches `message.metadata.skill`, so a "
        "named-dispatch server — this crate's own among them — refuses every "
        "call to a multi-skill plane as ambiguous, while the single-skill "
        "fallback keeps every other test green",
        """                "metadata": {
                    "skill": capability,
                    EXT_CALLER_CONTEXT: Value::Object(governance),
                }""",
        """                "metadata": {
                    EXT_CALLER_CONTEXT: Value::Object(governance),
                }""",
    ),
    "ALegacyResourceNotFoundIsInDoubt": (
        "src/tools/mcp.rs",
        "a_legacy_resource_not_found_is_a_refusal_not_an_unknown_outcome",
        "an older server's -32002 falls to the in-doubt arm, so a read of a "
        "resource that does not exist is retried under policy forever "
        "instead of refused as the judgement it is",
        """                        | ErrorCode::PARSE_ERROR
                        | ErrorCode::RESOURCE_NOT_FOUND""",
        """                        | ErrorCode::PARSE_ERROR""",
    ),
    "AQuotaRefusalCarriesNoIdentity": (
        "src/api/a2a.rs",
        "a_full_quota_is_back_pressure_with_no_arithmetic_in_the_answer",
        "the quota refusal loses its ErrorInfo pair, leaving only a numeral "
        "in space A2A reserves — this crate's own client then classifies its "
        "own back-pressure as an unknown fault and escalates instead of "
        "coming back",
        """            code::QUOTA_EXHAUSTED => Some((SELF_DOMAIN, QUOTA_EXHAUSTED_REASON)),""",
        """            code::QUOTA_EXHAUSTED => None,""",
    ),
    "AForeignNumeralIsBelieved": (
        "src/peers/a2a.rs",
        "back_pressure_is_identified_by_its_error_info_not_its_numeral",
        "a bare -32029 from any server classifies as a clean refusal, so a "
        "foreign implementation-defined fault — possibly raised mid-execution "
        "— licenses resending a mutating call",
        """        -32029 if e.names_reason(super::ERROR_DOMAIN, super::QUOTA_EXHAUSTED_REASON) => {""",
        """        -32029 => {""",
    ),
    "ADisownedTurnIsAnAnswer": (
        "src/model/bedrock.rs",
        "a_malformed_tool_use_stop_is_unusable_not_an_answer",
        "a `malformed_tool_use` stop passes through as a completion, handing "
        "the caller's tool loop a fragment the provider itself disowned",
        """            StopReason::EndTurn | StopReason::ToolUse | StopReason::StopSequence => false,""",
        """            StopReason::EndTurn | StopReason::ToolUse | StopReason::StopSequence => false,
            StopReason::MalformedToolUse => false,""",
    ),
    "AFilteredConverseTurnIsAnAnswer": (
        "src/model/bedrock.rs",
        "a_filtered_or_unknown_stop_is_unusable_not_an_answer",
        "completeness is a denylist again: a `content_filtered` stop passes "
        "through as a whole answer carrying whatever text survived the filter",
        """            StopReason::EndTurn | StopReason::ToolUse | StopReason::StopSequence => false,""",
        """            StopReason::EndTurn | StopReason::ToolUse | StopReason::StopSequence => false,
            StopReason::ContentFiltered => false,""",
    ),
    "AGeminiOtherStopIsAnAnswer": (
        "src/model/gemini.rs",
        "gemini_every_finish_reason_but_stop_is_not_an_answer",
        "completeness is a denylist again: `OTHER`, a malformed tool call or a "
        "reason Google adds next passes through as a whole answer",
        """            Some("STOP") => false,""",
        """            Some(_) => false,""",
    ),
    "AFilteredChatCompletionIsAnAnswer": (
        "src/model/chat_completions.rs",
        "chat_completions_a_filtered_or_unknown_stop_is_not_an_answer",
        "a `content_filter` finish passes through as a whole answer carrying "
        "whatever text survived the filter",
        """            Some("stop" | "tool_calls" | "function_call") => false,""",
        """            Some("stop" | "tool_calls" | "function_call" | "content_filter") => false,""",
    ),
    "AFilteredResponseIsATruncation": (
        "src/model/openai.rs",
        "openai_a_filtered_or_unknown_status_is_not_an_answer",
        "a Responses answer cut by a content filter reads as a merely truncated "
        "one, and any unrecognised status as a complete one",
        """            ("incomplete", Some("max_output_tokens")) => true,""",
        """            ("incomplete", _) => true,
            (_, _) if true => false,""",
    ),
    "AnUnknownAnthropicStopIsAnAnswer": (
        "src/model/anthropic.rs",
        "anthropic_an_unknown_stop_reason_is_not_an_answer",
        "a stop reason the driver has never seen passes through as a whole answer",
        """        Some("end_turn" | "stop_sequence" | "tool_use") => false,""",
        """        Some(_) => false,""",
    ),
    "GeminiDiscardsBodyAdvice": (
        "src/model/gemini.rs",
        "gemini_retry_advice_in_the_body_reaches_the_driver",
        "the RetryInfo window inside Google's 429 body is dropped, so the "
        "default policy spends every attempt in milliseconds against a window "
        "measured in tens of seconds and reports the provider down",
        """            retry_after: retry_info_seconds(body),""",
        """            retry_after: {
                let _ = body;
                None
            },""",
    ),
    "APlaintextPeerIsSpoken": (
        "src/peers/a2a.rs",
        "a_plaintext_peer_endpoint_and_card_url_are_refused",
        "a plaintext peer endpoint is connected to, so the run's payload and "
        "a bearer credential cross the network in cleartext for every "
        "on-path observer",
        """        if parsed.scheme() != "https"
            && !(self.loopback_allowed()
                && crate::netguard::is_loopback_name(&host.to_ascii_lowercase()))
        {
            return Err(PeerError::Refused {""",
        """        if parsed.scheme() == "gopher"
            && !(self.loopback_allowed()
                && crate::netguard::is_loopback_name(&host.to_ascii_lowercase()))
        {
            return Err(PeerError::Refused {""",
    ),
    "APlaintextCardIsFetched": (
        "src/peers/discovery.rs",
        "a_plaintext_peer_endpoint_and_card_url_are_refused",
        "a plaintext card URL is fetched, so the interface URL that steers "
        "the credential-bearing call that follows is whatever the network "
        "says it is",
        """        if parsed.scheme() != "https"
            && !(self.loopback_allowed()
                && crate::netguard::is_loopback_name(&host.to_ascii_lowercase()))
        {
            return Err(DiscoveryError::Refused(format!(""",
        """        if parsed.scheme() == "gopher"
            && !(self.loopback_allowed()
                && crate::netguard::is_loopback_name(&host.to_ascii_lowercase()))
        {
            return Err(DiscoveryError::Refused(format!(""",
    ),
    "AnInThreadInstructionIsObeyed": (
        "src/model/mod.rs",
        "an_instruction_role_inside_the_turn_list_is_refused",
        "a system-role message inside the turn list reaches the provider, so "
        "an untrusted value shaped as a turn is obeyed as a directive without "
        "ever passing the trust check the one real instruction slot gets",
        """            Some("system") => Some("system"),""",
        """            Some("system") => None,""",
    ),
    "CommentaryJoinsTheAnswer": (
        "src/model/openai.rs",
        "commentary_phase_text_stays_out_of_the_answer",
        "commentary-phase narration is concatenated into Completion::text, "
        "polluting the answer and breaking the JSON parse of a schema-bearing "
        "final turn",
        """            .filter(|item| item.get("phase").and_then(Value::as_str) != Some("commentary"))""",
        """            .filter(|_| true)""",
    ),
    "ACancelIsSilentlyARead": (
        "src/peers/a2a.rs",
        "this_planes_client_cancels_a_task_on_this_planes_server",
        "the cancel body carries GetTask, so the acknowledgement validates, "
        "the effect reports success — and the peer keeps running work the "
        "caller believes it stopped",
        """            "method": "CancelTask",""",
        """            "method": "GetTask",""",
    ),
    "AMenuDoesNotCountAsAuthority": (
        "src/manifest/mod.rs",
        "a_sensitivity_only_protected_field_does_not_lift_the_mutating_gate",
        "the mutating-grant authority check ignores value menus, so the "
        "flagship declarative select-from-a-menu configuration is refused at "
        "parse and every menu-bound agent is pushed back into code",
        """                        && f.allowed_values().is_empty()""",
        """                        && true""",
    ),
    "AValueMenuApprovesEverything": (
        "src/runtime/ctx.rs",
        "a_value_outside_the_declared_set_is_refused_before_the_tool",
        "the declared value set is consulted and every value passes it, so a "
        "field that reads as menu-bound accepts whatever an injected prompt "
        "chose — the select-from-a-menu discipline reduced to decoration",
        """                    .is_some_and(|actual| field.allowed_values().contains(actual))""",
        """                    .is_some_and(|actual| {
                        let _ = actual;
                        true
                    })""",
    ),
    "ARefusalLosesItsGrounds": (
        "src/model/anthropic.rs",
        "a_refusals_stated_grounds_reach_the_error",
        "the provider's stop_details are dropped from a refusal, so a "
        "decline arrives as one bare sentence and the operator diffs prompts "
        "against a black box",
        """            for key in ["category", "explanation"] {""",
        """            for key in ["never-populated"] {""",
    ),
    # ── What the ledger counts ──────────────────────────────────────────────
    "AReadyWaveOutrunsTheStepCeiling": (
        "src/runtime/executor.rs",
        "a_ready_wave_cannot_outrun_the_step_ceiling",
        "step admission ignores what it has already handed out in this wave, so "
        "a whole ready set asks the same unmoved figure and every branch is "
        "admitted under a ceiling of two",
        """                Mode::Live | Mode::Resume => ledger
                    .lock()
                    .expect("budget mutex")
                    .admit_step(admitted.len()),""",
        """                Mode::Live | Mode::Resume => ledger
                    .lock()
                    .expect("budget mutex")
                    .admit_step(0),""",
    ),
    "AnAdmittedEffectTakesNoSlot": (
        "src/core/budget.rs",
        "the_last_effect_slot_is_taken_by_one_step_not_by_every_step_that_asks",
        "admission checks the effect ceiling without taking the slot, so the "
        "window between the verdict and the billing is one every concurrently "
        "dispatched step passes through on the same last slot",
        """        self.can_admit_effect(outbound)?;
        self.consumed.effects += 1;
        self.consumed.egress_bytes = self.consumed.egress_bytes.saturating_add(outbound);
        Ok(())""",
        """        self.can_admit_effect(outbound)""",
    ),
    "ARecordedFailureCostsTwoSlots": (
        "src/runtime/ctx.rs",
        "a_recorded_failure_costs_the_one_slot_it_cost_live",
        "a replayed failure is billed by the arm that reads it and again by the "
        "code deciding what the run did next, so a resume exhausts a ceiling "
        "its own history never reached, at a point no record contains",
        """        // Deliberately bills nothing. The recorded failure was billed by the""",
        """        self.bill_replayed(crate::core::Spend::default(), 0);
        // Deliberately bills nothing. The recorded failure was billed by the""",
    ),
    "ASupersededFigureIsDiscarded": (
        "src/journal/replay.rs",
        "a_reconciled_attempt_replays_at_what_it_actually_spent",
        "a terminal record overwrites the slot rather than adding to it, so a "
        "reconciled attempt replays at the probe's figure alone and the run "
        "stops somewhere its own history never did",
        """            let carried = slot.replay.spend();
            slot.replay = state;
            slot.replay.add_spend(carried);""",
        """            slot.replay = state;""",
    ),
    "AWideReadySetIsDispatchedWhole": (
        "src/runtime/executor.rs",
        "the_ready_set_is_dispatched_no_wider_than_declared",
        "the declared parallelism is not applied to dispatch, so a fan-out is as "
        "wide as its author wrote it and every metered ceiling is overshot by "
        "that width",
        "        .buffered(width)",
        "        .buffered(width.max(usize::MAX))",
    ),
    "AWallClockCeilingIsNeverMeasured": (
        "src/runtime/executor.rs",
        "a_wall_clock_ceiling_stops_the_run",
        "nothing reads a clock into the ledger, so elapsed time stays at zero "
        "for the life of every run and a declared wall-clock ceiling can never "
        "fire — a manifest field naming a control the runtime does not apply",
        """        let at = cx.now().await?;
        ledger.lock().expect("budget mutex").observe_clock(at);""",
        """        let _ = cx;""",
    ),
    "ARequiredVerifierIsAdvisory": (
        "src/runtime/executor.rs",
        "a_required_verifier_binds_the_successor_a_replanner_proposes",
        "the plane's plan contract drops the verifier requirement, so the one "
        "contract rule with no other spelling binds a caller validating its own "
        "graph and not the successor a replanner proposes mid-run",
        """        if self.require_verifier {
            contract.require_verifier()
        } else {
            contract
        }""",
        """        contract""",
    ),
    "AQuarantineLevelIsServedFromAPage": (
        "src/store/redb.rs",
        "the_quarantine_level_is_not_bounded_by_a_page_size",
        "the quarantine gauge is read from a bounded listing, so it rises, "
        "flattens at the page size and reads as a plateau exactly when the "
        "backlog stops being survivable",
        """                n += 1;
            }
            Ok(n)""",
        """                n += 1;
                if n >= 100 {
                    break;
                }
            }
            Ok(n)""",
    ),
    "ASubscriptionPhaseDefaultsToForward": (
        "src/store/redb_events.rs",
        "an_unreadable_subscription_phase_is_refused_rather_than_defaulted",
        "a subscription phase this store cannot read is answered `Forward`, so "
        "a compensating wait's delivery is journaled on the forward cursor — "
        "the wait is never satisfied and a strict replay meets a record nothing "
        "requested",
        """    decoded("step phase", s, crate::core::Phase::parse(s))""",
        """    Ok(crate::core::Phase::parse(s).unwrap_or_default())""",
    ),
    "TheOperatorViewHasItsOwnStatusRule": (
        "src/api/mod.rs",
        "an_unrecognised_outcome_is_quarantined_rather_than_echoed",
        "the run view reads a conclusion with its own match instead of the "
        "runtime's, so an outcome no code anywhere acts on is echoed to an "
        "operator as though it were a state",
        "    let observed = observed_status(&records);",
        """    let observed = records.last().and_then(|r| match r.kind() {
        crate::journal::RecordKind::RunConcluded { outcome, .. } => {
            Some(RunStatus::Quarantined(outcome.clone()))
        }
        _ => None,
    });
    let observed = observed.map(|s| match s {
        RunStatus::Quarantined(o) if o != "quarantined" => RunStatus::Failed(o),
        other => other,
    });""",
    ),
    "AnAtomicMemberIsFreeOnReplay": (
        "src/runtime/group.rs",
        "a_replayed_atomic_member_is_not_applied_again",
        "a replayed atomic member is walked past without billing the slot the "
        "gate took live, so a group is free on the second pass and charged on "
        "the first",
        """                    Some(crate::journal::EffectReplay::Done { spend, .. }) => {
                        self.bill_replayed(spend, 0);
                        continue;
                    }""",
        """                    Some(crate::journal::EffectReplay::Done { .. }) => continue,""",
    ),
    "AQuarantineSealsTheJournal": (
        "src/runtime/executor.rs",
        "a_quarantined_run_is_open_and_seals_only_when_it_truly_ends",
        "a quarantine freezes the journal and publishes a Merkle leaf, so the "
        "one record that answers it can never be appended — the format makes "
        "'a human must resolve it before it can run again' impossible",
        """            Self::Succeeded
                | Self::Cancelled { .. }
                | Self::Abandoned { .. }
                | Self::Swept""",
        """            Self::Succeeded
                | Self::Cancelled { .. }
                | Self::Abandoned { .. }
                | Self::Quarantined(_)
                | Self::Swept""",
    ),
    "AQuarantineNeedsNoAnswerToResume": (
        "src/runtime/executor.rs",
        "an_assertion_alone_does_not_reopen_the_run",
        "an unanswered quarantine resumes on its own, so the conclusion that "
        "exists to stop and be looked at is buried in a retry loop instead — "
        "which is how an undecidable situation becomes an unnoticed one",
        """        "quarantined" => quarantine_decision(records).is_none().then(|| {""",
        """        "quarantined" => None.map(|()| {""",
    ),
    "AReopenIsAStandingLicence": (
        "src/runtime/executor.rs",
        "reopening_without_answering_the_doubt_quarantines_again",
        "one person's judgement is read as standing rather than spent by the "
        "pass it authorized, so every later resume of a run that quarantined "
        "again carries on unasked — a feedback path with no bound, repeating "
        "external side effects",
        """        .take_while(|r| !matches!(r.kind(), RecordKind::RunConcluded { .. }))""",
        """        .take_while(|_| true)""",
    ),
    "AnAbandonmentIsRecordedAndIgnored": (
        "src/runtime/executor.rs",
        "abandoning_leaves_the_world_exactly_as_the_run_left_it",
        "an operator's decision to close an unanswerable run is journaled and "
        "then never acted on, so the run stays in the quarantine backlog while "
        "the operator has been told it was handled — the exact shape the "
        "ignored cancellation request had",
        """    let (decision, record) = quarantine_decision(records)?;""",
        """    let (decision, record) = quarantine_decision(records).filter(|_| false)?;""",
    ),
    "AQuarantinedRunAcceptsACancellation": (
        "src/runtime/executor.rs",
        "cancelling_a_quarantined_run_is_refused_and_names_the_two_verbs",
        "a stop request against a quarantined run is recorded and acknowledged "
        "and then walked past, so an operator believes they stopped a run that "
        "is holding an unresolved payment",
        """        if recorded_conclusion(&records).as_deref() == Some("quarantined") {""",
        """        if false {""",
    ),
    "AClosedRunAcceptsAStopOnceARecordFollowsItsConclusion": (
        "src/runtime/executor.rs",
        "a_stop_after_an_abandoned_run_was_answered_is_refused",
        "the closed-run check reads the last record rather than the latest "
        "conclusion, so an answer recorded after an abandonment lets a stop be "
        "recorded and acknowledged against a run that is over",
        """        if let Some(status) = resume_is_closed(&records) {""",
        """        if let Some(status) = resume_is_closed(&records)
            && matches!(records.last().map(Record::kind), Some(RecordKind::RunConcluded { .. }))
        {""",
    ),
    "AnAssertionOverwritesARecordedOutcome": (
        "src/runtime/executor.rs",
        "an_assertion_cannot_overwrite_an_outcome_the_journal_holds",
        "a person may replace an outcome the journal already holds, so an "
        "operator can talk a run out of compensating work that is standing in "
        "the world and the record shows an orderly reconciliation",
        """        let Some(undecided) = crate::journal::undecided_effects(&records)
            .into_iter()
            .find(|u| u.effect == effect)
        else {""",
        """        let Some(undecided) = crate::journal::undecided_effects(&records)
            .into_iter()
            .next()
        else {""",
    ),
    "AnAssertedValueIsTrusted": (
        "src/runtime/executor.rs",
        "an_asserted_result_names_its_author_and_is_not_trusted",
        "a value an operator typed carries the lattice bottom, so the 3 a.m. "
        "resolution verb is the one place in this design where a person "
        "declassifies by typing",
        """                declared: output
                    .is_some()
                    .then(crate::core::DeclaredOutput::untrusted),""",
        """                declared: output
                    .is_some()
                    .then(crate::core::DeclaredOutput::trusted),""",
    ),
    "AnAssertionIsUnattributed": (
        "src/runtime/executor.rs",
        "an_asserted_result_names_its_author_and_is_not_trusted",
        "a person's assertion is journaled as if the effect's own probe had "
        "answered, so 'the provider told us' and 'somebody asserted it' are "
        "the same record and nobody can tell which decided a run could carry on",
        """                asserted_by: Some(asserted_by.clone()),""",
        """                asserted_by: None,""",
    ),
    "AnAbandonedDoubtIsNotAFinding": (
        "src/audit.rs",
        "an_abandoned_doubt_is_reportable_from_the_journal_forever",
        "closing a run takes its unresolved effect off the only listing that "
        "carried it and nothing replaces it, so what the run left in the world "
        "is undiscoverable the moment somebody stops looking",
        """            crate::journal::undecided_effects(records)
                .into_iter()
                .map(|u| Finding::EffectUndecided {""",
        """            Vec::<crate::core::Undecided>::new()
                .into_iter()
                .map(|u| Finding::EffectUndecided {""",
    ),
    "AnAbandonmentIsSilent": (
        "src/runtime/executor.rs",
        "abandoning_a_quarantined_run_emits_its_event",
        "writing off a run that left something unexplained in the world "
        "announces nothing, so the only party who learns of it is the one who "
        "decided it — an intervention visible only to whoever made it",
        """        RunStatus::Abandoned { actor, reason } => {
            tracing::error!(
                target: telemetry::ABANDONED,""",
        """        RunStatus::Abandoned { actor, reason } => {
            let _ = (actor, reason);
            tracing::trace!(
                target: "agentplane::nowhere",""",
    ),
    "AFailedRunLogsItsReasonInClear": (
        "src/runtime/executor.rs",
        "a_failed_runs_event_carries_a_digest_not_the_reason",
        "a failed run's event carries the reason's text — a skill's or a "
        "provider's words over the caller's data — into the log, where neither "
        "the journal's seal nor an erasure reaches it",
        """                error_type = "failed",""",
        """                error_type = "failed", reason = %reason,""",
    ),
    "AnUndecidableEffectLogsTheProvidersText": (
        "src/runtime/executor.rs",
        "an_undecidable_effects_events_carry_no_provider_text",
        "an undecidable effect's event carries the provider's failure text, "
        "which quotes the request it refused, into a log the erasure of that "
        "run never reaches",
        """                        error_type = "undecidable",""",
        """                        error_type = "undecidable", %detail,""",
    ),
    "AFailedCompensationLogsItsErrorText": (
        "src/runtime/executor.rs",
        "a_failed_compensations_event_carries_no_error_text",
        "a failed compensation's event carries the reversal's error text, "
        "which quotes the caller's data, into the log in clear",
        """                    error_type = fault.class(),""",
        """                    error_type = fault.class(), detail = %outcome,""",
    ),
    "AVersionIsWrittenAndNeverRead": (
        "src/journal/record.rs",
        "a_record_from_a_shape_this_build_does_not_know_is_refused",
        "a record's schema version is written on every append and never read "
        "back, so a journal written one shape ahead parses cleanly with the "
        "fields this build has never heard of dropped on the floor",
        """            Ok(body) if body.v == upcaster.current_version(body.kind.kind_str()) => Ok(body),""",
        """            Ok(body) => Ok(body),
            #[allow(unreachable_patterns)]""",
    ),
    "AVersionSkewIsReportedAsTampering": (
        "src/journal/upcast.rs",
        "a_version_skew_is_not_reported_as_tampering",
        "a rolling deploy that put a writer ahead of its readers reaches an "
        "operator as 'the history has been altered' — spending the one alarm "
        "that has to stay believable on a deployment ordering mistake",
        """            _ => Err(StoreError::UnknownRecordVersion {
                kind: kind.to_owned(),
                version,
                reads: 1,
            }),""",
        """            _ => Err(StoreError::Corrupt {
                seq: 0,
                detail: format!("record {kind} is v{version}"),
            }),""",
    ),
    "AnExportVerdictHidesItsOwnWidth": (
        "src/export.rs",
        "a_framing_member_this_build_does_not_know_bounds_the_verdict",
        "a framing line written by a later build carries members this reader "
        "passes over in silence, so the report says the file is sound without "
        "saying it read part of it — on the artifact handed to somebody with no "
        "other copy",
        """        if let Some(kind) = value.get("kind").and_then(Value::as_str) {
            note_unknown_members(kind, report.selection.is_some(), &value, &mut report);
        }""",
        """        if false {
            note_unknown_members("", false, &value, &mut report);
        }""",
    ),
    "ADrillAssertsACauseItCannotEstablish": (
        "src/drill.rs",
        "a_header_this_build_cannot_parse_names_both_causes",
        "a sealed header another build wrote is reported as loss or tampering, "
        "so a drill pages somebody to hunt a fault while the remedy is which "
        "binary is running — on the report an auditor reads to decide whether "
        "erasure worked",
        """        Some(Err(e @ KeyError::UnreadableHeader { .. })) => report.findings.push(format!(""",
        """        Some(Err(e @ KeyError::Destroyed { .. })) if false => report.findings.push(format!(""",
    ),
    "ASealedHeaderTakesUnknownMembers": (
        "src/keyring/mod.rs",
        "a_header_member_this_build_does_not_know_is_refused",
        "an envelope's header is read with members this build never saw taken "
        "silently off the floor, so a data key is unwrapped under parameters "
        "another build wrote down — on the one format whose misreading decides "
        "whether data is still readable",
        """#[serde(deny_unknown_fields)]
pub struct WrappedKey {""",
        """pub struct WrappedKey {""",
    ),
    "AMissingEffectIsOnlyADigest": (
        "src/journal/replay.rs",
        "strict_replay_rejects_a_build_that_does_something_different",
        "a strict pass that finds the record holds an effect this build never "
        "asked for names it by key alone, so an operator hunting a missing call "
        "is handed a digest and sent to read the journal by hand",
        """            Some(kind) => write!(f, "`{kind}` ({})", self.key),""",
        """            Some(_) => write!(f, "{}", self.key),""",
    ),
    "AnOverrunIsOnlyADigest": (
        "src/core/error.rs",
        "strict_replay_rejects_a_build_that_does_more_than_the_record",
        "a build that runs past the end of its own history reports the key of "
        "the call it made and not the call, so the finding names nothing the "
        "developer who added it would recognise",
        """        "replay overrun: journal is exhausted but the run requested `{kind}` ({actual}) — \\""",
        """        "replay overrun: journal is exhausted but the run requested {actual}{kind:.0} — \\""",
    ),
    "AnAttentionRollUpCallsSilenceHealth": (
        "src/runtime/attention.rs",
        "attention_names_each_condition_and_what_it_could_not_check",
        "a backlog this plane has no store for is left out of the answer "
        "instead of being named as unchecked, so a plane that could not look "
        "and a plane that found nothing return the same empty list — which is "
        "the one reading an operator must never be given",
        """            None => out.not_checked.push(
                "obligations — this plane holds no case store, so whether any went \\
                 unaccounted for was not established",
            ),""",
        """            None => {}""",
    ),
    "AnUnexpiredWaitIsAFinding": (
        "src/runtime/attention.rs",
        "a_wait_needs_a_person_only_once_its_instant_has_passed",
        "every waiting run is reported as needing a person, expired or not — so "
        "scheduling something for next Tuesday pages somebody every day until "
        "Tuesday, and a roll-up that cries wolf is one people stop reading",
        """            .filter(|w| w.reason.until() <= at)""",
        """            .filter(|w| w.reason.until() >= crate::core::Timestamp::UNIX_EPOCH)""",
    ),
    "AnAuthOracleIsAccepted": (
        "src/testkit/conformance_auth.rs",
        "the_auth_battery_rejects_an_oracle",
        "the authenticator battery stops separating a refused credential from "
        "an absent one, so a deployment whose implementation answers `Missing` "
        "for a token it looked at passes it — and that bit tells a prober the "
        "token was the right shape",
        """            Err(AuthError::Rejected) => {}
            Err(AuthError::Missing) => r.record(""",
        """            Err(AuthError::Missing | AuthError::Rejected) => {}
            #[allow(unreachable_patterns)]
            Err(AuthError::Missing) => r.record(""",
    ),
    "AWaitingRunIsNeverListed": (
        "src/store/redb.rs",
        "a_restored_event_wait_is_subscribed_by_nothing_until_the_run_is_resumed",
        "a run whose last record is a suspension is not indexed as waiting, so "
        "the recovery runbook's last step — re-arm the suspended runs — names a "
        "verb with no argument an operator can obtain, and after a restore "
        "those runs lie inert with nothing pointing at them",
        """                        crate::journal::RecordKind::RunSuspended { reason } => Some(reason.clone()),""",
        """                        crate::journal::RecordKind::RunSuspended { .. } => None,""",
    ),
    "AResumedRunStaysOnTheWaitingList": (
        "src/store/redb.rs",
        "redb_satisfies_the_journal_store_contract",
        "the waiting index only ever gains rows, so a run that suspended once "
        "is listed as waiting forever — an oldest-first page whose head is "
        "permanent, which is the shape that makes a backlog unworkable rather "
        "than merely wrong",
        """                    if let Some(prior) = at
                        .remove((tenant.as_str(), key.as_str()))
                        .map_err(|e| be(&e))?
                        .map(|v| v.value())
                    {""",
        """                    if let Some(prior) = at
                        .get((tenant.as_str(), key.as_str()))
                        .map_err(|e| be(&e))?
                        .map(|v| v.value())
                        .filter(|_| waiting.is_some())
                    {""",
    ),
    "ADivergenceIsTwoDigests": (
        "src/journal/replay.rs",
        "a_divergence_names_the_call_that_moved",
        "a run quarantined for non-determinism reports two effect keys and "
        "nothing else, so the developer who changed the code is handed a pair "
        "of hashes — and the reason is journaled, which makes the unhelpful "
        "version the permanent one",
        """                detail: entry.diverged_from(asked, attempt),""",
        """                detail: String::new(),""",
    ),
    "ADivergenceQuotesASealedArgument": (
        "src/journal/replay.rs",
        "a_divergence_says_which_of_the_three_things_moved",
        "the sentence a divergence journals into a run's conclusion is "
        "composed from the effect's arguments, which are a sealed field — so a "
        "plaintext copy of caller data lands where an erasure cannot reach it",
        """        format!(
            "both perform `{}` at attempt {}, so the arguments differ — they are sealed with \\
             the record, so comparing them needs a reader holding the key",
            what.kind, what.attempt
        )""",
        """        format!(
            "both perform `{}` at attempt {}, with arguments {} rather than {}",
            what.kind, what.attempt, asked.args, asked.args
        )""",
    ),
    "AShapeSkewIsAnEncodingFault": (
        "src/journal/record.rs",
        "a_shape_this_build_cannot_read_at_its_own_version_is_a_build_skew",
        "the only skew a pre-freeze deployment can meet — a shape that moved "
        "without the version moving — reaches an operator as a serde message "
        "about a column number, with nothing saying the bytes are intact or "
        "which binary to run",
        """        Some((kind, version)) => StoreError::UnreadableRecordShape {""",
        """        Some(_) => StoreError::Encoding(parse),
        #[allow(unreachable_patterns)]
        Some((kind, version)) => StoreError::UnreadableRecordShape {""",
    ),
    "AnOldReaderCallsAnExportTampered": (
        "src/export.rs",
        "a_record_from_a_newer_build_is_not_reported_as_tampering",
        "an export written one hard cut ahead reads as a damaged file to the "
        "one audience that has no other copy — the build skew is reported in "
        "the vocabulary of an edit, record by record",
        """        crate::core::StoreError::UnreadableRecordShape { .. } => {""",
        """        crate::core::StoreError::Corrupt { .. } => {""",
    ),
    "AnUndeclaredFieldIsDroppedOnTheFloor": (
        "src/journal/record.rs",
        "a_field_this_build_does_not_know_is_refused",
        "a record carrying a field this build does not know is read anyway, "
        "with the unknown part discarded, so an authorization or recovery "
        "verdict is reached over evidence the reader never saw",
        """#[serde(tag = "kind", rename_all = "PascalCase", deny_unknown_fields)]""",
        """#[serde(tag = "kind", rename_all = "PascalCase")]""",
    ),
    "ARecordFieldIsQuietlyRenamed": (
        "src/journal/record.rs",
        "every_record_kind_hashes_to_its_golden_vector",
        "a record's field is renamed on the wire, which rehashes every record "
        "this build will ever write and breaks every journal ever written — "
        "and reads in review as a tidy-up. Field *order* is deliberately not "
        "this mutation: canonical form sorts keys, so reordering the struct is "
        "invisible to the format and a corpus that caught it was pinning "
        "something the chain does not depend on",
        """    pub epoch: Epoch,""",
        """    #[serde(rename = "ep")]
    pub epoch: Epoch,""",
    ),
    "TheChainHashesUncanonicalBytes": (
        "src/journal/record.rs",
        "every_record_kind_hashes_to_its_golden_vector",
        "a record is sealed over `serde_json`'s output rather than canonical "
        "bytes, so the hash depends on the order the struct happens to declare "
        "its fields and on whichever `Map` implementation the dependency graph "
        "unified to — the two things `canon` exists to take out of the format",
        """        let raw = canon::to_bytes(&body)?;""",
        """        let raw = serde_json::to_vec(&body)?;""",
    ),
    "ADeadLetterListingShowsThePayload": (
        "src/api/mod.rs",
        "a_dead_letter_is_readable_and_carries_no_payload",
        "the diagnostic listing hands back the counterparty's message body — a "
        "confidentiality decision nobody took, and on a sealed plane one that "
        "shows ciphertext to some deployments and plaintext to others",
        """            reason: letter.reason.clone(),
        }""",
        """            reason: letter.event.payload.to_string(),
        }""",
    ),
    "ARearmIsReportedAsDoneWhateverHappened": (
        "src/api/mod.rs",
        "a_parked_registration_is_listed_and_re_armed",
        "re-arming a registration that was never parked answers the operator "
        "'done', so they wait for a sweep that has nothing to do",
        """    Ok(Json(RearmAnswer { rearmed }))""",
        """    Ok(Json(RearmAnswer { rearmed: true || rearmed }))""",
    ),
    # The operator API's published document. The router and the document are
    # built from one table, so a route can be served undocumented only by
    # adding it beside the table, and documented unserved only by serving it
    # under another method.
    "ARouteIsServedBesideTheTable": (
        "src/api/mod.rs",
        "every_routed_operation_is_documented_and_no_other",
        "a route is added to the operator router outside the table the OpenAPI "
        "document is generated from, so it is served, gated and absent from the "
        "document every generated client is built from",
        "        router.with_state(self)",
        '        router.route("/drills", axum::routing::get(last_drill)).with_state(self)',
    ),
    "TheDocumentNamesARouteTheRouterLacks": (
        "src/api/mod.rs",
        "every_documented_operation_answers_through_the_router",
        "the router serves the dead-letter listing at a path the document does "
        "not name, so a generated client's call to the documented path answers "
        "404",
        "            router = router.route(route.path, route.served());",
        '            router = router.route(&route.path.replacen("/dead-letters", "/dead-letter", 1), route.served());',
    ),
    "DecidingWithoutATaskStoreIsAConflict": (
        "src/api/mod.rs",
        "a_missing_store_does_not_describe_the_plane",
        "a decision posted to a plane built without a task store answers 409, "
        "which tells the decider their verdict lost a race, where every other "
        "task route says the store is missing",
        """    s.plane.tasks().ok_or_else(|| unavailable("task"))?;
    s.plane.events().ok_or_else(|| unavailable("event"))?;""",
        """    s.plane.events().ok_or_else(|| unavailable("event"))?;""",
    ),
    "DeliveringWithoutAnEventStoreIsAConflict": (
        "src/api/mod.rs",
        "a_missing_store_does_not_describe_the_plane",
        "an event posted to a plane built without an event store answers 409, "
        "which a bus treats as permanent and drops, where the plane is missing "
        "a store and the document says 501",
        """    let s = api.authorize(caller, action::EVENT_DELIVER, input.kind())?;
    s.plane.events().ok_or_else(|| unavailable("event"))?;""",
        """    let s = api.authorize(caller, action::EVENT_DELIVER, input.kind())?;""",
    ),
    "AnOpenMemberSaysNothing": (
        "src/core/case.rs",
        "every_open_member_of_the_document_says_what_it_holds",
        "a case's state reaches the document as `{}`, so a client author cannot "
        "tell that the plane never reads it",
        """    #[schemars(extend("x-agentplane-holds" = "The case's state as its adapter wrote it, validated per kind by the adapter; the plane does not read it."))]
""",
        "",
    ),
    "TheDocumentListsADispositionReconcileRefuses": (
        "src/api/mod.rs",
        "the_documented_dispositions_are_the_ones_reconcile_accepts",
        "the document lists a disposition the handler refuses, so a client "
        "validating against it sends a reconcile that answers 400",
        """    #[schemars(extend("enum" = ["landed", "did_not_happen"]))]""",
        """    #[schemars(extend("enum" = ["landed", "did_not_happen", "unknown"]))]""",
    ),
    "TheDocumentNamesAnotherAction": (
        "src/api/openapi.rs",
        "every_documented_operation_answers_through_the_router",
        "the document says lifting a halt asks `api:halt.place`, so a deployment "
        "writing rules from it grants the wrong capability for the lift",
        "        action: action::HALT_LIFT,",
        "        action: action::HALT_PLACE,",
    ),
    "AResponseMemberIsHiddenFromTheSchema": (
        "src/api/mod.rs",
        "a_response_validates_against_the_document",
        "a task view serves `digest` and the document omits it, so a generated "
        "client built against the closed schema rejects every task it reads",
        "    pub digest: crate::core::Digest,",
        "    #[schemars(skip)]\n    pub digest: crate::core::Digest,",
    ),
    "ARejectedBodyAnswersInPlainText": (
        "src/api/mod.rs",
        "a_refused_body_answers_with_the_documented_error",
        "a halt body the extractor refuses answers axum's plain text instead of "
        "the documented error object, so a client parsing the one error shape "
        "crashes on the refusal it most needs to read",
        "    Uniform(Json(body)): Uniform<Json<PlaceHaltRequest>>,",
        "    Json(body): Json<PlaceHaltRequest>,",
    ),
    "AnErrorClassListsNoStatus": (
        "src/api/openapi.rs",
        "a_response_validates_against_the_document",
        "the document lists no 501 on any operation while a plane built without "
        "a store answers 501, so a generated client meets a status it was told "
        "cannot happen",
        "            Self::NotWired => 501,",
        "            Self::NotWired => 500,",
    ),
    "TheGeneratorDriftsFromThePublishedFile": (
        "src/api/openapi.rs",
        "the_published_openapi_is_the_generated_document",
        "the generated document moves and the file the site publishes does not, "
        "so integrators generate clients from a description of another build",
        """            "title": "agentplane operator API",""",
        """            "title": "agentplane operator API (drifted)",""",
    ),
    "TheVerbPrintsSomethingElse": (
        "src/bin/agentplane.rs",
        "the_openapi_verb_prints_the_published_document",
        "`agentplane openapi` prints an empty object, so a client generated from "
        "the binary's own output has no operations",
        "    serde_json::to_string_pretty(&agentplane::api::openapi::document())",
        "    serde_json::to_string_pretty(&serde_json::json!({}))",
    ),
    "TheOfflineSweepSkipsTheQuarantineBacklog": (
        "src/runtime/executor.rs",
        "the_offline_sweep_covers_every_ending_and_the_quarantine_backlog",
        "the export's default sweep omits quarantined runs, so the artifact an "
        "auditor is handed holds everything that finished and nothing that did "
        "not — and looks complete",
        """pub const OUTCOMES_OF_RECORD: &[&str] = &[
    "succeeded",
    "cancelled",
    "abandoned",
    "quarantined",""",
        """pub const OUTCOMES_OF_RECORD: &[&str] = &[
    "succeeded",
    "cancelled",
    "abandoned",""",
    ),
    # ── The asserted rung ───────────────────────────────────────────────────
    #
    # A seat beside somebody else's agent records that agent's account of
    # itself. Every bug here has the same shape: a report acquires the standing
    # of something this runtime dispatched.
    "AnObservationSealsAsThisPlanesWork": (
        "src/observe/mod.rs",
        "an_acp_session_is_recorded_audited_and_never_reads_as_an_effect",
        "an observed session is sealed under `succeeded`, so a session this "
        "plane only watched is indistinguishable in the outcome index from work "
        "it ran, governed and authorized",
        """                outcome: crate::runtime::OBSERVED_OUTCOME.to_owned(),""",
        """                outcome: "succeeded".to_owned(),""",
    ),
    "AnObservationWearsAnOrdinaryRecordKind": (
        "src/observe/mod.rs",
        "an_acp_session_is_recorded_audited_and_never_reads_as_an_effect",
        "an observed step is written as an ordinary note, so the rung is lost "
        "and a reader cannot tell what this runtime dispatched from what "
        "somebody else's agent said it did",
        """            RecordKind::Observed {
                session: self.id.clone(),
                reported: step,
                detail,
            },""",
        """            RecordKind::Note {
                text: format!("{}: {:?}", self.id, step),
            },""",
    ),
    "AnObservedRecordEscapesItsCase": (
        "src/observe/mod.rs",
        "an_observed_session_is_reachable_through_the_case_it_names",
        "an observed session's records are written without the case stamp, so "
        "the matter correlated on the session id walks past the very records it "
        "was opened to make findable",
        """        if let Some(case) = self.case {
            entry = entry.case(case);
        }""",
        """        let _ = self.case;""",
    ),
    "AnUnknownToolStatusReadsAsFinished": (
        "src/observe/acp.rs",
        "an_unfamiliar_tool_status_claims_the_least",
        "a tool-call status this build does not recognise is recorded as "
        "`completed`, so a word from a newer revision puts a claim on the record "
        "that the observed agent never made",
        """        _ => ObservedStatus::Pending,""",
        """        _ => ObservedStatus::Completed,""",
    ),
    "APresentationUpdateIsRecordedAsATurn": (
        "src/observe/acp.rs",
        "a_presentation_update_is_reported_rather_than_dropped",
        "every update this plane does not map is recorded as a user turn, so a "
        "streamed thought chunk enters the evidence log as something a person "
        "asked for",
        """        _ => unrecorded(),
    }
}""",
        """        _ => Mapped::Step {
            step: ObservedStep::Prompted,
            detail: update.title.clone(),
        },
    }
}""",
    ),

    # ── Erasure, and the three causes it is confused with ───────────────────
    "AnOutageReadsAsAnErasure": (
        "src/keyring/journal.rs",
        "a_journal_read_during_a_key_ring_outage_is_not_an_erasure",
        "the journal's sealed read swallows every key failure, so a KMS that is "
        "briefly unreachable reads back exactly like a run whose data was "
        "lawfully destroyed",
        """                match super::envelope::open_or_erased(keys, aad.as_bytes(), &envelope)
                    .await
                    .map_err(|e| StoreError::Backend(e.to_string()))?
                {
                    Some(plain) => {
                        *field = serde_json::from_slice(&plain)?;
                        found.opened += 1;
                    }""",
        """                match super::envelope::open(keys, aad.as_bytes(), &envelope)
                    .await
                    .ok()
                {
                    Some(plain) => {
                        *field = serde_json::from_slice(&plain)?;
                        found.opened += 1;
                    }""",
    ),
    "APushCredentialIsDroppedOnAnyFailure": (
        "src/keyring/push.rs",
        "a_push_credential_is_not_dropped_because_the_ring_is_down",
        "a credential that will not open is dropped whatever the cause, so a key "
        "ring that is down sends the notification without the authentication it "
        "was registered with",
        """        let opened = super::envelope::open_or_erased(self.keys.as_ref(), aad.as_bytes(), &envelope)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(opened""",
        """        let opened = super::envelope::open(self.keys.as_ref(), aad.as_bytes(), &envelope)
            .await
            .ok();
        Ok(opened""",
    ),
    "AnErasedRunFailsAsAMalformedRecord": (
        "src/runtime/executor.rs",
        "an_erased_run_names_the_erasure_and_can_still_be_abandoned",
        "a resume of a run whose payloads were erased falls through to the "
        "parser, which reports a missing field — sending an operator to look for "
        "a corrupt journal instead of telling them the data is gone",
        "            if sealed_payload(plan) {",
        "            if false {",
    ),
    "AnErasureRunsUnderLiveWork": (
        "src/blob/mod.rs",
        "erasing_a_case_that_is_still_open_is_refused",
        "the rule that a matter must be closed before it is erased lives in the "
        "retention pass's selection only, so the Article 17 path destroys the key "
        "under runs that can then never be replayed or unwound",
        """    if let Some(open) = found.filter(|c| c.status != crate::core::CaseStatus::Closed) {""",
        """    if let Some(open) = found.filter(|_| false) {""",
    ),
    "TheCeilingIgnoresReservations": (
        "src/quota/mod.rs",
        "a_period_ceiling_bounds_suspended_runs",
        "the period ceiling counts settled spend and not what admitted runs "
        "hold, so every run admitted before any settles — all of them, when "
        "they suspend first — may spend its whole budget past the ceiling",
        "            && settled.saturating_add(reserved).saturating_add(requested) > limit",
        "            && settled.saturating_add(requested) > limit",
    ),
    "TheSpendCheckReadsBeforeItReserves": (
        "src/store/postgres_quota.rs",
        "postgres_spend_ceiling_holds_under_concurrent_admission",
        "admission reads the period and inserts its hold without the tenant's "
        "admission lock, so two instances each read a period with room and "
        "both land — the ceiling yields under the concurrent load it exists for",
        """        tx.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            &[&format!("quota-admission:{}:{tenant}", tenant.len())],""",
        """        tx.query_one(
            "SELECT hashtextextended($1, 0)",
            &[&format!("quota-admission:{}:{tenant}", tenant.len())],""",
    ),
    "SettlementKeepsTheReservation": (
        "src/store/redb_quota.rs",
        "a_settled_run_releases_its_unspent_reservation",
        "the concluding settlement keeps what the run did not spend, so every "
        "run that finishes under budget leaves the period a little fuller until "
        "it admits nothing at all",
        "                if settlement.concludes {",
        "                if false && settlement.concludes {",
    ),
    "ASuspendedPassIsChargedTwice": (
        "src/store/redb_quota.rs",
        "a_suspended_pass_is_not_charged_twice",
        "a pass settlement accrues its spend without taking it out of the run's "
        "hold, so a run that suspends is counted once settled and again reserved",
        "                                tokens.saturating_sub(settlement.spend.tokens),",
        "                                tokens,",
    ),
    "ReleaseKeepsTheReservation": (
        "src/store/redb_quota.rs",
        "redb_satisfies_the_quota_store_contract",
        "releasing an admission whose journal never landed frees its slot and "
        "keeps its spend hold, so a crash before the admission record strands a "
        "reservation over no run, forever",
        """                let mut reserved = w.open_table(RESERVED).map_err(|e| be(&e))?;
                reserved
                    .remove((tenant.as_str(), run.as_str()))
                    .map_err(|e| be(&e))?;
            }
            w.commit().map_err(|e| be(&e))?;
            Ok(())""",
        """            }
            w.commit().map_err(|e| be(&e))?;
            Ok(())""",
    ),
    "AnUnboundedRunIsAdmitted": (
        "src/quota/mod.rs",
        "a_run_with_no_money_ceiling_is_refused_under_a_money_quota",
        "a run with no ceiling on a unit the tenant bounds is admitted holding "
        "only its per-call figure, so it spends without limit against a period "
        "that believes it reserved for it",
        "        let ceiling = ceiling.ok_or(names.0)?;",
        "        let ceiling = ceiling.unwrap_or(0);",
    ),
    "RecoveryForgetsTheConcludingPass": (
        "src/runtime/executor.rs",
        "a_settled_run_releases_its_unspent_reservation",
        "a resume re-derives a run's concluding pass as not concluding, so its "
        "settlement disagrees with the receipt the live conclusion wrote and "
        "every resume of a finished run is refused as corruption",
        "                    concludes: concluded_in(records, epoch),",
        "                    concludes: false,",
    ),
    "AResumeIsCheckedForSpend": (
        "src/runtime/executor.rs",
        "a_resume_past_the_ceiling_is_not_refused",
        "a resume is refused once the period is full, stranding an admitted "
        "run mid-saga with its reversals unrun",
        """            quotas
                .carry(run, period)
                .await
                .map_err(RuntimeError::Store)?;""",
        """            crate::quota::check_spend(
                self.tenant.as_str(),
                period,
                &self.quota,
                quotas.spent(period).await.map_err(RuntimeError::Store)?,
                Spend::ZERO,
                Spend::ZERO,
            )
            .map_err(RuntimeError::QuotaExceeded)?;
            quotas
                .carry(run, period)
                .await
                .map_err(RuntimeError::Store)?;""",
    ),
    "AResumeLeavesItsHoldBehind": (
        "src/runtime/executor.rs",
        "a_resume_across_a_period_boundary_follows_the_stated_rule",
        "a resume in a later period spends there while its hold stays in the "
        "period it was admitted in, so the new period admits against room the "
        "resumed run is about to use",
        """            quotas
                .carry(run, period)
                .await
                .map_err(RuntimeError::Store)?;""",
        """            let _ = (quotas, period);""",
    ),
    "ReservationsListNothing": (
        "src/runtime/attention.rs",
        "a_full_period_names_the_runs_that_hold_it",
        "a stopped run holding part of the tenant's period is never named, so "
        "a period filled by runs nobody will conclude refuses every admission "
        "with nothing pointing at what would free it",
        "            .filter(|h| stopped.contains(&h.run))",
        "            .filter(|_| false)",
    ),
    "ValidateTotalsAnUnboundedTerm": (
        "src/bin/agentplane.rs",
        "validate_names_every_unbounded_term",
        "validate prints a worst case for a unit whose ceiling or per-call "
        "figure the declaration leaves open, so a guess reads as a bound",
        "            _ => None,\n        };\n        let shown",
        "            _ => Some(ceiling.unwrap_or(0).saturating_add(per_call.unwrap_or(0))),\n        };\n        let shown",
    ),
    "ACommissionIsSettledTwice": (
        "src/runtime/ctx.rs",
        "a_commission_accrues_to_the_tenant_period_once",
        "a commission's cost is the effect's spend as well as the sub-run's, so "
        "the tenant's period is charged twice for one call and the "
        "commissioning run's ceiling counts it twice",
        "    fn spend(&self, _output: &Self::Output) -> crate::core::Spend {\n        crate::core::Spend::ZERO\n    }",
        "    fn spend(&self, output: &Self::Output) -> crate::core::Spend {\n        crate::core::Spend { tokens: output.tokens, minor_units: output.minor_units }\n    }",
    ),
    "AReservationIgnoresTheStepsInFlight": (
        "src/runtime/executor.rs",
        "a_reservation_covers_every_step_in_flight",
        "the reservation covers one overshooting call however many steps the "
        "run has in flight, so a fan-out ends several calls past a hold sized "
        "for one",
        "    budget.parallelism().min(plan.nodes.len()).max(1)",
        "    let _ = (budget, plan);\n    1",
    ),
    "AnAnswerPastItsInputCeilingIsUsed": (
        "src/model/mod.rs",
        "a_call_over_its_input_ceiling_fails_and_is_billed",
        "a completion that sent more than its role's max_input_tokens is handed "
        "on, so the per-call figure a tenant's quota reserves is not a bound on "
        "any call the run goes on to use",
        "                && completion.usage.input_tokens > u64::from(max)",
        "                && completion.usage.input_tokens > u64::from(max).saturating_mul(u64::MAX)",
    ),
    "OneRolesBoundCoversAnUnboundedRole": (
        "src/manifest/mod.rs",
        "a_manifest_derives_its_per_call_bound_from_every_role",
        "a role that leaves one call's input unbounded is skipped when the "
        "run's per-call figure is derived, so the other role's figure is "
        "reserved for calls it does not bound",
        "            let one = r.call_bound()?;",
        "            let Some(one) = r.call_bound() else {\n                return Some(most);\n            };",
    ),
    "AnUnopenedConclusionKeepsItsHold": (
        "src/runtime/executor.rs",
        "an_abandoned_quarantine_gives_back_its_reservation",
        "a run concluded by a decision no execution pass opened — an abandoned "
        "quarantine — settles nothing, so it keeps its reservation and every "
        "abandonment leaves a slice of the tenant's period held forever",
        "            if concludes {\n                quotas.release(run).await.map_err(pending)?;\n            }",
        "            let _ = concludes;",
    ),
    "AStoppedResumeUnwindsBeforeItReplays": (
        "src/runtime/executor.rs",
        "a_stopped_resume_unwinds_with_the_recorded_outputs_in_reverse_completion_order",
        "a cancellation on a resume unwinds before the recorded steps replay, so each compensation is handed null for the output it undoes and the steps are undone in id order rather than in reverse of the order they finished",
        "            let at_frontier = ready.is_empty() || ready.iter().any(|s| !succeeded.contains(s));",
        "            let at_frontier = { let _ = &succeeded; true };",
    ),
    "RecoveryRetriesAConclusionNoMarkerOpened": (
        "src/runtime/executor.rs",
        "recovery_hands_back_a_concluded_run_rather_than_resuming_it",
        "recovery finishes a conclusion only when a quota pass marker opened it, so without a quota store a run that concluded and lost its owner is resumed — a failure retried by a crash's timing, and a compensated one refused and recovered every lease period for ever",
        "        let Some(last) = records.last() else {\n            return Ok(None);\n        };\n        let RecordKind::RunConcluded {",
        "        let Some(last) = records.last().filter(|l| records.iter().any(|r| r.body.epoch == l.body.epoch && matches!(r.kind(), RecordKind::QuotaPassStarted { .. }))) else {\n            return Ok(None);\n        };\n        let RecordKind::RunConcluded {",
    ),
    "AResumeRunsWithNoDestinationRegistered": (
        "src/runtime/executor.rs",
        "a_resume_registers_the_destinations_its_admission_could_not",
        "a run whose admission failed to register its destinations is concluded failed, and resuming it executes the whole run with nothing watching its history",
        "            self.register(run, recorded_case_id(&records))",
        "            let _ = (run, &records);\n            std::future::ready(Ok::<(), crate::core::StoreError>(()))",
    ),
    "ACaselessPlaneResumesACaseBoundRun": (
        "src/runtime/executor.rs",
        "a_case_bound_run_is_refused_a_resume_on_a_plane_with_no_case_store",
        "a plane with no case store resumes a case-bound run and writes its records under the run alone, where erasing the case misses them",
        "            Some(case) if self.cases.is_none() => Err(RuntimeError::NoCaseStore {",
        "            Some(case) if self.cases.is_none() && false => Err(RuntimeError::NoCaseStore {",
    ),
    "AnUndoPassesThePolicyUnjudged": (
        "src/runtime/ctx.rs",
        "a_compensation_the_policy_refuses_quarantines_instead_of_running",
        "a compensation's effects skip the declaration and the policy along with the budget, so undo is a door to any effect the policy refuses",
        "        self.declared(key, descriptor, ceilings).await?;",
        "        if self.undoing() {\n            self.count_unadmitted(outbound_bytes);\n            return Ok(());\n        }\n        self.declared(key, descriptor, ceilings).await?;",
    ),
    "ACaseListsARunBeforeItExists": (
        "src/runtime/executor.rs",
        "a_crash_while_attaching_leaves_no_run_the_journal_lacks",
        "the case row is written before the admission's append, so a process that dies between the two leaves a case listing a run no journal holds, and nothing can tell which case to take it off",
        "            .append(lease.epoch, records)",
        "            .append(lease.epoch, {\n                if let Some(ctx) = case_ctx.as_ref() {\n                    ctx.cases.attach_run(ctx.case_id, run).await.map_err(RuntimeError::from_store)?;\n                }\n                records\n            })",
    ),
    "ARunIsNeverPutOnItsCase": (
        "src/runtime/executor.rs",
        "a_crash_before_attaching_is_attached_by_the_recovery",
        "a run's registration skips its case, so a case-bound run is missing from the matter's own list of what happened in it",
        "            cases.attach_run(case, run).await?;",
        "            let _ = (case, cases);",
    ),
    "AnUnreadableSuccessorIsSkipped": (
        "src/runtime/executor.rs",
        "an_unreadable_successor_plan_refuses_the_resume",
        "a successor plan this build cannot parse is dropped, so every later replan lands on the wrong plan and the resume freezes a new successor mid-history",
        "        .map(|plan| {",
        "        .filter(|plan| sealed_payload(plan) || serde_json::from_value::<PlanIR>((*plan).clone()).is_ok())\n        .map(|plan| {",
    ),
    "TheOwnerMayApproveTheirOwnTask": (
        "src/runtime/ctx.rs",
        "the_person_a_run_acts_for_cannot_approve_it",
        "only the admitting caller is barred from a run's tasks, so the person a served run acts for — or the workload acting as them — approves their own request",
        "                Some([c.owner().id.clone(), c.subject().id.clone()])",
        "                Some([String::new(), c.subject().id.clone()])",
    ),
    "AWithdrawnPersonsDelegatesCarryOn": (
        "src/quota/mod.rs",
        "a_halt_naming_a_person_reaches_the_work_delegated_from_them",
        "a subject halt is matched against the acting workload alone, so withdrawing a person stops nothing a service is doing on their behalf",
        "            .filter(|id| chain.links().any(|link| link.id == *id))",
        "            .filter(|id| chain.subject().id == *id)",
    ),
    "ATaskIdIsReadBeforeTheCaller": (
        "src/api/a2a.rs",
        "every_method_is_authenticated",
        "a task id is parsed before the caller is authenticated, so an unauthenticated caller with a malformed id is answered about tasks rather than challenged",
        "        let caller = self.authenticate(headers).await?;\n        let run = task_id(params)?;",
        "        let run = task_id(params)?;\n        let caller = self.authenticate(headers).await?;",
    ),
    "APlaneOnAFullBackendIgnoresHalts": (
        "src/runtime/executor.rs",
        "a_plane_on_a_full_backend_obeys_halts_without_being_told_to",
        "a plane wired from one full backend and never told `.quota` holds no quota store, so it admits past every halt an operator throws",
        "            .quota(stores.quotas, crate::quota::TenantQuota::default())\n",
        "",
    ),
    "ASealedHistoryRestoresUnderAnyTenant": (
        "src/export.rs",
        "a_sealed_export_is_refused_by_a_tenant_its_envelopes_do_not_name",
        "a sealed export restores under a tenant its envelopes do not name, so every payload opens for nobody and erase_case there destroys a key that wraps none of it while reporting success",
        "        Some(sealer) if sealer == tenant => Ok(()),",
        "        Some(_) => Ok(()),",
    ),
    "TheLogPlacesEveryRunFirst": (
        "src/store/redb.rs",
        "redb_satisfies_the_journal_store_contract",
        "the one-pass log walk places every sealed run at index 0, so an export stamps each run block with a position the Merkle log does not hold and the verifier reports tampering",
        "                    *slot = Some((rank, digest(head)?));",
        "                    *slot = Some((0, digest(head)?));",
    ),
    "TheInFlightWalkPagesByActivity": (
        "src/export.rs",
        "a_run_writing_during_the_in_flight_walk_is_still_listed",
        "the in-flight walk pages by last activity, so a run that appends during the walk jumps above the cursor and an export taken for recovery silently lacks it",
        "    let mut after: Option<RunId> = None;\n    while found.runs.len() < limit {\n        let page = store.runs_by_id(after, CASE_PAGE).await?;\n        if page.is_empty() {\n            break;\n        }\n        after = page.last().copied();\n",
        "    let mut after: Option<(u64, RunId)> = None;\n    while found.runs.len() < limit {\n        let rows = store.recent_runs(after, CASE_PAGE).await?;\n        if rows.is_empty() {\n            break;\n        }\n        after = rows.last().map(|(run, at)| (*at, *run));\n        let page: Vec<RunId> = rows.into_iter().map(|(run, _)| run).collect();\n",
    ),
    "ARestoreAppendsToARunItAlreadyHolds": (
        "src/export.rs",
        "a_restore_refuses_a_store_already_holding_one_of_its_runs",
        "a restore checks a held run only when it reaches it, so a file whose later run the store already holds is refused after its earlier runs were written — a partial restore behind the refusal",
        "        if store.head(run.run).await?.seq != 0 {",
        "        if store.head(run.run).await?.seq != 0 && false {",
    ),
    "ARestoreTrustsTheHashItRebuilt": (
        "src/export.rs",
        "a_restore_refuses_a_record_that_rebuilds_to_another_hash",
        "a restore never compares a rebuilt record's hash with the file's, so an open run a store kept differently from what it was handed restores silently — no leaf covers it",
        "                if written.hash != *want {",
        "                if written.hash != *want && false {",
    ),
    "ASealedJournalLendsNoTransaction": (
        "src/keyring/journal.rs",
        "a_sealed_journal_commits_a_co_located_resource_sealed",
        "a sealed journal answers that it has no transaction, so every atomic group on a sealed Postgres plane is refused at registration as if the backend were embedded",
        "        self.inner.atomic().map(|_| self as &dyn AtomicJournal)",
        "        None",
    ),
    "ASealedWriteReopensWhatItSealed": (
        "src/keyring/journal.rs",
        "a_sealed_append_hands_back_what_it_was_given_without_the_ring",
        "a sealed append re-opens every payload it just sealed after the commit, so a key service failing in between reports a committed write as a backend error and the caller retries a write that landed",
        "        let written = self.inner.append(epoch, sealed).await?;\n        self.reopened(written, plain).await",
        "        let written = self.inner.append(epoch, sealed).await?;\n        drop(plain);\n        self.open_all(written).await",
    ),
    "NoCaseBlocksReadsAsNoCases": (
        "src/export.rs",
        "a_dropped_case_layer_is_a_finding_not_a_quiet_file",
        "a file whose records name cases and which carries no case block at all, with a trailer claiming none, is filed as not checked rather than as a finding, so a stripped case layer reads as a plane that had no cases",
        "    for case in stamped.difference(carried) {",
        "    if carried.is_empty() {\n        return;\n    }\n    for case in stamped.difference(carried) {",
    ),
    "AForeignCanonIsCheckedAnyway": (
        "src/export.rs",
        "a_foreign_canon_rule_is_unverifiable_not_a_finding",
        "the offline pass reads past a header naming a canon this build does not implement and rehashes every record with its own algorithm, so a file from another build reads as tampered",
        "                if report.unverifiable.is_some() {\n                    return Ok(report);\n                }\n",
        "",
    ),
    "AnUnverifiableExportIsAFinding": (
        "src/bin/agentplane.rs",
        "the_exit_statuses_are_one_table",
        "verify exits 1 for an export under a canon this build does not implement, so a script pages somebody about tampering where there is only another build",
        "    } else if report.unverifiable.is_some() {\n        exit::UNVERIFIABLE",
        "    } else if report.unverifiable.is_some() {\n        exit::FINDING",
    ),
    "AHoldReadsPastAMemberItDoesNotKnow": (
        "src/core/case.rs",
        "a_legal_hold_survives_export_and_restore",
        "a legal hold carrying a member this build does not know is read anyway, so the Rust reader passes a case block the second reader refuses",
        "#[serde(deny_unknown_fields)]\npub struct LegalHold {",
        "pub struct LegalHold {",
    ),
    "AnUnconcludedRunIsSealed": (
        "src/store/redb.rs",
        "redb_satisfies_the_journal_store_contract",
        "the embedded store seals a run with no records or one still mid-flight, so the log commits the zero digest or freezes a history that never ended",
        "    if kind.as_deref() == Some(\"RunConcluded\") {",
        "    if kind.as_deref() != Some(\"never\") {",
    ),
    "AnUnconcludedRunIsSealedOnPostgres": (
        "src/store/postgres.rs",
        "postgres_satisfies_the_journal_store_contract",
        "the shared store seals a run with no records or one still mid-flight, so the log commits the zero digest or freezes a history that never ended",
        "            Some(row) if row.get::<_, String>(1) == \"RunConcluded\" => {",
        "            Some(row) => {",
    ),
    "NonUtf8TextStaysSealedUncounted": (
        "src/keyring/journal.rs",
        "a_text_payload_that_opens_to_non_utf8_is_an_error",
        "a sealed text field whose plaintext is not UTF-8 is silently left sealed and counted neither opened nor erased, so a reader cannot tell it from an erasure it did not count",
        "                        *field = String::from_utf8(plain).map_err(|e| {",
        "                        let kept = field.clone();\n                        *field = String::from_utf8(plain).or_else(|_| Ok(kept)).map_err(|e: std::string::FromUtf8Error| {",
    ),
    "ANoOpResumeWritesAPassMarker": (
        "src/runtime/executor.rs",
        "a_no_op_resume_under_a_quota_repeats_no_conclusion",
        "a resume writes its quota pass marker before it knows it will write anything, so a resume reaching the conclusion the record holds leaves a marker as the run's last record and every status reader reports a failed run as still working",
        "        let through = self.marking_pass(run, &quota);",
        "        if let Some(marker) = quota.started() {\n            self.store.append(lease.expect(\"resume holds a lease\").epoch, vec![Append::new(run, marker)]).await.map_err(RuntimeError::from_store)?;\n        }\n        let through = self.marking_pass(run, &quota);",
    ),
    "AMixedReadySetStopsBeforeItReplays": (
        "src/runtime/executor.rs",
        "a_stop_on_a_mixed_ready_set_unwinds_with_the_recorded_outputs",
        "a resume whose ready set holds a recorded success beside new work checks for a stop before the recorded step replays, so the unwind hands its compensation null for the output it undoes",
        "                && ready.iter().any(|s| succeeded.contains(s))\n                && ready.iter().any(|s| !succeeded.contains(s))",
        "                && ready.is_empty()\n                && ready.iter().any(|s| !succeeded.contains(s))",
    ),
    "ARestoreReSealsWhatItRestores": (
        "src/export.rs",
        "a_restore_refuses_a_sealing_target_before_writing",
        "a restore into a journal that seals as it writes is refused only by the journal's own append, which says that a sealed journal cannot store written bytes rather than what the target is and that the unwrapped store is then opened with the keyring",
        "    if store.seals() {",
        "    if store.seals() && store.tenant().is_empty() {",
    ),
    "ASealedJournalStoresWrittenBytes": (
        "src/keyring/journal.rs",
        "a_sealed_journal_refuses_written_bytes",
        "a restored append into a sealed journal is stored as its bytes stand, so a payload from a plaintext export sits readable in a store whose every other record is sealed",
        "            if entry.written().is_some() {",
        "            if entry.written().is_some() && entry.case.is_some() {",
    ),
    "AnIndexTrustsTheCallersBody": (
        "src/journal/record.rs",
        "a_restored_append_is_indexed_by_its_bytes",
        "a store indexes a restored append by its public fields, which a caller can change after Append::restored, so the by-case, exactly-once, admission and outcome indexes describe a record its own bytes contradict",
        "        Ok((body, Some(raw)))",
        "        Ok((fields, Some(raw)))",
    ),
    "ASealKeepsBytesNamingAnotherPosition": (
        "src/journal/record.rs",
        "a_store_refuses_written_bytes_naming_another_position",
        "a store files written bytes naming seq 1 at seq 2, so the record's own body contradicts the chain position it is stored and read under",
        "        if body.seq != seq || body.epoch != epoch || body.run != fields.run {",
        "        if body.epoch != epoch || body.run != fields.run {",
    ),
    "ARestoreKeepsNonCanonicalBytes": (
        "src/export.rs",
        "non_canonical_record_bytes_are_refused_and_reported",
        "a restore stores record bytes that hash to their claim and are not canonical, so the store holds a record no writer under the export's canon produces",
        "        .is_ok_and(|value| crate::core::canon::value_bytes(&value) != raw)",
        "        .is_ok_and(|value| crate::core::canon::value_bytes(&value) != raw && raw.is_empty())",
    ),
    "AVerifyPassesNonCanonicalBytes": (
        "src/export.rs",
        "non_canonical_record_bytes_are_refused_and_reported",
        "verify passes record bytes that hash to their claim and are not canonical, and names a member written twice a build skew",
        "        .is_ok_and(|wire| crate::core::canon::value_bytes(&wire) != raw_bytes)",
        "        .is_ok_and(|wire| crate::core::canon::value_bytes(&wire) != raw_bytes && raw_bytes.is_empty())",
    ),
    "ACaselessPlaneFailsARecordedStop": (
        "src/runtime/executor.rs",
        "a_caseless_plane_records_a_stop_for_a_case_bound_run",
        "a plane with no case store records an operator's stop for a case-bound run and then reports it as failed, though the plane with the case store will honour it",
        "                    | RuntimeError::NoCaseStore { .. }\n                    | RuntimeError::PayloadsSealed { .. },\n                ) => {}",
        "                    | RuntimeError::PayloadsSealed { .. },\n                ) => {}",
    ),
    "ThePlanesOwnChainBarsItsOperator": (
        "src/runtime/ctx.rs",
        "the_planes_own_principal_may_approve_a_run_the_embedder_started",
        "four-eyes bars the principals of the plane's own chain from a run the embedder started, so the operator whose identity is the plane's root can approve none of the plane's tasks",
        "            Some(c) if !self.plane_chain().await? => {",
        "            Some(c) => {",
    ),
    "ACallerWithThePlanesChainIsThePlane": (
        "src/runtime/executor.rs",
        "a_caller_presenting_the_planes_chain_cannot_approve_its_run",
        "whether a run acts as the plane is read off the chain it holds, so a served caller presenting a chain equal to the plane's approves the run it asked for",
        "            plane_chain: matches!(acting_as, Acting::Plane) && self.identity.is_some(),",
        "            plane_chain: self.identity.is_some() && acting_as.resolve(self.identity.as_ref()) == self.identity.as_ref(),",
    ),
    "AForeignCanonRestoreIsAnOutage": (
        "src/bin/agentplane.rs",
        "the_exit_statuses_are_one_table",
        "restore reads past a header naming a canon this build does not implement and fails through the general error path, so a script pages the store's owner about an outage where there is only another build",
        "    agentplane::export::foreign_canon(&header)",
        "    agentplane::export::foreign_canon(&header).filter(|_| header.is_empty())",
    ),
    "RestoreReadsCanonBeforeKind": (
        "src/export.rs",
        "the_exit_statuses_are_one_table",
        "restore reads a canon off a first line that is no export header, or one of another format version, and exits unverifiable where verify reports a finding",
        "    if !ours {",
        "    if false {",
    ),
    "AForeignTenantCredentialIsAParameterError": (
        "src/api/a2a.rs",
        "a_peer_cannot_name_a_tenant_its_credential_does_not_hold",
        "a credential for another tenant is answered HTTP 200 with a parameter error, so the client reads a malformed request and retries it with the same credential rather than being told to authenticate",
        "            return Err(RpcError::unauthenticated(\n                crate::api::AuthError::Rejected.to_string(),",
        "            return Err(RpcError::new(\n                code::INVALID_PARAMS,\n                crate::api::AuthError::Rejected.to_string(),",
    ),
    "AForeignTenantRefusalNamesTheTenant": (
        "src/api/a2a.rs",
        "a_peer_cannot_name_a_tenant_its_credential_does_not_hold",
        "a credential for another tenant is refused in words of its own, which tells a prober the token is valid elsewhere",
        "                crate::api::AuthError::Rejected.to_string(),\n            ));\n        }\n        Ok(caller)",
        "                \"this endpoint does not serve your tenant\",\n            ));\n        }\n        Ok(caller)",
    ),
    "ASealedPlaneMissesTheIndex": (
        "src/runtime/executor.rs",
        "a_sealed_planes_subject_erasure_reaches_the_semantic_index",
        "the plane wraps its index around a sealed memory store, so the store's own subject erasure runs beneath the wrapper and leaves the person's embeddings in the index",
        "                None if memories.seals() => {",
        "                None if memories.seals() && memories.tenant().is_empty() => {",
    ),
    "AnIndexElsewhereIsCalledASeal": (
        "src/runtime/executor.rs",
        "a_store_indexed_elsewhere_is_refused_as_such",
        "a plane refuses an unsealed store that tells another index as a sealed store missing its index, so the operator is sent to rewire a seal that does not exist",
        "                Some(_) => return Err(BuildError::MemoryIndexedElsewhere),",
        "                Some(_) => return Err(BuildError::SealedMemoryMissesIndex),",
    ),
    "ARefusedKeyDestructionIsDropped": (
        "src/keyring/memory.rs",
        "a_key_the_ring_refused_after_an_expiry_is_destroyed_later",
        "a key the ring refuses after an expiry or cascade erased its rows is forgotten, so no retry finds it and every backup of the erased version still opens",
        "        let mut owed = self.owed.lock().await;",
        "        let mut owed: Vec<OwedKey> = Vec::new();\n        let _ = &self.owed;",
    ),
    "ASealDoesNotSayWhatItsErasureReaches": (
        "src/keyring/memory.rs",
        "a_sealed_planes_subject_erasure_reaches_the_semantic_index",
        "a sealed memory store does not report the index beneath it, so the composition whose subject erasure reaches the index is refused with the one that misses it",
        "        self.inner.erasure_index()",
        "        None",
    ),
    "ANoLedgerPlaneRefusesEveryPass": (
        "src/runtime/executor.rs",
        "a_plane_with_no_ledger_resumes_what_no_pass_billed",
        "a plane with no quota store refuses every run whose admission opened a pass, so it cannot resume anything a plane with the default unlimited ledger admitted",
        "                    RecordKind::QuotaPassStarted {\n                        period: Some(_),\n                        ..\n                    }",
        "                    RecordKind::QuotaPassStarted { .. }",
    ),
    "AConclusionAfterTheMarkerNamesTheHeadBeforeIt": (
        "src/runtime/pass_journal.rs",
        "a_resume_that_only_concludes_names_the_head_it_sits_on",
        "a resume whose first write is its conclusion keeps the head it read before the pass marker landed, so a sound recovered run audits and verifies as a conclusion drawn over another history",
        "                && *chain_head == marker.prev_hash",
        "                && *chain_head == marker.hash",
    ),
    "ASealedRunKeepsItsSlot": (
        "src/runtime/executor.rs",
        "a_sealed_run_still_holding_a_slot_is_released",
        "a run sealed by a plane with no quota store keeps its admission slot in the ledger forever, since no resume or recovery selects a sealed run again",
        "            if sealed.is_none() {",
        "            if sealed.is_some() {",
    ),

    # ── A checkpoint that says when it was seen ─────────────────────────────
    "ACosignatureForgetsItsTime": (
        "src/journal/witness.rs",
        "a_cosignature_carries_the_time_its_signature_covers",
        "the cosignature getter reports a time other than the one its witness "
        "signed, so every freshness judgement measures from a number nobody's "
        "signature covers",
        """            .filter(|time| *time != 0)""",
        """            .map(|_| 1)""",
    ),
    "AnIdleLogIsNeverResubmitted": (
        "src/runtime/sweeper.rs",
        "an_unchanged_log_is_resubmitted_once_the_interval_passes",
        "the declared checkpoint interval is never reached, so an idle plane is "
        "never re-submitted and its witnesses' latest time goes stale while it "
        "is healthy",
        """            (Some(interval), Some(last)) => now - last < interval,""",
        """            (Some(_), Some(_)) => true,""",
    ),
    "AnIntervalWithoutWitnessesIsAccepted": (
        "src/runtime/executor.rs",
        "an_interval_without_witnesses_is_refused_at_build",
        "a checkpoint interval with no witness to submit to builds, so a "
        "declared interval is a promise nothing keeps",
        """            return Err(BuildError::IntervalWithoutWitnesses);""",
        """            let _ = BuildError::IntervalWithoutWitnesses;""",
    ),
    "FreshnessIsNotCompared": (
        "src/audit.rs",
        "a_stale_witness_is_a_finding_and_a_fresh_one_is_not",
        "a witness key older than the auditor's maximum age is not a finding, "
        "so a plane that went silent audits clean",
        """        } else if age > max_age {""",
        """        } else if false {""",
    ),
    "AnIntervalShorterThanTheSweepIsAccepted": (
        "src/bin/agentplane.rs",
        "serve_refuses_an_interval_shorter_than_its_sweep",
        "serve accepts a checkpoint interval shorter than the sweep that keeps "
        "it, so the declared interval is one the plane cannot meet",
        """        if sweep != 0 && secs < u64::from(sweep) {""",
        """        if false {""",
    ),
    "ServeSubmitsToNoWitness": (
        "src/bin/agentplane.rs",
        "serve_wires_its_submission_witnesses_into_the_sweep",
        "serve parses its submission witnesses and never hands them to the "
        "plane, so its sweep submits to nobody",
        """    let mut builder = builder.witnesses(witnesses, quorum);""",
        """    let mut builder = {
        let _ = (witnesses, quorum);
        builder
    };""",
    ),

    # ── A verdict bound to the trajectory it was reached from ───────────────
    "AGraderVerdictLastHashIsNotCompared": (
        "src/grader_verdict.rs",
        "a_grader_verdict_over_an_edited_prefix_is_refused_naming_the_last_hash",
        "a sidecar is not held to the hash of the record it names, so a verdict "
        "reached over one history stays bound after the records it judged are "
        "rewritten and re-linked",
        """    if at.hash != sidecar.last_hash {""",
        """    if false {""",
    ),
    "AGraderVerdictSeqFallsBackToTheLastRecord": (
        "src/grader_verdict.rs",
        "a_grader_verdict_past_the_last_record_present_is_refused",
        "a sidecar naming a seq the export does not hold is read against the "
        "run's last record instead, so a verdict about records nobody can show "
        "binds to whatever the file ends with",
        """    let Some(at) = records.iter().find(|r| r.body.seq == sidecar.last_seq) else {""",
        """    let Some(at) = records.iter().find(|r| r.body.seq == sidecar.last_seq).or(records.last()) else {""",
    ),
    "AClosedGraderVerdictIsNotHeldToTheSeal": (
        "src/grader_verdict.rs",
        "a_grader_verdict_claiming_a_sealed_run_is_refused_over_a_prefix_or_an_open_run",
        "a sidecar claiming a sealed run is bound over a prefix or an unsealed "
        "run, so a verdict about part of a run reads as a verdict about all of it",
        """    if !sidecar.open && (!*sealed || last != sidecar.last_seq) {""",
        """    if false {""",
    ),
    "AGraderVerdictIsBoundBeforeTheChainVerifies": (
        "src/grader_verdict.rs",
        "no_grader_verdict_is_bound_over_a_run_whose_chain_is_broken",
        "a sidecar is checked against a run whose chain does not verify, so a "
        "binding to bytes nobody can vouch for reads as a binding",
        """    };
    if !report.sound.contains(&run) {
        return refuse(""",
        """    };
    if false {
        return refuse(""",
    ),
    "AGraderVerdictSignatureIsNotChecked": (
        "src/grader_verdict.rs",
        "a_grader_verdict_signed_by_an_untrusted_key_is_refused",
        "a grader signature is never verified, so any key id on any sidecar "
        "reads as the trusted grader's",
        """    if !graders.verify(""",
        """    if false && !graders.verify(""",
    ),
    "TheBinderCallsEveryRunSealed": (
        "src/grader_verdict.rs",
        "a_bound_grader_verdict_over_an_open_run_states_it_open_and_verifies",
        "the binder states every run sealed, so a verdict over an unfinished "
        "run claims to be about the whole of it",
        """    let open = !(*sealed && last_seq == last);""",
        """    let open = !(*sealed || last_seq == last);""",
    ),
    "TheSubjectReportListsEveryOutboundEffect": (
        "src/subject.rs",
        "a_subject_report_lists_only_the_subjects_effects",
        "the report drops its provenance filter, so every outbound effect reads as "
        "carrying the subject's data",
        """.filter(|(source, _)| names(label, source))""",
        """.filter(|_| true)""",
    ),
    "TheSubjectReportMatchesByPrefix": (
        "src/subject.rs",
        "a_source_that_merely_contains_the_id_is_not_traced",
        "the join matches any source starting with the item's, so another item's "
        "effects are listed under this subject",
        """    label.provenance.contains(source)""",
        """    label.provenance.iter().any(|p| p.0.starts_with(source.0.trim_end_matches('x')) || p.0.contains(source.0.trim_start_matches("memory:")))""",
    ),
    "TheCoverageListOmitsAClass": (
        "src/subject.rs",
        "every_untraced_class_is_named_in_coverage",
        "a class the report cannot trace is missing from its coverage list, so an "
        "untraced flow reads as one that did not happen",
        """        Self::CodedStep,\n""",
        "",
    ),
    "TheCoverageNeverMarksATrustedItem": (
        "src/subject.rs",
        "every_untraced_class_is_named_in_coverage",
        "a trusted item, whose recall leaves no source in any label, never marks "
        "its class met, so the gap it opens is not flagged on the report it opens",
        """Class::TrustedItem => items.iter().any(|i| i.trust == Some(Trust::Trusted)),""",
        """Class::TrustedItem => items.iter().any(|i| i.trust == Some(Trust::Untrusted)) && false,""",
    ),
    "TheSubjectReportForgetsTheSubject": (
        "src/subject.rs",
        "a_subject_report_changes_no_store",
        "the read-only report erases the subject's memory after selecting it",
        """        let ids = memories.subject_ids(subject).await?;\n""",
        """        let ids = memories.subject_ids(subject).await?;\n        memories.forget_subject(subject).await?;\n""",
    ),
    "TheAdmittedInputForgetsItsSubject": (
        "src/runtime/executor.rs",
        "a_subject_named_by_run_input_is_traced_to_the_tool_it_reached",
        "a bound run's input carries no reference to its binding, so the effects "
        "its input reached are listed for nobody",
        """        let input = input.attributed(&subjects);""",
        """        let input = input.attributed(&BTreeSet::new());""",
    ),
    "SubjectReferencesRideInProvenance": (
        "src/core/label.rs",
        "an_allowed_sources_field_answers_the_same_for_a_subject_bound_value",
        "a subject binding lands in provenance, so every field allowed only from "
        "its sender refuses every subject-bound value",
        """        self.label.data_subjects.extend(subjects.iter().copied());""",
        """        self.label.provenance.extend(subjects.iter().map(|r| SourceId::new(format!("subject:{}", r.index))));""",
    ),
    "ThePolicyContextCarriesSubjects": (
        "src/core/label.rs",
        "a_cedar_context_label_carries_no_subject_references",
        "the policy context carries subject references, so a bound run's request "
        "differs from the same request unbound and a strict schema refuses it",
        """        label.data_subjects.clear();""",
        """        let _ = &mut label;""",
    ),
    "TheEffectArgsCarrySubjects": (
        "src/policy/requests.rs",
        "a_cedar_context_args_label_carries_no_subject_references",
        "a label embedded in an effect's arguments keeps its subject references, "
        "so `task.open`'s justification puts them in front of every rule",
        """                map.remove("data_subjects");""",
        """                let _ = map.get("data_subjects");""",
    ),
    "TheJoinForgetsItsDataSubjects": (
        "src/core/label.rs",
        "the_join_is_a_bounded_semilattice_over_the_whole_domain",
        "a join keeps only one side's subject references, so a value built from "
        "a bound input is attributed to nobody",
        """                .union(&other.data_subjects)\n""",
        """                .union(&self.data_subjects)\n""",
    ),
    "TheSubjectLivesOnlyInTheLiveProcess": (
        "src/runtime/executor.rs",
        "a_bound_run_resumed_in_a_new_process_keeps_its_subject",
        "a resumed run does not read its references back from `DataSubjectBound`, "
        "so what it does after the resume is listed for nobody",
        """                subjects: recorded_subjects(run, &records),""",
        """                subjects: BTreeSet::new(),""",
    ),
    "AnInboundEventForgetsTheRunsSubject": (
        "src/runtime/ctx.rs",
        "an_event_forwarded_by_a_bound_run_is_traced",
        "an event delivered to a bound run is not attributed to its subject, so "
        "an effect forwarding it is listed for nobody",
        """        Tainted::with_label(payload, label).attributed(&self.subjects)""",
        """        Tainted::with_label(payload, label)""",
    ),
    "ACaseStateReadForgetsTheRunsSubject": (
        "src/runtime/ctx.rs",
        "case_state_forwarded_by_a_bound_run_is_traced",
        "case state read by a bound run is not attributed to its subject, so an "
        "effect forwarding it is listed for nobody",
        """        let state = Tainted::with_label(snapshot.state, label).attributed(&self.subjects);""",
        """        let state = Tainted::with_label(snapshot.state, label);""",
    ),
    "AnUnresolvedSubjectFallsBackToNone": (
        "src/runtime/executor.rs",
        "a_subject_binding_that_cannot_resolve_fails_the_run",
        "a binding that selects nothing is skipped, so a declared run is admitted "
        "attributed to nobody",
        """                    return Err(refuse(&binding, "it selects nothing in the run's input"));""",
        """                    continue;""",
    ),
    "ARefusedSubjectOpensACase": (
        "src/runtime/executor.rs",
        "a_refused_subject_binding_opens_no_case",
        "the run is correlated before its bindings resolve, so every message its "
        "agent cannot read a subject from opens a case nothing ever runs in",
        """        let bound = bind_subjects(&declared, subjects, &input, case.is_some())?;""",
        """        if let (Some(CaseBinding::Correlate { kind, keys }), Some(cases)) = (&case, self.cases.as_ref()) {
            cases.correlate_or_open(kind, keys, now_for_admission()).await.map_err(RuntimeError::from_store)?;
        }
        let bound = bind_subjects(&declared, subjects, &input, case.is_some())?;""",
    ),
    "AnUnboundSubjectIsAServerFault": (
        "src/api/a2a.rs",
        "a_message_with_no_data_subject_is_invalid_params_and_opens_no_case",
        "a message its agent cannot read a data subject from is answered "
        "`-32603 Internal error`, so the caller retries a message that is refused "
        "every time",
        """        // reads its data subject from, and the same message is refused again.
        Err(e @ crate::core::RuntimeError::SubjectUnbound { .. }) => {""",
        """        // reads its data subject from, and the same message is refused again.
        Err(e @ crate::core::RuntimeError::SubjectUnbound { .. }) if false => {""",
    ),
    "AnUnboundSubjectIsAServerFaultWhenImmediate": (
        "src/api/a2a.rs",
        "a_message_with_no_data_subject_is_invalid_params_and_opens_no_case",
        "`returnImmediately` answers a message with no data subject as a server "
        "fault while the blocking send answers it as invalid params",
        """            Err(e @ crate::core::RuntimeError::SubjectUnbound { .. }) => Err(subject_unbound(&e)),""",
        """            Err(e @ crate::core::RuntimeError::SubjectUnbound { .. }) if false => Err(subject_unbound(&e)),""",
    ),
    "AnUnboundSubjectIsAServerFaultWhenStreamed": (
        "src/api/a2a.rs",
        "a_message_with_no_data_subject_is_invalid_params_and_opens_no_case",
        "a streamed message with no data subject is answered as a server fault "
        "while the blocking send answers it as invalid params",
        """                Err(e @ crate::core::RuntimeError::SubjectUnbound { .. }) => {
                    return Err(subject_unbound(&e));""",
        """                Err(e @ crate::core::RuntimeError::SubjectUnbound { .. }) if false => {
                    return Err(subject_unbound(&e));""",
    ),
    "AnUnboundSubjectExitsAsAnOutage": (
        "src/bin/agentplane.rs",
        "an_unbound_subject_exits_as_usage",
        "`agentplane run` reports an input its agent cannot read a subject from as "
        "an operational failure, so a script retries an input that is refused "
        "every time",
        """        e @ agentplane::core::RuntimeError::SubjectUnbound { .. } => usage(e.to_string()),""",
        """        e @ agentplane::core::RuntimeError::SubjectUnbound { .. } => e.to_string().into(),""",
    ),
    "ALiteralDataSubjectIsAccepted": (
        "src/manifest/binding.rs",
        "a_literal_data_subject_is_refused",
        "a literal data subject parses, so every run's intake is attributed to one "
        "party",
        """            MemorySubject::Literal(_) => Err(format!(""",
        """            MemorySubject::Literal(_) if false => Err(format!(""",
    ),
    "ACorrelationDataSubjectIsAccepted": (
        "src/manifest/binding.rs",
        "a_correlation_data_subject_is_refused",
        "a correlation key parses as a data subject, so the subject is sealed in "
        "one record and left in the clear in every case record, and an erasure "
        "leaves the identifier behind",
        """            MemorySubject::Correlation(_) => Err(format!(""",
        """            MemorySubject::Correlation(_) if false => Err(format!(""",
    ),
    "TheBoundSubjectIsWrittenInTheClear": (
        "src/journal/payload.rs",
        "an_erased_binding_names_nobody_and_leaves_no_subject_in_the_clear",
        "a run's data subject is not sealed, so it survives the erasure of the "
        "run's case in the clear",
        """            .map(|bound| {""",
        """            .filter(|_| false).map(|bound| {""",
    ),
    "TheSubjectReportOmitsBoundRuns": (
        "src/subject.rs",
        "a_subject_report_names_the_runs_an_erasure_acts_on",
        "the report lists no bound run, so an erasure request is not told which "
        "runs and cases hold the subject's journaled data",
        """                                    bound.push(entry);""",
        """                                    drop(entry);""",
    ),
    "TheTraceMatchesOnlyItsOwnRunsReferences": (
        "src/subject.rs",
        "a_child_run_forwarding_a_parents_input_is_traced",
        "a reference is matched only inside the run that bound it, so a "
        "commissioned run forwarding its parent's input is listed for nobody",
        """                            label.data_subjects.intersection(&refs).copied().collect();""",
        """                            label.data_subjects.iter().filter(|r| r.run == run && refs.contains(*r)).copied().collect();""",
    ),
    "ACommissionedAnswerForgetsItsSubjects": (
        "src/runtime/ctx.rs",
        "a_subject_a_commissioned_run_bound_is_traced_in_its_parent",
        "a commissioned answer comes back with its sensitivity and none of its "
        "data-subject references, so what a specialist bound is listed for nobody "
        "past the delegation boundary",
        """            data_subjects: answer.label().data_subjects.clone(),""",
        """            data_subjects: BTreeSet::new(),""",
    ),
    "AHandedRunIsUnboundIngress": (
        "src/subject.rs",
        "a_handed_run_counts_only_once_it_reads_beyond_its_input",
        "a commissioned run handed the subject's references is counted as unbound "
        "ingress though its whole intake is traced, so the class is marked on "
        "every report a delegation appears in",
        """            if admitted && !binds && (!handed_refs || reads_beyond_input) {""",
        """            if admitted && !binds {""",
    ),
    "AHandedRunReadingCaseStateIsTraced": (
        "src/subject.rs",
        "a_handed_run_counts_only_once_it_reads_beyond_its_input",
        "a handed run that reads case state is treated as fully traced, though "
        "that read is attributed to its own bindings and it has none",
        """                    RecordKind::EffectStarted { descriptor, .. }
                        if descriptor.kind == CASE_STATE_READ =>
                    {
                        reads_beyond_input = true;
                    }""",
        """                    RecordKind::EffectStarted { descriptor, .. }
                        if descriptor.kind == CASE_STATE_READ =>
                    {
                        let _ = &mut reads_beyond_input;
                    }""",
    ),
    "ARememberedIntakeIsUnmarked": (
        "src/subject.rs",
        "a_handed_run_counts_only_once_it_reads_beyond_its_input",
        "a memory write by a run taking in the subject is never marked, so data "
        "that left the trace through memory reads as data that went nowhere",
        """                        remembered |= takes_in && descriptor.kind == REMEMBER;""",
        """                        remembered |= false && descriptor.kind == REMEMBER;""",
    ),
    "GrantUseIsCountedByKind": (
        "src/grants.rs",
        "only_the_uncalled_grant_is_unused",
        "any tool call counts as use of every grant, so a grant nobody called "
        "reads as used",
        """    grant == Some(called)""",
        """    let _ = (grant, called);\n    true""",
    ),
    "ASealedCallReadsAsNoCall": (
        "src/grants.rs",
        "every_args_dependent_figure_is_not_derivable_when_sealed",
        "a call whose arguments are sealed reads as no call, so a grant the agent "
        "did use is marked unused and proposed for removal",
        """    } else if unread > 0 {""",
        """    } else if unread > 0 && false {""",
    ),
    "TheProposalAddsAGrant": (
        "src/grants.rs",
        "the_proposal_never_adds_or_widens",
        "the proposal carries a grant the input did not declare, so publishing it "
        "widens the agent's authority",
        """    let mut proposal = manifest.clone();""",
        """    let mut proposal = manifest.clone();\n    proposal.spec.tools.extend(manifest.spec.tools.first().cloned().map(|mut g| {\n        g.reference = \"tool://extra/grant\".into();\n        g\n    }));""",
    ),
    "TheProposalWidensAKeptGrant": (
        "src/grants.rs",
        "the_proposal_never_adds_or_widens",
        "the proposal drops a kept grant's protected fields and approval, so a "
        "narrowing widens what the grants it keeps allow",
        """        manifest: proposal,""",
        """        manifest: {\n            let mut p = proposal;\n            for g in &mut p.spec.tools {\n                g.protected_fields.clear();\n                g.requires_approval = false;\n            }\n            p\n        },""",
    ),
    "TheGrantReportImportsAStore": (
        "src/grants.rs",
        "the_grant_report_imports_no_store_or_client",
        "the export-only report names a store type, which is the first step to the "
        "plane query it stands in for",
        "use std::io::BufRead;\n",
        "use std::io::BufRead;\n#[allow(unused_imports)]\nuse crate::journal::JournalStore;\n",
    ),
    "TheStarterWritesAFixedToken": (
        "src/bin/agentplane.rs",
        "init_serve_writes_three_distinct_accepted_tokens",
        "init --serve writes the same tokens on every machine, so every plane "
        "started from the getting-started page accepts a credential every "
        "reader of this repository can compute",
        """        .try_fill_bytes(&mut bytes)""",
        """        .try_fill_bytes(&mut [0_u8; 0])""",
    ),
    "InitServeOverwritesAnExistingFile": (
        "src/bin/agentplane.rs",
        "init_serve_refuses_and_writes_nothing_when_a_file_exists",
        "init --serve into a directory holding a reviewed file writes the "
        "starter's files around it before stopping, so half a generated plane "
        "sits beside the deployment's own",
        """        .find(|name| dir.join(name).symlink_metadata().is_ok())""",
        """        .find(|name| false && dir.join(name).symlink_metadata().is_ok())""",
    ),
    "TheTokenFileIsWrittenWithTheDefaultMode": (
        "src/bin/agentplane.rs",
        "init_serve_writes_three_distinct_accepted_tokens",
        "the generated token file and the framework token are world-readable, "
        "so any local user can act as the operator",
        """            open.mode(if secret { 0o600 } else { 0o644 });""",
        """            open.mode(0o644);""",
    ),
    "TheStarterCarriesItsOwnPolicy": (
        "src/bin/agentplane.rs",
        "init_serve_writes_the_shipped_policy",
        "init --serve writes a policy of its own rather than the shipped "
        "bundle, so the file CI and the guides reason about is not the one a "
        "plane started from them enforces",
        """    written.create(dir, SERVED_FILES[1], SERVED_POLICY, false)?;""",
        """    written.create(dir, SERVED_FILES[1], "permit(principal, action, resource);\n", false)?;""",
    ),
    "TheBundleGrantsNoIncidentVerb": (
        "examples/serve-policy.cedar",
        "the_shipped_bundle_permits_the_on_call_verbs_to_operators_only",
        "the shipped bundle stops granting the on-call verbs, so a deployment "
        "started from it finds halt, abandon and reconcile denied during the "
        "incident that needs them",
        """@id("on-call verbs")\npermit(""",
        """@id("on-call verbs")\nforbid(""",
    ),
    "TheStatedPathLengthDrifts": (
        "site/content/docs/getting-started.md",
        "the_zero_to_governed_count_is_the_block_it_counts",
        "the getting-started page states a zero-to-governed path length the "
        "block beside it does not hold, so the published figure is one "
        "nothing re-derives",
        """**Six commands** take""",
        """**Seven commands** take""",
    ),
    "AQuickstartImportsThePlane": (
        "examples/frameworks/openai-agents/quickstart.py",
        "every_framework_quickstart_is_wire_level_and_short",
        "a framework quickstart imports a package of this project, so the walk "
        "an adopter copies needs an integration library rather than the wire",
        """from agents.mcp import MCPServerStreamableHttp\n""",
        """from agents.mcp import MCPServerStreamableHttp\nimport agentplane\n""",
    ),
    "ServeAcceptsABareUrl": (
        "src/bin/agentplane.rs",
        "serve_refuses_a_url_that_is_not_the_a2a_endpoint",
        "serve publishes a --url that is not the A2A endpoint on its card, so "
        "every client that follows the card is answered 404",
        """    if url.ends_with("/a2a") {\n        return Ok(url);""",
        """    if true || url.ends_with("/a2a") {\n        return Ok(url);""",
    ),
    "TheStarterPlaneRunsAsRoot": (
        "src/bin/agentplane.rs",
        "init_serve_runs_the_plane_as_the_token_files_owner_and_never_root",
        "init --serve run under sudo writes a compose file that runs the plane "
        "as root",
        """    if uid == 0 {\n        return Err(usage(""",
        """    if false && uid == 0 {\n        return Err(usage(""",
    ),
    "AFailedInitServeLeavesItsFiles": (
        "src/bin/agentplane.rs",
        "a_failed_init_serve_removes_what_it_wrote",
        "init --serve failing partway leaves the files it wrote, and every "
        "re-run is refused over them",
        """        if !self.kept {""",
        """        if false && !self.kept {""",
    ),
    "TheStarterPostgresTrustsTheNetwork": (
        "examples/compose.yaml",
        "init_serve_gives_postgres_a_password_off_the_command_line",
        "the starter's Postgres takes no password, so on Linux any local "
        "process reaches it over the bridge as the superuser",
        """      POSTGRES_PASSWORD_FILE: /run/secrets/postgres_password\n""",
        """      POSTGRES_HOST_AUTH_METHOD: trust\n""",
    ),
    "TheStarterPublishesMcpBeyondLoopback": (
        "examples/compose.yaml",
        "init_serve_gives_postgres_a_password_off_the_command_line",
        "the starter publishes its MCP listener on every interface, so the "
        "machine's network reaches a plane its owner started to try locally",
        '      - "127.0.0.1:8081:8081"',
        '      - "8081:8081"',
    ),
    "TheOperatorCannotListHalts": (
        "examples/serve-policy.cedar",
        "the_shipped_bundle_lets_an_operator_see_what_it_can_stop",
        "the shipped bundle grants the halt switch and not the halt list, so "
        "the on-call person is sent to lift a halt they cannot find",
        """        Action::"api:halt.list",\n""",
        """        // api:halt.list\n""",
    ),
    "APeerDeliversEveryKind": (
        "examples/serve-policy.cedar",
        "the_shipped_bundle_grants_a_peer_no_event_kind",
        "the shipped bundle grants a peer a2a:event.deliver on every kind, so "
        "a peer answers any wait its task reaches, whatever the wait is for",
        """        Action::"a2a:task.continue",\n""",
        """        Action::"a2a:task.continue",\n        Action::"a2a:event.deliver",\n""",
    ),
    "AQuickstartNeedsAModel": (
        "examples/frameworks/langgraph/quickstart.py",
        "every_framework_quickstart_is_wire_level_and_short",
        "a quickstart reads a model name with no default, so the published "
        "keyless block ends in a KeyError",
        """    if not (model := os.environ.get("QUICKSTART_MODEL")):""",
        """    if not (model := os.environ["QUICKSTART_MODEL"]):""",
    ),
    "TheLockMissesAPin": (
        "examples/frameworks/microsoft-agent-framework/requirements.txt",
        "every_framework_quickstart_is_wire_level_and_short",
        "a quickstart pins a version its hashed lock does not, so CI installs "
        "one closure and the requirements name another",
        """a2a-sdk==1.2.1""",
        """a2a-sdk==1.2.0""",
    ),
    "TheBlockNeedsAnUnnamedProgram": (
        "site/content/docs/getting-started.md",
        "the_zero_to_governed_count_is_the_block_it_counts",
        "the zero-to-governed block runs a program the sentence stating what "
        "the machine needs does not name",
        """with `git`, `docker` and `uv`""",
        """with `docker` and `uv`""",
    ),
    # ── The second reader's signatures ──────────────────────────────────────
    "TheSecondReaderAcceptsAnyRecordSignature": (
        "tools/verify_export.py",
        "the_second_reader_checks_every_signature_in_the_signed_golden_artifacts",
        "the second reader counts a record signature as verified without "
        "checking it, so a forged or altered signature passes the reader an "
        "auditor runs without this crate",
        """    if not ed25519_verify(public, record_signing_input(claimed), signature):""",
        """    if not True:""",
    ),
    "TheSecondReaderSignsRecordsWithoutTheDomain": (
        "tools/verify_export.py",
        "the_second_reader_checks_every_signature_in_the_signed_golden_artifacts",
        "the second reader verifies a record signature over the bare chain "
        "hash, so it accepts a signature made for another domain and refuses "
        "every honest one",
        """    return sha256(RECORD_DOMAIN + b"\\x00" + chain_hash)""",
        """    return chain_hash""",
    ),
    "AnUnsignedRecordPassesTheSecondReader": (
        "tools/verify_export.py",
        "the_second_reader_checks_every_signature_in_the_signed_golden_artifacts",
        "with a key supplied, a record with no signature passes the second "
        "reader, so stripping signatures is a way to pass",
        """    if signed is None:
        report.note(f"{where} is absent, inside a verification that required one")
        return""",
        """    if signed is None:
        return""",
    ),
    "TheSecondReaderTriesEveryRecordKey": (
        "tools/verify_export.py",
        "the_second_reader_checks_every_signature_in_the_signed_golden_artifacts",
        "the second reader tries every supplied key instead of the one the "
        "record's key_id names, so a record is attributed to a key that did "
        "not sign it",
        """    public = keys.get(key_id) if isinstance(key_id, str) else None""",
        """    public = next(
        (k for k in keys.values() if ed25519_verify(k, record_signing_input(claimed), signature)),
        None,
    )""",
    ),
    "TheSecondReaderDecodesAKeyAtOrAboveP": (
        "tools/verify_export.py",
        "the_second_readers_self_test_reports_every_case",
        "the second reader decodes a point whose y is at or above p, so a key "
        "spelled y = p + 1 — the identity, written a second way — verifies a "
        "signature RFC 8032 §5.1.3 says must fail to decode",
        """    if y >= ED_P:
        return None""",
        """    if False:
        return None""",
    ),
    "TheSecondReaderDecodesNegativeZero": (
        "tools/verify_export.py",
        "the_second_readers_self_test_reports_every_case",
        "the second reader decodes x = 0 with the sign bit set, so a second "
        "spelling of a point with x = 0 verifies as the first",
        """    if x == 0 and sign == 1:
        return None""",
        """    if False:
        return None""",
    ),
    "TheSecondReaderHonoursAZeroTime": (
        "tools/verify_export.py",
        "the_second_readers_self_test_reports_every_case",
        "the second reader honours a cosignature the witness signed at time 0, "
        "which tlog-witness forbids and the Rust reader refuses, so the two "
        "readers disagree on whether the checkpoint was cosigned",
        """    if timestamp == 0:""",
        """    if False:""",
    ),
    "TheSecondReaderHonoursATimePastTheLargest": (
        "tools/verify_export.py",
        "the_second_readers_self_test_reports_every_case",
        "the second reader honours a cosignature signed at a time above 2^63-1, "
        "which the format refuses and the Rust reader cannot even represent",
        """    if timestamp > LARGEST_TIMESTAMP:""",
        """    if False:""",
    ),
    "AWeakRecordKeyIsTrusted": (
        "src/policy/signing.rs",
        "a_small_order_key_is_not_trusted",
        "a small-order public key is trusted as a record key, so a signature that "
        "verifies under it without anybody's secret makes a forged record read "
        "as signed",
        """        if key.is_weak() {""",
        """        if false {""",
    ),
    "TheSecondReaderAcceptsANonCanonicalS": (
        "tools/verify_export.py",
        "the_second_reader_checks_every_signature_in_the_signed_golden_artifacts",
        "the second reader's Ed25519 accepts S at or above the group order, "
        "so one valid signature has a second spelling the Rust reader refuses",
        """    if s >= ED_L:
        return False""",
        """    if False:
        return False""",
    ),
    "ACosignatureLineMatchesOnNameAlone": (
        "tools/verify_export.py",
        "the_second_reader_checks_every_signature_in_the_signed_golden_artifacts",
        "the second reader honours a note line whose name matches a witness key "
        "and whose key id does not, so the name a line carries — which anybody "
        "can type — is what selects the key",
        """    public = witnesses.get((name, decoded[:4]))""",
        """    public = next((p for (n, _), p in witnesses.items() if n == name), None)""",
    ),
    "TheSecondReaderDropsTheCosignatureTimeLine": (
        "tools/verify_export.py",
        "the_second_reader_checks_every_signature_in_the_signed_golden_artifacts",
        "the second reader verifies a cosignature over the header and body "
        "without the time line, so the signed time is not what the signature "
        "covers and every honest cosignature fails",
        """    return b"cosignature/v1\\ntime " + str(timestamp).encode("ascii") + b"\\n" + body""",
        """    return b"cosignature/v1\\n" + body""",
    ),
    "TheSecondReaderNeverFindsAWitnessStale": (
        "tools/verify_export.py",
        "the_second_reader_checks_every_signature_in_the_signed_golden_artifacts",
        "under --max-checkpoint-age the second reader never finds a witness "
        "older than the maximum, so a log a witness stopped seeing long ago "
        "reads as fresh",
        """        elif age > max_age:""",
        """        elif False:""",
    ),
    "TheSecondReaderJudgesAnUnverifiedTime": (
        "tools/verify_export.py",
        "the_second_reader_checks_every_signature_in_the_signed_golden_artifacts",
        "the second reader judges freshness from the time a note line claims "
        "whether or not its cosignature verified, so anybody who can write a "
        "line makes a stale log read as fresh",
        """        for name, timestamp in anchor.cosigned:
            if name not in latest""",
        """        for name, timestamp in [(n, claimed_time(d)) for n, d in anchor.lines]:
            if timestamp is None:
                continue
            if name not in latest""",
    ),
    "TheSecondReaderAcceptsAnyGraderSignature": (
        "tools/verify_export.py",
        "the_second_reader_checks_every_signature_in_the_signed_golden_artifacts",
        "under --grader-key the second reader holds a sidecar without checking "
        "its signature, so a verdict whose content was swapped after signing "
        "reads as the grader's",
        """    if not ed25519_verify(public, sidecar_signing_input(sidecar), signature):""",
        """    if not True:""",
    ),
    "AFileCheckpointsCosignaturesAreDropped": (
        "src/bin/agentplane.rs",
        "a_cosigned_note_file_names_its_witness_in_verify",
        "verify reads a cosigned note handed as a --checkpoint file and checks "
        "none of its lines, so the Rust reader says nobody vouched for an "
        "anchor the second reader says a witness cosigned",
        """    let cosignatures = agentplane::journal::cosignatures_in(&note, &trusted);""",
        """    let cosignatures: Vec<agentplane::journal::Cosignature> = {
        let _ = (&note, &trusted);
        Vec::new()
    };""",
    ),
    "APackageLeafIsAcceptedWithoutItsPath": (
        "src/export.rs",
        "a_package_with_a_damaged_path_is_not_sound",
        "a disclosure package's leaf is sound whatever its path says, so a run "
        "that is in no history the header names verifies as one of the matter's",
        """        && !leaf_is_proved(seal, pass.index, pass.proof.as_deref(), &report.checkpoint)""",
        """        && !leaf_is_proved(seal, pass.index, pass.proof.as_deref(), &report.checkpoint)
        && false""",
    ),
    "APackageIsHeldToTheWholeLogCount": (
        "src/export.rs",
        "one_matter_verifies_sound_against_an_outside_anchor",
        "a disclosure package is settled by the whole-log count, so every honest "
        "package of one matter reads as runs deleted from the plane",
        """    if report.selection.is_some() {
        settle_package(""",
        """    if false {
        settle_package(""",
    ),
    "APackageProofIsTakenAtTheLiveSize": (
        "src/export.rs",
        "a_package_taken_while_runs_seal_verifies",
        "a package's paths are taken against the live log, so a run sealed while "
        "the file is written makes every path fail against the header's root",
        """                .inclusion_proof_at(run, log_size)""",
        """                .inclusion_proof(run)""",
    ),
    "APackageCarriesEveryCase": (
        "src/export.rs",
        "a_package_carries_only_its_runs_cases",
        "a disclosure package carries every case the plane holds, so the "
        "recipient of one matter receives the account of every other",
        """    if package.is_some() {
        for id in stamped {""",
        """    if false {
        for id in stamped {""",
    ),
    "RestoreReadsAPackage": (
        "src/export.rs",
        "restore_refuses_a_disclosure_package",
        "restore and a strict replay read a package as an export and refuse it "
        "only for its format version, so the operator is told the file is from "
        "another build rather than that it is one matter",
        """            Some(DISCLOSURE_KIND) => return Err(std::io::Error::other(PACKAGE_REFUSED)),""",
        """            Some(DISCLOSURE_KIND) => {}""",
    ),
    "ReadRunsReadsAPackage": (
        "src/export.rs",
        "policy_check_refuses_a_disclosure_package",
        "policy check and grants answer a package as a file that is no export, so "
        "neither says it was handed one matter rather than the plane",
        """            Some(DISCLOSURE_KIND) if !header => {""",
        """            Some(DISCLOSURE_KIND) if false => {""",
    ),
    "APathProvedLeafIsNotSound": (
        "src/export.rs",
        "a_grader_verdict_binds_to_a_disclosed_run",
        "a run proved by its path is left out of the sound list, so no grader's "
        "verdict binds to a disclosed run",
        """        report.sound.push(run);""",
        """        if report.selection.is_none() {
            report.sound.push(run);
        }""",
    ),
    "TheSecondReaderSkipsThePackagePath": (
        "tools/verify_export.py",
        "a_frozen_package_verifies_by_its_paths_in_both_readers",
        "the second reader accepts a package whose path does not prove its leaf, "
        "so the independent reader passes a run in no history the header names",
        """                or not path_proves(leaf_hash(seal), index, log_size, hashes, claimed_root)""",
        """                or False""",
    ),
    "TheInclusionPrefixIgnoresTheSize": (
        "src/store/redb.rs",
        "redb_satisfies_the_journal_store_contract",
        "a proof asked at a past size is taken over the live log, so a path "
        "against an earlier checkpoint fails against that checkpoint's root",
        """            proof: crate::core::merkle::inclusion_proof(prefix, at),""",
        """            proof: crate::core::merkle::inclusion_proof(&leaves, at),""",
    ),
    "TheDisclosureIsDeliveredUnrecorded": (
        "src/disclosure.rs",
        "no_byte_is_emitted_when_the_disclosure_cannot_be_recorded",
        "a package is delivered though its act could not be recorded, so a copy "
        "leaves the plane that no later erasure can name",
        """        .map_err(DiscloseError::Unrecorded)?;""",
        """        .map_or(Ok(()), |_| Ok::<(), DiscloseError>(()))?;""",
    ),
    "AnErasureDoesNotReadTheDisclosureRegister": (
        "src/blob/mod.rs",
        "an_unsealed_disclosure_is_reported_not_reached",
        "an erasure names no disclosure of what it erased, so the operator "
        "believes the obligation discharged while a copy is outside the plane",
        """        .disclosures(cases, runs)""",
        """        .disclosures(&[], &[])""",
    ),
    "RetentionDropsTheDisclosures": (
        "src/retention.rs",
        "a_retention_pass_names_the_disclosures_of_what_it_erased",
        "a retention pass erases a disclosed matter and its report names no copy",
        """                    .extend(n.copies.iter().map(|copy| format!("case {case}: {copy}")));""",
        """                    .extend(n.copies.iter().take(0).map(|copy| format!("case {case}: {copy}")));""",
    ),
    "EveryDisclosureIsReportedSealed": (
        "src/disclosure.rs",
        "an_unsealed_disclosure_is_reported_not_reached",
        "an erasure reports a plaintext copy as sealed, so the operator reads "
        "payloads as unopenable that the recipient holds in the clear",
        """        let reach = if self.sealed {""",
        """        let reach = if true {""",
    ),
    "TheDisclosureListingIgnoresTheRun": (
        "src/disclosure.rs",
        "a_disclosure_is_recorded_with_the_digest_of_what_left",
        "a disclosure is found by its case only, so a case-less run's copy is "
        "named by no erasure and no listing",
        """        self.cases.iter().any(|c| cases.contains(c)) || self.runs.iter().any(|r| runs.contains(r))""",
        """        self.cases.iter().any(|c| cases.contains(c)) || runs.is_empty() && false""",
    ),
    "ASealedPackageIsRecordedClear": (
        "src/export.rs",
        "an_erasure_names_the_disclosure_of_what_it_erased",
        "a sealed plane's package is recorded as plaintext, so its erasure "
        "claims a copy it reaches is out of reach",
        """                            sealed |= found.iter().any(|r| carries_sealed(r.raw()));""",
        """                            sealed |= found.is_empty() && carries_sealed(&[]);""",
    ),
    "ALaterHeaderReChoosesTheRules": (
        "src/export.rs",
        "a_later_header_is_a_finding_and_ignored",
        "a header past the first line is read, so a whole export with runs "
        "removed relabels itself a package and the deletion goes unreported",
        """                if !is_first {
                    report.findings.push(format!(""",
        """                if false {
                    report.findings.push(format!(""",
    ),
    "TheSecondReaderReadsALaterHeader": (
        "tools/verify_export.py",
        "a_later_header_is_a_finding_and_ignored",
        "the second reader names a later header only as an unknown framing line, "
        "so the two readers disagree on why the file is not sound",
        """        if kind in (HEADER_KIND, PACKAGE_KIND):""",
        """        if False:""",
    ),
    "AnIndexWithoutASealPlacesNothingSilently": (
        "src/export.rs",
        "a_block_with_an_index_and_no_seal_is_a_finding",
        "a block claiming a log position with no seal is read as an open run, "
        "so a stripped seal reads as a state rather than a removal",
        """    let malformed = claims_place && placed.is_none();""",
        """    let malformed = false && claims_place && placed.is_none();""",
    ),
    "AStrippedLeafReadsAsAnOpenRun": (
        "src/export.rs",
        "a_concluded_run_without_its_leaf_is_a_finding",
        "a package run whose conclusion seals and whose leaf was removed reads as "
        "open, so the path that would have failed is simply never checked",
        """        && crate::audit::has_sealing_conclusion(&pass.resealed)""",
        """        && crate::audit::has_sealing_conclusion(&pass.resealed)
        && false""",
    ),
    "TheSecondReaderTakesAStrippedLeafAsOpen": (
        "tools/verify_export.py",
        "a_concluded_run_without_its_leaf_is_a_finding",
        "the second reader reads a sealed run with its leaf removed as open, so "
        "the independent reader passes a package whose path was deleted",
        """            if outcome in SEALED_OUTCOMES and run not in leafed:""",
        """            if False:""",
    ),
    "APackageWritesAConclusionWithoutItsLeaf": (
        "src/export.rs",
        "a_package_refuses_a_concluded_run_it_cannot_place",
        "the writer carries a run that sealed after its checkpoint as open, so "
        "an honest package reads to every verifier as a leaf stripped from it",
        """                            if placed.is_none() && crate::audit::has_sealing_conclusion(&found) {""",
        """                            if false && placed.is_none() && crate::audit::has_sealing_conclusion(&found) {""",
    ),
    "ARunCarriedTwiceStaysSound": (
        "src/export.rs",
        "a_repeated_run_or_index_is_a_finding",
        "a run carried in two blocks keeps the sound verdict its first block "
        "earned, so a file offering two histories for one run vouches for one",
        """        report.sound.retain(|run| *run != pass.run);""",
        """        let _ = &report.sound;""",
    ),
    "TheSecondReaderTakesARunTwice": (
        "tools/verify_export.py",
        "a_repeated_run_or_index_is_a_finding",
        "the second reader keys a run's blocks by its id, so a run carried twice "
        "is read as one and the second history overwrites the first",
        """            if str(current_run) in report.blocks:
                report.note(""",
        """            if False:
                report.note(""",
    ),
    "ASelectedCaseMayBeOmitted": (
        "src/export.rs",
        "a_selected_case_the_package_omits_is_a_finding",
        "a package omits a matter its own header names and verifies sound, so a "
        "recipient is told it holds a case the file does not carry",
        """        if !carried.contains(&case) {""",
        """        if false && !carried.contains(&case) {""",
    ),
    "TheSecondReaderIgnoresTheSelection": (
        "tools/verify_export.py",
        "a_selected_case_the_package_omits_is_a_finding",
        "the second reader passes a package that omits a case its header names",
        """    for case in sorted(set(map(str, selected_cases)) - carried):""",
        """    for case in []:""",
    ),
    "ADisclosureIsRecordedForADestinationThatCannotReceive": (
        "src/disclosure.rs",
        "an_unreceivable_destination_is_refused_before_recording",
        "a destination that is a directory is found only at the rename, after "
        "the act is recorded, so the register names a copy that never left",
        """    receivable(destination).map_err(DiscloseError::Write)?;""",
        """    let _ = receivable;""",
    ),
    "APostgresInclusionPrefixIgnoresTheSize": (
        "src/store/postgres.rs",
        "postgres_satisfies_the_journal_store_contract",
        "the shared backend proves at the live size whatever size it is asked "
        "for, so a package path fails against its own header's root — the redb "
        "mutation cannot reach this copy of the rule",
        """            proof: crate::core::merkle::inclusion_proof(prefix, at),""",
        """            proof: crate::core::merkle::inclusion_proof(&leaves, at),""",
    ),
    "AHaltLiftIsNotJournaled": (
        "src/runtime/executor.rs",
        "a_lifted_halt_names_who_lifted_it",
        "lifting a halt removes the row and writes nothing, so who let the work "
        "start again — and the stop they ended — is gone with the row",
        """        let run = self
            .seal_operator_record(
                RecordKind::HaltLifted {
                    scope: scope.key(),
                    by: by.clone(),
                    at,
                    reason: halt.reason.clone(),
                    thrown_by: halt.by.clone(),
                    thrown_at: halt.at,
                },
                None,
                HALT_LIFTED_OUTCOME,
                None,
            )
            .await?;""",
        """        let run = RunId::generate();
        let _ = (by, at);""",
    ),
    "AHoldReleaseIsNotJournaled": (
        "src/runtime/executor.rs",
        "a_released_hold_names_who_released_it",
        "releasing a hold removes the row and writes nothing, so the instruction "
        "that let an erasure reach the matter names nobody",
        """        let run = self
            .seal_operator_record(
                RecordKind::HoldReleased {
                    by: by.clone(),
                    at,
                    placed_by: standing.by.clone(),
                    placed_at: standing.placed_at,
                },
                Some(case),
                HOLD_RELEASED_OUTCOME,
                None,
            )
            .await?;""",
        """        let run = RunId::generate();
        let _ = (by, at, &standing);""",
    ),
    "ASinkContentRuleIsNotEvaluated": (
        "src/runtime/ctx.rs",
        "a_content_rule_refuses_a_value_at_its_sink",
        "a declared content rule is evaluated at the sink and its refusal "
        "discarded, so the value it names is sent",
        """        let refused = outcome.refused.first().cloned();""",
        """        let refused: Option<crate::content::Hit> = None;""",
    ),
    "ARedactedValueIsSentWhole": (
        "src/runtime/ctx.rs",
        "a_redacted_call_sends_and_records_only_the_redacted_bytes",
        "a redaction is computed and the effect is never rebound, so the "
        "value goes out whole while the gates judge the redacted copy",
        """            Some(value) => effect.rebind(value.clone()),""",
        """            Some(_) => true,""",
    ),
    "RedactionIsLiveOnly": (
        "src/runtime/ctx.rs",
        "a_redacted_call_sends_and_records_only_the_redacted_bytes",
        "redaction is applied only where dispatch is live, so a replay keys the "
        "effect over the unredacted value and cannot find the call it recorded",
        """            Some(value) => effect.rebind(value.clone()),""",
        """            Some(value) if self.writes_enabled() => effect.rebind(value.clone()),
            Some(_) => false,""",
    ),
    "APrebuiltSinkSendsUnredacted": (
        "src/runtime/ctx.rs",
        "a_redact_rule_at_a_prebuilt_sink_refuses",
        "an effect that cannot take a redaction is dispatched with the value "
        "the redaction exists to keep from crossing",
        """        if let Some(hit) = refused.or_else(|| redaction.filter(|_| !rebound))""",
        """        if let Some(hit) = refused.or_else(|| redaction.filter(|_| false && !rebound))""",
    ),
    "AContentRefusalReplaysAsADenial": (
        "src/runtime/ctx.rs",
        "a_content_refusal_strict_replays_to_the_same_conclusion",
        "a recorded content refusal replays as an authorization denial, so the "
        "replay ends a run the original answered by asking again",
        """            if action == crate::core::ACTION_EGRESS || action == crate::core::ACTION_CONTENT =>""",
        """            if action == crate::core::ACTION_EGRESS =>""",
    ),
    "AContentRefusalIsNotCounted": (
        "src/runtime/ctx.rs",
        "a_content_refusal_counts_against_the_denial_ceiling",
        "a content refusal is not counted toward max_denials, so a loop may "
        "probe a rule without limit",
        """        if let Err(exceeded) = self.ledger.lock().expect("budget mutex").record_denial() {
            return StepError::Budget(exceeded);
        }
        denial.into()""",
        """        if !matches!(denial, PolicyError::Content { .. })
            && let Err(exceeded) = self.ledger.lock().expect("budget mutex").record_denial()
        {
            return StepError::Budget(exceeded);
        }
        denial.into()""",
    ),
    "AClassificationAssignsInsteadOfJoining": (
        "src/core/content.rs",
        "no_content_verdict_lowers_a_label",
        "a classify rule sets the sensitivity it names instead of joining it, "
        "so a rule naming a lower level lowers a secret value's label",
        """    classified.map_or(declared, |raised| declared.max(raised))""",
        """    classified.map_or(declared, |raised| raised)""",
    ),
    "TheTagBlockIsNotHidden": (
        "src/core/visible.rs",
        "the_invisible_matcher_refuses_hidden_code_points_and_passes_the_named_residue",
        "the tag characters drop out of the hidden set, so text a model reads "
        "and a reviewer cannot see passes an invisible rule",
        """            | 0xE0000..=0xE007F
""",
        "",
    ),
    "TheMatchIsNamedInTheReason": (
        "src/content/mod.rs",
        "no_content_refusal_records_the_matched_text",
        "a content refusal's pointer carries the matched text, so the record "
        "of a refusal holds what the rule refused to let cross",
        """                        pointer: shown.to_owned(),""",
        """                        pointer: text.to_owned(),""",
    ),
    "ASourceVerdictIsNotRecorded": (
        "src/runtime/ctx.rs",
        "a_source_escalation_survives_strict_replay_without_the_rule",
        "the verdict a source rule reached is not written beside the output, so "
        "a replay labels the value as if no rule had matched",
        """                            declared: crate::core::DeclaredOutput::of(effect),
                            content: content.clone(),""",
        """                            declared: crate::core::DeclaredOutput::of(effect),
                            content: None,""",
    ),
    "ASourceClassificationIsNotJoined": (
        "src/runtime/ctx.rs",
        "a_source_escalation_survives_strict_replay_without_the_rule",
        "a source rule's classification is recorded and not applied, so the "
        "value reaches the next sink at the level its producer declared",
        """                self.source_raise = content.and_then(|c| c.sensitivity);""",
        """                self.source_raise = None;
                let _ = content;""",
    ),
    "ReplayIgnoresTheRecordedVerdict": (
        "src/runtime/ctx.rs",
        "a_replayed_arrival_keeps_its_recorded_label",
        "a replayed output's label ignores the recorded content verdict, so a "
        "replay under a declaration without the rule re-judges the arrival",
        """                declared.sensitivity =
                    crate::core::ContentVerdict::raise(content.as_ref(), declared.sensitivity);
                Ok(Replayed::Answered(""",
        """                Ok(Replayed::Answered(""",
    ),
    "AReplayedSourceRefusalPasses": (
        "src/runtime/ctx.rs",
        "a_source_refusal_is_recorded_beside_the_output_and_replayed",
        "a recorded source refusal is not handed to the step on replay, so the "
        "replay continues past where the run was refused",
        """                self.arrival_refusal(content.as_ref())?;
                declared.sensitivity =""",
        """                declared.sensitivity =""",
    ),
    "ADeliveredEventSkipsSourceRules": (
        "src/runtime/executor.rs",
        "a_source_rule_applies_to_an_event_delivered_while_suspended",
        "an event delivered to a suspended run is recorded unjudged, so the "
        "source rule covers only the event a waiting step claims itself",
        """            let content = self.delivered_verdict(&history, &event.payload);""",
        """            let content: Option<crate::core::ContentVerdict> = None;""",
    ),
    "ABufferedEventSkipsSourceRules": (
        "src/runtime/ctx.rs",
        "a_source_rule_applies_to_an_event_delivered_while_suspended",
        "an event claimed from the buffer is recorded unjudged",
        """            let content = self.source_verdict(AWAIT_KIND, &buffered.event.payload);""",
        """            let content: Option<crate::core::ContentVerdict> = None;""",
    ),
    "AdmissionContentRulesAreSkipped": (
        "src/runtime/executor.rs",
        "an_admission_rule_refuses_hidden_code_points_with_nothing_recorded",
        "admission rules are never evaluated, so a run is admitted over input "
        "a declared rule refuses",
        """        let input = self.admit_content(&agent, input)?;
""",
        "",
    ),
    "ACheckerErrorPasses": (
        "src/runtime/ctx.rs",
        "a_checker_outage_refuses_the_guarded_call",
        "a checker that could not answer is read as one that found nothing, so "
        "an outage of the classifier lets every value through",
        """                Err(StepError::Effect(_) | StepError::Policy(_)) => {
                    Some(crate::core::ContentVerdict {
                        rules: vec![id.clone()],
                        sensitivity: None,
                        refused: Some(crate::core::ContentRefusal {
                            rule: id.clone(),
                            pointer: String::new(),
                        }),
                    })
                }""",
        """                Err(StepError::Effect(_) | StepError::Policy(_)) => None,""",
    ),
    "AnUnregisteredCheckerBuilds": (
        "src/runtime/executor.rs",
        "a_check_naming_an_unregistered_checker_refuses_the_build",
        "a plane builds with a declared check nothing can run, so a reviewer's "
        "control exists only in the file",
        """                Self::check_content_checkers(&self.checkers, m)?;
""",
        "",
    ),
    "ASinkCheckIsNotRun": (
        "src/runtime/ctx.rs",
        "a_checker_outage_refuses_the_guarded_call",
        "the declared checks at a sink are never dispatched, so the classifier "
        "a deployment brought judges nothing",
        """        let (checks, verdict) = self
            .run_checks(crate::content::At::Sink(&kind), sent)
            .await?;""",
        """        let (checks, verdict): (Vec<String>, crate::core::ContentVerdict) =
            (Vec::new(), crate::core::ContentVerdict { rules: Vec::new(), sensitivity: None, refused: None });
        let _ = sent;""",
    ),
    "ASourceCheckIsNotRun": (
        "src/runtime/ctx.rs",
        "a_check_at_a_source_judges_what_the_call_returned",
        "a check declared on a call's output never runs, so what a model "
        "returned flows on at the level its producer declared",
        """        let label = self.checked_arrival(&kind, &output, label).await?;
""",
        "",
    ),
    "ACheckCategoryOutsideTheDeclarationPasses": (
        "src/content/mod.rs",
        "a_checker_outage_refuses_the_guarded_call",
        "a checker reporting a category it never declared is believed, so a "
        "malformed answer is read as a clean one",
        """        if let Some(unknown) = categories
            .iter()
            .find(|c| !self.checker.categories().contains(*c))""",
        """        if let Some(unknown) = categories
            .iter()
            .find(|c| false && !self.checker.categories().contains(*c))""",
    ),
    "ASinkClassificationIsIgnored": (
        "src/runtime/ctx.rs",
        "a_sink_classification_raises_the_label_the_gates_judge",
        "a sink rule that classifies parses and changes nothing, so the label "
        "the gates judge is the one the producer declared",
        """        let classified = [outcome.sensitivity, verdict.sensitivity]""",
        """        let classified = [None, verdict.sensitivity]""",
    ),
    "JoinDropsProvenance": (
        "src/core/label.rs",
        "the_join_is_a_bounded_semilattice_over_the_whole_domain",
        "a join keeps one side's provenance and forgets the other's, so a value "
        "mixed from two sources answers for one",
        """            provenance: self.provenance.union(&other.provenance).cloned().collect(),""",
        """            provenance: self.provenance.clone(),""",
    ),
    "ProjectionTreatsAPrefixAsAnAncestor": (
        "src/core/label.rs",
        "rebase_and_projection_agree_with_the_pointer_model",
        "a projection at `/a` carries a mark on `/ab` down, so a release reaches "
        "a sibling field whose name merely starts the same",
        """            .filter(|rest| rest.starts_with('/'))
            .map(|rest| Self {""",
        """            .filter(|rest| rest.starts_with('/') || !rest.is_empty())
            .map(|rest| Self {""",
    ),
    "CaseStateWriteIgnoresVersion": (
        "src/store/redb_cases.rs",
        "redb_satisfies_the_case_layer_contracts",
        "a case-state write ignores the version it was read at, so of several "
        "runs racing on one case every one wins and all but the last vanish",
        """                    Some((kind, status, _, ver, at)) if ver == expected.0 => {""",
        """                    Some((kind, status, _, ver, at)) if ver == expected.0 || ver != expected.0 => {""",
    ),
    "ForgetLeavesAVersionReadable": (
        "src/store/redb_memory.rs",
        "redb_satisfies_the_memory_store_contract",
        "forgetting a memory removes its current entry and leaves its history "
        "readable by id and version",
        """                for version in doomed {""",
        """                for version in doomed.into_iter().filter(|_| false) {""",
    ),
    "ARetriedErasureRewritesItsReason": (
        "src/testkit/memory_keyring.rs",
        "the_memory_key_ring_satisfies_the_key_ring_contract",
        "a second destruction overwrites the first one's reason, so a retry "
        "rewrites the account of why the data went",
        """            .or_insert_with(|| (at, reason.to_owned()));""",
        """            .and_modify(|first| *first = (at, reason.to_owned()))
            .or_insert_with(|| (at, reason.to_owned()));""",
    ),
    "AConsumedMessageIsClaimedAgain": (
        "src/store/redb_events.rs",
        "redb_satisfies_the_case_layer_contracts",
        "a run's own claim is recovered whether or not its wait consumed it, so "
        "the run's next wait on the same key is handed the first message again",
        """                                .is_some_and(|claimed| claimed.value() == effect);""",
        """                                .is_some_and(|_| true)
                            || (row.3 == 1 && row.7 == run);""",
    ),
    "AnUnsubscribeShedsEveryWait": (
        "src/store/redb_events.rs",
        "redb_satisfies_the_case_layer_contracts",
        "retiring one wait sheds every message its run holds claimed, so a "
        "sibling wait's undelivered message is delivered as null",
        """            shed_claimed(&w, &tenant, &run, Some(&effect))?;""",
        """            shed_claimed(&w, &tenant, &run, None)?;""",
    ),
    "AnInStepClaimLeavesTheWaitMatchable": (
        "src/store/redb_events.rs",
        "redb_satisfies_the_case_layer_contracts",
        "a wait that claimed its message in step stays matchable, so a second "
        "message is claimed for it and discarded by its delivery",
        """                        w.open_table(PARKED)
                            .map_err(|e| be(&e))?
                            .insert((tenant.as_str(), run.as_str(), effect.as_str()), ts(at))
                            .map_err(|e| be(&e))?;
                        let corr_t""",
        """                        let corr_t""",
    ),
    "ARetriedTargetedMessageIsANewTurn": (
        "src/store/redb_events.rs",
        "redb_satisfies_the_case_layer_contracts",
        "a peer's retry of a message the run already consumed is delivered to "
        "the run's next wait as that turn's input",
        """                        (Some(_), None) => false,""",
        """                        (Some(_), None) => true,""",
    ),
    "ADuplicateIsNeverReoffered": (
        "src/runtime/executor.rs",
        "a_retried_delivery_offers_a_message_a_crash_left_unmatched",
        "a counterparty's retry is answered from the dedup alone, so a message "
        "stored by a delivery that died before matching is never offered",
        """        if !fresh && !rematch {""",
        """        if !fresh {""",
    ),
    "ALostDecisionReportsSuccess": (
        "src/runtime/sweeper.rs",
        "a_decision_that_lost_to_the_runs_conclusion_is_refused",
        "a decision that lost to the run's conclusion is reported delivered, so "
        "the decider believes an approval reached a run that never saw it",
        """        if !settled && !matches!(delivery, crate::core::Delivery::Resumed { .. }) {""",
        """        if false && !settled && !matches!(delivery, crate::core::Delivery::Resumed { .. }) {""",
    ),
    "AnAnswerLandsAfterTheConclusion": (
        "src/runtime/executor.rs",
        "a_message_for_a_concluded_run_goes_to_the_live_waiter_behind_it",
        "a delivery appends an answer after a durable conclusion, leaving a run "
        "its seal refuses and a message consumed by nobody",
        """        let closed = resume_is_closed(&history).is_some();""",
        """        let closed = resume_is_closed(&history).is_some() && false;""",
    ),
    "AWakeLandsAfterTheConclusion": (
        "src/runtime/sweeper.rs",
        "a_timer_for_a_concluded_run_finishes_it_rather_than_waking_it",
        "a timer wake is appended after a durable conclusion, leaving a run its "
        "seal refuses",
        """        let closed = super::executor::resume_is_closed(&history).is_some();""",
        """        let closed = super::executor::resume_is_closed(&history).is_some() && false;""",
    ),
    "AClosedRunsUnconsumedMessageIsShed": (
        "src/store/redb_events.rs",
        "redb_satisfies_the_case_layer_contracts",
        "retiring a closed run sheds a message it claimed and never consumed, so "
        "a message that arrived in time is lost to the run that concluded first",
        """            let released = release_claimed(&w, &tenant, &run, &unanswered)?;""",
        """            let released: Vec<InboundEvent> = Vec::new();
            let _ = &unanswered;""",
    ),
    "AParkedWaitClaimsASecondMessage": (
        "src/store/redb_events.rs",
        "redb_satisfies_the_case_layer_contracts",
        "a wait that already holds a targeted message claims a buffered one "
        "beside it, and retiring the wait sheds one of the two unread",
        """                            && ((row.3 == 0 && !parked_here) || own_claim)""",
        """                            && ((row.3 == 0 && (parked_here || !parked_here)) || own_claim)""",
    ),
    "AnAddressedMessageIsOfferedToAnother": (
        "src/store/redb_events.rs",
        "redb_satisfies_the_case_layer_contracts",
        "a message sent to one run by name, which that run never consumed, is "
        "offered to another run waiting on the same key",
        """        if addressed {
            // Its run's alone""",
        """        if addressed && false {
            // Its run's alone""",
    ),
    "TheSweepSkipsUnsealedConclusions": (
        "src/runtime/sweeper.rs",
        "a_lift_concluded_but_not_sealed_is_sealed_by_the_next_sweep",
        "an operator record that concluded and crashed before its seal is never "
        "finished, so it lists as a live run forever",
        """            report.seals_finished = self.seal_unsealed_conclusions(RECOVERY_BATCH).await?;""",
        """            report.seals_finished = 0;""",
    ),
    "TheHoldGoesBeforeTheRecord": (
        "src/runtime/executor.rs",
        "a_lift_whose_record_cannot_be_written_leaves_the_halt_standing",
        "the hold row is removed before the release is recorded, so a journal "
        "that refuses the record leaves the matter erasable with nobody named",
        """            };
        };
        let run = self
            .seal_operator_record(
                RecordKind::HoldReleased {""",
        """            };
        };
        cases.release_hold_if(case, &standing).await.map_err(RuntimeError::Store)?;
        let run = self
            .seal_operator_record(
                RecordKind::HoldReleased {""",
    ),
    "ATerminalReleaseNeedsNoActor": (
        "src/bin/agentplane.rs",
        "a_terminal_lift_without_an_actor_is_refused",
        "a terminal hold release with no --actor is recorded under a placeholder, "
        "so the record that exists to name who released it names nobody",
        """        let by = lifter(opts.actor.as_deref(), "release a hold")?;""",
        """        let by = lifter(opts.actor.as_deref().or(Some("anonymous")), "release a hold")?;""",
    ),
    "TheRowGoesBeforeTheRecord": (
        "src/runtime/executor.rs",
        "a_lift_whose_record_cannot_be_written_leaves_the_halt_standing",
        "the halt row is removed before the lift is recorded, so a journal that "
        "refuses the record leaves the work started again with nobody named",
        """            return Ok(None);
        };
        let run = self
            .seal_operator_record(
                RecordKind::HaltLifted {""",
        """            return Ok(None);
        };
        quotas.lift_halt(scope).await.map_err(RuntimeError::Store)?;
        let run = self
            .seal_operator_record(
                RecordKind::HaltLifted {""",
    ),
    "ALiftReadsBackAsAQuarantine": (
        "src/runtime/executor.rs",
        "every_outcome_this_build_writes_is_one_it_can_read_back",
        "the reader loses the arm for a lift, so a run this plane sealed itself "
        "reads back as quarantined instead of naming who lifted the halt",
        """        HALT_LIFTED_OUTCOME => recorded_halt_lift(records).map_or_else(""",
        """        "never-written-by-this-build" => recorded_halt_lift(records).map_or_else(""",
    ),
    "TheLiftRouteBypassesTheRuntime": (
        "src/api/mod.rs",
        "a_hold_release_and_a_halt_lift_name_who_made_them",
        "the lift route removes the row through the quota store directly, so a "
        "lift over the wire answers with a record that was never written",
        """    let record = s
        .plane
        .lift_halt(&scope, &by, now_for_account())
        .await
        .map_err(|e| control_stands(&e))?;""",
        """    let record = s
        .plane
        .quota_store_if_wired()
        .ok_or_else(|| unavailable("quota"))?
        .lift_halt(&scope)
        .await
        .map_err(|_| store_failed())?
        .then(|| crate::runtime::ControlLifted {
            record: crate::core::RunId::generate(),
            removed: true,
        });""",
    ),
    "ALiftRemovesWhateverStands": (
        "src/runtime/executor.rs",
        "a_halt_rethrown_during_a_lift_still_stands",
        "the lift removes whatever row stands at the scope, so a halt re-thrown "
        "after the lift read the old one is deleted under a record naming the old",
        """            .lift_halt_if(&halt)""",
        """            .lift_halt(scope)""",
    ),
    "ALiftSwallowsARethrow": (
        "src/runtime/executor.rs",
        "a_halt_rethrown_during_a_lift_still_stands",
        "a lift whose conditional removal found a re-thrown halt answers success, "
        "so the operator is told the scope is clear while the new halt stands",
        """            if now.iter().any(|h| &h.scope == scope) {""",
        """            if now.iter().any(|h| &h.scope == scope) && now.is_empty() {""",
    ),
    "ALiftClaimsARemovalItDidNotMake": (
        "src/runtime/executor.rs",
        "a_lift_beaten_by_another_answers_not_removed",
        "a lift another lift beat to the row answers that it removed it, so two "
        "operators are each told they cleared the same halt",
        """                });
            }
        }
        Ok(Some(ControlLifted {
            record: run,
            removed,
        }))""",
        """                });
            }
        }
        let _ = removed;
        Ok(Some(ControlLifted {
            record: run,
            removed: true,
        }))""",
    ),
    "TheRedbConditionalLiftIgnoresTheRow": (
        "src/store/redb_quota.rs",
        "redb_satisfies_the_quota_store_contract",
        "the redb conditional lift removes the row without comparing it, so a "
        "halt re-thrown over the one a lifter read is deleted",
        """                        super::halt_from_row(expected.scope.clone(), row) == expected""",
        """                        let _ = super::halt_from_row(expected.scope.clone(), row);
                        true""",
    ),
    "AStandingControlReadsAsAStoreFailure": (
        "src/api/mod.rs",
        "a_lift_whose_removal_fails_names_the_record_it_wrote",
        "a lift recorded over a row that stayed answers a bare store failure, so "
        "the operator retries without the run that holds the first record",
        """        .map_err(|e| control_stands(&e))?;""",
        """        .map_err(|_| store_failed())?;""",
    ),
    "ATerminalLiftNeedsNoActor": (
        "src/bin/agentplane.rs",
        "a_terminal_lift_without_an_actor_is_refused",
        "a terminal lift with no --actor is recorded under a placeholder, so the "
        "record that exists to name who lifted it names nobody in particular",
        """        let by = lifter(opts.actor.as_deref(), "lift a halt")?;""",
        """        let by = lifter(opts.actor.as_deref().or(Some("anonymous")), "lift a halt")?;""",
    ),
    "TheHaltListingDropsWhoThrewIt": (
        "src/api/mod.rs",
        "the_halt_and_hold_listings_name_who_now_and_before",
        "the standing halt listing answers why and not who, so the person who "
        "finds a plane stopped cannot ask the one person who knows",
        """                reason: halt.reason,
                by: halt.by.actor().to_owned(),""",
        """                reason: halt.reason,
                by: String::new(),""",
    ),
    "TheLiftHistoryIsOldestFirst": (
        "src/runtime/executor.rs",
        "the_halt_and_hold_listings_name_who_now_and_before",
        "the lift history pages oldest first, so once it is longer than a page "
        "the lift that just happened never appears",
        """        self.operator_records(HALT_LIFTED_OUTCOME, limit).await""",
        """        self.operator_records(HALT_LIFTED_OUTCOME, limit)
            .await
            .map(|mut page| {
                page.reverse();
                page
            })""",
    ),
    "AReleaseIsNotInTheMattersHistory": (
        "src/runtime/executor.rs",
        "a_release_record_survives_the_erasure_it_authorized",
        "the release record is not stamped with its case, so the matter's "
        "history — what survives its erasure — lacks the instruction that "
        "permitted the erasure",
        """                Some(case),
                HOLD_RELEASED_OUTCOME,""",
        """                None,
                HOLD_RELEASED_OUTCOME,""",
    ),
    "TheExchangeDropsTheSubject": (
        "src/peers/mod.rs",
        "a_peer_credential_names_the_run_s_subject",
        "the exchange names one fixed subject for every run, so the peer sees "
        "the same caller whoever the run acts for",
        """                subject: chain.owner().id.clone(),""",
        """                subject: "plane".to_owned(),""",
    ),
    "TheCacheKeysOnAudienceAlone": (
        "src/peers/credentials.rs",
        "a_cached_credential_is_never_lent_to_another_subject",
        "the cache holds one credential per audience, so the first person's "
        "credential is served to every later run that calls the same peer",
        """        let key = (audience.clone(), subject.to_owned());""",
        """        let key = (audience.clone(), String::new());""",
    ),
    "TheSubjectIsNotChecked": (
        "src/peers/credentials.rs",
        "a_credential_for_another_subject_is_refused_before_the_call",
        "a credential the issuer minted for somebody else is presented, telling "
        "the peer the call is for a person it is not for",
        """    if credential.subject() != Some(subject) {""",
        """    if credential.subject().is_none() {""",
    ),
    "ASubjectBoundDoorFallsBackToTheStaticCredential": (
        "src/peers/mod.rs",
        "a_chainless_served_run_is_refused_a_subject_bound_peer",
        "a run acting for nobody reaches a subject-bound peer under the "
        "credential held beside the source — the ambient authority the source "
        "was wired to rule out",
        """            Asker::Nobody => Err(PeerError::NoSubject { peer: peer.clone() }),""",
        """            Asker::Nobody => Ok(Presentation::Held(held)),""",
    ),
    "ATaskPollPresentsThePlanesCredential": (
        "src/peers/mod.rs",
        "a_remote_task_poll_names_the_same_subject_as_its_call",
        "a task read presents the credential held for the peer rather than the "
        "run's owner's, so the peer is told nobody asked",
        """    /// Prepare a task read under the same peer grant as the call that
    /// created it, presenting the credential `asker` is owed.
    ///
    /// # Errors
    ///
    /// [`PeerError::Unknown`] for an unregistered peer,
    /// [`PeerError::WrongAudience`] for a held credential bound elsewhere,
    /// and, at a peer with a credential source, [`PeerError::NoSubject`] for
    /// a run acting for nobody and [`PeerError::NoPlaneCredential`] for a run
    /// admitted as the plane with no held credential.
    pub fn prepare(
        registry: &PeerRegistry,
        client: Arc<dyn PeerClient>,
        task: PeerTask,
        asker: Asker<'_>,
    ) -> Result<Self, PeerError> {
        let Some(grant) = registry.grant(&task.peer).cloned() else {
            return Err(PeerError::Unknown { peer: task.peer });
        };
        let presentation = registry.presentation(&task.peer, asker)?;""",
        """    /// Prepare a task read under the same peer grant as the call that
    /// created it, presenting the credential `asker` is owed.
    ///
    /// # Errors
    ///
    /// [`PeerError::Unknown`] for an unregistered peer,
    /// [`PeerError::WrongAudience`] for a held credential bound elsewhere,
    /// and, at a peer with a credential source, [`PeerError::NoSubject`] for
    /// a run acting for nobody and [`PeerError::NoPlaneCredential`] for a run
    /// admitted as the plane with no held credential.
    pub fn prepare(
        registry: &PeerRegistry,
        client: Arc<dyn PeerClient>,
        task: PeerTask,
        asker: Asker<'_>,
    ) -> Result<Self, PeerError> {
        let Some(grant) = registry.grant(&task.peer).cloned() else {
            return Err(PeerError::Unknown { peer: task.peer });
        };
        let _ = asker;
        let presentation = Presentation::Held(registry.credential_for(&task.peer)?.cloned());""",
    ),
    "TheBindingIsNotRecorded": (
        "src/runtime/ctx.rs",
        "a_subject_bound_hop_records_its_subject_and_audience",
        "a hop's announcement no longer says whom its credential named, so a "
        "reader cannot tell a call the peer could check from one it could not",
        """                    credential: effect.credential_binding(),""",
        """                    credential: None,""",
    ),
    "AnIssuerOutageIsInDoubt": (
        "src/peers/mod.rs",
        "an_issuer_outage_fails_the_call_without_doubt",
        "an issuer that could not be reached reads as a call in doubt, and a "
        "mutating peer quarantines over a call that never left",
        """                        Err(EffectError::Unavailable {
                            driver: audience.to_string(),
                            detail,
                        })""",
        """                        Err(EffectError::Interrupted {
                            driver: audience.to_string(),
                            detail,
                        })""",
    ),
    "AWithdrawnSubjectsCredentialIsServed": (
        "src/runtime/ctx.rs",
        "a_withdrawn_subjects_credential_is_not_presented",
        "a hop inside a step begun before a halt presents the withdrawn owner's "
        "held credential, until the step ends",
        """                self.withdrawal_at_hop(key).await?;""",
        """                let _ = key;""",
    ),
    "AWithdrawnSubjectsCredentialStaysHeld": (
        "src/runtime/ctx.rs",
        "a_withdrawn_subjects_credential_is_not_presented",
        "a withdrawal leaves the subject's credential in the source, served "
        "again the moment the halt is lifted rather than obtained afresh",
        """            wiring.registry.forget(&withdrawal.subject);""",
        """            let _ = (wiring, &withdrawal.subject);""",
    ),
    "AHopWithholdingIsNeverSuperseded": (
        "src/journal/replay.rs",
        "a_withdrawn_subjects_credential_is_not_presented",
        "a hop's later announcement does not supersede its withholding, so a "
        "strict replay stops at a pause the run's own records show it resuming "
        "from",
        """        self.supersede_withheld(key);
        self.effects.push(Journaled {""",
        """        self.effects.push(Journaled {""",
    ),
    "AnOlderWithholdingStillStands": (
        "src/journal/replay.rs",
        "a_hop_withheld_twice_stands_withheld_once",
        "a hop withheld twice keeps both withholdings, so every resume consumes "
        "the older one, never reaches the frontier, and the run cannot resume",
        """        self.supersede_withheld(key);
        self.unannounced(""",
        """        self.unannounced(""",
    ),
    "TheExchangeRequestOmitsTheActor": (
        "src/peers/exchange.rs",
        "the_exchange_request_carries_the_owner_and_the_actor",
        "the exchange posts no actor token, so the issuer cannot tell which "
        "plane is asserting the subject and must take the assertion from nobody",
        """            ("actor_token", self.actor_token.expose()),""",
        """            ("actor_token", ""),""",
    ),
    "AnIssuerRefusalCarriesItsProse": (
        "src/peers/exchange.rs",
        "an_issuer_refusal_is_final_and_names_only_its_code",
        "an issuer's refusal reaches a journaled failure in the issuer's own "
        "words, rather than the OAuth error code alone",
        """                .map_or_else(|_| "no error code".to_owned(), |r| r.error);""",
        """                .map_or_else(|_| "no error code".to_owned(), |_| String::from_utf8_lossy(&body).into_owned());""",
    ),
    "TheApprovalOmitsTheReach": (
        "src/runtime/declarative.rs",
        "an_approval_of_a_consultation_shows_the_callee_s_reach",
        "an approval of a consultation shows the capability and the arguments "
        "and not what the callee may do, so a reviewer authorizes a reach they "
        "never saw and the digest covers no particular callee",
        """        spec.justification.reach = reach;""",
        """        let _ = reach;""",
    ),
    "TheReachDropsRequiresApproval": (
        "src/runtime/reach.rs",
        "an_approval_of_a_consultation_shows_the_callee_s_reach",
        "every grant of the callee reads as unattended, so a reviewer cannot "
        "tell a mutation the callee's own run asks a person about from one "
        "nobody sees",
        """            requires_approval: grant.requires_approval,""",
        """            requires_approval: false,""",
    ),
    "TheReachHidesWhatTheCalleeConsults": (
        "src/runtime/reach.rs",
        "the_reach_names_but_does_not_expand_the_callee_s_agents",
        "the agents and peers a callee may hand work on to are not marked, so "
        "the reviewer cannot see the approval reaches further than one hop",
        """                .is_some_and(|id| id.server == crate::tools::AGENT_SERVER || consults(&id.server)),""",
        """                .is_some_and(|_| false),""",
    ),
    "AnUndeclaredCalleeShowsNoStatement": (
        "src/runtime/declarative.rs",
        "an_undeclared_callee_is_named_as_such",
        "a consultation of an agent no declaration governs carries no reach at "
        "all, so the approval is silent where it should say nothing bounds it",
        """        cx.reach(&id.tool).await
    } else {""",
        """        Ok(cx.reach(&id.tool).await?.filter(|r| r.declaration.is_some()))
    } else {""",
    ),
    "TheRenderingOmitsTheReach": (
        "src/core/task.rs",
        "the_rendering_shows_the_callee_s_reach",
        "the reach is digested but no surface shows it, so the reviewer "
        "approves a section they were never shown",
        """            evidence,
            reach,""",
        """            evidence,
            reach: reach.filter(|_| false),""",
    ),
    "TheReachIsReadFromThePlaneOnReplay": (
        "src/runtime/ctx.rs",
        "a_finished_consultation_replays_after_its_callee_is_redeployed",
        "the reach an approval showed is re-derived from the plane on every "
        "pass, so a redeployed callee rewrites the digest of an approval "
        "already given and a finished run no longer replays",
        """        Ok(read.peek().clone())""",
        """        let _ = read;
        Ok(self.plane.upgrade().and_then(|plane| plane.reach_of(capability)))""",
    ),
    "AnApprovedConsultationIsNotPinned": (
        "src/runtime/declarative.rs",
        "a_redeployed_callee_is_named_in_the_refusal",
        "a consultation is dispatched to whichever revision answers now, not "
        "the one its approval showed",
        """            cx.commission_pinned(capability, input, declared.digest)""",
        """            cx.commission(capability, input)""",
    ),
    "TheCommissionIgnoresThePin": (
        "src/runtime/ctx.rs",
        "a_changed_callee_is_refused_after_approval",
        "a consultation pinned to an approved revision is dispatched to "
        "whichever revision answers the capability now",
        """            terms = terms.expect_declaration(pin);""",
        """            let _ = pin;""",
    ),
    "APinMismatchIsInDoubt": (
        "src/runtime/ctx.rs",
        "a_changed_callee_is_refused_after_approval",
        "a pinned consultation refused before any sub-run existed reads as in "
        "doubt, and the run quarantines over a call that never ran",
        """                crate::core::RuntimeError::DeclarationPinMismatch { .. } => {""",
        """                crate::core::RuntimeError::DeclarationPinMismatch { .. } if false => {""",
    ),
    "ACommissionHidesItsSubRun": (
        "src/runtime/ctx.rs",
        "an_agent_is_consulted_as_a_granted_tool_and_replay_wakes_nobody",
        "a consultation's journaled answer names no run, so a reader of the "
        "delegating run's journal cannot follow the delegation to the work",
        """            run: Some(out.run_id.to_string()),""",
        """            run: None,""",
    ),
    "AnOutcomeRecordsNoDuration": (
        "src/runtime/ctx.rs",
        "an_effects_outcome_records_how_long_it_took",
        "an effect's outcome says nothing of how long the call took, so a "
        "reader of the journal cannot tell a slow provider from a slow plane",
        """        let elapsed_ms = Some(u64::try_from(began.elapsed().as_millis()).unwrap_or(u64::MAX));""",
        """        let elapsed_ms: Option<u64> = { let _ = began; None };""",
    ),
    "ThePlaneStreamsNothing": (
        "src/model/mod.rs",
        "the_plane_forwards_a_declarative_agents_live_output",
        "a model call the plane builds ignores the plane's stream observer, so "
        "a surface following a run sees nothing until the call has finished",
        """            self.stream = observer;""",
        """            let _ = observer;""",
    ),
    "AnIssuerRefusalIsRetried": (
        "src/peers/exchange.rs",
        "an_issuer_refusal_is_final_and_names_only_its_code",
        "an issuer's 4xx refusal reads as an outage, so the call is retried "
        "against an answer no retry changes",
        """            let answered = status.is_client_error()""",
        """            let answered = false && status.is_client_error()""",
    ),
    "APlaneRunNamesThePlanesOwner": (
        "src/runtime/ctx.rs",
        "a_run_admitted_as_the_plane_presents_no_subject_bound_credential",
        "a run admitted as the plane is exchanged for its chain's owner, so the "
        "plane's own authority reaches the peer dressed as a person's",
        """        let prepare = if self.plane_chain().await? {""",
        """        let prepare = if false {""",
    ),
}

# Which constitutional invariant each guarantee serves.
#
# The invariants are what this runtime *has to* do; the table above is what
# somebody has shown to be falsifiable. Nothing connected the two, so an
# invariant could lose its last piece of evidence — to a rename, a deleted row,
# a rewritten test — and read exactly as it did when it had some. Reading the
# suite against the invariants rather than against the code found six tests, for
# the announce-act-record protocol and the effect key it turns on, that no
# mutation named at all.
#
# Beside the mutations rather than in the design document, so the names cannot
# drift from the rows they point at, and `--check` reads both in one pass.
#
# A sample, not a census: a row proves an invariant is falsifiable somewhere,
# never that its evidence is complete.
INVARIANTS: dict[str, tuple[str, list[str]]] = {
    "I1": (
        "the journal is the execution truth",
        ["ReplayRePerforms", "DenialNotJournaled", "PolicyOnReplay"],
    ),
    "I2": (
        "intent precedes action",
        ["AnAnnouncementWithNoOutcomeIsAssumedHarmless", "RetryWhatLanded"],
    ),
    "I3": (
        "effect identity is runtime-owned",
        [
            "AnAttemptDoesNotChangeAnEffectsIdentity",
            "TwoEffectsInAStepCollideOnOneKey",
            "ACanonRuleChangeReadsAsDivergence",
        ],
    ),
    "I4": (
        "replay divergence is quarantined",
        ["IgnoreKeyMismatch", "ReleaseReplayDriftIgnored"],
    ),
    "I5": (
        "unknown outcomes remain unknown",
        [
            "AMutatingDoubtUnwindsInsteadOfAsking",
            "AnInDoubtEffectIsAnApology",
            "AGroupReversesThroughDoubt",
        ],
    ),
    "I6": (
        "authority only narrows",
        ["DelegationCanWiden", "ValidityCanWiden", "AudienceCanWiden"],
    ),
    "I7": (
        "authorization is about data as well as action",
        ["TrustToolOutput", "ReadOnlyProtectedFieldsIgnored", "AnOpenObjectSchemaIsAccepted"],
    ),
    "I8": (
        "plans are frozen authorization graphs",
        ["PlanFieldLabelsFlattened", "NoScopeGate", "APlanFormatNoProviderWillAccept"],
    ),
    "I9": (
        "ownership and shared state use different protocols",
        [
            "EveryInstanceSharesALeaseOwner",
            "ReleasingALeaseForgetsTheEpoch",
            "ARestoreFlattensTheEpoch",
        ],
    ),
    "I10": (
        "completion is structural",
        ["ARequiredVerifierIsAdvisory", "UnwindForwards"],
    ),
    "I11": (
        "integrity claims are narrow and explicit",
        ["AnExpiredChainIsAdmitted", "TheProofsStartingSizeIsGuessed"],
    ),
    "I12": (
        "no declared control may be advisory",
        [
            "TheStandInEnforcesAnySchema",
            "TheModelsSpellingOfAToolIsUnchecked",
            "ADanglingContinuationIsHonoured",
        ],
    ),
    "I13": (
        "a finding must be findable",
        [
            "AQuarantineIsUnfindable",
            "AGroupCommitsByBeingForgotten",
            "ARefusedResumeIsListedNowhere",
            "AFailedResumeReleasesTheOnlyLeaseListingIt",
        ],
    ),
    "I14": (
        "conclusion is not closure",
        ["AQuarantineSealsTheJournal", "UnknownOutcomeResumes"],
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

    **What it therefore does not cover: the replacement.** An anchor can match
    while the text that replaces it no longer compiles — change a function's
    signature and every replacement that *calls* it is stale, though every anchor
    still reads correctly. The sweep reports that as `ERROR — did not compile`
    rather than as a caught guarantee, which is the right answer and an expensive
    one to wait for. So a signature change means running the mutations that name
    the callers, not trusting a green `--check`.
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

    # Every mutation lands in exactly one shard, for every split CI might use.
    #
    # The slice is a rounded division, and a slip there is silent in the worst
    # way: a mutation in no shard is a guarantee the sweep never checks, while
    # every shard still passes and the summary still says every guarantee is
    # falsifiable. Checked here because this answers in milliseconds and the
    # sweep that would notice runs for hours.
    names = list(MUTANTS)
    for total in (1, 2, 6, 10, 16, len(names)):
        seen = [n for k in range(1, total + 1) for n in _shard(names, k, total)]
        if sorted(seen) != sorted(names):
            missing = [n for n in names if n not in set(seen)]
            twice = sorted({n for n in seen if seen.count(n) > 1})
            print(
                f"--shard k/{total} does not partition the table: "
                f"{len(missing)} mutation(s) in no slice, {len(twice)} in more than one"
            )
            bad += 1

    for name, (path, test, _desc, find, _replace) in MUTANTS.items():
        target = ROOT / path
        if not target.exists():
            print(f"{name}: {path} does not exist")
            bad += 1
            continue
        n = target.read_text().count(find)
        if n != 1:
            print(f"{name}: anchors {n} times in {path} (expected 1)")
            bad += 1
        # The *test* half, through the same resolver a sweep uses. A name this
        # cannot place is a row that verifies nothing, and it fails in the
        # slowest possible way otherwise: the sweep builds the crate, runs
        # nothing, and reports an error forty minutes in. `--verify` is the
        # only thing that used to notice, so the answer is to ask its own
        # locator here rather than to re-implement the question.
        if _locate(test) is None:
            print(
                f"{name}: no test named '{test}'. This field takes a bare "
                f"function name, not a module path"
            )
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


    # A unit test inside a binary. Named before the library sweep below,
    # because `--lib` does not compile `src/bin` at all: located as a library
    # test, such a row runs a selector matching **no test**, and cargo's
    # `0 passed` reads as a mutation nothing caught rather than as a row this
    # tool could not place.
    for path in sorted((root / "src" / "bin").glob("*.rs")):
        if f"fn {test}(" in path.read_text():
            return f"bin:{path.stem}", None

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


# Seconds one mutation costs, by the test target its check builds, measured warm
# on one machine. `None` is a library unit test, which runs `--all-features
# --lib` and therefore pays for the largest build this crate has.
#
# **These only affect balance.** A stale number makes a shard uneven, which is
# what an unweighted split guarantees anyway; it can never make a sweep skip a
# mutation or reach a wrong verdict. Re-measure with
# `/usr/bin/time -p python3 tools/mutants.py <name> --verify` on one mutation
# per target, warm.
#
# The spread is the reason this table exists at all: an equal *count* of
# mutations is not an equal amount of work, and splitting ten ways by count put
# every library unit test in two shards that then ran three times as long as the
# rest — a matrix finishes when its slowest job does.
_SECONDS_BY_TARGET: dict[str | None, int] = {
    None: 160,  # --all-features --lib
    "bin:agentplane": 160,  # --all-features --bin: the same library build
    "wire": 54,
    "guards": 45,
    "process": 45,
    "engine": 27,
    "trust": 19,
    "live": 30,
}


@functools.lru_cache(maxsize=None)
def _cost(row) -> int:
    """What one mutation's check costs, for balancing only.

    Takes a row in either shape the two callers hold — a bare name from
    [`check`], or the `(name, entry)` pair the sweep sorts — so the partition
    `check` proves is the partition the sweep performs. Two shard functions is
    the one way this could be wrong and still look right.

    Cached because [`_locate`] reads every source file in the repository and
    `check` shards the table six different ways: uncached, proving the partition
    costs more than the sweep it is protecting.
    """
    name = row if isinstance(row, str) else row[0]
    found = _locate(MUTANTS[name][1])
    if not found:
        return 1
    return _SECONDS_BY_TARGET.get(found[0], 60)


def _shard(rows: list, shard: int, total: int) -> list:
    """One slice of `rows`, as `--shard k/n` selects it.

    Contiguous, because `rows` arrives grouped by the feature set each mutation
    builds under and the point of a slice is to stay inside as few of those
    groups as possible.

    Split by **cost rather than by count**. A mutation checked by a library unit
    test costs six times one checked in the `trust` binary, so ten equal counts
    are not ten equal jobs; the slices below are equal in seconds and therefore
    unequal in length, which is the right way round when what is being divided
    is time.

    Shared with [`check`] rather than written twice: a slice that dropped a
    mutation would leave it in no shard at all, and a sweep that skipped a
    guarantee prints the same summary as one that checked it.
    """
    weights = [_cost(row) for row in rows]
    budget = sum(weights)
    lo = hi = acc = 0
    for i, w in enumerate(weights):
        if acc < budget * (shard - 1) / total:
            lo = hi = i + 1
        if acc < budget * shard / total:
            hi = i + 1
        acc += w
    # The last shard takes whatever rounding left behind, so the slices always
    # partition the table however the weights fall.
    return rows[lo:] if shard == total else rows[lo:hi]


def _build_key(test: str) -> tuple[str, str]:
    """The `(features, target)` pair a mutation's check is built under.

    Read from [`_locate`] rather than derived a second way, so the order a
    sweep runs in cannot disagree with the command `verify` then issues — two
    models of one build would put a mutation in the group whose dependencies
    it does not use, and the grouping would quietly buy nothing.
    """
    found = _locate(test)
    if not found:
        # A test nothing can find has no build. Sorted last, under its own key,
        # so it neither joins a group nor splits one.
        return ("~~missing", test)
    target, feats = found
    if feats is None:
        return ("all", target or "")
    return (",".join(sorted(set(feats) | {"redb", "testkit"})), target or "")


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
        # A unit test in the library or in a binary: build everything, because
        # the gate that decides whether this test exists is not in the file it
        # lives in. The binary needs naming — `--lib` does not compile one.
        unit = ["--bin", target.removeprefix("bin:")] if target else ["--lib"]
        selector = ["--all-features", *unit]
        features = "all"
    else:
        # `redb` and `testkit` are what a test needs to stand up a plane at all.
        feats |= {"redb", "testkit"}
        features = ",".join(sorted(feats))
        selector = ["--features", features, "--test", target]

    # The cost model here is one library rebuild per mutation, and two ambient
    # defaults fight it — hard enough that a six-way CI shard outgrew its job.
    #
    # CI cache actions export CARGO_INCREMENTAL=0, which is right for a
    # one-shot build that will be cached and wrong for a loop recompiling the
    # crate once per one-line mutation: it is the difference between an
    # incremental rebuild measured in seconds and a full one measured in
    # minutes, 72 times per shard. And full debuginfo makes linking each large
    # test binary the second cost, buying line numbers no verdict reads — the
    # classifier parses test names, never backtraces.
    #
    # Overridden here rather than in the sweep script so a bare `--verify`
    # behaves identically to the sweep — one implementation, because the two
    # briefly disagreed about everything else and this would be no different.
    # `*_MUTANTS` variables are the opt-out, mirroring RUSTFLAGS_MUTANTS.
    env = dict(os.environ)
    env["CARGO_INCREMENTAL"] = env.get("CARGO_INCREMENTAL_MUTANTS", "1")
    env["CARGO_PROFILE_DEV_DEBUG"] = env.get("CARGO_PROFILE_DEV_DEBUG_MUTANTS", "0")
    env["CARGO_PROFILE_TEST_DEBUG"] = env.get("CARGO_PROFILE_TEST_DEBUG_MUTANTS", "0")

    def run(args: list[str]) -> str | None:
        """Run one cargo invocation, or `None` if it had to be killed.

        A mutation can make a test *hang* rather than fail — remove a gate and
        the work it was refusing runs, and if that work waits on something the
        test never supplies, nothing ever returns. Without a bound this blocks
        until the CI job's own timeout, which names no mutation and reads as
        infrastructure. Bounded, it is an INCONCLUSIVE verdict pointing at the
        one mutation to go look at.

        Killed by process group, not by pid: `subprocess`'s own timeout kills
        cargo and leaves rustc and the test binary running, which is how a
        "stopped" sweep goes on holding the target lock.
        """
        proc = subprocess.Popen(
            ["cargo", "test", *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=ROOT,
            env=env,
            start_new_session=True,
        )
        try:
            return proc.communicate(timeout=TIMEOUT_SECONDS)[0]
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.communicate()
            return None

    if apply(name) != 0:
        return 2
    try:
        out = run([*selector, test])
        if out is None:
            print(
                f"{name}: INCONCLUSIVE — `{test}` did not finish within "
                f"{TIMEOUT_SECONDS}s and was killed. A mutation that makes a test "
                f"hang has proved nothing: the guarantee is unpinned until the "
                f"test is rewritten to fail rather than block. Raise the bound "
                f"with MUTANTS_TIMEOUT_SECS only if the test is genuinely slow."
            )
            return 2
        if _target_did_not_build(out):
            # The derived feature set does not build the target, which is a
            # defect in this tool or in the test file — never a verdict about
            # the mutation. Said out loud, because the fallback below *works*:
            # `--all-features` builds everything, the named test fails, and the
            # sweep reports KILLED having paid for the whole suite. Thirty per
            # cent of this table did exactly that, correctly and eight times
            # over, and the only symptom was a slow CI shard.
            print(
                f"{name}: ERROR — `--features {features} --test {target}` does not "
                f"build. The feature set is derived from the target's own sources, "
                f"so a test using a gated module without naming the feature makes "
                f"the whole target unbuildable here while `--all-features` hides it."
            )
            print("\n".join(out.splitlines()[-6:]))
            return 2
        if not _named_test_failed(out, test):
            # Slow path, and only here: the named test held, so the question is
            # now whether *anything* did.
            out = run(["--all-features", "--no-fail-fast"])
            if out is None:
                print(
                    f"{name}: INCONCLUSIVE — the whole-suite fallback did not "
                    f"finish within {TIMEOUT_SECONDS}s and was killed."
                )
                return 2
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


def _target_did_not_build(out: str) -> bool:
    """Whether the *target* failed to compile, as opposed to the mutation.

    The distinction is the whole point. A mutation that breaks the file is a
    badly written mutation and already has a verdict; a target that cannot be
    built under the feature set derived for it is a tooling fault that produces
    the *right* answer down a path that costs eight times as much. Told apart by
    where the error is: a mutation edits `src/`, so an error pointing into
    `tests/` is not about it.
    """
    if "could not compile" not in out:
        return False
    return bool(re.search(r"^\s*-->\s*tests/", out, re.M))


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


def _added_lines(diff: str) -> dict[str, set[int]]:
    """Line numbers touched in each file's post-image, from a `-U0` diff."""
    out: dict[str, set[int]] = {}
    path = ""
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            path = line[6:]
            out.setdefault(path, set())
        elif line.startswith("@@"):
            m = re.search(r"\+(\d+)(?:,(\d+))?", line)
            if m and path:
                start, count = int(m.group(1)), int(m.group(2) or 1)
                out[path].update(range(start, start + max(count, 1)))
    return out


def _signature_spans(src: list[str]) -> list[tuple[str, range]]:
    """Each `fn name`'s line span from its declaration to the close of its
    parameter list — the region where adding an argument breaks every
    replacement that calls it."""
    spans = []
    for i, line in enumerate(src):
        m = re.search(r"\bfn\s+([a-z_][a-z0-9_]*)\s*[(<]", line)
        if not m:
            continue
        depth, end = 0, i
        for j in range(i, min(i + 40, len(src))):
            depth += src[j].count("(") - src[j].count(")")
            end = j
            if depth <= 0 and "(" in "".join(src[i : j + 1]):
                break
        spans.append((m.group(1), range(i + 1, end + 2)))
    return spans


def affected(since: str | None = None) -> int:
    """Name the mutations a signature change in the working tree may have broken.

    `--check` reads only the *find* half, so it cannot see a **replacement** that
    stopped compiling — and the replacement is the half that calls into the
    code. Add a parameter to a function and every mutation whose replacement
    calls it becomes an ERROR: reported by a sweep as "not pinned", identical to
    a guarantee that genuinely lost its test, and invisible until CI runs the
    hour-long job. That has happened twice to the same anchor.

    So this lists, rather than judges: every `fn` whose signature line the
    working diff touches, and every mutation mentioning one. Run `--verify` on
    what comes back. A listing cannot give false confidence the way a
    heuristic check would — and a parameter count parsed out of Rust by regex
    would be exactly that.
    """
    where = [since] if since else []
    diff = subprocess.run(
        ["git", "diff", "-U0", *where, "--", "src/"],
        capture_output=True, text=True, cwd=ROOT, check=False,
    ).stdout
    # A changed line that falls inside a **parameter list** — which is not the
    # same as a changed `fn` line. The break this exists to find was a sixth
    # parameter added to `gate` on a line of its own, leaving `fn gate(`
    # untouched: matching on the `fn` line alone misses exactly the case that
    # has now bitten twice. A function merely *added* is excluded, since no
    # replacement written before it existed can call it.
    names: set[str] = set()
    base = since or "HEAD"
    for path, lines in _added_lines(diff).items():
        src = (ROOT / path).read_text().splitlines() if (ROOT / path).exists() else []
        before = subprocess.run(
            ["git", "show", f"{base}:{path}"],
            capture_output=True, text=True, cwd=ROOT, check=False,
        ).stdout
        existed = {m for m in re.findall(r"\bfn\s+([a-z_][a-z0-9_]*)", before)}
        for name, span in _signature_spans(src):
            # It has to have existed before: a replacement written against a
            # function that did not yet exist cannot be calling it.
            if name in existed and any(n in span for n in lines):
                names.add(name)
    if not names:
        scope = f"since {since}" if since else "in the working tree"
        print(f"no function signature in src/ changed {scope}")
        return 0
    hits = sorted(
        n for n, (_f, _t, _d, find, repl) in MUTANTS.items()
        if any(re.search(rf"(?<![a-z_]){re.escape(fn)}\s*\(", find + repl) for fn in names)
    )
    print(f"{len(names)} function(s) changed: {', '.join(sorted(names))}\n")
    if not hits:
        print("no mutation mentions any of them")
        return 0
    print(f"{len(hits)} mutation(s) mention one — `--verify` each:")
    for n in hits:
        print(f"  python3 tools/mutants.py {n} --verify")
    return 0


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--check":
        return check()
    if sys.argv[1:2] == ["--affected"] and len(sys.argv) <= 3:
        return affected(sys.argv[2] if len(sys.argv) == 3 else None)
    if sys.argv[1:2] == ["--list"]:
        # Emitted **grouped by the feature set each mutation is checked under**,
        # because that set is what decides the build. Cargo keeps one set of
        # compiled artifacts per feature combination, so moving from one to
        # another rebuilds the library and every dependency for the combination
        # being moved to; staying inside one rebuilds only the library, whose
        # single line changed.
        #
        # The table is authored by subject, and the thirteen feature sets are
        # scattered through it — so in authoring order a sweep switches
        # combination about two thirds of the time and pays a dependency build
        # for almost every mutation. Grouping makes each combination's
        # dependencies build once.
        #
        # `--shard k/n` then takes a **contiguous** slice of that grouped order,
        # so a shard sees one or two combinations rather than all thirteen. The
        # slices are equal in length, which is the balance that matters once
        # build locality is what a shard's cost is made of.
        #
        # Sharding is for separate checkouts. Two shards on one tree would
        # rewrite the same files under each other, which is what the sweep's
        # lock refuses.
        shard, total = 1, 1
        if sys.argv[2:3] == ["--shard"] and len(sys.argv) == 4:
            try:
                shard, total = (int(p) for p in sys.argv[3].split("/", 1))
            except ValueError:
                print("--shard takes k/n, as in --shard 2/6", file=sys.stderr)
                return 2
            if not 1 <= shard <= total:
                print(f"--shard {shard}/{total} is out of range", file=sys.stderr)
                return 2
        elif len(sys.argv) != 2:
            print(__doc__, file=sys.stderr)
            return 2
        rows = sorted(
            MUTANTS.items(),
            # `_locate` answers with the target and features `verify` will use,
            # so this orders by the real build rather than by a guess from the
            # table. A mutation whose test cannot be found sorts last under a
            # key of its own; `verify` reports it, and it must not silently
            # join another group's build.
            key=lambda kv: _build_key(kv[1][1]),
        )
        for name, (path, test, desc, _, _) in _shard(rows, shard, total):
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
