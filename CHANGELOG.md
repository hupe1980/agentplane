# Changelog

Notable changes per release, on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

**Written for somebody who already depends on a version.** Each entry says what
changed and what to do about it. Anything needing more than a line or two is in
[upgrading](https://hupe1980.github.io/agentplane/docs/upgrading/); why a design
was chosen is not here.

**Two categories are ours.** `Assurance` is a change to what the project can
*prove* — a guarantee that gained a test, a surface walked adversarially.
`Known` is a limitation shipped deliberately.

**Pre-alpha.** `0.x` bumps carry breaking changes with no deprecation cycle.
Breaking entries are marked **BREAKING**.

Entries for `0.1.0`–`0.9.0` are reconstructed from tags and commit history.

## [0.44.0] — unreleased

### Security

- **BREAKING (wire): a producer can no longer spell another producer's
  `(source, id)`.** Joined with U+001F, `("bus\u{1f}x", "EV-1")` and
  `("bus", "x\u{1f}EV-1")` were one key, so an emitter could pre-empt another's
  next message as an apparent retry — a silent suppression. `core::origin_key`
  puts the source's length in front instead. Event dedup and A2A admission keys
  both move; **drain before upgrading** →
  [upgrading](https://hupe1980.github.io/agentplane/docs/upgrading/).

### Fixed

- **`cedar-policy`'s lower bound is `4.13.0`, the first release this adapter
  compiles against.** It said `4.12.0`, which has no
  `ValidationWarning::InvalidActionApplication` — so a build resolving the low
  end of the range did not compile. Nothing else changes; every resolution that
  worked still resolves the same version.

- **The export self-test is published with the damage it actually does.** The
  assurance page and the README said six cases and listed six; the seventh — a
  framing member from a later writer — has run all along and was named in
  neither. The check is unchanged; what an evaluator reads about it is not.

- **The tenant spend ceiling's overshoot is documented as what it is.** The
  crate and the operator guide both said *at most the concurrency ceiling times
  the per-run budget*. Resumes are never gated and suspended runs are unbounded,
  so a tenant with a thousand runs awaiting approval can carry a thousand per-run
  budgets past a crossed ceiling. No code changes; what you size ceilings from
  does.

- **Every metered budget refusal states its rule rather than a tally.** These
  ceilings stop the *next* operation once the figure is **at** the limit, so
  `1s permitted, 1s elapsed` read as an off-by-one. Effects, tokens, money and
  wallclock now read `nothing further starts at or past 1s; 1s elapsed`. The
  record's structured `exhaustion` is unchanged, and `elapsed_secs` documents
  that it counts second boundaries.

### Known

- **Per-capability aggregates are refused, and the page an adopter reads says
  so.** A plane query for run count, effect count, outbound bytes, denials and
  outcome mix per capability is not coming: an export already carries every
  record, so each effect's `outbound_bytes` joins to its run's `capability` — a
  distribution, where the query would be a summary, and the *median* such a
  baseline is wanted for cannot be computed from totals at all →
  [status](https://hupe1980.github.io/agentplane/docs/status/#deliberately-not-built).

### Assurance

- **An unknown field at a known record version is pinned as refused.** The
  version arm is never taken for it — every durable version is `1` until the
  freeze, and a hard cut changes a shape without touching it — so the refusal
  rested on `deny_unknown_fields` surviving a `flatten`, which nothing checked.
  It does, and now a mutation says so.

## [0.43.0] — 2026-09-20

### Added

- **A record beside an agent this plane does not run.** `observe::Session`
  writes what somebody else's agent was asked, reported doing and was allowed
  to do, as a run of its own with no admission, sealed under the outcome
  `observed` and sharing no record kind with a dispatched effect. An `audit`
  lists such runs as unadmitted; an `export` carries them. New:
  `RecordKind::Observed`, `RunStatus::Observed`, `core::ObservedStep` →
  [interop](https://hupe1980.github.io/agentplane/docs/interop/#observing-an-agent-you-do-not-run).

- **`observe::Session::in_case` — bind an observed session to a matter.**
  Correlate a case on the session id and *show me the record for session X* is
  one indexed read. Without it, the answer is a scan of runs with the
  `observed` outcome.

- **`acp` — the Agent Client Protocol's session updates, mapped onto those
  records.** Types only, pinned to `acp/v1`: the connection stays with the
  editor that holds the session. The updates that carry evidence are recorded;
  the rest come back as `Mapped::NotRecorded` carrying the wire's own spelling.

### Fixed

- **BREAKING: an audit is held to every checkpoint the auditor brought, not
  the tallest one.** Picking the highest anchor picks a fork, because the
  history fed to a fresh witness is the longest anybody holds.
  `Evidence::anchors` replaces `prior` and each is checked separately;
  `NotAppendOnly`, `WrongLog` and `Shrunk` name which one failed;
  `export::verify` takes the same slice →
  [upgrading](https://hupe1980.github.io/agentplane/docs/upgrading/).

- **BREAKING: a key ring that is down no longer reads as a completed
  erasure.** Every sealing decorator left a payload sealed on any `KeyError`,
  so an unreachable KMS was indistinguishable from data somebody had lawfully
  destroyed. Only `Destroyed` is forgiven now. `SealedCases`, `SealedTasks`,
  `SealedEvents` and `SealedPush` return `Result` where they returned a
  value.

- **BREAKING: a webhook credential is no longer dropped because the key ring
  was down.** `SealedPush` returned the registration with its token removed and
  the notification went out unauthenticated. A read that cannot get the
  credential now fails, and the outbox retries.

- **`erase_case` refuses a matter that is still open** —
  `EraseError::CaseStillOpen`. Destroying the key freezes every run the case
  covers: nothing can be replayed or unwound again. Conclude the runs, close
  the matter, then erase.

- **A run whose payloads were erased says so.** Resuming one complained about
  a missing `version` field; it answers `RuntimeError::PayloadsErased` now.
  Such a run could previously be neither resumed nor cancelled — `abandon`
  closes it.

- **An A2A task read could panic on a caller's argument.** `tasks/get` matched
  an over-budget arm with `unreachable!`, correct only because that call site
  passed no budget. The unmetered read is its own entry point now and cannot
  return that variant.

### Assurance

- **A record kind's fields are held against the record body's.** `RecordKind`
  is flattened into the body, so a variant field named after a body field is
  one key on the wire — and it seals, hashes and re-derives cleanly, failing
  only when something reads the record back. The rule was a comment on one
  variant; it is a guard over every variant and every field now.

- **Equivocation is model-checked.** `tla/Equivocation.tla` covers an operator
  showing two histories of one log: what a single witness settles, what it
  cannot, and which reader still sees the fork. Its two mutants are a reader
  that keeps the tallest anchor and a witness that signs without recording.

- **The containment measurement this project owes says what it has to
  publish.** A deterministic gate has no attack-success rate — a deployment
  does — so the policy bundle a run used, and how open its tasks were, are part
  of the figure rather than footnotes under it →
  [status](https://hupe1980.github.io/agentplane/docs/status/).

## [0.42.0] — 2026-09-20

### Added

- **The remedy verbs on the CLI: `reconcile`, `quarantine`, `decide`,
  `acknowledge`, `cancel`, `rearm`.** `agentplane attention` names a remedy
  for every condition it reports, and those remedies were HTTP-only — on the
  embedded backend, unreachable exactly when the plane is down. A new guard
  holds the two lists together.

- **A rehearsal leaves a record.** `drill` wrote its verdict to a log and
  nowhere else, so *when did you last rehearse, and did it pass* was
  answerable only from whatever ran the verb. `CaseStore` gains
  `record_drill`/`last_drill`; `Runtime::last_drill`, `agentplane drill --last`
  and `GET /drill` read it, and `attention` reports a failed one. The record
  names its checkpoint origin, so a drill over a restored copy cannot read as
  one over production.

- **`Runtime::record_quarantine_decision` — answer a quarantine without
  driving the run.** What a terminal can do: it holds the journal and not the
  agent. The decision is durable and the next resume applies it, which the
  verb says rather than reporting the run as moved.

### Fixed

- **A task's `evidence` was unsealed in the worklist.** The trail behind a
  proposal is assembled from what tools and models produced, and the journal
  sealed its copy while the task store did not — so it outlived a case erasure
  in the one store an operator browses by hand. Each entry keeps its trust
  label, which is not the caller's data.

- **A withheld run read back as `quarantined`.** `GET /runs/{run}`, `export`
  and the MCP task view all go through one reader, and it had no arm for
  `withheld` — so a run paused under a withdrawn credential answered *this
  build does not recognise its own record*. The guard that should have caught
  it iterated the export's outcome list rather than the writer's.

- **`attention` named remedies the runtime refuses.** An exhausted or withheld
  run cannot be abandoned — that answers a doubt, and neither is one. Both now
  name `cancel`.

- **The shipped policy bundle listed a third of the operator vocabulary as
  "the full sets".** `examples/serve-policy.cedar` enumerated 16 actions against
  40, missing every incident verb. Cedar denies what no rule permits, so a
  bundle copied from it refuses `api:halt.place` during the incident. The list
  is complete and a guard holds it to `api::action::ALL`, `a2a::action::ALL`
  and `core::ACTIONS`.

- **`data:release` was permitted by nothing in that bundle.** A bundle granting
  admission and effects refuses every typed release, silently: `preflight`
  reports rules that cannot evaluate, and a rule nobody wrote evaluates fine. It
  stays denied, and the file says so where the rule would go →
  [security](https://hupe1980.github.io/agentplane/docs/security/).

### Known

- **A recall is screened item by item, not as a set.** Collusive and salami
  poisoning split an objective into fragments that are individually
  innocuous. No runtime screen catches that: a set-level rule needs a
  similarity threshold, which is a deployment's number wearing a runtime's
  authority. The writes behind a recalled set stay enumerable from the
  journal, which detects rather than prevents.

### Changed

- **BREAKING: `opendal` 0.59.** `OpenDalBlobs::new` takes an
  `opendal::Operator`, so an embedder constructing one moves with it. The 0.58
  hold is gone: 0.59.0 did not build, and 0.59.2 does. `jsonschema` moves to
  0.56, which is internal.

- **BREAKING: every sentence on a task carries who wrote it.**
  `Justification`'s `summary`, `cost` and `evidence` are `Tainted<String>`. A
  declared dry-run preview is a tool's answer over the caller's data and reached
  the worklist as a plain `String`, indistinguishable from the runtime's own
  notes beside it. `TaskView.has_untrusted_prose` answers it once for a
  reviewer's client.

- **BREAKING: `EffectDone` carries `by`, the operator who minted an awaited
  event.** An approval travels as the effect's output and that field is sealed,
  so a lawful erasure destroyed the approver's name. Every operator act that
  stops a run already named its actor in the clear; this is the same rule for
  the one that lets a run carry on. `InboundEvent` gains `by`, and the store
  contract checks it round-trips.

- **BREAKING: a conclusion no longer repeats a reason its own record holds.**
  `RunConcluded.reason` is the run's own account — a failure, a replan, a
  quarantine. A cancellation, abandonment, crossing or withdrawal carries the
  actor and the reason together on its own record, in the clear; the sealed
  copy beside it made one sentence two facts that disagreed after an erasure.

- **BREAKING: an approval names its decider as an `Operator`, and an
  unanswered window names nobody.** `Decision::actor` becomes
  `Decision::decided` — `Decided::By(Operator)` or `Decided::OnExpiry`. The
  reserved names `system:unattended` and `system:expiry` are gone, and the
  record now carries the basis that established the decider →
  [upgrading](https://hupe1980.github.io/agentplane/docs/upgrading/).

- **BREAKING: `Runtime::decide_task` refuses an expiry decision.** That door
  runs the claim, the eligibility check and four-eyes; an expiry has nobody to
  run them against, so accepting one passed every control by having nothing to
  test. Applying an expiry stays the sweeper's.

### Assurance

- **What a model may be shown over MCP is a rule about the resource *kind*.**
  A kind crosses only where the runtime can bound what crosses without reading
  it: that admits the declaration and an audit report, and refuses journals and
  cases. A new test holds the report to it.

- **The list every run-status agreement test walks is pinned by a mutation.**
  `every_status` cannot be derived, so a variant added to `RunStatus` and
  forgotten there leaves those tests walking a list that no longer describes the
  type. `every_run_status_variant_is_listed` reads the enum out of the source; a
  mutation now removes a variant and holds the guard to catching it.

## [0.41.0] — 2026-09-20

### Added

- **`testkit::conformance_auth` — a contract for the `Authenticator` a
  deployment writes.** An empty request must be `Missing`, not an anonymous
  caller; a credential presented and refused must be `Rejected`, since
  `Missing` for it tells a prober the token was the right shape; an accepted
  request must name the actor you say it does. The outbound credential seams
  get none — audience is enforced at the boundary, not per implementation.

- **`Runtime::attention` — does anything on this plane need a person right
  now, and which thing.** One call over every backlog with a listing, plus the
  open conclusions whose answer is a person's. Conditions are named rather than
  summed, each with its remedy, and a backlog this plane has no store for is
  reported as `not_checked`. `agentplane attention` exits non-zero when
  something does; `GET /attention` under `api:attention`.

- **`JournalStore::waiting_runs` — the runs that are waiting, and for what.**
  The listing the recovery runbook's last step needs, soonest due first. Derived
  from the journal rather than from the timer and subscription tables, so it
  still answers on a plane restored from an export, which carries neither.
  `agentplane waiting` and `GET /runs/waiting` (`api:run.waiting`) →
  [upgrading](https://hupe1980.github.io/agentplane/docs/upgrading/).

- **`StoreError::UnreadableRecordShape` — a record at the version this build
  writes whose shape it cannot parse.** Before the freeze that is the only build
  skew there is, and it arrived as a bare serde message. The refusal now says
  the bytes hash as written and another build produced them.

- **`KeyError::UnreadableHeader` — a sealed envelope at a readable version whose
  header will not parse.** Damage or another build's shape, and nothing has
  authenticated the bytes yet. `drill` reports both causes and the step that
  separates them.

- **A resume under an edited declaration is refused, by name.** The manifest
  digest is recorded at admission, so `Mode::Resume` compares it and raises
  `RuntimeError::DeclarationChanged` before replaying — instead of letting the
  change surface later as two differing effect keys. Coded skills are unaffected:
  this crate cannot identify an embedder's binary and does not claim to.

### Removed

- **BREAKING: `core::AgentRef`.** A prelude type nothing constructed, nothing
  read, and whose doc described what `journal::AgentIdentity` actually does. A
  new guard, `no_public_struct_is_dead`, covers what `dead_code` cannot: a
  `pub use` makes a dead type reachable API, and the lint goes quiet.

### Changed

- **BREAKING: the A2A message extension is `…/a2a/ext/caller-context/v1`, and
  the constant is `EXT_CALLER_CONTEXT`.** The old URI named a delegation chain
  the block deliberately does not carry, and skipped the `ext/` segment its
  four siblings use →
  [upgrading](https://hupe1980.github.io/agentplane/docs/upgrading/).

- **BREAKING: every replay finding names the call, not its digest.** A
  divergence reads *history performed `x` here and this build asks for `y`*; a
  strict pass that verified less names the effect that went missing. Arguments
  stay unquoted — they are sealed and a conclusion is not →
  [upgrading](https://hupe1980.github.io/agentplane/docs/upgrading/).

- **BREAKING: `WrappedKey` refuses unknown members.** A durable format that
  travels with the payload it sealed; a skipped member would unwrap under
  parameters this build never saw.

- **`agentplane verify` names framing members it does not know**, in
  `not_checked` rather than as a finding — *sound* over a file the reader
  understood part of is a wider verdict than it earned.
  `tools/verify_export.py` implements the same rule.

### Fixed

- **A one-shot `agentplane` verb prints its answer, not a metric stream.**
  Metrics carry their own `tracing` target so a subscriber can filter them, and
  this binary is a subscriber: a first `run` emitted two metric events that
  buried the two lines the guide shows. `serve` still streams them, and
  `RUST_LOG` reaches them anywhere.

- **`agentplane verify` no longer calls an export from a newer build tampered.**
  Every unreadable record produced *it was edited after it was sealed*, and one
  of them stopped the block's head advancing, so the records after it were
  reported unlinked and missing too.

### Assurance

- **Two questions an adopter had to infer are answered in writing.** Where a
  content classifier hangs — behind an effect, producing a label, never on the
  policy seam, which is total and pure and journals no permit — is stated on
  `PolicyEngine` itself and on the security page. And the statutory mapping is
  the guide site's alone, downstream of the mechanisms: a change to a mechanism
  a row cites obliges re-reading that row.

- **The migration and rollback procedure is rehearsed, across two released
  builds.** Everything above came out of it. It also settles what the procedure
  means today: a hard cut is unreadable in both directions, so the rollback
  window before the freeze is zero and a shape change is a fresh journal.

## [0.40.0] — 2026-09-18

### Added

- **`tools::MCP_REVISION` — the revision this plane serves and offers.** One
  value behind `server/discover`'s advertised set, the handshake ceiling and the
  client's first offer. The published [support policy](https://hupe1980.github.io/agentplane/docs/interop/#protocol-revisions)
  states the unit: a revision plus the extensions it is chosen for.

- **`AuditReport::unadmitted` — the runs an audit found no warrant for, and the
  outcome each concluded under.** Every run whose chain verified is now in
  exactly one of `warrants` and `unadmitted`. Some have no admission by design:
  the sweeper opens a run of its own.

### Removed

- **BREAKING: `McpClient::KNOWN_VERSIONS` is replaced by
  `SPOKEN_REVISIONS`, which holds two revisions rather than five.** It named
  every revision the SDK can parse; it now names the two this host is exercised
  against. A handshake settling on `2024-11-05`, `2025-03-26` or `2025-06-18` is
  refused at construction instead of proceeding.

- **BREAKING: `policy::EVALUATOR_SEMANTICS` is replaced by
  `policy::evaluator_semantics()`, and it names Cedar's *language* version.**
  Every policy bundle digest moves once, so an open run resumed across this
  release is refused and must be re-admitted. After it, a Cedar upgrade moves no
  digest unless it moves the language version. `policy::CEDAR_LANGUAGE` is the
  revision this adapter is held to.

- **BREAKING (wire): the delegation chain no longer travels in A2A message
  metadata.** The extension still declares itself and still carries the
  capability and the provenance; the `chain` member is gone. Nothing in this
  crate read it. Take a peer's chain from the credential your authenticator
  issues.

### Fixed

- **A journaled policy bundle named an evaluator the build was not running.**
  The identity carried a hard-coded `cedar-policy/4.12.0` while the dependency
  requirement was a range and the build linked 4.13.0. It is read from the
  linked evaluator now.

- **A Cedar rule no request can satisfy is refused at construction**, named by
  its `@id`. Cedar 4.13 reclassified that finding from a validation error to a
  warning, so such a policy set had begun compiling silently.

- **BREAKING (API): `POST /halts` answers `reach` instead of `does_not_stop`,
  and the sentence now depends on the scope.** A `subject:` halt *does* reach
  runs already executing, which the old sentence denied for every scope. The
  operator guide is corrected to match.

### Known

- **The durable commit dominates what the gate costs.** Authorization runs about
  26 µs per effect at three rules and the label gate does not rise above the
  spread between identical runs; against ~8.5 ms of fsync neither is resolvable.
  Tune the store, not the policy set. What a *refusal* costs the work it stops
  is not measured here.

- **Reading hostile tool output in a side context is a pattern, not a runtime
  feature.** `planned` is the declarative answer when the task's shape is known
  up front; otherwise compose it from a `quarantined`-role call under
  `expecting(schema)`. The [security guide](https://hupe1980.github.io/agentplane/docs/security/#quarantining-a-parse)
  names the four things such a branch must not do.

- **Provenance is per value, not per claim.** A label's source set answers
  *influenced by these*, never *this sentence came from that one*, and that is
  settled rather than pending: the only derivable finer form is a verbatim span
  match, which would omit everything a model paraphrased. `Label::provenance`
  now says so.

### Changed

- **BREAKING (example): `journal_bench` is `gate_bench`, and it measures each
  control separately.** `just perf` reports the journal append, one policy
  evaluation and the label gate as deltas on the same store, beside the spread
  across repeated baseline runs. It needs `--features redb,cedar`.

- **The delegation chain's absence from a peer message is stated where it was
  contradicted.** Three passages in the guides still said a peer receives the
  caller's chain; the hop is checked against it here and the peer derives its
  own from the credential.

- **A verified export says what it structurally cannot carry.** Webhook delivery
  cursors and worklist decisions no run has consumed are store rows, not
  records, so they do not survive a restore — stated on every pass rather than
  discovered later as a fault. A lost cursor costs repetition; a lost decision
  re-opens the task.

- **A policy rule at an effect can name the revision that is acting.** The
  governing declaration now reaches `context.agent` at `effect:perform` and
  `information_flow.release`, not only at `run:admit` — same block, same
  construction. An effect's principal is the agent's name, which any manifest can
  claim, so a rule that trusts one revision binds to `context.agent.digest`. A
  run no declaration governs carries no `agent` block; guard with
  `context has agent`.

- **A throttled effect records the window the peer asked for.** `Retry-After`
  informed the schedule and reached no reader; `EffectFailed`'s message now
  names it, so a short throttle and a long one are distinguishable after the
  fact. It stays on the message rather than becoming a typed field a skill could
  branch on — a replayed failure is rebuilt from that string.

### Assurance

- **The benchmark refuses to time a run that did not do the work**, and the
  operations page is held to the axes it reports. A refused effect is faster
  than a performed one, so an axis that stops working reads as an improvement
  until something checks.

- **A memory formed from untrusted material names the sources it was formed
  from.** Provenance is the dimension nothing else supplies, and it had no
  test.

- **The interop page's revision set is held to the code's.** A revision this
  host refuses may not appear on the page as one it offers, and one it speaks
  must appear.

- **The versioned cryptographic domains are enumerated and held closed**, and
  in the published inventory: `RunAdmitted.policy_bundle` and
  `DeadlineRegistered.calendar_digest` are each derived through one.

- **An unresolvable field path is pinned at both gates.** A protected field
  whose pointer matches no member refuses the call; a field-scoped release
  naming an untracked path refuses the release. Both were already correct and
  neither had a test.

- **The `subject:` halt scope is exercised over HTTP**, both arms: a workload
  halt must not claim to reach running work, and a withdrawal must not repeat
  the workload sentence.

- **The chain's absence from A2A metadata is pinned**, together with the
  extension still carrying its own metadata, so the check cannot pass by the
  whole extension disappearing.

## [0.39.0] — 2026-09-18

### Added

- **`core::Operator` — who asked for an operator act, and what established the
  name.** `Basis` is `authenticated` (a credential named them), `asserted`
  (somebody with the store typed it) or `connected` (the party on a connection
  this runtime accepted, named by the channel). It is stored, never inferred
  from the surface an act arrived on.
- **`QuotaStore::lift_halt`**, so throwing a stop and lifting one are separate
  verbs rather than one call taking an `Option`. It answers whether a halt was
  standing — during an incident, *I cleared it* and *I cleared the wrong scope*
  are different facts.
- **`HaltScope::FORMS`** — the scope grammar, once. It was spelled in five
  places and the fourth form, `subject:`, had reached three of them.

### Changed

- **BREAKING — every operator act records who asked.** `Halt` and `LegalHold`
  gain `by`; `RunCancelled`, `BreakGlass`, `QuarantineDecided`,
  `EffectReconciled` and `Cancellation` carry an `Operator` where they carried a
  name; `AuthorityWithheld` gains the operator from the halt that withdrew the
  authority. The runtime cannot check any of these acts, so the name beside one
  is the whole of its evidence — and the two surfaces they arrive on establish
  that name differently.
- **BREAKING — `agentplane halt` and `agentplane hold` require `--actor`**, and
  record it as *asserted*. `Runtime::set_halt` takes the operator and the
  instant; `decide_quarantine` and `reconcile_effect` take an `Operator`.
- **BREAKING — the operator API returns `{actor, basis}`** for
  `cancellation_requested_by` and `decided_by`, rather than a bare name.
- **Both store schemas gained attribution columns** — `quota_halted`,
  `case_legal_holds` and `run_cancel`. Direct DDL edits; pre-alpha.

### Fixed

- **A conclusion whose attribution record was missing was served under the name
  `"unknown"`.** Four arms of one match fabricated an operator where a fifth —
  an exhausted run with no typed ceiling verdict — already quarantined. A
  fabricated actor is worse than a missing one: it is indistinguishable from a
  real operator with that name, and it reached the operator API as fact. All of
  them quarantine now.
- **Three pages said the second reader re-derives 27 record vectors.** It
  re-derives 29. The corpus grew with `AuthorityWithheld` and
  `AuthorityRestored`; the sentence counting it did not.
- **The emergency stop's fourth scope was invisible.** `subject:` — the only
  scope that reaches work already running — was missing from the CLI's `--scope`
  help, from the refusal a typo produces, and from the operator API's
  documentation. The grammar has one home now.

### Assurance

- **`decide_quarantine` and `reconcile_effect` lost a runtime check each**,
  because `Operator` has no empty value: what was a check on one path is now a
  property of the type on every path that builds one.
- Two mutations, both `--verify` KILLED: a conclusion given a fabricated name,
  and a store that records every halt as though the name had been typed.
- **A guard holds every published count of the record vocabulary to the tree.**
  The existing check asked whether the format specification *names* every record
  kind, which stayed green while the pages saying *how many* were wrong by two.

## [0.38.0] — 2026-09-16

### Added

- **The emergency stop is on the operator API** — `GET`/`POST /halts`,
  `POST /halts/lift`. Throwing and lifting are separate capabilities
  (`api:halt.place`, `api:halt.lift`): granting the power to stop the plane says
  nothing about who may start it again.
- **`GET /runs/live` — what is executing now**, and `Runtime::running_runs`
  behind it. Each entry carries the agent, its revision and the delegation
  subject; `?subject=` narrows. A slot whose lease has lapsed is marked
  `stranded` — the recovery sweep's to resume, not yours to cancel.
- **`HaltScope::Subject` — stop work by the authority it acts for.** The only
  scope that reaches runs already executing, and it **pauses** them: a run under
  a withdrawn credential stops at its next step boundary as `RunStatus::Withheld`
  with its completed work intact, and lifting the halt resumes it.
- **Two record kinds, `AuthorityWithheld` and `AuthorityRestored`.** The second
  supersedes the first, as `BudgetReadmitted` supersedes `BudgetRefused`; a
  reader takes the last word. The published
  [format specification](https://hupe1980.github.io/agentplane/docs/format/) now
  names twenty-nine kinds.
- **`runtime::Stores` and `Runtime::builder_with`** — the six store handles as a
  value, for a deployment that picks its backend at run time.

### Changed

- **BREAKING — `--store` takes a `postgres://` connection string**, and every
  verb that opens a store takes `--tenant` beside it. On the shared store the
  operator verbs run beside a serving plane, which on `redb` they cannot.
  [Upgrading](https://hupe1980.github.io/agentplane/docs/upgrading/).
- **BREAKING — `RunStatus` gained `Withheld`, `HaltScope` gained `Subject`**, and
  `HaltScope::covers` takes the delegation subject beside the agent identity.
  Exhaustive matches stop compiling, which is the intended way to find out.
- **BREAKING — `agentplane run --store` wires the whole plane**, as `serve` did.
  A manifest declaring memory or a wait built under one verb and was refused
  under the other.
- **The locked-store refusal says what to do about it.** *Database already open*
  did not say that something else holds the file, or that the shared store has no
  such rule.

### Fixed

- **Two reachable panics removed.** `RunFailure`'s `Display` had an
  `unreachable!()` on a status its own public field can hold, so formatting an
  error panicked. Two copies of a JSON type-name match carried another; all three
  are now `core::canon::json_kind`.
- **A poisoned mutex no longer becomes a permanent fault.** The drain deregisters
  a run from a `Drop`, so a poisoned lock aborted the process. `core::poison::recover`
  states the rule per lock; the ledger keeps its propagating unwrap.
- **The A2A request future is boxed.** It carried the executor's locals — sixteen
  kilobytes on the stack per concurrent request.

### Assurance

- **The CLI smoke check says why a verb failed**, holds an export to its tenant,
  and holds a build without `postgres` to naming the feature.
- **The documented-flag guard follows `#[command(flatten)]`.** It modelled a
  flattened field as a flag of its own.

## [0.37.0] — 2026-09-14

### Added

- **`spec.input`** — the reviewed shape an agent *takes*, mirroring
  `spec.output`. Optional, digest-covered, refused when it constrains nothing.
  It is what a catalogue offers a model as an `inputSchema`.
- **`Manifest::input_schema`**, for a catalogue to offer.
- **A served catalogue refuses a capability nothing on the plane provides**
  (`ServeError::NoProvider`), at construction rather than at the first call.
- **Serving MCP — `mcp-server`, `tools::serve::McpServer`.** Agents as MCP
  tools and their reviewed instructions as prompts, admitted through the funnel
  an A2A message takes. A suspended run answers as a **Task whose id is the run
  id**, so `tasks/get` reads the journal rather than a table beside it.
  One resource is served — the declaration, with its digest — and nothing that
  carries a payload. Older revisions are refused; the
  [status page](https://hupe1980.github.io/agentplane/docs/status/) says why.
- **`testkit::conformance_policy`** — the contract `PolicyEngine` states in
  prose and no signature expresses: total, pure, no state carried between
  requests, a refusal that names a rule, a bundle identity that does not move,
  and a `digest` that is the bundle's. Run it against the engine you wire, not
  a stand-in.
- **`blob::TOMBSTONE_FORMAT_VERSION` is reachable.** It was declared inside a
  private module, so one of the five durable-format versions had no path a
  reader could name — and the enumeration that calls itself closed could not be
  checked by anybody.
- **Legal holds on cases — `CaseStore::place_hold`, `release_hold`, `hold`,
  `holds`, and the `agentplane hold` verb.** The one control that makes an
  erasure *fail*: a retention pass runs on a window nobody re-reads, and the
  matter somebody has been ordered to preserve looks exactly like every other
  closed case old enough to sweep. The hold is checked before the first
  tombstone, so a refusal leaves nothing half-erased; `retention::plan` reports
  `due` and `held` separately so a dry run and a pass agree; and
  `RetentionReport::held` is its own field, because a control doing its job must
  not read as a failure. Holds were previously available on memory items only.
- **Two examples for surfaces that had none** — `serve_mcp` drives this plane's
  MCP server with the SDK's own client over an in-process pipe, and
  `retention_hold` runs a retention pass against a matter under a preservation
  order. Both are in `just examples`.
- **Hold routes on the operator API** — `GET /holds`, `POST /holds`,
  `POST /holds/release`, under three separate capabilities. `api:hold.place` and
  `api:hold.release` are deliberately not one grant: placing a hold preserves
  data and lifting one is what lets the next pass destroy it, so *who may
  authorise destruction* is handed out separately from *who may prevent it*.
- **`MemoryStore::legal_holds`** — the listing the item-level hold never had.
  `legal_hold(id)` answers only for somebody who already knows which id to ask
  about, which is detection without delivery.
- **Every cacheable MCP result carries `ttlMs` and `cacheScope`**, `private` and
  `0`. Required by the revision this server speaks, and not decoration: the
  protocol's default scope is `public`, so an omitted field lets a shared
  intermediary hold a governed declaration and serve it to somebody else — a
  copy no erasure reaches.

### Changed

- **BREAKING — the erasure verbs return `blob::EraseError`, not `BlobError`.**
  `erase_case` and `erase_run` are not blob operations: they walk a case, expire
  each blob and destroy a key scope, and they can now refuse outright. Folding a
  refusal into `BlobError` made two unrelated reads — the drill's `get`, and
  `ScopedBlobs`'s error renaming — match a state neither can observe. Match on
  `EraseError::{UnderLegalHold, Blob, Store}`.
- **BREAKING — `CaseStore` and `MemoryStore` gained methods.** Any store
  implemented outside this crate needs `place_hold`, `release_hold`, `hold`,
  `holds` and `legal_holds`. The conformance batteries cover all of them.
- **BREAKING — external media retention scopes are namespaced `media/<policy>`.**
  An erasure scope is `tenant/<unit>`, and the two free-text vocabularies feeding
  `<unit>` now carry a prefix each: a policy named `alice` and a memory subject
  named `alice` otherwise shared a key, so one unit's erasure destroyed the
  other's — the failure `TenantId`'s refusal of `/` prevents, one level down.
  Bytes sealed under the old scope are unreachable through the new one;
  pre-alpha, so recreate.
- **BREAKING — `ErasureCoordinator::acquire` takes an `UnderLock` proof.** Only
  `under_lock` can construct one, so taking a lifecycle lock without the
  release-on-both-paths wrapper is a compile error rather than a rule in a doc
  comment. A decorating coordinator forwards the proof it was handed.
- **`Lease::new` and `Lease::token` are public.** `ErasureCoordinator` is a
  seam, and without a constructor it was a public trait nobody outside this
  crate could implement.
- **`UnderLock::for_test` under `testkit`**, because a distributed lock is only
  testable by being held across an assertion, which `under_lock`'s closure
  cannot do. A guard refuses any call to it from the crate itself.
- **BREAKING — `Lease::holding` carries the lock**, so dropping a lease releases
  the scope. `release` remains the tidy path.

### Security

- **`rustls` 0.23.45** (RUSTSEC-2026-0285, medium): TLS 1.3 handshake messages
  were accepted across encryption-level boundaries. Reached this tree through
  every HTTPS path — `reqwest`, the A2A server, the MCP client, the AWS SDK.

- **A cancelled erasure could strand a subject permanently.** Two paths, both
  silent: a dropped `Lease` released nothing, and a cancelled `acquire` returned
  a pooled connection whose abandoned lock request was granted the moment the
  holder released. Every later erasure of that subject blocked forever. A lease
  carries what holds the lock and the lock session is detached from the pool;
  both paths are pinned against a real `PostgreSQL`.
- **A provider could report its way under a budget.** `Usage::spend` summed the
  `input_tokens` and `output_tokens` a provider returned with a plain `+`, and
  a provider is untrusted data: a response claiming `u64::MAX` input tokens
  wrapped to a spend of **zero** in a release build, so the run counted as free
  against its ceiling. `Spend::plus` was already saturating for exactly this
  reason; this is the addition one step earlier, where the outside gets in.

### Fixed

- **Every command in the documented recovery drill failed.** `operations.md`
  spelled `export --out` (there is no such flag), and gave `verify` and
  `restore` a `--file` where both take a positional, with `--anchor` for what is
  spelled `--checkpoint`; `serve --manifest` was positional too. The block an
  operator copies under pressure was the one that had drifted.
- **`SealedCases::by_status` filtered on a branch that cannot be taken**, which
  read as *erased cases are dropped from a listing* and was neither true nor
  what the memory decorator beside it does.
- **Six items had no description at all**, their summaries absorbed by the doc
  comment above them or never written. `netguard::all_public` — the SSRF gate —
  was the worst: its summary sat on the error enum below it, carrying the
  instruction to connect to exactly the addresses it returned onto a type its
  caller never reads.
- **The architecture page counted two determinism escapes where there are
  thirteen**, and presented lint gating as a layer that protects a skill author
  — it is this crate's `clippy.toml` and does not reach your crate. The page
  now carries the stanza to copy and says which layer holds regardless.
- **The status page said nothing about the Agent Client Protocol**, which is
  the question an adopter running coding agents arrives with. It is answered,
  in both directions.
- **The security page did not say who the sensitivity lattice governs.** It
  governs what may leave *a run*, so the operator API returns journal payloads
  to whoever holds the read verb — correct for the party whose journal it is,
  and the boundary an adopter needs stated before putting anything else in
  front of those records.

### Assurance

- **A documented command line is checked against the CLI.** Flags are read out
  of the clap definitions, so the check runs wherever the tests do rather than
  only where the binary is built. `upgrading.md` is exempt: showing the old
  spelling beside the new one is that page's content.
- **A documented function name is checked without a parenthesis.** The guard
  holding the guides to the crate's real surface only flagged an invented name
  written as a call, and these pages cite a member as `BlobStore::expire` far
  more often than as `expire(..)`. It now checks both, and knows public fields,
  consts and enum variants. Names the upgrading page mentions *because they were
  removed* are asserted absent rather than exempted, so resurrecting one fails.

- **Every sealing decorator is run through the contract it re-implements.** A
  key ring makes the wrapper the store the runtime is given, and only the blob
  decorator had ever been handed a battery. All six pass; a guard holds each to
  a named battery run.
- **The doc-comment guard could not see the defect it is named for.** It
  required the line before an absorbed summary to end a sentence, so an
  absorption separated by a blank line passed — and its own advice was to add
  that blank line. It now also refuses any item whose documentation opens on a
  `# Errors` or `# Panics` section, which is what an absorbed summary leaves
  behind.
- **Every durable format is held to version 1, and the list of them is held to
  being complete.** Pre-freeze a shape change is a hard cut rather than a bump,
  and the enumeration is documented as closed — but nothing compared the
  constants against it, and a sixth format would have been discovered at the
  freeze.
- **The changelog cannot describe a released version again.** A guard reads the
  tags: a version that is tagged may not still be headed *unreleased*, and the
  newest entry must be the version in `Cargo.toml`.
- **Seven public functions were exercised by nothing**, and are now tested. A
  guard refuses a public function that nothing calls and no test names.

## [0.36.0] — 2026-09-13

### Added

- **`core::seconds_after`** — the one conversion from a window of seconds to an
  instant, failing both ways it can. With `core::MAX_WINDOW_SECONDS`,
  `first_instant()` and `last_instant()`.
- **`memory::access_expiry`** — where a sliding access window lapses, public
  because a custom `MemoryStore` indexes on the same instant.
- **`DeadlineState::is_unaccounted`** — the obligation listing's membership
  rule, on the vocabulary rather than beside one reader.
- **`runtime::Redelivered`** — what a redelivery pass finished, and how much of
  the waiting list it examined.
- **A conformance battery for `BlobStore`**: `testkit::conformance_blob`.
  `check` is the contract every store carries; `check_backing` adds the
  envelope pair, which a sealing decorator refuses on purpose. Run it against
  your composed handles, not only your backend.
- **A conformance battery for `Calendar`**: `testkit::conformance_calendar`.
  Hostile counts are derived from the specs you declare supported.
- **`BlobError::UnreadableTombstone`** and **`StoreError::BlobErased`**.
- **`tools::TaskRetention`**, replacing `McpTaskSnapshot::ttl_ms` — **BREAKING**,
  because `ttlMs` is nullable and `null` means *unlimited*, which an `Option`
  could not tell from *unstated*.

### Fixed

- **An erasure could be undone by ordinary work.** A blob's address is its
  content, so a run producing the same bytes again landed on the object an
  erasure removed and put the data back. `put` and `put_at` now refuse an
  erased address.
- **An unreadable tombstone read as a completed erasure.** The object-store
  backend defaulted both halves of a damaged tombstone to *expired at the
  epoch*, which the recovery drill counted as retention working. It is a
  versioned record with a fallible reader now, and a finding when it does not
  read. **BREAKING** on disk: recreate rather than migrate.
- **A refused erasure-undo was classified as a store outage**, so a media fetch
  kept re-fetching an artifact somebody had removed.
- **BREAKING — a restore was judged by the log's name.**
  `RestoreReport::is_faithful` compared the whole checkpoint, so a byte-perfect
  restore into another tenant reported as a failure and `agentplane restore`
  exited non-zero on it. The verdict is the commitment: same root at same size.
- **A manifest could abort the process.** A declared retention window, a
  deadline's `params`, and `--older-than-days` each reached `time` arithmetic
  that panics rather than returning. All three refuse now.
- **A grace window a caller could not subtract ended the sweep tick.**
- **An audit withheld a run's warrant because the run had a finding.**
  `releases` and `warrants` are collected once the chain verifies, so the run an
  investigator opened the report for carries both. A run's faults are reported
  together rather than at the first one.
- **The redelivery pass could not say it was behind** — five capped sweeps, four
  saturation flags. **BREAKING**: `Saturation` gains `redeliveries`.
- **A listing page's read could wrap to nothing** at a ceiling of `usize::MAX`.

### Changed

- **BREAKING — a declared retention window is bounded above as well as below.**
  `spec.memory.formation.retention_seconds` and `access_retention_seconds` are
  refused past the span a timestamp can name.
- **The obligation listing's membership rule is one rule.** Two functions each
  documented themselves as the only one, and the one in `core` had no caller;
  a guard now holds the SQL copy to naming both of its conjuncts.
- `clippy::duration_suboptimal_units` is no longer allowed: the unstable
  constructors it asks for reached the declared MSRV.

### Assurance

- **The disaster-recovery release blocker is discharged, and no release
  blockers remain.** The drill now runs against a real
  `PostgreSQL` server, restores into a tenant of a database another tenant is
  using, and ends by admitting new work whose seal extends the restored log.
  RPO/RTO targets are on the operations page.
- **Format-freeze condition 7 is met**: the algorithm-agility plan is
  [written down](https://hupe1980.github.io/agentplane/docs/format/#algorithm-agility)
  and was already implemented — signatures agile by key, hashes by version,
  nothing rehashing stored bytes. `canon` is stated to name the digest
  algorithm as well as the canonicalization rule, which is what makes a hash
  replacement a bump rather than a migration.
- **The open-before-freeze list was tested against its own membership rule.**
  Four of twelve questions change no durable format and no protocol whichever
  way they are answered; they moved out, so the freeze is not shown as blocked
  on work that cannot block it. Eight remain.
- **The design is graded against the OWASP Top 10 for Agentic Applications.**
  Five of ten rows carry no residual, four carry one that is now written down,
  and one states a non-goal, with every residual written down. Internal
  documents only; nothing in the crate moved.
- The mutation harness can anchor a unit test inside a binary.
- Mutation count **738**.

## [0.35.0] — 2026-09-13

### Added

- **GenAI span attributes.** A completion's effect span carries
  `gen_ai.provider.name`, `gen_ai.request.model`, `gen_ai.response.model`,
  `gen_ai.response.finish_reasons`, `gen_ai.usage.{input,output}_tokens` and the
  cache split `gen_ai.usage.cache_{read,write}.input_tokens`; a tool call carries
  `gen_ai.tool.name`; the run span carries `gen_ai.agent.name` and
  `gen_ai.conversation.id`. Two new `Effect` seams supply them,
  `gen_ai_request` before dispatch and `gen_ai_response` after the answer. Both
  default to `None`, so a non-`GenAI` effect claims none of them.
- **`Completion::model` — the model that answered.** Filled by every driver whose
  wire names one, buffered and streamed; `None` for Bedrock's `Converse`, which
  names none. A journaled effect output, so a run's evidence answers *which
  weights served this* rather than which were asked for.
- **`error.type` on a failed attempt**, carrying the fault class — `timeout`,
  `refused`, `rate_limited`, `metered`, and the rest of `EffectError::class()`.
- **`agentplane.effect.key` on an effect span** — the join between a trace and the
  journal. A digest over the call, so it discloses no argument value.
- **`JournalStore::read_page(run, from, limit)`**, the bounded read.
- **Both record-serving surfaces now show a record's envelope** — `run`, `case`,
  `step`, `phase` and `effect_key` beside the payload, from one shared renderer.

### Changed

- **BREAKING — five admission methods removed**: `spawn_once`, `spawn_in_case`,
  `spawn_in_case_once`, `spawn_correlated`, `run_in_case_once`. None had a
  caller. Each is `run_under`/`spawn_under` with `RunTerms`, which composes a
  case binding, correlation keys, an idempotency key and a per-run chain.
- **BREAKING — where the convention names a fact, its name is what is emitted.**
  `agentplane.agent` is `gen_ai.agent.name`; `agentplane.case.id` is
  `gen_ai.conversation.id`, because a second spelling in this crate's namespace
  is read by nothing generic. The bare `semconv` field is `agentplane.semconv`.
- **BREAKING — `JournalStore` gained a required method.** `read_page` is required
  rather than defaulted to read-then-truncate, because that default is the defect.

### Fixed

- **A restore reset the fencing token.** An export carries no lease table, so a
  restored run whose records reached epoch 7 was leased at **1** — and quota
  settlement identifies a pass by that number. A first lease now starts one past
  the highest epoch the run's journal records, on both backends. An epoch issued
  and never written under stays the runbook's: the old deployment must not reach
  the restored store.
- **An erased effect answered the trait's defaults for the two `GenAI` seams.**
  `Box<dyn AnyEffect>` forwarded 16 of `Effect`'s 18 methods, and every `Effect`
  method has a default — so the same call opened a span naming a model when
  typed and naming none when boxed. A guard now holds the three method lists to
  each other.
- **`agentplane.run.failed` was emitted and published nowhere.** It is the event
  added *because* an operator running the shipped server had no way to learn why
  a run failed — and it was in neither `telemetry::LOUD_EVENTS`, the list a
  deployment wires its alerts from, nor the operations page's table headed
  *every*. The delivery it exists for routed around it.
- **`agentplane.witness.integrity` was emitted as a field, not a target.** Every
  other event carries its identity in its `target`, so a subscriber filtering the
  way the operations page prescribes received nothing — for the one event whose
  audience is not the operator running the plane.
- **The effect span carried no `agentplane.mode`**, while the module doc says
  every span carries it and makes that argument about effect latency specifically.
- **A failed span said only that something failed.** `agentplane.outcome` makes a
  failure countable and says nothing about what went wrong, so a dashboard built
  on the convention reported a plane with no failures at all — the one claim this
  runtime exists not to make.
- **`GET /runs/{run}/history` read a run's whole remaining journal per page.**
  The page bounded what was returned; nothing bounded what was read, so walking a
  long run cost the square of its length. Checked in the store contract battery,
  because a backend ignoring the limit serves byte-identical answers and differs
  only in what it costs.
- **Both record-serving surfaces dropped the envelope.** A reader could see that
  an effect started and not which effect, could not pair a start with its outcome
  or one attempt with the next, and could not tell a forward record from a
  compensating one.

### Known

- The convention's Opt-In content attributes — `gen_ai.input.messages`,
  `gen_ai.output.messages`, `gen_ai.system_instructions`,
  `gen_ai.tool.definitions`, `gen_ai.tool.call.arguments` — are not emitted and
  will not be. A prompt is where governed values arrive, and a trace exporter is
  an egress the sink gates do not cover. Also absent, each for its own stated
  reason: `gen_ai.response.id`, `server.address`, and `gen_ai.provider.name` on
  the run span.

### Assurance

- **The three properties the disaster-recovery blocker named as unasserted now
  have tests**, and writing them is what found the fencing defect above: lease
  reset on both backends, tenant isolation in both directions, and the event
  half of wait recovery — including the loss it prevents, since a message
  delivered before the repair buffers and a buffered message nobody claims
  dead-letters.
- Mutation count **725**.

## [0.34.0] — 2026-09-11

### Added

- **Graceful shutdown.** `agentplane serve` drains on `SIGTERM`/`SIGINT` rather
  than being cut off mid-effect. `--drain-secs` (default 25,
  `AGENTPLANE_DRAIN_SECS`) bounds it; whatever is still running when it ends is
  named on stderr. Keep it under the supervisor's own kill timer.
- **`Runtime::drain(grace) -> DrainReport`** and **`Runtime::is_draining()`** —
  the same for an embedder, the second for a readiness probe. Run the drain
  *beside* your own shutdown (`tokio::join!`), not after it.
- **`RuntimeError::Draining`** — admission refuses while an instance stops,
  before the lease and before the first append, so a caller retries elsewhere
  with nothing to reconcile. On A2A: `-32031` / `DRAINING`, beside
  `-32029 QUOTA_EXHAUSTED` and `-32030 HALTED`. A2A subscriptions end on a drain.
- **`Budget::max_egress_bytes`** and `spec.budgets.max_egress_bytes` — bounds
  bytes sent into sinks. Exact, not overshooting: the effect that would cross
  the ceiling is the effect refused. `BudgetExceeded::Egress { allowed, used,
  attempted }`; `Consumed::egress_bytes` is the tally. Reads cost nothing, and
  `0` means *may read, may not send*.
- **`GET /runs/{run}/history?from=<seq>`** serves one run's records, cursored by
  `next_from`. Needs the new action **`api:run.history`** — grant it, or the
  route is refused to everybody.
- **`RunView.decided_by`** on `GET /runs/{run}`, from a new `RunStatus::actor()`
  — who ended the run, distinct from `cancellation_requested_by`.
- **`RunStatus::Swept` and `RunStatus::BrokeGlass { actor, reason }`.**
- **`FakeProvider::without_constrained_decoding()`** — opt out of the new schema
  refusal for a provider that genuinely accepts more.
- **`examples/camel_live.rs`** — the dual-model (CaMeL) pattern against two real
  OpenAI models, asserting at the wire which one was shown the injection.
  `just camel-live`.
- **Live batteries for the `OpenAI`-compatible wire and the embedding wire.**
  `HF_TOKEN`, or `CHAT_COMPLETIONS_BASE_URL` pointed at a local engine.

### Changed

- **BREAKING — a plan step's `args` and a parse step's `schema` are JSON text.**
  Constrained decoding has no free-form object, so the old plan format could not
  be asked for at all. `tool`, `args`, `parse` and `answer` are required and
  nullable. Affects hand-written plans only.
- **BREAKING — a declarative agent's object schemas must be closed.** Every
  object in `spec.output.schema` and `spec.tools[].arguments` needs
  `additionalProperties: false`, refused at parse. Coded agents are exempt.
- **BREAKING — `FakeProvider` refuses a schema constrained decoding cannot
  enforce**, before generating, as the `OpenAI` driver does. Its echo now also
  stops at `max_output_tokens`, reporting `truncated`.
- **BREAKING — `ToolBox::with` closes the schemas it generates.** `schemars`
  omits `additionalProperties: false`, so typed tools were advertised without
  constraint. A tool declaration is in a model call's effect key, so replaying a
  journal written before this reports divergence on the first such call.
- **BREAKING — a formed memory's content is a string.** The forming schema
  declared `"content": {}`, which constrained decoding refuses.
- **A drain releases no lease.** A release asserts *takeover is safe now*, and
  for a run inside `perform` it is not. The residue of a drain is deliberately
  that of a crash: an expired lease still naming an owner, which the recovery
  sweep reads.
- **`Spend` and `Sensitivity` implement `Display`.** Refusals said
  `Spend { tokens: 0, minor_units: 5000 }` and named a level `Internal` where
  the manifest says `internal`.
- Seven `nursery` lints enabled (`or_fun_call`, `redundant_clone`,
  `needless_collect`, `needless_pass_by_ref_mut`, `string_lit_as_bytes`,
  `use_self`, `too_long_first_doc_paragraph`) and the 48 findings fixed.
- `just --list` publishes a summary per recipe instead of the tail of a
  paragraph.

### Fixed

- **`execution.kind: planned` had never run against a real provider.** Its plan
  format fell outside the subset constrained decoding accepts, so the `OpenAI`
  driver refused it before sending.
- **A prompt field named `input` was mistaken for the wire's own.** The
  declarative planner's prompt is `{ system, input, tools }`; five drivers read
  `input` as an envelope and sent one field, dropping the rest. The envelope now
  opens only when the object carries nothing else but `system`.
- **A continuation with no tool exchanges is refused in one place.** The rule
  was written three times across drivers and implemented by `FakeProvider`
  nowhere.
- **`spec.memory.formation` could not run against a real provider**, and typed
  tool arguments were advertised without constraint.
- **`strict_schema_problem` was missing four rules**, each verified against the
  live API: an array with no `items`, `oneOf`, `allOf`, and a subschema with no
  `type`. It is now public.
- **Ten published manifests declared schemas no `OpenAI`-backed run could use** —
  four shipped `examples/*.yaml` and five documentation pages.
- **A reviewed prompt could name a tool in the model's own spelling**
  (`server__tool`) without that name being granted. Both spellings are checked
  now.
- **The drain gate would have refused the runs it was waiting for.**
  `cx.commission` admits through the same funnel; admission now takes an `Entry`
  argument distinguishing a caller from a run already executing here.
- **A break-glass crossing reported itself as `quarantined`**, replacing the
  operator's stated reason with a sentence about the build. A guard now holds
  every spelling in `OUTCOMES_OF_RECORD` to a status that spells itself back.
- **Seven entries were filed one release late.** They described work that
  shipped in 0.31.0 and are now under it; a reader on that version was told they
  lacked six things they had.
- The security page said what `max_denials` *checks* rather than what it bounds:
  the channel a model can probe is the sink refusal, not an engine denial.
- Three source comments narrated a previous implementation rather than the rule.

### Assurance

- **Every constitutional invariant names the evidence for it.** Reading the
  suite against what the runtime is *required* to do found six tests — for the
  announce-act-record protocol and the effect key it turns on — that no mutation
  named. A guard holds every invariant to naming at least one that exists.
- Mutation count **715**.

## [0.33.0] — 2026-09-10

### Added

- **`RuntimeBuilder::witnesses(witnesses, quorum)`** — the witness tier had no
  caller: nothing submitted a checkpoint and nothing read one back, while
  `verify --checkpoint` told operators to supply one a witness cosigned.
  Submission runs last on `sweep`, off the run path.
- **`SweepReport.{cosignatures, witness_shortfall, witness_integrity}`**, the
  last two in `needs_attention`. An integrity refusal also emits
  `agentplane.witness.integrity`.
- **`WitnessReader`**, separate from `Witness`: submitting needs the log's
  signing key, reading needs only the URL and the keys the reader trusts. Speaks
  `tlog-witness` monitor retrieval; `HttpWitness` gained a `monitoring` prefix.
- **`BuildError::WitnessQuorumUnreachable`** — refuses a quorum larger than the
  witness list, and a witness list with no quorum.
- **`agentplane audit --witness <prefix> --witness-key <name>=<base64>`**, and
  the same on `verify` (which also needs `--origin`). Two witnesses disagreeing
  on one tree size print `SPLIT VIEW`. `cli` now enables `witness-http`.
- **`export::runs_in_flight(store, limit)`** — `agentplane export` includes
  in-flight runs by default and says how many on stderr; `--outcome` turns it
  off.
- **`RestoreReport::awaiting`** — the run ids that came back waiting, since a
  restored wait is armed by nothing until its run is resumed.
- **`AuditReport::held_to`** — which checkpoint the audit ran against.

### Changed

- **BREAKING — `MemoryWitness::new(signer, observed_at)`** takes an observation
  timestamp and refuses one at or before the epoch.
- **BREAKING — `HttpWitness::new`** takes a `LogKey` where it took a
  `NoteSignature`.
- **BREAKING — `Witness` has no `latest`.** Reading is `WitnessReader`.
- **`WitnessError::Inconsistent` and `::Unsigned`** are new variants.
- `RestoreReport` gained a field; `runtime::observed_status` lost its `http`
  feature gate.

### Fixed

- **The witness client could not have submitted to a real witness.**
  `HttpWitness` held the log's note signature as a configuration field, but a
  `signed-note` signature covers the note body, which changes every checkpoint —
  so it was correct for one submission and `403`d forever after, blaming key
  registration.
- **A `422` was reported as `Forked` whatever its cause.** Only equal sizes with
  unequal roots stays `Forked`; a `422` on growth is `Inconsistent`, and the two
  causes the client can see are refused before a request goes out.
- **A cosignature with timestamp zero was counted**, which `tlog-witness`
  forbids in as many words.
- **Six outbound clients followed redirects and honoured an ambient proxy.** The
  egress allowlist is consulted once, for the first hop, and `reqwest` strips
  only three headers across origins — so `x-api-key`, `x-goog-api-key` and
  `X-Vault-Token` travelled, and a 307 re-sent the prompt body. All nine now go
  through `netguard::guarded_client`, held by a guard.
- **A refused redirect was reported as the provider being unavailable**, so the
  retry ladder spent every attempt on an answer that could not change.
- **An export taken for disaster recovery carried no run that was still
  working.** The default sweep indexed conclusions only. The loss was invisible:
  the Merkle log commits to sealed runs, so the file rebuilt to the same root at
  the same size.
- **A verified anchor's basis was printed to stderr and lost at the first
  redirect**; a split view printed and did not bind; an offline verification was
  silent about the tails it cannot pin.

### Assurance

- Mutation count **689**. Seven new anchors.

## [0.32.0] — 2026-09-08

### Changed

- **BREAKING — ids carry their type prefix everywhere, including on the wire.**
  `Serialize` writes `run_01J8Z…` where it wrote the bare ULID; `Deserialize`,
  `parse` and new `FromStr` impls on `RunId`/`CaseId`/`BatchId` accept both. A
  refusal names the type and the input instead of surfacing `ulid`'s
  `invalid length`, and `parse` strips only its own type's prefix. Durable-format
  cut: every chain digest moves, so recreate the store with `export`/`restore`
  rather than migrating.

## [0.31.0] — 2026-09-07

### Added

- **`core::ACTIONS`, `PolicyRequest::is_effect` and `is_admission`** — a
  `PolicyEngine` can now tell which requests it will be asked. `ACTION_DECLARED`
  and `ACTION_EGRESS` are documented as never asked.
- **`EffectStarted.outbound_bytes`** — how much a call sent is a question the
  journal answers.
- **`agentplane validate --require-annotation`.**
- **`BatchStore::items_needing_attention(batch, limit)`**, `BatchReport::exhausted`,
  `BatchReport::needs_attention()`, `ItemOutcome::is_settled` and `settled_tags`
  — a batch's unsettled items are a listing rather than a count. Both backends
  implement it.
- **`QuotaStore::running_runs(limit)`** — the runs holding a tenant's
  concurrency slots, named rather than counted.
- **`examples/batch_run.rs`.**

### Changed

- **BREAKING — the published binary and container image no longer carry
  `testkit`.** The deterministic provider moved to a `fake-model` feature;
  `agentplane::testkit::FakeProvider` still resolves, and `testkit` implies
  `fake-model`.
- **BREAKING — redb 3 → 4** (the on-disk format moved: recreate the store),
  **rand 0.9 → 0.10** (`rand_chacha` gone, `rand` re-exported as
  `agentplane::rand`), **ulid 1 → 3** (`Ulid::new` → `generate`), base64 0.23,
  jsonschema 0.55, chacha20poly1305 0.11.
- `just examples` builds twice rather than thirteen times; a test-only AWS
  dependency is no longer linked into every example.

### Fixed

- **`max_denials` did not bound the refusal a model can actually probe.** It
  counted engine denials; the probeable channel is the sink refusal, which comes
  back as `REFUSED` and lets the loop continue.
- Three egress refusals read as two sentences spliced together, and a refusal by
  this plane was reported as the provider refusing.
- An audit report was silent about the runs that never started.
- The CLI reached A2A peers over plaintext and said nothing.
- `RunId::generate` documented itself as monotonic, which it is not.

### Assurance

- A guard computes the feature closure and holds `testkit` out of the published
  binary; the entropy stream behind `StepCtx::rng` is pinned to literal words.

### Known

- `opendal` is held at 0.58 because 0.59.0 does not build.

## [0.30.0] — 2026-09-06

### Added

- **The record format has a published specification**, and
  **`tools/verify_export.py`** — a second implementation that reads it and
  derives the same bytes. `--canon-check` re-derives all 27 record vectors from
  their parsed values; `--self-test` damages an export six ways and asserts each
  is reported.
- **An obligation backlog verb.** `CaseStore::acknowledge_breach(case, name, …)`
  and a level that falls: the obligation stays `Breached`, what ends is the
  question. Breaking on four types.
- **`netguard::intake` is public** — a response-size bound for drivers this
  crate does not ship.

### Changed

- **BREAKING — canonical spellings replace string matching.** `Phase::as_str`,
  `Priority::rank`, `TaskState::is_queued`/`is_pending`/`awaits_expiry` and
  `ItemOutcome`'s five hand-written spellings are now single sources: a rank was
  a table with an `_ => 3`, six decoders refused what their own writer emitted,
  and `Phase` had no canonical spelling at all.

### Fixed

- **The format specification was not implementable as written**: the export's
  dispatch rule contradicted itself, the record line's members were never named,
  the case block's members were never given, the trailer's `unreadable` entries
  had no stated shape, and the step that decides what verification means was
  omitted.
- **The record format's conformance corpus pinned bytes nothing writes.** Every
  vector in `records.jsonl` changed; no journal moved.
- The export corpus had no case layer.
- Every PostgreSQL fault reported itself as `db error`.
- An obligation nobody could read stopped being outstanding.
- **A counterparty could decide how much memory its answer cost.** Only governed
  media had the bound; the streamed path had half of it.
- A documentation link pointed at an unpublished API, and the gate-parity guard
  could only see half of a workflow — its first version could not fail.

### Known

- Two response bodies this crate never holds, so it cannot bound them: MCP over
  stdio or streamable HTTP (framing belongs to `rmcp`), and Bedrock (the AWS SDK
  owns the transport).

## [0.29.0] — 2026-09-05

### Added

- **The quarantine has verbs.** An operator can assert a missing fact, reopen a
  run for judgement, or abandon it — and abandoning leaves a record. An
  assertion supplies a missing fact and never replaces a recorded one; the value
  supplied is untrusted, not by the operator's choice; abandoning unwinds
  nothing, because impatience is not evidence.
- **The two backlogs an alert pointed at and nothing could open** are now
  listable.
- **The durable formats are pinned to bytes** rather than to their own reader.

### Changed

- **BREAKING — `Runtime::request_cancel` refuses a quarantined run.** Cancelling
  asks for work to be undone; a quarantine means the runtime cannot say what
  happened.
- `export` and `audit` sweep quarantined runs by default.
- The documentation is grouped rather than a list of nineteen pages.

### Fixed

- **Every record carried a schema version and no reader ever looked at it.**
- Writing off an unexplained mutation announced nothing.
- Six sealing arms could gain a payload field and seal nothing.
- The local gate did not compile the tests CI compiles.
- Every emoji in a heading was naming that heading's URL.

### Assurance

- A hand-written list of an enum's variants that nothing held to the enum.

## [0.28.0] — 2026-09-05

### Added

- **`spec.budgets.max_parallel_steps`.**
- **`RuntimeBuilder::require_verifier()`.**
- **`agentplane.runs.quarantined`**, the level behind the quarantine counter.

### Changed

- **BREAKING — `RunOutcome::spend` is now `RunOutcome::consumed`.**
- The architecture page is six pages.

### Removed

- **BREAKING — `PlanNode::quorum`.** A panel is a subgraph.

### Fixed

- **`max_wallclock_secs` had never been enforced.**
- **A ceiling checked once per member of a ready set was that ceiling multiplied
  by the set's width.**
- **A replayed run reached a different tally than the run it replays**: a
  recorded failure was billed twice, a superseded record's figure was dropped,
  and a reconciliation was a second slot on one path and none on the other.
- The operator view had its own rule for what a run's history says — an
  `exhausted` conclusion with no typed ceiling was reported as one, and an
  uninterpretable outcome string was echoed straight through.
- A subscription phase this store could not read was answered `Forward`.
- The table of *every* event listed ten of fourteen, and the page arguing the
  project is falsifiable was the part nothing falsified.

### Known

- Nothing resolves a quarantine, and the gauge says so.

## [0.27.0] — 2026-09-03

### Added

- **An emergency stop that names what it stops** — halt a tenant, an agent, or
  one revision.
- **A durable manifest registry** with an enumerable inventory, and
  **`metadata.annotations`**.
- **A retention pass**, with an honest account of what it cannot reach.
- **A plane can bound what it writes down** (`max_sensitivity_journaled`).
- **A reviewer can be shown consequences**, not only the instruction — a tool
  grant's `preview`.
- **The egress allowlist reaches the tool path.**
- **`--drill-every`**, and the observability last mile.

### Changed

- **`agentplane retain` lists; it does not pretend to erase.**
- The mutation sweep is ordered by what it builds; dependencies updated, and the
  MCP fixtures state their version.

### Fixed

- **A concurrent publish could overwrite a published version on Postgres.**
- **A halt mid-batch failed every remaining item, permanently**; a halt reached
  peers as back-pressure; a halt was displayed as a quota.
- **Retention skipped every case on a sealed plane with no blob store.**
- A preview's whole answer went into the worklist row.
- A policy denial — and a Cedar denial — names the rule rather than the request
  or `policy1`; a sink argument mismatch says where the two values differ.
- `max_denials` is declarable in a manifest.
- The replay marking, as documented; the security model implied an egress
  coverage it did not have.

## [0.26.0] — 2026-09-01

### Changed

- **BREAKING — conclusions are typed and are no longer called seals.**

### Fixed

- Quota accounting keeps one identity across a live pass.

## [0.25.0] — 2026-08-30

### Added

- **Audience and validity attenuate, and bind at admission.**
- **Peers are wired on the plane**, not carried by a skill.

### Changed

- **BREAKING — a served run acts as its caller, never as the plane.**

### Removed

- **BREAKING — `DelegationScheme`.**

## [0.24.0] — 2026-08-28

### Added

- **A decision's amendment is the call**, not advice — a reviewer's arguments
  are what runs.
- **`one_of`**: the declarative fragment of release.
- **`PeerTaskCancel`**, the client half of the A2A task lifecycle.
- **`approved_call`** and three more examples for claims only the test suite
  could vouch for; a step-by-step tutorial verified against the real binary.

### Changed

- **BREAKING — release marks ride the value, never the label.**
- **A2A back-pressure is identified by a `(domain, reason)` pair, not a
  numeral**, and outbound A2A refuses plaintext on both legs.
- Example output reads as narration everywhere, and the example index answers
  every question the fleet can.

### Fixed

- **The instruction slot is singular by enforcement.**
- Bedrock authenticates every way Bedrock authenticates; provider drivers stop
  discarding what the provider said; OpenAI commentary narration stays out of
  the answer.
- The A2A client can name a skill on a multi-skill plane.
- Refusing to close a case is a business answer, not a store fault.
- `planned_run` no longer dodges the gate it exists to demonstrate, and a
  getting-started snippet that could not parse.

## [0.23.0] — 2026-08-27

### Changed

- The case-store contract pins blob-list scoping in both directions.

### Fixed

- **The erasure unit leads the blob's storage address.**
- The drill reads through the handle the plane wrote through.

## [0.22.0] — 2026-08-21

### Added

- **`Destination::try_also_signed_with`.**

### Changed

- **A refusal keeps its class across every surface**, and a conclusion's reason
  reaches whoever the conclusion reaches.
- Case-history truncation is a fact rather than an inference.

### Fixed

- **A witness cosignature is now the one real witnesses produce.**

## [0.21.0] — 2026-08-21

### Added

- **The manifest format ships as a JSON Schema.**

### Changed

- **BREAKING — a semantic selection is screened against durable truth.**

### Fixed

- **The bill is the bill** — providers are metered as reported.
- **A CloudEvent can wake a run, and its identity cannot be forged**; an A2A
  message id deduplicates at admission, scoped to its producer.
- **Escalation now does what its name has always claimed**, an escalated task
  leaves the overdue scan, and the four-eyes operands survive the shared store.
- **A missed obligation outlives the case that missed it**, and the sweeper no
  longer writes one off before escalating the case.
- **One batch runs one frozen plan**, enforced where the plan lives.
- Gemini carries the whole transcript rather than the latest turn; a schema no
  longer fails every tool-calling turn; one formation answer cannot supersede
  itself.
- A wipe the optimizer was allowed to delete; every `Content-Encoding` line is
  checked; the push token rides and rotation is not a flag day.
- A mark written to nowhere is a refusal; a row the store cannot read is damage,
  not a default; a report on an unknown batch is not an empty batch.
- The MCP context gate refuses for real reasons.

## [0.20.0] — 2026-08-20

### Added

- **Admission is at-most-once when a message says who it is.**
- **A verifier beside the signer**, `try_signed_with`, and a reason on the seal.
- **The admission index has a retention verb**, and no default.

### Fixed

- **Security — a conclusion's reason reached the store in the clear.**

## [0.19.0] — 2026-08-19

### Added

- **One `CloudEvents` envelope, in both directions.**
- **`spec.memory.recall`**, so a declarative agent can read what it wrote.
- **`KeyError::UnknownFormat`**, so a build skew is not read as tampering, and
  sealed envelopes carry a format version.
- **`McpClient::negotiated_version`**, so a downgrade is not silent.

### Changed

- **Body signing is Standard Webhooks, and covers the replay.**
- The embedding space is wiring, not a string a caller types; the address rule
  moved into the client, and the client is reused.

### Fixed

- **A rate limit was retried as if nobody knew when to come back.**
- **One slow receiver decided when everybody else's events went out.**
- **Abandoning a push registration deleted the only cursor there was**, and a
  receiver's answer was counted rather than read.
- Every push delivery announced the wrong media type.
- Both A2A URL legs were dereferenced without an address check; two outbound
  clients had no timeout at all; three A2A surfaces each kept their own copy of
  one mapping.
- **`Completion::truncated` was produced by five drivers and read by none**; a
  severed Gemini stream billed nothing it had already been told; one
  cache-accounting rule, spelled once.
- The drill answered "nothing to check" for state it could not read; a Postgres
  column this store could not read became a decision.

### Security

- `h2` advisory RUSTSEC-2026-0258.

## [0.18.0] — 2026-08-15

### Changed

- **BREAKING — the record format version is `1`.**

### Fixed

- **Security — the evidence layer, where nothing was verifying anything.**
- **A catalogue edit could declassify history**; sink gates re-judged effects
  that had already happened.
- **An erasure that reports success and misses**, and a driver attesting a
  destination it was not told about.
- Three types where `serde` was the constructor nobody counted; a rule enforced
  at one of its two doors; two checks that arrived one stage too late.
- Answering an MCP elicitation needed no grant; `cx.embed` could only embed a
  literal; a capability served but never advertised.

## [0.17.0] — 2026-08-15

### Fixed

- **A broken policy set is a defect, and says so before it runs.**
- **A domain separation the type system now enforces.**

## [0.16.0] — 2026-08-14

### Added

- **The case layer exports, verifies and restores** (format 2).
- **`Runtime::drill`**, the live half of the case-layer drill.

### Changed

- **BREAKING — the version hard cut**, plus smaller breaking cuts each with a
  one-line migration.

### Fixed

- **Security — what erasure must reach, and what an export may carry**; the
  second pass is the same run as the first, and one layer deeper.
- The wire, the record, and the models that check them; storage and sealing.

## [0.15.0] — 2026-08-12

### Added

- **`oversight.triage`** — a task beside the answer, not in front of it.
- **`StepCtx::call_tool`**, so a skill's reach is its manifest's reach.
- **A memory subject may name the party the run is about.**
- **An operator-configured outbox**, on the same journal cursor.
- **A prompt may not name a tool the agent was not granted.**
- **`Manifest::parse_each` and the `manifests!` macro.**

### Changed

- The delivery loop moved out of the A2A server.

### Fixed

- A timestamp on a wire is RFC 3339, and the build now says so.

## [0.14.0] — 2026-08-10

### Added

- **Every store-side concurrency claim is raced against a real PostgreSQL.**
- **A task can be taken over from a holder who is not coming back.**

### Changed

- **Canonicalization is a complete RFC 8785 implementation.**
- The export header stops asking the caller for a fact.

### Fixed

- **A witness could not report the one thing it exists to catch.**
- **The PostgreSQL run ceiling no longer yields under the load it exists for**,
  and a task claim no longer deadlocks the pool it runs on.
- **A satisfied waiter no longer swallows a second event.**
- An internationalised host grant no longer silently never matches, on either
  surface; a stitched-together log is named for what it is; a parse step no
  longer accepts arguments nothing executes.
- The mutation sweep stops paying for two defaults that fight it.

### Assurance

- The label lattice, the push outbox and the card signatures walked
  adversarially; the first-contact surface executed rather than read.

## [0.13.0] — 2026-08-10

### Added

- **`GET /cases?status=…`** — what is escalated right now.
- **`RuntimeError::UnknownTenant`.**

### Changed

- **BREAKING — security: break-glass is a door, not a step.**
  `Planes::cross(caller, target, reason)`, and `Planes::get` takes the caller
  rather than a tenant.

### Fixed

- **Security — `api:run.list` was missing from `action::ALL`**, so a
  deny-by-default deployment could not grant it.
- **A plan's digest no longer degrades to a constant**, and a witness's
  unreadable `409` body is no longer read as size zero.
- Twenty-three doc comments had absorbed the one below them, and the guard for
  that shape was blind to it.

### Assurance

- The chain keeping `requires_approval` off a hand-written skill; a plan's
  content address checked field by field; each tenant's policy engine held to
  deciding its own requests.

## [0.12.0] — 2026-08-09

### Added

- **Client-side interoperability evidence against an independent server.**
- **A plane serves an Agent Card per agent** — `A2aServer::hosting(..)`.
- **`ErasureCoordinator`, and a PostgreSQL implementation.**
- **Canonicalization is versioned**, and a rule change reads as *unverifiable*
  rather than as divergence.

### Fixed

- An absent `tenant` was sent as JSON `null` instead of being omitted; a flaky
  Vault container test.

## [0.11.0] — 2026-08-09

### Added

- **`Runtime::case_of(run)`** — which case a run belongs to.
- **`PushSender::allow_plaintext_loopback`** (`testkit` only).
- **`DeadlineSpec::minutes`**, joining `hours` and `days`.
- **`PushSweepReport::needs_attention()`**, matching `SweepReport`.

### Changed

- **BREAKING — a `mutates: true` grant with no `protected_fields` is refused at
  parse** for a declarative agent.
- **BREAKING — `BuildError::OversightUnreachable`**: an agent declaring
  `spec.oversight` on a plane with no worklist is refused.
- **BREAKING — A2A method parameters are per-method**, and unknown names are
  refused.
- **BREAKING — one `Duration` on the public surface.**

### Fixed

- **The worked taint-gate policy in the security docs was an outage.**
- A push webhook that will never be delivered to is abandoned, not retried
  forever; the getting-started guide points services at `try_build()`.

## [0.10.0] — 2026-08-08

### Added

- **An `upgrading` page** — a migration list for the refusals that break
  existing deployments.
- **`cx.manifest()`** in the manifest reference; a near-miss hint when a
  hand-written plan names a tool by the wrong spelling.

### Changed

- **BREAKING — every admission door takes `Tainted<Value>`.**
- **`--no-default-features --features postgres` now delivers a store.**
- `build()` points long-running services at `try_build`.

### Fixed

- **The mutation sweep was switched off in CI**, and three mutations had rotted
  into code that no longer compiled.
- `Append::into_body` and `testkit::conformance_case` were gated on `redb`
  despite not needing it; `just test-postgres`/`test-vault` did not pass
  `--no-default-features`.
- The A2A conformance verdict could not distinguish a passing MUST row from a
  skipped one; the regulation and erasure pages contradicted each other on
  journaled personal data.

### Assurance

- Adversarial mutation sweeps over the SSRF classifier (67 of 111 survived) and
  the label lattice (39 of 109) — both sets of tests were rewritten.

## [0.9.0] — 2026-08-08

- **Added** `model::embeddings` — OpenAI-compatible, Bedrock Titan and Cohere
  embedding drivers, so semantic retrieval needs no bespoke embedder.
- **Changed — breaking** CLI argument parsing is per-verb: a flag lives on its
  subcommand, `--strict` requires `--replay`, and the two input flags conflict.
  `run --push-host …` no longer parses.

## [0.8.0] — 2026-08-07

- **Added** A2A push notifications — tenant-keyed durable registrations, a
  governed transport, and an `A2aPushWorker` for the operator scheduler.
- **Fixed** a JSON `null` in a Cedar request context denied everything, because
  Cedar refuses a whole context containing one.

## [0.7.0] — 2026-08-07

- **Fixed** A2A task state was derived two ways — an enum match on the immediate
  response and a string match behind `_ => Failed` on every read-back path — so
  one task could give two answers.

## [0.6.0] — 2026-08-07

- **Added** Bedrock reasoning dialects (`ReasoningDialect::Nova`), declared rather
  than sniffed from a model id.
- **Changed** errors user code holds report through `Display` under `Debug`, so
  `fn main() -> Result<_, E>` shows the sentence somebody wrote.
- **Changed** docs use `cargo add` rather than pinning a version that goes stale.

## [0.5.0] — 2026-08-07

- **Added** sealing at rest from one `.keyring(..)` call — journal payloads, case
  state, task proposals, event payloads and blob bytes. The chain commits to
  ciphertext, so an auditor with no keys verifies a run whose payloads are gone.
- **Added** break-glass: a cross-tenant read is sealed into the crossed tenant's
  own journal, with a mandatory reason, before any data is served.
- **Added** `security.max_sensitivity_journaled` — a ceiling on what may be
  written down forever, refused at dispatch before the announcement.

## [0.4.0] — 2026-08-07

- **Added** multi-agent rooms: several manifests in one file separated by `---`,
  with identity staying per-agent.
- **Added** a `chat-completions` driver for the OpenAI-compatible wire — TGI,
  vLLM, Ollama, llama.cpp, hosted routers.
- **Added** documentation guards: every published API name, manifest field and
  YAML fragment is checked against the code.

## [0.3.0] — 2026-08-06

- **Added** standing authority — a spend ceiling bound to an authorization rather
  than a run or a billing period, revocable, with idempotent draws.
- **Changed** canonicalization key ordering moved to UTF-16 code units so signed
  Agent Cards verify against RFC 8785 rather than only against this crate. Every
  digest moved.

## [0.2.0] — 2026-08-05

- **Added** governed memory on both backends — formation, retention, legal hold,
  cascading forget and cryptographic erasure.
- **Added** PostgreSQL push delivery storage.

## [0.1.0] — 2026-08-02

- First tagged release: the effect protocol, the hash-chained journal, replay and
  resume, the redb backend (replacing an earlier Turso/SQLite one),
  content-addressed blobs for oversized records, and the mutation harness that
  requires each guarantee's named test to fail when the guarantee is removed.
