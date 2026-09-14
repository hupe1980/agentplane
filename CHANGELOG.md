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

## [0.37.0] — unreleased

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

- **The disaster-recovery release blocker is discharged, and the roadmap's
  release-blocker list is empty.** The drill now runs against a real
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
  and one states a non-goal — and the residuals are what the roadmap's
  milestones are made of. Internal documents only; nothing in the crate moved.
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
