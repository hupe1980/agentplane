# Changelog

Notable changes per release, following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

**Pre-alpha, and versioned accordingly.** The crate *is* published — `0.x` bumps
carry breaking changes without deprecation cycles, because a hard cut is cheaper
than a compatibility shim, and pre-1.0 is the window in which that is an honest
trade rather than a broken promise. Every breaking entry says what to do about
it, and [upgrading](https://hupe1980.github.io/agentplane/docs/upgrading/)
carries the ones that need more than a sentence.

This line used to read *the crate is not published*, which stopped being true at
the first release and stayed on the page — the shape this project catalogues as a
premise that expired. It matters more here than most: an entry's audience is
somebody who already depends on a version, so "nobody has yet depended on it" is
exactly the assumption a changelog may not make.

**This file carries the reasoning, not just the diff.** It used to share that job
with a status page listing everything built — two hundred rows, nearly all of them
phrased as *X used to do Y, now it does Z*, which is a change and not a status.
Keeping one fact in two places is the defect this project treats most seriously
elsewhere, so the list is gone and the entries below are where a mechanism's
history lives. [Status](https://hupe1980.github.io/agentplane/docs/status/) now
answers only what a status page can: what will move, what is deliberately absent,
and how to check either. What *exists* is answered by the
[concepts](https://hupe1980.github.io/agentplane/docs/concepts/) page, the
[API reference](https://docs.rs/agentplane), and the test suite.

Entries for `0.1.0`–`0.9.0` are reconstructed from tags and commit history rather
than written at the time, so they are deliberately terse — inventing more would be
archaeology presented as a record.

## [Unreleased]

Two audit rounds, two structural closures: recovery gained its initiator, and
the case layer crossed the export boundary.

### Added — the case layer exports, verifies and restores (format 2)

- **Export format 2 carries every case** — state as stored (sealed stays
  sealed; plaintext would quietly undo erasure), version, status, correlation,
  runs, deadlines and blob digests — as `agentplane.export.case` lines, with
  the count in the trailer. A hard cut from format 1: a reader that tolerated
  the lines' absence could not tell *this plane had no cases* from *the case
  layer was dropped*.

  **Why.** Case rows are the one durable structure a journal replay cannot
  rebuild: they live beside the history, not in it. `agentplane restore` used
  to rebuild a journal whose records stamp cases that then did not exist —
  every matter's obligations, correlation and erasure unit gone, in a store
  whose Merkle roots proved the *journal* faithful.

- **The verifier holds the two halves to each other.** A record stamped with a
  case the file does not carry is a finding; the trailer's case count against
  the blocks read is what catches the layer stripped *whole*. The two live
  questions an offline file cannot answer — blob bytes behind the digests, and
  sealed-state keys — are reported as unchecked rather than passed.

- **`CaseStore::cases` and `CaseStore::import_case`** (breaking: required
  trait methods). Enumeration is paged with a cursor, because `by_status`'s
  uncursored bound would enumerate a prefix and call it everything.
  `import_case` is the same deployment-authority seam governed memory keeps
  for direct writes: the ordinary paths cannot say "version 41, escalated,
  this exact id". The conformance battery holds the import to **every read
  path** (`case`, `correlate`, `by_status`, `due`, `blobs_of`) on both
  backends, because an import that rebuilds five indexes out of six reads
  perfectly until somebody queries the sixth.

- **`to_jsonl`/`from_jsonl` take an optional case store** (breaking); the CLI
  wires it always — an optional flag would be a way to quietly produce the
  file the verifier flags.

### Added — the sweep recovers the runs an instance died holding

- **`JournalStore::abandoned_runs`** (breaking: a required method on the store
  trait) answers one precise question: which leases expired while still naming
  an owner. The set is exact rather than heuristic because every clean exit —
  sealed, failed, *suspended* — releases its lease; only a crash skips that
  call. redb scans its lease table; Postgres gets a partial index
  (`run_lease_abandoned`) over held rows.

  **Why.** Every resume had an event-shaped driver: an inbound message, a
  fired timer, an operator, a batch retry. A run crashed mid-step with none of
  those pending had *no driver at all* — it concluded nothing, so no outcome
  listing carried it; its wake was consumed, so no waiting list named it; and
  the operations guide's sentence "lease expires, another instance claims at
  `epoch + 1`, resumes via replay" described a mechanism with no subject. I13's
  failure mode, applied to the recovery mechanism itself, and invisible
  precisely because every *part* was built.

- **The sweep's recovery pass** drains that queue: bounded batch (32, small on
  purpose — a recovered run executes live from its frontier, which may
  dispatch a model call), per-run failure containment, `LeaseHeld` treated as
  another instance getting there first rather than as an error, and the one
  degenerate case — a lease over an **empty** journal, an admission that died
  before its first append — cleared rather than retried forever. Each takeover
  is written into the sweep's own sealed run as **`SweptAction::RunRecovered`**
  (breaking: new enum variant), because a takeover fences the previous owner
  and *who fenced whom* must be answerable from the journal. `SweepReport`
  carries `runs_recovered` and `recovery_failures`; only failures page.

### Fixed — sweep evidence survives the tick's own failure

- **The ledger sealed only after every phase succeeded**, so an error in a
  later phase (the timer backend unreachable, say) left with the account of
  breaches and expiries the earlier phases had already applied to state — no
  sealed run, and not even `evidence_lost`, because the report died with the
  error. Evidence already earned is now sealed before any phase's error
  propagates. A mutation that reorders the two is killed by
  `sweep_evidence_survives_a_later_phase_failure`.

### Fixed — one bad run no longer blocks the timer batch

- **`fire_timers` returns `WokenRuns { fired, failed }`** (breaking: it
  returned the fired count) and contains per-timer failures instead of
  aborting the batch at the first error — a single unresumable run held a veto
  over every later wake in the tick. A failed wake is not lost: the lease it
  acquired lapses unreleased, and the recovery pass picks the run up.
- **A re-fired timer no longer appends a duplicate wake.** A crash between the
  wake's append and the timer's disarm left both standing, and the re-claimed
  timer wrote the wake into the chain a second time. The retry is now a second
  *resume*, never a second record.

### Audit notes

- MCP 2026-07-28 and A2A 1.0.x remain the current baselines; no spec drift.
- [2608.02645] (verified tool calls under non-atomic failures) recorded in
  §11.1 as experimental corroboration of the reconciliation design, not a gap.

[2608.02645]: https://arxiv.org/abs/2608.02645

## [0.15.0] — 2026-08-12

Six things a regulated deployment ran into, and each is the same shape: a
mechanism that was correct for the case it was built for and had no spelling for
the mirror-image case beside it.

### Added — a memory subject may name the party the run is about

- **`memory_formation.subject` accepts a binding.** `$correlation/<namespace>`,
  `$case` and `$input/<pointer>` resolve per run; a literal still means what it
  says, and a literal that genuinely begins with `$` is now spelled `$$`.

  **Why this is a defect and not a caveat.** A subject is the unit
  `MemoryStore::forget_subject` erases, so a literal one pools every customer,
  meter and matter the agent ever reasoned about under one key. One party's facts
  are then recalled into another party's run, and an erasure request naming one
  person cannot be satisfied without destroying everybody's. A **coded** skill
  never had the problem — `MemoryWrite::new` takes the subject as a runtime value
  — so only the declarative tier was stuck with a compile-time literal, and the
  declarative tier is the one this crate otherwise pushes people toward. A
  deployment of 28 specialists reasoning about one metering point at a time
  shipped memory on two of them for exactly this reason, and wrote a test to stop
  a 27th being added without the argument being made again.

  Four refusals, because every wrong answer here is silent until an erasure
  request: an unrecognised `$` value is refused rather than filed as a constant
  (`$correlaton/malo` would file every party under the typo); a binding that
  cannot resolve **fails the run** rather than falling back to the literal or to
  a default; `$input` is refused unless the field it names is **trusted**, since
  a subject taken from untrusted input is whoever supplied it choosing whose
  memories this run writes into; and a case-bound subject on a plane with no case
  store is refused at `build` (`MemorySubjectUnbindable`), as is any formation on
  a plane with no memory store (`FormationWithoutMemory`) — formation runs after
  the answer, so left to run time it fails once the run has already paid for its
  model calls.

  The keys a binding resolves against are recorded on the run's `CaseBound`
  journal record and read back from there on resume, never re-read from the case.
  A case accumulates business keys over months; re-reading them would let a
  resumed run resolve a subject the live run never saw, write a second memory
  under a second scope, and produce a history that disagrees with itself.
  `StepCtx::correlation()` and `correlation_value(namespace)` expose the same
  values, so a hand-written skill reading those memories back does not have to
  guess at a naming convention.

### Added — `oversight.triage`: a task beside the answer, not in front of it

- **`approval: none` plus `triage` rules.** A rule is a predicate over the
  declared `output.schema` and an audience; a matching answer is returned *and*
  opens a worklist row.

  **The shape neither existing mode could express.** `Approval::ToolsOnly`'s
  argument is right — gating a tool-calling agent's *answer* is a review that
  arrives after the money moved — but it does not hold for an agent that
  **cannot** act, and this runtime guarantees a whole class of those: a
  `tool-calling` agent's arguments come from a model completion, so a mutating
  grant with no `protected_fields` is refused by the taint gate on every run,
  which is why the parser refuses that grant outright. For an advisory agent
  `tools-only` gates nothing and `required` is a worklist that *blocks* — one
  suspended run per finding, at whatever rate counterparties miss their
  deadlines.

  **Why this may hold a predicate when `approval` may not.** `approval` has no
  condition deliberately: *"require approval when severity is high"* changes what
  the agent **does**, and that is one step from an `if`. A triage rule changes
  nothing — same answer, same validation, same memories — and its only effect is
  a row in a worklist. That is reporting, and reporting is the one place a
  declaration can carry a condition without becoming control flow.

  Five total operators (`equals`, `in`, `at_least`, `at_most`, `exists`), no
  nesting, no `or`, no negation; conditions within a rule are conjunctive and
  rules are independent. `triage` requires `spec.output`, and every condition is
  typed against that schema — refused where the schema *provably* cannot produce
  the pointer, and deliberately silent where the walk cannot decide (`$ref`,
  `anyOf`, an open object), because a rule that can never fire reads in review
  exactly like one that does. An oversight block that performs nothing —
  `approval: none`, empty `triage`, no grant asking for approval — is refused.

- **`StepCtx::open_task`**, the coded equivalent: a journaled effect that opens a
  row and returns, with the task id derived from the effect key so a resume
  addresses the row it already opened rather than growing a worklist by one per
  restart. It is deliberately **not** a sink: a worklist row's whole purpose is to
  put untrusted content in front of a person, so refusing untrusted content there
  would mean a task could only carry findings nobody needs to review.

### Added — `StepCtx::call_tool`, so a skill's reach is its manifest's reach

- **A coded skill dispatches through the plane's own catalogue.** It had to
  construct and carry one, and nothing bound that catalogue to the manifest
  governing the skill. `ToolCatalog::from_manifest` was the right primitive and
  one call away — but the *obvious* thing, hand-building a catalogue with the
  tools you know you call, compiles, runs, and grants reach the declaration never
  described. Worse, it can be **laxer**: a `ToolSafety::read_only` entry for a
  tool the manifest calls mutating exempts it from the whole-value taint gate and
  carries `Recovery::Retry`, so a timed-out money-moving call is sent again.
  `try_build` refuses exactly that divergence for the plane's catalogue; a
  catalogue built inside a skill never passed under that check.

  `examples/governed_transfer.rs` demonstrated the hand-built form, which is what
  a reader copies, and now demonstrates the governed one. `ToolCall::prepare`
  documents when it is still the right call and what to derive it from.

### Added — an operator-configured outbox, on the same journal cursor

- **`push::Outbox`, `push::Destination`, `push::DeliveryWorker`,
  `push::Projection`, `push::RunCompleted`, `RuntimeBuilder::outbox`.** A
  destination the *deployment* configured, receiving a payload the embedder
  shapes, for every run.

  `PushConfig` is A2A-shaped by construction — a **caller** supplies the URL, it
  is scoped to one task, it carries a `StreamResponse` — and the three controls
  around it (host allowlist, HTTPS, all-answer public-address checks) exist
  because of that first fact. The mirror image had no spelling at all, so
  services emitted their result event at request time with retries and dropped it
  on failure: the one outbound path with no persist-before-dispatch, in a system
  whose whole argument is that the journal is the plan of record.

  Destinations are registered at **admission**, so no run exists unwatched, and
  delivery reads the run's own records past a cursor that advances only on 2xx.
  The three URL controls are lifted for an operator destination and only for one,
  each for a stated reason: there is no caller to check against an allowlist; an
  in-cluster collector on plaintext HTTP is ordinary, and refusing it pushes
  operators toward a TLS-terminating sidecar that forwards in clear; and
  resolving inward is the entire point. Everything else is unchanged. Both kinds
  of registration share one store and are told apart by an `operator:` prefix a
  caller cannot use — the A2A server refuses a `pushNotificationConfig.id` that
  begins with it.

### Changed — the delivery loop moved out of the A2A server

- **`PushSweepReport` is `agentplane::push::PushSweepReport`**, re-exported from
  `api::a2a`, and the cursor loop is `push::DeliveryWorker` parameterised by a
  `Projection`. `A2aPushWorker` is a thin binding of it and its API is unchanged.
  The discipline — read past the cursor, POST, advance on 2xx, back off, abandon
  a permanent refusal — has nothing to do with A2A; it lived there because A2A
  was the first caller, which made the mechanism an operator most wants reachable
  only by speaking somebody else's protocol.

### Added — `Manifest::parse_each` and the `manifests!` macro

- **A directory of single-agent files, embedded, keyed by declared name.**
  `parse_all` covers a *room* — several agents in one file, because they are one
  deployable thing — and the other common layout had no support, so every
  embedder wrote `&[(&str, &str)]` with a name typed beside each path. The name
  is **already in the document** as `metadata.name`, so that table is one fact
  written twice with nothing checking that the two agree; and a file included
  under two constants, which is what happens while adding the next agent, builds
  and runs with one agent registered twice and another silently absent. A
  duplicate name is now refused, naming both paths. No glob: a macro expanding a
  directory listing would make the set of agents a plane runs depend on what is
  on disk rather than on what a reviewer reads.

### Added — a prompt may not name a tool the agent was not granted

- **Any `tool://server/name` in `spec.identity.role` or `constraints` must be
  granted.** An ungranted name comes back to the model as a *failed call*, which
  is right — it can correct itself and never gets the tool it nearly named — but
  it means a **procedure** naming an ungranted tool fails quietly: the model
  asks, is refused, improvises, and the step silently does not happen with
  nothing in the journal saying the instruction was unfollowable. One deployment
  found twelve such instructions across eleven manifests, five naming things that
  were not tools at all.

  It only sees references spelled as references — prose naming a tool by bare
  identifier is indistinguishable from an ordinary noun, and a check that guessed
  would refuse manifests over the word "search".

### Fixed — a timestamp on a wire is RFC 3339, and the build now says so

- **`MemoryItem::{created_at, expires_at, superseded_at}` and `Recall::as_of`
  serialised as `time`'s component array**, as did the `memory.remember`,
  `memory.touch`, `memory.sweep-expired` and `authority.draw` effect descriptors
  — so a journal an independent party reads carried
  `[2027, 15, 8, 0, 0, 0, 0, 0, 0]` where it should carry a date. It parses, it
  round-trips, and every consumer expecting a date gets nine numbers whose first
  element looks like a year.

  `core::format_timestamp` is the answer inside a `json!` literal, where there is
  no field to hang `#[serde(with = ...)]` on, and the `Timestamp` alias now
  documents the hazard — it is public API, so it lands in *your* tool payloads
  too, where this crate cannot check it. `tests/guards/timestamps.rs` walks the
  crate's serialized types and fails on the shape, with the detector exercised on
  a known input first so it cannot pass by being inert.

### Fixed — smaller things found on the way

- **`Task::created_at` was the deadline instant.** Both fields then said *when
  this is due*, so a worklist reported every row as created in the future and
  "oldest first" silently meant "soonest due" — a defensible ordering under a
  field name that denies it, which is the worst combination for an operator
  explaining a backlog. It is now the run's journaled clock.
- **`RuntimeBuilder::agent` carried a `# Panics` section describing refusals it
  does not raise.** They are `build`'s, and `try_build` returns them — which is
  the whole point of the split for a daemon assembling a plane from files it did
  not write. The section sent readers looking for a fallible variant of the wrong
  call.
- **`FakeProvider::will_structure`**, for scripting a schema-declaring agent.
  `will_say` sets the completion's *text* and leaves `structured` empty, so a
  test scripted with it gets `{"text": "..."}` where it expected its own shape.
  The diagnostic for that existed; the constructor avoiding it did not, so every
  such test spelled a five-field `Completion` literal by hand.

## [0.14.0] — 2026-08-10

### Fixed — the mutation sweep stops paying for two defaults that fight it

- **A shard outgrew its CI job, at roughly five minutes per mutation.** Two
  ambient settings compounded: the CI cache action exports
  `CARGO_INCREMENTAL=0` — right for a one-shot build that will be cached,
  wrong for a loop recompiling the crate once per one-line mutation — and
  full debuginfo made linking each large test binary the second cost, buying
  line numbers no verdict reads, since the classifier parses test names and
  never opens a backtrace. `mutants.py --verify` now runs cargo with
  incremental on and debuginfo off, in the verifier itself rather than the
  sweep script so a bare `--verify` behaves identically — one implementation,
  for the reason the two classifiers were merged. `*_MUTANTS` environment
  variables are the opt-out, mirroring `RUSTFLAGS_MUTANTS`. Measured on one
  mutation at steady state: 458 CPU-seconds to 67, which on a two-core runner
  is the difference between a sweep and a timeout.

### Fixed — a task claim no longer deadlocks the pool it runs on

- **`TaskStore::claim`, `take_over` and `open` held a pooled connection while
  re-entering the pool.** Each verb took a connection, then called
  `Self::task` for its eligibility and re-read steps — which acquired a
  *second* connection while the first was held. Sixteen reviewers racing one
  task on a small pool each held a connection and waited for one that only
  another waiter could release: a deadlock under exactly the concurrency the
  claim verb exists to survive, and only where the pool is small enough to
  exhaust — every large development machine passed over the defect a CI
  runner hung on for an hour and a half. All reads made while a connection is
  held now go through `task_on`, which reads on the connection the caller
  already holds; one connection per verb, acquired once.

- **`PostgresStore::connect_sized` names the connection ceiling**, because the
  fix deserved a test that does not depend on the runner. The race now runs
  sixteen claimers against a pool of four, making the exhaustion condition a
  property of the test rather than of whichever machine executes it — and a
  deployment sharing its database with other services gets the sizing knob it
  was owed anyway.

### Changed — canonicalization is a complete RFC 8785 implementation

- **Doubles format by ECMAScript's rules, and `canon::VERSION` is 3.** The one
  JCS rule deliberately left unimplemented is implemented: `1e30` becomes
  `1e+30`, `100.0` becomes `100`, `1e-7` stays `1e-7` — held to the standard's
  own Appendix vectors rather than to this crate's opinion of them, which makes
  them cross-implementation golden vectors for the one format a third party
  verifies. The gap was survivable only while a guard asserted the signed Agent
  Card carried no numbers, and that guard had a hole shaped like the tenancy
  window this project already catalogued: extension `params` are arbitrary
  deployment JSON, so a number could reach a signed card through data no
  in-tree fixture ever sees — and the signature would verify against this
  crate and nothing else. A store written under rule 2 replays as
  `CanonicalizationChanged` — unverifiable, not divergent; the pre-freeze
  remedy is recreate.

- **Integers stay exact, and the bound is enforced where it binds.** JCS reads
  every number as an IEEE-754 double, under which two distinct integers above
  2⁵³ collapse into one representation — and a canonicalizer that collapses two
  different values into one byte string would give two different effects one
  key, the exact fallback `canon::value_bytes` refuses. So integers serialize
  exactly (identical to the ECMAScript form within ±2⁵³, where I-JSON draws
  interoperability too), and the one externally-verified artifact refuses the
  range outside it: `signing_input` walks the card and returns
  `UnrepresentableNumber` naming the offending path, on both the signing and
  verifying sides. The test-only guard is retired for the boundary refusal —
  a control that must be tested for became one that cannot be skipped.

### Changed — an open question settled by reading the API that had answered it

- **The embedder's resumable output stream is the journal read itself.** The
  open question — whether a resumable cursor over already-journaled events, the
  A2A stream's own mechanism, should be offered to a coded skill or re-opens
  the second-truth problem by another name — was settled by observation:
  `Runtime::journal()` is public and `JournalStore::read(run, from)` *is* that
  cursor — durable, seq-scoped, reconnect-safe, serveable by any instance, and
  the only mechanism the A2A stream consumes. The accessor that settles the
  question was the one undocumented public method in the file, so the answer
  was true and unfindable; it now documents itself, and the decision record
  carries the reasoning. No curated event type is added between the records and
  the wire, deliberately: a third vocabulary drifts from the other two.

### Changed — the export header stops asking the caller for a fact

- **`export::to_jsonl` no longer takes a canonicalization version.** The header
  names the rule the digests were computed under, and that is a fact about the
  build that wrote them — yet the writer asked for it as an argument, which made
  the one self-describing line of the format a line any embedder could make
  lie. Every call site in the tree passed `canon::VERSION` verbatim, which is
  what a fact looks like when it is requested as a parameter. The writer now
  reads the constant itself. **Breaking:** drop the third argument.

### Fixed — a stitched-together log is named for what it is

- **`verify` holds the run blocks' log positions to the contiguous `0..N` the
  checkpoint commits to.** Two blocks claiming one position — an export spliced
  from two histories — previously surfaced only as a root mismatch, which tells
  an auditor that something is wrong but not that two runs claim one place in
  history; worse, a tree rebuilt over duplicated positions compared garbage
  against the root and reported the wrong defect. A duplicated or missing
  position is now its own finding, and the root comparison runs only over a
  well-formed position set.

### Changed — documentation

- **The "enforcement below the code" claim gained the qualifier the field now
  requires.** Kernel-level policy enforcement for agent harnesses is published
  (eBPF over system actions — genuinely below the process), so altitude alone
  stopped being the distinction, and the constitution now says which pair
  survives at any altitude: flow on values, and evidence unified with recovery.
  The open containment-benchmark item likewise records that the
  adaptive-evaluation methodology for this defence family now exists in
  published form, with its first small-scale data point — deterministic
  out-of-band enforcement holding where in-band defences fell.

### Fixed — a witness could not report the one thing it exists to catch

- **A shrunken log was reported as routine unavailability.** C2SP `tlog-witness`
  specifies `400 Bad Request` for *old size exceeds checkpoint size*: the witness
  is at N, this log now offers a checkpoint smaller than N, and runs it already
  cosigned are gone. `HttpWitness` had no arm for 400, so it fell to the
  catch-all and became `WitnessError::Unavailable` — which the quorum classifies
  as **routine**, beside a timeout.

  `WitnessError::Shrank` documents itself as *the single most important thing a
  witness catches, and the one an operator auditing itself structurally cannot*.
  It was constructed in exactly one place: `MemoryWitness`, the in-process
  witness explicitly documented as useless as a trust anchor. So on the only
  witness that can be a real one, a deleted run raised no alarm — and the
  runtime deliberately provokes that 400, since the quorum sends
  `old_size > checkpoint.size` when the witness is ahead.

  A fact kept in two places had drifted with it: the security page said no
  remote C2SP client ships, while the README and getting-started say `HttpWitness`
  does. What is absent is a **counterparty**, not code, and all three pages now
  say that.

### Fixed — an internationalised host grant no longer silently never matches, on either surface

- **Host grants are canonicalised the way the URL they guard is** — for both
  governed media and push webhooks, through one shared
  `netguard::canonical_host`. A grant is compared against `Url::host_str`,
  which the URL crate has already IDNA-encoded to punycode — but each grant
  went only through a lowercase/trim, so `allow_host("münchen.example")`
  stored the Unicode form and never matched the `xn--mnchen-3ya.example` a
  URL to that host carries. Fail-closed — every request to the intended host
  refused — but **silently**, reading like a wrong URL rather than a wrong
  grant, the quiet-misconfiguration shape this crate refuses loudly
  everywhere else.

  Found auditing media, then — per the rule that a defect of a shape has a
  sibling — checked in push and found identical, so the fix is one function
  in the module both already share for the address rule rather than two that
  could drift. A grant carrying anything beyond a bare host (a port,
  userinfo, a path) is now refused at configuration time on both surfaces
  rather than stored as something that cannot match. The rest of the media
  SSRF machinery — the `netguard` classifier (every range pinned from both
  edges, IPv4-mapped judged as v4, one private answer poisoning the whole
  resolution), per-hop re-resolution and DNS pinning, redirect
  re-authorisation, decompression refusal, and the streamed byte ceiling —
  audited clean.

### Audited clean — the first-contact surface, executed rather than read

- Every example in the CI recipe runs green; the CLI's error paths were
  probed as a newcomer hits them — a typo'd manifest field names itself and
  the valid set, malformed input JSON names the position, an unknown
  capability lists what the plane provides — and the getting-started page
  pre-empts the traps its reader would otherwise find in order (the MSRV
  patch-component pitfall, the non-re-exported `async-trait`/`tokio` deps,
  capability-versus-skill-name, `Debug` as the `fn main` reporting path).
  Two deliberate behaviours observed and left: `--input` defaults to `{}`
  (documented on the flag; an agent declaring an input contract still
  refuses), and the CLI's default log filter shows the crate's own INFO
  events (overridable with `RUST_LOG`, and the answer stays clean on
  stdout).

### Added — every store-side concurrency claim is now raced against a real PostgreSQL

- Three more Docker-backed race tests join the quota-admission one, so every
  mechanism whose correctness argument is "this serialises" carries evidence
  rather than a comment: **authority draws** (sixteen racers against a
  mandate affording exactly three — three land, the ledger reads exactly
  €90, thirteen are refused `Exhausted`), **task claims** (sixteen
  reviewers, one holder, fifteen told who holds it), and **timer sweeps**
  (two concurrent sweepers partition twelve due wake-ups disjointly and
  completely — `SKIP LOCKED` doing what it says). All three corroborated —
  these mechanisms were sound, unlike the quota ceiling raced last — and
  the distinction between corroborating a race and proving one stays
  documented where the tests live.

### Fixed — a satisfied waiter no longer swallows a second event

- **A subscription outlived the match that satisfied it, and the window
  swallowed messages.** `match_waiter` claims the event and hands the run to
  its resume; the run unsubscribes *later*, in its own store call. Between
  the two — sequentially, on any backend, no race required — a second event
  matching the same key was matched to the same already-satisfied waiter and
  claimed for its run: parked under a claim nobody consumes, and claimed
  events never dead-letter, so the message vanished from every listing an
  operator reads instead of aging out with a reason. Proven red with a
  battery case before the fix. The claim now **retires the subscription in
  its own transaction** on both backends; the resumed wait re-subscribes
  idempotently and recovers its own claimed event through the crash-recovery
  arm, so nothing legitimate needed the stale registration.

  `deliver_to` deliberately does **not** retire, and the asymmetry is the
  two paths' retry semantics — found by the battery refusing the symmetric
  fix: a retried targeted delivery rebuilds its `Matched` from the
  subscription rows to resume a run that crashed between claim and resume,
  and a second distinct message claimed through a satisfied targeted wait is
  recovered by the protocol itself, because the task's next continuation
  re-matches the claimed event for the same run. The broadcast path has no
  such retry loop, which is why it retires and the targeted path does not.
  The reasoning is written at both sites, so the next symmetric "cleanup"
  meets it before the battery does.

### Fixed — the PostgreSQL run ceiling no longer yields under the load it exists for

- **Two admissions racing for one remaining slot both landed.** The reserve
  ran as a single `INSERT … WHERE (SELECT COUNT(*)…) < limit` statement, on a
  comment claiming the decision happened "inside the row lock the write
  takes" — and no such lock exists: two INSERTs of *different* rows lock
  nothing in common, and under READ COMMITTED each statement's count subquery
  reads its own snapshot. Falsified against a real server before the fix was
  trusted: **sixteen concurrent admissions put eight runs through a ceiling
  of four.** The catalogued yields-under-load shape, on the §9.1 control
  whose whole promise is surviving scale-out — and invisible to every
  sequential test, which is why the store had passed. The count and insert
  now decide under a per-tenant transaction-scoped advisory lock (other
  tenants' admissions do not wait), and a genuinely concurrent test races
  sixteen tasks for four slots against a real PostgreSQL in the guards
  suite. redb was never exposed — its single writer is the serialisation —
  which is exactly how a two-backend contract hides a one-backend race.

- **Recording an unreserved batch item reported success while writing
  nothing**, on both backends — told *recorded* over an outcome that
  vanished, the same lie a release that freed nothing tells. Now
  `NotFound`, read from the row count the write already produces, and pinned
  in the shared battery.

- The rest of the quota and batch stores audited clean: the ceiling-of-zero
  edge compares outside the loop and stops a tenant dead; the running set
  is a set, not a counter, so a stranded slot names its run; spend accrual
  saturates; batch reservation returns the original run id so a crashed
  batch replays instead of re-performing; and the batch cursor is the
  contiguous terminal prefix, holding position behind a suspended item.

### Audited clean — the push outbox and the card signatures, adversarially

- **The A2A push worker held ten probes across both backends**: the cursor
  advances only after every payload of a record returned 2xx, monotonically
  (`GREATEST`/`max`), so racing workers duplicate and never lose; a partial
  multi-payload delivery redelivers from the record boundary, which
  at-least-once permits; `attempts` is reset **on success** in both stores,
  so the abandonment ceiling means consecutive failures as documented, not
  lifetime ones; permanent refusals abandon immediately while a projection
  failure — this plane's own bug — stays transient but still ceilinged,
  because a record that cannot be projected now cannot be projected next
  tick either and the cursor never moves past it; the ceiling arithmetic
  makes `max_attempts(1)` mean one attempt; and a receiver answering
  strangely is transient, not trusted.

- **The card JWS held ten**: the algorithm is compared against the constant
  and a header's `none` is skipped rather than believed; the signature
  covers the RFC 7515 signing input itself, not its hash; verification
  reuses the `protected` segment exactly as it arrived, so there is no
  re-canonicalization to disagree; `kid` is read only from the
  signature-covered header, never the unprotected slot; and the payload
  excludes signatures by *removal*, because an empty array and an absent
  field canonicalize differently.

### Fixed — a parse step no longer accepts arguments nothing executes

- **A plan step carrying both `parse` and `args` was accepted, and the args
  silently ignored** — a field that parses and is never read, the
  accepted-prose shape the manifest refuses for `routed`, arrived in the one
  artifact whose whole point is that what is accepted is what runs. Refused
  at execution with the reason named. The rest of the planner held under
  twelve adversarial probes, recorded because the tier carries the crate's
  strongest security claim: forward and self references refuse; `$$` escapes
  exactly one dollar; a planner literal — string, number or bool, at any
  nesting depth — carries the completion's untrusted label while a reference
  carries the label of the value it names, which is what makes exfiltration
  a *gate* decision rather than a routing accident; the final answer is
  resolvable only as a reference, so a planner cannot fabricate it as a
  literal; the runtime's escape bit overwrites any planner-declared
  collision in a parse schema and is read fail-closed; tool names match
  byte for byte with the wire-name hint derived rather than second-sourced;
  and the step ceiling is enforced in code as well as in the response
  schema, because a bound held only by what a provider did with a schema is
  a bound the next driver quietly loses.

### Audited clean — the label lattice, adversarially

- The information-flow core (`core/label.rs`) was walked with eleven
  adversarial probes and produced **no finding**, recorded because an audit
  that only reports defects teaches nothing about where it looked: the
  `Trust`/`Sensitivity` orderings that make `max` the correct join; the
  conservative ancestor walk (`/ab` cannot false-match `/a` — truncation is
  at pointer boundaries only); `object`/`array` assembly maintaining
  whole-label ≥ join of tracked fields; `map`/`zip` discarding field paths
  they would invalidate rather than keeping labels that no longer point at
  their values; field releases refusing where lineage is not tracked instead
  of borrowing whole-value precision; a released leaf not laundering its
  parent object's label; `project_pointer`'s rebase unable to capture `/ab`
  under an `/a` prefix; and RFC 6901 escaping in the order that cannot
  double-escape. External corroboration on the same pass: the 2024–2026
  defense literature (CaMeL, FIDES, Progent, RTBAS, FORGE) has converged on
  deterministic out-of-band enforcement over per-value labels — the shape
  this module implements — with the known utility trade-off already recorded
  under the open context-branching question.

### Added — a task can be taken over from a holder who is not coming back

- **`TaskStore::take_over` and `POST /tasks/{task}/takeover`
  (`api:task.takeover`).** The claim family had three members and three
  answers to the same crash-or-absence question: events re-claim for the
  claiming run, timers age their claims out on a lease — and tasks had
  nothing, because only the holder may release. A task claimed by a reviewer
  who left was parked until its deadline breached, turning a routine handover
  into an escalation; the release endpoint's own docs name "an operator edits
  the database" as the anti-pattern it exists to prevent, and the absent
  holder was exactly that case. A take-over displaces a **named** holder —
  `from` is a compare-and-swap, so a decision made from a stale queue view
  fails rather than displacing whoever holds the task now, the same rule a
  case write follows by naming the version it read — and re-checks
  eligibility in full through the same ladder `claim` uses, extracted to one
  implementation so the two verbs cannot drift a rung: four-eyes exclusion
  does not thin because the previous reviewer left. An unheld task is
  refused (`NotHeld`), because the verb for that is `claim`, and accepting
  it would hide a stale view. Its own policy action lets a deployment hand
  displacement to a queue lead without handing it to every reviewer. Like
  claim and release it is a reservation in the store, not a decision — the
  decision eventually taken still records its decider. The conformance
  battery pins the stale-view refusal, the exclusion, the legitimate
  handover and the unheld refusal on both backends; the API denial walk
  covers the new route, which the route/vocabulary agreement test enforced
  before the route could ship without it.

### Fixed — a crash between an event's claim and its run's resume no longer loses the message

- **An event claimed for a run was hidden from that run's own recovery.**
  `match_waiter` claims durably; resuming the claimed run is a separate step;
  a process can die between the two. The event then sat claimed for a run
  that never saw it: the counterparty's retry was answered `Duplicate` (the
  dedup working exactly as designed), the resumed wait re-subscribed and
  asked `claim_for` — which filtered to *unclaimed* events, hiding the run's
  own message from it — and the run slept until its deadline breached. A
  message that arrived in time, lost anyway, in the failure mode §5.2 exists
  to prevent and the one that presents as a process silently never
  completing. The targeted path already had the answer: `deliver_to` grants a
  retried delivery idempotent re-matching for the claiming run. `claim_for`
  now grants the same — an event claimed **by this subscription's run** is
  claimable again, on both backends, while any other run still finds nothing.
  The conformance battery walks the crash sequence store-call by store-call:
  match, then re-claim by the owner (must succeed), then claim by a stranger
  (must not).

- Checked sound on the same pass: the `(source, id)` dedup identity built by
  one function with an unforgeable separator; both API transports setting
  `source` from the authenticated caller, never the body; claim atomicity in
  both directions; and the buffer-before-match ordering. The `EventStore`
  trait docs understated the dedup identity as "by event id" — the exact
  imprecision §5.2 warns about — and now state the pair and the reason.

### Fixed — a revoked draw is an answer, and now the runtime treats it as one

- **Every standing-authority refusal flattened to an error that reads as
  in-doubt.** The `AuthorityError` taxonomy is built on the distinction its
  module docs open with — revoked is *"not retryable, ever"*, exhausted may be
  followed by a larger authority, and conflating them teaches a caller to
  retry a decision that has been taken back. The effect's error mapping then
  collapsed all five refusals to `Other`, whose disposition is **in-doubt**:
  a revoked draw was retried under the full policy (the store idempotently
  refusing each attempt), the final failure read *"may well have been
  applied"* over a refusal the store answered with certainty, and a draw
  deferred in an effect group quarantined the group — paging an operator —
  where the cheap abort was the truthful settlement. Refusals now map to
  `Refused` (an answer: one attempt, a failed run) and store unavailability
  to `Unavailable` (retried, safe *because of* the receipt dedup). The journal
  is the test's witness: one `EffectStarted` for the draw, and `Failed`
  rather than `Quarantined`.

  The sibling `Other` mappings in the same module were checked for the same
  shape and stand: they wrap `StoreError`, which cannot certify that nothing
  landed, so the conservative in-doubt default is honest there. The authority
  case was different in kind — a typed refusal is certainty, and reporting
  certainty as doubt is the defect.

  The store layers themselves audited clean: draw-receipt idempotence keyed on
  the dispatch identifier, `FOR UPDATE` with a post-lock receipt re-check on
  PostgreSQL, refusal ordering shared through one `permits`, first-revocation
  wins, and terms immutable by canonical-byte comparison.

### Fixed — a cascade now passes through tombstones, on both backends at once

- **Cascading erasure could not route through an individually-forgotten
  intermediate.** A → B → C, with B corrected away by `forget`: a later
  cascade from poisoned A never reached C, so the summary-of-a-summary stayed
  readable after the erasure request that named its root reported success.
  Two defects composed. The traversal skipped any node with no current entry —
  in **both** backends, with the identical filter, which is what a contract
  written from one misreading looks like (the battery's cascade was one level
  deep, so nothing could see it). And `forget` deleted the tombstone's
  *incoming* edges, severing the route even for a corrected traversal — the
  same call whose own comment kept the *outgoing* edges "so a later erasure
  can still find derived summaries" cut the path by which an upstream erasure
  would arrive. Edges now survive a forget in both directions (the read path
  keeps them harmless — `derivatives` skips tombstoned targets — and the
  tombstone prevents id reuse), the traversal enqueues every edge target, and
  the count reports only ids whose state the call actually removed: a
  tombstone is routed, not counted. The shared conformance battery now walks
  a three-deep chain with the middle link erased first, so both backends are
  held to it by the same assertion.

### Fixed — a refusal that is an answer is no longer retried as a fault

- **`EffectError::Refused`: the peer understood the request and said no, and
  the retry loop spends no attempt on it.** The model error taxonomy drew this
  line — `RateLimited` documented as "worth retrying", `Refused` as "repeating
  is pointless" — and the distinction governed nothing: both collapsed to one
  variant at the effect boundary, and the retry loop's only gates were
  disposition, recovery and attempt count. So a permanently-wrong request (an
  unknown model, a schema the provider rejects, input filtered on the way in)
  burned every permitted attempt with backoff, identically to a 429 — the
  catalogued shape of a declaration that does nothing, wearing the catalogued
  shape of a caller taught to retry the permanent. The bit is **recorded** on
  the failure (`EffectFailed.permanent`), because the retry decision is
  recomputed on replay: a replay that could not see it would expect the retry
  the live run never made and report divergence over a faithful history — the
  test pins live behaviour and strict replay both.

- **HTTP 408 and 425 are transient, not judgements.** The shared status
  classifier put every 4xx in the refused-before-generating class; these two —
  the server timing out or declining to process *early* — are the 4xx codes
  whose documented remedy is the retry, and under the rule above they would
  have become terminal. Now classed with the retryable failures.

### Changed — a landscape claim narrowed to what shipped software permits

- **"Governance cannot be added afterwards" was half-falsified, and the
  constitution now says which half.** Governance toolkits ship as framework
  middleware — per-action policy engines on callback/middleware hooks, with
  identity, capability gating and trust scoring — so per-action allow/deny
  demonstrably layers on afterwards, and a document claiming otherwise would
  be arguing with shipped software. The claim is narrowed to the three things
  the hook position structurally cannot supply, which were always this
  design's actual claims: enforcement *below* the code it governs (an
  in-process hook is advisory against its own process), flow (a label travels
  on the value; no interceptor can reconstruct provenance at the boundary it
  fires on), and evidence unified with recovery (a middleware audit trail is
  a second log beside execution). The hook-chain rejection likewise now names
  the governance-toolkit form beside Strands, since the pattern outgrew one
  framework's extension point.

  The same pass walked the effect-group machinery (`runtime/group.rs`) and
  the budget core against their constitutional claims — every commit path,
  the three-conjunct cheap-abort guard, the `CommitUnknown` split, the
  reversing-flag scoping, atomic-member replay — and found **no defect**,
  recorded here because an audit that only reports findings teaches nothing
  about where it looked.

### Fixed — two ways a counterparty could spend what it should not

- **An off-spec witness can no longer invent a shrink.** C2SP's 400 is a
  statement about the request's own two numbers — `old` exceeds the checkpoint
  size — and both are in hand before the witness answers. The arm mapped
  *every* 400 to `Shrank`, so a witness answering 400 outside its protocol (a
  mis-parse, a proxy's error page) manufactured a fork-class alert for a
  request whose own numbers show none. The arm is now guarded by the same rule
  the 409 arm already held: a witness is untrusted, so its reply can *confirm*
  an integrity finding the request evidences and must never *invent* one. An
  off-spec 400 is routine unavailability, named as off-spec.

- **A content-filtered `ListTasks` has a cost ceiling.** The paged index
  bounded the unfiltered listing — and a `status` or `contextId` filter handed
  the unbounded scan straight back, because the filter is answerable only by
  reading each candidate's journal and the spec's `totalSize` is the exact
  pre-pagination count. One field, and any authenticated peer buys a scan of
  every run the tenant ever wrote, per request. `filter_scan_budget`
  (default 1024 candidate reads, settable on `A2aServer`) refuses an
  over-budget filter naming the lever that narrows without reading —
  `statusTimestampAfter` is answered from the index. Refused rather than
  truncated, deliberately: a total that quietly stopped counting reports a
  smaller tenant, not a bounded scan, and the spec requires the exact count.

### Fixed — the audit engine audited, and the false alarm mattered most

- **An open run no longer audits as an integrity finding.** The audit flagged
  *every* run the log held no leaf for — and an open run (failed and resumable,
  exhausted, still executing) legitimately has no leaf, so a healthy plane with
  ordinary open runs audited as damaged on every pass. A false integrity alarm
  is how the true one stops being believed. The decision now belongs to the
  run's own records: a **sealing** conclusion with no leaf behind it is history
  the log no longer commits to and stays the finding it always should have
  been; an open run is listed sound on chain and signatures, with the limit
  said once in `not_checked` — an open run's tail has no leaf to pin it, so
  truncation is undetectable until it seals. The sealed-or-not rule is
  `runtime::SEALED_OUTCOMES`, not a re-spelling of it. `testkit` gained
  `Schedule::leafless(run)` because a healthy store cannot produce the
  serious half on request — sealing always writes the leaf — and the finding
  for the most serious state the audit reports was reachable by no test.

- **A mid-audit seal no longer reads as tampering.** The audit captured its
  checkpoint first and asked for inclusion proofs after, so a run sealed in
  between carried a proof against a larger tree than the root in hand —
  `BadInclusion`, on a healthy busy plane. The same race the export had, in
  its sibling. The checkpoint now catches up once; a plane sealing
  continuously through the audit lands in `not_checked` as unpinnable, which
  is the honest answer.

- **Three doc comments had absorbed the item below them** — the catalogued
  absorbed-doc shape, in the one escape variant its guard names but cannot
  cheaply catch: a one-line absorbed doc lands as the block's *final* line,
  where no blank `///` follows and the detector's loop never reaches. `audit`'s whole
  doc block (its `# Errors` included) sat on `releases_in`, leaving `audit`
  undocumented; `run_correlated`'s correlation explanation sat on
  `run_in_case`, whose block then contradicted itself about whether the case
  exists; the `skills` field's summary sat on `per_agent`. Found by running
  the final-line variant of the guard's own fingerprint over the whole tree —
  34 hits, 3 defects — and the guard now documents that sweep as the review
  prompt, with the measured reason it is not automated: 31 legitimate
  punchlines to 3 defects is a guard that trains its reader to skim.

### Fixed — the export was audited before it shipped, and five gaps did not survive it

- **The verifier now checks the format version it was told to pin.** The header
  carried `version: 1` "so a reader pins this" — and no reader did, including
  this crate's own two. A declaration only the writer consults is a declaration
  that does nothing: `verify` would have parsed a future format as far as its
  lines looked familiar and reported findings about a file it never understood,
  and `restore` — whose parser deliberately skips what it does not recognise —
  would have rebuilt whatever subset happened to parse and called it a history.
  `verify` now reports a foreign version as a finding; `restore` refuses it
  outright, because the two failure modes differ: a misleading report is bad,
  and an unknowable partial restore reported as complete is worse.

- **A relabelled run block is caught by its own records.** Chain, leaf and
  Merkle checks all verify *bytes*, so an export that filed run B's records and
  B's leaf under run A's id passed every one of them — and `sound` then named a
  run whose history is somebody else's. Only the label lied, and the label is
  what a reader looks a run up by. Every record's `body.run` is now held to the
  block it sits under; the record's run id is inside the hashed body, so the
  check cannot itself be forged around.

- **A run sealed after the export's checkpoint is exported as still open.**
  `to_jsonl` reads the checkpoint first and each run's log position after, so a
  run sealed in between carried an index the header's checkpoint does not commit
  to — and the verifier then rebuilt a tree one leaf larger than the root it
  compares against, reporting tampering where there was only time. A race every
  busy plane hits, producing exactly the false alarm that teaches operators to
  disbelieve the alarm. The export now describes the log *as of its checkpoint*:
  the late run's records are all present, its seal travels in the next export.

- **An open run with an edited record is no longer listed sound.** A sealed
  run's tampering surfaces at the leaf comparison; an open run has no leaf, so
  the per-record findings were the only control — and they never reached the
  verdict. The report produced a finding *and* listed the run sound, two halves
  of one artifact contradicting each other. Per-record findings now carry to the
  run's verdict.

- **The sealed-outcome list moved from the binary into the library.** The
  export CLI's default sweep named the sealed outcomes as string literals —
  two implementations of one rule, where a new sealing outcome would have been
  silently dropped from exactly the artifact an auditor asks for.
  `runtime::SEALED_OUTCOMES` now lives beside `RunStatus::seals`, and a test
  holds the two to each other variant by variant, which literals in a binary
  could never be held to.

### Added — the audit verbs take evidence, not just a store

- **`audit --key <id>=<hex> --prior <report.json> [--require-signatures]` and
  `verify --key <id>=<hex>`.** The library call has taken a verifier and a prior
  checkpoint all along; the verbs hardcoded neither, so the signature check and
  the deletion check were real and unreachable without linking the crate and
  writing Rust — the exact dependency these verbs exist to remove. `--prior`
  takes the `current` field of an earlier report, so each audit prints the
  checkpoint the next one checks against; the loop is the deletion check.
  `cli` now includes the `signing` feature for this. `--key` on `verify` is
  strict about unsigned records deliberately — inside a signed history, the
  unsigned record is the one an attacker who cannot sign would add — while
  `audit` keeps strictness behind `--require-signatures`, because history
  written before signing was configured is legitimately unsigned.

### Added — restore, and it proves itself

- **`agentplane restore <export> --store <path>`** rebuilds a journal from an
  export and proves it by one comparison: equal Merkle roots at equal size. That
  is stronger than "the rows loaded" — it means every record, in every run, in
  the order the log recorded them, rebuilt to the same commitment. A restored run
  **strict-replays on a plane that never executed it**, consuming every effect
  from history and performing none.

  It replays the ordinary `append` path rather than writing rows, which is the
  safety argument: `append` maintains six derived indexes — case, exactly-once,
  outcome plus its ordering counter, and both halves of the discovery index — and
  a restore that rebuilt five would leave a store that reads perfectly until
  somebody queries the sixth. The test therefore asserts through the query
  surfaces, not only the checkpoint.

  Two details reproduce the original bytes rather than similar ones. Runs are
  **sealed in log-index order**, because that order *is* the Merkle log — seal in
  file order and the same leaves give a different root. And `epoch` is **carried,
  not re-derived**: it is inside the hashed body, so a run that ever changed
  hands would rehash under one fresh lease, and those are exactly the runs a
  failover produced. Both backends fence only when a lease row *exists*, so
  restoring into a store with no leases writes each record under its own epoch.
  `Append::from_body` exists so that field list lives in one place — a restore
  that forgot `phase` would replay a compensation as a forward record and hash
  differently for a reason no diff shows.

  What does not survive is named in the report: signatures, unless the restoring
  store holds the original key (hashes and the root are unaffected, since a
  signature is over the chain hash and stored beside it), and activity
  timestamps, which are rebuilt at restore time.

  **The epoch property was very nearly untested.** Every run in the round-trip
  test had epoch 1, so flattening epochs changed nothing and the mutation
  survived — on the one behaviour the whole design exists for. There is now a
  run that changed hands, built by appending with no lease, which reproduces
  precisely the history a takeover leaves without waiting one out.

### Added — the restore drill

- **`agentplane verify <export>` recomputes an export and checks it against its
  own checkpoint.** Putting bytes back into a store proves bytes moved; it does
  not prove they are the bytes that were taken, in the order they were taken,
  with nothing dropped from the middle. This establishes that — from the file
  alone, with no store and no runtime.

  Every record is re-sealed through `Record::seal`, the same function the store
  seals with, so agreement is evidence about the bytes rather than the file
  agreeing with itself. Sequences must be contiguous, because a removed *tail*
  breaks no link. Signatures go through `Record::verify_attested` with
  `require_signature`, so one implementation answers *is this signed history
  sound* rather than two.

- **The export now carries Merkle log positions, and it could not verify without
  them.** This was a real gap in what shipped last round: the leaf *order* is
  store state assigned at seal time and appears in no record, so an export could
  be walked but not checked against the checkpoint in its own header. Delete a
  whole run and every surviving chain still verifies perfectly — a chain links
  records *within* a run and knows nothing about its neighbours. Only the
  rebuilt tree notices.

  Each run now gets a block line carrying its log index and leaf, and `verify`
  rebuilds the tree from them. Absent for an open run, which is a state rather
  than a gap. `Checkpoint` gained `Deserialize` for the same reason it gained
  `Serialize`: the reader hands it back.

  **Two fixtures in this work were measuring themselves** and are recorded
  because the shape recurs. One grepped for `RunId::to_string()` — `run_01K…` —
  while the JSON form is bare, so it removed nothing and the "did the edit
  land" assertion was satisfied vacuously. The other edited a field the export
  does not contain. Both now assert the fixture changed something before
  asserting the control noticed.

### Fixed — a protocol listing read the whole store

- **`tasks/list` cost O(every record the tenant had ever written.)** It called
  `JournalStore::recent_runs`, which returned **every** run unbounded, then read
  the *complete journal of each* to build a task it might not even return, and
  paginated afterwards. Any authenticated peer could ask, repeatedly.

  The signature was the cause: it offered nothing to bound with, so the caller
  could not have done better. Every other listing in this crate takes a limit
  and reports truncation; this was the exception, and it was the one a remote
  party could reach. `recent_runs(after, limit)` is now a bounded, cursored page
  in a total order — `(updated_at, run)` descending, the tie-break included in
  the contract because both backends keep whole-second timestamps, so ties are
  ordinary and a cursor landing mid-tie drops or duplicates a row.

  The listing now reads a journal only when the answer needs one: for the runs on
  the page, and — where `contextId` or `status` is given — for the candidates it
  must examine to report an exact total. Permission and `statusTimestampAfter`
  are index-only and cost nothing.

  **`totalSize` nearly became an information leak in the process.** The first
  version answered the unfiltered case with a cheap `count_runs()` off the
  index, which counts rows the caller is not permitted to see — so the listing
  would hide the tasks and the number would report them. `list_tasks_omits_tasks_the_caller_cannot_read`
  caught it. Counting now happens after the permission check, and `count_runs`
  was removed rather than left as a faster wrong answer.

  **Breaking:** `JournalStore::recent_runs` takes `(after, limit)`. An embedder's
  own store must page in the stated order; the conformance battery now checks
  it, which it could not before — an unbounded read has no page boundary to get
  wrong, so there was nothing to check.

### Added — getting the record out

- **`agentplane export` and `agentplane audit`.** The offline audit existed and
  was a library call, so the independent party the whole evidence argument is
  built around had to link this crate and write Rust. And there was no export at
  all — an auditor who can *check* a history but cannot *obtain* it is still
  dependent on the operator, and a supervisor asking a regulated entity to
  demonstrate an exit is asking about obtaining.

  Both verbs take a store and nothing else. `export` writes JSON Lines: a header
  naming the log, its checkpoint and the canonicalization rule the digests were
  computed under; one line per record carrying `prev_hash` and `hash` so the
  chain re-walks from the file alone; and a trailer. Three properties are
  refusals of an easier design — it streams rather than building a `Vec` (the
  export that matters most is from the largest store); it is framed, so a file
  cut short by a full disk ends *without* a trailer rather than looking
  complete; and it names runs it could not read instead of dropping them.

  `ExportedRecord` is written out by hand rather than derived on `Record`,
  because this is a durable format and a derive makes the wire shape a side
  effect of a field list. `AuditReport` and `Checkpoint` now implement
  `Serialize` for the same reason the verbs exist.

  It exports what the chain committed to — ciphertext where a key ring is
  configured. An export of plaintext would put a copy beyond the reach of key
  destruction and undo cryptographic erasure.

- **`testkit::faults` can make a run unreadable.** Fault injection covered the
  append path only, which is where the interesting write failure lives — but a
  *reader* of history has its own bad state, and a healthy store never produces
  it on request: both backends answer an unknown run with an empty read rather
  than an error, correctly. So the export's "names what it could not read" test
  was written against a run that does not exist, asserted an accounting identity
  that held either way, and passed with the reporting deleted. `Schedule::unreadable`
  makes the state reachable; the mutation now dies.

## [0.13.0] — 2026-08-10

### Changed — security

- **Break-glass is a door, not a step.** `Planes::cross(caller, target, reason)`
  is how you reach a tenant that is not the caller's, and it returns the plane
  only once the crossing is sealed into that tenant's journal. Previously
  `record_break_glass` and reaching for the plane were two calls in a documented
  order, and nothing enforced it: an admin handler that skipped the first got a
  cross-tenant read with nothing on the record. The runtime's own rule is that a
  control which must be invoked is not one, and this was the last place it had
  to be.

- **`Planes::get` takes the caller, not a tenant** — and this is what made the
  entry above true rather than aspirational. Building the door left a window
  beside it for one revision: `cross` was correct, and every artifact called it
  *the only way to reach a tenant that is not the caller's*, while the ordinary
  lookup still accepted a bare `TenantId` and handed any registered plane to
  anyone who named it. `planes.get(&victim_tenant)` was a complete cross-tenant
  read with no record, and the tenancy table listed the control as built.

  Both halves passed review, because neither was wrong on its own: the new call
  did everything claimed of it, and the old one had been correct for as long as
  its only caller passed the tenant it had just authenticated. What was false
  was the pair. A claim about *the only way* is a claim about every other way,
  so it cannot be checked by reading the mechanism it names — the review that
  matters is of the doors it is not.

  Both lookups now take `&Caller`, so the only tenant a handler can name is the
  one its credential resolved to. The claim is narrowed to what a library can
  actually hold: **no path reaches another tenant's plane by accident**, since
  none can name one. A deliberate crossing is still possible — an embedder's
  `Authenticator` decides what a credential means and can mint a caller for any
  tenant — and that is a seam a deployment owns, not a forgotten step.

  `cross` now takes the whole `Caller` too. Its actor, roles and tenant are one
  fact, and passed apart a handler could record one operator's name against
  another's crossing: written, signed, and wrong.

  **Migration.** `planes.get(&caller.tenant)` becomes `planes.get(&caller)`;
  `planes.cross(&caller.tenant, &target, &actor, &caller.roles, reason)` becomes
  `planes.cross(&caller, &target, reason)`.

### Added — a finding has to be findable

- **`GET /cases?status=…` — what is escalated right now.** An escalation is the
  sweeper saying an obligation was missed and somebody was told, and "told"
  meant a status written onto the case. `CaseStore::by_status` existed; nothing
  exposed it. So the only way to read an escalation back was `/cases/{case}`,
  which needs the id — the answer was available to everyone except the person
  who had to ask. Newest first, `truncated` when the page overflows, and an
  unrecognised status is a `400` rather than a quiet fallback to `open`, which
  would answer *what is escalated* with a list of healthy cases.

  The route listing quarantined runs asserted the opposite in a comment — *every
  other backlog here is findable by whoever must clear it, escalated cases
  included* — written on the route that had just closed the same hole one
  surface over. A claim about the doors you are not looking at, made while
  looking at this one.

### Fixed — security

- **`api:run.list` was missing from `action::ALL`.** A deployment writes its
  policy rules by enumerating that list and its engine denies by default, so the
  verb nobody saw is the verb nobody granted — and the route behind it answers
  *what is quarantined right now*. The backlog added specifically so that a
  quarantine reaches a human was, for any operator who trusted the exported
  vocabulary, refused to everybody.

  The test meant to catch this agreed with the bug. It compares `action::ALL`
  against the verbs the gate-denial walk actually asked, and that walk did not
  call `/runs` either: two omissions that cancel, which passes forever and makes
  the wrong contract look pinned. The walk now covers every route, and both
  halves are held by mutations.

  **Grant `api:run.list` and `api:case.list` explicitly.** They are the two read
  verbs an on-call person needs and the two an allowlist built from route names
  alone will miss.

### Fixed — integrity

- **A plan's digest no longer degrades to a constant.** `PlanIR::digest` read
  `canon::to_bytes(self).unwrap_or_default()`, and `Digest::of(&[])` is the same
  value for every plan — so any plan that failed to serialize would have shared
  one content address with every other, under the digest that is journaled at
  admission and binds a run to the graph it was authorized to execute. This is
  the exact fallback `canon::value_bytes` refuses one layer down, in a doc
  comment explaining why: *a fallback would make two different values hash
  identically*. One rule, two implementations, and the weaker one was on the
  authorization identity.

  Now routed through `value_bytes`, so the abort rule lives in one place.
  Unreachable today — every field is a string, integer, enum, digest or JSON
  value — and written as an abort because the *reason* it is unreachable is a
  property of the fields, which a field added later is what would change.

- **A witness's unreadable 409 body is no longer read as size zero.** The body
  of a stale reply is the witness's own tree size, and the caller acts on it by
  building a consistency proof from there and resubmitting. `unwrap_or_default()`
  turned a blank body, an HTML error page or a stray newline into a definite
  claim of size 0 — which the caller then submits a proof from, the witness
  rejects, and the rejection is classified as `Forked` or `Shrank`: the
  **integrity** bucket. So an unreadable reply manufactured a fork alert, the one
  outcome `WitnessError::Stale`'s own documentation says must not happen, since
  a team paged twice for a routine cursor mismatch stops believing the alert that
  matters. A witness is untrusted; what it did not say it does not get to have
  said. An unparseable size is now `Unavailable` — routine, retried, not escalated.

### Added — assurance

- **The chain that keeps `requires_approval` off a hand-written skill is now
  pinned by a test.** `StepCtx::sink` does not consult the field, and that is
  sound only because no manifest can put the two together: a grant needing
  approval needs `spec.oversight`, oversight needs `spec.execution`, a
  declarative agent provides exactly one capability, and two skills may not
  claim one capability. Four refusals across three files, each reading as being
  about something else, and nothing named the conjunction — so any one of them
  relaxing would have opened the gap in silence with every existing test still
  passing. The property was sound and unheld; it is now both.

- **A plan's content address is now checked field by field.** The existing test
  round-tripped a plan through the journal and asserted the digest matched,
  which proves stability and not coverage: a digest that ignored topology
  entirely, or dropped every node, passes it. Twelve identity-bearing changes
  are now asserted to move the digest, and all of them to be pairwise distinct —
  the assertion that catches a digest which has become a constant.

- **Each tenant's own policy engine is held to deciding its own requests.** Two
  planes, two engines that disagree, and each asked exactly once. This is the
  evidence behind the constitution's claim that per-plane *is* tenant-scoped;
  the claim rests on the registry resolving the plane before it asks the policy
  question, and nothing pinned that order.

### Changed — documentation

- **Release blocker 3 was largely an expired premise, and is rewritten.** It
  read *identities, policy bundles, manifests and egress grants are still
  plane-wide, and tenant-safe export, restore and witness proofs do not exist*.
  Three of those four clauses no longer describe this system: "plane-wide"
  stopped being distinct from tenant-scoped when a plane became single-tenant;
  witness proofs are tenant-scoped and §9.1's own table said so four lines
  above, marked **built**; and egress names hosts a deployment may reach rather
  than tenant state. What survives is export and restore, which do not exist in
  any form.

  The release-blocker list is the one artifact answering *may this ship yet*, so
  a stale entry costs more there than anywhere. Every item now has to name the
  check that would show it discharged, or it outlives its premise while looking
  like an open question.

  A same-tenant `cross` is refused — that is `Planes::get`, and recording
  routine access as break-glass buries the real crossings. An unregistered
  target is refused rather than defaulted, as the ordinary tenant gate is.

  `record_break_glass` stays for an embedder recording a crossing made some
  other way. New mutation `CrossingServesBeforeItRecords`, killed by
  `crossing_to_another_tenant_records_before_it_serves`.

- **`RuntimeError::UnknownTenant`** — new variant, for a tenant this process
  serves no plane for. The enum is `#[non_exhaustive]`, so this is additive.

### Fixed — documentation

- **Twenty-three doc comments had absorbed the one below them.** Inserting an
  item between an existing doc block and its own item is valid Rust, so the
  block silently takes on the next item's documentation and the item below is
  published bare. `EffectError::spend` carried `disposition`'s summary while
  `disposition` — the accessor that decides `DidNotHappen`/`InDoubt`/`Landed` —
  had none; `RuntimeBuilder::signing_as` and `lease_ttl` both carried `owner`'s,
  and `owner` had none; `Tainted::peek`, `Record::seal_signed` and
  `Record::MAX_RECORD_BYTES` were the same shape. All twenty-three are split
  back onto the items they describe, across `src/` and `tests/`.

  Nothing was wrong with the *code*; every one of these was a reader following
  published rustdoc to the wrong method.

### Fixed — assurance

- **The guard for that shape was blind to it.** `no_doc_comment_has_absorbed_-
  the_one_below_it` fingerprinted a block with two `# Errors` sections, which
  the two instances that motivated it happened to have and the other
  twenty-three did not. It also never scanned outside `src/`, so the two
  instances in the guard's own file were unreachable. Both are fixed: the scan
  now covers `tests/` and `examples/`, and a second fingerprint runs beside the
  first — a one-sentence line closing a paragraph directly after another
  complete sentence, which is what a spliced summary looks like. It carries a
  self-test that fails on the real instances before it runs over the tree, and
  states in its own documentation what it therefore does not catch.

  Seven doc blocks were reflowed to give a paragraph-final punchline its own
  paragraph, which is what makes the second fingerprint exact rather than
  advisory.

- **A duplicated assertion loop** in the same guard: the `ABSENT_BY_DESIGN`
  check ran twice, verbatim, the second copy with mangled message whitespace.

## [0.12.0] — 2026-08-09

### Fixed — testing

- **A flaky Vault container test.** `WaitFor` matching a stdout line means the
  process printed it, not that Docker has finished publishing the port, so a
  one-shot `get_host_port_ipv4` failed as `PortNotExposed` on a loaded machine.
  Both call sites now retry within a bound; a genuinely dead container still
  fails loudly. Worth an entry because a flake trains people to re-run rather
  than read, which costs more than the test is worth.

### Fixed — interoperability

- **An absent `tenant` was sent as JSON `null` instead of being omitted**, and a
  comment above the line said *"omitted entirely when the interface declares
  none"* — which is what it was meant to do and not what it did. `json!` renders
  `None` as `null`; ProtoJSON omits a field at its default value, so the
  reference server answered `invalid type: null, expected a string`. The same
  bug was in `GetTask` and in the governance extension's `provenance`.

  **This crate's own server accepted all of it** — `serde` reads `null` into an
  `Option` as `None` — so every in-repo test agreed with the bug. It took a
  server nobody here wrote to find it, on the first round trip.

### Added

- **Client-side interoperability evidence, against an independent server.** The
  protocol project's conformance kit validates *servers*, so this crate's client
  had no outside authority to talk to — the one interoperability gap the kit
  cannot close, and a release blocker. `a2a-server-lf` (the reference Rust SDK's
  server) now stands up in-process as a **dev-dependency** test double: its
  request handler, its task store, its JSON-RPC framing, none of it written
  here. Two tests: a full `SendMessage` round trip, and a disposition mapping
  taken from the reference server's own refusal rather than from a canned
  fixture written to this crate's reading of the spec.

  Pre-1.0 churn is acceptable here in a way it is not on a shipped boundary:
  nothing in `src/` links these crates and `cargo package` does not carry
  dev-dependencies. `default-features = false` keeps a TLS stack out of it — the
  double binds a loopback port over plain HTTP.

- **Canonicalization is versioned, and a rule change reads as *unverifiable*
  rather than *divergent*.** `core::canon::VERSION` is journaled on
  `RunAdmitted`, defaulting to `1` on read so a record written before the field
  existed says the UTF-8 ordering that produced it. Replay compares it before
  recomputing anything: a run written under another rule is
  `RuntimeError::CanonicalizationChanged`, not a quarantine.

  Why it mattered: every effect key comes out of the canonicalizer, so the
  change from UTF-8 byte ordering to RFC 8785's UTF-16 code units moved all of
  them at once. A replay of healthy history recomputed different keys and
  reported **non-determinism** — the most serious conclusion this runtime
  reaches — with nothing on the record to say the rule had moved. The chain was
  never implicated and the test asserts that too: it hashes the bytes it stored
  rather than re-canonicalizing them, so a refusal that also implied corruption
  would be the wrong answer twice.

- **A plane serves an Agent Card per agent.** `A2aServer::hosting(..)` takes
  several manifests; each agent gets a full card at `/agents/{name}/agent-card.json`,
  and the well-known path stays one valid card describing the first. A new
  `agent-directory` extension on that card lists every agent, its card path and
  its manifest digest. The discriminator is a **path**, not `AgentInterface::tenant`
  — that field's documented meaning is the tenant id a caller echoes back, so
  overloading it to select an agent would put two meanings in one string on a
  multi-tenant plane. Skill dispatch already spanned every agent on the runtime;
  what was missing was discovery. Two agents advertising one skill id is refused
  at construction (`ServerSetupError::AmbiguousSkill`), because A2A dispatch is
  named and a name resolving to two agents is a routing decision the caller did
  not make. An empty plane is `ServerSetupError::NoAgents`.

- **`ErasureCoordinator`, and a PostgreSQL implementation.**
  `EncryptedMemoryStore` serialised subject erasure against writes and
  legal-hold changes with a process-local mutex — correct on a single writer,
  silently nothing on an active-active plane. The lock is now a seam:
  `LocalCoordinator` is the mutex, named for what it is and answering
  `is_distributed() == false`; `PostgresCoordinator` (from
  `PostgresStore::erasure_coordinator()`) is a **session** advisory lock in the
  database the plane already shares, so an instance that dies mid-erasure
  releases by dying. Wire it with `EncryptedMemoryStore::coordinated_by(..)`.
  Held by a test that races two coordinators against a live PostgreSQL and
  asserts both halves — the second instance blocks while the first holds, and is
  granted once it releases.

  **The unsafe pairing is refused at `build`.** `JournalStore::is_shared` (new,
  and **required** — no default, so a shared backend cannot answer
  *single-writer* by saying nothing) meets `MemoryStore::erasure_is_distributed`
  (new, defaulting to `None` for a store with no lifecycle lock), and a shared
  store beside a process-local lock is `BuildError::ErasureCoordinatorNotShared`.
  Four cases are pinned, because the two that must still build are what keep it
  from being a ban.

  `ErasureCoordinator::acquire` is documented as **not cancel-safe**: dropping it
  mid-flight can leave the lock taken with no lease to release, because the
  PostgreSQL coordinator has a query outstanding on a pooled connection at that
  moment. Found by a test that wrapped it in a `timeout` and hung the suite. Use
  `under_lock`; to ask whether a scope is locked without taking it, use
  `PostgresStore::erasure_probe`.

## [0.11.0] — 2026-08-09

### Changed — breaking

- **A `mutates: true` grant with no `protected_fields` is refused at parse for a
  `tool-calling` agent.** Three facts composed: a model completion is untrusted
  unconditionally, the tool loop builds a call's arguments from it, and a
  mutating sink whose grant names no protected fields refuses an untrusted
  argument bundle outright. Together, such a grant could never fire — and the
  run did not fail cleanly, it *succeeded having done nothing the model asked
  for*. Reported from a migration with 108 such grants across 27 manifests, all
  unreachable, each reading as a live capability. Three fixes, and the message
  gives all three: declare the authority-bearing arguments in
  `protected_fields` (ordinary untrusted content may sit beside them, which is
  what the feature is for); move to `execution.kind: planned`, whose arguments
  are resolved by the runtime; or say `mutates: false`.

- **`BuildError::OversightUnreachable`.** An agent declaring `spec.oversight` or
  a `requires_approval` grant now refuses the build on a plane with no case
  store, worklist or timers. Both facts are known at `build`; left to run time
  it arrived at the first real approval with a person already waiting.

- **A2A method parameters are per-method and unknown names are refused.** One
  `CommonParams` served every method, so a field belonging to one was silently
  accepted by another. `ListTasks` was the case that mattered: a request whose
  `contextId` was misspelled — or spelled `context_id`, which the A2A
  specification's §5.5 forbids — parsed cleanly, dropped the filter, and
  answered with **every** task the caller may see, shaped exactly like the
  scoped list. Found by the protocol project's own conformance kit, whose
  JSON-RPC client sends snake_case: five CORE-LIST rows had been passing over a
  filter that never ran.

### Added

- **`Runtime::case_of(run)`** — which case a run belongs to, read from the
  journal rather than a column beside it.
- **`PushSender::allow_plaintext_loopback`** (`testkit` only) — lifts the HTTPS
  and public-address refusals for a webhook on this machine, so the conformance
  kit's `http://localhost:PORT` receiver is reachable and its **ten push MUSTs
  run at all**. The operator host grant is not lifted, and a plaintext public
  destination stays refused.

### Fixed

- **The worked taint-gate policy in `docs/security` was an outage.**
  `context.label` is the *whole bundle's* label, so in a tool loop the `forbid`
  matched every mutating call. A deployment shipped it and its unit tests
  passed, because a hand-written context is a context assembled to suit the
  rule. The page now says so and offers a scoped form.
- The `getting-started` guide points services at `try_build()`.

### Changed — breaking (continued)

- **One `Duration` on the public surface.** `StepCtx::deadline`'s `warn_before`,
  `Runtime::sweep_events`'s `grace` and `Runtime::sweep`'s `event_grace` took
  `time::Duration` while `StepCtx::sleep` took `std::time::Duration` — two types
  spelled the same word, only one from a crate this one re-exports, so a caller
  with the obvious `use std::time::Duration` met a type error naming a
  dependency the guides never mention. They now all take
  `std::time::Duration`. It is also **unsigned**, which makes two states
  unrepresentable that the signed type allowed: a negative `warn_before` put
  `warn_at` *after* the instant it warns about, and a negative grace window
  moved the dead-letter cutoff forward of now.

  `time::Duration::hours(1)` becomes `std::time::Duration::from_secs(3600)`.
  (`Duration::from_hours` is still unstable on the declared MSRV, which is also
  why `clippy::duration_suboptimal_units` is allowed with the command that
  re-derives the premise.)

- **`DeadlineSpec::minutes`** joins `hours` and `days`. `WallClock` resolved
  `"minutes"` and nothing spelled it, which is where `"minute"` and `"mins"`
  start diverging between an application and its calendar adapter.

### Fixed

- **A push webhook that will never be delivered to is abandoned, not retried
  forever.** The operator's host grant is re-checked at *delivery* as well as at
  registration, because a registration outlives the configuration that permitted
  it — but the worker noticed the refusal and then rescheduled it, so a host
  taken off the allowlist bought one more attempt every 256 seconds for as long
  as the journal existed. Permanent refusals (`NotHttps`, `HostNotGranted`,
  `Malformed`) now abandon the registration; transient ones keep their backoff
  and gain a ceiling, `A2aPushWorker::max_attempts` (32 by default). `Unroutable`
  stays transient, because it covers DNS and DNS changes.

- **`PushSweepReport::needs_attention()`**, matching `SweepReport`. Giving up on
  a peer's webhook used to produce `retries: 1` on an *info* line — the same
  shape a rebooting receiver produces — so `agentplane serve` logged an
  unrecoverable delivery failure as routine progress. New field:
  `PushSweepReport::abandoned`.

- **`--features bedrock` alone now exposes `BedrockEmbedder`.** The `embeddings`
  module was gated on `providers` while holding the Bedrock driver, so a
  Bedrock-only build paid for the AWS SDK and could not name an embedder at all —
  leaving semantic retrieval unavailable to the deployments that chose Bedrock
  because their data may not leave one account. The gate is now
  `any(providers, bedrock)`, and a `const _` in `lib.rs` names each embedder so a
  future gate regression fails this crate's build.

- **An embedding component no `f32` can hold is refused.** `1e39` parses as an
  ordinary JSON number and narrows to `inf`, which the length check could not
  see; `serde_json::to_value` then writes it as `null`, so every out-of-range
  component would have shared one effect key. A zero-magnitude vector is refused
  for the neighbouring reason — it has no direction to rank against.

- **The `run_trusted` that never existed.** The README and the getting-started
  page published the plane's *no such capability* message with a method name
  deleted in 0.10.0. A guard now formats the real error and holds both pages to
  it.

- **`DeadlineSpec::working_days`, which never existed either.** The concepts
  page taught obligations with it — beside a comment saying *five working days*
  while the call said one, the tell that nobody had run it. A second guard now
  refuses any documented `Type::associated_fn` this crate does not declare; the
  previous one covered `StepCtx` alone.

- **`Duration::from_hours(24)` in a published snippet.** Still unstable, so the
  `cx.sleep` example on the architecture page did not compile.

### Testing

- `RecordingPush`, the A2A push test double, now honours its own `validate`. It
  did not, so *the grant is re-checked at delivery* had no test that travelled
  the worker's path — the one path an operator's revocation takes.
- An automated sweep over `model::embeddings` left **14 of 53** mutations alive,
  including `check_egress -> Ok(())`, both `revision()` implementations, and the
  whole of `BedrockEmbedder::embed`. 14 became 0. The egress test itself was the
  interesting repair: it pointed at an unresolvable host and asserted the failure
  named it, which a DNS error does too, so it passed with the ceiling deleted.

## [0.10.0] — 2026-08-08

### Changed — breaking

- **Every admission door takes `Tainted<Value>`.** `Runtime::run` took a bare
  `serde_json::Value` and admitted it as `Trusted`, which is right for an
  operator's literal and silently wrong for a plane started by inbound events —
  `require_trusted` protected fields were satisfied by counterparty-chosen
  values, the egress ceiling had nothing untrusted to join with, and the journal
  recorded no contact with outside data, with nothing failing.

  Eleven doors became eight, and two names changed meaning:

  | before | after |
  |---|---|
  | `run(target, Value)` | `run(target, Tainted<Value>)` |
  | `run_tainted(..)` | removed — `run` is the labelled door |
  | `run_in_case(target, .., kind, keys)` (correlated) | `run_correlated(..)` |
  | `run_tainted_in_case(target, .., CaseId)` | `run_in_case(..)` — *this exact case* |
  | `run_tainted_correlated(..)` | `run_correlated(..)` |
  | `run_plan(plan, Value)` | `run_plan(plan, Tainted<Value>)` |
  | `run_plan_in_case(..)` | `run_plan_correlated(..)` |
  | `spawn_tainted_in_case` / `spawn_tainted_correlated` | `spawn_in_case` / `spawn_correlated` |

  Wrap an operator's own literal: `run(cap, Tainted::trusted(json!(..)))`. A
  `run_trusted`/`run_tainted` pair was tried first and rejected — it doubles every
  shape and still lets `run_trusted(cap, payload)` compile over data nobody
  vouched for. A label is a value; a method name cannot be computed.

- **`--no-default-features --features postgres` now delivers a store.** `store`
  was declared under the `redb` feature while holding *both* backends, so a
  Postgres-only build compiled, pulled `tokio-postgres` in, and exposed no store
  module at all. If you worked around it by also enabling `redb`, you no longer
  need to.

### Added

- **`upgrading`** — a migration page for the refusals that break existing
  manifests and call sites, with the shortest correct fix for each.
- **Plans in `concepts`** — *the unit of concurrency is the plan node*, with
  `PlanIR::fan_out`. Its absence had led at least one evaluation to conclude
  in-run fan-out was impossible and to design around it.
- **`cx.manifest()` in the manifest reference** — a coded skill reads its own
  declaration, so behaviour in Rust and a digest-covered prompt are not the
  trade-off the page implied.
- **A near-miss hint on plan tool names.** A hand-written plan naming the
  manifest spelling (`svc__get_gas`) rather than the wire spelling
  (`svc__get_ugas`, `_` escaping as `_u`) was refused as *not granted*, which
  reads as a policy problem. The refusal now names both spellings.
- **`SemanticRetriever` scope**, answered at the trait: a static operator-ingested
  reference corpus is a first-class use, *as memory items* — a hit is a
  `Selected { id, version, digest }`, so an external corpus is ingested rather
  than federated.

### Fixed

- **Three mutations had rotted into code that no longer compiled**, so three
  guarantees were unfalsifiable while every check stayed green: strict replay
  never re-opening the policy gate, a retried draw double-spending a standing
  authorization, and an Agent Card advertising undeclared capabilities. Each was
  broken by a *successful* change elsewhere; `just anchors` reported all three
  present, because it checks text and not types.
- **The mutation sweep was switched off in CI.** The job was gated to pull
  requests on the reasoning that a push to `main` had already passed it — true of
  a repository that merges, and this one has never opened a pull request. It runs
  on every push now.
- **`Append::into_body`** was gated on `redb` while `PostgresStore` calls it on
  every append, so the Postgres backend did not compile standalone at all.
- **`testkit::conformance_case`** was gated on `redb` despite naming no redb
  type, making the Postgres case-layer contract untestable without linking the
  embedded backend.
- **`just test-postgres` / `test-vault`** did not pass `--no-default-features`,
  so the section comment claiming each seam runs "with *only* its own features
  on" was false for both.
- **The A2A conformance verdict could not distinguish a passing MUST row from a
  skipped one.** `just test-a2a-tck` now prints every skip and holds the pass
  count to a floor.
- **`docs/regulation` contradicted `docs/erasure`** on whether journaled personal
  data can be erased. It described the world before `SealedJournal`: with a key
  ring wired, the chain commits to ciphertext and destroying the wrapping key
  erases every copy while the history still verifies. The wrong page is the one a
  data-protection reader reaches first, and it blocked an evaluation.

### Assurance

- **SSRF classifier**: 67 of 111 mutations survived, because the tests were a
  list of addresses that must be refused — which cannot fail when a bound moves
  *outward*. Every range is now pinned from both sides. 67 missed → 1, and that
  one is a provably equivalent mutant.
- **Label lattice**: 39 of 109 survived, including `field_labels` replaced with
  an empty iterator. Pinned from both sides; 39 → 18.
- `build()` now points long-running services at `try_build`.

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
