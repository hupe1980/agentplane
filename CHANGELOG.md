# Changelog

Notable changes per release, on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
with two departures, stated here rather than left for a reader to infer.

**Each entry carries a headline**, not a bare category — *Fixed — a rate limit was
retried as if nobody knew when to come back* rather than a bullet under `Fixed`.
The categories are the standard ones; the sentence after the dash is what makes
230 of them scannable.

**Two categories are ours.** `Assurance` is a change to what the project can
*prove* — a test that could not fail, a mutation that stopped killing, a surface
walked adversarially and found sound. `Known` is a limitation shipped
deliberately, with the reason. Neither is a code change and both belong to a
reader deciding whether to depend on this.

What is **not** here: literature reviews, competitor comparisons and citations.
They are how a design got decided, not what a release changed, and a reader who
already depends on a version is owed the second. This file ships inside the
crate, so anything it points at has to be something the reader received.

**Pre-alpha, and versioned accordingly.** The crate *is* published, so `0.x`
bumps carry breaking changes without deprecation cycles — a hard cut is cheaper
than a compatibility shim, and pre-1.0 is the window in which that is an honest
trade rather than a broken promise. Every breaking entry says what to do about
it; [upgrading](https://hupe1980.github.io/agentplane/docs/upgrading/) carries
the ones needing more than a sentence. Every entry is written for somebody who
already depends on a version, which is the one assumption this file may not drop.

**This file carries the reasoning, not just the diff**, and it is the only place
that does: a mechanism's history lives here and nowhere else, because keeping one
fact in two places is the defect this project treats most seriously.
[Status](https://hupe1980.github.io/agentplane/docs/status/) answers what will
move and what is deliberately absent; what *exists* is answered by the
[concepts](https://hupe1980.github.io/agentplane/docs/concepts/) page, the
[API reference](https://docs.rs/agentplane), and the test suite.

Entries for `0.1.0`–`0.9.0` are reconstructed from tags and commit history rather
than written at the time, so they are deliberately terse — inventing more would be
archaeology presented as a record.

## [0.28.0] — 2026-09-05

### Changed — the architecture page is six pages

It had grown to **29,745 words** on one URL: a reader had no way to navigate it,
and a search engine had one page competing for every query the project answers,
which is how a page about everything ranks for nothing. It is now a hub plus five
pages, each with its own title, description and canonical URL:

| Page | What it answers |
|---|---|
| Architecture | the determinism boundary, the module layout, where each mechanism lives |
| The effect protocol | at-most-once outward calls, sagas, transactional groups, stopping a run |
| The journal | what the chain, the signatures and the Merkle log prove — and refuse to |
| Plans, cases and time | authorization graphs, cases, waits, timers, budgets, worklists, batches |
| Models, agents and peers | everything the runtime calls that it does not own |
| Publishing and pinning agents | the manifest as an artifact, and the registry that will not rewrite a version |

The page's own "Testing" section became **How this is proven** — the
specifications, the mutation sweep, and why a green suite is not the argument. It
was the detail behind the landing page's credibility claim and it was buried at
line 3,192 of the longest page on the site; the claim now links to it.

Split by word count with the total asserted before and after, so no paragraph
moved by accident. `tests/guards/docs.rs` gained a check that every published
page is linked from the README — splitting one page into six is exactly how a
page ends up published and unreachable.

### Fixed — the page arguing the project is falsifiable was the part nothing falsified

The landing page's *"Why you should believe any of it"* offers four figures. Three
were wrong: **6** TLA+ specifications against seven in the tree, **18** broken
specs against twenty-six, and **106** code mutations against six hundred and
forty-four. The README's list of specifications named six of the seven, omitting
`EffectGroup` — the transactional tier, which is the hardest claim here to
believe without a proof and therefore the one worth naming.

Both are now counted from the tree at test time rather than restated, so adding a
specification or a mutation moves the page or fails the build.

### Fixed — the table of *every* event listed ten of fourteen

The operations page heads a table *"Every failure P7 exists to surface has its own
event target"*. It omitted `run.unreproducible`, `run.recovered`, `run.replanned`
and `policy.denied` — an integrity finding, a takeover, a plan change, and every
policy refusal. A table headed *every* is an alerting checklist: an operator
builds a dashboard from it once and does not come back, so a short list is not a
smaller table, it is four signals nobody is watching. Checked against
`telemetry::LOUD_EVENTS` now.

Also removed two leaks of internal vocabulary — a page cited invariants by number
("I12", "I2") and linked to a page that never defines them, so a reader following
the link found nothing. Both now state the rule instead.

### Fixed — the operator view had its own rule for what a run's history says

`GET /runs/{run}` matched the last record itself instead of asking the runtime,
and a second copy of a rule is only as strong as its laxest arm. Two of them
were laxer:

- **An `exhausted` conclusion carrying no typed ceiling was reported as an
  ordinary exhaustion**, with the field simply absent. I14 names the operator API
  as one of three surfaces where an exhausted run keeps the exact ceiling
  verdict; the runtime's own reader quarantines that record precisely because
  there is nothing to raise and nothing to act on. Automation asking *which limit
  do I raise* read `null`.
- **An outcome string this build cannot interpret was echoed straight into
  `status`.** The reader beside it fails closed — "a conclusion this build cannot
  interpret is not permission to treat the run as ordinary" — and so does the A2A
  projection. The operator surface was the one that failed open.

There is now one reader, `observed_status`, and idempotent admission, the
operator view and the A2A projection answer from it. The A2A module had already
written the rule down — *"three views of one fact, and three copies of this match
would agree until somebody added a record kind"* — and the native surface was the
copy nobody counted.

### Fixed — a subscription phase this store could not read was answered `Forward`

The third copy of one decoder. The shared-store backend refused an unreadable
phase and the timer store was taught to in 0.21; the redb *event* store still
answered `Forward` for anything it did not recognise, with a comment defending
the totality — while the case id and effect key decoded three lines away already
answered `Corrupt`. One decoder guessed while its neighbours refused.

What the default costs is specific: the phase selects which replay cursor the
delivered event is journaled under, and forward and compensating effects must
never share one. A compensating wait whose phase is misread has its answer filed
on the forward cursor, so that wait is never satisfied and the run waits forever,
while a strict replay meets a record on the forward cursor nothing requested and
quarantines. Both are silent at the moment the column is misread.

### Added — `agentplane.runs.quarantined`, the level behind the quarantine counter

`agentplane.quarantines` is a `Counter`, and its description promised *"this
number only falls when someone acts"* — which no counter can do. It is monotonic
and it lives in the process, so after a restart it reads zero over a backlog of
forty, and a backlog that stopped growing reads exactly like one that was
cleared. The description now says what a counter is; the number it was reaching
for exists.

The gauge is observed from the store, like every other gauge here, through a new
`JournalStore::count_by_outcome` — never from `runs_by_outcome(..).len()`, because
a gauge served from a bounded listing rises, flattens at the page size and reads
as a plateau exactly when the backlog stops being survivable. It counts the same
derived index the listing pages, so the number an operator alerts on and the page
they open from it cannot disagree.

`count_by_outcome` is a required trait method with no default: a default of zero
is a gauge that reports "nothing is wrong" for every store whose author did not
notice, which is the failure the whole instrument exists to remove.

### Known — nothing resolves a quarantine, and the gauge says so

Adding the level made the hole in front of it plain, so it is stated rather than
papered over. The runtime's most serious conclusion is the one an operator cannot
act on: a resume re-reaches the same conclusion, and `request_cancel` against a
quarantined run records the stop, answers `recorded: true`, and is then ignored.
So this gauge only ever rises, and its description says that outright rather than
implying a number that drains.

The missing verb is now a release blocker with its shape written down — including
the two questions that make it a design rather than a change: what a `Landed`
verdict from an offline operator derives its label from, and the fact that
closing a quarantine takes it off the only listing that carries it, so the
finding has to outlive the status first.

### Fixed — a ceiling checked once per member of a ready set was a ceiling multiplied by that set's width

A plan's ready set is dispatched concurrently, and both count-based ceilings
were check-then-act against a figure that moves only when work *finishes*. So a
whole wave asked the same question of the same unmoved number and every branch
was told yes: `Budget::steps(2)` ran three branches of a three-wide fan-out, and
`Budget::effects(2)` performed three concurrent effects. The count-based limits
were documented as the exact ones — the escape hatch offered to anyone who needs
a hard cap rather than the metered ceilings' approximation — so the field where
it mattered most was the field it did not hold in.

Every existing budget test used a linear plan and effects that succeed, which is
why it survived: with a ready set of one there is no wave, and with no failures
there is no second billing path.

Two fixes, one rule — *the check and the deduction are the same act*:

- `Ledger::admit_step` takes what the caller has already admitted in this wave,
  so a ready set is admitted against a running figure rather than a stale one.
- `Ledger::admit_effect` takes the slot in the same lock that checked for it, so
  the window between a verdict and the announcement it authorises is gone.
  `can_admit_effect` is the pure question, for the one caller that asks early and
  dispatches through the ordinary gate afterwards.

An announcement no ceiling gates — a compensating call, a durable wait — takes
its slot through `Ledger::count_effect`. Exempt from the *verdict*, not from the
count: a run must not walk through a ceiling by phrasing its work as an undo,
and a pass replaying the announcement bills one either way.

### Fixed — a replayed run reached a different tally than the run it replays

The central claim of journaled spend is that a replay reaches the same verdict at
the same point. Three arms of the replay loop broke the arithmetic that claim
rests on, and none of them could be seen by an assertion about a run's *status*:

- **A recorded failure was billed twice.** The arm that read it billed the
  recorded figure, and the code deciding what the run did next billed a second
  slot on top. A run that failed an attempt and retried consumed two operations
  live and three on resume — so a run with room to spare concluded `Exhausted`
  against a ceiling its own history never reached, at a point no record contains.
- **A superseded record's figure was dropped.** One attempt can write three
  records: the announcement, the failure carrying what died mid-flight, and a
  probe's verdict carrying what the recovered call reports. The live pass adds
  every figure it is handed; the replay slot took only the last one, so a
  reconciled attempt replayed at a fraction of its cost. `StepCursor::settle`
  now carries the superseded state's spend forward.
- **A reconciliation was a second slot on one path and none on the other.** The
  probe asks about an attempt already admitted and already counted, under the
  same effect key; it now reports its spend without taking a second slot.

Beside them, two announcements that were billed on replay and not live — an
awaited event and a durable sleep — now take their slot where they are
announced; and an **atomic group member**, which was gated against the ceiling
and then counted by neither path, now takes one on both. A ceiling that checks a
write and never counts it is a ceiling a group walks through.

The rule is one sentence, and it is now the one the tests assert: **one
announced attempt costs one slot and every figure its records carry, on the pass
that announces it and on every pass that replays it.** Asserted as a *tally* —
a strict replay's `RunOutcome::consumed` must equal the live run's — because an
outcome-shaped assertion cannot see any of this.

### Fixed — `max_wallclock_secs` had never been enforced

A declared ceiling, refused at zero by both parsers, carried into `Budget`,
compared by the ledger against `Consumed::elapsed_secs` — and nothing anywhere
wrote that field. `Ledger::observe_elapsed` had no caller outside its own unit
test, so elapsed time stayed at zero for the life of every run and the limit
could not fire. A manifest field naming a control the runtime does not apply is
the one release state the invariants refuse outright.

Enforced now, the way the module docs had already argued for: one **journaled**
clock read at each step boundary, taken only by a run that declared the ceiling.
Journaled rather than ambient because a verdict read off the wall is a different
verdict every time you look, and an exhausted run would replay as healthy.

Two consequences worth knowing:

- Elapsed time is the distance between the **extremes** of what a run has read,
  not between the first and last arrival. A ready set is dispatched
  concurrently, so arrival order belongs to the scheduler, and a ceiling that
  depended on it would fire on some passes over one history and not others.
- A step's first effect is that reading when a wall-clock ceiling is declared and
  the skill's own when it is not, so such a history replays under a *raised*
  ceiling and not under a build that removed it. Every other ceiling can be
  changed in either direction between passes; this one can only go up.
- It stops the **next** step. Nothing cancels work in flight — that would abort
  an effect mid-call and manufacture the unknown outcome the protocol exists to
  refuse — so a single step that overruns is not interrupted. What bounds one
  call is the driver's own timeout.

### Added — `spec.budgets.max_parallel_steps`

How many of a plan's ready set may be dispatched at once. Absent, the bound is
the plan's own width, which is the right default for a graph you wrote and the
wrong one for a graph anything else may widen — and until now it was the only
bound there was, in a runtime whose sibling subsystem (webhook delivery) has
bounded its fan-out since 0.19.

It is also what makes the *metered* ceilings' honest statement a bounded one.
Those are checked before an operation and billed after it, so a run overshoots
one by at most an operation's cost **per step in flight**; the documentation said
"at most one operation" and was written when nothing ran two at once. Dispatch
uses `buffered`, not `buffer_unordered`: narrowing a wave must not reorder it.

### Removed — `PlanNode::quorum`; a panel is a subgraph

A field declaring "judge this node's work more than once, from declared angles",
validated for having a subject, covered by the plan digest — and never read by
the executor. A node carrying it ran exactly once.

It is removed rather than implemented, and the project's own rule decides it:
`routed`/`router` are refused as topologies "because this runtime does not
execute that choice, and accepting them would digest prose while behaviour lived
elsewhere". The same applies here twice over. The runtime has no way to hand a
node a *lens*, so there is nothing to execute; and the graph already expresses a
panel exactly — *k* nodes depending on the subject, each declaring `verifies`,
and a terminal node depending on all of them that decides with `Quorum`. A field
would be a second spelling of a shape the plan already has.

`core::Quorum` is unchanged and is what the aggregator tallies with. Its
refusals are the load-bearing part and they bind a deserialized panel too:
distinct lenses, majority thresholds, and no resolution for a split.

### Added — `RuntimeBuilder::require_verifier()`

`Contract::require_verifier` existed, `plan::validate` honoured it, and
`PlanNode::verifies` was documented as being "named so the contract can require
one" — and the runtime built its contract from its registered capabilities and
nothing else, so the requirement could be reached only by a caller validating
its own graph. That left the gap exactly where it matters: a **replanner's successor** is
a plan proposed mid-run by a component the embedder did not write, and it was
admitted against a weaker contract than the plan it replaces. A control that
holds for the first plan and not for its replacement is a control a replan
removes.

`Contract::max_steps` stays a validator option and says so: a run's step ceiling
is `Budget::max_steps`, which counts what actually executes across every version
of the plan, and two ceilings of one name are two answers to one question.

### Changed — `RunOutcome::spend` is now `RunOutcome::consumed`

The whole tally — steps, effects, spend, elapsed, refusals — rather than only the
money. It is the observable the parity property above is asserted through, and
independently it is the answer to the question an operator asks after a run stops
short: *which ceiling, and how close was it?* `RunOutcome::spend()` remains as an
accessor for the metered half, so `out.spend.tokens` becomes `out.spend().tokens`.

`Spend::is_zero` is gone; `Spend::is_free` (and `is_free_ref`, for
`skip_serializing_if`) was the same predicate under a second name.

## [0.27.0] — 2026-09-03

### Fixed — a concurrent publish could overwrite a published version on Postgres

The registry's immutability rule was enforced by a `SELECT … FOR UPDATE`
followed by an upsert. A row lock cannot serialise the race that matters — two
publishes of *different* content both finding **no** row — so both decided to
insert, and the `ON CONFLICT DO UPDATE` let whichever landed second silently
replace the first: the exact outcome the primary key exists to refuse, on the
backend the rule is actually about. Now a transaction-scoped advisory lock on
the key is taken before the read, the insert is a plain insert (an upsert would
turn any future hole in that reasoning into a silent overwrite), and adopting an
attestation is a column update. Pinned by a twenty-round concurrent publish
against a real server: exactly one lands, the other is `Immutable`, and what
resolves is the winner byte for byte.

### Changed — the mutation sweep is ordered by what it builds

A mutation's cost is dominated by the feature set its check runs under: cargo
keeps one set of compiled artifacts per feature combination, so moving between
two rebuilds the library *and every dependency* for the one being moved to.
This table holds thirteen combinations, scattered through it because it is
authored by subject — so a sweep in authoring order switched combination about
two thirds of the time, and a shard that walked all thirteen paid for thirteen
dependency graphs in time and in the disk they all stay on.

`--list` now emits the table grouped by that feature set, and `--shard k/n`
takes a contiguous slice of the grouped order rather than a round-robin one, so
a shard walks one to six combinations instead of all thirteen while the slices
stay equal in length.

What that buys is stated narrowly, because the obvious claim does not survive
measurement: on a pipeline whose dependency artifacts are already cached the
per-mutation cost is the library rebuild and the test-binary relink, which
grouping does not change. What it does change is how many dependency graphs a
shard builds and keeps on disk — thirteen combinations of this crate's graph is
about as much space as a runner has — and it makes a sweep against a cold
target coherent rather than thrashing.

The wall-clock improvement comes from the matrix, six shards to ten: fewer
mutations each, measured at fourteen minutes for a shard of sixty-four against
the twenty-two minutes a shard of a hundred and six took.

The order comes from the same `_locate` that `verify` uses to build its cargo
command, so a mutation cannot be grouped under a build it does not use, and
`--check` now asserts that the slices partition the table for every split CI
might pick. An off-by-one there would leave a mutation in no shard at all —
and every shard would still pass, reporting that every guarantee is
falsifiable.

### Fixed — the local gate did not check the docs site

`just ci` carries the claim that it is the same set of commands CI runs, so a
check cannot drift between a contributor's machine and the pipeline. The site's
link check was not in it — it lived only in the pages workflow — so a
documentation change could pass the gate, land, and fail CI on a broken
internal anchor, which is what happened to a link into a new heading whose
generated id includes the slugified name of its emoji. `just ci` now runs
`site-check`, and the CI job installs the pinned generator to match. The check
skips external links deliberately: an anchor is a property of this repository,
an external link is a property of somebody else's server.

Headings that link targets point at carry an explicit `{#id}`, which is what
the rest of the docs already do — an emoji in a heading otherwise puts its
Unicode name in the anchor.

### Changed — dependencies updated; the MCP fixtures state their version

`cargo update` (rmcp 3.1.4 → 3.2.0, a2a-server-lf 0.4.3, hyper 1.11.1, and
the usual small bumps). rmcp 3.2 moved its `ProtocolVersion::LATEST` back to
2025-11-25 to keep `initialize` working on legacy dialects, and the wire
fixtures here advertised `ProtocolVersion::default()` — so the test that pins
the negotiated dialect to 2026-07-28 was checking the dependency's constant
against itself, and a dependency bump downgraded every handshake in the suite
until `InputRequired` results became illegal. The fixture servers now state
`V_2026_07_28`, the version the spec text names.

The larger finding was in `src/`: rmcp 3.2 made `initialize` legacy-only, as
the spec's `2026-07-28` revision requires — that revision replaced the
handshake with `server/discover` and per-request metadata — so every
`host_info().serve(transport)` in the tree negotiated **down** to 2025-11-25,
silently: `tools/call` kept working, the tasks extension and structured results
this crate is written against simply never appeared, and nothing said why.
Three call sites each choosing a lifecycle were three chances to make that
mistake. **New:** `McpClient::connect(server, transport, destination)` owns
it — `server/discover` preferring 2026-07-28, `initialize` at 2025-11-25 when
the server is legacy — and the binary, the example and the tests go through
it. `McpClient::new` remains for an embedder whose transport is already
running.

### Fixed — a halt mid-batch failed every remaining item, permanently

`run_item` classified every admission error — a halt, a tenant ceiling, a store
outage — as a terminal `Failed` item and recorded it in the batch store. So the
emergency stop, thrown mid-batch, wrote *failed* over every item behind it; when
the stop lifted, the next pass read those outcomes as terminal and skipped them
forever. A stop turned into loss by bookkeeping. An admission that never
happened is no outcome of the item: the pass now returns the refusal as its
error, the reservation stays outcome-less, and the next pass admits the item as
*reserved, never finished*. A **run** that fails still does not stop the batch.

### Fixed — a halt reached peers as back-pressure

The A2A server answered every quota refusal with `QUOTA_EXHAUSTED` and *retry
later* — a halt included, so every compliant peer backed off and retried the
one refusal that means somebody is dealing with an incident. A halt now has its
own code (`-32030`) and `ErrorInfo` reason (`HALTED`), identified by the pair
and never the numeral like its sibling, with a fixed message that carries none
of the operator's words. The client classifies the marked pair as a refusal
whose detail says *do not retry*; a bare `-32030` from a foreign server stays an
unknown fault. One function maps all three admission sites, because a halt that
reached one as a ceiling would be a peer told *retry* by `message/send` and
*stop* by `message/stream`.

### Fixed — retention skipped every case on a sealed plane with no blob store

`retain` returned before erasing anything when no blob store was wired. A plane
that seals its journal with a key ring and stores no blobs is an ordinary
shape, and for it the erasure that reaches every copy is the **key
destruction** — so the pass left the one act that matters undone for want of a
lesser act with nowhere to land, while reporting a clean count. `erase_case`
now takes `Option<&dyn BlobStore>`: with no store the linked digests are left
and the key scope is destroyed; on a sealed plane the drill then reads the
bytes as *erased by design* through the key. The pass names the missing
tombstones in `not_erasable` and carries on. **Breaking:** `erase_case`'s first
argument is an `Option`.

### Fixed — a preview's whole answer went into the worklist row

A dry run listing the four thousand records it would touch has done its job by
the first screenful; the rest was a task nobody could open. The evidence is
bounded at `PREVIEW_EVIDENCE_BYTES` (64 KiB) and the bound is **stated** on
the row — total size and a digest of the whole answer — because a silent
truncation is a bounded result shaped exactly like a complete one. The
journaled effect output still holds every byte, which is what the digest
matches against.

### Fixed — a halt was displayed as a quota

`RuntimeError::QuotaExceeded` prefixed its message with `quota:`, so an
operator refused by the emergency stop read `quota: the whole tenant is
halted …` — a stop reported as back-pressure, which is the confusion
`QuotaError::Halted` exists to prevent. The variant is transparent now; the
inner error already says which of the two it is. `examples/approved_call`
also printed its section headers after the runs they describe, filing a tool's
own output line under the previous section.

### Changed — `agentplane retain` lists; it does not pretend to erase

The shipped binary wires no blob store and no key ring — a redb file is a
journal and a case layer — so a verb that walked the cases, erased nothing and
printed `erased: 0` beside a clean exit code was a control that read as having
run. The verb now answers the half it can, through the same selection rule
`Runtime::retain` uses (`retention::plan`, so a listing and an erasure cannot
disagree about which cases), and refuses the other half by name. **Breaking:**
`--dry-run` is required.

An external evaluation against a governance control catalogue — reproduced with
seven runnable demos — produced fourteen findings. All fourteen are addressed
below. Where a finding's premise turned out to be wrong, the entry says so
rather than shipping a control that answers the wrong question.

### Fixed — a policy denial names the rule, not the request

`StepError::Denied` already formats the action and the resource, and the Cedar
adapter formatted them again, so an auditor read
`policy denied 'effect:perform' on 'tool.call': 'effect:perform' on 'tool.call'
refused by policy1` — half the line spent saying the same thing twice. The
adapter's reason is now the half the wrapper cannot know: `refused by
betragsgrenze-5000-eur`. `DenyAll` and the default-deny message follow the same
rule.

`PolicyDecision::Deny`'s documentation now states the contract, because it is
one a third-party engine has to follow too.

### Fixed — Cedar denials name the rule, not `policy1`

`PolicySet::from_str` assigns positional ids, so a forty-rule set produced forty
denials that each named a number — the outcome the required reason exists to
prevent. Cedar treats `@id` as an ordinary annotation and does **not** adopt it
as the `PolicyId`, so the adapter now reads it explicitly and prefers it:

```cedar
@id("betragsgrenze-5000-eur")
forbid (principal, action == Action::"effect:perform", resource)
when { context.args.amount_eur > 5000 };
```

Two rules answering to one name are refused at construction
(`CedarError::AmbiguousRuleName`), including the case where one rule's `@id`
collides with another's generated id — a name that reads like an answer and
points at the wrong rule is worse than a number that points at the right one.

**Breaking:** `EVALUATOR_SEMANTICS` is now `agentplane-adapter/3`, so every
policy bundle digest moves. An open run resumed across the change presents a
different bundle and is refused, which is the drift check working. Pre-alpha:
re-admit rather than migrate.

### Fixed — `max_denials` is declarable in a manifest

`Budget::max_denials` is named in the security model as the control that bounds
the one bit a uniform refusal cannot hide — and `manifest::Budgets` did not
expose it, so the declarative tier, the one aimed at reviewers rather than Rust
authors, could not bound the policy-probing side channel at all. It is now
`spec.budgets.max_denials`. `0` is accepted, like `max_replans`: it is counted
after the refusal, so it means *the first refusal ends the run*.

### Fixed — a sink argument mismatch says where the two values differ

The refusal said only that the bound value and the labelled one were not the
same, leaving the reader with two JSON documents and a diff to do by eye — and
the commonest case is the least visible: a payload still at its `null` default
beside a labelled object. It now names the first differing RFC 6901 pointer and
both canonical digests. Neither value is printed: the labelled one is precisely
the data these gates exist to keep out of a log.

**Breaking:** `PolicyError::SinkArgumentsMismatch` gains `at`, `bound` and
`sent`. New: `core::canon::first_difference`.

### Added — `metadata.annotations`

A governance catalogue asks a registry entry for business owner, technical
owner, risk class and a ticket. `deny_unknown_fields` refused all four, and the
consequence was not that deployments did without — it was a second registry keyed
on `name + version + digest`, drifting from the file. Two sources of truth about
one agent is the defect this format exists to remove, arriving by the door
marked *strictness*.

One opaque map closes it without weakening the rule, because the map is intent
by construction: the runtime never reads it, the digest covers it, and keys are
namespaced in Kubernetes' own grammar — a DNS-subdomain prefix, a name of at
most 63 characters, 256 KiB in all — so an entry carries into a cluster object
unchanged. The prefix is required where Kubernetes makes it optional, because an
unqualified key is exactly the name a future first-class field would want; the
reserved `agentplane.hupe1980.github.io/` prefix and a blank value are refused
too. Who reads them is Kubernetes' own line between API server and
controllers: the runtime never acts on one, as the API server never does, while
the embedder's wiring — a deploy pipeline, a cluster controller — may, and the
map is public for exactly that.

### Added — an emergency stop that names what it stops

**Breaking:** `Runtime::set_halt` and `QuotaStore::set_halt` take a `HaltScope`;
`Runtime::halted`/`QuotaStore::halted` are replaced by `halts()`, which returns
every standing halt.

A tenant-wide switch is the right answer when the plane is the incident and the
wrong one at three in the morning when agent 12 of 28 is misbehaving — and
hosting several agents is what a multi-document manifest and `A2aServer::hosting`
are for. The options were stop all 28 or ship a policy change; neither is an
emergency stop. `HaltScope::Agent` stops every revision of one declared name,
and `HaltScope::Revision` stops one exact reviewed digest, so a fix published as
a new version runs while the broken one stays stopped.

Scopes are **independent rows**, not one flag the last writer wins: an incident
that widens and then partly resolves is the ordinary shape, and lifting a narrow
stop must not lift the broad one under it. Where several halts cover a run the
narrowest is the reason reported.

New CLI verbs: `agentplane halt --scope ... --reason ...` / `--lift`, and
`agentplane halts`. `QuotaStore::halts` must report a scope it cannot parse as
`StoreError::Corrupt` rather than skipping it — a halt an instance silently
ignores is indistinguishable, from outside, from one that was lifted.

**Breaking (schema):** `quota_halted` is keyed `(tenant, scope)` on both
backends. Recreate rather than migrate.

### Added — a durable manifest registry, and an enumerable inventory

`MemoryRegistry` proves the rules and dies with the process, so *which agents
does this organisation run* — the first question a governance function asks —
had no answer. Both shipped stores now implement `Registry`, tenant-scoped like
every other table, and `Registry::names()` is the inventory.

The rules are shared rather than reimplemented: `manifest::registry` exposes
`decide_publish`, `attest_manifest`, `check_attestation` and `reparse`, and each
backend only *performs* the decision. Three hand-written copies of "may this
replace what is there" are three chances to get it subtly different, and the one
that is wrong is whichever nobody tested. `testkit::conformance_registry` holds
all three to one contract.

Immutability is a claim about a race as much as about a rule, so the read, the
decision and the write are one transaction on both backends — `FOR UPDATE` on
Postgres, redb's single writer otherwise.

**Breaking:** `Registry` gains `names()`.

### Added — a retention pass, and an honest account of what it cannot reach

`erase_case` and `erase_run` erase one unit; nothing walked them on a window, so
retention was something each deployment implemented once in Rust and the
declarative tier could not implement at all. `Runtime::retain(older_than, at,
reason)` and `agentplane retain --older-than-days N --reason ... [--dry-run]`
erase every **closed** case opened before the window.

Every pass returns `not_erasable` beside its count, and that list is the half
that matters: without a key ring, blob tombstones cover the live store only and
journal payloads stay verbatim. A number with no coverage statement beside it is
how a deployment comes to believe an erasure obligation is discharged.

### Added — a plane can bound what it writes down

`spec.security.max_sensitivity_journaled` was read only from a manifest, so a
plane of hand-written skills — every plane before the declarative tier and many
after it — had no way to state the decision at all, and the default is the
unerasable one. `RuntimeBuilder::max_sensitivity_journaled` is the twin,
enforced at the same gate; where both are present the stricter binds.

An enforcement point rather than a build-time warning, because a lint that let
the run proceed would be the advisory control this project refuses everywhere
else.

### Added — a reviewer can be shown consequences, not only the instruction

`archive(older_than: "2024-01-01")` shows an instruction and not the four
thousand records it will touch. The runtime cannot compute that preview — it
needs the tool's own dry run — but a grant can now name one:

```yaml
- ref: "tool://archive/purge"
  requires_approval: true
  preview: "tool://archive/purge_preview"
```

The preview is dispatched with the same arguments before the task opens and its
answer lands in `Justification.evidence`: an ordinary effect, journaled, gated,
metered and replayed rather than repeated. A `preview` without
`requires_approval`, one naming a grant declared `mutates: true`, one naming an
ungranted tool, and one naming the grant itself are each refused at parse. If the
preview fails the task opens anyway and says so — refusing the call because its
preview was unavailable would turn a read-only convenience into a second thing
that can stop a payment.

### Added — the egress allowlist reaches the tool path

`core::Egress` covered the model drivers, peers, push and media — every outbound
path except the most-used one. A deployment wiring `.tools(catalog, my_client)`
got no egress control and no warning, while the security model read as though the
rule covered everything.

The split is the one the rest of the crate makes: **the client owns the
connection, the plane owns the destination.** `RuntimeBuilder::egress` is
consulted before the effect exists, so nothing leaves, nothing is journaled and
nothing is metered.

**Breaking:** `ToolClient` gains `destination(&ToolId) -> Destination`, with no
default — a default of `Local` would let a remote transport answer *reaches
nobody* by saying nothing, which is the fail-open `JournalStore::is_shared`
avoids the same way. `McpClient::new` takes a `Destination`, because this crate
never dereferences an MCP URL and an initialised `RunningService` does not
disclose the host it dialled. `ToolCall::prepare` takes `Option<&Egress>`.

### Added — `--drill-every`, and the observability last mile

`Runtime::drill` could only be reached by writing Rust, so the tier that is a
YAML file could not rehearse its own recovery — and a control that exists and is
never exercised is one an audit cannot count. `agentplane serve --drill-every
86400` runs it on a timer beside `--sweep-every`, logging a finding at `error`
with the report attached.

`examples/observability.rs` closes the gap between *instrumented* and
*monitored*: a real subscriber that keeps replays out of latency, shows that
gauges exist only once something queries the stores, and keys an alert on
`SweepReport::needs_attention()`. No exporter is linked — the OTLP wiring is in
the example's own docs, verbatim.

### Fixed — the replay marking, as documented

`runtime::telemetry`'s module docs said *every effect span carries
`EFFECT_REPLAYED`*, which understated what actually happens and misled a bridge
author in the unsafe direction: a replayed effect opens **no span at all**, and
emits a `debug` event on the same target instead. A span-derived histogram is
therefore clean by construction; what is not safe is keying on the *target* and
treating everything on it as a span.

### Fixed — the security model implied an egress coverage it did not have

The page's framing — *one rule, shared by …* — read as exhaustive, and an
evaluator concluded from it that a remote MCP server was a crate-owned URL
dereference outside `netguard`. It is not: this crate never dereferences an MCP
URL. `McpClient::new` takes an already-initialised `rmcp` service, the
transport is dialled by the embedder, and the `mcp-http` feature enables an
`rmcp` transport rather than adding a URL this crate holds — so there is
nothing for `netguard` to guard, which is exactly why `Destination` is supplied
by the wiring rather than inferred. That reasoning existed nowhere a reader
could find it. The security model now carries a table of every outbound path,
who checks it, and how the host is known, with Bedrock's *nobody* stated in the
same table rather than in a footnote.

### Added — the status page states the freeze conditions

*When does the journal format freeze* was the one question an adopter of a
regulated deployment could not answer from the docs, and the page that should
have carried it said only *will change*. It now carries the freeze as eight
checkable conditions, one met, and the interim position stated plainly: treat
the export as the long-term artifact and the store as disposable — `export`,
`verify` and `restore` already work, and an export taken today is verifiable
today by a party who has never run this crate. No date, because inventing one
would be the claim the page exists to avoid.

## [0.26.0] — 2026-09-01

### Changed — **breaking**: conclusions are typed and no longer called seals

`RecordKind::RunSealed` is now `RunConcluded`. The old name was false for
`failed` and `exhausted`: both append a conclusion but deliberately leave the
journal open for resume. That ambiguity caused the HTTP run view to report an
open failed run as `sealed: true`; it now derives the field from actual Merkle
inclusion.

An exhausted conclusion also carries its structured `BudgetExceeded` verdict.
Previously idempotent redelivery reconstructed every exhausted run as
`RunStatus::Failed(reason)`, losing the resumable state and forcing callers to
parse prose. Existing pre-freeze journals use the old variant and must be
recreated; there is intentionally no compatibility alias or migration.

### Fixed — quota accounting keeps one identity across a live pass

Admission checked spend in the current billing period and settlement computed
the period again. A run crossing midnight or month-end could therefore be
authorized against the old ledger and charged to the new one. The period is now
captured once per live pass and carried to settlement; a later resume starts a
new pass in its resume period, while strict replay remains unbilled.

A wired quota store also records active runs when every ceiling is `None`.
Previously the runtime returned after the halt check and skipped reservation,
so `running()` reported zero during real work and adding a limit started from a
falsely empty ledger.

Settlement itself is no longer two best-effort writes. `QuotaPassStarted` is
journaled before effects; `QuotaStore::settle(QuotaSettlement)` stores an exact
`(run, epoch)` receipt, accrues spend, and releases the admission slot in one
backend transaction. Identical retries are no-ops and changed retries are
corruption. Physical sealing and lease release happen only after acknowledgement;
on failure the expired owned lease drives the existing recovery sweep, which
derives the pass from journal evidence and retries without double charging.
This is a breaking store and journal format change: `QuotaStore::accrue` is
removed, PostgreSQL/redb gain settlement receipts, `RunConcluded` gains
`live_spend`, and pre-freeze stores must be recreated.

`QuotaStore`, `TimerStore`, `BatchStore`, and `AuthorityStore` also gain a
required `tenant()` accessor, and `try_build` refuses any handle scoped
differently from the plane. Previously these tenant-keyed operational stores
were omitted from the startup check, so an `acme` plane could run correctly
while reserving and charging `globex`'s ledger, claiming its timers, settling
its batch items, or drawing its standing authority.

## [0.25.0] — 2026-08-30

An audit round over the identity tier, asking of I6 — *audience-bound,
time-bounded, depth-bounded, monotonically attenuating; ambient credentials
prohibited* — which of its five clauses the code actually enforced. Two of
them, and the fifth was violated by the served surface.

### Changed — **breaking**: a served run acts as its caller, never as the plane

The A2A server admitted every peer's run under the chain the plane was built
with (`RuntimeBuilder::acting_as`). The message named the peer, the sink
labels named the peer, and the `IdentityBound` record named the plane's
operator — for every caller. That is an ambient credential by I6's own
definition, and the confused deputy the field now audits shipping frameworks
for: a peer whose own credential permits `billing.*` was gated by a chain
holding everything. A chain is now **per run**. `Caller` carries
`acting_as`, produced by the `Authenticator` like the actor and the tenant
(never from a body — the governance extension's chain remains a claim), and
the server threads it into admission through the new `RunTerms::acting_as`,
where it is what the plan is checked against, what the policy context
carries, and what the journal records. The plane's own chain covers exactly
the runs the embedder starts in-process; a caller presenting no chain still
acts under it. For `agentplane serve`, a token-file entry with `scope`
becomes that caller's chain, rooted at the actor and bound to the entry's
tenant. Pinned by `AServedRunActsAsThePlane` and the two orderings of
"caller's chain over the plane's" at the gate and at the record.

The chain then has to reach the *steps*, and it did not: `StepCtx` carried
the plane's chain into every `effect:perform` and `release` policy request
and into `commission`'s depth, so a run admitted for a caller was judged
per effect as the operator — and a *resumed* run of any kind acted under
whatever chain the plane was configured with at resume time rather than the
one its journal records. Both are now the run's: live from admission, on
replay from `IdentityBound` (re-checked structurally, never re-verified),
pinned by `AStepActsAsThePlane` and `AResumedRunActsAsThePlane`. And it
travels across `cx.commission`: a sub-run is admitted under the orderer's
chain plus one link naming the commissioned agent (`agent/<capability>`,
scope, expiry and audience inherited), the in-plane twin of the extra link a
peer call already sends outward — the sibling divergence this crate's
audits keep finding, closed on the hand-off that has no network to notice
it. `ACommissionDropsTheChain` pins it.

The outbound leg had the mirror-image gap: `PeerCall::prepare` takes the
caller's chain, and a skill had no way to read the run's — `StepCtx` exposed
no accessor — so the only chain a peer call could carry was one the skill
held ambiently. `StepCtx::acting_as()` returns the chain the run was admitted
under, and the peers module now says that is the one to extend.

`RunTerms` is public and is the general form of the fourteen `run_*`/`spawn_*`
methods — `in_case`, `correlated`, `once`, `acting_as`, composed —
consumed by `run_under`, `spawn_under` and `run_plan_under`. The named
methods stay as the conveniences they were; the axes multiply, and a method
per combination would not.

### Added — audience and validity attenuate, and bind at admission

`Principal` carried an id and a scope. I6 requires four bounds; the type
enforced two (scope, depth). `Principal::audience` and `Principal::not_after`
are the other two, and they attenuate exactly as scope does — a delegate may
not outlive its delegator (`ValidityWidened`) or name a plane the chain was
not issued for (`AudienceWidened`), checked at every hop and therefore at
every deserialization. The clocked half lives in one place:
`Delegation::admissible(plane, at)` runs at admission and nowhere else,
refusing `Expired` and `WrongAudience` as `RuntimeError::Delegation` — its
own variant, because "obtain a fresh credential" and "this rule says no"
call for different responses. Replay never asks it: a run admitted under a
live chain is history, and the recorded chain is re-checked structurally
only. Both bounds are enforced where declared and only there — a chain
naming neither acts anywhere, indefinitely — so a credential that carries
them is held to them and one that does not is not silently widened into a
wildcard. Anchors `ValidityCanWiden`, `AudienceCanWiden`,
`AnExpiredChainIsAdmitted`, `AChainForAnotherPlaneIsAdmitted`,
`NoAdmissionBoundsCheck`.

### Added — peers are wired on the plane, not carried by a skill

The outbound A2A path was a complete effect surface with no way in: no
builder method wired a registry or client, no `StepCtx` method reached one,
no manifest grant could name a peer, and no CLI flag could point at one — a
skill had to construct `PeerCall::prepare(&registry, client, &chain, ..)`
from state it carried itself, chain included. `RuntimeBuilder::peers(registry,
client)` wires them once; `StepCtx::call_peer(peer, capability, &payload)`
extends the run's chain by one link and dispatches through the sink gate;
`peer_task` and `cancel_peer_task` cover the task lifecycle. A manifest grants
a peer's capability as `tool://<peer>/<capability>` — the peer's registry id
is its server name, so the reviewed document reads as it does for any tool,
and the four things a server name can be (a transport, typed tools, `agent`,
a peer) are settled at build with a name that could be two of them refused.
The grant governs the hop: `PeerCall::governed_by` takes its protected
fields, ceiling and `mutates`, the answer is labelled with the grant's
reference so a source rule can name it, and a governed skill calling a peer
its manifest never listed is refused like an ungranted tool. Build refuses a
grant outside the peer's registry scope and a peer grant on a specialist; a
capability outside the grant is `PeerError::NotGranted` and never leaves.
`PeerRouter` reaches several peers by id, and `agentplane run|serve|replay
--peer NAME=URL` wires one with its token read from
`AGENTPLANE_PEER_TOKEN_<NAME>` (the `:full` image now carries `a2a`).
Eight anchors, `APeerCallSkipsTheGrantScope` through
`APeerNamedLikeAToolServerBuilds`; the `peer_call` example runs both planes
in one process.

### Removed — `DelegationScheme`

A public seam with no caller: the runtime never invoked it, so implementing
it verified nothing (shape 29). The seam that turns a credential into a chain
is the `Authenticator`, which already produces every other fact about a
caller and now produces this one.

## [0.24.0] — 2026-08-28

An audit round over the examples and the developer surface — a runnable
example is a claim the crate makes about itself, and one was making a false
one — followed by a deep pass over the interop tier: the model-provider seam,
MCP, and A2A, checked against the released specs and the ecosystem's
reference implementations. A further pass audited the information-flow core
itself — trust, taint, and typed release — against CaMeL, FIDES, and the
2026 attack literature.

### Changed — **breaking**: release marks ride the value, never the label

The information-flow audit's one structural finding. A destination-scoped
release mark covers exactly the value a release was granted over; a label
joins into every value derived from it. Storing marks *inside* `Label` made
"a join must drop or rebase marks" a convention each call site had to
remember — `zip`, `object` and `array` remembered, and the site that folds
conversation history into an outbound value did not, unioning marks granted
over other values. No reachable path could exploit it today (every effect
boundary rebuilds labels fresh, and memory items rebuild theirs from stored
trust and provenance), but an invariant held by call-site memory is the
defect this crate refuses everywhere else, so it is now held by the type:
`Label` is a pure provenance/trust/sensitivity join-semilattice, marks live
on `Tainted` (read them with `release_marks()`), and only the operations
that can prove value lineage — projection, assembly, transform — move one.
A bare label, read from anything and joined anywhere, structurally cannot
transport a release; a mutation reintroducing the carry is pinned
(`ADependencyJoinCarriesAReleaseAcrossValues`). The `Released` journal
record consequently drops `result_label`/`result_field_labels`: the marks a
release attaches are fully determined by the recorded `release`, and a
second spelling of one decision is free to drift from the rule that derives
it.

The join laws themselves are now a checked model rather than three sampled
assertions: the label domain is finite, so idempotence, commutativity,
associativity, identity and the upper-bound property are verified by
exhaustive quantification over the whole domain, and the mark algebra by
its round-trip law (rebased into an assembly, projected back out, the
original mark returns). This discharges the algebraic half of the required
field-level information-flow model in-tree; the sink-gate protocol under
concurrent replay stays on the formal-model list, where a state-space
search actually earns its cost.

### Added — a decision's amendment is the call, not advice

The information-flow audit's second find, and an I12 violation hiding on the
oversight surface: `Decision::amendment` flowed from the HTTP decide endpoint
into the stored decision, was documented on the operations page — and nothing
in the runtime ever read it. A reviewer answering "approved, with these
arguments" was recorded as if their answer governed while the model's
original arguments ran.

On an approved call task the amendment now **is** the call, in both
declarative tiers. The substitute is a different value with a different
author, and its label says so: **trusted** — the decision channel is
authenticated, actor-attributed and bound to one call, the authority basis
run input and `release` already rest on, while the reviewer's free-text
`reason` stays untrusted and out of the model's context — with provenance
`task:agent.approve_call` alone and the original arguments' sensitivity, so
an edit can never declassify what the reviewer was shown. Every gate then
runs on the substitute: the tool's declared schema at the decision, menus,
ceilings and field rules at dispatch. Two consequences are pinned by tests
rather than prose: an approval *without* an amendment still releases nothing
(the model's arguments keep the model's label, so a field demanding a
trusted author refuses a waved-through value), and a source-constrained
field admits a reviewer's value only where the operator listed
`task:agent.approve_call` in `allowed_sources` — the feature is a channel
the disciplines judge, not a bypass around them. Mutation anchors
`AReviewersAmendmentIsAdvisory` and
`AnAmendmentIsAsUntrustedAsTheValueItReplaces` hold both halves.

This is the approve-with-edit gesture the framework survey found in every
strong oversight API (LangChain's `edit` decision, Pydantic AI's
`ToolApproved(override_args=…)`, Microsoft's approval responses) — landed
here with the two properties none of them state: a label that records whose
value ran, and field disciplines that still judge it. The residue is the one
every human-in-the-loop control carries: a reviewer can be talked into
typing the attacker's value, and the journal's actor attribution is the
accountability for that, not a prevention.

### Added — `one_of`: the declarative fragment of release

The question this answers: should `cx.release` — today a coded-skill API —
also be expressible in the manifest, so declarative agents get the CaMeL
pattern? The research (classical declassification theory, CaMeL and its
design-patterns follow-up, FIDES, CXI, APPA, and the policy-compiler line)
converges on a two-layer split no surveyed system deviates from:
declarations name the *bounds*; a trusted per-instance act picks the value.
A standing manifest `release:` verb would be a self-authorized
declassification whose predicate an attacker-chosen value can satisfy — the
active attacker then decides what is disclosed, the exact failure robust
declassification names, and the classical laundering results show declared
predicates compose across invocations into total disclosure. So release
stays coded, evidence-bearing, policy-judged per instance.

What *is* sound as a standing declaration is the fragment where review
semantics are total: a closed value set, every entry approved by the
reviewer, so an untrusted influence choosing among them discloses only the
choice. `ProtectedField` gained exactly that — `one_of`, a fourth discipline
beside trust, provenance and sensitivity, conjoined with them rather than
substituting (an allowed source answering an unlisted value is refused).
Matching is exact structural equality; a menu counts as an authority rule
for the mutating-grant check, so a menu-only grant is the flagship
declarative select-from-a-menu configuration; the menu is digest-covered and
flows into the published JSON schema. Deliberately inexpressible: patterns
and formats (a regex admits a language nobody enumerated), and numeric
ranges — not for soundness but because JSON number equality across integer
and double representations is the ±2⁵³ hazard the card-signing work already
met. The residual is stated where operators read: the attacker picks
*which* entry, so a menu belongs only where every entry is acceptable
whichever is chosen. For values no list can hold, the two-layer form is
already expressible end to end — bind the field's `allowed_sources` to a
coded validator agent and let it canonicalise, validate and release.

### Fixed — Bedrock authenticates every way Bedrock authenticates

An audit of the driver against AWS's full auth surface found one gap:
`aws-config` is depended on with `default-features = false` (the default set
drags the legacy TLS stack), and the hand-picked feature list predated the
`aws login` console-session flow — so a `login_session` profile failed to
resolve with a `MissingFeature` error while every other chain member worked.
The `credentials-login` feature is now enabled; the rest of the surface was
verified already covered: SSO and `credential_process` (features this crate
enables explicitly), assume-role, web identity, container and IMDSv2 roles
(never feature-gated), and Bedrock API keys — the SDK reads
`AWS_BEARER_TOKEN_BEDROCK` on the `Client::new(&sdk_config)` path both
`from_env` constructors use, switching the client to HTTP bearer auth. The
driver docs now state the coverage, including the two nuances worth knowing:
the env key overrides SigV4 for the whole client, and the SDK reads it from
the environment only — a programmatic key goes through
`Config::builder().bearer_token(..)` and `from_client`. Out of scope by
design: the Anthropic-native and OpenAI-compatible Bedrock routes (different
endpoints entirely — this driver is the Converse API) and bidirectional
streaming (SigV4-only, unused here).

### Fixed — the instruction slot is singular by enforcement

Every driver accepts a `messages`/`input` turn list and passes it to the wire
verbatim, and providers now accept instruction roles *inside* that list —
`system` on every chat wire, `developer` on OpenAI's, mid-thread `system` on
current Anthropic models. That made each turn a potential second instruction
slot: the one real slot, the top-level `system` key, is a protected field an
untrusted value cannot fill, while a `{"role": "system", ...}` element placed
as a turn would be obeyed as a directive with the gate seeing ordinary
content. Refused now, before dispatch, at the effect boundary and in every
driver — the same double enforcement provider-side media URLs get, because
the `ModelProvider` trait is public and a custom driver deserves the same
floor. The scan is deliberately shallow (only the direct elements of the
conversation positions a driver hands to the wire), so data that merely
contains a `role` field stays data.

### Added — `PeerTaskCancel`: the client half of the A2A task lifecycle

The client could create work at a peer (`SendMessage`) and poll it
(`GetTask`), and a run that was itself cancelled had no way to propagate the
stop — the cancellation ended at this plane's edge while the peer kept
spending on an answer nobody would read. `A2aClient` now speaks `CancelTask`,
`PeerClient` grew the verb (default refusal, like task lookup), and
`PeerTaskCancel` is the journaled effect, prepared under the same grant and
audience-bound credential as the call that created the task. It mutates and
still declares `Recovery::Retry`, and the license for that pairing is the
protocol's own construction: a repeat of a cancel that landed meets
`TaskNotCancelable`, a clean pre-action refusal, never a second act. The
MCP side has had this symmetry (`McpTaskCancel`) all along; the wire test
drives the full loop — create a suspending task through this plane's own
server, cancel it through the effect, observe `CANCELED` by polling, and
confirm the repeat is refused.

### Fixed — OpenAI commentary narration stays out of the answer

Responses now marks the model's on-the-way narration `phase: "commentary"`
(typically the preamble beside a tool call). Concatenated into
`Completion::text` it polluted the answer, and on a schema-bearing final turn
the preamble broke the JSON parse of an otherwise valid answer — a metered
`Unusable` for a completion the provider delivered intact. Commentary is now
excluded from the canonical text on both the buffered and streaming paths
(they share the one parser), and nothing is lost: the continuation carries
every output item verbatim, and a live observer still streams the deltas.

### Fixed — the A2A client can name a skill on a multi-skill plane

This crate's own server dispatches on `message.metadata.skill` — named,
never inferred, and advertised on the card as a declared extension — while
its own client carried the capability only inside its governance extension
metadata, where the server deliberately does not look for a dispatch
decision. Every self round-trip test ran against a single-skill plane, whose
fallback dispatches without a name, so the two halves agreed everywhere
except the first two-skill deployment, which refused its own sibling as
ambiguous. The client now writes the capability into the field its server
reads; a receiver that infers ignores the key, because message metadata is
opaque to the protocol. The test that pins it runs the client against a
two-skill plane, where no fallback can mask the miss.

### Changed — A2A back-pressure is identified by a pair, not a numeral

External research this round surfaced that A2A 1.0 reserves
`-32001..-32099` — the same band JSON-RPC gives implementations — so the
server-defined `-32029` this plane answers a full quota with could later be
assigned a spec meaning of its own. The number was never the right identity:
the server now attaches a `google.rpc.ErrorInfo` under this project's own
domain (`agentplane.hupe1980.github.io` / `QUOTA_EXHAUSTED`), and the client
refuses-and-backs-off only on that pair. The sharper half is what the client
stops doing: a bare `-32029` from a foreign server is an
implementation-defined fault that may have been raised mid-execution, and
classifying it as a clean refusal licensed resending a mutating call on
somebody else's ambiguous numeral. Unmarked, it now lands in doubt.

### Changed — outbound A2A refuses plaintext on both legs

Push delivery has refused non-HTTPS webhooks from the start; the peer call
and the card fetch — the legs that carry the run's payload, a bearer
credential, and the address the next call will trust — did not, which is the
audited pattern of this layer: a rule enforced where it was first written
and not on its siblings. Both now refuse `http://` outright, with loopback
*names* in a `testkit` build as the one exception. A scheme that arrives
inside a discovered card is untrusted input, so it is not the far side's
choice to make.

### Fixed — provider drivers stop discarding what the provider said

Three per-driver corollaries of the failure-mapping rule, each found by
checking the drivers against the providers' current wire contracts:

- **Gemini's retry window reaches the retry loop.** Google names its 429
  window inside the body as a `google.rpc.RetryInfo` duration, not in a
  `Retry-After` header — read only from the header, the advice was discarded
  and the default policy spent every attempt in milliseconds against a
  window measured in tens of seconds, then reported the provider down. Whole
  seconds only, zero and fractions read as no advice, and the `max_advice`
  ceiling still bounds it.
- **Bedrock's `malformed_model_output`/`malformed_tool_use` stops are
  metered `Unusable`, not answers.** Converse emits them when it could not
  parse what the model produced; what survives in the content blocks is a
  fragment, and passing it through handed the caller's tool loop a
  plausible-looking call the provider itself disowned.
- **An Anthropic refusal carries its stated grounds.** The API populates
  `stop_details` (category, explanation) on a refusal and nowhere else;
  dropped, a decline arrived as one bare sentence and the operator was left
  diffing prompts against a black box.

MCP gained the mirror-image courtesy: negotiation downgrades by design, and
an older server still answers a `resources/read` for a missing URI with the
legacy `-32002` — which the current spec tells clients to keep accepting. It
classified as *outcome unknown* and was retried under policy forever;
nothing ran, and it now classifies as the refusal it is. Card signatures
additionally carry the spec's `typ: "JOSE"` protected-header field for
third-party JWS verifiers, and the push token header's provenance is now
stated honestly in its docs: the spelling is the reference SDK's, because
A2A 1.0 dropped the 0.3-era header definition without naming a replacement.

The external sweep otherwise validated the layer against the released specs:
MCP 2026-07-28 remains current (stateless core, `server/discover`, MRTR,
tasks as the official `io.modelcontextprotocol/tasks` extension with exactly
the get/update/cancel client verbs this host implements), A2A 1.0.1 remains
the newest release (now governed under the Linux Foundation's Agentic AI
Foundation), and the framework survey (Strands, LangGraph, Pydantic-AI,
OpenAI Agents SDK, ADK, Vercel AI SDK, rig/swiftide/genai) confirmed the
seam decisions other stacks bled on reactively: opaque provider-tagged
continuations for signed reasoning, MCP session lifetime as an explicit
axis, static tool surfaces over runtime discovery, and no sampling
parameters in the portable request — both Anthropic and Google removed or
deprecated exactly the knobs this seam never carried.


### Fixed — `planned_run` no longer dodges the gate it exists to demonstrate

The example's mailer was declared `mutates: false` and its catalogue was
hand-built in Rust, laxer than nothing — the two moves `governed_transfer`'s
own commentary calls the dangerous direction. A mailer that sends is a
mutating sink: calling it read-only exempted its arguments from the taint
gate the example claims to showcase, and made a timed-out send *retryable* —
the one condition under which this runtime does something twice. The example
now declares what is true: `mutates: true`, `/to` restricted by
`allowed_sources: ["tool://crm/lookup"]`, and the catalogue derived from the
manifest with `ToolCatalog::from_manifest`. That turns the module's central
sentence — *the recipient must be the address the lookup actually returned* —
from an observation into an enforcement, and the example proves it both ways:
the reference-built plan passes because its provenance **is** the CRM, and a
third scenario runs the plan a hijacked or hallucinating planner would write,
a literal recipient, refused at the sink with
`protected field '/to' … derives from undeclared source 'model:fake/planner-1'`.
The schema admits the string; the provenance rule does not admit its author.

### Added — `approved_call`: the oversight headline, runnable

`requires_approval` — a person sees the exact tool and the exact arguments
before dispatch — was a README headline row with tests and no example. New
`examples/approved_call.rs` runs the whole shape offline: the model asks to
move money, the run suspends (a row, not a thread), the worklist task carries
`tool://ledger/transfer` and the verbatim arguments, approval releases
exactly that call, refusal goes back to the model as a failed call without
the reviewer's words, and a strict replay reassembles the approved run —
human decision included — opening no task and moving no money. The manifest
pairs the gate with `/recipient: allowed_sources: [model:fake/teller-1]`,
which is the reviewed sentence "the model may author this field" — two
independent controls, both in the file.

### Added — three examples for the claims only the test suite could vouch for

The second pass of the round asked which *headline* sentences had no runnable
demonstration, and three did. The 2026 convergence is "kill the worker, resume
from the last completed step", and server-backed engines demonstrate that
half; what the surveyed frameworks do not demonstrate is a takeover that is
itself sealed evidence in an embedded runtime, a budget pause that resumes
into a *recorded* re-admission, or a stop that undoes what the run already
did:

- **`recovered_run`** — "recovery is *initiated*, not merely possible", run on
  two in-process instances. Instance A performs stage one and is aborted
  mid-run; for one lease TTL the dead look exactly like the busy; then
  `abandoned_runs` names the stranded run and instance B's ordinary `sweep`
  takes it over — fenced, journaled in the sweep's own sealed run, and
  finished with no stage repeated. The one deliberately un-demonstrated case
  is written into the fixture's comment: a death *between an effect's
  announcement and its record* is the unknown-outcome case and quarantines
  instead.
- **`budget_pause`** — exhaustion as a pause with a protocol, at the effect
  ceiling: the third posting never starts; resuming under the same ceiling
  re-refuses without stacking a second refusal; a plane built with the raised
  ceiling re-admits (`BudgetReadmitted` beside the old refusal), performs the
  third posting once, and the whole history verifies strictly. The industry
  pattern this answers — kill the runaway agent — converts a cost control
  into lost work; this one converts it into a decision on the record.
- **`operator_stop`** — the two brakes, in one file because their difference
  is the lesson: cancelling a run *undoes what it did* (the hold is released,
  the journal names who asked and why, a second asker does not displace the
  first, and the conclusion is `Cancelled`, not `Failed`), while the
  store-backed halt stops **new admissions only**, on every instance sharing
  the store, with the operator's reason in the refusal — existing work keeps
  its right to finish or be cancelled properly, because stranding a saga
  mid-unwind turns an incident into a second one.

### Fixed — refusing to close a case is a business answer, not a store fault

Found by *reading the examples' output*, which is what this round was for:
`clearing_case` printed its close-refusal as `refused: backend: case … has 2
open deadline(s)` — the `Backend` variant, which means *the storage engine
failed*. Both backends did this, with two different message spellings, and the
consequences compound: the operator API maps `Store(_)` to 500, so a case that
lawfully refuses closure would report as an internal error; and the
conformance battery only checked that `close` *errs*, so a store that was
merely unreachable read as enforcing the rule. New
`StoreError::ObligationsOutstanding { case, outstanding }` carries the rule in
one spelling for both backends; the battery now pins the refusal's **type** on
`close` and on the agent path (`set_status(Closed)`) both — an outage can no
longer impersonate enforcement. Two mutation anchors
(`AClosureRefusalWearsAFaultsType`, per backend) `--verify` KILLED; mutation
count **572**.

### Changed — example output reads as narration, everywhere

Running every example and reading the output as a newcomer found three that
did not hold up: `tool_loop`'s bounded-loop scenario printed its four tool
reads above its own header (filed visually under the previous scenario — the
header now prints before the run); and `memory_run` and `standing_authority`
compressed five demonstrations each into one summary line, leaving the
provenance label, the hold-beats-calendar sweep, the refusal-consumes-nothing
check and the revocation/exhaustion distinction all invisible outside their
assertions. Both now narrate section by section like the rest of the fleet —
including the honest, unabridged refusal text a skill actually receives.
`openai_live` was run against the real API in the same pass: schema-shaped
answer, 94 tokens, strict replay with zero further calls.

### Fixed — a getting-started snippet that could not parse

The cookbook's oversight recipe wrote `deadline: klaerung` where the format
is a `{ name, kind, params }` object — outside the docs guard's reach because
the fragment carries no `apiVersion`, so nothing compiled it. The snippet now
parses, and the same section gains the per-call form (`approval: tools-only`
+ `requires_approval`) with a pointer at the new example.

### Added — a step-by-step tutorial, verified against the real binary

The docs had a how-to collection, a reference, explanations and a fast tour —
and no learning-oriented tutorial, the page every comparable runtime leads
with. [Your first agent](https://hupe1980.github.io/agentplane/docs/first-agent/)
builds one support-triage agent from an empty file to a durable, tool-using,
pinnable declaration, no Rust required. Its method is the format's own:
**start too small and let the refusals teach** — every error message on the
page is captured from the shipped CLI, not paraphrased, and every full
manifest checkpoint is parsed by the docs guard in CI (invalid teaching
states appear only as fragments, which the guard checks for YAML
well-formedness — the same split the guard already enforces everywhere).
The page is deliberately honest where the offline story thins: the
deterministic fake has no judgement, so the tool step proves wiring and
grants and points at `tool_loop` — or a live model — for choice.

### Changed — the example index answers every question the fleet can

The getting-started "pick the example for your question" table stopped
growing when the fleet did not: `tool_loop`, `planned_run`, `sealed_run`,
`effect_group`, `memory_run`, `mcp_tools` and `standing_authority` were
runnable answers no page pointed at. Every offline example has its row now. Four examples also
dropped a redundant `.provides(name)` where the capability *is* the skill's
name — the default the getting-started page teaches, taught back by the
examples instead of contradicted.

## [0.23.0] — 2026-08-27

Two audit rounds. The first walked the transactional tier: effect groups, the
atomic-member replay path, exhaustion at the effect ceiling, and replanning
lineage — findings that share one shape the catalogue already names, a rule
enforced in one place and silently absent from its twin, plus one distinction
that existed nowhere at all: whether a store failure happened before or after
a call reached the world. The second walked the recovery-and-resources tier —
the blob store's erasure semantics, the drill's reading path, and the
sweeper's takeover evidence — and found the tenant-isolation argument
unapplied at the unit erasure actually names.

### Changed — the case-store contract pins blob-list scoping in both directions

**Affects anyone implementing `CaseStore` against their own backend.** The
conformance battery asserted only that a case's blob list *contains* its own
artifact — one-sided, and satisfied exactly by a `blobs_of` that returns every
case's blobs. It now also asserts the other case's artifact is **absent**, on
both shipped backends and yours: the list is what an erasure request walks, so
one that answers across matters erases data nobody named and reports more
discharged than the case ever held. A store that scopes its reads already
passes; one that does not now fails the battery instead of failing an erasure.

### Fixed — the erasure unit leads the blob's storage address

Content addressing gave identical bytes one storage key, and the erasure unit
is the case — so two cases of one tenant holding the same document held **one
object**. One case's erasure tombstoned the other's data while discharging
the first's request, and the drill read the survivor's loss as *erased by
design*, the one verdict built not to page. Sealed deployments had a second
face of it: the later case's write re-sealed the shared object under its own
scope, so either case's key destruction stranded the other. This is the tenant-isolation
argument — "tenant leads the path, so one tenant's erasure cannot
destroy another's" — that was never applied one level down, at the unit
erasure actually names.

The storage key is now `blob::unit_address(scope, digest)` — a
domain-separated hash of the erasure scope and the content digest — for
sealed and unsealed deployments alike (`blob::ScopedBlobs`, composed under
`EncryptedBlobs`). Journals keep committing to the content digest, which
still identifies and verifies the bytes; identical bytes in two cases are two
objects, and one case's tombstones and key destruction reach exactly its own
copies. Deduplication ends at the erasure-unit boundary on purpose. The scope
string moved to one implementation (`core::erasure_scope`) consumed by the
key ring and the blob layer both, because a scope that destroyed keys under
one spelling and expired blobs under another would report one erasure and
perform two half-erasures. **Breaking**: objects stored by earlier builds sit
at bare content addresses nothing reads any more — recreate the store, per
the pre-freeze rule. `blob::erase_case` now takes the tenant unconditionally.

### Fixed — the drill reads through the handle the plane wrote through

`Runtime::drill` handed the drill the bare blob store, which it read at bare
content digests. On a sealed deployment every intact artifact therefore
reported as **corrupt** — the only verdict that pages, raised for every
healthy blob, which is how the real alarm stops being believed. Nothing
caught it because the drill's fixture wrote plaintext blobs beside sealed
case state — a deployment shape no ring produces. The drill now derives each
case's own handle (unit-scoped address, sealing envelope when a ring is
supplied) from the bare store, `drill::Stores` carries the tenant those
scopes are derived under, and the fixture writes the way `store_blob` does.
A retired-floor or destroyed-key answer on a blob now reaches the report
through the same three-way classification sealed case state gets.

### Fixed — a takeover's note lands before the takeover

The recovery pass resumed an abandoned run and then wrote the `run_recovered`
note into the sweep's evidence run — act before note, against the sweeper's
own rule, and recovery is the one pass where that order loses the record
permanently rather than briefly: a resume that concludes releases the lease
and leaves the recovery queue, so a crash between the resume and the note
left a fenced, resumed run whose takeover no journal accounts for, with no
tick ever re-selecting it. The note now lands first — a note that cannot be
written skips the takeover for a tick that can write it — and carries the
lapse and the takeover, not the outcome, which the recovered run's own
journal already answers.

### Fixed — a landed call whose record was refused is no longer "did not happen"

When an effect's `perform` returned and the journal then refused the terminal
append, the error surfaced as a bare store failure — the same type a
pre-dispatch failure produces. The effect-group abort classified it as *never
dispatched*, took the cheap abort, and settled `Aborted` ("taken back whole")
over a send that had already gone out; the orphaned announcement was then
re-performed by the next resume, around members the abort had reversed. The
classification now happens at the one place that knows the answer:
`perform_once` returns the new `StepError::Unrecorded { key, disposition,
detail }`, carrying what this process observed the call do, and both
consumers of "may this failure have externalised" — the group's cheap abort
and the executor's abandoned-group settlement — branch on it. A landed send
with a lost record now quarantines its group; the general path is unchanged
(the run fails open, and the resume resolves the orphan by its declared
recovery, exactly as after a crash).

### Fixed — a resumed atomic member consumes its recorded refusal

The rule that a gate must not re-decide a dispatch history already settled
was enforced on the ordinary dispatch loop and not on the atomic-member path,
which consumed the recorded `PolicyDenied`/`BudgetRefused` from the cursor and
then ran the gate *fresh*. A resume under a gate whose answer had changed
dispatched — and committed, in a new transaction — a member the recorded run
was refused, appending a second history under the same key. The path now
routes replayed refusals through the same implementation the ordinary loop
uses; a record an atomic member cannot have written (a `Failed`, an orphan —
its records commit with its transaction) quarantines as divergence instead of
being consumed and ignored.

### Fixed — a raised ceiling un-pauses an effect-limited run

"Exhaustion is a pause" was true at the step ceiling and false at the effect
ceiling: `max_steps` refusals were re-asked against the ledger in force on
resume (journaling `BudgetReadmitted`), while a `BudgetRefused` recorded under
an effect key replayed verbatim forever — so a run exhausted by `max_effects`
stayed exhausted under a budget that now admits it. The effect tier now
follows the same protocol through one shared implementation: strict replay
consumes the refusal verbatim; a resume re-asks the ledger, re-concludes
without stacking a second refusal when the answer is still no, and journals
`BudgetReadmitted` under the effect's key when it is yes. The replay cursor
learned the supersession, so a readmitted history strict-verifies as
refusal-then-continuation rather than stopping at a verdict the run's own
later records overturn. Policy denials deliberately stay verbatim on both
paths: a budget is raised, a policy is argued with, and resume admission
already pins the exact bundle.

The boundary of the rule is the history frontier, and the condition is
`writes_enabled` — a re-admission is a write, and bookkeeping writes begin
where history ends. A refusal *inside* the replayed prefix was already
answered by the run itself: a group's deferred member refused by the ceiling
is followed on the record by the abort's reversals and settlement, and
re-admitting it mid-prefix would dispatch the send into recorded history —
divergence and a quarantine manufactured out of an operator's raise. Such a
refusal re-raises verbatim and the resume re-reaches the recorded abort.

### Fixed — an unsettled group under a seal is an audit finding

The design claimed "a group neither taken nor taken back is a query", and no
such query existed — the shape the catalogue files as a survey sentence
nobody checked. The honest delivery story is now stated and enforced: an
unsettled group can only be left by a crash or a store failure, both of which
put its run in a backlog that is already drained (failed, abandoned,
quarantined), and the resume settles it. The one state no resume repairs — a
**sealed** conclusion over an opened, never-settled group — is a new
`agentplane audit` finding (`Finding::GroupUnsettled`), because nothing may
resume a sealed run and whether its members were taken or taken back is then
permanently undecided. An open run's unsettled group deliberately does not
flag: alarming on the ordinary crash shape teaches the reader the finding is
weather.

### Fixed — a successor plan must say why it exists

`PlanIR::succeed_with` sets version, parent and reason together, and the
runtime checked two of the three: a `Replanner` returning `reason: None`
froze a plan into the journal as having replaced another with nothing on the
record saying why. Rejected now, beside the lineage check. **Breaking** for a
`Replanner` that built successors by hand without a reason — return
`succeed_with(..)`'s result, or set `reason`.

### Changed — design notes

External research this round corroborated rather than moved the design, and
is cited in the architecture notes: two further groups converged on
staged-then-committed tool effects (Cordon; the ACID reframing), which is the
deferred-member class; a negative result showed provenance-*weighted*
retrieval ranking has no usable operating point, which is the experimental
case for hard labels over score terms; and AWS shipped history-keyed Cedar
clauses (Dogwood) with exactly the two costs the design records for
history-keyed policy — analyzability loss and a trusted-event-source
requirement. An IETF draft now specifies per-agent Merkle-checkpointed,
witness-countersigned records — the witness architecture arriving as a
proposed standard; tracked, not adopted.

## [0.22.0] — 2026-08-21

An audit of the evidence-and-authority tier: the witness client, and the
operator API's refusal classification. Its central finding is one this
project's own catalogue predicted — a test double written from the same
misreading as the code — found where it costs the most: the one subsystem
whose entire value is that somebody *else* can check it.

### Fixed — a witness cosignature is now the one real witnesses produce

`HttpWitness` could never have verified a cosignature from an actual C2SP
witness — omniwitness, ArmoredWitness, the network the module exists to
reach. Three misreadings compounded: the trusted-key id was derived with
`signed-note`'s plain-signature algorithm byte (`0x01`) instead of
`tlog-cosignature`'s (`0x04`), so every real witness's line was skipped as an
unknown key; the payload was read as a bare 64-byte signature, where the spec
leads it with an eight-byte big-endian timestamp; and the signed message was
taken to be the submitted note verbatim, where the spec specifies
`cosignature/v1`, a `time` line, then the note body with signature lines
excluded. Nothing failed, because the test's fake witness *imported the
crate's own key-id helper and signed the crate's own message construction* —
a signer/verifier pair that round-trips cleanly through a shared mistake and
agrees with no witness that exists.

The verification now implements the spec, and is pinned two ways a shared
misreading cannot survive: the message construction and payload layout are
asserted against `tlog-cosignature`'s published worked example — literal
bytes, not a round trip — and the test fake derives its key id and message
from the spec's words with its own SHA-256, so the fake and the crate can
disagree again. `MemoryWitness` produces the same payload shape (timestamp
zero, stating that an in-process witness has no clock of record), so
`Cosignature::signature` means one thing regardless of which witness produced
it. A signature over the bare note — the shape of a *log's own* claim about
itself — is refused by construction, which is the whole point of the domain
separation: without it, the log vouching for itself and somebody else
watching it grow are interchangeable bytes.

The catalogue gains the sharpened tell: a test double that builds its answers
by calling the implementation's helpers can only ever confirm the
implementation. A double derives its bytes from the spec's words; a wire
format is additionally pinned to a published vector.

### Changed — a refusal keeps its class across every surface

Deciding a task claimed first and wrapped every claim refusal — four-eyes
exclusion, wrong role, a holder, an id naming nothing — into a policy denial.
The words survived; the class did not. In process, a mistyped task id read as
"policy denied", which no policy did; over HTTP it surfaced as 403, the
permanent answer for the transient mistake. `RuntimeError` now carries
`TaskClaim(ClaimError)` (transparent, so refusals keep the store's own
words), `decide_task` passes the claim protocol's refusals through, and the
HTTP surface answers a decide exactly as it answers a claim, from the same
classification function: 403 for ineligibility, 404 for an id that names
nothing, 409 for contention, 500 for an outage. `ClaimError` moved to `core`
beside `Task` to carry that (still re-exported from `case`, so existing
imports hold).

Cancelling a run had the sibling defect with one status: every refusal was
409. A mistyped run id told the operator "somebody else got there first" and
sent them to read an intervention that does not exist; a store outage taught
a retrying client that a retryable failure is permanent. Unknown ids are 404
and outages 500, as the delivery and claim routes already answered.

### Changed — a conclusion's reason reaches whoever the conclusion reaches

Reported from the field, and the report's own diagnosis was right: `RunSealed`
carries a `reason` so that *why* a run failed outlives the process that wrote
it — and the two surfaces that deliver conclusions both destructured it away
behind a `..`, the exact shape the payload-sealing list already refuses for
this record. A receiver of `io.agentplane.run.completed` got `outcome:
"failed"` and nothing else; `GET /runs/{run}` answered the same. Both now
carry `reason`, absent (not null) for a success, and both destructure every
field of the seal so the next field added must ask deliver-or-not at the
build. The reason rides only to audiences the seal opens for — the operator
event namespace and the operator API; the caller-facing A2A stream
deliberately does not carry it, because a counterparty is told the outcome,
not the plane's internals.

### Added — `Destination::try_also_signed_with`

The rotation half of push signing now pairs like the primary half:
`also_signed_with` panics, `try_also_signed_with` reports — with
`SigningKeyError::NoPrimary` for a rotation secret configured before any
primary, a refusal the panic previously made unreachable only if the caller
hand-checked the precondition first, which is the check written twice. Both
secrets come from the same file at the same moment inside the same builder,
so both belong on that builder's error path, naming the destination.

### Changed — case-history truncation is a fact, not an inference

The case view fetched exactly its history bound and reported `truncated` when
the result filled it — the inference every list route on the same surface
already refuses, stated in a comment three routes away. A matter with exactly
the bound's worth of records read as cut off. The view now asks for one more
than the bound, like its siblings; `Api::history_limit` makes the bound
configurable (its own knob, not `limit` — widening a list page should not
silently deepen every case view), with the default unchanged at 200.

## [0.21.0] — 2026-08-21

Five passes. The fifth audits governed memory, semantic retrieval, media
ingestion and the manifest against the current field — the mid-2026 memory
frameworks and the memory-poisoning literature — and its finding is one
defect with three faces: the two retrieval tiers answered lifecycle
differently. The fourth is a deep audit of the interop layer — MCP, A2A,
CloudEvents/push, and the model-provider drivers — against the specs as
released (MCP 2026-07-28, A2A 1.0.1, CloudEvents 1.0, Standard Webhooks 1.0)
and against the failure modes the wider ecosystem is publicly fighting. Its
sharpest lesson is structural: nearly every defect sat where one driver or one
backend deviated from a sibling that got it right, invisible to any test that
exercises only the sibling. The seam invariants are now spelled once and
pinned per driver.

### Changed — a semantic selection is screened against durable truth

A semantic index is derived, so between rebuilds it keeps naming versions
that are no longer current — and each staleness had its own wrong answer. A
superseded version kept being served after its correction, so the ranked tier
was the one place a repair did not reach. An expired version was served past
the disposal date its writer stated, which the deterministic tier already
refused. And an erased version failed the entire query, so every lawful
retention sweep was a semantic-search outage lasting until the next index
rebuild. Live dispatch now screens every hit against the authoritative store
before the selection is journaled: a hit whose version is not the one a fresh
recall would see simply leaves the selection. The cutoff rides in the record
(`SemanticQuery::as_of`, from the run's journaled clock), and the screen is
`MemoryStore::current` — a new required method, the by-id twin of `recall`'s
lifecycle rule, which `version` deliberately cannot answer because replay
needs it to keep serving superseded and expired state. Integrity findings
stay loud: a moved digest and an out-of-scope hit are refusals on live and
replay both. The retriever-misconduct refusals (an answer past `limit`, a
non-finite score) moved into the effect, before the record is written — a
selection holding a NaN score journals as `null` and could never be read
back. Custom `MemoryStore` implementations must add `current`; the
conformance battery pins its semantics on both shipped backends.

### Added — the manifest format ships as a JSON Schema

`Manifest::json_schema()` and `agentplane schema` emit the format as one
draft-07 JSON Schema document, published at
`https://hupe1980.github.io/agentplane/agent.schema.json` — so a single
`# yaml-language-server: $schema=…` modeline gives any editor autocomplete,
hover documentation and inline unknown-field errors while a manifest is being
written, instead of at `agentplane validate`. It is generated from the very
types the parser deserializes into, which is what keeps it honest: the derive
reads the same serde attributes, so unknown fields, missing fields, wrong
types and wrong enum spellings fail the schema exactly as they fail the
parser, and hover prose is the first paragraph of each item's own
documentation rather than a second copy. The parser stays authoritative — the
semantic refusals (an unstated budget, a control nothing performs) run only
there, and the schema's own description says so. Guards pin the published
file byte-for-byte to the generator, pin parser-acceptance ⇒
schema-acceptance on a full-featured manifest, and pin that both sides refuse
the same shape errors.

### Fixed — one formation answer cannot supersede itself

A formation answer proposing the same key twice wrote two versions back to
back, so the *later* proposal silently superseded the one the declaration's
first-wins rule prefers. Duplicates are now skipped — first wins, matching
the truncation rule — and a duplicate does not spend a `max_items` slot,
because it is not a distinct fact.

### Fixed — a wipe the optimizer was allowed to delete

`BodySigning` zeroed its push signing keys on drop with a hand-written store
loop. A plain write into a buffer that is about to be freed is a dead store
the compiler may remove, so the wipe was a control that compiled, read as
protection in review, and might never have executed — the keys stay in freed
heap either way. It now holds `Zeroizing<Vec<u8>>`, which is the mechanism
the rest of the crate already uses for secrets (`Secret`, `DataKey`) and the
reason that crate exists: volatile writes the optimizer may not elide. The
hand-written `Drop` is gone rather than corrected, because the type that
zeroizes is the one that cannot be forgotten at the next field.

### Fixed — every `Content-Encoding` line is checked

The media fetcher read only the first `Content-Encoding` header line, so a
response carrying `identity` on one line and a real coding on another reached
the signature check with coded bytes. Every value is checked now; the format
signatures made the gap mostly theoretical, but a check that reads half the
header is a check that documents itself wrongly.

### Fixed — a schema no longer fails every tool-calling turn

The tool-calling loop attaches the declared output schema to every model
turn, and four of five drivers judged a mid-loop turn — a tool call and no
sibling text — as "the answer is not JSON": a metered failure whose error
path carries no continuation, so the provider's signed reasoning was dropped
from the retry and the provider rejected the conversation. The exemption a
tool-asking turn earns (a schema binds only the final answer) is now spelled
once in the shared wire helper, and each driver pins it, because the copy
that drifts is on whichever driver a deployment does not exercise. Bedrock
already had it right, which is what proved the intent.

### Fixed — Gemini carries the whole transcript, not the latest turn

Gemini's continuation held only the last model turn, so round three of a tool
loop was sent without round one's signed turn — the model re-asked for the
same tools or answered with amnesia, silently. The state is now an array of
contents accumulated exactly as every sibling driver accumulates, and the
two-round wire test pins the shape signature-for-signature. In the same
family: an unstored OpenAI request now asks for `reasoning.encrypted_content`
(without it, stateless multi-turn reasoning fails against the live API while
every local round trip passes), Anthropic maps `xhigh` instead of refusing an
effort the provider documents, and `model_context_window_exceeded` /
`pause_turn` are reported as unfinished answers rather than complete ones.

### Fixed — the bill is the bill

Bedrock reported Converse's cache counters beside `input_tokens` instead of
folding them in, so the token ceiling read a fraction of the real spend the
moment caching worked — the exact "bill nobody can reconcile" the usage type
documents. Both Bedrock paths now share the one cache arithmetic. A Bedrock
guardrail intervention is a metered refusal on the buffered path as well as
the streamed one; an SSE decode failure classifies by the same severed-stream
ladder as a dead connection instead of pinning to `Unaccounted`; a reasoning
item opening counts as generation evidence, so a stream cut mid-reasoning is
never "safe to repeat"; and the SSE decoder reassembles codepoints split
across TLS frames instead of writing two replacement characters into the
journal.

### Fixed — an A2A message id deduplicates at admission, scoped to its producer

`SendMessage` correlated on the bare `messageId` without an admission key.
This crate's own client keeps the id stable across retries precisely so a
peer can deduplicate — and the server did not: an in-doubt retry of a
blocking send executed twice, and one peer replaying another's id joined the
victim's case and was handed its case id. Admission is now keyed on the
authenticated sender joined with the id (the same spelling inbound events
bless), a retry answers with the run the key already admitted, and an empty
id is refused. Also under A2A conformance: an unset `historyLength` returns
the full capped history (the protocol's default; only an explicit `0` means
none), a `mediaType` on a text or data part is accepted as the label the
spec says it is, `totalSize` saturates at the wire's `int32`, a retransmit
of the message that completed a task answers with the task instead of a
terminal-state error, and the skill-selection convention is a declared card
extension instead of folklore in an error message.

### Fixed — the MCP context gate refuses for real reasons

The labels-are-history refactor removed the grant ceilings from MCP effect
descriptors, and the manifest gate kept comparing against them — so every
manifest-governed prompt and resource read was refused unconditionally, with
a message about a sensitivity mismatch that did not exist, and no test
dispatched one to notice. The gate now compares the grant against what the
wiring itself declares (both directions, since two artifacts stating one
decision must agree), and the granted-read test would fail on either
regression. Around the same gate: every MCP call carries a whole-request
deadline (the transport waits forever, and a wedged server hung the step
with nothing journaled), a negotiated version outside the known set is
refused at construction, a task poll names the output ceiling its snapshot
carries instead of defaulting to `Public`, `tasks/update` authority moved
into the manifest (`spec.context.task_input`), and `serve` prints each
server's advertisement drift beside its negotiated version.

### Fixed — a CloudEvent can wake a run, and its identity cannot be forged

The inbound half of the CloudEvents route buffered every conformant event
forever: nothing mapped an envelope to a correlation key, so acceptance was
a dead letter with a 200. `subject` — the standard's own "what this event is
about" — now becomes the correlation key, and nothing else does. The
"unforgeable" `(source, id)` pair now actually is: control characters are
refused in the attributes the U+001F-joined dedup identity is built from.
Structured mode is chosen by one case-insensitive predicate shared between
parser and route; extensions cannot shadow core attributes or carry
non-scalar values; duplicated attribute headers are refused; a store outage
answers 503 so a bus retries instead of dropping.

### Fixed — the push token rides, and rotation is not a flag day

The A2A push token was stored, sealed, redacted — and never sent, so a
receiver that validated it rejected every delivery while the plane retried
thirty-two times and parked. It now rides every delivery as
`x-a2a-notification-token`. Standard Webhooks signing gained the sender half
of key rotation (`also_signed_with`: one space-separated header element per
key, so a receiver holding either verifies); both due scans serve
longest-due first on both backends, closing a starvation-by-name under
saturation; one registration drains a bounded page per sweep instead of
holding a fan-out slot for its whole backlog; an operator destination's URL
is refused at configuration instead of parking one registration per run; and
`RunCompleted::for_tenant` stamps the `tenantid` extension multi-tenant
buses need.

Three passes before it. The third is aimed at implementation maturity in the
tiers no round had named — batch, timers — asking of each store verb the
honesty questions earlier rounds settled elsewhere: does a write that matched
nothing say so, does a decoder that cannot read a row refuse, does an absence
read as an absence. Five defects, every one a store answering something other
than the truth, and none reachable by a test that only drives the happy path.

### Fixed — one batch runs one frozen plan, enforced where the plan lives

`BatchStore::open` refuses a batch reopened under a different plan digest
(`StoreError::BatchPlanChanged`, naming both digests), and the new
`BatchStore::plan_digest` answers what a batch was opened as. The sentence
"a batch whose plan could change between items would be several acts wearing
one name" was a comment on a field: `open` was idempotent on the id alone, so
a resume offering an edited plan silently kept the old row's digest while the
runner executed the new plan — items 60,001+ settling under a plan the
batch's own record does not name, invisible to every audit that trusts the
record. The runner cannot enforce this; by the time an item executes, the
store's row is the only witness. Same-digest reopen stays an idempotent
retry.

### Fixed — a mark written to nowhere is a refusal, not a success

`mark_exhausted` on an unknown batch now answers `NotFound` on both backends.
It is the one bit that lets a census read as *finished* — lost, a batch is
`Running` forever with no symptom — and both backends reported it written
while writing nothing: Postgres discarded the row count two functions above
the `record` implementation whose comment explains why row counts must be
read, and redb took the `if let Some` arm and fell through. The same class as
the `release`-that-freed-nothing defect the conformance battery already pins;
the battery now pins this one too.

### Fixed — a row the store cannot read is damage, not a default

Three decoders answered corruption with an invented value:

* Batch item outcomes (both backends) decoded an unknown outcome string to
  *no outcome yet* — a damaged row read as an item that never ran, carried by
  the census as in-flight forever, keeping the batch `Running` over damage
  nobody is told about. Now `StoreError::Corrupt`, and the census refuses
  rather than filing the row in a bucket.
* The redb timer store decoded an unknown phase to `Forward` — with a comment
  defending totality — while the Postgres twin was already fallible and even
  carries the mutation anchor for exactly this defect
  (`ADamagedPhaseColumnDecodesAsForward`). Two implementations of one rule,
  disagreeing at the boundary nobody probed: a damaged compensating-phase
  timer would have fed the unwind logic the forward half of the saga. Now
  both refuse.

### Fixed — a report on an unknown batch is not an empty batch

`Runtime::batch_report` refuses an id no batch was opened under. A census
cannot tell "no such batch" from "batch with no items yet" — both count zero
rows — so a mistyped id answered an empty `Running` report: healthy-looking
work that never starts, watched instead of corrected.

### Changed — breaking

* `StoreError` gains `BatchPlanChanged`. `BatchStore` gains `plan_digest`;
  implementors must add it, and `open`/`mark_exhausted` gain refusal
  contracts the conformance battery now enforces.
* `Runtime::batch_report` returns `NotFound` for unknown ids.
* No schema changes; the Postgres DDL is untouched this pass.

Two passes. The second is over the oversight surface — the worklist, the one
tier whose consumer is a person — asking of each declared behaviour what the
runtime actually does when it fires. One declaration turned out to be a word:
`on_expiry: escalate` promised to "widen the audience and keep waiting" in the
manifest reference, the field docs and the state's own name, and its entire
enforcement was a state flag. Nothing widened. Worse, the flag pointed the
other way twice over: an escalated task stayed reserved to whoever had sat on
it, and stayed in the bounded scan that drives expiry — forever, since
deciding it is exactly what did not happen — so enough escalated rows would
eventually fill every batch and the `deny`/`proceed` policies of the tasks
behind them would silently stop firing, plane-wide. Human review is a finite
resource an escalation policy spends, and a queue an attacker can flood is an
oversight control an attacker can switch off.

### Fixed — escalation now does what its name has always claimed

The manifest gains `spec.oversight.escalate_to`, `TaskSpec` gains
`escalate_to(role)`, and `TaskStore` gains one compound verb, `escalate`, that
does three things in one transaction: the declared roles **join** the
audience (a union — the original reviewers remain eligible; replacing them
would be a reassignment wearing a wider name), the stale reservation is
cleared (the claim belonged to the window that closed, and an escalation that
keeps it has widened the audience to people who cannot claim the row), and
the state says what happened. One verb rather than three writes because the
three must not be separable. Four-eyes survives it: the proposer is barred
from the wider audience exactly as from the narrow one, and the conformance
battery holds every backend to that.

The declaration is refused where it cannot mean anything, in both tiers, with
mirrored rules — which tier an agent was written in must not decide whether
its oversight declaration is checked. `escalate` with no `escalate_to` is a
promise with no operand. `escalate_to` beside a policy that never escalates
is a declaration nothing reads. And `escalate` over an empty audience is
refused because empty already means *anyone*, which no list can widen — the
union deliberately leaves an empty audience empty rather than narrowing it,
and the parser keeps that branch unreachable.

A racing decision beats an escalation: the store's write is guarded on the
task still being pending, so a reviewer answering in the window between the
sweep's read and its write wins, and the sweep's escalation is a no-op rather
than an un-deciding.

### Fixed — an escalated task leaves the overdue scan

`overdue` now returns `open` and `claimed` tasks only, on both backends.
Escalation is the one expiry disposition that leaves its task pending and
past due indefinitely, so the scan that kept returning escalated rows was
accumulating permanent residents at the head of a bounded oldest-first batch
(512). Once they filled it, the sweep would re-select and no-op the same 512
rows every tick, report `saturated`, and never reach a younger task again —
the declared expiry policies of everything behind them disabled by load,
which no test that watches a single task can see. The sweeper's escalation
arm now writes the ledger note first and escalates second, because `escalate`
is the write that removes the task from the driving query — shape 34's rule,
applied to the loop where it was found to hold only by accident.

### Fixed — the four-eyes operands survive the shared store

The Postgres task columns `candidate_roles` and `excluded_actors` are now
`TEXT[]`, not comma-joined `TEXT`. A role or actor name is an identifier the
deployment's authenticator mints — a SPIFFE id, an email, an LDAP DN — and
this store does not get to constrain its alphabet: joined on a comma, an
excluded actor named `spiffe://acme/ns,prod/agent` read back as two actors
named neither, and the person barred from deciding was barred no longer. The
embedded store round-tripped the same name verbatim, which is the worst
version of the defect — the two backends disagreed about a security control's
operand, and which one a deployment ran decided whether dual control held.
The conformance battery now opens a task whose names carry the old delimiter
and asserts both halves: verbatim round-trip, and the exclusion still firing.

### Changed — breaking

* `Oversight` gains `escalate_to`; `on_expiry: escalate` now requires it,
  requires bounded `approvers` (when the block opens approval or call tasks)
  and bounded triage audiences, and `escalate_to` without `escalate` is
  refused. Previously-accepted manifests declaring bare `escalate` are now
  parse errors — deliberately, since what they declared did not exist.
* `TaskSpec`/`Task` gain `escalate_to`; `StepCtx::task` and
  `StepCtx::open_task` apply the same refusals as the parser.
* `TaskStore` gains `escalate(id)`. Implementors must add it; both shipped
  backends and `SealedTasks` do. `overdue` now excludes `escalated` tasks —
  a caller that wants every pending-and-late task was reading the wrong verb,
  because this one has always been the expiry sweep's driving query.
* Postgres `tasks` DDL: `candidate_roles`/`excluded_actors` become `TEXT[]`,
  and `escalate_to TEXT[]` is added. Schema edited in place; recreate the
  store (pre-release, no migration).
* `OpenTask`'s effect descriptor gains `escalate_to`, so effect keys over
  task-opening effects change; existing journals replay as divergence
  (pre-release, recreate).

The first pass is over I13 — *a finding must be findable* — asking of each terminal
conclusion not whether it is delivered, but **where it is delivered to, and what
else can take it off that list**. Two answers came back, and neither was a
missing mechanism. Both were real findings, correctly detected, handed to a
channel that belonged to something else: one to a case status that closure
retires, one to the outcome bucket that means *try again later*. Detection
without delivery is the failure I13 names; these are its subtler form, where
delivery happens and lands somewhere nobody is looking.

### Fixed — a missed obligation outlives the case that missed it

`CaseStore::breached(limit)` lists obligations in the `breached` state, and
`GET /obligations` serves them under a new `api:obligation.list` verb.

There was no such query. A breach reached an operator as the escalation it
produced — a *case status* — and that is why it read as covered: something did
arrive. But `close` admits a case once no obligation is still **outstanding**,
and a breached one is not outstanding. So the record of what a matter missed
left every listing at the moment the matter was filed away, which is the moment
people stop looking, and `close`'s own comment says as much: *an unmet
obligation survives closure, because closure is the moment people stop looking.*
It survived the row and not the surface.

The route is the third door named in a single sentence written on the run
listing two releases ago — *escalated cases, overdue tasks, breached
obligations*. Overdue tasks were findable through the worklist; escalated cases
got a route when that claim was checked; the third name went unread because a
breach did reach somebody, until the case closed. A survey sentence half-checked
is worse than one nobody checked, because the half that was fixed is what makes
the rest read as settled.

`api:obligation.list` is its own verb rather than a widened `api:case.list`, so
a compliance function can be granted *what did we miss* without also being
granted the contents of every matter. Deployments enumerating `action::ALL` to
write rules must grant it; a default-deny engine refuses it otherwise.

### Fixed — the sweeper wrote off an obligation before it escalated the case

`sweep_deadlines` now escalates the case first and marks the obligation
`Breached` second.

`due` selects obligations that are still `pending` or `warned`, so writing
`Breached` is the write that removes one from the only pass that looks at it.
Done first, it turned the escalation that follows into a step with no retry: a
crash in that window left a breach recorded, a case saying nothing had happened,
and no later tick able to select the obligation again. One lost finding per
crash, in the subsystem whose entire purpose is not to lose one.

The dangerous order is the one that reads better — primary fact before derived
one, cause before consequence. `sweep_tasks` had it right by construction, since
`overdue` keeps returning a task after it is escalated, and that accident is
what made the asymmetry visible. The rule:
*the write that removes an item from the query driving the loop goes last.* It
costs repeated work on a retry and nothing else, because every other write in
these loops is already idempotent — which is what makes them safe on a timer to
begin with.

The test fails the *second* write and asserts the obligation is still selected
by `due`. No timing, no race: false in the wrong order, and a store that refused
everything would fail the positive half beside it.

### Fixed — a rewritten pinned read quarantines the run instead of failing it

New `StepError::Unreproducible`, classified untrustworthy by the executor, with
`agentplane.run.unreproducible` and a counter beside it.

I1 exempts a read whose answer cannot change from the effect protocol — bytes by
digest, a memory by id *and* version — on the stated condition that the
immutability claim is **checked rather than assumed**. The check was there and
fired correctly. What it produced was `StoreError::Backend(String)` carrying
`MemoryError::Rewritten`'s message, which made a store contradicting its own
immutability indistinguishable, to anything but a string match, from a store
that was briefly unreachable — and left the run `Failed`.

`Failed` is an ordinary outcome here: open, resumable, and not what an operator
audits. So the one condition meaning *the durable record is not trustworthy* was
filed in the bucket meaning *try again later*, and `GET /runs?outcome=quarantined`
— where somebody looks for exactly this — did not list it. The argument against
it was already written in the codebase, on `Undecidable`: *a distinct variant
rather than a message, because the executor quarantines on it, and a run's
disposition must not hinge on the wording of a string.*

**Absence is deliberately not this.** A version that was *forgotten* is an
erasure somebody asked for and recorded; it still fails the run, because routing
it here would fill the integrity backlog with lawful decisions. Telling erasure
from loss is the job `drill` does at the case layer, applied where the read
happens.

The semantic recall path returned one refusal for two situations — a digest that
moved and a retriever answering outside the query's scope. They are now separate:
the first is the authoritative store contradicting itself, the second is the
index misbehaving while durable truth is intact, and an operator reading the
merged message would go looking in the wrong system.

### Changed — breaking

* `CaseStore` gains `breached`. Implementors must add it; both shipped backends
  and `SealedCases` do. Postgres needs no DDL change — the existing
  `case_deadlines_due` index leads on the two columns it filters.
* `StepError` gains `Unreproducible`. Exhaustive matches over it must handle the
  variant; a run that previously concluded `Failed` on a rewritten memory now
  concludes `Quarantined`.
* `action::ALL` gains `api:obligation.list`.

Mutation count **527** — nine anchors added across the two passes, each
verified by `--apply`, including one aimed at the Postgres `overdue` query
specifically: the redb mutation cannot reach the shared store's copy of the
rule, and an anchor that kills on one backend reads as coverage of both.

## [0.20.0] — 2026-08-20

One pass over the receiving edge, from a deployment report: a plane that emits
signed events at-least-once, and a plane that *takes* them, had asymmetric
support. The sending half was finished; the receiving half was left to whoever
wrote the receiver.

### Added — admission is at-most-once when a message says who it is

`run_once`, `run_correlated_once`, `spawn_once` and `spawn_correlated_once` take
an admission key and return `Admission` — `Fresh`, `Replayed`, or `InFlight`.

The key rides on the `RunAdmitted` record, and the store claims `(tenant, key)`
**inside the transaction that appends it**. That ordering is the whole design: a
ledger a caller writes before the run strands the key over a run that never
existed if the process dies between the two, and every recovery for that is
machinery this shape does not need. A refused admission — a policy denial, a
quota ceiling, a rejected batch — spends no key, because the key and the records
commit together or not at all. Postgres holds it with a primary key on
`run_admission`; redb holds it with the shape of a table key, the way `CORR_OPEN`
holds one open case per business key.

A duplicate is answered rather than refused: a caller that retried wants the
original run, not a conflict to interpret. The case that motivated it is the
**suspended** one — a run parked on a four-eyes decision has already opened the
task, so a redelivery that admitted would put a second identical approval in
front of a reviewer, which is a control degrading into a guess. `Admission` says
*this is already waiting for you*.

The event buffer was the obvious place to put this and is the wrong one.
`EventStore::buffer` already reports "already seen" for a `(source, id)` over the
same store — but an event nobody subscribes to is dead-lettered by the sweep, and
a non-empty dead-letter list means *a correlation key is wrong somewhere*. A
receiver using the buffer as an idempotency ledger would dead-letter nearly every
message it admits, so `needs_attention()` would be permanently true and that
signal spent buying deduplication. Two concerns can share an identity without
sharing a table.

`JournalStore::admitted_as` and `CaseStore::detach_run` are new required methods,
neither with a default — see [upgrading]. The conformance battery covers the
invariant in both directions, including that an unkeyed admission claims nothing.

### Added — a verifier beside the signer

`WebhookVerifier` checks what `Destination::signed_with` produces: Standard
Webhooks, over the raw bytes, with a five-minute tolerance and `also_accepting`
for a rotation.

Shipping only a signer means every receiver writes the interesting half itself,
and the interesting half is not the HMAC — it is the two things around it. A
signature authenticates bytes, not freshness, so a captured POST replays forever
unless a stale timestamp is refused; at-least-once delivery makes duplicates
ordinary, so genuine bytes arrive twice unless the receiver deduplicates on the
id. Both are what a second implementation omits, because omitting them looks like
working software: every test passes, every delivery verifies, and the failure is
a replay nobody sees.

`verify` refuses the first and returns `VerifiedDelivery { id, timestamp }` for
the second — `id` is what `run_correlated_once` takes as its admission key, so
the two halves of this release meet at that field. Refusals are typed, the
comparison does not short-circuit, and a body is never parsed before it is
verified.

### Fixed — security: a conclusion's reason reached the store in the clear

`RecordKind::RunSealed` was control-plane — an outcome word and a chain head,
neither of them the caller's data — so `journal::payload` sealed nothing for it.
Adding a `reason` to that variant put a provider's refusal, quoting the request
it refused, into a record the key ring walks past.

The mapping's own comment had defended listing every record kind by name:
*a new variant does not build until somebody has answered it*. That is true of
variants and silent about **fields** — `K::RunSealed { .. }` kept matching, kept
compiling, and kept sealing nothing. Every arm now destructures every field and
binds the ignored ones explicitly, so the second question reaches the build too.
It is shape 33 in the constitution's catalogue: an exhaustive match that is
exhaustive over the wrong axis.

### Added — the admission index has a retention verb, and no default

`JournalStore::forget_admissions(older_than)` retires claimed keys. There is
deliberately no automatic window: retiring a key reopens the door it closed, so
the window must exceed the emitter's retry horizon and is the operator's to
choose. Absent a call, keys are kept — the safe default is the one that cannot
admit a duplicate on a timer, and the size of the index is something a
deployment's database monitoring already reports.

`agentplane forget-admissions --store … --older-than-days N` is the operator's
door to it, for the reason `drill` has one: a verb reachable only from Rust is
absent from a deployment that is only a YAML file. The window is a required
argument with no default — choosing one would be this crate picking somebody
else's retry horizon.

Also refused now: an **empty** admission key, and one over
`MAX_ADMISSION_KEY_BYTES`. An unset header arrives as `""`, and `""` is a
perfectly good key — the first message claims it and every later message is
answered with the first one's run. Silent, total, and produced by a
configuration mistake.

### Added — `try_signed_with`, and a reason on the seal

`Destination::try_signed_with` and `BodySigning::try_new` report a bad key rather
than panicking. `signed_with` is usually called inside a deployment's own
builder, where an abort arrives before the exit code and the log line that would
have named which destination was wrong — the `build`/`try_build` pair, in the
small.

`RecordKind::RunSealed` gained `reason`. It carried only the outcome word, so the
chain recorded *that* a run failed and not *why*: the reason survived in the log
of the process that wrote it and nowhere an operator, an audit or a replayed
admission could reach. `None` for a success, which has no why.

[upgrading]: https://hupe1980.github.io/agentplane/docs/upgrading/

## [0.19.0] — 2026-08-19

Six passes: two over the confidentiality layer — one over its rules, one over
the bytes those rules turned out to imply something about — one over the
outward-facing edges, the model providers and the two protocols this plane
speaks, one over memory, retrieval and the manifest surface in front of them,
one over outbound delivery and the event envelope at both ends of it, and one
over how this plane *waits* and how it *connects*.

The confidentiality passes each found a shape that was holding something else
open: the first a release blocker, the second the format's own
algorithm-agility story.

The edges passes found two shapes, each more than once. **A rule implemented
once per surface**: a severed Gemini stream threw away usage the provider had
already reported, because the accumulator holding it had no accessor and the
other drivers' ladders were never compared; three A2A surfaces each carried
their own copy of one task-state mapping. Neither is a wrong answer anybody
could see — both are *agreements that happen to hold*, and both fail on the
next edit rather than on this one.

**A control counted rather than checked** is the second, and it is the one that
had teeth. `netguard` opened by naming the crate's URL dereferences as *two*,
and there were four: both A2A legs — the card fetch, and the call to the
interface URL that card advertises — connected to an address nobody had
checked. The sentence was true when it was written, nothing re-checked it, and
the doors it did not know about were the ones standing open. The same sweep
found two outbound clients with no timeout at all and a completion field five
drivers produce and nothing reads.

**A durable format that does not say which format it is.** A sealed envelope
described its own lengths and not its own construction. That is invisible
while one build writes and reads the bytes — which is every test — because the
defect only exists *across* builds, and a durable format is precisely the
artifact that outlives the build that wrote it. It is now shape 30 in the
constitution's catalogue, and the sealed envelope is the worst place to have
had it: the innermost check is an AEAD, so a reader meeting a construction it
did not know walked its own layout over somebody else's and reported *the
sealed payload did not authenticate* — the sentence that means tampering.

The last pass found three defects with one thing in common: **nothing could
observe any of them**. A rate limit retried three times in a second is correct
by its policy and reports the provider as down. A delivery sweep that serves
receivers one at a time produces counters identical to one that does not. A
fresh TLS handshake per webhook is a cost, not a failure. None of the three
fails a test, appears in a report, or looks wrong when read — and all three are
the plane doing exactly what it was told, at the edge where it talks to somebody
else's server.

The pattern is worth naming because it is not the usual one this document
records. These are not claims that expired or rules implemented twice; they are
**defaults that were never a decision** — a schedule computed because computing
one is what retry loops do, a loop written sequentially because the first
version had one row, a client rebuilt per request because a pin lives on a
client. Each was right at the moment it was written and none was ever revisited.
It is now shape 32 in the constitution's catalogue, and the entry says what
finding it costs: the other shapes are found by re-reading a claim or diffing
two implementations, and this one only by asking, of a mechanism nobody is
complaining about, what one would write there today.

The memory pass found one omission and one failure that could not fail.

**The omission** was a whole half of a tier. A declarative agent could form
durable facts on every run and had no way to read one back: recall lived on
`StepCtx`, so the reading half of memory was reachable only from Rust — in the
tier whose entire premise is that no Rust is written. Nothing was broken, every
test passed, and the feature was half a feature.

**The failure that could not fail** is the sharper one, and it is a new shape.
Cosine similarity is *total*: it is defined between any two vectors of equal
width. So a query embedded by one model revision and searched against an index
built by another does not error, degrade or return nothing — it returns a
confidently ranked list of unrelated memories, at full speed, with a plausible
score beside every hit. The old API asked a caller to type the embedding model
and the index snapshot into every query by hand, which is one chance to get it
wrong per call site, and the only symptom of getting it wrong is *quality* —
which has no threshold anybody can assert against in a test. This is now shape
31 in the constitution's catalogue: a total operation cannot report a wrong
input, so where one sits at a correctness boundary the check has to happen
somewhere the operation is not.

**The push pass found the same shape twice, on both sides of one envelope.**
This plane emits `CloudEvents` and could not read one; it labelled every
delivery `application/a2a+json`, including the structured-mode envelope it had
just built, which is a valid event that reaches nothing that parses one. Both
are the constitution's *a claim that nothing re-checks*: the concept document
said inbound events "align to `CloudEvents` 1.0" and no code in the crate had
ever parsed the envelope, so alignment meant a struct with similarly named
fields. The consumer wrote the parser instead — and its version keyed
deduplication on `id` alone, which is the exact collision the crate's own doc
comment on `InboundEvent::source` warns about, three paragraphs of it, in the
file the consumer never had to open.

### Fixed — a rate limit was retried as if nobody knew when to come back

Every HTTP driver classified a 429 as `RateLimited` and threw away the
`Retry-After` beside it. The retry loop then computed its own schedule: with
the default policy, three attempts inside about seven hundred milliseconds
against a window measured in tens of seconds. Every attempt is refused, the
effect fails, and the run reports the provider as down — while the provider had
already said, in the response, exactly when it would answer.

Nothing was broken by any local reading. The classification was right, the
schedule was right for what it was, and the tests passed because a test that
scripts a rate limit scripts one that clears. What was wrong is a **premise**:
exponential backoff is a guess about when a service recovers, and it is the
correct shape only where guessing is all anybody can do. A throttle is the one
outbound failure in this crate where the peer knows the answer, and the runtime
was declining to read it.

`ModelError::RateLimited` and a new `EffectError::RateLimited` carry the
window; `wire::classify_status` takes the response headers; and
`RetryPolicy::wait_before` is the single place that chooses between the named
window and the computed schedule. The parsing rule is `core::retry_after_seconds`,
shared with push — delta-seconds only, because the HTTP-date form means trusting
the peer's clock against ours, and zero because it would replace a backoff with
no wait at all. Both read as *no advice*, identically to an absent header.

**Two ceilings, and this is the part worth arguing.** The obvious
implementation clamps advice to `max_backoff` and ships. That conflates two
different risks under one number: `max_backoff` is small *because* a guess made
in ignorance should not be long, and advice is not a guess. Clamping a peer's
sixty-second window to a ten-second guess-ceiling reproduces the original defect
with an extra step. So `RetryPolicy::max_advice` is its own ceiling, defaulting
to a minute, and it bounds the thing that actually needs bounding — how long
this plane will hold a worker on the word of a party with an interest in never
being called again. Advice past it is **clamped, not discarded**: waiting part
of a window is closer to right than ignoring it, and if the window really was
longer the next refusal names what is left.

What did **not** move is the boundary the retry module already drew. The wait is
still in-process, so `max_advice` is also a bound on worker occupancy, and a
rate limit measured in more than minutes is still not a retry — it is
`cx.sleep()`, which costs a row instead of a thread. Making the runtime suspend
on a long window is a durable-format question (the wait would have to be
journaled beside the failure that caused it, so replay consumes it in order),
and it is recorded as one rather than half-built.

The corroboration is Temporal's, which reached the same two-part answer from the
other direction: its AI cookbook translates an HTTP `Retry-After` into
`ApplicationError.next_retry_delay` and bounds what it will accept from the
header, because the number comes from outside.

### Fixed — one slow receiver decided when everybody else's events went out

`DeliveryWorker::run_once` served its due registrations strictly in order. A
receiver has fifteen seconds to answer, so four dead endpoints at the head of a
page delayed every registration behind them by a minute — and a plane with more
due rows than a tick can drain fell permanently behind on *all* of them because
of the worst one.

This was invisible in every test and in every report. The sweep's counters are
identical whether it took a second or a minute, `saturated` describes the page
and not the clock, and no assertion in the suite could have failed: sequential
delivery is not wrong, it is slow, and slowness is the one property a test suite
built on in-memory doubles cannot observe.

Registrations share no cursor, no receiver and no task, so nothing about the
cursor discipline requires them to be served in order — serving them in order
requires only that every receiver be as fast as the slowest, which is not a
property anybody can arrange. The sweep now fans out, bounded by
`DeliveryWorker::max_in_flight` (16). Bounded rather than free because a sweep
is the one place this runtime knows how much outbound work exists, and `limit`
is a page size rather than a concurrency budget.

Ordering **within** a registration is untouched and always will be: that loop is
a cursor that may only move forward, and concurrency inside it would break the
only thing a cursor means.

The test is a rendezvous rather than a stopwatch — both deliveries must be in
flight at once for a barrier to release — so a sequential worker deadlocks there
instead of merely being slower. A timing assertion would have passed on a fast
machine that ran them one after another, which is the shape of test this
project treats as a test that cannot fail.

### Changed — the address rule moved into the client, and the client is reused

`PushSender` and `A2aClient` built a **fresh `reqwest::Client` for every
request**. Not an oversight: pinning a connection to pre-approved addresses is
how both stopped a name resolving somewhere else between the check and the
connect, and a pin is a property of the client. Correct, and it meant a new
connection pool, a new TLS session and a new handshake per delivery and per
delegation — the difference between multiplexing over one connection and opening
a socket per event, paid by exactly the two loops that repeat.

The rule now lives in the client's own DNS resolver
(`netguard::GuardedResolver`), so one pooled client serves a whole sweep. That
keeps the guarantee and **strengthens** it: a pooled client opens connections
long after any pre-flight returned, and those are precisely the ones a one-shot
check never saw. Pinning covered the request it was computed for; the resolver
covers every connection there will ever be.

The pre-flight stays, and is not redundant. A DNS hook can only *fail*, so the
resolver cannot say which refusal happened — and a forbidden address must not
read as a receiver that is merely down, because one is never retried and the
other always is. One rule (`netguard::judge`), called twice: once to decide what
the operator is told, once to decide what the socket reaches. Two spellings of
it would agree everywhere except the boundary nobody probed, which is the defect
this crate has already shipped once in this exact area.

**The mutation sweep is what settled the design here, and it is worth
recording.** The first attempt kept the three settings that make a client
guarded — the resolver, `no_proxy`, `redirect::none` — spelled out at each
caller, with a mutation deleting the resolver line. It **survived**: every
caller-level test still passed, because every caller also runs the pre-flight,
and no test can make DNS answer one way for a check and another way for a
connect. An enforcement whose removal nothing observes is the shape this project
catalogues, so the wiring became structural instead: one `guarded_client`
constructor, because the three settings are not independent — a proxy is
resolved *instead of* the destination, so it makes the resolver unreachable, and
a redirect makes the judged host the wrong host. A client with two of the three
looks guarded and is not.

That still leaves one testable claim, and it is the one that matters: a guarded
client must fail to reach a server **genuinely listening on this machine**.
There is no pre-flight in that test and a real listener is bound, so the default
resolver would succeed — which is what makes the failure mean something. The
mutation is killed by it.

One visible consequence: a peer endpoint resolving inward is now
`PeerError::Refused` rather than sometimes surfacing as `Unreachable` from the
client build. `Refused` is `DidNotHappen` and never retried, which is the
correct reading — a forbidden address does not become permitted by waiting.

### Added — one `CloudEvents` envelope, in both directions

`core::CloudEvent` parses a 1.0 message in structured **or** binary HTTP
content mode, validates it, and emits one; `POST /events` accepts either
alongside this plane's own shape, and `RunCompleted` builds its payload through
the same type.

One type rather than an emitter and a reader, because two ends written
separately drift and nothing fails when they do: an emitter that sorts
attributes one way, a reader that accepts an attribute nothing emits, and a
media type that is a string literal in whichever file happened to need it. The
round trip is now an assertion — what this plane emits is what it would accept.

It **refuses** rather than guesses, and each refusal is a message that would
otherwise be passed on unread: an unknown `specversion`; an empty or missing
`id`, `source` or `type`; `data_base64`, because a payload here is a JSON value
and decoding bytes to hand a run something it cannot address is a conversion
nobody asked for; an extension name that is not lowercase alphanumeric, because
a binding with case-insensitive keys delivers it under a different name; and a
non-JSON `datacontenttype` in binary mode, because wrapping arbitrary bytes in
a JSON string is a silent retype.

On the way in, the `source` a run is woken under is still the authenticated
caller and never the body's claim — a caller holding both halves of
`(source, id)` can deduplicate against another party's messages by naming them.
What is new is that the producer's claim is no longer *discarded* either: it
rides inside the buffered event's id. A gateway authenticates as itself, so the
transport identity cannot separate the producers behind it, and both of them
number their messages from one. Keying on `id` alone drops the second
counterparty's message as a retry of the first, silently, which is the failure
`(source, id)` exists to prevent and the one the field translation kept
reintroducing.

Correlation keys are deliberately **not** derived from extension attributes. A
CloudEvents extension is a flat lowercase string with no namespace, so any
mapping would be this plane inventing a convention and citing the spec for it; a
producer that must correlate posts the native shape, where the keys are stated.

### Fixed — every push delivery announced the wrong media type

`PushSender` hard-coded `Content-Type: application/a2a+json` for both
namespaces. A2A's own webhook was correct; the operator outbox posted a
`CloudEvents` structured-mode envelope under it, and every conformant receiver —
Knative, Dapr, Event Grid, anything using a CloudEvents SDK — routes on that
header. The event was well formed, the POST returned 2xx from a permissive
receiver, and nothing anywhere reported that the envelope had not been
recognised as one.

The media type is now the payload's to state: `Projection::messages` returns
`PushMessage`s that each carry one, `PushMessage::cloudevent` takes it and the
message id from the event itself, and `RunCompleted` posts
`application/cloudevents+json; charset=UTF-8`.

A single hard-coded header was serviceable while one projection existed. It
became wrong the moment a second joined the same loop, which is the general
form: a constant that is correct because there is only one caller is a defect
scheduled for whenever there are two.

### Changed — body signing is Standard Webhooks, and covers the replay

`Destination::signed_with(&secret)` — no header argument — and every delivery
carries `webhook-id`, `webhook-timestamp` and, when a key is configured,
`webhook-signature: v1,<base64>` of `HMAC-SHA256(key, "{id}.{timestamp}.{body}")`.

The old scheme was `sha256=<hex>` over the body alone, in a header the operator
named. Its own documentation stated the hole: no timestamp and no nonce in the
signed input, so a captured POST replays forever and every check still passes —
it is a genuine body, genuinely signed. The stated mitigation was that the
receiver must deduplicate on the event's identity, which is true and is
somebody else's discipline, asserted nowhere and defaulting to absent.

Binding the id and the instant into the signature moves that from advice to
mechanism: a receiver with a tolerance window and an idempotency key has a
delivery that expires. Choosing the published spelling over a house one is the
other half — a receiver verifies with a library it did not write, in whichever
of the spec's eight languages it happens to be, rather than with twenty lines
somebody transcribed from our documentation. The interoperability is pinned by
the spec's own published example vector, not only by our own round trip.

Two smaller consequences, both refusals at configuration: a key shorter than 24
bytes is rejected where it is written, because a MAC key an attacker can search
is a check that reads exactly like one that means something; and a secret
spelled `whsec_<base64>` is decoded, because that form names base64 *of the key*
and signing the prefixed text produces a MAC no conformant verifier accepts —
a failure that would surface only as a receiver refusing everything, for a
reason no log on this side explains.

### Fixed — abandoning a push registration deleted the only cursor there was

A receiver that answered permanently, or stayed silent past the retry ceiling,
had its registration removed and a warning logged. The row *is* the cursor: it
is the only record of how far that receiver got, so deleting it made the
undelivered tail of that run unrecoverable without a scan nobody schedules. In
the one subsystem whose argument is *the journal is the outbox, and a crash may
repeat an event but cannot lose one*, the documented failure path lost events.

Registrations are now **parked**: `PushStore::park` keeps the row and its
cursor, `parked` lists them, `unpark` re-arms one at the record its receiver
never acknowledged. A parked row is excluded from both due queries, so it costs
no sweep — the objection that killed the obvious fix, a row retried until the
journal is deleted, does not apply to a row that is not retried at all.
`PushSweepReport::abandoned` is now `parked`, and both backends carry the flag
(`push_delivery` gained a column and a partial due index).

### Fixed — a receiver's answer was counted rather than read

Three defects in one retry policy, each invisible in a test that only asserts a
receiver eventually gets its event.

**Every rejection was transient.** A receiver answering `410 Gone` — the status
that means *this endpoint is retired* — was retried for the full ceiling like
one that was rebooting. `410` is now permanent, and deliberately nothing else
is: a 404 during a deploy and a 401 while a credential rotates are answers that
change, and parking a run's events on the first of them loses more than the
wasted retries cost.

**`Retry-After` was discarded.** A receiver naming its own recovery is the one
party who knows, and a sender that overrides it with a fixed schedule is
choosing to be told twice. It is now honoured — and bounded to an hour, because
it is advice from the one party with an interest in never being called again.
Only the delta-seconds form is read; acting on the HTTP-date form means trusting
the receiver's clock against ours.

**The backoff had no spread.** Every registration pointed at one receiver fails
in the same sweep and was scheduled to return at the same instant, so the moment
that receiver recovered it was hit by its entire backlog at once — a recovering
service knocked over by the sender that had been waiting politely for it. The
delay is now drawn from the lower half of the window, offset by a hash of the
registration and its attempt count. Derived rather than random because
`run_once` takes its clock from the caller precisely so a schedule is
reproducible: a random draw would make every backoff assertion in this crate
unwritable, which is how the omission survived.

The retry ceiling's documentation also claimed "a little over two hours" for
32 attempts. The schedule sums to about an hour and forty at most. A number in
prose that no test reads is the same shape as the media type above.

### Added — `spec.memory.recall`, so a declarative agent can read what it wrote

**Breaking: `spec.memory_formation` moved to `spec.memory.formation`.** Every
field under it is unchanged, and `deny_unknown_fields` makes the old spelling a
parse error rather than a block that is silently ignored. The move exists
because the block gained its other half.

A declared recall reads before the first model call and folds the selected
memories into the prompt under `/memory`, beside the trusted `/system`
instruction and the caller's `/input`, as `{id, purpose, content, written_at}`.
Each item carries **the label it was written with** — a fact a model produced
last week stays untrusted this week, and the same egress ceiling and the same
protected-field rules govern everything the answer then reaches for. That is
the property the memory-poisoning literature says decides the outcome:
information flow carried *across* the write and back out of the read, rather
than content inspected at either end, because the attacks that work carry no
linguistic signal at all.

The `/memory` key is present even when nothing was recalled. A prompt whose
shape depends on what the store happened to hold is one nobody can read against
the manifest, and an instruction saying *use what you remember* would address a
field that sometimes does not exist.

Four refusals arrive with it, and one is a design statement rather than a
validation: **`execution.kind: planned` may not declare a recall.** That kind
refuses untrusted input because its plan is compiled from what the planner
reads, and a recalled memory is untrusted whenever whatever wrote it was —
allowing it would be that refusal walked around through the store. The other
three: an empty `memory: {}` block, a `limit` outside `1..=50` (`0` reads in
review as a ceiling and behaves as an agent that remembers nothing), and a
`memory` block beside a coded skill, which calls `StepCtx::recall` and
`StepCtx::form_memories` at moments it chooses. `BuildError::FormationWithoutMemory`
became `BuildError::MemoryWithoutStore { agent, declared }`, naming which half
wanted a store.

**There is deliberately no `spec.memory.search`.** Similarity is computed over
item content, so anything able to write a memory is a ranking signal: an
attacker who cannot taint a value can still decide *which* clean values a model
is shown, and no label anywhere in the run shows it. A deterministic recall's
order is a fixed rule no stored item can move, which is what makes it safe to
spell as one reviewed line. Ranked retrieval stays a Rust call, where accepting
that channel is a decision somebody visibly made.

### Changed — the embedding space is wiring, not a string a caller types

**Breaking, for every caller of `cx.embed` and `cx.semantic_recall` and every
`SemanticRetriever` implementation.** `RuntimeBuilder::semantic_memory(embedder,
retriever)` takes the two together, and `build` refuses a plane whose embedder
revision is not the one the index declares it accepts queries in
(`BuildError::EmbeddingSpaceMismatch`) or that has no authoritative memory to
materialise hits from (`BuildError::SemanticMemoryWithoutStore`).

`SemanticRetriever` gains `index() -> IndexIdentity { snapshot, query_revision }`.
`query_revision` is the revision a **query** vector must come from, which is
deliberately not "what the documents were embedded with": asymmetric embedders
embed a query and a document differently on purpose, so an index built from
`…/search_document` names `…/search_query` here. The index states what it
accepts; matching it is the wiring's job, and the two strings differing is the
normal case rather than the suspicious one.

So `cx.semantic_recall` now takes a `SemanticSearch` — a subject, an optional
purpose, a limit and a sensitivity ceiling — and a `Tainted<String>`. It embeds
and ranks as two journaled effects and assembles the `SemanticQuery` itself.
`SemanticQuery`'s `embedding_model` and `index_snapshot` collapsed into one
`index: IndexIdentity` that the runtime fills in, and `cx.embed` returns
`Tainted<Embedding>` — the floats *and* the revision, read from the driver
rather than supplied beside it.

A retriever returning more hits than the declared limit is now **refused**
rather than truncated. Truncating would leave the selection's membership decided
by the seam's iteration order — a ranking nobody chose, arriving as though
somebody had — and every extra hit costs an authoritative store read before
anything downstream could drop it.

`InMemorySemanticRetriever::new` takes `(IndexIdentity, Vec<SemanticVector>)`;
its separate `identity` string is gone, because the effect key already carries
the profile and the index. Its own snapshot self-check is gone too: every query
is now built from `index()`, so that check could only ever compare a value with
itself — shape 29, arrived at from the other direction.

### Changed — sealed envelopes carry a format version

**Breaking, and it is the heaviest kind this project ships: envelopes written
by 0.18.0 and earlier do not open.** There is no migration and there cannot
be one. Sealed bytes are rotation-immutable — the journal's hash chain commits
to the envelope bytes, which is what lets an auditor holding no keys verify a
run whose payloads were erased — so nothing can rewrite an old envelope into
the new shape without breaking the chain around it. A deployment holding
sealed data from an earlier version keeps it readable by staying on that
version, or discards it. See
[upgrading](https://hupe1980.github.io/agentplane/docs/upgrading/).

The layout is now `[u8 version][u32 len][wrapped data key][nonce][ciphertext ‖
tag]`, and the version is read **before any offset is trusted** — which is the
whole property, since a parser that reads a length first has already committed
to a layout it has no rule for. One number, exposed as
`keyring::ENVELOPE_FORMAT_VERSION`, naming the entire construction: layout,
nonce width and AEAD together. Not a layout version beside a cipher
identifier, because changing the cipher changes what the bytes mean, two
numbers would be two spellings of one decision free to disagree, and a reader
choosing between suites by trial is an oracle rather than a parser. It stays
`1` until the durable-format freeze, like every other version in the crate.

This closes the algorithm-agility half of the durable-format freeze blocker
for the confidentiality layer: a second AEAD is a second version, and a build
that does not know it refuses instead of guessing.

### Added — `KeyError::UnknownFormat`, so a build skew is not read as tampering

The same argument that produced `KeyError::Retired` one release ago, one layer
down. An envelope naming a version this build does not read is not
`Destroyed` — nothing was erased and no key moved — and it must not be
`Refused`, which reaches `agentplane drill` as *this case's sealed state
neither opens nor was its key destroyed*: loss or tampering, for a condition
whose remedy is which binary is running.

It is reachable from ordinary operations rather than incidents, which is why
it needs to be legible: a mixed-version fleet mid-deploy, a rollback, and a
restore from a backup taken by a newer plane all produce it. The drill reports
such a case as a finding carrying its own remedy — it *is* a finding, because
this plane is holding a case it cannot read — beside the retired-version arm
and away from the arm that pages somebody.

### Fixed — the drill answered "nothing to check" for state it could not read

The half that made the above worth finding. `probe_sealed_case_state` returned
`None` to mean *this state was never sealed*, and returned the same `None`
when the state **was** marked sealed and could not be parsed: base64 that
would not decode, a header that would not read, and — the one with teeth — an
envelope whose erasure scope named a **different case**.

So a case the plane could no longer read was counted as a case with nothing to
check. No finding, no unchecked entry, and `is_sound()` still true: detection
withheld by the pass whose only job is detection, and invisible to every test
that counts findings rather than reading them. The foreign-scope row is the
sharpest of the three, because it is not merely unreadable — erasing that case
destroys a key which does not reach those bytes, so the data survives the
deletion request and the drill's answer was that the case was clean.

Past the sealed marker, every failure is now an answer. Damage and a foreign
scope are refusals that reach the loss-or-tampering arm, which is where they
belong; only an unknown version gets the reversible classification.

### Fixed — a failure variant added later would have cost nothing

`EffectError::spend` and `ModelError::usage` each matched one variant and
defaulted the rest to zero. The default is **free**, and these are what the
token, cost and `max_effects` ceilings are computed from — the ceilings that
exist to bound exactly the runaway a flaky provider produces. A variant added
later that burned tokens before dying would have compiled, passed every test,
and spent nothing. Both are now exhaustive, so the question has to be answered
before the code builds. No existing variant's answer changed.

### Fixed — a severed Gemini stream billed nothing it had already been told

Gemini sends `usageMetadata` on the chunks themselves, cumulatively, so a
stream cut off mid-answer has already been told what it burned. The
accumulator stored it, a unit test pinned that it stored it, and the
severed-stream classifier could not reach it: there was no accessor, so every
cut Gemini stream reported `Unaccounted` — generation happened, cost unknown —
while the driver was holding the cost.

The consequence is the one the ceiling exists to prevent. `Unaccounted` bills
zero, so the token and cost ceilings that bound a runaway provider counted
nothing during exactly the failure they were bought for. The driver's own
`buffered()` documentation had been asserting the opposite the whole time:
*a severed connection can say what it burned* was the stated reason streaming
is this driver's default.

Bedrock already had the full three-rung ladder — usage seen is `Interrupted`,
generation without usage is `Unaccounted`, nothing seen is safe to repeat — and
Gemini now reaches the same top rung, parsing through the buffered path's own
function so the normalisation that costs money (thought tokens billed as
output and added, cached input a subset and not added) keeps one spelling.

The general rule is now in the constitution rather than left per driver:
**"this provider cannot do better" and "this driver did not look" produce the
same `Unaccounted`, and only the first is honest.** Under-reaching is invisible
to every test that checks the variant instead of the counts, so each streaming
driver owes a test asserting the rung it claims.

### Fixed — three A2A surfaces each kept their own copy of one mapping

`tasks/get`, `tasks/list` and the snapshot a subscription opens with are three
views of one run's history. Each derived the A2A task state from its own
byte-identical copy of the same match, and the drift had already started: the
listing answered `"unknown"` where the others answered `"running"`.

This is the duplicate-rule shape at its most dangerous, because a disagreement
here is worse than a wrong answer. A client that polled, one that listed and
one that subscribed would each be told something different about the same task,
each would be behaving correctly, and the protocol gives them no way to
discover it. The copies would have agreed right up until somebody added a
record kind or reworded a suspension.

One function now reads the history. The surfaces differ only in what they do
with an empty one — no such task for a fetch, a working row for a listing that
must not fail its page over one unreadable run — which is a real difference and
is now the only one. A test drives all three over the wire against a task that
is *input-required*, the one state all three can be asked about at once: a
subscription to a finished task is refused before it reaches the stream, so a
completed run would have left the third surface untested.

Note what was **not** unified: `RunStatus → TaskState` and the sealed-outcome
string mapping stay two functions, as their own documentation insists. The
enum match is exhaustive and the compiler checks it; folding it into the string
match behind `_ => Failed` would delete the only compile-time check and produce
the same wrong answer twice, which is harder to notice than two different ones.

### Fixed — both A2A URL legs were dereferenced without an address check

`netguard`'s own documentation opened by naming the crate's URL dereferences:
*two features* — governed media and push delivery — each of which resolves a
host, checks every answer, pins the connection to exactly those addresses,
refuses redirects and bounds the request. There were four, and the two it did
not know about are A2A's.

**Card discovery** fetched with a bare client: no address check, no redirect
policy, no timeout, behind an allowlist that is optional and therefore absent by
default. A card URL arrives from a config, a registry entry or a message and is
routinely the first attacker-influenced string a deployment handles, which the
module's own docs said in the paragraph above the code that did none of it.

**The peer call** is the leg that matters more, because it carries data outward
rather than fetching. `AgentCard::endpoint` takes the interface URL straight out
of a *discovered card* and hands it to the client that posts the run's payload
and a bearer credential. A forged card cannot widen a grant — that is the
property that makes discovery survivable — but it can name an address, and
nothing checked which one.

Both now do what media and push already did. Two details are the ones that
matter: the connection is **pinned** to the addresses that passed, because a
check followed by a second resolution is the rebinding attack it appears to
stop; and **redirects are refused**, because every check above applies to the
first hop only. `is_loopback_name` moved into `netguard`, where the address
rules live, so push and both A2A legs share one spelling of it — and the
loopback exception stays `testkit`-gated, absent from any production build, and
keyed on a host that *is* loopback rather than one that resolved there.

### Fixed — two outbound clients had no timeout at all

Found by the same sweep. `HttpWitness` and `VaultTransit` each built a bare
`reqwest::Client` with no whole-request timeout, so a server that accepts the
connection and never answers holds the caller indefinitely. For the witness that
stalls checkpoint publication — an availability failure in the evidence layer,
caused by the party whose whole purpose is to be independent of this one. For
Vault it is worse: sealing and opening go through that client, so with a keyring
configured it is most writes.

### Fixed — `Completion::truncated` was produced by five drivers and read by none

Every driver computes it, and three of them carry a paragraph explaining why —
*a partial answer returned as a whole one is a silent truncation, which this
crate refuses everywhere else*. Nothing anywhere read the bit. It is the
catalogue's shape 26 exactly: the artifact always had the right shape, so every
test asking *did we get a completion* passed, and there was no input that made
any code path behave differently.

The coded tier keeps the choice, which is the documented contract: a caller
holding the `Completion` knows whether early-stopping prose is useful to them.
The declarative tier has no such caller — the loop *is* the caller — so it
decides, and the two halves are separated because only one is dangerous. A
truncated turn **carrying tool calls** has been cut somewhere inside its own
output, leaving the last call's arguments as whatever survived: syntactically
valid JSON saying something the model did not finish saying. Running that is not
a degraded answer, it is a side effect performed on a request nobody wrote. A
truncated turn with no tool calls is merely a partial answer, and is refused
rather than settled as the run's output.

`FakeProvider::truncated()` makes the state producible — a modifier on whatever
answer was queued last, rather than a variant of each constructor, because a
provider stops mid-turn for one reason and it can happen to any shape of turn.
A refusal no fake can provoke is a rule nothing proves the runtime honours.

### Added — `McpClient::negotiated_version`, so a downgrade is not silent

MCP negotiation is a designed downgrade: this host offers `2026-07-28`, a
server answers with a version it speaks, and the connection proceeds on that.
The client does not refuse — that is the protocol working, and it is why MCP
and A2A are treated differently, since A2A asserts its version rather than
negotiating it.

What was missing is that the outcome was unknowable. An older server serves
`tools/call` correctly and simply never returns a task, so the Tasks extension
this module is written against is absent with nothing failing: a long-running
tool behaves synchronously, a governed suspension never happens, and no error
anywhere names the cause. `agentplane serve --mcp` now prints the negotiated
version beside each server, because the declarative tier has no Rust in which
to ask.

Its test is driven by a hand-rolled server that actually answers `2025-06-18`,
which matters more than it sounds: rmcp's own server handler *negotiates*, so
against any cooperating fixture the offered and negotiated versions are the
same string and an accessor that returned a constant would pass.

### Fixed — one cache-accounting rule, spelled once

Anthropic reports cached tokens *beside* `input_tokens` rather than inside it,
so both are added back to mean *everything the provider processed*. That
arithmetic was written twice — once on the buffered path, once in the stream
accumulator. They agreed, and the copy that drifts is always on whichever path
a deployment does not exercise, which for a streaming-by-default driver is the
buffered one. The symptom would have been a bill nobody could reconcile rather
than a failure. Both now call `Usage::with_cache_beside_input`.

### Security — `h2` advisory RUSTSEC-2026-0258

`h2` is updated to 0.4.16. The advisory is unbounded memory growth from empty
`DATA` frames, and it reaches this crate through the HTTP/2 stack the A2A
server listens on — a remote denial of service against the one surface built to
accept calls from parties this plane does not control.

### Fixed — a Postgres column this store could not read became a decision

Three of the case store's six string decoders refused an unrecognised value
and three answered with a default, decided by nothing. A decoder that answers
with a fallback cannot report that the row was damaged, so the damage arrives
as a *decision* — and `phase` is the one with teeth, because it tells a step's
forward pass from its compensating one and defaulted to `Forward`. `OnExpiry`
and `Priority` defaulted to their safe values, which is exactly what made them
the wrong answer: a fail-closed default is still a fact the store invented
about a row nobody could read.

All six now refuse, like their neighbours and like the embedded backend, whose
rows go through serde and have always rejected an unknown variant. Every call
site already returned `StoreError`, so this costs a `?`.

### Fixed — `bearer` was not a bearer credential

`TokenAuthenticator` compared the `Authorization` scheme case-sensitively, and
RFC 9110 §11.1 defines it as case-insensitive. The failure has the worst shape
an authenticator can produce: `bearer <token>` is a legal request, and
answering it `Missing` tells a conforming client *you sent no credential* — so
the client retries exactly what it already did. Only the scheme name is
case-folded; the token keeps its bytes and its constant-time comparison, and a
test pins both halves, because folding the token would silently shrink the
space an attacker has to search.

**A seam method the architecture forbids anyone to call.** `KeyRing::rewrap`
was the standard answer to key rotation, implemented correctly against Vault's
transit engine, exercised by the conformance battery — and impossible to run.
It is now shape 29 in the constitution's catalogue, and the interesting part is
not that it was dead code but that it was *load-bearing in the wrong
direction*: a baseline requirement read as met because the capability existed,
which is how the hazard it should have removed went unnamed.

### Removed — `KeyRing::rewrap`

**Breaking.** The method is gone from the trait, from `VaultTransit`, from
`MemoryKeyRing`, and from the key-ring conformance battery. Implementors of
`KeyRing` delete their `rewrap` and nothing else changes; no stored bytes move,
and no wire or durable format is affected.

It could never have run. An envelope carries its wrapped data key inline and the
journal's hash chain commits to the envelope bytes — the decision that lets an
auditor holding no keys verify a run whose payloads have been erased. Re-wrapping
a journal payload therefore rewrites a record the chain covers, breaking the
chain it sits inside. Re-wrapping only the other stores would not have bought the
operational result either: a scope's journal payloads and its case state share
one wrapping key, so the scope stays pinned to the oldest version any of its
journal envelopes names, and rewriting case rows does not move that floor.

The rule its absence implies is now stated rather than left to be discovered:
**sealed payload bytes never change, and the erasure scope is the rotation
unit.** That costs less than it sounds like, because a scope is already one
case, one run, or one memory subject — a compromised wrapping key exposes that
unit and nothing else, which is what rotation is bought for. Adding a key version
stays safe and needs nothing from this crate; envelopes sealed before a rotation
keep opening, and a test now pins that rather than pinning re-wrapping.

This is also the model AWS KMS assumes: it retains every prior version of a key's
material in perpetuity, resolves the right one from the ciphertext on decrypt,
and offers no way to delete an individual version — only the whole key, which is
erasure. Rotation there is automatic and needs nothing from an application.

### Added — `KeyError::Retired`, so a version floor is not read as data loss

Deleting a capability without asking what it was protecting against leaves the
hazard and loses the reminder, and here the residue was real. Every KMS can
refuse to decrypt below a version floor — Vault's `min_decryption_version`.
Because envelopes now demonstrably pin their key version for life, raising that
floor past a live envelope makes un-erased history unreadable: an erasure nobody
requested, that no retention record explains.

Both existing classifications were wrong for it, in opposite directions.
`Destroyed` would claim a discharged obligation that was never requested.
`Refused` was what actually happened, and it reached `agentplane drill` as *this
case's sealed state neither opens nor was its key destroyed* — the sentence that
pages somebody to look for tampering, while the cause is one reversible setting.

So it is its own answer. `KeyError::Retired { scope, key_id }` names the version
the floor has to readmit, `VaultTransit` maps Vault's wording onto it, and the
drill reports such a case as a finding that carries its own remedy instead of a
suspected loss. `MemoryKeyRing::retire_below` models the floor, because an error
variant no test can produce is a classification nothing proves the runtime
honours. The runtime cannot stop an operator moving a floor; what it owes is that
moving it too far is legible, which is I13 applied to a control it does not own.

This discharges the re-encryption clause of the durable-format freeze blocker,
which required the design to specify how re-encryption preserves historical
verification before freeze. The answer is the second of the two the blocker
named: it does not re-encrypt.

### Fixed — a new record kind would have defaulted to unsealed

`journal::payload::payloads` — the single list deciding which fields are sealed
at rest — ended in a wildcard arm returning "nothing to seal". A record kind
added later would have compiled, passed every existing test, and silently
carried the caller's data in the clear, which is the failure that module's own
documentation calls silent by construction. The match is now exhaustive over all
26 kinds, so a new variant does not build until somebody has answered the
question. Behaviour for existing records is unchanged.

## [0.18.0] — 2026-08-15

Three adversarial passes — over the information-flow layer, the evidence layer,
and the type boundaries themselves — each turning up one shape that then
repeated.

The first is **a decision input that was a lookup rather than a fact**. A
value's label was re-derived on every replay from declarations that live in
operator configuration, so editing a catalogue rewrote what a finished run had
been permitted to do — and, because a resume replays its prefix and then
dispatches live, rewrote it for runs still in flight. Three of the entries below
are that one defect reached from different directions.

The second is **a rule enforced at one of its doors**. Field feedback on 0.17.0
supplied the first instance and, read against the reporting deployment's own
source, the second; it turned up three more times once it had a name.

The third is that shape carried to its sharpest form: **a validated type whose
derived deserializer is a second constructor**. Three types said in their own
doc comments that a bad state was unrepresentable, and `#[derive(Deserialize)]`
wrote it directly into their private fields. It is now shape 28 in the
constitution's catalogue.

### Fixed — three types where `serde` was the constructor nobody counted

Each of these establishes an invariant in a fallible constructor, keeps its
fields private so nothing else can reach them, and says so in prose. Each also
derived `Deserialize`, which reaches those fields and needs no permission. The
severity is in which door it is: a value arrives from a credential, a store row,
a journal record or a peer far more often than from a call to the constructor,
so the guarded path was the rare one.

**`Delegation` could widen.** The type's own words were "every value of this
type has already been checked … there is no `Delegation::new(links)` that would
let an unverified chain exist". The derive was that function. A chain rooted at
`crm.read` deserialized into one whose subject holds `*` — I6 inverted through
the path `DelegationScheme` implementations actually take, since a credential
parser reaches a chain by parsing rather than by calling `delegate`. Depth
bypassed `MAX_DELEGATION_DEPTH` the same way, and an empty `links` array
deserialized into a chain whose `owner()` then panicked.

`Delegation` now deserializes through `rehydrate`, which is the re-check written
for exactly this and previously reachable only when someone remembered to call
it. The owner is a field rather than the head of a `Vec`, so the empty chain is
not a refused value but an unrepresentable one, and the two accessors that
carried `expect("a chain always has a root")` no longer need it. The wire form
is unchanged.

**`TenantId` could carry the separator its key scope splits on.** The newtype
exists, in its own words, because "a name containing a separator could make two
different tenants produce one scope — the failure that looks like nothing at all
until one of them erases the other's data". Units already contain separators
(`event/{source}/{id}`, `memory/{subject}`), so this is not a corner: tenant
`acme` with unit `event/counterparty/42` and tenant `acme/event/counterparty`
with unit `42` derive the identical key scope. Both stores write, nothing fails,
and either tenant's erasure destroys the other's key and reports success. A
tenant name reaches the runtime from a credential claim an `Authenticator`
parsed and from stored rows — all `serde`.

**`Quorum` could need nobody.** `need: 0` reported `Pass` having judged nothing,
and a non-majority threshold — the case `QuorumError::NotAMajority` describes as
resolvable "depending on tally order rather than on the judgements" — did
precisely that, with 2 of 4 splitting 2–2 reported as `Pass`. A quorum rides on
`PlanNode`, and plans are deserialized from a store, from a journal, and from a
`Replanner` parsing a model's proposal. That last one is untrusted output, and a
panel is the control a hijacked plan most wants weakened.

All three now use `#[serde(try_from)]` onto a wire type that carries no
invariant, so the constructor is the only road in and the compiler keeps it that
way. That is deliberately not a validating call at each read site, which would
be the same mistake one layer out.

**This is a breaking change in the honest direction.** A stored value that never
satisfied the invariant now fails to deserialize instead of loading. Nothing
this crate writes can produce one; a hand-written fixture or a bespoke
`Authenticator` can, and a read error is the correct outcome — silently
accepting it is what let the collision exist. See
[upgrading](https://hupe1980.github.io/agentplane/docs/upgrading/).

### Fixed — a catalogue edit could declassify history

An effect's output label has three parts. Its provenance comes from
`Effect::source`, which every effect derives from something already inside its
key, so it cannot move without divergence. The other two — `Effect::trust` and
`Effect::output_sensitivity` — come from operator configuration: a `ToolSafety`
entry, an MCP grant, a `PeerGrant`. Those change with an edit, they recompile
nothing, and none of them reaches the effect key.

They were re-read from the catalogue on every replay. So lowering a tool's
declared `output_sensitivity` from `Secret` to `Public` silently relabelled
every value any past run had read through that tool. Nothing diverged, because
nothing about the call had changed — the mechanism designed to catch a program
reading history it did not write cannot see a configuration edit, and should
not be asked to.

Calling this an audit problem understates it. `Mode::Resume` replays its prefix
and then dispatches **live**, so a run suspended while holding a `Secret` tool
result woke holding a `Public` one, and the live tail of that resume could send
it to a sink the original label forbade. The exfiltration path this crate cares
most about, opened by a config change nobody would think to review as one.

`EffectDone` now carries a `DeclaredOutput` — the trust and sensitivity the
effect declared when it landed — and `EffectReconciled` carries one for a
recovered output. Replay reads them back. The field is required rather than
defaulted, for the same reason `RunAdmitted.input_label` is: both halves of a
missing answer read as *more permissive than the truth*.

The general rule is worth more than the fix: a
decision's inputs belong on the record wherever the decision is **reproduced**
rather than re-made. The spend was already journaled on exactly this argument.
The label was the half nobody had followed through.

### Fixed — sink gates re-judged effects that had already happened

The manifest-derived ceilings had applied to live dispatch only since they
existed, with a comment explaining why: a replayed effect reads its result from
the journal, so consulting today's manifest would refuse an effect that already
happened or bless one that was refused. The same comment then exempted the
effect's own ceiling and protected fields on the grounds that *those are code,
and a code change that alters an outcome is divergence*.

That reading does not survive contact with the effects that actually reach
sinks. A tool's `max_sensitivity` and `protected_fields` come from an operator
catalogue; an MCP prompt's come from a reviewed grant; a peer's come from its
`PeerGrant`. All configuration, none of it in any key. Every sink gate now
applies to live dispatch only — the verdict is in the journal either way, as
the result beside the effect or as the refusal's own record — and past the
frontier of a resume they all apply in full, unchanged.

Two consequences fell out, and both were latent bugs of their own:

**`McpPrompt` and `McpResource` hashed their grant's sensitivities into the
effect key.** That was the workaround for the entry above — turning a silent
relabel into a loud divergence — and it worked by making an operator who raised
a ceiling break the audit replay of every historical run through that prompt.
A configuration edit should not cost the verifiability of finished runs. With
the label now journaled the workaround has nothing left to protect, and the
grants are out of the key.

**A sink refusal read back from the journal became a `StepError::Denied`.**
Live, it is a `StepError::Policy`, which a tool-calling loop reports to the
model as `REFUSED` so it can try another route; a denial ends the run. Once
replay stopped re-deriving these and started reading the record, the two shapes
diverged and a replayed run would end where the original had continued. The
`PolicyDenied` record already distinguishes them by `action`, so
`PolicyError::Recorded` rebuilds the right one — carrying the recorded wording,
for the reason `BudgetExceeded::Recorded` does.

### Fixed — `cx.embed` could only embed a literal

`Embed` declared no `max_sensitivity`, so it inherited the trait default,
`Public`. Embedding is an egress — the text goes to a provider — and everything
that has crossed a trust boundary is already `Internal`. Every query worth
embedding is one: a user's question, a model's rewrite, a recalled memory. The
whole semantic-recall path was therefore reachable only by embedding a
hard-coded trusted string, which is what the one test covering it did.

`cx.embed` now takes the ceiling. It is a parameter and not a constant because
there is no answer this crate could pick for every deployment — and the
neighbouring `SemanticQuery::max_sensitivity` had been asking for exactly that
decision, about the retriever, since it was written. Two providers, two
ceilings.

### Fixed — answering an MCP elicitation needed no grant

`prompts/get` and `resources/read` each require an operator grant, on the rule
that a server describing a capability proves it exists and not that an agent may
use it. `tasks/update` — which sends this plane's data back to the same server —
required none, and ran at a `Public` ceiling nobody had chosen and nothing let
them raise.

`McpAccess::task_input` grants it, per server rather than per task, because a
task id is minted at runtime and an operator cannot review a name that does not
exist yet. Ungranted, `update_task` refuses. The whole-value taint gate is
unchanged and still in front: an untrusted response reaches an MCP server
through a `release` or not at all.

### Changed — the record format version is `1`

`canon::VERSION` and `export::FORMAT_VERSION` are both `1` and stay there until
the format freeze. The record version had been counting the pre-release cuts,
reaching 4, with a refusal message narrating each one.

The count implied those journals were readable. They never were — the reason
each cut refuses rather than lifts is that the old record still *parses*, with
moved and added fields taking their defaults, so a resumed run answers an audit
question falsely instead of failing to answer it. Collapsing to `1` says the
same thing in a number: this build reads what this build writes, and anything
else is a fresh journal. After the freeze the `Upcaster` seam takes over, which
is why it stays wired now rather than being introduced by the first migration
that needs it.

### Fixed — a capability served but never advertised

The plane refused a manifest advertising a capability no skill provides, and
accepted a skill answering a capability the manifest never names. The second is
the quiet one: the skill is governed by that manifest — budget, model grants,
egress ceiling and policy identity all apply — the run journals correctly, and
nothing anywhere records that the agent answers more than its file claims.

The declaration is the artifact that gets reviewed, digested and pinned, and
`peers::card` builds the A2A card from exactly that field. So the gap was a door
in a reviewed surface that the review could not see. It is the argument this
crate already makes about prompts — one composed in the deployer's code has no
version, changes in a deploy, and nothing connects the change to the runs it
affected — applied to an agent's capabilities.

`BuildError::ProvidesWhatItDoesNotAdvertise` names the extra capabilities. A
skill registered with `RuntimeBuilder::skill` rather than under an `Agent` has
no declaration to contradict and is unaffected.

### Fixed — two checks that arrived one stage too late

Both from field feedback on a model-free specialist that was bricked by its own
declaration, and both the same shape: the manifest layer knew enough to refuse
at parse and refused somewhere else instead, or not at all.

- **A zero budget ceiling was refused at parse and accepted at the builder.**
  See below — the rule now lives on `Budget` and both doors ask it.
- **A declarative agent with no model parsed clean.** `spec.execution` means
  the runtime drives the agent by calling a model, and the model is named
  rather than defaulted, so `execution` without `spec.models.privileged` is a
  document that can never assemble. It was refused at build
  (`BuildError::DeclarativeWithoutModel`) — which is after the review, since
  `agentplane validate` is the verb an author runs before deploying. Both
  halves are on the same page, so it is refused at parse; the build check stays
  as the backstop for a `Manifest` built in Rust.

### Fixed — a rule enforced at one of its two doors

A zero budget ceiling was refused when it arrived in a manifest and accepted
when it arrived through `RuntimeBuilder::budget` — and the builder is the path
this crate documents first. An embedder wiring `max_tokens: 0` in Rust got a
plane that refused its first effect on every run it would ever make, with the
`Budget` doc comment describing the manifest's refusal as though it were the
whole rule.

`Budget::bricked_ceiling` is now the single definition of which ceilings are
already spent at zero, and both the parser and `RuntimeBuilder::try_build`
(`BuildError::BudgetPermitsNothing`) refuse from it. `max_replans` and
`max_denials` stay excluded, because zero means something for both.

Worth stating as a shape rather than a bug: the manifest layer is where
declarations get checked, so it accumulates checks — and every one of them is a
rule about a value that some embedder reaches without a manifest. A check that
lives only there is a check whose enforcement depends on which door the caller
used. `StandingAuthority::validate` had this right already, by putting the rule
on the type.

### Fixed — security: the evidence layer, where nothing was verifying anything

An adversarial pass over the parts of this crate whose whole job is to be
checkable by somebody else. The common shape across every finding: a control
that produced the right-looking artifact and had no verifier, so the mistake
could not fail. Each one is now pinned by a test that checks against something
outside the code that makes it — an external vector, `ed25519_dalek` directly,
or a checkpoint from outside the file.

- **A witness's cosignature was never verified.** `HttpWitness` parsed the
  first signature line of a `200`, discarded its four-byte key id, and recorded
  it. A quorum was therefore a count of HTTP status codes: any endpoint
  answering `200` with a well-formed base64 string met it, and the whole
  argument for witnessing — that an independent party observed this log —
  rested on nothing.

  `HttpWitness::new` now takes the `TrustedWitness` keys the deployment
  accepts and refuses to build without one. **Every** line is considered, not
  just the first, so the answering server cannot decide which cosignature
  counts by reordering its reply. A line is matched by name **and** note key
  id — `signed-note`'s conjunction, because the name is whatever the server
  typed — and verified as Ed25519 over the exact note text submitted.

- **The two witnesses in this crate could not check each other.**
  `CheckpointSigner::sign` took a `Digest`, so `MemoryWitness` signed
  `SHA-256(note)` while `HttpWitness` verified over the note text, which is
  what C2SP specifies. Neither could be checked by any `signed-note`
  implementation outside this crate. Nothing failed, because nothing verified.
  `sign` takes `&[u8]`, and the blanket `impl<T: Signer> CheckpointSigner for T`
  — which is how a digest signer came to stand in for a message signer with no
  cast to notice — is gone. This crate already carried the argument for JWS
  cards: *signing its hash instead would verify perfectly here and nowhere
  else.*

- **An export was checked against its own header.** The Merkle root rebuilt
  from an export was compared with the checkpoint in the export's header, which
  an editor who drops a run rewrites too. `export::verify` takes the checkpoint
  the reader was given, and `agentplane verify` grew `--checkpoint`; without
  one the report lists **deletion** under `not_checked` rather than reporting
  sound. The same reasoning the record rehash already applied one level down.

- **A checkpoint had more than one spelling.** `Checkpoint::from_note` used
  `lines()`, accepting a missing final newline, eating a `\r`, and ignoring a
  fourth line. There were also two hand-rolled base64 decoders that disagreed
  with each other, neither canonical. The signature covers the *text*, so
  several texts naming one checkpoint is a split view assembled out of encoding
  slack. One strict decoder now, and a note is exactly three newline-terminated
  lines with a canonical origin, size and root.

- **The empty log's root was not RFC 6962's.** `merkle::root(&[])` returned
  thirty-two zero bytes; the specification says `SHA-256("")`. A size-0
  checkpoint is what a fresh log first submits, so this disagreed with every
  conforming verifier at the first opportunity — and zero is also what an
  uninitialised buffer and a truncated read produce. `merkle::empty_root()`.

- **One malformed submission could page an operator forever.** A witness has
  nothing to check a *first* checkpoint against, so it recorded whatever it was
  given. A size-0 checkpoint carrying any other root names a log that cannot
  exist, and once remembered, every honest checkpoint afterwards failed
  consistency and was reported as `Forked` — the integrity bucket,
  permanently, for that origin. `Checkpoint::is_coherent` is checked at the
  door.

- **A key name was structure treated as a label.** The field's documentation
  said "no spaces" and nothing enforced it, so a name carrying a space, a
  newline or an em dash produced a note that serialised fine and read back as a
  different name, a truncated payload, or a signature line nobody wrote.
  `SignedNote::with_signature` is fallible, and the reader holds the same rule
  as the writer.

Also removed: a staleness comparison in `MemoryWitness` that the check eight
lines above had already made and refused, so the branch could not be taken.

### Fixed — an erasure that reports success and misses

The plane's tenant scopes its data keys; each store handle is scoped
separately. When a key ring is wired, `build()` seals case, event, task, memory
and outbox state under the **plane's** tenant while the store writes its rows
under its **own** — and if those two disagree, nothing is wrong in a way
anything can see. Both scopes are real. The run works. The erasure works: it
destroys exactly the key it was asked for, reports success, and does not reach
the rows, because they were sealed under the other scope.

That is the one failure a deletion guarantee may not have, and it was already
solved — for the journal and the blob store, which answer a `tenant()` question
at build so a mismatch is a startup refusal. The other five store traits had no
such accessor, so the same mismatch on those was unaskable. The sealed wrappers
took the tenant as a **second argument beside the store**, with a doc comment
asking the caller to keep two copies of one fact in step.

`CaseStore`, `EventStore`, `TaskStore`, `MemoryStore` and `PushStore` now carry
the same `tenant()` accessor the journal has, defaulting to `default`, and
`try_build` refuses a disagreement with `BuildError::StateStoreTenant` before it
seals anything. The refusal names the store and both tenants. A store that never
overrides the accessor answers `default` and is refused against a non-default
plane — the safe direction, and the reason this catches a wiring mistake rather
than proving isolation.

`build` can only ask that of a store it is *given*. A wrapper an embedder seals
before handing it over reports, from the outside, the tenant it was told to seal
for — which is the plane's, with the disagreement one layer down. So the six
wrappers check the pair where both halves are in hand and refuse at the wrap.
Six tests in this repository were wiring an unscoped store and sealing it for a
named tenant, which is how easy the shape is to write.

### Fixed — a driver attesting a destination it was not told about

`Bedrock::from_client(client, region)` took the region beside the client that
already held one. That region is what `request_profile` puts on the record, and
the profile is effect identity — so a driver built with a `us-east-1` client and
the string `"eu-west-1"` sent every call to Virginia and swore to Ireland, on a
record whose purpose is to be evidence. Nothing could notice: the copy the
journal attests is precisely the copy nothing checks. `BedrockEmbedder` had the
same shape, where the region is half of `revision()` and therefore decides
whether a stored vector belongs to the index being queried.

Both now read the region **from the client** and refuse one that carries none.
The second copy is gone rather than guarded, which is the only fix that cannot
drift back.

Also documented rather than fixed, because the SDK makes it unfixable: Bedrock
is the one model driver with no `egress` allowlist. It is handed a built client
whose endpoint the SDK will not disclose, so the only host it could check is one
derived from the region — which an endpoint override makes a fiction, and a
control that looks like one and is not is worse than an absent one. `core::egress`
now names which drivers ask and says plainly that this one does not.

See [upgrading](https://hupe1980.github.io/agentplane/docs/upgrading/) for each
call-site change.

## [0.17.0] — 2026-08-15

Field feedback from a regulated deployment upgrading 28 specialists, and the
report was right about every symptom and wrong about one cause — which is the
part worth keeping, because the wrong cause would have produced the wrong fix.

### Fixed — a broken policy set is a defect, and says so before it runs

- **`PolicyDecision` gained `Malformed`** (breaking: match arms). *The rules
  say no* and *the rules are broken* call for opposite responses, and 0.16
  already said so — but both were spelled `Deny` and the difference lived
  inside a reason string, so nothing could branch on it without matching
  message text. A deployment whose rules had begun erroring on every request
  read them as ordinary refusals and spent an afternoon looking for the rule
  that fired. The distinction is a variant now: still refused at the gate,
  because an unevaluable rule may be the `forbid` that would have stopped the
  call, but reported as a defect, and the operator API answers 500 rather than
  403.

- **Two gates would have failed open on it.** Both the effect gate and
  admission destructured the decision with `let … else` over `Deny`, so every
  *other* variant took the permit branch — a widened vocabulary opening the
  door it exists to hold. They now name the permit as the arm that passes and
  refuse everything else, which is the shape that cannot rot the next time a
  decision is added.

- **A policy set that cannot answer this plane's questions is refused at
  build.** Cedar evaluates every rule against every request, so a `when`
  clause reading an attribute the request does not carry errors rather than
  failing to match, and one unguarded rule denies every effect of every run
  from a set that parsed cleanly and validated against its schema. That is
  what the deployment hit: rules reading `context.delegation_depth`, written
  when a delegation chain was always configured, on a plane that later ran
  without one. `try_build` now evaluates the compiled set against a canonical
  request of each shape the plane will issue and refuses with
  `BuildError::PolicyUnevaluable`, naming the attribute and the `context has …`
  guard that fixes it.

  Asked through a new `PolicyEngine::preflight`, not by calling `authorize` at
  build: the trap belongs to *total* evaluators, and an engine written as Rust
  code has neither the trap nor anything to say. The default reports nothing.
  The probes carry the delegation attributes exactly when the plane has a
  chain configured — the questions this plane will really ask, not a stricter
  hypothetical, because a boot check that refuses working deployments is one
  people disable.

  The docs were teaching the misconception: the policy reference said an
  absent attribute meant a rule "simply does not match, so it fails closed".
  It errors. The context table now separates always-present attributes from
  conditional ones, and `upgrading` carries the one-operator fix.

### Fixed — a domain separation the type system now enforces

- **A Merkle leaf is its own type.** `leaf_hash` took a `Digest` and returned
  one, and `root` took `Digest`s meaning *already-hashed leaves* — so a caller
  who skipped the call built a tree with no leaf/interior separation, got a
  plausible root, and nothing noticed. The module docs called the prefix "not
  optional" while the signature made it exactly that, which is a contract the
  runtime relies on rather than checks, on a seam published for other people to
  use. (Breaking: `root`, `inclusion_proof`, `consistency_proof` and
  `verify_inclusion` take `LeafHash`.)

  Every caller in this crate was already correct, so no root changed and no
  stored checkpoint moved — this is the mistake becoming unrepresentable rather
  than a bug being fixed. What it prevents is the second-preimage attack the
  prefixes exist for: without them an interior node's preimage can be presented
  as a leaf, and a tree of *n* leaves reinterpreted as a different tree with the
  same root. A `compile_fail` doctest holds the guarantee, and it is on `root`
  rather than in the test module, where rustdoc would never have collected it.

  The tree is now also pinned to RFC 6962 hashes computed by another
  implementation. Checkpoints go to witnesses that verify with somebody else's
  code, so a tree agreeing only with itself is the failure that matters: these
  vectors would catch a prefix change that every other test in the file would
  happily accept.

### Added

- **Operator push destinations can sign their bodies.** Bearer auth proves the
  sender held a token, not that the body is what the sender wrote — and the
  token transits every hop. `Destination::signed_with(header, secret)` adds an
  HMAC-SHA256 over the exact bytes POSTed, as `sha256=<hex>`.

  What it proves: this byte string was written by a holder of the secret and
  arrived unaltered. What it does not: **freshness** — there is no timestamp or
  nonce, so a captured delivery verifies forever, and a receiver must dedup on
  the event's own identity (`RunCompleted` carries CloudEvents' `source`/`id`;
  a custom projection carries whatever the embedder put there); origin to a
  third party, since a shared secret is symmetric; and that a destination was
  signed at all — a receiver has to *require* the header, or an attacker simply
  omits it.

  Breaking: `PushSender::for_operator_destinations` takes the destinations,
  because that is where the keys are — a sender for signed destinations cannot
  be constructed without them, and a missing signature is otherwise visible
  only at the receiver. The signing key deliberately never reaches the push
  store: a caller's bearer token must be persisted (the request that carried it
  is over), while an operator's key is this deployment's own configuration,
  read at every start — persisting it would put a forge-anything key in a row
  per run per destination and freeze rotation at admission.

  Delivered bodies are now canonical (RFC 8785) rather than serde's incidental
  key order, since the signature covers the bytes on the wire and a receiver
  that re-serializes before verifying should get the same ones.

- **`RunOutcome::reason()` and `RunStatus::reason()`.** The terminal reason
  lived inside the variants — a string on `Failed`, a typed `SuspendReason`, a
  typed `BudgetExceeded` — so an embedder mapping outcomes onto a wire type had
  to match all of them, and the lazy path was to read the status and stop. One
  deployment shipped an empty summary on failed runs for a while. Typed
  variants are formatted rather than dropped: an exhaustion names the ceiling
  it hit, which is the whole content of an exhaustion.

### Changed

- **Every optional feature is now linted alone, not merely compiled.** `just
  features` ran `cargo check`, so a lint in a configuration outside `lint`'s
  four curated ones was caught by nothing — a `clippy::unused_self` in the push
  delivery path lived in `push`-without-`testkit` for as long as that
  combination existed. Compiling a feature alone proves it builds; linting it
  alone is what the rest of the codebase is held to.

- **A memory-formation instruction is prose a model reads, and is checked like
  it.** The refusal that stops a declared prompt sending the model after a tool
  it was never granted scanned `identity.role` and `identity.constraints` but
  not `memory_formation.instruction` — the one instruction written for a
  *different* model, which is offered the same grants and goes the same way:
  asks, is refused, improvises, and the extraction quietly does something else.

- **`sha2` moved to 0.11 and `hmac` 0.13 is a direct dependency.** Both were
  already being compiled — `ed25519-dalek` 3.0, `aws-sigv4` and
  `postgres-protocol` pull them — so this crate had been building two hash
  majors and reaching for the older one. The signing code that arrived with
  push destinations was twenty-five hand-written lines of RFC 2104 that passed
  RFC 4231's vectors; passing vectors is the argument for keeping hand-rolled
  crypto and it is not good enough here, because a substrate whose pitch is
  auditability should not ask a reviewer to check a MAC by eye when the audited
  construction is already in the binary. The vectors stayed and now prove the
  crate *uses* it correctly.

  Every effect key, chain link, Merkle leaf and blob address comes out of
  `Digest`, so swapping the hasher underneath had to be shown — not assumed —
  to change nothing. It is now pinned by golden vectors computed with `shasum`
  and Python rather than by running this code and writing down the answer,
  which is a test that would have agreed with itself under any value. The
  design document claimed such vectors existed; they did not.

- **A budget ceiling of zero is refused at parse.** `max_tokens: 0` read like
  "no permission to spend" and did something else entirely: every ceiling is an
  accumulate-and-compare checked *before* the work, so zero refused the first
  effect of any kind — a model-free agent's single read-only tool call
  included. The same holds for `max_effects`, `max_steps`, `max_minor_units`
  and `max_wallclock_secs`; `max_replans: 0` and `max_denials: 0` are
  untouched, because there zero means something a deployment might want. Omit
  the ceiling for "no limit"; use the emergency stop to stop a tenant's work,
  which is the control that says somebody is dealing with an incident rather
  than "not right now".

---

## [0.16.0] — 2026-08-14

Four audit rounds. Recovery gained its initiator, the case layer crossed the
export boundary, and a full-surface audit closed the rest — most of it one
shape repeated: a gate correct on the first pass and absent on the second, a
crash or a resume being the pass nobody re-checked. The fourth round went
looking for what the third had missed and found the same shape one layer
deeper: mechanisms that only run *after* a crash — the orphan arm, the
failure unwind, the wake re-registration — each quietly assuming the
machinery around it had held, plus two erasure-completeness failures and one
leak on the export path. The catalogue gained a shape for it: enforcement
whose only caller is a crash needs its negative test to *be* a crash.

### Fixed — security: what erasure must reach, and what an export may carry

- **An export through a sealed journal carried plaintext.** `SealedJournal`
  hands reads back opened — its job for the runtime, whose steps must read
  what they wrote — and the export copied the opened `body` into the file, so
  destroying a key no longer reached the copy somebody exported last month;
  the verifier then flagged the honest export as tampered, because its
  display half disagreed with its sealed wire bytes. The export now derives
  the display copy from the wire bytes the chain hashed — body-matches-wire
  true by construction, sealed payloads staying sealed — with no fallback to
  the in-memory view: a record whose raw bytes will not parse files the run
  as unreadable rather than exporting the one thing the derivation exists to
  keep out.

- **Cascading erasure missed superseded derivative versions.** Re-deriving a
  rolling summary deleted the derivation edges its earlier version held, so
  forgetting a poisoned source reported success while the superseded summary
  version that absorbed it stayed readable. Derivation edges are now
  per-version on both backends, traversal walks the union, and the cascade
  erases superseded versions whose sources are doomed. Beside it: subject
  erasure on Postgres no longer fails on a page-size conversion (the RTBF
  path was dead on the exact topology the distributed coordinator exists
  for), and the event buffer's copy of an inbound payload — previously
  reachable by no erasure an operator could invoke — is stripped once the
  claimed event's delivered copy is in the journal, with an erasure verb for
  the rows that never delivered.

- **Two payload fields wrote caller-reachable text into the clear.** A
  reconciliation probe's failure detail is a provider echoing the request it
  was asked about — the same class as `EffectFailed.error` — and a group
  settlement's detail names a failing invariant over the caller's values.
  Both now seal, with the routing halves (the disposition, the outcome, the
  Option's presence) staying clear. The sealing decorators for events, tasks
  and push registrations also bind tenant and purpose into their AAD, so two
  attacker-chosen identifiers can no longer manufacture a cross-purpose AAD
  collision.

- **A release's destination is now a control, not a note.** The typed release
  journaled its destination and nothing checked it: after `apply_release` the
  improved label was indistinguishable at every gate from natively trusted
  data, so a value released for one sink passed at every other. Releases now
  ride the label as destination-scoped marks applied at the sink — a value
  released for `tool://ledger/transfer` arrives at `tool://mail/send` exactly
  as untrusted as before the release, and a released value written to memory
  keeps its unreleased labels, because a release is for a destination, not
  for storage. The journal's sensitivity ceiling judges the base label for
  the same reason — a release never lowers what may be written down — and a
  release's `destination` must now be the exact provenance-style identity of
  the sink it is for. Beside it, strict replay of a sink-gate refusal now
  consumes the recorded verdict instead of quarantining the run that
  honestly recorded it. (Breaking: labels carry release marks; eager
  improvement is gone.)

### Fixed — the second pass, one layer deeper

- **Two instances could both hold a run's first lease on Postgres.** The
  first acquisition had nothing to lock — `SELECT … FOR UPDATE` over an
  absent row — so two concurrent first-acquires both computed epoch 1 and the
  loser's upsert overwrote the winner: split-brain under one fence, reachable
  by two workers driving the same batch. Acquisition is now a single guarded
  statement; the race has a live two-instance test that fails on the old
  shape.

- **A resolved orphan's failure skipped the classifier.** Re-performing a
  crashed effect on resume returned its failure directly, bypassing the
  disposition and stop machinery — so a mutating re-performance that timed
  out in doubt read as a plain failure, and the unwind then compensated
  completed steps around a call that may have landed. The re-performance now
  hands its failure back to the ordinary attempt loop, which decides exactly
  as it would live: in-doubt mutating outcomes quarantine, transients retry
  under policy.

- **The failure unwind now takes the same gates as cancellation — exactly
  when it closes the run.** A failure that will compensate something closes
  the run to resume, so it now also refuses to unwind around an unknown
  outcome and extends its list to every step that mutated without completing
  — chiefly the suspended sibling that severity ordering stranded holding a
  landed mutation, whose work otherwise stood forever in a world where
  everything around it was reversed. A failure that compensates nothing keeps
  its resume and takes neither gate, because the resume is what resolves its
  orphans and re-registers its waits. What counts as having mutated is the
  effect's recorded outcome, not its announcement: a call the driver
  classified `DidNotHappen` is not undone, because a compensation for work
  that never landed is the refund for money nobody took.

- **An orphaned wait re-registers on resume.** A crash — or a transient store
  error — between announcing a durable sleep or event wait and registering
  its timer or subscription left a run that suspended forever: no driver, no
  queue naming it, indistinguishable from work in progress. A resume now
  re-arms the timer (the instant is journaled, and arming keeps the first
  registration) and re-walks the wait's registration idempotently, skipping
  only the announcement that provably survived.

- **The wake path hands its lease over instead of releasing it.** A timer or
  event delivery used to record the wake, release its bookkeeping lease, and
  let the resume acquire a fresh one — and a crash between the two left a
  *released* lease over a run whose timer was already disarmed, invisible to
  the abandonment queue, which lists only leases that expired still naming an
  owner. The resume now continues under the wake's own lease, so the run is
  owned continuously from wake to conclusion and a crash anywhere in between
  reaches the queue.

- **A strict pass is now a pure read.** Strict verification released the
  *live owner's* lease on the way out (both stores release on epoch match
  alone, so a regression check could stop a healthy run's heartbeat and
  invite a fence), accrued the historical run's spend into the current
  period on every look, and skipped the fewer-effects check on every
  early-stop path — a build that failed or suspended earlier than the record
  "verified" histories it had only half-read. All three are closed; the
  unconsumed-effects check now runs on every strict conclusion.

- **Tenant spend accrues once.** The run's own budget deliberately re-bills
  replayed history so a resume exhausts where the original did — but the
  period ledger accrued the same figure at every conclusion, so a run that
  suspended N times billed its prefix N times. The ledger now tracks what
  each pass actually dispatched, and settlement accrues only that.

- **One open, one settlement, one conclusion.** Group records and open
  conclusions are not effects, so the cursor could not dedup them: every
  resume of a still-failing run appended another `GroupOpened`, another
  `GroupSettled` and another `RunSealed{failed}`. All three are now read back
  and deduplicated — by count, not by name, so a step that legitimately opens
  and settles the same group name twice keeps both pairs.

- **A batch item at a ceiling reads `exhausted`, not `failed`.** (Breaking:
  `ItemOutcome::Exhausted` is a new non-terminal variant.) Exhaustion is a
  pause everywhere else in the runtime; the batch census filed it as
  terminal failure, teaching operators to re-run items whose work was intact.
  An exhausted item now holds the batch cursor like a suspended one and is
  counted in its own census column.

### Fixed — the wire, the record, and the models that check them

- **Anthropic dropped a reasoning turn whose only answer was a tool call.**
  A thinking block beside a `tool_use` with no sibling text was classified
  unusable before the continuation was assembled, so the next turn re-sent
  without the thinking signature and the provider rejected it. Choosing a
  tool is an answer; the turn now carries its blocks verbatim. (Bedrock's
  ordering was already sound; both drivers now pin it with byte-for-byte
  continuation tests.)

- **The MCP client now negotiates `2026-07-28` explicitly** instead of
  inheriting whatever its dependency defaults to (which had silently become
  the superseded `2025-11-25`), with the version string pinned by a wire
  test so a dependency bump cannot retarget the suite. The
  `InputRequiredResult` refusal — a server that stopped mid-operation to ask
  a question has done an unknown amount of it — gained the negative tests it
  never had, on all three surfaces.

- **Back-pressure on the A2A surface is no longer spelled as a permanent
  refusal.** A tenant at its ceiling answered with the spec's
  missing-operation code — teaching a compliant caller to abandon work that
  would succeed in a minute — and the refusal text leaked quota arithmetic.
  A server-defined code now carries a digit-free message, this crate's own
  client reads it as a retryable refusal, and a test drives the quota path
  through the wire.

- **The offline verifier stopped believing its own trailer.** A run block
  with zero records verified as sound, an honestly-declared unreadable run
  was reported as tampering, and only one of the trailer's counts was ever
  compared — so deleting an open run's tail records verified clean. Every
  count is now settled against what was read, empty blocks are findings,
  declared-unreadable runs land in `not_checked`, restore refuses a file cut
  short or a line without wire bytes, and the audit states its sampling
  scope and reports an empty run as unchecked rather than sound. The
  case-layer drill gained a CLI verb (`agentplane drill`) that fails only on
  loss — erased-by-design stays informative — and says when sealed-state
  coverage could not be established at all.

- **The formal models lost their unreachable endings and their untested
  verb.** Authorization's "done" state was unreachable under the shipped
  constants — a model verifying that every run is denied — and Fencing
  accepted epoch-zero writes from two instances while carrying no `Renew`
  action at all, leaving the settled renew-versus-acquire split unverifiable.
  Both are fixed with TLC runs, new mutants mapped to the Rust tests that
  kill them, prefix-equality append-only properties, and explicit liveness
  assumptions; the spec README's state counts now come from the harness that
  derives them.

### Changed — smaller cuts with a reason

- `RuntimeBuilder::lease_ttl` no longer panics in the setter: a sub-2-second
  lease is refused at `build`/`try_build` as `BuildError::LeaseUnrenewable`,
  so a plane assembled from runtime input reports it as a diagnostic instead
  of aborting the process. The stores refuse sub-second TTLs themselves now
  rather than silently clamping — boundary enforcement for embedders that
  never pass through this builder.
- Task re-claim by the current holder is idempotent success on both backends
  (Postgres refused its own holder), the task queue serves priority before
  age on both (Postgres ordered by age alone, so an urgent task behind older
  normal ones was absent from the page), and purpose-less memory recall
  follows one selection rule everywhere — most trusted rank first, newest
  within a rank — where the backends previously disagreed about which facts
  fill a bounded recall.
- `Release::fields`/`evidence` and `Tainted::object` take `impl
  Into<String>`, deleting the `.to_owned()` noise from the first snippets a
  reader copies; the README quickstart's example commands are now guarded
  against the features they require, and the feature-table guard checks both
  directions.
- An advertisement that outgrows its operator grant is warned about where it
  is observed, instead of being visible only to code that asks.
- **`StepCtx::sink_with` accepts the fallible builder it was written for.**
  `StepError` gained `Tool`, the conversion the trait behind `sink_with`
  needs to take a `Result` — so the guides' own shape, handing back the
  `Result` that `ToolCall::prepare` already produces, compiles. It had never
  compiled: the trait's fallible arm was a capability with no conversion
  behind it, every caller in the crate passed an infallible builder, and the
  published snippet that teaches the shape was the only thing exercising it.
  A refusal there fails the step, because the catalogue is consulted before
  anything leaves.

### Fixed — security: the second pass is the same run as the first

- **Resume enforces every gate on its live tail.** A resumed run is a live run
  from its frontier on, and the tail past the recorded prefix ran under fewer
  gates than the first attempt: the egress and sensitivity ceilings, the
  mutates strengthening on tool grants, the delegation depth and the step
  budget were applied live and not on resume — so a crash *removed controls*,
  and the run that finished was not the run that was admitted. The resume tail
  now dispatches through the same gate stack, and manifest-sink and delegation
  refusals are journaled as `PolicyDenied` under the key the refused dispatch
  would have carried, so a strict or resumed pass consumes the refusal instead
  of re-deciding a verdict that is already history.

- **The lease protocol split: `acquire` claims, `renew` extends** (breaking:
  `JournalStore::renew` is a required method; same-owner re-acquire of a held
  lease is now an error). `acquire` used to renew for the same owner, and two
  failures hid in the convenience. A heartbeat racing its own run's conclusion
  could re-take the lease the conclusion had just *released* — a concluded run
  with a live lease, which the recovery sweep then "recovers" forever. And a
  second entry point on the same instance — a cancel, a delivery — could
  "acquire" a run mid-execution and drive a second execution under the **same
  epoch**, the split-brain fencing exists to prevent and cannot see. `acquire`
  is now a pure claim that always bumps the epoch and refuses a held lease
  even from its own holder; heartbeats call `renew`, which succeeds only for
  the exact `(owner, epoch)` and keeps it. Beside it: cancelling a live run is
  acknowledged and observed at the next step boundary, and the claimed-event/
  lease race — a delivery dying between claim and resume — is finished by a
  new sweep pass, reported as `SweepReport.events_redelivered`.

- **Cedar fails closed on evaluation errors.** Cedar is total: a `when` clause
  reading an attribute that does not exist makes the rule silently vanish, and
  an `Allow` could arrive with evaluation errors beside it — a policy set that
  was *broken*, reported as permission. An `Allow` accompanied by evaluation
  errors is now a denial, reported as malformed rather than as a refusal,
  because "the rules say no" and "the rules are broken" call for opposite
  responses.

- **Exhaustion pauses instead of unwinding.** Unwinding on exhaustion made the
  three ends of an exhausted run contradict each other: the work was reversed,
  the run stayed resumable, and the resume then reported success over a world
  where the work no longer stood. An exhausted run's mutations now stand,
  because the operator's two honest options both need them standing: raise the
  ceiling and resume — the resume re-evaluates the recorded budget refusal
  against the current ledger and journals **`BudgetReadmitted`** (new record)
  naming the ceiling it continued under — or cancel, which unwinds. One door
  closes with it: a run that has already compensated is closed to resume, with
  "start a fresh run" as the refusal, because continuing over reversed work
  would report success about a world where it no longer stands.

- **Doubt is terminal for retries and opaque to cancellation.** A mutating
  effect whose retries end `InDoubt` quarantines the run rather than failing
  it — a failure invites the unwind, and compensating a call that may have
  landed is a reversal for work nobody can account for. Cancellation obeys the
  same rule from the other direction: it refuses to unwind through recorded
  doubt.

- **Strict replay fails on effects the build never requested.** A build that
  asked for *fewer* effects than history holds used to pass strict — the
  verification checked what ran, not what remained — so a deleted step read as
  a verified history. Strict now fails naming the first unconsumed key.

- **Admission and its error paths clean up after themselves.** A refused
  admission used to leak its lease and its quota slot, throttling the tenant
  on ghosts; both are released now. The sweeper writes each decision durably
  before applying it; a census failure degrades the metrics report instead of
  discarding it; strict replay no longer writes deadline registrations; and a
  resume acquires the lease *before* reading history — reading first raced the
  owner it was about to fence — and no longer duplicates `StepFinished`
  records.

- **A declarative tool loop honours `spec.output.schema` on every turn** and
  validates the settled answer. Which turn answers is the model's choice, so a
  schema attached only where the runtime guessed the answer would land is a
  contract the model can step around by answering a turn early.

- **Three decorative-control shapes are refused at parse.** A mutating grant
  needs at least one protected field carrying a trust or source rule — a
  ceiling-only field bounds how *secret* an argument may be, not who authored
  it, so the model's untrusted completion filled every authority-bearing field
  unconstrained. `oversight.approval: tools-only` requires every mutating
  grant to declare `requires_approval` — a mode that gates tool calls while
  the transfer beside them runs unattended is a declared control nothing
  enforces. And the quarantined role's `max_tokens`/`reasoning_effort` are now
  enforced on every call the role serves (`ModelRole`) rather than parsed and
  dropped.

- **A completion's label floor is its egress ceiling.** A caller who raised
  `max_sensitivity` to show the model a confidential prompt has said what
  class of data the answer derives from, and a completion labelled below its
  own prompt is a laundering primitive — ask the model to restate the secret
  and read it back a level down. The output sensitivity floor now derives from
  the ceiling, and streamed labels never dip below the terminal floor.

### Fixed — storage and sealing

- **Postgres, correctness pass**: seal is fenced and transactional;
  `match_waiter` locks the subscription row; a task claim's CAS checks state;
  batches cannot span runs; the sweep cutoff is `<=` (an obligation due *at*
  the tick was invisible to it); dead letters carry their correlation keys;
  a write against a missing row returns `NotFound` instead of succeeding over
  nothing; unique violations are classified by constraint; new indexes and
  `CHECK` constraints. And a URL demanding TLS (`sslmode=require` or stricter)
  is **refused rather than silently downgraded** to plaintext — libpq's
  `sslmode` is a gradation, not a switch, and the module doc now lays out the
  shapes that need no connector and the sidecar answer for the one that does.

- **Memory lifecycle**: an expired item keeps its derivation edges, so an
  erasure cascade routes *through* the tombstone instead of stopping at it —
  summaries of an expired source were unreachable exactly when the request
  mattered. The Postgres expiry sweep takes the graph lock. And sliding
  retention opens its window at the write, with `expires_at` a hard ceiling
  (`min`, not `max`) — an untouched item now expires instead of outliving the
  bound its declaration promised.

- **The journal's sealed set widened, and the envelope binds identity.**
  Sealed: `RunAdmitted.input`, `EffectStarted.descriptor.args`,
  `EffectDone.output`, `EffectReconciled.output`, `EffectFailed.error` (the
  message only), `Note.text`, `PlanFrozen.plan`. The last four were caller
  data in the clear beside sealed prompts — a reconciliation probe's output is
  the same data an `EffectDone`'s is, and a frozen plan embeds the trusted
  input it was compiled from. AAD binds tenant and record identity, so
  ciphertext moved to another record fails to authenticate. `blob::erase_run`
  is the erasure verb for case-less runs (sealed under `tenant/<run>`), and
  push webhook credentials seal at rest — `SealedPush`, wrapped automatically
  by `RuntimeBuilder::keyring`.

- **`agentplane audit` binds the verified chain head to the Merkle leaf.** A
  truncated-but-internally-consistent prefix of a sealed run verified: the
  prefix's chain passes on its own, and the log's genuine leaf passes against
  the genuine tree — two halves of two different claims. The leaf is now held
  to the recomputed head before the tree math, and a mismatch is a finding:
  the served history is not the one the checkpoint commits to.

### Fixed — wire

- **Push delivery filters ownership in the store query** and reports foreign
  backlog as `unserved` — visibility for the operator, instead of a worker
  paging past registrations it will never serve. `A2aPushWorker` is now a type
  alias of `push::DeliveryWorker`.
- **Peer failures are honest about what is known**: HTTP 5xx and unknown RPC
  errors are `PeerError::InDoubt` — "the outcome is unknown" — and `TimedOut`
  means a timeout, nothing else. Mapping a 5xx to a retryable failure is how a
  peer's half-applied task gets a second application.
- **A2A**: `CancelTask` carries `contextId`; `ListTasks` artifact inclusion is
  budgeted, with tasks past the budget marked
  `io.agentplane.a2a/artifactsOmitted` and a sealed-run cache so the
  reassembly is not paid twice; peer provenance is `peer:{actor}` everywhere,
  one spelling for every path a peer's data enters.
- **Media ingest fails loudly on a blob store returning a foreign digest** —
  trusting the store's answer would journal an address whose bytes are
  somebody else's. Bracketed IPv6 literals now work, judged by the address
  policy rather than dying in DNS resolution.

### Changed — DX, breaking, each with its one-line migration

- **`Effect::source()` names the concrete source**: `tool://{server}/{name}`,
  `model:{provider}/{model}`, `agent/{capability}`. The family spellings no
  longer match — rewrite `allowed_sources: [effect:model.complete]` as the
  concrete identity, e.g. `model:anthropic/claude-sonnet-5`.
- **`cx.sink_with(&args, |v| Effect::new(.., v))` is the dispatch shape** —
  move the effect's construction into the closure and delete the
  `.peek().clone()`; two-arg `sink` remains for effects binding their outbound
  value internally.
- **`Runtime::builder_on(store)`** wires all six stores of a `FullBackend` in
  one call — replace the six-cast chain.
- **`SkillDescriptor::provides` defaults to the skill name** — delete
  `.provides(x)` wherever `x` is the name; keep it where the capability
  genuinely differs (declaring replaces the default, it does not add).
- **The prelude re-exports `async_trait`** — drop the `cargo add async-trait`
  step; `use agentplane::prelude::*` is enough.
- **`RunOutcome::success() -> Result<Tainted<Value>, RunFailure>`** — replace
  the status match with `.success()?` where anything short of an answer is an
  error.
- **`cx.complete(prompt)` / `complete_with`** — a manifest-governed skill uses
  the declaration's model through the plane's registry; delete the
  `Arc<dyn ModelProvider>` field from the skill struct.
- **Tool wire names render `.` as `-`** (`agent__blog-research`), and `-` or
  `__` inside a tool/server component is refused at declaration — rename the
  component; fixtures asserting the old wire spelling need the new one.
- **CLI**: `replay <run-id> --store <db> --manifest <file> [--strict]`
  replaces `run --replay/--strict`; `run --input -` reads stdin; new
  `card <manifest> --url <base>` prints the derived Agent Card.

### Changed — the version hard cut

- **`export::FORMAT_VERSION` and `canon::VERSION` are both 1.** The case-layer
  export below landed as "format 2", and the numbers were starting to tell a
  version story for a format nobody has frozen — pre-freeze, the standing
  policy is a hard cut, and a version sequence implies a compatibility promise
  this stage deliberately does not make. The constants collapsed back to 1;
  the entry below keeps its name because that is what the change was called
  when it landed, and the case lines are simply part of format 1.
  `RunAdmitted.canon` is required rather than defaulted, and an export carries
  each record's **raw wire bytes** — verification rehashes those, holding the
  file to the writer's bytes rather than to this build's re-serialization.

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

### Added — `Runtime::drill`, the live half of the case-layer drill

- **The two questions no exported file can answer, answered where they live.**
  `Runtime::drill` walks every case with the plane's own stores: each blob
  digest is **read and re-hashed** (`get`, never `has` — presence without
  integrity passes over altered bytes), and sealed case state is **proven to
  open** with the plaintext dropped on the spot, so the probe cannot become a
  decryption oracle.

  **The three-way verdict is the point.** Intact; *erased by design* — a
  tombstone or a destroyed key is retention reporting itself, counted and
  never a finding; and lost — bytes gone with no tombstone, bytes altered, or
  sealed state that neither opens nor was destroyed. Only the third pages
  anyone, because a drill that alarms on erasure teaches operators that
  findings are noise, which is how a real loss gets ignored six months later.
  A store the drill was not given is `not_checked`, not silently passed.

  On `Runtime` rather than only the free `drill::drill`, so it runs against
  the stores the runs actually used — a hand-wired drill can pass over the
  wrong bucket. `keyring::probe_sealed_case_state` is the new probe seam,
  beside `SealedCases` because the AAD rule is that decorator's own.

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

### Assurance — the first-contact surface, executed rather than read

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
  of four.** The catalogued yields-under-load shape, on the tenant-isolation control
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

### Assurance — the push outbox and the card signatures, adversarially

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

### Assurance — the label lattice, adversarially

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
  message that arrived in time, lost anyway, in the failure mode the worklist exists
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
  imprecision the oversight model warns about — and now state the pair and the reason.

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
  witness proofs are tenant-scoped and the operations table said so four lines
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

### Assurance

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
