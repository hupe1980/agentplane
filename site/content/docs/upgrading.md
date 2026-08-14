+++
title = "Upgrading"
description = "What breaks between pre-alpha releases, why, and the shortest correct fix for each."
weight = 11
+++

Pre-alpha means hard cuts rather than deprecation cycles, and a manifest or a
call site that stops working is the intended way to find out. What this page owes
you is the *reason* and the shortest correct fix — a refusal you have to reverse
engineer costs an afternoon, which is one afternoon more than the change saved.

Every entry here is a **parse-time, build-time or replay-time** refusal. None
of them changes what a running agent does silently, which is the property that
makes a hard cut acceptable at this stage.

---

## A source rule names the concrete source, not an effect family

An effect's output now carries the identity an operator actually grants as its
provenance: a tool call answers as `tool://server/name`, a model completion as
`model:{provider}/{model}`, a commission as `agent/{capability}`. The old
family spellings — `effect:tool.call`, `effect:model.complete` — are what
`Effect::source` still says for effects nobody writes source rules about (the
clock, a case read), and they **no longer match** anything a tool, model or
commission produces.

```yaml
# before — satisfied by whichever tool an injected prompt reached first
- path: /correction
  allowed_sources: [effect:model.complete]

# after — the rule can finally say what it meant
- path: /correction
  allowed_sources: [model:anthropic/claude-sonnet-5]
```

**Why it is worth your manifests.** A family is too coarse for the one rule
that matters. "The recipient must come from the CRM lookup" was unsatisfiable
strictly — every granted tool answered as `effect:tool.call` — and satisfiable
loosely by whichever tool an injected prompt reached first, which is the
opposite of what the rule was written to prevent. A rule naming the old
spelling now refuses every argument it governs, so the failure is loud rather
than permissive: rewrite it against the concrete source.

---

## `JournalStore::acquire` is a pure claim; renewal is `renew`

`JournalStore` gained `renew(run, owner, epoch, ttl)`, so a store you implement
stops compiling until it distinguishes the two. And `acquire` no longer renews
for the same owner: a lease that is currently held and unexpired is refused
with `LeaseHeld`, **including when the caller itself is the holder**.

**Why the convenience had to go.** Two failures hid in acquire-as-renew. A
heartbeat racing its own run's conclusion could re-acquire the lease the
conclusion had just *released*, leaving a live, never-released lease over a
concluded run — which the recovery sweep then "recovers" forever. And a second
entry point on the same instance — a cancel, a delivery — could "acquire" the
lease of a run the instance was actively executing and drive a second execution
under the **same epoch**, which fencing exists to make impossible and cannot
see. `renew` succeeds only on a lease held, unexpired and unreleased by exactly
`(owner, epoch)`, and keeps the epoch — bumping it would fence the owner
against its own in-flight writes. A failed renewal means *stop*: the caller no
longer owns the run.

If you implement the trait, the store conformance battery covers both methods;
run it rather than eyeballing the transaction boundaries — checked-and-written
must be one store transaction, or a lapse between read and write renews over
the new owner.

---

## Exhaustion pauses; it no longer unwinds

A run that hits a declared budget keeps its completed work standing. It used to
unwind, and the three ends of an exhausted run contradicted each other: the
work was reversed, the run stayed resumable, and the resume then reported
success over a world where the work no longer stood.

The operator's two honest options both need the work standing. **Raise the
ceiling and resume** — the resume re-evaluates the recorded budget refusal
against the current ledger and journals a `BudgetReadmitted` record naming the
ceiling it continued under, so "who raised what to let this continue" is
answerable from the chain. Or **cancel**, which unwinds through the same path a
failure does.

One door closes with it: a run that has already **compensated** is closed to
resume, because continuing over reversed work would report success about a
world where it no longer stands. Start a fresh run.

---

## Tool wire names render dots as `-`, and refuse what would collide

How a model names a tool is `server__tool`, with `.` in a component rendered as
`-`: the grant `tool://agent/blog.research` reaches the model as
`agent__blog-research`. To keep that mapping invertible, a tool or server
component containing `-` or `__`, or starting or ending with `_`, is **refused
at declaration**.

**Why.** The separator has to be recognisable in reverse — the name the model
picks is matched byte for byte and mapped back to the grant — and a component
that may itself contain `-` or `__` makes one wire name ambiguous between two
grants. If a declared name stops parsing, rename the component; fixtures and
transcripts asserting the old spelling need the new one.

---

## `cx.sink_with` is the dispatch shape; the two-pass spelling is gone from the docs

```rust
// before — the same data written twice, held together by a runtime check
let call = ModelCall::new(provider, model, prompt.peek().clone());
let answer = cx.sink(call, &prompt).await?;

// after — the closure receives the inner value; one argument, not two
let answer = cx
    .sink_with(&prompt, |value| ModelCall::new(provider, model, value))
    .await?;
```

Fallible construction composes — the closure may return a `Result`, which is
what `ToolCall::prepare` needs. The two-arg `sink` remains for effects that
bind their outbound value internally (a governed media fetch derives its bound
arguments from the URL it was constructed over) and for callers holding an
effect built elsewhere; the byte-for-byte binding check runs underneath either
way.

Two smaller cuts travel with it, both removing boilerplate rather than
breaking code. The prelude now re-exports `async_trait`, so `cargo add
async-trait` is no longer part of writing a skill. And a skill governed by a
manifest calls `cx.complete(&prompt)` (or `complete_with` to adjust the call):
the privileged role supplies the model and its reviewed ceilings, the plane
supplies the driver — no more `Arc<dyn ModelProvider>` field carrying wiring
the manifest never described.

---

## A skill's name is its capability unless it says otherwise

`SkillDescriptor::provides` is now a default rather than an obligation: a skill
that declares nothing answers its own name. Declaring a capability **replaces**
the default rather than adding to it, so a skill that provides `demo.greet` is
not also silently reachable as `greet` — one declared surface, not two.

The name/capability split earns its keep in a plan graph, where one skill
answers an abstract capability another step names; a hello-world program should
not have to invent two names for one thing. Keep `.provides(..)` exactly where
the two genuinely differ.

---

## `Runtime::builder_on` wires a full backend in one call

```rust
// before — six casts of one Arc, spelled out by every deployment
Runtime::builder(store.clone() as Arc<dyn JournalStore>)
    .cases(store.clone() as Arc<dyn CaseStore>)
    .tasks(store.clone() as Arc<dyn TaskStore>)
    // ... events, timers, memory ...

// after
Runtime::builder_on(store)
```

Any backend implementing the six store traits — both shipped ones do — is a
`FullBackend`. The à-la-carte methods remain and override individual stores
afterwards; blob storage stays an explicit `.blobs(..)` decision, because bytes
routinely live in a different system than rows.

---

## `RunOutcome::success()` folds the two questions into one `?`

```rust
let answer = runtime.run("greet", input).await?.success()?;
```

Every caller acting on a run's answer asks the same pair — did it work, and
what did it say — and pattern-matching `status` to learn the first is how the
second gets read off a run that quarantined. `success()` returns
`Result<Tainted<Value>, RunFailure>`; the failure carries the run id and the
whole `RunStatus`, so telling a suspension from a quarantine later needs no
re-plumbing. `status` and `output` stay public for callers whose branches
genuinely differ.

---

## The CLI grew a `replay` verb, and `run` lost the flags that belonged to it

```sh
# before
agentplane run agent.yaml --replay 01J… --strict

# after — a recorded run is its own verb
agentplane replay 01J… --store runs.redb --manifest agent.yaml --strict
```

Re-executing a recorded run needs a store and takes a run id, not an input —
almost nothing `run` needs, which is why the flags kept failing to parse in
combinations the help text could not explain. Two additions beside it:
`run --input -` reads stdin, and `agentplane card <manifest> --url <base>`
prints the Agent Card a served manifest would advertise, so what a peer will
see is reviewable before anything listens on a socket.

---

## The journal's sealed set widened, and the envelope binds identity

What `.keyring(..)` seals in the journal is now: `RunAdmitted.input`,
`EffectStarted.descriptor.args`, `EffectDone.output`,
`EffectReconciled.output`, `EffectFailed.error` (the message only),
`Note.text` and `PlanFrozen.plan`. The last four were caller data sitting in
the clear beside sealed prompts — a reconciliation probe's output is the same
data `EffectDone.output` is, a note is prose somebody wrote about the case, and
a frozen plan embeds the trusted input it was compiled from. The envelope's
associated data now binds the **tenant and the record's identity**, so
ciphertext moved to another record fails to authenticate rather than opening as
somebody else's payload.

Two neighbours of the same cut: `blob::erase_run` erases a **case-less** run's
sealed payloads — the erasure unit is the run, since a run with no case links
no blobs through the case layer — and push webhook credentials now seal at
rest (`SealedPush`, wrapped automatically by `RuntimeBuilder::keyring`).

Stores sealed by an earlier build no longer open under this one; the pre-freeze
remedy is the standing one — recreate the store, or keep the old build to read
the old history. Verification is unaffected either way: the chain commits to
ciphertext.

---

## `memory_formation.subject` may be a binding, and a `$` typo is now refused

Existing literals are unchanged. What changed is that a subject beginning with
`$` is parsed rather than taken as a constant, so an unrecognised binding is a
**parse error**:

```text
'$correlaton/malo' is not a binding this crate understands. Use
'$correlation/<namespace>', '$case', '$input/<pointer>', or write '$$' for a
literal that really begins with a dollar sign
```

A literal that genuinely begins with `$` is now spelled `$$`.

**Why it is worth a hard cut.** A subject is the unit `forget_subject` erases. A
literal one pools every party the agent reasoned about under a single key, so one
party's facts are recalled into another's run and an erasure request naming one
person cannot be satisfied without destroying everybody's. Filing memories under
a *typo* is the same defect with a worse cause, and it is invisible until
somebody asks to be forgotten — so an unrecognised binding is refused rather than
stored.

The shortest fix for a per-party agent:

```yaml
memory_formation:
  subject: "$correlation/malo"   # was: "agent:clearing"
```

Two build-time refusals arrive with it, both of facts knowable at `build`:
`FormationWithoutMemory` (formation runs *after* the answer, so a missing memory
store fails once the run has already paid for its model calls) and
`MemorySubjectUnbindable` (a case-bound subject on a plane with no case store
could never resolve).

---

## `spec.oversight.approval` gained `none`, and a block that does nothing is refused

`approval: none` with an empty `triage` and no grant asking for approval is now
**refused at parse**. Nothing had that shape before — `approval` was required and
had only two values — so this breaks nothing that parsed; it is stated here
because the new value makes the shape expressible.

The value exists for agents that **cannot act**: a `tool-calling` agent granting
no mutating tool is advisory by construction, and for those `tools-only` gates
nothing while `required` suspends every run until somebody approves a report. See
[`spec.oversight.triage`](@/docs/manifest.md#spec-oversight-triage).

---

## A prompt may not name a tool the agent was not granted

Any `tool://server/name` written in `spec.identity.role` or `constraints` must be
a tool `spec.tools` grants, or the manifest is **refused at parse**.

**Why.** An ungranted name comes back to the model as a *failed call*, which is
right — the model can correct itself and never gets the tool it nearly named.
The cost is that a **procedure** naming an ungranted tool fails quietly: the
model asks, is refused, improvises, and the step silently does not happen with
nothing in the journal saying the instruction was unfollowable. One deployment
found twelve such instructions across eleven manifests.

The check only sees references spelled as references — prose naming a tool by
bare identifier is indistinguishable from an ordinary noun — and it does not
exempt illustrative ones: a prompt containing the literal text
`tool://server/name` as a placeholder is refused. The trade is one-sided, since a
false positive is a parse error naming the exact string.

---

## Timestamps on a wire are RFC 3339

`MemoryItem::{created_at, expires_at, superseded_at}` and `Recall::as_of` now
serialise as RFC 3339 strings rather than `time`'s **component array**, and the
`memory.remember`, `memory.touch`, `memory.sweep-expired` and `authority.draw`
effect descriptors do the same. Stored memories and journals written by an
earlier build no longer deserialise; recreate them, per the standing pre-freeze
remedy.

**The hazard, because `Timestamp` is public API and lands in your payloads too.**
It is a re-export of `time::OffsetDateTime`, whose *derived* `Serialize` — absent
the `serde-human-readable` feature, which this crate does not enable — emits nine
numbers:

```text
[2027, 15, 8, 0, 0, 0, 0, 0, 0]
 year  ordinal-day  h  m  s  ns  offset-h  offset-m  offset-s
```

It parses, it round-trips, and every consumer expecting a date gets an array
whose first element looks like a year. A model asked to do arithmetic on one
answers confidently and wrongly.

Use `#[serde(with = "time::serde::rfc3339")]` on a struct field, and
`agentplane::core::format_timestamp` inside a `json!` literal. `tests/guards`
walks the crate's serialized types and fails on a component array, so this is now
enforced rather than remembered.

---

## `PushSweepReport` moved to `agentplane::push`

The delivery loop — read past the cursor, POST, advance on 2xx, back off, abandon
a permanent refusal — is now `push::DeliveryWorker`, parameterised by a
`Projection`. `A2aPushWorker` is now a type alias of `push::DeliveryWorker`, so
existing call sites keep compiling; `api::a2a::PushSweepReport` is a re-export.

It moved because the cursor discipline has nothing to do with A2A. It lived
inside the A2A server because A2A was the first caller, which made the one
mechanism an operator most wants reachable only by speaking somebody else's
protocol and only for a caller-supplied URL. See
[emit an event per run](@/docs/cookbook.md#outbox-tray-emit-an-event-per-run-without-an-outbox-table).

---

## Canonicalization and format versions collapse to 1

The canonicalization rule (`canon::VERSION`) and the export format
(`export::FORMAT_VERSION`) are now both **1**, and the `canon` field on
`RunAdmitted` is required rather than defaulted. The numbers that used to sit
there were a version history for a format nobody had frozen — pre-freeze, a
hard cut is the standing policy, and a version story implies a compatibility
promise this stage deliberately does not make.

The rule itself is unchanged: RFC 8785 — UTF-16 key ordering and ECMAScript
number formatting (`1e30` → `"1e+30"`, `100.0` → `"100"`), with integers
outside ±2⁵³ refused at card signing because JCS reads every number as a
double and past that line two distinct integers share one byte string.

A store written by an earlier build still opens and its history still verifies
— the chain hashes stored bytes, not re-canonicalized ones — but **replaying a
run recorded under another rule number refuses** with
`CanonicalizationChanged`: unverifiable by this build, which is a different
sentence from *diverged*. The pre-freeze remedy is the standing one: recreate
the store, or keep the old build to read the old history. Exports from
earlier builds are likewise refused by `verify`/`restore`, which name the
version they cannot read. An export now carries each record's **raw wire
bytes** — the exact bytes the chain hashed — and verification rehashes those
rather than re-serializing, so a file is held to the writer's bytes instead of
to this build's idea of them.

---

## `recent_runs` is a bounded page

`JournalStore::recent_runs` takes a cursor and a limit, so a store you implement
yourself stops compiling until it pages.

```rust
// before — every run the tenant ever wrote, in one Vec
async fn recent_runs(&self) -> Result<Vec<(RunId, u64)>, StoreError>;

// after — a cursored page in a total order: (updated_at, run) descending
async fn recent_runs(
    &self,
    after: Option<(u64, RunId)>,
    limit: usize,
) -> Result<Vec<(RunId, u64)>, StoreError>;
```

**Why it is worth your impl block.** The unbounded form cost O(every record the
tenant had ever written) on a listing any authenticated peer could request
repeatedly, and the signature was the cause: it offered nothing to bound with,
so the caller could not have done better. The tie-break is part of the contract
— both shipped backends keep whole-second timestamps, so ties are ordinary
rather than exotic, and a cursor landing mid-tie would drop or duplicate a row.
The store conformance battery checks the order and the page boundary; run it
against your backend rather than eyeballing the sort.

---

## A mutating grant must name its protected fields

A `tool-calling` agent whose grant declares `mutates: true` and no
`protected_fields` no longer parses.

```yaml
# before — parsed, and could never dispatch
- ref: tool://ledger/post
  mutates: true
  description: Post an amount to an account.

# after — the authority-bearing argument is named
- ref: tool://ledger/post
  mutates: true
  description: Post an amount to an account.
  protected_fields:
    - path: /account
      require_trusted: true
```

**Why it is worth your manifests.** The grant could not fire. A model completion
is untrusted unconditionally, the tool loop builds a call's arguments from it,
and a mutating sink with no field rules refuses an untrusted argument bundle
outright — so every such call was refused, and the run **succeeded having done
nothing the model asked for**. One evaluation had 108 of these across 27
manifests, each reading to a reviewer as a live capability with a human in front
of it.

Three fixes and the refusal names all three. Declaring the fields is the one to
reach for first: it is what makes the call reachable *and* governed, with
ordinary untrusted content sitting beside the protected selector. Otherwise move
to `execution.kind: planned`, whose step arguments are resolved by the runtime
from `$input/…` references and keep the input's labels, or set `mutates: false`
if the call really does not change anything.

If you had an approval on such a grant, this also removes the worse case: the
task opened with the exact arguments, a named human approved it, and the taint
gate refused afterwards.

---

## Oversight needs a plane that can ask somebody

An agent declaring `spec.oversight`, or any grant with `requires_approval: true`,
now refuses the build unless the runtime has a case store, a worklist and timers.

```rust
Runtime::builder(store)
    .cases(cases)
    .tasks(tasks)
    .timers(timers)   // ← all three, or the build says which is missing
    .agent(Agent::new(&manifest))
    .build();
```

(`Runtime::builder_on(store)` wires all of them to one backend in a single
call, which is what a deployment on one `RedbStore` or `PostgresStore` means
anyway.)

**Why it is worth the wiring.** It built cleanly before, and failed at the first
real approval — with a person already waiting, on the code path a test suite is
least likely to reach.

One half a build cannot check, so it is here instead: a run admitted through
plain `run(..)` belongs to no case, and nothing on a case-less run can ask a
human or register a deadline whatever its manifest says. Use `run_correlated(..)`
or `run_in_case(..)`.

---

## Durations on the public surface are `std::time::Duration`

`StepCtx::deadline`'s `warn_before`, `Runtime::sweep_events`'s `grace` and
`Runtime::sweep`'s `event_grace` took `time::Duration`, from the `time` crate,
while `StepCtx::sleep` took the standard one.

```rust
// before
cx.deadline("aperak", &DeadlineSpec::days(1), Some(time::Duration::hours(1))).await?;
rt.sweep(now, time::Duration::hours(1)).await?;

// after
use std::time::Duration;
cx.deadline("aperak", &DeadlineSpec::days(1), Some(Duration::from_secs(3600))).await?;
rt.sweep(now, Duration::from_secs(3600)).await?;
```

**Why it is worth your call sites.** Two of them. The surface had two types
spelled `Duration`, and only one came from a crate this one re-exports — so a
caller with the obvious `use std::time::Duration` met a type error naming a
dependency no guide mentions, and had to add `time` at a version that matched
this crate's. And `time::Duration` is **signed**: a negative `warn_before`
compiled and put the warning *after* the instant it warns about, which is a
warning that can only fire once the obligation is already breached. A quantity
that only makes sense non-negative is an unsigned type here, as money already
is.

`Duration::from_hours` and `from_days` are still unstable on the declared MSRV,
so spell hours and days in seconds — `from_secs(3600)`, `from_secs(86_400)`.

`DeadlineSpec::minutes` now exists beside `hours` and `days`. The built-in
`WallClock` always resolved `"minutes"`; nothing spelled it, which is where an
application and a calendar adapter start disagreeing about whether the kind is
`"minutes"`, `"minute"` or `"mins"`.

---

## Admission takes a label, not a bare value

`Runtime::run` and its siblings took a `serde_json::Value` and admitted it as
**`Trusted`**. That is right for a literal an operator wrote and silently wrong
for a plane whose runs are started by inbound events.

```rust
// before
rt.run("claim.assess", json!({ "id": "CLM-9" })).await?;

// after — the operator's own literal, vouched for
rt.run("claim.assess", Tainted::trusted(json!({ "id": "CLM-9" }))).await?;

// after — a payload that arrived from outside, kept honest
rt.run("claim.assess", inbound).await?;
```

**Why it is worth your call sites.** A deployment whose runs came from inbound
events passed counterparty data straight in, and three controls went quiet at
once: `require_trusted` protected fields were satisfied by attacker-chosen
values, the egress ceiling had nothing untrusted to join with, and the journal
recorded no contact with outside data. Nothing failed and its suite stayed green.

The renames that came with it, because the old names were a trap of their own:

| before | after |
|---|---|
| `run(target, Value)` | `run(target, Tainted<Value>)` |
| `run_tainted(..)` | *gone* — `run` is the tainted door |
| `run_in_case(target, .., kind, keys)` — **correlated** | `run_correlated(..)` |
| `run_tainted_in_case(target, .., CaseId)` | `run_in_case(..)` — *this exact case* |
| `run_tainted_correlated(..)` | `run_correlated(..)` |
| `run_plan(plan, Value)` | `run_plan(plan, Tainted<Value>)` |
| `run_plan_in_case(..)` | `run_plan_correlated(..)` |
| `spawn_tainted_in_case` / `spawn_tainted_correlated` | `spawn_in_case` / `spawn_correlated` |

Eleven doors became eight. A `run_trusted`/`run_tainted` pair was tried first and
rejected: it doubles every shape, puts `run_trusted_in_case` one word from
`run_tainted_in_case`, and still lets `run_trusted(cap, payload)` compile over
data nobody vouched for. A label is a **value** — it can be computed, threaded
through an adapter, or derived from where a message arrived, and a method name
can do none of that.

---

## `models.quarantined` must be selectable

A manifest declaring a quarantined model on `execution.kind: completion` or
`tool-calling`, with no `memory_formation`, is now **refused at parse**:

```text
spec.models.quarantined: ... the second role reads as dual-model isolation
while one model does all the work
```

This breaks manifests written against earlier guidance, at parse, with no
warning phase — so it is worth being blunt about what it caught: a deployment
with 28 manifests all declaring the role, and an operator guide claiming
dual-model isolation, had **nothing selecting the quarantined model**. Every call
went to the privileged one. The file read as a control and was decoration.

Exactly two things point a model at untrusted-derived content on their own, so
exactly three fixes exist:

1. **Drop the role.** Correct whenever the agent is a completion or a tool loop
   and you were not relying on isolation. This is the right answer for most.
2. **Declare `memory_formation`.** Extraction then runs on the quarantined
   model — the reviewer's designated model writes the durable memory while the
   answer stays on the privileged one.
3. **Move to `execution.kind: planned`.** `parse` steps run on the quarantined
   model under a fixed extraction-only instruction, which is the dual-model
   pattern in full.

**What `planned` costs**, so the third option is a decision and not a leap: the
planner sees only **trusted** input — untrusted input is refused, because the
planner reads the input to write the plan — control flow is fixed before
anything hostile is read, and step outputs travel as references rather than
through a model's context. That is the point, and it is also the constraint: an
agent that must react to what a tool *said* wants the loop, not a plan.

A coded skill is exempt: it chooses its own models, so the declaration is a
reviewed allowlist rather than something a tier selects from.

Also refused: `privileged` and `quarantined` naming the same provider and model.
Two roles, one model behind both, is isolation spelled as if it were on.

---

## A tool loop with nothing to reach refuses the build

A manifest declaring `execution.kind: tool-calling` on a plane with no tool
catalogue used to assemble cleanly and then fail **identically on every run**.
Both facts are known at `build`, so it is a `BuildError` now, naming the agent,
its grants, and both fixes — `toolbox(..)` (derived from the declaration) or
`.tools(catalog, client)` (stated by hand).

This is worth knowing because of the shape it catches: a service whose tests
wired a stub catalogue and whose production wiring passed `None` had green tests
and 166 grants across 14 servers that could never have been called. Tests cannot
see that arrangement; the builder can.

Agents whose grants are **all** `tool://agent/…` are exempt and need no
catalogue — those dispatch through `commission`.

---

## `--features postgres` now delivers Postgres

`store` was declared under the `redb` feature while holding *both* backends, so
`--no-default-features --features postgres` compiled, pulled `tokio-postgres` in,
and exposed **no store module at all**. If you worked around it by also enabling
`redb`, you no longer need to.

---

## Checking your own upgrade

```sh
agentplane validate <manifest>...   # every parse refusal, before deploying
cargo check --all-targets           # every admission call site
```

`validate` reads a room as happily as a single agent, and names *which* document
broke — two thirds of a room must not deploy.
