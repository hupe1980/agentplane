+++
title = "Upgrading"
description = "What breaks between pre-alpha releases, why, and the shortest correct fix for each."
weight = 11
+++

Pre-alpha means hard cuts rather than deprecation cycles, and a manifest or a
call site that stops working is the intended way to find out. What this page owes
you is the *reason* and the shortest correct fix — a refusal you have to reverse
engineer costs an afternoon, which is one afternoon more than the change saved.

Every entry here is a **parse-time, build-time, read-time or replay-time**
refusal. None of them changes what a running agent does silently, which is the
property that makes a hard cut acceptable at this stage.

---

## `spec.memory_formation` moved under `spec.memory`, which also reads

**Affected:** every manifest declaring `memory_formation`.

```yaml
# before
memory_formation:
  subject: "$correlation/malo"
  purpose: clearing
  instruction: "Record stable facts stated in the source."

# after
memory:
  formation:
    subject: "$correlation/malo"
    purpose: clearing
    instruction: "Record stable facts stated in the source."
```

Every field under `formation` is unchanged. `deny_unknown_fields` means the old
spelling is a parse error naming the field, not a silently ignored block.

The move exists because the block gained its other half: `spec.memory.recall`,
so a declarative agent can read what it wrote without dropping into Rust.

```yaml
memory:
  recall:
    subject: "$correlation/malo"
    purpose: clearing
    limit: 5              # 1..=50, most trusted first then newest
    refresh_access: false
  formation:
    subject: "$correlation/malo"
    purpose: clearing
    instruction: "Record stable facts stated in the source."
```

The selected memories are folded into the prompt under `/memory`, beside
`/system` and `/input`, as `{id, purpose, content, written_at}` — each carrying
**the label it was written with**, so a fact a model produced last week is
untrusted this week too. Four refusals come with it: an empty `memory: {}`
block, a `limit` outside `1..=50`, a `memory` block beside a coded skill, and a
recall on `execution.kind: planned` (that kind refuses untrusted input because
its plan is compiled from what the planner reads, and a recalled memory is
untrusted whenever whatever wrote it was).

`BuildError::FormationWithoutMemory` became
`BuildError::MemoryWithoutStore { agent, declared }`, where `declared` names
which half wanted a store.

## The embedder and the index are wired together, and a query no longer names its own space

**Affected:** every caller of `cx.embed` or `cx.semantic_recall`, and every
`SemanticRetriever` implementation.

```rust
// before — the space was three strings a caller typed
let vector = cx.embed(embedder, text, Sensitivity::Internal).await?;
let hits = cx.semantic_recall(retriever, Tainted::trusted(SemanticQuery {
    subject, purpose, text, embedding: vector.peek().clone(),
    embedding_model: "embed-v3@2026-07-01".into(),
    index_snapshot: "support-2026-08-05".into(),
    limit: 5, max_sensitivity: Sensitivity::Internal,
})).await?;

// after — the space comes from the wiring, which `build` already checked
let runtime = Runtime::builder(journal)
    .memory(memories)
    .semantic_memory(embedder, retriever)
    .build();

let hits = cx.semantic_recall(
    SemanticSearch::about(subject)
        .for_purpose("support")
        .limit(5)
        .max_sensitivity(Sensitivity::Internal),
    Tainted::trusted("refund policy".to_owned()),
).await?;
```

The reason is a failure that never failed. Cosine similarity is defined between
any two vectors of equal width, so a query embedded by one revision against an
index built by another returns a ranked list of unrelated memories rather than
an error — reaching an operator months later as "retrieval quality". Three
strings a caller typed by hand were three chances to make that mistake per call
site.

For a `SemanticRetriever` implementation:

```rust
// new required method
fn index(&self) -> IndexIdentity {
    IndexIdentity {
        snapshot: "support-2026-08-05".into(),
        // The revision a *query* vector must come from — not what the
        // documents were embedded with. Asymmetric embedders embed the two
        // deliberately differently, so an index built from `…/search_document`
        // names `…/search_query` here.
        query_revision: "voyage-3-large/query".into(),
    }
}
```

`SemanticQuery` keeps `subject`, `purpose`, `text`, `embedding`, `limit` and
`max_sensitivity`; its `embedding_model` and `index_snapshot` collapsed into one
`index: IndexIdentity`, and the runtime fills it in. `InMemorySemanticRetriever::new`
takes `(IndexIdentity, Vec<SemanticVector>)` — the separate `identity` string is
gone, since the effect key already carries the profile and the index. Its
snapshot self-check is gone too: the runtime builds every query from
`index()`, so the check could only ever compare a value with itself.

`cx.embed` now returns `Tainted<Embedding>` — `{ vector, revision }` — with the
revision read from the driver rather than supplied by the caller. Two new build
refusals: `BuildError::EmbeddingSpaceMismatch` and
`BuildError::SemanticMemoryWithoutStore`. A retriever returning **more hits than
the query's `limit`** is now refused rather than truncated, so an implementation
that treated the limit as advisory has to honour it.

---

## Sealed envelopes carry a format version, and older ones do not open

**Affected:** any deployment that configured a `keyring`. This is the heaviest
break this project ships, and unlike every other entry on this page it is not
reversible by editing a call site.

Envelopes now lead with the construction they were written to:

```text
before  [u32 len][wrapped data key][24-byte nonce][ciphertext ‖ tag]
after   [u8 version][u32 len][wrapped data key][24-byte nonce][ciphertext ‖ tag]
```

**Bytes sealed by 0.18.0 and earlier do not open under 0.19.0**, and there is
no migration — not because one was skipped, but because one cannot exist. The
journal's hash chain commits to the envelope bytes, which is what lets an
auditor holding no keys verify a run whose payloads were erased; rewriting an
envelope therefore rewrites a record the chain covers. Sealed bytes are
rotation-immutable, and that rule applies to the format as much as to the keys.

Two ways forward, and which one applies is a retention question rather than a
technical one:

- **Sealed data you still need** — stay on 0.18.x for as long as you need to
  read it. The bytes are intact; only this build declines to guess at them.
- **Sealed data you do not** — erase the scopes (`agentplane` erasure destroys
  the wrapping key, which is the discharge a regulator asked for anyway) or
  drop the stores, then upgrade.

Run `agentplane drill` after upgrading. A case whose state is still in the old
shape now reports itself by name rather than as suspected tampering:

```text
case 8f2c…: this sealed envelope is format version 0 and this build reads 1 —
the bytes are intact and not erased; they open under a build that reads
version 0
```

If you implement `KeyRing` yourself, nothing changes — the envelope is built
above your trait, and `data_key`, `open` and `destroy` are untouched. What is
worth knowing is the new refusal your callers can now see:

```rust
// before: a version this build cannot read reached the cipher and came back as
// "the sealed payload did not authenticate" — indistinguishable from tampering
Err(KeyError::Refused("the sealed payload did not authenticate".into()))

// after: its own variant, naming what would read it
Err(KeyError::UnknownFormat { version: 2, supported: 1 })
```

`keyring::ENVELOPE_FORMAT_VERSION` is the constant to compare against. Like
`canon::VERSION` and `export::FORMAT_VERSION`, it stays `1` until the
durable-format freeze.

---

## `KeyRing::rewrap` is gone, and a retired key version is its own error

**Affected:** anyone implementing `KeyRing` themselves. Deployments using
`VaultTransit` or `MemoryKeyRing` need no change, and no stored bytes move.

Delete your `rewrap` implementation:

```rust
// before
#[async_trait]
impl KeyRing for MyRing {
    async fn data_key(&self, scope: &str) -> Result<(DataKey, WrappedKey), KeyError> { … }
    async fn open(&self, wrapped: &WrappedKey) -> Result<DataKey, KeyError> { … }
    async fn destroy(&self, scope: &str, at: Timestamp, reason: &str) -> Result<(), KeyError> { … }
    async fn rewrap(&self, wrapped: &WrappedKey) -> Result<WrappedKey, KeyError> { … }
}

// after — the trait has three methods
#[async_trait]
impl KeyRing for MyRing {
    async fn data_key(&self, scope: &str) -> Result<(DataKey, WrappedKey), KeyError> { … }
    async fn open(&self, wrapped: &WrappedKey) -> Result<DataKey, KeyError> { … }
    async fn destroy(&self, scope: &str, at: Timestamp, reason: &str) -> Result<(), KeyError> { … }
}
```

Re-wrapping could never have run. The journal's hash chain commits to the
envelope bytes, and the envelope carries its wrapped data key inline — so
re-wrapping a journal payload rewrites a record the chain covers. Sealed payload
bytes are rotation-immutable, and the erasure scope (one case, one run, one
memory subject) is the rotation unit instead.

**The half worth acting on** is the `KeyError` variant that replaces it. If your
key service can refuse to decrypt below a version floor — Vault's
`min_decryption_version`, and most have an equivalent — map that refusal to the
new variant rather than leaving it as `Refused`:

```rust
// before: a reversible setting reaches `agentplane drill` as
// "neither opens nor was its key destroyed" — the signature of loss or tampering
Err(KeyError::Refused(format!("{url}: {reason}")))

// after: the operator is told which floor to lower
Err(KeyError::Retired {
    scope: wrapped.scope.clone(),
    key_id: wrapped.wrapped_by.clone(),
})
```

Skipping this degrades safely — you get `Refused`, which reads as an incident
rather than as a discharged erasure — but somebody will spend an afternoon
hunting a fault that is one configuration line.

---

## `Delegation`, `TenantId` and `Quorum` now validate when deserialized

Each of these establishes an invariant in a fallible constructor. Each also
derived `Deserialize`, which wrote the private fields directly — so a value that
the constructor refuses could be *loaded*, and loading is the common path: these
arrive from a credential, a store row, a journal record or a peer far more often
than from a call to `new`.

Deserializing now goes through the constructor. A value that never satisfied the
invariant fails to load instead:

```text
a tenant id may not contain '/': it becomes part of composite keys and key-ring
scopes, where a separator makes two distinct tenants collide into one
```

**Nothing this crate writes can produce such a value**, so an ordinary
deployment sees no change. You are affected if you hand-wrote a fixture, or if
your `Authenticator` or `DelegationScheme` builds one of these types by parsing
JSON rather than by calling its constructor:

```rust
// before — compiles, and silently yields a chain that may widen
let chain: Delegation = serde_json::from_value(claims["chain"].clone())?;
```

```rust
// after — the same line now returns the attenuation error when the chain
// widens, exceeds MAX_DELEGATION_DEPTH, or is empty. Handle it as a
// credential rejection, which is what it is.
let chain: Delegation = serde_json::from_value(claims["chain"].clone())
    .map_err(|e| MyAuthError::Untrustworthy(e.to_string()))?;
```

**Why a read error is the right outcome.** For `TenantId` the value at stake is
a key scope: units already contain separators (`event/{source}/{id}`), so a
tenant named `acme/event/counterparty` derives the identical scope to tenant
`acme` with unit `event/counterparty/42`. Both stores write, nothing fails, and
either tenant's erasure destroys the other's key and reports success. Accepting
the name quietly is what creates that pair.

One API change came with it: `Delegation` stores its owner as a field rather
than as the head of a list, so an empty chain is unrepresentable rather than a
value whose `owner()` panics. `owner()` and `depth()` are now `const fn`. The
serialized form is unchanged — still `{"links": [...]}`, owner first — so stored
chains and journaled records read back exactly as before.

## A Cedar rule reading a conditional context attribute now refuses to build

If a rule reads `context.delegation_depth`, `context.owner`, `context.scope`
or `context.label` without guarding it, the plane no longer assembles:

```text
this plane's policy set cannot be evaluated: `effect:perform` on
`preflight.effect`: … record does not have the attribute `delegation_depth` …
```

**The fix is one operator per rule.** Cedar's `has` makes the read safe on
every request shape, and the rule means exactly what it meant before:

```text
# before — correct only while every request happened to carry the attribute
forbid(principal, action == Action::"effect:perform", resource)
when { context.delegation_depth >= 1 };
```

```cedar
# after
forbid(principal, action == Action::"effect:perform", resource)
when { context has delegation_depth && context.delegation_depth >= 1 };
```

**Why the refusal is worth an afternoon of nobody's time.** Cedar evaluates
every rule against every request, so an unguarded read of an absent attribute
*errors* rather than failing to match — and since an unevaluable rule may be
the `forbid` that would have stopped the call, the gate refuses. One such rule
denies every effect of every run. This is not new behaviour in the gate: what
changed is that the refusal now happens at `build`/`try_build`, against a
canonical request of each shape the plane will issue, instead of at the first
effect of the first run.

The attributes that are conditional, and when they are present:

| Attribute | Present |
|---|---|
| `delegation_depth`, `owner`, `subject`, `scope` | only where a delegation chain is configured (`RuntimeBuilder::acting_as`) |
| `label` | sinks only — the calls that bind a labelled value |

A plane that *does* configure a chain may read the delegation attributes
unguarded: the preflight probes the shapes that plane actually produces, not a
stricter hypothetical, so a working deployment is not refused for a rule that
is correct there.

Two related changes come with it. `PolicyDecision` gained a **`Malformed`**
variant, so an engine that cannot evaluate its rules is distinguishable from
one whose rules refuse — previously the difference existed only inside a
reason string, and nothing could branch on it without matching message text. A
`Malformed` decision refuses the call exactly as a denial does; what changes is
that the operator is told to fix the policy set rather than sent looking for
the rule that fired, and the operator API answers 500 rather than 403. If you
match on `PolicyDecision` exhaustively, add the arm.

---

## Journals from an older build are refused, and the record version is `1`

`EffectDone` now carries the trust and sensitivity the effect declared for its
output, and `EffectReconciled` carries them for a recovered one. Both are
required fields, so a journal written by an earlier build is refused on read:

```text
record EffectDone is v4, and this build writes and reads v1 only. Record shapes
change by hard cut until the format freeze, so a journal at another version is
refused rather than read with fields quietly defaulted …
```

**The fix is a fresh journal.** Nothing migrates, on purpose: the missing field
was never written, and defaulting it would answer an audit question falsely
rather than fail to answer it.

The number moved *down*, from 4 to 1, which is the other half of the same
decision. `canon::VERSION` and `export::FORMAT_VERSION` are both 1 and stay
there until the format freeze; a record version that counted the pre-release
cuts implied those journals were readable, which they never were. After the
freeze, bumping becomes an RFC-level change and the `Upcaster` seam starts
earning its keep.

---

## A replayed value keeps the label it was read under

This is a behaviour change rather than a refusal, and the only one on this page,
because the old behaviour could not be made to fail loudly — that was the
problem with it.

An effect's output label has three parts. Its provenance comes from
`Effect::source`, which every effect derives from something already inside its
key. The other two — `Effect::trust` and `Effect::output_sensitivity` — come
from **operator configuration**: a `ToolSafety` entry, an MCP grant, a
`PeerGrant`. Those are edited without recompiling, and none of them reaches the
effect key.

They were re-read from the catalogue on every replay. So lowering one:

```rust
// yesterday
.tool(ToolId::new("crm", "lookup"), ToolSafety::read_only()
    .output_sensitivity(Sensitivity::Secret))
// today
.tool(ToolId::new("crm", "lookup"), ToolSafety::read_only()
    .output_sensitivity(Sensitivity::Public))
```

silently declassified every value replay handed back. Nothing diverged, because
nothing about the call had changed. The damage is not confined to audits: a
`Resume` replays its prefix and then dispatches live, so a run suspended while
holding a `Secret` result woke holding a `Public` one, and its live tail could
send it where the original label forbade.

The declaration is now journaled with the result and read back. **Nothing to
fix in your code** — but two consequences are worth knowing. Editing a
catalogue no longer changes what a finished run was allowed to do, which is the
point. And a value whose declared sensitivity you *raise* keeps the lower label
on existing history; if that matters, the runs predating the change are the ones
to re-examine, not the catalogue.

---

## Sink gates apply to live dispatch only, and MCP grants left the effect key

The manifest-derived ceilings already worked this way. Now the effect's own
`max_sensitivity`, its `protected_fields` and the whole-value taint gate do
too: on a replayed prefix the verdict is read from the journal — a pass as the
`EffectDone` beside it, a refusal as its own record — instead of being decided
again.

The reason is the same one the entry above gives. For every effect that reaches
a sink, "the sink's own ceiling is code" was not true: a tool's ceiling comes
from `ToolSafety`, an MCP prompt's from a reviewed grant, a peer's from its
`PeerGrant`.

Two visible consequences:

* **`McpPrompt` and `McpResource` no longer hash their grant's sensitivities
  into the effect key.** They did, which turned an operator raising a ceiling
  into `NonDeterminism` for every historical run through that prompt — an audit
  replay failing over a configuration edit. If you have journals whose replay
  you want to compare across such an edit, they are readable again.
* **A sink refusal read back from the journal is a `PolicyError::Recorded`**,
  carrying the recorded wording. It stays a `StepError::Policy`, so a
  tool-calling loop still tells the model `REFUSED` and may route around it — a
  replay that turned it into `StepError::Denied` would end a run the original
  finished.

---

## `cx.embed` takes the ceiling it sends text under

```rust
// before
cx.embed(embedder, text).await?
// after
cx.embed(embedder, text, Sensitivity::Internal).await?
```

`Embed` declared no ceiling of its own, so it inherited the trait default of
`Public`. Embedding is an egress — the text goes to a provider — and every
query worth embedding has crossed a trust boundary, which makes it at least
`Internal`. The path was therefore reachable only by embedding a hard-coded
literal, and the ceiling nobody could raise was the strictest one available.

`SemanticQuery::max_sensitivity` is unchanged and still separate: the embedder
and the retriever are two providers, and a deployment may well trust one and
not the other.

---

## Answering an MCP elicitation needs its own grant

```rust
McpAccess::new()
    .prompt("summarize", McpDataSafety::public())
    .task_input(McpDataSafety::public().max_input(Sensitivity::Internal))
//   ^ new; without it, `update_task` refuses
```

```text
the operator did not grant this server input responses — an elicitation is a
server asking this plane for data, and nothing about the server raising one
says it may have an answer
```

`update_task` was reachable by anyone holding a task handle, at a `Public`
ceiling no operator had chosen and nothing let them raise — while `prompts/get`
and `resources/read` on the same connection both required a grant. One grant per
server rather than per task, because a task id is minted at runtime and an
operator cannot review a name that does not exist yet.

The whole-value taint gate is unchanged and still stands in front of this: an
untrusted response reaches an MCP server through a `release` or not at all.

---

## A skill may not answer a capability its manifest does not advertise

The plane already refused the converse — a manifest advertising a capability no
skill provides. This is the direction that left no trace:

```rust
Runtime::builder(store)
    .agent(Agent::new(&manifest)          // provides: [work.do]
        .skill(Worker)                    // answers work.do
        .skill(Helper))                   // answers work.helper  ← now refused
    .try_build()?;
```

```text
BuildError::ProvidesWhatItDoesNotAdvertise {
    agent: "…", undeclared: ["work.helper"],
}
```

Everything about the old behaviour worked: the extra skill was governed by that
manifest, its budget and grants applied, and runs journaled correctly. The only
thing wrong was that `spec.capabilities.provides` did not mention it — and that
file is what gets reviewed, digested, pinned, and turned into the A2A card. A
reviewer approving it approved a smaller surface than the plane served.

**The fix is one line**: add the capability to `provides`. If it genuinely
belongs to a different agent, register it on one — a skill passed to
`RuntimeBuilder::skill` rather than to an `Agent` has no declaration to
contradict and is untouched.

---

## A declarative agent with no model is refused at parse

`spec.execution` says the runtime drives the agent by calling a model, and the
model is *named* rather than defaulted — falling back to another registered
driver would run the agent on a model its own declaration does not name. So a
document with `execution` and no `spec.models.privileged` could never assemble
a plane, and `agentplane validate` used to approve it anyway:

```text
spec.execution cannot be enforced here: this agent's behaviour is declared, so
the runtime drives it by calling a model — and no `spec.models.privileged`
names one …
```

`BuildError::DeclarativeWithoutModel` remains as the backstop, for a `Manifest`
constructed in Rust without passing a parser. What changed is that the refusal
now arrives from `validate`, before a deploy, rather than from whichever
process first tried to build a plane.

An agent with **no** `spec.execution` is untouched: a coded skill chooses its
own models, which is a different and legitimate claim.

---

## A budget ceiling of zero is refused, at parse *and* at build

`budgets: { max_tokens: 0 }` — and the same for `max_effects`, `max_steps`,
`max_minor_units` and `max_wallclock_secs` — is a parse error. It read like "no
permission to spend"; what it did was refuse the **first effect of any kind**,
because every ceiling is an accumulate-and-compare checked before the work. An
agent declaring it could never perform a single tool call, model-free or not.

The same budget reaches the runtime through `RuntimeBuilder::budget` without
passing a parser, so a plane wired in Rust is refused too:

```text
BuildError::BudgetPermitsNothing { field: "max_tokens" }
```

Both refusals come from one rule, `Budget::bricked_ceiling`, so a sixth ceiling
cannot be added to one list and forgotten in the other. `max_replans` and
`max_denials` are deliberately excluded: zero is meaningful for both — *do not
replan*, and *the first refusal ends the run*.

Omit the ceiling for "no limit". To stop a tenant's work, use the emergency
stop (`QuotaStore::set_halt`), which is the control that means it.

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

## `HttpWitness::new` takes the keys it will believe

A remote witness's `200` used to be taken at its word. It carries a
`signed-note` signature line, and the client recorded that line as a
cosignature without checking it, so a quorum was a count of HTTP status codes:
any endpoint answering `200` with a well-formed base64 string satisfied it.

`HttpWitness::new` now takes a third argument and refuses to build without at
least one key:

```rust
use agentplane::journal::{HttpWitness, TrustedWitness};

let witness = HttpWitness::new(
    "https://witness.example",
    log_signature,
    vec![TrustedWitness::ed25519("witness-1", witness_public_key)],
)?;
```

Every signature line on a reply is now matched to a trusted key by **name and
four-byte note key id** — `signed-note` says a verifier must ignore a signature
sharing one but not the other, and the name is whatever the answering server
typed — and then verified as Ed25519 over the exact note text that was
submitted. A reply nothing verifies is a refusal, not a cosignature.

Get the public key from whoever operates the witness. `TrustedWitness::ed25519`
derives the key id itself; supplying one beside a key would be a second copy of
one fact, and the copy that is wrong is the one nothing checks.

---

## `CheckpointSigner` signs bytes, and there is no blanket impl

C2SP `signed-note` specifies a signature over the note **text**: pure Ed25519,
not Ed25519 over a pre-hash. `CheckpointSigner::sign` took a `Digest`, so a
checkpoint was signed over `SHA-256(note)` — sixty-four bytes of the right
algorithm under the right key that verify against no witness, no auditor and no
`signed-note` implementation anywhere.

```rust
// before
async fn sign(&self, hash: &Digest) -> Result<Vec<u8>, SignError>;
// after
async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignError>;
```

The blanket `impl<T: Signer> CheckpointSigner for T` is gone with it: `Signer`
covers a 32-byte digest and this covers a message, and a blanket impl let one
stand in for the other with no cast to notice. `Ed25519Signer` implements both
explicitly, so a deployment holding a local key under the `signing` feature
needs no change. A KMS-backed signer implements `CheckpointSigner` directly and
must sign the bytes it is handed.

---

## The empty log's Merkle root is `SHA-256("")`

`merkle::root(&[])` returned thirty-two zero bytes. RFC 6962 fixes the empty
tree's hash, and the root is the one value in this crate that is *not* private:
it goes into a `tlog-checkpoint`, gets cosigned by witnesses this project does
not operate, and is recomputed by verifiers it did not write. A size-0
checkpoint is exactly what a fresh log first submits, so the old value
disagreed with every conforming implementation at the first opportunity.

Use `merkle::empty_root()` where you compared against `Digest::ZERO`. Zero
remains the *chain's* genesis link, which is a different thing and unchanged.

A checkpoint claiming size 0 beside any other root is now refused by
`MemoryWitness` rather than remembered — a witness holds every later checkpoint
to its first, so one incoherent submission would report every honest one
afterwards as `Forked`, forever.

---

## `export::verify` takes the checkpoint you were given

The Merkle root rebuilt from an export was compared with the checkpoint in the
export's **own header**. That catches a dropped run only from an editor who
forgot to rewrite the header, and this crate already refuses that reasoning one
level down: a record's `prev_hash` is checked by rehashing the wire bytes, never
against the previous line, because "the file agrees with itself" is what a
competent editor achieves.

```rust
// before
export::verify(input, verifier)?;
// after — `None` still works, and now says what it did not check
export::verify(input, verifier, Some(&checkpoint))?;
```

With `None`, the report lists **deletion** under `not_checked` instead of
reporting sound. On the CLI:

```sh
agentplane verify history.jsonl --checkpoint cp.note
```

`--checkpoint` reads a `tlog-checkpoint` note, a cosigned signed note, or the
`current` field of an `audit` report — whichever form you hold it in.

---

## A checkpoint note and a key name are parsed canonically

`Checkpoint::from_note` used `lines()`, which accepted a missing final newline,
dropped a `\r` before it, and ignored anything after the third line. The
signature covers the *text*, so several texts mapping to one checkpoint means
an operator can hand two auditors different bytes that both verify and both
name the same history. It now requires exactly three newline-terminated lines,
a non-empty origin, a canonical decimal size, and a canonically padded root.

The crate's base64 decoding is strict for the same reason: `=` only as trailing
pad, a whole number of quads, and zero bits below the last whole byte.

`SignedNote::with_signature` is fallible, because a key name is structure on
the wire rather than a label — the line is `— <name> <base64>`, so a name
carrying a space, a newline or an em dash serialises without complaint and
reads back as a different name, a truncated payload, or a signature line nobody
wrote. Add `?` or `.expect(..)` at the call site.

## A store scoped to another tenant is refused at build

If the plane and one of its state stores disagree about the tenant, `try_build`
now refuses:

```text
this plane runs as tenant 'acme' but its case store serves 'default'. With a
key ring wired the plane seals that state under 'acme' while the store keeps it
under 'default' — both scopes are real, so nothing fails at runtime and an
erasure for either tenant destroys a key that does not reach these rows
```

The journal and blob stores already answered this question. `CaseStore`,
`EventStore`, `TaskStore`, `MemoryStore` and `PushStore` now do too, so the
mismatch is caught before anything is sealed rather than discovered when a
deletion request turns out not to have reached the data.

**The fix is to scope every handle the way the plane is scoped**:

```rust
// before — the plane is acme, every store is on `default`, and this built
let store = RedbStore::open("plane.redb")?;
let runtime = Runtime::builder(Arc::new(store))
    .tenant(TenantId::new("acme")?)
    .cases(Arc::new(RedbStore::open("cases.redb")?))
    .keyring(keys)
    .try_build()?;
```

```rust
// after
let tenant = TenantId::new("acme")?;
let runtime = Runtime::builder(Arc::new(
        RedbStore::open("plane.redb")?.for_tenant(tenant.clone()),
    ))
    .tenant(tenant.clone())
    .cases(Arc::new(RedbStore::open("cases.redb")?.for_tenant(tenant)))
    .keyring(keys)
    .try_build()?;
```

A single-tenant deployment is unaffected: an unscoped store answers `default`,
which is what an unscoped plane runs as.

If you implement one of those traits yourself, override `tenant()` to return
the tenant your handle is actually scoped to. The default is `default`, which
is refused against a non-default plane — deliberately the safe direction, since
a store that silently claimed the plane's tenant would defeat the check.

---

## `Bedrock::from_client` reads the region from the client

The region is no longer a second argument, and both constructors are fallible:

```rust
// before — two copies of one fact, free to disagree, and the journal
// attested the one nothing checked
let driver = Bedrock::from_client(client, "eu-west-1");
let embedder = BedrockEmbedder::from_client(client, "eu-central-1", model, dialect);
```

```rust
// after — the region comes from the client that will do the connecting
let driver = Bedrock::from_client(client)?;
let embedder = BedrockEmbedder::from_client(client, model, dialect)?;
```

The region goes into `request_profile` for the driver and into `revision()` for
the embedder, so both are effect identity: a driver built with a `us-east-1`
client and the string `"eu-west-1"` sent its calls to Virginia and recorded
Ireland. A client carrying no region is now refused, because an empty region on
the record reads as an answered question.

`from_env(region)` is unchanged apart from its error type — it sets the region
on the config it builds, so the client it hands over already carries it.

---

---

## Checking your own upgrade

```sh
agentplane validate <manifest>...   # every parse refusal, before deploying
cargo check --all-targets           # every admission call site
```

`validate` reads a room as happily as a single agent, and names *which* document
broke — two thirds of a room must not deploy.
