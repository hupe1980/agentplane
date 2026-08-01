# 🔐 Security model

What this runtime defends, how, and — the part most security documents omit —
**what it does not cover**. The residual column in every table below is not
decoration: a threat model without one is marketing.

The short version. Two questions are usually conflated and are answered by
different machinery here:

- *May this **principal** act?* → authorization, evaluated before every effect.
- *May this **value** go there?* → information-flow labels, checked at every sink.

A system that answers only the first will happily let an authorized agent post a
secret it read three steps ago to a legitimate endpoint.

---

## Information-flow labels

Payloads are opaque to the engine — it never parses business data — but they are
never *unlabeled*. Policy over unlabeled blobs is policy over nothing.

```rust
pub struct Label {
    provenance:  BTreeSet<SourceId>,
    trust:       Trust,        // Trusted | Untrusted
    sensitivity: Sensitivity,  // Public | Internal | Confidential | Secret
}
```

Labels **join** on combination — trust degrades to the worse, sensitivity
escalates to the higher, provenance accumulates. A bounded join-semilattice, and
the reason derived values inherit untrust automatically.

`Tainted<T>` exposes `peek()` (reading is fine — the enforcement point is at
*sinks*, not at reads) but no infallible unwrap. Leaving the lattice requires
`cx.declassify(value, reason)`, which writes a `Declassified` record carrying
the reason and the label it left with.

Two gates run at every sink:

- **Egress ceiling** — a value's sensitivity may not exceed what the sink is
  cleared for. This is the exfiltration path that actually matters: not the
  network, but a legitimate-looking call carrying a secret read three steps ago.
- **Taint gate** — untrusted data may not reach a *mutating* sink without an
  explicit, journaled declassification.

### Judging a step more than once

A single execution of a high-stakes judgement is not adequate evidence: an agent
at 61 % pass^1 is around 25 % at pass^8. `core::Quorum` declares several
judgements of one node's work and how many must agree.

What the type refuses carries the design. **Lenses must be distinct** — three
identical judgements against one model share their blind spots, so they agree
confidently and wrongly about exactly the cases a second opinion was for.
**Thresholds must be majorities** — 2-of-4 can be reached for pass *and* fail at
once, so which one is reported would depend on tally order. And **a split panel
has no resolution**: `Outcome::NoQuorum` carries the tally and offers no
accessor that decides, because a panel that could not agree is the signal a
person should look, and resolving it silently converts *we do not know* into
*approved*.

The plan contract adds the structural half: a node declaring a quorum must
depend on something. On a node with no subject a panel repeats *the work* rather
than reviewing it — and for a mutating step, repeats it on the world.

### Where the plane may connect

The sensitivity lattice governs *what* may leave a run. Egress allowlisting
governs *where it may leave to*, and they close different holes: a value can sit
perfectly within its ceiling and still be posted to a host nobody granted.

`core::Egress` is a set of granted hosts. A model driver or peer client
configured with one refuses any other destination **before the request is
built** — nothing sent, nothing metered, and the disposition is `DidNotHappen`
rather than in doubt, because it truly did not.

Two details carry most of the value. There are **no wildcards**: `*.example.com`
grants every host anybody can register under a domain, including a dangling
subdomain an attacker takes over. And the allowlist **never parses a URL** — URL
parsing is where allowlists break, so the caller hands over a host parsed by the
same library that will do the connecting, and the allowlist does set membership.
It cannot disagree with the client about what the host is because it never forms
its own opinion.

An unconfigured seam is no control, spelled as absence: there is no
`Egress::allow_all()`, for the same reason there is no `AllowAll` policy engine.

### Provenance that a callee can check

A tool call carries a little context — which run, which case, which effect, which
agent — under MCP's `_meta`. Sent as plain fields it is a set of claims the
callee cannot verify: a compromised proxy, gateway or upstream agent writes
whatever it likes, and a receiving tool cannot tell a real `run_id` from an
invented one. That is fine for a log line and disqualifying for a decision.

The block is therefore signed by the plane's workload identity
(`Runtime::signing_as`), and what the signature covers is the point. Signing the
identifiers alone would produce something *convincing and wrong*: valid for those
identifiers on any request, so an observer could lift a legitimate block onto a
different call and it would verify. The payload binds the call — the effect kind
and a digest of the arguments — so moving the block or changing an argument
breaks it. Arguments go in by digest so the payload stays bounded and the
caller's data does not end up in whatever logs the signed input.

A plane with no signer sends the fields unsigned rather than self-signing: a
self-signed block looks attested and proves nothing, since the party being
checked chose the key.

It is not authorization. A verified block says who called and what they asked
for; whether they may is the callee's decision.

### The refusal is an output too

Both gates decide whether an action is permitted. What they say when the answer
is *no* is a separate question, and getting it wrong hands back the very thing
they exist to protect.

The refusal messages are written for an operator reading a journal, so they are
precise: which sink, what sensitivity, which ceiling. Fed into an agent's next
prompt — which is what an agent loop naturally does with an error — that
precision turns the policy into a queryable service. Injected content steering
the loop can probe it: vary the request, watch which variants come back refused,
read the boundary off the answers. The egress ceiling is the sharpest case,
because its message reports the *sensitivity of the data*. A handful of probes
classify data the run was never permitted to reveal, and none of it ever crosses
the boundary — the classification leaks through the refusals alone.

So the audiences are separated. `Display` keeps everything, for the journal and
the operator; `PolicyError::for_model()` returns one uniform sentence for
anything that reaches a prompt. An auditor can still answer *why*; the thing that
might be attacking the policy learns nothing it can tell apart.

That leaves the refused/allowed bit itself, which no wording removes short of
fabricating success. `Budget::max_denials` bounds it instead — a ceiling on how
often one run may be refused, checked **before** the policy is consulted, since a
refusal is journaled as it happens and a ceiling applied afterwards bounds
nothing an observer has not already seen. It reads as a security control and is
equally an operational one: a run stuck in a denial loop has stopped making
progress.

## The trust boundary

An effect is how the deterministic zone reaches the outside world, so its result
*is* the outside world's data — a tool response, a peer's answer, a model
completion. Those are the three inputs the whole injection-resistance
architecture is about.

`cx.effect()` returns `Tainted<E::Output>`. The label comes from the effect's own
`trust()` declaration, and **the default is untrusted**.

### Why the default runs that way

Wrong in the safe direction produces spurious taint: a sink refuses, you see it
immediately, you fix the declaration. Wrong in the other direction is a prompt
injection reaching a mutating tool, and you see that as a wire transfer. So an
effect that declares nothing gets the conservative answer — the same rule
`Recovery::RequiresOperator` follows for a mutating effect that declares no
semantics.

Three of the runtime's own effects declare `Trusted`: the journaled clock, the
recorded-value wrapper, and calendar resolution. None crosses a boundary.
`tests/guards/layering.rs` requires a fourth to be named first, because declaring
`Trusted` opts an effect out of the taint gate, the egress ceiling, *and* the
refusal to replan on untrusted data — all at once, and silently.

### The hole this closed

`cx.effect()` used to return a bare value. Every guarantee downstream of the
label therefore depended on the skill author wrapping the result correctly — and
the runtime's own fixtures wrapped tool results in `Tainted::trusted(..)`.

That has a consequence worth being blunt about: **the refusal to replan on
untrusted data was implemented, tested, and unfalsifiable.** Deleting it would
have failed no test, because the fixtures laundered the taint before it reached
the check. Moving the label from the call site to the effect is what made the
existing guarantee real; `tests/trust/boundary.rs` now asserts it against a fixture
that forwards a tool result, and the refusal fires.

The fixtures had to become honest in the process. A step that writes to a ledger
now returns *that it wrote*, not the ledger's response — which is the real
pattern anyway: data may set parameters, not choose control flow.

### Sensitivity composes upward only

`output_sensitivity()` is combined with the sensitivity the trust level already
implies, by **maximum**. An effect can raise its output to `Secret`; it cannot
declare a tool response less sensitive than its provenance implies. An effect
able to lower its own label would be a laundering primitive with a polite name.

### Leaving the lattice

`declassify` is the only exit and it returns a bare value, so re-entering as
trusted is an assertion someone signed for. The reason and the label it left with
are journaled.

## Delegation

A principal is not a config string. It is a link in a chain running from a human
owner down to the workload actually calling a tool — because "which agent did
this" is answerable from a log line and "**on whose behalf**" is not, and the
second one is what an auditor asks.

### Attenuation is enforced by construction

`Delegation` has no public constructor that takes a list of links. It is built by
`root` and extended by `delegate`, and `delegate` refuses a scope wider than its
delegator's. An escalating chain is therefore **not representable** — there is no
validation step somebody can forget, because there is no way to build the invalid
value in the first place.

### Scope is deliberately a poor language

Two forms: `billing.reconcile` and `billing.*`. That is the whole grammar.

Richer patterns — regex, negation, conditions — are where scope stops being
*checkable*. Attenuation must be decidable by containment, and negation makes
containment undecidable in general. Conditions belong in the policy engine, which
is built to evaluate them. This layer has to be simple enough to be provably
monotonic, and a language you can prove things about is worth more here than one
you can express things in.

The encoding is where the bug lives:

* **`admin.*` must not cover `administrator-override`.** The boundary is a
  segment, not a character. A plain `starts_with` grants the longest and most
  alarming capability in the system through a pattern that reads as if it only
  covers a family.
* **Wildcards against wildcards.** `billing.*` contains `billing.eu.*`; neither
  `billing.eu.*` nor `billing.fr` contains the other.
* **An exact grant never becomes a family.** `audit.check` does not contain
  `audit.check.*`.

### The plan is where authority is checked

The plan is already the authorization graph, so a plan naming a capability
outside the chain's scope never starts — rather than failing at whichever step
happens to reach it first. The refusal depends only on the frozen plan and the
recorded chain, both of which are journaled, so it is deterministic.

### Verified once, journaled, re-checked on the way back

Credentials expire. Two tempting answers are both wrong:

* Re-verifying during replay fails an audit of a decision that was perfectly
  sound when it was made.
* Trusting whatever storage holds lets a forged chain in through the audit path —
  the path nobody thinks of as an authorization boundary.

So the credential is verified once at admission, the resulting chain is recorded
at `IdentityBound`, and `rehydrate` re-checks the **structural** property on the
way back in. That costs nothing and is timeless, unlike a signature. It runs the
same predicate the constructor does, deliberately: two definitions of "valid
chain" is how the storage path drifts from the construction path.

`spec/Delegation.tla` models building, storing, *tampering*, and loading, and its
mutants are the two failures above.

## Authorization

Two gates exist and neither subsumes the other. The information-flow lattice
answers *may this value go there* and travels with the data. Policy answers *may
this principal do this at all* and travels with the request. Either alone leaves
a hole: a correctly-labelled value sent by someone with no authority, or an
authorized caller exfiltrating a secret through an innocuous-looking sink.

### The engine cannot fail

`authorize` is synchronous and returns a `PolicyDecision`, not a `Result`. There
is no way to say "the policy service was unreachable", because a layer that can
fail open turns itself off exactly when a system is under stress. That is the
constraint that makes an embedded evaluator the right shape rather than a network
call — and the trait's vocabulary (`principal`, `action`, `resource`, `context`)
is Cedar's, so that adapter is thin. The crate ships no engine: picking one for
the embedder is the same mistake as picking their tracing exporter.

There is no `AllowAll`. A permissive engine and no engine are the same behaviour,
and having two ways to spell it is how a plane ends up with a policy layer
everyone believes is on. The default is `DenyAll`, and whether an engine governed
a run is recorded at admission.

### Replay never re-opens the gate

This is the part that is easy to get wrong, and the failure is silent. A policy
decision depends on a rule set that changes over time, so re-evaluating during
replay lets today's rules re-judge last year's run — the chain still verifies,
and now describes something that never happened.

The answer is the effect protocol, unchanged: **policy is evaluated only when an
effect is actually dispatched.** A replayed effect's result comes from the
journal, so it never reaches the world and never reaches the gate.

That settles what to record, too:

* A **permit** needs no record. The effect's own `EffectStarted` is already the
  evidence it was allowed, and journaling "yes" beside every call doubles the log
  to say nothing.
* A **denial** must be recorded, because a denial is a place the run *stopped*.
  Without a record, replay reaches it, finds no history, and reports that this
  build performs more effects than the recorded one — a divergence alarm for a
  code change nobody made. `BudgetRefused` exists for exactly this reason;
  `PolicyDenied` is its twin, and so is `EffectReplay::Denied`.

Authorization runs before the budget is charged. An unauthorized call must not
first consume the run's allowance, or a denied principal can still exhaust a
budget by asking.

### How it is checked

`spec/Authorization.tla` models a run, a rule change, and a replay, with
invariants `NothingForbiddenIsPerformed`, `ReplayNeverConsultsPolicy`,
`DenialIsDurable`, `ReplayPerformsNothing`, `NoRedundantPermitRecords`. Two
mutants must trip them: re-evaluating during replay, and stopping on a denial
without recording it.

In `tests/trust/policy.rs`, every test that replays uses an engine that **panics if
consulted**. The guarantee is enforced by construction rather than asserted after
the fact, so a re-evaluation cannot slip through by happening to return the same
answer.

## Calling other people's tools

An MCP server advertises its tools with annotations — `readOnlyHint`,
`destructiveHint`, `idempotentHint` — and the specification is explicit that
clients **must** treat them as untrusted.

That warning lands harder here than in most runtimes, because of how the effect
declarations compose:

```text
readOnlyHint: true  →  mutates() == false
                    →  Recovery defaults to Retry
                    →  a timed-out call is sent again
```

A server marking its own money-moving tool read-only would therefore be choosing,
from the far side of the trust boundary, the one condition under which this
runtime performs an operation twice.

### Safety comes from the operator, provenance from the world

`ToolCatalog` is written by the operator and decides everything the runtime will
do when a call goes wrong: `mutates`, `recovery`, the sensitivity ceiling, the
retry policy. Two rules follow:

* **A tool absent from the catalogue cannot be called.** Fail closed. Runtime
  tool discovery is precisely how an agent acquires authority nobody granted, and
  a conservative default for an unknown tool is still authority.
* **Advertised hints are recorded and compared, never obeyed.** `overclaiming()`
  lists tools where the server claims more safety than was granted. That is not a
  nuisance to normalise: a server that *starts* advertising itself as read-only
  after an upgrade is indistinguishable, from here, from one that has been
  replaced.

What the catalogue cannot do is make a tool's output trusted. It governs
authority, not provenance — the result is the outside world's data whatever the
operator thinks of the tool.

### MCP is only the wire

`McpClient` carries the call and does one hard thing: for every way a call can
fail, say whether the request reached the far side. The catalogue decides what a
tool may do; the transport decides what is known about what happened.

| `ServiceError` | Disposition |
|---|---|
| `McpError` (`METHOD_NOT_FOUND`, `INVALID_PARAMS`, parse) | `DidNotHappen` |
| `McpError` (anything else) | `InDoubt` |
| `Timeout`, `Cancelled` | `InDoubt` |
| `TransportSend`, `TransportClosed` | `InDoubt` |
| `UnexpectedResponse` | `Landed` |

Three of those are worth defending, because the tempting answer is wrong in the
expensive direction each time:

* **`Cancelled` is not `DidNotHappen`.** Cancelling cancels *our* interest in the
  answer. Whether the server stops executing is the server's choice.
* **`TransportSend` is not `DidNotHappen`.** A framed message can fail partway
  through the write, and from here a partial write and a refused connection are
  the same error.
* **A non-rejection `McpError` is not `DidNotHappen`.** Only an explicit
  rejection — bad method, bad params, unparseable — means the tool never ran.

That last one had **no test** until mutation testing found it: the suite
exercised only `INVALID_PARAMS`, which is legitimately a rejection, so a mutation
collapsing the whole `McpError` arm into "the server declined" passed everything.
`a_server_error_during_execution_is_in_doubt_not_a_rejection` covers it now.

Tests run a real rmcp server in-process over a duplex pipe — genuine
initialisation, `tools/list` and `tools/call` — with no network and no child
process. The fixture server *lies*: it advertises a money-moving tool as
`readOnlyHint: true`, so the "annotations are not obeyed" property is checked
against an actual wire response rather than a hand-built struct.

### The disposition is the whole safety story

`ToolError` exists so the transport must say what it knows about whether the call
reached the far side:

| | Disposition | Because |
|---|---|---|
| `Unreachable` | `DidNotHappen` | never left |
| `Refused` | `DidNotHappen` | the server declined before running anything |
| `TimedOut` | `InDoubt` | sent, no answer — a timeout is not evidence |
| `ToolFailed` | `Landed` | the tool ran; a repeat is a second invocation |
| `Malformed` | `Landed` | it answered, unusably |

`ToolFailed` maps to `Landed` rather than `InDoubt` deliberately. `InDoubt`
invites the effect's `Recovery` to resolve the outcome, and for one the peer has
already reported there is nothing to resolve — asking again returns the same
error, and repeating the call is the only other option.

Fitting MCP to this exposed a gap in `EffectError`: there was no way to say *the
peer performed the operation and it failed*. `Rejected` means nothing was
applied, and the only other `Landed` variant was a decode error. Hence
`EffectError::Performed`.

## 🚨 Refusals leak

Every mechanism above decides whether an action is permitted. What the agent is
*told* when the answer is no is a separate question, and getting it wrong hands
back the thing the gate was protecting.

Refusal messages are written for an operator reading a journal, so they are
precise: which principal, which sink, what sensitivity, which ceiling. Fed into
an agent's next prompt — which is what an agent loop naturally does with an error
— that precision turns the policy into a queryable service. Injected content
steering the loop can probe it: vary the request, watch which variants come back
refused, and read the boundary off the answers.

The egress ceiling was the sharpest case: its message reported *the sensitivity
of the data*. A handful of probes classify data the run was never permitted to
reveal, and none of it ever crosses the boundary — the classification leaks
through the refusals alone.

So the audiences are separated. `Display` keeps everything, for the journal and
the operator. `PolicyError::for_model()` returns one uniform sentence for
anything that reaches a prompt. An auditor can still answer *why*; the thing that
might be attacking the policy learns nothing it can tell apart.

That leaves the refused/allowed bit itself, which no wording removes short of
fabricating success. `Budget::max_denials` bounds it instead — a ceiling on how
often one run may be refused, checked **before** the policy is consulted, since a
refusal is journaled as it happens and a ceiling applied afterwards bounds
nothing an observer has not already seen.

## 🕳️ What is not covered

Stated plainly, because a reader who assumes otherwise will size their risk
wrongly:

| Gap | Why it is open |
|---|---|
| **The native skill tier is trusted** | A `dyn Skill` compiled into the binary can open its own socket. The gate governs what goes through `cx.effect`, and nothing else. The Wasm tier is the intended answer and is not built |
| **An operator who holds the signing key** | Signatures bind authorship, not existence. Whoever controls the workload identity can produce a perfectly signed alternative history |
| **Split views** | Nothing stops a deployer showing one auditor one history and another a different one. Both verify. Closing this needs witness cosigning, which is designed and not built |
| **Revocation** | A delegation is valid until it expires; there is no revocation list, because checking one means I/O on the authorization path — the exact property removed so a gate cannot fail open under load. Chains are short-lived and audience-bound instead |
| **Implicit flows** | Labels track explicit data flow. Not side channels, not a model leaking through phrasing |
| **A compromised allowlisted endpoint** | Egress allowlisting decides *where* traffic may go, not what the far side does with it |
