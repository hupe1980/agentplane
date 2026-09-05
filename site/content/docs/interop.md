+++
title = "Models, agents and peers"
description = "Calling models, other agents and A2A peers: governed egress, MCP tools, media fetching, and exactly what crosses the wire."
weight = 10
+++

Everything this runtime calls that it does not own. The rule is the same at
every boundary: the far side is untrusted, the destination is declared, and what
comes back is labelled.

## Calling a model

A completion is an effect like any other — journaled once, replayed from the
record, untrusted on the way back. The prompt is part of the effect key, so an
edited template shows up on replay as divergence rather than as a run that
quietly did something else.

What is different is the meter.

### A failed call is not a free call

Every other outward call this crate makes either happens or does not. A model
call has a third state: it ran, generated four hundred tokens, and the stream
died. The provider bills those tokens. The answer is unusable.

Charging `Spend::default()` on a failure counts the call against `max_effects`
and counts **zero** against the token and cost ceilings — the ones that exist to
bound runaway spend. A retry loop against a flaky provider would then burn real
money against a limit reading nothing, so a failure is billed for what it burned.

So `EffectError::Metered` carries what was consumed, the ledger charges it on the
failure path, and `EffectFailed` records it — because without the record a
replayed run reaches a different budget verdict than the one that actually
happened.

### A died-mid-stream call is `Landed`

The usual reasoning about reaching the peer is inverted here. We know it reached
the provider: we watched it generate. What is missing is the *answer*, and
repeating the call buys a second bill for the same question. `InDoubt` would
invite `Recovery` to resolve an outcome that is not uncertain at all.

A refusal *before* generation — bad request, unknown model, rate limit — is
`DidNotHappen` and costs nothing. Rate limiting is the one case in this crate
where retrying is unambiguously safe, and the only one where the peer tells you
*when* — see [when the peer names the window](@/docs/plans-cases.md#when-the-peer-names-the-window).

### Why the budget fixture calls twice

A fixture making exactly one call passes whether or not the failure is billed,
because an interrupted stream is `Landed` and therefore never retried. The
fixture does what a real skill would — swallow the failure and ask again with a
reworded prompt — so the second call is refused by the ceiling the first call's
tokens consumed.

## Calling other agents

A peer hop is a tool call with two extra problems, and both are identity rather
than transport.

### Token confusion

To call a peer you hand it a credential. If that credential is not bound to *that
peer*, the peer can replay it elsewhere — and it need not be malicious to do so,
only compromised or confused. A bearer token sent to peer B and accepted by peer
A is the whole vulnerability class, and it is why OAuth grew Resource Indicators
(RFC 8707).

This runtime cannot make peer A check the audience. What it can do, and what
`PeerRegistry::credential_for` enforces, is never hand a peer a credential minted
for someone else. The check lives on the accessor rather than at the call site,
so no code path can reach a credential without passing it.

`PeerCredential` also refuses to render its own secret: this crate writes logs,
span attributes and error messages, and a secret with a `Debug` impl ends up in
all three. The audience stays visible, because that is the part worth debugging.

### The chain a peer receives is the run's

`cx.call_peer` extends the run's chain — `cx.acting_as()`, which on a served
plane is the *caller's* — by one link naming the peer, and dispatches through
the plane's own registry and transport (`RuntimeBuilder::peers`). A skill never
carries a registry or a client of its own: a chain a skill held in its own state
would be an ambient credential, the same owner on every peer call whoever asked
for the run. A run admitted without a chain has none to extend and is refused at
the call.

The peer is a server name in a grant. `tool://reviewer/audit.check` is offered
to a tool-calling model like any tool and dispatches to the registered peer
`reviewer`; the grant's protected fields and ceiling govern the hop at the sink,
its `mutates` can only make the hop more cautious than the registry's wiring,
and the answer is labelled with the same reference so a source rule can name
it. Which of the four things a server name can be — a tool transport, typed
tools, an agent on this plane, a peer — is settled once, at build, and a name
that could be two of them refuses the build.

### Obtaining the credential

`PeerCredential` models a token already bound to one audience. Getting one is
OAuth token exchange (RFC 8693) naming a `resource` (RFC 8707), behind the
`TokenExchange` seam.

Three decisions there are worth stating.

**A credential must never enter the journal.** The journal is append-only,
hash-chained, permanent and read by auditors — a bearer token in an `EffectDone`
record cannot be redacted later, because the record's hash covers it and the
chain would break. It can only be discovered. So acquisition is deliberately not
a journaled effect; it is transport metadata in the same sense a run's lease is.
Replaying a recorded token would be useless anyway, since it has expired.

Three things enforce that rather than describing it: the type has no
`Serialize`, so it cannot be written by accident; its `Debug` redacts, so it
cannot reach a log line or span attribute; and `tests/trust/peers.rs` runs a real peer
call and scans every record's bytes for the secret. `tests/guards/layering.rs` holds the
first two in place, because deriving `Serialize` on a credential is a one-word
change no compiler would object to.

**Freshness is measured against a margin, not the expiry.** A token with two
seconds left will lapse in flight, and the peer's rejection arrives as a failure
of *unknown* disposition — when it was really a refresh nobody scheduled.
`Cached` refreshes at `expiry - skew`.

**The issuer is not taken at its word.** An issuer that ignores `resource` hands
back a token the peer can spend elsewhere, which defeats the binding entirely, so
the returned audience is re-checked locally.

Expiry is checked against a supplied `now` rather than a clock read, which keeps
it testable at arbitrary instants and adds no escape to the determinism gate.

### Authority narrows at the boundary

A peer acts on our behalf, so it receives the caller's chain plus one link.
`Delegation::delegate` already refuses to widen and caps depth, so a hop cannot
lend a peer more than the caller holds, and a request cannot wander arbitrarily
far from the human who authorised it.

A grant wider than the caller's own authority is **refused, not clipped**.
Clipping would silently absorb a misconfiguration; an operator who granted a peer
`billing.*` from an agent holding only `audit.*` has made a mistake worth seeing.

The grant comes from the operator's registry, never from the peer's agent card —
for exactly the reason MCP annotations are not taken from a server. A party
describing its own privileges is not a source of truth about them.

### And the rest is the usual discipline

Fail closed on an unregistered peer. Responses untrusted — a peer feels like ours
because it is our agent, but it runs elsewhere, under someone else's control, and
may itself have read the internet. And a disposition on every failure that says
whether the request reached the far side.

## Calling peers and models over the wire

Two drivers ship, both off by default and both thin. What each carries is a
**failure mapping**, and that is the entire design content — the JSON is
commodity, the mapping decides whether a request may be sent again and whether
the budget is telling the truth.

### MCP, context and tools (`mcp`)

`McpClient` is a host, not only a tool transport. It uses one explicit
`host_info()` capability profile: Tasks are negotiated; elicitation, sampling,
roots and subscriptions are absent because the runtime has no governed callback
path for them. Advertising a callback and then handling it inside `perform`
would put nondeterministic human/model/filesystem work inside one effect and off
the journal.

Three data paths are built:

* `McpPrompt` performs an exact-granted `prompts/get`; arguments, server, name
  and sensitivity contract are in effect identity.
* `McpResource` performs an exact-granted `resources/read`; text and blobs stay
  typed protocol JSON and arrive untrusted.
* a tool may return `resultType: task`; `McpTaskPoll`, `McpTaskUpdate` and
  `McpTaskCancel` expose `tasks/get`, `tasks/update` and `tasks/cancel` as
  separate effects. Polling is a replayable read, updates bind the exact
  labelled responses and default to operator recovery, and cooperative cancel
  is idempotent but never mistaken for proof that work stopped.

For manifested agents, `spec.context` — prompts, resources, and `task_input`
for answering a server's input requests — is the review artifact and
`McpAccess::from_manifest` is the deployment catalogue; the gate refuses a
dispatch whose wired ceilings disagree with the grant's, in either direction.
Server discovery is still only a diff: an MCP server cannot grant itself a
prompt, resource or tool, and `agentplane serve` prints each server's
advertisement drift beside its negotiated version. Every call carries a
whole-request deadline — the transport itself waits forever, and a wedged
server would otherwise hang a step with nothing journaled — and a negotiated
version outside the set this host speaks is refused at construction, because
an unknown dialect cannot even be downgraded to.

**The negotiated protocol version is readable, because a downgrade costs
silence.** MCP answers an offered version with one the server speaks, and the
connection proceeds on that — a designed downgrade, unlike A2A, whose version is
asserted and whose mismatch is refused. An older server serves `tools/call`
correctly and simply never returns a task, so the Tasks extension above is
absent with nothing failing: a long-running tool behaves synchronously, a
governed suspension never happens, and no error names the cause.
`McpClient::negotiated_version()` reports what the handshake settled on rather
than what was offered, and `agentplane serve --mcp` prints it beside each
server, because the declarative tier has no Rust in which to ask.

### A2A, calling out (`a2a`)

The outbound effect is deliberately narrow: an A2A 1.0 JSON-RPC `SendMessage`
call to an operator-pinned endpoint. It sends `A2A-Version: 1.0`, declares its
extension in `A2A-Extensions`, uses ProtoJSON enum/part forms, and validates that
the response contains exactly one `task` or `message`. `CardClient` separately
provides Agent Card discovery, optional mandatory verification, and
binding/version/tenant-aware interface selection.

**Both A2A legs dereference a URL somebody else influenced, and both are guarded
the same way.** Discovery fetches the card URL; the outbound call connects to
the interface URL *the card advertised*, carrying this run's payload and a
bearer credential. A card is a description and never a grant, so a forged one
cannot widen authority — but it can name an address, and these are the two
places an address becomes a connection. Each resolves the host, checks every
answer against `netguard`, refuses redirects, and bounds the whole request. The
address check is the client's own DNS resolver, so it holds for **every**
connection the client opens rather than for the one request a pin was computed
for — which is what makes it real against DNS rebinding and what lets one
client be reused. Refusing redirects is what stops an allowed host handing the
decision to a third one. The
host allowlist stays optional on both, because a deployment that discovers
agents from the open internet cannot enumerate them in advance — with none set,
the address rule is the only lock, which is why it is unconditional. Loopback is
permitted only through a `testkit`-gated opt-in, and only for a host that *is* a
loopback literal or `localhost`, never one that merely resolved there. The server provides
`GetTask`, `ListTasks`, streaming/subscription, cancellation, durable push, and
extended cards. A returned Task becomes a typed `PeerTask`; `PeerTaskCall` polls
it as an untrusted journaled effect under the same peer grant and
audience-bound credential, and `PeerTaskCancel` asks the peer to stop it — a
run that commissioned remote work and is itself cancelled propagates the stop
instead of leaving the peer spending on an answer nobody will read. The cancel
is cooperative and safely retryable: a repeat of one that landed meets the
protocol's `TaskNotCancelable` refusal, never a second act. Strict replay
reads the recorded snapshot and never polls again. Subscription remains a server-side journal view rather than a
second client event channel; outbound callers use explicit polling or an
application webhook mapped into the existing inbound-event boundary.

A2A tasks are long-running and stateful, so "did the peer act?" is not a detail.

| Failure | Known | Disposition |
|---|---|---|
| DNS, TLS, connection refused | nothing was written | `DidNotHappen` |
| timeout, or the connection died after the write | it may have arrived | `InDoubt` |
| HTTP 401/403/404; JSON-RPC parse/method/params; A2A failed-precondition/input errors | read and declined | `DidNotHappen` |
| HTTP 5xx; JSON-RPC `-32603`; A2A `-32006`; malformed success envelope | arrived; whether it acted is unknown | `InDoubt` |
| a `Task` in state `TASK_STATE_FAILED`, `TASK_STATE_CANCELED`, or `TASK_STATE_REJECTED` | a task exists and may have acted | `Landed` |

The two expensive rows are the last two. `-32603` can be raised *after* a peer
has started work. A2A 1.0's `-32006` is `InvalidAgentResponseError`, mapped to
`INTERNAL`/HTTP 500 — not a clean decline. Treating either as proof that nothing
happened is how a half-finished transfer gets sent twice. Symmetrically, a task
in a terminal unsuccessful state is not in doubt: the peer created a task and
reported its outcome, so `Recovery` has nothing left to discover.

The delegation chain and provenance travel under a declared extension URI rather
than being smuggled into a free-form field, so a peer that does not understand it
still receives a well-formed message. The delegation chain remains a claim. The
provenance block is separately attested and bound to the call, so a peer with the
workload verifier can check who made that exact request; neither substitutes for
the peer's own authorization decision.

#### A plane with many agents serves a card for each

A2A's well-known card path is singular per host, so a plane hosting several
declared agents could give each its own card only by running a server per agent
— 28 specialists, 28 processes. `A2aServer::hosting(..)` takes the room's
manifests instead:

```rust
let server = A2aServer::hosting(runtime, auth, &security, &manifests, url)?;
// /.well-known/agent-card.json   → the first manifest's card
// /agents/researcher/agent-card.json → the researcher's own card
```

**The discriminator is a path, and that is a decision.** The obvious shortcut is
the `tenant` field A2A puts on every `AgentInterface`, and it is the wrong one:
its documented meaning is *the tenant id to send back on a request*, so
overloading it to select an **agent** would make every caller echo an agent name
into a field reserved for tenancy — and a plane that also serves several tenants
would then have two meanings in one string.

So the well-known path stays exactly what the specification says: one valid card
describing one real agent. An `agent-directory` extension on it lists every
agent, its card path and its **manifest digest**, so a caller can find the rest
without the plane inventing a discovery endpoint. Each agent's own card is the
card it would have alone — sharing a plane must not change the identity a
consumer pins, which is the same rule that makes a document's digest inside a
room file equal its digest by itself.

Dispatch already spanned every agent, because they are all on the runtime; what
was missing was only discovery. Two agents advertising **one skill id** is
refused at construction: A2A dispatch is named, never inferred, and a name
resolving to two agents is a routing decision the caller did not make.

#### Reading somebody else's card

`CardClient` fetches a card from the well-known path, optionally verifies it, and
selects an interface. Four rules, each of which exists because the obvious
version is wrong.

**Fetching is an egress decision.** A card URL usually arrives from a config, a
registry entry or a message — the first attacker-influenced string a deployment
handles — and "just fetch it" is how a plane is made to probe its own network.
The host is checked against the allowlist before the request is built, so a
refused host is never even resolved.

**Verification is opt-in, and once on it is mandatory.** Most cards in the wild
are unsigned, so a client that refused them all would not be used. But a client
that verifies *only when a signature is present* is one an attacker downgrades by
stripping it — so with a verifier configured, an unsigned card is refused.

**Selection matches binding and version.** An agent may publish the same binding
at several protocol versions; matching the binding alone picks an endpoint
speaking a protocol this client does not, and the failure then surfaces as a
confusing wire error rather than "we do not speak that". Card order is the
publisher's preference and is respected within the versions we can speak.

**The tenant travels with the endpoint.** A2A says to echo the selected
interface's `tenant` on every request and to omit it when the interface omits it.
A client that skips this can only ever reach an agent serving the default
tenant — which is why `Endpoint` carries it rather than leaving it to each call
site.

None of this produces authority. A card describes *reachability*; what a peer may
be sent comes from the operator's `PeerRegistry`. That split is what makes a
forged card survivable — the worst it can do is waste a request.

### A2A, being called (`a2a-server`)

The other half, and a different problem: everything arriving here was written by
somebody else.

A reader arriving from A2A should be handed the vocabulary rather than left to
derive it, because the two sets of nouns overlap without matching:

| A2A says | this runtime means | why they differ |
|---|---|---|
| `Task` | a **run** — one journaled, replayable execution | A2A's Task is the wire view of a run's lifecycle |
| `contextId` | a **case** — the long-lived matter many runs share | which is why every task carries one, and why a server needs a case layer to serve A2A at all |
| *(no equivalent)* | a **human task** — a worklist item awaiting a person | "task" is already three protocols' word; this one never crosses the A2A wire |

The mapping is deliberately at the adapter and not in the core's names:
protocols are wire contracts, and renaming the engine after one of several
adapters would make `task` mean three things in one codebase.

It is a **separate router**, not routes on the operator API. That surface's
invariant is that every route authenticates, and an Agent Card is public by
definition — it is what a caller reads *before* it has credentials. Adding one
unauthenticated path to a surface built on "every route authenticates" deletes
the invariant for the one route nobody would think to check.

| Method | Behaviour |
|---|---|
| `SendMessage` | blocking returns a completed `Task` with the answer artifact; `returnImmediately` returns a working `Task` |
| `GetTask` | state, bounded input history, and replay-reconstructed terminal artifacts |
| `CancelTask` | a durable stop request; the task stays `WORKING` |
| `GetExtendedAgentCard` | the authenticated card |
| `SendStreamingMessage`, `SubscribeToTask` | SSE status and artifact updates, read from the journal; terminal subscription is refused |
| `ListTasks` | newest-first, cursor-paginated and per-task-authorized tasks with context/status/time filters, bounded history, and optional artifacts. A content filter's cost is bounded (`filter_scan_budget`, default 1024 candidate reads): the spec's `totalSize` is the exact pre-pagination count, so an unbounded filter would let one field buy a scan of every run the tenant ever wrote — over budget is a refusal naming `statusTimestampAfter` as the lever that narrows from the index, never a quietly truncated total. Artifact inclusion is budgeted too — reassembling artifacts replays each task's run, so a page past the budget returns the remaining tasks without artifacts and marks each with `io.agentplane.a2a/artifactsOmitted` in `Task.metadata`, because a bounded result must not be shaped like a complete one; `GetTask` on the marked id recovers them, and a sealed-run cache keeps the reassembly from being paid twice |
| the push-notification configs | durable create/get/list/delete when wired; the protocol-specific refusal otherwise |
| anything else | `-32601`, method not found |

**One task has one state, whichever surface reports it.** `GetTask`, the row a
task occupies in `ListTasks`, and the snapshot a subscription opens with are
three views of one run's history, and they answer from one function that reads
it. Three copies of that reading would agree until a record kind was added or a
suspension reworded — after which a client that polled, one that listed and one
that subscribed would each be told something different, each would be behaving
correctly, and the protocol gives them no way to discover the disagreement. The
surfaces differ only in what an *empty* history means: no such task for a fetch,
a working row for a listing that must not fail its page over one unreadable run.

**Blocking is the default, and unset means blocking** — the spec's rule. A
successful blocking call returns the skill output as a text or data artifact; a
status-only completed Task would discard the answer and be useless to an
interoperable client.
`configuration.returnImmediately` switches to returning as soon as the task
exists, leaving the caller to poll `GetTask`. Admission still happens before
either returns: the policy gate, the lease and the admission records are written
first, so the id handed back is one `GetTask` can already answer for. Spawning
first and admitting later would hand out ids for runs the gate went on to
refuse, turning a decline into a task that never appears.

Further decisions are load-bearing.

**The card describes the deployment, not compiled code.** `A2aServer::new`
requires a typed bearer scheme and scopes, because a client cannot authenticate
from an abstract `Authenticator` it cannot see. Push stays false and its methods
use `PushNotificationNotSupportedError` until `with_push` supplies durable
registration/cursor storage and a governed transport. Configure before signing:
the capability is in the signed payload. `push_worker()` returns the handle an
operator schedules on each instance.

**Parts are a oneof.** Exactly one of text, data, raw, or URL must be present.
This server advertises text and JSON data; raw and URL file parts are refused as
unsupported before a skill runs, and a declared `mediaType` must agree with the
chosen member. Inbound messages must have `ROLE_USER`, so an unknown file field
or a server-role message is refused rather than accepted as ordinary input.

**Context continues with a new task; task input continues the same run.** A
message carrying only `contextId` opens another immutable run in the same case.
A message carrying `taskId` must name an `INPUT_REQUIRED` run and completes the
exact journaled wait effect on which it stopped. The event store inserts and
claims that message for the named run in one backend transaction; ordinary
correlation matching would be wrong because two tasks may wait on the same
business key. The authenticated peer and stable `messageId` form the dedup
identity, a supplied `contextId` must match, and retrying the message after it
completed the task returns the current Task rather than applying it twice.

**The 1.0 method names only.** 1.0 renamed every method; `message/send` was 0.3.
A server that answers both accepts clients which have silently lost half the
protocol, and they never find out, because the call works.

**A missing `A2A-Version` is a refusal.** The spec reads an empty value as 0.3,
so an absent header is a 0.3 client — and answering it with 1.0 semantics hands
it a response shape it will mis-parse field by field.

**The capability is named, never inferred.** A2A has no "call this skill" field;
the protocol assumes the agent works out what is being asked. This plane will
not. The skill comes from `message.metadata.skill`, matched against the card's
advertised ids; with exactly one skill there is nothing to infer, and with
several and none named the call is refused. Choosing what to run by reading
untrusted prose would let the sender pick the capability. The convention binds
both halves: this plane's own client writes its capability into that same
field, and the card declares it as an extension so a foreign caller learns
the rule before the first refusal rather than from it.

**A peer's message is untrusted.** It is admitted as `Tainted` with provenance
`peer:<caller>` — never as trusted input — so a protected sink field can name
the one counterparty it will accept an amount from. Admitting it as trusted
would let a value that arrived over the network wear the runtime's own
authority.

The skill receives stable `text` and `data` projections plus the exact inbound
Message under reserved `$a2a_message`. Keeping the original roles, Parts,
metadata, extensions and references in the admitted record is what lets
`GetTask` reconstruct history rather than inventing a look-alike message later.

Refusals carry the spec's codes rather than a generic error, because a caller
has to tell *this agent cannot do that* from *you spelled it wrong*: one is
worth reporting, the other worth retrying differently. For the same reason a
policy denial comes back as a `Message` decline rather than `-32603` — an
internal error reads as a transient fault, and the caller retries a decision
that will never change. The decline says only that it was declined: the
runtime's own denial names the action and resource the gate keyed on, which is
enough to map this plane's authorization vocabulary by probing it.

Back-pressure — a full quota refusing admission — answers with a
server-defined code (`-32029`) **and** a `google.rpc.ErrorInfo` under this
project's own domain, and the pair is the identity: JSON-RPC gives
implementations `-32000..-32099` while A2A 1.0 reserves `-32001..-32099` for
its own table, so the numeral alone can mean something else to somebody
standards-compliant. The client backs off only on the marked pair; a bare
`-32029` from a foreign server is an unknown fault and stays in doubt. The
message beside the code is one fixed sentence with no numbers in it — the
quota's counters are the operator's to read, not a prober's.

A halt is the other admission refusal, and it is deliberately **not** the same
answer: `-32030` with the reason `HALTED`, under the same domain and the same
pair-is-the-identity rule. A ceiling says *come back*; a halt says somebody is
dealing with an incident, and a peer that backs off and retries is doing
exactly what the switch exists to end. The message is fixed and carries none of
the operator's reason — the counterparty gets the outcome, not the plane's
internals.

Outbound, both legs refuse plaintext: the peer call carries the run's payload
and a bearer credential, and the card fetch decides where that call will go,
so neither speaks `http` to anything but a testkit loopback name — the same
rule push delivery applies to webhook URLs.

Push is advertised exactly when its durable worker is wired. Streaming is
advertised true because status and artifact events exist; `SubscribeToTask`
follows 1.0 by refusing terminal tasks.

#### A signed card says who published it

A card is fetched unauthenticated from a host a caller may not control. TLS says
the bytes came from that host; it says nothing about whether the host is the
party whose capabilities the card describes — and it says nothing at all once
the card has been copied into a registry, a cache, or a repository.
`A2aServer::signing_cards_with` attaches a detached JWS (RFC 7515) over the card
canonicalized per RFC 8785.

Four decisions carry it.

**It is a real JWS.** Everywhere else in this crate a signature covers a digest,
because everywhere else the input is already a hash. Here the signature is over
the standard signing input itself — `BASE64URL(protected).BASE64URL(payload)` —
because a card is verified by software nobody here wrote. Signing `H(m)` instead
produces a perfectly valid signature over the wrong message: it verifies against
our own verifier and is rejected by every conforming one. That is why card
signing has its own seam rather than reusing the record `Signer`.

**The algorithm comes from a constant.** The verifier never reads `alg` from the
card it is checking — that is the oldest JWS attack, and a card is precisely the
attacker-supplied document it was invented for.

**Signed at publish, not at derivation.** The signature covers the card as
*served*, interface URL and tenant included. Those are deployment facts; a
signature taken before they were set would cover a document nobody serves.

**Several signatures coexist**, so a publisher rotates keys without a window in
which nobody can verify the card.

Canonicalization is [`core::canon`](@/docs/architecture.md#canonical-bytes), which orders keys by
UTF-16 code unit and formats doubles by ECMAScript's rules, exactly as RFC 8785
requires — `1e+30` where `serde_json` writes `1e30`, which is the difference
between a signature every conforming verifier accepts and one only this crate
does. The standard's own number vectors are in the test suite. One bound is
enforced at the signature itself: an integer outside ±2⁵³ has no double of its
own, so a conforming verifier would recompute different bytes than were signed,
and `signing_input` refuses it naming the path — on both the signing and
verifying sides.

#### Push: the one URL a caller chooses

Every other outbound destination in this crate is granted by an operator. A
webhook URL is supplied by whoever created the task, which makes push the one
feature where an untrusted party names an address this plane will connect to,
with a payload about somebody's work.

Three controls, none sufficient alone:

- **An operator host grant.** A caller may pick any URL under a permitted host
  and no host outside it. This is the primary control; the rest are the second
  lock. Matching is exact — suffix matching is how a grant for `acme.example` is
  satisfied by `evil-acme.example`.
- **Every resolved address checked, at the moment the socket is opened.** One
  private answer refuses the whole resolution, so a name that answers with a
  public address and a private one reaches nothing. The check is the client's
  own DNS resolver rather than a per-request pin, which is what lets one pooled
  client serve a whole sweep — see [one client, judged at
  connect](#one-client-judged-at-connect).
- **HTTPS only.** The payload describes a task; sending it in clear to an
  address the recipient chose is a disclosure with extra steps.

The grant is re-checked **at delivery**, not only at registration. A
registration outlives the configuration that permitted it, and the tasks that
outlive a config change are exactly the long-running ones push exists for.

The **journal is the outbox**. Each registration stores the first sequence not
acknowledged by that receiver. Workers derive the same status and artifact
`StreamResponse` payloads as SSE and advance only after HTTP 2xx. A crash after
POST but before cursor persistence repeats the payload; it cannot lose it.
redb and PostgreSQL persist cursor, retry instant, attempt count and diagnostic.
Several active-active workers may duplicate delivery, which receivers are
required to process idempotently; monotonic advancement prevents regression.
Failures back off exponentially, terminal acknowledgement removes the config,
and registering after completion starts at the terminal record so it is not an
inert promise.

**A sweep is bounded, not serialised.** Registrations share no cursor, no
receiver and no task, so nothing about the cursor discipline requires them to be
served one at a time — and serving them that way requires only that every
receiver be as fast as the slowest. One endpoint sitting on its fifteen-second
timeout would decide when the rest of the plane's events go out, and a plane
with more due rows than a tick can drain falls permanently behind on all of
them. `DeliveryWorker::max_in_flight` bounds the fan-out (sixteen by default),
because a sweep is the one place this runtime knows how much outbound work
exists and `limit` is a page size rather than a concurrency budget. Ordering
*within* one registration is untouched: that loop is a cursor that may only move
forward.

#### One client, judged at connect

Pinning a connection to pre-approved addresses is the obvious way to stop a name
resolving somewhere else between the check and the connect. It costs an HTTP
client per destination — a pin is a property of the client — so a caller that
pins builds a fresh connection pool, TLS session and handshake for every
message. A delivery sweep or an agent delegating to a peer in a loop pays that
per event.

The rule lives in the client's DNS resolver instead. That keeps the guarantee
and drops the cost, and strengthens it: a **pooled** client opens connections
long after any pre-flight returned, and those are exactly the ones a one-shot
check never saw.

The pre-flight stays, and is not redundant — the two cover different things.
The pre-flight judges **every** destination once, including an IP literal, and
is the only one that can say *which* refusal happened: a DNS hook can only fail,
and a forbidden address must not read as a receiver that is merely down, because
one is never retried and the other always is. The resolver judges **every name
resolution**, which is what closes the window between that one check and a
connection the pool opens later.

An IP-literal host never reaches a resolver — the connector dials it directly —
and nothing is lost by that: a literal has exactly one address, the pre-flight
already judged it, and it is the one dialled. A name is the case with a second
answer in it. One rule, `netguard::judge`, called from both.

The three settings that make a client guarded are one constructor rather than
three a caller remembers, because they are not independent:

| Setting | Why it is not optional |
|---|---|
| custom DNS resolver | it is what judges the address at all |
| `no_proxy` | a proxied request resolves the **proxy**, so the resolver is never asked about the destination |
| `redirect::none` | a judgement about the endpoint says nothing about the third host it forwards to |

A client with two of the three looks guarded and is not, and the address it
would then reach is one no test can make DNS answer with on demand. So the
guarantee is structural, and the one behaviour a test *can* observe is that a
guarded client fails to reach a server genuinely listening on this machine.

Artifacts are delivered because A2A defines push and streaming over the same
union. This makes task-level authorization and the destination host grant
load-bearing: registering a URL is an explicit authorization to send that
task's updates there. The opaque A2A `token` is not confused with
`AuthenticationInfo`: only the latter forms the HTTP `Authorization` header,
while the token rides as its own `x-a2a-notification-token` header for the
receiver to validate a push's origin with. Credentials are never returned or
printed.

The IP classification is [`netguard`](@/docs/architecture.md#module-layout), shared with governed
media. Two implementations of one rule diverge, and the one that diverges is
whichever nobody probed at the boundary.

#### The stream is a view of the journal, not an event bus

The obvious way to stream progress is an in-process broadcast channel: a step
finishes, it publishes, subscribers receive. It is wrong here in three ways that
only appear in production.

A channel's events live in memory, so a subscriber that reconnects has **missed**
whatever happened while it was away and nothing can tell it what. A channel is
per process, so a subscriber attached to the instance that is *not* running the
work receives nothing — and which instance that is changes after every failover.
And a channel is a second record of what happened, which can disagree with the
first.

Reading updates from the journal instead makes the stream exactly as durable as
the run: a client that drops and re-subscribes picks up the current state and
continues, any instance can serve it, and the events cannot disagree with history
because they *are* history. The cost is a poll rather than a push — one indexed
read per subscriber per interval — and it is stated rather than hidden.

Two endings, not one. The spec requires closing on a terminal state; this also
closes on `INPUT_REQUIRED`, because a suspended run may be waiting on a person
for a week and holding a connection open for that is a leak with a spec
reference. Reconnecting costs the client nothing, since the stream is rebuilt
from history rather than resumed from memory.

There is deliberately **no SSE keep-alive**. It was tried: with it the response
body did not end when the stream did, so the connection outlived the task — the
exact failure the design is shaped to avoid. An idle stream may be reaped by
an intermediary, which is the better failure, because a client can recover from a
closed connection and cannot recover from one that never ends.

### Model providers (`providers`, `bedrock`)

The `providers` feature ships four HTTP drivers: Anthropic Messages, OpenAI
**Responses** — Responses rather than Chat Completions because it is the current
primitive and reports both usage and completeness directly — Google Gemini
`generateContent`, and a `chat-completions` driver for the OpenAI-compatible
wire every self-hosted server speaks. The separate `bedrock` feature ships
Amazon Bedrock Runtime Converse through the AWS SDK; separate gating avoids
imposing its dependency graph on the HTTP drivers.

They exist partly to prove the seam is right — that a driver can report *what a
failure consumed* — and partly because the thing a driver must not get wrong is
not the transport. Three of the four carry provider-owned continuation
state (OpenAI's encrypted reasoning items, Anthropic's signed thinking blocks,
Gemini's thought signatures), and all three do it the same way: **the provider's
own turn, verbatim and opaque**. That is a shape rather than three
accommodations. A driver that normalises the assistant turn into a neutral
representation has nowhere to keep what it does not understand, and what it does
not understand is exactly what the next request has to return.

Status classification is shared between them, in `model::wire`, because it is
doctrine rather than vendor detail:

| Response | Metered |
|---|---|
| connect/DNS/TLS failure, `4xx`, `429`, `529` | no |
| `5xx` | *unknown* — see below |
| a generated refusal, or an answer with no text | **yes** |

A refusal *before* generating costs nothing; a refusal *after* costs whatever it
took to decide. A budget that cannot tell them apart under-counts exactly when a
model is being difficult.

Details worth stating:

* **There is no stale universal model-profile boolean.** Provider SDKs expose
  model profiles, native web/code/MCP tools, tool search, caching and compaction,
  but those features do not share execution, billing or replay semantics.
  Portable capabilities such as tools, schema mode, continuation and streaming
  are typed here; provider-specific capabilities remain explicit provider
  configuration. Provider-native tools are not represented as ordinary
  `ToolDeclaration`s because they execute outside the plane's tool sink.
* **Deferred tool search is not authority discovery.** Current OpenAI and
  Anthropic models can search thousands of deferred tools, which improves token
  cost. Letting that search load executable authority would bypass exact
  manifest review. Applications should keep the initial surface small or expose
  an aggregate/governed retrieval tool until a search effect journals the query,
  loaded definitions and grant recheck.
* **Provider configuration that changes the wire is effect identity.** Each
  driver publishes a non-secret request profile: endpoint, API/driver version,
  per-model schema mode, streaming mode and timeout. Strict replay therefore
  cannot reuse a completion produced under a different provider request shape.
  API keys are transport credentials and never enter the profile or journal.
* **Every call is time-bounded.** All drivers apply a configurable whole-request
  timeout, five minutes by default, across connection, generation and stream.
  A timeout after streamed output uses the same partial-generation accounting as
  any other severed stream.
* **A severed stream is classified by what its wire already said.** Three rungs:
  `Interrupted` once usage is known, which carries a bill; `Unaccounted` after
  generation without usage, never free and never counted; `Unavailable` before
  generation, safe to repeat and costing nothing. Which rung a provider can
  reach is a property of its wire — Anthropic, Gemini and Bedrock report usage
  as the answer is delivered, so a cut connection carries a bill; OpenAI's
  Responses stream and the Chat Completions wire report it only in a terminal
  event, so a cut one can say generation happened and nothing more.

  Every driver must reach the best rung its wire allows, because *this provider
  cannot do better* and *this driver did not look* produce the same
  `Unaccounted` and only the first is honest. Under-reaching is invisible to any
  test that checks the variant rather than the counts, and its cost is that the
  token ceiling bounding a runaway provider reads zero during exactly the
  failure it was bought for. Each streaming driver therefore carries a test
  asserting the rung it claims.
* **Reasoning effort is typed and digest-covered.** `none`, `minimal`, `low`,
  `medium`, `high`, `xhigh` and `max` map to OpenAI `reasoning.effort`;
  Anthropic accepts its supported subset and renders adaptive thinking plus
  `output_config.effort`, refusing unsupported values before dispatch. The
  manifest field reaches declarative completion requests.

  Reasoning-enabled tool continuation is self-contained and journaled.
  `Completion::continuation` carries provider-tagged opaque state; the next
  `ModelCall` commits to it in effect identity. OpenAI round-trips complete
  Responses output items, including encrypted reasoning and assistant phase.
  Anthropic's buffered path retains complete assistant blocks and its streaming
  accumulator reassembles thinking and signature deltas before tool results.
  A missing or wrong-provider state fails closed. No `previous_response_id` or
  provider-held conversation is replay truth.

  OpenAI Responses also set `store: false` by default. Provider retention is an
  explicit `OpenAi::retain_responses` opt-in and enters the provider profile and
  effect identity, so changing data handling cannot silently reuse an old
  completion. A retained response id remains an operational correlation handle,
  never replay truth.

* **Bedrock streams conservatively.** Converse text, governed inline
  images/documents, tools/results, signed or redacted reasoning continuation,
  usage, truncation, native JSON Schema and forced-tool fallback are supported.
  Document names are constant and neutral because Bedrock treats them as model
  input. `ConverseStream` is the default;
  `.buffered()` opts out. Region, stream mode, timeout and schema mode enter the
  provider profile. Access, validation and not-found errors are refusals;
  throttling and model-not-ready are retryable. Stream failures follow the three-rung ladder
  above, reaching `Interrupted` because `ConverseStream` reports usage in its
  metadata event. A *universal* reasoning-effort mapping
  remains refused rather than guessed across model families; a **declared** one
  is rendered. `.reasoning(ReasoningDialect::Nova)` names the family a driver
  instance serves and sends Amazon Nova 2 extended thinking as
  `additionalModelRequestFields.reasoningConfig` — declared rather than read off
  the model id, in the request profile so switching it is divergence, and
  refusing the levels Nova has no counterpart for rather than collapsing them.

* **Live deltas are labelled projections, not replay truth.** An optional
  `ModelStreamObserver` receives visible text and terminal usage while the
  provider still produces one canonical completion. Events inherit untrusted
  trust and the call's output sensitivity; opaque reasoning is never exposed.
  Observer delivery is advisory and strict replay emits no live events.

* **Structured output has two modes, because native support is not universal.**
  `SchemaMode::Native` uses the provider's constrained decoding, where a
  non-conforming answer is *unproducible*. `SchemaMode::ForcedTool` declares one
  tool whose input schema is the answer's shape and forces it with `tool_choice`
  — the universal fallback, working wherever tool calling does. Native is the
  default so an unconsidered deployment gets the strong thing; emulation is
  weaker in one stated way, so a model that ignores the forced call is a loud
  metered failure rather than an empty success.

  The mode is resolved **per model**, not per driver — the constraint belongs to
  the model and one driver serves many. Anthropic's Models API can be asked which
  capabilities a model has; OpenAI's `/v1/models` returns no capability flags at
  all, so configuration is the only answer that works for both. On OpenAI,
  `strict: true` inside a *function definition* works on every tool-capable
  model while native `text.format` is newer-models-only, so emulation there is
  the more compatible option at the same strictness.
* **A schema strict mode cannot accept is refused before it is sent.** OpenAI's
  strict mode takes a subset of JSON Schema — `additionalProperties: false`
  everywhere, every property in `required`, no `default` — and rejects the rest
  with a 400 that does not say which rule broke. The driver names the rule, and
  does not rewrite the schema: that would make the effect key record one shape
  while the wire carried another.
* **Provider enforcement is not blindly trusted.** Returned structured output is
  parsed and validated locally against the exact requested schema. External
  schema reference resolution is disabled, so validation cannot become hidden
  network or file I/O. Parseable but non-conforming output is a metered unusable
  result.
* **Reasoning tokens are billed and invisible.** A driver reporting only readable
  output would tell a reasoning-heavy run's budget it cost a fraction of what it
  did.
* **A cut-off answer says so.** `Completion` carries a typed `truncated` flag
  rather than a stop reason the caller has to recognise. It is not an error —
  prose that stops early is readable, and only the caller knows whether they were
  parsing JSON — but a partial answer returned as a whole one is exactly the
  silent truncation refused everywhere else.
* **A provider's error body is trimmed** before it becomes an error message.
  Providers echo the prompt back in error payloads, and a prompt carries whatever
  the run was working on; an unbounded message turns a failure into an
  exfiltration channel into the log aggregator.

`ModelError::Unavailable` names the 5xx case instead of guessing it. Both guesses
are wrong in different ways — fatal makes a blip end a run, free lets a retry
loop spend against a ceiling reading zero — so it is treated as safe to repeat
(a completion does not change the world) with the documented cost that the
ceiling may under-count by at most one call. A streaming driver whose wire reports usage
must report `Interrupted` with what it saw, rather than the `Unaccounted` a
driver that merely did not look would produce.
