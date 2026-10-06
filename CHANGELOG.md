# Changelog

Notable changes per release, on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

**Written for somebody who already depends on a version.** Each entry says what
changed and what to do about it. Moving a deployment between builds is the
[upgrading](https://hupe1980.github.io/agentplane/docs/upgrading/) procedure;
why a design was chosen is not here.

**Two categories are ours.** `Assurance` is a change to what the project can
*prove* — a guarantee that gained a test, a surface walked adversarially.
`Known` is a limitation shipped deliberately.

**Pre-alpha.** `0.x` bumps carry breaking changes with no deprecation cycle.
Breaking entries are marked **BREAKING**.

Entries for `0.1.0`–`0.9.0` are reconstructed from tags and commit history.

## [0.46.0] — unreleased

### Added

- **A peer can be told who asked.** `PeerGrant::with_source` presents each
  call, task read and cancel with a credential for the run's owner, checked
  for audience and subject; a run acting for nobody is refused.
  `EffectStarted.credential` records which kind went out, and a `subject:`
  halt now pauses a run at its next such call. **BREAKING:** the
  `TokenExchange` and `CredentialSource` methods take the subject;
  `PeerTaskCall`/`PeerTaskCancel::prepare` take an `Asker`;
  `prepare_with_credential` and `Fixed` are removed. Record change: hard cut.
- **An approval of a consultation shows the agent it hands work to.**
  `Justification::reach` states the consulted agent's revision, grants,
  budgets and delegation ceiling, read once and journaled (`agent.reach`) and
  inside the task digest; the consultation is pinned to that revision, so a
  callee redeployed since is refused, naming both. Coded skills get
  `StepCtx::reach` and `StepCtx::commission_pinned`. The stored
  justification gains an optional field (hard cut).
- **A plane can follow every model call's live output.**
  `RuntimeBuilder::observe_model_streams` takes a `RunStreamObserver`, which
  receives each call's text deltas and usage with its run — declarative agents'
  calls included. Advisory and live-only, as `ModelCall::streaming_to` is.
- **An effect's outcome records how long the call took** (`EffectDone` and
  `EffectFailed` gain `elapsed_ms`). Record change: hard cut, versions stay 1.
- **A consultation names the run that answered it.** The journaled output of
  an `agent.commission` effect carries the sub-run's id (`run`).
- **`peers::TokenEndpoint`** (`a2a`): RFC 8693 token exchange against the
  deployment's issuer, naming the run's owner as subject and the plane as
  actor. HTTPS only; an issuer's 4xx refusal is final, never retried.
- **Content rules (`spec.security.content`).** Deterministic `pattern`,
  `contains` and `invisible` rules at admission, sources and sinks that
  `refuse`, `classify` or (at a sink) `redact`, plus `checks` handed to a
  `ContentChecker` (`RuntimeBuilder::content_checker`). `agentplane content
  check` runs them offline. A sink refusal is a `PolicyDenied` under
  `effect:content`. Record change (hard cut): `EffectStarted.content_rules`,
  `EffectDone.content`. → [security](https://hupe1980.github.io/agentplane/docs/security/#content-rules)
- **A subject's trace follows the data a run took in.** `spec.data_subjects`
  (`$input/<pointer>` or `$case`) or `RunTerms::subject` binds a run's
  subjects into a sealed `DataSubjectBound` record, and values derived from
  its input, events and case state carry `Label::data_subjects`.
  `agentplane subject` lists what it touched; an unresolvable binding refuses
  the run (`SubjectUnbound`). Record change: hard cut.
- **One matter can leave the plane without the rest.** `agentplane export
  --case/--run --to --actor` writes a disclosure package that both readers
  verify leaf by leaf; the act is recorded first, erasure and retention name
  each copy, and `agentplane disclosures` lists them. A package proves
  inclusion, not completeness, and restore, replay, `policy check` and
  `grants` refuse one. Export format change: hard cut.
- **A page for trying an agent.** `agentplane dev <manifest>` serves one
  loopback page, behind a per-process token, to start, follow, cancel and
  re-run runs; watch the model write; read a run as a timeline or a
  conversation, with call durations and spend; deliver events; decide tasks;
  strict-replay and export. Saving the file rebuilds the plane. It runs only
  over memory or a `--scratch` directory it created. Feature `dev`.
- **One run's journal in the terminal.** `agentplane history <run> --store …`
  prints each record escaped, and exits `1` for a run the store does not hold
  whatever `--from` names; `--json` prints the history route's records, where
  JSON escapes only U+0000–U+001F (`journal::view::record_view`,
  `core::visible::escape`).
- **A decision can name the version of the task it was made against.** Every
  task view and `agentplane tasks` serve `digest`, the stored row's version; a
  decide body's `digest` or `decide --digest` refuses a row that changed since,
  with nothing recorded (`412`, exit `1`, `RuntimeError::TaskChanged`,
  `Runtime::decide_task_at`).
- **A checkpoint says how fresh it is.** `audit --max-checkpoint-age` judges
  each witness key's signed cosignature time against the auditor's clock, and
  `serve --witness-submit … --witness-interval` re-submits an unchanged
  checkpoint so an idle plane stays fresh (`Cosignature::timestamp`).
- **An outside verdict can be bound to the records it judged.** `agentplane
  bind` writes a grader-verdict sidecar over `(run, last_seq, last_hash,
  open)`; `verify --grader-verdict` and `tools/verify_export.py` refuse one
  whose prefix no longer matches (`grader_verdict`).
- **The second reader checks who signed.** `tools/verify_export.py` verifies
  record signatures (`--key`), witness cosignatures (`--witness-key`) and
  grader-verdict signatures (`--grader-key`), and judges checkpoint freshness
  (`--max-checkpoint-age`). **BREAKING:** both readers refuse a small-order
  Ed25519 key.
- **An admission can pin the declaration revision.**
  `RunTerms::expect_declaration` and `run --expect-digest` refuse, before policy
  and with nothing recorded, when another revision or no declaration governs
  the capability (`RuntimeError::DeclarationPinMismatch`).
- **Where a subject's data went.** `agentplane subject <subject>` and
  `subject::Trace` list the outbound effects whose clear label provenance names
  the subject's memory items, and the recalls that read them, read-only, beside
  a coverage list naming every class of flow the report cannot trace.
- **Which grants an agent never used.** `agentplane grants --from <export>
  --manifest <file>` and `grants::Grants` mark each tool grant used, unused or
  not established (sealed or erased calls), report menus and egress headroom,
  and with `--propose` write a manifest with whole unused grants removed.
- **An agent framework reaches the plane over MCP.** `serve --mcp-addr`
  serves the file's agents as MCP tools over Streamable HTTP at `/mcp`, under
  `--tokens` and `--policy` (`mcp:*` actions) with `Host`/`Origin` checks;
  each call is admitted as the token's actor, and a session belongs to its
  creator. Feature `mcp-server-http`; library `tools::serve_http::McpHttp`.
- **BREAKING: `execution.kind: call`** dispatches the one granted tool with the
  input as its arguments, with no model. The input is validated against
  `spec.input` — which must be closed (`additionalProperties: false`) — and
  against the tool's declaration, as a planned step's arguments are.
  `ExecutionKind` gains `Call`.
- **BREAKING: served MCP speaks `2025-11-25` too, per extension.** A host
  without the Tasks extension, on either revision, is offered only tools whose
  runs cannot suspend (`Manifest::may_suspend`); older revisions are refused.
- **`serve` takes a room file.** A2A serves its one `topology.role:
  orchestrator`, refusing a room without exactly one.
- **`agentplane init --serve <DIR>`** writes a plane ready to run: starter
  agent, shipped policy, generated tokens and Postgres password (`0600`),
  `store.env` and a loopback-only `compose.yaml`. It refuses to overwrite,
  cleans up after a partial failure, and the plane refuses to run as root.
  Needs the `:full` features.
- **Framework quickstarts** for the OpenAI Agents SDK, LangGraph, Pydantic AI,
  Google ADK and Microsoft Agent Framework (`examples/frameworks/`), each with
  a hash-pinned `requirements.lock`. `just frameworks` runs them against the
  `:full` image, on every push to `main` and before a release image is
  signed.
- **A Helm chart** in `deploy/helm/agentplane/`: non-root, read-only, the
  operator listener on its own `ClusterIP` Service, the Postgres connection
  string from a Secret (`storeSecret.existingSecret`, as `AGENTPLANE_STORE`),
  `sessionAffinity: ClientIP` with more than one replica (MCP sessions are
  per-pod), a pod rolled when either Secret changes on upgrade, and render
  failures for more than one replica without a Postgres store and for a `store`
  value holding a password. Not published.
- **BREAKING: the shipped `serve-policy.cedar` grants more.** `operator` gains
  the on-call verbs (`api:halt.place`, `api:halt.lift`, `api:run.abandon`,
  `api:effect.reconcile`, `api:hold.place`, `api:hold.release`) and the reads
  beside them (`api:run.history`, `api:halt.list`, `api:run.live`,
  `api:run.waiting`, `api:attention`); `framework` gains `mcp:prompt.read` and
  `mcp:resource.read`. Lifting a legal hold goes to the same role; the bundle's
  header says how to give it to another. Re-read a copy you rely on to deny
  them.
- **The operator API has an OpenAPI 3.1 document**, generated from the
  router: published as `openapi.json` on the guide site and printed by
  `agentplane openapi`. It is outside the compatibility promise. A build
  without `push` answers `/push` routes with 501.
- **A generated Python operator client**, `clients/python/agentplane_operator.py`:
  standard library only, one method per operation, `OperatorError` on every
  refusal and on every redirect, which it never follows. Copy it; regenerate
  with `tools/gen_operator_client.py`.
- **Every shipped reader reads through an upcaster.** Both stores
  (`upcasting_with`), `export::verify_with` and `export::from_jsonl_with`
  default to `journal::current_upcaster()`; `verify` reads a record's version
  from its bytes before it believes a failed parse, and a version no upcaster
  reaches is a skew, never an edit. Record bytes that hash to their claim and
  are not canonical are a `verify` finding, and `restore` refuses them;
  `tools/verify_export.py` reports them too.
- **A restore keeps the bytes each record was written with**
  (`Append::restored`, `Record::seal_at`), so a chain restored across a shape
  change hashes as the exported one. **BREAKING:** `ExportedRecord::body` is an
  `export::DisplayBody`; build an `Append` with `Append::new`; an external
  `JournalStore` must store `Append::written()` bytes unchanged
  (`testkit::conformance::check_upcasting`).
- **The upgrade across a shape change is rehearsed in-tree** over an export one
  record shape older (`testkit::older_shape`). The upgrading guide states
  readers before writers, when the rollback window closes, and that standing
  authority is re-issued after a restore.

### Changed

- **BREAKING: an erasure takes the disclosure register.** `blob::erase_case`
  and `blob::erase_run` take `Option<&dyn DisclosureRegister>` and return the
  copies they name (`blob::Erased`, `Vec<String>`); `retention::Stores` and
  `runtime::Stores` gain `disclosures`, and `FullBackend` requires the register.
  `JournalStore::inclusion_proof_at` proves at a past size.
- **BREAKING: a body the operator API cannot read answers the documented
  error object.** Malformed JSON, a wrong content type, an unknown member, or an
  undecodable path or query answered axum's plain text; it is now
  `{"error": "<sentence>"}` with the same status. Every answer is a named,
  schema-derived type; no member moved. `Api::router` is built from
  `api::openapi::ROUTES`.
- **BREAKING (record change): lifting a halt and releasing a hold name who
  did it.** Each is journaled first, as the sealed run of a new record kind
  (`HaltLifted`, `HoldReleased`). `Runtime::lift_halt` takes the operator and
  returns `ControlLifted`; `Runtime::release_hold`, `lifted_halts` and
  `released_holds` are new. A control re-placed in between stays and the lift
  fails (`RuntimeError::ControlStands`). `--lift` requires `--actor`;
  `halt list --lifted` and `hold list --released` read the history. A sweep
  seals a lease-free run a crash left unsealed.
### Assurance

- **Every protocol the release bar names is model-checked or answered by a
  written decision.** New TLA+ models: `Quota`, `RateWindow`, `SinkGate`,
  `KeyLifecycle`, `Delivery`, `TaskDelivery`. `tla/verify.sh` discovers every
  spec and checks liveness mutants (`--self-test`, `--only`).
- **The erasure guide places every record kind and store** against the clear
  digests an erasure does not reach, with the remedies. A test recovers an
  erased low-entropy value from an export's effect key and release digest; a
  guard fails on a record kind the page does not place.
- **The security guide lists the context of every gate** — `run:admit`,
  `data:release` and the keys all three share — held to the request builders by
  a guard.
- **`RunAdmitted.admitted_by` is held clear through an erasure**, by a test
  that erases a run's case and reads the initiator back.

### Security

- **A halt thrown with `agentplane halt` stops `serve`, `run` and `replay`.**
  Every plane the binary builds comes from one helper that wires the quota
  store. Before, those verbs built planes without it: halts were never read,
  the halt and live-run routes answered 500, and a tool `rate_limit` refused to build.
- **BREAKING: `FullBackend` requires `QuotaStore`, and `Stores` carries
  `quotas`.** `builder_on`/`builder_with` wire it with no ceilings, so a
  library-built plane obeys halts, subject withdrawals and rate ceilings
  without `.quota(..)`; `.quota(store, limits)` is needed only to state
  limits. A plane with no quota store resumes a run unless one of its passes accrued spend to a period; an
  admission slot it cannot give back is released by the ledger's own plane
  once the run is sealed (`SweepReport::slots_released`).
- **BREAKING: an A2A continuation is authorized on the kind it delivers.** A
  message with `taskId` asks `a2a:event.deliver` on the awaited event's kind as
  well as `a2a:task.continue`, so the kind rules `POST /events` enforces hold on
  both doors. The example bundle grants it on no kind, with a commented
  per-kind rule to copy.
- **A2A push registrations are bounded:** at most 10 per task and an id of at
  most 128 bytes (`INVALID_PARAMS`); re-registering a held id still replaces it.
- **BREAKING: A2A answers a refused credential with HTTP 401** and
  `WWW-Authenticate: Bearer`, not HTTP 200 with `-32600` — including a valid
  credential for a tenant the endpoint does not serve, refused in the same
  sentence as any other so it does not say the token is valid elsewhere.
- **The operator API no longer echoes an unevaluable policy set's reason**;
  the 500 carries a fixed sentence and the reason stays in the operator's log.
  A plaintext-peer refusal names the host, not the URL.
- **BREAKING: a compensation or group reversal is checked against the
  declaration and the policy**; only the budget exempts it. A refused undo
  fails its compensation and the run quarantines.
- **The person a run acts for cannot decide its tasks.** Beside the admitting
  caller, four-eyes bars the root and acting subject of a caller's chain; a run
  admitted as the plane (`RunAdmitted.plane_chain`) bars neither, even when a
  caller presents an equal chain.
- **BREAKING: a `subject:` halt matches any principal on a run's chain**, so
  withdrawing a person stops what a delegate does for them, at admission and
  in flight.
- **A2A `GetTask` and `CancelTask` authenticate before reading the task id**;
  a malformed id no longer earns an unauthenticated caller `TASK_NOT_FOUND`.
- **A sealed export is refused by a tenant its envelopes do not name.** Its
  ciphertext opened for nobody there, and `erase_case` destroyed a key that
  wrapped none of it while reporting success.
- **BREAKING: a policy principal is typed.** `PolicyRequest.principal_kind`
  says whether it is a chain subject or API caller (Cedar `Subject::"…"`) or a
  chainless run's capability (`Capability::"…"`); `Agent::"…"` is gone, so a
  rule for the person `alice` no longer admits a capability named `alice`.
  The evaluator is `agentplane-adapter/5`, and every bundle digest moves:
  drain open runs before upgrading, and rewrite `Agent::` rules.
- **BREAKING: a wait can name its sender.** `AwaitSpec::from(source)` and
  `Subscription.from` hold every delivery path to that `InboundEvent.source`,
  which for an event over the API or A2A is `peer:<actor>`. Postgres adds the
  column at open; a redb store written by an older build refuses to open —
  recreate it and restore from an export.
- **BREAKING: erasure reaches the semantic index.** `SemanticRetriever::forget`
  is required; `IndexedMemoryStore` tells it after every erasure verb, owing the
  next verb what it could not. A sealed store (new required `MemoryStore::seals`)
  holds the index beneath the seal, or `build` refuses it.
- **BREAKING: a `Release` or `ReleaseScope` is validated on deserialization**:
  one read from a journal, wire or file is refused when its scope improves
  nothing, its basis or destination is blank, its field scope is empty or not
  JSON Pointers, or it names no evidence — as the constructors refuse.

### Fixed

- **BREAKING (store schema): a message is consumed once, by the one wait that
  claimed it.** A run's second wait on a key was handed its first message
  again as `null`; a retried targeted message could be a second turn; and
  retiring one wait shed every claim its run held. A claim now names its
  wait. redb and Postgres event tables change: recreate the store.
- **A delivery to a run whose conclusion is durable journals nothing.** A
  message or timer arriving between a run's conclusion and its seal left the
  run unsealable; it now finishes the run. `EventStore::unsubscribe_run`
  takes the unanswered waits and returns their claims for the next waiter,
  dead-lettering any addressed to that run.
- **A counterparty's retry offers a message a crash left unmatched**, instead
  of being answered `Duplicate` from the dedup alone.
- **A decision that lost to its run's conclusion is refused**
  (`ClaimError::NotPending`) instead of reported delivered.
- **The key-ring battery runs against `MemoryKeyRing`**, and holds that a
  second destruction leaves the first one's account standing.
- **BREAKING: `serve --url` is the A2A endpoint**, `/a2a` under the public
  address: the card advertises it as the interface URL, and the guides'
  bare-host form sent every card-following client to a path that answers 404.
  `serve` now refuses a `--url` that does not end in `/a2a`, naming the URL to
  pass.

- **BREAKING: embeddings are metered.** `Embedder::embed` returns `Embedded`
  with the service's reported usage (the OpenAI wire, Titan, Gemini), which
  counts against the run's ceilings; `.pricing(..)` prices it, and a money
  ceiling beside an unpriced embedder is refused at build. A priced embedder
  whose reply reports no input tokens refuses the call rather than metering it
  free — Cohere on Bedrock reports none, so a priced Cohere embedder refuses
  every call.
- **BREAKING: rate rows are kept 31 days, whatever the window.** A narrower
  declaration no longer prunes a wider one's count; `rate_limit` windows above
  31 days are refused at parse, and a `RateCeiling` built in code with a window
  of zero or above 31 days is refused at reservation
  (`QuotaError::UncountableRate`).
- **Zero or negative deadline counts are refused** by `WallClock` and at parse.
- **BREAKING: `Quorum::tally` takes `(lens, verdict)` pairs** and refuses an
  unknown or repeated lens; `core::QuorumOutcome` is `PanelOutcome`.
- **A Gemini stream refused at the intake ceiling reports the usage** its
  chunks carried; a result answers under the provider's call id. SSE decoding
  is linear in the bytes received: a line arriving over many chunks is
  searched once, and invalid UTF-8 is replaced in one pass.
- **`models.<role>.max_tokens: 0` is refused at parse.**
- **BREAKING: standing-authority `expires_at` and revocation `at` serialize as
  RFC 3339**, which changes the stored authority rows: recreate the store and
  re-issue standing authority.
- **The authenticator battery records a panic** and probes `Bearer` with no
  token, as its doc claimed.
- **`tasks` and `waiting` exit 5 when `--limit` cut the listing short**, and
  both print `truncated`, as the exit-status table says.
- **A store the plane was built without is 501 on every operator route** —
  halts, live runs and push re-arm answered 500 or 409, and a task decision or
  an event delivery answered 409.
- **MCP task ids over stdio are documented as bearer capabilities**: no host
  is authenticated on a pipe and a task outlives its session.
- **A stop on a resumed run unwinds with the recorded outputs, in reverse
  completion order.** The cancellation and withdrawal checks wait for the
  resume's frontier, so replayed steps refill what the unwind reads; a ready
  set holding recorded and new steps replays the recorded ones first.
- **Recovery finishes a concluded run instead of resuming it**, with or
  without a quota store: it seals or releases the lease. A compensated run no
  longer fails recovery every lease period.
- **A resume registers the run first** — its case membership and outbox
  destinations — so an admission that failed or died partway is watched once
  it runs. **BREAKING:** case attachment follows the admission append, and
  `CaseStore::detach_run` is removed; a registration refused after the append
  concludes the run `failed`.
- **A plane with no case store refuses to resume a case-bound run**
  (`RuntimeError::NoCaseStore`), whose records would otherwise sit outside the
  case erasure reaches. A stop or a delivered answer on such a plane is
  recorded and left to a plane with one, as with no provider.
- **A successor plan the build cannot read refuses the resume** instead of
  being skipped, which shifted every later replan.
- **A no-op resume under a quota appends nothing.** A resume's quota pass
  marker rides its first append, so a resume reaching the conclusion the run
  holds writes neither a marker nor a second conclusion, and the run's last
  record stays its conclusion. When that append is a conclusion, the marker
  goes just before it, so the conclusion names the head it sits on.
- **BREAKING: `restore` refuses a store already holding any run in the file**,
  or one that seals as it writes (new required `JournalStore::seals`), before
  writing, and checks every rebuilt record's hash against the file's; a
  retried partial restore appended open runs a second time.
- **The in-flight walk pages by run id** (**BREAKING:** new
  `JournalStore::runs_by_id`), so a run appending mid-walk is still exported.
- **Export reads log positions in one pass** (`JournalStore::log_positions`,
  defaulted) instead of rereading the whole log per run.
- **A sealed Postgres journal lends its transaction**, sealing the group's
  records inside it; every atomic group on a sealed plane was refused.
- **A sealed append hands back the plaintext it was given** rather than
  re-opening its own ciphertext, so a KMS failure after commit no longer
  reports a committed write as failed. A sealed text payload that opens to
  non-UTF-8 is an error, not a silent sealed field.
- **BREAKING: `export::to_jsonl` takes the case store**, and records naming
  cases in a file with no case block are a finding, as in the second reader.
- **BREAKING: an export under an unknown `canon` is unverifiable**: both
  readers stop at the header (`VerifyReport::unverifiable`), and `restore`
  refuses it before opening the store; `verify`, `restore` and
  `tools/verify_export.py` exit 6, `restore` only for a header of this format
  version. Before, Rust rehashed with SHA-256.
- **Both backends refuse to seal a run whose last record is not its
  conclusion**; an empty run sealed the zero digest into the log.
- **`tools/verify_export.py`** refuses a lone surrogate, compares bodies type
  for type, requires the first `seq` to be 1 and `placed_at` to be RFC 3339,
  and exits 4 for a file it cannot read, as `agentplane verify` does; the Rust
  reader refuses a hold with an unknown member.
- **A key the ring refuses after an expiry, cascade or `forget_subject` erased
  its rows is owed** by `EncryptedMemoryStore` and destroyed by its next
  erasure verb, which fails while it cannot; a retry found nothing to erase and
  the key survived.
- **Postgres timers** carry `CHECK (>= 0)` and a `(tenant, fire_at)` index.
- **`RedbStore::tamper_for_test` and `delete_run_for_test` need `testkit`.**

## [0.45.0] — 2026-09-29

### Security

- **Nobody but the worklist can answer a human task.** An event whose kind is
  in the `agentplane.` namespace is refused at every intake — `POST /events`
  (403), A2A, `deliver`, `deliver_to` — and a task accepts only an answer from
  its own worklist under the decider it names. Before, anyone allowed to post
  events could approve any task under any name.
- **An approval binds to what the reviewer was shown.** A decision names the
  digest of the task its decider saw, and a run refuses an approval of a task
  edited between proposal and decision. A proposal the plane cannot open — a
  terminal with no key ring — is marked withheld and cannot be approved
  (`ProposalWithheld`, 422); a rejection is buffered for the plane that holds
  the agent.
- **BREAKING: the caller who started a run cannot approve it.**
  `RunAdmitted.admitted_by` records the initiator, and every task the run
  opens excludes them.
- **BREAKING: a served caller without a delegation chain acts under none.** It
  no longer inherits the plane's chain — which made the operator's authority an
  ambient credential — but is still bounded by it (scope, admissibility,
  depth). Authority holders are typed (`Holder`); A2A and MCP refuse at startup
  a policy set that cannot evaluate that request shape.
- **BREAKING: A2A tasks belong to the peer that admitted them.** Reads, writes,
  streams, push configurations and `contextId` joins on another peer's task
  answer `TASK_NOT_FOUND`; `ListTasks` lists only your own and stops at
  `statusTimestampAfter`; a policy rule can name the owner as `context.owner`.
- **BREAKING: the MCP server needs a policy engine and answers only for its own
  runs.** `tasks/get` and `tasks/cancel` refuse a run this surface did not
  admit; a completed task carries its result; a host retry is the same run.
  Idempotency keys and request ids are scoped to a session.
- **BREAKING: a standing authority is drawn only by its holder, and only with
  an id the run's own code chose.** An id from model or peer text is refused.
- **BREAKING: batch items are admitted untrusted** unless the source vouches
  with `BatchItem::labelled`.
- **BREAKING: a plane with no policy engine refuses every `release`.** A
  release is the one call that lowers a label.
- **Telemetry never carries a failure's words.** Loud events name the run, the
  error class and a digest of the reason; the text stays in the journal, where
  erasure reaches it. **BREAKING** for log consumers.
- **Transport errors name the host, never the URL**, and a peer or client is
  never shown a store's error text, so webhook and peer secrets no longer reach
  parked registrations or logs.
- **Vault transit keys are derived from the scope** (`ap-` + SHA-256), so no
  scope can share a key or escape the URL path. Re-provision keys. **BREAKING**
- **Token files refuse tokens under 32 bytes and the published example
  values.** **BREAKING**
- **Erasing one event no longer destroys another's key.** The event key scope
  is length-prefixed like the dedup key, so `("bus/x", "1")` and
  `("bus", "x/1")` no longer share one.

### Fixed

- **A task is settled once.** Expiry and decision race through a
  compare-and-set; the loser is refused (`ClaimError::AlreadyAnswered`, 409),
  and an expiry that meets an answer already on record settles to that answer.
- **A decision or stop from a plane that cannot drive the run** — an
  operator's terminal — no longer quarantines a governed run: it is buffered
  for the plane that holds the agent. A sealed run there is reported as
  key-absent (`PayloadsSealed`), not erased.
- **A run that concludes closed retires its timers, event subscriptions and
  parked waits and withdraws the tasks it waited on**, so a dead run no longer
  swallows another run's event or fires forever. A parked wait is never matched
  to a second message. **BREAKING** for store implementors.
- **Deadline sweeps:** a breach is one conditional transaction that never
  reopens a closed case, applied first and noted after (a crash between is
  noted by the next tick, once); a lost race is recorded as `not_applied`; warned
  obligations and held timers no longer starve due ones.
- **A run refused on resume is listed, not lost.** A resume refused because
  the declaration or policy bundle changed quarantines the run, naming both
  digests, instead of returning `DeclarationChanged`/`PolicyBundleChanged`.
  **BREAKING** for callers matching those errors.
- **A resume that fails after a wake, a delivery or a recovery keeps its
  lease**, so the recovery sweep retries it; a recovery the journal itself
  refuses quarantines the run instead of retrying every lease period. A lost
  recovery race is not counted as a failure.
- **A failure unwinds interrupted siblings' landed work**, and `attention`
  lists failed runs still standing on landed work.
- **Unwinding after a replan undoes what ran**, as the skill its `StepStarted`
  names; a successor must carry completed steps over unchanged; an aborted
  effect group no longer quarantines or double-compensates its step.
  **BREAKING** for replanners that redeclared completed steps.
- **A tool that ran and failed is retried only if it declares
  `retry_landed`.**
- **Erasure reaches memory backups**: every memory version has its own key,
  and an erased subject can be written again. An erased buffered event is
  dead-lettered and its wait reopened, never delivered as `null`. Blob and
  memory payloads use the versioned envelope, bound to their row;
  `StepCompensated.outcome` is sealed. **BREAKING**
- **Exports carry legal holds and restore places them**, so a recovered plane
  never erases a preserved matter. **BREAKING** export format.
- **The Postgres Merkle log stays append-only under concurrent seals.** Seal
  positions are allocated under a per-tenant lock in commit order; before, a
  witness could see an honest history as a fork.
- **`export::verify` checks an anchor older than the export** against the
  file's own leaves, and a record's hash before parsing it, so an edited line
  is reported as edited rather than as build skew. **Restore refuses before
  writing** a line whose hash or version does not hold.
- **`audit` reports truncation and exits 5; `export` refuses a truncated
  export** unless `--allow-partial`. **BREAKING**
- **BREAKING: `max_minor_units` binds.** A model role declares `pricing`
  (minor units per million input, output, cache-read and cache-write tokens);
  a money ceiling over an unpriced role is refused at load. A commission's
  spend is settled into the tenant's period once.
- **`max_egress_bytes` counts everything a model call sends** — tool results,
  the conversation so far, tool declarations and attached media — not only the
  prompt.
- **`EffectStarted.mutates` records the value the policy gate was asked with**
  (the grant-widened claim). **BREAKING** record meaning.
- **A tool's error text carries the tool's label**, so a confidential failure
  cannot reach a model cleared below it.
- **A filtered or cut-off model answer is never read as complete.** Stop
  reasons are allowlisted per provider.
- **A model stream that fails partway is retried under its policy.** A call
  with no world effect is billed and asked again.
- **A driver's timeout is no longer part of a model call's identity**, so
  raising it does not break replay of runs already in flight.
- **Cancelling a run that has finished answers 409**; a failed or exhausted
  run can still be stopped.
- **A batch item withheld under a withdrawn authority is counted as withheld**,
  not as exhausted.
- **A breach acknowledgement records who and on what basis**, like every other
  operator act.
- **`/runs/live?subject=` reports truncation from the page it read**, so a
  filtered answer never claims nothing is running when it did not look.
- **Suspended-run hints carry `--tenant`, are shell-quoted, and never print a
  Postgres password**; ambiguous `--peer` names are refused.
- **Several published Cedar examples were refused by `preflight` or failed on
  every call.** Each now guards what it reads, and the build probes a mutating
  call, a labelled call, every resource a rule names and the served actions.

### Changed

- **BREAKING: store traits.** `EventStore::minter`,
  `CaseStore::breaches_to_note`/`mark_breach_noted`,
  `JournalStore::recent_runs_from`; `TaskStore::set_state` returns whether it
  applied; `MemoryStore::forget_cascading` returns `Cascade`; `sweep_expired`
  returns the swept ids; memory `Cascade`/`sweep_expired` carry versions;
  `TimerStore::pending` is removed (use `waiting_runs`).
- **BREAKING: effect keys are domain-separated** at the hash, so every key
  changes; recreate stores written by an earlier build.
- **BREAKING: nested record payloads refuse unknown members**, as the top level
  already did.
- **BREAKING: a record signature is named a signature**, not an attestation —
  it is a workload-key signature, not a hardware attestation.
  `ExportedRecord::attestation` is `signature` on the wire; `Attestation` is
  `KeySignature`, `AttestError` is `SignatureError`, `Record::attestation` and
  `Provenance::attestation` are `signature`, `Signer::attest` is
  `signature_over`, `verify_attested` is `verify_signed`, and the provenance
  metadata key is `io.github.hupe1980.agentplane/signature`.
- **BREAKING: one CLI exit-code table** — 0 ok, 1 finding, 2 usage,
  3 suspended, 4 operational, 5 partial — printed in `--help`. `halt` prints
  text unless `--json` (also on `init`, `validate`, `digest`).
- **BREAKING: CLI.** `retain` is `retention plan`; `halt list` and `hold list`
  list what stands; a decision is `decide <task> approve|reject`; escalation
  names its audience in the type (`Expiry::escalate_to(..)`).
- **`serve --policy` takes a bundle file or directory**, through the same
  loader as `policy check`.
- **`capabilities.provides` defaults to the agent's name** for a declarative
  agent.
- **BREAKING (testkit): the fake provider calls the first offered tool on a
  tool loop's first turn**, so a fake-driven run proves its transport was
  reached; a test expecting a plain answer on turn one must offer no tools.

### Added

- **A tenant spend quota reserves each run's worst case at admission** — its
  ceiling plus one call per step in flight, from declared per-call maxima
  (`max_input_tokens`, output ceilings, price) — in the transaction that checks
  the ceiling, so a period's spend is bounded. Under a spend quota an unbounded
  run is refused; `validate` prints the worst case. **BREAKING**: recreate
  stores; `QuotaStore::reserve` takes a `SpendHold`.
- **`spec.tools[].rate_limit: { count, window_seconds }`** caps calls to one tool
  across every run of a tenant in a sliding window. A full window pauses the run
  like a budget (`BudgetExceeded::Rate`); a retry spends once; an undo is never
  refused. **BREAKING**: `QuotaStore` gains `reserve_rate` and `rate_room`.
- **`agentplane policy check --bundle … --from export.jsonl
  [--candidate …]`** re-derives every gated request an export records, through
  the gates' own builders, and reports what the bundle would deny, what a
  candidate would newly deny, and what it could not evaluate.
- **`agentplane replay --strict` answers whether an edited declaration
  diverges** — verified, diverged (the first effect, with both digests) or
  cannot replay — from a store or `--from` export files, with no provider
  credential. **BREAKING**: it no longer prints the run's output or exits 3.
- **Every task surface shows invisible and bidirectional characters visibly**
  and flags words mixing scripts. **BREAKING**: new `tasks.withheld` column.
- **`agentplane run` handles every declarative feature.** Runs correlate by
  default (`--correlate k=v` joins an existing case) and `--acting-as` gives
  peer calls a chain.
- **`agentplane tasks`** lists open approvals, and **`agentplane init`** writes
  a valid starter manifest.
- **`attention` names the runs, tasks and cases behind each condition**, and
  its remedies name the verb on the surface serving them.
- **`serve --log-format json`**, and `--version` lists the compiled features.
- **`schemars` is re-exported**, so a tool author derives `JsonSchema` without
  matching versions.
- **`agentplane replay` waits out a terminal's short lease** after `decide`, so
  approve-then-resume works in one sitting.

### Assurance

- **Nothing published may cite a feature specification.** The docs guard
  refuses a path into the specification tree or a bare requirement identifier,
  and `just package` refuses them in the tarball.

## [0.44.0] — 2026-09-21

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
