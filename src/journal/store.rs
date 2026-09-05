//! The journal store contract.

use std::fmt::Debug;
use std::time::Duration;

use async_trait::async_trait;

use crate::core::{Digest, Epoch, RunId, Seq, StoreError};

use super::{Append, Record};

/// A run's current chain position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Head {
    pub seq: Seq,
    pub hash: Digest,
}

impl Head {
    /// Where an unwritten run starts.
    #[must_use]
    pub const fn genesis() -> Self {
        Self {
            seq: 0,
            hash: Digest::ZERO,
        }
    }
}

/// Ownership of a run, held by one instance for a bounded time.
///
/// The epoch is the fencing token. Every append carries it, and the store
/// rejects a stale one *in the same transaction that writes* — so an instance
/// that was paused, partitioned, or GC-stalled and then wakes up cannot append
/// to a run someone else has taken over. Split-brain is prevented by the store's
/// arbitration, not by hoping the clocks agree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    pub run: RunId,
    pub owner: String,
    pub epoch: Epoch,
}

/// A commitment to every run sealed so far.
///
/// Deliberately shaped like a [C2SP `tlog-checkpoint`](https://github.com/C2SP/C2SP/blob/main/tlog-checkpoint.md):
/// an origin naming the log, a size, and a root. Using the interoperable shape
/// rather than a bespoke one means existing verifiers and witness operators
/// work — and inventing a format here would buy nothing and cost every
/// integrator.
///
/// `Serialize` because a checkpoint is the artifact that has to leave: it heads
/// every export and appears in every audit report, and a reader who has to link
/// this crate to parse it is not the independent party either exists for.
/// `Deserialize` because the same reader hands it back — verifying an export
/// means comparing a rebuilt root against the checkpoint the file carries.
/// [`Checkpoint::to_note`] remains the interoperable text form for a witness or
/// a ticket; these are for a consumer already reading JSON.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Checkpoint {
    /// Which log. A deployment-chosen name, so two planes' checkpoints cannot
    /// be confused for one another.
    pub origin: String,
    /// How many runs are committed to.
    pub size: u64,
    /// The Merkle root over their sealed digests.
    pub root: Digest,
}

use super::note::{b64, unb64};

impl Checkpoint {
    /// The C2SP `tlog-checkpoint` note body: origin, size, base64 root.
    ///
    /// A text form matters more than it looks. A checkpoint is the one artifact
    /// that has to **leave the operator's control** — handed to an auditor,
    /// posted to a witness, pasted into a ticket — and an artifact that only
    /// exists as a Rust struct cannot do that. Using the interoperable encoding
    /// rather than a bespoke one means the thing they hold is checkable by tools
    /// this project did not write.
    #[must_use]
    pub fn to_note(&self) -> String {
        format!(
            "{}\n{}\n{}\n",
            self.origin,
            self.size,
            b64(self.root.as_bytes())
        )
    }

    /// Whether this checkpoint's size and root can both be true.
    ///
    /// One pair is checkable without holding the log: the empty tree has
    /// exactly one root, so a checkpoint claiming size 0 beside any other root
    /// is describing a log that cannot exist. That matters more than a tidy
    /// invariant because of what a witness does with a first submission — it
    /// has no prior memory to check against, so it records what it is told and
    /// holds every later checkpoint to it. One incoherent size-0 submission
    /// therefore poisons the origin permanently: every honest checkpoint
    /// afterwards fails consistency against a root no log ever had, and is
    /// reported as `Forked` — an integrity page, forever, from a single
    /// malformed request.
    #[must_use]
    pub fn is_coherent(&self) -> bool {
        self.size != 0 || self.root == crate::core::merkle::empty_root()
    }

    /// Read one back.
    ///
    /// # Errors
    ///
    /// If the note is malformed. Deliberately strict: a checkpoint that parses
    /// "close enough" is a checkpoint that compares against the wrong log.
    pub fn from_note(note: &str) -> Result<Self, StoreError> {
        let bad = |what: &str| StoreError::Backend(format!("checkpoint note: {what}"));
        // Split rather than `lines()`, and the difference is the whole
        // canonicity argument. `lines()` accepts a missing final newline, drops
        // a `\r` before it, and ignores anything past the third line, so
        // `origin\r\n42\r\nroot\r\n`, `origin\n42\nroot` and
        // `origin\n42\nroot\nanything\n` would all name one checkpoint. The
        // signature covers the *text*, so several texts mapping to one value is
        // an operator able to hand two auditors different bytes that both
        // verify and both name the same history. Exactly three lines, each
        // newline-terminated, nothing after.
        let body = note.strip_suffix('\n').ok_or_else(|| {
            bad("the note does not end in a newline, which is part of what \
                                gets signed")
        })?;
        let mut parts = body.split('\n');
        let origin = parts.next().ok_or_else(|| bad("no origin"))?;
        let size = parts.next().ok_or_else(|| bad("no size"))?;
        let root = parts.next().ok_or_else(|| bad("no root"))?;
        if parts.next().is_some() {
            return Err(bad(
                "the note carries more than the three lines tlog-checkpoint defines; \
                 extra lines are refused rather than ignored, because a parser that \
                 ignores them lets two different signed texts name one checkpoint",
            ));
        }
        if origin.is_empty() {
            return Err(bad("the origin is empty, so the note names no log"));
        }
        // A leading zero, a `+`, or surrounding space would all be accepted by
        // `parse` after trimming, and each is a second spelling of one number.
        if size.is_empty()
            || !size.bytes().all(|b| b.is_ascii_digit())
            || (size.len() > 1 && size.starts_with('0'))
        {
            return Err(bad(
                "the size is not a canonical decimal number — no sign, no leading zero, \
                 no surrounding space, because each is a second spelling of one log",
            ));
        }
        let size = size
            .parse::<u64>()
            .map_err(|e| bad(&format!("size is not a number: {e}")))?;
        let root = unb64(root).ok_or_else(|| bad("root is not canonical RFC 4648 base64"))?;
        let root: [u8; 32] = root.try_into().map_err(|_| bad("root is not 32 bytes"))?;
        Ok(Self {
            origin: origin.to_owned(),
            size,
            root: Digest::from_bytes(root),
        })
    }
}

/// Evidence that one run is in the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inclusion {
    /// Position in the log, in seal order.
    pub index: u64,
    /// The log size this proof is against.
    ///
    /// Carried because the tree's shape depends on it. The size is authenticated
    /// by the checkpoint, not by the proof — see [`crate::core::merkle`].
    pub size: u64,
    /// The run's terminal chain hash: the leaf value.
    pub seal: Digest,
    /// Sibling hashes, leaf-upwards.
    pub proof: Vec<Digest>,
}

/// A durable request that a run stop.
///
/// Carries the asker's name because an intervention with nobody attached to it
/// is an outage, not oversight — the same rule a human decision follows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cancellation {
    pub actor: String,
    pub reason: String,
}

/// Append-only, hash-chained run history.
///
/// Implementations must guarantee, atomically:
///
/// 1. **Fencing** — when a lease exists, reject appends whose epoch is not the
///    current lease. A token from the future is no more proof of ownership than
///    a stale one; accepting it lets a caller invent authority without acquiring
///    the run.
/// 2. **Exactly-once** — reject a second `EffectStarted` for an effect key that
///    already started in this run.
/// 3. **Chaining** — assign contiguous `seq` and link `prev_hash` to the run's
///    current head.
///
/// All three are storage invariants rather than application logic, because
/// application logic can be bypassed by the next caller and a constraint cannot.
#[async_trait]
pub trait JournalStore: Send + Sync + Debug {
    /// Append a batch, sealing each record into the chain.
    ///
    /// The whole batch commits or none of it does: a partially written step
    /// would leave a journal that describes something that never happened.
    async fn append(&self, epoch: Epoch, batch: Vec<Append>) -> Result<Vec<Record>, StoreError>;

    /// Whether more than one plane instance can write to this store.
    ///
    /// **No default, deliberately.** A default of `false` would let an
    /// embedder's shared backend answer *single-writer* by saying nothing, and
    /// the runtime uses this answer to refuse configurations that are unsafe on
    /// a shared store — and a control that fails open when an implementer forgets
    /// is not a control. It would be a property the runtime *relies on* while
    /// only the implementations this crate happens to ship establish it.
    ///
    /// Answer `true` if two processes pointed at the same durable state can
    /// both append. `redb` is a file with a single writer and answers `false`;
    /// `PostgreSQL` is the topology an embedded store cannot serve and answers
    /// `true`. A decorator delegates to what it wraps — the question is about
    /// the durable state, not about the layers in front of it.
    fn is_shared(&self) -> bool;

    /// This store's own transaction, when a co-located resource can join it.
    ///
    /// `None` — the default — means the backend cannot offer it, which is the
    /// honest answer for an embedded store with no notion of a foreign table.
    /// A capability spelled as absence rather than as a method that fails at
    /// commit: an atomic member is refused when it is *registered*, which is the
    /// only time refusing is free.
    ///
    /// See [`AtomicJournal`](crate::journal::AtomicJournal) for why this is
    /// worth having at all — where the resource shares the journal's database,
    /// compensation that never has to run beats compensation that runs
    /// correctly.
    fn atomic(&self) -> Option<&dyn crate::journal::AtomicJournal> {
        None
    }

    /// Read a run's records from `from` (inclusive, 1-based) onward.
    async fn read(&self, run: RunId, from: Seq) -> Result<Vec<Record>, StoreError>;

    /// Concluded runs whose *latest* conclusion is `outcome`, newest first.
    ///
    /// The question this exists for is *what is quarantined right now?* — and
    /// until it existed, the answer was "watch the logs". A quarantine is the
    /// most serious conclusion this runtime reaches: the recorded history can no
    /// longer be trusted, or a mutation is in a state nobody can establish. It
    /// produced a run status, an `error!` event and a counter, none of which an
    /// operator can query, and a run started with `spawn` returns before the
    /// status exists at all.
    ///
    /// Longitudinal studies of production agent runtimes name that shape as the
    /// most common failure mode: not an undetected fault, but a detected one
    /// whose signal never reaches a human in a form they can act on. Every other
    /// backlog here is findable by whoever must clear it — escalated cases,
    /// overdue tasks, breached obligations. This one was not.
    ///
    /// A **derived** index: the outcome's home is the chain — the store
    /// maintains this index from the `RunSealed` record inside `append`, in
    /// the same transaction, so it can be rebuilt from the journal and is a
    /// convenience, never an authority. **The last conclusion wins**: a failed
    /// run is listed while it stands failed, and moves to `succeeded` when a
    /// resume concludes it again. An index that kept the first conclusion
    /// would list a resumed run as failed for the rest of its life — a backlog
    /// page that never drains, which is worse than no page, because a wrong
    /// answer reads exactly like a right one.
    ///
    /// A stored run id that does not parse is **corruption**, reported as
    /// [`StoreError::Corrupt`] rather than silently thinned out of the page.
    /// Every backend must hold this: a listing that quietly drops the
    /// quarantined run it could not parse is the unreachable-signal failure
    /// this method exists to remove, and it reads as a clean page.
    ///
    /// Bounded, and the bound is visible: `limit` results means *at least*
    /// that many, not exactly.
    ///
    /// **Newest first**, and that ordering is part of the contract rather than
    /// an incidental property of the index. A bounded query in ascending order
    /// is a page that stops changing: once a plane's quarantine backlog exceeds
    /// one page, the same runs come back forever and the quarantine that just
    /// happened is precisely the one that never appears. That is the failure
    /// this method exists to remove, reintroduced by the ordering — a signal
    /// that is emitted, indexed, queryable, and still does not reach anyone.
    ///
    /// The backlog an operator has already seen is the one they can afford to
    /// page past; the one that arrived while they were not looking is not.
    ///
    /// # Errors
    ///
    /// If the store is unreachable.
    async fn runs_by_outcome(&self, outcome: &str, limit: usize) -> Result<Vec<RunId>, StoreError>;

    /// How many runs currently rest on this conclusion.
    ///
    /// The **level** behind [`runs_by_outcome`](Self::runs_by_outcome)'s page.
    /// A quarantine counter tells an operator how often runs were set aside; it
    /// cannot tell them how many are set aside *now*, because a counter is
    /// monotonic and a backlog that stopped growing looks exactly like one that
    /// was cleared. The number that falls when somebody acts has to be observed,
    /// and this is what observes it.
    ///
    /// **Never served from a bounded listing.** `runs_by_outcome(..).len()`
    /// would rise, flatten at the page size and read as a plateau at the moment
    /// it became a backlog — the specific failure the census exists to avoid, so
    /// this counts the index rather than a page of it.
    ///
    /// Reads the same derived index `runs_by_outcome` pages, so the two cannot
    /// disagree about one plane: last conclusion wins, and a resumed run leaves
    /// the count it was in.
    ///
    /// Intended for the conclusions that are backlogs — the ones nothing clears
    /// but a person. Counting an outcome that every healthy run reaches is a
    /// scan of the whole plane, and the caller is choosing to pay for it.
    ///
    /// # Errors
    ///
    /// If the store is unreachable, or the index holds a row it cannot read —
    /// the same refusal as the listing, for the same reason.
    async fn count_by_outcome(&self, outcome: &str) -> Result<u64, StoreError>;

    /// The run that holds this admission key, if one does.
    ///
    /// A **derived** index, as `runs_by_outcome` is: the key's home is the
    /// `RunAdmitted` record, and the store maintains this from that record
    /// inside [`append`](Self::append), in the same transaction. So it rebuilds
    /// from the journal, and — the load-bearing part — the key is claimed at the
    /// instant the run becomes real, because taking it *is* writing the run.
    ///
    /// Implementations must refuse a second `RunAdmitted` carrying a key this
    /// tenant already issued, with
    /// [`StoreError::DuplicateAdmission`](crate::core::StoreError::DuplicateAdmission)
    /// naming the holder. That refusal is the arbiter and this read is not: two
    /// instances racing both see `None` here, and the constraint picks the
    /// winner.
    ///
    /// Tenant-scoped, as a correlation key is: an admission key is a business
    /// value, and two tenants using the same one is ordinary.
    ///
    /// **No default**, for the reason [`is_shared`](Self::is_shared) has none: a
    /// store that forgot this would answer "nothing has been admitted" and the
    /// duplicate would proceed.
    ///
    /// # Errors
    ///
    /// If the store is unreachable.
    async fn admitted_as(&self, key: &str) -> Result<Option<RunId>, StoreError>;

    /// Retire admission keys claimed before `older_than`. Returns how many.
    ///
    /// **Retiring a key reopens the door it closed**, so this is a verb an
    /// operator calls deliberately rather than a sweep that runs by default.
    /// The window MUST exceed the emitter's retry horizon: a redelivery
    /// arriving after its key is retired admits a second run, which is the
    /// failure the key exists to prevent, delivered on a timer.
    ///
    /// It exists because the alternative is an index that only grows. Other
    /// durable runtimes bound this by default — Restate expires an idempotency
    /// key a day after the invocation completes, Temporal's dedup window is its
    /// namespace retention — and both are making the same trade in the other
    /// direction. Absent a call to this, keys are kept forever: the safe
    /// default is the one that cannot silently admit a duplicate, and the size
    /// of the index is a fact the deployment's own database monitoring already
    /// reports.
    ///
    /// The claimed instant is store-observed, not journaled: it orders
    /// retirement and nothing else. A key's *authority* is the `RunAdmitted`
    /// record, which is why retiring a row alters no history.
    ///
    /// # Errors
    ///
    /// If the store is unreachable.
    async fn forget_admissions(
        &self,
        older_than: crate::core::Timestamp,
    ) -> Result<usize, StoreError>;

    /// Runs ordered by last durable append, newest first, one bounded page.
    ///
    /// A derived discovery index for protocol task listing, never the authority
    /// for status: callers still read each run's journal head. The timestamp is
    /// store-observed append time and exists only for ordering and cursor
    /// stability.
    ///
    /// # Why this is paged, and why that was not optional
    ///
    /// It returned **every run in the tenant**, unbounded, and its one caller
    /// then read the complete journal of each before paginating. So a single
    /// `tasks/list` over A2A cost O(every record the tenant has ever written),
    /// repeatable by any authenticated peer — a scan the caller could not bound
    /// because the signature offered nothing to bound it with. Every other
    /// listing in this crate takes a limit and says when it truncated; this one
    /// was the exception, and it was the one a remote party could call.
    ///
    /// `after` is a position in *this* ordering — the `(updated_at, run)` of the
    /// last row a caller saw — and paging resumes strictly below it. Filtering
    /// in the caller instead is what forced the whole index into memory: a
    /// cursor applied after the read is a cursor that read everything first.
    ///
    /// Ties are broken by run id descending, so the order is total. Without that
    /// two runs sharing a timestamp could straddle a page boundary and be served
    /// twice or not at all, and the timestamp has whole-second granularity on
    /// both backends — so ties are ordinary rather than exotic.
    async fn recent_runs(
        &self,
        after: Option<(u64, RunId)>,
        limit: usize,
    ) -> Result<Vec<(RunId, u64)>, StoreError>;

    /// Every record belonging to a case, oldest first.
    ///
    /// *Show me everything about this matter* is the question a regulated
    /// deployment asks, and it is not answerable by listing the case's runs and
    /// reading each: that is a join whose cost grows with the case's life, and
    /// it **misses** every record written by a run the case does not own.
    ///
    /// A sweep is exactly that run. One tick may escalate several cases and
    /// belongs to none of them, so the record explaining *why this case is
    /// escalated* is invisible to a per-run walk. This is the read that finds
    /// it.
    ///
    /// Bounded, and the bound is visible: a caller that gets `limit` records
    /// back has learned that there are at least that many, not that there are
    /// exactly that many. See [`crate::runtime::Saturation`] for the same
    /// distinction on the sweep side.
    ///
    /// # Errors
    ///
    /// If the store is unreachable.
    async fn case_history(
        &self,
        case: crate::core::CaseId,
        limit: usize,
    ) -> Result<Vec<Record>, StoreError>;

    /// The run's current chain head.
    async fn head(&self, run: RunId) -> Result<Head, StoreError>;

    /// Take ownership of a run, returning the fencing epoch to write under.
    ///
    /// A **pure claim**: it succeeds only on a lease that is free — never
    /// granted, released, or expired — and it always bumps the epoch past the
    /// previous holder's, which fences them. A lease that is currently held
    /// and unexpired is refused with [`StoreError::LeaseHeld`], **including
    /// when the caller itself is the holder**.
    ///
    /// That last refusal is deliberate. Letting `acquire` renew for the same
    /// owner would be the convenient reading, and two failures hide in it. A
    /// heartbeat racing its own run's conclusion could
    /// re-acquire the lease the conclusion had just *released*, leaving a
    /// live, never-released lease over a concluded run — which the recovery
    /// sweep then "recovers" forever. And a second entry point on the same
    /// instance (a cancel, a delivery) could "acquire" the lease of a run the
    /// instance was actively executing and drive a second execution under the
    /// **same epoch**, which fencing exists to make impossible and cannot see.
    /// Renewal is a different operation with a different failure mode, so it
    /// is a different method: [`renew`](Self::renew).
    ///
    /// Lease timing has **whole-second granularity**, and a TTL that truncates
    /// to zero seconds is refused rather than clamped up — a store that
    /// rounded "expire immediately" to "hold for a second" would be enforcing
    /// a contract nobody stated. The expiry addition is checked too: a TTL
    /// near `Duration::MAX` is refused instead of wrapping into the past. The
    /// runtime never sends either (its builder refuses TTLs below its own
    /// two-second minimum); the store-level refusal is the boundary for every
    /// other embedder of this trait.
    async fn acquire(&self, run: RunId, owner: &str, ttl: Duration) -> Result<Lease, StoreError>;

    /// Extend a lease this caller still holds, without ever claiming one.
    ///
    /// Succeeds only when the lease is currently held, unexpired, unreleased,
    /// by exactly `(owner, epoch)` — and keeps the epoch, because bumping it
    /// would fence the owner against its own in-flight writes. Anything else
    /// fails with [`StoreError::LeaseNotHeld`]: the lease was released (the
    /// run concluded), lapsed (anyone may have taken it), or is held by
    /// somebody else (somebody did). A failed renewal means *stop* — the
    /// caller no longer owns the run, and the store will fence its next
    /// append anyway.
    ///
    /// The refusal to claim is the entire contract. A renewal that "helpfully"
    /// re-took an expired or released lease would fence the run with its own
    /// heartbeat, or resurrect a lease over a run that already handed it back
    /// — and a concluded run with a live lease is a run the recovery sweep
    /// re-executes when the lease lapses.
    ///
    /// Checked and written inside one store transaction, like every other
    /// lease operation: a read-then-write renewal has a window in which the
    /// lease can lapse and be claimed, and renewing over the new owner is the
    /// split-brain the epoch exists to prevent.
    ///
    /// The TTL contract is [`acquire`](Self::acquire)'s: whole-second
    /// granularity, sub-second values refused, overflow refused.
    async fn renew(
        &self,
        run: RunId,
        owner: &str,
        epoch: Epoch,
        ttl: Duration,
    ) -> Result<Lease, StoreError>;

    /// Runs whose lease **expired without being released** — the runs an
    /// instance died holding.
    ///
    /// The lease discipline makes this set precise. Every clean exit hands its
    /// lease back through [`release_lease`](Self::release_lease), whatever the
    /// outcome — sealed, failed, suspended. Only a crash skips that call, so an
    /// expired lease that still names an owner is not "a run that is resting":
    /// it is a run somebody was executing when their process stopped, and
    /// nothing else in the system will ever touch it again unless an event, a
    /// timer or an operator happens to.
    ///
    /// That "happens to" is the gap this query closes. Fencing makes takeover
    /// *safe* and replay makes it *correct*, but neither makes it **happen** —
    /// a run crashed mid-step with no pending timer and no inbound event has no
    /// driver, appears in no backlog (it concluded nothing, so no outcome
    /// listing carries it; its subscriptions were consumed, so no waiting list
    /// names it), and waits forever while looking exactly like work in
    /// progress. Detection without delivery, applied to the recovery mechanism
    /// itself. The sweeper drains this queue; this method is what makes the
    /// queue exist.
    ///
    /// **Oldest expiry first**, so the longest-stranded run is recovered first
    /// and a bounded page cannot starve it behind fresher failures. Bounded,
    /// and the bound is visible: `limit` results means *at least* that many.
    ///
    /// Expiry is judged by the store's own clock — the same clock
    /// [`acquire`](Self::acquire) stamps leases with, because two clocks
    /// disagreeing about one row is how a live owner gets recovered out from
    /// under its own heartbeat. A recovered run that was in fact still owned is
    /// not corrupted either way: the recovering instance bumps the epoch, and
    /// the store fences the previous owner's next append.
    ///
    /// A stored run id that does not parse is **corruption**, reported as
    /// [`StoreError::Corrupt`] rather than skipped: a stranded run silently
    /// dropped from this listing is a run nothing will ever recover, and this
    /// is the one page it can appear on.
    ///
    /// # Errors
    ///
    /// If the store is unreachable.
    async fn abandoned_runs(&self, limit: usize) -> Result<Vec<RunId>, StoreError>;

    /// Hand a lease back, so the next instance need not wait out the TTL.
    ///
    /// The counterpart to [`acquire`](Self::acquire), and the difference between
    /// a graceful shutdown and a crash. Without it every restart waits for
    /// expiry, and the temptation is to make the owner string constant so that
    /// the replacement "renews" instead — which quietly disables fencing,
    /// because two live instances then read each other's lease as their own.
    ///
    /// A release primitive is what lets the owner stay unique per process.
    ///
    /// Takes the caller's `epoch` and releases only if it is the one holding the
    /// lease. A fenced caller must not be able to free the lease of the instance
    /// that took over from it — that would hand the run to a third party while
    /// the rightful owner is mid-write.
    ///
    /// Releasing a lease you do not hold is **not an error**. A process shutting
    /// down after being fenced is in exactly that position, and making it fail
    /// would turn an orderly exit into a log full of alarms about a run that is
    /// already somebody else's problem.
    ///
    /// Idempotent: releasing twice is releasing once.
    ///
    /// # Errors
    ///
    /// If the store cannot be reached.
    async fn release_lease(&self, run: RunId, epoch: Epoch) -> Result<(), StoreError>;

    /// Whose rows this handle can reach.
    ///
    /// The default is `default`, which is the tenant a store serves until told
    /// otherwise — a real tenant rather than an absence, so the single-tenant
    /// path is the same code as the multi-tenant one.
    ///
    /// This exists so a mismatch is a **startup refusal** rather than a silent
    /// leak. A plane's tenant scopes its data keys and reaches its policy
    /// requests, but the store handle is built separately and has to be scoped
    /// separately. Nothing about `RuntimeBuilder::tenant(acme)` over a store
    /// left on `default` looks wrong at runtime: it works, and it writes acme's
    /// runs into everybody's keyspace. Asking the store who it serves lets
    /// `build()` catch that before the first run.
    fn tenant(&self) -> &str {
        crate::core::TenantId::DEFAULT
    }

    /// Close the chain and return its terminal hash — what a signature covers.
    ///
    /// A seal is a **freeze**, not a status report: the run enters the Merkle
    /// log at its current head, and from that instant `append` refuses the run
    /// with [`StoreError::RunSealed`] — even for the caller legitimately
    /// holding the current epoch, because an append past the leaf would leave
    /// every checkpoint attesting a prefix of a history that kept growing.
    /// Only conclusions nothing may resume are sealed
    /// (`RunStatus::seals`); a failed or exhausted run concludes without
    /// sealing and stays open for resume. First seal wins; a re-seal changes
    /// nothing.
    async fn seal(&self, run: RunId, epoch: Epoch, outcome: &str) -> Result<Digest, StoreError>;

    /// A commitment to the **set** of sealed runs.
    ///
    /// The per-run chain stops at the run boundary, so deleting an entire run
    /// leaves every remaining run verifying perfectly — see [`crate::core::merkle`].
    /// This closes that: a Merkle root over sealed-run digests, which moves if
    /// any of them is removed.
    ///
    /// On its own it is still only as trustworthy as the store. It becomes
    /// evidence when a checkpoint is **published somewhere the operator does not
    /// control** and compared later — which is the part deliberately left to the
    /// deployment, because a witness this crate chose would be a witness the
    /// crate's author picked for somebody else's audit.
    ///
    /// # Errors
    ///
    /// If the store is unreachable.
    async fn checkpoint(&self) -> Result<Checkpoint, StoreError>;

    /// Prove the log has only *grown* since a checkpoint of `old_size`.
    ///
    /// This is what makes a published checkpoint evidence, and without it the
    /// Merkle log is close to useless in practice: the root moves on **every**
    /// seal, so an auditor comparing two roots cannot tell legitimate growth
    /// from a deletion followed by growth. A consistency proof separates them —
    /// it shows every leaf committed to before is still committed to, in the
    /// same position.
    ///
    /// # Errors
    ///
    /// If the store is unreachable, or `old_size` exceeds the current log.
    async fn consistency_proof(&self, old_size: u64) -> Result<Vec<Digest>, StoreError>;

    /// Prove a sealed run is in the log this checkpoint commits to.
    ///
    /// Returns `None` for a run that was never sealed — which is an answer, not
    /// an error: an unsealed run is not in the log because it has not finished.
    ///
    /// # Errors
    ///
    /// If the store is unreachable.
    async fn inclusion_proof(&self, run: RunId) -> Result<Option<Inclusion>, StoreError>;

    /// Ask a run to stop, durably.
    ///
    /// **Deliberately not fenced, and that is the whole point.** Every other
    /// write here requires the lease, because two writers appending to one chain
    /// is the corruption fencing exists to prevent. A stop request is the
    /// opposite situation: the operator asking is *not* the run's owner, has no
    /// epoch, and is usually asking precisely because the owner is busy doing
    /// something they want stopped. Requiring the lease would mean the only
    /// party who can cancel a running agent is the process running it.
    ///
    /// So the request lands beside the chain rather than in it, exactly as a
    /// lease does, and the *owner* journals `RunCancelled` when it observes the
    /// request at its next step boundary. That keeps "who asked, and why" inside
    /// the hash chain without letting an unfenced writer append to it.
    ///
    /// Idempotent: returns `false` if a request was already recorded, so a
    /// retried or duplicated call does not overwrite the original asker.
    ///
    /// # Errors
    ///
    /// If the store is unreachable.
    async fn request_cancel(
        &self,
        run: RunId,
        actor: &str,
        reason: &str,
    ) -> Result<bool, StoreError>;

    /// The pending stop request for a run, if one was made.
    ///
    /// # Errors
    ///
    /// If the store is unreachable.
    async fn cancellation(&self, run: RunId) -> Result<Option<Cancellation>, StoreError>;

    /// Verify a run's chain end to end.
    async fn verify(&self, run: RunId) -> Result<Digest, StoreError> {
        let records = self.read(run, 1).await?;
        Record::verify_chain(&records, Digest::ZERO)
    }
}
