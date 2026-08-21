//! Guards over the crate's own structure, and store contracts.
//!
//! One of a handful of integration targets rather than one per file. Cargo
//! compiles and links every integration test as its own crate, so thirty-three
//! files meant thirty-three links of the same dependency graph — ~56s to
//! rebuild after touching one line of the library.
//!
//! Collapsing them into a handful of grouped targets links five times instead
//! of thirty-three: measured at **56.3s down to ~24s** to rebuild after
//! touching one line of the library, which is the cost paid on every edit.
//!
//! A *single* target was measured too, at 17.8s. It is faster here and worse
//! where it is less visible: the mutation sweep rebuilds a test binary per
//! mutant, and one binary holding every module relinks all of it ninety-six
//! times. Five groups keep both costs reasonable rather than optimising one
//! into the other.

mod authority;
mod conformance;
mod docs;
#[cfg(feature = "push")]
mod due_conformance;
mod groups;
mod interactions;
mod layering;
mod media;
mod memory;
mod metrics;
mod outbox;
mod postgres;
mod push;
mod quota;
#[cfg(feature = "manifest")]
mod schema;
mod store_contracts;
mod timestamps;
mod vault;

/// Serialises tests that install an ambient `tracing` subscriber.
///
/// `tracing::subscriber::set_default` sets a **thread-local** dispatcher, and
/// the work under test does not necessarily run on the thread that set it. Two
/// such tests running at once therefore lose each other's events, and the
/// assertion reads as "the runtime did not emit this" rather than "another test
/// was listening".
///
/// It never used to matter, which is the interesting part: `metrics.rs` and
/// `telemetry.rs` were separate integration files, so cargo built them as
/// separate *binaries* and ran them as separate *processes*. That isolation was
/// a side effect of the build layout, not a property anybody chose, and
/// grouping the files removed it — whereupon the metrics assertions began
/// failing intermittently with *nothing* captured, which reads as "the runtime
/// emitted no metric" rather than "another test was installing a dispatcher".
///
/// Serialising installation here was not sufficient on its own: `telemetry`
/// now lives in a **different target**, so the two never share a process. This
/// lock still earns its place for the tests that remain, and it states the
/// constraint instead of leaving it to a file layout to imply.
pub fn ambient_subscriber() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static OPEN: std::sync::Once = std::sync::Once::new();

    // Hold the level filter open for the life of the binary.
    //
    // `tracing` gates every event on a process-wide max level derived from the
    // *global* dispatcher. With only thread-local subscribers there is no
    // global, the filter sits closed, and whether an event survives to reach a
    // thread-local subscriber depends on what other threads happen to be doing
    // — which is why these tests failed roughly one run in eight with *nothing*
    // captured, reading as "the runtime emitted no metric".
    //
    // A permissive global dispatcher fixes the level, and a thread-local
    // `set_default` still takes precedence for the thread that installs one, so
    // each test keeps collecting only its own events.
    OPEN.call_once(|| {
        let _ = tracing::subscriber::set_global_default(tracing_subscriber::registry());
    });
    // A panicking test poisons the lock, and every later test would then fail
    // for a reason that has nothing to do with what it checks.
    LOCK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
mod blobs;
