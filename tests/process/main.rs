//! Plans, cases, and work that spans more than one run.
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

mod batches;
mod cases;
mod plans;
mod replanning;
mod tasks;
mod telemetry;
mod timers;
mod waits;

/// Serialises tests that install an ambient `tracing` subscriber, and holds the
/// level filter open for the life of the binary.
///
/// `tracing` gates every event on a process-wide max level derived from the
/// *global* dispatcher. With only thread-local `set_default` subscribers there
/// is no global, the filter sits closed, and whether an event survives to reach
/// a thread-local subscriber depends on what other threads are doing. The
/// symptom is a capture assertion failing with *nothing* recorded, which reads
/// as "the runtime emitted no span" rather than "the filter was shut".
///
/// A permissive global dispatcher fixes the level; a thread-local `set_default`
/// still takes precedence on the thread that installs one, so each test still
/// sees only its own events.
pub fn ambient_subscriber() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static OPEN: std::sync::Once = std::sync::Once::new();
    OPEN.call_once(|| {
        let _ = tracing::subscriber::set_global_default(tracing_subscriber::registry());
    });
    // A panicking test poisons the lock, and every later test would then fail
    // for a reason that has nothing to do with what it checks.
    LOCK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
