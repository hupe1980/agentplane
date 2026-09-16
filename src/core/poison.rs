//! Taking a lock over state a panic cannot leave half-written.
//!
//! `Mutex::lock` reports that some **other thread** panicked while holding the
//! lock. That is a fact about a thread, not about the data — the standard
//! library cannot know whether the panicking thread broke an invariant, so it
//! reports the possibility and lets the caller decide.
//!
//! Most of this crate's locks guard a membership set or a derived cache, where a
//! panicking thread either inserted an entry or did not. Propagating the poison
//! there converts one thread's panic into a **permanent** fault in every later
//! reader, for the life of the process.
//!
//! One case makes that concrete. [`InFlight`] deregisters a run from a `Drop`, so
//! a panicking task deregisters too — and a poisoned lock turns that unwrap into
//! a panic inside a `Drop` during unwinding, which is an immediate `abort`.
//!
//! So the rule is per lock:
//!
//! - **Derived or membership state** — [`recover`]. Nothing to break.
//! - **An invariant across fields**, the ledger being the one here, keeps the
//!   propagating unwrap: a ceiling whose accounting may have been interrupted
//!   must not read as sound.
//!
//! [`InFlight`]: crate::runtime::drain

use std::sync::{Mutex, MutexGuard};

/// Lock, ignoring a poison flag left by another thread's panic.
///
/// For state where a panic cannot leave a broken invariant — see the module
/// documentation for which locks those are, and for the one that is not.
pub(crate) fn recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // `into_inner` is the whole point: the guard is handed over, the poison flag
    // stays set for anyone who does care, and this reader carries on.
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::recover;
    use std::sync::{Arc, Mutex};

    #[test]
    fn a_poisoned_lock_still_hands_over_its_data() {
        let lock = Arc::new(Mutex::new(vec![1_u8]));
        let poisoner = Arc::clone(&lock);
        // Panic while holding it, which is what sets the flag.
        let panicked = std::thread::spawn(move || {
            let _guard = poisoner.lock().expect("fresh lock");
            panic!("on purpose");
        })
        .join();
        assert!(panicked.is_err(), "the helper thread must have panicked");
        assert!(
            lock.lock().is_err(),
            "the lock must be poisoned, or this test proves nothing"
        );

        let mut guard = recover(&lock);
        guard.push(2);
        assert_eq!(*guard, vec![1, 2]);
    }
}
