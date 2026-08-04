//! A key ring in this process. **For tests, and unreachable without `testkit`.**
//!
//! It holds the wrapping key beside the data it protects, so it protects that
//! data from nobody: anyone who can read the ciphertext can read the key. That
//! is why it lives here rather than beside the seam — the feature gate is the
//! guarantee, because a warning in a doc comment is not one.
//!
//! What it does implement exactly is the *semantics* worth testing without a
//! KMS, and it implements them the way a service does: a **wrapping key** per
//! scope, a fresh data key per call sealed under it, destruction, idempotent
//! tombstones, and rotation by re-wrapping.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;

use crate::core::{KeyId, Timestamp};
use crate::keyring::{DataKey, KeyError, KeyRing, WrappedKey};

/// A key ring in this process. **For tests.**
///
/// It holds the wrapping keys beside the data they protect, so it protects that
/// data from nobody: anyone who can read the ciphertext can read the keys. What
/// it does model faithfully is the shape a real service has — a named wrapping
/// key per scope, a fresh data key per call, and erasure by destroying the
/// wrapping key rather than by refusing to look.
#[derive(Debug, Default)]
pub struct MemoryKeyRing {
    state: Mutex<RingState>,
}

#[derive(Debug, Default)]
struct RingState {
    /// The wrapping key per scope. This is what erasure destroys.
    wrapping: HashMap<String, [u8; 32]>,
    destroyed: HashMap<String, (Timestamp, String)>,
    /// Bumped by [`MemoryKeyRing::rotate`]; the id a new wrap is stamped with.
    generation: u64,
}

impl MemoryKeyRing {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Move to a new wrapping key id. Existing data keys stay openable until
    /// rewrapped, which is what makes rotation not an outage.
    pub fn rotate(&self) {
        self.state.lock().expect("keyring lock").generation += 1;
    }

    /// The current wrapping key's id.
    #[must_use]
    pub fn current_key_id(&self) -> KeyId {
        format!(
            "memory-kek-{}",
            self.state.lock().expect("keyring lock").generation
        )
    }

    fn tombstone(state: &RingState, scope: &str) -> Option<KeyError> {
        state
            .destroyed
            .get(scope)
            .map(|(at, reason)| KeyError::Destroyed {
                scope: scope.to_owned(),
                at: *at,
                reason: reason.clone(),
            })
    }

    /// Seal or open a data key under a scope's wrapping key.
    ///
    /// XOR, and deliberately so: this type protects nothing by construction, and
    /// a real-looking cipher here would invite somebody to reach for it in
    /// anger. What is faithful is *when* it fails — once the wrapping key is
    /// gone, so is every data key sealed under it.
    fn xor(kek: &[u8; 32], bytes: &[u8]) -> Vec<u8> {
        bytes
            .iter()
            .zip(kek.iter().cycle())
            .map(|(b, k)| b ^ k)
            .collect()
    }

    fn kek(state: &mut RingState, scope: &str) -> [u8; 32] {
        *state.wrapping.entry(scope.to_owned()).or_insert_with(|| {
            use rand::RngCore as _;
            let mut k = [0u8; 32];
            // The determinism gate exists so a replayed run reads a journaled
            // value instead of drawing a fresh one. Key material is the opposite
            // case on both counts: it must be unpredictable, and it must never
            // be journaled — a key in the chain is a key erasure cannot destroy.
            #[allow(clippy::disallowed_methods)]
            rand::rng().fill_bytes(&mut k);
            k
        })
    }
}

#[async_trait]
impl KeyRing for MemoryKeyRing {
    async fn data_key(&self, scope: &str) -> Result<(DataKey, WrappedKey), KeyError> {
        let mut state = self.state.lock().expect("keyring lock");
        if let Some(gone) = Self::tombstone(&state, scope) {
            return Err(gone);
        }
        let generation = state.generation;
        let kek = Self::kek(&mut state, scope);

        // Fresh per call, exactly as a service mints one.
        let mut dek = [0u8; 32];
        {
            use rand::RngCore as _;
            #[allow(clippy::disallowed_methods)]
            rand::rng().fill_bytes(&mut dek);
        }
        Ok((
            DataKey::new(dek),
            WrappedKey {
                scope: scope.to_owned(),
                wrapped_by: format!("memory-kek-{generation}"),
                sealed: Self::xor(&kek, &dek),
            },
        ))
    }

    async fn open(&self, wrapped: &WrappedKey) -> Result<DataKey, KeyError> {
        let mut state = self.state.lock().expect("keyring lock");
        if let Some(gone) = Self::tombstone(&state, &wrapped.scope) {
            return Err(gone);
        }
        // Absent rather than tombstoned: a scope this ring never wrapped for.
        // Minting one here would open nothing and hide the mistake.
        if !state.wrapping.contains_key(&wrapped.scope) {
            return Err(KeyError::Refused(format!(
                "no wrapping key for scope '{}'",
                wrapped.scope
            )));
        }
        let kek = Self::kek(&mut state, &wrapped.scope);
        let raw = Self::xor(&kek, &wrapped.sealed);
        let mut dek = [0u8; 32];
        if raw.len() != dek.len() {
            return Err(KeyError::Refused(
                "a wrapped data key is not the right length".to_owned(),
            ));
        }
        dek.copy_from_slice(&raw);
        Ok(DataKey::new(dek))
    }

    async fn destroy(&self, scope: &str, at: Timestamp, reason: &str) -> Result<(), KeyError> {
        let mut state = self.state.lock().expect("keyring lock");
        // The wrapping key, not the data keys: every data key ever sealed under
        // it becomes unopenable, wherever its copies are.
        state.wrapping.remove(scope);
        // First destruction stands: a retry must not rewrite when or why.
        state
            .destroyed
            .entry(scope.to_owned())
            .or_insert_with(|| (at, reason.to_owned()));
        Ok(())
    }

    async fn rewrap(&self, wrapped: &WrappedKey) -> Result<WrappedKey, KeyError> {
        let dek = self.open(wrapped).await?;
        let mut state = self.state.lock().expect("keyring lock");
        let generation = state.generation;
        let kek = Self::kek(&mut state, &wrapped.scope);
        Ok(WrappedKey {
            scope: wrapped.scope.clone(),
            wrapped_by: format!("memory-kek-{generation}"),
            sealed: Self::xor(&kek, dek.expose()),
        })
    }
}
