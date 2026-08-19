//! A key ring in this process. **For tests, and unreachable without `testkit`.**
//!
//! It holds the wrapping key beside the data it protects, so it protects that
//! data from nobody: anyone who can read the ciphertext can read the key. That
//! is why it lives here rather than beside the seam — the feature gate is the
//! guarantee, because a warning in a doc comment is not one.
//!
//! What it does implement exactly is the *semantics* worth testing without a
//! KMS, and it implements them the way a service does: a **wrapping key** per
//! scope and generation, a fresh data key per call sealed under it,
//! destruction, idempotent tombstones, rotation that adds a genuinely
//! different key without disturbing the old ones, and a version floor below
//! which decryption is refused as retired rather than as loss.

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
    /// The wrapping key per scope **and generation**. Erasure destroys every
    /// generation of a scope at once; rotation adds a generation without
    /// touching the old ones.
    ///
    /// Generation-dependent on purpose. Holding one KEK per scope and letting
    /// [`MemoryKeyRing::rotate`] bump only a *label* would make every rotation
    /// property vacuous: `open` could ignore `wrapped_by`, nothing would ever
    /// fail to open, and "payloads sealed before the rotation stay readable"
    /// would be true because nothing had rotated. With a key per generation,
    /// `open` must consult `wrapped_by` to find the right KEK — exactly as a
    /// KMS resolves a key version — and a wrap this ring never issued is
    /// refused instead of silently opened with whatever key is current.
    wrapping: HashMap<String, HashMap<u64, [u8; 32]>>,
    destroyed: HashMap<String, (Timestamp, String)>,
    /// Bumped by [`MemoryKeyRing::rotate`]; the id a new wrap is stamped with.
    generation: u64,
    /// The lowest generation [`MemoryKeyRing::open`] will still decrypt.
    floor: u64,
}

impl MemoryKeyRing {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Move to a new wrapping key.
    ///
    /// The next mint draws a **fresh KEK** under the new generation; prior
    /// generations keep their keys, so envelopes sealed before the rotation
    /// still open. That is the property sealed-byte immutability rests on —
    /// rotation adds a version, it does not invalidate one — and it is what
    /// makes rotation something other than an outage.
    pub fn rotate(&self) {
        self.state.lock().expect("keyring lock").generation += 1;
    }

    /// Refuse to decrypt below `generation`, as a KMS version floor does.
    ///
    /// Vault's `min_decryption_version` and its equivalents elsewhere. Modelled
    /// here because it is the one operator action that makes un-erased history
    /// unreadable, and a ring that could not express it would leave
    /// [`KeyError::Retired`] unreachable in every test — an error variant no
    /// test can produce is a classification nothing proves the runtime honours.
    pub fn retire_below(&self, generation: u64) {
        self.state.lock().expect("keyring lock").floor = generation;
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

    /// The KEK for one scope and generation, minted on first use.
    ///
    /// Only the *writing* path calls this — minting a data key under the
    /// current generation. The opening path must never mint: a KEK invented at
    /// decryption time opens nothing and hides the mistake.
    fn kek(state: &mut RingState, scope: &str, generation: u64) -> [u8; 32] {
        *state
            .wrapping
            .entry(scope.to_owned())
            .or_default()
            .entry(generation)
            .or_insert_with(|| {
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

    /// The generation a wrap names, or why it cannot be trusted.
    fn generation_of(wrapped_by: &str) -> Result<u64, KeyError> {
        wrapped_by
            .strip_prefix("memory-kek-")
            .and_then(|g| g.parse::<u64>().ok())
            .ok_or_else(|| {
                KeyError::Refused(format!(
                    "'{wrapped_by}' is not a wrapping key id this ring issues"
                ))
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
        let kek = Self::kek(&mut state, scope, generation);

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
        let state = self.state.lock().expect("keyring lock");
        if let Some(gone) = Self::tombstone(&state, &wrapped.scope) {
            return Err(gone);
        }
        // The wrap says which generation sealed it, and that is the key that
        // must open it — a KMS resolves the key version from the ciphertext's
        // own metadata the same way. Looked up, never minted: a scope or
        // generation this ring never wrapped for is a wrap somebody else
        // produced, and inventing a key here would "open" it to garbage and
        // hide the mistake. This check does NOT authenticate the wrap — XOR
        // has no integrity, deliberately, and a tampered `sealed` still opens
        // to wrong bytes; only the erasure and rotation *semantics* are
        // faithful here, never the cryptography.
        let generation = Self::generation_of(&wrapped.wrapped_by)?;
        // Checked before the lookup, so a retired version reports itself as
        // retired rather than falling through to "no wrapping key for scope",
        // which reads as loss.
        if generation < state.floor {
            return Err(KeyError::Retired {
                scope: wrapped.scope.clone(),
                key_id: wrapped.wrapped_by.clone(),
            });
        }
        let Some(kek) = state
            .wrapping
            .get(&wrapped.scope)
            .and_then(|generations| generations.get(&generation))
        else {
            return Err(KeyError::Refused(format!(
                "no wrapping key for scope '{}' at generation {generation}",
                wrapped.scope
            )));
        };
        let raw = Self::xor(kek, &wrapped.sealed);
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
}
