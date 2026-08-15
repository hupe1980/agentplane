//! Binding runs to each other.
//!
//! # The gap a per-run chain leaves
//!
//! Each run's records are chained to each other, and nothing chains one run to
//! the next. So the property a chain delivers stops at the run boundary:
//! **deleting an entire run leaves every remaining run verifying perfectly.**
//! What is left pointing at the deleted run is a case row — ordinary mutable
//! data that goes in the same delete.
//!
//! Signing does not close this. A signature says who wrote a record; it says
//! nothing about whether some *other* record ever existed. An operator removing
//! a run removes its signatures with it.
//!
//! What closes it is committing to the **set** of runs: a Merkle tree whose
//! leaves are sealed-run digests. Remove a leaf and the root changes, so a root
//! published earlier no longer matches the store — and "published earlier" is
//! the part that has to leave the operator's control — the checkpoint's job.
//!
//! # RFC 6962, not a hand-rolled tree
//!
//! Leaf and interior hashes are domain-separated by a prefix byte, exactly as
//! Certificate Transparency does. Without that separation a leaf can be made to
//! collide with an interior node, and an attacker who controls leaf content can
//! present a subtree as a leaf — the second-preimage attack the prefix exists to
//! prevent. It costs one byte per hash and it is not optional.
//!
//! # Which is why a leaf hash is its own type
//!
//! "Not optional" was, for a while, exactly optional: [`leaf_hash`] took a
//! `Digest` and returned one, and [`root`] took `Digest`s meaning
//! *already-hashed leaves* — so skipping the call produced a tree with no leaf
//! separation, a plausible root, and nothing to notice. Every caller in this
//! crate happened to get it right, which is the shape of defect this project
//! treats most seriously: a property the runtime **relies on** rather than
//! **checks**, on a seam published for other people to use.
//!
//! [`LeafHash`] closes it where the evidence is strongest — construction.
//! There is one way to make one, it applies the prefix, and a tree built from
//! raw digests does not compile. The prefix bytes are checked by the RFC 6962
//! vectors below; what the type adds is that they cannot be skipped.

use crate::core::Digest;

/// A leaf hash: `H(0x00 ‖ digest)`.
///
/// Distinct from [`Digest`] on purpose. Both are thirty-two bytes and the
/// compiler is the only thing that can tell "the digest of a sealed run" from
/// "that digest, hashed as a leaf" — and the difference is the whole
/// second-preimage defence. A function taking `Digest` for a leaf is a
/// function whose contract lives in its documentation, which is where this one
/// lived until a reader pointed out that nothing enforced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LeafHash(Digest);

impl LeafHash {
    /// The hash itself, for the callers that must serialize or compare it.
    ///
    /// Deliberately not `From<LeafHash> for Digest`-and-back: going *out* is
    /// safe, and the missing direction is the point — nothing reconstructs a
    /// `LeafHash` from an arbitrary digest, because that is precisely the
    /// mistake the type exists to refuse.
    #[must_use]
    pub const fn digest(self) -> Digest {
        self.0
    }
}

/// Prefix for a leaf hash. See the module docs on why this is not optional.
const LEAF: u8 = 0x00;
/// Prefix for an interior hash.
const NODE: u8 = 0x01;

/// Hash one leaf — the only way to obtain a [`LeafHash`].
#[must_use]
pub fn leaf_hash(value: &Digest) -> LeafHash {
    let mut bytes = Vec::with_capacity(33);
    bytes.push(LEAF);
    bytes.extend_from_slice(value.as_bytes());
    LeafHash(Digest::of(&bytes))
}

fn node_hash(left: &Digest, right: &Digest) -> Digest {
    let mut bytes = Vec::with_capacity(65);
    bytes.push(NODE);
    bytes.extend_from_slice(left.as_bytes());
    bytes.extend_from_slice(right.as_bytes());
    Digest::of(&bytes)
}

/// The root over a list of leaves, each already hashed by [`leaf_hash`].
///
/// Taking [`LeafHash`] rather than [`Digest`] is the second-preimage defence
/// made structural: a caller who forgets to leaf-hash cannot reach this
/// function at all, rather than getting a plausible root over an
/// undifferentiated tree with nothing to say so.
///
/// ```compile_fail
/// use agentplane::core::{merkle, Digest};
/// // Raw digests are not leaves: a tree built from them has no domain
/// // separation between leaves and interior nodes.
/// let _ = merkle::root(&[Digest::of(b"a"), Digest::of(b"b")]);
/// ```
///
/// ```
/// use agentplane::core::{merkle, Digest};
/// let leaves = [merkle::leaf_hash(&Digest::of(b"a")), merkle::leaf_hash(&Digest::of(b"b"))];
/// assert_ne!(merkle::root(&leaves), Digest::ZERO);
/// ```
///
/// An empty log hashes to [`empty_root`], which is `SHA-256("")` — RFC 6962's
/// value, not this crate's choice.
#[must_use]
pub fn root(leaves: &[LeafHash]) -> Digest {
    if leaves.is_empty() {
        return empty_root();
    }
    if leaves.len() == 1 {
        return leaves[0].0;
    }
    // Split at the largest power of two below the length, per RFC 6962. Not at
    // the midpoint: the power-of-two split is what makes a tree's left subtree
    // stable as the log grows, which is what consistency proofs between two
    // checkpoints rely on.
    let k = split_point(leaves.len());
    let (l, r) = leaves.split_at(k);
    node_hash(&root(l), &root(r))
}

/// The root of the empty log: `SHA-256("")`, per RFC 6962.
///
/// Not a convention this crate gets to pick. The Merkle root is the one value
/// here that is **not** private: it goes into a `tlog-checkpoint`, gets
/// cosigned by witnesses this project does not operate, and is recomputed by
/// verifiers this project did not write. RFC 6962 fixes the empty tree's hash,
/// and a size-0 checkpoint is exactly what a fresh log first submits.
///
/// Thirty-two zero bytes would also be the worse value on its own terms:
/// that is what an uninitialised buffer, a default-constructed struct and a
/// truncated read all produce, so "the empty log" and "this field was never
/// filled in" would share a representation. `SHA-256("")` is a value nothing
/// produces by accident.
#[must_use]
pub fn empty_root() -> Digest {
    Digest::of(b"")
}

/// Largest power of two strictly less than `n`.
fn split_point(n: usize) -> usize {
    debug_assert!(n > 1);
    let mut k: usize = 1;
    // `k.checked_mul(2)` rather than `k * 2`: a size past 2^63 doubles into an
    // overflow, which in release wraps to zero and loops forever — so a store
    // or a submitted checkpoint claiming `u64::MAX` hangs the verifier instead
    // of being refused by it. An audit runs against a store it did not write,
    // so the party under examination could stop the examination with one
    // number.
    while k.checked_mul(2).is_some_and(|next| next < n) {
        k *= 2;
    }
    k
}

/// The sibling hashes proving `index` is in a log of `leaves`.
///
/// Ordered leaf-upwards, so a verifier folds them in the order it receives them.
#[must_use]
pub fn inclusion_proof(leaves: &[LeafHash], index: usize) -> Vec<Digest> {
    // The verifier refuses `index >= size`; without the same guard here the
    // prover answers a short, wrong proof instead of nothing, and the caller
    // ships it. Both stores read the leaf set and the run's rank in separate
    // snapshots, so a run sealing between the two really does ask for the leaf
    // one past the end — and the honest, busy plane then reports a false
    // integrity finding against itself.
    if index >= leaves.len() {
        return Vec::new();
    }
    let mut proof = Vec::new();
    build_proof(leaves, index, &mut proof);
    proof
}

fn build_proof(leaves: &[LeafHash], index: usize, out: &mut Vec<Digest>) {
    if leaves.len() <= 1 {
        return;
    }
    let k = split_point(leaves.len());
    let (l, r) = leaves.split_at(k);
    if index < k {
        build_proof(l, index, out);
        out.push(root(r));
    } else {
        build_proof(r, index - k, out);
        out.push(root(l));
    }
}

/// Whether `leaf` really sits at `index` in a log of `size` with this `root`.
///
/// Takes `size` as well as the proof because the tree's shape depends on it —
/// a proof verified without the size can be replayed against a differently
/// shaped tree, which is how an inclusion proof gets accepted for a log that
/// never contained the leaf.
#[must_use]
pub fn verify_inclusion(
    leaf: LeafHash,
    index: usize,
    size: usize,
    proof: &[Digest],
    expected: &Digest,
) -> bool {
    if index >= size {
        return false;
    }
    // The path is discovered top-down, but the proof arrives leaf-upwards — the
    // recursion that builds it pushes the deepest sibling first. So the
    // decisions are collected walking down and then consumed in reverse, which
    // is the order the hashes are in.
    let mut went_left = Vec::new();
    let mut idx = index;
    let mut len = size;
    while len > 1 {
        let k = split_point(len);
        if idx < k {
            went_left.push(true);
            len = k;
        } else {
            went_left.push(false);
            idx -= k;
            len -= k;
        }
    }

    if went_left.len() != proof.len() {
        // A proof with the wrong number of hashes is not a proof for this tree.
        // Accepting a longer one would let an attacker pad a valid proof; a
        // shorter one would let them truncate the path and skip a sibling.
        return false;
    }

    let mut hash = leaf.digest();
    for (sibling, left) in proof.iter().zip(went_left.iter().rev()) {
        hash = if *left {
            node_hash(&hash, sibling)
        } else {
            node_hash(sibling, &hash)
        };
    }
    hash == *expected
}

/// Sibling hashes proving a log of `old_size` is a **prefix** of one of
/// `leaves.len()`.
///
/// # Why an inclusion proof is not enough on its own
///
/// The root moves whenever anything is appended, which is constantly. So an
/// auditor comparing two checkpoints and seeing a different root has learnt
/// nothing: legitimate growth looks exactly like deletion-plus-growth.
///
/// A consistency proof separates them. It shows the earlier tree is a prefix of
/// the later one — that every leaf committed to before is still committed to, in
/// the same position. **That** is what makes a published checkpoint evidence:
/// not "the root changed", but "the root changed in the only way an append-only
/// log is allowed to change".
///
/// Returns an empty proof when `old_size == leaves.len()` (nothing to prove) and
/// when `old_size == 0` (an empty log is a prefix of everything).
#[must_use]
pub fn consistency_proof(leaves: &[LeafHash], old_size: usize) -> Vec<Digest> {
    if old_size == 0 || old_size > leaves.len() {
        return Vec::new();
    }
    let mut out = Vec::new();
    subproof(old_size, leaves, true, &mut out);
    out
}

/// RFC 6962's `SUBPROOF`.
///
/// `complete` tracks whether the old tree is exactly the subtree being examined.
/// When it is, its root is already known to the verifier and need not be sent —
/// which is the whole reason this parameter exists rather than always emitting
/// the hash.
fn subproof(m: usize, leaves: &[LeafHash], complete: bool, out: &mut Vec<Digest>) {
    if m == leaves.len() {
        if !complete {
            out.push(root(leaves));
        }
        return;
    }
    let k = split_point(leaves.len());
    let (l, r) = leaves.split_at(k);
    if m <= k {
        subproof(m, l, complete, out);
        out.push(root(r));
    } else {
        subproof(m - k, r, false, out);
        out.push(root(l));
    }
}

/// Whether `new_root` really extends `old_root` without disturbing it.
///
/// Reconstructs *both* roots from the proof. Checking only the new one would
/// accept a proof for some other old tree entirely — which is how a fork gets
/// presented as an extension.
#[must_use]
pub fn verify_consistency(
    old_size: usize,
    old_root: &Digest,
    new_size: usize,
    new_root: &Digest,
    proof: &[Digest],
) -> bool {
    if old_size > new_size {
        return false;
    }
    if old_size == 0 {
        // Every log extends the empty one, so there is no *proof* to check —
        // but the pair still has to be a coherent checkpoint. An empty log
        // hashes to `empty_root()` and nothing else, so a caller
        // presenting size 0 beside any other root is presenting a checkpoint
        // that never existed, and answering `true` would bless it. Checking
        // the proof and ignoring the root would make "consistent with the
        // empty log" a sentence that accepts whatever root is put beside it.
        //
        // What this does not check, because nothing here can: that the
        // *new* pair is a real checkpoint. Growth from nothing has no proof
        // to verify against, so a first checkpoint is trusted or witnessed on
        // other grounds — which is what the witness exists for.
        return proof.is_empty() && *old_root == empty_root();
    }
    if old_size == new_size {
        return proof.is_empty() && old_root == new_root;
    }

    let mut fed = 0;
    let Some((old, new)) = rebuild(old_size, new_size, proof, &mut fed, true, old_root) else {
        return false;
    };
    // Both roots must come out, and nothing may be left over: a proof with
    // trailing hashes is not the proof for these two trees.
    old == *old_root && new == *new_root && fed == proof.len()
}

/// Rebuild `(old_root, new_root)` from the proof.
///
/// `complete` says whether the subtree being examined *is* the old tree. When it
/// is, the prover omits its hash — because the verifier was handed the old root
/// as a parameter and already has it. Reading for a hash that was deliberately
/// not sent is how a correct proof gets rejected, and the smallest case that
/// shows it is a log growing from 1 to 2.
fn rebuild(
    m: usize,
    n: usize,
    proof: &[Digest],
    fed: &mut usize,
    complete: bool,
    old_root: &Digest,
) -> Option<(Digest, Digest)> {
    if m == n {
        if complete {
            return Some((*old_root, *old_root));
        }
        let h = *proof.get(*fed)?;
        *fed += 1;
        return Some((h, h));
    }

    let k = split_point(n);
    if m <= k {
        let (old, new_left) = rebuild(m, k, proof, fed, complete, old_root)?;
        let right = *proof.get(*fed)?;
        *fed += 1;
        Some((old, node_hash(&new_left, &right)))
    } else {
        let (old_right, new_right) = rebuild(m - k, n - k, proof, fed, false, old_root)?;
        let left = *proof.get(*fed)?;
        *fed += 1;
        Some((node_hash(&left, &old_right), node_hash(&left, &new_right)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<LeafHash> {
        (0..n)
            .map(|i| leaf_hash(&Digest::of(&[u8::try_from(i).unwrap()])))
            .collect()
    }

    /// **The tree is RFC 6962's, pinned to hashes computed outside this crate.**
    ///
    /// A checkpoint is submitted to witnesses that verify it with somebody
    /// else's code, so agreeing with ourselves proves nothing: these two values
    /// were produced by Python's `hashlib` from the RFC's own construction —
    /// `leaf = SHA256(0x00 ‖ d)`, `node = SHA256(0x01 ‖ l ‖ r)` — and a tree
    /// that stopped matching them would still verify perfectly against every
    /// other test in this file while agreeing with no witness in the network.
    ///
    /// It is also the check that says the prefixes are the *right* bytes rather
    /// than merely present and different, which is all `a_leaf_is_not_a_node`
    /// below can tell.
    #[test]
    fn the_tree_matches_rfc_6962_computed_elsewhere() {
        let a = Digest::of(b"a");
        let b = Digest::of(b"b");
        assert_eq!(
            leaf_hash(&a).digest().to_hex(),
            "a23bd5b06da9048238a65b3f1d9d0b9e15fae3dde262688e6489aa4c763d1820",
            "the leaf hash left RFC 6962, and every published checkpoint with it"
        );
        assert_eq!(
            root(&[leaf_hash(&a), leaf_hash(&b)]).to_hex(),
            "ad5ca6cddc0b27c6a83e332bf28011769236e6c6a1f786ebf7b5267b37a5bd22",
            "the interior hash left RFC 6962"
        );
    }

    /// A tree cannot be built from digests that were never leaf-hashed.
    ///
    /// Not a runtime assertion — there is nothing to assert, because the
    /// mistake no longer type-checks. The test is here to say so, and to fail
    /// loudly if somebody widens the signature back to `Digest`: at that point
    /// this file compiles again with the line below uncommented, and the
    /// second-preimage defence is once more a thing callers must remember.
    ///
    #[test]
    fn a_raw_digest_is_not_a_leaf() {
        // That a raw digest cannot *be* a leaf is enforced by the compiler and
        // demonstrated by the `compile_fail` doctest on `root`, where rustdoc
        // actually collects it — inside this module it would never have run.
        // What is checkable here is the other half: the constructor prefixes.
        let a = Digest::of(b"a");
        assert_ne!(
            leaf_hash(&a).digest(),
            a,
            "leaf_hash returned its input, so the prefix is not being applied"
        );
    }

    /// **"Consistent with the empty log" is a claim about a specific root.**
    ///
    /// Growth from nothing has no proof to verify, which made it tempting to
    /// answer `true` and move on — and that answer accepted any `old_root` a
    /// caller put beside `size 0`, including one no log ever had. A witness
    /// asked to cosign growth from such a checkpoint would have agreed that a
    /// tree it never saw was extended correctly, which is the one question
    /// witnessing exists to answer.
    ///
    /// Three halves, because the first two alone would each pass under a
    /// different wrong implementation: the empty checkpoint must verify, a
    /// wrong root must not, and a proof offered where none can exist must not.
    #[test]
    fn growth_from_the_empty_log_still_names_the_empty_root() {
        let after = root(&leaves(3));

        assert!(
            verify_consistency(0, &empty_root(), 3, &after, &[]),
            "the honest empty checkpoint must verify, or nothing can ever grow"
        );
        assert!(
            !verify_consistency(0, &Digest::of(b"a root no log ever had"), 3, &after, &[]),
            "size 0 was accepted beside a root that is not the empty log's — a \
             checkpoint that never existed verified as the ancestor of one that does"
        );
        assert!(
            !verify_consistency(0, &empty_root(), 3, &after, &[after]),
            "a proof was accepted where there is nothing to prove"
        );
    }

    #[test]
    fn an_empty_log_hashes_the_way_rfc_6962_says() {
        // Pinned to the hex an implementation nobody here wrote computes, not
        // to `Digest::of(b"")` — restating the definition would pass against
        // any definition, including the wrong one this replaced.
        assert_eq!(
            root(&[]).to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "the empty tree's root is SHA-256 of the empty string; it was thirty-two \
             zero bytes, which no conforming verifier computes and which an \
             uninitialised buffer produces by accident"
        );
        assert_ne!(
            root(&[]),
            Digest::ZERO,
            "and it must not be the value a default-constructed struct carries"
        );
    }

    #[test]
    fn every_leaf_proves_its_own_inclusion() {
        for n in 1..=17 {
            let l = leaves(n);
            let r = root(&l);
            for i in 0..n {
                let proof = inclusion_proof(&l, i);
                assert!(
                    verify_inclusion(l[i], i, n, &proof, &r),
                    "leaf {i} of {n} failed to prove"
                );
            }
        }
    }

    /// The property the whole mechanism exists for.
    #[test]
    fn removing_a_leaf_changes_the_root() {
        let l = leaves(8);
        let before = root(&l);
        let mut without = l.clone();
        without.remove(3);
        assert_ne!(
            before,
            root(&without),
            "a run was deleted and the root did not move — which is the entire \
             thing this is for"
        );
    }

    /// A proof for one leaf must not verify another.
    #[test]
    fn a_proof_does_not_transfer() {
        let l = leaves(8);
        let r = root(&l);
        let proof = inclusion_proof(&l, 2);
        assert!(!verify_inclusion(l[5], 5, 8, &proof, &r));
        assert!(!verify_inclusion(l[2], 3, 8, &proof, &r));
    }

    /// Extra hashes appended to a valid proof must not be ignored.
    #[test]
    fn a_padded_proof_is_rejected() {
        let l = leaves(8);
        let r = root(&l);
        let mut proof = inclusion_proof(&l, 2);
        proof.push(Digest::ZERO);
        assert!(
            !verify_inclusion(l[2], 2, 8, &proof, &r),
            "a proof with trailing junk verified, so any valid proof can be \
             padded into a different-looking one"
        );
    }

    /// A leaf must not be presentable as an interior node.
    ///
    /// The reason for the domain-separation prefix: without it, a leaf whose
    /// value happens to be `hash(left) ‖ hash(right)` could stand in for the
    /// node above it.
    #[test]
    fn leaves_and_nodes_are_domain_separated() {
        let a = Digest::of(b"a");
        let b = Digest::of(b"b");
        assert_ne!(
            leaf_hash(&a).digest(),
            Digest::of(a.as_bytes()),
            "a leaf hash is a plain hash of its value, so the prefix is missing"
        );
        assert_ne!(node_hash(&a, &b), leaf_hash(&a).digest());
    }

    // ── Consistency: append-only, or forked? ────────────────────────────────

    /// Every append is provably an append.
    #[test]
    fn growth_is_provably_append_only() {
        for n in 1..=17usize {
            let new = leaves(n);
            let new_root = root(&new);
            for m in 1..=n {
                let old = &new[..m];
                let old_root = root(old);
                let proof = consistency_proof(&new, m);
                assert!(
                    verify_consistency(m, &old_root, n, &new_root, &proof),
                    "a log of {m} growing to {n} could not prove it only appended"
                );
            }
        }
    }

    /// **The property that makes a checkpoint evidence.**
    ///
    /// Without this, an auditor comparing two roots learns nothing: legitimate
    /// growth changes the root exactly as deletion does. A consistency proof is
    /// what separates "runs were added" from "a run was removed and others
    /// added".
    #[test]
    fn a_deletion_cannot_be_passed_off_as_growth() {
        let original = leaves(8);
        let old_root = root(&original);

        // Somebody removes leaf 3 and appends two more. The log is *longer* than
        // it was, so a size check sees growth.
        let mut forked = original.clone();
        forked.remove(3);
        forked.push(leaf_hash(&Digest::of(b"new-a")));
        forked.push(leaf_hash(&Digest::of(b"new-b")));
        let forked_root = root(&forked);
        assert!(forked.len() > original.len(), "the log did grow");

        // No proof can make that look like an append.
        let attempted = consistency_proof(&forked, original.len());
        assert!(
            !verify_consistency(
                original.len(),
                &old_root,
                forked.len(),
                &forked_root,
                &attempted
            ),
            "a log with a run deleted from the middle passed as an append-only \
             extension — which is the only thing a published checkpoint is for"
        );
    }

    /// A forged old root is rejected where the prefix straddles a split.
    ///
    /// Worth its own test because the obvious one does not exercise this. When
    /// the old tree is a left-aligned prefix — 8 of 9, say — the verifier never
    /// *reconstructs* the old root: the prover omits it precisely because the
    /// verifier was handed it, so comparing it to itself is tautological. The
    /// binding only does work when the prefix straddles a split and the old root
    /// is rebuilt from proof hashes.
    ///
    /// Found by mutation testing: deleting the old-root comparison changed
    /// nothing, because every test then present used the left-aligned shape.
    #[test]
    fn a_forged_old_root_is_rejected() {
        let l = leaves(9);
        let new_root = root(&l);
        // 5 of 9 straddles: the top split is at 8, and 5 falls inside the left
        // subtree's right half, so the old root is rebuilt rather than echoed.
        let proof = consistency_proof(&l, 5);
        let real = root(&l[..5]);
        assert!(verify_consistency(5, &real, 9, &new_root, &proof));

        let forged = Digest::of(b"not the old root");
        assert!(
            !verify_consistency(5, &forged, 9, &new_root, &proof),
            "a consistency proof verified against an old root the log never had, \
             which is how a fork is presented as an extension"
        );
    }

    /// A proof for one pair of sizes must not verify another.
    #[test]
    fn a_consistency_proof_does_not_transfer() {
        let l = leaves(9);
        let r = root(&l);
        let proof = consistency_proof(&l, 4);
        assert!(!verify_consistency(5, &root(&l[..5]), 9, &r, &proof));
        assert!(!verify_consistency(
            4,
            &root(&l[..4]),
            8,
            &root(&l[..8]),
            &proof
        ));
    }

    /// Shrinking is never consistent.
    #[test]
    fn a_log_cannot_shrink() {
        let l = leaves(8);
        assert!(!verify_consistency(8, &root(&l), 4, &root(&l[..4]), &[]));
    }

    /// A padded proof is rejected, as for inclusion.
    #[test]
    fn a_padded_consistency_proof_is_rejected() {
        let l = leaves(8);
        let mut proof = consistency_proof(&l, 3);
        proof.push(Digest::ZERO);
        assert!(!verify_consistency(3, &root(&l[..3]), 8, &root(&l), &proof));
    }

    /// The empty log extends into anything, and needs no proof to say so.
    #[test]
    fn the_empty_log_is_a_prefix_of_everything() {
        let l = leaves(5);
        assert!(verify_consistency(0, &empty_root(), 5, &root(&l), &[]));
        // But a proof offered for it is a proof of nothing.
        assert!(!verify_consistency(
            0,
            &empty_root(),
            5,
            &root(&l),
            &[Digest::ZERO]
        ));
    }

    /// A size that changes the tree's *shape* is rejected.
    ///
    /// Note what this does **not** claim, because the first version of this test
    /// claimed it and was wrong. A size that leaves the path shape unchanged —
    /// 7 versus 8, for a leaf in the left subtree — verifies identically, because
    /// every sibling on the path is supplied by the prover and the arithmetic
    /// cannot tell the two trees apart.
    ///
    /// That is not a hole; it is where the boundary actually is. An inclusion
    /// proof is verified against `(leaf, index, size, root)`, and **the size and
    /// root come from a signed checkpoint** — so lying about the size means
    /// forging the checkpoint. RFC 6962 has exactly this shape for exactly this
    /// reason. Expecting the proof arithmetic to authenticate its own parameters
    /// is asking the wrong component.
    #[test]
    fn a_size_that_changes_the_shape_is_rejected() {
        let l = leaves(8);
        let r = root(&l);
        let proof = inclusion_proof(&l, 2);

        // 9 leaves puts an extra level above: the path is longer, so the proof
        // no longer has the right number of hashes.
        assert!(!verify_inclusion(l[2], 2, 9, &proof, &r));
        // 4 leaves is shorter for the same reason.
        assert!(!verify_inclusion(l[2], 2, 4, &proof, &r));
    }
}
