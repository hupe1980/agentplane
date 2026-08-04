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

use crate::core::Digest;

/// Prefix for a leaf hash. See the module docs on why this is not optional.
const LEAF: u8 = 0x00;
/// Prefix for an interior hash.
const NODE: u8 = 0x01;

/// Hash one leaf.
#[must_use]
pub fn leaf_hash(value: &Digest) -> Digest {
    let mut bytes = Vec::with_capacity(33);
    bytes.push(LEAF);
    bytes.extend_from_slice(value.as_bytes());
    Digest::of(&bytes)
}

fn node_hash(left: &Digest, right: &Digest) -> Digest {
    let mut bytes = Vec::with_capacity(65);
    bytes.push(NODE);
    bytes.extend_from_slice(left.as_bytes());
    bytes.extend_from_slice(right.as_bytes());
    Digest::of(&bytes)
}

/// The root over a list of already-hashed leaves.
///
/// An empty log hashes to [`Digest::ZERO`], which is the same convention the
/// per-run chain uses for an unwritten run — so "nothing has happened yet" reads
/// the same everywhere.
#[must_use]
pub fn root(leaves: &[Digest]) -> Digest {
    if leaves.is_empty() {
        return Digest::ZERO;
    }
    if leaves.len() == 1 {
        return leaves[0];
    }
    // Split at the largest power of two below the length, per RFC 6962. Not at
    // the midpoint: the power-of-two split is what makes a tree's left subtree
    // stable as the log grows, which is what consistency proofs between two
    // checkpoints rely on.
    let k = split_point(leaves.len());
    let (l, r) = leaves.split_at(k);
    node_hash(&root(l), &root(r))
}

/// Largest power of two strictly less than `n`.
fn split_point(n: usize) -> usize {
    debug_assert!(n > 1);
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// The sibling hashes proving `index` is in a log of `leaves`.
///
/// Ordered leaf-upwards, so a verifier folds them in the order it receives them.
#[must_use]
pub fn inclusion_proof(leaves: &[Digest], index: usize) -> Vec<Digest> {
    let mut proof = Vec::new();
    build_proof(leaves, index, &mut proof);
    proof
}

fn build_proof(leaves: &[Digest], index: usize, out: &mut Vec<Digest>) {
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
    leaf: &Digest,
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

    let mut hash = *leaf;
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
pub fn consistency_proof(leaves: &[Digest], old_size: usize) -> Vec<Digest> {
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
fn subproof(m: usize, leaves: &[Digest], complete: bool, out: &mut Vec<Digest>) {
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
        // Every log extends the empty one, and there is nothing to check —
        // but a proof offered for it is a proof of nothing, so refuse it rather
        // than ignore it.
        return proof.is_empty();
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
/// as a parameter and already has it. Forgetting that is how a correct proof
/// gets rejected: the first version of this returned `None` there and failed
/// every log growing from 1 to 2.
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

    fn leaves(n: usize) -> Vec<Digest> {
        (0..n)
            .map(|i| leaf_hash(&Digest::of(&[u8::try_from(i).unwrap()])))
            .collect()
    }

    #[test]
    fn an_empty_log_is_zero() {
        assert_eq!(root(&[]), Digest::ZERO);
    }

    #[test]
    fn every_leaf_proves_its_own_inclusion() {
        for n in 1..=17 {
            let l = leaves(n);
            let r = root(&l);
            for i in 0..n {
                let proof = inclusion_proof(&l, i);
                assert!(
                    verify_inclusion(&l[i], i, n, &proof, &r),
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
        assert!(!verify_inclusion(&l[5], 5, 8, &proof, &r));
        assert!(!verify_inclusion(&l[2], 3, 8, &proof, &r));
    }

    /// Extra hashes appended to a valid proof must not be ignored.
    #[test]
    fn a_padded_proof_is_rejected() {
        let l = leaves(8);
        let r = root(&l);
        let mut proof = inclusion_proof(&l, 2);
        proof.push(Digest::ZERO);
        assert!(
            !verify_inclusion(&l[2], 2, 8, &proof, &r),
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
            leaf_hash(&a),
            Digest::of(a.as_bytes()),
            "a leaf hash is a plain hash of its value, so the prefix is missing"
        );
        assert_ne!(node_hash(&a, &b), leaf_hash(&a));
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
        assert!(verify_consistency(0, &Digest::ZERO, 5, &root(&l), &[]));
        // But a proof offered for it is a proof of nothing.
        assert!(!verify_consistency(
            0,
            &Digest::ZERO,
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
        assert!(!verify_inclusion(&l[2], 2, 9, &proof, &r));
        // 4 leaves is shorter for the same reason.
        assert!(!verify_inclusion(&l[2], 2, 4, &proof, &r));
    }
}
