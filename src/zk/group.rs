//! The set of subscribers a proof shows membership of.

use ark_bn254::Fr;
use ark_ff::Zero as _;

use super::field::{FieldElement, Poseidon2};

/// The deepest tree the circuit accepts: 2^16 members.
pub const MAX_DEPTH: usize = 16;

/// The subscribers' identity commitments, as a Lean incremental Merkle tree.
///
/// This is the tree Semaphore v4 uses: leaves in insertion order, each pair
/// hashed with Poseidon, and a node without a right sibling carried up
/// unchanged rather than paired with a zero. Its root is what the Control
/// Plane checks a proof against, so the leaves must be exactly the
/// registry's, in the registry's order — including the zeros it leaves where
/// a member was removed, which keep every later member's position, and so
/// their proofs, intact.
///
/// # Examples
///
/// ```
/// # use singula::zk::{FieldElement, Group};
/// let leaves: Vec<FieldElement> = ["111", "222", "333"]
///     .iter()
///     .map(|s| s.parse())
///     .collect::<Result<_, _>>()?;
/// let group = Group::new(&leaves)?;
/// assert_eq!(group.depth(), 2);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Group {
    /// `levels[0]` is the leaves, the last level is the root alone.
    levels: Vec<Vec<Fr>>,
}

/// Why a group could not be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum GroupError {
    /// The group has no members.
    #[error("a group needs at least one member")]
    Empty,
    /// More members than the circuit's tree can hold.
    #[error("{0} members need a deeper tree than the circuit's {MAX_DEPTH} levels")]
    TooLarge(usize),
}

/// One member's path to the root, as the circuit takes it.
pub(crate) struct MerkleProof {
    /// Bit `k` set when the node at the `k`-th recorded level is a right child.
    pub(crate) index: u64,
    /// Siblings from the leaf up, only for the levels that had one.
    pub(crate) siblings: Vec<Fr>,
}

impl Group {
    /// Builds the tree over `members`, in order.
    ///
    /// # Errors
    ///
    /// Returns [`GroupError`] if there are no members or more than 2^16.
    pub fn new(members: &[FieldElement]) -> Result<Self, GroupError> {
        if members.is_empty() {
            return Err(GroupError::Empty);
        }
        if members.len() > 1 << MAX_DEPTH {
            return Err(GroupError::TooLarge(members.len()));
        }

        let mut poseidon = Poseidon2::new();
        let mut levels = vec![members.iter().map(|m| m.0).collect::<Vec<_>>()];
        while let Some(level) = levels.last().filter(|l| l.len() > 1) {
            let next = level
                .chunks(2)
                .map(|pair| match *pair {
                    [left, right] => poseidon.hash(left, right),
                    // The odd node out is carried up as it is.
                    _ => pair[0],
                })
                .collect();
            levels.push(next);
        }
        Ok(Self { levels })
    }

    /// The tree's root.
    #[must_use]
    pub fn root(&self) -> FieldElement {
        // `new` refuses an empty group, so the top level holds the root.
        FieldElement(
            self.levels
                .last()
                .and_then(|l| l.first())
                .copied()
                .unwrap_or_default(),
        )
    }

    /// The number of levels above the leaves.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.levels.len() - 1
    }

    /// The number of members.
    #[must_use]
    pub fn len(&self) -> usize {
        self.levels[0].len()
    }

    /// Always `false`: a group has at least one member.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Where `commitment` sits among the members, if it is one. Zero, the
    /// mark of a removed member, is never a member.
    #[must_use]
    pub fn index_of(&self, commitment: FieldElement) -> Option<usize> {
        if commitment.0.is_zero() {
            return None;
        }
        self.levels[0].iter().position(|&m| m == commitment.0)
    }

    /// The path from member `index` to the root.
    pub(crate) fn proof(&self, mut index: usize) -> MerkleProof {
        let mut path = 0;
        let mut siblings = Vec::with_capacity(self.depth());
        for level in &self.levels[..self.depth()] {
            let is_right = index & 1 == 1;
            let sibling = if is_right {
                index.checked_sub(1)
            } else {
                index.checked_add(1)
            };
            // A node with no sibling was carried up; it adds no step to the path.
            if let Some(&node) = sibling.and_then(|i| level.get(i)) {
                path |= u64::from(is_right) << siblings.len();
                siblings.push(node);
            }
            index >>= 1;
        }
        MerkleProof {
            index: path,
            siblings,
        }
    }

    /// The root `proof` leads to from `leaf`; equal to [`root`](Self::root)
    /// for a member's own proof.
    #[cfg(test)]
    fn climb(leaf: Fr, proof: &MerkleProof) -> Fr {
        let mut poseidon = Poseidon2::new();
        proof
            .siblings
            .iter()
            .enumerate()
            .fold(leaf, |node, (k, &sibling)| {
                if proof.index >> k & 1 == 1 {
                    poseidon.hash(sibling, node)
                } else {
                    poseidon.hash(node, sibling)
                }
            })
    }
}

impl std::fmt::Debug for Group {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Group")
            .field("members", &self.len())
            .field("depth", &self.depth())
            .field("root", &self.root())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn elements(values: &[&str]) -> Vec<FieldElement> {
        values
            .iter()
            .map(|v| v.parse().expect("a field element"))
            .collect()
    }

    #[test]
    fn matches_the_javascript_root() {
        // `@semaphore-protocol/group` 4.14 over these four members.
        let group = Group::new(&elements(&[
            "111",
            "222",
            "333",
            "15653118452981836033022399046009658219270373379659789120083529738828725496177",
        ]))
        .expect("a valid group");
        assert_eq!(group.depth(), 2);
        assert_eq!(
            group.root().to_string(),
            "3881502877410273639496825438787094142074691482808384733927727840319965635296"
        );
    }

    #[test]
    fn carries_a_lone_node_up_as_the_control_plane_does() {
        // The Control Plane's `LeanRoot` over 1..=5.
        let group = Group::new(&elements(&["1", "2", "3", "4", "5"])).expect("a valid group");
        assert_eq!(group.depth(), 3);
        assert_eq!(
            group.root().to_string(),
            "11512324111804726054755717642058292259866309947044530224809882918003853859592"
        );
        let single = Group::new(&elements(&["1"])).expect("a valid group");
        assert_eq!(
            (single.depth(), single.root().to_string()),
            (0, "1".to_owned())
        );
    }

    #[test]
    fn every_members_proof_leads_to_the_root() {
        let values: Vec<String> = (1..=11).map(|i| i.to_string()).collect();
        let refs: Vec<&str> = values.iter().map(String::as_str).collect();
        let group = Group::new(&elements(&refs)).expect("a valid group");
        for i in 0..group.len() {
            let proof = group.proof(i);
            assert!(proof.siblings.len() <= group.depth());
            assert_eq!(
                Group::climb(group.levels[0][i], &proof),
                group.root().0,
                "member {i}"
            );
        }
    }

    #[test]
    fn keeps_removed_members_in_place() {
        // The Control Plane's `LeanRoot` over 1, 0, 3: a zero is hashed like
        // any other leaf.
        let group = Group::new(&elements(&["1", "0", "3"])).expect("a valid group");
        assert_eq!(
            group.root().to_string(),
            "12939351148439286594095646211748194464721892567872607149920319543512426040882"
        );
        assert_eq!(group.index_of(elements(&["3"])[0]), Some(2));
        assert_eq!(group.index_of(elements(&["0"])[0]), None);
    }

    #[test]
    fn refuses_what_the_circuit_cannot_prove() {
        assert_eq!(Group::new(&[]), Err(GroupError::Empty));
    }
}
