//! Making Semaphore proofs.

use std::io::Cursor;

use ark_bn254::{Bn254, Fr};
use ark_ec::AffineRepr as _;
use ark_ff::{BigInteger as _, PrimeField as _, UniformRand as _};
use ark_groth16::{Groth16, PreparedVerifyingKey, ProvingKey, prepare_verifying_key};
use ark_relations::r1cs::ConstraintMatrices;
use circom_prover::prover::ark_circom::{CircomReduction, read_zkey};
use rand_core::OsRng;

use super::claim::Claim;
use super::field::FieldElement;
use super::group::{Group, MAX_DEPTH};
use super::identity::Identity;
use super::witness::{Graph, GraphError};

/// Semaphore's proving key for trees up to 2^16 members: the artifact PSE
/// publishes for Semaphore 4.13.0 from its trusted setup, byte for byte. The
/// Control Plane's verifying key is this key's.
const ZKEY: &[u8] = include_bytes!("../../zk/semaphore-16.zkey");
/// The same circuit compiled to a witness graph, as `semaphore-rs` ships it.
pub(crate) const GRAPH: &[u8] = include_bytes!("../../zk/semaphore-16.graph");

/// Makes proofs of membership.
///
/// Loading the circuit takes a moment, so make one `Prover` and share it; it
/// is `Send + Sync`, and proving borrows it immutably.
///
/// # Examples
///
/// ```no_run
/// # use singula::{Epoch, StarId};
/// # use singula::zk::{Claim, Group, Identity, Prover};
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let signature = String::new();
/// # let members = Vec::new();
/// let prover = Prover::new()?;
/// let identity = Identity::from_signature(&signature);
/// let group = Group::new(&members)?;
/// let proof = prover.prove(
///     &identity,
///     &group,
///     Claim::Session { control_plane: StarId(7), epoch: Epoch(137), index: 0 },
/// )?;
/// # let _ = proof;
/// # Ok(())
/// # }
/// ```
pub struct Prover {
    graph: Graph,
    proving_key: ProvingKey<Bn254>,
    verifying_key: PreparedVerifyingKey<Bn254>,
    matrices: ConstraintMatrices<Fr>,
}

/// Why the circuit could not be loaded.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LoadError {
    /// The proving key could not be read.
    #[error("the proving key could not be read")]
    ProvingKey(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The witness graph could not be read.
    #[error("the witness graph could not be read")]
    Graph(#[source] GraphError),
}

/// Why a proof could not be made.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProveError {
    /// The identity's commitment is not in the group.
    #[error("the identity is not a member of the group")]
    NotAMember,
    /// The witness could not be computed.
    #[error("the witness could not be computed")]
    Witness(#[source] GraphError),
    /// The proving system failed.
    #[error("the proof could not be made: {0}")]
    Proving(String),
    /// The proof did not verify under the circuit's own key, so the Control
    /// Plane would refuse it too.
    #[error("the proof does not verify; it was not returned")]
    SelfCheck,
}

/// A proof of membership, ready for the Control Plane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessProof {
    /// What the proof was made for. It is good for this claim only.
    pub claim: Claim,
    /// The root of the group the proof was made against.
    pub merkle_root: FieldElement,
    /// Spent once per claim: the same identity and claim always give the
    /// same nullifier, and nothing else links it to the identity.
    pub nullifier: FieldElement,
    /// The Groth16 proof as eight 32-byte big-endian coordinates, in the
    /// order Ethereum's pairing precompile takes them: `A.x, A.y`, then `B`
    /// with each Fq2 pair high coefficient first, then `C.x, C.y`.
    pub points: [[u8; 32]; 8],
}

impl Prover {
    /// Loads the bundled circuit.
    ///
    /// # Errors
    ///
    /// Returns [`LoadError`] if the bundled files cannot be read, which
    /// means the crate itself is damaged.
    pub fn new() -> Result<Self, LoadError> {
        let graph = Graph::parse(GRAPH).map_err(LoadError::Graph)?;
        let (proving_key, matrices) = read_zkey::<_, Bn254>(&mut Cursor::new(ZKEY))
            .map_err(|e| LoadError::ProvingKey(e.into()))?;
        let verifying_key = prepare_verifying_key(&proving_key.vk);
        Ok(Self {
            graph,
            proving_key,
            verifying_key,
            matrices,
        })
    }

    /// Proves that `identity` is a member of `group`, for `claim`.
    ///
    /// This takes tens of milliseconds of CPU time; in async code, run it on
    /// a blocking thread.
    ///
    /// # Errors
    ///
    /// Returns [`ProveError::NotAMember`] if the identity is not in the group.
    /// The other errors mean the bundled circuit misbehaved; the proof is
    /// checked before it is returned, so a bad one is never sent.
    pub fn prove(
        &self,
        identity: &Identity,
        group: &Group,
        claim: Claim,
    ) -> Result<AccessProof, ProveError> {
        let member = group
            .index_of(identity.commitment())
            .ok_or(ProveError::NotAMember)?;
        let path = group.proof(member);
        let mut siblings = path.siblings.clone();
        siblings.resize(MAX_DEPTH, Fr::from(0u8));

        let witness = self
            .graph
            .witness(&[
                ("secret", &[identity.circuit_secret()]),
                ("merkleProofLength", &[Fr::from(path.siblings.len() as u64)]),
                ("merkleProofIndex", &[Fr::from(path.index)]),
                ("merkleProofSiblings", &siblings),
                ("message", &[claim.message().0]),
                ("scope", &[claim.scope().0]),
            ])
            .map_err(ProveError::Witness)?;

        // Groth16's blinding factors: fresh for every proof, so no two link.
        let blind_r = Fr::rand(&mut OsRng);
        let blind_s = Fr::rand(&mut OsRng);
        let proof = Groth16::<Bn254, CircomReduction>::create_proof_with_reduction_and_matrices(
            &self.proving_key,
            blind_r,
            blind_s,
            &self.matrices,
            self.matrices.num_instance_variables,
            self.matrices.num_constraints,
            &witness,
        )
        .map_err(|e| ProveError::Proving(e.to_string()))?;

        // The circuit's public signals: root, nullifier, hash(message), hash(scope).
        let public = &witness[1..self.matrices.num_instance_variables];
        let verified =
            Groth16::<Bn254>::verify_proof(&self.verifying_key, &proof, public).unwrap_or(false);
        if !verified || public.first() != Some(&group.root().0) {
            return Err(ProveError::SelfCheck);
        }

        let (a, b, c) = (proof.a, proof.b, proof.c);
        let (ax, ay) = a.xy().unwrap_or_default();
        let (bx, by) = b.xy().unwrap_or_default();
        let (cx, cy) = c.xy().unwrap_or_default();
        let points = [ax, ay, bx.c1, bx.c0, by.c1, by.c0, cx, cy].map(|p| {
            let mut out = [0; 32];
            out.copy_from_slice(&p.into_bigint().to_bytes_be());
            out
        });
        Ok(AccessProof {
            claim,
            merkle_root: FieldElement(public[0]),
            nullifier: FieldElement(public[1]),
            points,
        })
    }
}

impl std::fmt::Debug for Prover {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Prover")
            .field("constraints", &self.matrices.num_constraints)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest as _, Sha256};

    use super::*;

    /// The bundled files are the published ones (see NOTICE), so anyone can
    /// check them against their sources.
    #[test]
    fn bundles_the_published_artifacts() {
        let sha = |bytes: &[u8]| hex::encode(Sha256::digest(bytes));
        assert_eq!(
            sha(ZKEY),
            "948763c7315a337b7722c0344a28af4be66fbbc618474d6dbe9036e799d1a3b5"
        );
        assert_eq!(
            sha(GRAPH),
            "55702b8b08e6bf03a11244ba0f922a27d34a48e4419020b9215316dfe2d41f35"
        );
    }

    #[test]
    fn loads_the_bundled_circuit() {
        assert!(Prover::new().is_ok());
    }
}
