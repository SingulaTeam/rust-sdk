//! Anonymous access with Semaphore.
//!
//! A subscriber is admitted without saying which subscriber they are. Each
//! holds an [`Identity`] whose commitment sits in the subscription registry;
//! to open a session they prove, in zero knowledge, that their commitment is
//! in the registry's [`Group`] — and nothing more. The proof carries a
//! nullifier fixed by the [`Claim`], so the same subscriber cannot spend the
//! same slot twice, yet two proofs by one subscriber cannot be linked.
//!
//! ```text
//! wallet signature ──► Identity ──► commitment ─┐
//!                                               ├─► Prover::prove(Claim) ──► AccessProof
//! registry commitments ──► Group ──► root ──────┘
//! ```
//!
//! The circuit is Semaphore v4 for trees up to 2^16 members. Its proving key
//! and witness graph ship inside the crate, so proving needs no files and no
//! network.

mod baby_jubjub;
mod blake512;
mod claim;
mod field;
mod group;
mod identity;
mod prover;
mod witness;

pub use claim::Claim;
pub use field::{FieldElement, FieldElementError};
pub use group::{Group, GroupError, MAX_DEPTH};
pub use identity::{Identity, IdentityError};
pub use prover::{AccessProof, LoadError, ProveError, Prover};
pub use witness::GraphError;
