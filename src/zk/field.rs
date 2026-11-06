//! Elements of the field the circuit works in.

use std::fmt;
use std::str::FromStr;

use ark_bn254::Fr;
use ark_ff::{BigInt, BigInteger as _, PrimeField as _};
use light_poseidon::{Poseidon, PoseidonHasher as _};
use sha3::{Digest as _, Keccak256};

/// An element of the BN254 scalar field: an identity commitment, a group
/// root, a nullifier.
///
/// Shown and parsed in decimal, as Semaphore's JavaScript library and the
/// contracts write them; sent on the wire as 32 bytes big-endian.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FieldElement(pub(crate) Fr);

/// Why a value is not a [`FieldElement`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FieldElementError {
    /// The text is not a decimal number.
    #[error("a field element is written as a decimal number")]
    NotDecimal,
    /// The value is not below the field's modulus.
    #[error("the value is not below the BN254 scalar field modulus")]
    OutOfRange,
}

impl FieldElement {
    /// The element as 32 bytes, big-endian.
    #[must_use]
    pub fn to_be_bytes(&self) -> [u8; 32] {
        let mut out = [0; 32];
        out.copy_from_slice(&self.0.into_bigint().to_bytes_be());
        out
    }

    /// Reads 32 big-endian bytes.
    ///
    /// # Errors
    ///
    /// Returns [`FieldElementError::OutOfRange`] if the value is not below
    /// the modulus: reducing it instead would quietly turn one value into
    /// another.
    pub fn from_be_bytes(bytes: &[u8; 32]) -> Result<Self, FieldElementError> {
        let mut limbs = [0u64; 4];
        for (limb, chunk) in limbs.iter_mut().rev().zip(bytes.chunks_exact(8)) {
            let mut word = [0; 8];
            word.copy_from_slice(chunk);
            *limb = u64::from_be_bytes(word);
        }
        Fr::from_bigint(BigInt(limbs))
            .map(Self)
            .ok_or(FieldElementError::OutOfRange)
    }

    /// Semaphore's hash of a public input: keccak-256 of the value as 32
    /// bytes big-endian, shifted right by eight bits so it fits the field.
    pub(crate) fn semaphore_hash(value_be: &[u8; 32]) -> Self {
        let digest = Keccak256::digest(value_be);
        let mut shifted = [0; 32];
        shifted[1..].copy_from_slice(&digest[..31]);
        Self(Fr::from_be_bytes_mod_order(&shifted))
    }
}

impl FromStr for FieldElement {
    type Err = FieldElementError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(FieldElementError::NotDecimal);
        }
        // Little-endian 64-bit limbs; a carry out of the top limb means the
        // value is past 2^256, far outside the field.
        let mut limbs = [0u64; 4];
        for b in s.bytes() {
            let digit = match b {
                b'0'..=b'9' => u64::from(b - b'0'),
                _ => return Err(FieldElementError::NotDecimal),
            };
            let mut carry = digit;
            for limb in &mut limbs {
                let wide = u128::from(*limb) * 10 + u128::from(carry);
                // Splitting a 128-bit product into its low and high words.
                #[allow(clippy::cast_possible_truncation)]
                {
                    *limb = wide as u64;
                    carry = (wide >> 64) as u64;
                }
            }
            if carry != 0 {
                return Err(FieldElementError::OutOfRange);
            }
        }
        Fr::from_bigint(BigInt(limbs))
            .map(Self)
            .ok_or(FieldElementError::OutOfRange)
    }
}

impl fmt::Display for FieldElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0.into_bigint(), f)
    }
}

impl fmt::Debug for FieldElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FieldElement({self})")
    }
}

/// Poseidon over two inputs with circomlib's parameters: the hash of an
/// identity's public key, and of every pair of nodes in a group's tree.
pub(crate) struct Poseidon2(Poseidon<Fr>);

impl Poseidon2 {
    pub(crate) fn new() -> Self {
        // light-poseidon fails only for a width it has no parameters for, and
        // it ships circomlib's for every width up to 12.
        Self(
            Poseidon::<Fr>::new_circom(2)
                .unwrap_or_else(|_| unreachable!("circom parameters for width 2")),
        )
    }

    pub(crate) fn hash(&mut self, left: Fr, right: Fr) -> Fr {
        // It fails only for the wrong number of inputs, and there are two.
        self.0
            .hash(&[left, right])
            .unwrap_or_else(|_| unreachable!("two inputs for a width-2 hasher"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The scalar field modulus.
    const MODULUS: &str =
        "21888242871839275222246405745257275088548364400416034343698204186575808495617";

    #[test]
    fn reads_and_writes_decimal() {
        for s in [
            "0",
            "1",
            "111",
            "21888242871839275222246405745257275088548364400416034343698204186575808495616",
        ] {
            let e: FieldElement = s.parse().expect("in range");
            assert_eq!(e.to_string(), s);
        }
    }

    #[test]
    fn refuses_values_outside_the_field() {
        assert_eq!(
            MODULUS.parse::<FieldElement>(),
            Err(FieldElementError::OutOfRange)
        );
        assert_eq!(
            format!("{MODULUS}0").parse::<FieldElement>(),
            Err(FieldElementError::OutOfRange)
        );
        assert_eq!(
            "".parse::<FieldElement>(),
            Err(FieldElementError::NotDecimal)
        );
        assert_eq!(
            "-1".parse::<FieldElement>(),
            Err(FieldElementError::NotDecimal)
        );
        assert_eq!(
            "0x10".parse::<FieldElement>(),
            Err(FieldElementError::NotDecimal)
        );
    }

    #[test]
    fn bytes_round_trip_and_stay_canonical() {
        let e: FieldElement = "123456789".parse().expect("in range");
        assert_eq!(FieldElement::from_be_bytes(&e.to_be_bytes()), Ok(e));
        assert_eq!(
            FieldElement::from_be_bytes(&[0xff; 32]),
            Err(FieldElementError::OutOfRange)
        );
    }
}
