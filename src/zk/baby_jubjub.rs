//! Baby Jubjub, the twisted Edwards curve Semaphore identities live on.
//!
//! `ark-ed-on-bn254` describes the same curve with `a = 1`, a scaled model in
//! which every point has different coordinates. Semaphore, circomlib and the
//! JavaScript library all use `a = 168700, d = 168696`, and an identity's
//! commitment hashes the coordinates, so this crate defines the curve in that
//! model. The constants follow EIP-2494.
//!
//! Adapted from `semaphore-rs` (MIT, © 2025 Ethereum Foundation).

use ark_ec::models::CurveConfig;
use ark_ec::twisted_edwards::{Affine, MontCurveConfig, TECurveConfig};
use ark_ed_on_bn254::{Fq, Fr};
use ark_ff::{Field as _, MontFp};

/// A point in affine coordinates.
pub(crate) type Point = Affine<BabyJubjub>;

/// The curve parameters.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct BabyJubjub;

impl CurveConfig for BabyJubjub {
    type BaseField = Fq;
    type ScalarField = Fr;

    const COFACTOR: &'static [u64] = &[8];
    const COFACTOR_INV: Fr =
        MontFp!("2394026564107420727433200628387514462817212225638746351800188703329891451411");
}

impl TECurveConfig for BabyJubjub {
    const COEFF_A: Fq = MontFp!("168700");
    const COEFF_D: Fq = MontFp!("168696");
    /// The base point of the prime-order subgroup, `Base8` in circomlib.
    const GENERATOR: Point = Point::new_unchecked(
        MontFp!("5299619240641551281634865583518297030282874472190772894086521144482721001553"),
        MontFp!("16950150798460657717958625567821834550301663161624707787222815936182638968203"),
    );

    type MontCurveConfig = Self;
}

impl MontCurveConfig for BabyJubjub {
    const COEFF_A: Fq = MontFp!("168698");
    const COEFF_B: Fq = Fq::ONE;

    type TECurveConfig = Self;
}

#[cfg(test)]
mod tests {
    use ark_ec::{AffineRepr as _, CurveGroup as _};
    use ark_ff::PrimeField as _;

    use super::*;

    #[test]
    fn the_generator_is_on_the_curve_and_in_the_subgroup() {
        let g = BabyJubjub::GENERATOR;
        assert!(g.is_on_curve());
        assert!(g.is_in_correct_subgroup_assuming_on_curve());
        let order = Fr::MODULUS;
        assert!(g.mul_bigint(order).into_affine().is_zero());
    }
}
