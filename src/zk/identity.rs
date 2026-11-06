//! A subscriber's anonymous identity.

use std::fmt;

use ark_ec::{AffineRepr as _, CurveGroup as _};
use ark_ed_on_bn254::Fr as Scalar;
use ark_ff::{BigInteger as _, PrimeField as _};
use sha3::{Digest as _, Keccak256};
use zeroize::{Zeroize as _, Zeroizing};

use super::baby_jubjub::BabyJubjub;
use super::blake512::blake512;
use super::field::{FieldElement, Poseidon2};
use ark_ec::twisted_edwards::TECurveConfig as _;

/// A Semaphore identity, derived from a wallet signature so the same wallet
/// recovers the same identity on any device.
///
/// Its [`commitment`](Self::commitment) is what the subscription registry
/// stores; the secret behind it never leaves the client, and every proof
/// shows only that *some* member of the group made it.
///
/// # Derivation
///
/// ```text
/// signature = personal_sign(Identity::SIGNING_MESSAGE)        as the wallet returns it, 0x… hex
/// secret    = "0x" ‖ hex(keccak256(utf8(signature)))          66 characters, lowercase
/// identity  = Semaphore v4 Identity(utf8(secret))
/// ```
///
/// An Orbit with several slots joins the set with one identity per slot.
/// Slot 0 is the identity above; slot `i` is [`for_slot`](Self::for_slot):
///
/// ```text
/// secret_i  = "0x" ‖ hex(keccak256(utf8(secret_0) ‖ utf8("/slot/" ‖ i)))
/// ```
///
/// so one signature recovers every slot's identity, on any device, and a
/// renewed Orbit registers the same ones again.
///
/// Both steps hash *text*: the signature's hex string, then the secret's.
/// That is what the JavaScript client does, and doing anything else — such as
/// decoding the hex first — yields a different, equally valid identity that
/// is not in anyone's group.
///
/// # Examples
///
/// ```
/// # use singula::zk::Identity;
/// # let signature = format!("0x{}", "ab".repeat(65));
/// let identity = Identity::from_signature(&signature);
/// assert_eq!(
///     identity.commitment().to_string(),
///     "15653118452981836033022399046009658219270373379659789120083529738828725496177",
/// );
/// ```
pub struct Identity {
    secret: Zeroizing<String>,
    scalar: Scalar,
    commitment: FieldElement,
}

/// Why a string is not an identity secret.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IdentityError {
    /// Not `0x` followed by 64 lowercase hex digits.
    #[error("an identity secret is 0x followed by 64 lowercase hex digits")]
    Shape,
}

impl Identity {
    /// The message the wallet signs to derive the identity.
    pub const SIGNING_MESSAGE: &'static str = "Singula Anonymous Identity v1";

    /// Derives the identity from the wallet's signature of
    /// [`SIGNING_MESSAGE`](Self::SIGNING_MESSAGE), passed exactly as the
    /// wallet returned it.
    #[must_use]
    pub fn from_signature(signature: &str) -> Self {
        let digest = Keccak256::digest(signature.as_bytes());
        let mut secret = Zeroizing::new(String::with_capacity(66));
        secret.push_str("0x");
        secret.push_str(&Zeroizing::new(crate::hex::lower(&digest)));
        Self::derive(secret)
    }

    /// The identity of `slot` of the same subscriber; slot 0 is `self`.
    ///
    /// Call it on the slot-0 identity, the one derived from the wallet's
    /// signature: called on another slot's identity, it derives from that one
    /// and yields identities nobody registered.
    #[must_use]
    pub fn for_slot(&self, slot: u8) -> Self {
        if slot == 0 {
            return Self::derive(self.secret.clone());
        }
        let mut hasher = Keccak256::new();
        hasher.update(self.secret.as_bytes());
        hasher.update(format!("/slot/{slot}").as_bytes());
        let digest = hasher.finalize();
        let mut secret = Zeroizing::new(String::with_capacity(66));
        secret.push_str("0x");
        secret.push_str(&Zeroizing::new(crate::hex::lower(&digest)));
        Self::derive(secret)
    }

    /// Restores an identity from the secret [`secret`](Self::secret) returned.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Shape`] unless `secret` is `0x` and 64
    /// lowercase hex digits. Any other text would also derive *an* identity,
    /// so a mistake here — passing the signature itself, say — is refused
    /// rather than silently producing one nobody registered.
    pub fn from_secret(secret: &str) -> Result<Self, IdentityError> {
        let digits = secret.strip_prefix("0x").ok_or(IdentityError::Shape)?;
        if digits.len() != 64
            || !digits
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(IdentityError::Shape);
        }
        Ok(Self::derive(Zeroizing::new(secret.to_owned())))
    }

    /// Semaphore v4's derivation from a private key, here the secret's text:
    /// the scalar is BLAKE-512 of it, pruned as in `EdDSA` and divided by the
    /// cofactor; the commitment is Poseidon of the public key's coordinates.
    fn derive(secret: Zeroizing<String>) -> Self {
        let mut hash = [0u8; 64];
        hash.copy_from_slice(&blake512(secret.as_bytes()));
        hash[0] &= 0xf8;
        hash[31] &= 0x7f;
        hash[31] |= 0x40;
        let mut half = Zeroizing::new([0u8; 32]);
        half.copy_from_slice(&hash[..32]);
        hash.zeroize();
        let scalar = Scalar::from_le_bytes_mod_order(&shift_right_3(&half)[..]);

        let public = BabyJubjub::GENERATOR
            .mul_bigint(scalar.into_bigint())
            .into_affine();
        let (x, y) = public.xy().unwrap_or_default();
        let commitment = FieldElement(Poseidon2::new().hash(x, y));
        Self {
            secret,
            scalar,
            commitment,
        }
    }

    /// The identity's public commitment, as the subscription registry holds it.
    #[must_use]
    pub fn commitment(&self) -> FieldElement {
        self.commitment
    }

    /// The secret, for storing the identity so the wallet need not sign again.
    ///
    /// # Security
    ///
    /// Whoever holds it can make proofs as this subscriber. Store it only
    /// where the platform keeps secrets (a keychain or keystore), never in
    /// logs or plain files.
    #[must_use]
    pub fn secret(&self) -> &str {
        &self.secret
    }

    /// The scalar the circuit takes as its `secret` input.
    pub(crate) fn circuit_secret(&self) -> ark_bn254::Fr {
        ark_bn254::Fr::from_le_bytes_mod_order(&self.scalar.into_bigint().to_bytes_le())
    }
}

impl Drop for Identity {
    fn drop(&mut self) {
        self.scalar.zeroize();
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("commitment", &self.commitment)
            .finish_non_exhaustive()
    }
}

/// `bytes`, a little-endian integer, divided by eight.
fn shift_right_3(bytes: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    for i in 0..32 {
        let high = bytes.get(i + 1).map_or(0, |b| b << 5);
        out[i] = (bytes[i] >> 3) | high;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // From the JavaScript client (`@semaphore-protocol/identity` 4.14).
    const SECRET: &str = "0x08207bd92786697f8bed5caf78eda4d3b78fbc3326eb624744b966e7f94f5f59";
    const COMMITMENT: &str =
        "15653118452981836033022399046009658219270373379659789120083529738828725496177";

    #[test]
    fn derives_the_secret_as_the_javascript_client_does() {
        let identity = Identity::from_signature(&format!("0x{}", "ab".repeat(65)));
        assert_eq!(identity.secret(), SECRET);
    }

    #[test]
    fn matches_the_javascript_commitment() {
        let identity = Identity::from_secret(SECRET).expect("a valid secret");
        assert_eq!(identity.commitment().to_string(), COMMITMENT);
    }

    // Secrets from keccak256 in ethers, commitments from the JavaScript
    // client's Identity — both independent of this code.
    #[test]
    fn derives_slot_identities_as_specified() {
        let identity = Identity::from_secret(SECRET).expect("a valid secret");
        assert_eq!(identity.for_slot(0).commitment().to_string(), COMMITMENT);
        let one = identity.for_slot(1);
        assert_eq!(
            one.secret(),
            "0x976c305e927afc2e393a1dff1f3da3e0dc7235423acee385bbd278cf5dc907af"
        );
        assert_eq!(
            one.commitment().to_string(),
            "19751422218706389444983812489773668679027122603554410496338113707804051421573"
        );
        assert_eq!(
            identity.for_slot(4).commitment().to_string(),
            "21714642876634693321221689292305027903869427084713727062256826469565102761830"
        );
    }

    #[test]
    fn refuses_text_that_is_not_a_secret() {
        let signature = format!("0x{}", "ab".repeat(65));
        assert_eq!(
            Identity::from_secret(&signature).err(),
            Some(IdentityError::Shape)
        );
        assert_eq!(
            Identity::from_secret(&SECRET.to_uppercase()).err(),
            Some(IdentityError::Shape)
        );
        assert_eq!(
            Identity::from_secret(&SECRET[2..]).err(),
            Some(IdentityError::Shape)
        );
    }

    #[test]
    fn keeps_the_secret_out_of_debug() {
        let identity = Identity::from_secret(SECRET).expect("a valid secret");
        assert!(!format!("{identity:?}").contains(&SECRET[2..10]));
    }

    #[test]
    fn divides_by_eight() {
        let mut n = [0u8; 32];
        n[0] = 0b1000_0000;
        n[1] = 0b0000_0011;
        let q = shift_right_3(&n);
        assert_eq!((q[0], q[1]), (0b0111_0000, 0));
    }
}
