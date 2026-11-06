//! Ethereum's signature conventions, shared by everything that checks or
//! makes a wallet-style signature.

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use sha3::{Digest as _, Keccak256};

use crate::id::Address;

/// Why 65 bytes are not a signature some address made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Unrecoverable;

/// The hash `personal_sign` signs: `message` behind EIP-191's prefix, which
/// names its length in decimal so it can never be read as a transaction.
pub(crate) fn personal_message_hash(message: &[u8]) -> [u8; 32] {
    Keccak256::new()
        .chain_update(b"\x19Ethereum Signed Message:\n")
        .chain_update(message.len().to_string())
        .chain_update(message)
        .finalize()
        .into()
}

/// The address whose key made `signature`, `r ‖ s ‖ v`, over `prehash`.
pub(crate) fn recover(prehash: &[u8; 32], signature: &[u8; 65]) -> Result<Address, Unrecoverable> {
    let (rs, v) = signature.split_at(64);
    // Ethereum writes the recovery id as 27 or 28; some signers write 0 or 1.
    let recovery = match v[0] {
        v @ (27 | 28) => v - 27,
        v => v,
    };
    let recovery = RecoveryId::from_byte(recovery).ok_or(Unrecoverable)?;
    let rs = Signature::from_slice(rs).map_err(|_| Unrecoverable)?;
    let key =
        VerifyingKey::recover_from_prehash(prehash, &rs, recovery).map_err(|_| Unrecoverable)?;
    Ok(address_of(&key))
}

#[cfg(any(test, feature = "client"))]
/// Signs `prehash` as Ethereum does: `r ‖ s ‖ v` with `v` in {27, 28}, and a
/// low `s`, the only form contracts using `OpenZeppelin`'s ECDSA accept.
pub(crate) fn sign(key: &k256::ecdsa::SigningKey, prehash: &[u8; 32]) -> [u8; 65] {
    let (signature, recovery): (Signature, RecoveryId) = key.sign_prehash_recoverable(prehash);
    let mut out = [0; 65];
    out[..64].copy_from_slice(&signature.to_bytes());
    out[64] = 27 + recovery.to_byte();
    out
}

#[cfg(feature = "client")]
/// A fresh random signing key from the operating system's generator.
pub(crate) fn random_key() -> k256::ecdsa::SigningKey {
    use rand_core::{OsRng, RngCore as _};
    loop {
        let mut secret = zeroize::Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(secret.as_mut());
        // Out of range once in about 2^128 draws.
        if let Ok(key) = k256::ecdsa::SigningKey::from_slice(secret.as_ref()) {
            return key;
        }
    }
}

/// An address: the last 20 bytes of the hash of the uncompressed public key,
/// without its leading 0x04.
pub(crate) fn address_of(key: &VerifyingKey) -> Address {
    let point = key.to_sec1_point(false);
    let hash = Keccak256::digest(&point.as_bytes()[1..]);
    let mut address = [0; 20];
    address.copy_from_slice(&hash[12..]);
    Address(address)
}

#[cfg(test)]
mod tests {
    use k256::ecdsa::SigningKey;

    use super::*;

    /// A widely published test key: its address is well known.
    fn key() -> SigningKey {
        let secret =
            hex::decode("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
                .expect("hex");
        SigningKey::from_slice(&secret).expect("a valid key")
    }

    #[test]
    fn derives_the_known_address() {
        let want: Address = "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23"
            .parse()
            .expect("an address");
        assert_eq!(address_of(key().verifying_key()), want);
    }

    #[test]
    fn a_signature_recovers_its_signer() {
        let hash = personal_message_hash(b"hello");
        let signature = sign(&key(), &hash);
        assert!(matches!(signature[64], 27 | 28));
        assert_eq!(
            recover(&hash, &signature),
            Ok(address_of(key().verifying_key()))
        );
    }

    #[test]
    fn prefixes_like_personal_sign() {
        // keccak256("\x19Ethereum Signed Message:\n5hello"), as any wallet computes it.
        assert_eq!(
            hex::encode(personal_message_hash(b"hello")),
            "50b2c43fd39106bafbba0da34fc430e1f91e3c96ea2acee2bc34119f92b37750"
        );
    }
}
