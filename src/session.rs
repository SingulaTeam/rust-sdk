//! Receiving a session's credentials from its node.
//!
//! When a session opens, the client sends the public half of a fresh
//! [`SessionKeypair`]. The node answers with credentials for its tunnel,
//! encrypted to that key, so the Control Plane relaying them cannot read
//! them. The node also signs the exchange with the signer key it registered
//! in `StarRegistry`, so the client can check, against the chain, that the
//! answer came from the Star it asked for and not from whoever relayed it.
//!
//! # Construction
//!
//! ```text
//! digest  = keccak256("singula-node-session-v1"
//!                     ‖ session id                  (36 ASCII bytes)
//!                     ‖ client session public key   (32 bytes)
//!                     ‖ node session public key     (32 bytes))
//! origin  = ecrecover(EIP-191(digest), signature) == StarRegistry.getSigner(node)
//!
//! shared  = X25519(client session secret, node session public key)
//! key     = HKDF-SHA256(salt = none, ikm = shared, info = "singula-session-v1", 32 bytes)
//! plain   = AES-256-GCM-Open(key, nonce (12 bytes), ciphertext, no associated data)
//! ```
//!
//! Naming the client's key in the digest ties the signature to one request,
//! so a node's answer to someone else cannot be replayed into this session.

use std::fmt;

use aes_gcm::aead::{Aead as _, KeyInit as _};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::Sha256;
use sha3::{Digest as _, Keccak256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::id::{Address, SessionId};

/// Tags the node's signature so it cannot be mistaken for any other the
/// signer key makes.
const ORIGIN_DOMAIN: &[u8] = b"singula-node-session-v1";
/// The HKDF `info` that binds a derived key to this use; the node uses the same.
const KDF_INFO: &[u8] = b"singula-session-v1";
/// Length of an X25519 public key.
const PUBLIC_KEY_LEN: usize = 32;
/// Length of a recoverable secp256k1 signature, `r ‖ s ‖ v`.
const SIGNATURE_LEN: usize = 65;
/// Length of an AES-GCM nonce.
const NONCE_LEN: usize = 12;

/// The client's half of one session's key exchange.
///
/// Make a new one for every session and drop it once the credentials are
/// open: the secret is never written anywhere, and it is wiped from memory
/// when the keypair is dropped.
pub struct SessionKeypair {
    secret: StaticSecret,
    public: PublicKey,
}

impl SessionKeypair {
    /// A fresh keypair from the operating system's random number generator.
    #[must_use]
    pub fn generate() -> Self {
        Self::from_secret(StaticSecret::random_from_rng(OsRng))
    }

    fn from_secret(secret: StaticSecret) -> Self {
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// The public key to send with the session request.
    #[must_use]
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.public.to_bytes()
    }

    /// Checks that `sealed` came from the node whose registered signer is
    /// `node_signer`, and decrypts it.
    ///
    /// # Security
    ///
    /// `node_signer` must come from the chain — `StarRegistry.getSigner` for
    /// the Star the client asked for — and never from the Control Plane
    /// relaying the answer.
    ///
    /// # Errors
    ///
    /// Returns [`OpenError`] if a field has the wrong length, if the signature
    /// is malformed or not by `node_signer`, or if the ciphertext does not
    /// decrypt under the derived key. None of these can be retried: ask for a
    /// new session.
    pub fn open(
        &self,
        sealed: &SealedCredentials<'_>,
        node_signer: &Address,
    ) -> Result<Credentials, OpenError> {
        let ephemeral =
            fixed::<PUBLIC_KEY_LEN>(sealed.session_public_key, Field::SessionPublicKey)?;
        let signature = fixed::<SIGNATURE_LEN>(sealed.signer_signature, Field::SignerSignature)?;
        let digest = origin_digest(sealed.session, &self.public.to_bytes(), &ephemeral);
        if recover_signer(&digest, &signature)? != *node_signer {
            return Err(OpenError::WrongNode);
        }

        let nonce = fixed::<NONCE_LEN>(sealed.nonce, Field::Nonce)?;
        let key = self.derive_key(&PublicKey::from(ephemeral))?;
        let plain = Aes256Gcm::new(key.as_ref().into())
            .decrypt(&Nonce::from(nonce), sealed.ciphertext)
            .map_err(|_| OpenError::Decryption)?;
        Ok(Credentials(Zeroizing::new(plain)))
    }

    /// The AES key shared with the holder of `node_session_key`.
    fn derive_key(&self, node_session_key: &PublicKey) -> Result<Zeroizing<[u8; 32]>, OpenError> {
        let shared = self.secret.diffie_hellman(node_session_key);
        // A low-order point yields an all-zero secret that anyone can compute,
        // so the "encrypted" credentials would be readable by every relay.
        if !shared.was_contributory() {
            return Err(OpenError::WeakSessionKey);
        }
        let mut key = Zeroizing::new([0; 32]);
        Hkdf::<Sha256>::new(None, shared.as_bytes())
            .expand(KDF_INFO, key.as_mut())
            .map_err(|_| OpenError::Decryption)?;
        Ok(key)
    }
}

impl fmt::Debug for SessionKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionKeypair")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

/// The digest the node's signer key signs; see the module docs.
pub(crate) fn origin_digest(
    session: &SessionId,
    client_key: &[u8; 32],
    node_key: &[u8; 32],
) -> [u8; 32] {
    Keccak256::new()
        .chain_update(ORIGIN_DOMAIN)
        .chain_update(session.as_str())
        .chain_update(client_key)
        .chain_update(node_key)
        .finalize()
        .into()
}

/// The address whose key signed `digest` with the EIP-191 `personal_sign`
/// prefix, as the node does.
fn recover_signer(
    digest: &[u8; 32],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<Address, OpenError> {
    crate::eth::recover(&crate::eth::personal_message_hash(digest), signature)
        .map_err(|_| OpenError::BadSignature)
}

/// A node's sealed answer to a session request, as its fields arrive.
///
/// The byte fields are borrowed straight from the response and checked only
/// when [`SessionKeypair::open`] is called.
#[derive(Debug, Clone, Copy)]
pub struct SealedCredentials<'a> {
    /// The session the node opened.
    pub session: &'a SessionId,
    /// The node's ephemeral X25519 key for this session.
    pub session_public_key: &'a [u8],
    /// The node's signer-key signature over the exchange.
    pub signer_signature: &'a [u8],
    /// The AES-GCM nonce.
    pub nonce: &'a [u8],
    /// The encrypted credentials, with the 16-byte tag at the end.
    pub ciphertext: &'a [u8],
}

/// Decrypted session credentials.
///
/// These are the node's tunnel settings, encoded as the protocol's
/// `VlessCredentials` message. Whoever holds them can use the session, so
/// they are wiped from memory on drop and kept out of `Debug`.
pub struct Credentials(Zeroizing<Vec<u8>>);

impl Credentials {
    /// The encoded credentials.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Credentials {
    /// Credentials from plain bytes, for the client module's tests.
    #[cfg(all(test, feature = "client"))]
    pub(crate) fn for_tests(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Credentials({} bytes, redacted)", self.0.len())
    }
}

/// A field of [`SealedCredentials`], named in errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Field {
    /// [`SealedCredentials::session_public_key`].
    SessionPublicKey,
    /// [`SealedCredentials::signer_signature`].
    SignerSignature,
    /// [`SealedCredentials::nonce`].
    Nonce,
}

impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::SessionPublicKey => "session public key",
            Self::SignerSignature => "signer signature",
            Self::Nonce => "nonce",
        })
    }
}

/// Why sealed credentials could not be opened.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OpenError {
    /// A field is not the length the protocol fixes for it.
    #[error("the {field} is {got} bytes long, not {expected}")]
    Length {
        /// The field.
        field: Field,
        /// The length the protocol fixes.
        expected: usize,
        /// The length received.
        got: usize,
    },
    /// The signature is not a well-formed recoverable secp256k1 signature.
    #[error("the node's signature is malformed")]
    BadSignature,
    /// The signature is valid but not by the expected node's signer.
    #[error("the credentials are not signed by the node that was asked for")]
    WrongNode,
    /// The node's session key is a low-order point.
    #[error("the node's session key is not a usable X25519 key")]
    WeakSessionKey,
    /// The ciphertext was not sealed to this keypair, or was altered.
    #[error("the credentials do not decrypt with this session's key")]
    Decryption,
}

/// `bytes` as an array, or the error naming `field`.
fn fixed<const N: usize>(bytes: &[u8], field: Field) -> Result<[u8; N], OpenError> {
    bytes.try_into().map_err(|_| OpenError::Length {
        field,
        expected: N,
        got: bytes.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Generated by the node's Go implementation. The signer is a well-known
    // test key, not one used anywhere.
    const SESSION: &str = "8f14e45f-ceea-467f-a8d5-1a2b3c4d5e6f";
    const CLIENT_SECRET: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    const CLIENT_PUBLIC: &str = "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c";
    const NODE_SESSION_KEY: &str =
        "493e82fc74464a59268817623d2053c5eb8e2cc4a988b4fee179ec6b010d531d";
    const DERIVED_KEY: &str = "463e06572fca917a0864d9128dcdabb808aac8fafb0f8ca41f18576a37b9f97d";
    const ORIGIN_DIGEST: &str = "c0e25ce89115557f89b50946c93dcf251cb9aaa991d5ed0add9924ad28b12928";
    const SIGNER: &str = "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23";
    const SIGNATURE: &str = "8166f95390e92fe13c38cba6fc80891ef36536d32803d271d3885a5b7ef31a1e2cf3919931038f860dfc67d73474974ebd07bdc465fea5077a5b31544a80a6b51b";
    const NONCE: &str = "000102030405060708090a0b";
    const CIPHERTEXT: &str = "f2236b756fa3b82235bf50189264881439131f8884638a6d353e18e0893278a159c02e1a24a5253a7c5cc4d73d80bfe4d31e907f2f1f5c6757455885";
    const PLAINTEXT: &[u8] = b"sealed for the client, not the control plane";

    fn bytes(s: &str) -> Vec<u8> {
        hex::decode(s).expect("valid hex")
    }

    struct Fixture {
        session: SessionId,
        node_key: Vec<u8>,
        signature: Vec<u8>,
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                session: SESSION.parse().expect("a canonical session id"),
                node_key: bytes(NODE_SESSION_KEY),
                signature: bytes(SIGNATURE),
                nonce: bytes(NONCE),
                ciphertext: bytes(CIPHERTEXT),
            }
        }

        fn sealed(&self) -> SealedCredentials<'_> {
            SealedCredentials {
                session: &self.session,
                session_public_key: &self.node_key,
                signer_signature: &self.signature,
                nonce: &self.nonce,
                ciphertext: &self.ciphertext,
            }
        }
    }

    fn client() -> SessionKeypair {
        let secret: [u8; 32] = bytes(CLIENT_SECRET).try_into().expect("32 bytes");
        SessionKeypair::from_secret(StaticSecret::from(secret))
    }

    fn signer() -> Address {
        SIGNER.parse().expect("a valid address")
    }

    #[test]
    fn computes_the_same_digest_as_the_node() {
        let f = Fixture::new();
        let client_key = client().public_key();
        assert_eq!(hex::encode(client_key), CLIENT_PUBLIC);
        let node_key: [u8; 32] = f.node_key.as_slice().try_into().expect("32 bytes");
        assert_eq!(
            hex::encode(origin_digest(&f.session, &client_key, &node_key)),
            ORIGIN_DIGEST
        );
    }

    #[test]
    fn recovers_the_nodes_signer() {
        let digest: [u8; 32] = bytes(ORIGIN_DIGEST).try_into().expect("32 bytes");
        let signature: [u8; 65] = bytes(SIGNATURE).try_into().expect("65 bytes");
        assert_eq!(recover_signer(&digest, &signature), Ok(signer()));
    }

    #[test]
    fn derives_the_same_key_as_the_node() {
        let node: [u8; 32] = bytes(NODE_SESSION_KEY).try_into().expect("32 bytes");
        let key = client()
            .derive_key(&PublicKey::from(node))
            .expect("a usable key");
        assert_eq!(hex::encode(key.as_ref()), DERIVED_KEY);
    }

    #[test]
    fn opens_what_the_node_sealed() {
        let f = Fixture::new();
        let creds = client().open(&f.sealed(), &signer()).expect("opens");
        assert_eq!(creds.as_bytes(), PLAINTEXT);
    }

    #[test]
    fn refuses_another_nodes_answer() {
        let f = Fixture::new();
        let other = Address([0x11; 20]);
        assert_eq!(
            client().open(&f.sealed(), &other).err(),
            Some(OpenError::WrongNode)
        );
    }

    #[test]
    fn refuses_a_substituted_session_key() {
        let mut f = Fixture::new();
        f.node_key[0] ^= 1;
        assert_eq!(
            client().open(&f.sealed(), &signer()).err(),
            Some(OpenError::WrongNode)
        );
    }

    #[test]
    fn refuses_an_answer_to_someone_else() {
        // The node signed the exchange with the fixture's client key, not this one.
        let f = Fixture::new();
        let stranger = SessionKeypair::generate();
        assert_eq!(
            stranger.open(&f.sealed(), &signer()).err(),
            Some(OpenError::WrongNode)
        );
    }

    #[test]
    fn refuses_an_answer_for_another_session() {
        let mut f = Fixture::new();
        f.session = "00000000-0000-0000-0000-000000000000"
            .parse()
            .expect("a canonical session id");
        assert_eq!(
            client().open(&f.sealed(), &signer()).err(),
            Some(OpenError::WrongNode)
        );
    }

    #[test]
    fn refuses_altered_ciphertext() {
        let mut f = Fixture::new();
        f.ciphertext[0] ^= 1;
        assert_eq!(
            client().open(&f.sealed(), &signer()).err(),
            Some(OpenError::Decryption)
        );
    }

    #[test]
    fn refuses_a_malformed_signature() {
        let mut f = Fixture::new();
        f.signature[64] = 5;
        assert_eq!(
            client().open(&f.sealed(), &signer()).err(),
            Some(OpenError::BadSignature)
        );
        f.signature = vec![0; 65];
        assert_eq!(
            client().open(&f.sealed(), &signer()).err(),
            Some(OpenError::BadSignature)
        );
    }

    #[test]
    fn names_the_field_with_the_wrong_length() {
        let mut f = Fixture::new();
        f.nonce.pop();
        assert_eq!(
            client().open(&f.sealed(), &signer()).err(),
            Some(OpenError::Length {
                field: Field::Nonce,
                expected: 12,
                got: 11
            })
        );
    }

    #[test]
    fn refuses_a_low_order_session_key() {
        // The identity point: every secret maps it to zero.
        let weak = PublicKey::from([0; 32]);
        assert_eq!(
            client().derive_key(&weak).err(),
            Some(OpenError::WeakSessionKey)
        );
    }

    #[test]
    fn keeps_secrets_out_of_debug() {
        let f = Fixture::new();
        let creds = client().open(&f.sealed(), &signer()).expect("opens");
        let shown = format!("{creds:?} {:?}", client());
        assert!(!shown.contains("sealed for"));
        assert!(!shown.contains("1, 2, 3, 4, 5"));
    }
}
