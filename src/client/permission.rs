//! Permissions: blind-signed entitlements to hold sessions.
//!
//! Each window a subscription may take a fixed number of permissions, each
//! under an index of its own, network wide — so its devices can each take
//! some, and together never more; each permission admits one session. The
//! client chooses each permission's secret, blinds it, and has the Control
//! Plane sign what it cannot read — so when the permission is later spent, at
//! any Control Plane, nobody can tell which request, and so which subscriber,
//! it came from.
//!
//! RFC 9474, RSABSSA-SHA384-PSS-Randomized: the variant the Control Plane
//! verifies. The randomised variant signs `randomizer ‖ secret`, so a
//! permission is that prepared message together with its signature.

use blind_rsa_signatures::{
    BlindSignature, BlindingResult, DefaultRng, PublicKeySha384PSSRandomized,
};
use rand_core::{OsRng, RngCore as _};
use sha3::{Digest as _, Keccak256};
use zeroize::Zeroizing;

use super::call::{Conversation, Step, exchange, request_id};
use super::proto::client::client_message::Message as Outbound;
use super::proto::client::control_plane_message::Message as Inbound;
use super::proto::client::{self as wire, GetIssuerKeyRequest, TakePacketRequest};
use super::{ClientError, ControlPlaneClient};
use crate::chain::{Chain, Rpc};
use crate::id::{Epoch, StarId};
use crate::zk::{AccessProof, Claim};

/// Bytes of secret behind one permission: enough that nobody can guess one.
const SECRET_LEN: usize = 32;

/// A Control Plane's permission key for one window, checked against the
/// commitment it made on chain.
///
/// Only [`ControlPlaneClient::issuer_key`] makes one, and only after the
/// check: blinding under a key the issuer chose for one client alone would
/// mark every permission signed under it as that client's.
#[derive(Clone)]
pub struct IssuerKey {
    issuer: StarId,
    window: Epoch,
    packet_size: u32,
    der: Vec<u8>,
    key: PublicKeySha384PSSRandomized,
}

impl IssuerKey {
    /// The issuing Control Plane.
    #[must_use]
    pub fn issuer(&self) -> StarId {
        self.issuer
    }

    /// The window the key signs for.
    #[must_use]
    pub fn window(&self) -> Epoch {
        self.window
    }

    /// How many permissions a subscription may take per window under this
    /// key: the indices run from 0 below it.
    #[must_use]
    pub fn packet_size(&self) -> u32 {
        self.packet_size
    }

    /// What the issuer commits to on chain for this key.
    fn commitment(der: &[u8], packet_size: u32) -> [u8; 32] {
        Keccak256::new()
            .chain_update(der)
            .chain_update(packet_size.to_be_bytes())
            .finalize()
            .into()
    }
}

impl std::fmt::Debug for IssuerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuerKey")
            .field("issuer", &self.issuer)
            .field("window", &self.window)
            .field("packet_size", &self.packet_size)
            .finish_non_exhaustive()
    }
}

/// One permission: admits one session in its window, at any Control Plane.
///
/// Holding it is what entitles a session, so store it as a secret; spending
/// it twice is refused network-wide.
#[derive(Clone, PartialEq, Eq)]
pub struct Permission {
    /// The issuing Control Plane.
    pub issuer: StarId,
    /// The window it is valid in.
    pub window: Epoch,
    /// `randomizer ‖ secret`, what the issuer's key signed. It also names the
    /// permission in the spent set.
    pub prepared_message: Vec<u8>,
    /// The issuer's signature over `prepared_message`.
    pub signature: Vec<u8>,
    /// The issuer's public key, DER-encoded, for the verifier to look up.
    pub issuer_public_key: Vec<u8>,
}

impl Permission {
    pub(super) fn to_wire(&self) -> wire::Permission {
        wire::Permission {
            issuer_star_id: self.issuer.0,
            window: self.window.0,
            prepared_message: self.prepared_message.clone(),
            signature: self.signature.clone(),
            issuer_public_key: self.issuer_public_key.clone(),
        }
    }
}

impl std::fmt::Debug for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Permission")
            .field("issuer", &self.issuer)
            .field("window", &self.window)
            .finish_non_exhaustive()
    }
}

/// One blinded permission, waiting for the issuer's signature.
struct Pending {
    secret: Zeroizing<[u8; SECRET_LEN]>,
    blinding: BlindingResult,
}

impl IssuerKey {
    /// Blinds `count` fresh secrets: the messages to send, and what is needed
    /// to unblind the answers, in the same order.
    fn blind(&self, count: u32) -> Result<(Vec<Vec<u8>>, Vec<Pending>), ClientError> {
        let mut messages = Vec::new();
        let mut pending = Vec::new();
        for _ in 0..count {
            let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
            OsRng.fill_bytes(secret.as_mut());
            let blinding = self
                .key
                .blind(&mut DefaultRng, secret.as_ref())
                .map_err(|_| ClientError::Untrusted("the issuer's key cannot blind"))?;
            messages.push(blinding.blind_message.0.clone());
            pending.push(Pending { secret, blinding });
        }
        Ok((messages, pending))
    }

    /// Unblinds the issuer's signatures, checking each one now rather than
    /// when a session is wanted — by then the index is spent and there is
    /// nothing to fall back on.
    fn finish(
        &self,
        pending: &[Pending],
        signatures: Vec<Vec<u8>>,
    ) -> Result<Vec<Permission>, ClientError> {
        if signatures.len() != pending.len() {
            return Err(ClientError::Untrusted(
                "the issuer returned the wrong number of signatures",
            ));
        }
        pending
            .iter()
            .zip(signatures)
            .map(|(p, blind)| {
                let signature = self
                    .key
                    .finalize(&BlindSignature(blind), &p.blinding, p.secret.as_ref())
                    .map_err(|_| ClientError::Untrusted("an issuer signature does not verify"))?;
                let randomizer = p.blinding.msg_randomizer.ok_or(ClientError::Untrusted(
                    "a permission was blinded without a randomizer",
                ))?;
                let mut prepared_message = randomizer.0.to_vec();
                prepared_message.extend_from_slice(p.secret.as_ref());
                Ok(Permission {
                    issuer: self.issuer,
                    window: self.window,
                    prepared_message,
                    signature: signature.0,
                    issuer_public_key: self.der.clone(),
                })
            })
            .collect()
    }
}

impl ControlPlaneClient {
    /// The key this Control Plane signs the current window's permissions
    /// under, after checking it against the commitment on `chain`.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Untrusted`] if the key, its packet size or its
    /// window do not match what the issuer committed to, or if the issuer no
    /// longer holds the Control Plane role; and any error of the call or the
    /// chain read.
    pub async fn issuer_key<R: Rpc>(&self, chain: &Chain<R>) -> Result<IssuerKey, ClientError> {
        let id = request_id();
        let message = Outbound::GetIssuerKey(GetIssuerKeyRequest {
            request_id: id.to_string(),
        });
        let answer = exchange(
            self,
            Conversation {
                auth: None,
                request: Some(&id),
                messages: vec![message],
            },
            |m| match m {
                Inbound::GetIssuerKeyResult(r) if r.request_id == id.as_str() => {
                    Step::Done(if r.success {
                        Ok(r)
                    } else {
                        Err(ClientError::Refused {
                            code: 0,
                            message: r.error_message,
                        })
                    })
                }
                _ => Step::Skip,
            },
        )
        .await?;

        if answer.issuer_star_id != self.star.0 {
            return Err(ClientError::Untrusted("the key is for another issuer"));
        }
        let window = Epoch(answer.window);
        let committed = chain
            .permission_key_commitment(self.star, window)
            .await?
            .ok_or(ClientError::Untrusted(
                "the issuer committed to no key for this window",
            ))?;
        if !committed.issuer_active {
            return Err(ClientError::Untrusted(
                "the issuer is no longer a Control Plane",
            ));
        }
        if committed.packet_size != answer.packet_size || answer.packet_size == 0 {
            return Err(ClientError::Untrusted(
                "the packet size differs from the commitment",
            ));
        }
        if IssuerKey::commitment(&answer.issuer_public_key, answer.packet_size)
            != committed.key_hash
        {
            return Err(ClientError::Untrusted(
                "the key differs from the commitment",
            ));
        }
        let key = PublicKeySha384PSSRandomized::from_der(&answer.issuer_public_key)
            .map_err(|_| ClientError::Malformed("the issuer's key is not an RSA public key"))?;
        Ok(IssuerKey {
            issuer: self.star,
            window,
            packet_size: answer.packet_size,
            der: answer.issuer_public_key,
            key,
        })
    }

    /// Takes the window's permission at `index`.
    ///
    /// `proof` must be a [`Claim::Permission`] proof for `key`'s window and
    /// `index`. The index is spent network-wide when the issuer signs, so
    /// keep the permission: asking for the index again in the same window is
    /// refused.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::PermissionTaken`] if the index was taken
    /// already — by another of the subscription's devices, say — and another
    /// is worth trying; [`ClientError::Mismatch`] if the proof or key is for
    /// another window, index or issuer; [`ClientError::Untrusted`] if the
    /// signature does not verify; and any error of the call.
    pub async fn take_permission(
        &self,
        key: &IssuerKey,
        index: u32,
        proof: &AccessProof,
    ) -> Result<Permission, ClientError> {
        if key.issuer != self.star {
            return Err(ClientError::Mismatch("the key is another issuer's"));
        }
        if index >= key.packet_size {
            return Err(ClientError::Mismatch(
                "the index is beyond the issuer's count",
            ));
        }
        if proof.claim
            != (Claim::Permission {
                window: key.window,
                index,
            })
        {
            return Err(ClientError::Mismatch(
                "the proof is not for this window's permission at this index",
            ));
        }
        let (blinded, pending) = key.blind(1)?;
        let id = request_id();
        let message = Outbound::TakePacket(TakePacketRequest {
            request_id: id.to_string(),
            access: Some(super::session::wire_proof(proof, key.window, 0)),
            blinded,
            index,
        });
        let signatures = exchange(
            self,
            Conversation {
                auth: None,
                request: Some(&id),
                messages: vec![message],
            },
            |m| match m {
                Inbound::TakePacketResult(r) if r.request_id == id.as_str() => {
                    Step::Done(if r.success {
                        Ok(r.blind_signatures)
                    } else if r.index_taken {
                        Err(ClientError::PermissionTaken(index))
                    } else {
                        Err(ClientError::Refused {
                            code: 0,
                            message: r.error_message,
                        })
                    })
                }
                _ => Step::Skip,
            },
        )
        .await?;
        key.finish(&pending, signatures)?
            .pop()
            .ok_or(ClientError::Untrusted("the issuer returned no signature"))
    }
}

#[cfg(test)]
mod tests {
    use blind_rsa_signatures::{MessageRandomizer, Signature};
    use serde_json::Value;

    use super::*;

    /// A permission made by the desktop client and accepted by the Control
    /// Plane's CIRCL verifier (`permission_interop_test.go`): the issuer's
    /// public key, the prepared message and the signature.
    fn fixture() -> Value {
        serde_json::from_str(include_str!("testdata/permission-interop.json")).expect("valid JSON")
    }

    fn bytes(v: &Value, name: &str) -> Vec<u8> {
        hex::decode(v[name].as_str().expect("a hex string")).expect("valid hex")
    }

    /// The fixture's issuer.
    fn key(packet_size: u32) -> IssuerKey {
        issuer_from(bytes(&fixture(), "publicKeyDer"), packet_size)
    }

    fn issuer_from(der: Vec<u8>, packet_size: u32) -> IssuerKey {
        let key = PublicKeySha384PSSRandomized::from_der(&der).expect("an RSA public key");
        IssuerKey {
            issuer: StarId(8),
            window: Epoch(137),
            packet_size,
            der,
            key,
        }
    }

    #[test]
    fn a_control_plane_permission_verifies_here() {
        let f = fixture();
        let prepared = bytes(&f, "prepared");
        let (randomizer, secret) = prepared.split_at(32);
        let randomizer = MessageRandomizer(randomizer.try_into().expect("32 bytes"));
        let signature = Signature(bytes(&f, "signature"));
        assert!(
            key(5)
                .key
                .verify(&signature, Some(randomizer), secret)
                .is_ok()
        );
    }

    #[test]
    fn a_packet_round_trips_through_the_issuers_key() {
        let (der, secret_key) = super::super::testing::issuer_key();
        let issuer = issuer_from(der.clone(), 5);
        let (blinded, pending) = issuer.blind(issuer.packet_size).expect("blinds");
        assert_eq!(blinded.len(), 5);
        let signatures = blinded
            .iter()
            .map(|m| secret_key.blind_sign(m).expect("signs").0)
            .collect();
        let permissions = issuer.finish(&pending, signatures).expect("unblinds");
        assert_eq!(permissions.len(), 5);
        for p in &permissions {
            assert_eq!(p.prepared_message.len(), 64, "randomizer ‖ secret");
            let (randomizer, secret) = p.prepared_message.split_at(32);
            let randomizer = MessageRandomizer(randomizer.try_into().expect("32 bytes"));
            assert!(
                issuer
                    .key
                    .verify(&Signature(p.signature.clone()), Some(randomizer), secret)
                    .is_ok()
            );
        }
        assert_ne!(
            permissions[0].prepared_message,
            permissions[1].prepared_message
        );
    }

    #[test]
    fn refuses_signatures_that_do_not_verify() {
        let issuer = key(2);
        let (_, pending) = issuer.blind(2).expect("blinds");
        let wrong = vec![vec![1; 256], vec![2; 256]];
        assert!(matches!(
            issuer.finish(&pending, wrong),
            Err(ClientError::Untrusted(_))
        ));
        assert!(matches!(
            issuer.finish(&pending, vec![vec![1; 256]]),
            Err(ClientError::Untrusted(_))
        ));
    }

    #[test]
    fn commits_to_the_key_and_packet_size_together() {
        let der = bytes(&fixture(), "publicKeyDer");
        assert_ne!(
            IssuerKey::commitment(&der, 5),
            IssuerKey::commitment(&der, 6)
        );
        let mut packed = der.clone();
        packed.extend_from_slice(&5u32.to_be_bytes());
        let want: [u8; 32] = Keccak256::digest(&packed).into();
        assert_eq!(IssuerKey::commitment(&der, 5), want);
    }
}
