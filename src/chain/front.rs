//! A Control Plane's front: how to reach it where its endpoint is blocked.
//!
//! Every Control Plane runs the same front — VLESS over REALITY, forwarding
//! only to its own gRPC — so these values are the protocol's, not any one
//! Control Plane's. What differs is the REALITY public key, which each
//! publishes on chain beside its endpoint ([`ControlPlane::front`]).
//!
//! The SDK carries no tunnel engine: an application runs one (Xray, say)
//! with these settings and hands the SDK the connection it gives
//! ([`ControlPlaneClient::through`](crate::client::ControlPlaneClient::through)).
//! The front answers in plain HTTP/2; REALITY is what authenticates it, by
//! the key read from the chain.

use super::ControlPlane;

/// The front's only VLESS user. Public: what admits a client is reaching
/// the Control Plane's REALITY key, not knowing this.
pub const USER_ID: &str = "5c1e0d2b-4a01-4f3a-8e6d-77616e646572";
/// The server name to present.
pub const SERVER_NAME: &str = "account.adobe.com";
/// REALITY's short id, the same on every front.
pub const SHORT_ID: &str = "5367756c61f30e01";
/// The VLESS flow: XTLS Vision.
pub const FLOW: &str = "xtls-rprx-vision";
/// The TLS fingerprint to imitate.
pub const FINGERPRINT: &str = "chrome";
/// Where a front listens.
pub const PORT: u16 = 443;

/// One Control Plane's front.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Front {
    /// The host the Control Plane published for its endpoint.
    pub host: String,
    /// The port, [`PORT`].
    pub port: u16,
    /// The REALITY public key, X25519.
    pub public_key: [u8; 32],
}

impl Front {
    /// The public key as Xray writes it: base64url without padding.
    #[must_use]
    pub fn public_key_base64(&self) -> String {
        base64url(&self.public_key)
    }
}

impl ControlPlane {
    /// Its front, if it published a REALITY key.
    #[must_use]
    pub fn front(&self) -> Option<Front> {
        self.reality_key.map(|public_key| Front {
            host: self.host.clone(),
            port: PORT,
            public_key,
        })
    }
}

fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
        let chars = chunk.len() + 1;
        for i in 0..chars {
            out.push(char::from(ALPHABET[(n >> (18 - 6 * i) & 63) as usize]));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The key the Control Plane's test prints for its test signer, version 1.
    #[test]
    fn writes_the_key_as_xray_does() {
        let key = [
            0x0d, 0xbc, 0x57, 0xba, 0x4f, 0x3b, 0x2c, 0x7a, 0x4b, 0x55, 0x1f, 0xcd, 0x8f, 0xb6,
            0x00, 0x35, 0x56, 0x5c, 0x83, 0xd5, 0x6a, 0x79, 0x48, 0x8f, 0x14, 0x39, 0xbc, 0x29,
            0xa8, 0xc5, 0x47, 0x0c,
        ];
        let front = Front {
            host: "cp.example".into(),
            port: PORT,
            public_key: key,
        };
        assert_eq!(
            front.public_key_base64(),
            "DbxXuk87LHpLVR_Nj7YANVZcg9VqeUiPFDm8KajFRww"
        );
    }
}
