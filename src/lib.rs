//! A client for the Singula protocol.
//!
//! Singula routes traffic through independent nodes, called Stars, that are
//! coordinated by Control Planes and paid from an on-chain reward pool. This
//! crate is what a client needs to take part — except the tunnel: a session
//! ends with tunnel settings, and which engine carries the traffic is up to
//! the application.
//!
//! # Layers
//!
//! Each builds on the ones before it, and each is usable alone.
//!
//! | Module          | Feature  | What it is                                                        |
//! |-----------------|----------|-------------------------------------------------------------------|
//! | crate root      | —        | Identifiers, the digests a session signs, the session key exchange |
//! | `chain`         | `chain`  | Typed reads of the protocol's contracts                           |
//! | `zk`            | `zk`     | Anonymous identities, the subscriber group, membership proofs     |
//! | `client`        | `client` | Control Plane calls, and `client::Singula` over all of it         |
//!
//! Most applications start at `client::Singula`: `connect` opens a session
//! and keeps it — reporting its traffic and renewing it — until it is closed.
//!
//! # The core, by hand
//!
//! What a session is made of, should you need the wire formats directly:
//!
//! 1. Sign in: the subscriber's wallet signs a [`SignInMessage`].
//! 2. Ask for a session, sending the public halves of a fresh
//!    [`SessionKeypair`] and [`CheckpointKey`].
//! 3. Open the node's [`SealedCredentials`] with [`SessionKeypair::open`],
//!    checking them against the signer [`Address`] the node registered on
//!    chain.
//! 4. While the session runs, sign a [`Checkpoint`] whenever the Control Plane
//!    asks, and a [`Renewal`] to keep the lease.

#[cfg(feature = "chain")]
pub mod chain;
#[cfg(feature = "client")]
pub mod client;
mod digest;
mod eth;
#[cfg(any(feature = "chain", feature = "zk"))]
mod hex;
mod id;
mod session;
mod sign_in;
mod signing;
#[cfg(feature = "zk")]
pub mod zk;

pub use digest::{Checkpoint, Digest, Ending, Renewal};
pub use id::{
    Address, AddressError, Epoch, RequestId, RequestIdError, SessionId, SessionIdError, StarId,
    UnixTime,
};
pub use session::{Credentials, Field, OpenError, SealedCredentials, SessionKeypair};
pub use sign_in::{SignInError, SignInMessage};
pub use signing::{CheckpointKey, Signature};
