//! Proofs made by this crate, checked the way the Control Plane checks them.
//!
//! The verifying key here is the Control Plane's own copy
//! (`semaphore_vk_16.json`), not one derived from the crate's proving key, and
//! the public signals are rebuilt from vectors the Control Plane's Go code
//! produced. A proof passes only if both sides agree on the circuit, the
//! tree, the identity, the scope and the encoding of the points.

// The helpers below are part of the tests: a failed expectation in them is a
// failed test, with its reason attached.
#![allow(clippy::expect_used, clippy::panic)]

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use std::str::FromStr as _;

use ark_ff::PrimeField as _;
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, VerifyingKey, prepare_verifying_key};
use serde_json::Value;
use singula::zk::{AccessProof, Claim, FieldElement, Group, Identity, Prover};
use singula::{Epoch, StarId};

/// The JavaScript client's identity, and the group it was tested in.
const SECRET: &str = "0x08207bd92786697f8bed5caf78eda4d3b78fbc3326eb624744b966e7f94f5f59";
const MEMBERS: [&str; 4] = [
    "111",
    "222",
    "333",
    "15653118452981836033022399046009658219270373379659789120083529738828725496177",
];

/// The Control Plane's `SemaphoreHash` of the claims below.
const SESSION_MESSAGE: &str =
    "343371210433890290056162609015838183378480827683322587048381917224414179832";
const SESSION_SCOPE: &str =
    "144238274787227100379747289347751931288527938002097690447946830657197365998";
const PACKET_SCOPE: &str =
    "215721150169798234869930996536229829395638981024187311208781748876391599088";

const SESSION: Claim = Claim::Session {
    control_plane: StarId(7),
    epoch: Epoch(137),
    index: 3,
};
const PACKET: Claim = Claim::Permission {
    window: Epoch(137),
    index: 3,
};

struct Setup {
    prover: Prover,
    identity: Identity,
    group: Group,
    key: PreparedVerifyingKey<Bn254>,
}

impl Setup {
    fn new() -> Self {
        let members: Vec<FieldElement> = MEMBERS
            .iter()
            .map(|m| m.parse().expect("a field element"))
            .collect();
        Self {
            prover: Prover::new().expect("the bundled circuit loads"),
            identity: Identity::from_secret(SECRET).expect("a valid secret"),
            group: Group::new(&members).expect("a valid group"),
            key: control_plane_key(),
        }
    }

    fn prove(&self, claim: Claim) -> AccessProof {
        self.prover
            .prove(&self.identity, &self.group, claim)
            .expect("a member can prove")
    }

    /// The Control Plane's check: the proof against signals it rebuilds itself.
    fn verifies(&self, proof: &AccessProof, message: &str, scope: &str) -> bool {
        let signals = [
            self.group.root().to_string(),
            proof.nullifier.to_string(),
            message.to_owned(),
            scope.to_owned(),
        ]
        .map(|s| Fr::from_str(&s).unwrap_or_else(|()| panic!("{s} is a field element")));
        unpack(&proof.points).is_some_and(|p| {
            Groth16::<Bn254>::verify_proof(&self.key, &p, &signals).unwrap_or(false)
        })
    }
}

/// Right `a` of the journal's fixture: window 10, its key, and the Control
/// Plane's `SemaphoreHash` of the right's scope and message.
const RIGHT_KEY: (&str, &str) = (
    "e417ce2cc31ef29ce38c7a1e75631e8d8c8209a4f508b8e81c74d41c14ccc431",
    "0d2c42f380d728d51d87e4b26261bc4b3d4a6f5459c0b8b6d1077e19ef75c73a",
);
const RIGHT_SCOPE: &str =
    "447793967648333678719443863230786612109752310857686584872885604805821712085";
const RIGHT_MESSAGE: &str =
    "52204751582231114037403491615054938693844254530108889856078236979011909626";

fn right_claim(key: (&str, &str)) -> Claim {
    let bytes = |s: &str| -> [u8; 32] {
        hex::decode(s)
            .expect("valid hex")
            .try_into()
            .expect("32 bytes")
    };
    Claim::Right {
        window: Epoch(10),
        key: (bytes(key.0), bytes(key.1)),
    }
}

#[test]
fn a_right_proof_passes_the_control_planes_check() {
    let s = Setup::new();
    let proof = s.prove(right_claim(RIGHT_KEY));
    assert!(s.verifies(&proof, RIGHT_MESSAGE, RIGHT_SCOPE));
    let right = proof.to_right(0).expect("a right claim makes a right");
    assert_eq!(right.nullifier.0, proof.nullifier.to_be_bytes());
    assert!(
        s.prove(SESSION).to_right(0).is_none(),
        "only a right claim does"
    );

    // One slot, one nullifier a day, whatever key it delegates to.
    let other_key = s.prove(right_claim((RIGHT_KEY.1, RIGHT_KEY.0)));
    assert_eq!(other_key.nullifier, proof.nullifier);
    assert!(
        !s.verifies(&other_key, RIGHT_MESSAGE, RIGHT_SCOPE),
        "the message binds the key"
    );
}

#[test]
fn the_fixtures_right_verifies_as_we_hash_it() {
    // Made by the JavaScript client library, checked by the Control Plane's
    // Go journal; here against the scope and message this crate computes.
    let f: Value = serde_json::from_str(include_str!("data/journal-fixture.json"))
        .expect("the fixture parses");
    let r = &f["rights"]["a"];
    let field = |v: &Value| {
        let bytes = hex::decode(v.as_str().expect("hex").trim_start_matches("0x")).expect("hex");
        Fr::from_be_bytes_mod_order(&bytes)
    };
    let mut points = [[0u8; 32]; 8];
    for (p, v) in points
        .iter_mut()
        .zip(r["points"].as_array().expect("points"))
    {
        let raw = hex::decode(v.as_str().expect("hex").trim_start_matches("0x")).expect("hex");
        p[32 - raw.len()..].copy_from_slice(&raw);
    }
    let signals = [
        field(&f["sweepRoot"]),
        field(&r["nullifier"]),
        Fr::from_str(RIGHT_MESSAGE).unwrap_or_else(|()| panic!("a field element")),
        Fr::from_str(RIGHT_SCOPE).unwrap_or_else(|()| panic!("a field element")),
    ];
    let proof = unpack(&points).expect("points on their curves");
    assert!(
        Groth16::<Bn254>::verify_proof(&control_plane_key(), &proof, &signals).unwrap_or(false)
    );
}

#[test]
fn a_session_proof_passes_the_control_planes_check() {
    let s = Setup::new();
    let proof = s.prove(SESSION);
    assert_eq!(proof.merkle_root, s.group.root());
    assert!(s.verifies(&proof, SESSION_MESSAGE, SESSION_SCOPE));
}

#[test]
fn a_packet_proof_passes_the_control_planes_check() {
    let s = Setup::new();
    let proof = s.prove(PACKET);
    assert!(s.verifies(&proof, PACKET_SCOPE, PACKET_SCOPE));
}

#[test]
fn a_proof_is_good_for_its_own_claim_only() {
    let s = Setup::new();
    let session = s.prove(SESSION);
    assert!(!s.verifies(&session, PACKET_SCOPE, PACKET_SCOPE));
    // The same slot at another Control Plane or in another epoch has another scope.
    let other = s.prove(Claim::Session {
        control_plane: StarId(8),
        epoch: Epoch(137),
        index: 3,
    });
    assert!(!s.verifies(&other, SESSION_MESSAGE, SESSION_SCOPE));
}

#[test]
fn the_nullifier_is_fixed_by_the_claim() {
    let s = Setup::new();
    let (first, again) = (s.prove(SESSION), s.prove(SESSION));
    assert_eq!(
        first.nullifier, again.nullifier,
        "the same slot cannot be spent twice"
    );
    assert_ne!(
        first.points, again.points,
        "proofs are randomised, so they do not link"
    );
    assert_ne!(first.nullifier, s.prove(PACKET).nullifier);
}

#[test]
fn an_altered_proof_fails() {
    let s = Setup::new();
    let mut proof = s.prove(SESSION);
    proof.points.swap(2, 3);
    assert!(!s.verifies(&proof, SESSION_MESSAGE, SESSION_SCOPE));
}

#[test]
fn a_stranger_cannot_prove() {
    let s = Setup::new();
    let stranger = Identity::from_signature("0x00");
    assert!(matches!(
        s.prover.prove(&stranger, &s.group, SESSION),
        Err(singula::zk::ProveError::NotAMember)
    ));
}

/// The packed points back into a proof, reversing Ethereum's order of B's
/// coefficients — as the Control Plane's `Unpack` does. `None` if a point is
/// not on its curve or not in its subgroup, which the Control Plane refuses.
fn unpack(points: &[[u8; 32]; 8]) -> Option<Proof<Bn254>> {
    let p = points.map(|b| Fq::from_be_bytes_mod_order(&b));
    let a = G1Affine::new_unchecked(p[0], p[1]);
    let b = G2Affine::new_unchecked(Fq2::new(p[3], p[2]), Fq2::new(p[5], p[4]));
    let c = G1Affine::new_unchecked(p[6], p[7]);
    let valid = |on_curve: bool, in_subgroup: bool| on_curve && in_subgroup;
    (valid(
        a.is_on_curve(),
        a.is_in_correct_subgroup_assuming_on_curve(),
    ) && valid(
        b.is_on_curve(),
        b.is_in_correct_subgroup_assuming_on_curve(),
    ) && valid(
        c.is_on_curve(),
        c.is_in_correct_subgroup_assuming_on_curve(),
    ))
    .then_some(Proof { a, b, c })
}

fn control_plane_key() -> PreparedVerifyingKey<Bn254> {
    let json: Value =
        serde_json::from_str(include_str!("data/semaphore_vk_16.json")).expect("valid JSON");
    let fq = |v: &Value| {
        let bytes = hex::decode(v.as_str().expect("a hex string")).expect("valid hex");
        Fq::from_be_bytes_mod_order(&bytes)
    };
    let g1 = |v: &Value| G1Affine::new(fq(&v["x"]), fq(&v["y"]));
    let g2 = |v: &Value| {
        G2Affine::new(
            Fq2::new(fq(&v["x"]["c0"]), fq(&v["x"]["c1"])),
            Fq2::new(fq(&v["y"]["c0"]), fq(&v["y"]["c1"])),
        )
    };
    prepare_verifying_key(&VerifyingKey {
        alpha_g1: g1(&json["alpha_g1"]),
        beta_g2: g2(&json["beta_g2"]),
        gamma_g2: g2(&json["gamma_g2"]),
        delta_g2: g2(&json["delta_g2"]),
        gamma_abc_g1: json["ic"]
            .as_array()
            .expect("an array")
            .iter()
            .map(g1)
            .collect(),
    })
}

#[test]
fn an_identitys_right_key_is_derived_from_its_secret() {
    use singula::journal::{JournalParams, RightKey};
    let identity = Identity::from_secret(SECRET).expect("a valid secret");
    let secret: [u8; 32] = hex::decode(&SECRET[2..])
        .expect("valid hex")
        .try_into()
        .expect("32 bytes");
    let params = JournalParams::new(421_614);
    let from_identity = identity.right_key(params, Epoch(170)).expect("derives");
    let from_bytes = RightKey::derive(&secret, params, Epoch(170)).expect("derives");
    assert_eq!(from_identity.public_key(), from_bytes.public_key());
    let next_slot = identity
        .for_slot(1)
        .right_key(params, Epoch(170))
        .expect("derives");
    assert_ne!(
        next_slot.public_key(),
        from_identity.public_key(),
        "each slot its own key"
    );
}
