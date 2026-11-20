//! The journal's wire formats against the Control Planes' own fixture: real
//! Semaphore proofs, P-256 ping signatures and Control Plane attestations,
//! made by an independent implementation (singula-star's
//! `scripts/gen-ledger-fixture.cjs`) and checked there by the Go journal.

// The helpers below are part of the tests: a failed expectation in them is a
// failed test, with its reason attached.
#![allow(clippy::expect_used, clippy::panic)]

use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use serde_json::Value;
use singula::journal::{
    Attestation, JournalParams, Nullifier, Ping, RegistryVersion, RegistryVersionId, Versions,
    open_digest,
};
use singula::{Address, Epoch, SessionId, StarId, UnixTime};

fn fixture() -> Value {
    serde_json::from_str(include_str!("data/journal-fixture.json")).expect("the fixture parses")
}

fn bytes<const N: usize>(v: &Value) -> [u8; N] {
    let s = v.as_str().expect("a hex string");
    let raw = hex::decode(s.trim_start_matches("0x")).expect("hex");
    let mut out = [0; N];
    out[N - raw.len()..].copy_from_slice(&raw);
    out
}

fn params(f: &Value) -> JournalParams {
    JournalParams::new(f["params"]["chainId"].as_u64().expect("chain id"))
        .with_domain(bytes(&f["params"]["domain"]))
}

fn session(v: &Value) -> SessionId {
    let raw: [u8; 16] = bytes(v);
    let h = hex::encode(raw);
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
    .parse()
    .expect("a UUID")
}

fn version(f: &Value) -> RegistryVersion {
    let r = &f["registry"];
    let address: [u8; 20] = bytes(&r["address"]);
    let id = RegistryVersionId::new(
        f["params"]["chainId"].as_u64().expect("chain id"),
        Address(address),
        r["block"].as_u64().expect("block"),
        &bytes(&r["blockHash"]),
    );
    assert_eq!(id.0, bytes::<32>(&r["id"]), "the registry version id");
    let control_planes = f["cps"]
        .as_array()
        .expect("cps")
        .iter()
        .map(|c| {
            (
                StarId(c["id"].as_u64().expect("id")),
                Address(bytes(&c["signer"])),
            )
        })
        .collect();
    RegistryVersion::new(
        id,
        r["block"].as_u64().expect("block"),
        UnixTime(r["start"].as_i64().expect("start")),
        control_planes,
    )
}

/// The keys of the rights whose nullifier is `nullifier`: one, or two for
/// the slot the fixture gives two keys.
fn keys_of(f: &Value, nullifier: &[u8; 32]) -> Vec<VerifyingKey> {
    f["rights"]
        .as_object()
        .expect("rights")
        .values()
        .filter(|r| bytes::<32>(&r["nullifier"]) == *nullifier)
        .map(|r| {
            let mut sec1 = vec![4];
            sec1.extend(bytes::<32>(&r["keyX"]));
            sec1.extend(bytes::<32>(&r["keyY"]));
            VerifyingKey::from_sec1_bytes(&sec1).expect("a P-256 key")
        })
        .collect()
}

fn pings(f: &Value) -> impl Iterator<Item = (Ping, &Value)> {
    let window = Epoch(f["window"].as_u64().expect("window"));
    f["pings"]
        .as_object()
        .expect("pings")
        .values()
        .flat_map(move |group| {
            group.as_array().expect("a group").iter().map(move |g| {
                let ping = Ping::new(
                    window,
                    Nullifier(bytes(&g["nullifier"])),
                    session(&g["session"]),
                    StarId(g["node"].as_u64().expect("node")),
                    g["total"].as_u64().expect("total"),
                );
                (ping, g)
            })
        })
}

#[test]
fn every_ping_hashes_to_what_its_client_signed() {
    let f = fixture();
    let p = params(&f);
    for (ping, g) in pings(&f) {
        let mut rs = [0u8; 64];
        rs[..32].copy_from_slice(&bytes::<32>(&g["r"]));
        rs[32..].copy_from_slice(&bytes::<32>(&g["s"]));
        let signature = Signature::from_slice(&rs).expect("a signature");
        let hash = ping.hash(p);
        assert!(
            keys_of(&f, &ping.nullifier.0)
                .iter()
                .any(|k| k.verify_prehash(&hash, &signature).is_ok()),
            "the client's signature verifies over our ping hash"
        );
    }
}

#[test]
fn every_attestation_recovers_to_its_control_plane() {
    let f = fixture();
    let p = params(&f);
    let v = version(&f);
    for (ping, g) in pings(&f) {
        let hash = ping.hash(p);
        for a in g["attestations"].as_array().expect("attestations") {
            let cp = StarId(a["cp"].as_u64().expect("cp"));
            let att = Attestation::new(
                cp,
                UnixTime(a["receivedAt"].as_i64().expect("time")),
                RegistryVersionId(bytes(&a["version"])),
                bytes(&a["sig"]),
            );
            let want = v
                .control_planes
                .iter()
                .find(|(id, _)| *id == cp)
                .expect("a listed CP")
                .1;
            assert_eq!(att.signer(p, &hash), Some(want));
        }
    }
}

#[test]
fn an_ack_with_a_majority_commits_at_its_median() {
    let f = fixture();
    let p = params(&f);
    let v = version(&f);
    let versions = Versions::new(vec![v.clone()]).expect("a history");
    let (ping, g) = pings(&f)
        .find(|(p, _)| p.total == 600 && p.session.to_bytes()[15] == 1)
        .expect("the morning's 600 s ping");
    let atts: Vec<Attestation> = g["attestations"]
        .as_array()
        .expect("attestations")
        .iter()
        .map(|a| {
            Attestation::new(
                StarId(a["cp"].as_u64().expect("cp")),
                UnixTime(a["receivedAt"].as_i64().expect("t")),
                v.id,
                bytes(&a["sig"]),
            )
        })
        .collect();
    let now = UnixTime(atts[0].received_at.0 + 10);
    let committed = versions
        .check_ack(p, &ping.hash(p), v.id, &atts, now)
        .expect("a majority");
    assert_eq!(committed.at, atts[1].received_at, "the median of three");

    let one = &atts[..1];
    assert!(
        versions
            .check_ack(p, &ping.hash(p), v.id, one, now)
            .is_err(),
        "one of three is no majority"
    );
    let mut forged = atts.clone();
    forged[0].received_at = UnixTime(forged[0].received_at.0 - 1);
    assert!(
        versions
            .check_ack(p, &ping.hash(p), v.id, &forged, now)
            .is_err(),
        "a moved time fails its signature"
    );
}

#[test]
fn the_open_digest_is_what_the_client_signed() {
    let f = fixture();
    let o = &f["open"];
    let right = &f["rights"][o["right"].as_str().expect("a right name")];
    let digest = open_digest(
        params(&f),
        &bytes(&o["challenge"]),
        StarId(o["cp"].as_u64().expect("cp")),
        &bytes::<32>(&o["sessionKey"]),
    );
    let signature = Signature::from_slice(&bytes::<64>(&o["sig"])).expect("a signature");
    let mut sec1 = vec![4];
    sec1.extend(bytes::<32>(&right["keyX"]));
    sec1.extend(bytes::<32>(&right["keyY"]));
    VerifyingKey::from_sec1_bytes(&sec1)
        .expect("a P-256 key")
        .verify_prehash(&digest, &signature)
        .expect("the open signature verifies over our digest");
}
