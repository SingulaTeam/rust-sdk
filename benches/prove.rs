//! How long a client waits for a proof, and for the circuit to load.

// `criterion_group!` defines an undocumented function, and a failed setup is
// a failed benchmark.
#![allow(missing_docs, clippy::expect_used)]

use criterion::{Criterion, criterion_group, criterion_main};
use singula::zk::{Claim, FieldElement, Group, Identity, Prover};
use singula::{Epoch, StarId};

fn prove(c: &mut Criterion) {
    let identity = Identity::from_signature("0xbench");
    // A full tree: the deepest path the circuit allows, the worst case.
    let mut members: Vec<FieldElement> = (1..1u64 << 16)
        .map(|i| i.to_string().parse())
        .collect::<Result<_, _>>()
        .expect("small integers are field elements");
    members.push(identity.commitment());
    let Ok(group) = Group::new(&members) else {
        return;
    };
    let Ok(prover) = Prover::new() else { return };
    let claim = Claim::Session {
        control_plane: StarId(7),
        epoch: Epoch(137),
        index: 0,
    };

    c.bench_function("load the circuit", |b| b.iter(Prover::new));
    c.bench_function("prove at depth 16", |b| {
        b.iter(|| prover.prove(&identity, &group, claim));
    });
    c.bench_function("build a 2^16 group", |b| b.iter(|| Group::new(&members)));
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20);
    targets = prove
}
criterion_main!(benches);
