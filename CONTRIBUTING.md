# Contributing

Thank you for helping. This crate is how other people's software speaks the
Singula protocol, so it is held to a high bar: a change has to be correct
against the other implementations, not only against its own tests.

## Before you start

For anything larger than a fix, open an issue first and say what you intend.
It saves you writing something that does not fit, and us reviewing it.

To report a vulnerability, do **not** open an issue; see
[SECURITY.md](SECURITY.md).

## Building

Rust 1.87 or newer. Nothing else: the protocol buffers are compiled ahead of
time and checked in, and the zero-knowledge circuit ships inside the crate.

```text
cargo test --all-features
```

The proving tests are slow in debug builds; `--release` makes them fast.

## Before you open a pull request

Run what CI runs, and make it pass:

```text
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo clippy --all-targets -- -D warnings
cargo test --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
```

Tests against the live test network are ignored by default. If your change
touches the chain or the Control Plane calls, run them too:

```text
SINGULA_RPC_URL=https://… cargo test --all-features -- --ignored
```

## What a change has to respect

- **Wire formats are shared.** Digests, signatures, encodings and proofs must
  agree byte for byte with the Control Plane and the other clients. A change
  to one comes with test vectors produced by another implementation, not by
  this crate's own code — a vector the code wrote checks nothing.
- **Generated code is regenerated, never edited.** After changing anything
  in `proto/`, run `cargo run --manifest-path tools/codegen/Cargo.toml`.
- **No panics in library code.** No `unwrap`, `expect` or `panic!` outside
  tests; return an error that says what happened.
- **No blocking in async code.** File and CPU-heavy work goes to the blocking
  pool.
- **Secrets stay secret.** Keys and secrets are zeroized on drop and never
  appear in `Debug`, `Display` or logs.
- **Comments say why.** The protocol rule, the constraint, the failure being
  avoided — not a restatement of the code.
- **The public API stays small.** Add to it deliberately, document every item,
  and note it in [CHANGELOG.md](CHANGELOG.md) under *Unreleased*.

## Pull requests

Keep a pull request to one change, and say in its description what it
changes, why, and how you checked it. The template asks for exactly that.

## License

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this crate by you, as defined in the Apache-2.0
license, shall be dual licensed under the MIT and Apache-2.0 licenses,
without any additional terms or conditions.
