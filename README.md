# singula

A Rust client for the [Singula](https://singula.network) protocol: open sessions on independent nodes, report their traffic, renew them, and do it anonymously if you choose.

Singula routes traffic through Stars — nodes coordinated by Control Planes and paid from an on-chain reward pool. This crate is everything a client needs to take part, except the tunnel itself: a session ends with tunnel settings, and which engine carries the traffic (sing-box, Xray, your own) is up to you.

```rust
use singula::chain::{Chain, HttpRpc, Network};
use singula::client::store::FileStore;
use singula::client::wallet::LocalWallet;
use singula::client::{ConnectOptions, Singula, Traffic};
use singula::zk::Prover;

let chain = Chain::connect(HttpRpc::new(&rpc_url)?, Network::ARBITRUM_SEPOLIA).await?;
let singula = Singula::new(chain, Prover::new()?, FileStore::new("./singula-data")?);

let wallet = LocalWallet::random(); // or your own `Wallet` over a real one
let meter = || Traffic { up: 0, down: 0 }; // your tunnel engine's counters

let mut conn = singula.connect(&wallet, ConnectOptions::new(), meter).await?;
engine.start(conn.tunnel()); // address, port, REALITY key, covers

while let Some(event) = conn.next_event().await {
    // reports and renewals happen on their own; these say how they went
}
```

The whole program is [`examples/connect.rs`](examples/connect.rs).

## Installing

The crate is not on crates.io yet. Take it from this repository, pinned to a tag or a commit:

```toml
[dependencies]
singula = { git = "https://github.com/SingulaTeam/rust-sdk", tag = "v0.1.0", features = ["client", "http"] }
```

Build the API documentation locally with `cargo doc --open --all-features`.

## What it does

- **Anonymous access.** A subscriber proves, in zero knowledge, membership of the on-chain subscriber set. The Control Plane learns that *a* subscriber connected and nothing more. Semaphore v4, with the circuit bundled: proving needs no files and no network, and takes about 50 ms.
- **Permissions.** Each window, a subscription takes its blind-signed permissions one index at a time; each holds one session, wherever in the network it is spent. The issuer cannot recognise them when they are spent.
- **Sessions that keep themselves.** `connect` opens a session and returns a `Connection` whose background task reports traffic every 30 seconds, renews ahead of expiry, and takes the next window's permissions when the window turns.
- **Wallet operations without gas.** Buy (`mint`), activate — which joins the anonymity set in the same transaction — and register, relayed by a Control Plane. The wallet signs EIP-712 intents; the Control Plane cannot change them.
- **Governance without gas.** Open a proposal, vote on it or reply in its discussion (`governance`), as a subscriber or as a Star's owner. The wallet signs the action; a Control Plane relays it and `GasStation` pays.
- **Everything checked against the chain.** Which Control Planes exist, who runs a node and with which key, the key a window's permissions must be signed under: all read through the one pinned `SingulaProtocol` address, never taken from the party being checked.

## Features

| Feature       | What it adds                                                                 |
|---------------|------------------------------------------------------------------------------|
| *(default)*   | Identifiers, digests, the session key exchange, checkpoint signing           |
| `chain`       | Typed reads of the protocol's contracts, over a transport you provide        |
| `http`        | `HttpRpc`, a JSON-RPC transport over HTTPS                                    |
| `zk`          | Semaphore identities, the subscriber group, the prover (bundles ~3.7 MB)     |
| `client`      | Control Plane calls, `Singula`, `Connection`, wallets, stores                |
| `native-roots`| Trust the OS certificate store for Control Planes instead of Mozilla's roots |

`client` implies `chain` and `zk`. Most applications want `client` and `http`.

## What your application provides

| Trait          | For                                                    | Provided                         |
|----------------|--------------------------------------------------------|----------------------------------|
| `Rpc`          | Reaching an Ethereum node                              | `HttpRpc`                        |
| `Wallet`       | Signing as the subscriber                              | `LocalWallet` (key in memory)    |
| `Store`        | Keeping identity, sign-ins and permissions across runs | `FileStore`, `MemoryStore`       |
| `TrafficMeter` | Counting a session's bytes                             | any `Fn() -> Traffic`            |
| `TimeSource`   | The time, if the device's clock cannot be trusted      | `SystemTime`                     |

`Store` values are marked secret or not; put secret ones where your platform keeps secrets.

## Trust

- **The RPC endpoint is yours to choose.** Everything the client learns about the network comes through it; never use one a Control Plane suggests.
- **A node's answer is checked against the chain.** The credentials a Control Plane relays are signed by the node's registered signer key; the client verifies that before decrypting them.
- **Wallet signatures are checked before use.** A wallet that signs the wrong thing fails locally, not after a relay.
- **No routing in the SDK.** If calls to a Control Plane must travel through a tunnel or proxy, build the channel yourself and use `ControlPlaneClient::from_channel`.

## Lower level

`Singula` is built from public pieces, which you can use directly: `chain::Chain` for reads, `client::ControlPlaneClient` for single calls to a Control Plane, `zk::{Identity, Group, Prover}` for proofs, and the core types (`SessionKeypair`, `CheckpointKey`, `Checkpoint`, `Renewal`) for the wire formats.

## Minimum supported Rust version

1.87. Raising it is a minor-version change.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md). In short:

```text
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

Tests against the live test network are ignored by default:

```text
SINGULA_RPC_URL=https://… cargo test --all-features -- --ignored
```

## Security

Please report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. Third-party material bundled with the crate is listed in [NOTICE](NOTICE).

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this crate by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
