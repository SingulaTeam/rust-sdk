//! Regenerates `src/client/proto/` from the files in `proto/`.
//!
//! The generated code is checked in, so building the SDK needs neither this
//! tool nor `protoc`. Run it after changing the proto, from the repository
//! root:
//!
//! ```text
//! cargo run --manifest-path tools/codegen/Cargo.toml
//! ```

use std::error::Error;

const PROTOS: [&str; 3] = ["client.proto", "credentials.proto", "health.proto"];

fn main() -> Result<(), Box<dyn Error>> {
    // protox compiles the proto in pure Rust, so no protoc is needed here either.
    let descriptors = protox::compile(PROTOS, ["proto"])?;

    // The SDK's client: messages and client stubs.
    tonic_prost_build::configure()
        .build_server(false)
        // The service has an rpc named `Connect`, which would collide with the
        // generated `connect` constructor; channels are built by the SDK anyway.
        .build_transport(false)
        .out_dir("src/client/proto")
        .compile_fds(descriptors.clone())?;

    // Server stubs for the SDK's own tests, which stand up a Control Plane.
    // The messages are the client's, so only the services are generated.
    tonic_prost_build::configure()
        .build_client(false)
        .extern_path(".singula.client.v1", "crate::client::proto::client")
        .extern_path(".singula.admin.v1", "crate::client::proto::admin")
        .extern_path(".singula.node.v1", "crate::client::proto::node")
        .out_dir("src/client/proto/server")
        .compile_fds(descriptors)?;
    Ok(())
}
