//! The wire types, generated from `proto/` by `tools/codegen`.

#![allow(
    missing_docs,
    dead_code,
    unreachable_pub,
    clippy::pedantic,
    clippy::all,
    reason = "generated code: documented in the .proto files, and not every message is used"
)]

pub(crate) mod client {
    include!("proto/singula.client.v1.rs");
}

pub(crate) mod node {
    include!("proto/singula.node.v1.rs");
}

pub(crate) mod admin {
    include!("proto/singula.admin.v1.rs");
}

/// Server stubs, for the SDK's own tests.
#[cfg(test)]
pub(crate) mod server {
    pub(crate) mod client {
        include!("proto/server/singula.client.v1.rs");
    }

    pub(crate) mod admin {
        include!("proto/server/singula.admin.v1.rs");
    }
}
