//! Protocol and transport primitives for Smolder.
//!
//! The published package name is `smolder-smb-core`, while the Rust library
//! crate name remains `smolder_core`.
//!
//! It owns SMB auth/session state, request dispatch, and transport logic.
//! High-level SMB file facades, execution flows, and other operator workflows
//! belong in the `smolder` package, not this crate.
//!
//! Copyright (c) 2025 M00NLIG7

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod auth;
pub mod client;
pub mod crypto;
pub mod dfs;
pub mod error;
pub mod pipe;
pub mod rpc;
pub mod prelude {
    //! Common types and traits

    pub use crate::auth::{
        AuthProvider, NtlmAuthenticator, NtlmCredentials, NtlmRpcPacketIntegrity,
        NtlmSessionSecurity,
    };
    pub use crate::client::{
        Authenticated, CompoundRequest, CompoundResponse, Connected, Connection, DurableHandle,
        DurableOpenOptions, Negotiated, ResilientHandle, TreeConnected,
    };
    pub use crate::crypto::{derive_encryption_keys, EncryptionKeys};
    pub use crate::dfs::{resolve_unc_path, DfsReferral, UncPath};
    pub use crate::error::CoreError;
    pub use crate::pipe::{connect_tree, NamedPipe, PipeAccess, SmbSessionConfig};
    pub use crate::rpc::PipeRpcClient;
    pub use crate::transport::{TokioTcpTransport, Transport};
}

pub mod transport;
