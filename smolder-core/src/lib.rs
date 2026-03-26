//! Protocol and transport primitives for Smolder.
//!
//! `smolder-core` is the reusable library layer. It owns SMB auth/session
//! state, request dispatch, and transport logic. High-level SMB file facades,
//! execution flows, and other operator workflows belong in `smolder-tools`,
//! not this crate.
//!
//! Copyright (c) 2025 M00NLIG7

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod auth;
pub mod client;
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
        Authenticated, CompoundRequest, CompoundResponse, Connected, Connection, Negotiated,
        TreeConnected,
    };
    pub use crate::error::CoreError;
    pub use crate::pipe::{connect_tree, NamedPipe, PipeAccess, SmbSessionConfig};
    pub use crate::rpc::PipeRpcClient;
    pub use crate::transport::{TokioTcpTransport, Transport};
}

pub mod transport;
