//! Protocol and transport primitives for Smolder.
//!
//! The published package name is `smolder-smb-core`, while the Rust library
//! crate name remains `smolder_core`.
//!
//! It owns SMB auth/session state, request dispatch, and transport logic.
//! High-level SMB file facades, execution flows, and other operator workflows
//! belong in the `smolder` package, not this crate.
//!
//! This crate is the reusable library layer for:
//!
//! - SMB negotiate, session setup, signing, and encryption
//! - NTLM/SPNEGO authentication primitives
//! - Tree/file operations, compound dispatch, and credit-aware request flow
//! - DFS referral helpers
//! - Named-pipe and DCE/RPC transport on top of SMB
//! - Durable/reconnect and resiliency primitives
//!
//! The most common imports are re-exported in [`prelude`].
//!
//! # Usage model
//!
//! Use `smolder_core` when you want typed SMB/RPC client primitives and are
//! comfortable orchestrating the protocol yourself. If you want a higher-level
//! share/file API or operator-facing workflows such as `smbexec` and `psexec`,
//! use the `smolder` package instead.
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
