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
//! - NTLM/SPNEGO authentication primitives, with optional Kerberos support
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
//! # Public API Tiers
//!
//! The intended entry points for most consumers are:
//!
//! - [`client::Connection`] plus its typestate markers for negotiate, session,
//!   tree, and file operations
//! - [`pipe::SmbSessionConfig`], [`pipe::connect_tree`], and
//!   [`pipe::NamedPipe`] for `IPC$` and named-pipe transport
//! - [`rpc::PipeRpcClient`] for reusable DCE/RPC over SMB named pipes
//! - [`auth`] credential/authenticator types and [`error::CoreError`]
//! - [`transport::Transport`] when embedding the client over a custom transport
//!
//! Lower-level signing, preauth, and raw crypto helpers remain available for
//! expert users, but they are not the recommended starting surface. The repo's
//! API audit notes are in
//! [docs/reference/smolder-core-api.md](/Users/cmagana/Projects/smolder/docs/reference/smolder-core-api.md).
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
    //! Curated imports for the intended `smolder_core` entry points.
    //!
    //! Prefer this module when you want the supported high-level primitives
    //! without pulling in every expert-only module directly.

    pub use crate::auth::{
        AuthProvider, NtlmAuthenticator, NtlmCredentials, NtlmRpcPacketIntegrity,
        NtlmSessionSecurity,
    };
    #[cfg(feature = "kerberos-api")]
    pub use crate::auth::{
        KerberosAuthenticator, KerberosBackendKind, KerberosCredentialSourceKind,
        KerberosCredentials, KerberosTarget,
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
