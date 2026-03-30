//! Protocol and transport primitives for Smolder.
//!
//! The published package name is `smolder-smb-core`, while the Rust library
//! crate name remains `smolder_core`.
//!
//! # Feature Flags
//!
//! The supported cargo features are:
//!
//! - `kerberos`: stable public Kerberos API plus the current password-backed
//!   backend
//! - `kerberos-sspi`: backend-only flag for the current password-backed
//!   Kerberos implementation
//! - `kerberos-gssapi`: Unix ticket-cache and keytab backend using system
//!   GSS/Kerberos libraries
//!
//! The default build enables none of these features and stays the most
//! static-friendly profile. `kerberos-gssapi` is intentionally independent from
//! `kerberos-sspi`, so enabling Unix GSS credential-store support does not also
//! pull in the SSPI backend.
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
//! Use `smolder_core` when you want typed SMB/RPC client primitives or the new
//! embedded-client facade in [`facade`]. If you want operator-facing workflows
//! such as `smbexec` and `psexec`, use the `smolder` package instead.
//!
//! # Start here
//!
//! The fastest supported entry points are:
//!
//! - `cargo run -p smolder-smb-core --example client_session_connect`
//! - `cargo run -p smolder-smb-core --example client_file_roundtrip`
//! - `cargo run -p smolder-smb-core --example ntlm_tree_connect`
//! - `cargo run -p smolder-smb-core --example named_pipe_rpc_bind`
//! - `cargo run -p smolder-smb-core --features kerberos --example kerberos_tree_connect`
//!
//! Supporting project docs:
//!
//! - [docs/guide/examples.md](/Users/cmagana/Projects/smolder/docs/guide/examples.md)
//! - [docs/guide/cookbook.md](/Users/cmagana/Projects/smolder/docs/guide/cookbook.md)
//! - [docs/reference/support-policy.md](/Users/cmagana/Projects/smolder/docs/reference/support-policy.md)
//! - [docs/reference/versioning-policy.md](/Users/cmagana/Projects/smolder/docs/reference/versioning-policy.md)
//!
//! # Public API Tiers
//!
//! The intended entry points for most consumers are:
//!
//! - [`facade::Client`] and [`facade::ClientBuilder`] for embedded client usage
//! - [`facade::Session`], [`facade::Share`], [`facade::File`], and
//!   [`facade::OpenOptions`] for authenticated-session, share, and file flows
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

#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod auth;
pub mod client;
pub mod compression;
pub mod crypto;
pub mod dfs;
pub mod error;
pub mod facade;
pub mod pipe;
pub mod rpc;
pub mod samr;
pub mod srvsvc;
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
    #[cfg_attr(
        docsrs,
        doc(cfg(any(feature = "kerberos", feature = "kerberos-gssapi")))
    )]
    pub use crate::auth::{
        KerberosAuthenticator, KerberosBackendKind, KerberosCredentialSourceKind,
        KerberosCredentials, KerberosTarget,
    };
    pub use crate::client::{
        Authenticated, CompoundRequest, CompoundResponse, Connected, Connection, DurableHandle,
        DurableOpenOptions, Negotiated, ResilientHandle, TreeConnected,
    };
    pub use crate::compression::CompressionState;
    pub use crate::crypto::{derive_encryption_keys, EncryptionKeys};
    pub use crate::dfs::{resolve_unc_path, DfsReferral, UncPath};
    pub use crate::error::CoreError;
    pub use crate::facade::{
        Client, ClientBuilder, File, FileMetadata, OpenOptions, Session, Share,
    };
    pub use crate::pipe::{connect_session, connect_tree, NamedPipe, PipeAccess, SmbSessionConfig};
    pub use crate::rpc::PipeRpcClient;
    pub use crate::samr::{SamrClient, SamrDomain, SamrServerRevision, DEFAULT_SERVER_ACCESS};
    pub use crate::srvsvc::{ShareInfo1, ShareInfo2, SrvsvcClient, TimeOfDayInfo};
    pub use crate::transport::{TokioTcpTransport, Transport};
}

pub mod transport;
