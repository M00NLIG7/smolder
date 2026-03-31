//! High-level tools and integrations built on top of Smolder primitives.
//!
//! The published package name is `smolder`, while the Rust library crate name
//! remains `smolder_tools`.
//!
//! It owns ergonomic SMB file APIs, remote execution, and CLI integrations. It
//! depends on the `smolder-smb-core` package for SMB/RPC primitives rather than
//! extending the core crate with tool-specific behavior, and its session setup
//! now rides on the core client facade instead of duplicating negotiate/auth
//! orchestration.
//!
//! # Feature Flags
//!
//! The main optional feature is:
//!
//! - `kerberos`: enables Kerberos-capable high-level workflows and re-exports
//!   the Kerberos auth types from `smolder-smb-core`
//!
//! This crate is the right entry point when you want:
//!
//! - a higher-level SMB client builder and share/file API
//! - DFS-aware path handling and reconnect helpers
//! - operator workflows such as `smbexec` and `psexec`
//! - the standalone Smolder CLI binaries plus the `smolder` compatibility wrapper
//!
//! Lower-level protocol and transport pieces remain in the `smolder-smb-core`
//! and `smolder-proto` packages.
//!
//! The most common public types are re-exported in [`prelude`].
//!
//! # Start here
//!
//! The fastest supported entry points are:
//!
//! - `cargo run -p smolder --example file_roundtrip`
//! - `cargo run -p smolder --features kerberos --example kerberos_share_list`
//! - `cargo run -p smolder --example interactive_psexec`
//!
//! Supporting project docs:
//!
//! - <https://github.com/M00NLIG7/smolder/blob/main/docs/guide/examples.md>
//! - <https://github.com/M00NLIG7/smolder/blob/main/docs/guide/cookbook.md>
//! - <https://github.com/M00NLIG7/smolder/blob/main/docs/reference/support-policy.md>
//! - <https://github.com/M00NLIG7/smolder/blob/main/docs/reference/versioning-policy.md>
//!
//! Copyright (c) 2025 M00NLIG7

#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod cli;
pub mod fs;
pub mod reconnect;
pub mod remote_exec;
pub mod prelude {
    //! Common types and traits

    pub use crate::fs::{
        Lease, LeaseRequest, OpenOptions, RemoteFile, Share, SmbClient, SmbClientBuilder,
        SmbDirectoryEntry, SmbMetadata,
    };
    pub use crate::reconnect::ShareReconnectPlan;
    pub use crate::remote_exec::{
        ExecMode, ExecRequest, ExecResult, InteractiveReader, InteractiveSession, InteractiveStdin,
        InteractiveWaiter, RemoteExecBuilder, RemoteExecClient,
    };
    pub use smolder_core::prelude::{
        DurableHandle, DurableOpenOptions, NtlmCredentials, ResilientHandle,
    };
    #[cfg(feature = "kerberos")]
    #[cfg_attr(docsrs, doc(cfg(feature = "kerberos")))]
    pub use smolder_core::prelude::{
        KerberosBackendKind, KerberosCredentialSourceKind, KerberosCredentials, KerberosTarget,
    };
}
