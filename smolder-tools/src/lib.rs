//! High-level tools and integrations built on top of Smolder primitives.
//!
//! The published package name is `smolder`, while the Rust library crate name
//! remains `smolder_tools`.
//!
//! It owns ergonomic SMB file APIs, remote execution, and CLI integrations. It
//! depends on the `smolder-smb-core` package for SMB/RPC primitives rather than
//! extending the core crate with tool-specific behavior.
//!
//! This crate is the right entry point when you want:
//!
//! - a higher-level SMB client builder and share/file API
//! - DFS-aware path handling and reconnect helpers
//! - operator workflows such as `smbexec` and `psexec`
//! - the `smolder` CLI binary
//!
//! Lower-level protocol and transport pieces remain in the `smolder-smb-core`
//! and `smolder-proto` packages.
//!
//! The most common public types are re-exported in [`prelude`].
//!
//! Copyright (c) 2025 M00NLIG7

#![forbid(unsafe_code)]
#![warn(missing_docs)]

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
}
