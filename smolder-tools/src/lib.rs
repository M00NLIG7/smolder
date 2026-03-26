//! High-level tools and integrations built on top of Smolder primitives.
//!
//! `smolder-tools` owns ergonomic SMB file APIs, remote execution, and CLI
//! integrations. It depends on `smolder-core` for SMB/RPC primitives rather
//! than extending the core crate with tool-specific behavior.
//!
//! Copyright (c) 2025 M00NLIG7

#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[doc(hidden)]
pub use smolder_core::{auth, client, error, transport};

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
