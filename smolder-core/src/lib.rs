//! Protocol and transport primitives for Smolder.
//!
//! `smolder-core` is the reusable library layer. It owns SMB auth/session
//! state, share/file primitives, and transport logic. High-level execution or
//! operator workflows belong in `smolder-tools`, not this crate.
//!
//! Copyright (c) 2025 M00NLIG7

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod auth;
pub mod client;
pub mod error;
pub mod fs;
pub mod prelude {
    //! Common types and traits

    pub use crate::auth::{AuthProvider, NtlmAuthenticator, NtlmCredentials};
    pub use crate::client::{Authenticated, Connected, Connection, Negotiated, TreeConnected};
    pub use crate::error::CoreError;
    pub use crate::fs::{
        Lease, LeaseRequest, OpenOptions, RemoteFile, Share, SmbClient, SmbClientBuilder,
        SmbDirectoryEntry, SmbMetadata,
    };
    pub use crate::transport::{TokioTcpTransport, Transport};
}

pub mod transport;
