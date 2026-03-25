//! Smolder core crate
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
