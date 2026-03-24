//! Smolder core crate
//!
//! Copyright (c) 2025 M00NLIG7

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod client;
pub mod error;
pub mod prelude {
    //! Common types and traits

    pub use crate::client::{Authenticated, Connected, Connection, Negotiated, TreeConnected};
    pub use crate::error::CoreError;
    pub use crate::transport::{TokioTcpTransport, Transport};
}

pub mod transport;
