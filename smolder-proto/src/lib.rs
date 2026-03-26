//! Typed SMB2/3 and DCE/RPC wire codecs for Smolder.
//!
//! `smolder-proto` is the lowest layer in the Smolder workspace. It provides
//! packet structures, framing helpers, codec logic, and validation primitives
//! without taking on transport, session, or operator workflow concerns.
//!
//! Crate layout:
//!
//! - [`smb`]: SMB2/3 headers, request/response bodies, negotiate contexts,
//!   create contexts, transform headers, status codes, and framing helpers.
//! - [`rpc`]: DCE/RPC packet types, bind/request/response PDUs, and auth
//!   trailer codecs used on top of SMB named pipes.
//! - [`prelude`]: lightweight common exports for callers that want a smaller
//!   import surface.
//!
//! Higher layers live in:
//!
//! - `smolder-smb-core`: transport, auth/session, signing, encryption, named
//!   pipes, and RPC primitives
//! - `smolder`: high-level file APIs, remote execution, and CLI workflows
//!
//! Copyright (c) 2025 M00NLIG7

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod prelude {
    //! Common types and traits
}

/// RPC protocol modules.
pub mod rpc;

/// SMB protocol modules.
pub mod smb;
