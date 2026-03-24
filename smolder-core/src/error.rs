//! Errors returned by the core client/session layer.

use smolder_proto::smb::smb2::Command;
use smolder_proto::smb::ProtocolError;
use thiserror::Error;

/// Errors returned while driving SMB requests over a transport.
#[derive(Debug, Error)]
pub enum CoreError {
    /// The transport returned an I/O failure.
    #[error("transport error")]
    Io(#[from] std::io::Error),
    /// Packet encoding or decoding failed.
    #[error("protocol error")]
    Protocol(#[from] ProtocolError),
    /// The server responded with a different command than expected.
    #[error("unexpected response command: expected {expected:?}, got {actual:?}")]
    UnexpectedCommand {
        /// The command that was sent.
        expected: Command,
        /// The command returned by the peer.
        actual: Command,
    },
    /// The server returned a status code that the caller did not allow.
    #[error("unexpected status code 0x{status:08x} for {command:?}")]
    UnexpectedStatus {
        /// The command being processed.
        command: Command,
        /// The returned NTSTATUS value.
        status: u32,
    },
    /// The response was structurally valid but semantically unusable.
    #[error("invalid response: {0}")]
    InvalidResponse(&'static str),
}
