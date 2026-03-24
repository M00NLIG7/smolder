//! Shared protocol errors.

use thiserror::Error;

/// Errors returned when encoding or decoding SMB packets.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    /// The provided buffer ended before the field could be read.
    #[error("unexpected end of buffer while reading {field}")]
    UnexpectedEof {
        /// The field that could not be fully read.
        field: &'static str,
    },
    /// A fixed field or offset did not satisfy the protocol contract.
    #[error("invalid field {field}: {reason}")]
    InvalidField {
        /// The field name.
        field: &'static str,
        /// The reason it is invalid.
        reason: &'static str,
    },
    /// A packet exceeded a size limit enforced by the protocol.
    #[error("size limit exceeded for {field}")]
    SizeLimitExceeded {
        /// The field name.
        field: &'static str,
    },
}
