//! Authentication providers and protocol helpers.

mod ntlm;
mod ntlm_rpc;
mod spnego;

use smolder_proto::smb::smb2::NegotiateResponse;
use thiserror::Error;

pub use ntlm::{NtlmAuthenticator, NtlmCredentials};
pub use ntlm_rpc::{NtlmRpcPacketIntegrity, NtlmSessionSecurity};

/// Authentication errors returned while processing GSS/NTLM tokens.
#[derive(Debug, Error)]
pub enum AuthError {
    /// A token was malformed or violated the expected protocol flow.
    #[error("invalid authentication token: {0}")]
    InvalidToken(&'static str),
    /// The provider was called in an invalid state.
    #[error("invalid authentication state: {0}")]
    InvalidState(&'static str),
}

/// Drives a GSS-style authentication exchange for SMB `SESSION_SETUP`.
pub trait AuthProvider {
    /// Produces the first security token sent in the initial `SESSION_SETUP`.
    fn initial_token(&mut self, negotiate: &NegotiateResponse) -> Result<Vec<u8>, AuthError>;

    /// Processes a server security token and returns the next client token.
    fn next_token(&mut self, incoming: &[u8]) -> Result<Vec<u8>, AuthError>;

    /// Validates any final token returned by the server once authentication succeeds.
    fn finish(&mut self, _incoming: &[u8]) -> Result<(), AuthError> {
        Ok(())
    }

    /// Returns the exported session key, if the mechanism established one.
    fn session_key(&self) -> Option<&[u8]> {
        None
    }
}
