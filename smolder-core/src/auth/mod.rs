//! Authentication providers and protocol helpers.

#[cfg(all(unix, feature = "kerberos-gssapi"))]
#[allow(unsafe_code)]
mod kenobi_unix;
#[cfg(any(feature = "kerberos-sspi", feature = "kerberos-gssapi"))]
mod kerberos;
#[cfg(all(unix, feature = "kerberos-gssapi"))]
mod kerberos_gssapi;
#[cfg(any(feature = "kerberos-sspi", feature = "kerberos-gssapi"))]
mod kerberos_spn;
#[cfg(all(windows, feature = "kerberos-sspi"))]
#[allow(unsafe_code)]
mod kerberos_sspi;
mod ntlm;
mod ntlm_rpc;
mod ntlm_rpc_bind;
mod spnego;

use smolder_proto::smb::smb2::NegotiateResponse;
use thiserror::Error;

#[cfg(any(feature = "kerberos-sspi", feature = "kerberos-gssapi"))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(
        feature = "kerberos",
        feature = "kerberos-sspi",
        feature = "kerberos-gssapi"
    )))
)]
pub use kerberos::{
    KerberosAuthenticator, KerberosBackendKind, KerberosCredentialSourceKind, KerberosCredentials,
};
#[cfg(any(feature = "kerberos-sspi", feature = "kerberos-gssapi"))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(
        feature = "kerberos",
        feature = "kerberos-sspi",
        feature = "kerberos-gssapi"
    )))
)]
pub use kerberos_spn::KerberosTarget;
pub use ntlm::{NtlmAuthenticator, NtlmCredentials};
pub use ntlm_rpc::{NtlmRpcPacketIntegrity, NtlmSessionSecurity};
pub(crate) use ntlm_rpc_bind::NtlmRpcBindHandshake;

#[cfg(all(
    any(feature = "kerberos-sspi", feature = "kerberos-gssapi"),
    not(any(
        all(windows, feature = "kerberos-sspi"),
        all(unix, feature = "kerberos-gssapi")
    ))
))]
compile_error!("Kerberos requires kerberos-sspi on Windows or kerberos-gssapi on Unix");

/// SPNEGO mechanism identifiers supported by Smolder authentication helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SpnegoMechanism {
    /// Microsoft NTLM.
    Ntlm,
    /// Kerberos V5.
    KerberosV5,
}

/// Authentication errors returned while processing GSS/NTLM tokens.
#[derive(Debug, Error)]
pub enum AuthError {
    /// A token was malformed or violated the expected protocol flow.
    #[error("invalid authentication token: {0}")]
    InvalidToken(&'static str),
    /// The provider was called in an invalid state.
    #[error("invalid authentication state: {0}")]
    InvalidState(&'static str),
    /// The underlying authentication backend returned an error.
    #[error("authentication backend error: {0}")]
    Backend(String),
}

/// Drives a GSS-style authentication exchange for SMB `SESSION_SETUP`.
pub trait AuthProvider {
    /// Produces the first security token sent in the initial `SESSION_SETUP`.
    fn initial_token(&mut self, negotiate: &NegotiateResponse) -> Result<Vec<u8>, AuthError>;

    /// Processes a server security token and returns the next client token.
    fn next_token(&mut self, incoming: &[u8]) -> Result<Vec<u8>, AuthError>;

    /// Validates any final token returned by the server once authentication succeeds.
    ///
    /// The conservative default accepts only an empty final token. Providers whose mechanism can
    /// carry a final server token must override this method and validate that token explicitly.
    fn finish(&mut self, incoming: &[u8]) -> Result<(), AuthError> {
        if incoming.is_empty() {
            Ok(())
        } else {
            Err(AuthError::InvalidToken(
                "authentication provider did not validate the final server token",
            ))
        }
    }

    /// Returns the exported session key, if the mechanism established one.
    fn session_key(&self) -> Option<&[u8]> {
        None
    }
}
