//! Local security, resource, and deadline policy for SMB connections.

use std::time::Duration;

use smolder_proto::smb::smb2::Dialect;

/// Whether credentialed authentication may fall back to a guest or null SMB session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestFallbackPolicy {
    /// Reject guest and null sessions after credentialed authentication.
    Deny,
    /// Allow an endpoint to establish a guest/null session.
    ///
    /// This is an interoperability escape hatch for generic-library consumers. It must not be
    /// combined with a policy that requires signing or SMB encryption, because guest/null sessions
    /// generally do not establish the keys needed to satisfy those requirements.
    Allow,
}

/// Confidentiality required by local policy after authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfidentialityPolicy {
    /// Use SMB encryption when required by the server or share.
    Opportunistic,
    /// Require SMB 3.x encryption for every post-authentication SMB request.
    RequireSmbEncryption,
    /// Require SMB encryption unless the physical transport is authenticated SMB over QUIC.
    RequireEncryptionOrAuthenticatedQuic,
}

/// Security invariants enforced independently of server-selected negotiation values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityPolicy {
    minimum_dialect: Dialect,
    require_signing: bool,
    confidentiality: ConfidentialityPolicy,
    guest_fallback: GuestFallbackPolicy,
}

impl SecurityPolicy {
    /// Returns a low-level interoperability policy for callers constructing raw typestate flows.
    ///
    /// Guest/null fallback remains denied. Credentialed high-level constructors use
    /// [`SecurityPolicy::credentialed`] instead.
    #[must_use]
    pub const fn interoperable() -> Self {
        Self {
            minimum_dialect: Dialect::Smb210,
            require_signing: false,
            confidentiality: ConfidentialityPolicy::Opportunistic,
            guest_fallback: GuestFallbackPolicy::Deny,
        }
    }

    /// Returns the default policy for a credentialed reusable-library session.
    ///
    /// The default requires signing and rejects guest/null fallback while retaining SMB 2.1 and
    /// opportunistic encryption for compatibility. Call [`SecurityPolicy::pandora`] for the strict
    /// static-boundary profile.
    #[must_use]
    pub const fn credentialed() -> Self {
        Self {
            minimum_dialect: Dialect::Smb210,
            require_signing: true,
            confidentiality: ConfidentialityPolicy::Opportunistic,
            guest_fallback: GuestFallbackPolicy::Deny,
        }
    }

    /// Returns Pandora's strict SMB boundary policy.
    ///
    /// This profile requires SMB 3.1.1, signing, SMB encryption or an authenticated QUIC
    /// transport, and rejects guest/null fallback.
    #[must_use]
    pub const fn pandora() -> Self {
        Self {
            minimum_dialect: Dialect::Smb311,
            require_signing: true,
            confidentiality: ConfidentialityPolicy::RequireEncryptionOrAuthenticatedQuic,
            guest_fallback: GuestFallbackPolicy::Deny,
        }
    }

    /// Replaces the minimum acceptable negotiated dialect.
    #[must_use]
    pub const fn with_minimum_dialect(mut self, dialect: Dialect) -> Self {
        self.minimum_dialect = dialect;
        self
    }

    /// Enables or disables the local signing requirement.
    #[must_use]
    pub const fn with_required_signing(mut self, required: bool) -> Self {
        self.require_signing = required;
        self
    }

    /// Replaces the local confidentiality requirement.
    #[must_use]
    pub const fn with_confidentiality(mut self, confidentiality: ConfidentialityPolicy) -> Self {
        self.confidentiality = confidentiality;
        self
    }

    /// Replaces the guest/null fallback policy.
    #[must_use]
    pub const fn with_guest_fallback(mut self, guest_fallback: GuestFallbackPolicy) -> Self {
        self.guest_fallback = guest_fallback;
        self
    }

    /// Returns the minimum acceptable SMB dialect.
    #[must_use]
    pub const fn minimum_dialect(self) -> Dialect {
        self.minimum_dialect
    }

    /// Returns whether signing is required locally.
    #[must_use]
    pub const fn signing_required(self) -> bool {
        self.require_signing
    }

    /// Returns the configured confidentiality policy.
    #[must_use]
    pub const fn confidentiality(self) -> ConfidentialityPolicy {
        self.confidentiality
    }

    /// Returns the configured guest/null fallback policy.
    #[must_use]
    pub const fn guest_fallback(self) -> GuestFallbackPolicy {
        self.guest_fallback
    }
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self::interoperable()
    }
}

/// Explicit limits for data sizes and counts controlled by a remote SMB/RPC endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceLimits {
    /// Largest accepted framed SMB transport message.
    pub max_transport_message: usize,
    /// Largest result returned by a whole-file convenience helper.
    pub max_whole_file_size: u64,
    /// Largest authentication token accepted from a provider or remote endpoint.
    pub max_authentication_token_size: usize,
    /// Largest authentication mechanism key accepted from a provider.
    pub max_authentication_key_size: usize,
    /// Largest aggregate DCE/RPC response stub.
    pub max_rpc_stub_size: usize,
    /// Largest number of pages accepted from one RPC enumeration.
    pub max_rpc_pages: usize,
    /// Largest number of entries accepted from one NDR collection or aggregate enumeration.
    pub max_ndr_entries: usize,
    /// Largest UTF-16 code-unit count accepted from one NDR string.
    pub max_ndr_string_units: usize,
    /// Largest number of pages accepted from one SMB directory enumeration.
    pub max_directory_pages: usize,
    /// Largest aggregate entry count accepted from one SMB directory enumeration.
    pub max_directory_entries: usize,
    /// Largest newline-delimited control record accepted from a named pipe.
    pub max_control_line_size: usize,
    /// Largest SMB credit balance accepted from a server.
    pub max_credits: u32,
}

impl ResourceLimits {
    /// Conservative defaults for general embedded use.
    #[must_use]
    pub const fn conservative() -> Self {
        Self {
            max_transport_message: 16 * 1024 * 1024,
            max_whole_file_size: 64 * 1024 * 1024,
            max_authentication_token_size: 1024 * 1024,
            max_authentication_key_size: 1024 * 1024,
            max_rpc_stub_size: 16 * 1024 * 1024,
            max_rpc_pages: 1_024,
            max_ndr_entries: 1_000_000,
            max_ndr_string_units: 1_048_576,
            max_directory_pages: 1_024,
            max_directory_entries: 1_000_000,
            max_control_line_size: 1024 * 1024,
            max_credits: 8_192,
        }
    }
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self::conservative()
    }
}

/// Internal connect and request deadlines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperationTimeouts {
    /// Deadline for opening the underlying transport.
    pub connect: Duration,
    /// End-to-end deadline for one SMB request write and its complete correlated response flow.
    pub request: Duration,
}

impl OperationTimeouts {
    /// Bounded defaults suitable for non-interactive library use.
    #[must_use]
    pub const fn bounded() -> Self {
        Self {
            connect: Duration::from_secs(30),
            request: Duration::from_secs(30),
        }
    }
}

impl Default for OperationTimeouts {
    fn default() -> Self {
        Self::bounded()
    }
}

pub(crate) const fn dialect_rank(dialect: Dialect) -> u16 {
    dialect as u16
}

#[cfg(test)]
mod tests {
    use super::{ConfidentialityPolicy, GuestFallbackPolicy, SecurityPolicy};
    use smolder_proto::smb::smb2::Dialect;

    #[test]
    fn pandora_policy_encodes_required_security_values() {
        let policy = SecurityPolicy::pandora();
        assert_eq!(policy.minimum_dialect(), Dialect::Smb311);
        assert!(policy.signing_required());
        assert_eq!(
            policy.confidentiality(),
            ConfidentialityPolicy::RequireEncryptionOrAuthenticatedQuic
        );
        assert_eq!(policy.guest_fallback(), GuestFallbackPolicy::Deny);
    }

    #[test]
    fn credentialed_default_requires_signing_and_denies_guest() {
        let policy = SecurityPolicy::credentialed();
        assert!(policy.signing_required());
        assert_eq!(policy.guest_fallback(), GuestFallbackPolicy::Deny);
    }
}
