//! Minimal, crate-local type machinery used by the bounded GSS wrapper.
//!
//! Keeping these marker types local avoids making the published Kerberos feature depend on a
//! workspace-only patch or on an otherwise unnecessary wrapper crate.

/// GSS mechanism selected for credential acquisition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mechanism {
    /// Kerberos V5.
    KerberosV5,
}

/// Credential-usage marker types.
pub mod usage {
    /// Credentials usable for initiating a context.
    pub struct Outbound;

    /// Marker for credentials that may initiate a context.
    pub trait OutboundUsable {}
    impl OutboundUsable for Outbound {}
}

/// Requested GSS context capabilities.
#[derive(Debug, Clone, Copy, Default)]
pub struct CapabilityFlags(u8);

impl CapabilityFlags {
    pub const MUTUAL_AUTH: Self = Self(1 << 0);
    pub const INTEGRITY: Self = Self(1 << 1);
    pub fn add_flag(&mut self, flags: Self) {
        self.0 |= flags.0;
    }

    pub const fn contains_all(self, flags: Self) -> bool {
        self.0 & flags.0 == flags.0
    }
}

/// GSS context capability typestates.
pub mod typestate {
    pub struct MaybeSigning;
    pub struct MaybeEncryption;
    pub struct MaybeDelegation;
}
