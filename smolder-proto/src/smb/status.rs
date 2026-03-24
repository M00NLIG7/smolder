//! NTSTATUS values used by the SMB client.

/// A 32-bit NTSTATUS code carried in SMB headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NtStatus(pub u32);

impl NtStatus {
    /// `STATUS_SUCCESS`
    pub const SUCCESS: Self = Self(0x0000_0000);
    /// `STATUS_MORE_PROCESSING_REQUIRED`
    pub const MORE_PROCESSING_REQUIRED: Self = Self(0xc000_0016);
    /// `STATUS_LOGON_FAILURE`
    pub const LOGON_FAILURE: Self = Self(0xc000_006d);
    /// `STATUS_INVALID_NETWORK_RESPONSE`
    pub const INVALID_NETWORK_RESPONSE: Self = Self(0xc000_00c3);

    /// Returns the raw `u32` status code.
    #[must_use]
    pub const fn to_u32(self) -> u32 {
        self.0
    }

    /// Returns true when the status represents success.
    #[must_use]
    pub const fn is_success(self) -> bool {
        self.0 == Self::SUCCESS.0
    }
}

impl From<u32> for NtStatus {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<NtStatus> for u32 {
    fn from(value: NtStatus) -> Self {
        value.0
    }
}
