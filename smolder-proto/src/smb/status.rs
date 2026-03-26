//! NTSTATUS values used by the SMB client.

/// A 32-bit NTSTATUS code carried in SMB headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NtStatus(pub u32);

impl NtStatus {
    /// `STATUS_SUCCESS`
    pub const SUCCESS: Self = Self(0x0000_0000);
    /// `STATUS_PENDING`
    pub const PENDING: Self = Self(0x0000_0103);
    /// `STATUS_MORE_PROCESSING_REQUIRED`
    pub const MORE_PROCESSING_REQUIRED: Self = Self(0xc000_0016);
    /// `STATUS_NO_MORE_FILES`
    pub const NO_MORE_FILES: Self = Self(0x8000_0006);
    /// `STATUS_END_OF_FILE`
    pub const END_OF_FILE: Self = Self(0xc000_0011);
    /// `STATUS_OBJECT_NAME_NOT_FOUND`
    pub const OBJECT_NAME_NOT_FOUND: Self = Self(0xc000_0034);
    /// `STATUS_OBJECT_PATH_NOT_FOUND`
    pub const OBJECT_PATH_NOT_FOUND: Self = Self(0xc000_003a);
    /// `STATUS_OBJECT_NAME_COLLISION`
    pub const OBJECT_NAME_COLLISION: Self = Self(0xc000_0035);
    /// `STATUS_ACCESS_DENIED`
    pub const ACCESS_DENIED: Self = Self(0xc000_0022);
    /// `STATUS_LOGON_FAILURE`
    pub const LOGON_FAILURE: Self = Self(0xc000_006d);
    /// `STATUS_INVALID_NETWORK_RESPONSE`
    pub const INVALID_NETWORK_RESPONSE: Self = Self(0xc000_00c3);
    /// `STATUS_PIPE_NOT_AVAILABLE`
    pub const PIPE_NOT_AVAILABLE: Self = Self(0xc000_00ac);

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
