use std::{fmt::Display, num::NonZero};

use super::ffi::{
    gss_buffer_desc_struct, gss_display_status, gss_release_buffer, GSS_C_GSS_CODE, GSS_C_MECH_CODE,
};

const MAX_STATUS_TEXT_LENGTH: usize = 1_048_576;

#[derive(Clone, Copy, Debug)]
pub struct MechanismErrorCode(NonZero<u32>);
impl MechanismErrorCode {
    pub fn new(value: u32) -> Option<Self> {
        NonZero::new(value).map(Self)
    }
}
impl Display for MechanismErrorCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write_from_u32(self.0.into(), GSS_C_MECH_CODE, formatter)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct GssErrorCode(NonZero<u32>);
impl GssErrorCode {
    pub fn new(value: u32) -> Option<Self> {
        NonZero::new(value).map(Self)
    }
}
impl Display for GssErrorCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write_from_u32(self.0.into(), GSS_C_GSS_CODE, formatter)
    }
}

fn write_from_u32(
    value: u32,
    mechanism: i32,
    formatter: &mut std::fmt::Formatter<'_>,
) -> std::fmt::Result {
    let mut minor_status = 0;
    let mut more = 0;
    let mut buffer = gss_buffer_desc_struct {
        length: 0,
        value: std::ptr::null_mut(),
    };
    // SAFETY: all scalar inputs are initialized and `buffer` is a valid out descriptor.
    unsafe {
        gss_display_status(
            &mut minor_status,
            value,
            mechanism,
            std::ptr::null_mut(),
            &mut more,
            &mut buffer,
        )
    };
    if buffer.value.is_null() || buffer.length > MAX_STATUS_TEXT_LENGTH {
        release_buffer(&mut buffer);
        return formatter.write_str("GSS provider returned no bounded status text");
    }

    // SAFETY: the provider returned a non-null buffer and its length is explicitly bounded.
    let bytes = unsafe { std::slice::from_raw_parts(buffer.value.cast::<u8>(), buffer.length) };
    let mut owned = Vec::new();
    if owned.try_reserve_exact(bytes.len()).is_err() {
        release_buffer(&mut buffer);
        return Err(std::fmt::Error);
    }
    owned.extend_from_slice(bytes);
    release_buffer(&mut buffer);
    let text = std::str::from_utf8(&owned).map_err(|_| std::fmt::Error)?;
    formatter.write_str(text)
}

fn release_buffer(buffer: &mut gss_buffer_desc_struct) {
    if buffer.value.is_null() {
        return;
    }
    let mut minor = 0;
    // SAFETY: the provider transferred this output buffer to the caller.
    unsafe { gss_release_buffer(&mut minor, buffer) };
}

#[derive(Clone, Copy, Debug)]
pub enum Error {
    Gss(GssErrorCode),
    Mechanism(MechanismErrorCode),
}
impl Error {
    pub(crate) fn gss(value: u32) -> Option<Self> {
        GssErrorCode::new(value).map(Self::Gss)
    }
    pub(crate) fn mechanism(value: u32) -> Option<Self> {
        MechanismErrorCode::new(value).map(Self::Mechanism)
    }
}
impl std::error::Error for Error {}
impl Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Gss(gss) => gss.fmt(formatter),
            Self::Mechanism(mechanism) => mechanism.fmt(formatter),
        }
    }
}
impl From<GssErrorCode> for Error {
    fn from(value: GssErrorCode) -> Self {
        Self::Gss(value)
    }
}
impl From<MechanismErrorCode> for Error {
    fn from(value: MechanismErrorCode) -> Self {
        Self::Mechanism(value)
    }
}
