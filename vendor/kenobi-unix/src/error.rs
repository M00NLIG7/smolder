use std::{fmt::Display, num::NonZero};

use libgssapi_sys::{GSS_C_GSS_CODE, GSS_C_MECH_CODE, gss_buffer_desc_struct, gss_display_status, gss_release_buffer};

#[derive(Clone, Copy, Debug)]
pub struct MechanismErrorCode(NonZero<u32>);
impl MechanismErrorCode {
    pub fn new(val: u32) -> Option<Self> {
        NonZero::new(val).map(Self)
    }
}
impl Display for MechanismErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write_from_u32(self.0.into(), GSS_C_MECH_CODE as i32, f)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct GssErrorCode(NonZero<u32>);
impl GssErrorCode {
    pub fn new(val: u32) -> Option<Self> {
        NonZero::new(val).map(Self)
    }
}
impl Display for GssErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write_from_u32(self.0.into(), GSS_C_GSS_CODE as i32, f)
    }
}

fn write_from_u32(val: u32, mechanism: i32, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let mut minor_status = 0;
    let mut more = 0;
    let mut string = gss_buffer_desc_struct {
        length: 0,
        value: std::ptr::null_mut(),
    };
    unsafe {
        gss_display_status(
            &mut minor_status,
            val,
            mechanism,
            std::ptr::null_mut(),
            &mut more,
            &mut string,
        )
    };
    if !string.value.is_null() {
        let bytes = unsafe { std::slice::from_raw_parts(string.value as *const u8, string.length) };
        let string = std::str::from_utf8(bytes).unwrap();
        write!(f, "{string}")?;
    } else {
        write!(f, "")?;
    }
    let mut _s = 0;
    unsafe { gss_release_buffer(&mut _s, &mut string) };
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub enum Error {
    Gss(GssErrorCode),
    Mechanism(MechanismErrorCode),
}
impl Error {
    pub(crate) fn gss(val: u32) -> Option<Self> {
        GssErrorCode::new(val).map(Error::Gss)
    }
    pub(crate) fn mechanism(val: u32) -> Option<Self> {
        MechanismErrorCode::new(val).map(Error::Mechanism)
    }
}
impl std::error::Error for Error {}
impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Gss(gss) => gss.fmt(f),
            Self::Mechanism(mech) => mech.fmt(f),
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
