use std::{ffi::c_void, fmt::Display, ptr::NonNull};

use super::ffi::{
    gss_OID, gss_OID_desc_struct, gss_buffer_desc_struct, gss_buffer_t, gss_display_name,
    gss_name_struct, gss_release_buffer, gss_release_name, _GSS_S_FAILURE,
};

use crate::auth::kenobi_unix::{
    error::{GssErrorCode, MechanismErrorCode},
    Error,
};

const MAX_DISPLAY_NAME_LENGTH: usize = 1_048_576;

pub struct NameHandle {
    name: NonNull<gss_name_struct>,
}
// Provider-owned name handles deliberately remain !Send and !Sync.
impl NameHandle {
    /// # Safety
    /// `oid` must point to a valid OID descriptor for the duration of the import call.
    pub unsafe fn import(principal: &str, oid: *mut gss_OID_desc_struct) -> Result<Self, Error> {
        // SAFETY: caller supplies the valid OID; principal storage remains live for the call.
        let name = unsafe { import_name(principal, oid)? };
        Ok(Self { name })
    }

    pub fn as_mut(&mut self) -> *mut gss_name_struct {
        self.name.as_ptr()
    }
}

impl Drop for NameHandle {
    fn drop(&mut self) {
        let mut minor = 0;
        // SAFETY: this wrapper is the sole owner and releases the handle once.
        unsafe { gss_release_name(&mut minor, &mut NonNull::as_ptr(self.name)) };
    }
}

impl Display for NameHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut minor = 0;
        let mut buffer = gss_buffer_desc_struct {
            length: 0,
            value: std::ptr::null_mut(),
        };
        // SAFETY: the name handle is live and `buffer` is a valid out descriptor.
        let major = unsafe {
            gss_display_name(
                &mut minor,
                NonNull::as_ptr(self.name),
                &mut buffer,
                std::ptr::null_mut(),
            )
        };
        if Error::gss(major).is_some() || Error::mechanism(minor).is_some() {
            release_buffer(&mut buffer);
            return Ok(());
        }
        if buffer.value.is_null() || buffer.length > MAX_DISPLAY_NAME_LENGTH {
            release_buffer(&mut buffer);
            return Ok(());
        }
        // SAFETY: success returned a non-null provider buffer and length is explicitly bounded.
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
}

unsafe fn import_name(principal: &str, oid: gss_OID) -> Result<NonNull<gss_name_struct>, Error> {
    let mut minor = 0;
    let mut name_buffer = gss_buffer_desc_struct {
        length: principal.len(),
        value: principal.as_ptr() as *mut c_void,
    };
    let mut name = std::ptr::null_mut::<gss_name_struct>();
    // SAFETY: principal bytes remain live, `oid` is guaranteed by the caller, and `name` is a
    // valid out-pointer whose null result is checked below.
    if let Some(error) = GssErrorCode::new(unsafe {
        super::ffi::gss_import_name(&mut minor, &mut name_buffer as gss_buffer_t, oid, &mut name)
    }) {
        release_name(&mut name);
        return Err(error.into());
    }
    if let Some(error) = MechanismErrorCode::new(minor) {
        release_name(&mut name);
        return Err(error.into());
    }
    NonNull::new(name).ok_or_else(gss_failure)
}

fn release_name(name: &mut *mut gss_name_struct) {
    if name.is_null() {
        return;
    }
    let mut minor = 0;
    // SAFETY: this is an otherwise-unclaimed provider output handle.
    unsafe { gss_release_name(&mut minor, name) };
}

fn release_buffer(buffer: &mut gss_buffer_desc_struct) {
    if buffer.value.is_null() {
        return;
    }
    let mut minor = 0;
    // SAFETY: the provider transferred this output buffer after a successful display call.
    unsafe { gss_release_buffer(&mut minor, buffer) };
}

fn gss_failure() -> Error {
    Error::gss(_GSS_S_FAILURE).expect("GSS failure is a non-success status")
}
