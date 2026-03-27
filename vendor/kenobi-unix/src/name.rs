use std::{ffi::c_void, fmt::Display, ptr::NonNull};

use libgssapi_sys::{
    gss_OID, gss_OID_desc_struct, gss_buffer_desc_struct, gss_buffer_t, gss_display_name, gss_name_struct,
    gss_release_buffer, gss_release_name,
};

use crate::{
    Error,
    error::{GssErrorCode, MechanismErrorCode},
};

pub struct NameHandle {
    name: NonNull<gss_name_struct>,
}
unsafe impl Send for NameHandle {}
unsafe impl Sync for NameHandle {}
impl NameHandle {
    pub unsafe fn import(principal: &str, oid: *mut gss_OID_desc_struct) -> Result<Self, Error> {
        let name = unsafe { import_name(principal, oid)? };
        Ok(NameHandle { name })
    }
    pub fn as_mut(&mut self) -> *mut gss_name_struct {
        self.name.as_ptr()
    }
}
impl Drop for NameHandle {
    fn drop(&mut self) {
        let mut _s = 0;
        unsafe { gss_release_name(&mut _s, &mut NonNull::as_ptr(self.name)) };
    }
}
impl Display for NameHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut minor = 0;
        let mut buffer = gss_buffer_desc_struct {
            length: 0,
            value: std::ptr::null_mut(),
        };
        let major = unsafe {
            gss_display_name(
                &mut minor,
                NonNull::as_ptr(self.name),
                &mut buffer,
                std::ptr::null_mut(),
            )
        };
        if let Some(_gss_err) = Error::gss(major) {
            return Ok(());
        }
        if let Some(_mech_err) = Error::mechanism(minor) {
            return Ok(());
        }
        let sl = unsafe { std::slice::from_raw_parts(buffer.value as *mut u8, buffer.length) };
        let Ok(str) = std::str::from_utf8(sl) else {
            return Ok(());
        };
        write!(f, "{str}")?;
        let mut _min = 0;
        let _maj = unsafe { gss_release_buffer(&mut _min, &mut buffer) };
        Ok(())
    }
}

unsafe fn import_name(principal: &str, oid: gss_OID) -> Result<NonNull<gss_name_struct>, Error> {
    let mut minor = 0;
    let mut namebuffer = gss_buffer_desc_struct {
        length: principal.len(),
        value: principal.as_ptr() as *mut c_void,
    };
    let mut name = std::ptr::null_mut::<gss_name_struct>();
    if let Some(error) = GssErrorCode::new(unsafe {
        libgssapi_sys::gss_import_name(&mut minor, &mut namebuffer as gss_buffer_t, oid, &mut name)
    }) {
        return Err(error.into());
    };
    if let Some(err) = MechanismErrorCode::new(minor) {
        return Err(err.into());
    }
    Ok(NonNull::new(name).unwrap())
}
