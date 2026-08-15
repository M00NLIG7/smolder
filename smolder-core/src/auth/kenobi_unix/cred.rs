pub use super::types::usage::Outbound;
use super::types::Mechanism;
#[cfg(not(target_os = "macos"))]
use std::ffi::CString;
use std::{marker::PhantomData, ptr::NonNull, time::Duration};

use super::ffi::{
    gss_OID_set_desc, gss_acquire_cred, gss_acquire_cred_with_password, gss_buffer_desc,
    gss_cred_id_struct, gss_release_cred, GSS_C_INITIATE, _GSS_C_INDEFINITE, _GSS_S_FAILURE,
};
#[cfg(not(target_os = "macos"))]
use super::ffi::{gss_acquire_cred_from, gss_key_value_element_desc, gss_key_value_set_desc};

use crate::auth::kenobi_unix::{
    error::{GssErrorCode, MechanismErrorCode},
    name::NameHandle,
    Error,
};

pub struct Credentials<Usage = Outbound> {
    pub(crate) cred_handle: NonNull<gss_cred_id_struct>,
    _usage: PhantomData<Usage>,
}
// GSS credential handles deliberately remain !Send and !Sync: this wrapper cannot prove that every
// platform provider permits cross-thread ownership or concurrent access.
impl Credentials<Outbound> {
    pub fn outbound(
        principal: Option<&str>,
        time_required: Option<Duration>,
        mechanism: Mechanism,
    ) -> Result<Self, Error> {
        let mut name_type = crate::auth::kenobi_unix::nt_user_name();
        let mut name = principal
            .map(|principal| {
                // SAFETY: the OID descriptor references static bytes for the duration of import.
                unsafe { NameHandle::import(principal, &mut name_type) }
            })
            .transpose()?;
        let mut mechanism_oid = mechanism_oid(mechanism);
        let mut mechanism_set = gss_OID_set_desc {
            count: 1,
            elements: &mut mechanism_oid,
        };
        let mut minor = 0;
        let mut validity = 0;
        let mut credential = std::ptr::null_mut();
        // SAFETY: borrowed names/OIDs remain live for this synchronous call; all out-pointers are
        // initialized and the returned credential pointer is validated before ownership is taken.
        let major = unsafe {
            gss_acquire_cred(
                &mut minor,
                name.as_mut()
                    .map(NameHandle::as_mut)
                    .unwrap_or(std::ptr::null_mut()),
                required_seconds(time_required),
                &mut mechanism_set,
                GSS_C_INITIATE,
                &mut credential,
                std::ptr::null_mut(),
                &mut validity,
            )
        };
        finish_acquire(major, minor, credential)
    }

    pub fn outbound_with_password(
        principal: &str,
        password: &[u8],
        time_required: Option<Duration>,
        mechanism: Mechanism,
    ) -> Result<Self, Error> {
        const MAX_PASSWORD_BYTES: usize = 1_048_576;

        if principal.is_empty() || password.is_empty() || password.len() > MAX_PASSWORD_BYTES {
            return Err(gss_failure());
        }
        let mut name_type = crate::auth::kenobi_unix::nt_user_name();
        // SAFETY: the OID descriptor references static bytes for the duration of import.
        let mut name = unsafe { NameHandle::import(principal, &mut name_type) }?;
        let mut mechanism_oid = mechanism_oid(mechanism);
        let mut mechanism_set = gss_OID_set_desc {
            count: 1,
            elements: &mut mechanism_oid,
        };
        let mut password_buffer = gss_buffer_desc {
            length: password.len(),
            value: password.as_ptr().cast_mut().cast(),
        };
        let mut minor = 0;
        let mut validity = 0;
        let mut credential = std::ptr::null_mut();
        // SAFETY: principal/password/OID buffers remain live for this synchronous call; all output
        // pointers are initialized and the returned credential pointer is validated before use.
        let major = unsafe {
            gss_acquire_cred_with_password(
                &mut minor,
                name.as_mut(),
                &mut password_buffer,
                required_seconds(time_required),
                &mut mechanism_set,
                GSS_C_INITIATE,
                &mut credential,
                std::ptr::null_mut(),
                &mut validity,
            )
        };
        finish_acquire(major, minor, credential)
    }

    #[cfg(not(target_os = "macos"))]
    pub fn outbound_from_client_keytab(
        principal: Option<&str>,
        time_required: Option<Duration>,
        keytab_name: &str,
        cache_name: Option<&str>,
        mechanism: Mechanism,
    ) -> Result<Self, Error> {
        let mut name_type = crate::auth::kenobi_unix::nt_user_name();
        let mut name = principal
            .map(|principal| {
                // SAFETY: the OID descriptor references static bytes for the duration of import.
                unsafe { NameHandle::import(principal, &mut name_type) }
            })
            .transpose()?;
        let mut mechanism_oid = mechanism_oid(mechanism);
        let mut mechanism_set = gss_OID_set_desc {
            count: 1,
            elements: &mut mechanism_oid,
        };
        let keys = [
            CString::new("client_keytab").expect("literal has no NUL"),
            CString::new("ccache").expect("literal has no NUL"),
        ];
        let values = [
            CString::new(keytab_name).map_err(|_| gss_failure())?,
            CString::new(cache_name.unwrap_or("")).map_err(|_| gss_failure())?,
        ];
        let mut elements = [
            gss_key_value_element_desc {
                key: keys[0].as_ptr(),
                value: values[0].as_ptr(),
            },
            gss_key_value_element_desc {
                key: keys[1].as_ptr(),
                value: values[1].as_ptr(),
            },
        ];
        let store = gss_key_value_set_desc {
            count: elements.len(),
            elements: elements.as_mut_ptr(),
        };
        let mut minor = 0;
        let mut validity = 0;
        let mut credential = std::ptr::null_mut();
        // SAFETY: all names, OIDs, and credential-store C strings remain live for this synchronous
        // call; every output pointer is initialized and validated before ownership is taken.
        let major = unsafe {
            gss_acquire_cred_from(
                &mut minor,
                name.as_mut()
                    .map(NameHandle::as_mut)
                    .unwrap_or(std::ptr::null_mut()),
                required_seconds(time_required),
                &mut mechanism_set,
                GSS_C_INITIATE,
                &store,
                &mut credential,
                std::ptr::null_mut(),
                &mut validity,
            )
        };
        finish_acquire(major, minor, credential)
    }
}

impl<Usage> Drop for Credentials<Usage> {
    fn drop(&mut self) {
        let mut minor = 0;
        let mut credential = self.cred_handle.as_ptr();
        // SAFETY: this wrapper owns the provider credential and releases it exactly once.
        unsafe { gss_release_cred(&mut minor, &mut credential) };
    }
}

fn mechanism_oid(mechanism: Mechanism) -> super::ffi::gss_OID_desc {
    match mechanism {
        Mechanism::KerberosV5 => crate::auth::kenobi_unix::mech_kerberos(),
    }
}

fn required_seconds(duration: Option<Duration>) -> u32 {
    duration
        .map(|duration| duration.as_secs().try_into().unwrap_or(u32::MAX))
        .unwrap_or(_GSS_C_INDEFINITE)
}

fn finish_acquire(
    major: u32,
    minor: u32,
    mut credential: *mut gss_cred_id_struct,
) -> Result<Credentials<Outbound>, Error> {
    if let Some(error) = GssErrorCode::new(major) {
        release_unclaimed(&mut credential);
        return Err(error.into());
    }
    if let Some(error) = MechanismErrorCode::new(minor) {
        release_unclaimed(&mut credential);
        return Err(error.into());
    }
    let cred_handle = NonNull::new(credential).ok_or_else(gss_failure)?;
    Ok(Credentials {
        cred_handle,
        _usage: PhantomData,
    })
}

fn release_unclaimed(credential: &mut *mut gss_cred_id_struct) {
    if credential.is_null() {
        return;
    }
    let mut minor = 0;
    // SAFETY: the provider returned this otherwise-unclaimed credential output pointer.
    unsafe { gss_release_cred(&mut minor, credential) };
}

fn gss_failure() -> Error {
    Error::gss(_GSS_S_FAILURE).expect("GSS failure is nonzero")
}
