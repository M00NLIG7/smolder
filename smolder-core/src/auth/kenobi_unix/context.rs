use std::ops::Deref;
use std::ptr::NonNull;

use super::ffi::{
    gss_buffer_set_desc_struct, gss_ctx_id_t, gss_delete_sec_context,
    gss_inquire_sec_context_by_oid, gss_release_buffer_set, _GSS_S_FAILURE,
};

use crate::auth::kenobi_unix::Error;

const MAX_SESSION_KEY_LENGTH: usize = 1_048_576;

pub(crate) struct ContextHandle(gss_ctx_id_t);
// Contexts remain !Send and !Sync. GSS provider thread-safety differs by platform, and this
// wrapper exposes no process-global synchronization that could justify either marker trait.
impl ContextHandle {
    /// # Safety
    /// `ctx` must either be null or a live context whose sole ownership is transferred here.
    pub unsafe fn pick_up(ctx: gss_ctx_id_t) -> Option<Self> {
        (!ctx.is_null()).then_some(Self(ctx))
    }

    pub fn as_ptr(&self) -> gss_ctx_id_t {
        self.0
    }

    pub(crate) fn update(&mut self, ctx: gss_ctx_id_t) -> Result<(), Error> {
        if ctx.is_null() {
            return Err(gss_failure());
        }
        self.0 = ctx;
        Ok(())
    }

    pub fn session_key(&self) -> Result<SessionKey, Error> {
        let mut minor = 0;
        let mut buffer_set: *mut gss_buffer_set_desc_struct = std::ptr::null_mut();
        let mut session_key_oid = crate::auth::kenobi_unix::inq_sspi_session_key();
        // SAFETY: `self.0` is owned and live, the OID descriptor references static bytes, and
        // `buffer_set` is a valid out-pointer released by `SessionKey::drop` on success.
        let major = unsafe {
            gss_inquire_sec_context_by_oid(
                &mut minor,
                self.0,
                &mut session_key_oid,
                std::ptr::from_mut(&mut buffer_set),
            )
        };
        if let Some(error) = Error::gss(major) {
            if let Some(set) = NonNull::new(buffer_set) {
                release_buffer_set(set);
            }
            return Err(error);
        }
        if let Some(error) = Error::mechanism(minor) {
            if let Some(set) = NonNull::new(buffer_set) {
                release_buffer_set(set);
            }
            return Err(error);
        }

        let set = NonNull::new(buffer_set).ok_or_else(gss_failure)?;
        // SAFETY: GSS reported success and returned a non-null set descriptor. All contained
        // pointers/counts are validated before any slice is created.
        let descriptor = unsafe { set.as_ref() };
        if descriptor.count != 1 || descriptor.elements.is_null() {
            release_buffer_set(set);
            return Err(gss_failure());
        }
        // SAFETY: count is exactly one and `elements` was checked non-null.
        let key = unsafe { &*descriptor.elements };
        if key.length == 0 || key.length > MAX_SESSION_KEY_LENGTH || key.value.is_null() {
            release_buffer_set(set);
            return Err(gss_failure());
        }
        let value = NonNull::new(key.value.cast::<u8>()).ok_or_else(|| {
            release_buffer_set(set);
            gss_failure()
        })?;
        Ok(SessionKey {
            set,
            value,
            length: key.length,
        })
    }
}

impl Drop for ContextHandle {
    fn drop(&mut self) {
        let mut minor = 0;
        // SAFETY: this type is the sole owner of the live context handle and drops it once.
        unsafe { gss_delete_sec_context(&mut minor, &mut self.0, std::ptr::null_mut()) };
    }
}

pub struct SessionKey {
    set: NonNull<gss_buffer_set_desc_struct>,
    value: NonNull<u8>,
    length: usize,
}
// Session keys remain !Send and !Sync because their storage is owned by the provider's buffer set.
impl SessionKey {
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: constructor validation proved the pointer is non-null and `length` is bounded;
        // the GSS buffer set remains owned by `self` for the returned borrow's lifetime.
        unsafe { std::slice::from_raw_parts(self.value.as_ptr(), self.length) }
    }
}

impl Drop for SessionKey {
    fn drop(&mut self) {
        release_buffer_set(self.set);
    }
}

impl Deref for SessionKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

fn release_buffer_set(set: NonNull<gss_buffer_set_desc_struct>) {
    let mut minor = 0;
    let mut pointer = set.as_ptr();
    // SAFETY: `set` is a uniquely owned GSS buffer set returned by the provider.
    unsafe { gss_release_buffer_set(&mut minor, &mut pointer) };
}

fn gss_failure() -> Error {
    Error::gss(_GSS_S_FAILURE).expect("GSS failure is a non-success status")
}
