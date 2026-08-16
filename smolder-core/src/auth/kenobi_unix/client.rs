use std::{
    ffi::c_void,
    marker::PhantomData,
    ptr::NonNull,
    rc::Rc,
    time::{Duration, Instant},
};

use super::ffi::{
    gss_OID, gss_buffer_desc, gss_buffer_desc_struct, gss_channel_bindings_struct,
    gss_delete_sec_context, gss_init_sec_context, GSS_C_INTEG_FLAG, GSS_C_MUTUAL_FLAG,
    GSS_S_COMPLETE, GSS_S_CONTINUE_NEEDED, _GSS_C_INDEFINITE, _GSS_S_FAILURE,
};
use super::types::{usage::OutboundUsable, CapabilityFlags};

use crate::auth::kenobi_unix::{
    client::token::Token,
    context::{ContextHandle, SessionKey},
    cred::Credentials,
    error::{GssErrorCode, MechanismErrorCode},
    mech_kerberos,
    name::NameHandle,
    Error,
};
mod builder;

use super::types::typestate::{MaybeDelegation, MaybeEncryption, MaybeSigning};
pub use builder::ClientBuilder;

const GSS_ERROR_MASK: u32 = 0xffff_0000;

pub struct ClientContext<CU, S, E, D> {
    // The credential must outlive the security context even though it is not otherwise read.
    _cred: Rc<Credentials<CU>>,
    pub(crate) context: ContextHandle,
    next_token: Option<Token>,
    marker: PhantomData<(S, E, D)>,
}

impl<CU, S, E, D> ClientContext<CU, S, E, D> {
    pub fn last_token(&self) -> Option<&[u8]> {
        self.next_token.as_ref().map(|token| token.as_slice())
    }

    pub fn session_key(&self) -> Result<SessionKey, Error> {
        self.context.session_key()
    }
}

pub struct PendingClientContext<CU> {
    context: ContextHandle,
    cred: Rc<Credentials<CU>>,
    next_token: token::Token,
    flags: CapabilityFlags,
    target_principal: Option<NameHandle>,
    requested_duration: Option<Duration>,
    channel_bindings: Option<Box<[u8]>>,
    #[expect(dead_code)]
    valid_until: Instant,
}
impl<CU: OutboundUsable> PendingClientContext<CU> {
    pub fn step(self, token: &[u8]) -> Result<StepOut<CU>, Error> {
        step(
            Some(self.context),
            self.cred,
            self.flags,
            self.target_principal,
            Some(token),
            self.requested_duration,
            self.channel_bindings,
        )
    }
}
impl<CU> PendingClientContext<CU> {
    pub fn next_token(&self) -> &[u8] {
        self.next_token.as_slice()
    }
}

fn empty_token() -> gss_buffer_desc {
    gss_buffer_desc {
        length: 0,
        value: std::ptr::null_mut(),
    }
}

fn step<CU: OutboundUsable>(
    ctx: Option<ContextHandle>,
    cred: Rc<Credentials<CU>>,
    flags: CapabilityFlags,
    mut target_principal: Option<NameHandle>,
    token: Option<&[u8]>,
    requested_duration: Option<Duration>,
    channel_bindings: Option<Box<[u8]>>,
) -> Result<StepOut<CU>, Error> {
    let mut ctx_ptr = ctx
        .as_ref()
        .map(ContextHandle::as_ptr)
        .unwrap_or(std::ptr::null_mut());
    let mut minor_status = 0;
    let mut remaining_seconds = 0;
    let mut attributes = 0;
    let mut next_token = empty_token();
    let mut mech_type = std::ptr::null_mut();
    let mut input_token = token
        .map(|slice| gss_buffer_desc_struct {
            length: slice.len(),
            value: slice.as_ptr() as *mut c_void,
        })
        .unwrap_or(gss_buffer_desc_struct {
            length: 0,
            value: std::ptr::null_mut(),
        });
    let mut channel_application_buffer = channel_bindings.as_deref().map(as_channel_bindings);
    // SAFETY: all input buffers borrow live Rust allocations for this call, credential/name/context
    // handles remain owned by their wrappers, and every output pointer is validated before use.
    let major_status = unsafe {
        gss_init_sec_context(
            &mut minor_status,
            NonNull::as_ptr(cred.cred_handle),
            &mut ctx_ptr,
            target_principal
                .as_mut()
                .map_or(std::ptr::null_mut(), |nn| nn.as_mut()),
            &mut mech_kerberos(),
            convert_flags(flags),
            requested_duration.map_or(_GSS_C_INDEFINITE, |d| {
                d.as_secs().min(u32::MAX.into()) as u32
            }),
            channel_application_buffer
                .as_mut()
                .map_or(std::ptr::null_mut(), std::ptr::from_mut),
            &mut input_token,
            &mut mech_type,
            &mut next_token,
            &mut attributes,
            &mut remaining_seconds,
        )
    };
    match major_status {
        GSS_S_COMPLETE => {
            let context = own_context(ctx, ctx_ptr);
            // SAFETY: GSS transferred sole ownership of the output buffer descriptor.
            let next_token = unsafe { Token::pick_up(next_token) };
            let context = context?;
            let next_token = next_token?;
            if !selected_kerberos_mechanism(mech_type)
                || attributes & convert_flags(flags) != convert_flags(flags)
            {
                return Err(gss_failure());
            }
            Ok(StepOut::Finished(ClientContext {
                _cred: cred,
                context,
                next_token,
                marker: PhantomData,
            }))
        }
        stat if stat & GSS_ERROR_MASK == 0 && stat & GSS_S_CONTINUE_NEEDED != 0 => {
            let valid_until = Instant::now()
                .checked_add(Duration::from_secs(remaining_seconds.into()))
                .ok_or_else(gss_failure)?;
            let context = own_context(ctx, ctx_ptr);
            // SAFETY: GSS transferred sole ownership of the output buffer descriptor.
            let next_token = unsafe { Token::pick_up(next_token) };
            let context = context?;
            let next_token = next_token?.ok_or_else(gss_failure)?;
            if !selected_kerberos_mechanism(mech_type) {
                return Err(gss_failure());
            }
            Ok(StepOut::Pending(PendingClientContext {
                cred,
                context,
                next_token,
                flags,
                target_principal,
                valid_until,
                requested_duration,
                channel_bindings,
            }))
        }
        code => {
            // SAFETY: GSS transferred any output buffer descriptor even on a failed exchange.
            let _ = unsafe { Token::pick_up(next_token) };
            let existing_pointer = ctx.as_ref().map(ContextHandle::as_ptr);
            if !ctx_ptr.is_null() && existing_pointer != Some(ctx_ptr) {
                let mut _s = 0;
                // SAFETY: GSS returned this otherwise-unclaimed context from the failed call.
                unsafe { gss_delete_sec_context(&mut _s, &mut ctx_ptr, std::ptr::null_mut()) };
            }
            if let Some(err) = MechanismErrorCode::new(minor_status) {
                return Err(err.into());
            };
            Err(GssErrorCode::new(code)
                .expect("is not GSS_C_COMPLETE")
                .into())
        }
    }
}

fn own_context(
    existing: Option<ContextHandle>,
    pointer: super::ffi::gss_ctx_id_t,
) -> Result<ContextHandle, Error> {
    if let Some(mut existing) = existing {
        existing.update(pointer)?;
        return Ok(existing);
    }
    // SAFETY: a successful/continue GSS result transfers the newly-created context handle.
    unsafe { ContextHandle::pick_up(pointer) }.ok_or_else(gss_failure)
}

fn gss_failure() -> Error {
    Error::gss(_GSS_S_FAILURE).expect("GSS failure is a non-success status")
}

pub enum StepOut<CU> {
    Pending(PendingClientContext<CU>),
    Finished(ClientContext<CU, MaybeSigning, MaybeEncryption, MaybeDelegation>),
}

mod token {
    use super::super::ffi::{gss_buffer_desc, gss_release_buffer, _GSS_S_FAILURE};

    use crate::auth::kenobi_unix::Error;

    const MAX_GSS_TOKEN_LENGTH: usize = 16 * 1024 * 1024;

    pub struct Token(gss_buffer_desc);
    // Provider-owned token buffers deliberately remain !Send and !Sync.
    impl Drop for Token {
        fn drop(&mut self) {
            let mut _min = 0;
            // SAFETY: this wrapper is the sole owner of the provider-returned buffer.
            let _maj = unsafe { gss_release_buffer(&mut _min, &mut self.0) };
        }
    }
    impl Token {
        /// # Safety
        /// Must be sole owner of the underlying GSS buffer descriptor.
        pub unsafe fn pick_up(buf: gss_buffer_desc) -> Result<Option<Self>, Error> {
            if buf.value.is_null() {
                return if buf.length == 0 {
                    Ok(None)
                } else {
                    Err(gss_failure())
                };
            }
            if buf.length > MAX_GSS_TOKEN_LENGTH {
                let mut owned = Self(buf);
                let mut minor = 0;
                // SAFETY: ownership was transferred to `owned`; release before returning failure.
                unsafe { gss_release_buffer(&mut minor, &mut owned.0) };
                std::mem::forget(owned);
                return Err(gss_failure());
            }
            Ok(Some(Self(buf)))
        }
        pub fn as_slice(&self) -> &[u8] {
            // SAFETY: construction validated a non-null pointer and bounded length, and `self`
            // owns the GSS buffer for the returned borrow's lifetime.
            unsafe { std::slice::from_raw_parts(self.0.value.cast::<u8>(), self.0.length) }
        }
    }

    fn gss_failure() -> Error {
        Error::gss(_GSS_S_FAILURE).expect("GSS failure is a non-success status")
    }
}

fn selected_kerberos_mechanism(mechanism: gss_OID) -> bool {
    let Some(mechanism) = NonNull::new(mechanism) else {
        return false;
    };
    // SAFETY: GSS returned this OID descriptor for the synchronous context-init call. Its element
    // pointer and exact expected length are checked before creating a byte slice.
    let descriptor = unsafe { mechanism.as_ref() };
    let expected = crate::auth::kenobi_unix::MECH_KERBEROS;
    if usize::try_from(descriptor.length).ok() != Some(expected.len())
        || descriptor.elements.is_null()
    {
        return false;
    }
    // SAFETY: the provider-reported length equals the small static Kerberos OID length and the
    // element pointer is non-null.
    let actual =
        unsafe { std::slice::from_raw_parts(descriptor.elements.cast::<u8>(), expected.len()) };
    actual == expected
}

fn convert_flags(flags: CapabilityFlags) -> u32 {
    let mut out = 0;
    if flags.contains_all(CapabilityFlags::MUTUAL_AUTH) {
        out |= GSS_C_MUTUAL_FLAG;
    }
    if flags.contains_all(CapabilityFlags::INTEGRITY) {
        out |= GSS_C_INTEG_FLAG;
    }
    out
}

fn as_channel_bindings(arr: &[u8]) -> gss_channel_bindings_struct {
    gss_channel_bindings_struct {
        initiator_addrtype: 0,
        initiator_address: gss_buffer_desc_struct {
            length: 0,
            value: std::ptr::null_mut(),
        },
        acceptor_addrtype: 0,
        acceptor_address: gss_buffer_desc_struct {
            length: 0,
            value: std::ptr::null_mut(),
        },
        application_data: gss_buffer_desc_struct {
            length: arr.len(),
            value: arr.as_ptr() as *mut c_void,
        },
    }
}
