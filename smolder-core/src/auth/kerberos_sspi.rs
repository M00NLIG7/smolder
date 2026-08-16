//! Windows Kerberos backend using the platform SSPI ABI directly.
//!
//! Keeping this narrow wrapper in-tree removes the vulnerable optional RSA graph previously pulled
//! in by the pure-Rust `sspi` network client. The `Kerberos` security package is selected directly,
//! so SSPI cannot silently fall back to NTLM.

use std::ffi::c_void;
use std::marker::PhantomData;
use std::ptr::NonNull;
use std::rc::Rc;

use zeroize::{Zeroize, Zeroizing};

use super::kerberos::{KerberosBackend, KerberosCredentials, KerberosStep};
use super::kerberos_spn::KerberosTarget;
use super::AuthError;

const SEC_E_OK: i32 = 0;
const SEC_I_CONTINUE_NEEDED: i32 = 0x0009_0312;
const SEC_I_COMPLETE_NEEDED: i32 = 0x0009_0313;
const SEC_I_COMPLETE_AND_CONTINUE: i32 = 0x0009_0314;
const SECPKG_CRED_OUTBOUND: u32 = 2;
const SEC_WINNT_AUTH_IDENTITY_UNICODE: u32 = 2;
const ISC_REQ_MUTUAL_AUTH: u32 = 0x0000_0002;
const ISC_REQ_ALLOCATE_MEMORY: u32 = 0x0000_0100;
const ISC_REQ_INTEGRITY: u32 = 0x0001_0000;
const SECURITY_NATIVE_DREP: u32 = 0x0000_0010;
const SECBUFFER_VERSION: u32 = 0;
const SECBUFFER_TOKEN: u32 = 2;
const SECPKG_ATTR_SESSION_KEY: u32 = 9;
const MAX_SSPI_TOKEN_LENGTH: usize = 16 * 1024 * 1024;
const MAX_SESSION_KEY_LENGTH: usize = 1_048_576;

pub(super) struct SspiNegotiateKerberosBackend;

pub(super) struct SspiKerberosContext {
    credential: CredentialHandle,
    context: SecurityContextHandle,
    target_name: Vec<u16>,
    session_key: Option<Vec<u8>>,
    // Do not promise cross-thread handle movement without relying on undocumented provider state.
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl Drop for SspiKerberosContext {
    fn drop(&mut self) {
        if let Some(key) = self.session_key.as_mut() {
            key.zeroize();
        }
    }
}

impl SspiKerberosContext {
    fn new(credentials: &KerberosCredentials, target: &KerberosTarget) -> Result<Self, AuthError> {
        if credentials.kdc_url().is_some() {
            return Err(AuthError::InvalidState(
                "the native Windows Kerberos backend does not accept a custom KDC URL",
            ));
        }
        let target_name = wide_nul(&target_name(target)?, "kerberos target name")?;
        Ok(Self {
            credential: CredentialHandle::acquire(credentials)?,
            context: SecurityContextHandle::empty(),
            target_name,
            session_key: None,
            _not_send_or_sync: PhantomData,
        })
    }

    fn step(&mut self, incoming: Option<&[u8]>) -> Result<(bool, Vec<u8>), AuthError> {
        let mut output_buffer = SecBuffer {
            cb_buffer: 0,
            buffer_type: SECBUFFER_TOKEN,
            pv_buffer: std::ptr::null_mut(),
        };
        let mut output_descriptor = SecBufferDesc {
            ul_version: SECBUFFER_VERSION,
            c_buffers: 1,
            p_buffers: &mut output_buffer,
        };
        if incoming.is_some_and(|token| token.len() > MAX_SSPI_TOKEN_LENGTH) {
            return Err(AuthError::InvalidToken(
                "kerberos SSPI input token exceeded the configured maximum",
            ));
        }
        let mut input_buffer = incoming
            .map(|token| {
                Ok(SecBuffer {
                    cb_buffer: u32::try_from(token.len()).map_err(|_| {
                        AuthError::InvalidToken("kerberos SSPI input token exceeded u32")
                    })?,
                    buffer_type: SECBUFFER_TOKEN,
                    pv_buffer: token.as_ptr().cast_mut().cast(),
                })
            })
            .transpose()?;
        let mut input_descriptor = input_buffer.as_mut().map(|buffer| SecBufferDesc {
            ul_version: SECBUFFER_VERSION,
            c_buffers: 1,
            p_buffers: buffer,
        });
        let mut attributes = 0;
        let mut expiry = 0i64;
        let old_context = self.context.raw;
        let context = std::ptr::addr_of_mut!(self.context.raw);
        let existing = if self.context.valid {
            context
        } else {
            std::ptr::null_mut()
        };
        // SAFETY: all descriptors borrow live memory for this synchronous call. Credential and
        // context handles are owned by this wrapper; SSPI explicitly permits the existing and new
        // context parameters to identify the same handle during continuation. Raw pointers avoid
        // manufacturing two overlapping Rust `&mut` references for that documented ABI shape.
        // Output pointers, counts, and lengths are validated before use and released afterward.
        let status = unsafe {
            InitializeSecurityContextW(
                &mut self.credential.raw,
                existing,
                self.target_name.as_mut_ptr(),
                ISC_REQ_MUTUAL_AUTH | ISC_REQ_INTEGRITY | ISC_REQ_ALLOCATE_MEMORY,
                0,
                SECURITY_NATIVE_DREP,
                input_descriptor
                    .as_mut()
                    .map_or(std::ptr::null_mut(), |descriptor| descriptor),
                0,
                context,
                &mut output_descriptor,
                &mut attributes,
                &mut expiry,
            )
        };
        if matches!(
            status,
            SEC_E_OK | SEC_I_CONTINUE_NEEDED | SEC_I_COMPLETE_NEEDED | SEC_I_COMPLETE_AND_CONTINUE
        ) {
            self.context.valid = true;
        } else {
            release_sspi_buffer(output_buffer.pv_buffer);
            if !self.context.valid && self.context.raw != old_context {
                self.context.valid = true;
            }
            return Err(sspi_error("InitializeSecurityContextW", status));
        }
        if output_descriptor.c_buffers != 1
            || output_descriptor.p_buffers != std::ptr::from_mut(&mut output_buffer)
        {
            release_sspi_buffer(output_buffer.pv_buffer);
            return Err(AuthError::InvalidToken(
                "kerberos SSPI returned an invalid output buffer descriptor",
            ));
        }

        if matches!(status, SEC_I_COMPLETE_NEEDED | SEC_I_COMPLETE_AND_CONTINUE) {
            // SAFETY: SSPI returned a live context and output descriptor for completion.
            let completion =
                unsafe { CompleteAuthToken(&mut self.context.raw, &mut output_descriptor) };
            if completion != SEC_E_OK {
                release_sspi_buffer(output_buffer.pv_buffer);
                return Err(sspi_error("CompleteAuthToken", completion));
            }
            if output_descriptor.c_buffers != 1
                || output_descriptor.p_buffers != std::ptr::from_mut(&mut output_buffer)
            {
                release_sspi_buffer(output_buffer.pv_buffer);
                return Err(AuthError::InvalidToken(
                    "kerberos SSPI completion returned an invalid output buffer descriptor",
                ));
            }
        }

        let token = copy_provider_buffer(
            output_buffer.pv_buffer.cast::<u8>(),
            output_buffer.cb_buffer,
            MAX_SSPI_TOKEN_LENGTH,
            "kerberos SSPI output token",
        );
        release_sspi_buffer(output_buffer.pv_buffer);
        let token = token?;
        let complete = matches!(status, SEC_E_OK | SEC_I_COMPLETE_NEEDED);
        if complete {
            let required_attributes = ISC_REQ_MUTUAL_AUTH | ISC_REQ_INTEGRITY;
            if attributes & required_attributes != required_attributes {
                return Err(AuthError::InvalidToken(
                    "kerberos SSPI context omitted required mutual-authentication or integrity attributes",
                ));
            }
            self.session_key = Some(self.context.session_key()?);
        }
        Ok((complete, token))
    }
}

impl KerberosBackend for SspiNegotiateKerberosBackend {
    // The Windows Kerberos package emits raw Kerberos tokens. Smolder's common engine supplies the
    // SPNEGO wrapper, avoiding Negotiate-package fallback to NTLM.
    const SPNEGO_WRAPPED: bool = false;

    type Pending = SspiKerberosContext;
    type Context = SspiKerberosContext;

    fn initiate(
        credentials: &KerberosCredentials,
        target: &KerberosTarget,
    ) -> Result<KerberosStep<Self::Pending, Self::Context>, AuthError> {
        let mut context = SspiKerberosContext::new(credentials, target)?;
        let (complete, token) = context.step(None)?;
        if complete {
            Ok(KerberosStep::Finished {
                context,
                token: Some(token),
            })
        } else {
            Ok(KerberosStep::Continue {
                pending: context,
                token,
            })
        }
    }

    fn step(
        mut pending: Self::Pending,
        incoming: &[u8],
        _target: &KerberosTarget,
    ) -> Result<KerberosStep<Self::Pending, Self::Context>, AuthError> {
        let (complete, token) = pending.step(Some(incoming))?;
        if complete {
            Ok(KerberosStep::Finished {
                context: pending,
                token: (!token.is_empty()).then_some(token),
            })
        } else {
            Ok(KerberosStep::Continue { pending, token })
        }
    }

    fn session_key(context: &Self::Context) -> Result<Vec<u8>, AuthError> {
        context.session_key.clone().ok_or(AuthError::InvalidState(
            "Windows SSPI context completed without a session key",
        ))
    }
}

struct CredentialHandle {
    raw: SecHandle,
    valid: bool,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl CredentialHandle {
    fn acquire(credentials: &KerberosCredentials) -> Result<Self, AuthError> {
        credentials.validate_username_domain()?;
        let mut username = wide(credentials.username(), "kerberos username")?;
        let mut domain = wide(credentials.domain(), "kerberos domain")?;
        let mut password = Zeroizing::new(wide(credentials.password_text(), "kerberos password")?);
        let mut identity = SecWinntAuthIdentityW {
            user: username.as_mut_ptr(),
            user_length: checked_wide_len(&username, "kerberos username")?,
            domain: domain.as_mut_ptr(),
            domain_length: checked_wide_len(&domain, "kerberos domain")?,
            password: password.as_mut_ptr(),
            password_length: checked_wide_len(&password, "kerberos password")?,
            flags: SEC_WINNT_AUTH_IDENTITY_UNICODE,
        };
        let mut package = wide_nul("Kerberos", "SSPI package")?;
        let mut raw = SecHandle::zero();
        let mut expiry = 0i64;
        // SAFETY: UTF-16/package/identity buffers remain live for this synchronous call, and the
        // output handle is not used unless SSPI reports success.
        let status = unsafe {
            AcquireCredentialsHandleW(
                std::ptr::null_mut(),
                package.as_mut_ptr(),
                SECPKG_CRED_OUTBOUND,
                std::ptr::null_mut(),
                (&mut identity as *mut SecWinntAuthIdentityW).cast(),
                None,
                std::ptr::null_mut(),
                &mut raw,
                &mut expiry,
            )
        };
        if status != SEC_E_OK {
            return Err(sspi_error("AcquireCredentialsHandleW", status));
        }
        Ok(Self {
            raw,
            valid: true,
            _not_send_or_sync: PhantomData,
        })
    }
}

impl Drop for CredentialHandle {
    fn drop(&mut self) {
        if self.valid {
            // SAFETY: this wrapper owns the successful SSPI credential handle exactly once.
            unsafe { FreeCredentialsHandle(&mut self.raw) };
            self.valid = false;
        }
    }
}

struct SecurityContextHandle {
    raw: SecHandle,
    valid: bool,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl SecurityContextHandle {
    fn empty() -> Self {
        Self {
            raw: SecHandle::zero(),
            valid: false,
            _not_send_or_sync: PhantomData,
        }
    }

    fn session_key(&mut self) -> Result<Vec<u8>, AuthError> {
        if !self.valid {
            return Err(AuthError::InvalidState(
                "cannot query an incomplete Windows SSPI context",
            ));
        }
        let mut key = SecPkgContextSessionKey {
            session_key_length: 0,
            session_key: std::ptr::null_mut(),
        };
        // SAFETY: the context is live and `key` is a valid fixed-layout output structure.
        let status = unsafe {
            QueryContextAttributesW(
                &mut self.raw,
                SECPKG_ATTR_SESSION_KEY,
                (&mut key as *mut SecPkgContextSessionKey).cast(),
            )
        };
        if status != SEC_E_OK {
            return Err(sspi_error("QueryContextAttributesW(session key)", status));
        }
        let copied = copy_provider_buffer(
            key.session_key,
            key.session_key_length,
            MAX_SESSION_KEY_LENGTH,
            "Windows SSPI session key",
        );
        release_sspi_buffer(key.session_key.cast());
        let copied = copied?;
        if copied.is_empty() {
            return Err(AuthError::InvalidState(
                "Windows SSPI returned an empty Kerberos session key",
            ));
        }
        Ok(copied)
    }
}

impl Drop for SecurityContextHandle {
    fn drop(&mut self) {
        if self.valid {
            // SAFETY: this wrapper owns the successful SSPI context handle exactly once.
            unsafe { DeleteSecurityContext(&mut self.raw) };
            self.valid = false;
        }
    }
}

fn target_name(target: &KerberosTarget) -> Result<String, AuthError> {
    if let Some(principal) = target.explicit_principal() {
        if principal.trim().is_empty() {
            return Err(AuthError::InvalidState(
                "kerberos principal override must not be empty",
            ));
        }
        return Ok(principal.to_owned());
    }
    if target.service().trim().is_empty() || target.host().trim().is_empty() {
        return Err(AuthError::InvalidState(
            "kerberos service and target host must not be empty",
        ));
    }
    Ok(format!("{}/{}", target.service(), target.host()))
}

fn wide(value: &str, field: &'static str) -> Result<Vec<u16>, AuthError> {
    if value.contains('\0') {
        return Err(AuthError::InvalidState(field));
    }
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(value.len())
        .map_err(|_| AuthError::InvalidState(field))?;
    encoded.extend(value.encode_utf16());
    let _ = u32::try_from(encoded.len()).map_err(|_| AuthError::InvalidState(field))?;
    Ok(encoded)
}

fn wide_nul(value: &str, field: &'static str) -> Result<Vec<u16>, AuthError> {
    let mut encoded = wide(value, field)?;
    encoded
        .try_reserve(1)
        .map_err(|_| AuthError::InvalidState(field))?;
    encoded.push(0);
    Ok(encoded)
}

fn checked_wide_len(value: &[u16], field: &'static str) -> Result<u32, AuthError> {
    u32::try_from(value.len()).map_err(|_| AuthError::InvalidState(field))
}

fn copy_provider_buffer(
    pointer: *mut u8,
    length: u32,
    maximum: usize,
    field: &'static str,
) -> Result<Vec<u8>, AuthError> {
    let length = usize::try_from(length).map_err(|_| AuthError::InvalidToken(field))?;
    if length > maximum || (length != 0 && pointer.is_null()) {
        return Err(AuthError::InvalidToken(field));
    }
    if length == 0 {
        return Ok(Vec::new());
    }
    let pointer = NonNull::new(pointer).ok_or(AuthError::InvalidToken(field))?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(length)
        .map_err(|_| AuthError::InvalidToken(field))?;
    // SAFETY: the provider returned a non-null buffer, length is explicitly bounded, and the
    // provider allocation remains live until the caller invokes `FreeContextBuffer`.
    let source = unsafe { std::slice::from_raw_parts(pointer.as_ptr(), length) };
    output.extend_from_slice(source);
    Ok(output)
}

fn release_sspi_buffer(pointer: *mut c_void) {
    if pointer.is_null() {
        return;
    }
    // SAFETY: the pointer came from an SSPI output field documented for `FreeContextBuffer`.
    unsafe { FreeContextBuffer(pointer) };
}

fn sspi_error(operation: &'static str, status: i32) -> AuthError {
    AuthError::Backend(format!(
        "{operation} failed with Windows security status 0x{:08x}",
        status as u32
    ))
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
struct SecHandle {
    lower: usize,
    upper: usize,
}

impl SecHandle {
    const fn zero() -> Self {
        Self { lower: 0, upper: 0 }
    }
}

#[repr(C)]
struct SecBuffer {
    cb_buffer: u32,
    buffer_type: u32,
    pv_buffer: *mut c_void,
}

#[repr(C)]
struct SecBufferDesc {
    ul_version: u32,
    c_buffers: u32,
    p_buffers: *mut SecBuffer,
}

#[repr(C)]
struct SecWinntAuthIdentityW {
    user: *mut u16,
    user_length: u32,
    domain: *mut u16,
    domain_length: u32,
    password: *mut u16,
    password_length: u32,
    flags: u32,
}

#[repr(C)]
struct SecPkgContextSessionKey {
    session_key_length: u32,
    session_key: *mut u8,
}

type GetKeyFn = Option<
    unsafe extern "system" fn(*mut c_void, *mut c_void, u32, *mut *mut c_void, *mut i32) -> i32,
>;

#[link(name = "secur32")]
unsafe extern "system" {
    fn AcquireCredentialsHandleW(
        principal: *mut u16,
        package: *mut u16,
        credential_use: u32,
        logon_id: *mut c_void,
        auth_data: *mut c_void,
        get_key_fn: GetKeyFn,
        get_key_argument: *mut c_void,
        credential: *mut SecHandle,
        expiry: *mut i64,
    ) -> i32;

    fn FreeCredentialsHandle(credential: *mut SecHandle) -> i32;

    fn InitializeSecurityContextW(
        credential: *mut SecHandle,
        context: *mut SecHandle,
        target_name: *mut u16,
        context_requirements: u32,
        reserved1: u32,
        target_data_representation: u32,
        input: *mut SecBufferDesc,
        reserved2: u32,
        new_context: *mut SecHandle,
        output: *mut SecBufferDesc,
        context_attributes: *mut u32,
        expiry: *mut i64,
    ) -> i32;

    fn CompleteAuthToken(context: *mut SecHandle, token: *mut SecBufferDesc) -> i32;
    fn DeleteSecurityContext(context: *mut SecHandle) -> i32;
    fn QueryContextAttributesW(context: *mut SecHandle, attribute: u32, buffer: *mut c_void)
        -> i32;
    fn FreeContextBuffer(buffer: *mut c_void) -> i32;
}
