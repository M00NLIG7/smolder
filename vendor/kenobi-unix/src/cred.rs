pub use kenobi_core::cred::usage::{Both, Inbound, Outbound};
use kenobi_core::mech::Mechanism;
use std::{
    marker::PhantomData,
    ptr::NonNull,
    time::{Duration, Instant},
};

use libgssapi_sys::{
    _GSS_C_INDEFINITE, _GSS_S_FAILURE, GSS_C_ACCEPT, GSS_C_BOTH, GSS_C_INITIATE, gss_OID_set_desc,
    gss_acquire_cred, gss_cred_id_struct, gss_release_cred,
};

use crate::{
    Error,
    error::{GssErrorCode, MechanismErrorCode},
    name::NameHandle,
};

pub struct Credentials<Usage = Outbound> {
    pub(crate) cred_handle: NonNull<gss_cred_id_struct>,
    mechanism: Mechanism,
    valid_until: Instant,
    _usage: PhantomData<Usage>,
}
// Valid, because Credentials does not expose any mutability and is the sole owner of the underlying memory
unsafe impl<Usage> Send for Credentials<Usage> {}
unsafe impl<Usage> Sync for Credentials<Usage> {}
impl<Usage: CredentialsUsage> Credentials<Usage> {
    pub fn new(
        principal: Option<&str>,
        time_required: Option<Duration>,
        mechanism: Mechanism,
    ) -> Result<Self, super::Error> {
        let mut name_type = crate::nt_user_name();
        let mut name = principal
            .map(|p| unsafe { NameHandle::import(p, &mut name_type) })
            .transpose()?;
        let mut minor = 0;
        let mut validity = 0;
        let mut cred_handle = std::ptr::null_mut();
        let mut mech = match mechanism {
            Mechanism::KerberosV5 => crate::mech_kerberos(),
            Mechanism::Spnego => crate::mech_spnego(),
        };
        let mut mech_set = gss_OID_set_desc {
            count: 1,
            elements: &mut mech,
        };
        if let Some(error) = GssErrorCode::new(unsafe {
            gss_acquire_cred(
                &mut minor,
                name.as_mut().map(|re| re.as_mut()).unwrap_or_default(),
                time_required
                    .map(|d| d.as_secs().try_into().unwrap_or(u32::MAX))
                    .unwrap_or(_GSS_C_INDEFINITE),
                &mut mech_set,
                Usage::to_c(),
                &mut cred_handle,
                std::ptr::null_mut(),
                &mut validity,
            )
        }) {
            return Err(error.into());
        };
        if let Some(error) = MechanismErrorCode::new(minor) {
            return Err(error.into());
        }

        let valid_until = Instant::now() + Duration::from_secs(validity.into());
        let Some(cred_handle) = NonNull::new(cred_handle) else {
            return Err(Error::gss(_GSS_S_FAILURE).unwrap());
        };
        Ok(Self {
            cred_handle,
            mechanism,
            valid_until,
            _usage: PhantomData,
        })
    }
    pub fn mechanism(&self) -> Mechanism {
        self.mechanism
    }
    pub fn valid_until(&self) -> Instant {
        self.valid_until
    }
}
impl Credentials<Inbound> {
    pub fn inbound(
        principal: Option<&str>,
        time_required: Option<Duration>,
        mechanism: Mechanism,
    ) -> Result<Self, super::Error> {
        Self::new(principal, time_required, mechanism)
    }
}
impl Credentials<Outbound> {
    pub fn outbound(
        principal: Option<&str>,
        time_required: Option<Duration>,
        mechanism: Mechanism,
    ) -> Result<Self, super::Error> {
        Self::new(principal, time_required, mechanism)
    }
}
impl Credentials<Both> {
    pub fn both(
        principal: Option<&str>,
        time_required: Option<Duration>,
        mechanism: Mechanism,
    ) -> Result<Self, super::Error> {
        Self::new(principal, time_required, mechanism)
    }
}
impl<T> Drop for Credentials<T> {
    fn drop(&mut self) {
        let mut _s = 0;
        unsafe {
            gss_release_cred(&mut _s, &mut NonNull::as_ptr(self.cred_handle));
        }
    }
}
pub trait CredentialsUsage {
    fn to_c() -> i32;
}
impl CredentialsUsage for Inbound {
    fn to_c() -> i32 {
        GSS_C_ACCEPT as i32
    }
}
impl CredentialsUsage for Outbound {
    fn to_c() -> i32 {
        GSS_C_INITIATE as i32
    }
}
impl CredentialsUsage for Both {
    fn to_c() -> i32 {
        GSS_C_BOTH as i32
    }
}
