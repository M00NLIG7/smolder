pub use kenobi_core::cred::usage::{Both, Inbound, Outbound};
use kenobi_core::mech::Mechanism;
#[cfg(not(target_os = "macos"))]
use std::{
    ffi::CString,
    marker::PhantomData,
    ptr::NonNull,
    time::{Duration, Instant},
};
#[cfg(target_os = "macos")]
use std::{
    env,
    ffi::OsString,
    marker::PhantomData,
    ptr::NonNull,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use libgssapi_sys::{
    _GSS_C_INDEFINITE, _GSS_S_FAILURE, GSS_C_ACCEPT, GSS_C_BOTH, GSS_C_INITIATE, gss_OID_set_desc,
    gss_acquire_cred, gss_cred_id_struct, gss_release_cred,
};
#[cfg(not(target_os = "macos"))]
use libgssapi_sys::{gss_acquire_cred_from, gss_key_value_element_desc, gss_key_value_set_desc};

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

    pub fn outbound_from_client_keytab(
        principal: Option<&str>,
        time_required: Option<Duration>,
        keytab_name: &str,
        cache_name: Option<&str>,
        mechanism: Mechanism,
    ) -> Result<Self, super::Error> {
        #[cfg(target_os = "macos")]
        {
            let _guard = keytab_env_lock().lock().expect("keytab env mutex poisoned");
            let keytab_guard = EnvVarGuard::set("KRB5_CLIENT_KTNAME", Some(keytab_name));
            let acceptor_guard = EnvVarGuard::set("KRB5_KTNAME", Some(keytab_name));
            let cache_guard = EnvVarGuard::set("KRB5CCNAME", cache_name);
            let result = Self::new(principal, time_required, mechanism);
            drop(cache_guard);
            drop(acceptor_guard);
            drop(keytab_guard);
            result
        }
        #[cfg(not(target_os = "macos"))]
        {
            Self::new_from_cred_store(
                principal,
                time_required,
                mechanism,
                &[("client_keytab", keytab_name), ("ccache", cache_name.unwrap_or(""))],
            )
        }
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

#[cfg(not(target_os = "macos"))]
impl<Usage: CredentialsUsage> Credentials<Usage> {
    fn new_from_cred_store(
        principal: Option<&str>,
        time_required: Option<Duration>,
        mechanism: Mechanism,
        cred_store: &[(&str, &str)],
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
        let keys = cred_store
            .iter()
            .map(|(key, _)| CString::new(*key).map_err(|_| Error::gss(_GSS_S_FAILURE).unwrap()))
            .collect::<Result<Vec<_>, _>>()?;
        let values = cred_store
            .iter()
            .map(|(_, value)| CString::new(*value).map_err(|_| Error::gss(_GSS_S_FAILURE).unwrap()))
            .collect::<Result<Vec<_>, _>>()?;
        let mut elements = keys
            .iter()
            .zip(values.iter())
            .map(|(key, value)| gss_key_value_element_desc {
                key: key.as_ptr(),
                value: value.as_ptr(),
            })
            .collect::<Vec<_>>();
        let store = gss_key_value_set_desc {
            count: elements.len().try_into().unwrap_or(u32::MAX),
            elements: elements.as_mut_ptr(),
        };
        if let Some(error) = GssErrorCode::new(unsafe {
            gss_acquire_cred_from(
                &mut minor,
                name.as_mut().map(|re| re.as_mut()).unwrap_or_default(),
                time_required
                    .map(|d| d.as_secs().try_into().unwrap_or(u32::MAX))
                    .unwrap_or(_GSS_C_INDEFINITE),
                &mut mech_set,
                Usage::to_c(),
                &store,
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
}

#[cfg(target_os = "macos")]
fn keytab_env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[cfg(target_os = "macos")]
struct EnvVarGuard {
    key: &'static str,
    previous: Option<OsString>,
}

#[cfg(target_os = "macos")]
impl EnvVarGuard {
    fn set(key: &'static str, value: Option<&str>) -> Self {
        let previous = env::var_os(key);
        match value {
            Some(value) => {
                // SAFETY: keytab-backed credential acquisition is serialized through the
                // process-global mutex above. This backend uses environment overrides only
                // for the immediate credential-acquisition call and restores the previous
                // values before releasing the lock.
                unsafe { env::set_var(key, value) };
            }
            None => {
                // SAFETY: see rationale above for `set_var`.
                unsafe { env::remove_var(key) };
            }
        }
        Self { key, previous }
    }
}

#[cfg(target_os = "macos")]
impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        match self.previous.take() {
            // SAFETY: restoration happens under the same global mutex used for mutation, and
            // returns the process environment to its prior state before the lock is released.
            Some(value) => unsafe { env::set_var(self.key, value) },
            // SAFETY: see rationale above for `set_var`.
            None => unsafe { env::remove_var(self.key) },
        }
    }
}
