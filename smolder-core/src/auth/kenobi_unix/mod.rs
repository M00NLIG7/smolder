pub mod client;
mod context;
pub mod cred;
mod error;
mod ffi;
mod types;

use std::ffi::c_void;

use self::ffi::gss_OID_desc;
pub use error::Error;
pub mod mech;
mod name;

static MECH_KERBEROS: &[u8] = b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02";
static NT_USER_NAME: &[u8] = b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x01";
static INQ_SSPI_SESSION_KEY: &[u8] = b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x05";

fn oid(mech: &'static [u8]) -> gss_OID_desc {
    gss_OID_desc {
        length: mech.len() as u32,
        elements: mech.as_ptr() as *mut c_void,
    }
}
fn mech_kerberos() -> gss_OID_desc {
    oid(MECH_KERBEROS)
}
fn nt_user_name() -> gss_OID_desc {
    oid(NT_USER_NAME)
}

fn inq_sspi_session_key() -> gss_OID_desc {
    oid(INQ_SSPI_SESSION_KEY)
}

pub mod typestate {
    pub use super::types::typestate::{MaybeDelegation, MaybeEncryption, MaybeSigning};
}
