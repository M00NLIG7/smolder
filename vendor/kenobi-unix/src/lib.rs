pub mod client;
mod context;
pub mod cred;
mod error;

use std::ffi::c_void;

pub use error::Error;
use libgssapi_sys::gss_OID_desc;
pub mod mech;
mod name;
pub mod sign_encrypt;

static MECH_KERBEROS: &[u8] = b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02";
static MECH_SPNEGO: &[u8] = b"\x2b\x06\x01\x05\x05\x02";
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
fn mech_spnego() -> gss_OID_desc {
    oid(MECH_SPNEGO)
}

fn nt_user_name() -> gss_OID_desc {
    oid(NT_USER_NAME)
}

fn inq_sspi_session_key() -> gss_OID_desc {
    oid(INQ_SSPI_SESSION_KEY)
}

pub mod typestate {
    pub use kenobi_core::typestate::{
        Delegation, Encryption, MaybeDelegation, MaybeEncryption, MaybeSigning,
        NoDelegation, NoEncryption, NoSigning, Signing,
    };
}
