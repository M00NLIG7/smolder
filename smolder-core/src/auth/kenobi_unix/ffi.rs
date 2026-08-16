//! Narrow GSSAPI ABI required by Smolder's internal Kerberos wrapper.
//!
//! The layouts and signatures mirror RFC 2744/MIT-Heimdal GSSAPI headers. Every provider-owned
//! pointer is wrapped and validated by the calling modules before a Rust reference or slice is
//! created.

#![allow(non_camel_case_types, non_snake_case)]

#[cfg(not(target_os = "macos"))]
use std::ffi::c_char;
use std::ffi::{c_int, c_void};

#[repr(C)]
pub struct gss_name_struct {
    _private: [u8; 0],
}

#[repr(C)]
pub struct gss_cred_id_struct {
    _private: [u8; 0],
}

#[repr(C)]
pub struct gss_ctx_id_struct {
    _private: [u8; 0],
}

pub type gss_name_t = *mut gss_name_struct;
pub type gss_cred_id_t = *mut gss_cred_id_struct;
pub type gss_ctx_id_t = *mut gss_ctx_id_struct;

#[repr(C)]
pub struct gss_OID_desc_struct {
    pub length: u32,
    pub elements: *mut c_void,
}

pub type gss_OID_desc = gss_OID_desc_struct;
pub type gss_OID = *mut gss_OID_desc_struct;

#[repr(C)]
pub struct gss_OID_set_desc {
    pub count: usize,
    pub elements: gss_OID,
}

#[repr(C)]
pub struct gss_buffer_desc_struct {
    pub length: usize,
    pub value: *mut c_void,
}

pub type gss_buffer_desc = gss_buffer_desc_struct;
pub type gss_buffer_t = *mut gss_buffer_desc_struct;

#[repr(C)]
pub struct gss_channel_bindings_struct {
    pub initiator_addrtype: u32,
    pub initiator_address: gss_buffer_desc_struct,
    pub acceptor_addrtype: u32,
    pub acceptor_address: gss_buffer_desc_struct,
    pub application_data: gss_buffer_desc_struct,
}

#[repr(C)]
pub struct gss_buffer_set_desc_struct {
    pub count: usize,
    pub elements: gss_buffer_t,
}

#[cfg(not(target_os = "macos"))]
#[repr(C)]
pub struct gss_key_value_element_desc {
    pub key: *const c_char,
    pub value: *const c_char,
}

#[cfg(not(target_os = "macos"))]
#[repr(C)]
pub struct gss_key_value_set_desc {
    pub count: usize,
    pub elements: *mut gss_key_value_element_desc,
}

pub const GSS_C_MUTUAL_FLAG: u32 = 2;
pub const GSS_C_INTEG_FLAG: u32 = 32;

pub const GSS_C_INITIATE: c_int = 1;
pub const GSS_C_GSS_CODE: c_int = 1;
pub const GSS_C_MECH_CODE: c_int = 2;

pub const GSS_S_COMPLETE: u32 = 0;
pub const GSS_S_CONTINUE_NEEDED: u32 = 1;
pub const _GSS_C_INDEFINITE: u32 = u32::MAX;
pub const _GSS_S_FAILURE: u32 = 13 << 16;

#[cfg_attr(target_os = "macos", link(name = "GSS", kind = "framework"))]
#[cfg_attr(not(target_os = "macos"), link(name = "gssapi_krb5"))]
unsafe extern "C" {
    pub fn gss_acquire_cred(
        minor_status: *mut u32,
        desired_name: gss_name_t,
        time_req: u32,
        desired_mechs: *mut gss_OID_set_desc,
        cred_usage: c_int,
        output_cred_handle: *mut gss_cred_id_t,
        actual_mechs: *mut *mut gss_OID_set_desc,
        time_rec: *mut u32,
    ) -> u32;

    pub fn gss_acquire_cred_with_password(
        minor_status: *mut u32,
        desired_name: gss_name_t,
        password: gss_buffer_t,
        time_req: u32,
        desired_mechs: *mut gss_OID_set_desc,
        cred_usage: c_int,
        output_cred_handle: *mut gss_cred_id_t,
        actual_mechs: *mut *mut gss_OID_set_desc,
        time_rec: *mut u32,
    ) -> u32;

    pub fn gss_release_cred(minor_status: *mut u32, cred_handle: *mut gss_cred_id_t) -> u32;

    pub fn gss_init_sec_context(
        minor_status: *mut u32,
        claimant_cred_handle: gss_cred_id_t,
        context_handle: *mut gss_ctx_id_t,
        target_name: gss_name_t,
        mech_type: gss_OID,
        req_flags: u32,
        time_req: u32,
        input_chan_bindings: *mut gss_channel_bindings_struct,
        input_token: gss_buffer_t,
        actual_mech_type: *mut gss_OID,
        output_token: gss_buffer_t,
        ret_flags: *mut u32,
        time_rec: *mut u32,
    ) -> u32;

    pub fn gss_delete_sec_context(
        minor_status: *mut u32,
        context_handle: *mut gss_ctx_id_t,
        output_token: gss_buffer_t,
    ) -> u32;

    pub fn gss_display_status(
        minor_status: *mut u32,
        status_value: u32,
        status_type: c_int,
        mech_type: gss_OID,
        message_context: *mut u32,
        status_string: gss_buffer_t,
    ) -> u32;

    pub fn gss_display_name(
        minor_status: *mut u32,
        input_name: gss_name_t,
        output_name_buffer: gss_buffer_t,
        output_name_type: *mut gss_OID,
    ) -> u32;

    pub fn gss_import_name(
        minor_status: *mut u32,
        input_name_buffer: gss_buffer_t,
        input_name_type: gss_OID,
        output_name: *mut gss_name_t,
    ) -> u32;

    pub fn gss_release_name(minor_status: *mut u32, input_name: *mut gss_name_t) -> u32;
    pub fn gss_release_buffer(minor_status: *mut u32, buffer: gss_buffer_t) -> u32;

    pub fn gss_inquire_sec_context_by_oid(
        minor_status: *mut u32,
        context_handle: gss_ctx_id_t,
        desired_object: gss_OID,
        data_set: *mut *mut gss_buffer_set_desc_struct,
    ) -> u32;

    pub fn gss_release_buffer_set(
        minor_status: *mut u32,
        buffer_set: *mut *mut gss_buffer_set_desc_struct,
    ) -> u32;
}

#[cfg(not(target_os = "macos"))]
#[link(name = "gssapi_krb5")]
unsafe extern "C" {
    pub fn gss_acquire_cred_from(
        minor_status: *mut u32,
        desired_name: gss_name_t,
        time_req: u32,
        desired_mechs: *mut gss_OID_set_desc,
        cred_usage: c_int,
        cred_store: *const gss_key_value_set_desc,
        output_cred_handle: *mut gss_cred_id_t,
        actual_mechs: *mut *mut gss_OID_set_desc,
        time_rec: *mut u32,
    ) -> u32;
}
