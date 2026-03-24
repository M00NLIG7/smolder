//! SMB2 session setup bodies.

use bitflags::bitflags;
use bytes::{BufMut, BytesMut};

use super::{check_fixed_structure_size, get_u16, get_u32, get_u64, slice_from_offset, HEADER_LEN};
use crate::smb::ProtocolError;

bitflags! {
    /// Request security mode flags for `SESSION_SETUP`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct SessionSetupSecurityMode: u8 {
        /// Signing is enabled for the client.
        const SIGNING_ENABLED = 0x01;
        /// Signing is required for the client.
        const SIGNING_REQUIRED = 0x02;
    }
}

bitflags! {
    /// Response session flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct SessionFlags: u16 {
        /// Guest session.
        const IS_GUEST = 0x0001;
        /// Null session.
        const IS_NULL = 0x0002;
        /// Encryption required for this session.
        const ENCRYPT_DATA = 0x0004;
    }
}

/// SMB2 session setup request body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSetupRequest {
    /// Binding flags.
    pub flags: u8,
    /// Signing requirements for the client.
    pub security_mode: SessionSetupSecurityMode,
    /// Client capabilities.
    pub capabilities: u32,
    /// Channel sequence or binding identifier.
    pub channel: u32,
    /// Security buffer containing SPNEGO/NTLM payloads.
    pub security_buffer: Vec<u8>,
    /// Previous session identifier used for binding or reconnect.
    pub previous_session_id: u64,
}

impl SessionSetupRequest {
    /// Serializes the request body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(32 + self.security_buffer.len());
        out.put_u16_le(25);
        out.put_u8(self.flags);
        out.put_u8(self.security_mode.bits());
        out.put_u32_le(self.capabilities);
        out.put_u32_le(self.channel);
        out.put_u16_le((HEADER_LEN + 24) as u16);
        out.put_u16_le(self.security_buffer.len() as u16);
        out.put_u64_le(self.previous_session_id);
        out.extend_from_slice(&self.security_buffer);
        out.to_vec()
    }

    /// Parses the request body.
    pub fn decode(body: &[u8]) -> Result<Self, ProtocolError> {
        let mut input = body;
        check_fixed_structure_size(get_u16(&mut input, "structure_size")?, 25, "structure_size")?;
        let flags = super::get_u8(&mut input, "flags")?;
        let security_mode =
            SessionSetupSecurityMode::from_bits(super::get_u8(&mut input, "security_mode")?)
                .ok_or(ProtocolError::InvalidField {
                    field: "security_mode",
                    reason: "unknown session setup security bits set",
                })?;
        let capabilities = get_u32(&mut input, "capabilities")?;
        let channel = get_u32(&mut input, "channel")?;
        let security_buffer_offset = get_u16(&mut input, "security_buffer_offset")?;
        let security_buffer_length = usize::from(get_u16(&mut input, "security_buffer_length")?);
        let previous_session_id = get_u64(&mut input, "previous_session_id")?;
        let security_buffer = slice_from_offset(
            body,
            security_buffer_offset,
            security_buffer_length,
            "security_buffer",
        )?
        .to_vec();

        Ok(Self {
            flags,
            security_mode,
            capabilities,
            channel,
            security_buffer,
            previous_session_id,
        })
    }
}

/// SMB2 session setup response body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSetupResponse {
    /// Resulting session flags.
    pub session_flags: SessionFlags,
    /// Security token or challenge payload.
    pub security_buffer: Vec<u8>,
}

impl SessionSetupResponse {
    /// Serializes the response body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(16 + self.security_buffer.len());
        out.put_u16_le(9);
        out.put_u16_le(self.session_flags.bits());
        out.put_u16_le((HEADER_LEN + 8) as u16);
        out.put_u16_le(self.security_buffer.len() as u16);
        out.extend_from_slice(&self.security_buffer);
        out.to_vec()
    }

    /// Parses the response body.
    pub fn decode(body: &[u8]) -> Result<Self, ProtocolError> {
        let mut input = body;
        check_fixed_structure_size(get_u16(&mut input, "structure_size")?, 9, "structure_size")?;
        let session_flags = SessionFlags::from_bits(get_u16(&mut input, "session_flags")?).ok_or(
            ProtocolError::InvalidField {
                field: "session_flags",
                reason: "unknown session flags set",
            },
        )?;
        let security_buffer_offset = get_u16(&mut input, "security_buffer_offset")?;
        let security_buffer_length = usize::from(get_u16(&mut input, "security_buffer_length")?);
        let security_buffer = slice_from_offset(
            body,
            security_buffer_offset,
            security_buffer_length,
            "security_buffer",
        )?
        .to_vec();

        Ok(Self {
            session_flags,
            security_buffer,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SessionFlags, SessionSetupRequest, SessionSetupResponse, SessionSetupSecurityMode,
    };

    #[test]
    fn session_setup_request_roundtrips() {
        let request = SessionSetupRequest {
            flags: 0,
            security_mode: SessionSetupSecurityMode::SIGNING_ENABLED,
            capabilities: 0x11,
            channel: 0,
            security_buffer: vec![0x60, 0x48, 0x06, 0x06],
            previous_session_id: 55,
        };

        let encoded = request.encode();
        let decoded = SessionSetupRequest::decode(&encoded).expect("request should decode");

        assert_eq!(decoded, request);
    }

    #[test]
    fn session_setup_response_roundtrips() {
        let response = SessionSetupResponse {
            session_flags: SessionFlags::IS_GUEST,
            security_buffer: vec![0xa1, 0x81, 0x11],
        };

        let encoded = response.encode();
        let decoded = SessionSetupResponse::decode(&encoded).expect("response should decode");

        assert_eq!(decoded, response);
    }
}
