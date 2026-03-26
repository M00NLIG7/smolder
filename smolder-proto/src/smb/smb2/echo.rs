//! SMB2 echo request and response bodies.

use bytes::{BufMut, BytesMut};

use super::{check_fixed_structure_size, get_u16};
use crate::smb::ProtocolError;

/// SMB2 echo request body.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EchoRequest;

impl EchoRequest {
    /// Serializes the request body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(4);
        out.put_u16_le(4);
        out.put_u16_le(0);
        out.to_vec()
    }

    /// Parses the request body.
    pub fn decode(body: &[u8]) -> Result<Self, ProtocolError> {
        let mut input = body;
        check_fixed_structure_size(get_u16(&mut input, "structure_size")?, 4, "structure_size")?;
        let _reserved = get_u16(&mut input, "reserved")?;
        Ok(Self)
    }
}

/// SMB2 echo response body.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EchoResponse;

impl EchoResponse {
    /// Serializes the response body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(4);
        out.put_u16_le(4);
        out.put_u16_le(0);
        out.to_vec()
    }

    /// Parses the response body.
    pub fn decode(body: &[u8]) -> Result<Self, ProtocolError> {
        let mut input = body;
        check_fixed_structure_size(get_u16(&mut input, "structure_size")?, 4, "structure_size")?;
        let _reserved = get_u16(&mut input, "reserved")?;
        Ok(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::{EchoRequest, EchoResponse};

    #[test]
    fn echo_request_roundtrips() {
        let request = EchoRequest;
        let encoded = request.encode();
        let decoded = EchoRequest::decode(&encoded).expect("echo request should decode");
        assert_eq!(decoded, request);
    }

    #[test]
    fn echo_response_roundtrips() {
        let response = EchoResponse;
        let encoded = response.encode();
        let decoded = EchoResponse::decode(&encoded).expect("echo response should decode");
        assert_eq!(decoded, response);
    }
}
