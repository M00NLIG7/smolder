//! SMB2 cancel request body.

use bytes::{BufMut, BytesMut};

use super::{check_fixed_structure_size, get_u16};
use crate::smb::ProtocolError;

/// SMB2 cancel request body.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CancelRequest;

impl CancelRequest {
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

#[cfg(test)]
mod tests {
    use super::CancelRequest;

    #[test]
    fn cancel_request_roundtrips() {
        let request = CancelRequest;
        let encoded = request.encode();
        let decoded = CancelRequest::decode(&encoded).expect("cancel request should decode");
        assert_eq!(decoded, request);
    }
}
