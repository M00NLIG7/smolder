//! RFC1002 session service framing.

use bytes::{Buf, BufMut, BytesMut};

use super::ProtocolError;

/// Session service message type for SMB payloads.
pub const SESSION_MESSAGE: u8 = 0x00;
const LENGTH_MASK: usize = 0x00ff_ffff;

/// An RFC1002 session message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionMessage {
    /// The session service message type.
    pub message_type: u8,
    /// The framed payload.
    pub payload: Vec<u8>,
}

impl SessionMessage {
    /// Creates a session message carrying an SMB payload.
    #[must_use]
    pub fn new(payload: Vec<u8>) -> Self {
        Self {
            message_type: SESSION_MESSAGE,
            payload,
        }
    }

    /// Serializes a payload into an RFC1002 session frame without first allocating a `SessionMessage`.
    pub fn encode_payload(payload: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        if payload.len() > LENGTH_MASK {
            return Err(ProtocolError::SizeLimitExceeded { field: "payload" });
        }

        let mut out = BytesMut::with_capacity(4 + payload.len());
        out.put_u8(SESSION_MESSAGE);
        out.put_uint(payload.len() as u64, 3);
        out.extend_from_slice(payload);
        Ok(out.to_vec())
    }

    /// Serializes the frame into bytes.
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        if self.message_type == SESSION_MESSAGE {
            return Self::encode_payload(&self.payload);
        }
        if self.payload.len() > LENGTH_MASK {
            return Err(ProtocolError::SizeLimitExceeded { field: "payload" });
        }

        let mut out = BytesMut::with_capacity(4 + self.payload.len());
        out.put_u8(self.message_type);
        out.put_uint(self.payload.len() as u64, 3);
        out.extend_from_slice(&self.payload);
        Ok(out.to_vec())
    }

    /// Parses a framed session message.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() < 4 {
            return Err(ProtocolError::UnexpectedEof {
                field: "session header",
            });
        }

        let mut input = bytes;
        let message_type = input.get_u8();
        let payload_len = input.get_uint(3) as usize;
        if input.remaining() != payload_len {
            return Err(ProtocolError::InvalidField {
                field: "payload_len",
                reason: "frame length does not match payload",
            });
        }

        Ok(Self {
            message_type,
            payload: input.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{SessionMessage, SESSION_MESSAGE};

    #[test]
    fn session_message_roundtrips() {
        let message = SessionMessage::new(vec![0xfe, b'S', b'M', b'B']);
        let encoded = message.encode().expect("frame should encode");
        let decoded = SessionMessage::decode(&encoded).expect("frame should decode");

        assert_eq!(decoded.message_type, SESSION_MESSAGE);
        assert_eq!(decoded.payload, vec![0xfe, b'S', b'M', b'B']);
    }
}
