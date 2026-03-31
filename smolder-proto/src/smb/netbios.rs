//! RFC1002 session service framing.

use bytes::{Buf, BufMut, BytesMut};

use super::ProtocolError;

/// Session service message type for SMB payloads.
pub const SESSION_MESSAGE: u8 = 0x00;
/// Session request packet type used when establishing a NetBIOS session.
pub const SESSION_REQUEST: u8 = 0x81;
/// Positive session response packet type.
pub const POSITIVE_SESSION_RESPONSE: u8 = 0x82;
/// Negative session response packet type.
pub const NEGATIVE_SESSION_RESPONSE: u8 = 0x83;
/// Retarget session response packet type.
pub const RETARGET_SESSION_RESPONSE: u8 = 0x84;
/// Session keep-alive packet type.
pub const SESSION_KEEP_ALIVE: u8 = 0x85;
const LENGTH_MASK: usize = 0x00ff_ffff;
const ENCODED_NAME_LEN: usize = 32;
const NETBIOS_NAME_BYTES: usize = 16;

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

    /// Builds an RFC1002 session request packet for the provided called and calling names.
    pub fn session_request(called_name: &str, calling_name: &str) -> Result<Self, ProtocolError> {
        let mut payload = encode_name(called_name, 0x20)?;
        payload.extend_from_slice(&encode_name(calling_name, 0x00)?);
        Ok(Self {
            message_type: SESSION_REQUEST,
            payload,
        })
    }
}

/// Encodes one NetBIOS session-service name in second-level RFC1002 form.
pub fn encode_name(name: &str, suffix: u8) -> Result<Vec<u8>, ProtocolError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(ProtocolError::InvalidField {
            field: "name",
            reason: "NetBIOS name must not be empty",
        });
    }
    if !trimmed.is_ascii() {
        return Err(ProtocolError::InvalidField {
            field: "name",
            reason: "NetBIOS names must be ASCII",
        });
    }

    let mut canonical = [b' '; NETBIOS_NAME_BYTES];
    let upper = trimmed.to_ascii_uppercase();
    for (index, byte) in upper.bytes().take(NETBIOS_NAME_BYTES - 1).enumerate() {
        canonical[index] = byte;
    }
    canonical[NETBIOS_NAME_BYTES - 1] = suffix;

    let mut encoded = Vec::with_capacity(1 + ENCODED_NAME_LEN + 1);
    encoded.push(ENCODED_NAME_LEN as u8);
    for byte in canonical {
        encoded.push(b'A' + (byte >> 4));
        encoded.push(b'A' + (byte & 0x0f));
    }
    encoded.push(0);
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use super::{
        encode_name, SessionMessage, NEGATIVE_SESSION_RESPONSE, POSITIVE_SESSION_RESPONSE,
        SESSION_MESSAGE, SESSION_REQUEST,
    };
    use crate::smb::ProtocolError;

    #[test]
    fn session_message_roundtrips() {
        let message = SessionMessage::new(vec![0xfe, b'S', b'M', b'B']);
        let encoded = message.encode().expect("frame should encode");
        let decoded = SessionMessage::decode(&encoded).expect("frame should decode");

        assert_eq!(decoded.message_type, SESSION_MESSAGE);
        assert_eq!(decoded.payload, vec![0xfe, b'S', b'M', b'B']);
    }

    #[test]
    fn session_request_roundtrips() {
        let request =
            SessionMessage::session_request("FILESERVER", "SMOLDER").expect("request should encode");
        let encoded = request.encode().expect("request should frame");
        let decoded = SessionMessage::decode(&encoded).expect("request should decode");

        assert_eq!(decoded.message_type, SESSION_REQUEST);
        assert_eq!(decoded.payload.len(), 68);
    }

    #[test]
    fn encode_name_pads_and_uppercases() {
        let encoded = encode_name("fileSrv", 0x20).expect("name should encode");

        assert_eq!(encoded[0], 32);
        assert_eq!(encoded.len(), 34);
        assert_eq!(&encoded[1..5], b"EGEJ");
        assert_eq!(encoded[33], 0);
    }

    #[test]
    fn encode_name_rejects_non_ascii() {
        let error = encode_name("smolder-\u{00f1}", 0x20).expect_err("name should fail");
        assert_eq!(
            error,
            ProtocolError::InvalidField {
                field: "name",
                reason: "NetBIOS names must be ASCII",
            }
        );
    }

    #[test]
    fn negative_and_positive_response_frames_decode() {
        let positive = SessionMessage {
            message_type: POSITIVE_SESSION_RESPONSE,
            payload: Vec::new(),
        }
        .encode()
        .expect("positive response should encode");
        let negative = SessionMessage {
            message_type: NEGATIVE_SESSION_RESPONSE,
            payload: vec![0x82],
        }
        .encode()
        .expect("negative response should encode");

        assert_eq!(
            SessionMessage::decode(&positive)
                .expect("positive response should decode")
                .message_type,
            POSITIVE_SESSION_RESPONSE
        );
        assert_eq!(
            SessionMessage::decode(&negative)
                .expect("negative response should decode")
                .payload,
            vec![0x82]
        );
    }
}
