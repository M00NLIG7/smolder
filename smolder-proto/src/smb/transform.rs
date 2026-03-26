//! SMB 3.x transform-header wire types.

use bytes::{BufMut, BytesMut};

use super::error::ProtocolError;

/// Protocol identifier for an SMB 3.x transform header.
pub const TRANSFORM_PROTOCOL_ID: [u8; 4] = [0xfd, b'S', b'M', b'B'];

/// The fixed SMB 3.x transform header size in bytes.
pub const TRANSFORM_HEADER_LEN: usize = 52;

/// The dialect-dependent transform field value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransformValue(pub u16);

impl TransformValue {
    /// `Encrypted`
    pub const ENCRYPTED: Self = Self(0x0001);
}

/// An SMB 3.x transform header plus the encrypted SMB2 message bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransformHeader {
    /// The 16-byte signature or authentication tag.
    pub signature: [u8; 16],
    /// The 16-byte nonce field.
    pub nonce: [u8; 16],
    /// The size of the original SMB2 message before encryption.
    pub original_message_size: u32,
    /// The dialect-dependent flags or encryption algorithm field.
    pub flags_or_algorithm: TransformValue,
    /// The SMB session identifier for this encrypted message.
    pub session_id: u64,
    /// The encrypted SMB2 message that follows the transform header.
    pub encrypted_message: Vec<u8>,
}

impl TransformHeader {
    /// Serializes the transform header and ciphertext.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(TRANSFORM_HEADER_LEN + self.encrypted_message.len());
        out.extend_from_slice(&TRANSFORM_PROTOCOL_ID);
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&self.nonce);
        out.put_u32_le(self.original_message_size);
        out.put_u16_le(0);
        out.put_u16_le(self.flags_or_algorithm.0);
        out.put_u64_le(self.session_id);
        out.extend_from_slice(&self.encrypted_message);
        out.to_vec()
    }

    /// Decodes a transform header and the following encrypted bytes.
    pub fn decode(packet: &[u8]) -> Result<Self, ProtocolError> {
        if packet.len() < TRANSFORM_HEADER_LEN {
            return Err(ProtocolError::UnexpectedEof {
                field: "transform_header",
            });
        }
        if packet[..4] != TRANSFORM_PROTOCOL_ID {
            return Err(ProtocolError::InvalidField {
                field: "protocol_id",
                reason: "expected SMB transform protocol identifier",
            });
        }

        Ok(Self {
            signature: packet[4..20].try_into().map_err(|_| ProtocolError::UnexpectedEof {
                field: "signature",
            })?,
            nonce: packet[20..36].try_into().map_err(|_| ProtocolError::UnexpectedEof {
                field: "nonce",
            })?,
            original_message_size: u32::from_le_bytes(
                packet[36..40].try_into().map_err(|_| ProtocolError::UnexpectedEof {
                    field: "original_message_size",
                })?,
            ),
            flags_or_algorithm: TransformValue(u16::from_le_bytes(
                packet[42..44].try_into().map_err(|_| ProtocolError::UnexpectedEof {
                    field: "flags_or_algorithm",
                })?,
            )),
            session_id: u64::from_le_bytes(
                packet[44..52].try_into().map_err(|_| ProtocolError::UnexpectedEof {
                    field: "session_id",
                })?,
            ),
            encrypted_message: packet[TRANSFORM_HEADER_LEN..].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{TransformHeader, TransformValue, TRANSFORM_HEADER_LEN, TRANSFORM_PROTOCOL_ID};

    #[test]
    fn transform_header_roundtrips() {
        let packet = TransformHeader {
            signature: [0x11; 16],
            nonce: [0x22; 16],
            original_message_size: 0x0102_0304,
            flags_or_algorithm: TransformValue::ENCRYPTED,
            session_id: 0x1122_3344_5566_7788,
            encrypted_message: vec![0xaa, 0xbb, 0xcc, 0xdd],
        };

        let encoded = packet.encode();
        let decoded = TransformHeader::decode(&encoded).expect("transform header should decode");

        assert_eq!(encoded.len(), TRANSFORM_HEADER_LEN + 4);
        assert_eq!(&encoded[..4], &TRANSFORM_PROTOCOL_ID);
        assert_eq!(decoded, packet);
    }

    #[test]
    fn transform_header_rejects_wrong_protocol_id() {
        let mut packet = vec![0; TRANSFORM_HEADER_LEN];
        packet[..4].copy_from_slice(b"\xfeSMB");

        let error = TransformHeader::decode(&packet).expect_err("protocol mismatch should fail");

        assert_eq!(
            error.to_string(),
            "invalid field protocol_id: expected SMB transform protocol identifier"
        );
    }
}
