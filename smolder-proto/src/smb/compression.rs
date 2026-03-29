//! SMB 3.1.1 compression wire types.

use std::convert::TryFrom;

use bitflags::bitflags;
use bytes::{BufMut, BytesMut};

use super::error::ProtocolError;

/// Protocol identifier for an SMB 3.1.1 compression transform.
pub const COMPRESSION_TRANSFORM_PROTOCOL_ID: [u8; 4] = [0xfc, b'S', b'M', b'B'];

/// The fixed SMB 3.1.1 compression transform header size in bytes.
pub const COMPRESSION_TRANSFORM_HEADER_LEN: usize = 16;

bitflags! {
    /// `SMB2_COMPRESSION_CAPABILITIES.Flags`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct CompressionCapabilityFlags: u32 {
        /// The endpoint supports chained compression payloads.
        const CHAINED = 0x0000_0001;
    }
}

bitflags! {
    /// Compression transform flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct CompressionFlags: u16 {
        /// The payload uses chained compression formatting.
        const CHAINED = 0x0001;
    }
}

/// SMB compression algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum CompressionAlgorithm {
    /// `NONE`
    None = 0x0000,
    /// `LZNT1`
    Lznt1 = 0x0001,
    /// `LZ77`
    Lz77 = 0x0002,
    /// `LZ77+Huffman`
    Lz77Huffman = 0x0003,
    /// `Pattern_V1`
    PatternV1 = 0x0004,
    /// `LZ4`
    Lz4 = 0x0005,
}

impl TryFrom<u16> for CompressionAlgorithm {
    type Error = ProtocolError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0000 => Ok(Self::None),
            0x0001 => Ok(Self::Lznt1),
            0x0002 => Ok(Self::Lz77),
            0x0003 => Ok(Self::Lz77Huffman),
            0x0004 => Ok(Self::PatternV1),
            0x0005 => Ok(Self::Lz4),
            _ => Err(ProtocolError::InvalidField {
                field: "compression_algorithm",
                reason: "unknown compression algorithm",
            }),
        }
    }
}

/// SMB 3.1.1 compression transform header plus the following payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressionTransformHeader {
    /// The size of the original uncompressed segment.
    pub original_compressed_segment_size: u32,
    /// Compression algorithm for the current transform.
    pub compression_algorithm: CompressionAlgorithm,
    /// Compression flags.
    pub flags: CompressionFlags,
    /// Offset from the end of the header to the compressed segment for
    /// unchained payloads. For chained payloads, this is the payload length.
    pub offset_or_length: u32,
    /// Raw bytes following the header.
    pub payload: Vec<u8>,
}

impl CompressionTransformHeader {
    /// Serializes the compression transform header and following payload.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(COMPRESSION_TRANSFORM_HEADER_LEN + self.payload.len());
        out.extend_from_slice(&COMPRESSION_TRANSFORM_PROTOCOL_ID);
        out.put_u32_le(self.original_compressed_segment_size);
        out.put_u16_le(self.compression_algorithm as u16);
        out.put_u16_le(self.flags.bits());
        out.put_u32_le(self.offset_or_length);
        out.extend_from_slice(&self.payload);
        out.to_vec()
    }

    /// Decodes a compression transform header and the following payload bytes.
    pub fn decode(packet: &[u8]) -> Result<Self, ProtocolError> {
        if packet.len() < COMPRESSION_TRANSFORM_HEADER_LEN {
            return Err(ProtocolError::UnexpectedEof {
                field: "compression_transform_header",
            });
        }
        if packet[..4] != COMPRESSION_TRANSFORM_PROTOCOL_ID {
            return Err(ProtocolError::InvalidField {
                field: "protocol_id",
                reason: "expected SMB compression transform protocol identifier",
            });
        }

        let flags =
            CompressionFlags::from_bits(u16::from_le_bytes(packet[10..12].try_into().map_err(
                |_| ProtocolError::UnexpectedEof { field: "flags" },
            )?))
            .ok_or(ProtocolError::InvalidField {
                field: "flags",
                reason: "unknown compression flags set",
            })?;

        Ok(Self {
            original_compressed_segment_size: u32::from_le_bytes(
                packet[4..8]
                    .try_into()
                    .map_err(|_| ProtocolError::UnexpectedEof {
                        field: "original_compressed_segment_size",
                    })?,
            ),
            compression_algorithm: CompressionAlgorithm::try_from(u16::from_le_bytes(
                packet[8..10]
                    .try_into()
                    .map_err(|_| ProtocolError::UnexpectedEof {
                        field: "compression_algorithm",
                    })?,
            ))?,
            flags,
            offset_or_length: u32::from_le_bytes(packet[12..16].try_into().map_err(|_| {
                ProtocolError::UnexpectedEof {
                    field: "offset_or_length",
                }
            })?),
            payload: packet[COMPRESSION_TRANSFORM_HEADER_LEN..].to_vec(),
        })
    }

    /// Returns the uncompressed prefix bytes for an unchained payload.
    pub fn prefix_data(&self) -> Result<&[u8], ProtocolError> {
        if self.flags.contains(CompressionFlags::CHAINED) {
            return Err(ProtocolError::InvalidField {
                field: "flags",
                reason: "prefix data is only defined for unchained compression payloads",
            });
        }

        let offset = self.offset_or_length as usize;
        if offset > self.payload.len() {
            return Err(ProtocolError::UnexpectedEof {
                field: "compression_prefix",
            });
        }
        Ok(&self.payload[..offset])
    }

    /// Returns the compressed segment bytes for an unchained payload.
    pub fn compressed_data(&self) -> Result<&[u8], ProtocolError> {
        if self.flags.contains(CompressionFlags::CHAINED) {
            return Err(ProtocolError::InvalidField {
                field: "flags",
                reason: "compressed data split is only defined for unchained compression payloads",
            });
        }

        let offset = self.offset_or_length as usize;
        if offset > self.payload.len() {
            return Err(ProtocolError::UnexpectedEof {
                field: "compression_payload",
            });
        }
        Ok(&self.payload[offset..])
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CompressionAlgorithm, CompressionFlags, CompressionTransformHeader,
        COMPRESSION_TRANSFORM_HEADER_LEN, COMPRESSION_TRANSFORM_PROTOCOL_ID,
    };

    #[test]
    fn compression_transform_roundtrips_unchained_payload() {
        let packet = CompressionTransformHeader {
            original_compressed_segment_size: 123,
            compression_algorithm: CompressionAlgorithm::Lznt1,
            flags: CompressionFlags::empty(),
            offset_or_length: 4,
            payload: vec![0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33],
        };

        let encoded = packet.encode();
        let decoded =
            CompressionTransformHeader::decode(&encoded).expect("compression header should decode");

        assert_eq!(encoded.len(), COMPRESSION_TRANSFORM_HEADER_LEN + 7);
        assert_eq!(&encoded[..4], &COMPRESSION_TRANSFORM_PROTOCOL_ID);
        assert_eq!(decoded.prefix_data().expect("prefix should decode"), &[0xaa, 0xbb, 0xcc, 0xdd]);
        assert_eq!(
            decoded.compressed_data().expect("segment should decode"),
            &[0x11, 0x22, 0x33]
        );
        assert_eq!(decoded, packet);
    }

    #[test]
    fn compression_transform_rejects_unknown_flags() {
        let mut packet = vec![0; COMPRESSION_TRANSFORM_HEADER_LEN];
        packet[..4].copy_from_slice(&COMPRESSION_TRANSFORM_PROTOCOL_ID);
        packet[8..10].copy_from_slice(&(CompressionAlgorithm::Lznt1 as u16).to_le_bytes());
        packet[10..12].copy_from_slice(&0x0002u16.to_le_bytes());

        let error = CompressionTransformHeader::decode(&packet)
            .expect_err("unknown compression flags should fail");
        assert_eq!(
            error.to_string(),
            "invalid field flags: unknown compression flags set"
        );
    }
}
