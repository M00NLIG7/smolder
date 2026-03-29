//! SMB 3.1.1 compression helpers.

use lznt1::compress as lznt1_compress;
use lznt1::decompress as lznt1_decompress;
use lzxpress::data::compress as lz77_compress;
use lzxpress::data::decompress as lz77_decompress;
use smolder_proto::smb::compression::{
    CompressionAlgorithm, CompressionFlags, CompressionTransformHeader,
};

use crate::error::CoreError;

/// Negotiated SMB compression state for one session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressionState {
    /// The selected compression algorithm.
    pub algorithm: CompressionAlgorithm,
    /// Whether chained compression payloads are negotiated.
    pub chained: bool,
}

impl CompressionState {
    /// Creates a compression state from the negotiated server selection.
    #[must_use]
    pub fn new(algorithm: CompressionAlgorithm, chained: bool) -> Self {
        Self { algorithm, chained }
    }

    /// Compresses one SMB2 message into an SMB compression transform when beneficial.
    pub fn compress_message(&self, message: &[u8]) -> Result<Option<Vec<u8>>, CoreError> {
        if self.chained {
            return Err(CoreError::Unsupported(
                "SMB chained compression payloads are not supported yet",
            ));
        }
        if message.is_empty() {
            return Ok(None);
        }

        let compressed = match self.algorithm {
            CompressionAlgorithm::Lznt1 => {
                let mut buffer = Vec::new();
                lznt1_compress(message, &mut buffer);
                buffer
            }
            CompressionAlgorithm::Lz77 => lz77_compress(message)
                .map_err(|_| CoreError::InvalidInput("SMB LZ77 request could not be compressed"))?,
            CompressionAlgorithm::None
            | CompressionAlgorithm::Lz77Huffman
            | CompressionAlgorithm::PatternV1
            | CompressionAlgorithm::Lz4 => {
                return Err(CoreError::Unsupported(
                    "the negotiated SMB compression algorithm is not supported yet",
                ));
            }
        };

        if compressed.len() >= message.len() {
            return Ok(None);
        }

        Ok(Some(
            CompressionTransformHeader {
                original_compressed_segment_size: message.len() as u32,
                compression_algorithm: self.algorithm,
                flags: CompressionFlags::empty(),
                offset_or_length: 0,
                payload: compressed,
            }
            .encode(),
        ))
    }

    /// Decompresses one SMB compression transform into the original SMB2 bytes.
    pub fn decompress_message(
        &self,
        message: &CompressionTransformHeader,
    ) -> Result<Vec<u8>, CoreError> {
        if message.flags.contains(CompressionFlags::CHAINED) {
            return Err(CoreError::Unsupported(
                "SMB chained compression payloads are not supported yet",
            ));
        }
        if self.chained && message.flags.is_empty() {
            return Err(CoreError::InvalidResponse(
                "SMB response used an unexpected unchained compression payload",
            ));
        }
        if message.compression_algorithm != self.algorithm {
            return Err(CoreError::InvalidResponse(
                "SMB response used a compression algorithm that was not negotiated",
            ));
        }

        let prefix = message.prefix_data().map_err(CoreError::from)?;
        let compressed = message.compressed_data().map_err(CoreError::from)?;
        let mut output = prefix.to_vec();
        let decompressed = match message.compression_algorithm {
            CompressionAlgorithm::Lznt1 => {
                let mut buffer = Vec::new();
                lznt1_decompress(compressed, &mut buffer)
                    .map_err(|_| CoreError::InvalidResponse("SMB LZNT1 response could not be decompressed"))?;
                buffer
            }
            CompressionAlgorithm::Lz77 => lz77_decompress(compressed)
                .map_err(|_| CoreError::InvalidResponse("SMB LZ77 response could not be decompressed"))?,
            CompressionAlgorithm::None
            | CompressionAlgorithm::Lz77Huffman
            | CompressionAlgorithm::PatternV1
            | CompressionAlgorithm::Lz4 => {
                return Err(CoreError::Unsupported(
                    "the negotiated SMB compression algorithm is not supported yet",
                ));
            }
        };
        if decompressed.len() != message.original_compressed_segment_size as usize {
            return Err(CoreError::InvalidResponse(
                "SMB compressed response size did not match the transform header",
            ));
        }
        output.extend_from_slice(&decompressed);
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use smolder_proto::smb::compression::{
        CompressionAlgorithm, CompressionFlags, CompressionTransformHeader,
    };

    use super::CompressionState;

    #[test]
    fn decompresses_lznt1_uncompressed_fallback_blocks() {
        let state = CompressionState::new(CompressionAlgorithm::Lznt1, false);
        let original = b"hello";
        let message = CompressionTransformHeader {
            original_compressed_segment_size: original.len() as u32,
            compression_algorithm: CompressionAlgorithm::Lznt1,
            flags: CompressionFlags::empty(),
            offset_or_length: 0,
            payload: vec![0x04, 0x30, b'h', b'e', b'l', b'l', b'o'],
        };

        let decoded = state
            .decompress_message(&message)
            .expect("LZNT1 fallback block should decompress");
        assert_eq!(decoded, original);
    }

    #[test]
    fn compresses_lznt1_messages_when_the_transform_is_smaller() {
        let state = CompressionState::new(CompressionAlgorithm::Lznt1, false);
        let original = vec![b'A'; 4096];

        let encoded = state
            .compress_message(&original)
            .expect("compression should succeed")
            .expect("highly repetitive data should compress");
        let transform =
            CompressionTransformHeader::decode(&encoded).expect("transform should decode");
        let decoded = state
            .decompress_message(&transform)
            .expect("transform should decompress");

        assert_eq!(decoded, original);
    }

    #[test]
    fn skips_compression_when_the_transform_would_not_shrink() {
        let state = CompressionState::new(CompressionAlgorithm::Lznt1, false);
        let original: Vec<u8> = (0u8..32).collect();

        let encoded = state
            .compress_message(&original)
            .expect("compression should succeed");

        assert!(encoded.is_none());
    }

    #[test]
    fn rejects_unexpected_algorithm() {
        let state = CompressionState::new(CompressionAlgorithm::Lznt1, false);
        let message = CompressionTransformHeader {
            original_compressed_segment_size: 1,
            compression_algorithm: CompressionAlgorithm::Lz77,
            flags: CompressionFlags::empty(),
            offset_or_length: 0,
            payload: vec![0],
        };

        let error = state
            .decompress_message(&message)
            .expect_err("unexpected algorithm should fail");
        assert_eq!(
            error.to_string(),
            "invalid response: SMB response used a compression algorithm that was not negotiated"
        );
    }
}
