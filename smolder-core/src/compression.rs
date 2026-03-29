//! SMB 3.1.1 receive-side compression helpers.

use lznt1::decompress as lznt1_decompress;
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
