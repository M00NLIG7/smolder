//! SMB 3.1.1 compression helpers.

use lznt1::compress as lznt1_compress;
use lzxpress::data::compress as lz77_compress;
use smolder_proto::smb::compression::{
    CompressionAlgorithm, CompressionFlags, CompressionTransformHeader,
};

use crate::error::CoreError;

const MAX_DECOMPRESSED_MESSAGE_SIZE: usize = 0x00ff_ffff;

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
        self.decompress_message_with_limit(message, MAX_DECOMPRESSED_MESSAGE_SIZE)
    }

    pub(crate) fn decompress_message_with_limit(
        &self,
        message: &CompressionTransformHeader,
        maximum: usize,
    ) -> Result<Vec<u8>, CoreError> {
        let maximum = maximum.min(MAX_DECOMPRESSED_MESSAGE_SIZE);
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
        let decompressed_len = usize::try_from(message.original_compressed_segment_size)
            .map_err(|_| CoreError::InvalidResponse("SMB compressed response size was invalid"))?;
        if prefix
            .len()
            .checked_add(decompressed_len)
            .is_none_or(|len| len > maximum)
        {
            return Err(CoreError::InvalidResponse(
                "SMB compressed response expanded beyond maximum message size",
            ));
        }

        let output_capacity =
            prefix
                .len()
                .checked_add(decompressed_len)
                .ok_or(CoreError::InvalidResponse(
                    "SMB decompressed response length overflowed",
                ))?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(output_capacity)
            .map_err(|_| CoreError::AllocationFailed("decompressed SMB response"))?;
        output.extend_from_slice(prefix);
        let decompressed = match message.compression_algorithm {
            CompressionAlgorithm::Lznt1 => decompress_lznt1_bounded(compressed, decompressed_len)?,
            CompressionAlgorithm::Lz77 => decompress_lz77_bounded(compressed, decompressed_len)?,
            CompressionAlgorithm::None
            | CompressionAlgorithm::Lz77Huffman
            | CompressionAlgorithm::PatternV1
            | CompressionAlgorithm::Lz4 => {
                return Err(CoreError::Unsupported(
                    "the negotiated SMB compression algorithm is not supported yet",
                ));
            }
        };
        if decompressed.len() != decompressed_len {
            return Err(CoreError::InvalidResponse(
                "SMB compressed response size did not match the transform header",
            ));
        }
        output.extend_from_slice(&decompressed);
        Ok(output)
    }
}

fn decompress_lznt1_bounded(input: &[u8], expected: usize) -> Result<Vec<u8>, CoreError> {
    const HEADER_SIZE_MASK: u16 = 0x0fff;
    const HEADER_SIGNATURE_MASK: u16 = 0x7000;
    const HEADER_SIGNATURE: u16 = 0x3000;
    const HEADER_COMPRESSED: u16 = 0x8000;
    const BLOCK_LIMIT: usize = 4096;

    let mut output = bounded_output(expected, "SMB LZNT1 response")?;
    let mut input_offset = 0usize;
    while input_offset < input.len() {
        if input.len() - input_offset == 1 && input[input_offset] == 0 {
            break;
        }
        let header_end = input_offset
            .checked_add(2)
            .ok_or(CoreError::InvalidResponse(
                "SMB LZNT1 input offset overflowed",
            ))?;
        let header_bytes =
            input
                .get(input_offset..header_end)
                .ok_or(CoreError::InvalidResponse(
                    "SMB LZNT1 response ended inside a chunk header",
                ))?;
        let header = u16::from_le_bytes([header_bytes[0], header_bytes[1]]);
        input_offset = header_end;
        if header == 0 {
            if input[input_offset..].iter().any(|byte| *byte != 0) {
                return Err(CoreError::InvalidResponse(
                    "SMB LZNT1 response carried bytes after its terminator",
                ));
            }
            break;
        }
        if header & HEADER_SIGNATURE_MASK != HEADER_SIGNATURE {
            return Err(CoreError::InvalidResponse(
                "SMB LZNT1 response used an invalid chunk signature",
            ));
        }
        let chunk_len = usize::from((header & HEADER_SIZE_MASK) + 1);
        let chunk_end = input_offset
            .checked_add(chunk_len)
            .ok_or(CoreError::InvalidResponse(
                "SMB LZNT1 chunk length overflowed",
            ))?;
        let chunk = input
            .get(input_offset..chunk_end)
            .ok_or(CoreError::InvalidResponse(
                "SMB LZNT1 chunk extended past the response",
            ))?;
        if header & HEADER_COMPRESSED == 0 {
            let block_start = output.len();
            append_limited(
                &mut output,
                chunk,
                expected,
                block_start,
                BLOCK_LIMIT,
                "SMB LZNT1 response expanded beyond its declared size",
            )?;
        } else {
            decompress_lznt1_block(chunk, &mut output, expected, BLOCK_LIMIT)?;
        }
        input_offset = chunk_end;
    }
    if output.len() != expected {
        return Err(CoreError::InvalidResponse(
            "SMB LZNT1 response size did not match the transform header",
        ));
    }
    Ok(output)
}

fn decompress_lznt1_block(
    input: &[u8],
    output: &mut Vec<u8>,
    expected: usize,
    block_limit: usize,
) -> Result<(), CoreError> {
    let block_start = output.len();
    let mut input_offset = 0usize;
    let mut split = 12usize;
    let mut mask = (1usize << split) - 1;
    let mut threshold = 16usize;

    while input_offset < input.len() {
        let tags = input[input_offset];
        input_offset += 1;
        for bit in 0..8 {
            if input_offset >= input.len() {
                return Ok(());
            }
            if (tags >> bit) & 1 == 0 {
                ensure_lznt1_growth(output, 1, expected, block_start, block_limit)?;
                output.push(input[input_offset]);
                input_offset += 1;
            } else {
                let tuple_end = input_offset
                    .checked_add(2)
                    .ok_or(CoreError::InvalidResponse(
                        "SMB LZNT1 tuple offset overflowed",
                    ))?;
                let tuple =
                    input
                        .get(input_offset..tuple_end)
                        .ok_or(CoreError::InvalidResponse(
                            "SMB LZNT1 response ended inside a match tuple",
                        ))?;
                input_offset = tuple_end;
                let tuple = usize::from(u16::from_le_bytes([tuple[0], tuple[1]]));
                let length = (tuple & mask)
                    .checked_add(3)
                    .ok_or(CoreError::InvalidResponse(
                        "SMB LZNT1 match length overflowed",
                    ))?;
                let offset = (tuple >> split)
                    .checked_add(1)
                    .ok_or(CoreError::InvalidResponse(
                        "SMB LZNT1 match offset overflowed",
                    ))?;
                let block_output_len = output.len() - block_start;
                if offset > block_output_len {
                    return Err(CoreError::InvalidResponse(
                        "SMB LZNT1 match referenced bytes outside its chunk",
                    ));
                }
                ensure_lznt1_growth(output, length, expected, block_start, block_limit)?;
                for _ in 0..length {
                    let source = output.len() - offset;
                    let byte = output[source];
                    output.push(byte);
                }
            }

            let block_output_len = output.len() - block_start;
            while block_output_len > threshold {
                if split > 0 {
                    split -= 1;
                    mask = (1usize << split) - 1;
                }
                threshold = threshold.checked_mul(2).ok_or(CoreError::InvalidResponse(
                    "SMB LZNT1 adaptive threshold overflowed",
                ))?;
            }
        }
    }
    Ok(())
}

fn ensure_lznt1_growth(
    output: &[u8],
    additional: usize,
    expected: usize,
    block_start: usize,
    block_limit: usize,
) -> Result<(), CoreError> {
    let new_len = output
        .len()
        .checked_add(additional)
        .ok_or(CoreError::InvalidResponse(
            "SMB LZNT1 output length overflowed",
        ))?;
    if new_len > expected || new_len - block_start > block_limit {
        return Err(CoreError::InvalidResponse(
            "SMB LZNT1 response expanded beyond its declared size",
        ));
    }
    Ok(())
}

fn decompress_lz77_bounded(input: &[u8], expected: usize) -> Result<Vec<u8>, CoreError> {
    let mut output = bounded_output(expected, "SMB LZ77 response")?;
    let mut input_offset = 0usize;
    let mut nibble_offset = None;
    let mut flags = 0u32;
    let mut flags_remaining = 0u32;

    while input_offset < input.len() {
        if flags_remaining == 0 {
            flags = read_lz77_u32(input, &mut input_offset)?;
            flags_remaining = 32;
        }
        flags_remaining -= 1;
        if flags & (1u32 << flags_remaining) == 0 {
            let byte = *input.get(input_offset).ok_or(CoreError::InvalidResponse(
                "SMB LZ77 response ended inside a literal",
            ))?;
            input_offset += 1;
            ensure_lz77_growth(&output, 1, expected)?;
            output.push(byte);
            continue;
        }

        let tuple = usize::from(read_lz77_u16(input, &mut input_offset)?);
        let offset = tuple / 8 + 1;
        let mut length = tuple % 8;
        if length == 7 {
            length = if let Some(saved) = nibble_offset.take() {
                usize::from(input[saved] >> 4)
            } else {
                let byte = *input.get(input_offset).ok_or(CoreError::InvalidResponse(
                    "SMB LZ77 response ended inside a length nibble",
                ))?;
                nibble_offset = Some(input_offset);
                input_offset += 1;
                usize::from(byte & 0x0f)
            };
            if length == 15 {
                length = usize::from(*input.get(input_offset).ok_or(
                    CoreError::InvalidResponse("SMB LZ77 response ended inside a match length"),
                )?);
                input_offset += 1;
                if length == 255 {
                    length = usize::from(read_lz77_u16(input, &mut input_offset)?);
                    if length == 0 {
                        length = usize::try_from(read_lz77_u32(input, &mut input_offset)?)
                            .map_err(|_| {
                                CoreError::InvalidResponse("SMB LZ77 match length exceeded usize")
                            })?;
                    }
                    if length < 22 {
                        return Err(CoreError::InvalidResponse(
                            "SMB LZ77 response used an invalid extended match length",
                        ));
                    }
                    length -= 22;
                }
                length = length.checked_add(15).ok_or(CoreError::InvalidResponse(
                    "SMB LZ77 match length overflowed",
                ))?;
            }
            length = length.checked_add(7).ok_or(CoreError::InvalidResponse(
                "SMB LZ77 match length overflowed",
            ))?;
        }
        length = length.checked_add(3).ok_or(CoreError::InvalidResponse(
            "SMB LZ77 match length overflowed",
        ))?;
        if offset > output.len() {
            return Err(CoreError::InvalidResponse(
                "SMB LZ77 match referenced bytes before the output",
            ));
        }
        ensure_lz77_growth(&output, length, expected)?;
        for _ in 0..length {
            let source = output.len() - offset;
            let byte = output[source];
            output.push(byte);
        }
    }

    if output.len() != expected {
        return Err(CoreError::InvalidResponse(
            "SMB LZ77 response size did not match the transform header",
        ));
    }
    Ok(output)
}

fn bounded_output(expected: usize, resource: &'static str) -> Result<Vec<u8>, CoreError> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(expected)
        .map_err(|_| CoreError::AllocationFailed(resource))?;
    Ok(output)
}

fn ensure_lz77_growth(output: &[u8], additional: usize, expected: usize) -> Result<(), CoreError> {
    if output
        .len()
        .checked_add(additional)
        .is_none_or(|length| length > expected)
    {
        return Err(CoreError::InvalidResponse(
            "SMB LZ77 response expanded beyond its declared size",
        ));
    }
    Ok(())
}

fn read_lz77_u16(input: &[u8], offset: &mut usize) -> Result<u16, CoreError> {
    let end = offset.checked_add(2).ok_or(CoreError::InvalidResponse(
        "SMB LZ77 input offset overflowed",
    ))?;
    let bytes = input.get(*offset..end).ok_or(CoreError::InvalidResponse(
        "SMB LZ77 response ended inside a u16",
    ))?;
    *offset = end;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_lz77_u32(input: &[u8], offset: &mut usize) -> Result<u32, CoreError> {
    let end = offset.checked_add(4).ok_or(CoreError::InvalidResponse(
        "SMB LZ77 input offset overflowed",
    ))?;
    let bytes = input.get(*offset..end).ok_or(CoreError::InvalidResponse(
        "SMB LZ77 response ended inside a u32",
    ))?;
    *offset = end;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn append_limited(
    output: &mut Vec<u8>,
    bytes: &[u8],
    expected: usize,
    block_start: usize,
    block_limit: usize,
    error: &'static str,
) -> Result<(), CoreError> {
    let new_len = output
        .len()
        .checked_add(bytes.len())
        .ok_or(CoreError::InvalidResponse(error))?;
    if new_len > expected || new_len - block_start > block_limit {
        return Err(CoreError::InvalidResponse(error));
    }
    output.extend_from_slice(bytes);
    Ok(())
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
    fn compresses_and_boundedly_decompresses_lz77_messages() {
        let state = CompressionState::new(CompressionAlgorithm::Lz77, false);
        let original = vec![b'B'; 4096];

        let encoded = state
            .compress_message(&original)
            .expect("compression should succeed")
            .expect("repetitive data should compress");
        let transform =
            CompressionTransformHeader::decode(&encoded).expect("transform should decode");
        let decoded = state
            .decompress_message(&transform)
            .expect("bounded LZ77 transform should decompress");
        assert_eq!(decoded, original);
    }

    #[test]
    fn rejects_lznt1_and_lz77_streams_that_exceed_the_declared_output() {
        let lznt1 = CompressionState::new(CompressionAlgorithm::Lznt1, false);
        let lznt1_bomb = CompressionTransformHeader {
            original_compressed_segment_size: 16,
            compression_algorithm: CompressionAlgorithm::Lznt1,
            flags: CompressionFlags::empty(),
            offset_or_length: 0,
            payload: vec![0x03, 0xb0, 0x02, b'A', 0xff, 0x0f],
        };
        assert!(lznt1.decompress_message(&lznt1_bomb).is_err());

        let lz77 = CompressionState::new(CompressionAlgorithm::Lz77, false);
        let lz77_bomb = CompressionTransformHeader {
            original_compressed_segment_size: 16,
            compression_algorithm: CompressionAlgorithm::Lz77,
            flags: CompressionFlags::empty(),
            offset_or_length: 0,
            payload: vec![
                0x00, 0x00, 0x00, 0x40, b'A', 0x07, 0x00, 0x0f, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x01,
            ],
        };
        assert!(lz77.decompress_message(&lz77_bomb).is_err());
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

    #[test]
    fn rejects_compressed_responses_that_expand_past_frame_limit() {
        let state = CompressionState::new(CompressionAlgorithm::Lznt1, false);
        let message = CompressionTransformHeader {
            original_compressed_segment_size: 0x0100_0000,
            compression_algorithm: CompressionAlgorithm::Lznt1,
            flags: CompressionFlags::empty(),
            offset_or_length: 0,
            payload: Vec::new(),
        };

        let error = state
            .decompress_message(&message)
            .expect_err("oversized decompressed response should fail");
        assert_eq!(
            error.to_string(),
            "invalid response: SMB compressed response expanded beyond maximum message size"
        );
    }
}
