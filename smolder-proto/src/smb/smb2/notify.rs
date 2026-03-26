//! SMB2 change-notify request and response bodies.

use bitflags::bitflags;
use bytes::{BufMut, BytesMut};

use super::create::FileId;
use super::{check_fixed_structure_size, get_u16, get_u32, get_u64, slice_from_offset, HEADER_LEN};
use crate::smb::ProtocolError;

bitflags! {
    /// SMB2 change-notify request flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct ChangeNotifyFlags: u16 {
        /// Monitor the entire subtree.
        const WATCH_TREE = 0x0001;
    }
}

bitflags! {
    /// Change notification completion filter bits.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct CompletionFilter: u32 {
        /// Notify on file-name changes.
        const FILE_NAME = 0x0000_0001;
        /// Notify on directory-name changes.
        const DIR_NAME = 0x0000_0002;
        /// Notify on attribute changes.
        const ATTRIBUTES = 0x0000_0004;
        /// Notify on size changes.
        const SIZE = 0x0000_0008;
        /// Notify on last-write changes.
        const LAST_WRITE = 0x0000_0010;
        /// Notify on last-access changes.
        const LAST_ACCESS = 0x0000_0020;
        /// Notify on creation-time changes.
        const CREATION = 0x0000_0040;
        /// Notify on extended-attribute changes.
        const EA = 0x0000_0080;
        /// Notify on security descriptor changes.
        const SECURITY = 0x0000_0100;
        /// Notify on stream-name changes.
        const STREAM_NAME = 0x0000_0200;
        /// Notify on stream-size changes.
        const STREAM_SIZE = 0x0000_0400;
        /// Notify on stream-write changes.
        const STREAM_WRITE = 0x0000_0800;
    }
}

/// SMB2 change-notify request body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeNotifyRequest {
    /// Request-processing flags.
    pub flags: ChangeNotifyFlags,
    /// Maximum buffer the server may return.
    pub output_buffer_length: u32,
    /// Directory handle to monitor.
    pub file_id: FileId,
    /// Notification triggers of interest.
    pub completion_filter: CompletionFilter,
}

impl ChangeNotifyRequest {
    /// Creates a change-notify request for a directory handle.
    #[must_use]
    pub fn for_directory(
        file_id: FileId,
        completion_filter: CompletionFilter,
        output_buffer_length: u32,
    ) -> Self {
        Self {
            flags: ChangeNotifyFlags::empty(),
            output_buffer_length,
            file_id,
            completion_filter,
        }
    }

    /// Serializes the request body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(32);
        out.put_u16_le(32);
        out.put_u16_le(self.flags.bits());
        out.put_u32_le(self.output_buffer_length);
        out.put_u64_le(self.file_id.persistent);
        out.put_u64_le(self.file_id.volatile);
        out.put_u32_le(self.completion_filter.bits());
        out.put_u32_le(0);
        out.to_vec()
    }

    /// Parses the request body.
    pub fn decode(body: &[u8]) -> Result<Self, ProtocolError> {
        let mut input = body;
        check_fixed_structure_size(get_u16(&mut input, "structure_size")?, 32, "structure_size")?;
        let flags = ChangeNotifyFlags::from_bits(get_u16(&mut input, "flags")?).ok_or(
            ProtocolError::InvalidField {
                field: "flags",
                reason: "unknown change-notify flags set",
            },
        )?;
        let output_buffer_length = get_u32(&mut input, "output_buffer_length")?;
        let file_id = FileId {
            persistent: get_u64(&mut input, "file_id_persistent")?,
            volatile: get_u64(&mut input, "file_id_volatile")?,
        };
        let completion_filter =
            CompletionFilter::from_bits(get_u32(&mut input, "completion_filter")?).ok_or(
                ProtocolError::InvalidField {
                    field: "completion_filter",
                    reason: "unknown completion filter bits set",
                },
            )?;
        let _reserved = get_u32(&mut input, "reserved")?;
        Ok(Self {
            flags,
            output_buffer_length,
            file_id,
            completion_filter,
        })
    }
}

/// SMB2 change-notify response body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeNotifyResponse {
    /// Raw `FILE_NOTIFY_INFORMATION` bytes.
    pub output_buffer: Vec<u8>,
}

impl ChangeNotifyResponse {
    /// Serializes the response body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(8 + self.output_buffer.len());
        out.put_u16_le(9);
        let offset = if self.output_buffer.is_empty() {
            0
        } else {
            (HEADER_LEN + 8) as u16
        };
        out.put_u16_le(offset);
        out.put_u32_le(self.output_buffer.len() as u32);
        out.extend_from_slice(&self.output_buffer);
        out.to_vec()
    }

    /// Parses the response body.
    pub fn decode(body: &[u8]) -> Result<Self, ProtocolError> {
        let mut input = body;
        check_fixed_structure_size(get_u16(&mut input, "structure_size")?, 9, "structure_size")?;
        let output_buffer_offset = get_u16(&mut input, "output_buffer_offset")?;
        let output_buffer_length = get_u32(&mut input, "output_buffer_length")? as usize;
        let output_buffer = if output_buffer_offset == 0 || output_buffer_length == 0 {
            Vec::new()
        } else {
            slice_from_offset(
                body,
                output_buffer_offset,
                output_buffer_length,
                "output_buffer",
            )?
            .to_vec()
        };
        Ok(Self { output_buffer })
    }
}

#[cfg(test)]
mod tests {
    use super::{ChangeNotifyFlags, ChangeNotifyRequest, ChangeNotifyResponse, CompletionFilter};
    use crate::smb::smb2::FileId;

    #[test]
    fn change_notify_request_roundtrips() {
        let request = ChangeNotifyRequest {
            flags: ChangeNotifyFlags::WATCH_TREE,
            output_buffer_length: 4096,
            file_id: FileId {
                persistent: 0x1122_3344_5566_7788,
                volatile: 0x8877_6655_4433_2211,
            },
            completion_filter: CompletionFilter::FILE_NAME
                | CompletionFilter::DIR_NAME
                | CompletionFilter::LAST_WRITE,
        };

        let encoded = request.encode();
        let decoded =
            ChangeNotifyRequest::decode(&encoded).expect("change notify request should decode");
        assert_eq!(decoded, request);
    }

    #[test]
    fn change_notify_response_roundtrips() {
        let response = ChangeNotifyResponse {
            output_buffer: vec![1, 2, 3, 4, 5, 6],
        };

        let encoded = response.encode();
        let decoded =
            ChangeNotifyResponse::decode(&encoded).expect("change notify response should decode");
        assert_eq!(decoded, response);
    }
}
