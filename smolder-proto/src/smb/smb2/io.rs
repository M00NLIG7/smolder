//! SMB2 read and write bodies.

use bitflags::bitflags;
use bytes::{BufMut, BytesMut};

use super::create::FileId;
use super::{check_fixed_structure_size, get_u16, get_u32, get_u64, slice_from_offset, HEADER_LEN};
use crate::smb::ProtocolError;

bitflags! {
    /// SMB2 read request flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct ReadFlags: u8 {
        /// Do not buffer the read on the server.
        const READ_UNBUFFERED = 0x01;
        /// Request compressed data when supported.
        const REQUEST_COMPRESSED = 0x02;
    }
}

bitflags! {
    /// SMB2 read response flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct ReadResponseFlags: u32 {
        /// The response buffer contains an RDMA transform structure.
        const RDMA_TRANSFORM = 0x0000_0001;
    }
}

bitflags! {
    /// SMB2 write request flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct WriteFlags: u32 {
        /// Force the server to write through caches.
        const WRITE_THROUGH = 0x0000_0001;
        /// Request unbuffered I/O when supported.
        const WRITE_UNBUFFERED = 0x0000_0002;
    }
}

/// SMB2 flush request body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlushRequest {
    /// File handle to flush.
    pub file_id: FileId,
}

impl FlushRequest {
    /// Builds a flush request for an open file handle.
    #[must_use]
    pub fn for_file(file_id: FileId) -> Self {
        Self { file_id }
    }

    /// Serializes the request body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(24);
        out.put_u16_le(24);
        out.put_u16_le(0);
        out.put_u32_le(0);
        out.put_u64_le(self.file_id.persistent);
        out.put_u64_le(self.file_id.volatile);
        out.to_vec()
    }

    /// Parses the request body.
    pub fn decode(body: &[u8]) -> Result<Self, ProtocolError> {
        let mut input = body;
        check_fixed_structure_size(get_u16(&mut input, "structure_size")?, 24, "structure_size")?;
        let _reserved1 = get_u16(&mut input, "reserved1")?;
        let _reserved2 = get_u32(&mut input, "reserved2")?;
        let file_id = FileId {
            persistent: get_u64(&mut input, "file_id_persistent")?,
            volatile: get_u64(&mut input, "file_id_volatile")?,
        };

        Ok(Self { file_id })
    }
}

/// SMB2 flush response body.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FlushResponse;

impl FlushResponse {
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

/// SMB2 read request body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadRequest {
    /// Response data offset hint for the server.
    pub padding: u8,
    /// Read flags.
    pub flags: ReadFlags,
    /// Number of bytes to read.
    pub length: u32,
    /// File offset to read from.
    pub offset: u64,
    /// File handle to read from.
    pub file_id: FileId,
    /// Minimum number of bytes required.
    pub minimum_count: u32,
    /// Channel selection, zero for normal TCP.
    pub channel: u32,
    /// Remaining bytes when using alternate channels.
    pub remaining_bytes: u32,
    /// Optional channel information blob.
    pub read_channel_info: Vec<u8>,
}

impl ReadRequest {
    /// Builds a simple file read request with standard TCP semantics.
    #[must_use]
    pub fn for_file(file_id: FileId, offset: u64, length: u32) -> Self {
        Self {
            padding: (HEADER_LEN + 16) as u8,
            flags: ReadFlags::empty(),
            length,
            offset,
            file_id,
            minimum_count: 0,
            channel: 0,
            remaining_bytes: 0,
            read_channel_info: Vec::new(),
        }
    }

    /// Serializes the request body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(49 + self.read_channel_info.len());
        out.put_u16_le(49);
        out.put_u8(self.padding);
        out.put_u8(self.flags.bits());
        out.put_u32_le(self.length);
        out.put_u64_le(self.offset);
        out.put_u64_le(self.file_id.persistent);
        out.put_u64_le(self.file_id.volatile);
        out.put_u32_le(self.minimum_count);
        out.put_u32_le(self.channel);
        out.put_u32_le(self.remaining_bytes);
        let read_channel_info_offset = if self.read_channel_info.is_empty() {
            0
        } else {
            (HEADER_LEN + 48) as u16
        };
        out.put_u16_le(read_channel_info_offset);
        out.put_u16_le(self.read_channel_info.len() as u16);
        if self.read_channel_info.is_empty() {
            out.put_u8(0);
        } else {
            out.extend_from_slice(&self.read_channel_info);
        }
        out.to_vec()
    }

    /// Parses the request body.
    pub fn decode(body: &[u8]) -> Result<Self, ProtocolError> {
        let mut input = body;
        check_fixed_structure_size(get_u16(&mut input, "structure_size")?, 49, "structure_size")?;
        let padding = super::get_u8(&mut input, "padding")?;
        let flags = ReadFlags::from_bits(super::get_u8(&mut input, "flags")?).ok_or(
            ProtocolError::InvalidField {
                field: "flags",
                reason: "unknown read flags set",
            },
        )?;
        let length = get_u32(&mut input, "length")?;
        let offset = get_u64(&mut input, "offset")?;
        let file_id = FileId {
            persistent: get_u64(&mut input, "file_id_persistent")?,
            volatile: get_u64(&mut input, "file_id_volatile")?,
        };
        let minimum_count = get_u32(&mut input, "minimum_count")?;
        let channel = get_u32(&mut input, "channel")?;
        let remaining_bytes = get_u32(&mut input, "remaining_bytes")?;
        let read_channel_info_offset = get_u16(&mut input, "read_channel_info_offset")?;
        let read_channel_info_length =
            usize::from(get_u16(&mut input, "read_channel_info_length")?);
        let read_channel_info = if read_channel_info_offset == 0 || read_channel_info_length == 0 {
            Vec::new()
        } else {
            slice_from_offset(
                body,
                read_channel_info_offset,
                read_channel_info_length,
                "read_channel_info",
            )?
            .to_vec()
        };

        Ok(Self {
            padding,
            flags,
            length,
            offset,
            file_id,
            minimum_count,
            channel,
            remaining_bytes,
            read_channel_info,
        })
    }
}

/// SMB2 read response body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadResponse {
    /// Remaining byte count for alternate channel transports.
    pub data_remaining: u32,
    /// Response flags.
    pub flags: ReadResponseFlags,
    /// Returned file data.
    pub data: Vec<u8>,
}

impl ReadResponse {
    /// Serializes the response body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(16 + self.data.len());
        out.put_u16_le(17);
        out.put_u8((HEADER_LEN + 16) as u8);
        out.put_u8(0);
        out.put_u32_le(self.data.len() as u32);
        out.put_u32_le(self.data_remaining);
        out.put_u32_le(self.flags.bits());
        out.extend_from_slice(&self.data);
        out.to_vec()
    }

    /// Parses the response body.
    pub fn decode(body: &[u8]) -> Result<Self, ProtocolError> {
        let mut input = body;
        check_fixed_structure_size(get_u16(&mut input, "structure_size")?, 17, "structure_size")?;
        let data_offset = u16::from(super::get_u8(&mut input, "data_offset")?);
        let _reserved = super::get_u8(&mut input, "reserved")?;
        let data_length = get_u32(&mut input, "data_length")? as usize;
        let data_remaining = get_u32(&mut input, "data_remaining")?;
        let flags = ReadResponseFlags::from_bits(get_u32(&mut input, "flags")?).ok_or(
            ProtocolError::InvalidField {
                field: "flags",
                reason: "unknown read response flags set",
            },
        )?;
        let data = if data_offset == 0 || data_length == 0 {
            Vec::new()
        } else {
            slice_from_offset(body, data_offset, data_length, "data")?.to_vec()
        };

        Ok(Self {
            data_remaining,
            flags,
            data,
        })
    }
}

/// SMB2 write request body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteRequest {
    /// File offset to write to.
    pub offset: u64,
    /// File handle to write to.
    pub file_id: FileId,
    /// Channel selection, zero for normal TCP.
    pub channel: u32,
    /// Remaining byte count for alternate channels.
    pub remaining_bytes: u32,
    /// Optional alternate channel information.
    pub write_channel_info: Vec<u8>,
    /// Write processing flags.
    pub flags: WriteFlags,
    /// Data payload to write.
    pub data: Vec<u8>,
}

impl WriteRequest {
    /// Builds a simple file write request with standard TCP semantics.
    #[must_use]
    pub fn for_file(file_id: FileId, offset: u64, data: Vec<u8>) -> Self {
        Self {
            offset,
            file_id,
            channel: 0,
            remaining_bytes: 0,
            write_channel_info: Vec::new(),
            flags: WriteFlags::empty(),
            data,
        }
    }

    /// Serializes the request body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(48 + self.data.len() + self.write_channel_info.len());
        out.put_u16_le(49);
        out.put_u16_le((HEADER_LEN + 48) as u16);
        out.put_u32_le(self.data.len() as u32);
        out.put_u64_le(self.offset);
        out.put_u64_le(self.file_id.persistent);
        out.put_u64_le(self.file_id.volatile);
        out.put_u32_le(self.channel);
        out.put_u32_le(self.remaining_bytes);
        let write_channel_info_offset = if self.write_channel_info.is_empty() {
            0
        } else {
            (HEADER_LEN + 48 + self.data.len()) as u16
        };
        out.put_u16_le(write_channel_info_offset);
        out.put_u16_le(self.write_channel_info.len() as u16);
        out.put_u32_le(self.flags.bits());
        out.extend_from_slice(&self.data);
        out.extend_from_slice(&self.write_channel_info);
        out.to_vec()
    }

    /// Parses the request body.
    pub fn decode(body: &[u8]) -> Result<Self, ProtocolError> {
        let mut input = body;
        check_fixed_structure_size(get_u16(&mut input, "structure_size")?, 49, "structure_size")?;
        let data_offset = get_u16(&mut input, "data_offset")?;
        let length = get_u32(&mut input, "length")? as usize;
        let offset = get_u64(&mut input, "offset")?;
        let file_id = FileId {
            persistent: get_u64(&mut input, "file_id_persistent")?,
            volatile: get_u64(&mut input, "file_id_volatile")?,
        };
        let channel = get_u32(&mut input, "channel")?;
        let remaining_bytes = get_u32(&mut input, "remaining_bytes")?;
        let write_channel_info_offset = get_u16(&mut input, "write_channel_info_offset")?;
        let write_channel_info_length =
            usize::from(get_u16(&mut input, "write_channel_info_length")?);
        let flags = WriteFlags::from_bits(get_u32(&mut input, "flags")?).ok_or(
            ProtocolError::InvalidField {
                field: "flags",
                reason: "unknown write flags set",
            },
        )?;
        let data = if data_offset == 0 || length == 0 {
            Vec::new()
        } else {
            slice_from_offset(body, data_offset, length, "data")?.to_vec()
        };
        let write_channel_info = if write_channel_info_offset == 0 || write_channel_info_length == 0
        {
            Vec::new()
        } else {
            slice_from_offset(
                body,
                write_channel_info_offset,
                write_channel_info_length,
                "write_channel_info",
            )?
            .to_vec()
        };

        Ok(Self {
            offset,
            file_id,
            channel,
            remaining_bytes,
            write_channel_info,
            flags,
            data,
        })
    }
}

/// SMB2 write response body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteResponse {
    /// Number of bytes written by the server.
    pub count: u32,
}

impl WriteResponse {
    /// Serializes the response body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(16);
        out.put_u16_le(17);
        out.put_u16_le(0);
        out.put_u32_le(self.count);
        out.put_u32_le(0);
        out.put_u16_le(0);
        out.put_u16_le(0);
        out.to_vec()
    }

    /// Parses the response body.
    pub fn decode(body: &[u8]) -> Result<Self, ProtocolError> {
        let mut input = body;
        check_fixed_structure_size(get_u16(&mut input, "structure_size")?, 17, "structure_size")?;
        let _reserved = get_u16(&mut input, "reserved")?;
        let count = get_u32(&mut input, "count")?;
        let _remaining = get_u32(&mut input, "remaining")?;
        let _write_channel_info_offset = get_u16(&mut input, "write_channel_info_offset")?;
        let _write_channel_info_length = get_u16(&mut input, "write_channel_info_length")?;

        Ok(Self { count })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FlushRequest, FlushResponse, ReadFlags, ReadRequest, ReadResponse, ReadResponseFlags,
        WriteFlags, WriteRequest, WriteResponse,
    };
    use crate::smb::smb2::FileId;

    #[test]
    fn flush_request_and_response_roundtrip() {
        let request = FlushRequest {
            file_id: FileId {
                persistent: 3,
                volatile: 4,
            },
        };
        let response = FlushResponse;

        let encoded_request = request.encode();
        let decoded_request =
            FlushRequest::decode(&encoded_request).expect("request should decode");
        assert_eq!(decoded_request, request);

        let encoded_response = response.encode();
        let decoded_response =
            FlushResponse::decode(&encoded_response).expect("response should decode");
        assert_eq!(decoded_response, response);
    }

    #[test]
    fn read_request_roundtrips() {
        let request = ReadRequest {
            padding: 0x50,
            flags: ReadFlags::READ_UNBUFFERED,
            length: 4096,
            offset: 128,
            file_id: FileId {
                persistent: 7,
                volatile: 9,
            },
            minimum_count: 1024,
            channel: 0,
            remaining_bytes: 0,
            read_channel_info: vec![0xaa, 0xbb],
        };

        let encoded = request.encode();
        let decoded = ReadRequest::decode(&encoded).expect("request should decode");

        assert_eq!(decoded, request);
    }

    #[test]
    fn read_request_for_file_uses_zero_minimum_count() {
        let request = ReadRequest::for_file(
            FileId {
                persistent: 7,
                volatile: 9,
            },
            128,
            4096,
        );

        assert_eq!(request.padding, 0x50);
        assert_eq!(request.minimum_count, 0);
        assert_eq!(request.length, 4096);
        assert_eq!(request.offset, 128);
    }

    #[test]
    fn read_response_roundtrips() {
        let response = ReadResponse {
            data_remaining: 0,
            flags: ReadResponseFlags::empty(),
            data: b"hello smb".to_vec(),
        };

        let encoded = response.encode();
        let decoded = ReadResponse::decode(&encoded).expect("response should decode");

        assert_eq!(decoded, response);
    }

    #[test]
    fn write_request_roundtrips() {
        let request = WriteRequest {
            offset: 64,
            file_id: FileId {
                persistent: 11,
                volatile: 13,
            },
            channel: 0,
            remaining_bytes: 0,
            write_channel_info: vec![0xcc, 0xdd],
            flags: WriteFlags::WRITE_THROUGH,
            data: b"payload".to_vec(),
        };

        let encoded = request.encode();
        let decoded = WriteRequest::decode(&encoded).expect("request should decode");

        assert_eq!(decoded, request);
    }

    #[test]
    fn write_response_roundtrips() {
        let response = WriteResponse { count: 7 };

        let encoded = response.encode();
        let decoded = WriteResponse::decode(&encoded).expect("response should decode");

        assert_eq!(decoded, response);
    }
}
