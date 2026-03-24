//! SMB2 create and close bodies.

use bitflags::bitflags;
use bytes::{BufMut, BytesMut};

use super::{
    check_fixed_structure_size, get_u16, get_u32, get_u64, slice_from_offset, utf16le, HEADER_LEN,
};
use crate::smb::ProtocolError;

bitflags! {
    /// Share access flags in a create request.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct ShareAccess: u32 {
        /// Shared read.
        const READ = 0x0000_0001;
        /// Shared write.
        const WRITE = 0x0000_0002;
        /// Shared delete.
        const DELETE = 0x0000_0004;
    }
}

bitflags! {
    /// File attributes in a create request.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FileAttributes: u32 {
        /// Read-only file.
        const READONLY = 0x0000_0001;
        /// Hidden file.
        const HIDDEN = 0x0000_0002;
        /// System file.
        const SYSTEM = 0x0000_0004;
        /// Directory.
        const DIRECTORY = 0x0000_0010;
        /// Archive bit.
        const ARCHIVE = 0x0000_0020;
        /// Normal file.
        const NORMAL = 0x0000_0080;
    }
}

bitflags! {
    /// Create option flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct CreateOptions: u32 {
        /// Open directory.
        const DIRECTORY_FILE = 0x0000_0001;
        /// Write through.
        const WRITE_THROUGH = 0x0000_0002;
        /// Sequential access hint.
        const SEQUENTIAL_ONLY = 0x0000_0004;
        /// Non-directory file.
        const NON_DIRECTORY_FILE = 0x0000_0040;
        /// Delete on close.
        const DELETE_ON_CLOSE = 0x0000_1000;
        /// Open by file ID.
        const OPEN_BY_FILE_ID = 0x0000_2000;
    }
}

/// Requested oplock level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RequestedOplockLevel {
    /// No oplock.
    None = 0x00,
    /// II oplock.
    II = 0x01,
    /// Exclusive oplock.
    Exclusive = 0x08,
    /// Batch oplock.
    Batch = 0x09,
    /// Lease oplock.
    Lease = 0xff,
}

/// Granted oplock level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum OplockLevel {
    /// No oplock.
    None = 0x00,
    /// II oplock.
    II = 0x01,
    /// Exclusive oplock.
    Exclusive = 0x08,
    /// Batch oplock.
    Batch = 0x09,
    /// Lease oplock.
    Lease = 0xff,
}

/// Create disposition value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum CreateDisposition {
    /// Supersede existing object.
    Supersede = 0,
    /// Open if present, fail otherwise.
    Open = 1,
    /// Create if absent, fail if present.
    Create = 2,
    /// Open or create.
    OpenIf = 3,
    /// Overwrite existing only.
    Overwrite = 4,
    /// Overwrite or create.
    OverwriteIf = 5,
}

/// A 128-bit SMB file identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileId {
    /// Persistent file handle component.
    pub persistent: u64,
    /// Volatile file handle component.
    pub volatile: u64,
}

/// SMB2 create request body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateRequest {
    /// Requested oplock level.
    pub requested_oplock_level: RequestedOplockLevel,
    /// Desired impersonation level.
    pub impersonation_level: u32,
    /// Desired access mask.
    pub desired_access: u32,
    /// File attributes.
    pub file_attributes: FileAttributes,
    /// Share access mask.
    pub share_access: ShareAccess,
    /// Create disposition.
    pub create_disposition: CreateDisposition,
    /// Create options.
    pub create_options: CreateOptions,
    /// File name encoded as UTF-16LE.
    pub name: Vec<u8>,
}

impl CreateRequest {
    /// Creates a request using a Rust path string.
    #[must_use]
    pub fn from_path(path: &str) -> Self {
        Self {
            requested_oplock_level: RequestedOplockLevel::None,
            impersonation_level: 2,
            desired_access: 0x0012_019f,
            file_attributes: FileAttributes::NORMAL,
            share_access: ShareAccess::READ | ShareAccess::WRITE,
            create_disposition: CreateDisposition::OpenIf,
            create_options: CreateOptions::NON_DIRECTORY_FILE,
            name: utf16le(path),
        }
    }

    /// Serializes the request body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let buffer_len = self.name.len().max(1);
        let mut out = BytesMut::with_capacity(88 + buffer_len);
        out.put_u16_le(57);
        out.put_u8(self.requested_oplock_level as u8);
        out.put_u8(0);
        out.put_u32_le(self.impersonation_level);
        out.put_u64_le(0);
        out.put_u64_le(0);
        out.put_u32_le(self.desired_access);
        out.put_u32_le(self.file_attributes.bits());
        out.put_u32_le(self.share_access.bits());
        out.put_u32_le(self.create_disposition as u32);
        out.put_u32_le(self.create_options.bits());
        out.put_u16_le((HEADER_LEN + 56) as u16);
        out.put_u16_le(self.name.len() as u16);
        out.put_u32_le(0);
        out.put_u32_le(0);
        if self.name.is_empty() {
            out.put_u8(0);
        } else {
            out.extend_from_slice(&self.name);
        }
        out.to_vec()
    }

    /// Parses the request body.
    pub fn decode(body: &[u8]) -> Result<Self, ProtocolError> {
        let mut input = body;
        check_fixed_structure_size(get_u16(&mut input, "structure_size")?, 57, "structure_size")?;
        let requested_oplock_level = match super::get_u8(&mut input, "requested_oplock_level")? {
            0x00 => RequestedOplockLevel::None,
            0x01 => RequestedOplockLevel::II,
            0x08 => RequestedOplockLevel::Exclusive,
            0x09 => RequestedOplockLevel::Batch,
            0xff => RequestedOplockLevel::Lease,
            _ => {
                return Err(ProtocolError::InvalidField {
                    field: "requested_oplock_level",
                    reason: "unknown oplock level",
                })
            }
        };
        let _impersonation_flags = super::get_u8(&mut input, "impersonation_flags")?;
        let impersonation_level = get_u32(&mut input, "impersonation_level")?;
        let _smb_create_flags = get_u64(&mut input, "smb_create_flags")?;
        let _reserved = get_u64(&mut input, "reserved")?;
        let desired_access = get_u32(&mut input, "desired_access")?;
        let file_attributes = FileAttributes::from_bits(get_u32(&mut input, "file_attributes")?)
            .ok_or(ProtocolError::InvalidField {
                field: "file_attributes",
                reason: "unknown file attribute bits set",
            })?;
        let share_access = ShareAccess::from_bits(get_u32(&mut input, "share_access")?).ok_or(
            ProtocolError::InvalidField {
                field: "share_access",
                reason: "unknown share access bits set",
            },
        )?;
        let create_disposition = match get_u32(&mut input, "create_disposition")? {
            0 => CreateDisposition::Supersede,
            1 => CreateDisposition::Open,
            2 => CreateDisposition::Create,
            3 => CreateDisposition::OpenIf,
            4 => CreateDisposition::Overwrite,
            5 => CreateDisposition::OverwriteIf,
            _ => {
                return Err(ProtocolError::InvalidField {
                    field: "create_disposition",
                    reason: "unknown create disposition",
                })
            }
        };
        let create_options = CreateOptions::from_bits(get_u32(&mut input, "create_options")?)
            .ok_or(ProtocolError::InvalidField {
                field: "create_options",
                reason: "unknown create option bits set",
            })?;
        let name_offset = get_u16(&mut input, "name_offset")?;
        let name_length = usize::from(get_u16(&mut input, "name_length")?);
        let _context_offset = get_u32(&mut input, "create_contexts_offset")?;
        let _context_length = get_u32(&mut input, "create_contexts_length")?;
        let name = slice_from_offset(body, name_offset, name_length, "name")?.to_vec();

        Ok(Self {
            requested_oplock_level,
            impersonation_level,
            desired_access,
            file_attributes,
            share_access,
            create_disposition,
            create_options,
            name,
        })
    }
}

/// SMB2 create response body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateResponse {
    /// Granted oplock level.
    pub oplock_level: OplockLevel,
    /// File attributes returned by the server.
    pub file_attributes: FileAttributes,
    /// Allocation size.
    pub allocation_size: u64,
    /// End of file size.
    pub end_of_file: u64,
    /// File identifier.
    pub file_id: FileId,
    /// Optional create contexts.
    pub create_contexts: Vec<u8>,
}

impl CreateResponse {
    /// Serializes the response body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(96 + self.create_contexts.len());
        out.put_u16_le(89);
        out.put_u8(self.oplock_level as u8);
        out.put_u8(0);
        out.put_u32_le(0);
        out.put_u64_le(0);
        out.put_u64_le(0);
        out.put_u64_le(0);
        out.put_u64_le(0);
        out.put_u64_le(self.allocation_size);
        out.put_u64_le(self.end_of_file);
        out.put_u32_le(self.file_attributes.bits());
        out.put_u32_le(0);
        out.put_u64_le(self.file_id.persistent);
        out.put_u64_le(self.file_id.volatile);
        let offset = if self.create_contexts.is_empty() {
            0
        } else {
            (HEADER_LEN + 88) as u32
        };
        out.put_u32_le(offset);
        out.put_u32_le(self.create_contexts.len() as u32);
        out.extend_from_slice(&self.create_contexts);
        out.to_vec()
    }

    /// Parses the response body.
    pub fn decode(body: &[u8]) -> Result<Self, ProtocolError> {
        let mut input = body;
        check_fixed_structure_size(get_u16(&mut input, "structure_size")?, 89, "structure_size")?;
        let oplock_level = match super::get_u8(&mut input, "oplock_level")? {
            0x00 => OplockLevel::None,
            0x01 => OplockLevel::II,
            0x08 => OplockLevel::Exclusive,
            0x09 => OplockLevel::Batch,
            0xff => OplockLevel::Lease,
            _ => {
                return Err(ProtocolError::InvalidField {
                    field: "oplock_level",
                    reason: "unknown oplock level",
                })
            }
        };
        let _flags = super::get_u8(&mut input, "flags")?;
        let _create_action = get_u32(&mut input, "create_action")?;
        let _creation_time = get_u64(&mut input, "creation_time")?;
        let _last_access_time = get_u64(&mut input, "last_access_time")?;
        let _last_write_time = get_u64(&mut input, "last_write_time")?;
        let _change_time = get_u64(&mut input, "change_time")?;
        let allocation_size = get_u64(&mut input, "allocation_size")?;
        let end_of_file = get_u64(&mut input, "end_of_file")?;
        let file_attributes = FileAttributes::from_bits(get_u32(&mut input, "file_attributes")?)
            .ok_or(ProtocolError::InvalidField {
                field: "file_attributes",
                reason: "unknown file attribute bits set",
            })?;
        let _reserved2 = get_u32(&mut input, "reserved2")?;
        let file_id = FileId {
            persistent: get_u64(&mut input, "file_id_persistent")?,
            volatile: get_u64(&mut input, "file_id_volatile")?,
        };
        let create_contexts_offset = get_u32(&mut input, "create_contexts_offset")?;
        let create_contexts_length = get_u32(&mut input, "create_contexts_length")? as usize;
        let create_contexts = if create_contexts_offset == 0 || create_contexts_length == 0 {
            Vec::new()
        } else {
            slice_from_offset(
                body,
                create_contexts_offset as u16,
                create_contexts_length,
                "create_contexts",
            )?
            .to_vec()
        };

        Ok(Self {
            oplock_level,
            file_attributes,
            allocation_size,
            end_of_file,
            file_id,
            create_contexts,
        })
    }
}

/// SMB2 close request body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseRequest {
    /// Close flags.
    pub flags: u16,
    /// File identifier to close.
    pub file_id: FileId,
}

impl CloseRequest {
    /// Serializes the request body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(24);
        out.put_u16_le(24);
        out.put_u16_le(self.flags);
        out.put_u32_le(0);
        out.put_u64_le(self.file_id.persistent);
        out.put_u64_le(self.file_id.volatile);
        out.to_vec()
    }

    /// Parses the request body.
    pub fn decode(body: &[u8]) -> Result<Self, ProtocolError> {
        let mut input = body;
        check_fixed_structure_size(get_u16(&mut input, "structure_size")?, 24, "structure_size")?;
        let flags = get_u16(&mut input, "flags")?;
        let _reserved = get_u32(&mut input, "reserved")?;
        let file_id = FileId {
            persistent: get_u64(&mut input, "file_id_persistent")?,
            volatile: get_u64(&mut input, "file_id_volatile")?,
        };

        Ok(Self { flags, file_id })
    }
}

/// SMB2 close response body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseResponse {
    /// Close flags.
    pub flags: u16,
    /// Allocation size reported by the server.
    pub allocation_size: u64,
    /// End of file size.
    pub end_of_file: u64,
    /// File attributes.
    pub file_attributes: FileAttributes,
}

impl CloseResponse {
    /// Serializes the response body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(60);
        out.put_u16_le(60);
        out.put_u16_le(self.flags);
        out.put_u32_le(0);
        out.put_u64_le(0);
        out.put_u64_le(0);
        out.put_u64_le(0);
        out.put_u64_le(0);
        out.put_u64_le(self.allocation_size);
        out.put_u64_le(self.end_of_file);
        out.put_u32_le(self.file_attributes.bits());
        out.to_vec()
    }

    /// Parses the response body.
    pub fn decode(body: &[u8]) -> Result<Self, ProtocolError> {
        let mut input = body;
        check_fixed_structure_size(get_u16(&mut input, "structure_size")?, 60, "structure_size")?;
        let flags = get_u16(&mut input, "flags")?;
        let _reserved = get_u32(&mut input, "reserved")?;
        let _creation_time = get_u64(&mut input, "creation_time")?;
        let _last_access_time = get_u64(&mut input, "last_access_time")?;
        let _last_write_time = get_u64(&mut input, "last_write_time")?;
        let _change_time = get_u64(&mut input, "change_time")?;
        let allocation_size = get_u64(&mut input, "allocation_size")?;
        let end_of_file = get_u64(&mut input, "end_of_file")?;
        let file_attributes = FileAttributes::from_bits(get_u32(&mut input, "file_attributes")?)
            .ok_or(ProtocolError::InvalidField {
                field: "file_attributes",
                reason: "unknown file attribute bits set",
            })?;

        Ok(Self {
            flags,
            allocation_size,
            end_of_file,
            file_attributes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CloseRequest, CloseResponse, CreateRequest, CreateResponse, FileAttributes, FileId,
        OplockLevel, ShareAccess,
    };
    use super::{CreateDisposition, CreateOptions, RequestedOplockLevel};

    #[test]
    fn create_request_roundtrips() {
        let request = CreateRequest {
            requested_oplock_level: RequestedOplockLevel::Exclusive,
            impersonation_level: 2,
            desired_access: 0x0012_019f,
            file_attributes: FileAttributes::NORMAL,
            share_access: ShareAccess::READ | ShareAccess::WRITE,
            create_disposition: CreateDisposition::OpenIf,
            create_options: CreateOptions::NON_DIRECTORY_FILE,
            name: super::utf16le("notes.txt"),
        };

        let encoded = request.encode();
        let decoded = CreateRequest::decode(&encoded).expect("request should decode");

        assert_eq!(decoded, request);
    }

    #[test]
    fn create_request_with_empty_name_roundtrips() {
        let request = CreateRequest {
            requested_oplock_level: RequestedOplockLevel::None,
            impersonation_level: 2,
            desired_access: 0x0012_0081,
            file_attributes: FileAttributes::DIRECTORY,
            share_access: ShareAccess::READ | ShareAccess::WRITE | ShareAccess::DELETE,
            create_disposition: CreateDisposition::Open,
            create_options: CreateOptions::DIRECTORY_FILE,
            name: Vec::new(),
        };

        let encoded = request.encode();
        let decoded = CreateRequest::decode(&encoded).expect("request should decode");

        assert_eq!(decoded, request);
        assert_eq!(encoded.len(), 57);
    }

    #[test]
    fn create_response_roundtrips() {
        let response = CreateResponse {
            oplock_level: OplockLevel::Exclusive,
            file_attributes: FileAttributes::ARCHIVE,
            allocation_size: 4096,
            end_of_file: 128,
            file_id: FileId {
                persistent: 1,
                volatile: 2,
            },
            create_contexts: vec![0x01, 0x02],
        };

        let encoded = response.encode();
        let decoded = CreateResponse::decode(&encoded).expect("response should decode");

        assert_eq!(decoded, response);
    }

    #[test]
    fn close_request_and_response_roundtrip() {
        let request = CloseRequest {
            flags: 0x0001,
            file_id: FileId {
                persistent: 7,
                volatile: 8,
            },
        };
        let response = CloseResponse {
            flags: 0x0001,
            allocation_size: 4096,
            end_of_file: 128,
            file_attributes: FileAttributes::ARCHIVE,
        };

        let encoded_request = request.encode();
        let decoded_request =
            CloseRequest::decode(&encoded_request).expect("request should decode");
        assert_eq!(decoded_request, request);

        let encoded_response = response.encode();
        let decoded_response =
            CloseResponse::decode(&encoded_response).expect("response should decode");
        assert_eq!(decoded_response, response);
    }
}
