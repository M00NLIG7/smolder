//! SMB2 query and set-info request/response bodies.

use bitflags::bitflags;
use bytes::{BufMut, BytesMut};

use super::create::{FileAttributes, FileId};
use super::{
    check_fixed_structure_size, get_u16, get_u32, get_u64, slice_from_offset, utf16le,
    utf16le_string, HEADER_LEN,
};
use crate::smb::ProtocolError;

bitflags! {
    /// Flags for `QUERY_DIRECTORY`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct QueryDirectoryFlags: u8 {
        /// Restart enumeration from the beginning.
        const RESTART_SCANS = 0x01;
        /// Return a single entry.
        const RETURN_SINGLE_ENTRY = 0x02;
        /// Start from the provided index.
        const INDEX_SPECIFIED = 0x04;
        /// Reopen the search.
        const REOPEN = 0x10;
    }
}

/// File information classes used for directory enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum QueryDirectoryFileInformationClass {
    /// `FileDirectoryInformation`
    FileDirectoryInformation = 0x01,
}

/// SMB2 query-directory request body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryDirectoryRequest {
    /// The directory information class to return.
    pub file_information_class: QueryDirectoryFileInformationClass,
    /// Enumeration flags.
    pub flags: QueryDirectoryFlags,
    /// Resume index.
    pub file_index: u32,
    /// Directory handle returned by `CREATE`.
    pub file_id: FileId,
    /// Optional pattern encoded as UTF-16LE.
    pub file_name: Vec<u8>,
    /// Maximum response buffer length.
    pub output_buffer_length: u32,
}

impl QueryDirectoryRequest {
    /// Builds a standard `QUERY_DIRECTORY` request for a directory handle.
    #[must_use]
    pub fn for_pattern(file_id: FileId, pattern: &str, output_buffer_length: u32) -> Self {
        Self {
            file_information_class: QueryDirectoryFileInformationClass::FileDirectoryInformation,
            flags: QueryDirectoryFlags::RESTART_SCANS,
            file_index: 0,
            file_id,
            file_name: utf16le(pattern),
            output_buffer_length,
        }
    }

    /// Serializes the request body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(32 + self.file_name.len());
        out.put_u16_le(33);
        out.put_u8(self.file_information_class as u8);
        out.put_u8(self.flags.bits());
        out.put_u32_le(self.file_index);
        out.put_u64_le(self.file_id.persistent);
        out.put_u64_le(self.file_id.volatile);
        let file_name_offset = if self.file_name.is_empty() {
            0
        } else {
            (HEADER_LEN + 32) as u16
        };
        out.put_u16_le(file_name_offset);
        out.put_u16_le(self.file_name.len() as u16);
        out.put_u32_le(self.output_buffer_length);
        out.extend_from_slice(&self.file_name);
        out.to_vec()
    }

    /// Parses the request body.
    pub fn decode(body: &[u8]) -> Result<Self, ProtocolError> {
        let mut input = body;
        check_fixed_structure_size(get_u16(&mut input, "structure_size")?, 33, "structure_size")?;
        let file_information_class = match super::get_u8(&mut input, "file_information_class")? {
            0x01 => QueryDirectoryFileInformationClass::FileDirectoryInformation,
            _ => {
                return Err(ProtocolError::InvalidField {
                    field: "file_information_class",
                    reason: "unknown query-directory information class",
                })
            }
        };
        let flags = QueryDirectoryFlags::from_bits(super::get_u8(&mut input, "flags")?).ok_or(
            ProtocolError::InvalidField {
                field: "flags",
                reason: "unknown query-directory flags set",
            },
        )?;
        let file_index = get_u32(&mut input, "file_index")?;
        let file_id = FileId {
            persistent: get_u64(&mut input, "file_id_persistent")?,
            volatile: get_u64(&mut input, "file_id_volatile")?,
        };
        let file_name_offset = get_u16(&mut input, "file_name_offset")?;
        let file_name_length = usize::from(get_u16(&mut input, "file_name_length")?);
        let output_buffer_length = get_u32(&mut input, "output_buffer_length")?;
        let file_name = if file_name_offset == 0 || file_name_length == 0 {
            Vec::new()
        } else {
            slice_from_offset(body, file_name_offset, file_name_length, "file_name")?.to_vec()
        };

        Ok(Self {
            file_information_class,
            flags,
            file_index,
            file_id,
            file_name,
            output_buffer_length,
        })
    }
}

/// One `FileDirectoryInformation` entry returned by `QUERY_DIRECTORY`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryInformationEntry {
    /// Resume index for the directory entry.
    pub file_index: u32,
    /// Creation time in Windows ticks.
    pub creation_time: u64,
    /// Last access time in Windows ticks.
    pub last_access_time: u64,
    /// Last write time in Windows ticks.
    pub last_write_time: u64,
    /// Change time in Windows ticks.
    pub change_time: u64,
    /// End-of-file size.
    pub end_of_file: u64,
    /// Allocated size on disk.
    pub allocation_size: u64,
    /// File attributes.
    pub file_attributes: FileAttributes,
    /// Decoded file name.
    pub file_name: String,
}

/// SMB2 query-directory response body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryDirectoryResponse {
    /// Raw output buffer returned by the server.
    pub output_buffer: Vec<u8>,
}

impl QueryDirectoryResponse {
    /// Returns an empty response used for `STATUS_NO_MORE_FILES`.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            output_buffer: Vec::new(),
        }
    }

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

    /// Decodes all returned `FileDirectoryInformation` entries.
    pub fn directory_entries(&self) -> Result<Vec<DirectoryInformationEntry>, ProtocolError> {
        let mut entries = Vec::new();
        let mut cursor = self.output_buffer.as_slice();

        while !cursor.is_empty() {
            if cursor.len() < 64 {
                return Err(ProtocolError::UnexpectedEof {
                    field: "directory_information_entry",
                });
            }

            let next_entry_offset = u32::from_le_bytes(cursor[0..4].try_into().expect("slice len"));
            let entry_len = if next_entry_offset == 0 {
                cursor.len()
            } else {
                next_entry_offset as usize
            };
            if entry_len > cursor.len() || entry_len < 64 {
                return Err(ProtocolError::InvalidField {
                    field: "next_entry_offset",
                    reason: "directory entry extends past buffer",
                });
            }

            let mut input = &cursor[..entry_len];
            let _next_entry_offset = get_u32(&mut input, "next_entry_offset")?;
            let file_index = get_u32(&mut input, "file_index")?;
            let creation_time = get_u64(&mut input, "creation_time")?;
            let last_access_time = get_u64(&mut input, "last_access_time")?;
            let last_write_time = get_u64(&mut input, "last_write_time")?;
            let change_time = get_u64(&mut input, "change_time")?;
            let end_of_file = get_u64(&mut input, "end_of_file")?;
            let allocation_size = get_u64(&mut input, "allocation_size")?;
            let file_attributes =
                FileAttributes::from_bits(get_u32(&mut input, "file_attributes")?).ok_or(
                    ProtocolError::InvalidField {
                        field: "file_attributes",
                        reason: "unknown file attribute bits set",
                    },
                )?;
            let file_name_length = get_u32(&mut input, "file_name_length")? as usize;
            if file_name_length > input.len() {
                return Err(ProtocolError::UnexpectedEof { field: "file_name" });
            }
            let file_name = utf16le_string(&input[..file_name_length])?;

            entries.push(DirectoryInformationEntry {
                file_index,
                creation_time,
                last_access_time,
                last_write_time,
                change_time,
                end_of_file,
                allocation_size,
                file_attributes,
                file_name,
            });

            if next_entry_offset == 0 {
                break;
            }
            cursor = &cursor[entry_len..];
        }

        Ok(entries)
    }
}

/// Info type values for `QUERY_INFO` and `SET_INFO`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum InfoType {
    /// File information.
    File = 0x01,
    /// Filesystem information.
    FileSystem = 0x02,
    /// Security information.
    Security = 0x03,
    /// Quota information.
    Quota = 0x04,
}

/// File information classes used by `QUERY_INFO` and `SET_INFO`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FileInfoClass {
    /// `FileBasicInformation`
    BasicInformation = 0x04,
    /// `FileStandardInformation`
    StandardInformation = 0x05,
    /// `FileRenameInformation`
    RenameInformation = 0x0a,
    /// `FileDispositionInformation`
    DispositionInformation = 0x0d,
}

/// SMB2 query-info request body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryInfoRequest {
    /// The info type being queried.
    pub info_type: InfoType,
    /// The file information class.
    pub file_info_class: FileInfoClass,
    /// Maximum response size.
    pub output_buffer_length: u32,
    /// Optional input buffer.
    pub input_buffer: Vec<u8>,
    /// Additional information flags.
    pub additional_information: u32,
    /// Request flags.
    pub flags: u32,
    /// File handle returned by `CREATE`.
    pub file_id: FileId,
}

impl QueryInfoRequest {
    /// Creates a file-info query with no input buffer.
    #[must_use]
    pub fn for_file_info(file_id: FileId, file_info_class: FileInfoClass) -> Self {
        Self {
            info_type: InfoType::File,
            file_info_class,
            output_buffer_length: 4096,
            input_buffer: Vec::new(),
            additional_information: 0,
            flags: 0,
            file_id,
        }
    }

    /// Serializes the request body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(40 + self.input_buffer.len());
        out.put_u16_le(41);
        out.put_u8(self.info_type as u8);
        out.put_u8(self.file_info_class as u8);
        out.put_u32_le(self.output_buffer_length);
        let input_buffer_offset = if self.input_buffer.is_empty() {
            0
        } else {
            (HEADER_LEN + 40) as u16
        };
        out.put_u16_le(input_buffer_offset);
        out.put_u16_le(0);
        out.put_u32_le(self.input_buffer.len() as u32);
        out.put_u32_le(self.additional_information);
        out.put_u32_le(self.flags);
        out.put_u64_le(self.file_id.persistent);
        out.put_u64_le(self.file_id.volatile);
        out.extend_from_slice(&self.input_buffer);
        out.to_vec()
    }

    /// Parses the request body.
    pub fn decode(body: &[u8]) -> Result<Self, ProtocolError> {
        let mut input = body;
        check_fixed_structure_size(get_u16(&mut input, "structure_size")?, 41, "structure_size")?;
        let info_type = match super::get_u8(&mut input, "info_type")? {
            0x01 => InfoType::File,
            0x02 => InfoType::FileSystem,
            0x03 => InfoType::Security,
            0x04 => InfoType::Quota,
            _ => {
                return Err(ProtocolError::InvalidField {
                    field: "info_type",
                    reason: "unknown info type",
                })
            }
        };
        let file_info_class = match super::get_u8(&mut input, "file_info_class")? {
            0x04 => FileInfoClass::BasicInformation,
            0x05 => FileInfoClass::StandardInformation,
            0x0a => FileInfoClass::RenameInformation,
            0x0d => FileInfoClass::DispositionInformation,
            _ => {
                return Err(ProtocolError::InvalidField {
                    field: "file_info_class",
                    reason: "unknown file info class",
                })
            }
        };
        let output_buffer_length = get_u32(&mut input, "output_buffer_length")?;
        let input_buffer_offset = get_u16(&mut input, "input_buffer_offset")?;
        let _reserved = get_u16(&mut input, "reserved")?;
        let input_buffer_length = get_u32(&mut input, "input_buffer_length")? as usize;
        let additional_information = get_u32(&mut input, "additional_information")?;
        let flags = get_u32(&mut input, "flags")?;
        let file_id = FileId {
            persistent: get_u64(&mut input, "file_id_persistent")?,
            volatile: get_u64(&mut input, "file_id_volatile")?,
        };
        let input_buffer = if input_buffer_offset == 0 || input_buffer_length == 0 {
            Vec::new()
        } else {
            slice_from_offset(
                body,
                input_buffer_offset,
                input_buffer_length,
                "input_buffer",
            )?
            .to_vec()
        };

        Ok(Self {
            info_type,
            file_info_class,
            output_buffer_length,
            input_buffer,
            additional_information,
            flags,
            file_id,
        })
    }
}

/// SMB2 query-info response body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryInfoResponse {
    /// Raw output buffer returned by the server.
    pub output_buffer: Vec<u8>,
}

impl QueryInfoResponse {
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

/// Parsed `FILE_BASIC_INFORMATION`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileBasicInformation {
    /// Creation time in Windows ticks.
    pub creation_time: u64,
    /// Last access time in Windows ticks.
    pub last_access_time: u64,
    /// Last write time in Windows ticks.
    pub last_write_time: u64,
    /// Change time in Windows ticks.
    pub change_time: u64,
    /// File attributes.
    pub file_attributes: FileAttributes,
}

impl FileBasicInformation {
    /// Parses `FILE_BASIC_INFORMATION`.
    pub fn decode(buffer: &[u8]) -> Result<Self, ProtocolError> {
        let mut input = buffer;
        let creation_time = get_u64(&mut input, "creation_time")?;
        let last_access_time = get_u64(&mut input, "last_access_time")?;
        let last_write_time = get_u64(&mut input, "last_write_time")?;
        let change_time = get_u64(&mut input, "change_time")?;
        let file_attributes = FileAttributes::from_bits(get_u32(&mut input, "file_attributes")?)
            .ok_or(ProtocolError::InvalidField {
                field: "file_attributes",
                reason: "unknown file attribute bits set",
            })?;
        let _reserved = get_u32(&mut input, "reserved")?;
        Ok(Self {
            creation_time,
            last_access_time,
            last_write_time,
            change_time,
            file_attributes,
        })
    }
}

/// Parsed `FILE_STANDARD_INFORMATION`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileStandardInformation {
    /// Allocation size in bytes.
    pub allocation_size: u64,
    /// Logical file size in bytes.
    pub end_of_file: u64,
    /// Number of hard links.
    pub number_of_links: u32,
    /// Whether the file is pending deletion.
    pub delete_pending: bool,
    /// Whether the opened object is a directory.
    pub directory: bool,
}

impl FileStandardInformation {
    /// Parses `FILE_STANDARD_INFORMATION`.
    pub fn decode(buffer: &[u8]) -> Result<Self, ProtocolError> {
        let mut input = buffer;
        let allocation_size = get_u64(&mut input, "allocation_size")?;
        let end_of_file = get_u64(&mut input, "end_of_file")?;
        let number_of_links = get_u32(&mut input, "number_of_links")?;
        let delete_pending = super::get_u8(&mut input, "delete_pending")? != 0;
        let directory = super::get_u8(&mut input, "directory")? != 0;
        let _reserved = get_u16(&mut input, "reserved")?;
        Ok(Self {
            allocation_size,
            end_of_file,
            number_of_links,
            delete_pending,
            directory,
        })
    }
}

/// `FILE_RENAME_INFORMATION`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenameInformation {
    /// Replace the destination if it already exists.
    pub replace_if_exists: bool,
    /// New name encoded as UTF-16LE.
    pub file_name: Vec<u8>,
}

impl RenameInformation {
    /// Creates a rename payload for a path string.
    #[must_use]
    pub fn from_path(path: &str, replace_if_exists: bool) -> Self {
        Self {
            replace_if_exists,
            file_name: utf16le(path),
        }
    }

    /// Serializes the payload.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(20 + self.file_name.len());
        out.put_u8(u8::from(self.replace_if_exists));
        out.put_u8(0);
        out.put_u16_le(0);
        out.put_u32_le(0);
        out.put_u64_le(0);
        out.put_u32_le(self.file_name.len() as u32);
        out.extend_from_slice(&self.file_name);
        out.to_vec()
    }
}

/// `FILE_DISPOSITION_INFORMATION`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispositionInformation {
    /// Whether the file should be deleted on close.
    pub delete_pending: bool,
}

impl DispositionInformation {
    /// Serializes the payload.
    #[must_use]
    pub fn encode(self) -> Vec<u8> {
        vec![u8::from(self.delete_pending)]
    }
}

/// SMB2 set-info request body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetInfoRequest {
    /// The info type being updated.
    pub info_type: InfoType,
    /// The file information class being updated.
    pub file_info_class: FileInfoClass,
    /// Additional information flags.
    pub additional_information: u32,
    /// File handle returned by `CREATE`.
    pub file_id: FileId,
    /// Raw payload buffer.
    pub buffer: Vec<u8>,
}

impl SetInfoRequest {
    /// Builds a file-info set-info request.
    #[must_use]
    pub fn for_file_info(file_id: FileId, file_info_class: FileInfoClass, buffer: Vec<u8>) -> Self {
        Self {
            info_type: InfoType::File,
            file_info_class,
            additional_information: 0,
            file_id,
            buffer,
        }
    }

    /// Serializes the request body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(32 + self.buffer.len());
        out.put_u16_le(33);
        out.put_u8(self.info_type as u8);
        out.put_u8(self.file_info_class as u8);
        out.put_u32_le(self.buffer.len() as u32);
        let buffer_offset = if self.buffer.is_empty() {
            0
        } else {
            (HEADER_LEN + 32) as u16
        };
        out.put_u16_le(buffer_offset);
        out.put_u16_le(0);
        out.put_u32_le(self.additional_information);
        out.put_u64_le(self.file_id.persistent);
        out.put_u64_le(self.file_id.volatile);
        out.extend_from_slice(&self.buffer);
        out.to_vec()
    }

    /// Parses the request body.
    pub fn decode(body: &[u8]) -> Result<Self, ProtocolError> {
        let mut input = body;
        check_fixed_structure_size(get_u16(&mut input, "structure_size")?, 33, "structure_size")?;
        let info_type = match super::get_u8(&mut input, "info_type")? {
            0x01 => InfoType::File,
            0x02 => InfoType::FileSystem,
            0x03 => InfoType::Security,
            0x04 => InfoType::Quota,
            _ => {
                return Err(ProtocolError::InvalidField {
                    field: "info_type",
                    reason: "unknown info type",
                })
            }
        };
        let file_info_class = match super::get_u8(&mut input, "file_info_class")? {
            0x04 => FileInfoClass::BasicInformation,
            0x05 => FileInfoClass::StandardInformation,
            0x0a => FileInfoClass::RenameInformation,
            0x0d => FileInfoClass::DispositionInformation,
            _ => {
                return Err(ProtocolError::InvalidField {
                    field: "file_info_class",
                    reason: "unknown file info class",
                })
            }
        };
        let buffer_length = get_u32(&mut input, "buffer_length")? as usize;
        let buffer_offset = get_u16(&mut input, "buffer_offset")?;
        let _reserved = get_u16(&mut input, "reserved")?;
        let additional_information = get_u32(&mut input, "additional_information")?;
        let file_id = FileId {
            persistent: get_u64(&mut input, "file_id_persistent")?,
            volatile: get_u64(&mut input, "file_id_volatile")?,
        };
        let buffer = if buffer_offset == 0 || buffer_length == 0 {
            Vec::new()
        } else {
            slice_from_offset(body, buffer_offset, buffer_length, "buffer")?.to_vec()
        };

        Ok(Self {
            info_type,
            file_info_class,
            additional_information,
            file_id,
            buffer,
        })
    }
}

/// SMB2 set-info response body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SetInfoResponse;

impl SetInfoResponse {
    /// Serializes the response body.
    #[must_use]
    pub fn encode(self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(2);
        out.put_u16_le(2);
        out.to_vec()
    }

    /// Parses the response body.
    pub fn decode(body: &[u8]) -> Result<Self, ProtocolError> {
        let mut input = body;
        check_fixed_structure_size(get_u16(&mut input, "structure_size")?, 2, "structure_size")?;
        Ok(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DirectoryInformationEntry, DispositionInformation, FileBasicInformation, FileInfoClass,
        FileStandardInformation, InfoType, QueryDirectoryRequest, QueryDirectoryResponse,
        QueryInfoRequest, QueryInfoResponse, RenameInformation, SetInfoRequest, SetInfoResponse,
    };
    use crate::smb::smb2::{FileAttributes, FileId};

    #[test]
    fn query_directory_request_roundtrips() {
        let request = QueryDirectoryRequest::for_pattern(
            FileId {
                persistent: 1,
                volatile: 2,
            },
            "*",
            8192,
        );

        let encoded = request.encode();
        let decoded = QueryDirectoryRequest::decode(&encoded).expect("request should decode");
        assert_eq!(decoded, request);
    }

    #[test]
    fn query_directory_response_decodes_entries() {
        let first_name = crate::smb::smb2::utf16le("alpha.txt");
        let first_entry_len = (64 + first_name.len() + 7) & !7;
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&(first_entry_len as u32).to_le_bytes());
        buffer.extend_from_slice(&7_u32.to_le_bytes());
        buffer.extend_from_slice(&1_u64.to_le_bytes());
        buffer.extend_from_slice(&2_u64.to_le_bytes());
        buffer.extend_from_slice(&3_u64.to_le_bytes());
        buffer.extend_from_slice(&4_u64.to_le_bytes());
        buffer.extend_from_slice(&5_u64.to_le_bytes());
        buffer.extend_from_slice(&8_u64.to_le_bytes());
        buffer.extend_from_slice(&FileAttributes::ARCHIVE.bits().to_le_bytes());
        buffer.extend_from_slice(&(first_name.len() as u32).to_le_bytes());
        buffer.extend_from_slice(&first_name);
        buffer.resize(first_entry_len, 0);

        buffer.extend_from_slice(&0_u32.to_le_bytes());
        buffer.extend_from_slice(&8_u32.to_le_bytes());
        buffer.extend_from_slice(&10_u64.to_le_bytes());
        buffer.extend_from_slice(&11_u64.to_le_bytes());
        buffer.extend_from_slice(&12_u64.to_le_bytes());
        buffer.extend_from_slice(&13_u64.to_le_bytes());
        buffer.extend_from_slice(&0_u64.to_le_bytes());
        buffer.extend_from_slice(&0_u64.to_le_bytes());
        buffer.extend_from_slice(&FileAttributes::DIRECTORY.bits().to_le_bytes());
        let second_name = crate::smb::smb2::utf16le("nested");
        buffer.extend_from_slice(&(second_name.len() as u32).to_le_bytes());
        buffer.extend_from_slice(&second_name);

        let response = QueryDirectoryResponse {
            output_buffer: buffer,
        };
        let entries = response
            .directory_entries()
            .expect("directory entries should decode");

        assert_eq!(
            entries,
            vec![
                DirectoryInformationEntry {
                    file_index: 7,
                    creation_time: 1,
                    last_access_time: 2,
                    last_write_time: 3,
                    change_time: 4,
                    end_of_file: 5,
                    allocation_size: 8,
                    file_attributes: FileAttributes::ARCHIVE,
                    file_name: "alpha.txt".to_string(),
                },
                DirectoryInformationEntry {
                    file_index: 8,
                    creation_time: 10,
                    last_access_time: 11,
                    last_write_time: 12,
                    change_time: 13,
                    end_of_file: 0,
                    allocation_size: 0,
                    file_attributes: FileAttributes::DIRECTORY,
                    file_name: "nested".to_string(),
                },
            ]
        );
    }

    #[test]
    fn query_info_roundtrips() {
        let request = QueryInfoRequest {
            info_type: InfoType::File,
            file_info_class: FileInfoClass::BasicInformation,
            output_buffer_length: 4096,
            input_buffer: vec![0xaa, 0xbb],
            additional_information: 0x11,
            flags: 0x22,
            file_id: FileId {
                persistent: 3,
                volatile: 4,
            },
        };
        let encoded = request.encode();
        let decoded = QueryInfoRequest::decode(&encoded).expect("request should decode");
        assert_eq!(decoded, request);

        let response = QueryInfoResponse {
            output_buffer: vec![1, 2, 3],
        };
        let encoded = response.encode();
        let decoded = QueryInfoResponse::decode(&encoded).expect("response should decode");
        assert_eq!(decoded, response);
    }

    #[test]
    fn file_info_decoders_parse_basic_and_standard_information() {
        let mut basic = Vec::new();
        basic.extend_from_slice(&1_u64.to_le_bytes());
        basic.extend_from_slice(&2_u64.to_le_bytes());
        basic.extend_from_slice(&3_u64.to_le_bytes());
        basic.extend_from_slice(&4_u64.to_le_bytes());
        basic.extend_from_slice(&FileAttributes::ARCHIVE.bits().to_le_bytes());
        basic.extend_from_slice(&0_u32.to_le_bytes());

        let mut standard = Vec::new();
        standard.extend_from_slice(&8_u64.to_le_bytes());
        standard.extend_from_slice(&5_u64.to_le_bytes());
        standard.extend_from_slice(&2_u32.to_le_bytes());
        standard.push(1);
        standard.push(0);
        standard.extend_from_slice(&0_u16.to_le_bytes());

        let basic = FileBasicInformation::decode(&basic).expect("basic info should decode");
        let standard =
            FileStandardInformation::decode(&standard).expect("standard info should decode");

        assert_eq!(basic.creation_time, 1);
        assert_eq!(basic.file_attributes, FileAttributes::ARCHIVE);
        assert_eq!(standard.end_of_file, 5);
        assert!(standard.delete_pending);
        assert!(!standard.directory);
    }

    #[test]
    fn set_info_roundtrips() {
        let rename = RenameInformation::from_path("notes-renamed.txt", false);
        let request = SetInfoRequest::for_file_info(
            FileId {
                persistent: 5,
                volatile: 6,
            },
            FileInfoClass::RenameInformation,
            rename.encode(),
        );
        let encoded = request.encode();
        let decoded = SetInfoRequest::decode(&encoded).expect("request should decode");
        assert_eq!(decoded, request);

        let disposition = DispositionInformation {
            delete_pending: true,
        };
        assert_eq!(disposition.encode(), vec![1]);

        let encoded = SetInfoResponse.encode();
        let decoded = SetInfoResponse::decode(&encoded).expect("response should decode");
        assert_eq!(decoded, SetInfoResponse);
    }
}
