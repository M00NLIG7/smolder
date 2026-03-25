//! SMB2 create and close bodies.

use bitflags::bitflags;
use bytes::{BufMut, BytesMut};

use super::{
    check_fixed_structure_size, get_array, get_u16, get_u32, get_u64, put_padding,
    slice_from_offset, slice_from_offset32, utf16le, HEADER_LEN,
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
    /// SMB lease-state flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct LeaseState: u32 {
        /// No lease caching rights are granted.
        const NONE = 0x0000_0000;
        /// Read caching is requested or granted.
        const READ_CACHING = 0x0000_0001;
        /// Handle caching is requested or granted.
        const HANDLE_CACHING = 0x0000_0002;
        /// Write caching is requested or granted.
        const WRITE_CACHING = 0x0000_0004;
    }
}

bitflags! {
    /// SMB lease flags shared by lease-v2 request and response contexts.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct LeaseFlags: u32 {
        /// A lease break is in progress for the identified lease key.
        const BREAK_IN_PROGRESS = 0x0000_0002;
        /// The parent lease key field is present.
        const PARENT_LEASE_KEY_SET = 0x0000_0004;
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

impl FileId {
    /// Sentinel file identifier used by tree-scoped SMB2 operations without an open handle.
    pub const NONE: Self = Self {
        persistent: u64::MAX,
        volatile: u64::MAX,
    };
}

const LEASE_CONTEXT_NAME: &[u8; 4] = b"RqLs";

/// Generic SMB2 create-context container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateContext {
    /// Create-context name encoded in network byte order.
    pub name: Vec<u8>,
    /// Create-context payload bytes.
    pub data: Vec<u8>,
}

impl CreateContext {
    /// Builds a generic create context from a name and data payload.
    #[must_use]
    pub fn new(name: impl Into<Vec<u8>>, data: impl Into<Vec<u8>>) -> Self {
        Self {
            name: name.into(),
            data: data.into(),
        }
    }

    /// Builds an SMB 3.x lease-v2 create context.
    #[must_use]
    pub fn lease_v2(lease: LeaseV2) -> Self {
        Self::new(LEASE_CONTEXT_NAME.to_vec(), lease.encode())
    }

    /// Decodes the create context as an SMB 3.x lease-v2 payload when applicable.
    pub fn lease_v2_data(&self) -> Result<Option<LeaseV2>, ProtocolError> {
        if self.name != LEASE_CONTEXT_NAME {
            return Ok(None);
        }
        match self.data.len() {
            LeaseV2::LEN => LeaseV2::decode(&self.data).map(Some),
            LeaseV2::V1_LEN => LeaseV2::decode_v1(&self.data).map(Some),
            _ => Ok(None),
        }
    }
}

/// SMB 3.x lease-v2 request/response payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LeaseV2 {
    /// Client-generated key identifying the lease owner.
    pub lease_key: [u8; 16],
    /// Requested or granted lease state.
    pub lease_state: LeaseState,
    /// Lease flags.
    pub flags: LeaseFlags,
    /// Parent-directory lease key, when present.
    pub parent_lease_key: Option<[u8; 16]>,
    /// Lease epoch value.
    pub epoch: u16,
}

impl LeaseV2 {
    /// Encoded length of an SMB2 lease-v1 payload reused by some SMB 3.x servers in responses.
    pub const V1_LEN: usize = 32;
    /// Encoded length of an SMB 3.x lease-v2 payload.
    pub const LEN: usize = 52;

    /// Builds a lease-v2 payload with the provided key and state.
    #[must_use]
    pub fn new(lease_key: [u8; 16], lease_state: LeaseState) -> Self {
        Self {
            lease_key,
            lease_state,
            flags: LeaseFlags::empty(),
            parent_lease_key: None,
            epoch: 0,
        }
    }

    /// Sets or clears the parent lease key.
    #[must_use]
    pub fn with_parent_lease_key(mut self, parent_lease_key: Option<[u8; 16]>) -> Self {
        self.parent_lease_key = parent_lease_key;
        self
    }

    /// Serializes the lease payload.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::LEN);
        let mut flags = self.flags;
        if self.parent_lease_key.is_some() {
            flags |= LeaseFlags::PARENT_LEASE_KEY_SET;
        } else {
            flags.remove(LeaseFlags::PARENT_LEASE_KEY_SET);
        }
        out.extend_from_slice(&self.lease_key);
        out.put_u32_le(self.lease_state.bits());
        out.put_u32_le(flags.bits());
        out.put_u64_le(0);
        out.extend_from_slice(&self.parent_lease_key.unwrap_or([0; 16]));
        out.put_u16_le(self.epoch);
        out.put_u16_le(0);
        out
    }

    /// Parses a lease-v2 payload.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let mut input = bytes;
        let lease_key = get_array::<16>(&mut input, "lease_key")?;
        let lease_state = LeaseState::from_bits(get_u32(&mut input, "lease_state")?).ok_or(
            ProtocolError::InvalidField {
                field: "lease_state",
                reason: "unknown lease-state bits set",
            },
        )?;
        let flags = LeaseFlags::from_bits(get_u32(&mut input, "flags")?).ok_or(
            ProtocolError::InvalidField {
                field: "flags",
                reason: "unknown lease flags set",
            },
        )?;
        let _lease_duration = get_u64(&mut input, "lease_duration")?;
        let raw_parent_lease_key = get_array::<16>(&mut input, "parent_lease_key")?;
        let epoch = get_u16(&mut input, "epoch")?;
        let _reserved = get_u16(&mut input, "reserved")?;

        Ok(Self {
            lease_key,
            lease_state,
            flags,
            parent_lease_key: flags
                .contains(LeaseFlags::PARENT_LEASE_KEY_SET)
                .then_some(raw_parent_lease_key),
            epoch,
        })
    }

    /// Parses a lease-v1 response payload into the common lease shape.
    pub fn decode_v1(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let mut input = bytes;
        let lease_key = get_array::<16>(&mut input, "lease_key")?;
        let lease_state = LeaseState::from_bits(get_u32(&mut input, "lease_state")?).ok_or(
            ProtocolError::InvalidField {
                field: "lease_state",
                reason: "unknown lease-state bits set",
            },
        )?;
        let flags = LeaseFlags::from_bits(get_u32(&mut input, "flags")?).ok_or(
            ProtocolError::InvalidField {
                field: "flags",
                reason: "unknown lease flags set",
            },
        )?;
        let _lease_duration = get_u64(&mut input, "lease_duration")?;
        Ok(Self {
            lease_key,
            lease_state,
            flags,
            parent_lease_key: None,
            epoch: 0,
        })
    }
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
    /// Optional create contexts attached to the request.
    pub create_contexts: Vec<CreateContext>,
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
            create_contexts: Vec::new(),
        }
    }

    /// Serializes the request body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let contexts = encode_create_contexts(&self.create_contexts);
        let buffer_len = self.name.len().max(1) + contexts.len();
        let mut out = Vec::with_capacity(88 + buffer_len);
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
        let contexts_offset = if contexts.is_empty() {
            0
        } else {
            put_padding(&mut out, 8);
            (HEADER_LEN + out.len()) as u32
        };
        let contexts_length = contexts.len() as u32;
        out[48..52].copy_from_slice(&contexts_offset.to_le_bytes());
        out[52..56].copy_from_slice(&contexts_length.to_le_bytes());
        out.extend_from_slice(&contexts);
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
        let context_offset = get_u32(&mut input, "create_contexts_offset")?;
        let context_length = get_u32(&mut input, "create_contexts_length")? as usize;
        let name = if name_length == 0 {
            Vec::new()
        } else {
            slice_from_offset(body, name_offset, name_length, "name")?.to_vec()
        };
        let create_contexts = if context_offset == 0 || context_length == 0 {
            Vec::new()
        } else {
            decode_create_contexts(slice_from_offset32(
                body,
                context_offset,
                context_length,
                "create_contexts",
            )?)?
        };

        Ok(Self {
            requested_oplock_level,
            impersonation_level,
            desired_access,
            file_attributes,
            share_access,
            create_disposition,
            create_options,
            name,
            create_contexts,
        })
    }

    /// Returns the first lease-v2 create context attached to the request, if present.
    pub fn lease_v2(&self) -> Result<Option<LeaseV2>, ProtocolError> {
        find_lease_v2(&self.create_contexts)
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
    pub create_contexts: Vec<CreateContext>,
}

impl CreateResponse {
    /// Serializes the response body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let contexts = encode_create_contexts(&self.create_contexts);
        let mut out = BytesMut::with_capacity(96 + contexts.len());
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
        out.put_u32_le(contexts.len() as u32);
        out.extend_from_slice(&contexts);
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
            decode_create_contexts(slice_from_offset32(
                body,
                create_contexts_offset,
                create_contexts_length,
                "create_contexts",
            )?)?
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

    /// Returns the first granted lease-v2 response context, if present.
    pub fn lease_v2(&self) -> Result<Option<LeaseV2>, ProtocolError> {
        find_lease_v2(&self.create_contexts)
    }
}

fn encode_create_contexts(contexts: &[CreateContext]) -> Vec<u8> {
    let mut encoded = Vec::new();

    for (index, context) in contexts.iter().enumerate() {
        let mut entry = Vec::with_capacity(16 + context.name.len() + context.data.len() + 8);
        entry.put_u32_le(0);
        let name_offset = 16u16;
        entry.put_u16_le(name_offset);
        entry.put_u16_le(context.name.len() as u16);
        entry.put_u16_le(0);
        let data_offset = if context.data.is_empty() {
            0
        } else {
            let data_offset = align_up(usize::from(name_offset) + context.name.len(), 8);
            data_offset as u16
        };
        entry.put_u16_le(data_offset);
        entry.put_u32_le(context.data.len() as u32);
        entry.extend_from_slice(&context.name);
        put_padding(&mut entry, 8);
        entry.extend_from_slice(&context.data);
        put_padding(&mut entry, 8);
        if index + 1 != contexts.len() {
            let next = entry.len() as u32;
            entry[0..4].copy_from_slice(&next.to_le_bytes());
        }
        encoded.extend_from_slice(&entry);
    }

    encoded
}

fn decode_create_contexts(buffer: &[u8]) -> Result<Vec<CreateContext>, ProtocolError> {
    let mut contexts = Vec::new();
    let mut cursor = buffer;

    while !cursor.is_empty() {
        if cursor.len() < 16 {
            return Err(ProtocolError::UnexpectedEof {
                field: "create_context",
            });
        }
        let next = u32::from_le_bytes(cursor[0..4].try_into().expect("slice len"));
        let entry_len = if next == 0 {
            cursor.len()
        } else {
            next as usize
        };
        if entry_len > cursor.len() || entry_len < 16 || !entry_len.is_multiple_of(8) {
            return Err(ProtocolError::InvalidField {
                field: "next",
                reason: "create context extends past buffer",
            });
        }

        let entry = &cursor[..entry_len];
        let mut input = entry;
        let _next = get_u32(&mut input, "next")?;
        let name_offset = usize::from(get_u16(&mut input, "name_offset")?);
        let name_length = usize::from(get_u16(&mut input, "name_length")?);
        let _reserved = get_u16(&mut input, "reserved")?;
        let data_offset = usize::from(get_u16(&mut input, "data_offset")?);
        let data_length = get_u32(&mut input, "data_length")? as usize;
        let name = slice_from_context(entry, name_offset, name_length, "name")?.to_vec();
        let data = if data_offset == 0 || data_length == 0 {
            Vec::new()
        } else {
            slice_from_context(entry, data_offset, data_length, "data")?.to_vec()
        };
        contexts.push(CreateContext { name, data });

        if next == 0 {
            break;
        }
        cursor = &cursor[entry_len..];
    }

    Ok(contexts)
}

fn find_lease_v2(contexts: &[CreateContext]) -> Result<Option<LeaseV2>, ProtocolError> {
    for context in contexts {
        if let Some(lease) = context.lease_v2_data()? {
            return Ok(Some(lease));
        }
    }
    Ok(None)
}

fn slice_from_context<'a>(
    context: &'a [u8],
    offset: usize,
    len: usize,
    field: &'static str,
) -> Result<&'a [u8], ProtocolError> {
    let end = offset.checked_add(len).ok_or(ProtocolError::InvalidField {
        field,
        reason: "offset overflow",
    })?;
    if end > context.len() {
        return Err(ProtocolError::UnexpectedEof { field });
    }
    Ok(&context[offset..end])
}

fn align_up(value: usize, alignment: usize) -> usize {
    let remainder = value % alignment;
    if remainder == 0 {
        value
    } else {
        value + (alignment - remainder)
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
        CloseRequest, CloseResponse, CreateContext, CreateRequest, CreateResponse, FileAttributes,
        FileId, LeaseFlags, LeaseState, LeaseV2, OplockLevel, ShareAccess,
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
            create_contexts: Vec::new(),
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
            create_contexts: Vec::new(),
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
            create_contexts: vec![CreateContext::new(b"ExtA".to_vec(), vec![0x01, 0x02])],
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

    #[test]
    fn create_request_and_response_roundtrip_lease_v2_contexts() {
        let lease = LeaseV2::new(
            *b"lease-key-000000",
            LeaseState::READ_CACHING | LeaseState::HANDLE_CACHING,
        )
        .with_parent_lease_key(Some(*b"parent-lease-key"));
        let lease = LeaseV2 {
            flags: LeaseFlags::BREAK_IN_PROGRESS | LeaseFlags::PARENT_LEASE_KEY_SET,
            epoch: 3,
            ..lease
        };

        let request = CreateRequest {
            requested_oplock_level: RequestedOplockLevel::Lease,
            impersonation_level: 2,
            desired_access: 0x0012_019f,
            file_attributes: FileAttributes::NORMAL,
            share_access: ShareAccess::READ | ShareAccess::WRITE | ShareAccess::DELETE,
            create_disposition: CreateDisposition::OpenIf,
            create_options: CreateOptions::NON_DIRECTORY_FILE,
            name: super::utf16le("notes.txt"),
            create_contexts: vec![CreateContext::lease_v2(lease)],
        };

        let encoded_request = request.encode();
        let decoded_request =
            CreateRequest::decode(&encoded_request).expect("request should decode");
        assert_eq!(decoded_request, request);
        assert_eq!(
            decoded_request.lease_v2().expect("lease should parse"),
            Some(lease)
        );

        let response = CreateResponse {
            oplock_level: OplockLevel::Lease,
            file_attributes: FileAttributes::ARCHIVE,
            allocation_size: 4096,
            end_of_file: 128,
            file_id: FileId {
                persistent: 1,
                volatile: 2,
            },
            create_contexts: vec![CreateContext::lease_v2(lease)],
        };
        let encoded_response = response.encode();
        let decoded_response =
            CreateResponse::decode(&encoded_response).expect("response should decode");
        assert_eq!(decoded_response, response);
        assert_eq!(
            decoded_response.lease_v2().expect("lease should parse"),
            Some(lease)
        );
    }

    #[test]
    fn lease_v1_response_is_accepted_through_common_lease_parser() {
        let lease_key = *b"lease-key-000000";
        let mut payload = Vec::new();
        payload.extend_from_slice(&lease_key);
        payload.extend_from_slice(
            (LeaseState::READ_CACHING | LeaseState::HANDLE_CACHING)
                .bits()
                .to_le_bytes()
                .as_ref(),
        );
        payload.extend_from_slice(&LeaseFlags::BREAK_IN_PROGRESS.bits().to_le_bytes());
        payload.extend_from_slice(&0u64.to_le_bytes());

        let context = CreateContext::new(b"RqLs".to_vec(), payload);
        let lease = context
            .lease_v2_data()
            .expect("lease should decode")
            .expect("lease should exist");

        assert_eq!(lease.lease_key, lease_key);
        assert_eq!(lease.epoch, 0);
        assert!(lease.parent_lease_key.is_none());
        assert!(lease.flags.contains(LeaseFlags::BREAK_IN_PROGRESS));
    }
}
