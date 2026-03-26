//! SMB2 IOCTL request and response bodies.

use std::net::{Ipv4Addr, Ipv6Addr};

use bitflags::bitflags;
use bytes::BufMut;

use super::create::FileId;
use super::{
    check_fixed_structure_size, get_array, get_u16, get_u32, get_u64, put_padding,
    slice_from_offset32, utf16le, utf16le_string,
};
use crate::smb::ProtocolError;

const IOCTL_REQUEST_BODY_LEN: usize = 56;
const IOCTL_RESPONSE_BODY_LEN: usize = 48;
const AF_INET: u16 = 0x0002;
const AF_INET6: u16 = 0x0017;

/// SMB2 IOCTL / FSCTL control code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CtlCode(pub u32);

impl CtlCode {
    /// `FSCTL_DFS_GET_REFERRALS`
    pub const FSCTL_DFS_GET_REFERRALS: Self = Self(0x0006_0194);
    /// `FSCTL_LMR_REQUEST_RESILIENCY`
    pub const FSCTL_LMR_REQUEST_RESILIENCY: Self = Self(0x0014_01d4);
    /// `FSCTL_SRV_REQUEST_RESUME_KEY`
    pub const FSCTL_SRV_REQUEST_RESUME_KEY: Self = Self(0x0014_0078);
    /// `FSCTL_QUERY_NETWORK_INTERFACE_INFO`
    pub const FSCTL_QUERY_NETWORK_INTERFACE_INFO: Self = Self(0x0014_01fc);
    /// `FSCTL_VALIDATE_NEGOTIATE_INFO`
    pub const FSCTL_VALIDATE_NEGOTIATE_INFO: Self = Self(0x0014_0204);
}

bitflags! {
    /// SMB2 IOCTL request flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct IoctlFlags: u32 {
        /// The control code is an FSCTL, not a device-specific IOCTL.
        const IS_FSCTL = 0x0000_0001;
    }
}

bitflags! {
    /// Referral-header flags returned by `FSCTL_DFS_GET_REFERRALS`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct DfsReferralHeaderFlags: u32 {
        /// The referral response contains referral-server information.
        const REFERRAL_SERVERS = 0x0000_0001;
        /// The referral response contains storage-server targets.
        const STORAGE_SERVERS = 0x0000_0002;
    }
}

bitflags! {
    /// DFS referral entry flags for version 3 and 4 responses.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct DfsReferralEntryFlags: u16 {
        /// The referral entry is a domain/DC name-list referral.
        const NAME_LIST_REFERRAL = 0x0002;
        /// The referral entry is the first target in a target set.
        const TARGET_SET_BOUNDARY = 0x0004;
    }
}

/// Input buffer for `FSCTL_DFS_GET_REFERRALS`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DfsReferralRequest {
    /// Highest referral version understood by the client.
    pub max_referral_level: u16,
    /// UNC path that should be resolved.
    pub request_file_name: String,
}

impl DfsReferralRequest {
    /// Serializes the referral request payload.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.request_file_name.len() * 2);
        out.put_u16_le(self.max_referral_level);
        out.extend_from_slice(&utf16le(&self.request_file_name));
        out.put_u16_le(0);
        out
    }

    /// Parses the referral request payload.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let mut input = bytes;
        let max_referral_level = get_u16(&mut input, "max_referral_level")?;
        let request_file_name = utf16le_c_string(input, "request_file_name")?;
        Ok(Self {
            max_referral_level,
            request_file_name,
        })
    }
}

/// One parsed DFS referral entry from `FSCTL_DFS_GET_REFERRALS`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DfsReferralEntry {
    /// Referral-entry version. Smolder currently supports version 3 and 4.
    pub version: u16,
    /// Server type returned by the server.
    pub server_type: u16,
    /// Referral-entry flags.
    pub flags: DfsReferralEntryFlags,
    /// TTL in seconds for the referral entry.
    pub time_to_live: u32,
    /// DFS namespace path for root/link referrals.
    pub dfs_path: Option<String>,
    /// Alternate DFS path for root/link referrals, when provided.
    pub dfs_alternate_path: Option<String>,
    /// Network address for the concrete target, when provided.
    pub network_address: Option<String>,
    /// Domain/DC special name for name-list referrals.
    pub special_name: Option<String>,
    /// Expanded DC names for name-list referrals.
    pub expanded_names: Vec<String>,
}

impl DfsReferralEntry {
    /// Returns true when this entry is a name-list referral.
    #[must_use]
    pub fn is_name_list_referral(&self) -> bool {
        self.flags
            .contains(DfsReferralEntryFlags::NAME_LIST_REFERRAL)
    }
}

/// Parsed payload returned by `FSCTL_DFS_GET_REFERRALS`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DfsReferralResponse {
    /// Bytes of the original DFS path consumed by the server.
    pub path_consumed: u16,
    /// Header flags describing the response payload.
    pub header_flags: DfsReferralHeaderFlags,
    /// Parsed referral entries.
    pub referrals: Vec<DfsReferralEntry>,
}

impl DfsReferralResponse {
    /// Parses the DFS referral response payload.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let mut input = bytes;
        let path_consumed = get_u16(&mut input, "path_consumed")?;
        let referral_count = usize::from(get_u16(&mut input, "number_of_referrals")?);
        let header_flags =
            DfsReferralHeaderFlags::from_bits_truncate(get_u32(&mut input, "header_flags")?);
        let mut cursor = 8usize;
        let mut referrals = Vec::with_capacity(referral_count);

        for _ in 0..referral_count {
            if bytes.len().saturating_sub(cursor) < 12 {
                return Err(ProtocolError::UnexpectedEof {
                    field: "dfs_referral_entry",
                });
            }

            let version = u16::from_le_bytes([bytes[cursor], bytes[cursor + 1]]);
            let size = usize::from(u16::from_le_bytes([bytes[cursor + 2], bytes[cursor + 3]]));
            let server_type = u16::from_le_bytes([bytes[cursor + 4], bytes[cursor + 5]]);
            let flags = DfsReferralEntryFlags::from_bits_truncate(u16::from_le_bytes([
                bytes[cursor + 6],
                bytes[cursor + 7],
            ]));
            let time_to_live = u32::from_le_bytes([
                bytes[cursor + 8],
                bytes[cursor + 9],
                bytes[cursor + 10],
                bytes[cursor + 11],
            ]);
            if size < 12 || cursor.checked_add(size).is_none_or(|end| end > bytes.len()) {
                return Err(ProtocolError::InvalidField {
                    field: "dfs_referral_entry_size",
                    reason: "referral entry points outside the response buffer",
                });
            }

            let entry = match version {
                3 | 4 => decode_dfs_referral_v3_v4(
                    bytes,
                    cursor,
                    size,
                    version,
                    server_type,
                    flags,
                    time_to_live,
                )?,
                _ => {
                    return Err(ProtocolError::InvalidField {
                        field: "dfs_referral_entry_version",
                        reason: "unsupported DFS referral entry version",
                    })
                }
            };
            referrals.push(entry);
            cursor += size;
        }

        Ok(Self {
            path_consumed,
            header_flags,
            referrals,
        })
    }
}

/// Input buffer for `FSCTL_LMR_REQUEST_RESILIENCY`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NetworkResiliencyRequest {
    /// Requested resiliency timeout in milliseconds.
    pub timeout: u32,
}

impl NetworkResiliencyRequest {
    /// Encoded payload length.
    pub const LEN: usize = 8;

    /// Serializes the request payload.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::LEN);
        out.put_u32_le(self.timeout);
        out.put_u32_le(0);
        out
    }

    /// Parses the request payload.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != Self::LEN {
            return Err(ProtocolError::InvalidField {
                field: "network_resiliency_request",
                reason: "unexpected resiliency request length",
            });
        }
        let mut input = bytes;
        let timeout = get_u32(&mut input, "timeout")?;
        let _reserved = get_u32(&mut input, "reserved")?;
        Ok(Self { timeout })
    }
}

bitflags! {
    /// Network-interface capability flags returned by `FSCTL_QUERY_NETWORK_INTERFACE_INFO`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct NetworkInterfaceCapabilities: u32 {
        /// Receive Side Scaling is supported on the interface.
        const RSS_CAPABLE = 0x0000_0001;
        /// Remote Direct Memory Access is supported on the interface.
        const RDMA_CAPABLE = 0x0000_0002;
    }
}

/// A tree- or file-scoped SMB2 IOCTL request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoctlRequest {
    /// Control code for the request.
    pub ctl_code: CtlCode,
    /// Handle scope for the request, or [`FileId::NONE`] when no file handle is needed.
    pub file_id: FileId,
    /// Maximum input bytes the client is prepared to receive in the response.
    pub max_input_response: u32,
    /// Maximum output bytes the client is prepared to receive in the response.
    pub max_output_response: u32,
    /// IOCTL request flags.
    pub flags: IoctlFlags,
    /// Optional input buffer.
    pub input: Vec<u8>,
}

impl IoctlRequest {
    /// Builds a generic filesystem-control request with an optional input buffer.
    #[must_use]
    pub fn fsctl(
        ctl_code: CtlCode,
        file_id: FileId,
        max_output_response: u32,
        input: Vec<u8>,
    ) -> Self {
        Self {
            ctl_code,
            file_id,
            max_input_response: 0,
            max_output_response,
            flags: IoctlFlags::IS_FSCTL,
            input,
        }
    }

    /// Builds `FSCTL_QUERY_NETWORK_INTERFACE_INFO`.
    #[must_use]
    pub fn query_network_interface_info(max_output_response: u32) -> Self {
        Self::fsctl(
            CtlCode::FSCTL_QUERY_NETWORK_INTERFACE_INFO,
            FileId::NONE,
            max_output_response,
            Vec::new(),
        )
    }

    /// Builds `FSCTL_SRV_REQUEST_RESUME_KEY`.
    #[must_use]
    pub fn request_resume_key(file_id: FileId) -> Self {
        Self::fsctl(
            CtlCode::FSCTL_SRV_REQUEST_RESUME_KEY,
            file_id,
            32,
            Vec::new(),
        )
    }

    /// Builds `FSCTL_LMR_REQUEST_RESILIENCY`.
    #[must_use]
    pub fn request_resiliency(file_id: FileId, timeout: u32) -> Self {
        Self::fsctl(
            CtlCode::FSCTL_LMR_REQUEST_RESILIENCY,
            file_id,
            0,
            NetworkResiliencyRequest { timeout }.encode(),
        )
    }

    /// Builds `FSCTL_DFS_GET_REFERRALS`.
    #[must_use]
    pub fn get_dfs_referrals(request: DfsReferralRequest, max_output_response: u32) -> Self {
        Self::fsctl(
            CtlCode::FSCTL_DFS_GET_REFERRALS,
            FileId::NONE,
            max_output_response,
            request.encode(),
        )
    }

    /// Serializes the request body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(IOCTL_REQUEST_BODY_LEN + self.input.len().max(1));
        out.put_u16_le(57);
        out.put_u16_le(0);
        out.put_u32_le(self.ctl_code.0);
        out.put_u64_le(self.file_id.persistent);
        out.put_u64_le(self.file_id.volatile);
        let input_offset = if self.input.is_empty() {
            0
        } else {
            (super::HEADER_LEN + IOCTL_REQUEST_BODY_LEN) as u32
        };
        out.put_u32_le(input_offset);
        out.put_u32_le(self.input.len() as u32);
        out.put_u32_le(self.max_input_response);
        out.put_u32_le(0);
        out.put_u32_le(0);
        out.put_u32_le(self.max_output_response);
        out.put_u32_le(self.flags.bits());
        out.put_u32_le(0);
        if self.input.is_empty() {
            out.put_u8(0);
        } else {
            out.extend_from_slice(&self.input);
        }
        out.to_vec()
    }

    /// Parses the request body.
    pub fn decode(body: &[u8]) -> Result<Self, ProtocolError> {
        let mut input = body;
        check_fixed_structure_size(get_u16(&mut input, "structure_size")?, 57, "structure_size")?;
        let _reserved = get_u16(&mut input, "reserved")?;
        let ctl_code = CtlCode(get_u32(&mut input, "ctl_code")?);
        let file_id = FileId {
            persistent: get_u64(&mut input, "file_id_persistent")?,
            volatile: get_u64(&mut input, "file_id_volatile")?,
        };
        let input_offset = get_u32(&mut input, "input_offset")?;
        let input_count = get_u32(&mut input, "input_count")? as usize;
        let max_input_response = get_u32(&mut input, "max_input_response")?;
        let output_offset = get_u32(&mut input, "output_offset")?;
        let output_count = get_u32(&mut input, "output_count")?;
        let max_output_response = get_u32(&mut input, "max_output_response")?;
        let flags = IoctlFlags::from_bits(get_u32(&mut input, "flags")?).ok_or(
            ProtocolError::InvalidField {
                field: "flags",
                reason: "unknown ioctl flags set",
            },
        )?;
        let _reserved2 = get_u32(&mut input, "reserved2")?;
        if output_offset != 0 || output_count != 0 {
            return Err(ProtocolError::InvalidField {
                field: "output_offset",
                reason: "request-side output buffers are not supported",
            });
        }
        let input_buffer = if input_offset == 0 || input_count == 0 {
            Vec::new()
        } else {
            slice_from_offset32(body, input_offset, input_count, "input")?.to_vec()
        };

        Ok(Self {
            ctl_code,
            file_id,
            max_input_response,
            max_output_response,
            flags,
            input: input_buffer,
        })
    }
}

/// SMB2 IOCTL response body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoctlResponse {
    /// Control code echoed by the server.
    pub ctl_code: CtlCode,
    /// File identifier echoed by the server.
    pub file_id: FileId,
    /// Input buffer returned by the server, when present.
    pub input: Vec<u8>,
    /// Output buffer returned by the server.
    pub output: Vec<u8>,
    /// Response flags.
    pub flags: u32,
}

impl IoctlResponse {
    /// Serializes the response body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(IOCTL_RESPONSE_BODY_LEN + self.input.len() + self.output.len());
        out.put_u16_le(49);
        out.put_u16_le(0);
        out.put_u32_le(self.ctl_code.0);
        out.put_u64_le(self.file_id.persistent);
        out.put_u64_le(self.file_id.volatile);
        let input_offset = if self.input.is_empty() {
            0
        } else {
            (super::HEADER_LEN + IOCTL_RESPONSE_BODY_LEN) as u32
        };
        out.put_u32_le(input_offset);
        out.put_u32_le(self.input.len() as u32);
        let output_offset = if self.output.is_empty() {
            0
        } else {
            let aligned = IOCTL_RESPONSE_BODY_LEN + self.input.len();
            let aligned = (aligned + 7) & !7;
            (super::HEADER_LEN + aligned) as u32
        };
        out.put_u32_le(output_offset);
        out.put_u32_le(self.output.len() as u32);
        out.put_u32_le(self.flags);
        out.put_u32_le(0);
        out.extend_from_slice(&self.input);
        put_padding(&mut out, 8);
        out.extend_from_slice(&self.output);
        out.to_vec()
    }

    /// Parses the response body.
    pub fn decode(body: &[u8]) -> Result<Self, ProtocolError> {
        let mut input = body;
        check_fixed_structure_size(get_u16(&mut input, "structure_size")?, 49, "structure_size")?;
        let _reserved = get_u16(&mut input, "reserved")?;
        let ctl_code = CtlCode(get_u32(&mut input, "ctl_code")?);
        let file_id = FileId {
            persistent: get_u64(&mut input, "file_id_persistent")?,
            volatile: get_u64(&mut input, "file_id_volatile")?,
        };
        let input_offset = get_u32(&mut input, "input_offset")?;
        let input_count = get_u32(&mut input, "input_count")? as usize;
        let output_offset = get_u32(&mut input, "output_offset")?;
        let output_count = get_u32(&mut input, "output_count")? as usize;
        let flags = get_u32(&mut input, "flags")?;
        let _reserved2 = get_u32(&mut input, "reserved2")?;
        let input_buffer = if input_offset == 0 || input_count == 0 {
            Vec::new()
        } else {
            slice_from_offset32(body, input_offset, input_count, "input")?.to_vec()
        };
        let output_buffer = if output_offset == 0 || output_count == 0 {
            Vec::new()
        } else {
            slice_from_offset32(body, output_offset, output_count, "output")?.to_vec()
        };

        Ok(Self {
            ctl_code,
            file_id,
            input: input_buffer,
            output: output_buffer,
            flags,
        })
    }

    /// Decodes the output buffer as `FSCTL_DFS_GET_REFERRALS`.
    pub fn dfs_referral_response(&self) -> Result<Option<DfsReferralResponse>, ProtocolError> {
        if self.ctl_code != CtlCode::FSCTL_DFS_GET_REFERRALS {
            return Ok(None);
        }
        DfsReferralResponse::decode(&self.output).map(Some)
    }
}

fn utf16le_c_string(input: &[u8], field: &'static str) -> Result<String, ProtocolError> {
    let nul = input
        .chunks_exact(2)
        .position(|chunk| chunk == [0, 0])
        .ok_or(ProtocolError::InvalidField {
            field,
            reason: "UTF-16LE string is missing its terminating NUL",
        })?;
    utf16le_string(&input[..nul * 2]).map_err(|_| ProtocolError::InvalidField {
        field,
        reason: "invalid UTF-16LE string",
    })
}

fn utf16le_c_string_from_offset(
    bytes: &[u8],
    entry_start: usize,
    offset: u16,
    field: &'static str,
) -> Result<String, ProtocolError> {
    let start =
        entry_start
            .checked_add(usize::from(offset))
            .ok_or(ProtocolError::InvalidField {
                field,
                reason: "string offset overflow",
            })?;
    if start > bytes.len() {
        return Err(ProtocolError::UnexpectedEof { field });
    }
    utf16le_c_string(&bytes[start..], field)
}

fn utf16le_c_string_vec_from_offset(
    bytes: &[u8],
    entry_start: usize,
    offset: u16,
    count: usize,
    field: &'static str,
) -> Result<Vec<String>, ProtocolError> {
    let mut cursor =
        entry_start
            .checked_add(usize::from(offset))
            .ok_or(ProtocolError::InvalidField {
                field,
                reason: "string offset overflow",
            })?;
    let mut values = Vec::with_capacity(count);

    for _ in 0..count {
        if cursor > bytes.len() {
            return Err(ProtocolError::UnexpectedEof { field });
        }
        let remaining = &bytes[cursor..];
        let nul = remaining
            .chunks_exact(2)
            .position(|chunk| chunk == [0, 0])
            .ok_or(ProtocolError::InvalidField {
                field,
                reason: "UTF-16LE string list is missing a terminating NUL",
            })?;
        let byte_len = nul * 2;
        values.push(utf16le_string(&remaining[..byte_len]).map_err(|_| {
            ProtocolError::InvalidField {
                field,
                reason: "invalid UTF-16LE string",
            }
        })?);
        cursor += byte_len + 2;
    }

    Ok(values)
}

fn decode_dfs_referral_v3_v4(
    bytes: &[u8],
    entry_start: usize,
    size: usize,
    version: u16,
    server_type: u16,
    flags: DfsReferralEntryFlags,
    time_to_live: u32,
) -> Result<DfsReferralEntry, ProtocolError> {
    if flags.contains(DfsReferralEntryFlags::NAME_LIST_REFERRAL) {
        if size < 18 {
            return Err(ProtocolError::UnexpectedEof {
                field: "dfs_referral_name_list",
            });
        }
        let special_name_offset =
            u16::from_le_bytes([bytes[entry_start + 12], bytes[entry_start + 13]]);
        let expanded_name_count = usize::from(u16::from_le_bytes([
            bytes[entry_start + 14],
            bytes[entry_start + 15],
        ]));
        let expanded_name_offset =
            u16::from_le_bytes([bytes[entry_start + 16], bytes[entry_start + 17]]);
        let special_name = utf16le_c_string_from_offset(
            bytes,
            entry_start,
            special_name_offset,
            "dfs_special_name",
        )?;
        let expanded_names = if expanded_name_count == 0 {
            Vec::new()
        } else {
            utf16le_c_string_vec_from_offset(
                bytes,
                entry_start,
                expanded_name_offset,
                expanded_name_count,
                "dfs_expanded_names",
            )?
        };
        return Ok(DfsReferralEntry {
            version,
            server_type,
            flags,
            time_to_live,
            dfs_path: None,
            dfs_alternate_path: None,
            network_address: None,
            special_name: Some(special_name),
            expanded_names,
        });
    }

    if size < 24 {
        return Err(ProtocolError::UnexpectedEof {
            field: "dfs_referral_target",
        });
    }
    let dfs_path_offset = u16::from_le_bytes([bytes[entry_start + 12], bytes[entry_start + 13]]);
    let dfs_alternate_path_offset =
        u16::from_le_bytes([bytes[entry_start + 14], bytes[entry_start + 15]]);
    let network_address_offset =
        u16::from_le_bytes([bytes[entry_start + 16], bytes[entry_start + 17]]);

    let dfs_path = utf16le_c_string_from_offset(bytes, entry_start, dfs_path_offset, "dfs_path")?;
    let dfs_alternate_path = if dfs_alternate_path_offset == 0 {
        None
    } else {
        Some(utf16le_c_string_from_offset(
            bytes,
            entry_start,
            dfs_alternate_path_offset,
            "dfs_alternate_path",
        )?)
    };
    let network_address = if network_address_offset == 0 {
        None
    } else {
        Some(utf16le_c_string_from_offset(
            bytes,
            entry_start,
            network_address_offset,
            "dfs_network_address",
        )?)
    };

    Ok(DfsReferralEntry {
        version,
        server_type,
        flags,
        time_to_live,
        dfs_path: Some(dfs_path),
        dfs_alternate_path,
        network_address,
        special_name: None,
        expanded_names: Vec::new(),
    })
}

/// Parsed socket-address payload returned by `FSCTL_QUERY_NETWORK_INTERFACE_INFO`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkAddress {
    /// IPv4 network interface address.
    Ipv4(Ipv4Addr),
    /// IPv6 network interface address.
    Ipv6(Ipv6Addr),
    /// An address family Smolder does not decode yet.
    Unknown {
        /// Address-family value from the raw `SOCKADDR_STORAGE`.
        family: u16,
        /// Raw 128-byte `SOCKADDR_STORAGE` payload.
        raw: [u8; 128],
    },
}

/// One `NETWORK_INTERFACE_INFO` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkInterfaceInfo {
    /// Interface index reported by the server.
    pub if_index: u32,
    /// Capability flags reported by the server.
    pub capabilities: NetworkInterfaceCapabilities,
    /// Interface link speed in bits per second.
    pub link_speed: u64,
    /// Interface socket address.
    pub address: NetworkAddress,
}

/// Decoded output from `FSCTL_QUERY_NETWORK_INTERFACE_INFO`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkInterfaceInfoResponse {
    /// One entry per reported IP address.
    pub interfaces: Vec<NetworkInterfaceInfo>,
}

impl NetworkInterfaceInfoResponse {
    /// Decodes the response output buffer into typed network-interface entries.
    pub fn decode(buffer: &[u8]) -> Result<Self, ProtocolError> {
        let mut interfaces = Vec::new();
        let mut cursor = buffer;

        while !cursor.is_empty() {
            if cursor.len() < 152 {
                return Err(ProtocolError::UnexpectedEof {
                    field: "network_interface_info",
                });
            }

            let next = u32::from_le_bytes(cursor[0..4].try_into().expect("slice len"));
            let entry_len = if next == 0 {
                cursor.len()
            } else {
                next as usize
            };
            if entry_len > cursor.len() || entry_len < 152 || !entry_len.is_multiple_of(8) {
                return Err(ProtocolError::InvalidField {
                    field: "next",
                    reason: "network interface entry extends past buffer",
                });
            }

            let mut input = &cursor[..entry_len];
            let _next = get_u32(&mut input, "next")?;
            let if_index = get_u32(&mut input, "if_index")?;
            let capabilities =
                NetworkInterfaceCapabilities::from_bits(get_u32(&mut input, "capabilities")?)
                    .ok_or(ProtocolError::InvalidField {
                        field: "capabilities",
                        reason: "unknown network interface capability bits set",
                    })?;
            let _reserved = get_u32(&mut input, "reserved")?;
            let link_speed = get_u64(&mut input, "link_speed")?;
            let raw_address = get_array::<128>(&mut input, "sockaddr_storage")?;

            interfaces.push(NetworkInterfaceInfo {
                if_index,
                capabilities,
                link_speed,
                address: decode_network_address(raw_address),
            });

            if next == 0 {
                break;
            }
            cursor = &cursor[entry_len..];
        }

        Ok(Self { interfaces })
    }
}

/// Decoded output from `FSCTL_SRV_REQUEST_RESUME_KEY`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeKeyResponse {
    /// Opaque 24-byte resume key.
    pub resume_key: [u8; 24],
    /// Optional trailing context payload.
    pub context: Vec<u8>,
}

impl ResumeKeyResponse {
    /// Decodes the response output buffer into a resume key and optional context bytes.
    pub fn decode(buffer: &[u8]) -> Result<Self, ProtocolError> {
        if buffer.len() < 28 {
            return Err(ProtocolError::UnexpectedEof {
                field: "srv_request_resume_key",
            });
        }

        let mut input = buffer;
        let resume_key = get_array::<24>(&mut input, "resume_key")?;
        let context_length = get_u32(&mut input, "context_length")? as usize;
        if context_length > input.len() {
            return Err(ProtocolError::UnexpectedEof { field: "context" });
        }

        Ok(Self {
            resume_key,
            context: input[..context_length].to_vec(),
        })
    }
}

fn decode_network_address(raw: [u8; 128]) -> NetworkAddress {
    let family = u16::from_le_bytes([raw[0], raw[1]]);
    match family {
        AF_INET => NetworkAddress::Ipv4(Ipv4Addr::new(raw[4], raw[5], raw[6], raw[7])),
        AF_INET6 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&raw[8..24]);
            NetworkAddress::Ipv6(Ipv6Addr::from(octets))
        }
        _ => NetworkAddress::Unknown { family, raw },
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::{
        CtlCode, DfsReferralEntryFlags, DfsReferralHeaderFlags, DfsReferralRequest, IoctlFlags,
        IoctlRequest, IoctlResponse, NetworkAddress, NetworkInterfaceCapabilities,
        NetworkInterfaceInfoResponse, ResumeKeyResponse,
    };
    use crate::smb::smb2::{utf16le, FileId};

    #[test]
    fn ioctl_request_roundtrips() {
        let request = IoctlRequest {
            ctl_code: CtlCode::FSCTL_VALIDATE_NEGOTIATE_INFO,
            file_id: FileId {
                persistent: 1,
                volatile: 2,
            },
            max_input_response: 16,
            max_output_response: 8192,
            flags: IoctlFlags::IS_FSCTL,
            input: vec![0xaa, 0xbb, 0xcc],
        };

        let encoded = request.encode();
        let decoded = IoctlRequest::decode(&encoded).expect("request should decode");

        assert_eq!(decoded, request);
    }

    #[test]
    fn ioctl_response_roundtrips() {
        let response = IoctlResponse {
            ctl_code: CtlCode::FSCTL_QUERY_NETWORK_INTERFACE_INFO,
            file_id: FileId::NONE,
            input: vec![0x10, 0x20, 0x30, 0x40],
            output: vec![0x50, 0x60, 0x70],
            flags: 0,
        };

        let encoded = response.encode();
        let decoded = IoctlResponse::decode(&encoded).expect("response should decode");

        assert_eq!(decoded, response);
    }

    #[test]
    fn query_network_interface_info_response_decodes_ipv4_and_ipv6_entries() {
        let mut buffer = Vec::new();

        buffer.extend_from_slice(&152u32.to_le_bytes());
        buffer.extend_from_slice(&7u32.to_le_bytes());
        buffer.extend_from_slice(
            &NetworkInterfaceCapabilities::RSS_CAPABLE
                .bits()
                .to_le_bytes(),
        );
        buffer.extend_from_slice(&0u32.to_le_bytes());
        buffer.extend_from_slice(&10_000_000u64.to_le_bytes());
        let mut ipv4 = [0u8; 128];
        ipv4[0..2].copy_from_slice(&0x0002u16.to_le_bytes());
        ipv4[4..8].copy_from_slice(&Ipv4Addr::new(10, 0, 0, 1).octets());
        buffer.extend_from_slice(&ipv4);

        buffer.extend_from_slice(&0u32.to_le_bytes());
        buffer.extend_from_slice(&9u32.to_le_bytes());
        buffer.extend_from_slice(
            &NetworkInterfaceCapabilities::RDMA_CAPABLE
                .bits()
                .to_le_bytes(),
        );
        buffer.extend_from_slice(&0u32.to_le_bytes());
        buffer.extend_from_slice(&40_000_000u64.to_le_bytes());
        let mut ipv6 = [0u8; 128];
        ipv6[0..2].copy_from_slice(&0x0017u16.to_le_bytes());
        ipv6[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        buffer.extend_from_slice(&ipv6);

        let decoded =
            NetworkInterfaceInfoResponse::decode(&buffer).expect("response should decode");

        assert_eq!(decoded.interfaces.len(), 2);
        assert_eq!(decoded.interfaces[0].if_index, 7);
        assert_eq!(
            decoded.interfaces[0].address,
            NetworkAddress::Ipv4(Ipv4Addr::new(10, 0, 0, 1))
        );
        assert_eq!(decoded.interfaces[1].if_index, 9);
        assert_eq!(
            decoded.interfaces[1].address,
            NetworkAddress::Ipv6(Ipv6Addr::LOCALHOST)
        );
    }

    #[test]
    fn resume_key_response_decodes_opaque_key_and_context() {
        let mut buffer = Vec::new();
        buffer.extend(0u8..24u8);
        buffer.extend_from_slice(&3u32.to_le_bytes());
        buffer.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);

        let decoded = ResumeKeyResponse::decode(&buffer).expect("response should decode");

        assert_eq!(decoded.resume_key[0], 0);
        assert_eq!(decoded.resume_key[23], 23);
        assert_eq!(decoded.context, vec![0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn dfs_referral_request_roundtrips() {
        let request = DfsReferralRequest {
            max_referral_level: 4,
            request_file_name: r"\\domain\dfs\team".to_string(),
        };

        let encoded = request.encode();
        let decoded = DfsReferralRequest::decode(&encoded).expect("request should decode");

        assert_eq!(decoded, request);
    }

    #[test]
    fn dfs_referral_response_decodes_storage_target_entry() {
        let dfs_path = utf16le(r"\\domain\dfs\team");
        let alternate_path = utf16le(r"\\domain\dfs");
        let network_address = utf16le(r"\\server-b\teamshare");
        let dfs_path_offset = 24u16;
        let alternate_path_offset = dfs_path_offset + dfs_path.len() as u16 + 2;
        let network_address_offset = alternate_path_offset + alternate_path.len() as u16 + 2;

        let mut output = Vec::new();
        output.extend_from_slice(&0u16.to_le_bytes());
        output.extend_from_slice(&1u16.to_le_bytes());
        output.extend_from_slice(&DfsReferralHeaderFlags::STORAGE_SERVERS.bits().to_le_bytes());
        output.extend_from_slice(&4u16.to_le_bytes());
        output.extend_from_slice(&24u16.to_le_bytes());
        output.extend_from_slice(&0u16.to_le_bytes());
        output.extend_from_slice(
            &DfsReferralEntryFlags::TARGET_SET_BOUNDARY
                .bits()
                .to_le_bytes(),
        );
        output.extend_from_slice(&300u32.to_le_bytes());
        output.extend_from_slice(&dfs_path_offset.to_le_bytes());
        output.extend_from_slice(&alternate_path_offset.to_le_bytes());
        output.extend_from_slice(&network_address_offset.to_le_bytes());
        output.extend_from_slice(&[0u8; 6]);
        output.extend_from_slice(&dfs_path);
        output.extend_from_slice(&0u16.to_le_bytes());
        output.extend_from_slice(&alternate_path);
        output.extend_from_slice(&0u16.to_le_bytes());
        output.extend_from_slice(&network_address);
        output.extend_from_slice(&0u16.to_le_bytes());

        let decoded = super::DfsReferralResponse::decode(&output).expect("response should decode");

        assert_eq!(decoded.path_consumed, 0);
        assert_eq!(
            decoded.header_flags,
            DfsReferralHeaderFlags::STORAGE_SERVERS
        );
        assert_eq!(decoded.referrals.len(), 1);
        let entry = &decoded.referrals[0];
        assert_eq!(entry.version, 4);
        assert_eq!(entry.server_type, 0);
        assert!(entry
            .flags
            .contains(DfsReferralEntryFlags::TARGET_SET_BOUNDARY));
        assert_eq!(entry.time_to_live, 300);
        assert_eq!(entry.dfs_path.as_deref(), Some(r"\\domain\dfs\team"));
        assert_eq!(entry.dfs_alternate_path.as_deref(), Some(r"\\domain\dfs"));
        assert_eq!(
            entry.network_address.as_deref(),
            Some(r"\\server-b\teamshare")
        );
        assert!(!entry.is_name_list_referral());
    }

    #[test]
    fn dfs_referral_response_decodes_name_list_entry() {
        let special_name = utf16le("example.com");
        let dc_one = utf16le(r"\\dc1.example.com");
        let dc_two = utf16le(r"\\dc2.example.com");
        let special_name_offset = 18u16;
        let expanded_name_offset = special_name_offset + special_name.len() as u16 + 2;

        let mut output = Vec::new();
        output.extend_from_slice(&0u16.to_le_bytes());
        output.extend_from_slice(&1u16.to_le_bytes());
        output.extend_from_slice(
            &DfsReferralHeaderFlags::REFERRAL_SERVERS
                .bits()
                .to_le_bytes(),
        );
        output.extend_from_slice(&3u16.to_le_bytes());
        output.extend_from_slice(&18u16.to_le_bytes());
        output.extend_from_slice(&1u16.to_le_bytes());
        output.extend_from_slice(
            &DfsReferralEntryFlags::NAME_LIST_REFERRAL
                .bits()
                .to_le_bytes(),
        );
        output.extend_from_slice(&60u32.to_le_bytes());
        output.extend_from_slice(&special_name_offset.to_le_bytes());
        output.extend_from_slice(&2u16.to_le_bytes());
        output.extend_from_slice(&expanded_name_offset.to_le_bytes());
        output.extend_from_slice(&special_name);
        output.extend_from_slice(&0u16.to_le_bytes());
        output.extend_from_slice(&dc_one);
        output.extend_from_slice(&0u16.to_le_bytes());
        output.extend_from_slice(&dc_two);
        output.extend_from_slice(&0u16.to_le_bytes());

        let decoded = super::DfsReferralResponse::decode(&output).expect("response should decode");

        assert_eq!(
            decoded.header_flags,
            DfsReferralHeaderFlags::REFERRAL_SERVERS
        );
        assert_eq!(decoded.referrals.len(), 1);
        let entry = &decoded.referrals[0];
        assert_eq!(entry.version, 3);
        assert!(entry.is_name_list_referral());
        assert_eq!(entry.special_name.as_deref(), Some("example.com"));
        assert_eq!(
            entry.expanded_names,
            vec![
                r"\\dc1.example.com".to_string(),
                r"\\dc2.example.com".to_string()
            ]
        );
        assert_eq!(entry.dfs_path, None);
        assert_eq!(entry.network_address, None);
    }
}
