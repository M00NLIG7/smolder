//! SMB2 IOCTL request and response bodies.

use std::net::{Ipv4Addr, Ipv6Addr};

use bitflags::bitflags;
use bytes::BufMut;

use super::create::FileId;
use super::{
    check_fixed_structure_size, get_array, get_u16, get_u32, get_u64, put_padding,
    slice_from_offset32,
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
        CtlCode, IoctlFlags, IoctlRequest, IoctlResponse, NetworkAddress,
        NetworkInterfaceCapabilities, NetworkInterfaceInfoResponse, ResumeKeyResponse,
    };
    use crate::smb::smb2::FileId;

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
}
