//! SMB2 tree connect bodies.

use bitflags::bitflags;
use bytes::{BufMut, BytesMut};

use super::{check_fixed_structure_size, get_u16, get_u32, slice_from_offset, utf16le, HEADER_LEN};
use crate::smb::ProtocolError;

bitflags! {
    /// Tree capabilities negotiated for the share.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct TreeCapabilities: u32 {
        /// DFS share.
        const DFS = 0x0000_0008;
        /// Continuous availability.
        const CONTINUOUS_AVAILABILITY = 0x0000_0010;
        /// Scale-out share.
        const SCALEOUT = 0x0000_0020;
        /// Cluster share.
        const CLUSTER = 0x0000_0040;
        /// Asymmetric share.
        const ASYMMETRIC = 0x0000_0080;
        /// Redirect to owner.
        const REDIRECT_TO_OWNER = 0x0000_0100;
    }
}

bitflags! {
    /// Share flags from a tree connect response.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct ShareFlags: u32 {
        /// Manual caching.
        const MANUAL_CACHING = 0x0000_0000;
        /// Auto caching.
        const AUTO_CACHING = 0x0000_0010;
        /// VDO caching.
        const VDO_CACHING = 0x0000_0020;
        /// No caching.
        const NO_CACHING = 0x0000_0030;
        /// DFS share.
        const DFS = 0x0000_0001;
        /// DFS root.
        const DFS_ROOT = 0x0000_0002;
        /// Restrict exclusive opens.
        const RESTRICT_EXCLUSIVE_OPENS = 0x0000_0100;
        /// Force shared delete.
        const FORCE_SHARED_DELETE = 0x0000_0200;
        /// Allow namespace caching.
        const ALLOW_NAMESPACE_CACHING = 0x0000_0400;
        /// Access-based directory enumeration.
        const ACCESS_BASED_DIRECTORY_ENUM = 0x0000_0800;
        /// Force level 2 oplocks.
        const FORCE_LEVELII_OPLOCK = 0x0000_1000;
        /// Enable hash v1.
        const ENABLE_HASH_V1 = 0x0000_2000;
        /// Enable hash v2.
        const ENABLE_HASH_V2 = 0x0000_4000;
        /// Encrypt data.
        const ENCRYPT_DATA = 0x0000_8000;
        /// Identity remoting.
        const IDENTITY_REMOTING = 0x0004_0000;
    }
}

/// Share type returned by the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ShareType {
    /// Disk share.
    Disk = 0x01,
    /// Named pipe share.
    Pipe = 0x02,
    /// Printer share.
    Print = 0x03,
}

/// SMB2 tree connect request body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeConnectRequest {
    /// Request flags.
    pub flags: u16,
    /// UNC path encoded as UTF-16LE.
    pub path: Vec<u8>,
}

impl TreeConnectRequest {
    /// Creates a request for a UNC path string.
    #[must_use]
    pub fn from_unc(path: &str) -> Self {
        Self {
            flags: 0,
            path: utf16le(path),
        }
    }

    /// Serializes the request body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(16 + self.path.len());
        out.put_u16_le(9);
        out.put_u16_le(self.flags);
        out.put_u16_le((HEADER_LEN + 8) as u16);
        out.put_u16_le(self.path.len() as u16);
        out.extend_from_slice(&self.path);
        out.to_vec()
    }

    /// Parses the request body.
    pub fn decode(body: &[u8]) -> Result<Self, ProtocolError> {
        let mut input = body;
        check_fixed_structure_size(get_u16(&mut input, "structure_size")?, 9, "structure_size")?;
        let flags = get_u16(&mut input, "flags")?;
        let path_offset = get_u16(&mut input, "path_offset")?;
        let path_length = usize::from(get_u16(&mut input, "path_length")?);
        let path = slice_from_offset(body, path_offset, path_length, "path")?.to_vec();

        Ok(Self { flags, path })
    }
}

/// SMB2 tree disconnect request body.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TreeDisconnectRequest;

impl TreeDisconnectRequest {
    /// Serializes the request body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(4);
        out.put_u16_le(4);
        out.put_u16_le(0);
        out.to_vec()
    }

    /// Parses the request body.
    pub fn decode(body: &[u8]) -> Result<Self, ProtocolError> {
        let mut input = body;
        check_fixed_structure_size(get_u16(&mut input, "structure_size")?, 4, "structure_size")?;
        let _reserved = get_u16(&mut input, "reserved")?;
        Ok(Self)
    }
}

/// SMB2 tree disconnect response body.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TreeDisconnectResponse;

impl TreeDisconnectResponse {
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

/// SMB2 tree connect response body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeConnectResponse {
    /// The connected share type.
    pub share_type: ShareType,
    /// Response flags.
    pub share_flags: ShareFlags,
    /// Share capabilities.
    pub capabilities: TreeCapabilities,
    /// Server maximum access mask.
    pub maximal_access: u32,
}

impl TreeConnectResponse {
    /// Serializes the response body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(16);
        out.put_u16_le(16);
        out.put_u8(self.share_type as u8);
        out.put_u8(0);
        out.put_u32_le(self.share_flags.bits());
        out.put_u32_le(self.capabilities.bits());
        out.put_u32_le(self.maximal_access);
        out.to_vec()
    }

    /// Parses the response body.
    pub fn decode(body: &[u8]) -> Result<Self, ProtocolError> {
        let mut input = body;
        check_fixed_structure_size(get_u16(&mut input, "structure_size")?, 16, "structure_size")?;
        let share_type = match super::get_u8(&mut input, "share_type")? {
            0x01 => ShareType::Disk,
            0x02 => ShareType::Pipe,
            0x03 => ShareType::Print,
            _ => {
                return Err(ProtocolError::InvalidField {
                    field: "share_type",
                    reason: "unknown share type",
                })
            }
        };
        let _reserved = super::get_u8(&mut input, "reserved")?;
        let share_flags = ShareFlags::from_bits(get_u32(&mut input, "share_flags")?).ok_or(
            ProtocolError::InvalidField {
                field: "share_flags",
                reason: "unknown share flags set",
            },
        )?;
        let capabilities = TreeCapabilities::from_bits(get_u32(&mut input, "capabilities")?)
            .ok_or(ProtocolError::InvalidField {
                field: "capabilities",
                reason: "unknown tree capabilities set",
            })?;
        let maximal_access = get_u32(&mut input, "maximal_access")?;

        Ok(Self {
            share_type,
            share_flags,
            capabilities,
            maximal_access,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ShareFlags, ShareType, TreeCapabilities, TreeConnectRequest, TreeConnectResponse,
        TreeDisconnectRequest, TreeDisconnectResponse,
    };

    #[test]
    fn tree_connect_request_roundtrips() {
        let request = TreeConnectRequest::from_unc(r"\\server\share");
        let encoded = request.encode();
        let decoded = TreeConnectRequest::decode(&encoded).expect("request should decode");

        assert_eq!(decoded, request);
    }

    #[test]
    fn tree_connect_response_roundtrips() {
        let response = TreeConnectResponse {
            share_type: ShareType::Disk,
            share_flags: ShareFlags::ENCRYPT_DATA,
            capabilities: TreeCapabilities::CONTINUOUS_AVAILABILITY,
            maximal_access: 0x0012_019f,
        };

        let encoded = response.encode();
        let decoded = TreeConnectResponse::decode(&encoded).expect("response should decode");

        assert_eq!(decoded, response);
    }

    #[test]
    fn tree_disconnect_request_and_response_roundtrip() {
        let request = TreeDisconnectRequest;
        let response = TreeDisconnectResponse;

        let encoded_request = request.encode();
        let decoded_request =
            TreeDisconnectRequest::decode(&encoded_request).expect("request should decode");
        assert_eq!(decoded_request, request);

        let encoded_response = response.encode();
        let decoded_response =
            TreeDisconnectResponse::decode(&encoded_response).expect("response should decode");
        assert_eq!(decoded_response, response);
    }
}
