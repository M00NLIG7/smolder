//! Minimal connection-oriented DCE/RPC primitives used by remote exec flows.

use bitflags::bitflags;
use bytes::{Buf, BufMut, BytesMut};

use crate::smb::ProtocolError;

const RPC_VERSION: u8 = 5;
const RPC_VERSION_MINOR: u8 = 0;
const DATA_REPRESENTATION_LITTLE_ENDIAN: [u8; 4] = [0x10, 0x00, 0x00, 0x00];
const COMMON_HEADER_LEN: usize = 16;
const SEC_TRAILER_LEN: usize = 8;
const BIND_CONTEXT_ITEM_LEN: usize = 44;
const BIND_ACK_RESULT_LEN: usize = 24;
const NDR32_UUID: Uuid = Uuid::new(
    0x8a88_5d04,
    0x1ceb,
    0x11c9,
    [0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60],
);

bitflags! {
    /// DCE/RPC packet flags for connection-oriented PDUs.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct PacketFlags: u8 {
        /// First fragment in the sequence.
        const FIRST_FRAGMENT = 0x01;
        /// Last fragment in the sequence.
        const LAST_FRAGMENT = 0x02;
        /// Cancel pending, or `SUPPORT_HEADER_SIGN` on bind-family and auth3 PDUs.
        const PENDING_CANCEL = 0x04;
        /// Concurrent multiplexing supported.
        const CONCURRENT_MULTIPLEX = 0x10;
        /// Fault indicates the server did not execute the call.
        const DID_NOT_EXECUTE = 0x20;
        /// Packet contains an object UUID in the request body.
        const OBJECT_UUID = 0x80;
    }
}

impl PacketFlags {
    /// Header-sign support on bind-family and `rpc_auth_3` PDUs.
    pub const SUPPORT_HEADER_SIGN: Self = Self::from_bits_retain(0x04);
}

/// Connection-oriented DCE/RPC packet type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PacketType {
    /// Request PDU.
    Request = 0,
    /// Response PDU.
    Response = 2,
    /// Fault PDU.
    Fault = 3,
    /// Bind PDU.
    Bind = 11,
    /// Bind acknowledgement PDU.
    BindAck = 12,
    /// Third leg of a three-leg secure RPC bind.
    RpcAuth3 = 16,
}

impl TryFrom<u8> for PacketType {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Request),
            2 => Ok(Self::Response),
            3 => Ok(Self::Fault),
            11 => Ok(Self::Bind),
            12 => Ok(Self::BindAck),
            16 => Ok(Self::RpcAuth3),
            _ => Err(ProtocolError::InvalidField {
                field: "packet_type",
                reason: "unknown packet type",
            }),
        }
    }
}

/// DCE/RPC authentication service identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AuthType {
    /// No authentication.
    None = 0x00,
    /// GSS-API negotiate (SPNEGO).
    GssNegotiate = 0x09,
    /// NTLM / SSPI WinNT provider.
    WinNt = 0x0a,
    /// Schannel.
    GssSchannel = 0x0e,
    /// Kerberos.
    GssKerberos = 0x10,
    /// Netlogon secure channel.
    Netlogon = 0x44,
    /// Runtime default authentication service.
    Default = 0xff,
}

impl TryFrom<u8> for AuthType {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::None),
            0x09 => Ok(Self::GssNegotiate),
            0x0a => Ok(Self::WinNt),
            0x0e => Ok(Self::GssSchannel),
            0x10 => Ok(Self::GssKerberos),
            0x44 => Ok(Self::Netlogon),
            0xff => Ok(Self::Default),
            _ => Err(ProtocolError::InvalidField {
                field: "auth_type",
                reason: "unknown authentication type",
            }),
        }
    }
}

/// DCE/RPC authentication protection level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AuthLevel {
    /// Runtime default protection level.
    Default = 0x00,
    /// No protection.
    None = 0x01,
    /// Authenticate the connection establishment only.
    Connect = 0x02,
    /// Authenticate each call.
    Call = 0x03,
    /// Authenticate every packet.
    Packet = 0x04,
    /// Provide per-packet integrity.
    PacketIntegrity = 0x05,
    /// Provide per-packet privacy/confidentiality.
    PacketPrivacy = 0x06,
}

impl TryFrom<u8> for AuthLevel {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::Default),
            0x01 => Ok(Self::None),
            0x02 => Ok(Self::Connect),
            0x03 => Ok(Self::Call),
            0x04 => Ok(Self::Packet),
            0x05 => Ok(Self::PacketIntegrity),
            0x06 => Ok(Self::PacketPrivacy),
            _ => Err(ProtocolError::InvalidField {
                field: "auth_level",
                reason: "unknown authentication level",
            }),
        }
    }
}

/// Connection-oriented DCE/RPC authentication verifier appended to a PDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthVerifier {
    /// Authentication service identifier.
    pub auth_type: AuthType,
    /// Requested protection level.
    pub auth_level: AuthLevel,
    /// Reserved byte carried in the security trailer.
    pub auth_reserved: u8,
    /// Authentication context identifier.
    pub auth_context_id: u32,
    /// Authentication token or signature bytes.
    pub auth_value: Vec<u8>,
}

impl AuthVerifier {
    /// Builds an authentication verifier with a zero reserved byte.
    #[must_use]
    pub fn new(
        auth_type: AuthType,
        auth_level: AuthLevel,
        auth_context_id: u32,
        auth_value: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            auth_type,
            auth_level,
            auth_reserved: 0,
            auth_context_id,
            auth_value: auth_value.into(),
        }
    }
}

/// Mixed-endian UUID encoding used by DCE/RPC syntax identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Uuid {
    /// First UUID field.
    pub data1: u32,
    /// Second UUID field.
    pub data2: u16,
    /// Third UUID field.
    pub data3: u16,
    /// Final eight bytes.
    pub data4: [u8; 8],
}

impl Uuid {
    /// Builds a UUID from its native fields.
    pub const fn new(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Self {
        Self {
            data1,
            data2,
            data3,
            data4,
        }
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.put_u32_le(self.data1);
        out.put_u16_le(self.data2);
        out.put_u16_le(self.data3);
        out.extend_from_slice(&self.data4);
    }

    fn decode(input: &mut &[u8], field: &'static str) -> Result<Self, ProtocolError> {
        Ok(Self {
            data1: get_u32(input, field)?,
            data2: get_u16(input, field)?,
            data3: get_u16(input, field)?,
            data4: get_array::<8>(input, field)?,
        })
    }
}

/// RPC abstract or transfer syntax identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxId {
    /// Syntax UUID.
    pub uuid: Uuid,
    /// Major version.
    pub version: u16,
    /// Minor version.
    pub version_minor: u16,
}

impl SyntaxId {
    /// NDR32 transfer syntax identifier.
    pub const NDR32: Self = Self {
        uuid: NDR32_UUID,
        version: 2,
        version_minor: 0,
    };

    /// Builds a syntax identifier from UUID and version tuple.
    pub const fn new(uuid: Uuid, version: u16, version_minor: u16) -> Self {
        Self {
            uuid,
            version,
            version_minor,
        }
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        self.uuid.encode_into(out);
        out.put_u16_le(self.version);
        out.put_u16_le(self.version_minor);
    }

    fn decode(input: &mut &[u8], field: &'static str) -> Result<Self, ProtocolError> {
        Ok(Self {
            uuid: Uuid::decode(input, field)?,
            version: get_u16(input, field)?,
            version_minor: get_u16(input, field)?,
        })
    }
}

/// Common DCE/RPC header fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CommonHeader {
    /// Packet type.
    pub packet_type: PacketType,
    /// Packet flags.
    pub flags: PacketFlags,
    /// Fragment length including the header.
    pub frag_length: u16,
    /// Authentication token length, excluding the fixed security trailer.
    pub auth_length: u16,
    /// Client-assigned call identifier.
    pub call_id: u32,
}

impl CommonHeader {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.put_u8(RPC_VERSION);
        out.put_u8(RPC_VERSION_MINOR);
        out.put_u8(self.packet_type as u8);
        out.put_u8(self.flags.bits());
        out.extend_from_slice(&DATA_REPRESENTATION_LITTLE_ENDIAN);
        out.put_u16_le(self.frag_length);
        out.put_u16_le(self.auth_length);
        out.put_u32_le(self.call_id);
    }

    fn decode(bytes: &[u8]) -> Result<(Self, &[u8]), ProtocolError> {
        let mut input = bytes;
        let version = get_u8(&mut input, "rpc_version")?;
        if version != RPC_VERSION {
            return Err(ProtocolError::InvalidField {
                field: "rpc_version",
                reason: "unsupported rpc version",
            });
        }
        let version_minor = get_u8(&mut input, "rpc_version_minor")?;
        if version_minor != RPC_VERSION_MINOR {
            return Err(ProtocolError::InvalidField {
                field: "rpc_version_minor",
                reason: "unsupported rpc minor version",
            });
        }
        let packet_type = PacketType::try_from(get_u8(&mut input, "packet_type")?)?;
        let flags = PacketFlags::from_bits(get_u8(&mut input, "flags")?).ok_or(
            ProtocolError::InvalidField {
                field: "flags",
                reason: "unknown rpc packet flags set",
            },
        )?;
        let data_representation = get_array::<4>(&mut input, "data_representation")?;
        if data_representation != DATA_REPRESENTATION_LITTLE_ENDIAN {
            return Err(ProtocolError::InvalidField {
                field: "data_representation",
                reason: "unsupported data representation",
            });
        }
        let frag_length = get_u16(&mut input, "frag_length")?;
        if frag_length as usize > bytes.len() || (frag_length as usize) < COMMON_HEADER_LEN {
            return Err(ProtocolError::InvalidField {
                field: "frag_length",
                reason: "fragment length exceeds packet bounds",
            });
        }
        let auth_length = get_u16(&mut input, "auth_length")?;
        let call_id = get_u32(&mut input, "call_id")?;
        Ok((
            Self {
                packet_type,
                flags,
                frag_length,
                auth_length,
                call_id,
            },
            &bytes[COMMON_HEADER_LEN..frag_length as usize],
        ))
    }
}

/// DCE/RPC bind request with a single abstract syntax and transfer syntax.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindPdu {
    /// Call identifier.
    pub call_id: u32,
    /// Packet flags.
    pub flags: PacketFlags,
    /// Maximum transmit fragment size.
    pub max_xmit_frag: u16,
    /// Maximum receive fragment size.
    pub max_recv_frag: u16,
    /// Association group id.
    pub assoc_group_id: u32,
    /// Presentation context id.
    pub context_id: u16,
    /// Abstract syntax being requested.
    pub abstract_syntax: SyntaxId,
    /// Transfer syntax being requested.
    pub transfer_syntax: SyntaxId,
    /// Optional authentication verifier appended to the PDU.
    pub auth_verifier: Option<AuthVerifier>,
}

impl BindPdu {
    /// Encodes the bind PDU.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(12 + BIND_CONTEXT_ITEM_LEN + SEC_TRAILER_LEN + 16);
        body.put_u16_le(self.max_xmit_frag);
        body.put_u16_le(self.max_recv_frag);
        body.put_u32_le(self.assoc_group_id);
        body.put_u8(1);
        body.put_u8(0);
        body.put_u16_le(0);
        body.put_u16_le(self.context_id);
        body.put_u8(1);
        body.put_u8(0);
        self.abstract_syntax.encode_into(&mut body);
        self.transfer_syntax.encode_into(&mut body);
        let auth_length = append_auth_verifier(&mut body, self.auth_verifier.as_ref());

        let mut out = Vec::with_capacity(COMMON_HEADER_LEN + body.len());
        CommonHeader {
            packet_type: PacketType::Bind,
            flags: self.flags,
            frag_length: (COMMON_HEADER_LEN + body.len()) as u16,
            auth_length,
            call_id: self.call_id,
        }
        .encode_into(&mut out);
        out.extend_from_slice(&body);
        out
    }

    /// Decodes a bind PDU.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let (header, body) = CommonHeader::decode(bytes)?;
        if header.packet_type != PacketType::Bind {
            return Err(ProtocolError::InvalidField {
                field: "packet_type",
                reason: "expected bind pdu",
            });
        }
        let (mut body, auth_verifier) = split_auth_verifier(body, header.auth_length)?;
        let max_xmit_frag = get_u16(&mut body, "max_xmit_frag")?;
        let max_recv_frag = get_u16(&mut body, "max_recv_frag")?;
        let assoc_group_id = get_u32(&mut body, "assoc_group_id")?;
        let num_context_items = get_u8(&mut body, "num_context_items")?;
        let _reserved = get_u8(&mut body, "reserved")?;
        let _reserved2 = get_u16(&mut body, "reserved2")?;
        if num_context_items != 1 {
            return Err(ProtocolError::InvalidField {
                field: "num_context_items",
                reason: "only one bind context item is supported",
            });
        }
        let context_id = get_u16(&mut body, "context_id")?;
        let num_transfer_items = get_u8(&mut body, "num_transfer_items")?;
        let _reserved3 = get_u8(&mut body, "reserved3")?;
        if num_transfer_items != 1 {
            return Err(ProtocolError::InvalidField {
                field: "num_transfer_items",
                reason: "only one transfer syntax is supported",
            });
        }
        let abstract_syntax = SyntaxId::decode(&mut body, "abstract_syntax")?;
        let transfer_syntax = SyntaxId::decode(&mut body, "transfer_syntax")?;
        Ok(Self {
            call_id: header.call_id,
            flags: header.flags,
            max_xmit_frag,
            max_recv_frag,
            assoc_group_id,
            context_id,
            abstract_syntax,
            transfer_syntax,
            auth_verifier,
        })
    }
}

/// Single bind-ack context result item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindAckResult {
    /// Negotiation result code.
    pub result: u16,
    /// Reason code for the result.
    pub reason: u16,
    /// Accepted transfer syntax.
    pub transfer_syntax: SyntaxId,
}

/// DCE/RPC bind acknowledgement with a single result item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindAckPdu {
    /// Call identifier.
    pub call_id: u32,
    /// Packet flags.
    pub flags: PacketFlags,
    /// Maximum transmit fragment size.
    pub max_xmit_frag: u16,
    /// Maximum receive fragment size.
    pub max_recv_frag: u16,
    /// Association group id.
    pub assoc_group_id: u32,
    /// Secondary address returned by the server.
    pub secondary_address: Vec<u8>,
    /// Presentation context result.
    pub result: BindAckResult,
    /// Optional authentication verifier appended to the PDU.
    pub auth_verifier: Option<AuthVerifier>,
}

impl BindAckPdu {
    /// Encodes the bind-ack PDU.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let address_padding = padding_len(self.secondary_address.len() + 2);
        let mut body = Vec::with_capacity(
            10 + self.secondary_address.len() + address_padding + 4 + BIND_ACK_RESULT_LEN,
        );
        body.put_u16_le(self.max_xmit_frag);
        body.put_u16_le(self.max_recv_frag);
        body.put_u32_le(self.assoc_group_id);
        body.put_u16_le(self.secondary_address.len() as u16);
        body.extend_from_slice(&self.secondary_address);
        pad_to_4(&mut body);
        body.put_u8(1);
        body.put_u8(0);
        body.put_u16_le(0);
        body.put_u16_le(self.result.result);
        body.put_u16_le(self.result.reason);
        self.result.transfer_syntax.encode_into(&mut body);
        let auth_length = append_auth_verifier(&mut body, self.auth_verifier.as_ref());

        let mut out = Vec::with_capacity(COMMON_HEADER_LEN + body.len());
        CommonHeader {
            packet_type: PacketType::BindAck,
            flags: self.flags,
            frag_length: (COMMON_HEADER_LEN + body.len()) as u16,
            auth_length,
            call_id: self.call_id,
        }
        .encode_into(&mut out);
        out.extend_from_slice(&body);
        out
    }

    /// Decodes a bind-ack PDU.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let (header, body) = CommonHeader::decode(bytes)?;
        if header.packet_type != PacketType::BindAck {
            return Err(ProtocolError::InvalidField {
                field: "packet_type",
                reason: "expected bind-ack pdu",
            });
        }
        let (mut body, auth_verifier) = split_auth_verifier(body, header.auth_length)?;
        let max_xmit_frag = get_u16(&mut body, "max_xmit_frag")?;
        let max_recv_frag = get_u16(&mut body, "max_recv_frag")?;
        let assoc_group_id = get_u32(&mut body, "assoc_group_id")?;
        let secondary_address_len = get_u16(&mut body, "secondary_address_len")? as usize;
        let secondary_address = get_vec(&mut body, secondary_address_len, "secondary_address")?;
        skip_padding(
            &mut body,
            padding_len(secondary_address_len + 2),
            "secondary_address_padding",
        )?;
        let num_results = get_u8(&mut body, "num_results")?;
        let _reserved = get_u8(&mut body, "reserved")?;
        let _reserved2 = get_u16(&mut body, "reserved2")?;
        if num_results != 1 {
            return Err(ProtocolError::InvalidField {
                field: "num_results",
                reason: "only one bind result is supported",
            });
        }
        let result = get_u16(&mut body, "result")?;
        let reason = get_u16(&mut body, "reason")?;
        let transfer_syntax = SyntaxId::decode(&mut body, "transfer_syntax")?;
        Ok(Self {
            call_id: header.call_id,
            flags: header.flags,
            max_xmit_frag,
            max_recv_frag,
            assoc_group_id,
            secondary_address,
            result: BindAckResult {
                result,
                reason,
                transfer_syntax,
            },
            auth_verifier,
        })
    }
}

/// `rpc_auth_3` PDU carrying the final leg of a three-leg secure RPC bind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcAuth3Pdu {
    /// Call identifier.
    pub call_id: u32,
    /// Packet flags.
    pub flags: PacketFlags,
    /// Four-byte pad field ignored on receipt.
    pub pad: [u8; 4],
    /// Authentication verifier and token.
    pub auth_verifier: AuthVerifier,
}

impl RpcAuth3Pdu {
    /// Encodes the `rpc_auth_3` PDU.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut body =
            Vec::with_capacity(4 + SEC_TRAILER_LEN + self.auth_verifier.auth_value.len());
        body.extend_from_slice(&self.pad);
        let auth_length = append_auth_verifier(&mut body, Some(&self.auth_verifier));

        let mut out = Vec::with_capacity(COMMON_HEADER_LEN + body.len());
        CommonHeader {
            packet_type: PacketType::RpcAuth3,
            flags: self.flags,
            frag_length: (COMMON_HEADER_LEN + body.len()) as u16,
            auth_length,
            call_id: self.call_id,
        }
        .encode_into(&mut out);
        out.extend_from_slice(&body);
        out
    }

    /// Decodes the `rpc_auth_3` PDU.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let (header, body) = CommonHeader::decode(bytes)?;
        if header.packet_type != PacketType::RpcAuth3 {
            return Err(ProtocolError::InvalidField {
                field: "packet_type",
                reason: "expected rpc_auth_3 pdu",
            });
        }
        if header.auth_length == 0 {
            return Err(ProtocolError::InvalidField {
                field: "auth_length",
                reason: "rpc_auth_3 requires an authentication verifier",
            });
        }

        let (mut body, auth_verifier) = split_auth_verifier(body, header.auth_length)?;
        let pad = get_array::<4>(&mut body, "pad")?;
        if !body.is_empty() {
            return Err(ProtocolError::InvalidField {
                field: "rpc_auth_3",
                reason: "unexpected trailing bytes in rpc_auth_3 pad field",
            });
        }

        Ok(Self {
            call_id: header.call_id,
            flags: header.flags,
            pad,
            auth_verifier: auth_verifier.ok_or(ProtocolError::InvalidField {
                field: "auth_verifier",
                reason: "rpc_auth_3 requires an authentication verifier",
            })?,
        })
    }
}

/// DCE/RPC request PDU with an optional authentication verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestPdu {
    /// Call identifier.
    pub call_id: u32,
    /// Packet flags.
    pub flags: PacketFlags,
    /// Allocation hint for the server.
    pub alloc_hint: u32,
    /// Presentation context id.
    pub context_id: u16,
    /// Operation number.
    pub opnum: u16,
    /// Optional object UUID.
    pub object_uuid: Option<Uuid>,
    /// Marshaled stub data.
    pub stub_data: Vec<u8>,
    /// Optional authentication verifier appended to the PDU.
    pub auth_verifier: Option<AuthVerifier>,
}

impl RequestPdu {
    /// Encodes the request PDU.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut flags = self.flags;
        if self.object_uuid.is_some() {
            flags |= PacketFlags::OBJECT_UUID;
        }
        let object_len = usize::from(self.object_uuid.is_some()) * 16;
        let mut body =
            Vec::with_capacity(8 + object_len + self.stub_data.len() + SEC_TRAILER_LEN + 16);
        body.put_u32_le(self.alloc_hint);
        body.put_u16_le(self.context_id);
        body.put_u16_le(self.opnum);
        if let Some(object_uuid) = self.object_uuid {
            object_uuid.encode_into(&mut body);
        }
        body.extend_from_slice(&self.stub_data);
        let auth_length = append_auth_verifier(&mut body, self.auth_verifier.as_ref());

        let mut out = Vec::with_capacity(COMMON_HEADER_LEN + body.len());
        CommonHeader {
            packet_type: PacketType::Request,
            flags,
            frag_length: (COMMON_HEADER_LEN + body.len()) as u16,
            auth_length,
            call_id: self.call_id,
        }
        .encode_into(&mut out);
        out.extend_from_slice(&body);
        out
    }

    /// Decodes the request PDU.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let (header, body) = CommonHeader::decode(bytes)?;
        if header.packet_type != PacketType::Request {
            return Err(ProtocolError::InvalidField {
                field: "packet_type",
                reason: "expected request pdu",
            });
        }
        let (mut body, auth_verifier) = split_auth_verifier(body, header.auth_length)?;
        let alloc_hint = get_u32(&mut body, "alloc_hint")?;
        let context_id = get_u16(&mut body, "context_id")?;
        let opnum = get_u16(&mut body, "opnum")?;
        let object_uuid = if header.flags.contains(PacketFlags::OBJECT_UUID) {
            Some(Uuid::decode(&mut body, "object_uuid")?)
        } else {
            None
        };
        Ok(Self {
            call_id: header.call_id,
            flags: header.flags,
            alloc_hint,
            context_id,
            opnum,
            object_uuid,
            stub_data: body.to_vec(),
            auth_verifier,
        })
    }
}

/// DCE/RPC response PDU with an optional authentication verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponsePdu {
    /// Call identifier.
    pub call_id: u32,
    /// Packet flags.
    pub flags: PacketFlags,
    /// Allocation hint.
    pub alloc_hint: u32,
    /// Presentation context id.
    pub context_id: u16,
    /// Cancel count.
    pub cancel_count: u8,
    /// Marshaled stub data.
    pub stub_data: Vec<u8>,
    /// Optional authentication verifier appended to the PDU.
    pub auth_verifier: Option<AuthVerifier>,
}

impl ResponsePdu {
    /// Encodes the response PDU.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(8 + self.stub_data.len() + SEC_TRAILER_LEN + 16);
        body.put_u32_le(self.alloc_hint);
        body.put_u16_le(self.context_id);
        body.put_u8(self.cancel_count);
        body.put_u8(0);
        body.extend_from_slice(&self.stub_data);
        let auth_length = append_auth_verifier(&mut body, self.auth_verifier.as_ref());

        let mut out = Vec::with_capacity(COMMON_HEADER_LEN + body.len());
        CommonHeader {
            packet_type: PacketType::Response,
            flags: self.flags,
            frag_length: (COMMON_HEADER_LEN + body.len()) as u16,
            auth_length,
            call_id: self.call_id,
        }
        .encode_into(&mut out);
        out.extend_from_slice(&body);
        out
    }

    /// Decodes the response PDU.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let (header, body) = CommonHeader::decode(bytes)?;
        if header.packet_type != PacketType::Response {
            return Err(ProtocolError::InvalidField {
                field: "packet_type",
                reason: "expected response pdu",
            });
        }
        let (mut body, auth_verifier) = split_auth_verifier(body, header.auth_length)?;
        let alloc_hint = get_u32(&mut body, "alloc_hint")?;
        let context_id = get_u16(&mut body, "context_id")?;
        let cancel_count = get_u8(&mut body, "cancel_count")?;
        let _reserved = get_u8(&mut body, "reserved")?;
        Ok(Self {
            call_id: header.call_id,
            flags: header.flags,
            alloc_hint,
            context_id,
            cancel_count,
            stub_data: body.to_vec(),
            auth_verifier,
        })
    }
}

/// DCE/RPC fault PDU with an optional authentication verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaultPdu {
    /// Call identifier.
    pub call_id: u32,
    /// Packet flags.
    pub flags: PacketFlags,
    /// Allocation hint.
    pub alloc_hint: u32,
    /// Presentation context id.
    pub context_id: u16,
    /// Fault status code.
    pub status: u32,
    /// Optional stub bytes.
    pub stub_data: Vec<u8>,
    /// Optional authentication verifier appended to the PDU.
    pub auth_verifier: Option<AuthVerifier>,
}

impl FaultPdu {
    /// Encodes the fault PDU.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(12 + self.stub_data.len() + SEC_TRAILER_LEN + 16);
        body.put_u32_le(self.alloc_hint);
        body.put_u16_le(self.context_id);
        body.put_u8(0);
        body.put_u8(0);
        body.put_u32_le(self.status);
        body.extend_from_slice(&self.stub_data);
        let auth_length = append_auth_verifier(&mut body, self.auth_verifier.as_ref());

        let mut out = Vec::with_capacity(COMMON_HEADER_LEN + body.len());
        CommonHeader {
            packet_type: PacketType::Fault,
            flags: self.flags,
            frag_length: (COMMON_HEADER_LEN + body.len()) as u16,
            auth_length,
            call_id: self.call_id,
        }
        .encode_into(&mut out);
        out.extend_from_slice(&body);
        out
    }

    /// Decodes the fault PDU.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let (header, body) = CommonHeader::decode(bytes)?;
        if header.packet_type != PacketType::Fault {
            return Err(ProtocolError::InvalidField {
                field: "packet_type",
                reason: "expected fault pdu",
            });
        }
        let (mut body, auth_verifier) = split_auth_verifier(body, header.auth_length)?;
        let alloc_hint = get_u32(&mut body, "alloc_hint")?;
        let context_id = get_u16(&mut body, "context_id")?;
        let _cancel_count = get_u8(&mut body, "cancel_count")?;
        let _reserved = get_u8(&mut body, "reserved")?;
        let status = get_u32(&mut body, "status")?;
        Ok(Self {
            call_id: header.call_id,
            flags: header.flags,
            alloc_hint,
            context_id,
            status,
            stub_data: body.to_vec(),
            auth_verifier,
        })
    }
}

/// Top-level DCE/RPC packet enum for the supported PDU kinds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    /// Bind request packet.
    Bind(BindPdu),
    /// Bind-ack response packet.
    BindAck(BindAckPdu),
    /// `rpc_auth_3` packet.
    RpcAuth3(RpcAuth3Pdu),
    /// Request packet.
    Request(RequestPdu),
    /// Response packet.
    Response(ResponsePdu),
    /// Fault packet.
    Fault(FaultPdu),
}

impl Packet {
    /// Encodes the packet into bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Bind(packet) => packet.encode(),
            Self::BindAck(packet) => packet.encode(),
            Self::RpcAuth3(packet) => packet.encode(),
            Self::Request(packet) => packet.encode(),
            Self::Response(packet) => packet.encode(),
            Self::Fault(packet) => packet.encode(),
        }
    }

    /// Decodes any supported packet type from bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let (header, _) = CommonHeader::decode(bytes)?;
        match header.packet_type {
            PacketType::Bind => BindPdu::decode(bytes).map(Self::Bind),
            PacketType::BindAck => BindAckPdu::decode(bytes).map(Self::BindAck),
            PacketType::RpcAuth3 => RpcAuth3Pdu::decode(bytes).map(Self::RpcAuth3),
            PacketType::Request => RequestPdu::decode(bytes).map(Self::Request),
            PacketType::Response => ResponsePdu::decode(bytes).map(Self::Response),
            PacketType::Fault => FaultPdu::decode(bytes).map(Self::Fault),
        }
    }
}

fn append_auth_verifier(body: &mut Vec<u8>, auth_verifier: Option<&AuthVerifier>) -> u16 {
    let Some(auth_verifier) = auth_verifier else {
        return 0;
    };

    let auth_pad_length = padding_len_to_alignment(body.len(), 4);
    body.resize(body.len() + auth_pad_length, 0);
    body.put_u8(auth_verifier.auth_type as u8);
    body.put_u8(auth_verifier.auth_level as u8);
    body.put_u8(auth_pad_length as u8);
    body.put_u8(auth_verifier.auth_reserved);
    body.put_u32_le(auth_verifier.auth_context_id);
    body.extend_from_slice(&auth_verifier.auth_value);
    auth_verifier.auth_value.len() as u16
}

fn split_auth_verifier<'a>(
    body: &'a [u8],
    auth_length: u16,
) -> Result<(&'a [u8], Option<AuthVerifier>), ProtocolError> {
    if auth_length == 0 {
        return Ok((body, None));
    }

    let auth_length = usize::from(auth_length);
    if body.len() < auth_length + SEC_TRAILER_LEN {
        return Err(ProtocolError::UnexpectedEof {
            field: "auth_verifier",
        });
    }

    let sec_trailer_offset = body.len() - auth_length - SEC_TRAILER_LEN;
    if sec_trailer_offset % 4 != 0 {
        return Err(ProtocolError::InvalidField {
            field: "auth_verifier",
            reason: "security trailer is not 4-byte aligned",
        });
    }

    let mut sec_trailer = &body[sec_trailer_offset..sec_trailer_offset + SEC_TRAILER_LEN];
    let auth_type = AuthType::try_from(get_u8(&mut sec_trailer, "auth_type")?)?;
    let auth_level = AuthLevel::try_from(get_u8(&mut sec_trailer, "auth_level")?)?;
    let auth_pad_length = usize::from(get_u8(&mut sec_trailer, "auth_pad_length")?);
    let auth_reserved = get_u8(&mut sec_trailer, "auth_reserved")?;
    let auth_context_id = get_u32(&mut sec_trailer, "auth_context_id")?;

    if sec_trailer_offset < auth_pad_length {
        return Err(ProtocolError::InvalidField {
            field: "auth_pad_length",
            reason: "authentication padding exceeds body length",
        });
    }

    let body_len = sec_trailer_offset - auth_pad_length;
    if padding_len_to_alignment(body_len, 4) != auth_pad_length {
        return Err(ProtocolError::InvalidField {
            field: "auth_pad_length",
            reason: "authentication padding does not align the security trailer",
        });
    }

    Ok((
        &body[..body_len],
        Some(AuthVerifier {
            auth_type,
            auth_level,
            auth_reserved,
            auth_context_id,
            auth_value: body[sec_trailer_offset + SEC_TRAILER_LEN..].to_vec(),
        }),
    ))
}

fn get_u8(input: &mut &[u8], field: &'static str) -> Result<u8, ProtocolError> {
    if input.remaining() < 1 {
        return Err(ProtocolError::UnexpectedEof { field });
    }
    Ok(input.get_u8())
}

fn get_u16(input: &mut &[u8], field: &'static str) -> Result<u16, ProtocolError> {
    if input.remaining() < 2 {
        return Err(ProtocolError::UnexpectedEof { field });
    }
    Ok(input.get_u16_le())
}

fn get_u32(input: &mut &[u8], field: &'static str) -> Result<u32, ProtocolError> {
    if input.remaining() < 4 {
        return Err(ProtocolError::UnexpectedEof { field });
    }
    Ok(input.get_u32_le())
}

fn get_array<const N: usize>(
    input: &mut &[u8],
    field: &'static str,
) -> Result<[u8; N], ProtocolError> {
    if input.remaining() < N {
        return Err(ProtocolError::UnexpectedEof { field });
    }
    let mut value = [0; N];
    input.copy_to_slice(&mut value);
    Ok(value)
}

fn get_vec(input: &mut &[u8], len: usize, field: &'static str) -> Result<Vec<u8>, ProtocolError> {
    if input.remaining() < len {
        return Err(ProtocolError::UnexpectedEof { field });
    }
    let mut out = BytesMut::with_capacity(len);
    out.extend_from_slice(&input[..len]);
    input.advance(len);
    Ok(out.to_vec())
}

fn padding_len(length: usize) -> usize {
    padding_len_to_alignment(length, 4)
}

fn padding_len_to_alignment(length: usize, alignment: usize) -> usize {
    (alignment - (length % alignment)) % alignment
}

fn pad_to_4(out: &mut Vec<u8>) {
    let padding = padding_len(out.len());
    out.resize(out.len() + padding, 0);
}

fn skip_padding(input: &mut &[u8], len: usize, field: &'static str) -> Result<(), ProtocolError> {
    if input.remaining() < len {
        return Err(ProtocolError::UnexpectedEof { field });
    }
    input.advance(len);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        AuthLevel, AuthType, AuthVerifier, BindAckPdu, BindAckResult, BindPdu, CommonHeader,
        Packet, PacketFlags, RequestPdu, ResponsePdu, RpcAuth3Pdu, SyntaxId, Uuid,
    };

    const SVCCTL_SYNTAX: SyntaxId = SyntaxId::new(
        Uuid::new(
            0x367a_bb81,
            0x9844,
            0x35f1,
            [0xad, 0x32, 0x98, 0xf0, 0x38, 0x00, 0x10, 0x03],
        ),
        2,
        0,
    );

    #[test]
    fn bind_roundtrips() {
        let packet = BindPdu {
            call_id: 3,
            flags: PacketFlags::FIRST_FRAGMENT | PacketFlags::LAST_FRAGMENT,
            max_xmit_frag: 4280,
            max_recv_frag: 4280,
            assoc_group_id: 9,
            context_id: 0,
            abstract_syntax: SVCCTL_SYNTAX,
            transfer_syntax: SyntaxId::NDR32,
            auth_verifier: None,
        };
        let encoded = packet.encode();
        let decoded = BindPdu::decode(&encoded).expect("bind should decode");
        assert_eq!(decoded, packet);
    }

    #[test]
    fn bind_roundtrips_with_auth_verifier() {
        let packet = BindPdu {
            call_id: 3,
            flags: PacketFlags::FIRST_FRAGMENT
                | PacketFlags::LAST_FRAGMENT
                | PacketFlags::SUPPORT_HEADER_SIGN,
            max_xmit_frag: 4280,
            max_recv_frag: 4280,
            assoc_group_id: 9,
            context_id: 0,
            abstract_syntax: SVCCTL_SYNTAX,
            transfer_syntax: SyntaxId::NDR32,
            auth_verifier: Some(AuthVerifier::new(
                AuthType::WinNt,
                AuthLevel::PacketIntegrity,
                0x1234,
                vec![0xaa; 16],
            )),
        };
        let encoded = packet.encode();
        let decoded = BindPdu::decode(&encoded).expect("bind with auth should decode");
        assert_eq!(decoded, packet);
    }

    #[test]
    fn bind_ack_roundtrips() {
        let packet = BindAckPdu {
            call_id: 3,
            flags: PacketFlags::FIRST_FRAGMENT
                | PacketFlags::LAST_FRAGMENT
                | PacketFlags::SUPPORT_HEADER_SIGN,
            max_xmit_frag: 4280,
            max_recv_frag: 4280,
            assoc_group_id: 12,
            secondary_address: b"\\PIPE\\svcctl\0".to_vec(),
            result: BindAckResult {
                result: 0,
                reason: 0,
                transfer_syntax: SyntaxId::NDR32,
            },
            auth_verifier: None,
        };
        let encoded = packet.encode();
        let decoded = BindAckPdu::decode(&encoded).expect("bind ack should decode");
        assert_eq!(decoded, packet);
    }

    #[test]
    fn rpc_auth_3_roundtrips_auth_verifier() {
        let packet = RpcAuth3Pdu {
            call_id: 12,
            flags: PacketFlags::FIRST_FRAGMENT
                | PacketFlags::LAST_FRAGMENT
                | PacketFlags::SUPPORT_HEADER_SIGN,
            pad: [0xaa, 0xbb, 0xcc, 0xdd],
            auth_verifier: AuthVerifier::new(
                AuthType::WinNt,
                AuthLevel::Connect,
                1,
                vec![0x44; 24],
            ),
        };
        let encoded = packet.encode();
        let decoded = RpcAuth3Pdu::decode(&encoded).expect("rpc_auth_3 should decode");
        assert_eq!(decoded, packet);
    }

    #[test]
    fn request_roundtrips_with_object_uuid() {
        let packet = RequestPdu {
            call_id: 7,
            flags: PacketFlags::FIRST_FRAGMENT
                | PacketFlags::LAST_FRAGMENT
                | PacketFlags::OBJECT_UUID,
            alloc_hint: 12,
            context_id: 0,
            opnum: 15,
            object_uuid: Some(Uuid::new(1, 2, 3, [4, 5, 6, 7, 8, 9, 10, 11])),
            stub_data: vec![0xaa, 0xbb, 0xcc, 0xdd],
            auth_verifier: None,
        };
        let encoded = packet.encode();
        let decoded = RequestPdu::decode(&encoded).expect("request should decode");
        assert_eq!(decoded, packet);
    }

    #[test]
    fn request_roundtrips_with_auth_verifier() {
        let packet = RequestPdu {
            call_id: 7,
            flags: PacketFlags::FIRST_FRAGMENT | PacketFlags::LAST_FRAGMENT,
            alloc_hint: 12,
            context_id: 0,
            opnum: 15,
            object_uuid: None,
            stub_data: vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee],
            auth_verifier: Some(AuthVerifier::new(
                AuthType::WinNt,
                AuthLevel::PacketIntegrity,
                0,
                vec![0x11; 16],
            )),
        };
        let encoded = packet.encode();
        let decoded = RequestPdu::decode(&encoded).expect("request with auth should decode");
        assert_eq!(decoded, packet);
    }

    #[test]
    fn request_auth_verifier_uses_four_byte_alignment() {
        let packet = RequestPdu {
            call_id: 7,
            flags: PacketFlags::FIRST_FRAGMENT | PacketFlags::LAST_FRAGMENT,
            alloc_hint: 3,
            context_id: 0,
            opnum: 15,
            object_uuid: None,
            stub_data: vec![0xaa, 0xbb, 0xcc],
            auth_verifier: Some(AuthVerifier::new(
                AuthType::WinNt,
                AuthLevel::PacketIntegrity,
                0,
                vec![0x11; 16],
            )),
        };
        let encoded = packet.encode();
        let header = CommonHeader::decode(&encoded)
            .expect("request should decode")
            .0;

        assert_eq!(header.auth_length, 16);
        assert_eq!(encoded[30], 1);
    }

    #[test]
    fn response_roundtrips() {
        let packet = ResponsePdu {
            call_id: 7,
            flags: PacketFlags::FIRST_FRAGMENT | PacketFlags::LAST_FRAGMENT,
            alloc_hint: 4,
            context_id: 0,
            cancel_count: 0,
            stub_data: vec![1, 2, 3, 4],
            auth_verifier: None,
        };
        let encoded = packet.encode();
        let decoded = ResponsePdu::decode(&encoded).expect("response should decode");
        assert_eq!(decoded, packet);
    }

    #[test]
    fn packet_dispatch_decodes_bind_ack() {
        let packet = Packet::BindAck(BindAckPdu {
            call_id: 4,
            flags: PacketFlags::FIRST_FRAGMENT | PacketFlags::LAST_FRAGMENT,
            max_xmit_frag: 4280,
            max_recv_frag: 4280,
            assoc_group_id: 19,
            secondary_address: b"svcctl\0".to_vec(),
            result: BindAckResult {
                result: 0,
                reason: 0,
                transfer_syntax: SyntaxId::NDR32,
            },
            auth_verifier: None,
        });
        let encoded = packet.encode();
        let decoded = Packet::decode(&encoded).expect("packet should decode");
        assert_eq!(decoded, packet);
    }
}
