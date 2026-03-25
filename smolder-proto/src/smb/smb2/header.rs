//! SMB2 header definitions.

use std::convert::TryFrom;

use bitflags::bitflags;
use bytes::{BufMut, BytesMut};

use super::{
    get_array, get_u16, get_u32, get_u64, AsyncId, CreditCharge, MessageId, SessionId, TreeId,
    PROTOCOL_ID,
};
use crate::smb::ProtocolError;

bitflags! {
    /// SMB2 header flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct HeaderFlags: u32 {
        /// Response packets set this bit.
        const SERVER_TO_REDIR = 0x0000_0001;
        /// Async command packet.
        const ASYNC_COMMAND = 0x0000_0002;
        /// Related operations within a compound chain.
        const RELATED_OPERATIONS = 0x0000_0004;
        /// Message signature is present.
        const SIGNED = 0x0000_0008;
        /// Replay operation.
        const REPLAY_OPERATION = 0x1000_0000;
    }
}

/// SMB2 command codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum Command {
    /// `NEGOTIATE`
    Negotiate = 0x0000,
    /// `SESSION_SETUP`
    SessionSetup = 0x0001,
    /// `LOGOFF`
    Logoff = 0x0002,
    /// `TREE_CONNECT`
    TreeConnect = 0x0003,
    /// `TREE_DISCONNECT`
    TreeDisconnect = 0x0004,
    /// `CREATE`
    Create = 0x0005,
    /// `CLOSE`
    Close = 0x0006,
    /// `FLUSH`
    Flush = 0x0007,
    /// `READ`
    Read = 0x0008,
    /// `WRITE`
    Write = 0x0009,
    /// `QUERY_DIRECTORY`
    QueryDirectory = 0x000e,
    /// `QUERY_INFO`
    QueryInfo = 0x0010,
    /// `SET_INFO`
    SetInfo = 0x0011,
}

impl TryFrom<u16> for Command {
    type Error = ProtocolError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0000 => Ok(Self::Negotiate),
            0x0001 => Ok(Self::SessionSetup),
            0x0002 => Ok(Self::Logoff),
            0x0003 => Ok(Self::TreeConnect),
            0x0004 => Ok(Self::TreeDisconnect),
            0x0005 => Ok(Self::Create),
            0x0006 => Ok(Self::Close),
            0x0007 => Ok(Self::Flush),
            0x0008 => Ok(Self::Read),
            0x0009 => Ok(Self::Write),
            0x000e => Ok(Self::QueryDirectory),
            0x0010 => Ok(Self::QueryInfo),
            0x0011 => Ok(Self::SetInfo),
            _ => Err(ProtocolError::InvalidField {
                field: "command",
                reason: "unknown SMB2 command",
            }),
        }
    }
}

/// An SMB2 header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// The credit charge for the packet.
    pub credit_charge: CreditCharge,
    /// Status code in responses, zero in requests.
    pub status: u32,
    /// The command code.
    pub command: Command,
    /// Requested or granted credits.
    pub credit_request_response: u16,
    /// Header flags.
    pub flags: HeaderFlags,
    /// Compound request offset.
    pub next_command: u32,
    /// Message identifier.
    pub message_id: MessageId,
    /// Asynchronous identifier present on async headers.
    pub async_id: Option<AsyncId>,
    /// Tree identifier.
    pub tree_id: TreeId,
    /// Session identifier.
    pub session_id: SessionId,
    /// Packet signature.
    pub signature: [u8; 16],
}

impl Header {
    /// The fixed SMB2 header length.
    pub const LEN: usize = 64;
    /// Byte range containing the SMB2 signature field within an encoded header.
    pub const SIGNATURE_RANGE: std::ops::Range<usize> = 48..64;

    /// Builds a new request header with zero status and signature.
    #[must_use]
    pub fn new(command: Command, message_id: MessageId) -> Self {
        Self {
            credit_charge: CreditCharge(1),
            status: 0,
            command,
            credit_request_response: 1,
            flags: HeaderFlags::empty(),
            next_command: 0,
            message_id,
            async_id: None,
            tree_id: TreeId(0),
            session_id: SessionId(0),
            signature: [0; 16],
        }
    }

    /// Serializes the header.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(Self::LEN);
        out.extend_from_slice(&PROTOCOL_ID);
        out.put_u16_le(64);
        out.put_u16_le(self.credit_charge.0);
        out.put_u32_le(self.status);
        out.put_u16_le(self.command as u16);
        out.put_u16_le(self.credit_request_response);
        out.put_u32_le(self.flags.bits());
        out.put_u32_le(self.next_command);
        out.put_u64_le(self.message_id.0);
        if self.flags.contains(HeaderFlags::ASYNC_COMMAND) {
            out.put_u64_le(self.async_id.unwrap_or(AsyncId(0)).0);
        } else {
            out.put_u32_le(0);
            out.put_u32_le(self.tree_id.0);
        }
        out.put_u64_le(self.session_id.0);
        out.extend_from_slice(&self.signature);
        out.to_vec()
    }

    /// Parses an SMB2 header.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() < Self::LEN {
            return Err(ProtocolError::UnexpectedEof { field: "header" });
        }

        let mut input = bytes;
        let protocol_id = get_array::<4>(&mut input, "protocol_id")?;
        if protocol_id != PROTOCOL_ID {
            return Err(ProtocolError::InvalidField {
                field: "protocol_id",
                reason: "not an SMB2 packet",
            });
        }

        let structure_size = get_u16(&mut input, "structure_size")?;
        if structure_size != 64 {
            return Err(ProtocolError::InvalidField {
                field: "structure_size",
                reason: "header must be 64 bytes",
            });
        }

        let credit_charge = CreditCharge(get_u16(&mut input, "credit_charge")?);
        let status = get_u32(&mut input, "status")?;
        let command = Command::try_from(get_u16(&mut input, "command")?)?;
        let credit_request_response = get_u16(&mut input, "credit_request_response")?;
        let flags = HeaderFlags::from_bits(get_u32(&mut input, "flags")?).ok_or(
            ProtocolError::InvalidField {
                field: "flags",
                reason: "unknown header flags set",
            },
        )?;
        let next_command = get_u32(&mut input, "next_command")?;
        let message_id = MessageId(get_u64(&mut input, "message_id")?);
        let (async_id, tree_id) = if flags.contains(HeaderFlags::ASYNC_COMMAND) {
            (Some(AsyncId(get_u64(&mut input, "async_id")?)), TreeId(0))
        } else {
            let _reserved = get_u32(&mut input, "reserved")?;
            (None, TreeId(get_u32(&mut input, "tree_id")?))
        };
        let session_id = SessionId(get_u64(&mut input, "session_id")?);
        let signature = get_array::<16>(&mut input, "signature")?;

        Ok(Self {
            credit_charge,
            status,
            command,
            credit_request_response,
            flags,
            next_command,
            message_id,
            async_id,
            tree_id,
            session_id,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Command, Header, HeaderFlags};
    use crate::smb::smb2::{AsyncId, MessageId, SessionId, TreeId};

    #[test]
    fn header_roundtrips() {
        let mut header = Header::new(Command::TreeConnect, MessageId(42));
        header.flags = HeaderFlags::SIGNED;
        header.tree_id = TreeId(7);
        header.session_id = SessionId(99);
        header.status = 0xdead_beef;

        let encoded = header.encode();
        let decoded = Header::decode(&encoded).expect("header should decode");

        assert_eq!(decoded, header);
    }

    #[test]
    fn async_header_roundtrips() {
        let mut header = Header::new(Command::Write, MessageId(7));
        header.status = 0x0000_0103;
        header.flags = HeaderFlags::SERVER_TO_REDIR | HeaderFlags::ASYNC_COMMAND;
        header.async_id = Some(AsyncId(99));
        header.session_id = SessionId(55);

        let encoded = header.encode();
        let decoded = Header::decode(&encoded).expect("header should decode");

        assert_eq!(decoded, header);
        assert_eq!(decoded.tree_id, TreeId(0));
    }
}
