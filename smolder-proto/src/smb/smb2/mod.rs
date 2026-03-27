//! SMB2/3 wire types.

mod cancel;
mod create;
mod echo;
mod header;
mod info;
mod io;
mod ioctl;
mod lock;
mod negotiate;
mod notify;
mod session;
mod tree;

use bytes::Buf;

pub use cancel::CancelRequest;
pub use create::{
    CloseRequest, CloseResponse, CreateContext, CreateDisposition, CreateOptions, CreateRequest,
    CreateResponse, DurableHandleFlags, DurableHandleReconnect, DurableHandleReconnectV2,
    DurableHandleRequest, DurableHandleRequestV2, DurableHandleResponse, DurableHandleResponseV2,
    FileAttributes, FileId, LeaseFlags, LeaseState, LeaseV2, OplockLevel, RequestedOplockLevel,
    ShareAccess,
};
pub use echo::{EchoRequest, EchoResponse};
pub use header::{Command, Header, HeaderFlags};
pub use info::{
    DirectoryInformationEntry, DispositionInformation, FileBasicInformation, FileInfoClass,
    FileStandardInformation, InfoType, QueryDirectoryFileInformationClass, QueryDirectoryFlags,
    QueryDirectoryRequest, QueryDirectoryResponse, QueryInfoRequest, QueryInfoResponse,
    RenameInformation, SetInfoRequest, SetInfoResponse,
};
pub use io::{
    FlushRequest, FlushResponse, ReadFlags, ReadRequest, ReadResponse, ReadResponseFlags,
    WriteFlags, WriteRequest, WriteResponse,
};
pub use ioctl::{
    CtlCode, DfsReferralEntry, DfsReferralEntryFlags, DfsReferralHeaderFlags, DfsReferralRequest,
    DfsReferralResponse, IoctlFlags, IoctlRequest, IoctlResponse, NetworkAddress,
    NetworkInterfaceCapabilities, NetworkInterfaceInfo, NetworkInterfaceInfoResponse,
    NetworkResiliencyRequest, ResumeKeyResponse,
};
pub use lock::{LockElement, LockFlags, LockRequest, LockResponse};
pub use negotiate::{
    CipherId, Dialect, EncryptionCapabilities, GlobalCapabilities, NegotiateContext,
    NegotiateContextType, NegotiateRequest, NegotiateResponse, PreauthIntegrityCapabilities,
    PreauthIntegrityHashId, SigningMode,
};
pub use notify::{ChangeNotifyFlags, ChangeNotifyRequest, ChangeNotifyResponse, CompletionFilter};
pub use session::{
    LogoffRequest, LogoffResponse, SessionFlags, SessionSetupRequest, SessionSetupResponse,
    SessionSetupSecurityMode,
};
pub use tree::{
    ShareFlags, ShareType, TreeCapabilities, TreeConnectRequest, TreeConnectResponse,
    TreeDisconnectRequest, TreeDisconnectResponse,
};

use super::ProtocolError;

/// The SMB2 packet header size in bytes.
pub const HEADER_LEN: usize = 64;

/// Protocol identifier for SMB2+ packets.
pub const PROTOCOL_ID: [u8; 4] = [0xfe, b'S', b'M', b'B'];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// A message identifier assigned by the client.
pub struct MessageId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// An asynchronous command identifier assigned by the server.
pub struct AsyncId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// A negotiated session identifier.
pub struct SessionId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// A tree identifier scoped to a session.
pub struct TreeId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// The credit charge for a request.
pub struct CreditCharge(pub u16);

fn check_fixed_structure_size(
    structure_size: u16,
    expected: u16,
    field: &'static str,
) -> Result<(), ProtocolError> {
    if structure_size != expected {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "unexpected structure size",
        });
    }
    Ok(())
}

fn slice_from_offset<'a>(
    body: &'a [u8],
    offset_from_header: u16,
    len: usize,
    field: &'static str,
) -> Result<&'a [u8], ProtocolError> {
    let offset = usize::from(offset_from_header);
    if offset < HEADER_LEN {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "offset points before SMB2 body",
        });
    }

    let start = offset - HEADER_LEN;
    let end = start.checked_add(len).ok_or(ProtocolError::InvalidField {
        field,
        reason: "offset overflow",
    })?;

    if end > body.len() {
        return Err(ProtocolError::UnexpectedEof { field });
    }

    Ok(&body[start..end])
}

fn slice_from_offset32<'a>(
    body: &'a [u8],
    offset_from_header: u32,
    len: usize,
    field: &'static str,
) -> Result<&'a [u8], ProtocolError> {
    let offset = usize::try_from(offset_from_header).map_err(|_| ProtocolError::InvalidField {
        field,
        reason: "offset overflow",
    })?;
    if offset < HEADER_LEN {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "offset points before SMB2 body",
        });
    }

    let start = offset - HEADER_LEN;
    let end = start.checked_add(len).ok_or(ProtocolError::InvalidField {
        field,
        reason: "offset overflow",
    })?;

    if end > body.len() {
        return Err(ProtocolError::UnexpectedEof { field });
    }

    Ok(&body[start..end])
}

fn put_padding(buffer: &mut Vec<u8>, alignment: usize) {
    let remainder = buffer.len() % alignment;
    if remainder != 0 {
        buffer.resize(buffer.len() + (alignment - remainder), 0);
    }
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

fn get_u64(input: &mut &[u8], field: &'static str) -> Result<u64, ProtocolError> {
    if input.remaining() < 8 {
        return Err(ProtocolError::UnexpectedEof { field });
    }
    Ok(input.get_u64_le())
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

/// Encodes a Rust string as UTF-16LE without a terminating NUL.
#[must_use]
pub fn utf16le(input: &str) -> Vec<u8> {
    input
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>()
}

/// Decodes a UTF-16LE byte buffer without a terminating NUL.
pub fn utf16le_string(input: &[u8]) -> Result<String, ProtocolError> {
    if input.len() % 2 != 0 {
        return Err(ProtocolError::InvalidField {
            field: "utf16le_string",
            reason: "UTF-16LE byte length must be even",
        });
    }

    let utf16 = input
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    String::from_utf16(&utf16).map_err(|_| ProtocolError::InvalidField {
        field: "utf16le_string",
        reason: "invalid UTF-16LE sequence",
    })
}
