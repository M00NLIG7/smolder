//! Typed `samr` DCE/RPC helpers built on top of named pipes.

use smolder_proto::rpc::{SyntaxId, Uuid};

use crate::error::CoreError;
use crate::rpc::PipeRpcClient;
use crate::transport::TokioTcpTransport;

const SAMR_SYNTAX: SyntaxId = SyntaxId::new(
    Uuid::new(
        0x1234_5778,
        0x1234,
        0xabcd,
        [0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xac],
    ),
    1,
    0,
);
const SAMR_CONTEXT_ID: u16 = 0;
const SAMR_CONNECT5_OPNUM: u16 = 64;
const SAMR_CLOSE_HANDLE_OPNUM: u16 = 1;
const SAMR_ENUMERATE_DOMAINS_OPNUM: u16 = 6;
const SAM_SERVER_CONNECT: u32 = 0x0000_0001;
const SAM_SERVER_ENUMERATE_DOMAINS: u32 = 0x0000_0010;
const SAM_SERVER_LOOKUP_DOMAIN: u32 = 0x0000_0020;

/// Default SAM server access mask used by the typed client.
pub const DEFAULT_SERVER_ACCESS: u32 =
    SAM_SERVER_CONNECT | SAM_SERVER_ENUMERATE_DOMAINS | SAM_SERVER_LOOKUP_DOMAIN;

/// Revision/capability info returned by `SamrConnect5`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SamrServerRevision {
    /// Revision value returned by the server.
    pub revision: u32,
    /// Server capability flags.
    pub supported_features: u32,
}

/// Domain entry returned by `SamrEnumerateDomainsInSamServer`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamrDomain {
    /// Relative identifier. For server domain enumeration this is expected to be `0`.
    pub relative_id: u32,
    /// Domain name.
    pub name: String,
}

/// Typed `samr` client over an already-open RPC transport and server handle.
#[derive(Debug)]
pub struct SamrClient<T = TokioTcpTransport> {
    rpc: PipeRpcClient<T>,
    context_id: u16,
    server_handle: [u8; 20],
    revision: SamrServerRevision,
}

impl<T> SamrClient<T> {
    /// The `samr` abstract syntax identifier.
    pub const SYNTAX: SyntaxId = SAMR_SYNTAX;

    /// The default `samr` presentation context identifier.
    pub const CONTEXT_ID: u16 = SAMR_CONTEXT_ID;

    /// Returns the underlying RPC transport.
    #[must_use]
    pub fn rpc(&self) -> &PipeRpcClient<T> {
        &self.rpc
    }

    /// Returns the connected server revision/capabilities.
    #[must_use]
    pub fn revision(&self) -> SamrServerRevision {
        self.revision
    }

    /// Consumes the typed client and returns the underlying RPC transport without closing the server handle.
    #[must_use]
    pub fn into_rpc(self) -> PipeRpcClient<T> {
        self.rpc
    }
}

impl<T> SamrClient<T>
where
    T: crate::transport::Transport + Send,
{
    /// Performs the default `samr` bind and `SamrConnect5`.
    pub async fn bind(mut rpc: PipeRpcClient<T>) -> Result<Self, CoreError> {
        rpc.bind_context(Self::CONTEXT_ID, Self::SYNTAX).await?;
        let response = rpc
            .call(
                Self::CONTEXT_ID,
                SAMR_CONNECT5_OPNUM,
                encode_connect5_request(DEFAULT_SERVER_ACCESS),
            )
            .await?;
        let (server_handle, revision) = parse_connect5_response(&response)?;
        Ok(Self {
            rpc,
            context_id: Self::CONTEXT_ID,
            server_handle,
            revision,
        })
    }

    /// Calls `SamrEnumerateDomainsInSamServer` with a fresh enumeration context.
    pub async fn enumerate_domains(&mut self) -> Result<Vec<SamrDomain>, CoreError> {
        let response = self
            .rpc
            .call(
                self.context_id,
                SAMR_ENUMERATE_DOMAINS_OPNUM,
                encode_enumerate_domains_request(self.server_handle, 0, u32::MAX),
            )
            .await?;
        parse_enumerate_domains_response(&response)
    }

    /// Closes the server handle and returns the underlying RPC transport.
    pub async fn close(mut self) -> Result<PipeRpcClient<T>, CoreError> {
        let response = self
            .rpc
            .call(
                self.context_id,
                SAMR_CLOSE_HANDLE_OPNUM,
                encode_close_handle_request(self.server_handle),
            )
            .await?;
        parse_close_handle_response(&response)?;
        Ok(self.rpc)
    }
}

fn encode_connect5_request(desired_access: u32) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(20);
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&desired_access.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&3_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes
}

fn parse_connect5_response(response: &[u8]) -> Result<([u8; 20], SamrServerRevision), CoreError> {
    if response.len() < 32 {
        return Err(CoreError::InvalidResponse(
            "SamrConnect5 response was too short",
        ));
    }
    let out_version = u32::from_le_bytes(response[0..4].try_into().expect("version slice"));
    if out_version != 1 {
        return Err(CoreError::InvalidResponse(
            "SamrConnect5 returned an unexpected revision union arm",
        ));
    }
    let revision = u32::from_le_bytes(response[4..8].try_into().expect("revision slice"));
    let supported_features =
        u32::from_le_bytes(response[8..12].try_into().expect("features slice"));
    let mut server_handle = [0_u8; 20];
    server_handle.copy_from_slice(&response[12..32]);

    let status = if response.len() >= 36 {
        u32::from_le_bytes(response[32..36].try_into().expect("status slice"))
    } else {
        0
    };
    if status != 0 {
        return Err(CoreError::RemoteOperation {
            operation: "SamrConnect5",
            code: status,
        });
    }

    Ok((
        server_handle,
        SamrServerRevision {
            revision,
            supported_features,
        },
    ))
}

fn encode_enumerate_domains_request(
    server_handle: [u8; 20],
    enumeration_context: u32,
    preferred_maximum_length: u32,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(28);
    bytes.extend_from_slice(&server_handle);
    bytes.extend_from_slice(&enumeration_context.to_le_bytes());
    bytes.extend_from_slice(&preferred_maximum_length.to_le_bytes());
    bytes
}

fn parse_enumerate_domains_response(response: &[u8]) -> Result<Vec<SamrDomain>, CoreError> {
    let mut reader = NdrReader::new(response);
    let _enumeration_context = reader.read_u32("EnumerationContext")?;
    let buffer_referent = reader.read_u32("BufferReferent")?;
    let mut domains = Vec::new();
    let count_returned;

    if buffer_referent != 0 {
        let entries_read = reader.read_u32("EntriesRead")? as usize;
        let array_referent = reader.read_u32("RidEnumerationArray")?;
        if entries_read > 0 && array_referent == 0 {
            return Err(CoreError::InvalidResponse(
                "SamrEnumerateDomainsInSamServer returned entries without an array",
            ));
        }
        if array_referent != 0 {
            let max_count = reader.read_u32("RidEnumerationMaxCount")? as usize;
            if max_count < entries_read {
                return Err(CoreError::InvalidResponse(
                    "SamrEnumerateDomainsInSamServer returned fewer array slots than entries",
                ));
            }
            let mut raw_entries = Vec::with_capacity(entries_read);
            for _ in 0..entries_read {
                raw_entries.push(RidEnumeration {
                    relative_id: reader.read_u32("RelativeId")?,
                    name: reader.read_rpc_unicode_string("Name")?,
                });
            }
            domains = raw_entries
                .into_iter()
                .map(|entry| SamrDomain {
                    relative_id: entry.relative_id,
                    name: entry.name,
                })
                .collect();
        }
    }

    count_returned = reader.read_u32("CountReturned")? as usize;
    if count_returned != domains.len() {
        return Err(CoreError::InvalidResponse(
            "SamrEnumerateDomainsInSamServer count did not match returned entries",
        ));
    }

    let status = reader.read_u32("SamrEnumerateDomainsInSamServerStatus")?;
    if status != 0 && status != 0x0000_0105 {
        return Err(CoreError::RemoteOperation {
            operation: "SamrEnumerateDomainsInSamServer",
            code: status,
        });
    }

    Ok(domains)
}

fn encode_close_handle_request(handle: [u8; 20]) -> Vec<u8> {
    handle.to_vec()
}

fn parse_close_handle_response(response: &[u8]) -> Result<(), CoreError> {
    if response.len() < 24 {
        return Err(CoreError::InvalidResponse(
            "SamrCloseHandle response was too short",
        ));
    }
    let status = u32::from_le_bytes(response[20..24].try_into().expect("status slice"));
    if status != 0 {
        return Err(CoreError::RemoteOperation {
            operation: "SamrCloseHandle",
            code: status,
        });
    }
    Ok(())
}

#[derive(Debug)]
struct RidEnumeration {
    relative_id: u32,
    name: String,
}

struct NdrReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> NdrReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn align(&mut self, alignment: usize, field: &'static str) -> Result<(), CoreError> {
        let padding = (alignment - (self.offset % alignment)) % alignment;
        if self.remaining() < padding {
            return Err(CoreError::InvalidResponse(field));
        }
        self.offset += padding;
        Ok(())
    }

    fn read_u32(&mut self, field: &'static str) -> Result<u32, CoreError> {
        self.align(4, field)?;
        if self.remaining() < 4 {
            return Err(CoreError::InvalidResponse(field));
        }
        let value = u32::from_le_bytes(
            self.bytes[self.offset..self.offset + 4]
                .try_into()
                .expect("u32 slice should decode"),
        );
        self.offset += 4;
        Ok(value)
    }

    fn read_u16(&mut self, field: &'static str) -> Result<u16, CoreError> {
        if self.remaining() < 2 {
            return Err(CoreError::InvalidResponse(field));
        }
        let value = u16::from_le_bytes(
            self.bytes[self.offset..self.offset + 2]
                .try_into()
                .expect("u16 slice should decode"),
        );
        self.offset += 2;
        Ok(value)
    }

    fn read_rpc_unicode_string(&mut self, field: &'static str) -> Result<String, CoreError> {
        let length = self.read_u16(field)? as usize;
        let maximum_length = self.read_u16(field)? as usize;
        let buffer_referent = self.read_u32(field)?;
        if buffer_referent == 0 {
            return Ok(String::new());
        }
        self.align(4, field)?;
        let max_count = self.read_u32(field)? as usize;
        if max_count * 2 < length || maximum_length < length {
            return Err(CoreError::InvalidResponse(field));
        }
        let mut code_units = Vec::with_capacity(max_count);
        for _ in 0..max_count {
            code_units.push(self.read_u16(field)?);
        }
        self.align(4, field)?;
        let actual_units = length / 2;
        String::from_utf16(&code_units[..actual_units])
            .map_err(|_| CoreError::InvalidResponse("failed to decode samr UTF-16 string"))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        encode_close_handle_request, encode_connect5_request, encode_enumerate_domains_request,
        parse_close_handle_response, parse_connect5_response, parse_enumerate_domains_response,
        SamrDomain, SamrServerRevision, DEFAULT_SERVER_ACCESS,
    };
    use crate::error::CoreError;

    struct ResponseWriter {
        bytes: Vec<u8>,
        referent: u32,
    }

    impl ResponseWriter {
        fn new() -> Self {
            Self {
                bytes: Vec::new(),
                referent: 1,
            }
        }

        fn into_bytes(self) -> Vec<u8> {
            self.bytes
        }

        fn write_u32(&mut self, value: u32) {
            self.align(4);
            self.bytes.extend_from_slice(&value.to_le_bytes());
        }

        fn write_u16(&mut self, value: u16) {
            self.bytes.extend_from_slice(&value.to_le_bytes());
        }

        fn write_rpc_unicode_string(&mut self, value: &str) {
            let encoded = value.encode_utf16().collect::<Vec<_>>();
            let byte_len = (encoded.len() * 2) as u16;
            self.write_u16(byte_len);
            self.write_u16(byte_len);
            let referent = self.next_referent();
            self.write_u32(referent);
            self.align(4);
            self.write_u32(encoded.len() as u32);
            for code_unit in encoded {
                self.write_u16(code_unit);
            }
            self.align(4);
        }

        fn next_referent(&mut self) -> u32 {
            let current = self.referent;
            self.referent += 1;
            current
        }

        fn align(&mut self, alignment: usize) {
            let padding = (alignment - (self.bytes.len() % alignment)) % alignment;
            self.bytes.resize(self.bytes.len() + padding, 0);
        }
    }

    #[test]
    fn connect5_request_encodes_expected_revision_block() {
        assert_eq!(
            encode_connect5_request(DEFAULT_SERVER_ACCESS),
            [
                0_u32.to_le_bytes(),
                DEFAULT_SERVER_ACCESS.to_le_bytes(),
                1_u32.to_le_bytes(),
                3_u32.to_le_bytes(),
                0_u32.to_le_bytes(),
            ]
            .concat()
        );
    }

    #[test]
    fn connect5_response_decodes_revision_and_handle() {
        let mut response = vec![0_u8; 36];
        response[0..4].copy_from_slice(&1_u32.to_le_bytes());
        response[4..8].copy_from_slice(&3_u32.to_le_bytes());
        response[8..12].copy_from_slice(&0x10_u32.to_le_bytes());
        response[12..32].copy_from_slice(&[0x41; 20]);
        response[32..36].copy_from_slice(&0_u32.to_le_bytes());

        let (handle, revision) =
            parse_connect5_response(&response).expect("response should decode");
        assert_eq!(handle, [0x41; 20]);
        assert_eq!(
            revision,
            SamrServerRevision {
                revision: 3,
                supported_features: 0x10,
            }
        );
    }

    #[test]
    fn enumerate_domains_request_encodes_handle_and_context() {
        assert_eq!(
            encode_enumerate_domains_request([0x42; 20], 7, u32::MAX),
            [[0x42; 20].to_vec(), 7_u32.to_le_bytes().to_vec(), u32::MAX.to_le_bytes().to_vec()]
                .concat()
        );
    }

    #[test]
    fn enumerate_domains_response_decodes_builtin_and_account_domains() {
        let mut writer = ResponseWriter::new();
        writer.write_u32(0);
        let buffer_ref = writer.next_referent();
        writer.write_u32(buffer_ref);
        writer.write_u32(2);
        let array_ref = writer.next_referent();
        writer.write_u32(array_ref);
        writer.write_u32(2);
        writer.write_u32(0);
        writer.write_rpc_unicode_string("Builtin");
        writer.write_u32(0);
        writer.write_rpc_unicode_string("DESKTOP");
        writer.write_u32(2);
        writer.write_u32(0);

        assert_eq!(
            parse_enumerate_domains_response(&writer.into_bytes())
                .expect("response should decode"),
            vec![
                SamrDomain {
                    relative_id: 0,
                    name: "Builtin".to_owned(),
                },
                SamrDomain {
                    relative_id: 0,
                    name: "DESKTOP".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn close_handle_request_uses_handle_bytes_directly() {
        assert_eq!(encode_close_handle_request([0x33; 20]), [0x33; 20].to_vec());
    }

    #[test]
    fn close_handle_response_checks_status() {
        let mut response = vec![0_u8; 24];
        response[20..24].copy_from_slice(&5_u32.to_le_bytes());
        let error = parse_close_handle_response(&response).expect_err("non-zero status should fail");
        assert!(matches!(error, CoreError::RemoteOperation { .. }));
    }
}
