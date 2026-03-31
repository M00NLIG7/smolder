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
const SAMR_CONNECT2_OPNUM: u16 = 57;
const SAMR_CONNECT5_OPNUM: u16 = 64;
const SAMR_CLOSE_HANDLE_OPNUM: u16 = 1;
const SAMR_LOOKUP_DOMAIN_OPNUM: u16 = 5;
const SAMR_ENUMERATE_DOMAINS_OPNUM: u16 = 6;
const SAMR_OPEN_DOMAIN_OPNUM: u16 = 7;
const SAMR_ENUMERATE_USERS_OPNUM: u16 = 13;
const SAMR_OPEN_USER_OPNUM: u16 = 34;
const SAMR_QUERY_INFORMATION_USER_OPNUM: u16 = 36;
const SAM_SERVER_CONNECT: u32 = 0x0000_0001;
const SAM_SERVER_ENUMERATE_DOMAINS: u32 = 0x0000_0010;
const SAM_SERVER_LOOKUP_DOMAIN: u32 = 0x0000_0020;
const MAXIMUM_ALLOWED_ACCESS: u32 = 0x0200_0000;
const USER_READ_GENERAL: u32 = 0x0000_0001;
const USER_ACCOUNT_NAME_INFORMATION_CLASS: u32 = 7;

/// Default SAM server access mask used by the typed client.
pub const DEFAULT_SERVER_ACCESS: u32 =
    SAM_SERVER_CONNECT | SAM_SERVER_ENUMERATE_DOMAINS | SAM_SERVER_LOOKUP_DOMAIN;
/// Default domain access mask used by the typed client.
pub const DEFAULT_DOMAIN_ACCESS: u32 = MAXIMUM_ALLOWED_ACCESS;

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

/// Minimal SAM domain SID representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamrSid {
    /// SID revision.
    pub revision: u8,
    /// SID identifier authority bytes.
    pub identifier_authority: [u8; 6],
    /// SID subauthorities.
    pub sub_authorities: Vec<u32>,
}

/// Domain-scoped user enumeration entry returned by `SamrEnumerateUsersInDomain`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamrUser {
    /// User RID.
    pub relative_id: u32,
    /// Account name.
    pub name: String,
}

/// Typed user information returned by `SamrQueryInformationUser`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamrUserInfo {
    /// Account name returned by the server.
    pub account_name: String,
}

/// Typed `samr` domain client over an already-open domain handle.
#[derive(Debug)]
pub struct SamrDomainClient<T = TokioTcpTransport> {
    rpc: PipeRpcClient<T>,
    context_id: u16,
    server_handle: [u8; 20],
    domain_handle: [u8; 20],
    domain_name: String,
    domain_sid: SamrSid,
}

/// Typed `samr` user client over an already-open user handle.
#[derive(Debug)]
pub struct SamrUserClient<T = TokioTcpTransport> {
    rpc: PipeRpcClient<T>,
    context_id: u16,
    server_handle: [u8; 20],
    domain_handle: [u8; 20],
    user_handle: [u8; 20],
    relative_id: u32,
    domain_name: String,
    domain_sid: SamrSid,
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

impl<T> SamrDomainClient<T> {
    /// Returns the opened domain name.
    #[must_use]
    pub fn domain_name(&self) -> &str {
        &self.domain_name
    }

    /// Returns the opened domain SID.
    #[must_use]
    pub fn domain_sid(&self) -> &SamrSid {
        &self.domain_sid
    }

    /// Returns the underlying RPC transport.
    #[must_use]
    pub fn rpc(&self) -> &PipeRpcClient<T> {
        &self.rpc
    }
}

impl<T> SamrUserClient<T> {
    /// Returns the opened user RID.
    #[must_use]
    pub fn relative_id(&self) -> u32 {
        self.relative_id
    }

    /// Returns the name of the currently-open domain.
    #[must_use]
    pub fn domain_name(&self) -> &str {
        &self.domain_name
    }

    /// Returns the SID of the currently-open domain.
    #[must_use]
    pub fn domain_sid(&self) -> &SamrSid {
        &self.domain_sid
    }

    /// Returns the underlying RPC transport.
    #[must_use]
    pub fn rpc(&self) -> &PipeRpcClient<T> {
        &self.rpc
    }
}

impl<T> SamrClient<T>
where
    T: crate::transport::Transport + Send,
{
    /// Performs the default `samr` bind and `SamrConnect5`.
    pub async fn bind(mut rpc: PipeRpcClient<T>) -> Result<Self, CoreError> {
        rpc.bind_context(Self::CONTEXT_ID, Self::SYNTAX).await?;
        let response = match rpc
            .call(
                Self::CONTEXT_ID,
                SAMR_CONNECT5_OPNUM,
                encode_connect5_request(DEFAULT_SERVER_ACCESS),
            )
            .await
        {
            Ok(response) => response,
            Err(error) if should_fallback_to_connect2(&error) => {
                rpc.call(
                    Self::CONTEXT_ID,
                    SAMR_CONNECT2_OPNUM,
                    encode_connect2_request(DEFAULT_SERVER_ACCESS),
                )
                .await?
            }
            Err(error) => return Err(error),
        };
        let (server_handle, revision) = parse_connect_response(&response)?;
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

    /// Looks up the SID for a hosted SAM domain by exact name.
    pub async fn lookup_domain_sid(&mut self, domain_name: &str) -> Result<SamrSid, CoreError> {
        let response = self
            .rpc
            .call(
                self.context_id,
                SAMR_LOOKUP_DOMAIN_OPNUM,
                encode_lookup_domain_request(self.server_handle, domain_name)?,
            )
            .await?;
        parse_lookup_domain_response(&response)
    }

    /// Opens a domain handle by name and consumes the server-scoped client.
    pub async fn open_domain(mut self, domain_name: &str) -> Result<SamrDomainClient<T>, CoreError> {
        let domain_sid = self.lookup_domain_sid(domain_name).await?;
        let response = self
            .rpc
            .call(
                self.context_id,
                SAMR_OPEN_DOMAIN_OPNUM,
                encode_open_domain_request(self.server_handle, DEFAULT_DOMAIN_ACCESS, &domain_sid),
            )
            .await?;
        let domain_handle = parse_open_domain_response(&response)?;
        Ok(SamrDomainClient {
            rpc: self.rpc,
            context_id: self.context_id,
            server_handle: self.server_handle,
            domain_handle,
            domain_name: domain_name.to_owned(),
            domain_sid,
        })
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

impl<T> SamrDomainClient<T>
where
    T: crate::transport::Transport + Send,
{
    /// Enumerates users in the currently-open domain.
    pub async fn enumerate_users(
        &mut self,
        user_account_control: u32,
    ) -> Result<Vec<SamrUser>, CoreError> {
        let response = self
            .rpc
            .call(
                self.context_id,
                SAMR_ENUMERATE_USERS_OPNUM,
                encode_enumerate_users_request(
                    self.domain_handle,
                    0,
                    user_account_control,
                    u32::MAX,
                ),
            )
            .await?;
        parse_enumerate_users_response(&response)
    }

    /// Opens a user handle by RID and consumes the domain-scoped client.
    pub async fn open_user(mut self, relative_id: u32) -> Result<SamrUserClient<T>, CoreError> {
        let response = self
            .rpc
            .call(
                self.context_id,
                SAMR_OPEN_USER_OPNUM,
                encode_open_user_request(self.domain_handle, USER_READ_GENERAL, relative_id),
            )
            .await?;
        let user_handle = parse_open_user_response(&response)?;
        Ok(SamrUserClient {
            rpc: self.rpc,
            context_id: self.context_id,
            server_handle: self.server_handle,
            domain_handle: self.domain_handle,
            user_handle,
            relative_id,
            domain_name: self.domain_name,
            domain_sid: self.domain_sid,
        })
    }

    /// Closes the domain handle, then the server handle, and returns the underlying RPC transport.
    pub async fn close(mut self) -> Result<PipeRpcClient<T>, CoreError> {
        let response = self
            .rpc
            .call(
                self.context_id,
                SAMR_CLOSE_HANDLE_OPNUM,
                encode_close_handle_request(self.domain_handle),
            )
            .await?;
        parse_close_handle_response(&response)?;

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

impl<T> SamrUserClient<T>
where
    T: crate::transport::Transport + Send,
{
    /// Queries `UserAccountNameInformation` for the current user handle.
    pub async fn query_account_name(&mut self) -> Result<SamrUserInfo, CoreError> {
        let response = self
            .rpc
            .call(
                self.context_id,
                SAMR_QUERY_INFORMATION_USER_OPNUM,
                encode_query_user_request(
                    self.user_handle,
                    USER_ACCOUNT_NAME_INFORMATION_CLASS,
                ),
            )
            .await?;
        parse_query_account_name_response(&response)
    }

    /// Closes the user handle and returns the domain-scoped client.
    pub async fn close(mut self) -> Result<SamrDomainClient<T>, CoreError> {
        let response = self
            .rpc
            .call(
                self.context_id,
                SAMR_CLOSE_HANDLE_OPNUM,
                encode_close_handle_request(self.user_handle),
            )
            .await?;
        parse_close_handle_response(&response)?;
        Ok(SamrDomainClient {
            rpc: self.rpc,
            context_id: self.context_id,
            server_handle: self.server_handle,
            domain_handle: self.domain_handle,
            domain_name: self.domain_name,
            domain_sid: self.domain_sid,
        })
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

fn encode_connect2_request(desired_access: u32) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8);
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&desired_access.to_le_bytes());
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

fn parse_connect2_response(response: &[u8]) -> Result<([u8; 20], SamrServerRevision), CoreError> {
    if response.len() < 24 {
        return Err(CoreError::InvalidResponse(
            "SamrConnect2 response was too short",
        ));
    }

    let mut server_handle = [0_u8; 20];
    server_handle.copy_from_slice(&response[..20]);
    let status = u32::from_le_bytes(response[20..24].try_into().expect("status slice"));
    if status != 0 {
        return Err(CoreError::RemoteOperation {
            operation: "SamrConnect2",
            code: status,
        });
    }

    Ok((
        server_handle,
        SamrServerRevision {
            revision: 2,
            supported_features: 0,
        },
    ))
}

fn parse_connect_response(response: &[u8]) -> Result<([u8; 20], SamrServerRevision), CoreError> {
    match parse_connect5_response(response) {
        Ok(parsed) => Ok(parsed),
        Err(CoreError::InvalidResponse(_)) if response.len() >= 24 => parse_connect2_response(response),
        Err(error) => Err(error),
    }
}

fn should_fallback_to_connect2(error: &CoreError) -> bool {
    matches!(
        error,
        CoreError::RemoteOperation {
            operation: "rpc_fault",
            code: 1783,
        }
    )
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

fn encode_lookup_domain_request(
    server_handle: [u8; 20],
    domain_name: &str,
) -> Result<Vec<u8>, CoreError> {
    if domain_name.is_empty() || domain_name.contains('\0') {
        return Err(CoreError::PathInvalid(
            "SAMR domain name must be a non-empty UTF-16 string",
        ));
    }

    let mut writer = NdrWriter::new();
    writer.write_bytes(&server_handle);
    writer.write_ref_unicode_string(domain_name);
    Ok(writer.into_bytes())
}

fn parse_lookup_domain_response(response: &[u8]) -> Result<SamrSid, CoreError> {
    let mut reader = NdrReader::new(response);
    let sid_referent = reader.read_u32("DomainSidReferent")?;
    if sid_referent == 0 {
        return Err(CoreError::InvalidResponse(
            "SamrLookupDomainInSamServer did not return a SID",
        ));
    }
    let sid = reader.read_lookup_domain_sid("DomainSid")?;
    let status = reader.read_u32("SamrLookupDomainInSamServerStatus")?;
    if status != 0 {
        return Err(CoreError::RemoteOperation {
            operation: "SamrLookupDomainInSamServer",
            code: status,
        });
    }
    Ok(sid)
}

fn encode_open_domain_request(
    server_handle: [u8; 20],
    desired_access: u32,
    domain_sid: &SamrSid,
) -> Vec<u8> {
    let mut writer = NdrWriter::new();
    writer.write_bytes(&server_handle);
    writer.write_u32(desired_access);
    writer.write_u32(domain_sid.sub_authorities.len() as u32);
    writer.write_sid(domain_sid);
    writer.into_bytes()
}

fn parse_open_domain_response(response: &[u8]) -> Result<[u8; 20], CoreError> {
    if response.len() < 24 {
        return Err(CoreError::InvalidResponse(
            "SamrOpenDomain response was too short",
        ));
    }
    let mut domain_handle = [0_u8; 20];
    domain_handle.copy_from_slice(&response[..20]);
    let status = u32::from_le_bytes(response[20..24].try_into().expect("status slice"));
    if status != 0 {
        return Err(CoreError::RemoteOperation {
            operation: "SamrOpenDomain",
            code: status,
        });
    }
    Ok(domain_handle)
}

fn encode_enumerate_users_request(
    domain_handle: [u8; 20],
    enumeration_context: u32,
    user_account_control: u32,
    preferred_maximum_length: u32,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32);
    bytes.extend_from_slice(&domain_handle);
    bytes.extend_from_slice(&enumeration_context.to_le_bytes());
    bytes.extend_from_slice(&user_account_control.to_le_bytes());
    bytes.extend_from_slice(&preferred_maximum_length.to_le_bytes());
    bytes
}

fn encode_open_user_request(
    domain_handle: [u8; 20],
    desired_access: u32,
    relative_id: u32,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(28);
    bytes.extend_from_slice(&domain_handle);
    bytes.extend_from_slice(&desired_access.to_le_bytes());
    bytes.extend_from_slice(&relative_id.to_le_bytes());
    bytes
}

fn parse_open_user_response(response: &[u8]) -> Result<[u8; 20], CoreError> {
    if response.len() < 24 {
        return Err(CoreError::InvalidResponse(
            "SamrOpenUser response was too short",
        ));
    }
    let mut user_handle = [0_u8; 20];
    user_handle.copy_from_slice(&response[..20]);
    let status = u32::from_le_bytes(response[20..24].try_into().expect("status slice"));
    if status != 0 {
        return Err(CoreError::RemoteOperation {
            operation: "SamrOpenUser",
            code: status,
        });
    }
    Ok(user_handle)
}

fn encode_query_user_request(user_handle: [u8; 20], info_class: u32) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(24);
    bytes.extend_from_slice(&user_handle);
    bytes.extend_from_slice(&info_class.to_le_bytes());
    bytes
}

fn parse_query_account_name_response(response: &[u8]) -> Result<SamrUserInfo, CoreError> {
    let mut reader = NdrReader::new(response);
    let buffer_referent = reader.read_u32("UserInformationReferent")?;
    if buffer_referent == 0 {
        return Err(CoreError::InvalidResponse(
            "SamrQueryInformationUser did not return account-name data",
        ));
    }
    let info_class = reader.read_u32("UserInformationClass")?;
    if info_class != USER_ACCOUNT_NAME_INFORMATION_CLASS {
        return Err(CoreError::InvalidResponse(
            "SamrQueryInformationUser returned an unexpected information class",
        ));
    }
    let account_name = reader.read_rpc_unicode_string("AccountName")?;
    let status = reader.read_u32("SamrQueryInformationUserStatus")?;
    if status != 0 {
        return Err(CoreError::RemoteOperation {
            operation: "SamrQueryInformationUser",
            code: status,
        });
    }
    Ok(SamrUserInfo { account_name })
}

fn parse_enumerate_users_response(response: &[u8]) -> Result<Vec<SamrUser>, CoreError> {
    let mut reader = NdrReader::new(response);
    let _enumeration_context = reader.read_u32("EnumerationContext")?;
    let buffer_referent = reader.read_u32("BufferReferent")?;
    let mut users = Vec::new();

    if buffer_referent != 0 {
        let entries_read = reader.read_u32("EntriesRead")? as usize;
        let array_referent = reader.read_u32("RidEnumerationArray")?;
        if entries_read > 0 && array_referent == 0 {
            return Err(CoreError::InvalidResponse(
                "SamrEnumerateUsersInDomain returned entries without an array",
            ));
        }
        if array_referent != 0 {
            let max_count = reader.read_u32("RidEnumerationMaxCount")? as usize;
            if max_count < entries_read {
                return Err(CoreError::InvalidResponse(
                    "SamrEnumerateUsersInDomain returned fewer array slots than entries",
                ));
            }
            let mut raw_entries = Vec::with_capacity(entries_read);
            let mut headers = Vec::with_capacity(entries_read);
            for _ in 0..entries_read {
                raw_entries.push(RidEnumeration {
                    relative_id: reader.read_u32("RelativeId")?,
                    name: String::new(),
                });
                headers.push(reader.read_unicode_string_header("Name")?);
            }
            for (entry, header) in raw_entries.iter_mut().zip(headers) {
                entry.name = reader.read_deferred_unicode_string(header, "Name")?;
            }
            users = raw_entries
                .into_iter()
                .map(|entry| SamrUser {
                    relative_id: entry.relative_id,
                    name: entry.name,
                })
                .collect();
        }
    }

    let count_returned = reader.read_u32("CountReturned")? as usize;
    if count_returned != users.len() {
        return Err(CoreError::InvalidResponse(
            "SamrEnumerateUsersInDomain count did not match returned entries",
        ));
    }

    let status = reader.read_u32("SamrEnumerateUsersInDomainStatus")?;
    if status != 0 && status != 0x0000_0105 {
        return Err(CoreError::RemoteOperation {
            operation: "SamrEnumerateUsersInDomain",
            code: status,
        });
    }
    Ok(users)
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
            let mut headers = Vec::with_capacity(entries_read);
            for _ in 0..entries_read {
                raw_entries.push(RidEnumeration {
                    relative_id: reader.read_u32("RelativeId")?,
                    name: String::new(),
                });
                headers.push(reader.read_unicode_string_header("Name")?);
            }
            for (entry, header) in raw_entries.iter_mut().zip(headers) {
                entry.name = reader.read_deferred_unicode_string(header, "Name")?;
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

#[derive(Clone, Copy)]
struct UnicodeStringHeader {
    length: usize,
    maximum_length: usize,
    referent: u32,
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

    fn read_unicode_string_header(
        &mut self,
        field: &'static str,
    ) -> Result<UnicodeStringHeader, CoreError> {
        let length = self.read_u16(field)? as usize;
        let maximum_length = self.read_u16(field)? as usize;
        let referent = self.read_u32(field)?;
        Ok(UnicodeStringHeader {
            length,
            maximum_length,
            referent,
        })
    }

    fn read_deferred_unicode_string(
        &mut self,
        header: UnicodeStringHeader,
        field: &'static str,
    ) -> Result<String, CoreError> {
        if header.referent == 0 {
            return Ok(String::new());
        }
        self.align(4, field)?;
        let max_count = self.read_u32(field)? as usize;
        let offset = self.read_u32(field)? as usize;
        let actual_count = self.read_u32(field)? as usize;
        if offset != 0
            || actual_count > max_count
            || actual_count * 2 < header.length
            || header.maximum_length < header.length
        {
            return Err(CoreError::InvalidResponse(field));
        }
        let mut code_units = Vec::with_capacity(actual_count);
        for _ in 0..actual_count {
            code_units.push(self.read_u16(field)?);
        }
        self.align(4, field)?;
        let actual_units = header.length / 2;
        String::from_utf16(&code_units[..actual_units])
            .map_err(|_| CoreError::InvalidResponse("failed to decode samr UTF-16 string"))
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
        let offset = self.read_u32(field)? as usize;
        let actual_count = self.read_u32(field)? as usize;
        if offset != 0
            || actual_count > max_count
            || actual_count * 2 < length
            || maximum_length < length
        {
            return Err(CoreError::InvalidResponse(field));
        }
        let mut code_units = Vec::with_capacity(actual_count);
        for _ in 0..actual_count {
            code_units.push(self.read_u16(field)?);
        }
        self.align(4, field)?;
        let actual_units = length / 2;
        String::from_utf16(&code_units[..actual_units])
            .map_err(|_| CoreError::InvalidResponse("failed to decode samr UTF-16 string"))
    }

    fn read_sid(&mut self, field: &'static str) -> Result<SamrSid, CoreError> {
        if self.remaining() < 8 {
            return Err(CoreError::InvalidResponse(field));
        }
        let revision = self.bytes[self.offset];
        let sub_authority_count = self.bytes[self.offset + 1] as usize;
        let mut identifier_authority = [0_u8; 6];
        identifier_authority.copy_from_slice(&self.bytes[self.offset + 2..self.offset + 8]);
        self.offset += 8;

        let mut sub_authorities = Vec::with_capacity(sub_authority_count);
        for _ in 0..sub_authority_count {
            sub_authorities.push(self.read_u32(field)?);
        }

        Ok(SamrSid {
            revision,
            identifier_authority,
            sub_authorities,
        })
    }

    fn read_lookup_domain_sid(&mut self, field: &'static str) -> Result<SamrSid, CoreError> {
        let sub_authority_count = self.read_u32(field)? as usize;
        let sid = self.read_sid(field)?;
        if sid.sub_authorities.len() != sub_authority_count {
            return Err(CoreError::InvalidResponse(field));
        }
        Ok(sid)
    }
}

struct NdrWriter {
    bytes: Vec<u8>,
}

impl NdrWriter {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    fn write_u32(&mut self, value: u32) {
        self.align(4);
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn write_ref_unicode_string(&mut self, value: &str) {
        let encoded = value.encode_utf16().collect::<Vec<_>>();
        let byte_len = (encoded.len() * 2) as u16;
        self.write_u16(byte_len);
        self.write_u16(byte_len);
        self.write_u32(1);
        self.align(4);
        self.write_u32(encoded.len() as u32);
        self.write_u32(0);
        self.write_u32(encoded.len() as u32);
        for code_unit in encoded {
            self.write_u16(code_unit);
        }
    }

    fn write_sid(&mut self, sid: &SamrSid) {
        self.bytes.push(sid.revision);
        self.bytes.push(sid.sub_authorities.len() as u8);
        self.bytes.extend_from_slice(&sid.identifier_authority);
        for sub_authority in &sid.sub_authorities {
            self.write_u32(*sub_authority);
        }
    }

    fn write_u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn align(&mut self, alignment: usize) {
        let padding = (alignment - (self.bytes.len() % alignment)) % alignment;
        self.bytes.resize(self.bytes.len() + padding, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        encode_close_handle_request, encode_connect2_request, encode_connect5_request,
        encode_enumerate_domains_request, encode_enumerate_users_request,
        encode_lookup_domain_request, encode_open_domain_request, encode_open_user_request,
        encode_query_user_request, parse_close_handle_response, parse_connect2_response,
        parse_connect5_response, parse_enumerate_domains_response,
        parse_enumerate_users_response, parse_lookup_domain_response, parse_open_domain_response,
        parse_open_user_response, parse_query_account_name_response, SamrDomain,
        SamrServerRevision, SamrSid, SamrUser, SamrUserInfo, DEFAULT_DOMAIN_ACCESS,
        DEFAULT_SERVER_ACCESS, USER_ACCOUNT_NAME_INFORMATION_CLASS, USER_READ_GENERAL,
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
            self.write_u32(0);
            self.write_u32(encoded.len() as u32);
            for code_unit in encoded {
                self.write_u16(code_unit);
            }
            self.align(4);
        }

        fn write_unicode_string_header(&mut self, value: &str) -> u32 {
            let encoded = value.encode_utf16().collect::<Vec<_>>();
            let byte_len = (encoded.len() * 2) as u16;
            self.write_u16(byte_len);
            self.write_u16(byte_len);
            let referent = self.next_referent();
            self.write_u32(referent);
            referent
        }

        fn write_deferred_unicode_string(&mut self, value: &str) {
            let encoded = value.encode_utf16().collect::<Vec<_>>();
            self.align(4);
            self.write_u32(encoded.len() as u32);
            self.write_u32(0);
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
    fn connect2_request_encodes_null_server_name_and_access() {
        assert_eq!(
            encode_connect2_request(DEFAULT_SERVER_ACCESS),
            [0_u32.to_le_bytes(), DEFAULT_SERVER_ACCESS.to_le_bytes()].concat()
        );
    }

    #[test]
    fn connect2_response_decodes_handle() {
        let response = [[0x55; 20].to_vec(), 0_u32.to_le_bytes().to_vec()].concat();
        let (handle, revision) =
            parse_connect2_response(&response).expect("response should decode");
        assert_eq!(handle, [0x55; 20]);
        assert_eq!(
            revision,
            SamrServerRevision {
                revision: 2,
                supported_features: 0,
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
        writer.write_unicode_string_header("Builtin");
        writer.write_u32(0);
        writer.write_unicode_string_header("DESKTOP");
        writer.write_deferred_unicode_string("Builtin");
        writer.write_deferred_unicode_string("DESKTOP");
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
    fn enumerate_domains_response_decodes_standalone_samba_fixture() {
        let response = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00,
            0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00, 0x18, 0x00,
            0x08, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x0e, 0x00, 0x0c, 0x00,
            0x02, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00,
            0x42, 0x00, 0x31, 0x00, 0x30, 0x00, 0x34, 0x00, 0x46, 0x00, 0x44, 0x00, 0x37, 0x00,
            0x36, 0x00, 0x34, 0x00, 0x39, 0x00, 0x38, 0x00, 0x36, 0x00, 0x07, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x42, 0x00, 0x75, 0x00, 0x69, 0x00,
            0x6c, 0x00, 0x74, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        assert_eq!(
            parse_enumerate_domains_response(&response).expect("response should decode"),
            vec![
                SamrDomain {
                    relative_id: 0,
                    name: "B104FD764986".to_owned(),
                },
                SamrDomain {
                    relative_id: 1,
                    name: "Builtin".to_owned(),
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

    #[test]
    fn lookup_domain_request_encodes_server_handle_and_name() {
        assert_eq!(
            encode_lookup_domain_request([0x41; 20], "Builtin").expect("request should encode"),
            [
                [0x41; 20].to_vec(),
                14_u16.to_le_bytes().to_vec(),
                14_u16.to_le_bytes().to_vec(),
                1_u32.to_le_bytes().to_vec(),
                7_u32.to_le_bytes().to_vec(),
                0_u32.to_le_bytes().to_vec(),
                7_u32.to_le_bytes().to_vec(),
                b"B\0u\0i\0l\0t\0i\0n\0".to_vec(),
            ]
            .concat()
        );
    }

    #[test]
    fn lookup_domain_response_decodes_sid() {
        let response = [
            1_u32.to_le_bytes().to_vec(),
            2_u32.to_le_bytes().to_vec(),
            vec![1, 2, 0, 0, 0, 0, 0, 5],
            32_u32.to_le_bytes().to_vec(),
            544_u32.to_le_bytes().to_vec(),
            0_u32.to_le_bytes().to_vec(),
        ]
        .concat();

        assert_eq!(
            parse_lookup_domain_response(&response).expect("response should decode"),
            SamrSid {
                revision: 1,
                identifier_authority: [0, 0, 0, 0, 0, 5],
                sub_authorities: vec![32, 544],
            }
        );
    }

    #[test]
    fn open_domain_request_encodes_sid_inline() {
        let sid = SamrSid {
            revision: 1,
            identifier_authority: [0, 0, 0, 0, 0, 5],
            sub_authorities: vec![32, 544],
        };
        assert_eq!(
            encode_open_domain_request([0x41; 20], DEFAULT_DOMAIN_ACCESS, &sid),
            [
                [0x41; 20].to_vec(),
                DEFAULT_DOMAIN_ACCESS.to_le_bytes().to_vec(),
                2_u32.to_le_bytes().to_vec(),
                vec![1, 2, 0, 0, 0, 0, 0, 5],
                32_u32.to_le_bytes().to_vec(),
                544_u32.to_le_bytes().to_vec(),
            ]
            .concat()
        );
    }

    #[test]
    fn open_domain_response_decodes_handle() {
        let response = [[0x77; 20].to_vec(), 0_u32.to_le_bytes().to_vec()].concat();
        assert_eq!(
            parse_open_domain_response(&response).expect("response should decode"),
            [0x77; 20]
        );
    }

    #[test]
    fn enumerate_users_request_encodes_handle_context_and_filter() {
        assert_eq!(
            encode_enumerate_users_request([0x12; 20], 4, 0x20, u32::MAX),
            [
                [0x12; 20].to_vec(),
                4_u32.to_le_bytes().to_vec(),
                0x20_u32.to_le_bytes().to_vec(),
                u32::MAX.to_le_bytes().to_vec(),
            ]
            .concat()
        );
    }

    #[test]
    fn enumerate_users_response_decodes_entries() {
        let mut writer = ResponseWriter::new();
        writer.write_u32(0);
        let buffer_ref = writer.next_referent();
        writer.write_u32(buffer_ref);
        writer.write_u32(2);
        let array_ref = writer.next_referent();
        writer.write_u32(array_ref);
        writer.write_u32(2);
        writer.write_u32(500);
        writer.write_unicode_string_header("Administrator");
        writer.write_u32(501);
        writer.write_unicode_string_header("Guest");
        writer.write_deferred_unicode_string("Administrator");
        writer.write_deferred_unicode_string("Guest");
        writer.write_u32(2);
        writer.write_u32(0);

        assert_eq!(
            parse_enumerate_users_response(&writer.into_bytes()).expect("response should decode"),
            vec![
                SamrUser {
                    relative_id: 500,
                    name: "Administrator".to_owned(),
                },
                SamrUser {
                    relative_id: 501,
                    name: "Guest".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn open_user_request_encodes_handle_access_and_rid() {
        assert_eq!(
            encode_open_user_request([0x12; 20], USER_READ_GENERAL, 500),
            [
                [0x12; 20].to_vec(),
                USER_READ_GENERAL.to_le_bytes().to_vec(),
                500_u32.to_le_bytes().to_vec(),
            ]
            .concat()
        );
    }

    #[test]
    fn open_user_response_decodes_handle() {
        let response = [[0x66; 20].to_vec(), 0_u32.to_le_bytes().to_vec()].concat();
        assert_eq!(
            parse_open_user_response(&response).expect("response should decode"),
            [0x66; 20]
        );
    }

    #[test]
    fn query_user_request_encodes_handle_and_info_class() {
        assert_eq!(
            encode_query_user_request([0x22; 20], USER_ACCOUNT_NAME_INFORMATION_CLASS),
            [
                [0x22; 20].to_vec(),
                (USER_ACCOUNT_NAME_INFORMATION_CLASS as u32)
                    .to_le_bytes()
                    .to_vec(),
            ]
            .concat()
        );
    }

    #[test]
    fn query_account_name_response_decodes_value() {
        let mut writer = ResponseWriter::new();
        let buffer_ref = writer.next_referent();
        writer.write_u32(buffer_ref);
        writer.write_u32(USER_ACCOUNT_NAME_INFORMATION_CLASS);
        writer.write_rpc_unicode_string("Administrator");
        writer.write_u32(0);

        assert_eq!(
            parse_query_account_name_response(&writer.into_bytes())
                .expect("response should decode"),
            SamrUserInfo {
                account_name: "Administrator".to_owned(),
            }
        );
    }
}
