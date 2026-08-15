//! Typed `srvsvc` DCE/RPC helpers built on top of named pipes.

use std::fmt;

use smolder_proto::rpc::{SyntaxId, Uuid};

use crate::error::CoreError;
use crate::policy::ResourceLimits;
use crate::rpc::PipeRpcClient;
use crate::transport::TokioTcpTransport;

const SRVSVC_SYNTAX: SyntaxId = SyntaxId::new(
    Uuid::new(
        0x4b32_4fc8,
        0x1670,
        0x01d3,
        [0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88],
    ),
    3,
    0,
);
const SRVSVC_CONTEXT_ID: u16 = 0;
const NETR_SESSION_ENUM_OPNUM: u16 = 12;
const NETR_SHARE_ENUM_OPNUM: u16 = 15;
const NETR_SERVER_GET_INFO_OPNUM: u16 = 21;
const NETR_REMOTE_TOD_OPNUM: u16 = 28;
const MAX_PREFERRED_LENGTH: u32 = u32::MAX;
const ERROR_INVALID_LEVEL: u32 = 124;
const ERROR_MORE_DATA: u32 = 234;

struct EnumerationPage<T> {
    entries: Vec<T>,
    resume_handle: Option<u32>,
    status: u32,
}

/// Decoded `SHARE_INFO_1` entry returned by `NetrShareEnum` level 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareInfo1 {
    /// Share name.
    pub name: String,
    /// Raw `shi1_type` bitfield.
    pub share_type: u32,
    /// Optional share remark/comment.
    pub remark: Option<String>,
}

/// Decoded `SHARE_INFO_2` entry returned by `NetrShareGetInfo` level 2.
#[derive(Clone, PartialEq, Eq)]
pub struct ShareInfo2 {
    /// Share name.
    pub name: String,
    /// Raw `shi2_type` bitfield.
    pub share_type: u32,
    /// Optional share remark/comment.
    pub remark: Option<String>,
    /// Share permissions field.
    pub permissions: u32,
    /// Maximum concurrent uses.
    pub max_uses: u32,
    /// Current concurrent uses.
    pub current_uses: u32,
    /// Local backing path if present.
    pub path: Option<String>,
    /// Legacy share password field if present.
    pub password: Option<String>,
}

impl fmt::Debug for ShareInfo2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShareInfo2")
            .field("name", &self.name)
            .field("share_type", &self.share_type)
            .field("remark", &self.remark)
            .field("permissions", &self.permissions)
            .field("max_uses", &self.max_uses)
            .field("current_uses", &self.current_uses)
            .field("path", &self.path)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Decoded `TIME_OF_DAY_INFO` fields returned by `NetrRemoteTOD`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeOfDayInfo {
    /// Hours component in local server time.
    pub hours: u32,
    /// Minutes component in local server time.
    pub minutes: u32,
    /// Seconds component in local server time.
    pub seconds: u32,
    /// Day of month.
    pub day: u32,
    /// Month number in the range `1..=12`.
    pub month: u32,
    /// Full year value.
    pub year: u32,
    /// Weekday in the range `0..=6`.
    pub weekday: u32,
}

/// Decoded `SERVER_INFO_101` fields returned by `NetrServerGetInfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerInfo101 {
    /// Raw platform identifier.
    pub platform_id: u32,
    /// Server name returned by the endpoint.
    pub name: String,
    /// Server major version.
    pub version_major: u32,
    /// Server minor version.
    pub version_minor: u32,
    /// Raw server-type bitfield.
    pub server_type: u32,
    /// Optional server comment/description.
    pub comment: Option<String>,
}

/// Decoded `SERVER_INFO_103` fields returned by `NetrServerGetInfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerInfo103 {
    /// Raw platform identifier.
    pub platform_id: u32,
    /// Server name returned by the endpoint.
    pub name: String,
    /// Server major version.
    pub version_major: u32,
    /// Server minor version.
    pub version_minor: u32,
    /// Raw server-type bitfield.
    pub server_type: u32,
    /// Optional server comment/description.
    pub comment: Option<String>,
    /// Maximum number of users supported by the server.
    pub users: u32,
    /// Automatic disconnect time in minutes.
    pub disconnect_minutes: i32,
    /// Whether the server is hidden from browser listings.
    pub hidden: bool,
    /// Browser announce interval in seconds.
    pub announce: u32,
    /// Browser announce delta in milliseconds.
    pub announce_delta: u32,
    /// Number of licenses currently reported by the server.
    pub licenses: u32,
    /// Optional user path returned by the server.
    pub user_path: Option<String>,
    /// Raw capability bitfield.
    pub capabilities: u32,
}

/// Decoded `SESSION_INFO_10` entry returned by `NetrSessionEnum` level 10.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo10 {
    /// Remote client name if present.
    pub client_name: Option<String>,
    /// Authenticated username if present.
    pub username: Option<String>,
    /// Connected session age in seconds.
    pub time: u32,
    /// Idle time in seconds.
    pub idle_time: u32,
}

/// Typed `srvsvc` client over an already-open RPC transport.
#[derive(Debug)]
pub struct SrvsvcClient<T = TokioTcpTransport> {
    rpc: PipeRpcClient<T>,
    context_id: u16,
}

impl<T> SrvsvcClient<T> {
    /// The `srvsvc` abstract syntax identifier.
    pub const SYNTAX: SyntaxId = SRVSVC_SYNTAX;

    /// The default `srvsvc` presentation context identifier.
    pub const CONTEXT_ID: u16 = SRVSVC_CONTEXT_ID;

    /// Wraps an already-bound `srvsvc` RPC transport.
    #[must_use]
    pub fn new(rpc: PipeRpcClient<T>) -> Self {
        Self {
            rpc,
            context_id: Self::CONTEXT_ID,
        }
    }

    /// Returns the underlying RPC transport.
    #[must_use]
    pub fn rpc(&self) -> &PipeRpcClient<T> {
        &self.rpc
    }

    /// Consumes the client and returns the underlying RPC transport.
    #[must_use]
    pub fn into_rpc(self) -> PipeRpcClient<T> {
        self.rpc
    }
}

impl<T> SrvsvcClient<T>
where
    T: crate::transport::SmbTransport + Send,
{
    /// Performs the default `srvsvc` bind on a named-pipe RPC transport.
    pub async fn bind(mut rpc: PipeRpcClient<T>) -> Result<Self, CoreError> {
        if let Err(error) = rpc.bind_context(Self::CONTEXT_ID, Self::SYNTAX).await {
            return Err(rpc.close_after_error(error).await);
        }
        Ok(Self::new(rpc))
    }

    /// Calls `NetrRemoteTOD` and returns the decoded time-of-day structure.
    pub async fn remote_tod(&mut self) -> Result<TimeOfDayInfo, CoreError> {
        let response = self
            .rpc
            .call(
                self.context_id,
                NETR_REMOTE_TOD_OPNUM,
                encode_remote_tod_request(),
            )
            .await?;
        parse_remote_tod_response(&response)
    }

    /// Calls `NetrShareEnum` at information level 1.
    pub async fn share_enum_level1(&mut self) -> Result<Vec<ShareInfo1>, CoreError> {
        let limits = self.rpc.pipe().resource_limits();
        let mut entries = Vec::new();
        let mut resume_handle = None;
        for _ in 0..limits.max_rpc_pages {
            let response = self
                .rpc
                .call(
                    self.context_id,
                    NETR_SHARE_ENUM_OPNUM,
                    encode_share_enum_level1_page_request(resume_handle),
                )
                .await?;
            let page = parse_share_enum_level1_page_with_limits(&response, limits)?;
            append_bounded_entries(
                &mut entries,
                page.entries,
                limits.max_ndr_entries,
                "NetrShareEnum entries",
            )?;
            if page.status == 0 {
                return Ok(entries);
            }
            let next = page.resume_handle.ok_or(CoreError::InvalidResponse(
                "NetrShareEnum returned more data without a resume handle",
            ))?;
            if Some(next) == resume_handle {
                return Err(CoreError::InvalidResponse(
                    "NetrShareEnum did not advance its resume handle",
                ));
            }
            resume_handle = Some(next);
        }
        Err(CoreError::ResourceLimit {
            resource: "NetrShareEnum pages",
            requested: (limits.max_rpc_pages.saturating_add(1)) as u64,
            maximum: limits.max_rpc_pages as u64,
        })
    }

    /// Calls `NetrSessionEnum` at information level 10.
    ///
    /// Servers that reject level 10 with `ERROR_INVALID_LEVEL` are queried at level 1, whose
    /// identifying and timing fields are a superset of the level-10 result exposed here.
    pub async fn session_enum_level10(&mut self) -> Result<Vec<SessionInfo10>, CoreError> {
        match self.session_enum(10).await {
            Err(CoreError::RemoteOperation {
                operation: "NetrSessionEnum",
                code: ERROR_INVALID_LEVEL,
            }) => self.session_enum(1).await,
            result => result,
        }
    }

    async fn session_enum(&mut self, level: u32) -> Result<Vec<SessionInfo10>, CoreError> {
        let limits = self.rpc.pipe().resource_limits();
        let mut entries = Vec::new();
        let mut resume_handle = None;
        for _ in 0..limits.max_rpc_pages {
            let response = self
                .rpc
                .call(
                    self.context_id,
                    NETR_SESSION_ENUM_OPNUM,
                    encode_session_enum_page_request(level, resume_handle),
                )
                .await?;
            let page = parse_session_enum_page_with_limits(&response, level, limits)?;
            append_bounded_entries(
                &mut entries,
                page.entries,
                limits.max_ndr_entries,
                "NetrSessionEnum entries",
            )?;
            if page.status == 0 {
                return Ok(entries);
            }
            let next = page.resume_handle.ok_or(CoreError::InvalidResponse(
                "NetrSessionEnum returned more data without a resume handle",
            ))?;
            if Some(next) == resume_handle {
                return Err(CoreError::InvalidResponse(
                    "NetrSessionEnum did not advance its resume handle",
                ));
            }
            resume_handle = Some(next);
        }
        Err(CoreError::ResourceLimit {
            resource: "NetrSessionEnum pages",
            requested: (limits.max_rpc_pages.saturating_add(1)) as u64,
            maximum: limits.max_rpc_pages as u64,
        })
    }

    /// Calls `NetrShareGetInfo` at information level 2.
    pub async fn share_get_info_level2(
        &mut self,
        share_name: &str,
    ) -> Result<ShareInfo2, CoreError> {
        let response = self
            .rpc
            .call(
                self.context_id,
                16,
                encode_share_get_info_level2_request(share_name)?,
            )
            .await?;
        parse_share_get_info_level2_response_with_limits(
            &response,
            self.rpc.pipe().resource_limits(),
        )
    }

    /// Calls `NetrServerGetInfo` at information level 101.
    pub async fn server_get_info_level101(&mut self) -> Result<ServerInfo101, CoreError> {
        let response = self
            .rpc
            .call(
                self.context_id,
                NETR_SERVER_GET_INFO_OPNUM,
                encode_server_get_info_level101_request(),
            )
            .await?;
        parse_server_get_info_level101_response_with_limits(
            &response,
            self.rpc.pipe().resource_limits(),
        )
    }

    /// Calls `NetrServerGetInfo` at information level 103.
    pub async fn server_get_info_level103(&mut self) -> Result<ServerInfo103, CoreError> {
        let response = self
            .rpc
            .call(
                self.context_id,
                NETR_SERVER_GET_INFO_OPNUM,
                encode_server_get_info_level103_request(),
            )
            .await?;
        parse_server_get_info_level103_response_with_limits(
            &response,
            self.rpc.pipe().resource_limits(),
        )
    }
}

fn encode_remote_tod_request() -> Vec<u8> {
    0_u32.to_le_bytes().to_vec()
}

#[cfg(test)]
fn encode_share_enum_level1_request() -> Vec<u8> {
    encode_share_enum_level1_page_request(None)
}

fn encode_share_enum_level1_page_request(resume_handle: Option<u32>) -> Vec<u8> {
    let mut stub = Vec::with_capacity(if resume_handle.is_some() { 36 } else { 32 });
    stub.extend_from_slice(&0_u32.to_le_bytes());
    stub.extend_from_slice(&1_u32.to_le_bytes());
    stub.extend_from_slice(&1_u32.to_le_bytes());
    stub.extend_from_slice(&1_u32.to_le_bytes());
    stub.extend_from_slice(&0_u32.to_le_bytes());
    stub.extend_from_slice(&0_u32.to_le_bytes());
    stub.extend_from_slice(&MAX_PREFERRED_LENGTH.to_le_bytes());
    stub.extend_from_slice(&u32::from(resume_handle.is_some()).to_le_bytes());
    if let Some(resume_handle) = resume_handle {
        stub.extend_from_slice(&resume_handle.to_le_bytes());
    }
    stub
}

#[cfg(test)]
fn encode_session_enum_level10_request() -> Vec<u8> {
    encode_session_enum_page_request(10, None)
}

fn encode_session_enum_page_request(level: u32, resume_handle: Option<u32>) -> Vec<u8> {
    let mut stub = Vec::with_capacity(if resume_handle.is_some() { 44 } else { 40 });
    stub.extend_from_slice(&0_u32.to_le_bytes());
    stub.extend_from_slice(&0_u32.to_le_bytes());
    stub.extend_from_slice(&0_u32.to_le_bytes());
    stub.extend_from_slice(&level.to_le_bytes());
    stub.extend_from_slice(&level.to_le_bytes());
    stub.extend_from_slice(&1_u32.to_le_bytes());
    stub.extend_from_slice(&0_u32.to_le_bytes());
    stub.extend_from_slice(&0_u32.to_le_bytes());
    stub.extend_from_slice(&MAX_PREFERRED_LENGTH.to_le_bytes());
    stub.extend_from_slice(&u32::from(resume_handle.is_some()).to_le_bytes());
    if let Some(resume_handle) = resume_handle {
        stub.extend_from_slice(&resume_handle.to_le_bytes());
    }
    stub
}

fn append_bounded_entries<T>(
    aggregate: &mut Vec<T>,
    page: Vec<T>,
    maximum: usize,
    resource: &'static str,
) -> Result<(), CoreError> {
    let new_len = aggregate
        .len()
        .checked_add(page.len())
        .ok_or(CoreError::ResourceLimit {
            resource,
            requested: u64::MAX,
            maximum: maximum as u64,
        })?;
    if new_len > maximum {
        return Err(CoreError::ResourceLimit {
            resource,
            requested: new_len as u64,
            maximum: maximum as u64,
        });
    }
    aggregate
        .try_reserve(page.len())
        .map_err(|_| CoreError::AllocationFailed(resource))?;
    aggregate.extend(page);
    Ok(())
}

fn encode_share_get_info_level2_request(share_name: &str) -> Result<Vec<u8>, CoreError> {
    if share_name.is_empty() || share_name.contains('\0') {
        return Err(CoreError::PathInvalid(
            "share name for NetrShareGetInfo must be a non-empty UTF-16 string",
        ));
    }

    let mut writer = NdrWriter::new();
    writer.write_u32(0);
    writer.write_ref_wide_string(share_name);
    writer.write_u32(2);
    Ok(writer.into_bytes())
}

fn encode_server_get_info_level101_request() -> Vec<u8> {
    let mut writer = NdrWriter::new();
    writer.write_u32(0);
    writer.write_u32(101);
    writer.into_bytes()
}

fn encode_server_get_info_level103_request() -> Vec<u8> {
    let mut writer = NdrWriter::new();
    writer.write_u32(0);
    writer.write_u32(103);
    writer.into_bytes()
}

fn parse_remote_tod_response(response: &[u8]) -> Result<TimeOfDayInfo, CoreError> {
    const STRUCT_OFFSET: usize = 4;
    const STRUCT_LEN: usize = 48;
    const STATUS_OFFSET: usize = STRUCT_OFFSET + STRUCT_LEN;
    if response.len() < STATUS_OFFSET + 4 {
        return Err(CoreError::InvalidResponse(
            "NetrRemoteTOD response was too short",
        ));
    }

    let referent = u32::from_le_bytes(response[0..4].try_into().expect("referent slice"));
    if referent == 0 {
        return Err(CoreError::InvalidResponse(
            "NetrRemoteTOD did not return a TIME_OF_DAY_INFO buffer",
        ));
    }

    let read_u32 = |offset: usize| -> u32 {
        u32::from_le_bytes(
            response[offset..offset + 4]
                .try_into()
                .expect("DWORD slice should decode"),
        )
    };
    let status = read_u32(STATUS_OFFSET);
    if status != 0 {
        return Err(CoreError::RemoteOperation {
            operation: "NetrRemoteTOD",
            code: status,
        });
    }

    Ok(TimeOfDayInfo {
        hours: read_u32(STRUCT_OFFSET + 8),
        minutes: read_u32(STRUCT_OFFSET + 12),
        seconds: read_u32(STRUCT_OFFSET + 16),
        day: read_u32(STRUCT_OFFSET + 32),
        month: read_u32(STRUCT_OFFSET + 36),
        year: read_u32(STRUCT_OFFSET + 40),
        weekday: read_u32(STRUCT_OFFSET + 44),
    })
}

#[cfg(test)]
fn parse_share_enum_level1_page(response: &[u8]) -> Result<EnumerationPage<ShareInfo1>, CoreError> {
    parse_share_enum_level1_page_with_limits(response, ResourceLimits::default())
}

fn parse_share_enum_level1_page_with_limits(
    response: &[u8],
    limits: ResourceLimits,
) -> Result<EnumerationPage<ShareInfo1>, CoreError> {
    let mut reader = NdrReader::with_limits(response, limits);
    let level = reader.read_u32("Level")?;
    if level != 1 {
        return Err(CoreError::InvalidResponse(
            "NetrShareEnum did not return level 1 data",
        ));
    }
    let union_level = reader.read_u32("ShareInfo.Level")?;
    if union_level != 1 {
        return Err(CoreError::InvalidResponse(
            "NetrShareEnum returned an unexpected union level",
        ));
    }

    let container_referent = reader.read_u32("ShareInfo.ContainerReferent")?;
    if container_referent == 0 {
        return Err(CoreError::InvalidResponse(
            "NetrShareEnum did not return a level 1 container",
        ));
    }
    let entries_read = reader.read_u32("EntriesRead")? as usize;
    let buffer_referent = reader.read_u32("BufferReferent")?;
    let mut entries = Vec::new();
    if buffer_referent != 0 {
        let max_count = reader.read_u32("BufferMaxCount")? as usize;
        if max_count < entries_read {
            return Err(CoreError::InvalidResponse(
                "NetrShareEnum buffer count was smaller than entries read",
            ));
        }
        reader.validate_collection(entries_read, 12, "NetrShareEnum entries")?;
        entries
            .try_reserve_exact(entries_read)
            .map_err(|_| CoreError::AllocationFailed("NetrShareEnum entries"))?;

        for _ in 0..entries_read {
            entries.push(ShareInfo1Stub {
                name_referent: reader.read_u32("shi1_netname")?,
                share_type: reader.read_u32("shi1_type")?,
                remark_referent: reader.read_u32("shi1_remark")?,
                name: String::new(),
                remark: None,
            });
        }

        for entry in &mut entries {
            entry.name = if entry.name_referent != 0 {
                reader.read_wide_string("shi1_netname")?
            } else {
                String::new()
            };
            entry.remark = if entry.remark_referent != 0 {
                Some(reader.read_wide_string("shi1_remark")?)
            } else {
                None
            };
        }
    } else if entries_read != 0 {
        return Err(CoreError::InvalidResponse(
            "NetrShareEnum returned entries without a buffer",
        ));
    }

    let total_entries = reader.read_u32("TotalEntries")? as usize;
    if total_entries < entries_read {
        return Err(CoreError::InvalidResponse(
            "NetrShareEnum total entries was smaller than entries read",
        ));
    }

    let resume_handle_referent = reader.read_u32("ResumeHandleReferent")?;
    let resume_handle = if resume_handle_referent != 0 {
        Some(reader.read_u32("ResumeHandleValue")?)
    } else {
        None
    };
    let status = reader.read_u32("NetrShareEnumStatus")?;
    if status != 0 && status != ERROR_MORE_DATA {
        return Err(CoreError::RemoteOperation {
            operation: "NetrShareEnum",
            code: status,
        });
    }

    let mut decoded = Vec::new();
    decoded
        .try_reserve_exact(entries.len())
        .map_err(|_| CoreError::AllocationFailed("NetrShareEnum entries"))?;
    for entry in entries {
        decoded.push(ShareInfo1 {
            name: entry.name,
            share_type: entry.share_type,
            remark: entry.remark,
        });
    }
    Ok(EnumerationPage {
        entries: decoded,
        resume_handle,
        status,
    })
}

#[cfg(test)]
fn parse_share_enum_level1_response(response: &[u8]) -> Result<Vec<ShareInfo1>, CoreError> {
    let page = parse_share_enum_level1_page(response)?;
    if page.status == 0 {
        Ok(page.entries)
    } else {
        Err(CoreError::RemoteOperation {
            operation: "NetrShareEnum",
            code: page.status,
        })
    }
}

#[cfg(test)]
fn parse_session_enum_level10_page(
    response: &[u8],
) -> Result<EnumerationPage<SessionInfo10>, CoreError> {
    parse_session_enum_page_with_limits(response, 10, ResourceLimits::default())
}

fn parse_session_enum_page_with_limits(
    response: &[u8],
    expected_level: u32,
    limits: ResourceLimits,
) -> Result<EnumerationPage<SessionInfo10>, CoreError> {
    if expected_level != 1 && expected_level != 10 {
        return Err(CoreError::InvalidResponse(
            "NetrSessionEnum requested an unsupported information level",
        ));
    }

    let mut reader = NdrReader::with_limits(response, limits);
    let level = reader.read_u32("Level")?;
    if level != expected_level {
        return Err(CoreError::InvalidResponse(
            "NetrSessionEnum returned an unexpected information level",
        ));
    }
    let union_level = reader.read_u32("SessionInfo.Level")?;
    if union_level != expected_level {
        return Err(CoreError::InvalidResponse(
            "NetrSessionEnum returned an unexpected union level",
        ));
    }

    let container_referent = reader.read_u32("SessionInfo.ContainerReferent")?;
    let mut entries = Vec::new();
    let entries_read = if container_referent != 0 {
        let entries_read = reader.read_u32("EntriesRead")? as usize;
        let buffer_referent = reader.read_u32("BufferReferent")?;
        if buffer_referent != 0 {
            let max_count = reader.read_u32("BufferMaxCount")? as usize;
            if max_count < entries_read {
                return Err(CoreError::InvalidResponse(
                    "NetrSessionEnum buffer count was smaller than entries read",
                ));
            }
            let entry_wire_size = if expected_level == 1 { 24 } else { 16 };
            reader.validate_collection(entries_read, entry_wire_size, "NetrSessionEnum entries")?;
            entries
                .try_reserve_exact(entries_read)
                .map_err(|_| CoreError::AllocationFailed("NetrSessionEnum entries"))?;

            for _ in 0..entries_read {
                let client_name_referent = reader.read_u32(if expected_level == 1 {
                    "sesi1_cname"
                } else {
                    "sesi10_cname"
                })?;
                let username_referent = reader.read_u32(if expected_level == 1 {
                    "sesi1_username"
                } else {
                    "sesi10_username"
                })?;
                let (time, idle_time) = if expected_level == 1 {
                    let _num_opens = reader.read_u32("sesi1_num_opens")?;
                    let time = reader.read_u32("sesi1_time")?;
                    let idle_time = reader.read_u32("sesi1_idle_time")?;
                    let _user_flags = reader.read_u32("sesi1_user_flags")?;
                    (time, idle_time)
                } else {
                    (
                        reader.read_u32("sesi10_time")?,
                        reader.read_u32("sesi10_idle_time")?,
                    )
                };
                entries.push(SessionInfoStub {
                    client_name_referent,
                    username_referent,
                    time,
                    idle_time,
                    client_name: None,
                    username: None,
                });
            }

            for entry in &mut entries {
                entry.client_name = if entry.client_name_referent != 0 {
                    Some(reader.read_wide_string(if expected_level == 1 {
                        "sesi1_cname"
                    } else {
                        "sesi10_cname"
                    })?)
                } else {
                    None
                };
                entry.username = if entry.username_referent != 0 {
                    Some(reader.read_wide_string(if expected_level == 1 {
                        "sesi1_username"
                    } else {
                        "sesi10_username"
                    })?)
                } else {
                    None
                };
            }
        } else if entries_read != 0 {
            return Err(CoreError::InvalidResponse(
                "NetrSessionEnum returned entries without a buffer",
            ));
        }
        entries_read
    } else {
        0
    };

    let total_entries = reader.read_u32("TotalEntries")? as usize;
    if total_entries < entries_read {
        return Err(CoreError::InvalidResponse(
            "NetrSessionEnum total entries was smaller than entries read",
        ));
    }

    let resume_handle_referent = reader.read_u32("ResumeHandleReferent")?;
    let resume_handle = if resume_handle_referent != 0 {
        Some(reader.read_u32("ResumeHandleValue")?)
    } else {
        None
    };

    let status = reader.read_u32("NetrSessionEnumStatus")?;
    if status != 0 && status != ERROR_MORE_DATA {
        return Err(CoreError::RemoteOperation {
            operation: "NetrSessionEnum",
            code: status,
        });
    }
    if container_referent == 0 {
        return Err(CoreError::InvalidResponse(
            "NetrSessionEnum did not return an information container",
        ));
    }

    let mut decoded = Vec::new();
    decoded
        .try_reserve_exact(entries.len())
        .map_err(|_| CoreError::AllocationFailed("NetrSessionEnum entries"))?;
    for entry in entries {
        decoded.push(SessionInfo10 {
            client_name: entry.client_name,
            username: entry.username,
            time: entry.time,
            idle_time: entry.idle_time,
        });
    }
    Ok(EnumerationPage {
        entries: decoded,
        resume_handle,
        status,
    })
}

#[cfg(test)]
fn parse_session_enum_level10_response(response: &[u8]) -> Result<Vec<SessionInfo10>, CoreError> {
    let page = parse_session_enum_level10_page(response)?;
    if page.status == 0 {
        Ok(page.entries)
    } else {
        Err(CoreError::RemoteOperation {
            operation: "NetrSessionEnum",
            code: page.status,
        })
    }
}

#[cfg(test)]
fn parse_share_get_info_level2_response(response: &[u8]) -> Result<ShareInfo2, CoreError> {
    parse_share_get_info_level2_response_with_limits(response, ResourceLimits::default())
}

fn parse_share_get_info_level2_response_with_limits(
    response: &[u8],
    limits: ResourceLimits,
) -> Result<ShareInfo2, CoreError> {
    let mut reader = NdrReader::with_limits(response, limits);
    let level = reader.read_u32("Level")?;
    if level != 2 {
        return Err(CoreError::InvalidResponse(
            "NetrShareGetInfo returned an unexpected union level",
        ));
    }
    let info_referent = reader.read_u32("InfoStruct")?;
    if info_referent == 0 {
        return Err(CoreError::InvalidResponse(
            "NetrShareGetInfo did not return a SHARE_INFO_2 buffer",
        ));
    }

    let name_referent = reader.read_u32("shi2_netname")?;
    let share_type = reader.read_u32("shi2_type")?;
    let remark_referent = reader.read_u32("shi2_remark")?;
    let permissions = reader.read_u32("shi2_permissions")?;
    let max_uses = reader.read_u32("shi2_max_uses")?;
    let current_uses = reader.read_u32("shi2_current_uses")?;
    let path_referent = reader.read_u32("shi2_path")?;
    let password_referent = reader.read_u32("shi2_passwd")?;

    let name = if name_referent != 0 {
        reader.read_wide_string("shi2_netname")?
    } else {
        return Err(CoreError::InvalidResponse(
            "NetrShareGetInfo did not return a share name",
        ));
    };
    let remark = if remark_referent != 0 {
        Some(reader.read_wide_string("shi2_remark")?)
    } else {
        None
    };
    let path = if path_referent != 0 {
        Some(reader.read_wide_string("shi2_path")?)
    } else {
        None
    };
    let password = if password_referent != 0 {
        Some(reader.read_wide_string("shi2_passwd")?)
    } else {
        None
    };

    let status = reader.read_u32("NetrShareGetInfoStatus")?;
    if status != 0 {
        return Err(CoreError::RemoteOperation {
            operation: "NetrShareGetInfo",
            code: status,
        });
    }

    Ok(ShareInfo2 {
        name,
        share_type,
        remark,
        permissions,
        max_uses,
        current_uses,
        path,
        password,
    })
}

#[cfg(test)]
fn parse_server_get_info_level101_response(response: &[u8]) -> Result<ServerInfo101, CoreError> {
    parse_server_get_info_level101_response_with_limits(response, ResourceLimits::default())
}

fn parse_server_get_info_level101_response_with_limits(
    response: &[u8],
    limits: ResourceLimits,
) -> Result<ServerInfo101, CoreError> {
    let mut reader = NdrReader::with_limits(response, limits);
    let level = reader.read_u32("Level")?;
    if level != 101 {
        return Err(CoreError::InvalidResponse(
            "NetrServerGetInfo returned an unexpected union level",
        ));
    }
    let info_referent = reader.read_u32("ServerInfo101")?;
    if info_referent == 0 {
        return Err(CoreError::InvalidResponse(
            "NetrServerGetInfo did not return a SERVER_INFO_101 buffer",
        ));
    }

    let platform_id = reader.read_u32("sv101_platform_id")?;
    let name_referent = reader.read_u32("sv101_name")?;
    let version_major = reader.read_u32("sv101_version_major")?;
    let version_minor = reader.read_u32("sv101_version_minor")?;
    let server_type = reader.read_u32("sv101_type")?;
    let comment_referent = reader.read_u32("sv101_comment")?;

    let name = if name_referent != 0 {
        reader.read_wide_string("sv101_name")?
    } else {
        return Err(CoreError::InvalidResponse(
            "NetrServerGetInfo did not return a server name",
        ));
    };
    let comment = if comment_referent != 0 {
        Some(reader.read_wide_string("sv101_comment")?)
    } else {
        None
    };

    let status = reader.read_u32("NetrServerGetInfoStatus")?;
    if status != 0 {
        return Err(CoreError::RemoteOperation {
            operation: "NetrServerGetInfo",
            code: status,
        });
    }

    Ok(ServerInfo101 {
        platform_id,
        name,
        version_major,
        version_minor,
        server_type,
        comment,
    })
}

#[cfg(test)]
fn parse_server_get_info_level103_response(response: &[u8]) -> Result<ServerInfo103, CoreError> {
    parse_server_get_info_level103_response_with_limits(response, ResourceLimits::default())
}

fn parse_server_get_info_level103_response_with_limits(
    response: &[u8],
    limits: ResourceLimits,
) -> Result<ServerInfo103, CoreError> {
    if response.len() == 8 {
        if u32::from_le_bytes(response[0..4].try_into().expect("level slice")) != 103 {
            return Err(CoreError::InvalidResponse(
                "NetrServerGetInfo returned an unexpected union level",
            ));
        }
        return Err(CoreError::RemoteOperation {
            operation: "NetrServerGetInfo",
            code: u32::from_le_bytes(response[4..8].try_into().expect("status slice")),
        });
    }
    let mut reader = NdrReader::with_limits(response, limits);
    let level = reader.read_u32("Level")?;
    if level != 103 {
        return Err(CoreError::InvalidResponse(
            "NetrServerGetInfo returned an unexpected union level",
        ));
    }
    let info_referent = reader.read_u32("ServerInfo103")?;
    if info_referent == 0 {
        return Err(CoreError::InvalidResponse(
            "NetrServerGetInfo did not return a SERVER_INFO_103 buffer",
        ));
    }

    let platform_id = reader.read_u32("sv103_platform_id")?;
    let name_referent = reader.read_u32("sv103_name")?;
    let version_major = reader.read_u32("sv103_version_major")?;
    let version_minor = reader.read_u32("sv103_version_minor")?;
    let server_type = reader.read_u32("sv103_type")?;
    let comment_referent = reader.read_u32("sv103_comment")?;
    let users = reader.read_u32("sv103_users")?;
    let disconnect_minutes = reader.read_i32("sv103_disc")?;
    let hidden = reader.read_u32("sv103_hidden")? != 0;
    let announce = reader.read_u32("sv103_announce")?;
    let announce_delta = reader.read_u32("sv103_anndelta")?;
    let licenses = reader.read_u32("sv103_licenses")?;
    let userpath_referent = reader.read_u32("sv103_userpath")?;
    let capabilities = reader.read_u32("sv103_capabilities")?;

    let name = if name_referent != 0 {
        reader.read_wide_string("sv103_name")?
    } else {
        return Err(CoreError::InvalidResponse(
            "NetrServerGetInfo did not return a server name",
        ));
    };
    let comment = if comment_referent != 0 {
        Some(reader.read_wide_string("sv103_comment")?)
    } else {
        None
    };
    let user_path = if userpath_referent != 0 {
        Some(reader.read_wide_string("sv103_userpath")?)
    } else {
        None
    };

    let status = reader.read_u32("NetrServerGetInfoStatus")?;
    if status != 0 {
        return Err(CoreError::RemoteOperation {
            operation: "NetrServerGetInfo",
            code: status,
        });
    }

    Ok(ServerInfo103 {
        platform_id,
        name,
        version_major,
        version_minor,
        server_type,
        comment,
        users,
        disconnect_minutes,
        hidden,
        announce,
        announce_delta,
        licenses,
        user_path,
        capabilities,
    })
}

#[derive(Debug)]
struct ShareInfo1Stub {
    name_referent: u32,
    share_type: u32,
    remark_referent: u32,
    name: String,
    remark: Option<String>,
}

#[derive(Debug)]
struct SessionInfoStub {
    client_name_referent: u32,
    username_referent: u32,
    time: u32,
    idle_time: u32,
    client_name: Option<String>,
    username: Option<String>,
}

struct NdrReader<'a> {
    bytes: &'a [u8],
    offset: usize,
    max_entries: usize,
    max_string_units: usize,
}

impl<'a> NdrReader<'a> {
    fn with_limits(bytes: &'a [u8], limits: ResourceLimits) -> Self {
        Self {
            bytes,
            offset: 0,
            max_entries: limits.max_ndr_entries,
            max_string_units: limits.max_ndr_string_units,
        }
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

    fn read_i32(&mut self, field: &'static str) -> Result<i32, CoreError> {
        self.align(4, field)?;
        if self.remaining() < 4 {
            return Err(CoreError::InvalidResponse(field));
        }
        let value = i32::from_le_bytes(
            self.bytes[self.offset..self.offset + 4]
                .try_into()
                .expect("i32 slice should decode"),
        );
        self.offset += 4;
        Ok(value)
    }

    fn validate_collection(
        &self,
        count: usize,
        minimum_wire_size: usize,
        field: &'static str,
    ) -> Result<(), CoreError> {
        if count > self.max_entries {
            return Err(CoreError::ResourceLimit {
                resource: field,
                requested: count as u64,
                maximum: self.max_entries as u64,
            });
        }
        let minimum = count
            .checked_mul(minimum_wire_size)
            .ok_or(CoreError::InvalidResponse(field))?;
        if minimum > self.remaining() {
            return Err(CoreError::InvalidResponse(field));
        }
        Ok(())
    }

    fn read_wide_string(&mut self, field: &'static str) -> Result<String, CoreError> {
        self.align(4, field)?;
        let max_count = self.read_u32(field)? as usize;
        let offset = self.read_u32(field)? as usize;
        let actual_count = self.read_u32(field)? as usize;
        if offset > max_count || actual_count > max_count.saturating_sub(offset) {
            return Err(CoreError::InvalidResponse(field));
        }
        if actual_count > self.max_string_units {
            return Err(CoreError::ResourceLimit {
                resource: field,
                requested: actual_count as u64,
                maximum: self.max_string_units as u64,
            });
        }
        let wire_size = actual_count
            .checked_mul(2)
            .ok_or(CoreError::InvalidResponse(field))?;
        if wire_size > self.remaining() {
            return Err(CoreError::InvalidResponse(field));
        }

        let mut code_units = Vec::new();
        code_units
            .try_reserve_exact(actual_count)
            .map_err(|_| CoreError::AllocationFailed(field))?;
        for _ in 0..actual_count {
            code_units.push(self.read_u16(field)?);
        }
        self.align(4, field)?;

        if code_units.last().copied() == Some(0) {
            code_units.pop();
        }
        crate::bounded::utf16_string(&code_units, field, "failed to decode srvsvc UTF-16 string")
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

    fn write_u32(&mut self, value: u32) {
        self.align(4);
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn write_ref_wide_string(&mut self, value: &str) {
        self.align(4);
        let mut encoded = value.encode_utf16().collect::<Vec<_>>();
        encoded.push(0);
        let count = encoded.len() as u32;
        self.bytes.extend_from_slice(&count.to_le_bytes());
        self.bytes.extend_from_slice(&0_u32.to_le_bytes());
        self.bytes.extend_from_slice(&count.to_le_bytes());
        for code_unit in encoded {
            self.bytes.extend_from_slice(&code_unit.to_le_bytes());
        }
        self.align(4);
    }

    fn align(&mut self, alignment: usize) {
        let padding = (alignment - (self.bytes.len() % alignment)) % alignment;
        self.bytes.resize(self.bytes.len() + padding, 0);
    }
}

#[cfg(test)]
mod tests {
    use smolder_proto::rpc::{
        BindAckPdu, BindAckResult, Packet, PacketFlags, ResponsePdu, SyntaxId,
    };

    use super::{
        encode_remote_tod_request, encode_server_get_info_level101_request,
        encode_server_get_info_level103_request, encode_session_enum_level10_request,
        encode_session_enum_page_request, encode_share_enum_level1_page_request,
        encode_share_enum_level1_request, encode_share_get_info_level2_request,
        parse_remote_tod_response, parse_server_get_info_level101_response,
        parse_server_get_info_level103_response, parse_session_enum_level10_response,
        parse_session_enum_page_with_limits, parse_share_enum_level1_page_with_limits,
        parse_share_enum_level1_response, parse_share_get_info_level2_response, ServerInfo101,
        ServerInfo103, SessionInfo10, ShareInfo1, ShareInfo2, SrvsvcClient, TimeOfDayInfo,
        ERROR_MORE_DATA,
    };
    use crate::error::CoreError;
    use crate::policy::ResourceLimits;
    use crate::rpc::PipeRpcClient;
    use crate::test_support::{
        captured_rpc_packets, open_scripted_pipe, rpc_read_frame, successful_flush_frame,
        successful_write_frame,
    };

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

        fn write_i32(&mut self, value: i32) {
            self.align(4);
            self.bytes.extend_from_slice(&value.to_le_bytes());
        }

        fn write_wide_string(&mut self, value: &str) {
            self.align(4);
            let mut encoded = value.encode_utf16().collect::<Vec<_>>();
            encoded.push(0);
            let count = encoded.len() as u32;
            self.bytes.extend_from_slice(&count.to_le_bytes());
            self.bytes.extend_from_slice(&0_u32.to_le_bytes());
            self.bytes.extend_from_slice(&count.to_le_bytes());
            for code_unit in encoded {
                self.bytes.extend_from_slice(&code_unit.to_le_bytes());
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
    fn remote_tod_request_uses_null_server_pointer() {
        assert_eq!(encode_remote_tod_request(), 0_u32.to_le_bytes());
    }

    #[test]
    fn share_enum_level1_request_uses_null_server_and_max_preferred_length() {
        assert_eq!(
            encode_share_enum_level1_request(),
            [
                0_u32.to_le_bytes(),
                1_u32.to_le_bytes(),
                1_u32.to_le_bytes(),
                1_u32.to_le_bytes(),
                0_u32.to_le_bytes(),
                0_u32.to_le_bytes(),
                u32::MAX.to_le_bytes(),
                0_u32.to_le_bytes()
            ]
            .concat()
        );
    }

    #[test]
    fn session_enum_level10_request_uses_null_filters_and_max_preferred_length() {
        assert_eq!(
            encode_session_enum_level10_request(),
            [
                0_u32.to_le_bytes(),
                0_u32.to_le_bytes(),
                0_u32.to_le_bytes(),
                10_u32.to_le_bytes(),
                10_u32.to_le_bytes(),
                1_u32.to_le_bytes(),
                0_u32.to_le_bytes(),
                0_u32.to_le_bytes(),
                u32::MAX.to_le_bytes(),
                0_u32.to_le_bytes(),
            ]
            .concat()
        );
    }

    #[test]
    fn parse_remote_tod_response_decodes_time_fields() {
        let mut response = vec![0_u8; 56];
        response[0..4].copy_from_slice(&1_u32.to_le_bytes());
        response[12..16].copy_from_slice(&13_u32.to_le_bytes());
        response[16..20].copy_from_slice(&37_u32.to_le_bytes());
        response[20..24].copy_from_slice(&42_u32.to_le_bytes());
        response[36..40].copy_from_slice(&30_u32.to_le_bytes());
        response[40..44].copy_from_slice(&3_u32.to_le_bytes());
        response[44..48].copy_from_slice(&2026_u32.to_le_bytes());
        response[48..52].copy_from_slice(&1_u32.to_le_bytes());

        assert_eq!(
            parse_remote_tod_response(&response).expect("response should decode"),
            TimeOfDayInfo {
                hours: 13,
                minutes: 37,
                seconds: 42,
                day: 30,
                month: 3,
                year: 2026,
                weekday: 1,
            }
        );
    }

    #[test]
    fn parse_remote_tod_response_rejects_null_pointer() {
        let response = vec![0_u8; 56];
        let error = parse_remote_tod_response(&response).expect_err("null pointer should fail");
        assert!(matches!(error, CoreError::InvalidResponse(_)));
    }

    #[test]
    fn parse_share_enum_level1_response_decodes_entries() {
        let mut writer = ResponseWriter::new();
        writer.write_u32(1);
        writer.write_u32(1);
        let container_referent = writer.next_referent();
        writer.write_u32(container_referent);
        writer.write_u32(2);
        let array_referent = writer.next_referent();
        writer.write_u32(array_referent);
        writer.write_u32(2);

        let docs_name = writer.next_referent();
        let docs_remark = writer.next_referent();
        writer.write_u32(docs_name);
        writer.write_u32(0);
        writer.write_u32(docs_remark);

        let ipc_name = writer.next_referent();
        writer.write_u32(ipc_name);
        writer.write_u32(0x8000_0003);
        writer.write_u32(0);

        writer.write_wide_string("Docs");
        writer.write_wide_string("Documentation");
        writer.write_wide_string("IPC$");
        writer.write_u32(2);
        writer.write_u32(0);
        writer.write_u32(0);

        let response = writer.into_bytes();
        assert_eq!(
            parse_share_enum_level1_response(&response).expect("response should decode"),
            vec![
                ShareInfo1 {
                    name: "Docs".to_owned(),
                    share_type: 0,
                    remark: Some("Documentation".to_owned()),
                },
                ShareInfo1 {
                    name: "IPC$".to_owned(),
                    share_type: 0x8000_0003,
                    remark: None,
                },
            ]
        );

        let error = parse_share_enum_level1_page_with_limits(
            &response,
            ResourceLimits {
                max_ndr_entries: 1,
                ..ResourceLimits::default()
            },
        )
        .err()
        .expect("configured NDR entry maximum should be enforced before allocation");
        assert!(matches!(
            error,
            CoreError::ResourceLimit {
                resource: "NetrShareEnum entries",
                requested: 2,
                maximum: 1,
            }
        ));

        let error = parse_share_enum_level1_page_with_limits(
            &response,
            ResourceLimits {
                max_ndr_string_units: 2,
                ..ResourceLimits::default()
            },
        )
        .err()
        .expect("configured NDR string maximum should be enforced before allocation");
        assert!(matches!(
            error,
            CoreError::ResourceLimit {
                resource: "shi1_netname",
                maximum: 2,
                ..
            }
        ));
    }

    #[test]
    fn parse_share_enum_level1_response_decodes_standalone_samba_fixture() {
        let response = [
            0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00, 0x02, 0x00,
            0x00, 0x00, 0x08, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x02, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x02, 0x00, 0x14, 0x00, 0x02, 0x00, 0x03, 0x00,
            0x00, 0x80, 0x18, 0x00, 0x02, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x06, 0x00, 0x00, 0x00, 0x73, 0x00, 0x68, 0x00, 0x61, 0x00, 0x72, 0x00, 0x65, 0x00,
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00,
            0x00, 0x00, 0x49, 0x00, 0x50, 0x00, 0x43, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x29, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x29, 0x00, 0x00, 0x00, 0x49, 0x00,
            0x50, 0x00, 0x43, 0x00, 0x20, 0x00, 0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00,
            0x69, 0x00, 0x63, 0x00, 0x65, 0x00, 0x20, 0x00, 0x28, 0x00, 0x53, 0x00, 0x6d, 0x00,
            0x6f, 0x00, 0x6c, 0x00, 0x64, 0x00, 0x65, 0x00, 0x72, 0x00, 0x20, 0x00, 0x53, 0x00,
            0x61, 0x00, 0x6d, 0x00, 0x62, 0x00, 0x61, 0x00, 0x20, 0x00, 0x54, 0x00, 0x65, 0x00,
            0x73, 0x00, 0x74, 0x00, 0x20, 0x00, 0x46, 0x00, 0x69, 0x00, 0x78, 0x00, 0x74, 0x00,
            0x75, 0x00, 0x72, 0x00, 0x65, 0x00, 0x29, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
            0x00, 0x00, 0x1c, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        assert_eq!(
            parse_share_enum_level1_response(&response).expect("Samba response should decode"),
            vec![
                ShareInfo1 {
                    name: "share".to_owned(),
                    share_type: 0,
                    remark: Some(String::new()),
                },
                ShareInfo1 {
                    name: "IPC$".to_owned(),
                    share_type: 0x8000_0003,
                    remark: Some("IPC Service (Smolder Samba Test Fixture)".to_owned()),
                },
            ]
        );
    }

    #[test]
    fn share_enumeration_rejects_huge_count_before_allocation() {
        let response = [
            1u32.to_le_bytes(),
            1u32.to_le_bytes(),
            1u32.to_le_bytes(),
            u32::MAX.to_le_bytes(),
            1u32.to_le_bytes(),
            u32::MAX.to_le_bytes(),
        ]
        .concat();

        let error = parse_share_enum_level1_response(&response)
            .expect_err("tiny response with huge count must be rejected");
        assert!(matches!(error, CoreError::ResourceLimit { .. }));
    }

    #[test]
    fn direct_share_page_parser_does_not_return_partial_more_data() {
        let response = share_page("Docs", Some(7), ERROR_MORE_DATA);
        let error = parse_share_enum_level1_response(&response)
            .expect_err("one-page helper must not hide pagination status");
        assert!(matches!(
            error,
            CoreError::RemoteOperation {
                operation: "NetrShareEnum",
                code: ERROR_MORE_DATA
            }
        ));
    }

    #[tokio::test]
    async fn share_enumeration_paginates_until_terminal_status() {
        let bind_ack = Packet::BindAck(BindAckPdu {
            call_id: 1,
            flags: PacketFlags::FIRST_FRAGMENT | PacketFlags::LAST_FRAGMENT,
            max_xmit_frag: 4_280,
            max_recv_frag: 4_280,
            assoc_group_id: 0,
            secondary_address: b"\\PIPE\\srvsvc\0".to_vec(),
            result: BindAckResult {
                result: 0,
                reason: 0,
                transfer_syntax: SyntaxId::NDR32,
            },
            auth_verifier: None,
        });
        let first_stub = share_page("Docs", Some(7), ERROR_MORE_DATA);
        let second_stub = share_page("IPC$", None, 0);
        let (pipe, writes) = open_scripted_pipe(
            "srvsvc",
            vec![
                successful_write_frame(4, 72),
                successful_flush_frame(5),
                rpc_read_frame(bind_ack, 6),
                successful_write_frame(7, 56),
                successful_flush_frame(8),
                rpc_read_frame(
                    Packet::Response(ResponsePdu {
                        call_id: 2,
                        flags: PacketFlags::FIRST_FRAGMENT | PacketFlags::LAST_FRAGMENT,
                        alloc_hint: first_stub.len() as u32,
                        context_id:
                            SrvsvcClient::<crate::test_support::ScriptedTransport>::CONTEXT_ID,
                        cancel_count: 0,
                        stub_data: first_stub,
                        auth_verifier: None,
                    }),
                    9,
                ),
                successful_write_frame(10, 60),
                successful_flush_frame(11),
                rpc_read_frame(
                    Packet::Response(ResponsePdu {
                        call_id: 3,
                        flags: PacketFlags::FIRST_FRAGMENT | PacketFlags::LAST_FRAGMENT,
                        alloc_hint: second_stub.len() as u32,
                        context_id:
                            SrvsvcClient::<crate::test_support::ScriptedTransport>::CONTEXT_ID,
                        cancel_count: 0,
                        stub_data: second_stub,
                        auth_verifier: None,
                    }),
                    12,
                ),
            ],
        )
        .await;
        let mut client = SrvsvcClient::bind(PipeRpcClient::new(pipe))
            .await
            .expect("srvsvc bind should succeed");

        let shares = client
            .share_enum_level1()
            .await
            .expect("all pages should be returned");
        assert_eq!(
            shares
                .iter()
                .map(|share| share.name.as_str())
                .collect::<Vec<_>>(),
            vec!["Docs", "IPC$"]
        );

        let requests = captured_rpc_packets(&writes);
        let Packet::Request(second_request) = &requests[2] else {
            panic!("third captured RPC packet should be the second enumeration request");
        };
        assert_eq!(
            second_request.stub_data,
            encode_share_enum_level1_page_request(Some(7))
        );
    }

    #[test]
    fn parse_share_enum_level1_response_accepts_empty_remarks() {
        let mut writer = ResponseWriter::new();
        writer.write_u32(1);
        writer.write_u32(1);
        let container_referent = writer.next_referent();
        writer.write_u32(container_referent);
        writer.write_u32(1);
        let array_referent = writer.next_referent();
        writer.write_u32(array_referent);
        writer.write_u32(1);

        let docs_name = writer.next_referent();
        let docs_remark = writer.next_referent();
        writer.write_u32(docs_name);
        writer.write_u32(0);
        writer.write_u32(docs_remark);

        writer.write_wide_string("Docs");
        writer.write_u32(0);
        writer.write_u32(0);
        writer.write_u32(0);
        writer.write_u32(1);
        writer.write_u32(0);
        writer.write_u32(0);

        assert_eq!(
            parse_share_enum_level1_response(&writer.into_bytes()).expect("response should decode"),
            vec![ShareInfo1 {
                name: "Docs".to_owned(),
                share_type: 0,
                remark: Some(String::new()),
            }]
        );
    }

    fn share_page(name: &str, resume_handle: Option<u32>, status: u32) -> Vec<u8> {
        let mut writer = ResponseWriter::new();
        writer.write_u32(1);
        writer.write_u32(1);
        let container_referent = writer.next_referent();
        writer.write_u32(container_referent);
        writer.write_u32(1);
        let buffer_referent = writer.next_referent();
        writer.write_u32(buffer_referent);
        writer.write_u32(1);
        let name_referent = writer.next_referent();
        writer.write_u32(name_referent);
        writer.write_u32(0);
        writer.write_u32(0);
        writer.write_wide_string(name);
        writer.write_u32(2);
        writer.write_u32(u32::from(resume_handle.is_some()));
        if let Some(resume_handle) = resume_handle {
            writer.write_u32(resume_handle);
        }
        writer.write_u32(status);
        writer.into_bytes()
    }

    fn samba_session_level10_invalid_response() -> Vec<u8> {
        vec![
            0x0a, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x7c, 0x00, 0x00, 0x00,
        ]
    }

    fn samba_session_level1_response() -> Vec<u8> {
        vec![
            0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x08, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x02, 0x00,
            0x10, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x0b, 0x00, 0x00, 0x00, 0x31, 0x00, 0x37, 0x00, 0x32, 0x00, 0x2e, 0x00, 0x32, 0x00,
            0x31, 0x00, 0x2e, 0x00, 0x30, 0x00, 0x2e, 0x00, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x73, 0x00,
            0x6d, 0x00, 0x6f, 0x00, 0x6c, 0x00, 0x64, 0x00, 0x65, 0x00, 0x72, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]
    }

    #[test]
    fn parse_session_enum_level1_response_decodes_standalone_samba_fixture() {
        let page = parse_session_enum_page_with_limits(
            &samba_session_level1_response(),
            1,
            ResourceLimits::default(),
        )
        .expect("Samba level-1 response should decode");

        assert_eq!(
            page.entries,
            vec![SessionInfo10 {
                client_name: Some("172.21.0.1".to_owned()),
                username: Some("smolder".to_owned()),
                time: 0,
                idle_time: 0,
            }]
        );
        assert_eq!(page.status, 0);
    }

    #[test]
    fn parse_session_enum_level10_response_decodes_entries() {
        let mut writer = ResponseWriter::new();
        writer.write_u32(10);
        writer.write_u32(10);
        let container_referent = writer.next_referent();
        writer.write_u32(container_referent);
        writer.write_u32(2);
        let array_referent = writer.next_referent();
        writer.write_u32(array_referent);
        writer.write_u32(2);

        let client_ref = writer.next_referent();
        let user_ref = writer.next_referent();
        writer.write_u32(client_ref);
        writer.write_u32(user_ref);
        writer.write_u32(120);
        writer.write_u32(4);

        writer.write_u32(0);
        writer.write_u32(0);
        writer.write_u32(30);
        writer.write_u32(7);

        writer.write_wide_string(r"\\10.0.0.5");
        writer.write_wide_string("smolder");
        writer.write_u32(2);
        writer.write_u32(0);
        writer.write_u32(0);

        assert_eq!(
            parse_session_enum_level10_response(&writer.into_bytes())
                .expect("response should decode"),
            vec![
                SessionInfo10 {
                    client_name: Some(r"\\10.0.0.5".to_owned()),
                    username: Some("smolder".to_owned()),
                    time: 120,
                    idle_time: 4,
                },
                SessionInfo10 {
                    client_name: None,
                    username: None,
                    time: 30,
                    idle_time: 7,
                },
            ]
        );
    }

    #[tokio::test]
    async fn session_enumeration_falls_back_to_level1_when_samba_rejects_level10() {
        let bind_ack = Packet::BindAck(BindAckPdu {
            call_id: 1,
            flags: PacketFlags::FIRST_FRAGMENT | PacketFlags::LAST_FRAGMENT,
            max_xmit_frag: 4_280,
            max_recv_frag: 4_280,
            assoc_group_id: 0,
            secondary_address: b"\\PIPE\\srvsvc\0".to_vec(),
            result: BindAckResult {
                result: 0,
                reason: 0,
                transfer_syntax: SyntaxId::NDR32,
            },
            auth_verifier: None,
        });
        let level10 = samba_session_level10_invalid_response();
        let level1 = samba_session_level1_response();
        let (pipe, writes) = open_scripted_pipe(
            "srvsvc",
            vec![
                successful_write_frame(4, 72),
                successful_flush_frame(5),
                rpc_read_frame(bind_ack, 6),
                successful_write_frame(7, 64),
                successful_flush_frame(8),
                rpc_read_frame(
                    Packet::Response(ResponsePdu {
                        call_id: 2,
                        flags: PacketFlags::FIRST_FRAGMENT | PacketFlags::LAST_FRAGMENT,
                        alloc_hint: level10.len() as u32,
                        context_id:
                            SrvsvcClient::<crate::test_support::ScriptedTransport>::CONTEXT_ID,
                        cancel_count: 0,
                        stub_data: level10,
                        auth_verifier: None,
                    }),
                    9,
                ),
                successful_write_frame(10, 64),
                successful_flush_frame(11),
                rpc_read_frame(
                    Packet::Response(ResponsePdu {
                        call_id: 3,
                        flags: PacketFlags::FIRST_FRAGMENT | PacketFlags::LAST_FRAGMENT,
                        alloc_hint: level1.len() as u32,
                        context_id:
                            SrvsvcClient::<crate::test_support::ScriptedTransport>::CONTEXT_ID,
                        cancel_count: 0,
                        stub_data: level1,
                        auth_verifier: None,
                    }),
                    12,
                ),
            ],
        )
        .await;
        let mut client = SrvsvcClient::bind(PipeRpcClient::new(pipe))
            .await
            .expect("srvsvc bind should succeed");

        assert_eq!(
            client
                .session_enum_level10()
                .await
                .expect("Samba level-1 fallback should succeed"),
            vec![SessionInfo10 {
                client_name: Some("172.21.0.1".to_owned()),
                username: Some("smolder".to_owned()),
                time: 0,
                idle_time: 0,
            }]
        );

        let requests = captured_rpc_packets(&writes);
        let Packet::Request(level10_request) = &requests[1] else {
            panic!("second packet should be the level-10 request");
        };
        let Packet::Request(level1_request) = &requests[2] else {
            panic!("third packet should be the level-1 fallback request");
        };
        assert_eq!(
            level10_request.stub_data,
            encode_session_enum_page_request(10, None)
        );
        assert_eq!(
            level1_request.stub_data,
            encode_session_enum_page_request(1, None)
        );
    }

    #[test]
    fn share_get_info_level2_request_encodes_server_null_and_ref_string() {
        assert_eq!(
            encode_share_get_info_level2_request("IPC$").expect("request should encode"),
            [
                0_u32.to_le_bytes().to_vec(),
                5_u32.to_le_bytes().to_vec(),
                0_u32.to_le_bytes().to_vec(),
                5_u32.to_le_bytes().to_vec(),
                b"I\0P\0C\0$\0\0\0".to_vec(),
                0_u16.to_le_bytes().to_vec(),
                2_u32.to_le_bytes().to_vec(),
            ]
            .concat()
        );
    }

    #[test]
    fn parse_share_get_info_level2_response_decodes_entry() {
        let mut writer = ResponseWriter::new();
        writer.write_u32(2);
        let info_ref = writer.next_referent();
        let name_ref = writer.next_referent();
        let remark_ref = writer.next_referent();
        let path_ref = writer.next_referent();
        writer.write_u32(info_ref);
        writer.write_u32(name_ref);
        writer.write_u32(0x8000_0003);
        writer.write_u32(remark_ref);
        writer.write_u32(0);
        writer.write_u32(u32::MAX);
        writer.write_u32(1);
        writer.write_u32(path_ref);
        writer.write_u32(0);
        writer.write_wide_string("IPC$");
        writer.write_wide_string("Remote IPC");
        writer.write_wide_string(r"C:\Windows");
        writer.write_u32(0);

        assert_eq!(
            parse_share_get_info_level2_response(&writer.into_bytes())
                .expect("response should decode"),
            ShareInfo2 {
                name: "IPC$".to_owned(),
                share_type: 0x8000_0003,
                remark: Some("Remote IPC".to_owned()),
                permissions: 0,
                max_uses: u32::MAX,
                current_uses: 1,
                path: Some(r"C:\Windows".to_owned()),
                password: None,
            }
        );
    }

    #[test]
    fn share_info_debug_redacts_legacy_password() {
        const SECRET: &str = "AUDIT-SUPER-SECRET";
        let info = ShareInfo2 {
            name: "legacy".to_owned(),
            share_type: 0,
            remark: None,
            permissions: 0,
            max_uses: 1,
            current_uses: 0,
            path: None,
            password: Some(SECRET.to_owned()),
        };

        let debug = format!("{info:?}");
        assert!(!debug.contains(SECRET));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn server_get_info_level101_request_uses_null_server_and_expected_level() {
        assert_eq!(
            encode_server_get_info_level101_request(),
            [0_u32.to_le_bytes(), 101_u32.to_le_bytes()].concat()
        );
    }

    #[test]
    fn server_get_info_level103_request_uses_null_server_and_expected_level() {
        assert_eq!(
            encode_server_get_info_level103_request(),
            [0_u32.to_le_bytes(), 103_u32.to_le_bytes()].concat()
        );
    }

    #[test]
    fn parse_server_get_info_level101_response_decodes_entry() {
        let mut writer = ResponseWriter::new();
        writer.write_u32(101);
        let info_ref = writer.next_referent();
        let name_ref = writer.next_referent();
        let comment_ref = writer.next_referent();
        writer.write_u32(info_ref);
        writer.write_u32(500);
        writer.write_u32(name_ref);
        writer.write_u32(6);
        writer.write_u32(3);
        writer.write_u32(0x0000_0002);
        writer.write_u32(comment_ref);
        writer.write_wide_string("files1");
        writer.write_wide_string("Samba file server");
        writer.write_u32(0);

        assert_eq!(
            parse_server_get_info_level101_response(&writer.into_bytes())
                .expect("response should decode"),
            ServerInfo101 {
                platform_id: 500,
                name: "files1".to_owned(),
                version_major: 6,
                version_minor: 3,
                server_type: 0x0000_0002,
                comment: Some("Samba file server".to_owned()),
            }
        );
    }

    #[test]
    fn parse_server_get_info_level103_response_decodes_entry() {
        let mut writer = ResponseWriter::new();
        writer.write_u32(103);
        let info_ref = writer.next_referent();
        let name_ref = writer.next_referent();
        let comment_ref = writer.next_referent();
        let userpath_ref = writer.next_referent();
        writer.write_u32(info_ref);
        writer.write_u32(501);
        writer.write_u32(name_ref);
        writer.write_u32(10);
        writer.write_u32(0);
        writer.write_u32(0x0000_0002);
        writer.write_u32(comment_ref);
        writer.write_u32(250);
        writer.write_i32(-15);
        writer.write_u32(1);
        writer.write_u32(60);
        writer.write_u32(5);
        writer.write_u32(0);
        writer.write_u32(userpath_ref);
        writer.write_u32(0x0000_0003);
        writer.write_wide_string("files1");
        writer.write_wide_string("Samba file server");
        writer.write_wide_string(r"C:\Users");
        writer.write_u32(0);

        assert_eq!(
            parse_server_get_info_level103_response(&writer.into_bytes())
                .expect("response should decode"),
            ServerInfo103 {
                platform_id: 501,
                name: "files1".to_owned(),
                version_major: 10,
                version_minor: 0,
                server_type: 0x0000_0002,
                comment: Some("Samba file server".to_owned()),
                users: 250,
                disconnect_minutes: -15,
                hidden: true,
                announce: 60,
                announce_delta: 5,
                licenses: 0,
                user_path: Some(r"C:\Users".to_owned()),
                capabilities: 0x0000_0003,
            }
        );
    }
}
