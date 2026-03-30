//! Typed `srvsvc` DCE/RPC helpers built on top of named pipes.

use smolder_proto::rpc::{SyntaxId, Uuid};

use crate::error::CoreError;
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
const NETR_SHARE_ENUM_OPNUM: u16 = 15;
const NETR_REMOTE_TOD_OPNUM: u16 = 28;
const MAX_PREFERRED_LENGTH: u32 = u32::MAX;

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
#[derive(Debug, Clone, PartialEq, Eq)]
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
    T: crate::transport::Transport + Send,
{
    /// Performs the default `srvsvc` bind on a named-pipe RPC transport.
    pub async fn bind(mut rpc: PipeRpcClient<T>) -> Result<Self, CoreError> {
        rpc.bind_context(Self::CONTEXT_ID, Self::SYNTAX).await?;
        Ok(Self::new(rpc))
    }

    /// Calls `NetrRemoteTOD` and returns the decoded time-of-day structure.
    pub async fn remote_tod(&mut self) -> Result<TimeOfDayInfo, CoreError> {
        let response = self
            .rpc
            .call(self.context_id, NETR_REMOTE_TOD_OPNUM, encode_remote_tod_request())
            .await?;
        parse_remote_tod_response(&response)
    }

    /// Calls `NetrShareEnum` at information level 1.
    pub async fn share_enum_level1(&mut self) -> Result<Vec<ShareInfo1>, CoreError> {
        let response = self
            .rpc
            .call(
                self.context_id,
                NETR_SHARE_ENUM_OPNUM,
                encode_share_enum_level1_request(),
            )
            .await?;
        parse_share_enum_level1_response(&response)
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
        parse_share_get_info_level2_response(&response)
    }
}

fn encode_remote_tod_request() -> Vec<u8> {
    0_u32.to_le_bytes().to_vec()
}

fn encode_share_enum_level1_request() -> Vec<u8> {
    let mut stub = Vec::with_capacity(24);
    stub.extend_from_slice(&0_u32.to_le_bytes());
    stub.extend_from_slice(&1_u32.to_le_bytes());
    stub.extend_from_slice(&1_u32.to_le_bytes());
    stub.extend_from_slice(&0_u32.to_le_bytes());
    stub.extend_from_slice(&0_u32.to_le_bytes());
    stub.extend_from_slice(&MAX_PREFERRED_LENGTH.to_le_bytes());
    stub.extend_from_slice(&0_u32.to_le_bytes());
    stub
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

fn parse_share_enum_level1_response(response: &[u8]) -> Result<Vec<ShareInfo1>, CoreError> {
    let mut reader = NdrReader::new(response);
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

    let entries_read = reader.read_u32("EntriesRead")? as usize;
    let buffer_referent = reader.read_u32("BufferReferent")?;
    let mut entries = Vec::with_capacity(entries_read);
    if buffer_referent != 0 {
        let max_count = reader.read_u32("BufferMaxCount")? as usize;
        if max_count < entries_read {
            return Err(CoreError::InvalidResponse(
                "NetrShareEnum buffer count was smaller than entries read",
            ));
        }

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
        }

        for entry in &mut entries {
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

    if reader.remaining() >= 4 {
        let resume_handle_referent = reader.read_u32("ResumeHandleReferent")?;
        if resume_handle_referent != 0 && reader.remaining() >= 4 {
            let _ = reader.read_u32("ResumeHandleValue")?;
        }
    }

    Ok(entries
        .into_iter()
        .map(|entry| ShareInfo1 {
            name: entry.name,
            share_type: entry.share_type,
            remark: entry.remark,
        })
        .collect())
}

fn parse_share_get_info_level2_response(response: &[u8]) -> Result<ShareInfo2, CoreError> {
    let mut reader = NdrReader::new(response);
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

#[derive(Debug)]
struct ShareInfo1Stub {
    name_referent: u32,
    share_type: u32,
    remark_referent: u32,
    name: String,
    remark: Option<String>,
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

    fn read_wide_string(&mut self, field: &'static str) -> Result<String, CoreError> {
        self.align(4, field)?;
        let max_count = self.read_u32(field)? as usize;
        let offset = self.read_u32(field)? as usize;
        let actual_count = self.read_u32(field)? as usize;
        if offset != 0 || actual_count == 0 || max_count < actual_count {
            return Err(CoreError::InvalidResponse(field));
        }

        let mut code_units = Vec::with_capacity(actual_count);
        for _ in 0..actual_count {
            code_units.push(self.read_u16(field)?);
        }
        self.align(4, field)?;

        if code_units.last().copied() != Some(0) {
            return Err(CoreError::InvalidResponse(field));
        }
        code_units.pop();
        String::from_utf16(&code_units)
            .map_err(|_| CoreError::InvalidResponse("failed to decode srvsvc UTF-16 string"))
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
    use super::{
        encode_remote_tod_request, encode_share_enum_level1_request,
        encode_share_get_info_level2_request, parse_remote_tod_response,
        parse_share_enum_level1_response, parse_share_get_info_level2_response, ShareInfo1,
        ShareInfo2, TimeOfDayInfo,
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
                0_u32.to_le_bytes(),
                0_u32.to_le_bytes(),
                u32::MAX.to_le_bytes(),
                0_u32.to_le_bytes()
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
        writer.write_wide_string("IPC$");
        writer.write_wide_string("Documentation");
        writer.write_u32(2);
        writer.write_u32(0);

        assert_eq!(
            parse_share_enum_level1_response(&writer.into_bytes())
                .expect("response should decode"),
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
}
