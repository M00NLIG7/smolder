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
const NETR_REMOTE_TOD_OPNUM: u16 = 28;

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
}

fn encode_remote_tod_request() -> Vec<u8> {
    0_u32.to_le_bytes().to_vec()
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
mod tests {
    use super::{encode_remote_tod_request, parse_remote_tod_response, TimeOfDayInfo};
    use crate::error::CoreError;

    #[test]
    fn remote_tod_request_uses_null_server_pointer() {
        assert_eq!(encode_remote_tod_request(), 0_u32.to_le_bytes());
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
}
