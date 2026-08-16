use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use smolder_proto::rpc::Packet;
use smolder_proto::smb::netbios::SessionMessage;
use smolder_proto::smb::smb2::{
    Command, CreateResponse, Dialect, FileAttributes, FileId, FlushResponse, GlobalCapabilities,
    Header, HeaderFlags, MessageId, NegotiateRequest, NegotiateResponse, OplockLevel, ReadResponse,
    ReadResponseFlags, SessionFlags, SessionId, SessionSetupResponse, ShareFlags, ShareType,
    SigningMode, TreeCapabilities, TreeConnectRequest, TreeConnectResponse, TreeId, WriteRequest,
    WriteResponse,
};
use smolder_proto::smb::status::NtStatus;

use crate::auth::{AuthError, AuthProvider};
use crate::client::{Connection, TreeConnected};
use crate::pipe::{NamedPipe, PipeAccess};
use crate::transport::Transport;

#[derive(Debug)]
pub(crate) struct ScriptedTransport {
    reads: VecDeque<Vec<u8>>,
    writes: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl ScriptedTransport {
    fn new(reads: Vec<Vec<u8>>, writes: Arc<Mutex<Vec<Vec<u8>>>>) -> Self {
        Self {
            reads: reads.into(),
            writes,
        }
    }
}

#[async_trait]
impl Transport for ScriptedTransport {
    async fn send(&mut self, frame: &[u8]) -> std::io::Result<()> {
        self.writes
            .lock()
            .expect("scripted write lock")
            .push(frame.to_vec());
        Ok(())
    }

    async fn recv(&mut self) -> std::io::Result<Vec<u8>> {
        self.reads.pop_front().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "no scripted SMB response",
            )
        })
    }
}

struct FixedAuthProvider(Vec<u8>);

impl AuthProvider for FixedAuthProvider {
    fn initial_token(&mut self, _negotiate: &NegotiateResponse) -> Result<Vec<u8>, AuthError> {
        Ok(std::mem::take(&mut self.0))
    }

    fn next_token(&mut self, _incoming: &[u8]) -> Result<Vec<u8>, AuthError> {
        Err(AuthError::InvalidState(
            "scripted authentication unexpectedly requested another token",
        ))
    }
}

pub(crate) async fn open_scripted_pipe(
    pipe_name: &str,
    later_reads: Vec<Vec<u8>>,
) -> (NamedPipe<ScriptedTransport>, Arc<Mutex<Vec<Vec<u8>>>>) {
    let negotiate_response = NegotiateResponse {
        security_mode: SigningMode::ENABLED,
        dialect_revision: Dialect::Smb302,
        negotiate_contexts: Vec::new(),
        server_guid: *b"server-guid-0001",
        capabilities: GlobalCapabilities::LARGE_MTU,
        max_transact_size: 65_536,
        max_read_size: 65_536,
        max_write_size: 65_536,
        system_time: 1,
        server_start_time: 1,
        security_buffer: Vec::new(),
    };
    let mut reads = vec![
        response_frame(Command::Negotiate, 0, 0, 0, 0, negotiate_response.encode()),
        response_frame(
            Command::SessionSetup,
            0,
            1,
            11,
            0,
            SessionSetupResponse {
                session_flags: SessionFlags::empty(),
                security_buffer: Vec::new(),
            }
            .encode(),
        ),
        response_frame(
            Command::TreeConnect,
            0,
            2,
            11,
            7,
            TreeConnectResponse {
                share_type: ShareType::Pipe,
                share_flags: ShareFlags::empty(),
                capabilities: TreeCapabilities::empty(),
                maximal_access: 0x0012_019f,
            }
            .encode(),
        ),
        response_frame(
            Command::Create,
            0,
            3,
            11,
            7,
            CreateResponse {
                oplock_level: OplockLevel::None,
                file_attributes: FileAttributes::NORMAL,
                allocation_size: 0,
                end_of_file: 0,
                file_id: FileId {
                    persistent: 1,
                    volatile: 2,
                },
                create_contexts: Vec::new(),
            }
            .encode(),
        ),
    ];
    reads.extend(later_reads);
    let writes = Arc::new(Mutex::new(Vec::new()));
    let transport = ScriptedTransport::new(reads, Arc::clone(&writes));
    let negotiated = Connection::new(transport)
        .negotiate(&NegotiateRequest {
            security_mode: SigningMode::ENABLED,
            capabilities: GlobalCapabilities::LARGE_MTU,
            client_guid: *b"client-guid-0001",
            dialects: vec![Dialect::Smb302],
            negotiate_contexts: Vec::new(),
        })
        .await
        .expect("scripted negotiate");
    let authenticated = negotiated
        .authenticate(&mut FixedAuthProvider(vec![0x60, 0x48]))
        .await
        .expect("scripted authenticate");
    let tree: Connection<_, TreeConnected> = authenticated
        .tree_connect(&TreeConnectRequest::from_unc(r"\\server\IPC$"))
        .await
        .expect("scripted tree connect");
    let pipe = NamedPipe::open(tree, pipe_name, PipeAccess::ReadWrite)
        .await
        .expect("scripted pipe open");
    (pipe, writes)
}

pub(crate) fn response_frame(
    command: Command,
    status: u32,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    body: Vec<u8>,
) -> Vec<u8> {
    let mut header = Header::new(command, MessageId(message_id));
    header.flags = HeaderFlags::SERVER_TO_REDIR;
    header.status = status;
    header.session_id = SessionId(session_id);
    header.tree_id = TreeId(tree_id);
    let mut packet = header.encode();
    packet.extend_from_slice(&body);
    SessionMessage::new(packet)
        .encode()
        .expect("scripted SMB response should frame")
}

pub(crate) fn successful_write_frame(message_id: u64, count: u32) -> Vec<u8> {
    response_frame(
        Command::Write,
        NtStatus::SUCCESS.to_u32(),
        message_id,
        11,
        7,
        WriteResponse { count }.encode(),
    )
}

pub(crate) fn successful_flush_frame(message_id: u64) -> Vec<u8> {
    response_frame(
        Command::Flush,
        NtStatus::SUCCESS.to_u32(),
        message_id,
        11,
        7,
        FlushResponse.encode(),
    )
}

pub(crate) fn rpc_read_frame(packet: Packet, message_id: u64) -> Vec<u8> {
    response_frame(
        Command::Read,
        NtStatus::SUCCESS.to_u32(),
        message_id,
        11,
        7,
        ReadResponse {
            data_remaining: 0,
            flags: ReadResponseFlags::empty(),
            data: packet.encode(),
        }
        .encode(),
    )
}

pub(crate) fn captured_rpc_packets(writes: &Arc<Mutex<Vec<Vec<u8>>>>) -> Vec<Packet> {
    writes
        .lock()
        .expect("scripted write lock")
        .iter()
        .filter_map(|frame| {
            let session = SessionMessage::decode(frame).ok()?;
            let header = Header::decode(&session.payload).ok()?;
            (header.command == Command::Write).then_some(())?;
            let write = WriteRequest::decode(&session.payload[Header::LEN..]).ok()?;
            Packet::decode(&write.data).ok()
        })
        .collect()
}
