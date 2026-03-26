//! Reusable DCE/RPC transport primitives built on top of named pipes.

use smolder_proto::rpc::{
    AuthVerifier, BindAckPdu, BindPdu, Packet, PacketFlags, RequestPdu, ResponsePdu, SyntaxId, Uuid,
};

use crate::error::CoreError;
use crate::pipe::NamedPipe;
use crate::transport::TokioTcpTransport;

/// Reusable DCE/RPC client over a named pipe transport.
#[derive(Debug)]
pub struct PipeRpcClient<T = TokioTcpTransport> {
    pipe: NamedPipe<T>,
    next_call_id: u32,
}

impl<T> PipeRpcClient<T> {
    /// Wraps an opened named pipe.
    #[must_use]
    pub fn new(pipe: NamedPipe<T>) -> Self {
        Self {
            pipe,
            next_call_id: 1,
        }
    }

    /// Returns the underlying named pipe.
    #[must_use]
    pub fn pipe(&self) -> &NamedPipe<T> {
        &self.pipe
    }

    fn next_call_id(&mut self) -> u32 {
        let current = self.next_call_id;
        self.next_call_id += 1;
        current
    }
}

impl<T> PipeRpcClient<T>
where
    T: crate::transport::Transport + Send,
{
    /// Sends a bind PDU and returns the raw bind acknowledgement.
    pub async fn bind(
        &mut self,
        context_id: u16,
        abstract_syntax: SyntaxId,
    ) -> Result<BindAckPdu, CoreError> {
        self.bind_with_auth(context_id, abstract_syntax, None).await
    }

    /// Sends a bind PDU with an optional authentication verifier.
    pub async fn bind_with_auth(
        &mut self,
        context_id: u16,
        abstract_syntax: SyntaxId,
        auth_verifier: Option<AuthVerifier>,
    ) -> Result<BindAckPdu, CoreError> {
        let bind = Packet::Bind(BindPdu {
            call_id: self.next_call_id(),
            max_xmit_frag: self.pipe.fragment_size() as u16,
            max_recv_frag: self.pipe.fragment_size() as u16,
            assoc_group_id: 0,
            context_id,
            abstract_syntax,
            transfer_syntax: SyntaxId::NDR32,
            auth_verifier,
        });
        let response = self.pipe.call(bind.encode()).await?;
        let packet = Packet::decode(&response)?;
        let Packet::BindAck(bind_ack) = packet else {
            return Err(CoreError::InvalidResponse("expected rpc bind ack"));
        };
        Ok(bind_ack)
    }

    /// Sends a bind PDU and requires an acceptance result.
    pub async fn bind_context(
        &mut self,
        context_id: u16,
        abstract_syntax: SyntaxId,
    ) -> Result<BindAckPdu, CoreError> {
        let bind_ack = self.bind(context_id, abstract_syntax).await?;
        if bind_ack.result.result == 0 {
            return Ok(bind_ack);
        }
        Err(CoreError::RemoteOperation {
            operation: "rpc_bind",
            code: u32::from(bind_ack.result.reason),
        })
    }

    /// Sends a request PDU and returns the decoded response stub bytes.
    pub async fn call(
        &mut self,
        context_id: u16,
        opnum: u16,
        stub_data: Vec<u8>,
    ) -> Result<Vec<u8>, CoreError> {
        let response = self
            .call_with_auth(context_id, opnum, stub_data, None)
            .await?;
        Ok(response.stub_data)
    }

    /// Sends a request PDU and returns the decoded response PDU.
    pub async fn call_with_auth(
        &mut self,
        context_id: u16,
        opnum: u16,
        stub_data: Vec<u8>,
        auth_verifier: Option<AuthVerifier>,
    ) -> Result<ResponsePdu, CoreError> {
        self.call_with_object_pdu(context_id, opnum, None, stub_data, auth_verifier)
            .await
    }

    /// Sends a request PDU with an optional object UUID.
    pub async fn call_with_object(
        &mut self,
        context_id: u16,
        opnum: u16,
        object_uuid: Option<Uuid>,
        stub_data: Vec<u8>,
    ) -> Result<Vec<u8>, CoreError> {
        let response = self
            .call_with_object_pdu(context_id, opnum, object_uuid, stub_data, None)
            .await?;
        Ok(response.stub_data)
    }

    /// Sends a request PDU with an optional object UUID and authentication verifier.
    pub async fn call_with_object_pdu(
        &mut self,
        context_id: u16,
        opnum: u16,
        object_uuid: Option<Uuid>,
        stub_data: Vec<u8>,
        auth_verifier: Option<AuthVerifier>,
    ) -> Result<ResponsePdu, CoreError> {
        let request = Packet::Request(RequestPdu {
            call_id: self.next_call_id(),
            flags: PacketFlags::FIRST_FRAGMENT | PacketFlags::LAST_FRAGMENT,
            alloc_hint: stub_data.len() as u32,
            context_id,
            opnum,
            object_uuid,
            stub_data,
            auth_verifier,
        });
        let response = self.pipe.call(request.encode()).await?;
        let packet = Packet::decode(&response)?;
        match packet {
            Packet::Response(response) => Ok(response),
            Packet::Fault(fault) => Err(CoreError::RemoteOperation {
                operation: "rpc_fault",
                code: fault.status,
            }),
            _ => Err(CoreError::InvalidResponse("unexpected rpc packet type")),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use async_trait::async_trait;
    use smolder_proto::rpc::{
        AuthLevel, AuthType, AuthVerifier, BindAckPdu, BindAckResult, FaultPdu, Packet,
        PacketFlags, ResponsePdu, SyntaxId, Uuid,
    };
    use smolder_proto::smb::netbios::SessionMessage;
    use smolder_proto::smb::smb2::{
        Command, CreateResponse, Dialect, FileAttributes, FileId, GlobalCapabilities, Header,
        MessageId, NegotiateRequest, NegotiateResponse, OplockLevel, ReadResponse,
        ReadResponseFlags, SessionFlags, SessionSetupRequest, SessionSetupResponse,
        SessionSetupSecurityMode, ShareFlags, ShareType, SigningMode, TreeCapabilities,
        TreeConnectRequest, TreeConnectResponse, TreeId, WriteResponse,
    };
    use smolder_proto::smb::status::NtStatus;

    use crate::client::{Connection, TreeConnected};
    use crate::error::CoreError;
    use crate::pipe::{NamedPipe, PipeAccess};
    use crate::transport::Transport;

    use super::PipeRpcClient;

    const TEST_SYNTAX: SyntaxId = SyntaxId::new(
        Uuid::new(
            0x367a_bb81,
            0x9844,
            0x35f1,
            [0xad, 0x32, 0x98, 0xf0, 0x38, 0x00, 0x10, 0x03],
        ),
        2,
        0,
    );

    #[derive(Debug)]
    struct ScriptedTransport {
        reads: VecDeque<Vec<u8>>,
        writes: Vec<Vec<u8>>,
    }

    impl ScriptedTransport {
        fn new(reads: Vec<Vec<u8>>) -> Self {
            Self {
                reads: reads.into(),
                writes: Vec::new(),
            }
        }
    }

    #[async_trait]
    impl Transport for ScriptedTransport {
        async fn send(&mut self, frame: &[u8]) -> std::io::Result<()> {
            self.writes.push(frame.to_vec());
            Ok(())
        }

        async fn recv(&mut self) -> std::io::Result<Vec<u8>> {
            self.reads.pop_front().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "no scripted response")
            })
        }
    }

    #[tokio::test]
    async fn binds_and_returns_bind_ack() {
        let pipe = open_pipe(vec![bind_ack_response_frame()]).await;
        let mut rpc = PipeRpcClient::new(pipe);

        let bind_ack = rpc
            .bind_context(0, TEST_SYNTAX)
            .await
            .expect("bind should succeed");

        assert_eq!(bind_ack.result.result, 0);
        assert_eq!(bind_ack.result.transfer_syntax, SyntaxId::NDR32);
    }

    #[tokio::test]
    async fn bind_preserves_auth_verifier_on_bind_ack() {
        let verifier = AuthVerifier::new(
            AuthType::WinNt,
            AuthLevel::PacketIntegrity,
            0,
            vec![0x55; 16],
        );
        let pipe = open_pipe(vec![rpc_response_frame(Packet::BindAck(BindAckPdu {
            call_id: 1,
            max_xmit_frag: 4280,
            max_recv_frag: 4280,
            assoc_group_id: 0,
            secondary_address: b"\\PIPE\\svcctl\0".to_vec(),
            result: BindAckResult {
                result: 0,
                reason: 0,
                transfer_syntax: SyntaxId::NDR32,
            },
            auth_verifier: Some(verifier.clone()),
        }))])
        .await;
        let mut rpc = PipeRpcClient::new(pipe);

        let bind_ack = rpc
            .bind_with_auth(0, TEST_SYNTAX, Some(verifier.clone()))
            .await
            .expect("bind with auth should succeed");

        assert_eq!(bind_ack.auth_verifier, Some(verifier));
    }

    #[tokio::test]
    async fn call_returns_stub_data_on_response() {
        let pipe = open_pipe(vec![rpc_response_frame(Packet::Response(ResponsePdu {
            call_id: 1,
            flags: PacketFlags::FIRST_FRAGMENT | PacketFlags::LAST_FRAGMENT,
            alloc_hint: 4,
            context_id: 0,
            cancel_count: 0,
            stub_data: vec![1, 2, 3, 4],
            auth_verifier: None,
        }))])
        .await;
        let mut rpc = PipeRpcClient::new(pipe);

        let stub = rpc
            .call(0, 15, vec![0xaa, 0xbb])
            .await
            .expect("rpc call should succeed");

        assert_eq!(stub, vec![1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn call_with_auth_returns_response_pdu() {
        let verifier = AuthVerifier::new(
            AuthType::WinNt,
            AuthLevel::PacketIntegrity,
            1,
            vec![0x77; 16],
        );
        let pipe = open_pipe(vec![rpc_response_frame(Packet::Response(ResponsePdu {
            call_id: 1,
            flags: PacketFlags::FIRST_FRAGMENT | PacketFlags::LAST_FRAGMENT,
            alloc_hint: 4,
            context_id: 0,
            cancel_count: 0,
            stub_data: vec![9, 8, 7, 6],
            auth_verifier: Some(verifier.clone()),
        }))])
        .await;
        let mut rpc = PipeRpcClient::new(pipe);

        let response = rpc
            .call_with_auth(0, 15, vec![0xaa, 0xbb], Some(verifier.clone()))
            .await
            .expect("authenticated rpc call should succeed");

        assert_eq!(response.stub_data, vec![9, 8, 7, 6]);
        assert_eq!(response.auth_verifier, Some(verifier));
    }

    #[tokio::test]
    async fn call_maps_fault_to_remote_operation() {
        let pipe = open_pipe(vec![rpc_response_frame(Packet::Fault(FaultPdu {
            call_id: 1,
            flags: PacketFlags::FIRST_FRAGMENT | PacketFlags::LAST_FRAGMENT,
            alloc_hint: 0,
            context_id: 0,
            status: 0x1c01_0003,
            stub_data: Vec::new(),
            auth_verifier: None,
        }))])
        .await;
        let mut rpc = PipeRpcClient::new(pipe);

        let error = rpc
            .call(0, 15, vec![0xaa, 0xbb])
            .await
            .expect_err("rpc fault should fail");

        match error {
            CoreError::RemoteOperation { operation, code } => {
                assert_eq!(operation, "rpc_fault");
                assert_eq!(code, 0x1c01_0003);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    async fn open_pipe(reads: Vec<Vec<u8>>) -> NamedPipe<ScriptedTransport> {
        let connection = build_tree_connection(reads).await;
        NamedPipe::open(connection, "svcctl", PipeAccess::ReadWrite)
            .await
            .expect("pipe open should succeed")
    }

    fn bind_ack_response_frame() -> Vec<u8> {
        rpc_response_frame(Packet::BindAck(BindAckPdu {
            call_id: 1,
            max_xmit_frag: 4280,
            max_recv_frag: 4280,
            assoc_group_id: 0,
            secondary_address: b"\\PIPE\\svcctl\0".to_vec(),
            result: BindAckResult {
                result: 0,
                reason: 0,
                transfer_syntax: SyntaxId::NDR32,
            },
            auth_verifier: None,
        }))
    }

    fn rpc_response_frame(packet: Packet) -> Vec<u8> {
        let packet = packet.encode();
        let mut header = Header::new(Command::Read, MessageId(6));
        header.status = NtStatus::SUCCESS.to_u32();
        header.session_id = smolder_proto::smb::smb2::SessionId(11);
        header.tree_id = TreeId(7);

        let mut smb_packet = header.encode();
        smb_packet.extend_from_slice(
            &ReadResponse {
                data_remaining: 0,
                flags: ReadResponseFlags::empty(),
                data: packet,
            }
            .encode(),
        );
        SessionMessage::new(smb_packet)
            .encode()
            .expect("frame should encode")
    }

    async fn build_tree_connection(
        reads: Vec<Vec<u8>>,
    ) -> Connection<ScriptedTransport, TreeConnected> {
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
        let session_response = SessionSetupResponse {
            session_flags: SessionFlags::empty(),
            security_buffer: Vec::new(),
        };
        let tree_response = TreeConnectResponse {
            share_type: ShareType::Pipe,
            share_flags: ShareFlags::empty(),
            capabilities: TreeCapabilities::empty(),
            maximal_access: 0x0012_019f,
        };
        let create_response = CreateResponse {
            oplock_level: OplockLevel::None,
            file_attributes: FileAttributes::NORMAL,
            allocation_size: 0,
            end_of_file: 0,
            file_id: FileId {
                persistent: 1,
                volatile: 2,
            },
            create_contexts: Vec::new(),
        };

        let mut scripted_reads = vec![
            response_frame(
                Command::Negotiate,
                NtStatus::SUCCESS.to_u32(),
                0,
                0,
                0,
                negotiate_response.encode(),
            ),
            response_frame(
                Command::SessionSetup,
                NtStatus::SUCCESS.to_u32(),
                1,
                11,
                0,
                session_response.encode(),
            ),
            response_frame(
                Command::TreeConnect,
                NtStatus::SUCCESS.to_u32(),
                2,
                11,
                7,
                tree_response.encode(),
            ),
            response_frame(
                Command::Create,
                NtStatus::SUCCESS.to_u32(),
                3,
                11,
                7,
                create_response.encode(),
            ),
            response_frame(
                Command::Write,
                NtStatus::SUCCESS.to_u32(),
                4,
                11,
                7,
                WriteResponse { count: 72 }.encode(),
            ),
            response_frame(
                Command::Flush,
                NtStatus::SUCCESS.to_u32(),
                5,
                11,
                7,
                smolder_proto::smb::smb2::FlushResponse.encode(),
            ),
        ];
        scripted_reads.extend(reads);

        let transport = ScriptedTransport::new(scripted_reads);
        let connection = Connection::new(transport);
        let negotiate_request = NegotiateRequest {
            security_mode: SigningMode::ENABLED,
            capabilities: GlobalCapabilities::LARGE_MTU,
            client_guid: *b"client-guid-0001",
            dialects: vec![Dialect::Smb210, Dialect::Smb302],
            negotiate_contexts: Vec::new(),
        };
        let session_request = SessionSetupRequest {
            flags: 0,
            security_mode: SessionSetupSecurityMode::SIGNING_ENABLED,
            capabilities: 0,
            channel: 0,
            security_buffer: vec![0x60, 0x48],
            previous_session_id: 0,
        };
        let connection = connection
            .negotiate(&negotiate_request)
            .await
            .expect("negotiate should succeed");
        let connection = connection
            .session_setup(&session_request)
            .await
            .expect("session setup should succeed");
        let connection = connection
            .tree_connect(&TreeConnectRequest::from_unc(r"\\server\IPC$"))
            .await
            .expect("tree connect should succeed");
        connection
    }

    fn response_frame(
        command: Command,
        status: u32,
        message_id: u64,
        session_id: u64,
        tree_id: u32,
        body: Vec<u8>,
    ) -> Vec<u8> {
        let mut header = Header::new(command, MessageId(message_id));
        header.status = status;
        header.session_id = smolder_proto::smb::smb2::SessionId(session_id);
        header.tree_id = TreeId(tree_id);

        let mut packet = header.encode();
        packet.extend_from_slice(&body);
        SessionMessage::new(packet)
            .encode()
            .expect("response should frame")
    }
}
