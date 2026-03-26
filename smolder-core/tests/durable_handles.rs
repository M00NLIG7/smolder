use std::collections::VecDeque;

use async_trait::async_trait;
use smolder_core::client::{Connection, DurableOpenOptions, ResilientHandle};
use smolder_core::transport::Transport;
use smolder_proto::smb::netbios::SessionMessage;
use smolder_proto::smb::smb2::{
    Command, CreateContext, CreateRequest, CreateResponse, Dialect, DurableHandleFlags,
    DurableHandleReconnect, DurableHandleReconnectV2, DurableHandleRequestV2,
    DurableHandleResponse, DurableHandleResponseV2, FileAttributes, FileId, GlobalCapabilities,
    Header, HeaderFlags, IoctlRequest, NegotiateContext, NegotiateRequest, NegotiateResponse,
    OplockLevel, PreauthIntegrityCapabilities, PreauthIntegrityHashId, SessionFlags, SessionId,
    SessionSetupRequest, SessionSetupResponse, SessionSetupSecurityMode, ShareFlags, ShareType,
    SigningMode, TreeCapabilities, TreeConnectRequest, TreeConnectResponse, TreeId,
};
use smolder_proto::smb::status::NtStatus;

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

fn response_frame(
    command: Command,
    status: u32,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    body: Vec<u8>,
) -> Vec<u8> {
    let mut header = Header::new(command, smolder_proto::smb::smb2::MessageId(message_id));
    header.status = status;
    header.flags = HeaderFlags::SERVER_TO_REDIR;
    header.session_id = SessionId(session_id);
    header.tree_id = TreeId(tree_id);

    let mut packet = header.encode();
    packet.extend_from_slice(&body);
    SessionMessage::new(packet)
        .encode()
        .expect("response should frame")
}

fn outbound_create(frame: &[u8]) -> CreateRequest {
    let frame = SessionMessage::decode(frame).expect("frame should decode");
    CreateRequest::decode(&frame.payload[Header::LEN..]).expect("create request should decode")
}

fn outbound_ioctl(frame: &[u8]) -> IoctlRequest {
    let frame = SessionMessage::decode(frame).expect("frame should decode");
    IoctlRequest::decode(&frame.payload[Header::LEN..]).expect("ioctl request should decode")
}

fn preauth_context(salt: &[u8]) -> NegotiateContext {
    NegotiateContext::preauth_integrity(PreauthIntegrityCapabilities {
        hash_algorithms: vec![PreauthIntegrityHashId::Sha512],
        salt: salt.to_vec(),
    })
}

fn find_durable_request_v2(request: &CreateRequest) -> DurableHandleRequestV2 {
    request
        .create_contexts
        .iter()
        .find_map(|context| {
            context
                .durable_handle_request_v2_data()
                .expect("request context should decode")
        })
        .expect("expected durable v2 request context")
}

fn find_durable_reconnect_v2(request: &CreateRequest) -> DurableHandleReconnectV2 {
    request
        .create_contexts
        .iter()
        .find_map(|context| {
            context
                .durable_handle_reconnect_v2_data()
                .expect("request context should decode")
        })
        .expect("expected durable v2 reconnect context")
}

fn has_legacy_durable_request(request: &CreateRequest) -> bool {
    request.create_contexts.iter().any(|context| {
        context
            .durable_handle_request_data()
            .expect("request context should decode")
            .is_some()
    })
}

fn find_legacy_durable_reconnect(request: &CreateRequest) -> DurableHandleReconnect {
    request
        .create_contexts
        .iter()
        .find_map(|context| {
            context
                .durable_handle_reconnect_data()
                .expect("request context should decode")
        })
        .expect("expected legacy durable reconnect context")
}

fn negotiate_request_smb311() -> NegotiateRequest {
    NegotiateRequest {
        security_mode: SigningMode::ENABLED,
        capabilities: GlobalCapabilities::LARGE_MTU,
        client_guid: *b"client-guid-0200",
        dialects: vec![Dialect::Smb210, Dialect::Smb302, Dialect::Smb311],
        negotiate_contexts: vec![preauth_context(b"client-salt-0200")],
    }
}

fn negotiate_response_smb311() -> NegotiateResponse {
    NegotiateResponse {
        security_mode: SigningMode::ENABLED,
        dialect_revision: Dialect::Smb311,
        negotiate_contexts: vec![preauth_context(b"server-salt-0200")],
        server_guid: *b"server-guid-0200",
        capabilities: GlobalCapabilities::LARGE_MTU,
        max_transact_size: 65_536,
        max_read_size: 65_536,
        max_write_size: 65_536,
        system_time: 1,
        server_start_time: 1,
        security_buffer: vec![0x60, 0x03],
    }
}

fn negotiate_request_smb210() -> NegotiateRequest {
    NegotiateRequest {
        security_mode: SigningMode::ENABLED,
        capabilities: GlobalCapabilities::LARGE_MTU,
        client_guid: *b"client-guid-0201",
        dialects: vec![Dialect::Smb202, Dialect::Smb210],
        negotiate_contexts: Vec::new(),
    }
}

fn negotiate_response_smb210() -> NegotiateResponse {
    NegotiateResponse {
        security_mode: SigningMode::ENABLED,
        dialect_revision: Dialect::Smb210,
        negotiate_contexts: Vec::new(),
        server_guid: *b"server-guid-0201",
        capabilities: GlobalCapabilities::LARGE_MTU,
        max_transact_size: 65_536,
        max_read_size: 65_536,
        max_write_size: 65_536,
        system_time: 1,
        server_start_time: 1,
        security_buffer: vec![0x60, 0x03],
    }
}

fn session_request() -> SessionSetupRequest {
    SessionSetupRequest {
        flags: 0,
        security_mode: SessionSetupSecurityMode::SIGNING_ENABLED,
        capabilities: 0,
        channel: 0,
        security_buffer: vec![0x60, 0x48],
        previous_session_id: 0,
    }
}

fn session_response() -> SessionSetupResponse {
    SessionSetupResponse {
        session_flags: SessionFlags::empty(),
        security_buffer: vec![0xa1, 0x01],
    }
}

fn tree_response() -> TreeConnectResponse {
    TreeConnectResponse {
        share_type: ShareType::Disk,
        share_flags: ShareFlags::empty(),
        capabilities: TreeCapabilities::empty(),
        maximal_access: 0x0012_019f,
    }
}

#[tokio::test]
async fn durable_v2_open_reconnects_with_saved_create_guid() {
    let create_guid = *b"durable-guid-020";
    let initial_file_id = FileId {
        persistent: 0x11,
        volatile: 0x22,
    };
    let reopened_file_id = FileId {
        persistent: 0x33,
        volatile: 0x44,
    };
    let initial_response = CreateResponse {
        oplock_level: OplockLevel::None,
        file_attributes: FileAttributes::ARCHIVE,
        allocation_size: 4096,
        end_of_file: 128,
        file_id: initial_file_id,
        create_contexts: vec![CreateContext::new(
            b"DH2Q".to_vec(),
            DurableHandleResponseV2 {
                timeout: 45_000,
                flags: DurableHandleFlags::PERSISTENT,
            }
            .encode(),
        )],
    };
    let reopened_response = CreateResponse {
        oplock_level: OplockLevel::None,
        file_attributes: FileAttributes::ARCHIVE,
        allocation_size: 4096,
        end_of_file: 128,
        file_id: reopened_file_id,
        create_contexts: Vec::new(),
    };

    let request = CreateRequest::from_path("notes.txt");
    let options = DurableOpenOptions::new()
        .with_create_guid(create_guid)
        .with_timeout(45_000)
        .with_persistent(true);

    let transport_one = ScriptedTransport::new(vec![
        response_frame(
            Command::Negotiate,
            NtStatus::SUCCESS.to_u32(),
            0,
            0,
            0,
            negotiate_response_smb311().encode(),
        ),
        response_frame(
            Command::SessionSetup,
            NtStatus::SUCCESS.to_u32(),
            1,
            55,
            0,
            session_response().encode(),
        ),
        response_frame(
            Command::TreeConnect,
            NtStatus::SUCCESS.to_u32(),
            2,
            55,
            9,
            tree_response().encode(),
        ),
        response_frame(
            Command::Create,
            NtStatus::SUCCESS.to_u32(),
            3,
            55,
            9,
            initial_response.encode(),
        ),
    ]);
    let mut connection_one = Connection::new(transport_one)
        .negotiate(&negotiate_request_smb311())
        .await
        .expect("negotiate should succeed")
        .session_setup(&session_request())
        .await
        .expect("session setup should succeed")
        .tree_connect(&TreeConnectRequest::from_unc(r"\\server\share"))
        .await
        .expect("tree connect should succeed");

    let durable = connection_one
        .create_durable(&request, options.clone())
        .await
        .expect("durable open should succeed");
    assert_eq!(durable.file_id(), initial_file_id);

    let transport_one = connection_one.into_transport();
    let open_request = outbound_create(&transport_one.writes[3]);
    let durable_request = find_durable_request_v2(&open_request);
    assert_eq!(durable_request.create_guid, create_guid);
    assert_eq!(durable_request.timeout, 45_000);
    assert_eq!(durable_request.flags, DurableHandleFlags::PERSISTENT);

    let transport_two = ScriptedTransport::new(vec![
        response_frame(
            Command::Negotiate,
            NtStatus::SUCCESS.to_u32(),
            0,
            0,
            0,
            negotiate_response_smb311().encode(),
        ),
        response_frame(
            Command::SessionSetup,
            NtStatus::SUCCESS.to_u32(),
            1,
            55,
            0,
            session_response().encode(),
        ),
        response_frame(
            Command::TreeConnect,
            NtStatus::SUCCESS.to_u32(),
            2,
            55,
            9,
            tree_response().encode(),
        ),
        response_frame(
            Command::Create,
            NtStatus::SUCCESS.to_u32(),
            3,
            55,
            9,
            reopened_response.encode(),
        ),
    ]);
    let mut connection_two = Connection::new(transport_two)
        .negotiate(&negotiate_request_smb311())
        .await
        .expect("negotiate should succeed")
        .session_setup(&session_request())
        .await
        .expect("session setup should succeed")
        .tree_connect(&TreeConnectRequest::from_unc(r"\\server\share"))
        .await
        .expect("tree connect should succeed");

    let reopened = connection_two
        .reconnect_durable(&durable)
        .await
        .expect("durable reconnect should succeed");
    assert_eq!(reopened.file_id(), reopened_file_id);

    let transport_two = connection_two.into_transport();
    let reconnect_request = outbound_create(&transport_two.writes[3]);
    let reconnect_context = find_durable_reconnect_v2(&reconnect_request);
    assert_eq!(reconnect_context.file_id, initial_file_id);
    assert_eq!(reconnect_context.create_guid, create_guid);
    assert_eq!(reconnect_context.flags, DurableHandleFlags::PERSISTENT);
    assert!(
        reconnect_request
            .create_contexts
            .iter()
            .all(|context| context
                .durable_handle_request_v2_data()
                .expect("request context should decode")
                .is_none())
    );
}

#[tokio::test]
async fn durable_v1_open_reconnects_with_legacy_contexts_on_smb210() {
    let initial_file_id = FileId {
        persistent: 0x55,
        volatile: 0x66,
    };
    let reopened_file_id = FileId {
        persistent: 0x77,
        volatile: 0x88,
    };
    let initial_response = CreateResponse {
        oplock_level: OplockLevel::None,
        file_attributes: FileAttributes::ARCHIVE,
        allocation_size: 1024,
        end_of_file: 64,
        file_id: initial_file_id,
        create_contexts: vec![CreateContext::new(
            b"DHnQ".to_vec(),
            DurableHandleResponse.encode(),
        )],
    };
    let reopened_response = CreateResponse {
        oplock_level: OplockLevel::None,
        file_attributes: FileAttributes::ARCHIVE,
        allocation_size: 1024,
        end_of_file: 64,
        file_id: reopened_file_id,
        create_contexts: Vec::new(),
    };

    let transport_one = ScriptedTransport::new(vec![
        response_frame(
            Command::Negotiate,
            NtStatus::SUCCESS.to_u32(),
            0,
            0,
            0,
            negotiate_response_smb210().encode(),
        ),
        response_frame(
            Command::SessionSetup,
            NtStatus::SUCCESS.to_u32(),
            1,
            55,
            0,
            session_response().encode(),
        ),
        response_frame(
            Command::TreeConnect,
            NtStatus::SUCCESS.to_u32(),
            2,
            55,
            9,
            tree_response().encode(),
        ),
        response_frame(
            Command::Create,
            NtStatus::SUCCESS.to_u32(),
            3,
            55,
            9,
            initial_response.encode(),
        ),
    ]);
    let mut connection_one = Connection::new(transport_one)
        .negotiate(&negotiate_request_smb210())
        .await
        .expect("negotiate should succeed")
        .session_setup(&session_request())
        .await
        .expect("session setup should succeed")
        .tree_connect(&TreeConnectRequest::from_unc(r"\\server\share"))
        .await
        .expect("tree connect should succeed");

    let durable = connection_one
        .create_durable(&CreateRequest::from_path("legacy.txt"), DurableOpenOptions::new())
        .await
        .expect("legacy durable open should succeed");
    assert_eq!(durable.file_id(), initial_file_id);

    let transport_one = connection_one.into_transport();
    let open_request = outbound_create(&transport_one.writes[3]);
    assert!(has_legacy_durable_request(&open_request));

    let transport_two = ScriptedTransport::new(vec![
        response_frame(
            Command::Negotiate,
            NtStatus::SUCCESS.to_u32(),
            0,
            0,
            0,
            negotiate_response_smb210().encode(),
        ),
        response_frame(
            Command::SessionSetup,
            NtStatus::SUCCESS.to_u32(),
            1,
            55,
            0,
            session_response().encode(),
        ),
        response_frame(
            Command::TreeConnect,
            NtStatus::SUCCESS.to_u32(),
            2,
            55,
            9,
            tree_response().encode(),
        ),
        response_frame(
            Command::Create,
            NtStatus::SUCCESS.to_u32(),
            3,
            55,
            9,
            reopened_response.encode(),
        ),
    ]);
    let mut connection_two = Connection::new(transport_two)
        .negotiate(&negotiate_request_smb210())
        .await
        .expect("negotiate should succeed")
        .session_setup(&session_request())
        .await
        .expect("session setup should succeed")
        .tree_connect(&TreeConnectRequest::from_unc(r"\\server\share"))
        .await
        .expect("tree connect should succeed");

    let reopened = connection_two
        .reconnect_durable(&durable)
        .await
        .expect("legacy durable reconnect should succeed");
    assert_eq!(reopened.file_id(), reopened_file_id);

    let transport_two = connection_two.into_transport();
    let reconnect_request = outbound_create(&transport_two.writes[3]);
    let reconnect_context = find_legacy_durable_reconnect(&reconnect_request);
    assert_eq!(reconnect_context.file_id, initial_file_id);
}

#[tokio::test]
async fn resilient_handle_request_uses_resiliency_fsctl() {
    let file_id = FileId {
        persistent: 0xaa,
        volatile: 0xbb,
    };
    let transport = ScriptedTransport::new(vec![
        response_frame(
            Command::Negotiate,
            NtStatus::SUCCESS.to_u32(),
            0,
            0,
            0,
            negotiate_response_smb210().encode(),
        ),
        response_frame(
            Command::SessionSetup,
            NtStatus::SUCCESS.to_u32(),
            1,
            55,
            0,
            session_response().encode(),
        ),
        response_frame(
            Command::TreeConnect,
            NtStatus::SUCCESS.to_u32(),
            2,
            55,
            9,
            tree_response().encode(),
        ),
        response_frame(
            Command::Ioctl,
            NtStatus::SUCCESS.to_u32(),
            3,
            55,
            9,
            smolder_proto::smb::smb2::IoctlResponse {
                ctl_code: smolder_proto::smb::smb2::CtlCode::FSCTL_LMR_REQUEST_RESILIENCY,
                file_id,
                input: Vec::new(),
                output: Vec::new(),
                flags: 0,
            }
            .encode(),
        ),
    ]);
    let mut connection = Connection::new(transport)
        .negotiate(&negotiate_request_smb210())
        .await
        .expect("negotiate should succeed")
        .session_setup(&session_request())
        .await
        .expect("session setup should succeed")
        .tree_connect(&TreeConnectRequest::from_unc(r"\\server\share"))
        .await
        .expect("tree connect should succeed");

    let resilient = connection
        .request_resiliency(file_id, 30_000)
        .await
        .expect("resiliency request should succeed");
    assert_eq!(
        resilient,
        ResilientHandle {
            file_id,
            timeout: 30_000,
        }
    );

    let transport = connection.into_transport();
    let ioctl = outbound_ioctl(&transport.writes[3]);
    assert_eq!(
        ioctl.ctl_code,
        smolder_proto::smb::smb2::CtlCode::FSCTL_LMR_REQUEST_RESILIENCY
    );
    assert_eq!(ioctl.file_id, file_id);
    assert_eq!(ioctl.input, 30_000u32.to_le_bytes().into_iter().chain([0; 4]).collect::<Vec<_>>());
}

#[tokio::test]
async fn durable_reconnect_with_resiliency_reapplies_saved_timeout() {
    let create_guid = *b"durable-guid-021";
    let initial_file_id = FileId {
        persistent: 0x91,
        volatile: 0x92,
    };
    let reopened_file_id = FileId {
        persistent: 0xa1,
        volatile: 0xa2,
    };
    let initial_response = CreateResponse {
        oplock_level: OplockLevel::None,
        file_attributes: FileAttributes::ARCHIVE,
        allocation_size: 2048,
        end_of_file: 256,
        file_id: initial_file_id,
        create_contexts: vec![CreateContext::new(
            b"DH2Q".to_vec(),
            DurableHandleResponseV2 {
                timeout: 45_000,
                flags: DurableHandleFlags::empty(),
            }
            .encode(),
        )],
    };
    let reopened_response = CreateResponse {
        oplock_level: OplockLevel::None,
        file_attributes: FileAttributes::ARCHIVE,
        allocation_size: 2048,
        end_of_file: 256,
        file_id: reopened_file_id,
        create_contexts: Vec::new(),
    };

    let transport_one = ScriptedTransport::new(vec![
        response_frame(
            Command::Negotiate,
            NtStatus::SUCCESS.to_u32(),
            0,
            0,
            0,
            negotiate_response_smb311().encode(),
        ),
        response_frame(
            Command::SessionSetup,
            NtStatus::SUCCESS.to_u32(),
            1,
            55,
            0,
            session_response().encode(),
        ),
        response_frame(
            Command::TreeConnect,
            NtStatus::SUCCESS.to_u32(),
            2,
            55,
            9,
            tree_response().encode(),
        ),
        response_frame(
            Command::Create,
            NtStatus::SUCCESS.to_u32(),
            3,
            55,
            9,
            initial_response.encode(),
        ),
    ]);
    let mut connection_one = Connection::new(transport_one)
        .negotiate(&negotiate_request_smb311())
        .await
        .expect("negotiate should succeed")
        .session_setup(&session_request())
        .await
        .expect("session setup should succeed")
        .tree_connect(&TreeConnectRequest::from_unc(r"\\server\share"))
        .await
        .expect("tree connect should succeed");

    let durable = connection_one
        .create_durable(
            &CreateRequest::from_path("notes.txt"),
            DurableOpenOptions::new()
                .with_create_guid(create_guid)
                .with_timeout(45_000),
        )
        .await
        .expect("durable open should succeed")
        .with_resilient_timeout(30_000);

    let transport_two = ScriptedTransport::new(vec![
        response_frame(
            Command::Negotiate,
            NtStatus::SUCCESS.to_u32(),
            0,
            0,
            0,
            negotiate_response_smb311().encode(),
        ),
        response_frame(
            Command::SessionSetup,
            NtStatus::SUCCESS.to_u32(),
            1,
            55,
            0,
            session_response().encode(),
        ),
        response_frame(
            Command::TreeConnect,
            NtStatus::SUCCESS.to_u32(),
            2,
            55,
            9,
            tree_response().encode(),
        ),
        response_frame(
            Command::Create,
            NtStatus::SUCCESS.to_u32(),
            3,
            55,
            9,
            reopened_response.encode(),
        ),
        response_frame(
            Command::Ioctl,
            NtStatus::SUCCESS.to_u32(),
            4,
            55,
            9,
            smolder_proto::smb::smb2::IoctlResponse {
                ctl_code: smolder_proto::smb::smb2::CtlCode::FSCTL_LMR_REQUEST_RESILIENCY,
                file_id: reopened_file_id,
                input: Vec::new(),
                output: Vec::new(),
                flags: 0,
            }
            .encode(),
        ),
    ]);
    let mut connection_two = Connection::new(transport_two)
        .negotiate(&negotiate_request_smb311())
        .await
        .expect("negotiate should succeed")
        .session_setup(&session_request())
        .await
        .expect("session setup should succeed")
        .tree_connect(&TreeConnectRequest::from_unc(r"\\server\share"))
        .await
        .expect("tree connect should succeed");

    let (reopened, resilient) = connection_two
        .reconnect_durable_with_resiliency(&durable)
        .await
        .expect("durable reconnect with resiliency should succeed");
    assert_eq!(reopened.file_id(), reopened_file_id);
    assert_eq!(reopened.resilient_timeout(), Some(30_000));
    assert_eq!(
        resilient,
        Some(ResilientHandle {
            file_id: reopened_file_id,
            timeout: 30_000,
        })
    );

    let transport_two = connection_two.into_transport();
    let reconnect_request = outbound_create(&transport_two.writes[3]);
    let reconnect_context = find_durable_reconnect_v2(&reconnect_request);
    assert_eq!(reconnect_context.file_id, initial_file_id);
    assert_eq!(reconnect_context.create_guid, create_guid);

    let ioctl = outbound_ioctl(&transport_two.writes[4]);
    assert_eq!(
        ioctl.ctl_code,
        smolder_proto::smb::smb2::CtlCode::FSCTL_LMR_REQUEST_RESILIENCY
    );
    assert_eq!(ioctl.file_id, reopened_file_id);
    assert_eq!(ioctl.input, 30_000u32.to_le_bytes().into_iter().chain([0; 4]).collect::<Vec<_>>());
}
