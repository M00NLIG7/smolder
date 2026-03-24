//! Typestate SMB client built on top of wire-level packet codecs.

use tracing::{trace, trace_span, Instrument};

use smolder_proto::smb::netbios::SessionMessage;
use smolder_proto::smb::smb2::{
    CloseRequest, CloseResponse, Command, CreateRequest, CreateResponse, Header, MessageId,
    NegotiateRequest, NegotiateResponse, SessionId, SessionSetupRequest, SessionSetupResponse,
    TreeConnectRequest, TreeConnectResponse, TreeId,
};

use crate::error::CoreError;
use crate::transport::Transport;

/// Connected to a transport but no SMB negotiation has been performed.
#[derive(Debug, Clone, Copy, Default)]
pub struct Connected;

/// Negotiated dialect and server capabilities are known.
#[derive(Debug, Clone)]
pub struct Negotiated {
    /// The server negotiate response.
    pub response: NegotiateResponse,
}

/// The transport has an authenticated SMB session.
#[derive(Debug, Clone)]
pub struct Authenticated {
    /// Negotiate details for the connection.
    pub negotiated: NegotiateResponse,
    /// Session setup response.
    pub session: SessionSetupResponse,
    /// Assigned session identifier.
    pub session_id: SessionId,
}

/// The transport is connected to a tree and can issue file operations.
#[derive(Debug, Clone)]
pub struct TreeConnected {
    /// Negotiate details for the connection.
    pub negotiated: NegotiateResponse,
    /// Session setup response.
    pub session: SessionSetupResponse,
    /// Tree connect response.
    pub tree: TreeConnectResponse,
    /// Assigned session identifier.
    pub session_id: SessionId,
    /// Assigned tree identifier.
    pub tree_id: TreeId,
}

/// A typestate SMB connection over an abstract transport.
#[derive(Debug)]
pub struct Connection<T, State> {
    transport: T,
    next_message_id: u64,
    state: State,
}

impl<T> Connection<T, Connected> {
    /// Creates a new SMB connection over the provided transport.
    #[must_use]
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            next_message_id: 0,
            state: Connected,
        }
    }
}

impl<T, State> Connection<T, State> {
    /// Returns the current typestate payload.
    #[must_use]
    pub fn state(&self) -> &State {
        &self.state
    }

    /// Consumes the connection and returns the inner transport.
    #[must_use]
    pub fn into_transport(self) -> T {
        self.transport
    }
}

impl<T> Connection<T, Connected>
where
    T: Transport + Send,
{
    /// Performs `NEGOTIATE` and transitions into the negotiated state.
    pub async fn negotiate(
        mut self,
        request: &NegotiateRequest,
    ) -> Result<Connection<T, Negotiated>, CoreError> {
        let (header, response) = self
            .transact(
                Command::Negotiate,
                request.encode()?,
                SessionId(0),
                TreeId(0),
                &[0],
                NegotiateResponse::decode,
            )
            .await?;

        if header.session_id != SessionId(0) {
            return Err(CoreError::InvalidResponse(
                "negotiate response must not assign a session id",
            ));
        }

        Ok(Connection {
            transport: self.transport,
            next_message_id: self.next_message_id,
            state: Negotiated { response },
        })
    }
}

impl<T> Connection<T, Negotiated>
where
    T: Transport + Send,
{
    /// Performs `SESSION_SETUP` and transitions into the authenticated state.
    pub async fn session_setup(
        mut self,
        request: &SessionSetupRequest,
    ) -> Result<Connection<T, Authenticated>, CoreError> {
        let negotiated = self.state.response.clone();
        let (header, response) = self
            .transact(
                Command::SessionSetup,
                request.encode(),
                SessionId(0),
                TreeId(0),
                &[0],
                SessionSetupResponse::decode,
            )
            .await?;

        if header.session_id == SessionId(0) {
            return Err(CoreError::InvalidResponse(
                "session setup response must assign a session id",
            ));
        }

        Ok(Connection {
            transport: self.transport,
            next_message_id: self.next_message_id,
            state: Authenticated {
                negotiated,
                session: response,
                session_id: header.session_id,
            },
        })
    }
}

impl<T> Connection<T, Authenticated>
where
    T: Transport + Send,
{
    /// Performs `TREE_CONNECT` and transitions into the tree-connected state.
    pub async fn tree_connect(
        mut self,
        request: &TreeConnectRequest,
    ) -> Result<Connection<T, TreeConnected>, CoreError> {
        let authenticated = self.state.clone();
        let (header, response) = self
            .transact(
                Command::TreeConnect,
                request.encode(),
                authenticated.session_id,
                TreeId(0),
                &[0],
                TreeConnectResponse::decode,
            )
            .await?;

        if header.tree_id == TreeId(0) {
            return Err(CoreError::InvalidResponse(
                "tree connect response must assign a tree id",
            ));
        }

        Ok(Connection {
            transport: self.transport,
            next_message_id: self.next_message_id,
            state: TreeConnected {
                negotiated: authenticated.negotiated,
                session: authenticated.session,
                tree: response,
                session_id: authenticated.session_id,
                tree_id: header.tree_id,
            },
        })
    }
}

impl<T> Connection<T, TreeConnected>
where
    T: Transport + Send,
{
    /// Performs a `CREATE` request on the active tree.
    pub async fn create(&mut self, request: &CreateRequest) -> Result<CreateResponse, CoreError> {
        let tree_id = self.state.tree_id;
        let session_id = self.state.session_id;
        let (_, response) = self
            .transact(
                Command::Create,
                request.encode(),
                session_id,
                tree_id,
                &[0],
                CreateResponse::decode,
            )
            .await?;
        Ok(response)
    }

    /// Performs a `CLOSE` request on the active tree.
    pub async fn close(&mut self, request: &CloseRequest) -> Result<CloseResponse, CoreError> {
        let tree_id = self.state.tree_id;
        let session_id = self.state.session_id;
        let (_, response) = self
            .transact(
                Command::Close,
                request.encode(),
                session_id,
                tree_id,
                &[0],
                CloseResponse::decode,
            )
            .await?;
        Ok(response)
    }

    /// Returns the active session identifier.
    #[must_use]
    pub fn session_id(&self) -> SessionId {
        self.state.session_id
    }

    /// Returns the active tree identifier.
    #[must_use]
    pub fn tree_id(&self) -> TreeId {
        self.state.tree_id
    }
}

impl<T, State> Connection<T, State>
where
    T: Transport + Send,
{
    async fn transact<Response>(
        &mut self,
        command: Command,
        body: Vec<u8>,
        session_id: SessionId,
        tree_id: TreeId,
        accepted_statuses: &[u32],
        decode: fn(&[u8]) -> Result<Response, smolder_proto::smb::ProtocolError>,
    ) -> Result<(Header, Response), CoreError> {
        let message_id = MessageId(self.next_message_id);
        self.next_message_id += 1;

        let mut header = Header::new(command, message_id);
        header.session_id = session_id;
        header.tree_id = tree_id;

        let mut packet = header.encode();
        packet.extend_from_slice(&body);
        let frame = SessionMessage::new(packet).encode()?;

        trace!(?command, message_id = message_id.0, "sending smb request");
        self.transport
            .send(&frame)
            .instrument(trace_span!("smb_send", ?command, message_id = message_id.0))
            .await?;

        let response_frame = self
            .transport
            .recv()
            .instrument(trace_span!("smb_recv", ?command, message_id = message_id.0))
            .await?;
        let response_frame = SessionMessage::decode(&response_frame)?;
        if response_frame.payload.len() < Header::LEN {
            return Err(CoreError::InvalidResponse(
                "response shorter than SMB2 header",
            ));
        }

        let response_header = Header::decode(&response_frame.payload[..Header::LEN])?;
        if response_header.command != command {
            return Err(CoreError::UnexpectedCommand {
                expected: command,
                actual: response_header.command,
            });
        }
        if !accepted_statuses.contains(&response_header.status) {
            return Err(CoreError::UnexpectedStatus {
                command,
                status: response_header.status,
            });
        }

        let response = decode(&response_frame.payload[Header::LEN..])?;
        trace!(
            ?command,
            message_id = message_id.0,
            status = response_header.status,
            "received smb response"
        );

        Ok((response_header, response))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use async_trait::async_trait;
    use smolder_proto::smb::netbios::SessionMessage;
    use smolder_proto::smb::smb2::{
        CloseRequest, CloseResponse, Command, CreateRequest, CreateResponse, Dialect,
        FileAttributes, FileId, GlobalCapabilities, Header, MessageId, NegotiateRequest,
        NegotiateResponse, OplockLevel, SessionFlags, SessionId, SessionSetupRequest,
        SessionSetupResponse, SessionSetupSecurityMode, ShareFlags, ShareType, SigningMode,
        TreeCapabilities, TreeConnectRequest, TreeConnectResponse, TreeId,
    };

    use crate::client::Connection;
    use crate::transport::Transport;

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
        message_id: u64,
        session_id: u64,
        tree_id: u32,
        body: Vec<u8>,
    ) -> Vec<u8> {
        let mut header = Header::new(command, MessageId(message_id));
        header.status = 0;
        header.session_id = SessionId(session_id);
        header.tree_id = TreeId(tree_id);

        let mut packet = header.encode();
        packet.extend_from_slice(&body);
        SessionMessage::new(packet)
            .encode()
            .expect("response should frame")
    }

    fn outbound_header(frame: &[u8]) -> Header {
        let frame = SessionMessage::decode(frame).expect("frame should decode");
        Header::decode(&frame.payload[..Header::LEN]).expect("header should decode")
    }

    #[tokio::test]
    async fn typestate_flow_carries_session_and_tree_ids() {
        let negotiate_response = NegotiateResponse {
            security_mode: SigningMode::ENABLED,
            dialect_revision: Dialect::Smb311,
            negotiate_contexts: Vec::new(),
            server_guid: *b"server-guid-0001",
            capabilities: GlobalCapabilities::DFS | GlobalCapabilities::LARGE_MTU,
            max_transact_size: 65_536,
            max_read_size: 65_536,
            max_write_size: 65_536,
            system_time: 1,
            server_start_time: 1,
            security_buffer: vec![0x60, 0x03],
        };
        let session_response = SessionSetupResponse {
            session_flags: SessionFlags::empty(),
            security_buffer: vec![0xa1, 0x01],
        };
        let tree_response = TreeConnectResponse {
            share_type: ShareType::Disk,
            share_flags: ShareFlags::ENCRYPT_DATA,
            capabilities: TreeCapabilities::CONTINUOUS_AVAILABILITY,
            maximal_access: 0x0012_019f,
        };
        let create_response = CreateResponse {
            oplock_level: OplockLevel::Exclusive,
            file_attributes: FileAttributes::ARCHIVE,
            allocation_size: 4096,
            end_of_file: 128,
            file_id: FileId {
                persistent: 0x11,
                volatile: 0x22,
            },
            create_contexts: Vec::new(),
        };
        let close_response = CloseResponse {
            flags: 0,
            allocation_size: 4096,
            end_of_file: 128,
            file_attributes: FileAttributes::ARCHIVE,
        };

        let transport = ScriptedTransport::new(vec![
            response_frame(Command::Negotiate, 0, 0, 0, negotiate_response.encode()),
            response_frame(Command::SessionSetup, 1, 55, 0, session_response.encode()),
            response_frame(Command::TreeConnect, 2, 55, 9, tree_response.encode()),
            response_frame(Command::Create, 3, 55, 9, create_response.encode()),
            response_frame(Command::Close, 4, 55, 9, close_response.encode()),
        ]);

        let negotiate_request = NegotiateRequest {
            security_mode: SigningMode::ENABLED,
            capabilities: GlobalCapabilities::LARGE_MTU,
            client_guid: *b"client-guid-0001",
            dialects: vec![Dialect::Smb210, Dialect::Smb302, Dialect::Smb311],
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
        let tree_request = TreeConnectRequest::from_unc(r"\\server\share");
        let create_request = CreateRequest::from_path("notes.txt");
        let close_request = CloseRequest {
            flags: 0,
            file_id: create_response.file_id,
        };

        let connection = Connection::new(transport);
        let connection = connection
            .negotiate(&negotiate_request)
            .await
            .expect("negotiate should succeed");
        let connection = connection
            .session_setup(&session_request)
            .await
            .expect("session setup should succeed");
        let mut connection = connection
            .tree_connect(&tree_request)
            .await
            .expect("tree connect should succeed");

        let create = connection
            .create(&create_request)
            .await
            .expect("create should succeed");
        let close = connection
            .close(&close_request)
            .await
            .expect("close should succeed");

        assert_eq!(connection.session_id(), SessionId(55));
        assert_eq!(connection.tree_id(), TreeId(9));
        assert_eq!(create.file_id, close_request.file_id);
        assert_eq!(close.end_of_file, 128);

        let transport = connection.into_transport();
        assert_eq!(transport.writes.len(), 5);

        let negotiate_header = outbound_header(&transport.writes[0]);
        assert_eq!(negotiate_header.command, Command::Negotiate);
        assert_eq!(negotiate_header.message_id, MessageId(0));
        assert_eq!(negotiate_header.session_id, SessionId(0));
        assert_eq!(negotiate_header.tree_id, TreeId(0));

        let session_header = outbound_header(&transport.writes[1]);
        assert_eq!(session_header.command, Command::SessionSetup);
        assert_eq!(session_header.message_id, MessageId(1));
        assert_eq!(session_header.session_id, SessionId(0));

        let tree_header = outbound_header(&transport.writes[2]);
        assert_eq!(tree_header.command, Command::TreeConnect);
        assert_eq!(tree_header.message_id, MessageId(2));
        assert_eq!(tree_header.session_id, SessionId(55));
        assert_eq!(tree_header.tree_id, TreeId(0));

        let create_header = outbound_header(&transport.writes[3]);
        assert_eq!(create_header.command, Command::Create);
        assert_eq!(create_header.message_id, MessageId(3));
        assert_eq!(create_header.session_id, SessionId(55));
        assert_eq!(create_header.tree_id, TreeId(9));

        let close_header = outbound_header(&transport.writes[4]);
        assert_eq!(close_header.command, Command::Close);
        assert_eq!(close_header.message_id, MessageId(4));
        assert_eq!(close_header.session_id, SessionId(55));
        assert_eq!(close_header.tree_id, TreeId(9));
    }
}
