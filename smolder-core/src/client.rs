//! Typestate SMB client built on top of wire-level packet codecs.
//!
//! Most consumers should start with [`Connection`] and the typestate markers,
//! then layer [`crate::pipe::NamedPipe`] or [`crate::rpc::PipeRpcClient`] on
//! top when they need `IPC$` or DCE/RPC behavior. The preauth and signing
//! state types exposed by this module are internal session machinery and are
//! not the intended starting point for new integrations.

use smolder_proto::smb::smb2::{
    ChangeNotifyRequest, ChangeNotifyResponse, CloseRequest, CloseResponse, Command,
    CreateRequest, CreateResponse, EchoRequest, EchoResponse, FileId, FlushRequest,
    FlushResponse, Header, HeaderFlags, IoctlRequest, IoctlResponse, LockRequest, LockResponse,
    LogoffRequest, LogoffResponse, MessageId, NegotiateRequest, NegotiateResponse,
    NetworkInterfaceInfoResponse, QueryDirectoryRequest, QueryDirectoryResponse, QueryInfoRequest,
    QueryInfoResponse, ReadRequest, ReadResponse, ResumeKeyResponse, SessionId,
    SessionSetupRequest, SessionSetupResponse, SessionSetupSecurityMode, SetInfoRequest,
    SetInfoResponse,
    TreeConnectRequest, TreeConnectResponse, TreeDisconnectRequest, TreeDisconnectResponse,
    TreeId, WriteRequest, WriteResponse,
};
use smolder_proto::smb::status::NtStatus;
use tracing::{Instrument, trace, trace_span};

use crate::auth::AuthProvider;
use crate::error::CoreError;
use crate::transport::SmbTransport;

mod helpers;
mod state;

use self::helpers::*;
use self::state::RequestContext;
pub use self::state::{
    Authenticated, CompoundRequest, CompoundResponse, Connected, DurableHandle,
    DurableOpenOptions, Negotiated, PreauthIntegrityState, ResilientHandle, SigningState,
    TreeConnected,
};

/// A typestate SMB connection over an abstract transport.
#[derive(Debug)]
pub struct Connection<T, State> {
    transport: T,
    next_message_id: u64,
    available_credits: u32,
    state: State,
}

#[derive(Debug)]
struct TransactionFrames {
    header: Header,
    request_packet: Vec<u8>,
    response_packet: Vec<u8>,
}

impl TransactionFrames {
    fn body(&self) -> &[u8] {
        &self.response_packet[Header::LEN..]
    }

    fn into_parts(mut self) -> (Header, Vec<u8>) {
        let body = self.response_packet.split_off(Header::LEN);
        (self.header, body)
    }
}


impl<T> Connection<T, Connected> {
    /// Creates a new SMB connection over the provided transport.
    #[must_use]
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            next_message_id: 0,
            available_credits: 1,
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
    T: SmbTransport + Send,
{
    /// Performs `NEGOTIATE` and transitions into the negotiated state.
    pub async fn negotiate(
        mut self,
        request: &NegotiateRequest,
    ) -> Result<Connection<T, Negotiated>, CoreError> {
        let transaction = self
            .transact_framed(
                Command::Negotiate,
                request.encode()?,
                RequestContext::unsigned(SessionId(0), TreeId(0)),
                &[0],
            )
            .await?;
        let response = NegotiateResponse::decode(transaction.body())?;
        let preauth_integrity = negotiate_preauth_integrity_state(
            request,
            &response,
            &transaction.request_packet,
            &transaction.response_packet,
        )?;
        let compression = negotiate_compression_state(request, &response)?;

        if transaction.header.session_id != SessionId(0) {
            return Err(CoreError::InvalidResponse(
                "negotiate response must not assign a session id",
            ));
        }

        Ok(Connection {
            transport: self.transport,
            next_message_id: self.next_message_id,
            available_credits: self.available_credits,
            state: Negotiated {
                response,
                client_signing_mode: request.security_mode,
                preauth_integrity,
                compression,
            },
        })
    }
}

impl<T> Connection<T, Negotiated>
where
    T: SmbTransport + Send,
{
    /// Performs a multi-step authenticated `SESSION_SETUP` exchange.
    pub async fn authenticate<A>(
        mut self,
        auth_provider: &mut A,
    ) -> Result<Connection<T, Authenticated>, CoreError>
    where
        A: AuthProvider,
    {
        let client_signing_mode = self.state.client_signing_mode;
        let mut preauth_integrity = self.state.preauth_integrity.take();
        let security_mode = session_setup_security_mode(client_signing_mode);
        let mut session_id = SessionId(0);
        let mut next_token = auth_provider.initial_token(&self.state.response)?;

        loop {
            let request = SessionSetupRequest {
                flags: 0,
                security_mode,
                capabilities: 0,
                channel: 0,
                security_buffer: next_token,
                previous_session_id: 0,
            };
            let transaction = self
                .transact_framed(
                    Command::SessionSetup,
                    request.encode(),
                    RequestContext::unsigned(session_id, TreeId(0))
                        .with_compression(self.state.compression.clone()),
                    &[
                        NtStatus::SUCCESS.to_u32(),
                        NtStatus::MORE_PROCESSING_REQUIRED.to_u32(),
                    ],
                )
                .await?;
            let response = SessionSetupResponse::decode(transaction.body())?;
            let header = transaction.header;
            let success = header.status == NtStatus::SUCCESS.to_u32();
            update_session_setup_preauth(
                &mut preauth_integrity,
                &transaction.request_packet,
                &transaction.response_packet,
                success,
            )?;

            if header.session_id == SessionId(0) {
                return Err(CoreError::InvalidResponse(
                    "session setup response must assign a session id",
                ));
            }
            if session_id != SessionId(0) && header.session_id != session_id {
                return Err(CoreError::InvalidResponse(
                    "session setup response changed the active session id",
                ));
            }

            session_id = header.session_id;
            if success {
                let raw_response_session_key = auth_provider.session_key().map(ToOwned::to_owned);
                let response_session_key =
                    derive_smb_session_key(raw_response_session_key.as_deref());
                let signing_required = session_signing_required(
                    client_signing_mode,
                    self.state.response.security_mode,
                    response.session_flags,
                );
                let response_signing = derive_signing_state(
                    self.state.response.dialect_revision,
                    response_session_key.as_deref(),
                    preauth_integrity.as_ref(),
                )?;
                verify_final_session_setup_response(
                    self.state.response.dialect_revision,
                    &header,
                    &transaction.response_packet,
                    signing_required,
                    response_signing.as_deref(),
                )?;
                auth_provider.finish(&response.security_buffer)?;
                let raw_session_key = auth_provider.session_key().map(ToOwned::to_owned);
                let session_key = derive_smb_session_key(raw_session_key.as_deref());
                let signing = derive_signing_state(
                    self.state.response.dialect_revision,
                    session_key.as_deref(),
                    preauth_integrity.as_ref(),
                )?;
                let encryption = derive_encryption_state(
                    &self.state.response,
                    raw_session_key.as_deref(),
                    preauth_integrity.as_ref(),
                )?;
                let Connection {
                    transport,
                    next_message_id,
                    available_credits,
                    state,
                } = self;
                let Negotiated {
                    response: negotiated,
                    client_signing_mode,
                    compression,
                    ..
                } = state;
                let encryption_required =
                    session_encryption_required(&negotiated, response.session_flags)?;
                return Ok(Connection {
                    transport,
                    next_message_id,
                    available_credits,
                    state: Authenticated {
                        negotiated,
                        client_signing_mode,
                        session: response,
                        session_id,
                        preauth_integrity,
                        session_key,
                        signing_required,
                        signing,
                        encryption_required,
                        encryption,
                        compression,
                    },
                });
            }

            next_token = auth_provider.next_token(&response.security_buffer)?;
        }
    }

    /// Performs `SESSION_SETUP` and transitions into the authenticated state.
    pub async fn session_setup(
        mut self,
        request: &SessionSetupRequest,
    ) -> Result<Connection<T, Authenticated>, CoreError> {
        let client_signing_mode = self.state.client_signing_mode;
        let mut preauth_integrity = self.state.preauth_integrity.take();
        let transaction = self
            .transact_framed(
                Command::SessionSetup,
                request.encode(),
                RequestContext::unsigned(SessionId(0), TreeId(0))
                    .with_compression(self.state.compression.clone()),
                &[0],
            )
            .await?;
        let response = SessionSetupResponse::decode(transaction.body())?;
        let header = transaction.header;
        let success = header.status == NtStatus::SUCCESS.to_u32();
        update_session_setup_preauth(
            &mut preauth_integrity,
            &transaction.request_packet,
            &transaction.response_packet,
            success,
        )?;

        if header.session_id == SessionId(0) {
            return Err(CoreError::InvalidResponse(
                "session setup response must assign a session id",
            ));
        }
        verify_final_session_setup_response(
            self.state.response.dialect_revision,
            &header,
            &transaction.response_packet,
            request
                .security_mode
                .contains(SessionSetupSecurityMode::SIGNING_REQUIRED),
            None,
        )?;
        let signing_required = session_signing_required(
            client_signing_mode,
            self.state.response.security_mode,
            response.session_flags,
        );
        let encryption =
            derive_encryption_state(&self.state.response, None, preauth_integrity.as_ref())?;
        let Connection {
            transport,
            next_message_id,
            available_credits,
            state,
        } = self;
        let Negotiated {
            response: negotiated,
            client_signing_mode,
            compression,
            ..
        } = state;
        let encryption_required = session_encryption_required(&negotiated, response.session_flags)?;

        Ok(Connection {
            transport,
            next_message_id,
            available_credits,
            state: Authenticated {
                negotiated,
                client_signing_mode,
                session: response,
                session_id: header.session_id,
                preauth_integrity,
                session_key: None,
                signing_required,
                signing: None,
                encryption_required,
                encryption,
                compression,
            },
        })
    }
}

impl<T> Connection<T, Authenticated>
where
    T: SmbTransport + Send,
{
    /// Returns the active session identifier.
    #[must_use]
    pub fn session_id(&self) -> SessionId {
        self.state.session_id
    }

    /// Returns the exported session key for the authenticated session, if available.
    #[must_use]
    pub fn session_key(&self) -> Option<&[u8]> {
        self.state.session_key.as_deref()
    }

    /// Executes a raw compound request within the authenticated session.
    pub async fn compound_raw(
        &mut self,
        requests: &[CompoundRequest],
    ) -> Result<Vec<CompoundResponse>, CoreError> {
        let context = self.state.request_context();
        self.transact_compound_raw(requests, context).await
    }

    /// Performs an `ECHO` request against the active SMB session.
    pub async fn echo(&mut self) -> Result<EchoResponse, CoreError> {
        let context = self.state.request_context();
        let (_, response) = self
            .transact(
                Command::Echo,
                EchoRequest.encode(),
                context,
                &[NtStatus::SUCCESS.to_u32()],
                EchoResponse::decode,
            )
            .await?;
        Ok(response)
    }

    /// Performs `LOGOFF` and transitions back into the negotiated state.
    pub async fn logoff(mut self) -> Result<Connection<T, Negotiated>, CoreError> {
        let context = self.state.request_context();
        let _ = self
            .transact(
                Command::Logoff,
                LogoffRequest.encode(),
                context,
                &[0],
                LogoffResponse::decode,
            )
            .await?;
        let Connection {
            transport,
            next_message_id,
            available_credits,
            state,
        } = self;
        let Authenticated {
            negotiated: response,
            client_signing_mode,
            preauth_integrity,
            compression,
            ..
        } = state;

        Ok(Connection {
            transport,
            next_message_id,
            available_credits,
            state: Negotiated {
                response,
                client_signing_mode,
                preauth_integrity,
                compression,
            },
        })
    }

    /// Performs `TREE_CONNECT` and transitions into the tree-connected state.
    pub async fn tree_connect(
        mut self,
        request: &TreeConnectRequest,
    ) -> Result<Connection<T, TreeConnected>, CoreError> {
        let context = self.state.request_context();
        let (header, response) = self
            .transact(
                Command::TreeConnect,
                request.encode(),
                context,
                &[0],
                TreeConnectResponse::decode,
            )
            .await?;

        if header.tree_id == TreeId(0) {
            return Err(CoreError::InvalidResponse(
                "tree connect response must assign a tree id",
            ));
        }
        let Connection {
            transport,
            next_message_id,
            available_credits,
            state,
        } = self;
        let Authenticated {
            negotiated,
            client_signing_mode,
            session,
            session_id,
            preauth_integrity,
            session_key,
            signing_required,
            signing,
            encryption_required: _,
            encryption,
            compression,
        } = state;
        let encryption_required =
            tree_encryption_required(&negotiated, session.session_flags, response.share_flags)?;

        Ok(Connection {
            transport,
            next_message_id,
            available_credits,
            state: TreeConnected {
                negotiated,
                client_signing_mode,
                session,
                tree: response,
                session_id,
                tree_id: header.tree_id,
                preauth_integrity,
                session_key,
                signing_required,
                signing,
                encryption_required,
                encryption,
                compression,
            },
        })
    }
}

impl<T> Connection<T, TreeConnected>
where
    T: SmbTransport + Send,
{
    /// Executes a raw compound request on the active tree.
    pub async fn compound_raw(
        &mut self,
        requests: &[CompoundRequest],
    ) -> Result<Vec<CompoundResponse>, CoreError> {
        let context = self.state.request_context();
        self.transact_compound_raw(requests, context).await
    }

    /// Performs a `TREE_DISCONNECT` request and returns to the authenticated state.
    pub async fn tree_disconnect(mut self) -> Result<Connection<T, Authenticated>, CoreError> {
        let context = self.state.request_context();
        let _ = self
            .transact(
                Command::TreeDisconnect,
                TreeDisconnectRequest.encode(),
                context,
                &[0],
                TreeDisconnectResponse::decode,
            )
            .await?;
        let Connection {
            transport,
            next_message_id,
            available_credits,
            state,
        } = self;
        let TreeConnected {
            negotiated,
            client_signing_mode,
            session,
            session_id,
            preauth_integrity,
            session_key,
            signing_required,
            signing,
            encryption,
            compression,
            ..
        } = state;
        let encryption_required = session_encryption_required(&negotiated, session.session_flags)?;

        Ok(Connection {
            transport,
            next_message_id,
            available_credits,
            state: Authenticated {
                negotiated,
                client_signing_mode,
                session,
                session_id,
                preauth_integrity,
                session_key,
                signing_required,
                signing,
                encryption_required,
                encryption,
                compression,
            },
        })
    }

    /// Performs a `CREATE` request on the active tree.
    pub async fn create(&mut self, request: &CreateRequest) -> Result<CreateResponse, CoreError> {
        let context = self.state.request_context();
        let (_, response) = self
            .transact(
                Command::Create,
                request.encode(),
                context,
                &[0],
                CreateResponse::decode,
            )
            .await?;
        Ok(response)
    }

    /// Performs a durable `CREATE` request and captures the reconnect state.
    pub async fn create_durable(
        &mut self,
        request: &CreateRequest,
        options: DurableOpenOptions,
    ) -> Result<DurableHandle, CoreError> {
        let durable_request =
            durable_create_request(self.state.negotiated.dialect_revision, request, &options)?;
        let response = self.create(&durable_request).await?;
        build_durable_handle(
            self.state.negotiated.dialect_revision,
            request,
            response,
            &options,
        )
    }

    /// Replays a previously captured durable open against the current session/tree.
    pub async fn reconnect_durable(
        &mut self,
        handle: &DurableHandle,
    ) -> Result<DurableHandle, CoreError> {
        let reconnect_request =
            durable_reconnect_request(self.state.negotiated.dialect_revision, handle)?;
        let response = self.create(&reconnect_request).await?;
        Ok(handle.with_response(response))
    }

    /// Replays a durable open and reapplies resiliency when the handle recorded a timeout.
    pub async fn reconnect_durable_with_resiliency(
        &mut self,
        handle: &DurableHandle,
    ) -> Result<(DurableHandle, Option<ResilientHandle>), CoreError> {
        let reopened = self.reconnect_durable(handle).await?;
        if let Some(timeout) = handle.resilient_timeout() {
            let resilient = self.request_resiliency(reopened.file_id(), timeout).await?;
            return Ok((reopened.with_resilient_timeout(timeout), Some(resilient)));
        }
        Ok((reopened, None))
    }

    /// Requests handle resiliency for an existing open file identifier.
    pub async fn request_resiliency(
        &mut self,
        file_id: FileId,
        timeout: u32,
    ) -> Result<ResilientHandle, CoreError> {
        let _ = self
            .ioctl(&IoctlRequest::request_resiliency(file_id, timeout))
            .await?;
        Ok(ResilientHandle { file_id, timeout })
    }

    /// Performs an `ECHO` request against the active SMB session.
    pub async fn echo(&mut self) -> Result<EchoResponse, CoreError> {
        let context = self.state.session_request_context();
        let (_, response) = self
            .transact(
                Command::Echo,
                EchoRequest.encode(),
                context,
                &[NtStatus::SUCCESS.to_u32()],
                EchoResponse::decode,
            )
            .await?;
        Ok(response)
    }

    /// Performs a `LOCK` request on the active tree.
    pub async fn lock(&mut self, request: &LockRequest) -> Result<LockResponse, CoreError> {
        let context = self.state.request_context();
        let (_, response) = self
            .transact(
                Command::Lock,
                request.encode(),
                context,
                &[NtStatus::SUCCESS.to_u32()],
                LockResponse::decode,
            )
            .await?;
        Ok(response)
    }

    /// Performs a `CHANGE_NOTIFY` request on the active tree.
    pub async fn change_notify(
        &mut self,
        request: &ChangeNotifyRequest,
    ) -> Result<ChangeNotifyResponse, CoreError> {
        let context = self.state.request_context();
        let (_, response) = self
            .transact(
                Command::ChangeNotify,
                request.encode(),
                context,
                &[NtStatus::SUCCESS.to_u32()],
                ChangeNotifyResponse::decode,
            )
            .await?;
        Ok(response)
    }

    /// Performs a `READ` request on the active tree.
    pub async fn read(&mut self, request: &ReadRequest) -> Result<ReadResponse, CoreError> {
        let context = self.state.request_context();
        let (_, response) = self
            .transact(
                Command::Read,
                request.encode(),
                context,
                &[0],
                ReadResponse::decode,
            )
            .await?;
        Ok(response)
    }

    /// Performs a `WRITE` request on the active tree.
    pub async fn write(&mut self, request: &WriteRequest) -> Result<WriteResponse, CoreError> {
        let context = self.state.request_context();
        let (_, response) = self
            .transact(
                Command::Write,
                request.encode(),
                context,
                &[0],
                WriteResponse::decode,
            )
            .await?;
        Ok(response)
    }

    /// Performs a `CLOSE` request on the active tree.
    pub async fn close(&mut self, request: &CloseRequest) -> Result<CloseResponse, CoreError> {
        let context = self.state.request_context();
        let (_, response) = self
            .transact(
                Command::Close,
                request.encode(),
                context,
                &[0],
                CloseResponse::decode,
            )
            .await?;
        Ok(response)
    }

    /// Performs a `FLUSH` request on the active tree.
    pub async fn flush(&mut self, request: &FlushRequest) -> Result<FlushResponse, CoreError> {
        let context = self.state.request_context();
        let (_, response) = self
            .transact(
                Command::Flush,
                request.encode(),
                context,
                &[0],
                FlushResponse::decode,
            )
            .await?;
        Ok(response)
    }

    /// Performs an `IOCTL` request on the active tree.
    pub async fn ioctl(&mut self, request: &IoctlRequest) -> Result<IoctlResponse, CoreError> {
        let context = self.state.request_context();
        let (_, response) = self
            .transact(
                Command::Ioctl,
                request.encode(),
                context,
                &[NtStatus::SUCCESS.to_u32()],
                IoctlResponse::decode,
            )
            .await?;
        Ok(response)
    }

    /// Queries the server's network-interface inventory through `FSCTL_QUERY_NETWORK_INTERFACE_INFO`.
    pub async fn query_network_interfaces(
        &mut self,
        max_output_response: u32,
    ) -> Result<NetworkInterfaceInfoResponse, CoreError> {
        let response = self
            .ioctl(&IoctlRequest::query_network_interface_info(
                max_output_response,
            ))
            .await?;
        NetworkInterfaceInfoResponse::decode(&response.output).map_err(CoreError::from)
    }

    /// Requests a server-side resume key for an open file handle.
    pub async fn request_resume_key(
        &mut self,
        file_id: FileId,
    ) -> Result<ResumeKeyResponse, CoreError> {
        let response = self
            .ioctl(&IoctlRequest::request_resume_key(file_id))
            .await?;
        ResumeKeyResponse::decode(&response.output).map_err(CoreError::from)
    }

    /// Performs a `QUERY_DIRECTORY` request on the active tree.
    pub async fn query_directory(
        &mut self,
        request: &QueryDirectoryRequest,
    ) -> Result<QueryDirectoryResponse, CoreError> {
        let context = self.state.request_context();
        let (header, body) = self
            .transact_raw(
                Command::QueryDirectory,
                request.encode(),
                context,
                &[NtStatus::SUCCESS.to_u32(), NtStatus::NO_MORE_FILES.to_u32()],
            )
            .await?;
        if header.status == NtStatus::NO_MORE_FILES.to_u32() {
            return Ok(QueryDirectoryResponse::empty());
        }
        QueryDirectoryResponse::decode(&body).map_err(CoreError::from)
    }

    /// Performs a `QUERY_INFO` request on the active tree.
    pub async fn query_info(
        &mut self,
        request: &QueryInfoRequest,
    ) -> Result<QueryInfoResponse, CoreError> {
        let context = self.state.request_context();
        let (_, response) = self
            .transact(
                Command::QueryInfo,
                request.encode(),
                context,
                &[NtStatus::SUCCESS.to_u32()],
                QueryInfoResponse::decode,
            )
            .await?;
        Ok(response)
    }

    /// Performs a `SET_INFO` request on the active tree.
    pub async fn set_info(
        &mut self,
        request: &SetInfoRequest,
    ) -> Result<SetInfoResponse, CoreError> {
        let context = self.state.request_context();
        let (_, response) = self
            .transact(
                Command::SetInfo,
                request.encode(),
                context,
                &[NtStatus::SUCCESS.to_u32()],
                SetInfoResponse::decode,
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

    /// Returns the exported session key for the authenticated session, if available.
    #[must_use]
    pub fn session_key(&self) -> Option<&[u8]> {
        self.state.session_key.as_deref()
    }
}

impl<T, State> Connection<T, State>
where
    T: SmbTransport + Send,
{
    async fn transact_compound_raw(
        &mut self,
        requests: &[CompoundRequest],
        context: RequestContext,
    ) -> Result<Vec<CompoundResponse>, CoreError> {
        let request_packets = self.build_compound_request_packets(requests, &context)?;
        let payload = request_packets
            .iter()
            .flat_map(|packet| packet.iter().copied())
            .collect::<Vec<_>>();
        let message = encode_transport_payload(&payload, &context)?;
        let first_command = requests[0].command;
        let last_command = requests[requests.len() - 1].command;

        trace!(
            first_command = ?first_command,
            last_command = ?last_command,
            request_count = requests.len(),
            "sending compound smb request"
        );
        self.transport
            .send_message(&message)
            .instrument(trace_span!(
                "smb_send_compound",
                first_command = ?first_command,
                last_command = ?last_command,
                request_count = requests.len()
            ))
            .await?;

        let response_message = self
            .transport
            .recv_message()
            .instrument(trace_span!(
                "smb_recv_compound",
                first_command = ?first_command,
                last_command = ?last_command,
                request_count = requests.len()
            ))
            .await?;
        let (response_payload, encrypted_response) =
            decode_transport_payload(&response_message, &context)?;
        let response_packets = split_compound_packets(&response_payload)?;
        if response_packets.len() != requests.len() {
            return Err(CoreError::InvalidResponse(
                "compound response count did not match the request chain",
            ));
        }

        let mut responses = Vec::with_capacity(requests.len());
        let mut granted_credits = 0u32;
        for ((request, request_packet), response_packet) in requests
            .iter()
            .zip(request_packets.iter())
            .zip(response_packets.iter())
        {
            let request_header = Header::decode(&request_packet[..Header::LEN])?;
            let response_header = Header::decode(&response_packet[..Header::LEN])?;
            if response_header.command != request.command {
                return Err(CoreError::UnexpectedCommand {
                    expected: request.command,
                    actual: response_header.command,
                });
            }
            if response_header.message_id != request_header.message_id {
                return Err(CoreError::InvalidResponse(
                    "compound response message id did not match the request element",
                ));
            }
            if response_header.status == NtStatus::PENDING.to_u32()
                || response_header.flags.contains(HeaderFlags::ASYNC_COMMAND)
            {
                return Err(CoreError::Unsupported(
                    "compound async SMB responses are not supported yet",
                ));
            }
            if !encrypted_response {
                verify_response_signature(&response_header, response_packet, &context)?;
            }
            if !request.accepted_statuses.contains(&response_header.status) {
                return Err(CoreError::UnexpectedStatus {
                    command: request.command,
                    status: response_header.status,
                });
            }
            granted_credits = granted_credits
                .checked_add(u32::from(response_header.credit_request_response))
                .ok_or(CoreError::InvalidResponse(
                    "server granted too many SMB credits",
                ))?;
            responses.push(CompoundResponse {
                header: response_header,
                body: response_packet[Header::LEN..].to_vec(),
            });
        }
        self.apply_credit_grant(granted_credits)?;
        Ok(responses)
    }

    async fn transact<Response>(
        &mut self,
        command: Command,
        body: Vec<u8>,
        context: RequestContext,
        accepted_statuses: &[u32],
        decode: fn(&[u8]) -> Result<Response, smolder_proto::smb::ProtocolError>,
    ) -> Result<(Header, Response), CoreError> {
        let transaction = self
            .transact_framed(command, body, context, accepted_statuses)
            .await?;
        let response = decode(transaction.body())?;
        trace!(
            ?command,
            message_id = transaction.header.message_id.0,
            status = transaction.header.status,
            "received smb response"
        );

        Ok((transaction.header, response))
    }

    async fn transact_raw(
        &mut self,
        command: Command,
        body: Vec<u8>,
        context: RequestContext,
        accepted_statuses: &[u32],
    ) -> Result<(Header, Vec<u8>), CoreError> {
        let transaction = self
            .transact_framed(command, body, context, accepted_statuses)
            .await?;
        Ok(transaction.into_parts())
    }

    async fn transact_framed(
        &mut self,
        command: Command,
        body: Vec<u8>,
        context: RequestContext,
        accepted_statuses: &[u32],
    ) -> Result<TransactionFrames, CoreError> {
        if context.should_encrypt() && context.encryption.is_none() {
            return Err(CoreError::InvalidInput(
                "session requires encryption but no encryption key is available",
            ));
        }
        if !context.should_encrypt() && context.signing_required && context.signing.is_none() {
            return Err(CoreError::InvalidInput(
                "session requires signing but no signing key is available",
            ));
        }
        let message_id = self.preview_message_ids(1)?[0];

        let mut header = Header::new(command, message_id);
        header.session_id = context.session_id;
        header.tree_id = context.tree_id;
        header.credit_request_response = self.credit_request_hint_after_reserve(1);
        if context.signing.is_some() && !context.should_encrypt() {
            header.flags |= HeaderFlags::SIGNED;
        }

        let mut packet = header.encode();
        packet.extend_from_slice(&body);
        if let Some(signing) = context
            .signing
            .as_deref()
            .filter(|_| !context.should_encrypt())
        {
            signing.sign_packet(&mut packet)?;
        }
        let message = encode_transport_payload(&packet, &context)?;
        self.commit_message_ids(1)?;

        trace!(?command, message_id = message_id.0, "sending smb request");
        self.transport
            .send_message(&message)
            .instrument(trace_span!("smb_send", ?command, message_id = message_id.0))
            .await?;

        let mut pending_async_id = None;
        loop {
            let response_message = self
                .transport
                .recv_message()
                .instrument(trace_span!("smb_recv", ?command, message_id = message_id.0))
                .await?;
            let (response_payload, encrypted_response) =
                decode_transport_payload(&response_message, &context)?;
            if response_payload.len() < Header::LEN {
                return Err(CoreError::InvalidResponse(
                    "response shorter than SMB2 header",
                ));
            }

            let response_header = Header::decode(&response_payload[..Header::LEN])?;
            if response_header.command != command {
                return Err(CoreError::UnexpectedCommand {
                    expected: command,
                    actual: response_header.command,
                });
            }
            if response_header.message_id != message_id {
                return Err(CoreError::InvalidResponse(
                    "response message id did not match the request",
                ));
            }

            if response_header.status == NtStatus::PENDING.to_u32() {
                let async_id = validate_pending_response(&response_header)?;
                self.apply_credit_grant(u32::from(response_header.credit_request_response))?;
                pending_async_id = Some(async_id);
                trace!(
                    ?command,
                    message_id = response_header.message_id.0,
                    async_id = async_id.0,
                    "received interim async SMB response"
                );
                continue;
            }

            if let Some(async_id) = pending_async_id {
                validate_async_final_response(&response_header, async_id)?;
            }

            if command != Command::SessionSetup && !encrypted_response {
                verify_response_signature(&response_header, &response_payload, &context)?;
            }
            self.apply_credit_grant(u32::from(response_header.credit_request_response))?;
            if !accepted_statuses.contains(&response_header.status) {
                return Err(CoreError::UnexpectedStatus {
                    command,
                    status: response_header.status,
                });
            }

            return Ok(TransactionFrames {
                header: response_header,
                request_packet: packet,
                response_packet: response_payload,
            });
        }
    }

    fn preview_message_ids(&self, count: usize) -> Result<Vec<MessageId>, CoreError> {
        let count = self.validate_request_count(count)?;
        let start = self.next_message_id;

        Ok((0..count)
            .map(|offset| MessageId(start + u64::from(offset)))
            .collect())
    }

    fn commit_message_ids(&mut self, count: usize) -> Result<(), CoreError> {
        let count = self.validate_request_count(count)?;
        self.next_message_id =
            self.next_message_id
                .checked_add(u64::from(count))
                .ok_or(CoreError::InvalidInput(
                    "message id space exhausted for SMB request dispatch",
                ))?;
        self.available_credits -= count;
        Ok(())
    }

    fn validate_request_count(&self, count: usize) -> Result<u32, CoreError> {
        if count == 0 {
            return Err(CoreError::InvalidInput(
                "compound request chain must contain at least one element",
            ));
        }
        let count = u32::try_from(count)
            .map_err(|_| CoreError::InvalidInput("too many SMB requests in one chain"))?;
        if self.available_credits < count {
            return Err(CoreError::Unsupported(
                "insufficient SMB credits available for the requested chain",
            ));
        }

        Ok(count)
    }

    fn apply_credit_grant(&mut self, granted: u32) -> Result<(), CoreError> {
        self.available_credits =
            self.available_credits
                .checked_add(granted)
                .ok_or(CoreError::InvalidResponse(
                    "server granted too many SMB credits",
                ))?;
        Ok(())
    }

    fn credit_request_hint_after_reserve(&self, count: usize) -> u16 {
        const TARGET_CREDIT_FLOOR: u32 = 32;

        let count = u32::try_from(count).unwrap_or(u32::MAX);
        let available_after_reserve = self.available_credits.saturating_sub(count);
        count
            .max(TARGET_CREDIT_FLOOR.saturating_sub(available_after_reserve))
            .min(u32::from(u16::MAX)) as u16
    }

    fn build_compound_request_packets(
        &mut self,
        requests: &[CompoundRequest],
        context: &RequestContext,
    ) -> Result<Vec<Vec<u8>>, CoreError> {
        if requests.is_empty() {
            return Err(CoreError::InvalidInput(
                "compound request chain must contain at least one element",
            ));
        }
        if requests[0].related {
            return Err(CoreError::InvalidInput(
                "the first compound request element cannot be marked related",
            ));
        }
        if context.should_encrypt() && context.encryption.is_none() {
            return Err(CoreError::InvalidInput(
                "session requires encryption but no encryption key is available",
            ));
        }
        if !context.should_encrypt() && context.signing_required && context.signing.is_none() {
            return Err(CoreError::InvalidInput(
                "session requires signing but no signing key is available",
            ));
        }

        let message_ids = self.preview_message_ids(requests.len())?;
        let last_request_credit = self.credit_request_hint_after_reserve(requests.len());
        let mut packets = Vec::with_capacity(requests.len());
        for (index, (request, message_id)) in requests.iter().zip(message_ids.iter()).enumerate() {
            let mut header = Header::new(request.command, *message_id);
            header.session_id = context.session_id;
            header.tree_id = context.tree_id;
            header.credit_request_response = if index + 1 == requests.len() {
                last_request_credit
            } else {
                1
            };
            if request.related {
                header.flags |= HeaderFlags::RELATED_OPERATIONS;
            }
            if context.signing.is_some() && !context.should_encrypt() {
                header.flags |= HeaderFlags::SIGNED;
            }

            let base_len =
                Header::LEN
                    .checked_add(request.body.len())
                    .ok_or(CoreError::InvalidInput(
                        "compound request element was too large",
                    ))?;
            let packet_len = if index + 1 == requests.len() {
                base_len
            } else {
                align_to_8(base_len)
            };
            if index + 1 < requests.len() {
                header.next_command = u32::try_from(packet_len).map_err(|_| {
                    CoreError::InvalidInput(
                        "compound request element exceeded SMB next-command limits",
                    )
                })?;
            }

            let mut packet = header.encode();
            packet.extend_from_slice(&request.body);
            if index + 1 < requests.len() {
                packet.resize(packet_len, 0);
            }
            if let Some(signing) = context
                .signing
                .as_deref()
                .filter(|_| !context.should_encrypt())
            {
                signing.sign_packet(&mut packet)?;
            }
            packets.push(packet);
        }
        self.commit_message_ids(requests.len())?;

        Ok(packets)
    }
}

#[cfg(test)]
mod tests {
    use lznt1::compress as lznt1_compress;
    use std::collections::VecDeque;
    use std::sync::Arc;

    use async_trait::async_trait;
    use smolder_proto::smb::compression::{
        COMPRESSION_TRANSFORM_PROTOCOL_ID, CompressionAlgorithm, CompressionCapabilityFlags,
        CompressionFlags, CompressionTransformHeader,
    };
    use smolder_proto::smb::netbios::SessionMessage;
    use smolder_proto::smb::smb2::{
        AsyncId, ChangeNotifyFlags, ChangeNotifyRequest, ChangeNotifyResponse, CipherId,
        CloseRequest, CloseResponse, Command, CompletionFilter, CompressionCapabilities,
        CreateRequest, CreateResponse, Dialect, EchoResponse, EncryptionCapabilities,
        FileAttributes, FileId, FlushRequest, FlushResponse, GlobalCapabilities, Header,
        HeaderFlags, IoctlRequest, IoctlResponse, LockElement, LockFlags, LockRequest,
        LockResponse, LogoffRequest, LogoffResponse, MessageId, NegotiateContext, NegotiateRequest,
        NegotiateResponse, OplockLevel, PreauthIntegrityCapabilities, PreauthIntegrityHashId,
        ReadRequest, ReadResponse, ReadResponseFlags, SessionFlags, SessionId, SessionSetupRequest,
        SessionSetupResponse, SessionSetupSecurityMode, ShareFlags, ShareType, SigningMode,
        TransportCapabilities, TransportCapabilityFlags, TreeCapabilities, TreeConnectRequest,
        TreeConnectResponse, TreeDisconnectRequest, TreeId, WriteRequest, WriteResponse,
    };
    use smolder_proto::smb::status::NtStatus;
    use smolder_proto::smb::transform::TransformHeader;

    use crate::auth::{AuthError, AuthProvider};
    use crate::client::Connection;
    use crate::compression::CompressionState;
    use crate::crypto::{EncryptionState, derive_encryption_keys};
    use crate::error::CoreError;
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

    fn smb311_response_with_transport_security() -> NegotiateResponse {
        NegotiateResponse {
            security_mode: SigningMode::ENABLED,
            dialect_revision: Dialect::Smb311,
            server_guid: [0; 16],
            capabilities: GlobalCapabilities::ENCRYPTION,
            max_transact_size: 0x100000,
            max_read_size: 0x100000,
            max_write_size: 0x100000,
            system_time: 0,
            server_start_time: 0,
            security_buffer: Vec::new(),
            negotiate_contexts: vec![NegotiateContext::transport_capabilities(
                TransportCapabilities {
                    flags: TransportCapabilityFlags::ACCEPT_TRANSPORT_LEVEL_SECURITY,
                },
            )],
        }
    }

    #[test]
    fn transport_security_disables_smb_encryption_requirement() {
        let negotiated = smb311_response_with_transport_security();
        let required = super::session_encryption_required(&negotiated, SessionFlags::ENCRYPT_DATA)
            .expect("transport security should decode");
        assert!(!required);
    }

    #[test]
    fn transport_security_suppresses_derived_encryption_state() {
        let negotiated = smb311_response_with_transport_security();
        let encryption = super::derive_encryption_state(&negotiated, Some(&[0x11; 32]), None)
            .expect("transport security should decode");
        assert!(encryption.is_none());
    }

    #[test]
    fn duplicate_transport_security_contexts_are_rejected() {
        let mut negotiated = smb311_response_with_transport_security();
        negotiated
            .negotiate_contexts
            .push(NegotiateContext::transport_capabilities(
                TransportCapabilities {
                    flags: TransportCapabilityFlags::ACCEPT_TRANSPORT_LEVEL_SECURITY,
                },
            ));

        let error = super::transport_level_security_accepted(&negotiated)
            .expect_err("duplicate transport contexts should be rejected");
        assert!(matches!(
            error,
            CoreError::InvalidResponse(
                "SMB 3.1.1 negotiate response contained multiple transport-capabilities contexts"
            )
        ));
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
        let packet =
            response_packet_with_credits(command, status, message_id, session_id, tree_id, 1, body);
        SessionMessage::new(packet)
            .encode()
            .expect("response should frame")
    }

    fn response_frame_with_credits(
        command: Command,
        status: u32,
        message_id: u64,
        session_id: u64,
        tree_id: u32,
        credits: u16,
        body: Vec<u8>,
    ) -> Vec<u8> {
        let packet = response_packet_with_credits(
            command, status, message_id, session_id, tree_id, credits, body,
        );
        SessionMessage::new(packet)
            .encode()
            .expect("response should frame")
    }

    fn response_packet(
        command: Command,
        status: u32,
        message_id: u64,
        session_id: u64,
        tree_id: u32,
        body: Vec<u8>,
    ) -> Vec<u8> {
        response_packet_with_credits(command, status, message_id, session_id, tree_id, 1, body)
    }

    fn response_packet_with_credits(
        command: Command,
        status: u32,
        message_id: u64,
        session_id: u64,
        tree_id: u32,
        credits: u16,
        body: Vec<u8>,
    ) -> Vec<u8> {
        let mut header = Header::new(command, MessageId(message_id));
        header.status = status;
        header.flags = HeaderFlags::SERVER_TO_REDIR;
        header.session_id = SessionId(session_id);
        header.tree_id = TreeId(tree_id);
        header.credit_request_response = credits;

        let mut packet = header.encode();
        packet.extend_from_slice(&body);
        packet
    }

    fn request_packet_with_credits(
        command: Command,
        message_id: u64,
        session_id: u64,
        tree_id: u32,
        credits: u16,
        body: Vec<u8>,
    ) -> Vec<u8> {
        let mut header = Header::new(command, MessageId(message_id));
        header.session_id = SessionId(session_id);
        header.tree_id = TreeId(tree_id);
        header.credit_request_response = credits;

        let mut packet = header.encode();
        packet.extend_from_slice(&body);
        packet
    }

    fn async_response_frame(
        command: Command,
        status: u32,
        message_id: u64,
        async_id: u64,
        session_id: u64,
        body: Vec<u8>,
    ) -> Vec<u8> {
        let mut header = Header::new(command, MessageId(message_id));
        header.status = status;
        header.flags = HeaderFlags::SERVER_TO_REDIR | HeaderFlags::ASYNC_COMMAND;
        header.async_id = Some(AsyncId(async_id));
        header.session_id = SessionId(session_id);

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

    fn outbound_headers(frame: &[u8]) -> Vec<Header> {
        let frame = SessionMessage::decode(frame).expect("frame should decode");
        super::split_compound_packets(&frame.payload)
            .expect("compound frame should decode")
            .iter()
            .map(|packet| Header::decode(&packet[..Header::LEN]).expect("header should decode"))
            .collect()
    }

    fn outbound_session_setup(frame: &[u8]) -> SessionSetupRequest {
        let frame = SessionMessage::decode(frame).expect("frame should decode");
        SessionSetupRequest::decode(&frame.payload[Header::LEN..]).expect("request should decode")
    }

    fn outbound_read(frame: &[u8]) -> ReadRequest {
        let frame = SessionMessage::decode(frame).expect("frame should decode");
        ReadRequest::decode(&frame.payload[Header::LEN..]).expect("request should decode")
    }

    fn outbound_write(frame: &[u8]) -> WriteRequest {
        let frame = SessionMessage::decode(frame).expect("frame should decode");
        WriteRequest::decode(&frame.payload[Header::LEN..]).expect("request should decode")
    }

    fn outbound_flush(frame: &[u8]) -> FlushRequest {
        let frame = SessionMessage::decode(frame).expect("frame should decode");
        FlushRequest::decode(&frame.payload[Header::LEN..]).expect("request should decode")
    }

    fn outbound_ioctl(frame: &[u8]) -> IoctlRequest {
        let frame = SessionMessage::decode(frame).expect("frame should decode");
        IoctlRequest::decode(&frame.payload[Header::LEN..]).expect("request should decode")
    }

    fn preauth_context(salt: &[u8]) -> smolder_proto::smb::smb2::NegotiateContext {
        smolder_proto::smb::smb2::NegotiateContext::preauth_integrity(
            PreauthIntegrityCapabilities {
                hash_algorithms: vec![PreauthIntegrityHashId::Sha512],
                salt: salt.to_vec(),
            },
        )
    }

    fn encryption_context(cipher: CipherId) -> smolder_proto::smb::smb2::NegotiateContext {
        smolder_proto::smb::smb2::NegotiateContext::encryption_capabilities(
            EncryptionCapabilities {
                ciphers: vec![cipher],
            },
        )
    }

    fn compression_context(
        algorithm: CompressionAlgorithm,
    ) -> smolder_proto::smb::smb2::NegotiateContext {
        smolder_proto::smb::smb2::NegotiateContext::compression_capabilities(
            CompressionCapabilities {
                compression_algorithms: vec![algorithm],
                flags: CompressionCapabilityFlags::empty(),
            },
        )
    }

    fn sign_response_packet(signing: &super::SigningState, packet: &mut [u8]) {
        let mut header = Header::decode(&packet[..Header::LEN]).expect("header should decode");
        header.flags |= HeaderFlags::SIGNED | HeaderFlags::SERVER_TO_REDIR;
        packet[..Header::LEN].copy_from_slice(&header.encode());
        signing.sign_packet(packet).expect("response should sign");
    }

    fn compound_response_frame(
        elements: Vec<(Command, u32, u64, u64, u32, u16, Vec<u8>)>,
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        let total = elements.len();
        for (index, (command, status, message_id, session_id, tree_id, credits, body)) in
            elements.into_iter().enumerate()
        {
            let mut packet = response_packet_with_credits(
                command, status, message_id, session_id, tree_id, credits, body,
            );
            let is_last = index + 1 == total;
            if !is_last {
                let packet_len = super::align_to_8(packet.len());
                let mut header =
                    Header::decode(&packet[..Header::LEN]).expect("header should decode");
                header.next_command = u32::try_from(packet_len).expect("packet length should fit");
                packet[..Header::LEN].copy_from_slice(&header.encode());
                packet.resize(packet_len, 0);
            }
            payload.extend_from_slice(&packet);
        }
        SessionMessage::new(payload)
            .encode()
            .expect("compound frame should encode")
    }

    fn smb311_signing_state(
        negotiate_request: &NegotiateRequest,
        negotiate_response: &NegotiateResponse,
        session_request: &SessionSetupRequest,
        session_key: &[u8],
    ) -> Arc<super::SigningState> {
        let negotiate_request_packet = request_packet_with_credits(
            Command::Negotiate,
            0,
            0,
            0,
            32,
            negotiate_request.encode().expect("request should encode"),
        );
        let negotiate_response_packet = response_packet(
            Command::Negotiate,
            NtStatus::SUCCESS.to_u32(),
            0,
            0,
            0,
            negotiate_response.encode(),
        );
        let mut preauth = super::negotiate_preauth_integrity_state(
            negotiate_request,
            negotiate_response,
            &negotiate_request_packet,
            &negotiate_response_packet,
        )
        .expect("preauth state should derive")
        .expect("SMB 3.1.1 should negotiate preauth");
        let session_request_packet = request_packet_with_credits(
            Command::SessionSetup,
            1,
            0,
            0,
            32,
            session_request.encode(),
        );
        preauth
            .update(&session_request_packet)
            .expect("session request should update preauth state");
        super::derive_signing_state(Dialect::Smb311, Some(session_key), Some(&preauth))
            .expect("signing key should derive")
            .expect("signing state should be present")
    }

    fn smb302_encryption_state(session_key: &[u8]) -> Arc<EncryptionState> {
        let keys = derive_encryption_keys(
            Dialect::Smb302,
            CipherId::Aes128Ccm,
            session_key,
            None,
            None,
        )
        .expect("SMB 3.0.2 encryption keys should derive");
        Arc::new(EncryptionState::new(Dialect::Smb302, keys))
    }

    #[test]
    fn smb_session_key_uses_first_16_bytes_and_zero_pads_short_keys() {
        let full_key: Vec<u8> = (0u8..32).collect();
        assert_eq!(
            super::derive_smb_session_key(Some(&full_key)),
            Some((0u8..16).collect())
        );

        assert_eq!(
            super::derive_smb_session_key(Some(&[0x41, 0x42, 0x43])),
            Some(vec![
                0x41, 0x42, 0x43, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ])
        );
    }

    fn peer_encryption_state(state: &EncryptionState) -> EncryptionState {
        EncryptionState {
            dialect: state.dialect,
            cipher: state.cipher,
            encrypting_key: state.decrypting_key.clone(),
            decrypting_key: state.encrypting_key.clone(),
        }
    }

    fn encrypted_response_frame(
        state: &EncryptionState,
        command: Command,
        status: u32,
        message_id: u64,
        session_id: u64,
        tree_id: u32,
        body: Vec<u8>,
    ) -> Vec<u8> {
        let packet = response_packet(command, status, message_id, session_id, tree_id, body);
        let transform = state
            .encrypt_message(session_id, &packet)
            .expect("response packet should encrypt");
        SessionMessage::new(transform.encode())
            .encode()
            .expect("encrypted response should frame")
    }

    fn encrypted_compressed_response_frame(
        state: &EncryptionState,
        command: Command,
        status: u32,
        message_id: u64,
        session_id: u64,
        tree_id: u32,
        body: Vec<u8>,
    ) -> Vec<u8> {
        let packet = response_packet(command, status, message_id, session_id, tree_id, body);
        let mut compressed = Vec::new();
        lznt1_compress(&packet, &mut compressed);
        let transform = state
            .encrypt_message(
                session_id,
                &CompressionTransformHeader {
                    original_compressed_segment_size: packet.len() as u32,
                    compression_algorithm: CompressionAlgorithm::Lznt1,
                    flags: CompressionFlags::empty(),
                    offset_or_length: 0,
                    payload: compressed,
                }
                .encode(),
            )
            .expect("compressed response should encrypt");
        SessionMessage::new(transform.encode())
            .encode()
            .expect("encrypted compressed response should frame")
    }

    fn outbound_encrypted_packet(frame: &[u8], state: &EncryptionState) -> Vec<u8> {
        let frame = SessionMessage::decode(frame).expect("frame should decode");
        let transform =
            TransformHeader::decode(&frame.payload).expect("transform header should decode");
        state
            .decrypt_message(&transform)
            .expect("encrypted payload should decrypt")
    }

    fn decompress_transform_payload(payload: &[u8]) -> Vec<u8> {
        let transform =
            CompressionTransformHeader::decode(payload).expect("compression header should decode");
        CompressionState::new(transform.compression_algorithm, false)
            .decompress_message(&transform)
            .expect("compressed payload should decompress")
    }

    fn outbound_compressed_packet(frame: &[u8]) -> Vec<u8> {
        let frame = SessionMessage::decode(frame).expect("frame should decode");
        decompress_transform_payload(&frame.payload)
    }

    fn compressed_response_frame(
        command: Command,
        status: u32,
        message_id: u64,
        session_id: u64,
        tree_id: u32,
        body: Vec<u8>,
    ) -> Vec<u8> {
        let packet = response_packet(command, status, message_id, session_id, tree_id, body);
        let mut compressed = Vec::new();
        lznt1_compress(&packet, &mut compressed);
        SessionMessage::new(
            CompressionTransformHeader {
                original_compressed_segment_size: packet.len() as u32,
                compression_algorithm: CompressionAlgorithm::Lznt1,
                flags: CompressionFlags::empty(),
                offset_or_length: 0,
                payload: compressed,
            }
            .encode(),
        )
        .encode()
        .expect("compressed response should frame")
    }

    fn smb311_encryption_state(
        negotiate_request: &NegotiateRequest,
        negotiate_response: &NegotiateResponse,
        session_request: &SessionSetupRequest,
        session_key: &[u8],
        cipher: CipherId,
    ) -> Arc<EncryptionState> {
        let negotiate_request_packet = request_packet_with_credits(
            Command::Negotiate,
            0,
            0,
            0,
            32,
            negotiate_request.encode().expect("request should encode"),
        );
        let negotiate_response_packet = response_packet(
            Command::Negotiate,
            NtStatus::SUCCESS.to_u32(),
            0,
            0,
            0,
            negotiate_response.encode(),
        );
        let mut preauth = super::negotiate_preauth_integrity_state(
            negotiate_request,
            negotiate_response,
            &negotiate_request_packet,
            &negotiate_response_packet,
        )
        .expect("preauth state should derive")
        .expect("SMB 3.1.1 should negotiate preauth");
        let session_request_packet = request_packet_with_credits(
            Command::SessionSetup,
            1,
            0,
            0,
            32,
            session_request.encode(),
        );
        preauth
            .update(&session_request_packet)
            .expect("session request should update preauth state");
        let keys = derive_encryption_keys(
            Dialect::Smb311,
            cipher,
            session_key,
            None,
            Some(preauth.hash_value.as_slice()),
        )
        .expect("SMB 3.1.1 encryption keys should derive");
        Arc::new(EncryptionState::new(Dialect::Smb311, keys))
    }

    #[derive(Debug)]
    struct MockAuthProvider {
        initial_token: Vec<u8>,
        challenge_token: Vec<u8>,
        final_token: Vec<u8>,
        session_key: Option<Vec<u8>>,
        finished: bool,
    }

    impl AuthProvider for MockAuthProvider {
        fn initial_token(&mut self, _negotiate: &NegotiateResponse) -> Result<Vec<u8>, AuthError> {
            Ok(self.initial_token.clone())
        }

        fn next_token(&mut self, incoming: &[u8]) -> Result<Vec<u8>, AuthError> {
            assert_eq!(incoming, self.challenge_token);
            Ok(self.final_token.clone())
        }

        fn finish(&mut self, incoming: &[u8]) -> Result<(), AuthError> {
            assert!(incoming.is_empty());
            self.finished = true;
            Ok(())
        }

        fn session_key(&self) -> Option<&[u8]> {
            self.session_key.as_deref()
        }
    }

    #[tokio::test]
    async fn typestate_flow_carries_session_and_tree_ids() {
        let negotiate_response = NegotiateResponse {
            security_mode: SigningMode::ENABLED,
            dialect_revision: Dialect::Smb311,
            negotiate_contexts: vec![preauth_context(b"server-salt-0001")],
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
            share_flags: ShareFlags::empty(),
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
        let write_response = WriteResponse { count: 5 };
        let flush_response = FlushResponse;
        let read_response = ReadResponse {
            data_remaining: 0,
            flags: ReadResponseFlags::empty(),
            data: b"hello".to_vec(),
        };
        let close_response = CloseResponse {
            flags: 0,
            allocation_size: 4096,
            end_of_file: 128,
            file_attributes: FileAttributes::ARCHIVE,
        };
        let tree_disconnect_response = smolder_proto::smb::smb2::TreeDisconnectResponse;
        let logoff_response = LogoffResponse;

        let transport = ScriptedTransport::new(vec![
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
                55,
                0,
                session_response.encode(),
            ),
            response_frame(
                Command::TreeConnect,
                NtStatus::SUCCESS.to_u32(),
                2,
                55,
                9,
                tree_response.encode(),
            ),
            response_frame(
                Command::Create,
                NtStatus::SUCCESS.to_u32(),
                3,
                55,
                9,
                create_response.encode(),
            ),
            response_frame(
                Command::Write,
                NtStatus::SUCCESS.to_u32(),
                4,
                55,
                9,
                write_response.encode(),
            ),
            response_frame(
                Command::Flush,
                NtStatus::SUCCESS.to_u32(),
                5,
                55,
                9,
                flush_response.encode(),
            ),
            response_frame(
                Command::Read,
                NtStatus::SUCCESS.to_u32(),
                6,
                55,
                9,
                read_response.encode(),
            ),
            response_frame(
                Command::Close,
                NtStatus::SUCCESS.to_u32(),
                7,
                55,
                9,
                close_response.encode(),
            ),
            response_frame(
                Command::TreeDisconnect,
                NtStatus::SUCCESS.to_u32(),
                8,
                55,
                9,
                tree_disconnect_response.encode(),
            ),
            response_frame(
                Command::Logoff,
                NtStatus::SUCCESS.to_u32(),
                9,
                55,
                0,
                logoff_response.encode(),
            ),
        ]);

        let negotiate_request = NegotiateRequest {
            security_mode: SigningMode::ENABLED,
            capabilities: GlobalCapabilities::LARGE_MTU,
            client_guid: *b"client-guid-0001",
            dialects: vec![Dialect::Smb210, Dialect::Smb302, Dialect::Smb311],
            negotiate_contexts: vec![preauth_context(b"client-salt-0001")],
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
        let write_request = WriteRequest::for_file(create_response.file_id, 0, b"hello".to_vec());
        let flush_request = FlushRequest::for_file(create_response.file_id);
        let read_request = ReadRequest::for_file(create_response.file_id, 0, 5);
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
        let write = connection
            .write(&write_request)
            .await
            .expect("write should succeed");
        let flush = connection
            .flush(&flush_request)
            .await
            .expect("flush should succeed");
        let read = connection
            .read(&read_request)
            .await
            .expect("read should succeed");
        let close = connection
            .close(&close_request)
            .await
            .expect("close should succeed");
        let connection = connection
            .tree_disconnect()
            .await
            .expect("tree disconnect should succeed");
        let connection = connection.logoff().await.expect("logoff should succeed");

        assert_eq!(create.file_id, close_request.file_id);
        assert_eq!(write.count, 5);
        assert_eq!(flush, FlushResponse);
        assert_eq!(read.data, b"hello");
        assert_eq!(close.end_of_file, 128);
        assert_eq!(
            connection.state().response.dialect_revision,
            Dialect::Smb311
        );

        let transport = connection.into_transport();
        assert_eq!(transport.writes.len(), 10);

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

        let write_header = outbound_header(&transport.writes[4]);
        assert_eq!(write_header.command, Command::Write);
        assert_eq!(write_header.message_id, MessageId(4));
        assert_eq!(write_header.session_id, SessionId(55));
        assert_eq!(write_header.tree_id, TreeId(9));
        let write_body = outbound_write(&transport.writes[4]);
        assert_eq!(write_body.data, b"hello");
        assert_eq!(write_body.file_id, create_response.file_id);

        let flush_header = outbound_header(&transport.writes[5]);
        assert_eq!(flush_header.command, Command::Flush);
        assert_eq!(flush_header.message_id, MessageId(5));
        assert_eq!(flush_header.session_id, SessionId(55));
        assert_eq!(flush_header.tree_id, TreeId(9));
        let flush_body = outbound_flush(&transport.writes[5]);
        assert_eq!(flush_body.file_id, create_response.file_id);

        let read_header = outbound_header(&transport.writes[6]);
        assert_eq!(read_header.command, Command::Read);
        assert_eq!(read_header.message_id, MessageId(6));
        assert_eq!(read_header.session_id, SessionId(55));
        assert_eq!(read_header.tree_id, TreeId(9));
        let read_body = outbound_read(&transport.writes[6]);
        assert_eq!(read_body.length, 5);
        assert_eq!(read_body.file_id, create_response.file_id);

        let close_header = outbound_header(&transport.writes[7]);
        assert_eq!(close_header.command, Command::Close);
        assert_eq!(close_header.message_id, MessageId(7));
        assert_eq!(close_header.session_id, SessionId(55));
        assert_eq!(close_header.tree_id, TreeId(9));

        let tree_disconnect_header = outbound_header(&transport.writes[8]);
        assert_eq!(tree_disconnect_header.command, Command::TreeDisconnect);
        assert_eq!(tree_disconnect_header.message_id, MessageId(8));
        assert_eq!(tree_disconnect_header.session_id, SessionId(55));
        assert_eq!(tree_disconnect_header.tree_id, TreeId(9));
        let frame = SessionMessage::decode(&transport.writes[8]).expect("frame should decode");
        let tree_disconnect = TreeDisconnectRequest::decode(&frame.payload[Header::LEN..])
            .expect("request should decode");
        assert_eq!(tree_disconnect, TreeDisconnectRequest);

        let logoff_header = outbound_header(&transport.writes[9]);
        assert_eq!(logoff_header.command, Command::Logoff);
        assert_eq!(logoff_header.message_id, MessageId(9));
        assert_eq!(logoff_header.session_id, SessionId(55));
        assert_eq!(logoff_header.tree_id, TreeId(0));
        let frame = SessionMessage::decode(&transport.writes[9]).expect("frame should decode");
        let logoff =
            LogoffRequest::decode(&frame.payload[Header::LEN..]).expect("request should decode");
        assert_eq!(logoff, LogoffRequest);
    }

    #[tokio::test]
    async fn authenticate_loops_until_session_setup_succeeds() {
        let negotiate_response = NegotiateResponse {
            security_mode: SigningMode::ENABLED | SigningMode::REQUIRED,
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
        let challenge_response = SessionSetupResponse {
            session_flags: SessionFlags::empty(),
            security_buffer: vec![0xaa, 0xbb, 0xcc],
        };
        let success_response = SessionSetupResponse {
            session_flags: SessionFlags::empty(),
            security_buffer: Vec::new(),
        };

        let transport = ScriptedTransport::new(vec![
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
                NtStatus::MORE_PROCESSING_REQUIRED.to_u32(),
                1,
                77,
                0,
                challenge_response.encode(),
            ),
            response_frame(
                Command::SessionSetup,
                NtStatus::SUCCESS.to_u32(),
                2,
                77,
                0,
                success_response.encode(),
            ),
        ]);

        let negotiate_request = NegotiateRequest {
            security_mode: SigningMode::ENABLED,
            capabilities: GlobalCapabilities::LARGE_MTU,
            client_guid: *b"client-guid-0001",
            dialects: vec![Dialect::Smb210, Dialect::Smb302],
            negotiate_contexts: Vec::new(),
        };
        let mut auth_provider = MockAuthProvider {
            initial_token: vec![0x01, 0x02],
            challenge_token: vec![0xaa, 0xbb, 0xcc],
            final_token: vec![0x03, 0x04, 0x05],
            session_key: Some(vec![0x55; 16]),
            finished: false,
        };

        let connection = Connection::new(transport)
            .negotiate(&negotiate_request)
            .await
            .expect("negotiate should succeed")
            .authenticate(&mut auth_provider)
            .await
            .expect("authenticate should succeed");

        assert_eq!(connection.state().session_id, SessionId(77));
        assert_eq!(connection.state().session_key, Some(vec![0x55; 16]));
        assert!(auth_provider.finished);

        let transport = connection.into_transport();
        assert_eq!(transport.writes.len(), 3);

        let first_setup_header = outbound_header(&transport.writes[1]);
        assert_eq!(first_setup_header.session_id, SessionId(0));
        let first_setup = outbound_session_setup(&transport.writes[1]);
        assert_eq!(
            first_setup.security_mode,
            SessionSetupSecurityMode::SIGNING_ENABLED
        );
        assert_eq!(first_setup.security_buffer, vec![0x01, 0x02]);

        let second_setup_header = outbound_header(&transport.writes[2]);
        assert_eq!(second_setup_header.session_id, SessionId(77));
        let second_setup = outbound_session_setup(&transport.writes[2]);
        assert_eq!(second_setup.security_buffer, vec![0x03, 0x04, 0x05]);
    }

    #[tokio::test]
    async fn ioctl_queries_network_interfaces_on_tree_connection() {
        let negotiate_response = NegotiateResponse {
            security_mode: SigningMode::ENABLED,
            dialect_revision: Dialect::Smb311,
            negotiate_contexts: vec![preauth_context(b"server-salt-0001")],
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
            share_flags: ShareFlags::empty(),
            capabilities: TreeCapabilities::empty(),
            maximal_access: 0x0012_019f,
        };
        let ioctl_response = IoctlResponse {
            ctl_code: smolder_proto::smb::smb2::CtlCode::FSCTL_QUERY_NETWORK_INTERFACE_INFO,
            file_id: FileId::NONE,
            input: Vec::new(),
            output: {
                let mut output = Vec::new();
                output.extend_from_slice(&0u32.to_le_bytes());
                output.extend_from_slice(&7u32.to_le_bytes());
                output.extend_from_slice(&0u32.to_le_bytes());
                output.extend_from_slice(&0u32.to_le_bytes());
                output.extend_from_slice(&10_000_000u64.to_le_bytes());
                let mut sockaddr = [0u8; 128];
                sockaddr[0..2].copy_from_slice(&0x0002u16.to_le_bytes());
                sockaddr[4..8].copy_from_slice(&[192, 168, 1, 10]);
                output.extend_from_slice(&sockaddr);
                output
            },
            flags: 0,
        };

        let transport = ScriptedTransport::new(vec![
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
                55,
                0,
                session_response.encode(),
            ),
            response_frame(
                Command::TreeConnect,
                NtStatus::SUCCESS.to_u32(),
                2,
                55,
                9,
                tree_response.encode(),
            ),
            response_frame(
                Command::Ioctl,
                NtStatus::SUCCESS.to_u32(),
                3,
                55,
                9,
                ioctl_response.encode(),
            ),
        ]);

        let negotiate_request = NegotiateRequest {
            security_mode: SigningMode::ENABLED,
            capabilities: GlobalCapabilities::LARGE_MTU,
            client_guid: *b"client-guid-0001",
            dialects: vec![Dialect::Smb210, Dialect::Smb302, Dialect::Smb311],
            negotiate_contexts: vec![preauth_context(b"client-salt-0001")],
        };
        let session_request = SessionSetupRequest {
            flags: 0,
            security_mode: SessionSetupSecurityMode::SIGNING_ENABLED,
            capabilities: 0,
            channel: 0,
            security_buffer: vec![0x60, 0x48],
            previous_session_id: 0,
        };

        let mut connection = Connection::new(transport)
            .negotiate(&negotiate_request)
            .await
            .expect("negotiate should succeed")
            .session_setup(&session_request)
            .await
            .expect("session setup should succeed")
            .tree_connect(&TreeConnectRequest::from_unc(r"\\server\share"))
            .await
            .expect("tree connect should succeed");

        let interfaces = connection
            .query_network_interfaces(16 * 1024)
            .await
            .expect("ioctl query should succeed");

        assert_eq!(interfaces.interfaces.len(), 1);
        let transport = connection.into_transport();
        let header = outbound_header(&transport.writes[3]);
        assert_eq!(header.command, Command::Ioctl);
        assert_eq!(header.message_id, MessageId(3));
        assert_eq!(header.session_id, SessionId(55));
        assert_eq!(header.tree_id, TreeId(9));
        let request = outbound_ioctl(&transport.writes[3]);
        assert_eq!(
            request.ctl_code,
            smolder_proto::smb::smb2::CtlCode::FSCTL_QUERY_NETWORK_INTERFACE_INFO
        );
        assert_eq!(request.file_id, FileId::NONE);
        assert!(request.input.is_empty());
        assert_eq!(request.max_output_response, 16 * 1024);
    }

    #[tokio::test]
    async fn ioctl_requests_resume_key_for_open_file() {
        let negotiate_response = NegotiateResponse {
            security_mode: SigningMode::ENABLED,
            dialect_revision: Dialect::Smb311,
            negotiate_contexts: vec![preauth_context(b"server-salt-0001")],
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
            share_flags: ShareFlags::empty(),
            capabilities: TreeCapabilities::empty(),
            maximal_access: 0x0012_019f,
        };
        let create_response = CreateResponse {
            oplock_level: OplockLevel::None,
            file_attributes: FileAttributes::ARCHIVE,
            allocation_size: 4096,
            end_of_file: 128,
            file_id: FileId {
                persistent: 0x11,
                volatile: 0x22,
            },
            create_contexts: Vec::new(),
        };
        let ioctl_response = IoctlResponse {
            ctl_code: smolder_proto::smb::smb2::CtlCode::FSCTL_SRV_REQUEST_RESUME_KEY,
            file_id: create_response.file_id,
            input: Vec::new(),
            output: {
                let mut output = Vec::new();
                output.extend(0u8..24u8);
                output.extend_from_slice(&0u32.to_le_bytes());
                output.extend_from_slice(&[0, 0, 0, 0]);
                output
            },
            flags: 0,
        };

        let transport = ScriptedTransport::new(vec![
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
                55,
                0,
                session_response.encode(),
            ),
            response_frame(
                Command::TreeConnect,
                NtStatus::SUCCESS.to_u32(),
                2,
                55,
                9,
                tree_response.encode(),
            ),
            response_frame(
                Command::Create,
                NtStatus::SUCCESS.to_u32(),
                3,
                55,
                9,
                create_response.encode(),
            ),
            response_frame(
                Command::Ioctl,
                NtStatus::SUCCESS.to_u32(),
                4,
                55,
                9,
                ioctl_response.encode(),
            ),
        ]);

        let negotiate_request = NegotiateRequest {
            security_mode: SigningMode::ENABLED,
            capabilities: GlobalCapabilities::LARGE_MTU,
            client_guid: *b"client-guid-0001",
            dialects: vec![Dialect::Smb210, Dialect::Smb302, Dialect::Smb311],
            negotiate_contexts: vec![preauth_context(b"client-salt-0001")],
        };
        let session_request = SessionSetupRequest {
            flags: 0,
            security_mode: SessionSetupSecurityMode::SIGNING_ENABLED,
            capabilities: 0,
            channel: 0,
            security_buffer: vec![0x60, 0x48],
            previous_session_id: 0,
        };

        let mut connection = Connection::new(transport)
            .negotiate(&negotiate_request)
            .await
            .expect("negotiate should succeed")
            .session_setup(&session_request)
            .await
            .expect("session setup should succeed")
            .tree_connect(&TreeConnectRequest::from_unc(r"\\server\share"))
            .await
            .expect("tree connect should succeed");
        let create = connection
            .create(&CreateRequest::from_path("notes.txt"))
            .await
            .expect("create should succeed");

        let resume_key = connection
            .request_resume_key(create.file_id)
            .await
            .expect("resume-key ioctl should succeed");

        assert_eq!(resume_key.resume_key[0], 0);
        assert_eq!(resume_key.resume_key[23], 23);
        assert!(resume_key.context.is_empty());

        let transport = connection.into_transport();
        let header = outbound_header(&transport.writes[4]);
        assert_eq!(header.command, Command::Ioctl);
        let request = outbound_ioctl(&transport.writes[4]);
        assert_eq!(
            request.ctl_code,
            smolder_proto::smb::smb2::CtlCode::FSCTL_SRV_REQUEST_RESUME_KEY
        );
        assert_eq!(request.file_id, create_response.file_id);
        assert_eq!(request.max_output_response, 32);
    }

    #[tokio::test]
    async fn compound_raw_uses_consecutive_message_ids_and_related_flag() {
        let negotiate_response = NegotiateResponse {
            security_mode: SigningMode::ENABLED,
            dialect_revision: Dialect::Smb311,
            negotiate_contexts: vec![preauth_context(b"server-salt-0100")],
            server_guid: *b"server-guid-0100",
            capabilities: GlobalCapabilities::LARGE_MTU,
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
            share_flags: ShareFlags::empty(),
            capabilities: TreeCapabilities::empty(),
            maximal_access: 0x0012_019f,
        };
        let file_id = FileId {
            persistent: 0x11,
            volatile: 0x22,
        };
        let write_body = WriteRequest::for_file(file_id, 0, b"hello".to_vec()).encode();
        let flush_body = FlushRequest::for_file(file_id).encode();
        let transport = ScriptedTransport::new(vec![
            response_frame_with_credits(
                Command::Negotiate,
                NtStatus::SUCCESS.to_u32(),
                0,
                0,
                0,
                32,
                negotiate_response.encode(),
            ),
            response_frame(
                Command::SessionSetup,
                NtStatus::SUCCESS.to_u32(),
                1,
                55,
                0,
                session_response.encode(),
            ),
            response_frame(
                Command::TreeConnect,
                NtStatus::SUCCESS.to_u32(),
                2,
                55,
                9,
                tree_response.encode(),
            ),
            compound_response_frame(vec![
                (
                    Command::Write,
                    NtStatus::SUCCESS.to_u32(),
                    3,
                    55,
                    9,
                    1,
                    WriteResponse { count: 5 }.encode(),
                ),
                (
                    Command::Flush,
                    NtStatus::SUCCESS.to_u32(),
                    4,
                    55,
                    9,
                    1,
                    FlushResponse.encode(),
                ),
            ]),
        ]);
        let negotiate_request = NegotiateRequest {
            security_mode: SigningMode::ENABLED,
            capabilities: GlobalCapabilities::LARGE_MTU,
            client_guid: *b"client-guid-0100",
            dialects: vec![Dialect::Smb210, Dialect::Smb302, Dialect::Smb311],
            negotiate_contexts: vec![preauth_context(b"client-salt-0100")],
        };
        let session_request = SessionSetupRequest {
            flags: 0,
            security_mode: SessionSetupSecurityMode::SIGNING_ENABLED,
            capabilities: 0,
            channel: 0,
            security_buffer: vec![0x60, 0x48],
            previous_session_id: 0,
        };
        let mut connection = Connection::new(transport)
            .negotiate(&negotiate_request)
            .await
            .expect("negotiate should succeed")
            .session_setup(&session_request)
            .await
            .expect("session setup should succeed")
            .tree_connect(&TreeConnectRequest::from_unc(r"\\server\share"))
            .await
            .expect("tree connect should succeed");

        let responses = connection
            .compound_raw(&[
                super::CompoundRequest::new(Command::Write, write_body.clone()),
                super::CompoundRequest::related(Command::Flush, flush_body.clone()),
            ])
            .await
            .expect("compound request should succeed");

        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0].header.command, Command::Write);
        assert_eq!(responses[0].header.message_id, MessageId(3));
        assert_eq!(responses[1].header.command, Command::Flush);
        assert_eq!(responses[1].header.message_id, MessageId(4));

        let transport = connection.into_transport();
        let headers = outbound_headers(&transport.writes[3]);
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].message_id, MessageId(3));
        assert_eq!(
            headers[0].next_command as usize,
            super::align_to_8(Header::LEN + write_body.len())
        );
        assert!(!headers[0].flags.contains(HeaderFlags::RELATED_OPERATIONS));
        assert_eq!(headers[1].message_id, MessageId(4));
        assert_eq!(headers[1].next_command, 0);
        assert!(headers[1].flags.contains(HeaderFlags::RELATED_OPERATIONS));
        assert_eq!(headers[1].session_id, SessionId(55));
        assert_eq!(headers[1].tree_id, TreeId(9));
    }

    #[tokio::test]
    async fn compound_raw_requires_enough_credits_for_the_chain() {
        let negotiate_response = NegotiateResponse {
            security_mode: SigningMode::ENABLED,
            dialect_revision: Dialect::Smb311,
            negotiate_contexts: vec![preauth_context(b"server-salt-0101")],
            server_guid: *b"server-guid-0101",
            capabilities: GlobalCapabilities::LARGE_MTU,
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
            share_flags: ShareFlags::empty(),
            capabilities: TreeCapabilities::empty(),
            maximal_access: 0x0012_019f,
        };
        let negotiate_request = NegotiateRequest {
            security_mode: SigningMode::ENABLED,
            capabilities: GlobalCapabilities::LARGE_MTU,
            client_guid: *b"client-guid-0101",
            dialects: vec![Dialect::Smb210, Dialect::Smb302, Dialect::Smb311],
            negotiate_contexts: vec![preauth_context(b"client-salt-0101")],
        };
        let session_request = SessionSetupRequest {
            flags: 0,
            security_mode: SessionSetupSecurityMode::SIGNING_ENABLED,
            capabilities: 0,
            channel: 0,
            security_buffer: vec![0x60, 0x48],
            previous_session_id: 0,
        };
        let file_id = FileId {
            persistent: 0x33,
            volatile: 0x44,
        };
        let mut connection = Connection::new(ScriptedTransport::new(vec![
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
                55,
                0,
                session_response.encode(),
            ),
            response_frame(
                Command::TreeConnect,
                NtStatus::SUCCESS.to_u32(),
                2,
                55,
                9,
                tree_response.encode(),
            ),
        ]))
        .negotiate(&negotiate_request)
        .await
        .expect("negotiate should succeed")
        .session_setup(&session_request)
        .await
        .expect("session setup should succeed")
        .tree_connect(&TreeConnectRequest::from_unc(r"\\server\share"))
        .await
        .expect("tree connect should succeed");

        let error = connection
            .compound_raw(&[
                super::CompoundRequest::new(
                    Command::Write,
                    WriteRequest::for_file(file_id, 0, b"hello".to_vec()).encode(),
                ),
                super::CompoundRequest::related(
                    Command::Flush,
                    FlushRequest::for_file(file_id).encode(),
                ),
            ])
            .await
            .expect_err("compound request should fail without enough credits");

        assert!(matches!(error, CoreError::Unsupported(_)));
        let transport = connection.into_transport();
        assert_eq!(transport.writes.len(), 3);
    }

    #[tokio::test]
    async fn tree_connect_signs_authenticated_requests_for_smb3() {
        let negotiate_request = NegotiateRequest {
            security_mode: SigningMode::ENABLED,
            capabilities: GlobalCapabilities::LARGE_MTU,
            client_guid: *b"client-guid-0002",
            dialects: vec![Dialect::Smb210, Dialect::Smb302, Dialect::Smb311],
            negotiate_contexts: vec![preauth_context(b"client-salt-0002")],
        };
        let negotiate_response = NegotiateResponse {
            security_mode: SigningMode::ENABLED,
            dialect_revision: Dialect::Smb311,
            negotiate_contexts: vec![preauth_context(b"server-salt-0002")],
            server_guid: *b"server-guid-0002",
            capabilities: GlobalCapabilities::LARGE_MTU,
            max_transact_size: 65_536,
            max_read_size: 65_536,
            max_write_size: 65_536,
            system_time: 1,
            server_start_time: 1,
            security_buffer: vec![0x60, 0x03],
        };
        let session_response = SessionSetupResponse {
            session_flags: SessionFlags::empty(),
            security_buffer: Vec::new(),
        };
        let tree_response = TreeConnectResponse {
            share_type: ShareType::Disk,
            share_flags: ShareFlags::empty(),
            capabilities: TreeCapabilities::empty(),
            maximal_access: 0x0012_019f,
        };
        let session_request = SessionSetupRequest {
            flags: 0,
            security_mode: SessionSetupSecurityMode::SIGNING_ENABLED,
            capabilities: 0,
            channel: 0,
            security_buffer: vec![0x01, 0x02],
            previous_session_id: 0,
        };
        let signing = smb311_signing_state(
            &negotiate_request,
            &negotiate_response,
            &session_request,
            &[0x55; 16],
        );
        let mut signed_session_response_packet = response_packet(
            Command::SessionSetup,
            NtStatus::SUCCESS.to_u32(),
            1,
            77,
            0,
            session_response.encode(),
        );
        sign_response_packet(&signing, &mut signed_session_response_packet);

        let transport = ScriptedTransport::new(vec![
            response_frame(
                Command::Negotiate,
                NtStatus::SUCCESS.to_u32(),
                0,
                0,
                0,
                negotiate_response.encode(),
            ),
            SessionMessage::new(signed_session_response_packet)
                .encode()
                .expect("response should frame"),
            response_frame(
                Command::TreeConnect,
                NtStatus::SUCCESS.to_u32(),
                2,
                77,
                9,
                tree_response.encode(),
            ),
        ]);

        let mut auth_provider = MockAuthProvider {
            initial_token: vec![0x01, 0x02],
            challenge_token: Vec::new(),
            final_token: Vec::new(),
            session_key: Some(vec![0x55; 16]),
            finished: false,
        };

        let connection = Connection::new(transport)
            .negotiate(&negotiate_request)
            .await
            .expect("negotiate should succeed")
            .authenticate(&mut auth_provider)
            .await
            .expect("authenticate should succeed")
            .tree_connect(&TreeConnectRequest::from_unc(r"\\server\share"))
            .await
            .expect("tree connect should succeed");

        let transport = connection.into_transport();
        let header = outbound_header(&transport.writes[2]);
        assert!(header.flags.contains(HeaderFlags::SIGNED));
        assert_ne!(header.signature, [0; 16]);
    }

    #[tokio::test]
    async fn authenticated_echo_uses_session_context() {
        let negotiate_response = NegotiateResponse {
            security_mode: SigningMode::ENABLED,
            dialect_revision: Dialect::Smb302,
            negotiate_contexts: Vec::new(),
            server_guid: *b"server-guid-0011",
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
        let transport = ScriptedTransport::new(vec![
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
                44,
                0,
                session_response.encode(),
            ),
            response_frame(
                Command::Echo,
                NtStatus::SUCCESS.to_u32(),
                2,
                44,
                0,
                EchoResponse.encode(),
            ),
        ]);
        let session_request = SessionSetupRequest {
            flags: 0,
            security_mode: SessionSetupSecurityMode::SIGNING_ENABLED,
            capabilities: 0,
            channel: 0,
            security_buffer: vec![0x60, 0x48],
            previous_session_id: 0,
        };

        let mut connection = Connection::new(transport)
            .negotiate(&NegotiateRequest {
                security_mode: SigningMode::ENABLED,
                capabilities: GlobalCapabilities::LARGE_MTU,
                client_guid: *b"client-guid-0011",
                dialects: vec![Dialect::Smb210, Dialect::Smb302],
                negotiate_contexts: Vec::new(),
            })
            .await
            .expect("negotiate should succeed")
            .session_setup(&session_request)
            .await
            .expect("session setup should succeed");

        let response = connection.echo().await.expect("echo should succeed");
        assert_eq!(response, EchoResponse);

        let transport = connection.into_transport();
        let header = outbound_header(&transport.writes[2]);
        assert_eq!(header.command, Command::Echo);
        assert_eq!(header.session_id, SessionId(44));
        assert_eq!(header.tree_id, TreeId(0));
    }

    #[tokio::test]
    async fn tree_connect_encrypts_when_session_requires_encryption() {
        let session_key = [0x77; 16];
        let client_encryption = smb302_encryption_state(&session_key);
        let server_encryption = peer_encryption_state(client_encryption.as_ref());
        let negotiate_request = NegotiateRequest {
            security_mode: SigningMode::ENABLED,
            capabilities: GlobalCapabilities::LARGE_MTU | GlobalCapabilities::ENCRYPTION,
            client_guid: *b"client-guid-enc1",
            dialects: vec![Dialect::Smb210, Dialect::Smb302],
            negotiate_contexts: vec![encryption_context(CipherId::Aes128Ccm)],
        };
        let negotiate_response = NegotiateResponse {
            security_mode: SigningMode::ENABLED,
            dialect_revision: Dialect::Smb302,
            negotiate_contexts: vec![encryption_context(CipherId::Aes128Ccm)],
            server_guid: *b"server-guid-enc1",
            capabilities: GlobalCapabilities::LARGE_MTU | GlobalCapabilities::ENCRYPTION,
            max_transact_size: 65_536,
            max_read_size: 65_536,
            max_write_size: 65_536,
            system_time: 1,
            server_start_time: 1,
            security_buffer: vec![0x60, 0x03],
        };
        let session_response = SessionSetupResponse {
            session_flags: SessionFlags::ENCRYPT_DATA,
            security_buffer: Vec::new(),
        };
        let tree_response = TreeConnectResponse {
            share_type: ShareType::Disk,
            share_flags: ShareFlags::empty(),
            capabilities: TreeCapabilities::empty(),
            maximal_access: 0x0012_019f,
        };
        let transport = ScriptedTransport::new(vec![
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
                77,
                0,
                session_response.encode(),
            ),
            encrypted_response_frame(
                &server_encryption,
                Command::TreeConnect,
                NtStatus::SUCCESS.to_u32(),
                2,
                77,
                9,
                tree_response.encode(),
            ),
        ]);

        let mut auth_provider = MockAuthProvider {
            initial_token: vec![0x01, 0x02],
            challenge_token: Vec::new(),
            final_token: Vec::new(),
            session_key: Some(session_key.to_vec()),
            finished: false,
        };

        let connection = Connection::new(transport)
            .negotiate(&negotiate_request)
            .await
            .expect("negotiate should succeed")
            .authenticate(&mut auth_provider)
            .await
            .expect("authenticate should succeed")
            .tree_connect(&TreeConnectRequest::from_unc(r"\\server\share"))
            .await
            .expect("tree connect should succeed");

        assert!(connection.state().encryption_required);

        let transport = connection.into_transport();
        let packet = outbound_encrypted_packet(&transport.writes[2], &server_encryption);
        let header = Header::decode(&packet[..Header::LEN]).expect("header should decode");
        assert_eq!(header.command, Command::TreeConnect);
        assert_eq!(header.session_id, SessionId(77));
        assert!(!header.flags.contains(HeaderFlags::SIGNED));
    }

    #[tokio::test]
    async fn authenticate_accepts_compressed_session_setup_response_when_negotiated() {
        let negotiate_request = NegotiateRequest {
            security_mode: SigningMode::ENABLED,
            capabilities: GlobalCapabilities::LARGE_MTU,
            client_guid: *b"client-guid-cmpr",
            dialects: vec![Dialect::Smb311],
            negotiate_contexts: vec![
                preauth_context(b"client-salt-cmpr"),
                compression_context(CompressionAlgorithm::Lznt1),
            ],
        };
        let negotiate_response = NegotiateResponse {
            security_mode: SigningMode::ENABLED,
            dialect_revision: Dialect::Smb311,
            negotiate_contexts: vec![
                preauth_context(b"server-salt-cmpr"),
                compression_context(CompressionAlgorithm::Lznt1),
            ],
            server_guid: *b"server-guid-cmpr",
            capabilities: GlobalCapabilities::LARGE_MTU,
            max_transact_size: 65_536,
            max_read_size: 65_536,
            max_write_size: 65_536,
            system_time: 1,
            server_start_time: 1,
            security_buffer: vec![0x60, 0x03],
        };
        let session_response = SessionSetupResponse {
            session_flags: SessionFlags::empty(),
            security_buffer: Vec::new(),
        };
        let transport = ScriptedTransport::new(vec![
            response_frame(
                Command::Negotiate,
                NtStatus::SUCCESS.to_u32(),
                0,
                0,
                0,
                negotiate_response.encode(),
            ),
            compressed_response_frame(
                Command::SessionSetup,
                NtStatus::SUCCESS.to_u32(),
                1,
                44,
                0,
                session_response.encode(),
            ),
        ]);

        let mut auth_provider = MockAuthProvider {
            initial_token: vec![0x01, 0x02],
            challenge_token: Vec::new(),
            final_token: Vec::new(),
            session_key: None,
            finished: false,
        };

        let connection = Connection::new(transport)
            .negotiate(&negotiate_request)
            .await
            .expect("negotiate should succeed")
            .authenticate(&mut auth_provider)
            .await
            .expect("compressed session setup should authenticate");

        assert_eq!(connection.state().session_id, SessionId(44));
        assert_eq!(
            connection
                .state()
                .compression
                .as_ref()
                .expect("compression should be negotiated")
                .algorithm,
            CompressionAlgorithm::Lznt1
        );
        assert!(auth_provider.finished);
    }

    #[tokio::test]
    async fn tree_connect_accepts_encrypted_compressed_responses_when_negotiated() {
        let session_key = [0x22; 16];
        let negotiate_request = NegotiateRequest {
            security_mode: SigningMode::ENABLED,
            capabilities: GlobalCapabilities::LARGE_MTU | GlobalCapabilities::ENCRYPTION,
            client_guid: *b"client-guid-cmre",
            dialects: vec![Dialect::Smb311],
            negotiate_contexts: vec![
                preauth_context(b"client-salt-cmre"),
                encryption_context(CipherId::Aes128Gcm),
                compression_context(CompressionAlgorithm::Lznt1),
            ],
        };
        let negotiate_response = NegotiateResponse {
            security_mode: SigningMode::ENABLED,
            dialect_revision: Dialect::Smb311,
            negotiate_contexts: vec![
                preauth_context(b"server-salt-cmre"),
                encryption_context(CipherId::Aes128Gcm),
                compression_context(CompressionAlgorithm::Lznt1),
            ],
            server_guid: *b"server-guid-cmre",
            capabilities: GlobalCapabilities::LARGE_MTU | GlobalCapabilities::ENCRYPTION,
            max_transact_size: 65_536,
            max_read_size: 65_536,
            max_write_size: 65_536,
            system_time: 1,
            server_start_time: 1,
            security_buffer: vec![0x60, 0x03],
        };
        let session_request = SessionSetupRequest {
            flags: 0,
            security_mode: SessionSetupSecurityMode::SIGNING_ENABLED,
            capabilities: 0,
            channel: 0,
            security_buffer: vec![0x01, 0x02],
            previous_session_id: 0,
        };
        let client_encryption = smb311_encryption_state(
            &negotiate_request,
            &negotiate_response,
            &session_request,
            &session_key,
            CipherId::Aes128Gcm,
        );
        let server_encryption = peer_encryption_state(client_encryption.as_ref());
        let session_response = SessionSetupResponse {
            session_flags: SessionFlags::ENCRYPT_DATA,
            security_buffer: Vec::new(),
        };
        let tree_response = TreeConnectResponse {
            share_type: ShareType::Disk,
            share_flags: ShareFlags::empty(),
            capabilities: TreeCapabilities::empty(),
            maximal_access: 0x0012_019f,
        };
        let transport = ScriptedTransport::new(vec![
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
                63,
                0,
                session_response.encode(),
            ),
            encrypted_compressed_response_frame(
                &server_encryption,
                Command::TreeConnect,
                NtStatus::SUCCESS.to_u32(),
                2,
                63,
                12,
                tree_response.encode(),
            ),
        ]);
        let mut auth_provider = MockAuthProvider {
            initial_token: session_request.security_buffer.clone(),
            challenge_token: Vec::new(),
            final_token: Vec::new(),
            session_key: Some(session_key.to_vec()),
            finished: false,
        };

        let connection = Connection::new(transport)
            .negotiate(&negotiate_request)
            .await
            .expect("negotiate should succeed")
            .authenticate(&mut auth_provider)
            .await
            .expect("authenticate should succeed")
            .tree_connect(&TreeConnectRequest::from_unc(r"\\server\share"))
            .await
            .expect("encrypted compressed tree connect should succeed");

        assert_eq!(connection.session_id(), SessionId(63));
        assert_eq!(connection.tree_id(), TreeId(12));
        assert!(connection.state().encryption_required);
        assert_eq!(
            connection
                .state()
                .compression
                .as_ref()
                .expect("compression should be negotiated")
                .algorithm,
            CompressionAlgorithm::Lznt1
        );
    }

    #[tokio::test]
    async fn write_compresses_signed_tree_requests_when_negotiated() {
        let negotiate_request = NegotiateRequest {
            security_mode: SigningMode::ENABLED,
            capabilities: GlobalCapabilities::LARGE_MTU,
            client_guid: *b"client-guid-cmpw",
            dialects: vec![Dialect::Smb311],
            negotiate_contexts: vec![
                preauth_context(b"client-salt-cmpw"),
                compression_context(CompressionAlgorithm::Lznt1),
            ],
        };
        let negotiate_response = NegotiateResponse {
            security_mode: SigningMode::ENABLED,
            dialect_revision: Dialect::Smb311,
            negotiate_contexts: vec![
                preauth_context(b"server-salt-cmpw"),
                compression_context(CompressionAlgorithm::Lznt1),
            ],
            server_guid: *b"server-guid-cmpw",
            capabilities: GlobalCapabilities::LARGE_MTU,
            max_transact_size: 65_536,
            max_read_size: 65_536,
            max_write_size: 65_536,
            system_time: 1,
            server_start_time: 1,
            security_buffer: vec![0x60, 0x03],
        };
        let session_response = SessionSetupResponse {
            session_flags: SessionFlags::empty(),
            security_buffer: Vec::new(),
        };
        let tree_response = TreeConnectResponse {
            share_type: ShareType::Disk,
            share_flags: ShareFlags::empty(),
            capabilities: TreeCapabilities::empty(),
            maximal_access: 0x0012_019f,
        };
        let write_response = WriteResponse { count: 4096 };
        let transport = ScriptedTransport::new(vec![
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
                61,
                0,
                session_response.encode(),
            ),
            response_frame(
                Command::TreeConnect,
                NtStatus::SUCCESS.to_u32(),
                2,
                61,
                7,
                tree_response.encode(),
            ),
            response_frame(
                Command::Write,
                NtStatus::SUCCESS.to_u32(),
                3,
                61,
                7,
                write_response.encode(),
            ),
        ]);
        let mut auth_provider = MockAuthProvider {
            initial_token: vec![0x01, 0x02],
            challenge_token: Vec::new(),
            final_token: Vec::new(),
            session_key: Some(vec![0x44; 16]),
            finished: false,
        };
        let file_id = FileId {
            persistent: 0x1122_3344,
            volatile: 0x5566_7788,
        };

        let mut connection = Connection::new(transport)
            .negotiate(&negotiate_request)
            .await
            .expect("negotiate should succeed")
            .authenticate(&mut auth_provider)
            .await
            .expect("authenticate should succeed")
            .tree_connect(&TreeConnectRequest::from_unc(r"\\server\share"))
            .await
            .expect("tree connect should succeed");

        connection
            .write(&WriteRequest::for_file(file_id, 0, vec![b'A'; 4096]))
            .await
            .expect("write should succeed");

        let transport = connection.into_transport();
        let decompressed = outbound_compressed_packet(&transport.writes[3]);
        let header = Header::decode(&decompressed[..Header::LEN]).expect("header should decode");
        let request =
            WriteRequest::decode(&decompressed[Header::LEN..]).expect("write should decode");

        assert_eq!(header.command, Command::Write);
        assert_eq!(header.session_id, SessionId(61));
        assert_eq!(header.tree_id, TreeId(7));
        assert!(header.flags.contains(HeaderFlags::SIGNED));
        assert_eq!(request.write_channel_info, Vec::<u8>::new());
        assert_eq!(request.data.len(), 4096);
    }

    #[tokio::test]
    async fn write_compresses_before_encryption_when_session_requires_it() {
        let session_key = [0x33; 16];
        let negotiate_request = NegotiateRequest {
            security_mode: SigningMode::ENABLED,
            capabilities: GlobalCapabilities::LARGE_MTU | GlobalCapabilities::ENCRYPTION,
            client_guid: *b"client-guid-cme1",
            dialects: vec![Dialect::Smb311],
            negotiate_contexts: vec![
                preauth_context(b"client-salt-cme1"),
                encryption_context(CipherId::Aes128Gcm),
                compression_context(CompressionAlgorithm::Lznt1),
            ],
        };
        let negotiate_response = NegotiateResponse {
            security_mode: SigningMode::ENABLED,
            dialect_revision: Dialect::Smb311,
            negotiate_contexts: vec![
                preauth_context(b"server-salt-cme1"),
                encryption_context(CipherId::Aes128Gcm),
                compression_context(CompressionAlgorithm::Lznt1),
            ],
            server_guid: *b"server-guid-cme1",
            capabilities: GlobalCapabilities::LARGE_MTU | GlobalCapabilities::ENCRYPTION,
            max_transact_size: 65_536,
            max_read_size: 65_536,
            max_write_size: 65_536,
            system_time: 1,
            server_start_time: 1,
            security_buffer: vec![0x60, 0x03],
        };
        let session_request = SessionSetupRequest {
            flags: 0,
            security_mode: SessionSetupSecurityMode::SIGNING_ENABLED,
            capabilities: 0,
            channel: 0,
            security_buffer: vec![0x01, 0x02],
            previous_session_id: 0,
        };
        let client_encryption = smb311_encryption_state(
            &negotiate_request,
            &negotiate_response,
            &session_request,
            &session_key,
            CipherId::Aes128Gcm,
        );
        let server_encryption = peer_encryption_state(client_encryption.as_ref());
        let session_response = SessionSetupResponse {
            session_flags: SessionFlags::ENCRYPT_DATA,
            security_buffer: Vec::new(),
        };
        let write_response = WriteResponse { count: 4096 };
        let transport = ScriptedTransport::new(vec![
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
                62,
                0,
                session_response.encode(),
            ),
            encrypted_response_frame(
                &server_encryption,
                Command::Write,
                NtStatus::SUCCESS.to_u32(),
                2,
                62,
                0,
                write_response.encode(),
            ),
        ]);
        let mut auth_provider = MockAuthProvider {
            initial_token: session_request.security_buffer.clone(),
            challenge_token: Vec::new(),
            final_token: Vec::new(),
            session_key: Some(session_key.to_vec()),
            finished: false,
        };
        let file_id = FileId {
            persistent: 0x2233_4455,
            volatile: 0x6677_8899,
        };

        let mut connection = Connection::new(transport)
            .negotiate(&negotiate_request)
            .await
            .expect("negotiate should succeed")
            .authenticate(&mut auth_provider)
            .await
            .expect("authenticate should succeed");

        let responses = connection
            .compound_raw(&[super::CompoundRequest::new(
                Command::Write,
                WriteRequest::for_file(file_id, 0, vec![b'B'; 4096]).encode(),
            )])
            .await
            .expect("compound write should succeed");

        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].header.command, Command::Write);

        let transport = connection.into_transport();
        let decrypted = outbound_encrypted_packet(&transport.writes[2], &server_encryption);
        assert!(decrypted.starts_with(&COMPRESSION_TRANSFORM_PROTOCOL_ID));
        let decompressed = decompress_transform_payload(&decrypted);
        let header = Header::decode(&decompressed[..Header::LEN]).expect("header should decode");
        let request =
            WriteRequest::decode(&decompressed[Header::LEN..]).expect("write should decode");

        assert_eq!(header.command, Command::Write);
        assert_eq!(header.session_id, SessionId(62));
        assert_eq!(header.tree_id, TreeId(0));
        assert!(!header.flags.contains(HeaderFlags::SIGNED));
        assert_eq!(request.data.len(), 4096);
    }

    #[tokio::test]
    async fn tree_disconnect_encrypts_when_share_requires_encryption() {
        let session_key = [0x66; 16];
        let client_encryption = smb302_encryption_state(&session_key);
        let server_encryption = peer_encryption_state(client_encryption.as_ref());
        let negotiate_request = NegotiateRequest {
            security_mode: SigningMode::ENABLED,
            capabilities: GlobalCapabilities::LARGE_MTU | GlobalCapabilities::ENCRYPTION,
            client_guid: *b"client-guid-enc2",
            dialects: vec![Dialect::Smb210, Dialect::Smb302],
            negotiate_contexts: vec![encryption_context(CipherId::Aes128Ccm)],
        };
        let negotiate_response = NegotiateResponse {
            security_mode: SigningMode::ENABLED,
            dialect_revision: Dialect::Smb302,
            negotiate_contexts: vec![encryption_context(CipherId::Aes128Ccm)],
            server_guid: *b"server-guid-enc2",
            capabilities: GlobalCapabilities::LARGE_MTU | GlobalCapabilities::ENCRYPTION,
            max_transact_size: 65_536,
            max_read_size: 65_536,
            max_write_size: 65_536,
            system_time: 1,
            server_start_time: 1,
            security_buffer: vec![0x60, 0x03],
        };
        let session_response = SessionSetupResponse {
            session_flags: SessionFlags::empty(),
            security_buffer: Vec::new(),
        };
        let tree_response = TreeConnectResponse {
            share_type: ShareType::Disk,
            share_flags: ShareFlags::ENCRYPT_DATA,
            capabilities: TreeCapabilities::empty(),
            maximal_access: 0x0012_019f,
        };
        let tree_disconnect_response = smolder_proto::smb::smb2::TreeDisconnectResponse;
        let transport = ScriptedTransport::new(vec![
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
                88,
                0,
                session_response.encode(),
            ),
            response_frame(
                Command::TreeConnect,
                NtStatus::SUCCESS.to_u32(),
                2,
                88,
                11,
                tree_response.encode(),
            ),
            encrypted_response_frame(
                &server_encryption,
                Command::TreeDisconnect,
                NtStatus::SUCCESS.to_u32(),
                3,
                88,
                11,
                tree_disconnect_response.encode(),
            ),
        ]);

        let mut auth_provider = MockAuthProvider {
            initial_token: vec![0x01, 0x02],
            challenge_token: Vec::new(),
            final_token: Vec::new(),
            session_key: Some(session_key.to_vec()),
            finished: false,
        };

        let connection = Connection::new(transport)
            .negotiate(&negotiate_request)
            .await
            .expect("negotiate should succeed")
            .authenticate(&mut auth_provider)
            .await
            .expect("authenticate should succeed")
            .tree_connect(&TreeConnectRequest::from_unc(r"\\server\share"))
            .await
            .expect("tree connect should succeed");

        assert!(connection.state().encryption_required);

        let connection = connection
            .tree_disconnect()
            .await
            .expect("tree disconnect should succeed");

        assert!(!connection.state().encryption_required);

        let transport = connection.into_transport();
        let packet = outbound_encrypted_packet(&transport.writes[3], &server_encryption);
        let header = Header::decode(&packet[..Header::LEN]).expect("header should decode");
        assert_eq!(header.command, Command::TreeDisconnect);
        assert_eq!(header.session_id, SessionId(88));
        assert_eq!(header.tree_id, TreeId(11));
        assert!(!header.flags.contains(HeaderFlags::SIGNED));
    }

    #[tokio::test]
    async fn tree_lock_uses_tree_context() {
        let file_id = FileId {
            persistent: 0x1122_3344_5566_7788,
            volatile: 0x8877_6655_4433_2211,
        };
        let transport = ScriptedTransport::new(vec![
            response_frame(
                Command::Negotiate,
                NtStatus::SUCCESS.to_u32(),
                0,
                0,
                0,
                NegotiateResponse {
                    security_mode: SigningMode::ENABLED,
                    dialect_revision: Dialect::Smb302,
                    negotiate_contexts: Vec::new(),
                    server_guid: *b"server-guid-0021",
                    capabilities: GlobalCapabilities::LARGE_MTU,
                    max_transact_size: 65_536,
                    max_read_size: 65_536,
                    max_write_size: 65_536,
                    system_time: 1,
                    server_start_time: 1,
                    security_buffer: Vec::new(),
                }
                .encode(),
            ),
            response_frame(
                Command::SessionSetup,
                NtStatus::SUCCESS.to_u32(),
                1,
                55,
                0,
                SessionSetupResponse {
                    session_flags: SessionFlags::empty(),
                    security_buffer: Vec::new(),
                }
                .encode(),
            ),
            response_frame(
                Command::TreeConnect,
                NtStatus::SUCCESS.to_u32(),
                2,
                55,
                9,
                TreeConnectResponse {
                    share_type: ShareType::Disk,
                    share_flags: ShareFlags::empty(),
                    capabilities: TreeCapabilities::empty(),
                    maximal_access: 0x0012_019f,
                }
                .encode(),
            ),
            response_frame(
                Command::Lock,
                NtStatus::SUCCESS.to_u32(),
                3,
                55,
                9,
                LockResponse.encode(),
            ),
        ]);
        let session_request = SessionSetupRequest {
            flags: 0,
            security_mode: SessionSetupSecurityMode::SIGNING_ENABLED,
            capabilities: 0,
            channel: 0,
            security_buffer: vec![0x60, 0x48],
            previous_session_id: 0,
        };
        let mut connection = Connection::new(transport)
            .negotiate(&NegotiateRequest {
                security_mode: SigningMode::ENABLED,
                capabilities: GlobalCapabilities::LARGE_MTU,
                client_guid: *b"client-guid-0021",
                dialects: vec![Dialect::Smb210, Dialect::Smb302],
                negotiate_contexts: Vec::new(),
            })
            .await
            .expect("negotiate should succeed")
            .session_setup(&session_request)
            .await
            .expect("session setup should succeed")
            .tree_connect(&TreeConnectRequest::from_unc(r"\\server\share"))
            .await
            .expect("tree connect should succeed");

        let request = LockRequest::for_file(
            file_id,
            vec![LockElement {
                offset: 4096,
                length: 512,
                flags: LockFlags::EXCLUSIVE_LOCK | LockFlags::FAIL_IMMEDIATELY,
            }],
        );
        let response = connection
            .lock(&request)
            .await
            .expect("lock should succeed");
        assert_eq!(response, LockResponse);

        let transport = connection.into_transport();
        let header = outbound_header(&transport.writes[3]);
        assert_eq!(header.command, Command::Lock);
        assert_eq!(header.session_id, SessionId(55));
        assert_eq!(header.tree_id, TreeId(9));
    }

    #[tokio::test]
    async fn change_notify_handles_interim_async_response() {
        let file_id = FileId {
            persistent: 0x0102_0304_0506_0708,
            volatile: 0x1112_1314_1516_1718,
        };
        let response = ChangeNotifyResponse {
            output_buffer: vec![1, 2, 3, 4],
        };
        let transport = ScriptedTransport::new(vec![
            response_frame(
                Command::Negotiate,
                NtStatus::SUCCESS.to_u32(),
                0,
                0,
                0,
                NegotiateResponse {
                    security_mode: SigningMode::ENABLED,
                    dialect_revision: Dialect::Smb302,
                    negotiate_contexts: Vec::new(),
                    server_guid: *b"server-guid-noti",
                    capabilities: GlobalCapabilities::LARGE_MTU,
                    max_transact_size: 65_536,
                    max_read_size: 65_536,
                    max_write_size: 65_536,
                    system_time: 1,
                    server_start_time: 1,
                    security_buffer: Vec::new(),
                }
                .encode(),
            ),
            response_frame(
                Command::SessionSetup,
                NtStatus::SUCCESS.to_u32(),
                1,
                66,
                0,
                SessionSetupResponse {
                    session_flags: SessionFlags::empty(),
                    security_buffer: Vec::new(),
                }
                .encode(),
            ),
            response_frame(
                Command::TreeConnect,
                NtStatus::SUCCESS.to_u32(),
                2,
                66,
                12,
                TreeConnectResponse {
                    share_type: ShareType::Disk,
                    share_flags: ShareFlags::empty(),
                    capabilities: TreeCapabilities::empty(),
                    maximal_access: 0x0012_019f,
                }
                .encode(),
            ),
            async_response_frame(
                Command::ChangeNotify,
                NtStatus::PENDING.to_u32(),
                3,
                0x4444,
                66,
                Vec::new(),
            ),
            async_response_frame(
                Command::ChangeNotify,
                NtStatus::SUCCESS.to_u32(),
                3,
                0x4444,
                66,
                response.encode(),
            ),
        ]);
        let session_request = SessionSetupRequest {
            flags: 0,
            security_mode: SessionSetupSecurityMode::SIGNING_ENABLED,
            capabilities: 0,
            channel: 0,
            security_buffer: vec![0x60, 0x48],
            previous_session_id: 0,
        };
        let mut connection = Connection::new(transport)
            .negotiate(&NegotiateRequest {
                security_mode: SigningMode::ENABLED,
                capabilities: GlobalCapabilities::LARGE_MTU,
                client_guid: *b"client-guid-noti",
                dialects: vec![Dialect::Smb210, Dialect::Smb302],
                negotiate_contexts: Vec::new(),
            })
            .await
            .expect("negotiate should succeed")
            .session_setup(&session_request)
            .await
            .expect("session setup should succeed")
            .tree_connect(&TreeConnectRequest::from_unc(r"\\server\share"))
            .await
            .expect("tree connect should succeed");

        let request = ChangeNotifyRequest {
            flags: ChangeNotifyFlags::WATCH_TREE,
            output_buffer_length: 4096,
            file_id,
            completion_filter: CompletionFilter::FILE_NAME | CompletionFilter::LAST_WRITE,
        };
        let notify = connection
            .change_notify(&request)
            .await
            .expect("change notify should succeed");
        assert_eq!(notify, response);

        let transport = connection.into_transport();
        let header = outbound_header(&transport.writes[3]);
        assert_eq!(header.command, Command::ChangeNotify);
        assert_eq!(header.session_id, SessionId(66));
        assert_eq!(header.tree_id, TreeId(12));
    }

    #[tokio::test]
    async fn rejects_tampered_signed_tree_connect_response() {
        let negotiate_request = NegotiateRequest {
            security_mode: SigningMode::ENABLED,
            capabilities: GlobalCapabilities::LARGE_MTU,
            client_guid: *b"client-guid-0003",
            dialects: vec![Dialect::Smb210, Dialect::Smb302, Dialect::Smb311],
            negotiate_contexts: vec![preauth_context(b"client-salt-0003")],
        };
        let negotiate_response = NegotiateResponse {
            security_mode: SigningMode::ENABLED,
            dialect_revision: Dialect::Smb311,
            negotiate_contexts: vec![preauth_context(b"server-salt-0003")],
            server_guid: *b"server-guid-0003",
            capabilities: GlobalCapabilities::LARGE_MTU,
            max_transact_size: 65_536,
            max_read_size: 65_536,
            max_write_size: 65_536,
            system_time: 1,
            server_start_time: 1,
            security_buffer: vec![0x60, 0x03],
        };
        let session_request = SessionSetupRequest {
            flags: 0,
            security_mode: SessionSetupSecurityMode::SIGNING_ENABLED,
            capabilities: 0,
            channel: 0,
            security_buffer: vec![0x01, 0x02],
            previous_session_id: 0,
        };
        let session_response = SessionSetupResponse {
            session_flags: SessionFlags::empty(),
            security_buffer: Vec::new(),
        };
        let tree_response = TreeConnectResponse {
            share_type: ShareType::Disk,
            share_flags: ShareFlags::empty(),
            capabilities: TreeCapabilities::empty(),
            maximal_access: 0x0012_019f,
        };

        let signing = smb311_signing_state(
            &negotiate_request,
            &negotiate_response,
            &session_request,
            &[0x55; 16],
        );
        let mut signed_session_response_packet = response_packet(
            Command::SessionSetup,
            NtStatus::SUCCESS.to_u32(),
            1,
            77,
            0,
            session_response.encode(),
        );
        sign_response_packet(&signing, &mut signed_session_response_packet);

        let mut signed_tree_response_packet = response_packet(
            Command::TreeConnect,
            NtStatus::SUCCESS.to_u32(),
            2,
            77,
            9,
            tree_response.encode(),
        );
        sign_response_packet(&signing, &mut signed_tree_response_packet);
        let last = signed_tree_response_packet
            .last_mut()
            .expect("tree response packet should be non-empty");
        *last ^= 0xff;

        let transport = ScriptedTransport::new(vec![
            response_frame(
                Command::Negotiate,
                NtStatus::SUCCESS.to_u32(),
                0,
                0,
                0,
                negotiate_response.encode(),
            ),
            SessionMessage::new(signed_session_response_packet)
                .encode()
                .expect("response should frame"),
            SessionMessage::new(signed_tree_response_packet)
                .encode()
                .expect("response should frame"),
        ]);

        let mut auth_provider = MockAuthProvider {
            initial_token: vec![0x01, 0x02],
            challenge_token: Vec::new(),
            final_token: Vec::new(),
            session_key: Some(vec![0x55; 16]),
            finished: false,
        };

        let error = Connection::new(transport)
            .negotiate(&negotiate_request)
            .await
            .expect("negotiate should succeed")
            .authenticate(&mut auth_provider)
            .await
            .expect("authenticate should succeed")
            .tree_connect(&TreeConnectRequest::from_unc(r"\\server\share"))
            .await
            .expect_err("tampered signed response should be rejected");

        assert!(matches!(
            error,
            CoreError::InvalidResponse(
                "SMB response signature did not match the derived signing key"
            )
        ));
    }

    #[tokio::test]
    async fn rejects_unsigned_tree_connect_response_when_signing_is_required() {
        let negotiate_request = NegotiateRequest {
            security_mode: SigningMode::REQUIRED,
            capabilities: GlobalCapabilities::LARGE_MTU,
            client_guid: *b"client-guid-0004",
            dialects: vec![Dialect::Smb210, Dialect::Smb302],
            negotiate_contexts: Vec::new(),
        };
        let negotiate_response = NegotiateResponse {
            security_mode: SigningMode::ENABLED,
            dialect_revision: Dialect::Smb302,
            negotiate_contexts: Vec::new(),
            server_guid: *b"server-guid-0004",
            capabilities: GlobalCapabilities::LARGE_MTU,
            max_transact_size: 65_536,
            max_read_size: 65_536,
            max_write_size: 65_536,
            system_time: 1,
            server_start_time: 1,
            security_buffer: Vec::new(),
        };
        let challenge_response = SessionSetupResponse {
            session_flags: SessionFlags::empty(),
            security_buffer: vec![0xaa, 0xbb, 0xcc],
        };
        let success_response = SessionSetupResponse {
            session_flags: SessionFlags::empty(),
            security_buffer: Vec::new(),
        };
        let tree_response = TreeConnectResponse {
            share_type: ShareType::Disk,
            share_flags: ShareFlags::empty(),
            capabilities: TreeCapabilities::empty(),
            maximal_access: 0x0012_019f,
        };

        let transport = ScriptedTransport::new(vec![
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
                NtStatus::MORE_PROCESSING_REQUIRED.to_u32(),
                1,
                77,
                0,
                challenge_response.encode(),
            ),
            response_frame(
                Command::SessionSetup,
                NtStatus::SUCCESS.to_u32(),
                2,
                77,
                0,
                success_response.encode(),
            ),
            response_frame(
                Command::TreeConnect,
                NtStatus::SUCCESS.to_u32(),
                3,
                77,
                9,
                tree_response.encode(),
            ),
        ]);

        let mut auth_provider = MockAuthProvider {
            initial_token: vec![0x01, 0x02],
            challenge_token: vec![0xaa, 0xbb, 0xcc],
            final_token: vec![0x03, 0x04, 0x05],
            session_key: Some(vec![0x55; 16]),
            finished: false,
        };

        let error = Connection::new(transport)
            .negotiate(&negotiate_request)
            .await
            .expect("negotiate should succeed")
            .authenticate(&mut auth_provider)
            .await
            .expect("authenticate should succeed")
            .tree_connect(&TreeConnectRequest::from_unc(r"\\server\share"))
            .await
            .expect_err("unsigned response should be rejected when signing is required");

        assert!(matches!(
            error,
            CoreError::InvalidResponse("session requires signed SMB responses")
        ));
    }

    #[tokio::test]
    async fn write_handles_interim_async_response() {
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
            share_type: ShareType::Disk,
            share_flags: ShareFlags::empty(),
            capabilities: TreeCapabilities::empty(),
            maximal_access: 0x0012_019f,
        };

        let transport = ScriptedTransport::new(vec![
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
            async_response_frame(
                Command::Write,
                NtStatus::PENDING.to_u32(),
                3,
                99,
                11,
                Vec::new(),
            ),
            async_response_frame(
                Command::Write,
                NtStatus::SUCCESS.to_u32(),
                3,
                99,
                11,
                WriteResponse { count: 5 }.encode(),
            ),
        ]);

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
        let tree_request = TreeConnectRequest::from_unc(r"\\server\share");
        let write_request = WriteRequest::for_file(
            FileId {
                persistent: 0x11,
                volatile: 0x22,
            },
            0,
            b"hello".to_vec(),
        );

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

        let response = connection
            .write(&write_request)
            .await
            .expect("write should succeed after interim pending response");
        assert_eq!(response.count, 5);

        let transport = connection.into_transport();
        assert_eq!(transport.writes.len(), 4);
    }
}
