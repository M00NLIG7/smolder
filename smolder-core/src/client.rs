//! Typestate SMB client built on top of wire-level packet codecs.

use aes::Aes128;
use cmac::Cmac;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use smolder_proto::smb::netbios::SessionMessage;
use smolder_proto::smb::smb2::{
    AsyncId, CloseRequest, CloseResponse, Command, CreateRequest, CreateResponse, Dialect,
    FlushRequest, FlushResponse, Header, HeaderFlags, LogoffRequest, LogoffResponse, MessageId,
    NegotiateRequest, NegotiateResponse, PreauthIntegrityCapabilities, PreauthIntegrityHashId,
    QueryDirectoryRequest, QueryDirectoryResponse, QueryInfoRequest, QueryInfoResponse,
    ReadRequest, ReadResponse, SessionId, SessionSetupRequest, SessionSetupResponse,
    SessionSetupSecurityMode, SetInfoRequest, SetInfoResponse, SigningMode, TreeConnectRequest,
    TreeConnectResponse, TreeDisconnectRequest, TreeDisconnectResponse, TreeId, WriteRequest,
    WriteResponse,
};
use smolder_proto::smb::status::NtStatus;
use tracing::{trace, trace_span, Instrument};

use crate::auth::AuthProvider;
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
    /// Preauthentication integrity state for SMB 3.1.1, if negotiated.
    pub preauth_integrity: Option<PreauthIntegrityState>,
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
    /// Preauthentication integrity state for SMB 3.1.1, if negotiated.
    pub preauth_integrity: Option<PreauthIntegrityState>,
    /// Exported session key from the authentication mechanism.
    pub session_key: Option<Vec<u8>>,
    /// Derived request-signing state for the session, if available.
    pub signing: Option<SigningState>,
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
    /// Preauthentication integrity state for SMB 3.1.1, if negotiated.
    pub preauth_integrity: Option<PreauthIntegrityState>,
    /// Exported session key from the authentication mechanism.
    pub session_key: Option<Vec<u8>>,
    /// Derived request-signing state for the session, if available.
    pub signing: Option<SigningState>,
}

/// SMB 3.1.1 preauthentication transcript state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreauthIntegrityState {
    /// Negotiated preauthentication hash algorithm.
    pub hash_algorithm: PreauthIntegrityHashId,
    /// Rolling preauthentication hash value.
    pub hash_value: Vec<u8>,
}

impl PreauthIntegrityState {
    fn new(hash_algorithm: PreauthIntegrityHashId) -> Self {
        Self {
            hash_algorithm,
            hash_value: vec![0; 64],
        }
    }

    fn update(&mut self, packet: &[u8]) -> Result<(), CoreError> {
        self.hash_value = match self.hash_algorithm {
            PreauthIntegrityHashId::Sha512 => {
                let mut digest = Sha512::new();
                digest.update(&self.hash_value);
                digest.update(packet);
                digest.finalize().to_vec()
            }
        };
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SigningAlgorithm {
    HmacSha256,
    Aes128Cmac,
}

/// Derived signing state for an authenticated SMB session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningState {
    algorithm: SigningAlgorithm,
    key: Vec<u8>,
}

impl SigningState {
    fn sign_packet(&self, packet: &mut [u8]) -> Result<(), CoreError> {
        if packet.len() < Header::LEN {
            return Err(CoreError::InvalidInput("packet too short to sign"));
        }

        packet[Header::SIGNATURE_RANGE].fill(0);
        let signature = self.signature_for(packet)?;
        packet[Header::SIGNATURE_RANGE].copy_from_slice(&signature);
        Ok(())
    }

    fn verify_packet(&self, packet: &[u8]) -> Result<(), CoreError> {
        if packet.len() < Header::LEN {
            return Err(CoreError::InvalidResponse(
                "signed packet was shorter than an SMB2 header",
            ));
        }

        let mut signed_packet = packet.to_vec();
        let signature =
            <[u8; 16]>::try_from(&signed_packet[Header::SIGNATURE_RANGE]).map_err(|_| {
                CoreError::InvalidResponse("signed packet did not contain a full signature")
            })?;
        signed_packet[Header::SIGNATURE_RANGE].fill(0);

        if self.signature_for(&signed_packet)? != signature {
            return Err(CoreError::InvalidResponse(
                "SMB response signature did not match the derived signing key",
            ));
        }

        Ok(())
    }

    fn signature_for(&self, packet: &[u8]) -> Result<[u8; 16], CoreError> {
        match self.algorithm {
            SigningAlgorithm::HmacSha256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).map_err(|_| {
                    CoreError::InvalidInput("invalid SMB signing key for HMAC-SHA256")
                })?;
                mac.update(packet);
                let digest = mac.finalize().into_bytes();
                let mut signature = [0u8; 16];
                signature.copy_from_slice(&digest[..16]);
                Ok(signature)
            }
            SigningAlgorithm::Aes128Cmac => {
                let mut mac = Cmac::<Aes128>::new_from_slice(&self.key).map_err(|_| {
                    CoreError::InvalidInput("invalid SMB signing key for AES-128-CMAC")
                })?;
                mac.update(packet);
                let digest = mac.finalize().into_bytes();
                let mut signature = [0u8; 16];
                signature.copy_from_slice(&digest[..16]);
                Ok(signature)
            }
        }
    }
}

/// A typestate SMB connection over an abstract transport.
#[derive(Debug)]
pub struct Connection<T, State> {
    transport: T,
    next_message_id: u64,
    state: State,
}

#[derive(Debug)]
struct TransactionFrames {
    header: Header,
    body: Vec<u8>,
    request_packet: Vec<u8>,
    response_packet: Vec<u8>,
}

#[derive(Debug, Clone)]
struct RequestContext {
    session_id: SessionId,
    tree_id: TreeId,
    signing: Option<SigningState>,
}

impl RequestContext {
    fn new(session_id: SessionId, tree_id: TreeId, signing: Option<SigningState>) -> Self {
        Self {
            session_id,
            tree_id,
            signing,
        }
    }

    fn unsigned(session_id: SessionId, tree_id: TreeId) -> Self {
        Self::new(session_id, tree_id, None)
    }
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
        let transaction = self
            .transact_framed(
                Command::Negotiate,
                request.encode()?,
                RequestContext::unsigned(SessionId(0), TreeId(0)),
                &[0],
            )
            .await?;
        let header = transaction.header.clone();
        let response = NegotiateResponse::decode(&transaction.body)?;
        let preauth_integrity = negotiate_preauth_integrity_state(
            request,
            &response,
            &transaction.request_packet,
            &transaction.response_packet,
        )?;

        if header.session_id != SessionId(0) {
            return Err(CoreError::InvalidResponse(
                "negotiate response must not assign a session id",
            ));
        }

        Ok(Connection {
            transport: self.transport,
            next_message_id: self.next_message_id,
            state: Negotiated {
                response,
                preauth_integrity,
            },
        })
    }
}

impl<T> Connection<T, Negotiated>
where
    T: Transport + Send,
{
    /// Performs a multi-step authenticated `SESSION_SETUP` exchange.
    pub async fn authenticate<A>(
        mut self,
        auth_provider: &mut A,
    ) -> Result<Connection<T, Authenticated>, CoreError>
    where
        A: AuthProvider,
    {
        let negotiated = self.state.response.clone();
        let mut preauth_integrity = self.state.preauth_integrity.clone();
        let security_mode = session_setup_security_mode(negotiated.security_mode);
        let mut session_id = SessionId(0);
        let mut next_token = auth_provider.initial_token(&negotiated)?;

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
                    RequestContext::unsigned(session_id, TreeId(0)),
                    &[
                        NtStatus::SUCCESS.to_u32(),
                        NtStatus::MORE_PROCESSING_REQUIRED.to_u32(),
                    ],
                )
                .await?;
            let header = transaction.header;
            let response = SessionSetupResponse::decode(&transaction.body)?;
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
                let session_key = auth_provider.session_key().map(ToOwned::to_owned);
                let signing = derive_signing_state(
                    negotiated.dialect_revision,
                    session_key.as_deref(),
                    preauth_integrity.as_ref(),
                )?;
                verify_final_session_setup_response(
                    negotiated.dialect_revision,
                    &header,
                    &transaction.response_packet,
                    signing.as_ref(),
                )?;
                auth_provider.finish(&response.security_buffer)?;
                return Ok(Connection {
                    transport: self.transport,
                    next_message_id: self.next_message_id,
                    state: Authenticated {
                        negotiated,
                        session: response,
                        session_id,
                        preauth_integrity,
                        session_key,
                        signing,
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
        let negotiated = self.state.response.clone();
        let mut preauth_integrity = self.state.preauth_integrity.clone();
        let transaction = self
            .transact_framed(
                Command::SessionSetup,
                request.encode(),
                RequestContext::unsigned(SessionId(0), TreeId(0)),
                &[0],
            )
            .await?;
        let header = transaction.header;
        let response = SessionSetupResponse::decode(&transaction.body)?;
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
            negotiated.dialect_revision,
            &header,
            &transaction.response_packet,
            None,
        )?;

        Ok(Connection {
            transport: self.transport,
            next_message_id: self.next_message_id,
            state: Authenticated {
                negotiated,
                session: response,
                session_id: header.session_id,
                preauth_integrity,
                session_key: None,
                signing: None,
            },
        })
    }
}

impl<T> Connection<T, Authenticated>
where
    T: Transport + Send,
{
    /// Performs `LOGOFF` and transitions back into the negotiated state.
    pub async fn logoff(mut self) -> Result<Connection<T, Negotiated>, CoreError> {
        let negotiated = self.state.negotiated.clone();
        let preauth_integrity = self.state.preauth_integrity.clone();
        let context =
            RequestContext::new(self.state.session_id, TreeId(0), self.state.signing.clone());
        let _ = self
            .transact(
                Command::Logoff,
                LogoffRequest.encode(),
                context,
                &[0],
                LogoffResponse::decode,
            )
            .await?;

        Ok(Connection {
            transport: self.transport,
            next_message_id: self.next_message_id,
            state: Negotiated {
                response: negotiated,
                preauth_integrity,
            },
        })
    }

    /// Performs `TREE_CONNECT` and transitions into the tree-connected state.
    pub async fn tree_connect(
        mut self,
        request: &TreeConnectRequest,
    ) -> Result<Connection<T, TreeConnected>, CoreError> {
        let authenticated = self.state.clone();
        let context = RequestContext::new(
            authenticated.session_id,
            TreeId(0),
            authenticated.signing.clone(),
        );
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

        Ok(Connection {
            transport: self.transport,
            next_message_id: self.next_message_id,
            state: TreeConnected {
                negotiated: authenticated.negotiated,
                session: authenticated.session,
                tree: response,
                session_id: authenticated.session_id,
                tree_id: header.tree_id,
                preauth_integrity: authenticated.preauth_integrity,
                session_key: authenticated.session_key,
                signing: authenticated.signing,
            },
        })
    }
}

impl<T> Connection<T, TreeConnected>
where
    T: Transport + Send,
{
    /// Performs a `TREE_DISCONNECT` request and returns to the authenticated state.
    pub async fn tree_disconnect(mut self) -> Result<Connection<T, Authenticated>, CoreError> {
        let authenticated = Authenticated {
            negotiated: self.state.negotiated.clone(),
            session: self.state.session.clone(),
            session_id: self.state.session_id,
            preauth_integrity: self.state.preauth_integrity.clone(),
            session_key: self.state.session_key.clone(),
            signing: self.state.signing.clone(),
        };
        let context = RequestContext::new(
            authenticated.session_id,
            self.state.tree_id,
            authenticated.signing.clone(),
        );
        let _ = self
            .transact(
                Command::TreeDisconnect,
                TreeDisconnectRequest.encode(),
                context,
                &[0],
                TreeDisconnectResponse::decode,
            )
            .await?;

        Ok(Connection {
            transport: self.transport,
            next_message_id: self.next_message_id,
            state: authenticated,
        })
    }

    /// Performs a `CREATE` request on the active tree.
    pub async fn create(&mut self, request: &CreateRequest) -> Result<CreateResponse, CoreError> {
        let context = RequestContext::new(
            self.state.session_id,
            self.state.tree_id,
            self.state.signing.clone(),
        );
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

    /// Performs a `READ` request on the active tree.
    pub async fn read(&mut self, request: &ReadRequest) -> Result<ReadResponse, CoreError> {
        let context = RequestContext::new(
            self.state.session_id,
            self.state.tree_id,
            self.state.signing.clone(),
        );
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
        let context = RequestContext::new(
            self.state.session_id,
            self.state.tree_id,
            self.state.signing.clone(),
        );
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
        let context = RequestContext::new(
            self.state.session_id,
            self.state.tree_id,
            self.state.signing.clone(),
        );
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
        let context = RequestContext::new(
            self.state.session_id,
            self.state.tree_id,
            self.state.signing.clone(),
        );
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

    /// Performs a `QUERY_DIRECTORY` request on the active tree.
    pub async fn query_directory(
        &mut self,
        request: &QueryDirectoryRequest,
    ) -> Result<QueryDirectoryResponse, CoreError> {
        let context = RequestContext::new(
            self.state.session_id,
            self.state.tree_id,
            self.state.signing.clone(),
        );
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
        let context = RequestContext::new(
            self.state.session_id,
            self.state.tree_id,
            self.state.signing.clone(),
        );
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
        let context = RequestContext::new(
            self.state.session_id,
            self.state.tree_id,
            self.state.signing.clone(),
        );
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
    T: Transport + Send,
{
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
        let response = decode(&transaction.body)?;
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
        Ok((transaction.header, transaction.body))
    }

    async fn transact_framed(
        &mut self,
        command: Command,
        body: Vec<u8>,
        context: RequestContext,
        accepted_statuses: &[u32],
    ) -> Result<TransactionFrames, CoreError> {
        let message_id = MessageId(self.next_message_id);
        self.next_message_id += 1;

        let mut header = Header::new(command, message_id);
        header.session_id = context.session_id;
        header.tree_id = context.tree_id;
        if context.signing.is_some() {
            header.flags |= HeaderFlags::SIGNED;
        }

        let mut packet = header.encode();
        packet.extend_from_slice(&body);
        if let Some(signing) = context.signing.as_ref() {
            signing.sign_packet(&mut packet)?;
        }
        let frame = SessionMessage::new(packet.clone()).encode()?;

        trace!(?command, message_id = message_id.0, "sending smb request");
        self.transport
            .send(&frame)
            .instrument(trace_span!("smb_send", ?command, message_id = message_id.0))
            .await?;

        let mut pending_async_id = None;
        loop {
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
            if response_header.message_id != message_id {
                return Err(CoreError::InvalidResponse(
                    "response message id did not match the request",
                ));
            }

            if response_header.status == NtStatus::PENDING.to_u32() {
                let async_id = validate_pending_response(&response_header)?;
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

            if !accepted_statuses.contains(&response_header.status) {
                return Err(CoreError::UnexpectedStatus {
                    command,
                    status: response_header.status,
                });
            }

            return Ok(TransactionFrames {
                header: response_header,
                body: response_frame.payload[Header::LEN..].to_vec(),
                request_packet: packet.clone(),
                response_packet: response_frame.payload,
            });
        }
    }
}

fn validate_pending_response(header: &Header) -> Result<AsyncId, CoreError> {
    if !header.flags.contains(HeaderFlags::ASYNC_COMMAND) {
        return Err(CoreError::InvalidResponse(
            "pending response must use the async SMB2 header",
        ));
    }
    let async_id = header.async_id.ok_or(CoreError::InvalidResponse(
        "pending response was missing an async id",
    ))?;
    if async_id.0 == 0 {
        return Err(CoreError::InvalidResponse(
            "pending response async id must be nonzero",
        ));
    }
    Ok(async_id)
}

fn validate_async_final_response(header: &Header, async_id: AsyncId) -> Result<(), CoreError> {
    if !header.flags.contains(HeaderFlags::ASYNC_COMMAND) {
        return Err(CoreError::InvalidResponse(
            "final async response must use the async SMB2 header",
        ));
    }
    if header.async_id != Some(async_id) {
        return Err(CoreError::InvalidResponse(
            "final async response async id did not match the interim response",
        ));
    }
    Ok(())
}

fn negotiate_preauth_integrity_state(
    request: &NegotiateRequest,
    response: &NegotiateResponse,
    request_packet: &[u8],
    response_packet: &[u8],
) -> Result<Option<PreauthIntegrityState>, CoreError> {
    if response.dialect_revision != smolder_proto::smb::smb2::Dialect::Smb311 {
        return Ok(None);
    }

    let requested = single_preauth_context(&request.negotiate_contexts, true)?.ok_or(
        CoreError::InvalidInput(
            "SMB 3.1.1 negotiate requests must include a preauth integrity context",
        ),
    )?;
    let received = single_preauth_context(&response.negotiate_contexts, false)?.ok_or(
        CoreError::InvalidResponse(
            "SMB 3.1.1 negotiate responses must include exactly one preauth integrity context",
        ),
    )?;
    if received.hash_algorithms.len() != 1 {
        return Err(CoreError::InvalidResponse(
            "SMB 3.1.1 preauth negotiate response must select exactly one hash algorithm",
        ));
    }
    let algorithm = received.hash_algorithms[0];
    if !requested.hash_algorithms.contains(&algorithm) {
        return Err(CoreError::InvalidResponse(
            "server selected a preauth hash algorithm that was not offered by the client",
        ));
    }

    let mut preauth = PreauthIntegrityState::new(algorithm);
    preauth.update(request_packet)?;
    preauth.update(response_packet)?;
    Ok(Some(preauth))
}

fn single_preauth_context(
    contexts: &[smolder_proto::smb::smb2::NegotiateContext],
    request: bool,
) -> Result<Option<PreauthIntegrityCapabilities>, CoreError> {
    let mut found = None;
    for context in contexts {
        let Some(preauth) = context.as_preauth_integrity()? else {
            continue;
        };
        if found.is_some() {
            return Err(if request {
                CoreError::InvalidInput(
                    "SMB 3.1.1 negotiate request contained multiple preauth integrity contexts",
                )
            } else {
                CoreError::InvalidResponse(
                    "SMB 3.1.1 negotiate response contained multiple preauth integrity contexts",
                )
            });
        }
        found = Some(preauth);
    }
    Ok(found)
}

fn update_session_setup_preauth(
    preauth_integrity: &mut Option<PreauthIntegrityState>,
    request_packet: &[u8],
    response_packet: &[u8],
    success: bool,
) -> Result<(), CoreError> {
    let Some(preauth_integrity) = preauth_integrity.as_mut() else {
        return Ok(());
    };

    preauth_integrity.update(request_packet)?;
    if !success {
        preauth_integrity.update(response_packet)?;
    }

    Ok(())
}

fn verify_final_session_setup_response(
    dialect: Dialect,
    header: &Header,
    response_packet: &[u8],
    signing: Option<&SigningState>,
) -> Result<(), CoreError> {
    if header.status != NtStatus::SUCCESS.to_u32() || dialect != Dialect::Smb311 {
        return Ok(());
    }

    let Some(signing) = signing else {
        return Ok(());
    };

    if !header.flags.contains(HeaderFlags::SIGNED) {
        return Err(CoreError::InvalidResponse(
            "SMB 3.1.1 final session setup response must be signed",
        ));
    }

    signing.verify_packet(response_packet)
}

fn derive_signing_state(
    dialect: Dialect,
    session_key: Option<&[u8]>,
    preauth_integrity: Option<&PreauthIntegrityState>,
) -> Result<Option<SigningState>, CoreError> {
    let Some(session_key) = session_key else {
        return Ok(None);
    };

    let signing = match dialect {
        Dialect::Smb202 | Dialect::Smb210 => SigningState {
            algorithm: SigningAlgorithm::HmacSha256,
            key: session_key.to_vec(),
        },
        Dialect::Smb300 | Dialect::Smb302 => SigningState {
            algorithm: SigningAlgorithm::Aes128Cmac,
            key: derive_key(
                session_key,
                b"SMB2AESCMAC\0",
                b"SmbSign\0",
                Header::SIGNATURE_RANGE.len() * 8,
            )?,
        },
        Dialect::Smb311 => {
            let preauth_integrity = preauth_integrity.ok_or(CoreError::InvalidResponse(
                "SMB 3.1.1 session is missing preauth integrity state",
            ))?;
            SigningState {
                algorithm: SigningAlgorithm::Aes128Cmac,
                key: derive_key(
                    session_key,
                    b"SMBSigningKey\0",
                    &preauth_integrity.hash_value,
                    Header::SIGNATURE_RANGE.len() * 8,
                )?,
            }
        }
    };

    Ok(Some(signing))
}

fn derive_key(
    key: &[u8],
    label: &[u8],
    context: &[u8],
    output_bits: usize,
) -> Result<Vec<u8>, CoreError> {
    if output_bits == 0 {
        return Err(CoreError::InvalidInput(
            "derived SMB key length must be nonzero",
        ));
    }

    let output_bytes = output_bits / 8;
    let blocks = output_bytes.div_ceil(32);
    let mut derived = Vec::with_capacity(blocks * 32);

    for counter in 1..=u32::try_from(blocks)
        .map_err(|_| CoreError::InvalidInput("requested SMB key derivation output was too large"))?
    {
        let mut mac = Hmac::<Sha256>::new_from_slice(key)
            .map_err(|_| CoreError::InvalidInput("invalid SMB key derivation key"))?;
        mac.update(&counter.to_be_bytes());
        mac.update(label);
        mac.update(&[0]);
        mac.update(context);
        mac.update(&(output_bits as u32).to_be_bytes());
        derived.extend_from_slice(&mac.finalize().into_bytes());
    }

    derived.truncate(output_bytes);
    Ok(derived)
}

fn session_setup_security_mode(signing_mode: SigningMode) -> SessionSetupSecurityMode {
    let mut security_mode = SessionSetupSecurityMode::empty();
    if signing_mode.contains(SigningMode::ENABLED) {
        security_mode |= SessionSetupSecurityMode::SIGNING_ENABLED;
    }
    if signing_mode.contains(SigningMode::REQUIRED) {
        security_mode |= SessionSetupSecurityMode::SIGNING_REQUIRED;
    }
    security_mode
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use async_trait::async_trait;
    use smolder_proto::smb::netbios::SessionMessage;
    use smolder_proto::smb::smb2::{
        AsyncId, CloseRequest, CloseResponse, Command, CreateRequest, CreateResponse, Dialect,
        FileAttributes, FileId, FlushRequest, FlushResponse, GlobalCapabilities, Header,
        HeaderFlags, LogoffRequest, LogoffResponse, MessageId, NegotiateRequest, NegotiateResponse,
        OplockLevel, PreauthIntegrityCapabilities, PreauthIntegrityHashId, ReadRequest,
        ReadResponse, ReadResponseFlags, SessionFlags, SessionId, SessionSetupRequest,
        SessionSetupResponse, SessionSetupSecurityMode, ShareFlags, ShareType, SigningMode,
        TreeCapabilities, TreeConnectRequest, TreeConnectResponse, TreeDisconnectRequest, TreeId,
        WriteRequest, WriteResponse,
    };
    use smolder_proto::smb::status::NtStatus;

    use crate::auth::{AuthError, AuthProvider};
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
        status: u32,
        message_id: u64,
        session_id: u64,
        tree_id: u32,
        body: Vec<u8>,
    ) -> Vec<u8> {
        let packet = response_packet(command, status, message_id, session_id, tree_id, body);
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
        let mut header = Header::new(command, MessageId(message_id));
        header.status = status;
        header.flags = HeaderFlags::SERVER_TO_REDIR;
        header.session_id = SessionId(session_id);
        header.tree_id = TreeId(tree_id);

        let mut packet = header.encode();
        packet.extend_from_slice(&body);
        packet
    }

    fn request_packet(
        command: Command,
        message_id: u64,
        session_id: u64,
        tree_id: u32,
        body: Vec<u8>,
    ) -> Vec<u8> {
        let mut header = Header::new(command, MessageId(message_id));
        header.session_id = SessionId(session_id);
        header.tree_id = TreeId(tree_id);

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

    fn preauth_context(salt: &[u8]) -> smolder_proto::smb::smb2::NegotiateContext {
        smolder_proto::smb::smb2::NegotiateContext::preauth_integrity(
            PreauthIntegrityCapabilities {
                hash_algorithms: vec![PreauthIntegrityHashId::Sha512],
                salt: salt.to_vec(),
            },
        )
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
            SessionSetupSecurityMode::SIGNING_ENABLED | SessionSetupSecurityMode::SIGNING_REQUIRED
        );
        assert_eq!(first_setup.security_buffer, vec![0x01, 0x02]);

        let second_setup_header = outbound_header(&transport.writes[2]);
        assert_eq!(second_setup_header.session_id, SessionId(77));
        let second_setup = outbound_session_setup(&transport.writes[2]);
        assert_eq!(second_setup.security_buffer, vec![0x03, 0x04, 0x05]);
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
        let negotiate_request_packet = request_packet(
            Command::Negotiate,
            0,
            0,
            0,
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
            &negotiate_request,
            &negotiate_response,
            &negotiate_request_packet,
            &negotiate_response_packet,
        )
        .expect("preauth state should derive")
        .expect("SMB 3.1.1 should negotiate preauth");
        let session_request_packet =
            request_packet(Command::SessionSetup, 1, 0, 0, session_request.encode());
        preauth
            .update(&session_request_packet)
            .expect("session request should update preauth state");
        let signing =
            super::derive_signing_state(Dialect::Smb311, Some(&[0x55; 16]), Some(&preauth))
                .expect("signing key should derive")
                .expect("signing state should be present");
        let mut signed_session_response_packet = response_packet(
            Command::SessionSetup,
            NtStatus::SUCCESS.to_u32(),
            1,
            77,
            0,
            session_response.encode(),
        );
        let mut session_header = Header::decode(&signed_session_response_packet[..Header::LEN])
            .expect("header should decode");
        session_header.flags |= HeaderFlags::SIGNED;
        signed_session_response_packet[..Header::LEN].copy_from_slice(&session_header.encode());
        signing
            .sign_packet(&mut signed_session_response_packet)
            .expect("response should sign");

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
