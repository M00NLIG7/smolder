//! Typestate SMB client built on top of wire-level packet codecs.

use aes::Aes128;
use cmac::Cmac;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use smolder_proto::smb::netbios::SessionMessage;
use smolder_proto::smb::smb2::{
    AsyncId, ChangeNotifyRequest, ChangeNotifyResponse, CloseRequest, CloseResponse, Command,
    CreateContext, CreateRequest, CreateResponse, EchoRequest, EchoResponse, CipherId, Dialect,
    DurableHandleFlags, DurableHandleReconnect, DurableHandleReconnectV2, DurableHandleRequest,
    DurableHandleRequestV2, FileId, FlushRequest, FlushResponse, GlobalCapabilities, Header,
    HeaderFlags, IoctlRequest, IoctlResponse, LockRequest, LockResponse, LogoffRequest,
    LogoffResponse, MessageId, NegotiateRequest, NegotiateResponse, NetworkInterfaceInfoResponse,
    PreauthIntegrityCapabilities, PreauthIntegrityHashId, QueryDirectoryRequest,
    QueryDirectoryResponse, QueryInfoRequest, QueryInfoResponse, ReadRequest, ReadResponse,
    ResumeKeyResponse, SessionFlags, SessionId, SessionSetupRequest, SessionSetupResponse,
    SessionSetupSecurityMode, SetInfoRequest, SetInfoResponse, ShareFlags, SigningMode,
    TreeConnectRequest, TreeConnectResponse, TreeDisconnectRequest, TreeDisconnectResponse,
    TreeId, WriteRequest, WriteResponse,
};
use smolder_proto::smb::status::NtStatus;
use smolder_proto::smb::transform::{TransformHeader, TRANSFORM_PROTOCOL_ID};
use std::sync::Arc;
use tracing::{trace, trace_span, Instrument};

use crate::auth::AuthProvider;
use crate::crypto::{derive_encryption_keys, EncryptionState};
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
    /// Signing mode requested by the client during negotiate.
    pub client_signing_mode: SigningMode,
    /// Preauthentication integrity state for SMB 3.1.1, if negotiated.
    pub preauth_integrity: Option<PreauthIntegrityState>,
}

/// The transport has an authenticated SMB session.
#[derive(Debug, Clone)]
pub struct Authenticated {
    /// Negotiate details for the connection.
    pub negotiated: NegotiateResponse,
    /// Signing mode requested by the client during negotiate.
    pub client_signing_mode: SigningMode,
    /// Session setup response.
    pub session: SessionSetupResponse,
    /// Assigned session identifier.
    pub session_id: SessionId,
    /// Preauthentication integrity state for SMB 3.1.1, if negotiated.
    pub preauth_integrity: Option<PreauthIntegrityState>,
    /// Exported session key from the authentication mechanism.
    pub session_key: Option<Vec<u8>>,
    /// Whether the session requires signed responses and requests.
    pub signing_required: bool,
    /// Derived request-signing state for the session, if available.
    pub signing: Option<Arc<SigningState>>,
    /// Whether the session requires SMB 3.x encryption for all subsequent requests.
    pub encryption_required: bool,
    /// Derived SMB 3.x encryption state for the session, if available.
    pub encryption: Option<Arc<EncryptionState>>,
}

/// The transport is connected to a tree and can issue file operations.
#[derive(Debug, Clone)]
pub struct TreeConnected {
    /// Negotiate details for the connection.
    pub negotiated: NegotiateResponse,
    /// Signing mode requested by the client during negotiate.
    pub client_signing_mode: SigningMode,
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
    /// Whether the session requires signed responses and requests.
    pub signing_required: bool,
    /// Derived request-signing state for the session, if available.
    pub signing: Option<Arc<SigningState>>,
    /// Whether requests on this tree must use SMB 3.x encryption.
    pub encryption_required: bool,
    /// Derived SMB 3.x encryption state for the session, if available.
    pub encryption: Option<Arc<EncryptionState>>,
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

        let signature = <[u8; 16]>::try_from(&packet[Header::SIGNATURE_RANGE]).map_err(|_| {
            CoreError::InvalidResponse("signed packet did not contain a full signature")
        })?;

        if self.signature_for_verification(packet)? != signature {
            return Err(CoreError::InvalidResponse(
                "SMB response signature did not match the derived signing key",
            ));
        }

        Ok(())
    }

    fn signature_for_verification(&self, packet: &[u8]) -> Result<[u8; 16], CoreError> {
        const ZERO_SIGNATURE: [u8; 16] = [0; 16];
        let prefix = &packet[..Header::SIGNATURE_RANGE.start];
        let suffix = &packet[Header::SIGNATURE_RANGE.end..];

        match self.algorithm {
            SigningAlgorithm::HmacSha256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).map_err(|_| {
                    CoreError::InvalidInput("invalid SMB signing key for HMAC-SHA256")
                })?;
                mac.update(prefix);
                mac.update(&ZERO_SIGNATURE);
                mac.update(suffix);
                let digest = mac.finalize().into_bytes();
                let mut signature = [0u8; 16];
                signature.copy_from_slice(&digest[..16]);
                Ok(signature)
            }
            SigningAlgorithm::Aes128Cmac => {
                let mut mac = Cmac::<Aes128>::new_from_slice(&self.key).map_err(|_| {
                    CoreError::InvalidInput("invalid SMB signing key for AES-128-CMAC")
                })?;
                mac.update(prefix);
                mac.update(&ZERO_SIGNATURE);
                mac.update(suffix);
                let digest = mac.finalize().into_bytes();
                let mut signature = [0u8; 16];
                signature.copy_from_slice(&digest[..16]);
                Ok(signature)
            }
        }
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

/// A raw SMB request element within a compound chain.
#[derive(Debug, Clone)]
pub struct CompoundRequest {
    /// The SMB2 command to send.
    pub command: Command,
    /// The encoded SMB2 request body for this command.
    pub body: Vec<u8>,
    /// Whether this request should be flagged as related to the previous request.
    pub related: bool,
    /// Accepted NTSTATUS values for this response element.
    pub accepted_statuses: Vec<u32>,
}

impl CompoundRequest {
    /// Builds a new raw compound request that expects `STATUS_SUCCESS`.
    #[must_use]
    pub fn new(command: Command, body: Vec<u8>) -> Self {
        Self {
            command,
            body,
            related: false,
            accepted_statuses: vec![NtStatus::SUCCESS.to_u32()],
        }
    }

    /// Marks this request as related to the previous request in the chain.
    #[must_use]
    pub fn related(command: Command, body: Vec<u8>) -> Self {
        Self::new(command, body).with_related(true)
    }

    /// Sets whether this request is related to the previous request in the chain.
    #[must_use]
    pub fn with_related(mut self, related: bool) -> Self {
        self.related = related;
        self
    }

    /// Replaces the accepted status list for this response element.
    #[must_use]
    pub fn with_accepted_statuses(mut self, statuses: impl Into<Vec<u32>>) -> Self {
        self.accepted_statuses = statuses.into();
        self
    }
}

/// A raw SMB response element returned from a compound chain.
#[derive(Debug, Clone)]
pub struct CompoundResponse {
    /// The SMB2 response header for this element.
    pub header: Header,
    /// The raw SMB2 response body for this element, including any compound alignment padding.
    pub body: Vec<u8>,
}

/// Options used when requesting a durable open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableOpenOptions {
    /// Requested durable-open timeout in milliseconds for SMB 3.x durable-v2 opens.
    pub timeout: u32,
    /// Requested durable-handle flags, including persistent-handle requests.
    pub flags: DurableHandleFlags,
    /// Client-supplied durable-open identifier for SMB 3.x durable-v2 opens.
    pub create_guid: Option<[u8; 16]>,
}

impl DurableOpenOptions {
    /// Builds default durable-open options.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the SMB 3.x durable-open identifier.
    #[must_use]
    pub fn with_create_guid(mut self, create_guid: [u8; 16]) -> Self {
        self.create_guid = Some(create_guid);
        self
    }

    /// Sets the requested durable-open timeout in milliseconds.
    #[must_use]
    pub fn with_timeout(mut self, timeout: u32) -> Self {
        self.timeout = timeout;
        self
    }

    /// Replaces the requested durable-handle flags.
    #[must_use]
    pub fn with_flags(mut self, flags: DurableHandleFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Enables or disables persistent-handle requests.
    #[must_use]
    pub fn with_persistent(mut self, persistent: bool) -> Self {
        if persistent {
            self.flags |= DurableHandleFlags::PERSISTENT;
        } else {
            self.flags.remove(DurableHandleFlags::PERSISTENT);
        }
        self
    }
}

impl Default for DurableOpenOptions {
    fn default() -> Self {
        Self {
            timeout: 0,
            flags: DurableHandleFlags::empty(),
            create_guid: None,
        }
    }
}

/// Reconnectable durable open state captured from a successful `CREATE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableHandle {
    create_request: CreateRequest,
    response: CreateResponse,
    timeout: u32,
    flags: DurableHandleFlags,
    create_guid: Option<[u8; 16]>,
}

impl DurableHandle {
    /// Returns the current server-assigned file identifier.
    #[must_use]
    pub fn file_id(&self) -> FileId {
        self.response.file_id
    }

    /// Returns the original `CREATE` request used to establish the durable open.
    #[must_use]
    pub fn create_request(&self) -> &CreateRequest {
        &self.create_request
    }

    /// Returns the most recent `CREATE` response for the durable open.
    #[must_use]
    pub fn create_response(&self) -> &CreateResponse {
        &self.response
    }

    /// Returns the granted resilient/durable timeout in milliseconds.
    #[must_use]
    pub fn timeout(&self) -> u32 {
        self.timeout
    }

    /// Returns the granted durable-handle flags.
    #[must_use]
    pub fn flags(&self) -> DurableHandleFlags {
        self.flags
    }

    fn with_response(&self, response: CreateResponse) -> Self {
        Self {
            create_request: self.create_request.clone(),
            response,
            timeout: self.timeout,
            flags: self.flags,
            create_guid: self.create_guid,
        }
    }
}

/// File-handle resiliency state requested through `FSCTL_LMR_REQUEST_RESILIENCY`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResilientHandle {
    /// The file identifier covered by the resiliency request.
    pub file_id: FileId,
    /// The requested resiliency timeout in milliseconds.
    pub timeout: u32,
}

#[derive(Debug, Clone)]
struct RequestContext {
    session_id: SessionId,
    tree_id: TreeId,
    signing_required: bool,
    signing: Option<Arc<SigningState>>,
    encryption_required: bool,
    encryption: Option<Arc<EncryptionState>>,
}

impl RequestContext {
    fn new(
        session_id: SessionId,
        tree_id: TreeId,
        signing_required: bool,
        signing: Option<Arc<SigningState>>,
    ) -> Self {
        Self {
            session_id,
            tree_id,
            signing_required,
            signing,
            encryption_required: false,
            encryption: None,
        }
    }

    fn unsigned(session_id: SessionId, tree_id: TreeId) -> Self {
        Self::new(session_id, tree_id, false, None)
    }

    fn with_encryption(
        mut self,
        encryption_required: bool,
        encryption: Option<Arc<EncryptionState>>,
    ) -> Self {
        self.encryption_required = encryption_required;
        self.encryption = encryption;
        self
    }

    fn should_encrypt(&self) -> bool {
        self.encryption_required
    }
}

impl Authenticated {
    fn request_context(&self) -> RequestContext {
        RequestContext::new(
            self.session_id,
            TreeId(0),
            self.signing_required,
            self.signing.clone(),
        )
        .with_encryption(self.encryption_required, self.encryption.clone())
    }
}

impl TreeConnected {
    fn request_context(&self) -> RequestContext {
        RequestContext::new(
            self.session_id,
            self.tree_id,
            self.signing_required,
            self.signing.clone(),
        )
        .with_encryption(self.encryption_required, self.encryption.clone())
    }

    fn session_request_context(&self) -> RequestContext {
        RequestContext::new(
            self.session_id,
            TreeId(0),
            self.signing_required,
            self.signing.clone(),
        )
        .with_encryption(self.encryption_required, self.encryption.clone())
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
        let response = NegotiateResponse::decode(transaction.body())?;
        let preauth_integrity = negotiate_preauth_integrity_state(
            request,
            &response,
            &transaction.request_packet,
            &transaction.response_packet,
        )?;

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
                    RequestContext::unsigned(session_id, TreeId(0)),
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
                let session_key = auth_provider.session_key().map(ToOwned::to_owned);
                let signing_required = session_signing_required(
                    client_signing_mode,
                    self.state.response.security_mode,
                    response.session_flags,
                );
                let signing = derive_signing_state(
                    self.state.response.dialect_revision,
                    session_key.as_deref(),
                    preauth_integrity.as_ref(),
                )?;
                let encryption = derive_encryption_state(
                    &self.state.response,
                    session_key.as_deref(),
                    preauth_integrity.as_ref(),
                )?;
                verify_final_session_setup_response(
                    self.state.response.dialect_revision,
                    &header,
                    &transaction.response_packet,
                    signing_required,
                    signing.as_deref(),
                )?;
                auth_provider.finish(&response.security_buffer)?;
                let Connection {
                    transport,
                    next_message_id,
                    available_credits,
                    state,
                } = self;
                let Negotiated {
                    response: negotiated,
                    client_signing_mode,
                    ..
                } = state;
                let encryption_required = session_encryption_required(response.session_flags);
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
                RequestContext::unsigned(SessionId(0), TreeId(0)),
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
        let encryption = derive_encryption_state(&self.state.response, None, preauth_integrity.as_ref())?;
        let Connection {
            transport,
            next_message_id,
            available_credits,
            state,
        } = self;
        let Negotiated {
            response: negotiated,
            client_signing_mode,
            ..
        } = state;
        let encryption_required = session_encryption_required(response.session_flags);

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
            },
        })
    }
}

impl<T> Connection<T, Authenticated>
where
    T: Transport + Send,
{
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
        } = state;
        let encryption_required =
            tree_encryption_required(session.session_flags, response.share_flags);

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
            },
        })
    }
}

impl<T> Connection<T, TreeConnected>
where
    T: Transport + Send,
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
            ..
        } = state;
        let encryption_required = session_encryption_required(session.session_flags);

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
        let durable_request = durable_create_request(self.state.negotiated.dialect_revision, request, &options)?;
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
    T: Transport + Send,
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
        let frame = encode_session_frame(&payload, &context)?;
        let first_command = requests[0].command;
        let last_command = requests[requests.len() - 1].command;

        trace!(
            first_command = ?first_command,
            last_command = ?last_command,
            request_count = requests.len(),
            "sending compound smb request"
        );
        self.transport
            .send(&frame)
            .instrument(trace_span!(
                "smb_send_compound",
                first_command = ?first_command,
                last_command = ?last_command,
                request_count = requests.len()
            ))
            .await?;

        let response_frame = self
            .transport
            .recv()
            .instrument(trace_span!(
                "smb_recv_compound",
                first_command = ?first_command,
                last_command = ?last_command,
                request_count = requests.len()
            ))
            .await?;
        let (response_payload, encrypted_response) =
            decode_session_payload(&response_frame, &context)?;
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
        let frame = encode_session_frame(&packet, &context)?;
        self.commit_message_ids(1)?;

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
            let (response_payload, encrypted_response) =
                decode_session_payload(&response_frame, &context)?;
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


            if !accepted_statuses.contains(&response_header.status) {
                return Err(CoreError::UnexpectedStatus {
                    command,
                    status: response_header.status,
                });
            }
            self.apply_credit_grant(u32::from(response_header.credit_request_response))?;

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
        self.next_message_id = self
            .next_message_id
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
        self.available_credits = self
            .available_credits
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

            let base_len = Header::LEN
                .checked_add(request.body.len())
                .ok_or(CoreError::InvalidInput("compound request element was too large"))?;
            let packet_len = if index + 1 == requests.len() {
                base_len
            } else {
                align_to_8(base_len)
            };
            if index + 1 < requests.len() {
                header.next_command =
                    u32::try_from(packet_len).map_err(|_| CoreError::InvalidInput(
                        "compound request element exceeded SMB next-command limits",
                    ))?;
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

fn session_setup_debug_enabled() -> bool {
    std::env::var_os("SMOLDER_NTLM_DEBUG").is_some()
}

fn align_to_8(len: usize) -> usize {
    (len + 7) & !7
}

fn split_compound_packets(payload: &[u8]) -> Result<Vec<&[u8]>, CoreError> {
    if payload.len() < Header::LEN {
        return Err(CoreError::InvalidResponse(
            "response shorter than SMB2 header",
        ));
    }

    let mut packets = Vec::new();
    let mut offset = 0usize;
    loop {
        let header_end = offset
            .checked_add(Header::LEN)
            .ok_or(CoreError::InvalidResponse("compound response offset overflowed"))?;
        if header_end > payload.len() {
            return Err(CoreError::InvalidResponse(
                "compound response packet was truncated",
            ));
        }
        let header = Header::decode(&payload[offset..header_end])?;
        let next = header.next_command as usize;
        let end = if next == 0 {
            payload.len()
        } else {
            if next < Header::LEN || next % 8 != 0 {
                return Err(CoreError::InvalidResponse(
                    "compound response next-command offset was invalid",
                ));
            }
            offset.checked_add(next).ok_or(CoreError::InvalidResponse(
                "compound response offset overflowed",
            ))?
        };
        if end > payload.len() || end <= offset {
            return Err(CoreError::InvalidResponse(
                "compound response next-command offset was invalid",
            ));
        }
        packets.push(&payload[offset..end]);
        if next == 0 {
            break;
        }
        offset = end;
    }

    Ok(packets)
}

fn encode_session_frame(payload: &[u8], context: &RequestContext) -> Result<Vec<u8>, CoreError> {
    let session_payload = if context.should_encrypt() {
        let encryption = context.encryption.as_deref().ok_or(CoreError::InvalidInput(
            "session requires encryption but no encryption key is available",
        ))?;
        encryption.encrypt_message(context.session_id.0, payload)?.encode()
    } else {
        payload.to_vec()
    };
    SessionMessage::encode_payload(&session_payload).map_err(CoreError::from)
}

fn decode_session_payload(
    frame: &[u8],
    context: &RequestContext,
) -> Result<(Vec<u8>, bool), CoreError> {
    let frame = SessionMessage::decode(frame)?;
    if frame.payload.starts_with(&TRANSFORM_PROTOCOL_ID) {
        let encryption = context.encryption.as_deref().ok_or(CoreError::InvalidResponse(
            "received encrypted SMB response but no encryption state is available",
        ))?;
        let transform = TransformHeader::decode(&frame.payload)?;
        if transform.session_id != context.session_id.0 {
            return Err(CoreError::InvalidResponse(
                "encrypted SMB response session id did not match the active session",
            ));
        }
        return Ok((encryption.decrypt_message(&transform)?, true));
    }
    if context.should_encrypt() {
        return Err(CoreError::InvalidResponse(
            "session required encryption but the SMB response was not encrypted",
        ));
    }
    Ok((frame.payload, false))
}

fn durable_create_request(
    dialect: Dialect,
    request: &CreateRequest,
    options: &DurableOpenOptions,
) -> Result<CreateRequest, CoreError> {
    let mut request = request.clone();
    request.create_contexts = strip_durable_create_contexts(&request.create_contexts)?;
    request.create_contexts.push(match dialect {
        Dialect::Smb202 | Dialect::Smb210 => {
            CreateContext::durable_handle_request(DurableHandleRequest)
        }
        Dialect::Smb300 | Dialect::Smb302 | Dialect::Smb311 => {
            let create_guid = options.create_guid.ok_or(CoreError::InvalidInput(
                "durable SMB 3.x opens require a create GUID",
            ))?;
            CreateContext::durable_handle_request_v2(DurableHandleRequestV2 {
                timeout: options.timeout,
                flags: options.flags,
                create_guid,
            })
        }
    });
    Ok(request)
}

fn durable_reconnect_request(
    dialect: Dialect,
    handle: &DurableHandle,
) -> Result<CreateRequest, CoreError> {
    let mut request = handle.create_request.clone();
    request.create_contexts = strip_durable_create_contexts(&request.create_contexts)?;
    request.create_contexts.push(match dialect {
        Dialect::Smb202 | Dialect::Smb210 => {
            CreateContext::durable_handle_reconnect(DurableHandleReconnect {
                file_id: handle.file_id(),
            })
        }
        Dialect::Smb300 | Dialect::Smb302 | Dialect::Smb311 => {
            let create_guid = handle.create_guid.ok_or(CoreError::InvalidInput(
                "durable SMB 3.x reconnect is missing its create GUID",
            ))?;
            CreateContext::durable_handle_reconnect_v2(DurableHandleReconnectV2 {
                file_id: handle.file_id(),
                create_guid,
                flags: handle.flags,
            })
        }
    });
    Ok(request)
}

fn build_durable_handle(
    dialect: Dialect,
    request: &CreateRequest,
    response: CreateResponse,
    options: &DurableOpenOptions,
) -> Result<DurableHandle, CoreError> {
    let (timeout, flags, create_guid) = match dialect {
        Dialect::Smb202 | Dialect::Smb210 => {
            let granted = response
                .create_contexts
                .iter()
                .find_map(|context| context.durable_handle_response_data().transpose())
                .transpose()?
                .ok_or(CoreError::InvalidResponse(
                    "durable open response did not include the granted durable context",
                ))?;
            let _ = granted;
            (0, DurableHandleFlags::empty(), None)
        }
        Dialect::Smb300 | Dialect::Smb302 | Dialect::Smb311 => {
            let granted = response
                .create_contexts
                .iter()
                .find_map(|context| context.durable_handle_response_v2_data().transpose())
                .transpose()?
                .ok_or(CoreError::InvalidResponse(
                    "durable v2 open response did not include the granted durable context",
                ))?;
            (
                granted.timeout,
                granted.flags,
                Some(options.create_guid.ok_or(CoreError::InvalidInput(
                    "durable SMB 3.x opens require a create GUID",
                ))?),
            )
        }
    };

    Ok(DurableHandle {
        create_request: request.clone(),
        response,
        timeout,
        flags,
        create_guid,
    })
}

fn strip_durable_create_contexts(contexts: &[CreateContext]) -> Result<Vec<CreateContext>, CoreError> {
    let mut filtered = Vec::with_capacity(contexts.len());
    for context in contexts {
        if context.durable_handle_request_data()?.is_some()
            || context.durable_handle_reconnect_data()?.is_some()
            || context.durable_handle_request_v2_data()?.is_some()
            || context.durable_handle_reconnect_v2_data()?.is_some()
        {
            continue;
        }
        filtered.push(context.clone());
    }
    Ok(filtered)
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

fn verify_response_signature(
    header: &Header,
    response_packet: &[u8],
    context: &RequestContext,
) -> Result<(), CoreError> {
    if header.flags.contains(HeaderFlags::SIGNED) {
        let signing = context
            .signing
            .as_deref()
            .ok_or(CoreError::InvalidResponse(
                "received a signed SMB response but no signing key is available",
            ))?;
        return signing.verify_packet(response_packet);
    }

    if context.signing_required {
        return Err(CoreError::InvalidResponse(
            "session requires signed SMB responses",
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
    signing_required: bool,
    signing: Option<&SigningState>,
) -> Result<(), CoreError> {
    if header.status != NtStatus::SUCCESS.to_u32() || dialect != Dialect::Smb311 {
        return Ok(());
    }

    if !header.flags.contains(HeaderFlags::SIGNED) {
        if signing_required {
            return Err(CoreError::InvalidResponse(
                "SMB 3.1.1 final session setup response must be signed",
            ));
        }
        return Ok(());
    }

    let Some(signing) = signing else {
        return Ok(());
    };

    signing.verify_packet(response_packet)
}

fn derive_signing_state(
    dialect: Dialect,
    session_key: Option<&[u8]>,
    preauth_integrity: Option<&PreauthIntegrityState>,
) -> Result<Option<Arc<SigningState>>, CoreError> {
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

    Ok(Some(Arc::new(signing)))
}

fn derive_encryption_state(
    negotiated: &NegotiateResponse,
    session_key: Option<&[u8]>,
    preauth_integrity: Option<&PreauthIntegrityState>,
) -> Result<Option<Arc<EncryptionState>>, CoreError> {
    let Some(session_key) = session_key else {
        return Ok(None);
    };
    let Some(cipher) = negotiated_cipher(negotiated)? else {
        return Ok(None);
    };

    let keys = derive_encryption_keys(
        negotiated.dialect_revision,
        cipher,
        session_key,
        None,
        preauth_integrity.map(|state| state.hash_value.as_slice()),
    )?;
    Ok(Some(Arc::new(EncryptionState::new(
        negotiated.dialect_revision,
        keys,
    ))))
}

fn negotiated_cipher(negotiated: &NegotiateResponse) -> Result<Option<CipherId>, CoreError> {
    match negotiated.dialect_revision {
        Dialect::Smb202 | Dialect::Smb210 => Ok(None),
        Dialect::Smb300 | Dialect::Smb302 => {
            if negotiated.capabilities.contains(GlobalCapabilities::ENCRYPTION) {
                Ok(Some(CipherId::Aes128Ccm))
            } else {
                Ok(None)
            }
        }
        Dialect::Smb311 => {
            let mut selected = None;
            for context in &negotiated.negotiate_contexts {
                let Some(capabilities) = context.as_encryption_capabilities()? else {
                    continue;
                };
                if capabilities.ciphers.len() != 1 {
                    return Err(CoreError::InvalidResponse(
                        "SMB 3.1.1 negotiate response must select exactly one encryption cipher",
                    ));
                }
                if selected.replace(capabilities.ciphers[0]).is_some() {
                    return Err(CoreError::InvalidResponse(
                        "SMB 3.1.1 negotiate response contained multiple encryption contexts",
                    ));
                }
            }

            if negotiated.capabilities.contains(GlobalCapabilities::ENCRYPTION) && selected.is_none()
            {
                return Err(CoreError::InvalidResponse(
                    "SMB 3.1.1 negotiate response did not select an encryption cipher",
                ));
            }

            Ok(selected)
        }
    }
}

fn session_signing_required(
    client_signing_mode: SigningMode,
    server_signing_mode: SigningMode,
    session_flags: SessionFlags,
) -> bool {
    if session_flags
        .intersects(SessionFlags::IS_GUEST | SessionFlags::IS_NULL | SessionFlags::ENCRYPT_DATA)
    {
        return false;
    }

    client_signing_mode.contains(SigningMode::REQUIRED)
        || server_signing_mode.contains(SigningMode::REQUIRED)
}

fn session_encryption_required(session_flags: SessionFlags) -> bool {
    session_flags.contains(SessionFlags::ENCRYPT_DATA)
}

fn tree_encryption_required(session_flags: SessionFlags, share_flags: ShareFlags) -> bool {
    session_encryption_required(session_flags) || share_flags.contains(ShareFlags::ENCRYPT_DATA)
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
    use std::sync::Arc;

    use async_trait::async_trait;
    use smolder_proto::smb::netbios::SessionMessage;
    use smolder_proto::smb::smb2::{
        AsyncId, ChangeNotifyFlags, ChangeNotifyRequest, ChangeNotifyResponse, CipherId,
        CloseRequest, CloseResponse, Command, CompletionFilter, CreateRequest, CreateResponse,
        Dialect, EchoResponse, EncryptionCapabilities, FileAttributes, FileId, FlushRequest,
        FlushResponse, GlobalCapabilities, Header, HeaderFlags, IoctlRequest, IoctlResponse,
        LockElement, LockFlags, LockRequest, LockResponse, LogoffRequest, LogoffResponse,
        MessageId, NegotiateRequest, NegotiateResponse, OplockLevel,
        PreauthIntegrityCapabilities, PreauthIntegrityHashId, ReadRequest, ReadResponse,
        ReadResponseFlags, SessionFlags, SessionId, SessionSetupRequest, SessionSetupResponse,
        SessionSetupSecurityMode, ShareFlags, ShareType, SigningMode, TreeCapabilities,
        TreeConnectRequest, TreeConnectResponse, TreeDisconnectRequest, TreeId, WriteRequest,
        WriteResponse,
    };
    use smolder_proto::smb::transform::TransformHeader;
    use smolder_proto::smb::status::NtStatus;

    use crate::auth::{AuthError, AuthProvider};
    use crate::client::Connection;
    use crate::crypto::{derive_encryption_keys, EncryptionState};
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
        let session_request_packet =
            request_packet_with_credits(Command::SessionSetup, 1, 0, 0, 32, session_request.encode());
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

    fn outbound_encrypted_packet(frame: &[u8], state: &EncryptionState) -> Vec<u8> {
        let frame = SessionMessage::decode(frame).expect("frame should decode");
        let transform =
            TransformHeader::decode(&frame.payload).expect("transform header should decode");
        state
            .decrypt_message(&transform)
            .expect("encrypted payload should decrypt")
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
        let response = connection.lock(&request).await.expect("lock should succeed");
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
