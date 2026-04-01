use std::sync::Arc;

use aes::Aes128;
use cmac::Cmac;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use smolder_proto::smb::smb2::{
    Command, CreateRequest, CreateResponse, DurableHandleFlags, FileId, Header,
    NegotiateResponse, PreauthIntegrityHashId, SessionId, SessionSetupResponse, TreeConnectResponse,
    TreeId,
};
use smolder_proto::smb::status::NtStatus;

use crate::compression::CompressionState;
use crate::crypto::EncryptionState;
use crate::error::CoreError;

/// Connected to a transport but no SMB negotiation has been performed.
#[derive(Debug, Clone, Copy, Default)]
pub struct Connected;

/// Negotiated dialect and server capabilities are known.
#[derive(Debug, Clone)]
pub struct Negotiated {
    /// The server negotiate response.
    pub response: NegotiateResponse,
    /// Signing mode requested by the client during negotiate.
    pub client_signing_mode: smolder_proto::smb::smb2::SigningMode,
    /// Preauthentication integrity state for SMB 3.1.1, if negotiated.
    pub preauth_integrity: Option<PreauthIntegrityState>,
    /// Receive-side compression state, if negotiated.
    pub compression: Option<Arc<CompressionState>>,
}

/// The transport has an authenticated SMB session.
#[derive(Debug, Clone)]
pub struct Authenticated {
    /// Negotiate details for the connection.
    pub negotiated: NegotiateResponse,
    /// Signing mode requested by the client during negotiate.
    pub client_signing_mode: smolder_proto::smb::smb2::SigningMode,
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
    /// Receive-side compression state, if negotiated.
    pub compression: Option<Arc<CompressionState>>,
}

/// The transport is connected to a tree and can issue file operations.
#[derive(Debug, Clone)]
pub struct TreeConnected {
    /// Negotiate details for the connection.
    pub negotiated: NegotiateResponse,
    /// Signing mode requested by the client during negotiate.
    pub client_signing_mode: smolder_proto::smb::smb2::SigningMode,
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
    /// Receive-side compression state, if negotiated.
    pub compression: Option<Arc<CompressionState>>,
}

/// SMB 3.1.1 preauthentication transcript state.
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct PreauthIntegrityState {
    /// Negotiated preauthentication hash algorithm.
    pub hash_algorithm: PreauthIntegrityHashId,
    /// Rolling preauthentication hash value.
    pub hash_value: Vec<u8>,
}

impl PreauthIntegrityState {
    pub(super) fn new(hash_algorithm: PreauthIntegrityHashId) -> Self {
        Self {
            hash_algorithm,
            hash_value: vec![0; 64],
        }
    }

    pub(super) fn update(&mut self, packet: &[u8]) -> Result<(), CoreError> {
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
pub(super) enum SigningAlgorithm {
    HmacSha256,
    Aes128Cmac,
}

/// Derived signing state for an authenticated SMB session.
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct SigningState {
    pub(super) algorithm: SigningAlgorithm,
    pub(super) key: Vec<u8>,
}

impl SigningState {
    pub(super) fn sign_packet(&self, packet: &mut [u8]) -> Result<(), CoreError> {
        if packet.len() < Header::LEN {
            return Err(CoreError::InvalidInput("packet too short to sign"));
        }

        packet[Header::SIGNATURE_RANGE].fill(0);
        let signature = self.signature_for(packet)?;
        packet[Header::SIGNATURE_RANGE].copy_from_slice(&signature);
        Ok(())
    }

    pub(super) fn verify_packet(&self, packet: &[u8]) -> Result<(), CoreError> {
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
    pub(super) create_request: CreateRequest,
    pub(super) response: CreateResponse,
    pub(super) timeout: u32,
    pub(super) flags: DurableHandleFlags,
    pub(super) create_guid: Option<[u8; 16]>,
    pub(super) resilient_timeout: Option<u32>,
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

    /// Returns the resiliency timeout that should be reapplied after reconnect, if any.
    #[must_use]
    pub fn resilient_timeout(&self) -> Option<u32> {
        self.resilient_timeout
    }

    /// Associates a resiliency timeout with the durable handle for future reconnects.
    #[must_use]
    pub fn with_resilient_timeout(mut self, timeout: u32) -> Self {
        self.resilient_timeout = Some(timeout);
        self
    }

    pub(super) fn with_response(&self, response: CreateResponse) -> Self {
        Self {
            create_request: self.create_request.clone(),
            response,
            timeout: self.timeout,
            flags: self.flags,
            create_guid: self.create_guid,
            resilient_timeout: self.resilient_timeout,
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
pub(super) struct RequestContext {
    pub(super) session_id: SessionId,
    pub(super) tree_id: TreeId,
    pub(super) signing_required: bool,
    pub(super) signing: Option<Arc<SigningState>>,
    pub(super) encryption_required: bool,
    pub(super) encryption: Option<Arc<EncryptionState>>,
    pub(super) compression: Option<Arc<CompressionState>>,
    pub(super) compress_outbound: bool,
}

impl RequestContext {
    pub(super) fn new(
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
            compression: None,
            compress_outbound: false,
        }
    }

    pub(super) fn unsigned(session_id: SessionId, tree_id: TreeId) -> Self {
        Self::new(session_id, tree_id, false, None)
    }

    pub(super) fn with_encryption(
        mut self,
        encryption_required: bool,
        encryption: Option<Arc<EncryptionState>>,
    ) -> Self {
        self.encryption_required = encryption_required;
        self.encryption = encryption;
        self
    }

    pub(super) fn with_compression(mut self, compression: Option<Arc<CompressionState>>) -> Self {
        self.compression = compression;
        self
    }

    pub(super) fn with_outbound_compression(mut self, compress_outbound: bool) -> Self {
        self.compress_outbound = compress_outbound;
        self
    }

    pub(super) fn should_encrypt(&self) -> bool {
        self.encryption_required
    }
}

impl Authenticated {
    pub(super) fn request_context(&self) -> RequestContext {
        RequestContext::new(
            self.session_id,
            TreeId(0),
            self.signing_required,
            self.signing.clone(),
        )
        .with_encryption(self.encryption_required, self.encryption.clone())
        .with_compression(self.compression.clone())
        .with_outbound_compression(true)
    }
}

impl TreeConnected {
    pub(super) fn request_context(&self) -> RequestContext {
        RequestContext::new(
            self.session_id,
            self.tree_id,
            self.signing_required,
            self.signing.clone(),
        )
        .with_encryption(self.encryption_required, self.encryption.clone())
        .with_compression(self.compression.clone())
        .with_outbound_compression(true)
    }

    pub(super) fn session_request_context(&self) -> RequestContext {
        RequestContext::new(
            self.session_id,
            TreeId(0),
            self.signing_required,
            self.signing.clone(),
        )
        .with_encryption(self.encryption_required, self.encryption.clone())
        .with_compression(self.compression.clone())
        .with_outbound_compression(true)
    }
}
