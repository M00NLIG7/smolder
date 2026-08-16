//! Reusable IPC$ and named-pipe primitives built on top of the typestate client.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use rand::random;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use smolder_proto::smb::compression::{CompressionAlgorithm, CompressionCapabilityFlags};
use smolder_proto::smb::smb2::{
    CipherId, CloseRequest, Command, CompressionCapabilities, CreateDisposition, CreateOptions,
    CreateRequest, Dialect, EncryptionCapabilities, FileAttributes, FileId, FlushRequest,
    GlobalCapabilities, NegotiateContext, NegotiateRequest, PreauthIntegrityCapabilities,
    PreauthIntegrityHashId, ReadRequest, ShareAccess, SigningMode, TransportCapabilities,
    TransportCapabilityFlags, TreeConnectRequest, WriteRequest,
};
use smolder_proto::smb::status::NtStatus;

#[cfg(any(feature = "kerberos-sspi", feature = "kerberos-gssapi"))]
use crate::auth::{KerberosAuthenticator, KerberosCredentials, KerberosTarget};
use crate::auth::{NtlmAuthenticator, NtlmCredentials};
use crate::client::{Authenticated, Connection, TreeConnected};
use crate::error::CoreError;
use crate::policy::{OperationTimeouts, ResourceLimits, SecurityPolicy};
#[cfg(feature = "quic")]
use crate::transport::QuicTransport;
use crate::transport::{
    SmbTransport, TokioTcpTransport, TransportIdentity, TransportProtocol, TransportTarget,
};

const FILE_READ_DATA: u32 = 0x0000_0001;
const FILE_WRITE_DATA: u32 = 0x0000_0002;
const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
const READ_CONTROL: u32 = 0x0002_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;

/// SMB session configuration used to authenticate and connect to shares or pipes.
#[derive(Debug, Clone)]
pub struct SmbSessionConfig {
    target: TransportTarget,
    auth: SessionAuth,
    signing_mode: SigningMode,
    capabilities: GlobalCapabilities,
    dialects: Vec<Dialect>,
    client_guid: [u8; 16],
    compression: Option<CompressionCapabilities>,
    security_policy: SecurityPolicy,
    resource_limits: ResourceLimits,
    operation_timeouts: OperationTimeouts,
}

#[derive(Debug, Clone)]
enum SessionAuth {
    Ntlm(NtlmCredentials),
    #[cfg(any(feature = "kerberos-sspi", feature = "kerberos-gssapi"))]
    Kerberos {
        credentials: KerberosCredentials,
        target: KerberosTarget,
    },
}

impl SmbSessionConfig {
    /// Creates a new session configuration with SMB2/3 defaults.
    #[must_use]
    pub fn new(server: impl Into<String>, credentials: NtlmCredentials) -> Self {
        Self {
            target: TransportTarget::tcp(server),
            auth: SessionAuth::Ntlm(credentials),
            signing_mode: SigningMode::ENABLED | SigningMode::REQUIRED,
            capabilities: GlobalCapabilities::LARGE_MTU
                | GlobalCapabilities::LEASING
                | GlobalCapabilities::ENCRYPTION,
            dialects: vec![Dialect::Smb210, Dialect::Smb302, Dialect::Smb311],
            client_guid: random(),
            compression: None,
            security_policy: SecurityPolicy::credentialed(),
            resource_limits: ResourceLimits::default(),
            operation_timeouts: OperationTimeouts::default(),
        }
    }

    /// Creates a Pandora-compatible strict SMB 3.1.1 configuration.
    #[must_use]
    pub fn pandora(server: impl Into<String>, credentials: NtlmCredentials) -> Self {
        Self::new(server, credentials)
            .with_security_policy(SecurityPolicy::pandora())
            .with_dialects(vec![Dialect::Smb311])
            .with_signing_mode(SigningMode::ENABLED | SigningMode::REQUIRED)
    }

    /// Creates a new Kerberos-authenticated session configuration with SMB2/3 defaults.
    #[cfg(any(feature = "kerberos-sspi", feature = "kerberos-gssapi"))]
    #[must_use]
    pub fn kerberos(
        server: impl Into<String>,
        credentials: KerberosCredentials,
        target: KerberosTarget,
    ) -> Self {
        Self {
            target: TransportTarget::tcp(server),
            auth: SessionAuth::Kerberos {
                credentials,
                target,
            },
            signing_mode: SigningMode::ENABLED | SigningMode::REQUIRED,
            capabilities: GlobalCapabilities::LARGE_MTU
                | GlobalCapabilities::LEASING
                | GlobalCapabilities::ENCRYPTION,
            dialects: vec![Dialect::Smb210, Dialect::Smb302, Dialect::Smb311],
            client_guid: random(),
            compression: None,
            security_policy: SecurityPolicy::credentialed(),
            resource_limits: ResourceLimits::default(),
            operation_timeouts: OperationTimeouts::default(),
        }
    }

    /// Overrides the target SMB TCP port.
    #[must_use]
    pub fn with_port(mut self, port: u16) -> Self {
        self.target = self.target.with_port(port);
        self
    }

    /// Overrides the full transport target.
    #[must_use]
    pub fn with_transport_target(mut self, target: TransportTarget) -> Self {
        self.target = target;
        self
    }

    /// Overrides the SMB signing mode sent during negotiate.
    #[must_use]
    pub fn with_signing_mode(mut self, signing_mode: SigningMode) -> Self {
        self.signing_mode = signing_mode;
        self
    }

    /// Overrides the advertised SMB capabilities.
    #[must_use]
    pub fn with_capabilities(mut self, capabilities: GlobalCapabilities) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// Overrides the negotiate dialect list.
    #[must_use]
    pub fn with_dialects(mut self, dialects: Vec<Dialect>) -> Self {
        self.dialects = dialects;
        self
    }

    /// Overrides the client GUID sent during negotiate.
    #[must_use]
    pub fn with_client_guid(mut self, client_guid: [u8; 16]) -> Self {
        self.client_guid = client_guid;
        self
    }

    /// Overrides the advertised SMB compression capabilities.
    #[must_use]
    pub fn with_compression_capabilities(mut self, compression: CompressionCapabilities) -> Self {
        self.compression = Some(compression);
        self
    }

    /// Advertises unchained SMB compression with the provided algorithms.
    #[must_use]
    pub fn with_compression_algorithms(
        mut self,
        compression_algorithms: Vec<CompressionAlgorithm>,
    ) -> Self {
        self.compression = Some(CompressionCapabilities {
            compression_algorithms,
            flags: CompressionCapabilityFlags::empty(),
        });
        self
    }

    /// Replaces the local security policy.
    #[must_use]
    pub fn with_security_policy(mut self, security_policy: SecurityPolicy) -> Self {
        self.security_policy = security_policy;
        self
    }

    /// Replaces explicit limits for remote-controlled sizes and counts.
    #[must_use]
    pub fn with_resource_limits(mut self, resource_limits: ResourceLimits) -> Self {
        self.resource_limits = resource_limits;
        self
    }

    /// Replaces internal connect and request deadlines.
    #[must_use]
    pub fn with_operation_timeouts(mut self, operation_timeouts: OperationTimeouts) -> Self {
        self.operation_timeouts = operation_timeouts;
        self
    }

    /// Returns the logical SMB server name used for auth and share access.
    #[must_use]
    pub fn server(&self) -> &str {
        self.target.server()
    }

    /// Returns the configured dial host or IP address.
    #[must_use]
    pub fn connect_host(&self) -> &str {
        self.target.connect_host()
    }

    /// Returns the configured TLS server name for SMB over QUIC.
    #[must_use]
    pub fn tls_server_name(&self) -> &str {
        self.target.tls_server_name()
    }

    /// Returns the configured SMB TCP port.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.target.port()
    }

    /// Returns the configured transport target.
    #[must_use]
    pub fn transport_target(&self) -> &TransportTarget {
        &self.target
    }

    /// Returns the configured transport protocol.
    #[must_use]
    pub fn transport_protocol(&self) -> TransportProtocol {
        self.target.protocol()
    }

    /// Returns the configured SMB signing mode.
    #[must_use]
    pub fn signing_mode(&self) -> SigningMode {
        self.signing_mode
    }

    /// Returns the configured SMB capabilities.
    #[must_use]
    pub fn capabilities(&self) -> GlobalCapabilities {
        self.capabilities
    }

    /// Returns the configured negotiate dialects.
    #[must_use]
    pub fn dialects(&self) -> &[Dialect] {
        &self.dialects
    }

    /// Returns the configured client GUID.
    #[must_use]
    pub fn client_guid(&self) -> &[u8; 16] {
        &self.client_guid
    }

    /// Returns the configured SMB compression capabilities, if any.
    #[must_use]
    pub fn compression_capabilities(&self) -> Option<&CompressionCapabilities> {
        self.compression.as_ref()
    }

    /// Returns the local security policy.
    #[must_use]
    pub fn security_policy(&self) -> SecurityPolicy {
        self.security_policy
    }

    /// Returns remote-resource limits.
    #[must_use]
    pub fn resource_limits(&self) -> ResourceLimits {
        self.resource_limits
    }

    /// Returns internal operation deadlines.
    #[must_use]
    pub fn operation_timeouts(&self) -> OperationTimeouts {
        self.operation_timeouts
    }
}

/// Access mask preset used when opening a named pipe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeAccess {
    /// Open the pipe for reading only.
    ReadOnly,
    /// Open the pipe for writing only.
    WriteOnly,
    /// Open the pipe for both reading and writing.
    ReadWrite,
}

/// One opened named pipe handle on a tree-connected share, usually `IPC$`.
pub struct NamedPipe<T = TokioTcpTransport> {
    connection: Option<Connection<T, TreeConnected>>,
    file_id: FileId,
    fragment_size: u32,
    read_buffer: Vec<u8>,
    rpc_pdu_buffer: Vec<u8>,
    write_buffer: Vec<u8>,
    pending_read: Option<PendingRead<T>>,
    pending_write: Option<PendingWrite<T>>,
    pending_flush: Option<PendingFlush<T>>,
    eof: bool,
    closed: bool,
}

type PendingRead<T> = Pin<
    Box<
        dyn Future<
                Output = (
                    Connection<T, TreeConnected>,
                    Result<Option<Vec<u8>>, CoreError>,
                ),
            > + Send,
    >,
>;
type PendingWrite<T> = Pin<
    Box<
        dyn Future<
                Output = (
                    Connection<T, TreeConnected>,
                    Vec<u8>,
                    Result<usize, CoreError>,
                ),
            > + Send,
    >,
>;
type PendingFlush<T> =
    Pin<Box<dyn Future<Output = (Connection<T, TreeConnected>, Result<(), CoreError>)> + Send>>;

impl<T> std::fmt::Debug for NamedPipe<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NamedPipe")
            .field("file_id", &self.file_id)
            .field("fragment_size", &self.fragment_size)
            .field("read_buffer_len", &self.read_buffer.len())
            .field("rpc_pdu_buffer_len", &self.rpc_pdu_buffer.len())
            .field("write_buffer_capacity", &self.write_buffer.capacity())
            .field("eof", &self.eof)
            .field("closed", &self.closed)
            .finish()
    }
}

impl<T> Unpin for NamedPipe<T> {}

impl<T> NamedPipe<T> {
    pub(crate) fn invalidate_connection(&mut self) {
        if let Some(connection) = self.connection.as_mut() {
            connection.invalidate();
        }
    }
}

impl NamedPipe<TokioTcpTransport> {
    /// Connects to the target share and opens the named pipe with the requested access mode.
    pub async fn connect(
        config: &SmbSessionConfig,
        share: &str,
        pipe_name: &str,
        access: PipeAccess,
    ) -> Result<Self, CoreError> {
        let transport = TokioTcpTransport::connect_with_timeout(
            (config.transport_target().connect_host(), config.port()),
            config.operation_timeouts.connect,
        )
        .await?
        .with_max_message_size(config.resource_limits.max_transport_message);
        Self::connect_with_transport(transport, config, share, pipe_name, access).await
    }
}

#[cfg(feature = "quic")]
impl NamedPipe<QuicTransport> {
    /// Connects to the target share over QUIC and opens the named pipe with the requested access mode.
    pub async fn connect(
        config: &SmbSessionConfig,
        share: &str,
        pipe_name: &str,
        access: PipeAccess,
    ) -> Result<Self, CoreError> {
        let transport = QuicTransport::connect_with_timeout(
            config.transport_target(),
            config.operation_timeouts.connect,
        )
        .await?
        .with_max_message_size(config.resource_limits.max_transport_message);
        Self::connect_with_transport(transport, config, share, pipe_name, access).await
    }
}

impl<T> NamedPipe<T>
where
    T: SmbTransport + Send,
{
    /// Connects using an already-created transport, tree-connects to the target share,
    /// and opens the requested named pipe.
    pub async fn connect_with_transport(
        transport: T,
        config: &SmbSessionConfig,
        share: &str,
        pipe_name: &str,
        access: PipeAccess,
    ) -> Result<Self, CoreError> {
        let connection = connect_tree_with_transport(transport, config, share).await?;
        Self::open(connection, pipe_name, access).await
    }

    /// Opens a named pipe on an existing tree-connected share.
    pub async fn open(
        mut connection: Connection<T, TreeConnected>,
        pipe_name: &str,
        access: PipeAccess,
    ) -> Result<Self, CoreError> {
        let mut request = CreateRequest::from_path(pipe_name);
        request.desired_access = match access {
            PipeAccess::ReadOnly => {
                FILE_READ_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE
            }
            PipeAccess::WriteOnly => {
                FILE_WRITE_DATA
                    | FILE_READ_ATTRIBUTES
                    | FILE_WRITE_ATTRIBUTES
                    | READ_CONTROL
                    | SYNCHRONIZE
            }
            PipeAccess::ReadWrite => {
                FILE_READ_DATA
                    | FILE_WRITE_DATA
                    | FILE_READ_ATTRIBUTES
                    | FILE_WRITE_ATTRIBUTES
                    | READ_CONTROL
                    | SYNCHRONIZE
            }
        };
        request.create_disposition = CreateDisposition::Open;
        request.share_access = ShareAccess::READ | ShareAccess::WRITE;
        request.file_attributes = FileAttributes::NORMAL;
        request.create_options = CreateOptions::NON_DIRECTORY_FILE;
        let fragment_size = connection
            .state()
            .negotiated
            .max_transact_size
            .min(connection.state().negotiated.max_read_size)
            .min(connection.state().negotiated.max_write_size)
            .min(u32::from(u16::MAX));
        if fragment_size == 0 {
            return Err(CoreError::InvalidResponse(
                "server negotiated a zero-sized named-pipe transfer limit",
            ));
        }
        let capacity = fragment_size as usize;
        let mut read_buffer = Vec::new();
        read_buffer
            .try_reserve_exact(capacity)
            .map_err(|_| CoreError::AllocationFailed("named-pipe read buffer"))?;
        let mut write_buffer = Vec::new();
        write_buffer
            .try_reserve_exact(capacity)
            .map_err(|_| CoreError::AllocationFailed("named-pipe write buffer"))?;
        let response = connection.create(&request).await?;

        Ok(Self {
            connection: Some(connection),
            file_id: response.file_id,
            fragment_size,
            read_buffer,
            rpc_pdu_buffer: Vec::new(),
            write_buffer,
            pending_read: None,
            pending_write: None,
            pending_flush: None,
            eof: false,
            closed: false,
        })
    }

    /// Returns the active SMB file identifier for the pipe handle.
    #[must_use]
    pub fn file_id(&self) -> FileId {
        self.file_id
    }

    /// Returns the negotiated fragment size used for pipe read/write chunking.
    #[must_use]
    pub fn fragment_size(&self) -> u32 {
        self.fragment_size
    }

    /// Returns the remote-resource limits inherited from the physical SMB connection.
    #[must_use]
    pub fn resource_limits(&self) -> ResourceLimits {
        self.connection
            .as_ref()
            .expect("named pipe connection is present outside pending async I/O")
            .resource_limits()
    }

    fn connection_mut(&mut self) -> &mut Connection<T, TreeConnected> {
        self.connection
            .as_mut()
            .expect("named pipe connection should be present while no async I/O is pending")
    }

    fn take_connection(&mut self) -> Connection<T, TreeConnected> {
        self.connection
            .take()
            .expect("named pipe connection should be present while no async I/O is pending")
    }

    fn restore_connection(&mut self, connection: Connection<T, TreeConnected>) {
        assert!(
            self.connection.is_none(),
            "named pipe connection should not already be present",
        );
        self.connection = Some(connection);
    }

    /// Writes the full buffer into the named pipe.
    pub async fn write_all(&mut self, bytes: &[u8]) -> Result<(), CoreError> {
        if self.closed {
            return Err(CoreError::InvalidInput("named pipe is closed"));
        }
        if self.pending_read.is_some()
            || self.pending_write.is_some()
            || self.pending_flush.is_some()
        {
            return Err(CoreError::InvalidInput(
                "cannot write named pipe bytes while async I/O is pending",
            ));
        }

        let mut offset = 0;
        while offset < bytes.len() {
            let chunk_end = (offset + self.fragment_size as usize).min(bytes.len());
            let request =
                WriteRequest::for_file(self.file_id, 0, bytes[offset..chunk_end].to_vec());
            let response = self.connection_mut().write(&request).await?;
            let written = usize::try_from(response.count)
                .map_err(|_| CoreError::InvalidResponse("named pipe write count exceeded usize"))?;
            if written == 0 || written > chunk_end - offset {
                return Err(CoreError::InvalidResponse(
                    "named pipe write returned an invalid byte count",
                ));
            }
            offset += written;
        }
        let file_id = self.file_id;
        if let Err(error) = self
            .connection_mut()
            .flush(&FlushRequest::for_file(file_id))
            .await
        {
            handle_named_pipe_flush_error(error)?;
        }
        Ok(())
    }

    /// Reads one stream chunk from the named pipe. `None` indicates EOF.
    pub async fn read_chunk(&mut self) -> Result<Option<Vec<u8>>, CoreError> {
        if self.closed {
            return Err(CoreError::InvalidInput("named pipe is closed"));
        }
        if self.pending_read.is_some()
            || self.pending_write.is_some()
            || self.pending_flush.is_some()
        {
            return Err(CoreError::InvalidInput(
                "cannot read named pipe bytes while async I/O is pending",
            ));
        }
        if !self.read_buffer.is_empty() {
            return Ok(Some(std::mem::take(&mut self.read_buffer)));
        }
        if self.eof {
            return Ok(None);
        }

        let file_id = self.file_id;
        let fragment_size = self.fragment_size;
        let response = match self
            .connection_mut()
            .read(&ReadRequest::for_file(file_id, 0, fragment_size))
            .await
        {
            Ok(response) => response,
            Err(error) if is_named_pipe_broken_read(&error) => {
                self.eof = true;
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        if response.data.is_empty() {
            self.eof = true;
            return Ok(None);
        }
        Ok(Some(response.data))
    }

    /// Reads one length-delimited DCE/RPC fragment from the pipe.
    ///
    /// Bytes following the fragment remain buffered for the next call, so a single SMB pipe read
    /// may safely carry multiple coalesced RPC PDUs.
    pub async fn read_pdu(&mut self) -> Result<Vec<u8>, CoreError> {
        const RPC_COMMON_HEADER_LEN: usize = 16;

        loop {
            if self.rpc_pdu_buffer.len() >= RPC_COMMON_HEADER_LEN {
                let fragment_len = usize::from(u16::from_le_bytes([
                    self.rpc_pdu_buffer[8],
                    self.rpc_pdu_buffer[9],
                ]));
                if fragment_len < RPC_COMMON_HEADER_LEN {
                    return Err(CoreError::InvalidResponse(
                        "rpc fragment length was shorter than the common header",
                    ));
                }
                let maximum = self
                    .connection
                    .as_ref()
                    .expect("connection is present outside pending async I/O")
                    .resource_limits()
                    .max_rpc_stub_size
                    .saturating_add(RPC_COMMON_HEADER_LEN)
                    .min(usize::from(u16::MAX));
                if fragment_len > maximum {
                    return Err(CoreError::ResourceLimit {
                        resource: "DCE/RPC fragment",
                        requested: fragment_len as u64,
                        maximum: maximum as u64,
                    });
                }
                if self.rpc_pdu_buffer.len() >= fragment_len {
                    let trailing_len = self.rpc_pdu_buffer.len() - fragment_len;
                    let mut trailing = Vec::new();
                    trailing
                        .try_reserve_exact(trailing_len)
                        .map_err(|_| CoreError::AllocationFailed("DCE/RPC trailing PDU buffer"))?;
                    trailing.extend_from_slice(&self.rpc_pdu_buffer[fragment_len..]);
                    self.rpc_pdu_buffer.truncate(fragment_len);
                    return Ok(std::mem::replace(&mut self.rpc_pdu_buffer, trailing));
                }
            }

            let file_id = self.file_id;
            let fragment_size = self.fragment_size;
            let response = self
                .connection_mut()
                .read(&ReadRequest::for_file(file_id, 0, fragment_size))
                .await?;
            if response.data.is_empty() {
                return Err(CoreError::InvalidResponse(
                    "named pipe response ended before rpc fragment was complete",
                ));
            }
            self.rpc_pdu_buffer
                .try_reserve(response.data.len())
                .map_err(|_| CoreError::AllocationFailed("DCE/RPC receive buffer"))?;
            self.rpc_pdu_buffer.extend_from_slice(&response.data);
        }
    }

    /// Writes one request PDU and then reads one response PDU.
    pub async fn call(&mut self, request: Vec<u8>) -> Result<Vec<u8>, CoreError> {
        self.write_all(&request).await?;
        self.read_pdu().await
    }

    /// Reads the next newline-terminated UTF-8 control line from the pipe.
    pub async fn read_line(&mut self, buffer: &mut Vec<u8>) -> Result<Option<String>, CoreError> {
        let maximum = self.resource_limits().max_control_line_size;
        loop {
            if let Some(newline_index) = buffer.iter().position(|byte| *byte == b'\n') {
                let line_len = newline_index + 1;
                if line_len > maximum {
                    return Err(CoreError::ResourceLimit {
                        resource: "named-pipe control line",
                        requested: line_len as u64,
                        maximum: maximum as u64,
                    });
                }
                let line = std::str::from_utf8(&buffer[..line_len]).map_err(|_| {
                    CoreError::InvalidResponse("named-pipe control line was not valid UTF-8")
                })?;
                let line = line.trim();
                let mut text = String::new();
                text.try_reserve_exact(line.len())
                    .map_err(|_| CoreError::AllocationFailed("named-pipe control line"))?;
                text.push_str(line);
                buffer.drain(..line_len);
                return Ok(Some(text));
            }
            if buffer.len() > maximum {
                return Err(CoreError::ResourceLimit {
                    resource: "named-pipe control line",
                    requested: buffer.len() as u64,
                    maximum: maximum as u64,
                });
            }

            match self.read_chunk().await? {
                Some(bytes) => {
                    let next_line_bytes = bytes
                        .iter()
                        .position(|byte| *byte == b'\n')
                        .map_or(bytes.len(), |index| index + 1);
                    let prospective_line_len = buffer.len().checked_add(next_line_bytes).ok_or(
                        CoreError::ResourceLimit {
                            resource: "named-pipe control line",
                            requested: u64::MAX,
                            maximum: maximum as u64,
                        },
                    )?;
                    if prospective_line_len > maximum {
                        return Err(CoreError::ResourceLimit {
                            resource: "named-pipe control line",
                            requested: prospective_line_len as u64,
                            maximum: maximum as u64,
                        });
                    }
                    buffer
                        .try_reserve(bytes.len())
                        .map_err(|_| CoreError::AllocationFailed("named-pipe control line"))?;
                    buffer.extend_from_slice(&bytes);
                }
                None if buffer.is_empty() => return Ok(None),
                None => {
                    return Err(CoreError::InvalidResponse(
                        "interactive control pipe closed with a truncated line",
                    ));
                }
            }
        }
    }

    /// Closes the pipe handle and returns the underlying connection.
    pub async fn close(mut self) -> Result<Connection<T, TreeConnected>, CoreError> {
        if self.pending_read.is_some()
            || self.pending_write.is_some()
            || self.pending_flush.is_some()
        {
            return Err(CoreError::InvalidInput(
                "cannot close named pipe while async I/O is pending",
            ));
        }
        if self.closed {
            return Err(CoreError::InvalidInput("named pipe is already closed"));
        }

        self.closed = true;
        let file_id = self.file_id;
        let _ = self
            .connection_mut()
            .close(&CloseRequest { flags: 0, file_id })
            .await?;
        Ok(self.take_connection())
    }

    fn complete_pending_read(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), CoreError>> {
        let Some(future) = self.pending_read.as_mut() else {
            return Poll::Ready(Ok(()));
        };

        match future.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready((connection, result)) => {
                self.pending_read = None;
                self.restore_connection(connection);
                match result? {
                    Some(bytes) => {
                        if self.read_buffer.try_reserve(bytes.len()).is_err() {
                            return Poll::Ready(Err(CoreError::AllocationFailed(
                                "named-pipe async read buffer",
                            )));
                        }
                        self.read_buffer.extend_from_slice(&bytes);
                    }
                    None => self.eof = true,
                }
                Poll::Ready(Ok(()))
            }
        }
    }

    fn complete_pending_write(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<usize>, CoreError>> {
        let Some(future) = self.pending_write.as_mut() else {
            return Poll::Ready(Ok(None));
        };

        match future.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready((connection, mut buffer, result)) => {
                self.pending_write = None;
                self.restore_connection(connection);
                buffer.clear();
                self.write_buffer = buffer;
                Poll::Ready(result.map(Some))
            }
        }
    }

    fn complete_pending_flush(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), CoreError>> {
        let Some(future) = self.pending_flush.as_mut() else {
            return Poll::Ready(Ok(()));
        };

        match future.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready((connection, result)) => {
                self.pending_flush = None;
                self.restore_connection(connection);
                Poll::Ready(result)
            }
        }
    }
}

fn core_error_to_io(error: CoreError) -> io::Error {
    match error {
        CoreError::Io(error) | CoreError::LocalIo(error) => error,
        other => io::Error::other(other),
    }
}

fn handle_named_pipe_flush_error(error: CoreError) -> Result<(), CoreError> {
    match error {
        CoreError::UnexpectedStatus { command, status }
            if command == Command::Flush
                && (status == NtStatus::NOT_IMPLEMENTED.to_u32()
                    || status == NtStatus::PIPE_BROKEN.to_u32()) =>
        {
            Ok(())
        }
        other => Err(other),
    }
}

fn is_named_pipe_broken_read(error: &CoreError) -> bool {
    matches!(
        error,
        CoreError::UnexpectedStatus { command, status }
            if *command == Command::Read && *status == NtStatus::PIPE_BROKEN.to_u32()
    )
}

impl<T> AsyncRead for NamedPipe<T>
where
    T: SmbTransport + Send + 'static,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "named pipe is closed",
            )));
        }
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.pending_write.is_some() || this.pending_flush.is_some() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "named pipe has a pending write or flush operation",
            )));
        }

        loop {
            match this.complete_pending_read(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(core_error_to_io(error))),
                Poll::Ready(Ok(())) => {}
            }

            if !this.read_buffer.is_empty() {
                let to_copy = buf.remaining().min(this.read_buffer.len());
                buf.put_slice(&this.read_buffer[..to_copy]);
                this.read_buffer.drain(..to_copy);
                return Poll::Ready(Ok(()));
            }

            if this.eof {
                return Poll::Ready(Ok(()));
            }

            let mut connection = this.take_connection();
            let file_id = this.file_id;
            let fragment_size = this.fragment_size;
            this.pending_read = Some(Box::pin(async move {
                let result = connection
                    .read(&ReadRequest::for_file(file_id, 0, fragment_size))
                    .await
                    .map(|response| {
                        if response.data.is_empty() {
                            None
                        } else {
                            Some(response.data)
                        }
                    })
                    .or_else(|error| {
                        if is_named_pipe_broken_read(&error) {
                            Ok(None)
                        } else {
                            Err(error)
                        }
                    });
                (connection, result)
            }));
        }
    }
}

impl<T> AsyncWrite for NamedPipe<T>
where
    T: SmbTransport + Send + 'static,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "named pipe is closed",
            )));
        }
        if this.pending_read.is_some() || this.pending_flush.is_some() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "named pipe has a pending read or flush operation",
            )));
        }

        match this.complete_pending_write(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(core_error_to_io(error))),
            Poll::Ready(Ok(Some(written))) => return Poll::Ready(Ok(written)),
            Poll::Ready(Ok(None)) => {}
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let requested = buf.len().min(this.fragment_size as usize);
        let mut staged = std::mem::take(&mut this.write_buffer);
        staged.clear();
        staged.extend_from_slice(&buf[..requested]);
        let mut connection = this.take_connection();
        let file_id = this.file_id;
        this.pending_write = Some(Box::pin(async move {
            let request_buffer = staged;
            let request = WriteRequest::for_file(file_id, 0, request_buffer.clone());
            let result = connection.write(&request).await.and_then(|response| {
                let written = usize::try_from(response.count).map_err(|_| {
                    CoreError::InvalidResponse("named pipe write count exceeded usize")
                })?;
                if written == 0 || written > request_buffer.len() {
                    Err(CoreError::InvalidResponse(
                        "named pipe write returned an invalid byte count",
                    ))
                } else {
                    Ok(written)
                }
            });
            (connection, request_buffer, result)
        }));
        match this.complete_pending_write(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(core_error_to_io(error))),
            Poll::Ready(Ok(Some(written))) => Poll::Ready(Ok(written)),
            Poll::Ready(Ok(None)) => Poll::Ready(Ok(0)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "named pipe is closed",
            )));
        }
        if this.pending_read.is_some() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "named pipe has a pending read operation",
            )));
        }

        match this.complete_pending_write(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(core_error_to_io(error))),
            Poll::Ready(Ok(_)) => {}
        }

        if this.pending_flush.is_none() {
            let mut connection = this.take_connection();
            let file_id = this.file_id;
            this.pending_flush = Some(Box::pin(async move {
                let result = connection
                    .flush(&FlushRequest::for_file(file_id))
                    .await
                    .map(|_| ());
                (connection, result)
            }));
        }

        match this.complete_pending_flush(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => match handle_named_pipe_flush_error(error) {
                Ok(()) => Poll::Ready(Ok(())),
                Err(error) => Poll::Ready(Err(core_error_to_io(error))),
            },
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

/// Authenticates and tree-connects to the requested share.
pub async fn connect_session(
    config: &SmbSessionConfig,
) -> Result<Connection<TokioTcpTransport, Authenticated>, CoreError> {
    match config.transport_protocol() {
        TransportProtocol::Tcp => {
            let transport = TokioTcpTransport::connect_with_timeout(
                (config.transport_target().connect_host(), config.port()),
                config.operation_timeouts.connect,
            )
            .await?
            .with_max_message_size(config.resource_limits.max_transport_message);
            connect_session_with_transport(transport, config).await
        }
        TransportProtocol::Netbios => {
            let transport = TokioTcpTransport::connect_netbios_with_timeout(
                config.transport_target(),
                config.operation_timeouts.connect,
            )
            .await?
            .with_max_message_size(config.resource_limits.max_transport_message);
            connect_session_with_transport(transport, config).await
        }
        TransportProtocol::Quic => Err(CoreError::Unsupported(
            "SMB over QUIC requires connect_session_quic",
        )),
    }
}

/// Authenticates a session over SMB over QUIC.
#[cfg(feature = "quic")]
pub async fn connect_session_quic(
    config: &SmbSessionConfig,
) -> Result<Connection<QuicTransport, Authenticated>, CoreError> {
    let transport = QuicTransport::connect_with_timeout(
        config.transport_target(),
        config.operation_timeouts.connect,
    )
    .await?
    .with_max_message_size(config.resource_limits.max_transport_message);
    connect_session_with_transport(transport, config).await
}

/// Authenticates a session over an already-created transport.
pub async fn connect_session_with_transport<T>(
    transport: T,
    config: &SmbSessionConfig,
) -> Result<Connection<T, Authenticated>, CoreError>
where
    T: SmbTransport + Send,
{
    let transport_identity = transport.transport_identity();
    if let Some(actual_protocol) = transport_identity.protocol() {
        if actual_protocol != config.transport_protocol() {
            return Err(CoreError::InvalidInput(
                "configured transport protocol did not match the physical transport identity",
            ));
        }
    }
    let request = NegotiateRequest {
        security_mode: config.signing_mode,
        capabilities: config.capabilities,
        client_guid: config.client_guid,
        negotiate_contexts: default_negotiate_contexts(
            &config.dialects,
            config.capabilities,
            config.compression.as_ref(),
            transport_identity,
        ),
        dialects: config.dialects.clone(),
    };
    let connection = Connection::new(transport)
        .with_security_policy(config.security_policy)
        .with_resource_limits(config.resource_limits)
        .with_operation_timeouts(config.operation_timeouts)
        .negotiate(&request)
        .await?;
    match config.auth.clone() {
        SessionAuth::Ntlm(credentials) => {
            let mut auth = NtlmAuthenticator::new(credentials);
            connection.authenticate(&mut auth).await
        }
        #[cfg(any(feature = "kerberos-sspi", feature = "kerberos-gssapi"))]
        SessionAuth::Kerberos {
            credentials,
            target,
        } => {
            let mut auth = KerberosAuthenticator::new(credentials, target);
            connection.authenticate(&mut auth).await
        }
    }
}

/// Authenticates and tree-connects to the requested share.
pub async fn connect_tree(
    config: &SmbSessionConfig,
    share: &str,
) -> Result<Connection<TokioTcpTransport, TreeConnected>, CoreError> {
    match config.transport_protocol() {
        TransportProtocol::Tcp => {
            let transport = TokioTcpTransport::connect_with_timeout(
                (config.transport_target().connect_host(), config.port()),
                config.operation_timeouts.connect,
            )
            .await?
            .with_max_message_size(config.resource_limits.max_transport_message);
            connect_tree_with_transport(transport, config, share).await
        }
        TransportProtocol::Netbios => {
            let transport = TokioTcpTransport::connect_netbios_with_timeout(
                config.transport_target(),
                config.operation_timeouts.connect,
            )
            .await?
            .with_max_message_size(config.resource_limits.max_transport_message);
            connect_tree_with_transport(transport, config, share).await
        }
        TransportProtocol::Quic => Err(CoreError::Unsupported(
            "SMB over QUIC requires connect_tree_quic",
        )),
    }
}

/// Authenticates and tree-connects to the requested share over SMB over QUIC.
#[cfg(feature = "quic")]
pub async fn connect_tree_quic(
    config: &SmbSessionConfig,
    share: &str,
) -> Result<Connection<QuicTransport, TreeConnected>, CoreError> {
    let transport = QuicTransport::connect_with_timeout(
        config.transport_target(),
        config.operation_timeouts.connect,
    )
    .await?
    .with_max_message_size(config.resource_limits.max_transport_message);
    connect_tree_with_transport(transport, config, share).await
}

/// Authenticates and tree-connects to the requested share over an already-created transport.
pub async fn connect_tree_with_transport<T>(
    transport: T,
    config: &SmbSessionConfig,
    share: &str,
) -> Result<Connection<T, TreeConnected>, CoreError>
where
    T: SmbTransport + Send,
{
    let connection = connect_session_with_transport(transport, config).await?;
    let unc = format!(r"\\{}\{}", config.server(), normalize_share_name(share)?);
    connection
        .tree_connect(&TreeConnectRequest::from_unc(&unc))
        .await
}

fn default_negotiate_contexts(
    dialects: &[Dialect],
    capabilities: GlobalCapabilities,
    compression: Option<&CompressionCapabilities>,
    transport_identity: TransportIdentity,
) -> Vec<NegotiateContext> {
    if !dialects.contains(&Dialect::Smb311) {
        return Vec::new();
    }

    let mut contexts = vec![NegotiateContext::preauth_integrity(
        PreauthIntegrityCapabilities {
            hash_algorithms: vec![PreauthIntegrityHashId::Sha512],
            salt: random::<[u8; 32]>().to_vec(),
        },
    )];
    if capabilities.contains(GlobalCapabilities::ENCRYPTION) {
        contexts.push(NegotiateContext::encryption_capabilities(
            EncryptionCapabilities {
                ciphers: vec![CipherId::Aes128Gcm, CipherId::Aes128Ccm],
            },
        ));
    }
    if let Some(compression) = compression {
        contexts.push(NegotiateContext::compression_capabilities(
            compression.clone(),
        ));
    }
    if transport_identity.is_authenticated_quic() {
        contexts.push(NegotiateContext::transport_capabilities(
            TransportCapabilities {
                flags: TransportCapabilityFlags::ACCEPT_TRANSPORT_LEVEL_SECURITY,
            },
        ));
    }
    contexts
}

fn normalize_share_name(share: &str) -> Result<String, CoreError> {
    let share = share.trim_matches(['\\', '/']);
    if share.is_empty() {
        return Err(CoreError::PathInvalid("share name must not be empty"));
    }
    if share.contains(['\\', '/', '\0']) {
        return Err(CoreError::PathInvalid(
            "share name must not contain separators or NUL bytes",
        ));
    }
    Ok(share.to_string())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use async_trait::async_trait;
    use smolder_proto::smb::compression::{CompressionAlgorithm, CompressionCapabilityFlags};
    use smolder_proto::smb::netbios::SessionMessage;
    use smolder_proto::smb::smb2::{
        CipherId, CloseResponse, Command, CreateResponse, Dialect, FileAttributes, FileId,
        FlushResponse, GlobalCapabilities, Header, MessageId, NegotiateRequest, NegotiateResponse,
        OplockLevel, ReadResponse, ReadResponseFlags, SessionFlags, SessionSetupRequest,
        SessionSetupResponse, SessionSetupSecurityMode, ShareFlags, ShareType, SigningMode,
        TransportCapabilityFlags, TreeCapabilities, TreeConnectRequest, TreeConnectResponse,
        TreeId, WriteRequest, WriteResponse,
    };
    use smolder_proto::smb::status::NtStatus;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::auth::{AuthError, AuthProvider, NtlmCredentials};
    #[cfg(any(feature = "kerberos-sspi", feature = "kerberos-gssapi"))]
    use crate::auth::{KerberosCredentials, KerberosTarget};
    use crate::client::{Connection, TreeConnected};
    use crate::error::CoreError;
    use crate::transport::{Transport, TransportIdentity, TransportProtocol, TransportTarget};

    use super::{NamedPipe, PipeAccess, SmbSessionConfig};

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

    #[test]
    fn smb_session_config_defaults_enable_encryption() {
        let config = SmbSessionConfig::new("server", NtlmCredentials::new("user", "pass"));
        assert!(config.capabilities.contains(GlobalCapabilities::ENCRYPTION));

        let contexts = super::default_negotiate_contexts(
            &config.dialects,
            config.capabilities,
            None,
            TransportIdentity::unauthenticated(config.transport_protocol()),
        );
        assert_eq!(contexts.len(), 2);
        assert!(contexts[0]
            .as_preauth_integrity()
            .expect("preauth context should decode")
            .is_some());

        let encryption = contexts[1]
            .as_encryption_capabilities()
            .expect("encryption context should decode")
            .expect("encryption context should be present");
        assert_eq!(
            encryption.ciphers,
            vec![CipherId::Aes128Gcm, CipherId::Aes128Ccm]
        );
    }

    #[test]
    fn smb_session_config_can_enable_compression() {
        let config = SmbSessionConfig::new("server", NtlmCredentials::new("user", "pass"))
            .with_compression_algorithms(vec![
                CompressionAlgorithm::Lz77,
                CompressionAlgorithm::Lznt1,
            ]);

        let contexts = super::default_negotiate_contexts(
            &config.dialects,
            config.capabilities,
            config.compression_capabilities(),
            TransportIdentity::unauthenticated(config.transport_protocol()),
        );
        let compression = contexts[2]
            .as_compression_capabilities()
            .expect("compression context should decode")
            .expect("compression context should be present");
        assert_eq!(
            compression.compression_algorithms,
            vec![CompressionAlgorithm::Lz77, CompressionAlgorithm::Lznt1]
        );
        assert_eq!(compression.flags, CompressionCapabilityFlags::empty());
    }

    #[test]
    fn smb_session_config_can_override_transport_target() {
        let config = SmbSessionConfig::new("server", NtlmCredentials::new("user", "pass"))
            .with_transport_target(
                TransportTarget::quic("edge.lab.example")
                    .with_connect_host("127.0.0.1")
                    .with_tls_server_name("gateway.lab.example")
                    .with_port(8443),
            );

        assert_eq!(config.server(), "edge.lab.example");
        assert_eq!(config.connect_host(), "127.0.0.1");
        assert_eq!(config.tls_server_name(), "gateway.lab.example");
        assert_eq!(config.port(), 8443);
        assert_eq!(config.transport_protocol(), TransportProtocol::Quic);
        assert_eq!(
            config.transport_target(),
            &TransportTarget::quic("edge.lab.example")
                .with_connect_host("127.0.0.1")
                .with_tls_server_name("gateway.lab.example")
                .with_port(8443)
        );
    }

    #[test]
    fn smb_session_config_can_use_netbios_transport_target() {
        let config = SmbSessionConfig::new("server", NtlmCredentials::new("user", "pass"))
            .with_transport_target(
                TransportTarget::netbios("files.lab.example")
                    .with_connect_host("127.0.0.1")
                    .with_port(1139),
            );

        assert_eq!(config.server(), "files.lab.example");
        assert_eq!(config.connect_host(), "127.0.0.1");
        assert_eq!(config.port(), 1139);
        assert_eq!(config.transport_protocol(), TransportProtocol::Netbios);
        assert_eq!(
            config.transport_target(),
            &TransportTarget::netbios("files.lab.example")
                .with_connect_host("127.0.0.1")
                .with_port(1139)
        );
    }

    #[test]
    fn quic_target_adds_transport_capabilities_context() {
        let config = SmbSessionConfig::new("server", NtlmCredentials::new("user", "pass"))
            .with_transport_target(TransportTarget::quic("server"));

        let contexts = super::default_negotiate_contexts(
            &config.dialects,
            config.capabilities,
            config.compression_capabilities(),
            TransportIdentity::authenticated_quic(),
        );

        let transport = contexts
            .iter()
            .find_map(|context| {
                context
                    .as_transport_capabilities()
                    .expect("transport context should decode cleanly")
            })
            .expect("quic target should add transport capabilities");
        assert_eq!(
            transport.flags,
            TransportCapabilityFlags::ACCEPT_TRANSPORT_LEVEL_SECURITY
        );
    }

    #[test]
    fn netbios_target_does_not_add_transport_capabilities_context() {
        let config = SmbSessionConfig::new("server", NtlmCredentials::new("user", "pass"))
            .with_transport_target(TransportTarget::netbios("server"));

        let contexts = super::default_negotiate_contexts(
            &config.dialects,
            config.capabilities,
            config.compression_capabilities(),
            TransportIdentity::unauthenticated(config.transport_protocol()),
        );

        assert!(contexts.iter().all(|context| {
            context
                .as_transport_capabilities()
                .expect("transport context should decode cleanly")
                .is_none()
        }));
    }

    #[tokio::test]
    async fn connect_session_rejects_quic_without_explicit_quic_entrypoint() {
        let config = SmbSessionConfig::new("server", NtlmCredentials::new("user", "pass"))
            .with_transport_target(TransportTarget::quic("server"));

        let error = super::connect_session(&config)
            .await
            .expect_err("tcp-only helper should reject quic targets");
        assert!(matches!(
            error,
            CoreError::Unsupported("SMB over QUIC requires connect_session_quic")
        ));
    }

    #[cfg(any(feature = "kerberos-sspi", feature = "kerberos-gssapi"))]
    fn test_kerberos_credentials() -> KerberosCredentials {
        #[cfg(feature = "kerberos-sspi")]
        {
            KerberosCredentials::new("user@LAB.EXAMPLE", "pass")
        }

        #[cfg(all(not(feature = "kerberos-sspi"), unix, feature = "kerberos-gssapi"))]
        {
            KerberosCredentials::from_ticket_cache("user@LAB.EXAMPLE")
        }
    }

    #[cfg(any(feature = "kerberos-sspi", feature = "kerberos-gssapi"))]
    #[test]
    fn kerberos_smb_session_config_stores_kerberos_auth() {
        let config = SmbSessionConfig::kerberos(
            "server",
            test_kerberos_credentials(),
            KerberosTarget::for_smb_host("server.lab.example"),
        );

        assert!(matches!(config.auth, super::SessionAuth::Kerberos { .. }));
        assert!(config.capabilities.contains(GlobalCapabilities::ENCRYPTION));
    }

    struct PassthroughAuthProvider(Vec<u8>);

    impl AuthProvider for PassthroughAuthProvider {
        fn initial_token(&mut self, _negotiate: &NegotiateResponse) -> Result<Vec<u8>, AuthError> {
            Ok(self.0.clone())
        }

        fn next_token(&mut self, _incoming: &[u8]) -> Result<Vec<u8>, AuthError> {
            Err(AuthError::InvalidState(
                "passthrough test provider does not support challenge tokens",
            ))
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
        let mut header = Header::new(command, MessageId(message_id));
        header.flags |= smolder_proto::smb::smb2::HeaderFlags::SERVER_TO_REDIR;
        header.status = status;
        header.session_id = smolder_proto::smb::smb2::SessionId(session_id);
        header.tree_id = TreeId(tree_id);

        let mut packet = header.encode();
        packet.extend_from_slice(&body);
        SessionMessage::new(packet)
            .encode()
            .expect("response should frame")
    }

    fn outbound_write(frame: &[u8]) -> WriteRequest {
        let frame = SessionMessage::decode(frame).expect("frame should decode");
        WriteRequest::decode(&frame.payload[Header::LEN..]).expect("write request should decode")
    }

    #[tokio::test]
    async fn named_pipe_calls_round_trip_one_pdu() {
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
        let rpc_response = vec![
            0x05, 0x00, 0x02, 0x03, 0x10, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let close_response = CloseResponse {
            flags: 0,
            allocation_size: 0,
            end_of_file: 0,
            file_attributes: FileAttributes::NORMAL,
        };

        let reads = vec![
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
                WriteResponse {
                    count: rpc_response.len() as u32,
                }
                .encode(),
            ),
            response_frame(
                Command::Flush,
                NtStatus::SUCCESS.to_u32(),
                5,
                11,
                7,
                FlushResponse.encode(),
            ),
            response_frame(
                Command::Read,
                NtStatus::SUCCESS.to_u32(),
                6,
                11,
                7,
                ReadResponse {
                    data_remaining: 0,
                    flags: ReadResponseFlags::empty(),
                    data: rpc_response.clone(),
                }
                .encode(),
            ),
            response_frame(
                Command::Close,
                NtStatus::SUCCESS.to_u32(),
                7,
                11,
                7,
                close_response.encode(),
            ),
        ];

        let connection = build_tree_connection(reads).await;
        let mut pipe = NamedPipe::open(connection, "svcctl", PipeAccess::ReadWrite)
            .await
            .expect("pipe open should succeed");
        let response = pipe
            .call(rpc_response.clone())
            .await
            .expect("pipe call should succeed");
        assert_eq!(response, rpc_response);

        let connection = pipe.close().await.expect("pipe close should succeed");
        assert_eq!(connection.state().tree_id, TreeId(7));
    }

    #[tokio::test]
    async fn named_pipe_reads_control_lines() {
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

        let reads = vec![
            response_frame(
                Command::Create,
                NtStatus::SUCCESS.to_u32(),
                3,
                11,
                7,
                create_response.encode(),
            ),
            response_frame(
                Command::Read,
                NtStatus::SUCCESS.to_u32(),
                4,
                11,
                7,
                ReadResponse {
                    data_remaining: 0,
                    flags: ReadResponseFlags::empty(),
                    data: b"READY".to_vec(),
                }
                .encode(),
            ),
            response_frame(
                Command::Read,
                NtStatus::SUCCESS.to_u32(),
                5,
                11,
                7,
                ReadResponse {
                    data_remaining: 0,
                    flags: ReadResponseFlags::empty(),
                    data: b" 42\n".to_vec(),
                }
                .encode(),
            ),
        ];

        let connection = build_tree_connection(reads).await;
        let mut pipe = NamedPipe::open(connection, "smolder-control", PipeAccess::ReadOnly)
            .await
            .expect("pipe open should succeed");
        let mut buffer = Vec::new();

        let line = pipe
            .read_line(&mut buffer)
            .await
            .expect("line read should succeed")
            .expect("line should be present");
        assert_eq!(line, "READY 42");
    }

    #[tokio::test]
    async fn named_pipe_supports_async_read_trait() {
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

        let reads = vec![
            response_frame(
                Command::Create,
                NtStatus::SUCCESS.to_u32(),
                3,
                11,
                7,
                create_response.encode(),
            ),
            response_frame(
                Command::Read,
                NtStatus::SUCCESS.to_u32(),
                4,
                11,
                7,
                ReadResponse {
                    data_remaining: 0,
                    flags: ReadResponseFlags::empty(),
                    data: b"hello ".to_vec(),
                }
                .encode(),
            ),
            response_frame(
                Command::Read,
                NtStatus::SUCCESS.to_u32(),
                5,
                11,
                7,
                ReadResponse {
                    data_remaining: 0,
                    flags: ReadResponseFlags::empty(),
                    data: b"pipe".to_vec(),
                }
                .encode(),
            ),
            response_frame(
                Command::Read,
                NtStatus::SUCCESS.to_u32(),
                6,
                11,
                7,
                ReadResponse {
                    data_remaining: 0,
                    flags: ReadResponseFlags::empty(),
                    data: Vec::new(),
                }
                .encode(),
            ),
        ];

        let connection = build_tree_connection(reads).await;
        let mut pipe = NamedPipe::open(connection, "svcctl", PipeAccess::ReadOnly)
            .await
            .expect("pipe open should succeed");
        let mut bytes = Vec::new();
        pipe.read_to_end(&mut bytes)
            .await
            .expect("async read should succeed");

        assert_eq!(bytes, b"hello pipe");
    }

    #[tokio::test]
    async fn named_pipe_supports_async_write_trait() {
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
        let close_response = CloseResponse {
            flags: 0,
            allocation_size: 0,
            end_of_file: 0,
            file_attributes: FileAttributes::NORMAL,
        };

        let reads = vec![
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
                WriteResponse { count: 11 }.encode(),
            ),
            response_frame(
                Command::Flush,
                NtStatus::SUCCESS.to_u32(),
                5,
                11,
                7,
                FlushResponse.encode(),
            ),
            response_frame(
                Command::Close,
                NtStatus::SUCCESS.to_u32(),
                6,
                11,
                7,
                close_response.encode(),
            ),
        ];

        let connection = build_tree_connection(reads).await;
        let mut pipe = NamedPipe::open(connection, "svcctl", PipeAccess::WriteOnly)
            .await
            .expect("pipe open should succeed");
        AsyncWriteExt::write_all(&mut pipe, b"hello world")
            .await
            .expect("async write should succeed");
        AsyncWriteExt::flush(&mut pipe)
            .await
            .expect("flush should succeed");

        let connection = pipe.close().await.expect("pipe close should succeed");
        let writes = connection.into_transport().writes;
        let write = outbound_write(&writes[4]);

        assert_eq!(write.data, b"hello world");
    }

    #[tokio::test]
    async fn named_pipe_async_flush_ignores_not_implemented_status() {
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
        let close_response = CloseResponse {
            flags: 0,
            allocation_size: 0,
            end_of_file: 0,
            file_attributes: FileAttributes::NORMAL,
        };

        let reads = vec![
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
                WriteResponse { count: 11 }.encode(),
            ),
            response_frame(
                Command::Flush,
                NtStatus::NOT_IMPLEMENTED.to_u32(),
                5,
                11,
                7,
                FlushResponse.encode(),
            ),
            response_frame(
                Command::Close,
                NtStatus::SUCCESS.to_u32(),
                6,
                11,
                7,
                close_response.encode(),
            ),
        ];

        let connection = build_tree_connection(reads).await;
        let mut pipe = NamedPipe::open(connection, "svcctl", PipeAccess::WriteOnly)
            .await
            .expect("pipe open should succeed");
        AsyncWriteExt::write_all(&mut pipe, b"hello world")
            .await
            .expect("async write should succeed");
        AsyncWriteExt::flush(&mut pipe)
            .await
            .expect("flush should ignore not-implemented status on named pipes");

        let connection = pipe.close().await.expect("pipe close should succeed");
        let writes = connection.into_transport().writes;
        let write = outbound_write(&writes[4]);

        assert_eq!(write.data, b"hello world");
    }

    #[tokio::test]
    async fn named_pipe_async_flush_ignores_broken_pipe_status() {
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
        let close_response = CloseResponse {
            flags: 0,
            allocation_size: 0,
            end_of_file: 0,
            file_attributes: FileAttributes::NORMAL,
        };

        let reads = vec![
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
                WriteResponse { count: 11 }.encode(),
            ),
            response_frame(
                Command::Flush,
                NtStatus::PIPE_BROKEN.to_u32(),
                5,
                11,
                7,
                FlushResponse.encode(),
            ),
            response_frame(
                Command::Close,
                NtStatus::SUCCESS.to_u32(),
                6,
                11,
                7,
                close_response.encode(),
            ),
        ];

        let connection = build_tree_connection(reads).await;
        let mut pipe = NamedPipe::open(connection, "svcctl", PipeAccess::WriteOnly)
            .await
            .expect("pipe open should succeed");
        AsyncWriteExt::write_all(&mut pipe, b"hello world")
            .await
            .expect("async write should succeed");
        AsyncWriteExt::flush(&mut pipe)
            .await
            .expect("flush should ignore broken-pipe status on named pipes");

        let connection = pipe.close().await.expect("pipe close should succeed");
        let writes = connection.into_transport().writes;
        let write = outbound_write(&writes[4]);

        assert_eq!(write.data, b"hello world");
    }

    #[tokio::test]
    async fn named_pipe_read_chunk_treats_broken_pipe_as_eof() {
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
        let close_response = CloseResponse {
            flags: 0,
            allocation_size: 0,
            end_of_file: 0,
            file_attributes: FileAttributes::NORMAL,
        };

        let reads = vec![
            response_frame(
                Command::Create,
                NtStatus::SUCCESS.to_u32(),
                3,
                11,
                7,
                create_response.encode(),
            ),
            response_frame(
                Command::Read,
                NtStatus::PIPE_BROKEN.to_u32(),
                4,
                11,
                7,
                Vec::new(),
            ),
            response_frame(
                Command::Close,
                NtStatus::SUCCESS.to_u32(),
                5,
                11,
                7,
                close_response.encode(),
            ),
        ];

        let connection = build_tree_connection(reads).await;
        let mut pipe = NamedPipe::open(connection, "svcctl", PipeAccess::ReadOnly)
            .await
            .expect("pipe open should succeed");

        let chunk = pipe
            .read_chunk()
            .await
            .expect("broken pipe status should map to eof");
        assert_eq!(chunk, None);

        pipe.close().await.expect("pipe close should succeed");
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
            .authenticate(&mut PassthroughAuthProvider(
                session_request.security_buffer.clone(),
            ))
            .await
            .expect("session setup should succeed");
        connection
            .tree_connect(&TreeConnectRequest::from_unc(r"\\server\IPC$"))
            .await
            .expect("tree connect should succeed")
    }
}
