//! High-level embedded client facade built on top of the typestate SMB client.
//!
//! This module is the intended additive entry point for users who want a
//! friendlier `connect -> authenticate -> tree connect -> file workflow` path
//! without dropping directly into raw typestate orchestration.

use rand::random;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use smolder_proto::rpc::SyntaxId;
use smolder_proto::smb::compression::{CompressionAlgorithm, CompressionCapabilityFlags};
use smolder_proto::smb::smb2::{
    CloseRequest, CompressionCapabilities, CreateDisposition, CreateOptions, CreateRequest,
    Dialect, DispositionInformation, EchoResponse, FileAttributes, FileBasicInformation, FileId,
    FileInfoClass, FileStandardInformation, FlushRequest, GlobalCapabilities, QueryInfoRequest,
    ReadRequest, SessionId, SetInfoRequest, ShareAccess, SigningMode, TreeConnectRequest, TreeId,
    WriteRequest,
};

use crate::auth::NtlmCredentials;
#[cfg(feature = "kerberos-api")]
use crate::auth::{KerberosCredentials, KerberosTarget};
use crate::client::{
    Authenticated, Connection, DurableHandle, DurableOpenOptions, ResilientHandle, TreeConnected,
};
use crate::error::CoreError;
use crate::lsarpc::LsarpcClient;
use crate::pipe::{connect_session, NamedPipe, PipeAccess, SmbSessionConfig};
use crate::rpc::PipeRpcClient;
use crate::samr::SamrClient;
use crate::srvsvc::SrvsvcClient;
use crate::transport::{TokioTcpTransport, Transport, TransportProtocol, TransportTarget};
const MAX_IO_CHUNK_SIZE: usize = u16::MAX as usize;
const FILE_READ_DATA: u32 = 0x0000_0001;
const FILE_WRITE_DATA: u32 = 0x0000_0002;
const FILE_APPEND_DATA: u32 = 0x0000_0004;
const FILE_READ_EA: u32 = 0x0000_0008;
const FILE_WRITE_EA: u32 = 0x0000_0010;
const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
const DELETE: u32 = 0x0001_0000;
const READ_CONTROL: u32 = 0x0002_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;
const WINDOWS_TICK: u64 = 10_000_000;
const SEC_TO_UNIX_EPOCH: u64 = 11_644_473_600;

#[derive(Debug, Clone)]
enum BuilderAuth {
    Ntlm(NtlmCredentials),
    #[cfg(feature = "kerberos-api")]
    Kerberos {
        credentials: KerberosCredentials,
        target: KerberosTarget,
    },
}

/// Builder for the high-level SMB client facade.
#[derive(Debug, Clone)]
pub struct ClientBuilder {
    target: TransportTarget,
    auth: Option<BuilderAuth>,
    signing_mode: SigningMode,
    capabilities: GlobalCapabilities,
    dialects: Vec<Dialect>,
    client_guid: [u8; 16],
    compression: Option<CompressionCapabilities>,
}

impl ClientBuilder {
    /// Creates a new client builder for the target server.
    #[must_use]
    pub fn new(server: impl Into<String>) -> Self {
        Self {
            target: TransportTarget::tcp(server),
            auth: None,
            signing_mode: SigningMode::ENABLED,
            capabilities: GlobalCapabilities::LARGE_MTU
                | GlobalCapabilities::LEASING
                | GlobalCapabilities::ENCRYPTION,
            dialects: vec![Dialect::Smb210, Dialect::Smb302, Dialect::Smb311],
            client_guid: random(),
            compression: None,
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

    /// Configures NTLM credentials for the client.
    #[must_use]
    pub fn with_ntlm_credentials(mut self, credentials: NtlmCredentials) -> Self {
        self.auth = Some(BuilderAuth::Ntlm(credentials));
        self
    }

    /// Configures Kerberos credentials for the client.
    #[cfg(feature = "kerberos-api")]
    #[cfg_attr(
        docsrs,
        doc(cfg(any(feature = "kerberos", feature = "kerberos-gssapi")))
    )]
    #[must_use]
    pub fn with_kerberos_credentials(
        mut self,
        credentials: KerberosCredentials,
        target: KerberosTarget,
    ) -> Self {
        self.auth = Some(BuilderAuth::Kerberos {
            credentials,
            target,
        });
        self
    }

    /// Builds a reusable high-level client.
    pub fn build(self) -> Result<Client, CoreError> {
        let auth = self.auth.ok_or(CoreError::InvalidInput(
            "client builder requires NTLM or Kerberos credentials",
        ))?;

        let config = match auth {
            BuilderAuth::Ntlm(credentials) => {
                SmbSessionConfig::new(self.target.server().to_owned(), credentials)
            }
            #[cfg(feature = "kerberos-api")]
            BuilderAuth::Kerberos {
                credentials,
                target,
            } => SmbSessionConfig::kerberos(self.target.server().to_owned(), credentials, target),
        }
        .with_transport_target(self.target)
        .with_signing_mode(self.signing_mode)
        .with_capabilities(self.capabilities)
        .with_dialects(self.dialects)
        .with_client_guid(self.client_guid);
        let config = if let Some(compression) = self.compression {
            config.with_compression_capabilities(compression)
        } else {
            config
        };

        Ok(Client::from_session_config(config))
    }
}

/// High-level embedded SMB client facade.
#[derive(Debug, Clone)]
pub struct Client {
    config: SmbSessionConfig,
}

impl Client {
    /// Starts a new builder for the target server.
    #[must_use]
    pub fn builder(server: impl Into<String>) -> ClientBuilder {
        ClientBuilder::new(server)
    }

    /// Wraps an existing session configuration as a high-level client.
    #[must_use]
    pub fn from_session_config(config: SmbSessionConfig) -> Self {
        Self { config }
    }

    /// Returns the underlying session configuration.
    #[must_use]
    pub fn session_config(&self) -> &SmbSessionConfig {
        &self.config
    }

    /// Consumes the client and returns the underlying session configuration.
    #[must_use]
    pub fn into_session_config(self) -> SmbSessionConfig {
        self.config
    }

    /// Returns the configured SMB server host name or IP address.
    #[must_use]
    pub fn server(&self) -> &str {
        self.config.server()
    }

    /// Returns the configured SMB TCP port.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.config.port()
    }

    /// Returns the configured transport target.
    #[must_use]
    pub fn transport_target(&self) -> &TransportTarget {
        self.config.transport_target()
    }

    /// Returns the configured transport protocol.
    #[must_use]
    pub fn transport_protocol(&self) -> TransportProtocol {
        self.config.transport_protocol()
    }

    /// Connects and authenticates an SMB session.
    pub async fn connect(&self) -> Result<Session, CoreError> {
        let connection = connect_session(&self.config).await?;
        Ok(Session {
            server: self.config.server().to_owned(),
            connection,
        })
    }

    /// Connects, authenticates, and tree-connects to the requested share.
    pub async fn connect_share(&self, share: &str) -> Result<Share, CoreError> {
        self.connect().await?.connect_share(share).await
    }

    /// Connects directly to `IPC$`.
    pub async fn connect_ipc(&self) -> Result<Share, CoreError> {
        self.connect_share("IPC$").await
    }

    /// Connects, authenticates, opens `IPC$`, and binds a typed `lsarpc` client.
    pub async fn connect_lsarpc(&self) -> Result<LsarpcClient, CoreError> {
        self.connect().await?.connect_lsarpc().await
    }

    /// Connects, authenticates, opens `IPC$`, and binds a typed `srvsvc` client.
    pub async fn connect_srvsvc(&self) -> Result<SrvsvcClient, CoreError> {
        self.connect().await?.connect_srvsvc().await
    }
}

/// Authenticated SMB session returned by the high-level client.
#[derive(Debug)]
pub struct Session<T = TokioTcpTransport> {
    server: String,
    connection: Connection<T, Authenticated>,
}

impl<T> Session<T>
where
    T: Transport + Send,
{
    /// Returns the target SMB server for this session.
    #[must_use]
    pub fn server(&self) -> &str {
        &self.server
    }

    /// Returns the active SMB session identifier.
    #[must_use]
    pub fn session_id(&self) -> SessionId {
        self.connection.session_id()
    }

    /// Returns the exported SMB session key, if the auth mechanism established one.
    #[must_use]
    pub fn session_key(&self) -> Option<&[u8]> {
        self.connection.session_key()
    }

    /// Returns the wrapped authenticated connection.
    #[must_use]
    pub fn connection(&self) -> &Connection<T, Authenticated> {
        &self.connection
    }

    /// Returns a mutable reference to the wrapped authenticated connection.
    #[must_use]
    pub fn connection_mut(&mut self) -> &mut Connection<T, Authenticated> {
        &mut self.connection
    }

    /// Consumes the session wrapper and returns the underlying authenticated connection.
    #[must_use]
    pub fn into_connection(self) -> Connection<T, Authenticated> {
        self.connection
    }

    /// Performs an `ECHO` request against the active SMB session.
    pub async fn echo(&mut self) -> Result<EchoResponse, CoreError> {
        self.connection.echo().await
    }

    /// Tree-connects to the requested share.
    pub async fn connect_share(self, share: &str) -> Result<Share<T>, CoreError> {
        let normalized_share = normalize_share_name(share)?;
        let unc = format!(r"\\{}\{}", self.server, normalized_share);
        let connection = self
            .connection
            .tree_connect(&TreeConnectRequest::from_unc(&unc))
            .await?;
        Ok(Share {
            server: self.server,
            name: normalized_share,
            connection,
        })
    }

    /// Tree-connects directly to `IPC$`.
    pub async fn connect_ipc(self) -> Result<Share<T>, CoreError> {
        self.connect_share("IPC$").await
    }

    /// Opens a named pipe on `IPC$`.
    pub async fn connect_pipe(
        self,
        pipe_name: &str,
        access: PipeAccess,
    ) -> Result<NamedPipe<T>, CoreError> {
        self.connect_ipc().await?.open_pipe(pipe_name, access).await
    }

    /// Opens a named pipe on `IPC$` and wraps it as an RPC transport.
    pub async fn connect_rpc_pipe(
        self,
        pipe_name: &str,
        access: PipeAccess,
    ) -> Result<PipeRpcClient<T>, CoreError> {
        let pipe = self.connect_pipe(pipe_name, access).await?;
        Ok(PipeRpcClient::new(pipe))
    }

    /// Opens a named pipe on `IPC$`, performs an RPC bind, and returns the bound RPC client.
    pub async fn bind_rpc(
        self,
        pipe_name: &str,
        context_id: u16,
        abstract_syntax: SyntaxId,
    ) -> Result<PipeRpcClient<T>, CoreError> {
        let mut rpc = self
            .connect_rpc_pipe(pipe_name, PipeAccess::ReadWrite)
            .await?;
        rpc.bind_context(context_id, abstract_syntax).await?;
        Ok(rpc)
    }

    /// Opens `\\PIPE\\srvsvc` on `IPC$`, performs the bind, and returns a typed client.
    pub async fn connect_srvsvc(self) -> Result<SrvsvcClient<T>, CoreError> {
        let rpc = self
            .connect_rpc_pipe("srvsvc", PipeAccess::ReadWrite)
            .await?;
        SrvsvcClient::bind(rpc).await
    }

    /// Opens `\\PIPE\\lsarpc` on `IPC$`, performs the bind/open, and returns a typed client.
    pub async fn connect_lsarpc(self) -> Result<LsarpcClient<T>, CoreError> {
        let rpc = self
            .connect_rpc_pipe("lsarpc", PipeAccess::ReadWrite)
            .await?;
        LsarpcClient::bind(rpc).await
    }

    /// Opens a caller-selected SAMR-capable pipe on `IPC$`, performs the bind/connect, and returns a typed client.
    pub async fn connect_samr_pipe(self, pipe_name: &str) -> Result<SamrClient<T>, CoreError> {
        let rpc = self
            .connect_rpc_pipe(pipe_name, PipeAccess::ReadWrite)
            .await?;
        SamrClient::bind(rpc).await
    }

    /// Opens the default SAMR endpoint on `IPC$`, performs the bind/connect, and returns a typed client.
    pub async fn connect_samr(self) -> Result<SamrClient<T>, CoreError> {
        self.connect_samr_pipe("lsarpc").await
    }

    /// Logs off the authenticated SMB session.
    pub async fn logoff(self) -> Result<(), CoreError> {
        let _ = self.connection.logoff().await?;
        Ok(())
    }
}

/// Tree-connected SMB share returned by the high-level client/session facade.
#[derive(Debug)]
pub struct Share<T = TokioTcpTransport> {
    server: String,
    name: String,
    connection: Connection<T, TreeConnected>,
}

impl<T> Share<T>
where
    T: Transport + Send,
{
    /// Returns the target SMB server for this tree connection.
    #[must_use]
    pub fn server(&self) -> &str {
        &self.server
    }

    /// Returns the connected SMB share name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the active SMB session identifier.
    #[must_use]
    pub fn session_id(&self) -> SessionId {
        self.connection.session_id()
    }

    /// Returns the active SMB tree identifier.
    #[must_use]
    pub fn tree_id(&self) -> TreeId {
        self.connection.tree_id()
    }

    /// Returns the exported SMB session key, if the auth mechanism established one.
    #[must_use]
    pub fn session_key(&self) -> Option<&[u8]> {
        self.connection.session_key()
    }

    /// Returns the wrapped tree-connected connection.
    #[must_use]
    pub fn connection(&self) -> &Connection<T, TreeConnected> {
        &self.connection
    }

    /// Returns a mutable reference to the wrapped tree-connected connection.
    #[must_use]
    pub fn connection_mut(&mut self) -> &mut Connection<T, TreeConnected> {
        &mut self.connection
    }

    /// Consumes the share wrapper and returns the underlying tree-connected connection.
    #[must_use]
    pub fn into_connection(self) -> Connection<T, TreeConnected> {
        self.connection
    }

    /// Opens a file on the current tree and returns a high-level file wrapper.
    pub async fn open(mut self, path: &str, options: OpenOptions) -> Result<File<T>, CoreError> {
        let normalized_path = normalize_share_path(path)?;
        let dialect = self.connection.state().negotiated.dialect_revision;
        let create_request = options.to_create_request(&normalized_path)?;
        let (durable_handle, file_id) = if let Some(durable) = options.durable_options(dialect) {
            let durable_handle = self
                .connection
                .create_durable(&create_request, durable)
                .await?;
            (Some(durable_handle.clone()), durable_handle.file_id())
        } else {
            let response = self.connection.create(&create_request).await?;
            (None, response.file_id)
        };

        let resilient_handle = if let Some(timeout) = options.resilient_timeout {
            Some(self.connection.request_resiliency(file_id, timeout).await?)
        } else {
            None
        };

        Ok(File {
            share: self,
            path: normalized_path,
            file_id,
            durable_handle,
            resilient_handle,
        })
    }

    /// Opens a named pipe on the current tree, which is usually `IPC$`.
    pub async fn open_pipe(
        self,
        pipe_name: &str,
        access: PipeAccess,
    ) -> Result<NamedPipe<T>, CoreError> {
        let normalized_pipe = normalize_pipe_name(pipe_name)?;
        NamedPipe::open(self.connection, &normalized_pipe, access).await
    }

    /// Opens a named pipe on the current tree and wraps it as an RPC transport.
    pub async fn connect_rpc_pipe(
        self,
        pipe_name: &str,
        access: PipeAccess,
    ) -> Result<PipeRpcClient<T>, CoreError> {
        let pipe = self.open_pipe(pipe_name, access).await?;
        Ok(PipeRpcClient::new(pipe))
    }

    /// Opens a named pipe on the current tree, performs an RPC bind, and returns the bound client.
    pub async fn bind_rpc(
        self,
        pipe_name: &str,
        context_id: u16,
        abstract_syntax: SyntaxId,
    ) -> Result<PipeRpcClient<T>, CoreError> {
        let mut rpc = self
            .connect_rpc_pipe(pipe_name, PipeAccess::ReadWrite)
            .await?;
        rpc.bind_context(context_id, abstract_syntax).await?;
        Ok(rpc)
    }

    /// Opens `\\PIPE\\srvsvc` on the current tree, performs the bind, and returns a typed client.
    pub async fn connect_srvsvc(self) -> Result<SrvsvcClient<T>, CoreError> {
        let rpc = self
            .connect_rpc_pipe("srvsvc", PipeAccess::ReadWrite)
            .await?;
        SrvsvcClient::bind(rpc).await
    }

    /// Opens `\\PIPE\\lsarpc` on the current tree, performs the bind/open, and returns a typed client.
    pub async fn connect_lsarpc(self) -> Result<LsarpcClient<T>, CoreError> {
        let rpc = self
            .connect_rpc_pipe("lsarpc", PipeAccess::ReadWrite)
            .await?;
        LsarpcClient::bind(rpc).await
    }

    /// Opens a caller-selected SAMR-capable pipe on the current tree, performs the bind/connect, and returns a typed client.
    pub async fn connect_samr_pipe(self, pipe_name: &str) -> Result<SamrClient<T>, CoreError> {
        let rpc = self
            .connect_rpc_pipe(pipe_name, PipeAccess::ReadWrite)
            .await?;
        SamrClient::bind(rpc).await
    }

    /// Opens the default SAMR endpoint on the current tree, performs the bind/connect, and returns a typed client.
    pub async fn connect_samr(self) -> Result<SamrClient<T>, CoreError> {
        self.connect_samr_pipe("lsarpc").await
    }

    /// Reads the full contents of a file on the current tree.
    pub async fn read(&mut self, path: &str) -> Result<Vec<u8>, CoreError> {
        let normalized_path = normalize_share_path(path)?;
        let create_request = OpenOptions::new()
            .read(true)
            .to_create_request(&normalized_path)?;
        let response = self.connection.create(&create_request).await?;
        let file_id = response.file_id;
        let size = self.stat_by_id(file_id).await?.size;
        let mut output = Vec::with_capacity(usize::try_from(size).unwrap_or(0));
        let mut offset = 0u64;

        while offset < size {
            let remaining = size - offset;
            let chunk_len = remaining.min(MAX_IO_CHUNK_SIZE as u64) as u32;
            let response = self
                .connection
                .read(&ReadRequest::for_file(file_id, offset, chunk_len))
                .await?;
            if response.data.is_empty() {
                break;
            }
            offset = offset.saturating_add(response.data.len() as u64);
            output.extend_from_slice(&response.data);
        }

        self.connection
            .close(&CloseRequest { flags: 0, file_id })
            .await?;
        Ok(output)
    }

    /// Reads the full contents of a file on the current tree.
    ///
    /// This is an ergonomic alias for [`Share::read`] that matches the
    /// higher-level "get/put" workflow commonly used by embedded clients.
    pub async fn get(&mut self, path: &str) -> Result<Vec<u8>, CoreError> {
        self.read(path).await
    }

    /// Writes the full contents of a file on the current tree, creating it when absent.
    pub async fn write(&mut self, path: &str, data: &[u8]) -> Result<(), CoreError> {
        let normalized_path = normalize_share_path(path)?;
        let create_request = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .to_create_request(&normalized_path)?;
        let response = self.connection.create(&create_request).await?;
        let file_id = response.file_id;
        let mut offset = 0u64;

        while (offset as usize) < data.len() {
            let chunk_end = (offset as usize + MAX_IO_CHUNK_SIZE).min(data.len());
            self.connection
                .write(&WriteRequest::for_file(
                    file_id,
                    offset,
                    data[offset as usize..chunk_end].to_vec(),
                ))
                .await?;
            offset = chunk_end as u64;
        }

        self.connection
            .flush(&FlushRequest::for_file(file_id))
            .await?;
        self.connection
            .close(&CloseRequest { flags: 0, file_id })
            .await?;
        Ok(())
    }

    /// Writes the full contents of a file on the current tree, creating it when absent.
    ///
    /// This is an ergonomic alias for [`Share::write`] that matches the
    /// higher-level "get/put" workflow commonly used by embedded clients.
    pub async fn put(&mut self, path: &str, data: &[u8]) -> Result<(), CoreError> {
        self.write(path, data).await
    }

    /// Queries file metadata on the current tree.
    pub async fn stat(&mut self, path: &str) -> Result<FileMetadata, CoreError> {
        let normalized_path = normalize_share_path(path)?;
        let mut create_request = CreateRequest::from_path(&normalized_path);
        create_request.desired_access = FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;
        create_request.share_access = ShareAccess::READ | ShareAccess::WRITE | ShareAccess::DELETE;
        create_request.create_disposition = CreateDisposition::Open;
        create_request.create_options = CreateOptions::NON_DIRECTORY_FILE;
        let response = self.connection.create(&create_request).await?;
        let file_id = response.file_id;
        let metadata = self.stat_by_id(file_id).await?;
        self.connection
            .close(&CloseRequest { flags: 0, file_id })
            .await?;
        Ok(metadata)
    }

    /// Queries file metadata on the current tree.
    ///
    /// This is an ergonomic alias for [`Share::stat`] for callers that prefer
    /// a filesystem-style naming convention.
    pub async fn metadata(&mut self, path: &str) -> Result<FileMetadata, CoreError> {
        self.stat(path).await
    }

    /// Removes a file from the current tree by marking it delete-pending and closing it.
    pub async fn remove(&mut self, path: &str) -> Result<(), CoreError> {
        let normalized_path = normalize_share_path(path)?;
        let mut create_request = CreateRequest::from_path(&normalized_path);
        create_request.desired_access =
            DELETE | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;
        create_request.share_access = ShareAccess::READ | ShareAccess::WRITE | ShareAccess::DELETE;
        create_request.create_disposition = CreateDisposition::Open;
        create_request.create_options = CreateOptions::NON_DIRECTORY_FILE;
        let response = self.connection.create(&create_request).await?;
        let file_id = response.file_id;
        self.connection
            .set_info(&SetInfoRequest::for_file_info(
                file_id,
                FileInfoClass::DispositionInformation,
                DispositionInformation {
                    delete_pending: true,
                }
                .encode(),
            ))
            .await?;
        self.connection
            .close(&CloseRequest { flags: 0, file_id })
            .await?;
        Ok(())
    }

    /// Opens an existing file on the current tree for read access.
    pub async fn open_reader(self, path: &str) -> Result<File<T>, CoreError> {
        self.open(path, OpenOptions::new().read(true)).await
    }

    /// Opens a file on the current tree for write access, creating it when absent
    /// and truncating it before writing.
    pub async fn open_writer(self, path: &str) -> Result<File<T>, CoreError> {
        self.open(
            path,
            OpenOptions::new().write(true).create(true).truncate(true),
        )
        .await
    }

    /// Disconnects the tree and returns to an authenticated session wrapper.
    pub async fn disconnect(self) -> Result<Session<T>, CoreError> {
        let connection = self.connection.tree_disconnect().await?;
        Ok(Session {
            server: self.server,
            connection,
        })
    }

    /// Disconnects the tree and logs off the SMB session.
    pub async fn logoff(self) -> Result<(), CoreError> {
        self.disconnect().await?.logoff().await
    }

    async fn stat_by_id(&mut self, file_id: FileId) -> Result<FileMetadata, CoreError> {
        let basic = self
            .connection
            .query_info(&QueryInfoRequest::for_file_info(
                file_id,
                FileInfoClass::BasicInformation,
            ))
            .await?;
        let basic = FileBasicInformation::decode(&basic.output_buffer).map_err(CoreError::from)?;

        let standard = self
            .connection
            .query_info(&QueryInfoRequest::for_file_info(
                file_id,
                FileInfoClass::StandardInformation,
            ))
            .await?;
        let standard =
            FileStandardInformation::decode(&standard.output_buffer).map_err(CoreError::from)?;

        Ok(metadata_from_info(basic, standard))
    }
}

/// High-level open options for the embedded client facade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenOptions {
    read: bool,
    write: bool,
    create: bool,
    create_new: bool,
    truncate: bool,
    durable: Option<DurableOpenOptions>,
    resilient_timeout: Option<u32>,
}

impl OpenOptions {
    /// Builds a default empty option set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enables or disables read access.
    #[must_use]
    pub fn read(mut self, read: bool) -> Self {
        self.read = read;
        self
    }

    /// Enables or disables write access.
    #[must_use]
    pub fn write(mut self, write: bool) -> Self {
        self.write = write;
        self
    }

    /// Creates the file if it does not exist.
    #[must_use]
    pub fn create(mut self, create: bool) -> Self {
        self.create = create;
        self
    }

    /// Requires that the file be created and fail if it already exists.
    #[must_use]
    pub fn create_new(mut self, create_new: bool) -> Self {
        self.create_new = create_new;
        self
    }

    /// Truncates the file when it is opened.
    #[must_use]
    pub fn truncate(mut self, truncate: bool) -> Self {
        self.truncate = truncate;
        self
    }

    /// Requests a durable handle for the opened file.
    #[must_use]
    pub fn durable(mut self, durable: DurableOpenOptions) -> Self {
        self.durable = Some(durable);
        self
    }

    /// Requests handle resiliency for the opened file.
    #[must_use]
    pub fn resilient(mut self, timeout: u32) -> Self {
        self.resilient_timeout = Some(timeout);
        self
    }

    fn to_create_request(&self, path: &str) -> Result<CreateRequest, CoreError> {
        if !self.read && !self.write {
            return Err(CoreError::InvalidInput(
                "open options must request read and/or write access",
            ));
        }
        if (self.truncate || self.create || self.create_new) && !self.write {
            return Err(CoreError::InvalidInput(
                "create and truncate operations require write access",
            ));
        }

        let mut request = CreateRequest::from_path(path);
        request.desired_access = desired_access_mask(self);
        request.share_access = ShareAccess::READ | ShareAccess::WRITE | ShareAccess::DELETE;
        request.file_attributes = FileAttributes::NORMAL;
        request.create_options = CreateOptions::NON_DIRECTORY_FILE;
        request.create_disposition = create_disposition(self);
        Ok(request)
    }

    fn durable_options(&self, dialect: Dialect) -> Option<DurableOpenOptions> {
        self.durable.clone().map(|durable| {
            if dialect_supports_durable_v2(dialect) && durable.create_guid.is_none() {
                durable.with_create_guid(random())
            } else {
                durable
            }
        })
    }
}

impl Default for OpenOptions {
    fn default() -> Self {
        Self {
            read: false,
            write: false,
            create: false,
            create_new: false,
            truncate: false,
            durable: None,
            resilient_timeout: None,
        }
    }
}

/// High-level metadata for an SMB object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMetadata {
    /// Logical size of the object in bytes.
    pub size: u64,
    /// Allocated size of the object in bytes.
    pub allocation_size: u64,
    /// File attributes.
    pub attributes: FileAttributes,
    /// Creation time.
    pub created: Option<SystemTime>,
    /// Last access time.
    pub accessed: Option<SystemTime>,
    /// Last write time.
    pub written: Option<SystemTime>,
    /// Change time.
    pub changed: Option<SystemTime>,
    /// Whether the object is pending deletion.
    pub delete_pending: bool,
}

impl FileMetadata {
    /// Returns true when the object is a directory.
    #[must_use]
    pub fn is_directory(&self) -> bool {
        self.attributes.contains(FileAttributes::DIRECTORY)
    }

    /// Returns true when the object is a regular file.
    #[must_use]
    pub fn is_file(&self) -> bool {
        !self.is_directory()
    }
}

/// One open file handle on a tree-connected share.
#[derive(Debug)]
pub struct File<T = TokioTcpTransport> {
    share: Share<T>,
    path: String,
    file_id: FileId,
    durable_handle: Option<DurableHandle>,
    resilient_handle: Option<ResilientHandle>,
}

impl<T> File<T>
where
    T: Transport + Send,
{
    /// Returns the file path relative to the connected share.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the active SMB file identifier.
    #[must_use]
    pub fn file_id(&self) -> FileId {
        self.file_id
    }

    /// Returns the durable reconnect state captured for this file, if requested.
    #[must_use]
    pub fn durable_handle(&self) -> Option<&DurableHandle> {
        self.durable_handle.as_ref()
    }

    /// Returns the resiliency state captured for this file, if requested.
    #[must_use]
    pub fn resilient_handle(&self) -> Option<ResilientHandle> {
        self.resilient_handle
    }

    /// Returns the wrapped tree-connected connection.
    #[must_use]
    pub fn connection(&self) -> &Connection<T, TreeConnected> {
        self.share.connection()
    }

    /// Returns a mutable reference to the wrapped tree-connected connection.
    #[must_use]
    pub fn connection_mut(&mut self) -> &mut Connection<T, TreeConnected> {
        self.share.connection_mut()
    }

    /// Reads the full contents of the open file.
    pub async fn read_all(&mut self) -> Result<Vec<u8>, CoreError> {
        let metadata = self.stat().await?;
        let mut output = Vec::with_capacity(usize::try_from(metadata.size).unwrap_or(0));
        let mut offset = 0u64;

        while offset < metadata.size {
            let remaining = metadata.size - offset;
            let chunk_len = remaining.min(MAX_IO_CHUNK_SIZE as u64) as u32;
            let response = self
                .share
                .connection
                .read(&ReadRequest::for_file(self.file_id, offset, chunk_len))
                .await?;
            if response.data.is_empty() {
                break;
            }
            offset = offset.saturating_add(response.data.len() as u64);
            output.extend_from_slice(&response.data);
        }

        Ok(output)
    }

    /// Reads the full contents of the open file.
    ///
    /// This is an alias for [`File::read_all`] that matches the standard async
    /// I/O naming convention used by Rust callers.
    pub async fn read_to_end(&mut self) -> Result<Vec<u8>, CoreError> {
        self.read_all().await
    }

    /// Writes the full provided buffer to the open file starting at offset zero.
    pub async fn write_all(&mut self, data: &[u8]) -> Result<(), CoreError> {
        let mut offset = 0u64;
        while (offset as usize) < data.len() {
            let chunk_end = (offset as usize + MAX_IO_CHUNK_SIZE).min(data.len());
            self.share
                .connection
                .write(&WriteRequest::for_file(
                    self.file_id,
                    offset,
                    data[offset as usize..chunk_end].to_vec(),
                ))
                .await?;
            offset = chunk_end as u64;
        }
        Ok(())
    }

    /// Flushes the open file handle.
    pub async fn flush(&mut self) -> Result<(), CoreError> {
        let _ = self
            .share
            .connection
            .flush(&FlushRequest::for_file(self.file_id))
            .await?;
        Ok(())
    }

    /// Flushes all buffered SMB state for the open file handle.
    ///
    /// This is an alias for [`File::flush`] that matches common filesystem
    /// terminology used by embedders.
    pub async fn sync_all(&mut self) -> Result<(), CoreError> {
        self.flush().await
    }

    /// Queries metadata for the open file handle.
    pub async fn stat(&mut self) -> Result<FileMetadata, CoreError> {
        self.share.stat_by_id(self.file_id).await
    }

    /// Requests handle resiliency for the current file and stores the result for future reconnects.
    pub async fn request_resiliency(&mut self, timeout: u32) -> Result<ResilientHandle, CoreError> {
        let resilient = self
            .share
            .connection
            .request_resiliency(self.file_id, timeout)
            .await?;
        self.resilient_handle = Some(resilient);
        if let Some(durable) = self.durable_handle.take() {
            self.durable_handle = Some(durable.with_resilient_timeout(timeout));
        }
        Ok(resilient)
    }

    /// Closes the file and returns the tree-connected share wrapper.
    pub async fn close(mut self) -> Result<Share<T>, CoreError> {
        self.share
            .connection
            .close(&CloseRequest {
                flags: 0,
                file_id: self.file_id,
            })
            .await?;
        Ok(self.share)
    }

    /// Consumes the file wrapper and returns the share wrapper plus low-level file state.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        Share<T>,
        FileId,
        Option<DurableHandle>,
        Option<ResilientHandle>,
    ) {
        (
            self.share,
            self.file_id,
            self.durable_handle,
            self.resilient_handle,
        )
    }
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
    Ok(share.to_owned())
}

fn normalize_share_path(path: &str) -> Result<String, CoreError> {
    if path.contains('\0') {
        return Err(CoreError::PathInvalid("path must not contain NUL bytes"));
    }
    if matches!(path, "\\" | "/") {
        return Ok("\\".to_string());
    }

    let normalized = path
        .split(['\\', '/'])
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("\\");
    if normalized.is_empty() {
        return Err(CoreError::PathInvalid("path must not be empty"));
    }
    Ok(normalized)
}

fn normalize_pipe_name(pipe_name: &str) -> Result<String, CoreError> {
    if pipe_name.contains('\0') {
        return Err(CoreError::PathInvalid(
            "pipe name must not contain NUL bytes",
        ));
    }

    let normalized = pipe_name.trim().replace('/', "\\");
    let trimmed = normalized.trim_matches('\\');
    if trimmed.is_empty() {
        return Err(CoreError::PathInvalid("pipe name must not be empty"));
    }

    let trimmed = if trimmed.len() > 5 && trimmed[..5].eq_ignore_ascii_case("pipe\\") {
        trimmed[5..].trim_start_matches('\\')
    } else {
        trimmed
    };
    if trimmed.is_empty() {
        return Err(CoreError::PathInvalid("pipe name must not be empty"));
    }

    Ok(trimmed.to_owned())
}

fn desired_access_mask(options: &OpenOptions) -> u32 {
    let mut desired_access = READ_CONTROL | SYNCHRONIZE;
    if options.read {
        desired_access |= FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES;
    }
    if options.write {
        desired_access |=
            FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES;
    }
    desired_access
}

fn create_disposition(options: &OpenOptions) -> CreateDisposition {
    if options.create_new {
        CreateDisposition::Create
    } else if options.create && options.truncate {
        CreateDisposition::OverwriteIf
    } else if options.create {
        CreateDisposition::OpenIf
    } else if options.truncate {
        CreateDisposition::Overwrite
    } else {
        CreateDisposition::Open
    }
}

fn dialect_supports_durable_v2(dialect: Dialect) -> bool {
    matches!(dialect, Dialect::Smb300 | Dialect::Smb302 | Dialect::Smb311)
}

fn metadata_from_info(
    basic: FileBasicInformation,
    standard: FileStandardInformation,
) -> FileMetadata {
    let mut attributes = basic.file_attributes;
    if standard.directory {
        attributes |= FileAttributes::DIRECTORY;
    }

    FileMetadata {
        size: standard.end_of_file,
        allocation_size: standard.allocation_size,
        attributes,
        created: system_time_from_windows_ticks(basic.creation_time),
        accessed: system_time_from_windows_ticks(basic.last_access_time),
        written: system_time_from_windows_ticks(basic.last_write_time),
        changed: system_time_from_windows_ticks(basic.change_time),
        delete_pending: standard.delete_pending,
    }
}

fn system_time_from_windows_ticks(value: u64) -> Option<SystemTime> {
    if value == 0 {
        return None;
    }

    let unix_ticks = value.checked_sub(SEC_TO_UNIX_EPOCH * WINDOWS_TICK)?;
    Some(UNIX_EPOCH + Duration::from_nanos(unix_ticks.saturating_mul(100)))
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use async_trait::async_trait;
    use smolder_proto::smb::netbios::SessionMessage;
    use smolder_proto::smb::smb2::{
        CloseResponse, Command, CreateDisposition, CreateResponse, Dialect, FileAttributes, FileId,
        FlushResponse, GlobalCapabilities, Header, MessageId, NegotiateRequest, NegotiateResponse,
        OplockLevel, QueryInfoResponse, SessionFlags, SessionSetupResponse, ShareFlags, ShareType,
        SigningMode, TreeCapabilities, TreeConnectRequest, TreeConnectResponse, TreeId,
        WriteResponse,
    };
    use smolder_proto::smb::status::NtStatus;

    use crate::auth::NtlmAuthenticator;
    use crate::auth::NtlmCredentials;
    #[cfg(feature = "kerberos-api")]
    use crate::auth::{KerberosCredentials, KerberosTarget};
    use crate::client::Connection;
    use crate::transport::{TransportProtocol, TransportTarget};
    use crate::transport::Transport;

    use super::{
        normalize_pipe_name, normalize_share_name, normalize_share_path, Client, ClientBuilder,
        FileMetadata, OpenOptions, Share,
    };

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
        let mut header = Header::new(command, MessageId(message_id));
        header.status = status;
        header.credit_request_response = 1;
        header.session_id = smolder_proto::smb::smb2::SessionId(session_id);
        header.tree_id = TreeId(tree_id);

        let mut packet = header.encode();
        packet.extend_from_slice(&body);
        SessionMessage::new(packet)
            .encode()
            .expect("response should frame")
    }

    async fn build_share(reads: Vec<Vec<u8>>) -> Share<ScriptedTransport> {
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
        let negotiate_request = NegotiateRequest {
            security_mode: SigningMode::ENABLED,
            capabilities: GlobalCapabilities::LARGE_MTU,
            client_guid: *b"client-guid-0001",
            dialects: vec![Dialect::Smb210, Dialect::Smb302],
            negotiate_contexts: Vec::new(),
        };
        let connection = Connection::new(transport)
            .negotiate(&negotiate_request)
            .await
            .expect("negotiate should succeed");
        let mut auth = NtlmAuthenticator::new(NtlmCredentials::new("user", "pass"));
        let connection = connection
            .authenticate(&mut auth)
            .await
            .expect("authenticate should succeed");
        let connection = connection
            .tree_connect(&TreeConnectRequest::from_unc(r"\\server\share"))
            .await
            .expect("tree connect should succeed");

        Share {
            server: "server".to_owned(),
            name: "share".to_owned(),
            connection,
        }
    }

    #[test]
    fn builder_requires_credentials() {
        let error = Client::builder("server")
            .build()
            .expect_err("builder should reject missing credentials");
        assert!(matches!(
            error,
            crate::error::CoreError::InvalidInput(
                "client builder requires NTLM or Kerberos credentials"
            )
        ));
    }

    #[test]
    fn ntlm_builder_populates_session_config() {
        let client = ClientBuilder::new("server")
            .with_port(1445)
            .with_signing_mode(SigningMode::REQUIRED)
            .with_capabilities(GlobalCapabilities::ENCRYPTION)
            .with_dialects(vec![Dialect::Smb302])
            .with_client_guid(*b"0123456789abcdef")
            .with_ntlm_credentials(NtlmCredentials::new("user", "pass"))
            .build()
            .expect("builder should produce a client");

        let config = client.session_config();
        assert_eq!(client.server(), "server");
        assert_eq!(client.port(), 1445);
        assert_eq!(config.server(), "server");
        assert_eq!(config.port(), 1445);
        assert_eq!(config.signing_mode(), SigningMode::REQUIRED);
        assert_eq!(config.capabilities(), GlobalCapabilities::ENCRYPTION);
        assert_eq!(config.dialects(), &[Dialect::Smb302]);
        assert_eq!(config.client_guid(), b"0123456789abcdef");
    }

    #[test]
    fn builder_can_override_transport_target() {
        let client = ClientBuilder::new("server")
            .with_transport_target(TransportTarget::quic("edge.lab.example").with_port(8443))
            .with_ntlm_credentials(NtlmCredentials::new("user", "pass"))
            .build()
            .expect("builder should produce a client");

        assert_eq!(client.server(), "edge.lab.example");
        assert_eq!(client.port(), 8443);
        assert_eq!(client.transport_protocol(), TransportProtocol::Quic);
        assert_eq!(
            client.transport_target(),
            &TransportTarget::quic("edge.lab.example").with_port(8443)
        );
    }

    #[cfg(feature = "kerberos-api")]
    #[test]
    fn kerberos_builder_produces_client() {
        let credentials = {
            #[cfg(feature = "kerberos-sspi")]
            {
                KerberosCredentials::new("user@LAB.EXAMPLE", "pass")
            }
            #[cfg(all(unix, feature = "kerberos-gssapi", not(feature = "kerberos-sspi")))]
            {
                KerberosCredentials::from_ticket_cache("user@LAB.EXAMPLE")
            }
        };
        let target = KerberosTarget::for_smb_host("server.lab.example");
        let client = ClientBuilder::new("server.lab.example")
            .with_kerberos_credentials(credentials, target)
            .build()
            .expect("builder should produce a client");
        assert_eq!(client.server(), "server.lab.example");
        assert_eq!(client.port(), 445);
    }

    #[test]
    fn normalize_share_name_rejects_invalid_values() {
        assert_eq!(
            normalize_share_name(r"\\IPC$\\").expect("share should normalize"),
            "IPC$"
        );
        assert!(normalize_share_name("").is_err());
        assert!(normalize_share_name("share/path").is_err());
    }

    #[test]
    fn open_options_map_to_expected_create_request() {
        let request = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .to_create_request("docs\\report.txt")
            .expect("request should build");
        assert_eq!(request.create_disposition, CreateDisposition::OverwriteIf);
    }

    #[test]
    fn normalize_share_path_rejects_invalid_values() {
        assert_eq!(
            normalize_share_path(r"/docs//nested\file.txt/").expect("path should normalize"),
            "docs\\nested\\file.txt"
        );
        assert!(normalize_share_path("").is_err());
        assert!(normalize_share_path("\0bad").is_err());
    }

    #[test]
    fn normalize_pipe_name_rejects_invalid_values() {
        assert_eq!(
            normalize_pipe_name("srvsvc").expect("pipe should normalize"),
            "srvsvc"
        );
        assert_eq!(
            normalize_pipe_name(r"\\PIPE\\srvsvc").expect("pipe should normalize"),
            "srvsvc"
        );
        assert!(normalize_pipe_name("").is_err());
        assert!(normalize_pipe_name("\0bad").is_err());
    }

    #[tokio::test]
    async fn share_read_queries_metadata_and_reads_contents() {
        let create_response = CreateResponse {
            oplock_level: OplockLevel::None,
            file_attributes: FileAttributes::ARCHIVE,
            allocation_size: 5,
            end_of_file: 5,
            file_id: FileId {
                persistent: 1,
                volatile: 2,
            },
            create_contexts: Vec::new(),
        };
        let basic = QueryInfoResponse {
            output_buffer: {
                let mut buffer = Vec::new();
                buffer.extend_from_slice(&1u64.to_le_bytes());
                buffer.extend_from_slice(&2u64.to_le_bytes());
                buffer.extend_from_slice(&3u64.to_le_bytes());
                buffer.extend_from_slice(&4u64.to_le_bytes());
                buffer.extend_from_slice(&FileAttributes::ARCHIVE.bits().to_le_bytes());
                buffer.extend_from_slice(&0u32.to_le_bytes());
                buffer
            },
        };
        let standard = QueryInfoResponse {
            output_buffer: {
                let mut buffer = Vec::new();
                buffer.extend_from_slice(&5u64.to_le_bytes());
                buffer.extend_from_slice(&5u64.to_le_bytes());
                buffer.extend_from_slice(&1u32.to_le_bytes());
                buffer.push(0);
                buffer.push(0);
                buffer.extend_from_slice(&0u16.to_le_bytes());
                buffer
            },
        };
        let read_response = smolder_proto::smb::smb2::ReadResponse {
            data_remaining: 0,
            flags: smolder_proto::smb::smb2::ReadResponseFlags::empty(),
            data: b"hello".to_vec(),
        };

        let mut share = build_share(vec![
            response_frame(
                Command::Create,
                NtStatus::SUCCESS.to_u32(),
                3,
                11,
                7,
                create_response.encode(),
            ),
            response_frame(
                Command::QueryInfo,
                NtStatus::SUCCESS.to_u32(),
                4,
                11,
                7,
                basic.encode(),
            ),
            response_frame(
                Command::QueryInfo,
                NtStatus::SUCCESS.to_u32(),
                5,
                11,
                7,
                standard.encode(),
            ),
            response_frame(
                Command::Read,
                NtStatus::SUCCESS.to_u32(),
                6,
                11,
                7,
                read_response.encode(),
            ),
            response_frame(
                Command::Close,
                NtStatus::SUCCESS.to_u32(),
                7,
                11,
                7,
                CloseResponse {
                    flags: 0,
                    allocation_size: 5,
                    end_of_file: 5,
                    file_attributes: FileAttributes::ARCHIVE,
                }
                .encode(),
            ),
        ])
        .await;

        let data = share.read("notes.txt").await.expect("read should succeed");
        assert_eq!(data, b"hello");
    }

    #[tokio::test]
    async fn share_get_alias_reads_contents() {
        let create_response = CreateResponse {
            oplock_level: OplockLevel::None,
            file_attributes: FileAttributes::ARCHIVE,
            allocation_size: 5,
            end_of_file: 5,
            file_id: FileId {
                persistent: 1,
                volatile: 2,
            },
            create_contexts: Vec::new(),
        };
        let basic = QueryInfoResponse {
            output_buffer: {
                let mut buffer = Vec::new();
                buffer.extend_from_slice(&1u64.to_le_bytes());
                buffer.extend_from_slice(&2u64.to_le_bytes());
                buffer.extend_from_slice(&3u64.to_le_bytes());
                buffer.extend_from_slice(&4u64.to_le_bytes());
                buffer.extend_from_slice(&FileAttributes::ARCHIVE.bits().to_le_bytes());
                buffer.extend_from_slice(&0u32.to_le_bytes());
                buffer
            },
        };
        let standard = QueryInfoResponse {
            output_buffer: {
                let mut buffer = Vec::new();
                buffer.extend_from_slice(&5u64.to_le_bytes());
                buffer.extend_from_slice(&5u64.to_le_bytes());
                buffer.extend_from_slice(&1u32.to_le_bytes());
                buffer.push(0);
                buffer.push(0);
                buffer.extend_from_slice(&0u16.to_le_bytes());
                buffer
            },
        };
        let read_response = smolder_proto::smb::smb2::ReadResponse {
            data_remaining: 0,
            flags: smolder_proto::smb::smb2::ReadResponseFlags::empty(),
            data: b"hello".to_vec(),
        };

        let mut share = build_share(vec![
            response_frame(
                Command::Create,
                NtStatus::SUCCESS.to_u32(),
                3,
                11,
                7,
                create_response.encode(),
            ),
            response_frame(
                Command::QueryInfo,
                NtStatus::SUCCESS.to_u32(),
                4,
                11,
                7,
                basic.encode(),
            ),
            response_frame(
                Command::QueryInfo,
                NtStatus::SUCCESS.to_u32(),
                5,
                11,
                7,
                standard.encode(),
            ),
            response_frame(
                Command::Read,
                NtStatus::SUCCESS.to_u32(),
                6,
                11,
                7,
                read_response.encode(),
            ),
            response_frame(
                Command::Close,
                NtStatus::SUCCESS.to_u32(),
                7,
                11,
                7,
                CloseResponse {
                    flags: 0,
                    allocation_size: 5,
                    end_of_file: 5,
                    file_attributes: FileAttributes::ARCHIVE,
                }
                .encode(),
            ),
        ])
        .await;

        let data = share.get("notes.txt").await.expect("get should succeed");
        assert_eq!(data, b"hello");
    }

    #[tokio::test]
    async fn share_put_alias_writes_contents() {
        let create_response = CreateResponse {
            oplock_level: OplockLevel::None,
            file_attributes: FileAttributes::ARCHIVE,
            allocation_size: 5,
            end_of_file: 5,
            file_id: FileId {
                persistent: 1,
                volatile: 2,
            },
            create_contexts: Vec::new(),
        };

        let mut share = build_share(vec![
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
                WriteResponse { count: 5 }.encode(),
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
                CloseResponse {
                    flags: 0,
                    allocation_size: 5,
                    end_of_file: 5,
                    file_attributes: FileAttributes::ARCHIVE,
                }
                .encode(),
            ),
        ])
        .await;

        share
            .put("notes.txt", b"hello")
            .await
            .expect("put should succeed");
    }

    #[tokio::test]
    async fn share_stat_decodes_basic_and_standard_info() {
        let create_response = CreateResponse {
            oplock_level: OplockLevel::None,
            file_attributes: FileAttributes::ARCHIVE,
            allocation_size: 7,
            end_of_file: 5,
            file_id: FileId {
                persistent: 1,
                volatile: 2,
            },
            create_contexts: Vec::new(),
        };
        let basic = QueryInfoResponse {
            output_buffer: {
                let mut buffer = Vec::new();
                buffer.extend_from_slice(&1u64.to_le_bytes());
                buffer.extend_from_slice(&2u64.to_le_bytes());
                buffer.extend_from_slice(&3u64.to_le_bytes());
                buffer.extend_from_slice(&4u64.to_le_bytes());
                buffer.extend_from_slice(&FileAttributes::ARCHIVE.bits().to_le_bytes());
                buffer.extend_from_slice(&0u32.to_le_bytes());
                buffer
            },
        };
        let standard = QueryInfoResponse {
            output_buffer: {
                let mut buffer = Vec::new();
                buffer.extend_from_slice(&7u64.to_le_bytes());
                buffer.extend_from_slice(&5u64.to_le_bytes());
                buffer.extend_from_slice(&1u32.to_le_bytes());
                buffer.push(1);
                buffer.push(0);
                buffer.extend_from_slice(&0u16.to_le_bytes());
                buffer
            },
        };

        let mut share = build_share(vec![
            response_frame(
                Command::Create,
                NtStatus::SUCCESS.to_u32(),
                3,
                11,
                7,
                create_response.encode(),
            ),
            response_frame(
                Command::QueryInfo,
                NtStatus::SUCCESS.to_u32(),
                4,
                11,
                7,
                basic.encode(),
            ),
            response_frame(
                Command::QueryInfo,
                NtStatus::SUCCESS.to_u32(),
                5,
                11,
                7,
                standard.encode(),
            ),
            response_frame(
                Command::Close,
                NtStatus::SUCCESS.to_u32(),
                6,
                11,
                7,
                CloseResponse {
                    flags: 0,
                    allocation_size: 7,
                    end_of_file: 5,
                    file_attributes: FileAttributes::ARCHIVE,
                }
                .encode(),
            ),
        ])
        .await;

        let metadata: FileMetadata = share.stat("notes.txt").await.expect("stat should succeed");
        assert_eq!(metadata.size, 5);
        assert_eq!(metadata.allocation_size, 7);
        assert!(metadata.delete_pending);
        assert!(metadata.is_file());
    }
}
