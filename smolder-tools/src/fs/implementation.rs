//! High-level SMB2 file APIs built on top of the typestate client.

mod open_options;
mod remote_file;
mod share_helpers;

use std::path::Path;
use std::time::SystemTime;

use bytes::BytesMut;
use rand::random;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

use smolder_core::auth::NtlmCredentials;
#[cfg(feature = "kerberos")]
use smolder_core::auth::{KerberosCredentials, KerberosTarget};
use smolder_core::client::{Authenticated, Connection, DurableHandle, TreeConnected};
use smolder_core::dfs::{referrals_from_response, DfsReferral, UncPath};
use smolder_core::error::CoreError;
use smolder_core::facade::Client as CoreClient;
use smolder_core::transport::{TokioTcpTransport, Transport};
#[cfg(test)]
use smolder_proto::smb::smb2::{
    CipherId, EncryptionCapabilities, NegotiateContext, PreauthIntegrityCapabilities,
    PreauthIntegrityHashId,
};
use smolder_proto::smb::smb2::{
    CloseRequest, CloseResponse, CreateDisposition, CreateOptions, CreateRequest,
    DfsReferralRequest, Dialect, DispositionInformation, FileAttributes, FileBasicInformation,
    FileId, FileInfoClass, FileStandardInformation, GlobalCapabilities, IoctlRequest,
    QueryDirectoryFlags, QueryDirectoryRequest, QueryInfoRequest, RenameInformation,
    SetInfoRequest, ShareAccess, SigningMode, TreeConnectRequest,
};

pub use self::open_options::{Lease, LeaseRequest, OpenOptions};
pub use self::remote_file::RemoteFile;
use self::share_helpers::{
    connect_original_share_path, connect_share_path_with_resolver, directory_entry_from_query,
    metadata_from_info, normalize_share_name, normalize_share_path,
    normalize_share_path_with_options, parse_unc_share, resolve_share_path_with_referrals,
    should_fallback_direct_share_after_dfs_query,
};

const DEFAULT_PORT: u16 = 445;
const DEFAULT_TRANSFER_CHUNK_SIZE: u32 = 64 * 1024;
const DEFAULT_DFS_REFERRAL_MAX_RESPONSE: u32 = 64 * 1024;
const DEFAULT_DFS_REFERRAL_MAX_HOPS: usize = 8;
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
const FILE_LIST_DIRECTORY: u32 = 0x0000_0001;
const WINDOWS_TICK: u64 = 10_000_000;
const SEC_TO_UNIX_EPOCH: u64 = 11_644_473_600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CreateTarget {
    Directory,
    Any,
}

/// High-level metadata for an SMB object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmbMetadata {
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
}

impl SmbMetadata {
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

/// One directory entry returned by `Share::list`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmbDirectoryEntry {
    /// Entry name relative to the requested directory.
    pub name: String,
    /// Entry metadata.
    pub metadata: SmbMetadata,
}

/// Builder for an authenticated SMB2 client session.
#[derive(Debug, Clone)]
pub struct SmbClientBuilder {
    server: Option<String>,
    port: u16,
    auth: Option<SessionAuth>,
    require_encryption: bool,
    signing_mode: SigningMode,
    capabilities: GlobalCapabilities,
    dialects: Vec<Dialect>,
    client_guid: [u8; 16],
    transfer_chunk_size: u32,
}

#[derive(Debug, Clone)]
enum SessionAuth {
    Ntlm(NtlmCredentials),
    #[cfg(feature = "kerberos")]
    Kerberos {
        credentials: KerberosCredentials,
        target: KerberosTarget,
    },
}

impl Default for SmbClientBuilder {
    fn default() -> Self {
        Self {
            server: None,
            port: DEFAULT_PORT,
            auth: None,
            require_encryption: false,
            signing_mode: SigningMode::ENABLED,
            capabilities: GlobalCapabilities::LARGE_MTU
                | GlobalCapabilities::LEASING
                | GlobalCapabilities::ENCRYPTION,
            dialects: vec![Dialect::Smb210, Dialect::Smb302, Dialect::Smb311],
            client_guid: random(),
            transfer_chunk_size: DEFAULT_TRANSFER_CHUNK_SIZE,
        }
    }
}

impl SmbClientBuilder {
    /// Creates a new builder with SMB2 defaults suitable for Samba interop.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the target SMB server host name or IP address.
    #[must_use]
    pub fn server(mut self, server: impl Into<String>) -> Self {
        self.server = Some(server.into());
        self
    }

    /// Sets the TCP port used for the SMB connection.
    #[must_use]
    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Sets the NTLM credentials used during session setup.
    #[must_use]
    pub fn credentials(mut self, credentials: NtlmCredentials) -> Self {
        self.auth = Some(SessionAuth::Ntlm(credentials));
        self
    }

    /// Sets the Kerberos credentials and SMB target used during session setup.
    #[cfg(feature = "kerberos")]
    #[must_use]
    pub fn kerberos(mut self, credentials: KerberosCredentials, target: KerberosTarget) -> Self {
        self.auth = Some(SessionAuth::Kerberos {
            credentials,
            target,
        });
        self
    }

    /// Fails closed unless the authenticated SMB session/tree actually uses
    /// SMB 3.x encryption for subsequent requests.
    #[must_use]
    pub fn require_encryption(mut self, require_encryption: bool) -> Self {
        self.require_encryption = require_encryption;
        self
    }

    /// Overrides the SMB negotiate dialect list.
    #[must_use]
    pub fn dialects(mut self, dialects: Vec<Dialect>) -> Self {
        self.dialects = dialects;
        self
    }

    /// Overrides the SMB signing mode sent during negotiate.
    #[must_use]
    pub fn signing_mode(mut self, signing_mode: SigningMode) -> Self {
        self.signing_mode = signing_mode;
        self
    }

    /// Overrides the SMB global capabilities sent during negotiate.
    #[must_use]
    pub fn capabilities(mut self, capabilities: GlobalCapabilities) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// Overrides the client GUID sent during negotiate.
    #[must_use]
    pub fn client_guid(mut self, client_guid: [u8; 16]) -> Self {
        self.client_guid = client_guid;
        self
    }

    /// Sets the maximum file-transfer chunk size used by the high-level APIs.
    #[must_use]
    pub fn transfer_chunk_size(mut self, transfer_chunk_size: u32) -> Self {
        self.transfer_chunk_size = transfer_chunk_size.max(1);
        self
    }

    /// Connects to the configured server and completes SMB negotiate and session setup.
    pub async fn connect(self) -> Result<SmbClient<TokioTcpTransport>, CoreError> {
        let server = self
            .server
            .ok_or(CoreError::InvalidInput("server must be configured"))?;
        let auth = self
            .auth
            .ok_or(CoreError::InvalidInput("credentials must be configured"))?;
        let mut builder = CoreClient::builder(server.as_str())
            .with_port(self.port)
            .with_signing_mode(self.signing_mode)
            .with_capabilities(self.capabilities)
            .with_dialects(self.dialects)
            .with_client_guid(self.client_guid);

        match auth {
            SessionAuth::Ntlm(credentials) => {
                builder = builder.with_ntlm_credentials(credentials);
            }
            #[cfg(feature = "kerberos")]
            SessionAuth::Kerberos {
                credentials,
                target,
            } => {
                builder = builder.with_kerberos_credentials(credentials, target);
            }
        }

        let connection = builder.build()?.connect().await?.into_connection();
        Ok(SmbClient {
            server,
            connection,
            require_encryption: self.require_encryption,
            transfer_chunk_size: self.transfer_chunk_size,
        })
    }

    /// Connects to the UNC host, follows DFS referrals when needed, and
    /// returns the connected share plus the resolved relative path within it.
    pub async fn connect_share_path(
        self,
        unc: impl AsRef<str>,
    ) -> Result<(Share<TokioTcpTransport>, String), CoreError> {
        let builder = self;
        connect_share_path_with_resolver(unc.as_ref(), move |server| {
            let builder = builder.clone().server(server);
            async move { builder.connect().await }
        })
        .await
    }
}

/// An authenticated SMB session that can connect to a share.
#[derive(Debug)]
pub struct SmbClient<T = TokioTcpTransport> {
    server: String,
    connection: Connection<T, Authenticated>,
    require_encryption: bool,
    transfer_chunk_size: u32,
}

impl SmbClient<TokioTcpTransport> {
    /// Creates a builder for a new SMB client.
    #[must_use]
    pub fn builder() -> SmbClientBuilder {
        SmbClientBuilder::new()
    }
}

impl<T> SmbClient<T> {
    /// Wraps an already-authenticated typestate connection.
    #[must_use]
    pub fn from_connection(
        server: impl Into<String>,
        connection: Connection<T, Authenticated>,
    ) -> Self {
        Self {
            server: server.into(),
            connection,
            require_encryption: false,
            transfer_chunk_size: DEFAULT_TRANSFER_CHUNK_SIZE,
        }
    }

    /// Sets the maximum file-transfer chunk size used by derived shares.
    #[must_use]
    pub fn with_transfer_chunk_size(mut self, transfer_chunk_size: u32) -> Self {
        self.transfer_chunk_size = transfer_chunk_size.max(1);
        self
    }
}

impl<T> SmbClient<T>
where
    T: Transport + Send,
{
    /// Logs off the authenticated SMB session and drops the underlying transport.
    pub async fn logoff(self) -> Result<(), CoreError> {
        let SmbClient { connection, .. } = self;
        let _ = connection.logoff().await?;
        Ok(())
    }

    /// Connects the authenticated session to a share by share name.
    pub async fn share(self, share: impl AsRef<str>) -> Result<Share<T>, CoreError> {
        let share = normalize_share_name(share.as_ref())?;
        let unc = format!(r"\\{}\{}", self.server, share);
        let connection = self
            .connection
            .tree_connect(&TreeConnectRequest::from_unc(&unc))
            .await?;
        if self.require_encryption && !connection.state().encryption_required {
            return Err(CoreError::Unsupported(
                "SMB encryption was required but the connected share did not require encryption",
            ));
        }

        Ok(Share {
            server: self.server,
            name: share,
            connection: Some(connection),
            require_encryption: self.require_encryption,
            transfer_chunk_size: self.transfer_chunk_size,
        })
    }

    /// Connects the authenticated session to a share from a UNC path.
    pub async fn share_path(self, unc: impl AsRef<str>) -> Result<Share<T>, CoreError> {
        let (server, share) = parse_unc_share(unc.as_ref())?;
        if !server.eq_ignore_ascii_case(&self.server) {
            return Err(CoreError::PathInvalid(
                "UNC host does not match the connected SMB session",
            ));
        }
        self.share(share).await
    }

    /// Resolves a full UNC path, preferring DFS referral lookup over `IPC$`
    /// and falling back to a direct share connection when the path is not part
    /// of a DFS namespace.
    pub async fn share_path_auto(
        self,
        unc: impl AsRef<str>,
    ) -> Result<(Share<T>, String), CoreError> {
        let unc = unc.as_ref();
        let original = UncPath::parse(unc)?;
        if !original.server().eq_ignore_ascii_case(&self.server) {
            return Err(CoreError::PathInvalid(
                "UNC host does not match the connected SMB session",
            ));
        }

        let mut ipc = self.share("IPC$").await?;
        let query_result = ipc
            .connection_mut()
            .ioctl(&IoctlRequest::get_dfs_referrals(
                DfsReferralRequest {
                    max_referral_level: 4,
                    request_file_name: unc.to_string(),
                },
                DEFAULT_DFS_REFERRAL_MAX_RESPONSE,
            ))
            .await;

        match query_result {
            Ok(response) => {
                let referral_result = response
                    .dfs_referral_response()?
                    .ok_or(CoreError::InvalidResponse(
                        "DFS referral IOCTL did not return a DFS referral response",
                    ))
                    .and_then(|response| referrals_from_response(&response));
                let client = ipc.disconnect().await?;
                match referral_result {
                    Ok(referrals) => {
                        let (share_name, relative_path) =
                            resolve_share_path_with_referrals(&client.server, unc, &referrals)?;
                        let share = client.share(&share_name).await?;
                        Ok((share, relative_path))
                    }
                    Err(error) if should_fallback_direct_share_after_dfs_query(&error) => {
                        connect_original_share_path(client, &original).await
                    }
                    Err(error) => Err(error),
                }
            }
            Err(error) => {
                let client = ipc.disconnect().await?;
                if should_fallback_direct_share_after_dfs_query(&error) {
                    connect_original_share_path(client, &original).await
                } else {
                    Err(error)
                }
            }
        }
    }

    /// Resolves a UNC path through caller-supplied DFS referrals, connects to the
    /// resolved share, and returns the remaining relative path within that share.
    ///
    /// This method does not fetch referrals from the network. The caller must
    /// supply any DFS namespace mappings it wants applied.
    pub async fn share_path_with_referrals(
        self,
        unc: impl AsRef<str>,
        referrals: &[DfsReferral],
    ) -> Result<(Share<T>, String), CoreError> {
        let (share_name, relative_path) =
            resolve_share_path_with_referrals(&self.server, unc.as_ref(), referrals)?;
        let share = self.share(&share_name).await?;
        Ok((share, relative_path))
    }

    /// Resolves a UNC path by querying DFS referrals over `IPC$`, then connects
    /// to the resolved share and returns the remaining relative path.
    ///
    /// This only supports referral targets on the same SMB server as the
    /// authenticated session. Cross-server referrals require a new session.
    pub async fn share_path_resolving_dfs(
        self,
        unc: impl AsRef<str>,
    ) -> Result<(Share<T>, String), CoreError> {
        let unc = unc.as_ref();
        let original = UncPath::parse(unc)?;
        if !original.server().eq_ignore_ascii_case(&self.server) {
            return Err(CoreError::PathInvalid(
                "UNC host does not match the connected SMB session",
            ));
        }

        let (client, referrals) = self.fetch_dfs_referrals(unc).await?;
        let (share_name, relative_path) =
            resolve_share_path_with_referrals(&client.server, unc, &referrals)?;
        let share = client.share(&share_name).await?;
        Ok((share, relative_path))
    }

    async fn fetch_dfs_referrals(self, unc: &str) -> Result<(Self, Vec<DfsReferral>), CoreError> {
        let mut ipc = self.share("IPC$").await?;
        let response = ipc
            .connection_mut()
            .ioctl(&IoctlRequest::get_dfs_referrals(
                DfsReferralRequest {
                    max_referral_level: 4,
                    request_file_name: unc.to_string(),
                },
                DEFAULT_DFS_REFERRAL_MAX_RESPONSE,
            ))
            .await?;
        let referrals = referrals_from_response(&response.dfs_referral_response()?.ok_or(
            CoreError::InvalidResponse("DFS referral IOCTL did not return a DFS referral response"),
        )?)?;
        let client = ipc.disconnect().await?;
        Ok((client, referrals))
    }
}

/// A connected SMB share that provides path-oriented file operations.
#[derive(Debug)]
pub struct Share<T = TokioTcpTransport> {
    server: String,
    name: String,
    connection: Option<Connection<T, TreeConnected>>,
    require_encryption: bool,
    transfer_chunk_size: u32,
}

impl<T> Share<T> {
    /// Wraps an existing tree-connected typestate connection.
    #[must_use]
    pub fn from_connection(
        server: impl Into<String>,
        name: impl Into<String>,
        connection: Connection<T, TreeConnected>,
    ) -> Self {
        Self {
            server: server.into(),
            name: name.into(),
            connection: Some(connection),
            require_encryption: false,
            transfer_chunk_size: DEFAULT_TRANSFER_CHUNK_SIZE,
        }
    }

    /// Returns the connected server name.
    #[must_use]
    pub fn server(&self) -> &str {
        &self.server
    }

    /// Returns the connected share name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns whether the connected share requires SMB encryption.
    #[must_use]
    pub fn encryption_required(&self) -> bool
    where
        T: Transport + Send,
    {
        self.connection().state().encryption_required
    }

    /// Sets the maximum file-transfer chunk size used by this share.
    #[must_use]
    pub fn with_transfer_chunk_size(mut self, transfer_chunk_size: u32) -> Self {
        self.transfer_chunk_size = transfer_chunk_size.max(1);
        self
    }
}

impl<T> Share<T>
where
    T: Transport + Send,
{
    fn connection(&self) -> &Connection<T, TreeConnected> {
        self.connection
            .as_ref()
            .expect("share connection should be present while no remote file is open")
    }

    fn connection_mut(&mut self) -> &mut Connection<T, TreeConnected> {
        self.connection
            .as_mut()
            .expect("share connection should be present while no remote file is open")
    }

    fn take_connection(&mut self) -> Connection<T, TreeConnected> {
        self.connection
            .take()
            .expect("share connection should be present while no remote file is open")
    }

    fn restore_connection(&mut self, connection: Connection<T, TreeConnected>) {
        assert!(
            self.connection.is_none(),
            "share connection should not already be present",
        );
        self.connection = Some(connection);
    }

    /// Disconnects the current tree and returns to the authenticated client session.
    pub async fn disconnect(self) -> Result<SmbClient<T>, CoreError> {
        let Share {
            server,
            connection,
            require_encryption,
            transfer_chunk_size,
            ..
        } = self;
        let connection = connection
            .expect("share connection should be present while no remote file is open")
            .tree_disconnect()
            .await?;

        Ok(SmbClient {
            server,
            connection,
            require_encryption,
            transfer_chunk_size,
        })
    }

    /// Opens a remote file on the connected share.
    pub async fn open<'a>(
        &'a mut self,
        path: impl AsRef<str>,
        options: OpenOptions,
    ) -> Result<RemoteFile<'a, T>, CoreError> {
        if options.requests_lease() {
            self.ensure_lease_support()?;
        }
        let request = options.to_create_request(path.as_ref())?;
        let durable = if let Some(durable_options) =
            options.durable_options(self.connection().state().negotiated.dialect_revision)
        {
            Some(
                self.connection_mut()
                    .create_durable(&request, durable_options)
                    .await?,
            )
        } else {
            None
        };
        let response = if let Some(handle) = durable.as_ref() {
            handle.create_response().clone()
        } else {
            self.connection_mut().create(&request).await?
        };
        let resilient = if let Some(timeout) = options.resilient_timeout() {
            Some(
                self.connection_mut()
                    .request_resiliency(response.file_id, timeout)
                    .await?,
            )
        } else {
            None
        };
        let durable = match (durable, resilient) {
            (Some(handle), Some(resilient)) => {
                Some(handle.with_resilient_timeout(resilient.timeout))
            }
            (handle, _) => handle,
        };
        let lease = response
            .lease_v2()
            .map_err(CoreError::from)?
            .map(Lease::from);
        let max_read_size = self.max_read_size();
        let max_write_size = self.max_write_size();
        let connection = self.take_connection();

        Ok(RemoteFile::new(
            self,
            connection,
            response.file_id,
            lease,
            durable,
            resilient,
            response.end_of_file,
            max_read_size,
            max_write_size,
        ))
    }

    /// Reopens a previously captured durable handle on the current tree connection.
    pub async fn reopen_durable<'a>(
        &'a mut self,
        handle: &DurableHandle,
    ) -> Result<RemoteFile<'a, T>, CoreError> {
        let (reopened, resilient) = self
            .connection_mut()
            .reconnect_durable_with_resiliency(handle)
            .await?;
        let response = reopened.create_response().clone();
        let lease = response
            .lease_v2()
            .map_err(CoreError::from)?
            .map(Lease::from);
        let max_read_size = self.max_read_size();
        let max_write_size = self.max_write_size();
        let connection = self.take_connection();

        Ok(RemoteFile::new(
            self,
            connection,
            response.file_id,
            lease,
            Some(reopened),
            resilient,
            response.end_of_file,
            max_read_size,
            max_write_size,
        ))
    }

    /// Reads the full contents of a remote file into memory.
    pub async fn read(&mut self, path: impl AsRef<str>) -> Result<Vec<u8>, CoreError> {
        let buffer_size = self.max_read_size() as usize;
        let mut file = self.open(path, OpenOptions::new().read(true)).await?;
        let mut result = Vec::new();
        let mut buffer = BytesMut::with_capacity(buffer_size);

        let operation = async {
            loop {
                let read = file.read_chunk(&mut buffer).await?;
                if read == 0 {
                    break;
                }
                result.extend_from_slice(buffer.as_ref());
            }
            Ok::<(), CoreError>(())
        }
        .await;

        let close_result = file.close().await;
        match operation {
            Ok(()) => {
                close_result?;
                Ok(result)
            }
            Err(error) => {
                let _ = close_result;
                Err(error)
            }
        }
    }

    /// Streams a remote file into an async writer and returns the number of bytes written.
    pub async fn read_into<W>(
        &mut self,
        path: impl AsRef<str>,
        writer: &mut W,
    ) -> Result<u64, CoreError>
    where
        W: AsyncWrite + Unpin + Send,
    {
        let buffer_size = self.max_read_size() as usize;
        let mut file = self.open(path, OpenOptions::new().read(true)).await?;
        let mut buffer = BytesMut::with_capacity(buffer_size);
        let mut written = 0_u64;

        let operation = async {
            loop {
                let read = file.read_chunk(&mut buffer).await?;
                if read == 0 {
                    break;
                }
                writer
                    .write_all(buffer.as_ref())
                    .await
                    .map_err(CoreError::LocalIo)?;
                written += read as u64;
            }
            writer.flush().await.map_err(CoreError::LocalIo)?;
            Ok::<(), CoreError>(())
        }
        .await;

        let close_result = file.close().await;
        match operation {
            Ok(()) => {
                close_result?;
                Ok(written)
            }
            Err(error) => {
                let _ = close_result;
                Err(error)
            }
        }
    }

    /// Streams a remote file into an async writer, matching `smbclient`-style `cat`.
    pub async fn cat_into<W>(
        &mut self,
        path: impl AsRef<str>,
        writer: &mut W,
    ) -> Result<u64, CoreError>
    where
        W: AsyncWrite + Unpin + Send,
    {
        self.read_into(path, writer).await
    }

    /// Writes the provided bytes to a remote file, creating or truncating it.
    pub async fn write(&mut self, path: impl AsRef<str>, data: &[u8]) -> Result<(), CoreError> {
        let mut file = self
            .open(
                path,
                OpenOptions::new().write(true).create(true).truncate(true),
            )
            .await?;
        let operation = async {
            file.write_all(data).await?;
            file.flush().await?;
            Ok::<(), CoreError>(())
        }
        .await;
        let close_result = file.close().await;

        match operation {
            Ok(()) => {
                close_result?;
                Ok(())
            }
            Err(error) => {
                let _ = close_result;
                Err(error)
            }
        }
    }

    /// Downloads a remote file to a local filesystem path.
    pub async fn get<P>(&mut self, remote: impl AsRef<str>, local: P) -> Result<u64, CoreError>
    where
        P: AsRef<Path>,
    {
        let mut file = File::create(local).await.map_err(CoreError::LocalIo)?;
        self.read_into(remote, &mut file).await
    }

    /// Uploads a local filesystem path to a remote file, creating or truncating it.
    pub async fn put<P>(&mut self, local: P, remote: impl AsRef<str>) -> Result<u64, CoreError>
    where
        P: AsRef<Path>,
    {
        let mut local_file = File::open(local).await.map_err(CoreError::LocalIo)?;
        let buffer_size = self.max_write_size() as usize;
        let mut remote_file = self
            .open(
                remote,
                OpenOptions::new().write(true).create(true).truncate(true),
            )
            .await?;
        let mut buffer = vec![0; buffer_size];
        let mut written = 0_u64;

        let operation = async {
            loop {
                let read = local_file
                    .read(&mut buffer)
                    .await
                    .map_err(CoreError::LocalIo)?;
                if read == 0 {
                    break;
                }
                remote_file.write_all(&buffer[..read]).await?;
                written += read as u64;
            }
            remote_file.flush().await?;
            Ok::<(), CoreError>(())
        }
        .await;

        let close_result = remote_file.close().await;
        match operation {
            Ok(()) => {
                close_result?;
                Ok(written)
            }
            Err(error) => {
                let _ = close_result;
                Err(error)
            }
        }
    }

    /// Lists the entries in a directory.
    pub async fn list(
        &mut self,
        path: impl AsRef<str>,
    ) -> Result<Vec<SmbDirectoryEntry>, CoreError> {
        let query_size = self.max_query_size();
        let root_listing = path.as_ref().trim_matches(['\\', '/']).is_empty();
        let opened = self
            .create_handle(
                path.as_ref(),
                FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
                CreateDisposition::Open,
                CreateTarget::Directory,
                root_listing,
            )
            .await?;
        let file_id = opened.file_id;
        let mut first = true;
        let mut entries = Vec::new();

        let operation = async {
            loop {
                let mut request = QueryDirectoryRequest::for_pattern(file_id, "*", query_size);
                if !first {
                    request.flags = QueryDirectoryFlags::empty();
                }
                let response = self.connection_mut().query_directory(&request).await?;
                let decoded = response.directory_entries()?;
                if decoded.is_empty() {
                    break;
                }
                entries.extend(
                    decoded
                        .into_iter()
                        .filter(|entry| entry.file_name != "." && entry.file_name != "..")
                        .map(directory_entry_from_query),
                );
                first = false;
            }
            Ok::<(), CoreError>(())
        }
        .await;

        let close_result = self.close_file_id(file_id).await;
        match operation {
            Ok(()) => {
                close_result?;
                Ok(entries)
            }
            Err(error) => {
                let _ = close_result;
                Err(error)
            }
        }
    }

    /// Returns metadata for a file or directory.
    pub async fn stat(&mut self, path: impl AsRef<str>) -> Result<SmbMetadata, CoreError> {
        let opened = self
            .create_handle(
                path.as_ref(),
                FILE_READ_ATTRIBUTES,
                CreateDisposition::Open,
                CreateTarget::Any,
                false,
            )
            .await?;
        let file_id = opened.file_id;

        let operation = self.metadata_for_file_id(file_id).await;
        let close_result = self.close_file_id(file_id).await;
        match operation {
            Ok(metadata) => {
                close_result?;
                Ok(metadata)
            }
            Err(error) => {
                let _ = close_result;
                Err(error)
            }
        }
    }

    /// Renames a file or directory within the connected share.
    pub async fn rename(
        &mut self,
        from: impl AsRef<str>,
        to: impl AsRef<str>,
    ) -> Result<(), CoreError> {
        let opened = self
            .create_handle(
                from.as_ref(),
                DELETE | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
                CreateDisposition::Open,
                CreateTarget::Any,
                false,
            )
            .await?;
        let file_id = opened.file_id;
        let target = normalize_share_path_with_options(to.as_ref(), false)?;

        let operation = async {
            let request = SetInfoRequest::for_file_info(
                file_id,
                FileInfoClass::RenameInformation,
                RenameInformation::from_path(&target, false).encode(),
            );
            self.connection_mut().set_info(&request).await?;
            Ok::<(), CoreError>(())
        }
        .await;

        let close_result = self.close_file_id(file_id).await;
        match operation {
            Ok(()) => {
                close_result?;
                Ok(())
            }
            Err(error) => {
                let _ = close_result;
                Err(error)
            }
        }
    }

    /// Removes a file or empty directory from the connected share.
    pub async fn remove(&mut self, path: impl AsRef<str>) -> Result<(), CoreError> {
        let opened = self
            .create_handle(
                path.as_ref(),
                DELETE | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
                CreateDisposition::Open,
                CreateTarget::Any,
                false,
            )
            .await?;
        let file_id = opened.file_id;

        let operation = async {
            let request = SetInfoRequest::for_file_info(
                file_id,
                FileInfoClass::DispositionInformation,
                DispositionInformation {
                    delete_pending: true,
                }
                .encode(),
            );
            self.connection_mut().set_info(&request).await?;
            Ok::<(), CoreError>(())
        }
        .await;

        let close_result = self.close_file_id(file_id).await;
        match operation {
            Ok(()) => {
                close_result?;
                Ok(())
            }
            Err(error) => {
                let _ = close_result;
                Err(error)
            }
        }
    }

    async fn create_handle(
        &mut self,
        path: &str,
        desired_access: u32,
        create_disposition: CreateDisposition,
        target: CreateTarget,
        allow_empty_path: bool,
    ) -> Result<smolder_proto::smb::smb2::CreateResponse, CoreError> {
        let normalized = normalize_share_path_with_options(path, allow_empty_path)?;
        let mut request = CreateRequest::from_path(&normalized);
        request.desired_access = desired_access | READ_CONTROL | SYNCHRONIZE;
        request.create_disposition = create_disposition;
        request.share_access = ShareAccess::READ | ShareAccess::WRITE | ShareAccess::DELETE;
        request.file_attributes = match target {
            CreateTarget::Directory => FileAttributes::DIRECTORY,
            CreateTarget::Any => FileAttributes::NORMAL,
        };
        request.create_options = match target {
            CreateTarget::Directory => CreateOptions::DIRECTORY_FILE,
            CreateTarget::Any => CreateOptions::empty(),
        };
        self.connection_mut().create(&request).await
    }

    async fn close_file_id(&mut self, file_id: FileId) -> Result<CloseResponse, CoreError> {
        self.connection_mut()
            .close(&CloseRequest { flags: 0, file_id })
            .await
    }

    async fn metadata_for_file_id(&mut self, file_id: FileId) -> Result<SmbMetadata, CoreError> {
        let basic = self
            .connection_mut()
            .query_info(&QueryInfoRequest::for_file_info(
                file_id,
                FileInfoClass::BasicInformation,
            ))
            .await?;
        let standard = self
            .connection_mut()
            .query_info(&QueryInfoRequest::for_file_info(
                file_id,
                FileInfoClass::StandardInformation,
            ))
            .await?;

        let basic = FileBasicInformation::decode(&basic.output_buffer)?;
        let standard = FileStandardInformation::decode(&standard.output_buffer)?;
        Ok(metadata_from_info(basic, standard))
    }

    fn max_read_size(&self) -> u32 {
        let negotiated = self.connection().state().negotiated.max_read_size;
        negotiated.min(self.transfer_chunk_size).max(1)
    }

    fn max_write_size(&self) -> u32 {
        let negotiated = self.connection().state().negotiated.max_write_size;
        negotiated.min(self.transfer_chunk_size).max(1)
    }

    fn max_query_size(&self) -> u32 {
        let negotiated = self.connection().state().negotiated.max_transact_size;
        negotiated.min(self.transfer_chunk_size).max(1)
    }

    fn ensure_lease_support(&self) -> Result<(), CoreError> {
        let negotiated = &self.connection().state().negotiated;
        if !matches!(
            negotiated.dialect_revision,
            Dialect::Smb300 | Dialect::Smb302 | Dialect::Smb311
        ) {
            return Err(CoreError::Unsupported(
                "lease support currently requires an SMB 3.x dialect",
            ));
        }
        if !negotiated
            .capabilities
            .contains(GlobalCapabilities::LEASING)
        {
            return Err(CoreError::Unsupported(
                "server does not advertise SMB leasing support",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
fn default_negotiate_contexts(
    dialects: &[Dialect],
    capabilities: GlobalCapabilities,
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
    contexts
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};
    use std::io::SeekFrom;
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use smolder_core::dfs::{DfsReferral, UncPath};
    use smolder_proto::smb::netbios::SessionMessage;
    use smolder_proto::smb::smb2::{
        CipherId, CloseResponse, Command, CreateContext, CreateDisposition, CreateOptions,
        CreateRequest, CreateResponse, CtlCode, DfsReferralEntryFlags, DfsReferralHeaderFlags,
        DfsReferralRequest, Dialect, DirectoryInformationEntry, DurableHandleFlags,
        DurableHandleResponseV2, FileAttributes, FileBasicInformation, FileId, FileInfoClass,
        FileStandardInformation, FlushRequest, FlushResponse, GlobalCapabilities, Header,
        IoctlRequest, IoctlResponse, LeaseState, LeaseV2, MessageId, NegotiateRequest,
        NegotiateResponse, NetworkResiliencyRequest, OplockLevel, QueryDirectoryFlags,
        QueryDirectoryRequest, QueryDirectoryResponse, QueryInfoRequest, QueryInfoResponse,
        ReadRequest, ReadResponse, ReadResponseFlags, RequestedOplockLevel, SessionFlags,
        SessionSetupRequest, SessionSetupResponse, SessionSetupSecurityMode, SetInfoRequest,
        SetInfoResponse, ShareFlags, ShareType, SigningMode, TreeCapabilities, TreeConnectRequest,
        TreeConnectResponse, TreeDisconnectResponse, TreeId, WriteRequest, WriteResponse,
    };
    use smolder_proto::smb::status::NtStatus;
    use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

    use crate::fs::{LeaseRequest, OpenOptions, Share, SmbClient};
    use smolder_core::client::{Connection, DurableOpenOptions, ResilientHandle};
    use smolder_core::error::CoreError;
    use smolder_core::transport::Transport;

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
    fn smb_client_builder_defaults_enable_encryption() {
        let builder = super::SmbClientBuilder::new();
        assert!(builder
            .capabilities
            .contains(GlobalCapabilities::ENCRYPTION));

        let contexts = super::default_negotiate_contexts(&builder.dialects, builder.capabilities);
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
    fn smb_client_builder_skips_encryption_context_when_disabled() {
        let builder = super::SmbClientBuilder::new()
            .capabilities(GlobalCapabilities::LARGE_MTU | GlobalCapabilities::LEASING);
        let contexts = super::default_negotiate_contexts(&builder.dialects, builder.capabilities);

        assert_eq!(contexts.len(), 1);
        assert!(contexts[0]
            .as_preauth_integrity()
            .expect("preauth context should decode")
            .is_some());
        assert!(contexts[0]
            .as_encryption_capabilities()
            .expect("encryption context decode should succeed")
            .is_none());
    }

    #[test]
    fn smb_client_builder_can_require_encryption() {
        let builder = super::SmbClientBuilder::new().require_encryption(true);
        assert!(builder.require_encryption);
    }

    #[test]
    fn smb_client_builder_stores_ntlm_credentials() {
        let builder = super::SmbClientBuilder::new()
            .credentials(smolder_core::prelude::NtlmCredentials::new("user", "pass"));
        assert!(matches!(builder.auth, Some(super::SessionAuth::Ntlm(_))));
    }

    #[cfg(feature = "kerberos")]
    #[test]
    fn smb_client_builder_stores_kerberos_auth() {
        let builder = super::SmbClientBuilder::new().kerberos(
            smolder_core::prelude::KerberosCredentials::new("user", "pass"),
            smolder_core::prelude::KerberosTarget::for_smb_host("files1.lab.example"),
        );
        assert!(matches!(
            builder.auth,
            Some(super::SessionAuth::Kerberos { .. })
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
        response_frame_with_credits(command, status, message_id, session_id, tree_id, 1, body)
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
        let mut header = Header::new(command, MessageId(message_id));
        header.status = status;
        header.credit_request_response = credits;
        header.session_id = smolder_proto::smb::smb2::SessionId(session_id);
        header.tree_id = TreeId(tree_id);

        let mut packet = header.encode();
        packet.extend_from_slice(&body);
        SessionMessage::new(packet)
            .encode()
            .expect("response should frame")
    }

    fn outbound_create(frame: &[u8]) -> CreateRequest {
        let frame = SessionMessage::decode(frame).expect("frame should decode");
        CreateRequest::decode(&frame.payload[Header::LEN..]).expect("request should decode")
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

    fn outbound_query_directory(frame: &[u8]) -> QueryDirectoryRequest {
        let frame = SessionMessage::decode(frame).expect("frame should decode");
        QueryDirectoryRequest::decode(&frame.payload[Header::LEN..]).expect("request should decode")
    }

    fn outbound_query_info(frame: &[u8]) -> QueryInfoRequest {
        let frame = SessionMessage::decode(frame).expect("frame should decode");
        QueryInfoRequest::decode(&frame.payload[Header::LEN..]).expect("request should decode")
    }

    fn outbound_set_info(frame: &[u8]) -> SetInfoRequest {
        let frame = SessionMessage::decode(frame).expect("frame should decode");
        SetInfoRequest::decode(&frame.payload[Header::LEN..]).expect("request should decode")
    }

    fn outbound_ioctl(frame: &[u8]) -> IoctlRequest {
        let frame = SessionMessage::decode(frame).expect("frame should decode");
        IoctlRequest::decode(&frame.payload[Header::LEN..]).expect("request should decode")
    }

    #[test]
    fn open_options_map_to_expected_create_dispositions() {
        let open = OpenOptions::new().read(true);
        let open_request = open
            .to_create_request("docs/report.txt")
            .expect("open request should be valid");
        assert_eq!(open_request.create_disposition, CreateDisposition::Open);

        let create = OpenOptions::new().write(true).create(true);
        let create_request = create
            .to_create_request("docs/report.txt")
            .expect("create request should be valid");
        assert_eq!(create_request.create_disposition, CreateDisposition::OpenIf);

        let create_new = OpenOptions::new().write(true).create_new(true);
        let create_new_request = create_new
            .to_create_request("docs/report.txt")
            .expect("create-new request should be valid");
        assert_eq!(
            create_new_request.create_disposition,
            CreateDisposition::Create
        );

        let truncate = OpenOptions::new().write(true).truncate(true);
        let truncate_request = truncate
            .to_create_request("docs/report.txt")
            .expect("truncate request should be valid");
        assert_eq!(
            truncate_request.create_disposition,
            CreateDisposition::Overwrite
        );
    }

    #[test]
    fn invalid_open_options_are_rejected() {
        let error = OpenOptions::new()
            .to_create_request("notes.txt")
            .expect_err("open without access should fail");
        assert!(matches!(error, CoreError::InvalidInput(_)));

        let error = OpenOptions::new()
            .read(true)
            .truncate(true)
            .to_create_request("notes.txt")
            .expect_err("truncate without write should fail");
        assert!(matches!(error, CoreError::InvalidInput(_)));
    }

    #[test]
    fn share_paths_are_normalized() {
        let request = OpenOptions::new()
            .read(true)
            .to_create_request(r"/docs//nested\file.txt/")
            .expect("path should normalize");
        assert_eq!(
            request.name,
            smolder_proto::smb::smb2::utf16le("docs\\nested\\file.txt")
        );

        let dot_error = OpenOptions::new()
            .read(true)
            .to_create_request(r"docs\.\file.txt")
            .expect_err("relative segments should fail");
        assert!(matches!(dot_error, CoreError::PathInvalid(_)));

        let dot_dot_error = OpenOptions::new()
            .read(true)
            .to_create_request(r"docs\..\secret.txt")
            .expect_err("relative segments should fail");
        assert!(matches!(dot_dot_error, CoreError::PathInvalid(_)));
    }

    #[tokio::test]
    async fn open_with_lease_requests_lease_context_and_exposes_grant() {
        let granted_lease = LeaseV2::new(
            *b"lease-key-000000",
            LeaseState::READ_CACHING | LeaseState::HANDLE_CACHING,
        );
        let create_response = CreateResponse {
            oplock_level: OplockLevel::Lease,
            file_attributes: FileAttributes::ARCHIVE,
            allocation_size: 4,
            end_of_file: 4,
            file_id: FileId {
                persistent: 1,
                volatile: 2,
            },
            create_contexts: vec![CreateContext::lease_v2(granted_lease)],
        };
        let close_response = CloseResponse {
            flags: 0,
            allocation_size: 4,
            end_of_file: 4,
            file_attributes: FileAttributes::ARCHIVE,
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
                Command::Close,
                NtStatus::SUCCESS.to_u32(),
                4,
                11,
                7,
                close_response.encode(),
            ),
        ];

        let mut share = build_share(reads).await;
        let requested_lease = LeaseRequest::new(
            granted_lease.lease_key,
            LeaseState::READ_CACHING | LeaseState::HANDLE_CACHING,
        );
        let file = share
            .open(
                "notes.txt",
                OpenOptions::new().read(true).lease(requested_lease),
            )
            .await
            .expect("lease open should succeed");

        assert_eq!(
            file.lease().expect("lease should be present").key,
            granted_lease.lease_key
        );
        assert_eq!(
            file.lease().expect("lease should be present").state,
            granted_lease.lease_state
        );
        file.close().await.expect("close should succeed");

        let writes = transport_writes(share);
        let create = outbound_create(&writes[3]);
        assert_eq!(create.requested_oplock_level, RequestedOplockLevel::Lease);
        let requested = create.lease_v2().expect("lease should parse");
        assert_eq!(requested, Some(requested_lease.into_proto()));
    }

    #[tokio::test]
    async fn open_with_durable_handle_requests_v2_context_and_exposes_state() {
        let file_id = FileId {
            persistent: 0x11,
            volatile: 0x22,
        };
        let create_response = CreateResponse {
            oplock_level: OplockLevel::None,
            file_attributes: FileAttributes::ARCHIVE,
            allocation_size: 4,
            end_of_file: 4,
            file_id,
            create_contexts: vec![CreateContext::new(
                b"DH2Q".to_vec(),
                DurableHandleResponseV2 {
                    timeout: 30_000,
                    flags: DurableHandleFlags::PERSISTENT,
                }
                .encode(),
            )],
        };
        let close_response = CloseResponse {
            flags: 0,
            allocation_size: 4,
            end_of_file: 4,
            file_attributes: FileAttributes::ARCHIVE,
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
                Command::Close,
                NtStatus::SUCCESS.to_u32(),
                4,
                11,
                7,
                close_response.encode(),
            ),
        ];

        let mut share = build_share(reads).await;
        let durable = DurableOpenOptions::new()
            .with_timeout(30_000)
            .with_persistent(true);
        let file = share
            .open("notes.txt", OpenOptions::new().read(true).durable(durable))
            .await
            .expect("durable open should succeed");

        let durable_handle = file
            .durable_handle()
            .expect("durable state should be present");
        assert_eq!(durable_handle.file_id(), file_id);
        assert_eq!(durable_handle.timeout(), 30_000);
        assert_eq!(durable_handle.flags(), DurableHandleFlags::PERSISTENT);
        file.close().await.expect("close should succeed");

        let writes = transport_writes(share);
        let create = outbound_create(&writes[3]);
        let requested = create
            .create_contexts
            .iter()
            .find_map(|context| {
                context
                    .durable_handle_request_v2_data()
                    .expect("durable request should decode")
            })
            .expect("durable request v2 context should be present");
        assert_eq!(requested.timeout, 30_000);
        assert_eq!(requested.flags, DurableHandleFlags::PERSISTENT);
        assert_ne!(requested.create_guid, [0; 16]);
    }

    #[tokio::test]
    async fn open_with_resiliency_requests_ioctl_and_exposes_state() {
        let file_id = FileId {
            persistent: 0x33,
            volatile: 0x44,
        };
        let create_response = CreateResponse {
            oplock_level: OplockLevel::None,
            file_attributes: FileAttributes::ARCHIVE,
            allocation_size: 4,
            end_of_file: 4,
            file_id,
            create_contexts: Vec::new(),
        };
        let close_response = CloseResponse {
            flags: 0,
            allocation_size: 4,
            end_of_file: 4,
            file_attributes: FileAttributes::ARCHIVE,
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
                Command::Ioctl,
                NtStatus::SUCCESS.to_u32(),
                4,
                11,
                7,
                IoctlResponse {
                    ctl_code: CtlCode::FSCTL_LMR_REQUEST_RESILIENCY,
                    file_id,
                    input: Vec::new(),
                    output: Vec::new(),
                    flags: 0,
                }
                .encode(),
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

        let mut share = build_share(reads).await;
        let file = share
            .open("notes.txt", OpenOptions::new().read(true).resilient(45_000))
            .await
            .expect("resilient open should succeed");

        assert_eq!(
            file.resilient_handle(),
            Some(ResilientHandle {
                file_id,
                timeout: 45_000,
            })
        );
        file.close().await.expect("close should succeed");

        let writes = transport_writes(share);
        let ioctl = outbound_ioctl(&writes[4]);
        assert_eq!(ioctl.ctl_code, CtlCode::FSCTL_LMR_REQUEST_RESILIENCY);
        assert_eq!(ioctl.file_id, file_id);
        assert_eq!(
            NetworkResiliencyRequest::decode(&ioctl.input)
                .expect("resiliency request should decode"),
            NetworkResiliencyRequest { timeout: 45_000 }
        );
    }

    #[tokio::test]
    async fn reopen_durable_rebinds_handle_on_new_share_connection() {
        let original_file_id = FileId {
            persistent: 0x55,
            volatile: 0x66,
        };
        let reopened_file_id = FileId {
            persistent: 0x77,
            volatile: 0x88,
        };
        let original_response = CreateResponse {
            oplock_level: OplockLevel::None,
            file_attributes: FileAttributes::ARCHIVE,
            allocation_size: 8,
            end_of_file: 8,
            file_id: original_file_id,
            create_contexts: vec![CreateContext::new(
                b"DH2Q".to_vec(),
                DurableHandleResponseV2 {
                    timeout: 30_000,
                    flags: DurableHandleFlags::empty(),
                }
                .encode(),
            )],
        };
        let reopened_response = CreateResponse {
            oplock_level: OplockLevel::None,
            file_attributes: FileAttributes::ARCHIVE,
            allocation_size: 8,
            end_of_file: 8,
            file_id: reopened_file_id,
            create_contexts: vec![CreateContext::new(
                b"DH2Q".to_vec(),
                DurableHandleResponseV2 {
                    timeout: 30_000,
                    flags: DurableHandleFlags::empty(),
                }
                .encode(),
            )],
        };
        let close_response = CloseResponse {
            flags: 0,
            allocation_size: 8,
            end_of_file: 8,
            file_attributes: FileAttributes::ARCHIVE,
        };

        let mut original_share = build_share(vec![response_frame(
            Command::Create,
            NtStatus::SUCCESS.to_u32(),
            3,
            11,
            7,
            original_response.encode(),
        )])
        .await;
        let durable = original_share
            .open(
                "notes.txt",
                OpenOptions::new()
                    .read(true)
                    .durable(DurableOpenOptions::new().with_timeout(30_000)),
            )
            .await
            .expect("durable open should succeed")
            .durable_handle()
            .expect("durable state should be present")
            .clone();

        let reconnect_reads = vec![
            response_frame(
                Command::Create,
                NtStatus::SUCCESS.to_u32(),
                3,
                11,
                7,
                reopened_response.encode(),
            ),
            response_frame(
                Command::Close,
                NtStatus::SUCCESS.to_u32(),
                4,
                11,
                7,
                close_response.encode(),
            ),
        ];
        let mut reconnected_share = build_share(reconnect_reads).await;
        let file = reconnected_share
            .reopen_durable(&durable)
            .await
            .expect("durable reconnect should succeed");

        assert_eq!(file.file_id(), reopened_file_id);
        assert_eq!(
            file.durable_handle()
                .expect("durable state should remain present")
                .file_id(),
            reopened_file_id
        );
        file.close().await.expect("close should succeed");

        let writes = transport_writes(reconnected_share);
        let reconnect = outbound_create(&writes[3]);
        let requested = reconnect
            .create_contexts
            .iter()
            .find_map(|context| {
                context
                    .durable_handle_reconnect_v2_data()
                    .expect("durable reconnect should decode")
            })
            .expect("durable reconnect context should be present");
        assert_eq!(requested.file_id, original_file_id);
        assert_eq!(requested.flags, DurableHandleFlags::empty());
        assert_ne!(requested.create_guid, [0; 16]);
    }

    #[tokio::test]
    async fn reopen_durable_reapplies_saved_resiliency() {
        let original_file_id = FileId {
            persistent: 0xd1,
            volatile: 0xd2,
        };
        let reopened_file_id = FileId {
            persistent: 0xe1,
            volatile: 0xe2,
        };
        let durable_context = CreateContext::new(
            b"DH2Q".to_vec(),
            DurableHandleResponseV2 {
                timeout: 30_000,
                flags: DurableHandleFlags::empty(),
            }
            .encode(),
        );
        let original_response = CreateResponse {
            oplock_level: OplockLevel::None,
            file_attributes: FileAttributes::ARCHIVE,
            allocation_size: 8,
            end_of_file: 8,
            file_id: original_file_id,
            create_contexts: vec![durable_context.clone()],
        };
        let reopened_response = CreateResponse {
            oplock_level: OplockLevel::None,
            file_attributes: FileAttributes::ARCHIVE,
            allocation_size: 8,
            end_of_file: 8,
            file_id: reopened_file_id,
            create_contexts: vec![durable_context],
        };
        let close_response = CloseResponse {
            flags: 0,
            allocation_size: 8,
            end_of_file: 8,
            file_attributes: FileAttributes::ARCHIVE,
        };

        let mut original_share = build_share(vec![
            response_frame(
                Command::Create,
                NtStatus::SUCCESS.to_u32(),
                3,
                11,
                7,
                original_response.encode(),
            ),
            response_frame(
                Command::Ioctl,
                NtStatus::SUCCESS.to_u32(),
                4,
                11,
                7,
                IoctlResponse {
                    ctl_code: CtlCode::FSCTL_LMR_REQUEST_RESILIENCY,
                    file_id: original_file_id,
                    input: Vec::new(),
                    output: Vec::new(),
                    flags: 0,
                }
                .encode(),
            ),
        ])
        .await;
        let durable = original_share
            .open(
                "notes.txt",
                OpenOptions::new()
                    .read(true)
                    .durable(DurableOpenOptions::new().with_timeout(30_000))
                    .resilient(60_000),
            )
            .await
            .expect("durable resilient open should succeed")
            .durable_handle()
            .expect("durable state should be present")
            .clone();

        let reconnect_reads = vec![
            response_frame(
                Command::Create,
                NtStatus::SUCCESS.to_u32(),
                3,
                11,
                7,
                reopened_response.encode(),
            ),
            response_frame(
                Command::Ioctl,
                NtStatus::SUCCESS.to_u32(),
                4,
                11,
                7,
                IoctlResponse {
                    ctl_code: CtlCode::FSCTL_LMR_REQUEST_RESILIENCY,
                    file_id: reopened_file_id,
                    input: Vec::new(),
                    output: Vec::new(),
                    flags: 0,
                }
                .encode(),
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
        let mut reconnected_share = build_share(reconnect_reads).await;
        let file = reconnected_share
            .reopen_durable(&durable)
            .await
            .expect("durable reconnect should succeed");

        assert_eq!(
            file.resilient_handle(),
            Some(ResilientHandle {
                file_id: reopened_file_id,
                timeout: 60_000,
            })
        );
        assert_eq!(
            file.durable_handle()
                .expect("durable state should remain present")
                .resilient_timeout(),
            Some(60_000)
        );
        file.close().await.expect("close should succeed");

        let writes = transport_writes(reconnected_share);
        let reconnect = outbound_create(&writes[3]);
        let requested = reconnect
            .create_contexts
            .iter()
            .find_map(|context| {
                context
                    .durable_handle_reconnect_v2_data()
                    .expect("durable reconnect should decode")
            })
            .expect("durable reconnect context should be present");
        assert_eq!(requested.file_id, original_file_id);

        let ioctl = outbound_ioctl(&writes[4]);
        assert_eq!(ioctl.ctl_code, CtlCode::FSCTL_LMR_REQUEST_RESILIENCY);
        assert_eq!(ioctl.file_id, reopened_file_id);
        assert_eq!(
            NetworkResiliencyRequest::decode(&ioctl.input)
                .expect("resiliency request should decode"),
            NetworkResiliencyRequest { timeout: 60_000 }
        );
    }

    #[tokio::test]
    async fn reopened_durable_file_can_refresh_resiliency() {
        let original_file_id = FileId {
            persistent: 0x99,
            volatile: 0xaa,
        };
        let reopened_file_id = FileId {
            persistent: 0xbb,
            volatile: 0xcc,
        };
        let durable_context = CreateContext::new(
            b"DH2Q".to_vec(),
            DurableHandleResponseV2 {
                timeout: 30_000,
                flags: DurableHandleFlags::empty(),
            }
            .encode(),
        );
        let original_response = CreateResponse {
            oplock_level: OplockLevel::None,
            file_attributes: FileAttributes::ARCHIVE,
            allocation_size: 8,
            end_of_file: 8,
            file_id: original_file_id,
            create_contexts: vec![durable_context.clone()],
        };
        let reopened_response = CreateResponse {
            oplock_level: OplockLevel::None,
            file_attributes: FileAttributes::ARCHIVE,
            allocation_size: 8,
            end_of_file: 8,
            file_id: reopened_file_id,
            create_contexts: vec![durable_context],
        };
        let close_response = CloseResponse {
            flags: 0,
            allocation_size: 8,
            end_of_file: 8,
            file_attributes: FileAttributes::ARCHIVE,
        };

        let mut original_share = build_share(vec![response_frame(
            Command::Create,
            NtStatus::SUCCESS.to_u32(),
            3,
            11,
            7,
            original_response.encode(),
        )])
        .await;
        let durable = original_share
            .open(
                "notes.txt",
                OpenOptions::new()
                    .read(true)
                    .durable(DurableOpenOptions::new().with_timeout(30_000)),
            )
            .await
            .expect("durable open should succeed")
            .durable_handle()
            .expect("durable state should be present")
            .clone();

        let reconnect_reads = vec![
            response_frame(
                Command::Create,
                NtStatus::SUCCESS.to_u32(),
                3,
                11,
                7,
                reopened_response.encode(),
            ),
            response_frame(
                Command::Ioctl,
                NtStatus::SUCCESS.to_u32(),
                4,
                11,
                7,
                IoctlResponse {
                    ctl_code: CtlCode::FSCTL_LMR_REQUEST_RESILIENCY,
                    file_id: reopened_file_id,
                    input: Vec::new(),
                    output: Vec::new(),
                    flags: 0,
                }
                .encode(),
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
        let mut reconnected_share = build_share(reconnect_reads).await;
        let mut file = reconnected_share
            .reopen_durable(&durable)
            .await
            .expect("durable reconnect should succeed");

        let resilient = file
            .request_resiliency(60_000)
            .await
            .expect("resiliency refresh should succeed");
        assert_eq!(
            resilient,
            ResilientHandle {
                file_id: reopened_file_id,
                timeout: 60_000,
            }
        );
        assert_eq!(file.resilient_handle(), Some(resilient));
        file.close().await.expect("close should succeed");

        let writes = transport_writes(reconnected_share);
        let ioctl = outbound_ioctl(&writes[4]);
        assert_eq!(ioctl.ctl_code, CtlCode::FSCTL_LMR_REQUEST_RESILIENCY);
        assert_eq!(ioctl.file_id, reopened_file_id);
        assert_eq!(
            NetworkResiliencyRequest::decode(&ioctl.input)
                .expect("resiliency request should decode"),
            NetworkResiliencyRequest { timeout: 60_000 }
        );
    }

    #[tokio::test]
    async fn remote_file_reads_multiple_chunks() {
        let create_response = CreateResponse {
            oplock_level: OplockLevel::None,
            file_attributes: FileAttributes::ARCHIVE,
            allocation_size: 4,
            end_of_file: 7,
            file_id: FileId {
                persistent: 1,
                volatile: 2,
            },
            create_contexts: Vec::new(),
        };
        let close_response = CloseResponse {
            flags: 0,
            allocation_size: 4,
            end_of_file: 7,
            file_attributes: FileAttributes::ARCHIVE,
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
                    data: b"smol".to_vec(),
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
                    data: b"der".to_vec(),
                }
                .encode(),
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

        let mut share = build_share(reads).await;
        let data = share.read("notes.txt").await.expect("read should succeed");

        assert_eq!(data, b"smolder");

        let writes = transport_writes(share);
        let create = outbound_create(&writes[3]);
        assert_eq!(create.create_disposition, CreateDisposition::Open);

        let read_one = outbound_read(&writes[4]);
        assert_eq!(read_one.offset, 0);
        assert_eq!(read_one.length, 4);

        let read_two = outbound_read(&writes[5]);
        assert_eq!(read_two.offset, 4);
        assert_eq!(read_two.length, 3);
    }

    #[tokio::test]
    async fn remote_file_supports_async_read_and_seek_traits() {
        let create_response = CreateResponse {
            oplock_level: OplockLevel::None,
            file_attributes: FileAttributes::ARCHIVE,
            allocation_size: 4,
            end_of_file: 7,
            file_id: FileId {
                persistent: 1,
                volatile: 2,
            },
            create_contexts: Vec::new(),
        };
        let close_response = CloseResponse {
            flags: 0,
            allocation_size: 4,
            end_of_file: 7,
            file_attributes: FileAttributes::ARCHIVE,
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
                    data: b"smol".to_vec(),
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
                    data: b"lder".to_vec(),
                }
                .encode(),
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

        let mut share = build_share(reads).await;
        let mut file = share
            .open("notes.txt", OpenOptions::new().read(true))
            .await
            .expect("open should succeed");

        let mut prefix = [0_u8; 4];
        AsyncReadExt::read_exact(&mut file, &mut prefix)
            .await
            .expect("read_exact should succeed");
        assert_eq!(&prefix, b"smol");
        assert_eq!(file.position(), 4);

        let position = std::io::Seek::seek(&mut file, SeekFrom::Start(3))
            .expect("std::io::Seek should succeed");
        assert_eq!(position, 3);

        let async_position = AsyncSeekExt::seek(&mut file, SeekFrom::Current(0))
            .await
            .expect("AsyncSeek should report current position");
        assert_eq!(async_position, 3);

        let mut suffix = Vec::new();
        AsyncReadExt::read_to_end(&mut file, &mut suffix)
            .await
            .expect("read_to_end should succeed");
        assert_eq!(suffix, b"lder");
        file.close().await.expect("close should succeed");

        let writes = transport_writes(share);
        let read_one = outbound_read(&writes[4]);
        assert_eq!(read_one.offset, 0);
        assert_eq!(read_one.length, 4);

        let read_two = outbound_read(&writes[5]);
        assert_eq!(read_two.offset, 3);
        assert_eq!(read_two.length, 4);
    }

    #[tokio::test]
    async fn remote_file_writes_multiple_chunks() {
        let create_response = CreateResponse {
            oplock_level: OplockLevel::None,
            file_attributes: FileAttributes::ARCHIVE,
            allocation_size: 4,
            end_of_file: 0,
            file_id: FileId {
                persistent: 1,
                volatile: 2,
            },
            create_contexts: Vec::new(),
        };
        let close_response = CloseResponse {
            flags: 0,
            allocation_size: 8,
            end_of_file: 7,
            file_attributes: FileAttributes::ARCHIVE,
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
                WriteResponse { count: 4 }.encode(),
            ),
            response_frame(
                Command::Write,
                NtStatus::SUCCESS.to_u32(),
                5,
                11,
                7,
                WriteResponse { count: 3 }.encode(),
            ),
            response_frame(
                Command::Flush,
                NtStatus::SUCCESS.to_u32(),
                6,
                11,
                7,
                FlushResponse.encode(),
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

        let mut share = build_share(reads).await;
        share
            .write("notes.txt", b"smolder")
            .await
            .expect("write should succeed");

        let writes = transport_writes(share);
        let create = outbound_create(&writes[3]);
        assert_eq!(create.create_disposition, CreateDisposition::OverwriteIf);

        let write_one = outbound_write(&writes[4]);
        assert_eq!(write_one.offset, 0);
        assert_eq!(write_one.data, b"smol");

        let write_two = outbound_write(&writes[5]);
        assert_eq!(write_two.offset, 4);
        assert_eq!(write_two.data, b"der");

        let flush = outbound_flush(&writes[6]);
        assert_eq!(flush.file_id, create_response.file_id);
    }

    #[tokio::test]
    async fn remote_file_supports_async_write_traits() {
        let create_response = CreateResponse {
            oplock_level: OplockLevel::None,
            file_attributes: FileAttributes::ARCHIVE,
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
            allocation_size: 8,
            end_of_file: 7,
            file_attributes: FileAttributes::ARCHIVE,
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
                WriteResponse { count: 4 }.encode(),
            ),
            response_frame(
                Command::Write,
                NtStatus::SUCCESS.to_u32(),
                5,
                11,
                7,
                WriteResponse { count: 3 }.encode(),
            ),
            response_frame(
                Command::Flush,
                NtStatus::SUCCESS.to_u32(),
                6,
                11,
                7,
                FlushResponse.encode(),
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

        let mut share = build_share(reads).await;
        let mut file = share
            .open(
                "notes.txt",
                OpenOptions::new().write(true).create(true).truncate(true),
            )
            .await
            .expect("open should succeed");

        AsyncWriteExt::write_all(&mut file, b"smolder")
            .await
            .expect("trait write_all should succeed");
        AsyncWriteExt::flush(&mut file)
            .await
            .expect("trait flush should succeed");
        file.close().await.expect("close should succeed");

        let writes = transport_writes(share);
        let write_one = outbound_write(&writes[4]);
        assert_eq!(write_one.offset, 0);
        assert_eq!(write_one.data, b"smol");

        let write_two = outbound_write(&writes[5]);
        assert_eq!(write_two.offset, 4);
        assert_eq!(write_two.data, b"der");
    }

    #[tokio::test]
    async fn remote_file_flushes_current_handle() {
        let create_response = CreateResponse {
            oplock_level: OplockLevel::None,
            file_attributes: FileAttributes::ARCHIVE,
            allocation_size: 4,
            end_of_file: 4,
            file_id: FileId {
                persistent: 1,
                volatile: 2,
            },
            create_contexts: Vec::new(),
        };
        let close_response = CloseResponse {
            flags: 0,
            allocation_size: 4,
            end_of_file: 4,
            file_attributes: FileAttributes::ARCHIVE,
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
                Command::Flush,
                NtStatus::SUCCESS.to_u32(),
                4,
                11,
                7,
                FlushResponse.encode(),
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

        let mut share = build_share(reads).await;
        let mut file = share
            .open("notes.txt", OpenOptions::new().write(true))
            .await
            .expect("open should succeed");
        file.flush().await.expect("flush should succeed");
        file.close().await.expect("close should succeed");

        let writes = transport_writes(share);
        let flush = outbound_flush(&writes[4]);
        assert_eq!(flush.file_id, create_response.file_id);
    }

    #[tokio::test]
    async fn list_returns_directory_entries() {
        let create_response = CreateResponse {
            oplock_level: OplockLevel::None,
            file_attributes: FileAttributes::DIRECTORY,
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
            file_attributes: FileAttributes::DIRECTORY,
        };
        let listing = QueryDirectoryResponse {
            output_buffer: encode_directory_entries(&[
                DirectoryInformationEntry {
                    file_index: 1,
                    creation_time: 1,
                    last_access_time: 2,
                    last_write_time: 3,
                    change_time: 4,
                    end_of_file: 7,
                    allocation_size: 8,
                    file_attributes: FileAttributes::ARCHIVE,
                    file_name: "alpha.txt".to_string(),
                },
                DirectoryInformationEntry {
                    file_index: 2,
                    creation_time: 10,
                    last_access_time: 11,
                    last_write_time: 12,
                    change_time: 13,
                    end_of_file: 0,
                    allocation_size: 0,
                    file_attributes: FileAttributes::DIRECTORY,
                    file_name: "nested".to_string(),
                },
            ]),
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
                Command::QueryDirectory,
                NtStatus::SUCCESS.to_u32(),
                4,
                11,
                7,
                listing.encode(),
            ),
            response_frame(
                Command::QueryDirectory,
                NtStatus::NO_MORE_FILES.to_u32(),
                5,
                11,
                7,
                Vec::new(),
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

        let mut share = build_share(reads).await;
        let entries = share.list("").await.expect("list should succeed");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "alpha.txt");
        assert_eq!(entries[0].metadata.size, 7);
        assert!(entries[0].metadata.is_file());
        assert_eq!(entries[1].name, "nested");
        assert!(entries[1].metadata.is_directory());

        let writes = transport_writes(share);
        let create = outbound_create(&writes[3]);
        assert_eq!(create.create_options, CreateOptions::DIRECTORY_FILE);
        assert!(create.name.is_empty());
        assert_eq!(create.file_attributes, FileAttributes::DIRECTORY);

        let first_query = outbound_query_directory(&writes[4]);
        assert!(first_query
            .flags
            .contains(QueryDirectoryFlags::RESTART_SCANS));
        assert_eq!(
            first_query.file_name,
            smolder_proto::smb::smb2::utf16le("*")
        );

        let second_query = outbound_query_directory(&writes[5]);
        assert!(second_query.flags.is_empty());
    }

    #[tokio::test]
    async fn stat_reads_basic_and_standard_metadata() {
        let create_response = CreateResponse {
            oplock_level: OplockLevel::None,
            file_attributes: FileAttributes::ARCHIVE,
            allocation_size: 16,
            end_of_file: 7,
            file_id: FileId {
                persistent: 1,
                volatile: 2,
            },
            create_contexts: Vec::new(),
        };
        let close_response = CloseResponse {
            flags: 0,
            allocation_size: 16,
            end_of_file: 7,
            file_attributes: FileAttributes::ARCHIVE,
        };
        let basic_info = QueryInfoResponse {
            output_buffer: encode_basic_info(FileBasicInformation {
                creation_time: super::SEC_TO_UNIX_EPOCH * super::WINDOWS_TICK + 1,
                last_access_time: super::SEC_TO_UNIX_EPOCH * super::WINDOWS_TICK + 2,
                last_write_time: super::SEC_TO_UNIX_EPOCH * super::WINDOWS_TICK + 3,
                change_time: super::SEC_TO_UNIX_EPOCH * super::WINDOWS_TICK + 4,
                file_attributes: FileAttributes::ARCHIVE,
            }),
        };
        let standard_info = QueryInfoResponse {
            output_buffer: encode_standard_info(FileStandardInformation {
                allocation_size: 16,
                end_of_file: 7,
                number_of_links: 1,
                delete_pending: false,
                directory: false,
            }),
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
                Command::QueryInfo,
                NtStatus::SUCCESS.to_u32(),
                4,
                11,
                7,
                basic_info.encode(),
            ),
            response_frame(
                Command::QueryInfo,
                NtStatus::SUCCESS.to_u32(),
                5,
                11,
                7,
                standard_info.encode(),
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

        let mut share = build_share(reads).await;
        let metadata = share.stat("notes.txt").await.expect("stat should succeed");
        assert_eq!(metadata.size, 7);
        assert_eq!(metadata.allocation_size, 16);
        assert!(metadata.is_file());
        assert!(metadata.created.is_some());

        let writes = transport_writes(share);
        let first_query = outbound_query_info(&writes[4]);
        assert_eq!(first_query.file_info_class, FileInfoClass::BasicInformation);

        let second_query = outbound_query_info(&writes[5]);
        assert_eq!(
            second_query.file_info_class,
            FileInfoClass::StandardInformation
        );
    }

    #[tokio::test]
    async fn rename_updates_path_via_set_info() {
        let create_response = CreateResponse {
            oplock_level: OplockLevel::None,
            file_attributes: FileAttributes::ARCHIVE,
            allocation_size: 4,
            end_of_file: 4,
            file_id: FileId {
                persistent: 1,
                volatile: 2,
            },
            create_contexts: Vec::new(),
        };
        let close_response = CloseResponse {
            flags: 0,
            allocation_size: 4,
            end_of_file: 4,
            file_attributes: FileAttributes::ARCHIVE,
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
                Command::SetInfo,
                NtStatus::SUCCESS.to_u32(),
                4,
                11,
                7,
                SetInfoResponse.encode(),
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

        let mut share = build_share(reads).await;
        share
            .rename("notes.txt", "renamed.txt")
            .await
            .expect("rename should succeed");

        let writes = transport_writes(share);
        let set_info = outbound_set_info(&writes[4]);
        assert_eq!(set_info.file_info_class, FileInfoClass::RenameInformation);
        assert_eq!(
            set_info.buffer,
            smolder_proto::smb::smb2::RenameInformation::from_path("renamed.txt", false).encode()
        );
    }

    #[tokio::test]
    async fn remove_marks_file_delete_pending() {
        let create_response = CreateResponse {
            oplock_level: OplockLevel::None,
            file_attributes: FileAttributes::ARCHIVE,
            allocation_size: 4,
            end_of_file: 4,
            file_id: FileId {
                persistent: 1,
                volatile: 2,
            },
            create_contexts: Vec::new(),
        };
        let close_response = CloseResponse {
            flags: 0,
            allocation_size: 4,
            end_of_file: 4,
            file_attributes: FileAttributes::ARCHIVE,
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
                Command::SetInfo,
                NtStatus::SUCCESS.to_u32(),
                4,
                11,
                7,
                SetInfoResponse.encode(),
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

        let mut share = build_share(reads).await;
        share
            .remove("notes.txt")
            .await
            .expect("remove should succeed");

        let writes = transport_writes(share);
        let set_info = outbound_set_info(&writes[4]);
        assert_eq!(
            set_info.file_info_class,
            FileInfoClass::DispositionInformation
        );
        assert_eq!(set_info.buffer, vec![1]);
    }

    #[tokio::test]
    async fn share_disconnect_returns_authenticated_client() {
        let next_tree = TreeConnectResponse {
            share_type: ShareType::Disk,
            share_flags: ShareFlags::ENCRYPT_DATA,
            capabilities: TreeCapabilities::CONTINUOUS_AVAILABILITY,
            maximal_access: 0x0012_019f,
        };

        let reads = vec![
            response_frame(
                Command::TreeDisconnect,
                NtStatus::SUCCESS.to_u32(),
                3,
                11,
                7,
                TreeDisconnectResponse.encode(),
            ),
            response_frame(
                Command::TreeConnect,
                NtStatus::SUCCESS.to_u32(),
                4,
                11,
                9,
                next_tree.encode(),
            ),
        ];

        let share = build_share(reads).await;
        let client = share.disconnect().await.expect("disconnect should succeed");
        let share = client
            .share("archive")
            .await
            .expect("second tree connect should succeed");

        let writes = transport_writes(share);
        let disconnect_header = Header::decode(
            &SessionMessage::decode(&writes[3])
                .expect("frame should decode")
                .payload[..Header::LEN],
        )
        .expect("header should decode");
        assert_eq!(disconnect_header.command, Command::TreeDisconnect);

        let reconnect = SessionMessage::decode(&writes[4]).expect("frame should decode");
        let reconnect_header =
            Header::decode(&reconnect.payload[..Header::LEN]).expect("header should decode");
        assert_eq!(reconnect_header.command, Command::TreeConnect);
        let reconnect_request = TreeConnectRequest::decode(&reconnect.payload[Header::LEN..])
            .expect("request should decode");
        assert_eq!(
            reconnect_request.path,
            smolder_proto::smb::smb2::utf16le(r"\\server\archive")
        );
    }

    #[tokio::test]
    async fn share_rejects_tree_connects_that_do_not_require_encryption() {
        let tree_response = TreeConnectResponse {
            share_type: ShareType::Disk,
            share_flags: ShareFlags::empty(),
            capabilities: TreeCapabilities::empty(),
            maximal_access: 0x0012_019f,
        };

        let mut client = build_client_with_tree_response("server", tree_response, Vec::new()).await;
        client.require_encryption = true;

        let error = client
            .share("share")
            .await
            .expect_err("unencrypted share should be rejected");
        assert!(matches!(
            error,
            CoreError::Unsupported(
                "SMB encryption was required but the connected share did not require encryption"
            )
        ));
    }

    #[tokio::test]
    async fn share_accepts_tree_connects_that_require_encryption() {
        let tree_response = TreeConnectResponse {
            share_type: ShareType::Disk,
            share_flags: ShareFlags::ENCRYPT_DATA,
            capabilities: TreeCapabilities::empty(),
            maximal_access: 0x0012_019f,
        };

        let mut client = build_client_with_tree_response("server", tree_response, Vec::new()).await;
        client.require_encryption = true;

        let share = client
            .share("share")
            .await
            .expect("encrypted share should be accepted");
        assert_eq!(share.server(), "server");
        assert_eq!(share.name(), "share");
    }

    #[tokio::test]
    async fn share_path_with_referrals_connects_to_resolved_backend_share() {
        let tree_response = TreeConnectResponse {
            share_type: ShareType::Disk,
            share_flags: ShareFlags::empty(),
            capabilities: TreeCapabilities::empty(),
            maximal_access: 0x0012_019f,
        };
        let client = build_client(
            "server-b",
            vec![response_frame(
                Command::TreeConnect,
                NtStatus::SUCCESS.to_u32(),
                2,
                11,
                7,
                tree_response.encode(),
            )],
        )
        .await;
        let referrals = vec![DfsReferral::new(
            UncPath::parse(r"\\domain\dfs\team").expect("namespace should parse"),
            UncPath::parse(r"\\server-b\teamshare\docsroot").expect("target should parse"),
        )];

        let (share, relative_path) = client
            .share_path_with_referrals(r"\\domain\dfs\team\report.txt", &referrals)
            .await
            .expect("DFS share path should resolve");

        assert_eq!(share.server(), "server-b");
        assert_eq!(share.name(), "teamshare");
        assert_eq!(relative_path, r"docsroot\report.txt");

        let writes = transport_writes(share);
        let tree_connect = SessionMessage::decode(&writes[2]).expect("frame should decode");
        let request = TreeConnectRequest::decode(&tree_connect.payload[Header::LEN..])
            .expect("request should decode");
        assert_eq!(
            request.path,
            smolder_proto::smb::smb2::utf16le(r"\\server-b\teamshare")
        );
    }

    #[tokio::test]
    async fn share_path_with_referrals_rejects_different_backend_host() {
        let client = build_client("server-a", Vec::new()).await;
        let referrals = vec![DfsReferral::new(
            UncPath::parse(r"\\domain\dfs\team").expect("namespace should parse"),
            UncPath::parse(r"\\server-b\teamshare\docsroot").expect("target should parse"),
        )];

        let error = client
            .share_path_with_referrals(r"\\domain\dfs\team\report.txt", &referrals)
            .await
            .expect_err("different backend host should fail");

        assert_eq!(
            error.to_string(),
            "invalid path: resolved UNC host does not match the connected SMB session"
        );
    }

    #[tokio::test]
    async fn share_path_auto_falls_back_to_direct_share_when_dfs_query_is_not_covered() {
        let ipc_response = TreeConnectResponse {
            share_type: ShareType::Pipe,
            share_flags: ShareFlags::empty(),
            capabilities: TreeCapabilities::empty(),
            maximal_access: 0x0012_019f,
        };
        let share_response = TreeConnectResponse {
            share_type: ShareType::Disk,
            share_flags: ShareFlags::empty(),
            capabilities: TreeCapabilities::empty(),
            maximal_access: 0x0012_019f,
        };
        let client = build_client_with_tree_response(
            "server",
            ipc_response,
            vec![
                response_frame_with_credits(
                    Command::Ioctl,
                    NtStatus::PATH_NOT_COVERED.to_u32(),
                    3,
                    11,
                    7,
                    1,
                    Vec::new(),
                ),
                response_frame(
                    Command::TreeDisconnect,
                    NtStatus::SUCCESS.to_u32(),
                    4,
                    11,
                    7,
                    TreeDisconnectResponse.encode(),
                ),
                response_frame(
                    Command::TreeConnect,
                    NtStatus::SUCCESS.to_u32(),
                    5,
                    11,
                    9,
                    share_response.encode(),
                ),
            ],
        )
        .await;

        let (share, relative_path) = client
            .share_path_auto(r"\\server\share\docs\report.txt")
            .await
            .expect("non-DFS path should fall back to direct share");

        assert_eq!(share.server(), "server");
        assert_eq!(share.name(), "share");
        assert_eq!(relative_path, r"docs\report.txt");

        let writes = transport_writes(share);
        let ipc_tree_connect = SessionMessage::decode(&writes[2]).expect("frame should decode");
        let ipc_request = TreeConnectRequest::decode(&ipc_tree_connect.payload[Header::LEN..])
            .expect("request should decode");
        assert_eq!(
            ipc_request.path,
            smolder_proto::smb::smb2::utf16le(r"\\server\IPC$")
        );

        let ioctl = outbound_ioctl(&writes[3]);
        assert_eq!(ioctl.ctl_code, CtlCode::FSCTL_DFS_GET_REFERRALS);
        let disconnect = SessionMessage::decode(&writes[4]).expect("frame should decode");
        let disconnect_header =
            Header::decode(&disconnect.payload[..Header::LEN]).expect("header should decode");
        assert_eq!(disconnect_header.command, Command::TreeDisconnect);

        let share_tree_connect = SessionMessage::decode(&writes[5]).expect("frame should decode");
        let share_request = TreeConnectRequest::decode(&share_tree_connect.payload[Header::LEN..])
            .expect("request should decode");
        assert_eq!(
            share_request.path,
            smolder_proto::smb::smb2::utf16le(r"\\server\share")
        );
    }

    #[tokio::test]
    async fn share_path_auto_falls_back_to_direct_share_when_dfs_query_returns_not_found() {
        let ipc_response = TreeConnectResponse {
            share_type: ShareType::Pipe,
            share_flags: ShareFlags::empty(),
            capabilities: TreeCapabilities::empty(),
            maximal_access: 0x0012_019f,
        };
        let share_response = TreeConnectResponse {
            share_type: ShareType::Disk,
            share_flags: ShareFlags::empty(),
            capabilities: TreeCapabilities::empty(),
            maximal_access: 0x0012_019f,
        };
        let client = build_client_with_tree_response(
            "server",
            ipc_response,
            vec![
                response_frame_with_credits(
                    Command::Ioctl,
                    NtStatus::NOT_FOUND.to_u32(),
                    3,
                    11,
                    7,
                    1,
                    Vec::new(),
                ),
                response_frame(
                    Command::TreeDisconnect,
                    NtStatus::SUCCESS.to_u32(),
                    4,
                    11,
                    7,
                    TreeDisconnectResponse.encode(),
                ),
                response_frame(
                    Command::TreeConnect,
                    NtStatus::SUCCESS.to_u32(),
                    5,
                    11,
                    9,
                    share_response.encode(),
                ),
            ],
        )
        .await;

        let (share, relative_path) = client
            .share_path_auto(r"\\server\share\docs\report.txt")
            .await
            .expect("not-found DFS query should fall back to direct share");

        assert_eq!(share.server(), "server");
        assert_eq!(share.name(), "share");
        assert_eq!(relative_path, r"docs\report.txt");
    }

    #[tokio::test]
    async fn share_path_auto_falls_back_to_direct_share_when_dfs_driver_is_unavailable() {
        let ipc_response = TreeConnectResponse {
            share_type: ShareType::Pipe,
            share_flags: ShareFlags::empty(),
            capabilities: TreeCapabilities::empty(),
            maximal_access: 0x0012_019f,
        };
        let share_response = TreeConnectResponse {
            share_type: ShareType::Disk,
            share_flags: ShareFlags::empty(),
            capabilities: TreeCapabilities::empty(),
            maximal_access: 0x0012_019f,
        };
        let client = build_client_with_tree_response(
            "server",
            ipc_response,
            vec![
                response_frame_with_credits(
                    Command::Ioctl,
                    NtStatus::FS_DRIVER_REQUIRED.to_u32(),
                    3,
                    11,
                    7,
                    1,
                    Vec::new(),
                ),
                response_frame(
                    Command::TreeDisconnect,
                    NtStatus::SUCCESS.to_u32(),
                    4,
                    11,
                    7,
                    TreeDisconnectResponse.encode(),
                ),
                response_frame(
                    Command::TreeConnect,
                    NtStatus::SUCCESS.to_u32(),
                    5,
                    11,
                    9,
                    share_response.encode(),
                ),
            ],
        )
        .await;

        let (share, relative_path) = client
            .share_path_auto(r"\\server\share\docs\report.txt")
            .await
            .expect("non-DFS path should fall back when DFS driver is unavailable");

        assert_eq!(share.server(), "server");
        assert_eq!(share.name(), "share");
        assert_eq!(relative_path, r"docs\report.txt");
    }

    #[tokio::test]
    async fn share_path_auto_resolves_dfs_namespace_when_referrals_are_available() {
        let ipc_response = TreeConnectResponse {
            share_type: ShareType::Pipe,
            share_flags: ShareFlags::empty(),
            capabilities: TreeCapabilities::empty(),
            maximal_access: 0x0012_019f,
        };
        let share_response = TreeConnectResponse {
            share_type: ShareType::Disk,
            share_flags: ShareFlags::empty(),
            capabilities: TreeCapabilities::empty(),
            maximal_access: 0x0012_019f,
        };
        let client = build_client_with_tree_response(
            "server",
            ipc_response,
            vec![
                response_frame(
                    Command::Ioctl,
                    NtStatus::SUCCESS.to_u32(),
                    3,
                    11,
                    7,
                    IoctlResponse {
                        ctl_code: CtlCode::FSCTL_DFS_GET_REFERRALS,
                        file_id: FileId::NONE,
                        input: Vec::new(),
                        output: encode_dfs_referral_response(
                            r"\\server\dfs\team",
                            Some(r"\\server\dfs"),
                            r"\\server\teamshare\docsroot",
                        ),
                        flags: 0,
                    }
                    .encode(),
                ),
                response_frame(
                    Command::TreeDisconnect,
                    NtStatus::SUCCESS.to_u32(),
                    4,
                    11,
                    7,
                    TreeDisconnectResponse.encode(),
                ),
                response_frame(
                    Command::TreeConnect,
                    NtStatus::SUCCESS.to_u32(),
                    5,
                    11,
                    9,
                    share_response.encode(),
                ),
            ],
        )
        .await;

        let (share, relative_path) = client
            .share_path_auto(r"\\server\dfs\team\report.txt")
            .await
            .expect("DFS namespace should resolve over IPC$");

        assert_eq!(share.server(), "server");
        assert_eq!(share.name(), "teamshare");
        assert_eq!(relative_path, r"docsroot\report.txt");
    }

    #[tokio::test]
    async fn connect_share_path_follows_cross_server_dfs_referral_targets() {
        let ipc_response = TreeConnectResponse {
            share_type: ShareType::Pipe,
            share_flags: ShareFlags::empty(),
            capabilities: TreeCapabilities::empty(),
            maximal_access: 0x0012_019f,
        };
        let share_response = TreeConnectResponse {
            share_type: ShareType::Disk,
            share_flags: ShareFlags::empty(),
            capabilities: TreeCapabilities::empty(),
            maximal_access: 0x0012_019f,
        };
        let namespace_client = build_client_with_tree_response(
            "namespace",
            ipc_response.clone(),
            vec![
                response_frame(
                    Command::Ioctl,
                    NtStatus::SUCCESS.to_u32(),
                    3,
                    11,
                    7,
                    IoctlResponse {
                        ctl_code: CtlCode::FSCTL_DFS_GET_REFERRALS,
                        file_id: FileId::NONE,
                        input: Vec::new(),
                        output: encode_dfs_referral_response(
                            r"\\namespace\dfs\team",
                            Some(r"\\namespace\dfs"),
                            r"\\backend\teamshare\docsroot",
                        ),
                        flags: 0,
                    }
                    .encode(),
                ),
                response_frame(
                    Command::TreeDisconnect,
                    NtStatus::SUCCESS.to_u32(),
                    4,
                    11,
                    7,
                    TreeDisconnectResponse.encode(),
                ),
            ],
        )
        .await;
        let backend_client = build_client_with_tree_response(
            "backend",
            ipc_response,
            vec![
                response_frame_with_credits(
                    Command::Ioctl,
                    NtStatus::PATH_NOT_COVERED.to_u32(),
                    3,
                    11,
                    7,
                    1,
                    Vec::new(),
                ),
                response_frame(
                    Command::TreeDisconnect,
                    NtStatus::SUCCESS.to_u32(),
                    4,
                    11,
                    7,
                    TreeDisconnectResponse.encode(),
                ),
                response_frame(
                    Command::TreeConnect,
                    NtStatus::SUCCESS.to_u32(),
                    5,
                    11,
                    9,
                    share_response.encode(),
                ),
            ],
        )
        .await;

        let attempts = Arc::new(Mutex::new(Vec::new()));
        let attempts_ref = Arc::clone(&attempts);
        let clients = Arc::new(Mutex::new(BTreeMap::from([
            ("namespace".to_string(), VecDeque::from([namespace_client])),
            ("backend".to_string(), VecDeque::from([backend_client])),
        ])));
        let clients_ref = Arc::clone(&clients);

        let (share, relative_path) =
            super::connect_share_path_with_resolver::<ScriptedTransport, _, _>(
                r"\\namespace\dfs\team\report.txt",
                move |server: String| {
                    attempts_ref
                        .lock()
                        .expect("attempt log should remain accessible")
                        .push(server.clone());
                    let client = clients_ref
                        .lock()
                        .expect("client registry should remain accessible")
                        .get_mut(&server)
                        .and_then(VecDeque::pop_front)
                        .ok_or(CoreError::InvalidInput("missing scripted DFS client"));
                    std::future::ready(client)
                },
            )
            .await
            .expect("cross-server DFS target should reconnect with a fresh client");

        assert_eq!(share.server(), "backend");
        assert_eq!(share.name(), "teamshare");
        assert_eq!(relative_path, r"docsroot\report.txt");
        assert_eq!(
            *attempts.lock().expect("attempt log should remain readable"),
            vec!["namespace".to_string(), "backend".to_string()]
        );
    }

    #[tokio::test]
    async fn share_path_resolving_dfs_queries_ipc_and_connects_resolved_share() {
        let ipc_response = TreeConnectResponse {
            share_type: ShareType::Pipe,
            share_flags: ShareFlags::empty(),
            capabilities: TreeCapabilities::empty(),
            maximal_access: 0x0012_019f,
        };
        let share_response = TreeConnectResponse {
            share_type: ShareType::Disk,
            share_flags: ShareFlags::empty(),
            capabilities: TreeCapabilities::empty(),
            maximal_access: 0x0012_019f,
        };
        let client = build_client_with_tree_response(
            "server",
            ipc_response,
            vec![
                response_frame(
                    Command::Ioctl,
                    NtStatus::SUCCESS.to_u32(),
                    3,
                    11,
                    7,
                    IoctlResponse {
                        ctl_code: CtlCode::FSCTL_DFS_GET_REFERRALS,
                        file_id: FileId::NONE,
                        input: Vec::new(),
                        output: encode_dfs_referral_response(
                            r"\\server\dfs\team",
                            Some(r"\\server\dfs"),
                            r"\\server\teamshare\docsroot",
                        ),
                        flags: 0,
                    }
                    .encode(),
                ),
                response_frame(
                    Command::TreeDisconnect,
                    NtStatus::SUCCESS.to_u32(),
                    4,
                    11,
                    7,
                    TreeDisconnectResponse.encode(),
                ),
                response_frame(
                    Command::TreeConnect,
                    NtStatus::SUCCESS.to_u32(),
                    5,
                    11,
                    9,
                    share_response.encode(),
                ),
            ],
        )
        .await;

        let (share, relative_path) = client
            .share_path_resolving_dfs(r"\\server\dfs\team\report.txt")
            .await
            .expect("DFS share path should resolve through IPC$");

        assert_eq!(share.server(), "server");
        assert_eq!(share.name(), "teamshare");
        assert_eq!(relative_path, r"docsroot\report.txt");

        let writes = transport_writes(share);
        let ipc_tree_connect = SessionMessage::decode(&writes[2]).expect("frame should decode");
        let ipc_request = TreeConnectRequest::decode(&ipc_tree_connect.payload[Header::LEN..])
            .expect("request should decode");
        assert_eq!(
            ipc_request.path,
            smolder_proto::smb::smb2::utf16le(r"\\server\IPC$")
        );

        let ioctl = outbound_ioctl(&writes[3]);
        assert_eq!(ioctl.ctl_code, CtlCode::FSCTL_DFS_GET_REFERRALS);
        let dfs_request =
            DfsReferralRequest::decode(&ioctl.input).expect("DFS request should decode");
        assert_eq!(dfs_request.max_referral_level, 4);
        assert_eq!(
            dfs_request.request_file_name,
            r"\\server\dfs\team\report.txt"
        );

        let disconnect = SessionMessage::decode(&writes[4]).expect("frame should decode");
        let disconnect_header =
            Header::decode(&disconnect.payload[..Header::LEN]).expect("header should decode");
        assert_eq!(disconnect_header.command, Command::TreeDisconnect);

        let share_tree_connect = SessionMessage::decode(&writes[5]).expect("frame should decode");
        let share_request = TreeConnectRequest::decode(&share_tree_connect.payload[Header::LEN..])
            .expect("request should decode");
        assert_eq!(
            share_request.path,
            smolder_proto::smb::smb2::utf16le(r"\\server\teamshare")
        );
    }

    #[tokio::test]
    async fn share_path_resolving_dfs_rejects_cross_server_referral_targets() {
        let ipc_response = TreeConnectResponse {
            share_type: ShareType::Pipe,
            share_flags: ShareFlags::empty(),
            capabilities: TreeCapabilities::empty(),
            maximal_access: 0x0012_019f,
        };
        let client = build_client_with_tree_response(
            "server-a",
            ipc_response,
            vec![
                response_frame(
                    Command::Ioctl,
                    NtStatus::SUCCESS.to_u32(),
                    3,
                    11,
                    7,
                    IoctlResponse {
                        ctl_code: CtlCode::FSCTL_DFS_GET_REFERRALS,
                        file_id: FileId::NONE,
                        input: Vec::new(),
                        output: encode_dfs_referral_response(
                            r"\\server-a\dfs\team",
                            None,
                            r"\\server-b\teamshare\docsroot",
                        ),
                        flags: 0,
                    }
                    .encode(),
                ),
                response_frame(
                    Command::TreeDisconnect,
                    NtStatus::SUCCESS.to_u32(),
                    4,
                    11,
                    7,
                    TreeDisconnectResponse.encode(),
                ),
            ],
        )
        .await;

        let error = client
            .share_path_resolving_dfs(r"\\server-a\dfs\team\report.txt")
            .await
            .expect_err("cross-server DFS targets should fail");

        assert_eq!(
            error.to_string(),
            "invalid path: resolved UNC host does not match the connected SMB session"
        );
    }

    async fn build_client(server: &str, reads: Vec<Vec<u8>>) -> SmbClient<ScriptedTransport> {
        let tree_response = TreeConnectResponse {
            share_type: ShareType::Disk,
            share_flags: ShareFlags::empty(),
            capabilities: TreeCapabilities::empty(),
            maximal_access: 0x0012_019f,
        };
        build_client_with_tree_response(server, tree_response, reads).await
    }

    async fn build_client_with_tree_response(
        server: &str,
        tree_response: TreeConnectResponse,
        reads: Vec<Vec<u8>>,
    ) -> SmbClient<ScriptedTransport> {
        let negotiate_response = NegotiateResponse {
            security_mode: SigningMode::ENABLED,
            dialect_revision: Dialect::Smb302,
            negotiate_contexts: Vec::new(),
            server_guid: *b"server-guid-0001",
            capabilities: GlobalCapabilities::LARGE_MTU | GlobalCapabilities::LEASING,
            max_transact_size: 65_536,
            max_read_size: 4,
            max_write_size: 4,
            system_time: 1,
            server_start_time: 1,
            security_buffer: Vec::new(),
        };
        let session_response = SessionSetupResponse {
            session_flags: SessionFlags::empty(),
            security_buffer: Vec::new(),
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
            .session_setup(&session_request)
            .await
            .expect("session setup should succeed");
        SmbClient::from_connection(server, connection).with_transfer_chunk_size(4)
    }

    async fn build_share(reads: Vec<Vec<u8>>) -> Share<ScriptedTransport> {
        let client = build_client("server", reads).await;
        client
            .share("share")
            .await
            .expect("tree connect should succeed")
    }

    fn transport_writes(share: Share<ScriptedTransport>) -> Vec<Vec<u8>> {
        share
            .connection
            .expect("share connection should be present once the file handle is closed")
            .into_transport()
            .writes
    }

    fn encode_dfs_referral_response(
        dfs_path: &str,
        alternate_path: Option<&str>,
        network_address: &str,
    ) -> Vec<u8> {
        let dfs_path = smolder_proto::smb::smb2::utf16le(dfs_path);
        let alternate_path = alternate_path.map(smolder_proto::smb::smb2::utf16le);
        let network_address = smolder_proto::smb::smb2::utf16le(network_address);

        let dfs_path_offset = 24u16;
        let mut next_offset = dfs_path_offset + dfs_path.len() as u16 + 2;
        let alternate_path_offset = alternate_path.as_ref().map(|encoded| {
            let offset = next_offset;
            next_offset += encoded.len() as u16 + 2;
            offset
        });
        let network_address_offset = next_offset;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&DfsReferralHeaderFlags::STORAGE_SERVERS.bits().to_le_bytes());
        bytes.extend_from_slice(&4u16.to_le_bytes());
        bytes.extend_from_slice(&24u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(
            &DfsReferralEntryFlags::TARGET_SET_BOUNDARY
                .bits()
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&300u32.to_le_bytes());
        bytes.extend_from_slice(&dfs_path_offset.to_le_bytes());
        bytes.extend_from_slice(&alternate_path_offset.unwrap_or(0).to_le_bytes());
        bytes.extend_from_slice(&network_address_offset.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 6]);
        bytes.extend_from_slice(&dfs_path);
        bytes.extend_from_slice(&0u16.to_le_bytes());
        if let Some(alternate_path) = alternate_path {
            bytes.extend_from_slice(&alternate_path);
            bytes.extend_from_slice(&0u16.to_le_bytes());
        }
        bytes.extend_from_slice(&network_address);
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes
    }

    fn encode_directory_entries(entries: &[DirectoryInformationEntry]) -> Vec<u8> {
        let mut buffer = Vec::new();
        for (index, entry) in entries.iter().enumerate() {
            let file_name = smolder_proto::smb::smb2::utf16le(&entry.file_name);
            let entry_len = 64 + file_name.len();
            let padded_len = if index + 1 == entries.len() {
                entry_len
            } else {
                (entry_len + 7) & !7
            };
            let next_entry_offset = if index + 1 == entries.len() {
                0
            } else {
                padded_len as u32
            };

            buffer.extend_from_slice(&next_entry_offset.to_le_bytes());
            buffer.extend_from_slice(&entry.file_index.to_le_bytes());
            buffer.extend_from_slice(&entry.creation_time.to_le_bytes());
            buffer.extend_from_slice(&entry.last_access_time.to_le_bytes());
            buffer.extend_from_slice(&entry.last_write_time.to_le_bytes());
            buffer.extend_from_slice(&entry.change_time.to_le_bytes());
            buffer.extend_from_slice(&entry.end_of_file.to_le_bytes());
            buffer.extend_from_slice(&entry.allocation_size.to_le_bytes());
            buffer.extend_from_slice(&entry.file_attributes.bits().to_le_bytes());
            buffer.extend_from_slice(&(file_name.len() as u32).to_le_bytes());
            buffer.extend_from_slice(&file_name);
            if padded_len > entry_len {
                buffer.resize(buffer.len() + (padded_len - entry_len), 0);
            }
        }
        buffer
    }

    fn encode_basic_info(info: FileBasicInformation) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&info.creation_time.to_le_bytes());
        buffer.extend_from_slice(&info.last_access_time.to_le_bytes());
        buffer.extend_from_slice(&info.last_write_time.to_le_bytes());
        buffer.extend_from_slice(&info.change_time.to_le_bytes());
        buffer.extend_from_slice(&info.file_attributes.bits().to_le_bytes());
        buffer.extend_from_slice(&0_u32.to_le_bytes());
        buffer
    }

    fn encode_standard_info(info: FileStandardInformation) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&info.allocation_size.to_le_bytes());
        buffer.extend_from_slice(&info.end_of_file.to_le_bytes());
        buffer.extend_from_slice(&info.number_of_links.to_le_bytes());
        buffer.push(u8::from(info.delete_pending));
        buffer.push(u8::from(info.directory));
        buffer.extend_from_slice(&0_u16.to_le_bytes());
        buffer
    }
}
