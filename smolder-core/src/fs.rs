//! High-level SMB2 file APIs built on top of the typestate client.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::BytesMut;
use rand::random;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

use smolder_proto::smb::smb2::{
    CloseRequest, CloseResponse, CreateDisposition, CreateOptions, CreateRequest, Dialect,
    DispositionInformation, FileAttributes, FileBasicInformation, FileId, FileInfoClass,
    FileStandardInformation, FlushRequest, GlobalCapabilities, NegotiateContext, NegotiateRequest,
    PreauthIntegrityCapabilities, PreauthIntegrityHashId, QueryDirectoryFlags,
    QueryDirectoryRequest, QueryInfoRequest, ReadRequest, RenameInformation, SetInfoRequest,
    ShareAccess, SigningMode, TreeConnectRequest, WriteRequest,
};

use crate::auth::{NtlmAuthenticator, NtlmCredentials};
use crate::client::{Authenticated, Connection, TreeConnected};
use crate::error::CoreError;
use crate::transport::{TokioTcpTransport, Transport};

const DEFAULT_PORT: u16 = 445;
const DEFAULT_TRANSFER_CHUNK_SIZE: u32 = 64 * 1024;
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
    credentials: Option<NtlmCredentials>,
    signing_mode: SigningMode,
    capabilities: GlobalCapabilities,
    dialects: Vec<Dialect>,
    client_guid: [u8; 16],
    transfer_chunk_size: u32,
}

impl Default for SmbClientBuilder {
    fn default() -> Self {
        Self {
            server: None,
            port: DEFAULT_PORT,
            credentials: None,
            signing_mode: SigningMode::ENABLED,
            capabilities: GlobalCapabilities::LARGE_MTU,
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
        self.credentials = Some(credentials);
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
        let credentials = self
            .credentials
            .ok_or(CoreError::InvalidInput("credentials must be configured"))?;

        let transport = TokioTcpTransport::connect((server.as_str(), self.port)).await?;
        let request = NegotiateRequest {
            security_mode: self.signing_mode,
            capabilities: self.capabilities,
            client_guid: self.client_guid,
            negotiate_contexts: default_negotiate_contexts(&self.dialects),
            dialects: self.dialects,
        };
        let connection = Connection::new(transport).negotiate(&request).await?;

        let mut auth = NtlmAuthenticator::new(credentials);
        let connection = connection.authenticate(&mut auth).await?;
        Ok(SmbClient {
            server,
            connection,
            transfer_chunk_size: self.transfer_chunk_size,
        })
    }
}

/// An authenticated SMB session that can connect to a share.
#[derive(Debug)]
pub struct SmbClient<T = TokioTcpTransport> {
    server: String,
    connection: Connection<T, Authenticated>,
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

        Ok(Share {
            server: self.server,
            name: share,
            connection,
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
}

/// A connected SMB share that provides path-oriented file operations.
#[derive(Debug)]
pub struct Share<T = TokioTcpTransport> {
    server: String,
    name: String,
    connection: Connection<T, TreeConnected>,
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
            connection,
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
    /// Disconnects the current tree and returns to the authenticated client session.
    pub async fn disconnect(self) -> Result<SmbClient<T>, CoreError> {
        let Share {
            server,
            connection,
            transfer_chunk_size,
            ..
        } = self;
        let connection = connection.tree_disconnect().await?;

        Ok(SmbClient {
            server,
            connection,
            transfer_chunk_size,
        })
    }

    /// Opens a remote file on the connected share.
    pub async fn open<'a>(
        &'a mut self,
        path: impl AsRef<str>,
        options: OpenOptions,
    ) -> Result<RemoteFile<'a, T>, CoreError> {
        let request = options.to_create_request(path.as_ref())?;
        let response = self.connection.create(&request).await?;

        Ok(RemoteFile {
            share: self,
            file_id: response.file_id,
            position: 0,
            end_of_file: response.end_of_file,
            closed: false,
        })
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
                let response = self.connection.query_directory(&request).await?;
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
                DELETE | FILE_WRITE_ATTRIBUTES,
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
            self.connection.set_info(&request).await?;
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
            self.connection.set_info(&request).await?;
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
        self.connection.create(&request).await
    }

    async fn close_file_id(&mut self, file_id: FileId) -> Result<CloseResponse, CoreError> {
        self.connection
            .close(&CloseRequest { flags: 0, file_id })
            .await
    }

    async fn metadata_for_file_id(&mut self, file_id: FileId) -> Result<SmbMetadata, CoreError> {
        let basic = self
            .connection
            .query_info(&QueryInfoRequest::for_file_info(
                file_id,
                FileInfoClass::BasicInformation,
            ))
            .await?;
        let standard = self
            .connection
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
        let negotiated = self.connection.state().negotiated.max_read_size;
        negotiated.min(self.transfer_chunk_size).max(1)
    }

    fn max_write_size(&self) -> u32 {
        let negotiated = self.connection.state().negotiated.max_write_size;
        negotiated.min(self.transfer_chunk_size).max(1)
    }

    fn max_query_size(&self) -> u32 {
        let negotiated = self.connection.state().negotiated.max_transact_size;
        negotiated.min(self.transfer_chunk_size).max(1)
    }
}

/// An opened remote file handle borrowed from a share.
#[derive(Debug)]
pub struct RemoteFile<'a, T = TokioTcpTransport> {
    share: &'a mut Share<T>,
    file_id: FileId,
    position: u64,
    end_of_file: u64,
    closed: bool,
}

impl<'a, T> RemoteFile<'a, T>
where
    T: Transport + Send,
{
    /// Returns the underlying SMB file identifier.
    #[must_use]
    pub fn file_id(&self) -> FileId {
        self.file_id
    }

    /// Reads the next chunk into the provided buffer and returns the number of bytes read.
    pub async fn read_chunk(&mut self, buffer: &mut BytesMut) -> Result<usize, CoreError> {
        if self.position >= self.end_of_file {
            buffer.clear();
            return Ok(0);
        }

        let remaining = self.end_of_file - self.position;
        let read_length = remaining.min(u64::from(self.share.max_read_size())) as u32;
        let response = self
            .share
            .connection
            .read(&ReadRequest::for_file(
                self.file_id,
                self.position,
                read_length,
            ))
            .await?;
        buffer.clear();
        buffer.extend_from_slice(&response.data);
        self.position += response.data.len() as u64;
        Ok(response.data.len())
    }

    /// Writes the full buffer into the remote file at the current position.
    pub async fn write_all(&mut self, data: &[u8]) -> Result<(), CoreError> {
        let chunk_size = self.share.max_write_size() as usize;
        for chunk in data.chunks(chunk_size) {
            let response = self
                .share
                .connection
                .write(&WriteRequest::for_file(
                    self.file_id,
                    self.position,
                    chunk.to_vec(),
                ))
                .await?;
            if response.count as usize != chunk.len() {
                return Err(CoreError::InvalidResponse("short SMB write response"));
            }
            self.position += chunk.len() as u64;
            self.end_of_file = self.end_of_file.max(self.position);
        }
        Ok(())
    }

    /// Flushes the remote file handle to stable storage on the server.
    pub async fn flush(&mut self) -> Result<(), CoreError> {
        self.share
            .connection
            .flush(&FlushRequest::for_file(self.file_id))
            .await?;
        Ok(())
    }

    /// Closes the remote file handle.
    pub async fn close(mut self) -> Result<CloseResponse, CoreError> {
        if self.closed {
            return Err(CoreError::InvalidInput("remote file already closed"));
        }
        let response = self
            .share
            .connection
            .close(&CloseRequest {
                flags: 0,
                file_id: self.file_id,
            })
            .await?;
        self.closed = true;
        Ok(response)
    }
}

/// Rust-style options for opening a remote file.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OpenOptions {
    read: bool,
    write: bool,
    create: bool,
    truncate: bool,
    create_new: bool,
}

impl OpenOptions {
    /// Creates a new set of open options with all flags disabled.
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

    /// Enables or disables create-if-missing behavior.
    #[must_use]
    pub fn create(mut self, create: bool) -> Self {
        self.create = create;
        self
    }

    /// Enables or disables truncation of an existing file.
    #[must_use]
    pub fn truncate(mut self, truncate: bool) -> Self {
        self.truncate = truncate;
        self
    }

    /// Enables or disables create-new semantics.
    #[must_use]
    pub fn create_new(mut self, create_new: bool) -> Self {
        self.create_new = create_new;
        self
    }

    fn to_create_request(self, path: &str) -> Result<CreateRequest, CoreError> {
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

        let mut request = CreateRequest::from_path(&normalize_share_path(path)?);
        request.desired_access = desired_access_mask(self);
        request.share_access = ShareAccess::READ | ShareAccess::WRITE | ShareAccess::DELETE;
        request.file_attributes = FileAttributes::NORMAL;
        request.create_options = CreateOptions::NON_DIRECTORY_FILE;
        request.create_disposition = create_disposition(self);
        Ok(request)
    }
}

fn desired_access_mask(options: OpenOptions) -> u32 {
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

fn create_disposition(options: OpenOptions) -> CreateDisposition {
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

fn default_negotiate_contexts(dialects: &[Dialect]) -> Vec<NegotiateContext> {
    if !dialects.contains(&Dialect::Smb311) {
        return Vec::new();
    }

    vec![NegotiateContext::preauth_integrity(
        PreauthIntegrityCapabilities {
            hash_algorithms: vec![PreauthIntegrityHashId::Sha512],
            salt: random::<[u8; 32]>().to_vec(),
        },
    )]
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

fn normalize_share_path(path: &str) -> Result<String, CoreError> {
    normalize_share_path_with_options(path, false)
}

fn normalize_share_path_with_options(path: &str, allow_empty: bool) -> Result<String, CoreError> {
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
    if normalized.is_empty() && !allow_empty {
        return Err(CoreError::PathInvalid("path must not be empty"));
    }
    Ok(normalized)
}

fn metadata_from_info(
    basic: FileBasicInformation,
    standard: FileStandardInformation,
) -> SmbMetadata {
    let mut attributes = basic.file_attributes;
    if standard.directory {
        attributes |= FileAttributes::DIRECTORY;
    }

    SmbMetadata {
        size: standard.end_of_file,
        allocation_size: standard.allocation_size,
        attributes,
        created: system_time_from_windows_ticks(basic.creation_time),
        accessed: system_time_from_windows_ticks(basic.last_access_time),
        written: system_time_from_windows_ticks(basic.last_write_time),
        changed: system_time_from_windows_ticks(basic.change_time),
    }
}

fn directory_entry_from_query(
    entry: smolder_proto::smb::smb2::DirectoryInformationEntry,
) -> SmbDirectoryEntry {
    SmbDirectoryEntry {
        name: entry.file_name,
        metadata: SmbMetadata {
            size: entry.end_of_file,
            allocation_size: entry.allocation_size,
            attributes: entry.file_attributes,
            created: system_time_from_windows_ticks(entry.creation_time),
            accessed: system_time_from_windows_ticks(entry.last_access_time),
            written: system_time_from_windows_ticks(entry.last_write_time),
            changed: system_time_from_windows_ticks(entry.change_time),
        },
    }
}

fn system_time_from_windows_ticks(value: u64) -> Option<SystemTime> {
    if value == 0 {
        return None;
    }

    let unix_ticks = value.checked_sub(SEC_TO_UNIX_EPOCH * WINDOWS_TICK)?;
    Some(UNIX_EPOCH + Duration::from_nanos(unix_ticks.saturating_mul(100)))
}

fn parse_unc_share(unc: &str) -> Result<(String, String), CoreError> {
    let trimmed = unc
        .strip_prefix(r"\\")
        .ok_or(CoreError::PathInvalid("UNC path must start with \\\\"))?;
    let mut parts = trimmed.split('\\').filter(|segment| !segment.is_empty());
    let server = parts
        .next()
        .ok_or(CoreError::PathInvalid("UNC path must include a server"))?;
    let share = parts
        .next()
        .ok_or(CoreError::PathInvalid("UNC path must include a share"))?;
    if parts.next().is_some() {
        return Err(CoreError::PathInvalid(
            "UNC share paths must not include a file component",
        ));
    }

    Ok((server.to_string(), share.to_string()))
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use async_trait::async_trait;
    use smolder_proto::smb::netbios::SessionMessage;
    use smolder_proto::smb::smb2::{
        CloseResponse, Command, CreateDisposition, CreateOptions, CreateRequest, CreateResponse,
        Dialect, DirectoryInformationEntry, FileAttributes, FileBasicInformation, FileId,
        FileInfoClass, FileStandardInformation, FlushRequest, FlushResponse, GlobalCapabilities,
        Header, MessageId, NegotiateRequest, NegotiateResponse, OplockLevel, QueryDirectoryFlags,
        QueryDirectoryRequest, QueryDirectoryResponse, QueryInfoRequest, QueryInfoResponse,
        ReadRequest, ReadResponse, ReadResponseFlags, SessionFlags, SessionSetupRequest,
        SessionSetupResponse, SessionSetupSecurityMode, SetInfoRequest, SetInfoResponse,
        ShareFlags, ShareType, SigningMode, TreeCapabilities, TreeConnectRequest,
        TreeConnectResponse, TreeDisconnectResponse, TreeId, WriteRequest, WriteResponse,
    };
    use smolder_proto::smb::status::NtStatus;

    use crate::client::Connection;
    use crate::error::CoreError;
    use crate::fs::{OpenOptions, Share, SmbClient};
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

    async fn build_share(reads: Vec<Vec<u8>>) -> Share<ScriptedTransport> {
        let negotiate_response = NegotiateResponse {
            security_mode: SigningMode::ENABLED,
            dialect_revision: Dialect::Smb302,
            negotiate_contexts: Vec::new(),
            server_guid: *b"server-guid-0001",
            capabilities: GlobalCapabilities::LARGE_MTU,
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
        let client = SmbClient::from_connection("server", connection).with_transfer_chunk_size(4);
        client
            .share("share")
            .await
            .expect("tree connect should succeed")
    }

    fn transport_writes(share: Share<ScriptedTransport>) -> Vec<Vec<u8>> {
        share.connection.into_transport().writes
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
