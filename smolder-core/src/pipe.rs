//! Reusable IPC$ and named-pipe primitives built on top of the typestate client.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::BytesMut;
use rand::random;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use smolder_proto::smb::smb2::{
    CipherId, CloseRequest, CreateDisposition, CreateOptions, CreateRequest, Dialect,
    EncryptionCapabilities, FileAttributes, FileId, FlushRequest, GlobalCapabilities,
    NegotiateContext, NegotiateRequest, PreauthIntegrityCapabilities, PreauthIntegrityHashId,
    ReadRequest, ShareAccess, SigningMode, TreeConnectRequest, WriteRequest,
};

use crate::auth::{NtlmAuthenticator, NtlmCredentials};
use crate::client::{Connection, TreeConnected};
use crate::error::CoreError;
use crate::transport::{TokioTcpTransport, Transport};

const DEFAULT_PORT: u16 = 445;
const FILE_READ_DATA: u32 = 0x0000_0001;
const FILE_WRITE_DATA: u32 = 0x0000_0002;
const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
const READ_CONTROL: u32 = 0x0002_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;

/// SMB session configuration used to authenticate and connect to shares or pipes.
#[derive(Debug, Clone)]
pub struct SmbSessionConfig {
    server: String,
    port: u16,
    credentials: NtlmCredentials,
    signing_mode: SigningMode,
    capabilities: GlobalCapabilities,
    dialects: Vec<Dialect>,
    client_guid: [u8; 16],
}

impl SmbSessionConfig {
    /// Creates a new session configuration with SMB2/3 defaults.
    #[must_use]
    pub fn new(server: impl Into<String>, credentials: NtlmCredentials) -> Self {
        Self {
            server: server.into(),
            port: DEFAULT_PORT,
            credentials,
            signing_mode: SigningMode::ENABLED,
            capabilities: GlobalCapabilities::LARGE_MTU
                | GlobalCapabilities::LEASING
                | GlobalCapabilities::ENCRYPTION,
            dialects: vec![Dialect::Smb210, Dialect::Smb302, Dialect::Smb311],
            client_guid: random(),
        }
    }

    /// Overrides the target SMB TCP port.
    #[must_use]
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
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

    /// Returns the configured server host name or IP address.
    #[must_use]
    pub fn server(&self) -> &str {
        &self.server
    }

    /// Returns the configured SMB TCP port.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
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
    read_buffer: BytesMut,
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
            .field("write_buffer_capacity", &self.write_buffer.capacity())
            .field("eof", &self.eof)
            .field("closed", &self.closed)
            .finish()
    }
}

impl<T> Unpin for NamedPipe<T> {}

impl NamedPipe<TokioTcpTransport> {
    /// Connects to the target share and opens the named pipe with the requested access mode.
    pub async fn connect(
        config: &SmbSessionConfig,
        share: &str,
        pipe_name: &str,
        access: PipeAccess,
    ) -> Result<Self, CoreError> {
        let connection = connect_tree(config, share).await?;
        Self::open(connection, pipe_name, access).await
    }
}

impl<T> NamedPipe<T>
where
    T: Transport + Send,
{
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
        let response = connection.create(&request).await?;
        let fragment_size = connection
            .state()
            .negotiated
            .max_transact_size
            .min(connection.state().negotiated.max_read_size)
            .min(connection.state().negotiated.max_write_size)
            .min(u32::from(u16::MAX))
            .max(1024);

        Ok(Self {
            connection: Some(connection),
            file_id: response.file_id,
            fragment_size,
            read_buffer: BytesMut::with_capacity(fragment_size as usize),
            write_buffer: Vec::with_capacity(fragment_size as usize),
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
            if response.count == 0 {
                return Err(CoreError::InvalidResponse(
                    "named pipe write returned zero bytes",
                ));
            }
            offset = chunk_end;
        }
        let file_id = self.file_id;
        let _ = self
            .connection_mut()
            .flush(&FlushRequest::for_file(file_id))
            .await;
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
            let len = self.read_buffer.len();
            return Ok(Some(self.read_buffer.split_to(len).to_vec()));
        }
        if self.eof {
            return Ok(None);
        }

        let file_id = self.file_id;
        let fragment_size = self.fragment_size;
        let response = self
            .connection_mut()
            .read(&ReadRequest::for_file(file_id, 0, fragment_size))
            .await?;
        if response.data.is_empty() {
            self.eof = true;
            return Ok(None);
        }
        Ok(Some(response.data))
    }

    /// Reads one length-delimited DCE/RPC PDU from the pipe.
    pub async fn read_pdu(&mut self) -> Result<Vec<u8>, CoreError> {
        let mut buffer = Vec::new();
        let expected_len = loop {
            let file_id = self.file_id;
            let fragment_size = self.fragment_size;
            let response = self
                .connection_mut()
                .read(&ReadRequest::for_file(file_id, 0, fragment_size))
                .await?;
            if response.data.is_empty() {
                return Err(CoreError::InvalidResponse(
                    "named pipe read returned no data",
                ));
            }
            buffer.extend_from_slice(&response.data);
            if buffer.len() >= 10 {
                let frag_len = u16::from_le_bytes([buffer[8], buffer[9]]) as usize;
                break frag_len;
            }
        };

        while buffer.len() < expected_len {
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
            buffer.extend_from_slice(&response.data);
        }
        buffer.truncate(expected_len);
        Ok(buffer)
    }

    /// Writes one request PDU and then reads one response PDU.
    pub async fn call(&mut self, request: Vec<u8>) -> Result<Vec<u8>, CoreError> {
        self.write_all(&request).await?;
        self.read_pdu().await
    }

    /// Reads the next newline-terminated UTF-8 control line from the pipe.
    pub async fn read_line(&mut self, buffer: &mut Vec<u8>) -> Result<Option<String>, CoreError> {
        loop {
            if let Some(newline_index) = buffer.iter().position(|byte| *byte == b'\n') {
                let line = buffer.drain(..=newline_index).collect::<Vec<_>>();
                let text = String::from_utf8_lossy(&line).trim().to_string();
                return Ok(Some(text));
            }

            match self.read_chunk().await? {
                Some(bytes) => buffer.extend_from_slice(&bytes),
                None if buffer.is_empty() => return Ok(None),
                None => {
                    return Err(CoreError::InvalidResponse(
                        "interactive control pipe closed with a truncated line",
                    ))
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
                    Some(bytes) => self.read_buffer.extend_from_slice(&bytes),
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

impl<T> AsyncRead for NamedPipe<T>
where
    T: Transport + Send + 'static,
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
                let chunk = this.read_buffer.split_to(to_copy);
                buf.put_slice(&chunk);
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
                    });
                (connection, result)
            }));
        }
    }
}

impl<T> AsyncWrite for NamedPipe<T>
where
    T: Transport + Send + 'static,
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
                let written = response.count as usize;
                if written == 0 {
                    Err(CoreError::InvalidResponse(
                        "named pipe write returned zero bytes",
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
            Poll::Ready(Err(error)) => Poll::Ready(Err(core_error_to_io(error))),
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

/// Authenticates and tree-connects to the requested share.
pub async fn connect_tree(
    config: &SmbSessionConfig,
    share: &str,
) -> Result<Connection<TokioTcpTransport, TreeConnected>, CoreError> {
    let mut auth = NtlmAuthenticator::new(config.credentials.clone());
    let transport = TokioTcpTransport::connect((config.server.as_str(), config.port)).await?;
    let request = NegotiateRequest {
        security_mode: config.signing_mode,
        capabilities: config.capabilities,
        client_guid: config.client_guid,
        negotiate_contexts: default_negotiate_contexts(&config.dialects, config.capabilities),
        dialects: config.dialects.clone(),
    };
    let connection = Connection::new(transport).negotiate(&request).await?;
    let connection = connection.authenticate(&mut auth).await?;
    let unc = format!(r"\\{}\{}", config.server, normalize_share_name(share)?);
    connection
        .tree_connect(&TreeConnectRequest::from_unc(&unc))
        .await
}

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
    use smolder_proto::smb::netbios::SessionMessage;
    use smolder_proto::smb::smb2::{
        CipherId, CloseResponse, Command, CreateResponse, Dialect, FileAttributes, FileId,
        FlushResponse, GlobalCapabilities, Header, MessageId, NegotiateRequest, NegotiateResponse,
        OplockLevel, ReadResponse, ReadResponseFlags, SessionFlags, SessionSetupRequest,
        SessionSetupResponse, SessionSetupSecurityMode, ShareFlags, ShareType, SigningMode,
        TreeCapabilities, TreeConnectRequest, TreeConnectResponse, TreeId, WriteRequest,
        WriteResponse,
    };
    use smolder_proto::smb::status::NtStatus;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::auth::NtlmCredentials;
    use crate::client::{Connection, TreeConnected};
    use crate::transport::Transport;

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

        let contexts = super::default_negotiate_contexts(&config.dialects, config.capabilities);
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
            .session_setup(&session_request)
            .await
            .expect("session setup should succeed");
        connection
            .tree_connect(&TreeConnectRequest::from_unc(r"\\server\IPC$"))
            .await
            .expect("tree connect should succeed")
    }
}
