use std::future::Future;
use std::io::{self, Seek, SeekFrom};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite, ReadBuf};

use smolder_core::client::{Connection, DurableHandle, ResilientHandle, TreeConnected};
use smolder_core::error::CoreError;
use smolder_core::transport::{TokioTcpTransport, Transport};
use smolder_proto::smb::smb2::{
    CloseRequest, CloseResponse, FileId, FlushRequest, ReadRequest, WriteRequest,
};

use super::{Lease, Share};

/// An opened remote file handle borrowed from a share.
///
/// Call [`RemoteFile::close`] to preserve the physical connection for reuse. Dropping an open file
/// cannot perform asynchronous SMB `CLOSE`, so it invalidates the connection instead.
pub struct RemoteFile<'a, T = TokioTcpTransport> {
    share: &'a mut Share<T>,
    connection: Option<Connection<T, TreeConnected>>,
    file_id: FileId,
    lease: Option<Lease>,
    durable: Option<DurableHandle>,
    resilient: Option<ResilientHandle>,
    position: u64,
    end_of_file: u64,
    max_read_size: u32,
    max_write_size: u32,
    read_buffer: BytesMut,
    write_buffer: Vec<u8>,
    pending_read: Option<PendingRead<'a, T>>,
    pending_write: Option<PendingWrite<'a, T>>,
    pending_flush: Option<PendingFlush<'a, T>>,
    recovery: ConnectionRecovery<T>,
    closed: bool,
}

type ConnectionRecovery<T> = Arc<Mutex<Option<Connection<T, TreeConnected>>>>;

type PendingRead<'a, T> = Pin<
    Box<
        dyn Future<Output = (Connection<T, TreeConnected>, Result<Vec<u8>, CoreError>)> + Send + 'a,
    >,
>;
type PendingWrite<'a, T> = Pin<
    Box<
        dyn Future<
                Output = (
                    Connection<T, TreeConnected>,
                    Vec<u8>,
                    Result<usize, CoreError>,
                ),
            > + Send
            + 'a,
    >,
>;
type PendingFlush<'a, T> = Pin<
    Box<dyn Future<Output = (Connection<T, TreeConnected>, Result<(), CoreError>)> + Send + 'a>,
>;

/// Returns an in-flight connection to the owning file when its operation future is cancelled.
///
/// The recovered connection is always invalidated: cancellation may have occurred after a partial
/// write or before the correlated response was drained.
struct PendingConnection<T> {
    connection: Option<Connection<T, TreeConnected>>,
    recovery: ConnectionRecovery<T>,
}

impl<T> PendingConnection<T> {
    fn new(connection: Connection<T, TreeConnected>, recovery: ConnectionRecovery<T>) -> Self {
        Self {
            connection: Some(connection),
            recovery,
        }
    }

    fn connection_mut(&mut self) -> &mut Connection<T, TreeConnected> {
        self.connection
            .as_mut()
            .expect("pending operation owns its SMB connection")
    }

    fn into_connection(mut self) -> Connection<T, TreeConnected> {
        self.connection
            .take()
            .expect("completed operation owns its SMB connection")
    }
}

impl<T> Drop for PendingConnection<T> {
    fn drop(&mut self) {
        let Some(mut connection) = self.connection.take() else {
            return;
        };
        connection.invalidate();
        let mut recovery = self
            .recovery
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if recovery.is_none() {
            *recovery = Some(connection);
        }
    }
}

pub(super) struct RemoteFileParts<T> {
    pub(super) connection: Connection<T, TreeConnected>,
    pub(super) file_id: FileId,
    pub(super) lease: Option<Lease>,
    pub(super) durable: Option<DurableHandle>,
    pub(super) resilient: Option<ResilientHandle>,
    pub(super) end_of_file: u64,
    pub(super) max_read_size: u32,
    pub(super) max_write_size: u32,
}

impl<T> Unpin for RemoteFile<'_, T> {}

impl<'a, T> RemoteFile<'a, T>
where
    T: Transport + Send,
{
    pub(super) fn new(share: &'a mut Share<T>, parts: RemoteFileParts<T>) -> Self {
        Self {
            share,
            connection: Some(parts.connection),
            file_id: parts.file_id,
            lease: parts.lease,
            durable: parts.durable,
            resilient: parts.resilient,
            position: 0,
            end_of_file: parts.end_of_file,
            max_read_size: parts.max_read_size,
            max_write_size: parts.max_write_size,
            read_buffer: BytesMut::new(),
            write_buffer: Vec::new(),
            pending_read: None,
            pending_write: None,
            pending_flush: None,
            recovery: Arc::new(Mutex::new(None)),
            closed: false,
        }
    }

    fn connection_mut(&mut self) -> &mut Connection<T, TreeConnected> {
        self.connection
            .as_mut()
            .expect("remote file should own the share connection while open")
    }

    fn take_connection(&mut self) -> Connection<T, TreeConnected> {
        self.connection
            .take()
            .expect("remote file should own the share connection while open")
    }

    fn restore_connection(&mut self, connection: Connection<T, TreeConnected>) {
        assert!(
            self.connection.is_none(),
            "remote file should not already contain a connection",
        );
        self.connection = Some(connection);
    }

    fn complete_pending_read(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), CoreError>> {
        let Some(future) = self.pending_read.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        let (connection, result) = match future.as_mut().poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(output) => output,
        };
        self.pending_read = None;
        self.restore_connection(connection);

        match result {
            Ok(data) => {
                let data_len = data.len();
                // `Bytes` takes ownership of the already-bounded response allocation and converts
                // it back to a unique `BytesMut` without another infallible remote-sized reserve.
                self.read_buffer = Bytes::from(data).into();
                self.position += data_len as u64;
                Poll::Ready(Ok(()))
            }
            Err(error) => Poll::Ready(Err(error)),
        }
    }

    fn complete_pending_write(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<usize>, CoreError>> {
        let Some(future) = self.pending_write.as_mut() else {
            return Poll::Ready(Ok(None));
        };
        let (connection, buffer, result) = match future.as_mut().poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(output) => output,
        };
        self.pending_write = None;
        self.restore_connection(connection);
        self.write_buffer = buffer;

        match result {
            Ok(written) => {
                self.position += written as u64;
                self.end_of_file = self.end_of_file.max(self.position);
                Poll::Ready(Ok(Some(written)))
            }
            Err(error) => Poll::Ready(Err(error)),
        }
    }

    fn complete_pending_flush(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), CoreError>> {
        let Some(future) = self.pending_flush.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        let (connection, result) = match future.as_mut().poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(output) => output,
        };
        self.pending_flush = None;
        self.restore_connection(connection);
        Poll::Ready(result)
    }

    fn seek_position(&self, position: SeekFrom) -> io::Result<u64> {
        let (base, offset) = match position {
            SeekFrom::Start(offset) => return Ok(offset),
            SeekFrom::Current(offset) => (self.position as i128, i128::from(offset)),
            SeekFrom::End(offset) => (self.end_of_file as i128, i128::from(offset)),
        };
        let next = base + offset;
        if next < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot seek before start of file",
            ));
        }
        u64::try_from(next)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "seek offset overflow"))
    }

    /// Returns the underlying SMB file identifier.
    #[must_use]
    pub fn file_id(&self) -> FileId {
        self.file_id
    }

    /// Returns the granted lease for the handle, if the open requested one and the server granted it.
    #[must_use]
    pub fn lease(&self) -> Option<Lease> {
        self.lease
    }

    /// Returns the durable open state for the handle, if the open requested one.
    #[must_use]
    pub fn durable_handle(&self) -> Option<&DurableHandle> {
        self.durable.as_ref()
    }

    /// Returns the granted resiliency state for the handle, if requested.
    #[must_use]
    pub fn resilient_handle(&self) -> Option<ResilientHandle> {
        self.resilient
    }

    /// Returns the current logical position for the handle.
    #[must_use]
    pub fn position(&self) -> u64 {
        self.position
    }

    /// Returns the current logical file length reported by the server.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.end_of_file
    }

    /// Returns true when the handle currently points at an empty file.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Requests or refreshes handle resiliency on the current open file.
    pub async fn request_resiliency(&mut self, timeout: u32) -> Result<ResilientHandle, CoreError> {
        if self.closed {
            return Err(CoreError::InvalidInput("remote file already closed"));
        }
        if self.pending_read.is_some()
            || self.pending_write.is_some()
            || self.pending_flush.is_some()
        {
            return Err(CoreError::InvalidInput(
                "cannot change remote file resiliency while an async I/O operation is pending",
            ));
        }
        let file_id = self.file_id;
        let resilient = self
            .connection_mut()
            .request_resiliency(file_id, timeout)
            .await?;
        if let Some(durable) = self.durable.take() {
            self.durable = Some(durable.with_resilient_timeout(timeout));
        }
        self.resilient = Some(resilient);
        Ok(resilient)
    }

    /// Reads the next chunk into the provided buffer and returns the number of bytes read.
    pub async fn read_chunk(&mut self, buffer: &mut BytesMut) -> Result<usize, CoreError> {
        if self.position >= self.end_of_file {
            buffer.clear();
            return Ok(0);
        }

        let remaining = self.end_of_file - self.position;
        let read_length = remaining.min(u64::from(self.max_read_size)) as u32;
        let file_id = self.file_id;
        let position = self.position;
        let response = self
            .connection_mut()
            .read(&ReadRequest::for_file(file_id, position, read_length))
            .await?;
        let data_len = response.data.len();
        // Reuse the bounded protocol response allocation rather than allocating from a
        // remote-controlled length a second time.
        *buffer = Bytes::from(response.data).into();
        self.position += data_len as u64;
        Ok(data_len)
    }

    /// Writes the full buffer into the remote file at the current position.
    pub async fn write_all(&mut self, data: &[u8]) -> Result<(), CoreError> {
        let chunk_size = self.max_write_size as usize;
        for chunk in data.chunks(chunk_size) {
            let mut staged = std::mem::take(&mut self.write_buffer);
            staged.clear();
            staged
                .try_reserve(chunk.len())
                .map_err(|_| CoreError::AllocationFailed("remote file write buffer"))?;
            staged.extend_from_slice(chunk);
            let request = WriteRequest::for_file(self.file_id, self.position, staged);
            let response = self.connection_mut().write(&request).await?;
            self.write_buffer = request.data;
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
        let file_id = self.file_id;
        self.connection_mut()
            .flush(&FlushRequest::for_file(file_id))
            .await?;
        Ok(())
    }

    /// Closes the remote file handle.
    pub async fn close(mut self) -> Result<CloseResponse, CoreError> {
        if self.closed {
            return Err(CoreError::InvalidInput("remote file already closed"));
        }
        if self.pending_read.is_some()
            || self.pending_write.is_some()
            || self.pending_flush.is_some()
        {
            return Err(CoreError::InvalidInput(
                "cannot close remote file while an async I/O operation is pending",
            ));
        }
        let connection = self.take_connection();
        let mut pending = PendingConnection::new(connection, Arc::clone(&self.recovery));
        let result = pending
            .connection_mut()
            .close(&CloseRequest {
                flags: 0,
                file_id: self.file_id,
            })
            .await;
        let mut connection = pending.into_connection();
        if result.is_err() {
            connection.invalidate();
        }
        self.share.restore_connection(connection);
        if result.is_ok() {
            self.closed = true;
        }
        result
    }
}

impl<T> Drop for RemoteFile<'_, T> {
    fn drop(&mut self) {
        // Drop in-flight futures first. Their pending-connection guards return an invalidated
        // connection through `recovery`, rather than silently dropping it and leaving the parent
        // share in an impossible `None` state.
        self.pending_read = None;
        self.pending_write = None;
        self.pending_flush = None;

        let recovered = self
            .recovery
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let connection = self.connection.take().or(recovered);
        if let Some(mut connection) = connection {
            if !self.closed {
                // Drop cannot await SMB CLOSE. Prevent the still-open remote handle and any
                // partially-completed file operation from sharing this physical connection with
                // a later request; the owner must discard the invalidated connection.
                connection.invalidate();
            }
            debug_assert!(self.share.connection.is_none());
            self.share.connection = Some(connection);
        }
    }
}

fn core_error_to_io(error: CoreError) -> io::Error {
    match error {
        CoreError::Io(error) | CoreError::LocalIo(error) => error,
        other => io::Error::other(other),
    }
}

impl<T> AsyncRead for RemoteFile<'_, T>
where
    T: Transport + Send,
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
                "remote file is closed",
            )));
        }
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.pending_flush.is_some() || this.pending_write.is_some() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "remote file has a pending write or flush operation",
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

            if this.position >= this.end_of_file {
                return Poll::Ready(Ok(()));
            }

            let remaining = this.end_of_file - this.position;
            let read_length = remaining.min(u64::from(this.max_read_size)) as u32;
            let connection = this.take_connection();
            let mut pending = PendingConnection::new(connection, Arc::clone(&this.recovery));
            let file_id = this.file_id;
            let offset = this.position;
            this.pending_read = Some(Box::pin(async move {
                let result = pending
                    .connection_mut()
                    .read(&ReadRequest::for_file(file_id, offset, read_length))
                    .await
                    .map(|response| response.data);
                (pending.into_connection(), result)
            }));
        }
    }
}

impl<T> AsyncWrite for RemoteFile<'_, T>
where
    T: Transport + Send,
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
                "remote file is closed",
            )));
        }
        if this.pending_read.is_some() || this.pending_flush.is_some() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "remote file has a pending read or flush operation",
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

        let requested = buf.len().min(this.max_write_size as usize);
        let mut staged = std::mem::take(&mut this.write_buffer);
        staged.clear();
        if staged.try_reserve(requested).is_err() {
            this.write_buffer = staged;
            return Poll::Ready(Err(io::Error::other(
                "failed to allocate remote file write buffer",
            )));
        }
        staged.extend_from_slice(&buf[..requested]);
        let connection = this.take_connection();
        let mut pending = PendingConnection::new(connection, Arc::clone(&this.recovery));
        let file_id = this.file_id;
        let offset = this.position;
        this.pending_write = Some(Box::pin(async move {
            let request = WriteRequest::for_file(file_id, offset, staged);
            let result = pending
                .connection_mut()
                .write(&request)
                .await
                .and_then(|response| {
                    let written = response.count as usize;
                    if written == requested {
                        Ok(written)
                    } else {
                        Err(CoreError::InvalidResponse("short SMB write response"))
                    }
                });
            (pending.into_connection(), request.data, result)
        }));

        match this.complete_pending_write(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(Some(written))) => Poll::Ready(Ok(written)),
            Poll::Ready(Ok(None)) => Poll::Ready(Ok(0)),
            Poll::Ready(Err(error)) => Poll::Ready(Err(core_error_to_io(error))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.closed {
            return Poll::Ready(Ok(()));
        }
        if this.pending_read.is_some() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "remote file has a pending read operation",
            )));
        }

        match this.complete_pending_write(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(core_error_to_io(error))),
            Poll::Ready(Ok(_)) => {}
        }

        if this.pending_flush.is_none() {
            let connection = this.take_connection();
            let mut pending = PendingConnection::new(connection, Arc::clone(&this.recovery));
            let file_id = this.file_id;
            this.pending_flush = Some(Box::pin(async move {
                let result = pending
                    .connection_mut()
                    .flush(&FlushRequest::for_file(file_id))
                    .await
                    .map(|_| ());
                (pending.into_connection(), result)
            }));
        }

        match this.complete_pending_flush(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(core_error_to_io(error))),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

impl<T> AsyncSeek for RemoteFile<'_, T>
where
    T: Transport + Send,
{
    fn start_seek(self: Pin<&mut Self>, position: SeekFrom) -> io::Result<()> {
        let this = self.get_mut();
        if this.pending_read.is_some()
            || this.pending_write.is_some()
            || this.pending_flush.is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "remote file has a pending operation",
            ));
        }
        this.position = this.seek_position(position)?;
        this.read_buffer.clear();
        Ok(())
    }

    fn poll_complete(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        Poll::Ready(Ok(self.get_mut().position))
    }
}

impl<T> Seek for RemoteFile<'_, T>
where
    T: Transport + Send,
{
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        if self.pending_read.is_some()
            || self.pending_write.is_some()
            || self.pending_flush.is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "remote file has a pending operation",
            ));
        }
        self.position = self.seek_position(position)?;
        self.read_buffer.clear();
        Ok(self.position)
    }
}
