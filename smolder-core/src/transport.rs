//! Async transports used by the SMB client.

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, ToSocketAddrs};

/// Abstracts framed SMB request and response transport.
#[async_trait]
pub trait Transport {
    /// Writes a fully framed RFC1002 session message.
    async fn send(&mut self, frame: &[u8]) -> std::io::Result<()>;

    /// Reads a fully framed RFC1002 session message.
    async fn recv(&mut self) -> std::io::Result<Vec<u8>>;
}

/// `tokio` TCP transport for SMB over port 445.
#[derive(Debug)]
pub struct TokioTcpTransport {
    stream: TcpStream,
}

impl TokioTcpTransport {
    /// Connects to an SMB endpoint.
    pub async fn connect<A>(addr: A) -> std::io::Result<Self>
    where
        A: ToSocketAddrs,
    {
        let stream = TcpStream::connect(addr).await?;
        Ok(Self { stream })
    }
}

#[async_trait]
impl Transport for TokioTcpTransport {
    async fn send(&mut self, frame: &[u8]) -> std::io::Result<()> {
        self.stream.write_all(frame).await
    }

    async fn recv(&mut self) -> std::io::Result<Vec<u8>> {
        let mut header = [0_u8; 4];
        self.stream.read_exact(&mut header).await?;
        let payload_len =
            (usize::from(header[1]) << 16) | (usize::from(header[2]) << 8) | usize::from(header[3]);
        let mut payload = vec![0; payload_len];
        self.stream.read_exact(&mut payload).await?;

        let mut frame = Vec::with_capacity(header.len() + payload_len);
        frame.extend_from_slice(&header);
        frame.extend_from_slice(&payload);
        Ok(frame)
    }
}
