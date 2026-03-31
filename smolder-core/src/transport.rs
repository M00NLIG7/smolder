//! Async transports used by the SMB client.

use async_trait::async_trait;
use smolder_proto::smb::netbios::SessionMessage;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, ToSocketAddrs};

/// The network transport protocol used to carry SMB session traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProtocol {
    /// Classic SMB over TCP, typically on port `445`.
    Tcp,
    /// SMB over QUIC, typically on port `443`.
    Quic,
}

/// An SMB transport target including the server identity, port, and protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportTarget {
    server: String,
    port: u16,
    protocol: TransportProtocol,
}

impl TransportTarget {
    /// Creates a TCP transport target.
    #[must_use]
    pub fn tcp(server: impl Into<String>) -> Self {
        Self {
            server: server.into(),
            port: 445,
            protocol: TransportProtocol::Tcp,
        }
    }

    /// Creates a QUIC transport target.
    #[must_use]
    pub fn quic(server: impl Into<String>) -> Self {
        Self {
            server: server.into(),
            port: 443,
            protocol: TransportProtocol::Quic,
        }
    }

    /// Returns the SMB server host name or IP address.
    #[must_use]
    pub fn server(&self) -> &str {
        &self.server
    }

    /// Returns the configured port.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Returns the configured transport protocol.
    #[must_use]
    pub fn protocol(&self) -> TransportProtocol {
        self.protocol
    }

    /// Returns a copy of this target with a different port.
    #[must_use]
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }
}

/// Abstracts framed SMB request and response transport.
///
/// This is the compatibility layer for transports that carry RFC1002 session
/// messages, such as classic SMB over TCP on port `445`.
#[async_trait]
pub trait Transport {
    /// Writes a fully framed RFC1002 session message.
    async fn send(&mut self, frame: &[u8]) -> std::io::Result<()>;

    /// Reads a fully framed RFC1002 session message.
    async fn recv(&mut self) -> std::io::Result<Vec<u8>>;
}

/// Abstracts raw SMB message transport independent of RFC1002 framing.
///
/// Modern transports such as SMB over QUIC carry SMB messages directly rather
/// than RFC1002 session frames. Existing framed transports automatically adapt
/// through the blanket implementation below.
#[async_trait]
pub trait SmbTransport {
    /// Writes a raw SMB message or transform payload.
    async fn send_message(&mut self, message: &[u8]) -> std::io::Result<()>;

    /// Reads a raw SMB message or transform payload.
    async fn recv_message(&mut self) -> std::io::Result<Vec<u8>>;
}

#[async_trait]
impl<T> SmbTransport for T
where
    T: Transport + Send,
{
    async fn send_message(&mut self, message: &[u8]) -> std::io::Result<()> {
        let frame = SessionMessage::encode_payload(message).map_err(|error| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
        })?;
        self.send(&frame).await
    }

    async fn recv_message(&mut self) -> std::io::Result<Vec<u8>> {
        let frame = self.recv().await?;
        let message = SessionMessage::decode(&frame).map_err(|error| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
        })?;
        Ok(message.payload)
    }
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
