//! Async transports used by the SMB client.

use async_trait::async_trait;
use smolder_proto::smb::netbios::SessionMessage;
#[cfg(feature = "quic")]
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
#[cfg(feature = "quic")]
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(feature = "quic")]
use tokio::net::lookup_host;
use tokio::net::{TcpStream, ToSocketAddrs};

#[cfg(feature = "quic")]
use quinn::{
    ClientConfig as QuicClientConfig, Connection as QuicConnection, Endpoint, RecvStream,
    SendStream,
};
#[cfg(feature = "quic")]
use quinn_proto::crypto::rustls::QuicClientConfig as RustlsQuicClientConfig;
#[cfg(feature = "quic")]
use rustls::RootCertStore;

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
    connect_host: Option<String>,
    tls_server_name: Option<String>,
    port: u16,
    protocol: TransportProtocol,
}

impl TransportTarget {
    /// Creates a TCP transport target.
    #[must_use]
    pub fn tcp(server: impl Into<String>) -> Self {
        Self {
            server: server.into(),
            connect_host: None,
            tls_server_name: None,
            port: 445,
            protocol: TransportProtocol::Tcp,
        }
    }

    /// Creates a QUIC transport target.
    #[must_use]
    pub fn quic(server: impl Into<String>) -> Self {
        Self {
            server: server.into(),
            connect_host: None,
            tls_server_name: None,
            port: 443,
            protocol: TransportProtocol::Quic,
        }
    }

    /// Returns the logical SMB server name for auth, share access, and defaults.
    #[must_use]
    pub fn server(&self) -> &str {
        &self.server
    }

    /// Returns the dial host or IP address used for the underlying transport.
    #[must_use]
    pub fn connect_host(&self) -> &str {
        self.connect_host.as_deref().unwrap_or(&self.server)
    }

    /// Returns the TLS server name used by SMB over QUIC.
    #[must_use]
    pub fn tls_server_name(&self) -> &str {
        self.tls_server_name.as_deref().unwrap_or(&self.server)
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

    /// Returns a copy of this target with a different dial host or IP address.
    #[must_use]
    pub fn with_connect_host(mut self, connect_host: impl Into<String>) -> Self {
        self.connect_host = Some(connect_host.into());
        self
    }

    /// Returns a copy of this target with a different TLS server name.
    ///
    /// This is only used by SMB over QUIC. Classic SMB over TCP ignores it.
    #[must_use]
    pub fn with_tls_server_name(mut self, tls_server_name: impl Into<String>) -> Self {
        self.tls_server_name = Some(tls_server_name.into());
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
/// Some transports may carry SMB messages directly rather than RFC1002 session
/// frames. Existing framed transports automatically adapt through the blanket
/// implementation below.
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

/// `quinn` QUIC transport for SMB over QUIC.
#[cfg(feature = "quic")]
pub struct QuicTransport {
    _endpoint: Endpoint,
    connection: QuicConnection,
    send: SendStream,
    recv: RecvStream,
}

#[cfg(feature = "quic")]
impl std::fmt::Debug for QuicTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicTransport")
            .field("remote_address", &self.connection.remote_address())
            .field("local_ip", &self.connection.local_ip())
            .field("protocol", &TransportProtocol::Quic)
            .finish()
    }
}

#[cfg(feature = "quic")]
impl QuicTransport {
    /// Connects to an SMB-over-QUIC endpoint and opens the default long-lived
    /// bidirectional application stream.
    pub async fn connect(target: &TransportTarget) -> std::io::Result<Self> {
        if target.protocol() != TransportProtocol::Quic {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "QUIC transport requires a QUIC transport target",
            ));
        }

        let remote = lookup_host((target.connect_host(), target.port()))
            .await?
            .next()
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    "no QUIC socket address resolved for SMB target",
                )
            })?;
        let bind_addr = match remote {
            SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        };

        let mut endpoint = Endpoint::client(bind_addr)?;
        endpoint.set_default_client_config(default_quic_client_config()?);
        let connection = endpoint
            .connect(remote, target.tls_server_name())
            .map_err(quic_connect_error_to_io)?
            .await
            .map_err(quic_connection_error_to_io)?;
        let (send, recv) = connection
            .open_bi()
            .await
            .map_err(quic_connection_error_to_io)?;

        Ok(Self {
            _endpoint: endpoint,
            connection,
            send,
            recv,
        })
    }

    fn rustls_client_config() -> std::io::Result<rustls::ClientConfig> {
        let cert_result = rustls_native_certs::load_native_certs();
        let mut roots = RootCertStore::empty();
        let (added, _) = roots.add_parsable_certificates(cert_result.certs);
        if added == 0 {
            return Err(std::io::Error::other(
                "no trusted root certificates were loaded for SMB over QUIC",
            ));
        }

        let mut client_crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_crypto.alpn_protocols = vec![b"smb".to_vec()];
        Ok(client_crypto)
    }
}

#[cfg(feature = "quic")]
fn default_quic_client_config() -> std::io::Result<QuicClientConfig> {
    let client_crypto = QuicTransport::rustls_client_config()?;
    let quic_crypto = RustlsQuicClientConfig::try_from(client_crypto)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    Ok(QuicClientConfig::new(Arc::new(quic_crypto)))
}

#[cfg(feature = "quic")]
fn quic_connect_error_to_io(error: quinn::ConnectError) -> std::io::Error {
    std::io::Error::other(error.to_string())
}

#[cfg(feature = "quic")]
fn quic_connection_error_to_io(error: quinn::ConnectionError) -> std::io::Error {
    std::io::Error::other(error.to_string())
}

#[cfg(feature = "quic")]
fn quic_read_error_to_io(error: quinn::ReadError) -> std::io::Error {
    std::io::Error::other(error.to_string())
}

#[cfg(feature = "quic")]
#[async_trait]
impl SmbTransport for QuicTransport {
    async fn send_message(&mut self, message: &[u8]) -> std::io::Result<()> {
        self.send.write_all(message).await?;
        self.send.flush().await?;
        Ok(())
    }

    async fn recv_message(&mut self) -> std::io::Result<Vec<u8>> {
        let chunk = self
            .recv
            .read_chunk(usize::MAX, true)
            .await
            .map_err(quic_read_error_to_io)?
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "SMB over QUIC stream closed before a response arrived",
                )
            })?;
        Ok(chunk.bytes.to_vec())
    }
}

#[cfg(all(test, feature = "quic"))]
mod tests {
    use super::{QuicTransport, TransportProtocol, TransportTarget};

    #[test]
    fn quic_client_config_sets_smb_alpn() {
        let client_crypto =
            QuicTransport::rustls_client_config().expect("quic client crypto should build");
        assert_eq!(client_crypto.alpn_protocols, vec![b"smb".to_vec()]);
    }

    #[test]
    fn transport_target_defaults_connect_and_tls_names_to_server() {
        let target = TransportTarget::quic("files.lab.example");

        assert_eq!(target.server(), "files.lab.example");
        assert_eq!(target.connect_host(), "files.lab.example");
        assert_eq!(target.tls_server_name(), "files.lab.example");
        assert_eq!(target.protocol(), TransportProtocol::Quic);
    }

    #[test]
    fn transport_target_can_override_connect_and_tls_names() {
        let target = TransportTarget::quic("files.lab.example")
            .with_connect_host("127.0.0.1")
            .with_tls_server_name("gateway.lab.example")
            .with_port(8443);

        assert_eq!(target.server(), "files.lab.example");
        assert_eq!(target.connect_host(), "127.0.0.1");
        assert_eq!(target.tls_server_name(), "gateway.lab.example");
        assert_eq!(target.port(), 8443);
    }
}
