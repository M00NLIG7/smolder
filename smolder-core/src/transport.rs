//! Async transports used by the SMB client.

use async_trait::async_trait;
use smolder_proto::smb::netbios::{
    SessionMessage, NEGATIVE_SESSION_RESPONSE, POSITIVE_SESSION_RESPONSE, SESSION_KEEP_ALIVE,
    SESSION_MESSAGE,
};
use std::net::IpAddr;
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

const NETBIOS_WILDCARD_SERVER_NAME: &str = "*SMBSERVER";
const NETBIOS_CALLING_NAME: &str = "SMOLDER";

/// The network transport protocol used to carry SMB session traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProtocol {
    /// Classic SMB over TCP, typically on port `445`.
    Tcp,
    /// SMB over NetBIOS session service, typically on port `139`.
    Netbios,
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

    /// Creates a NetBIOS session-service transport target.
    #[must_use]
    pub fn netbios(server: impl Into<String>) -> Self {
        Self {
            server: server.into(),
            connect_host: None,
            tls_server_name: None,
            port: 139,
            protocol: TransportProtocol::Netbios,
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
        if message.message_type != SESSION_MESSAGE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "unexpected RFC1002 session message type 0x{:02x}",
                    message.message_type
                ),
            ));
        }
        Ok(message.payload)
    }
}

/// `tokio` TCP transport for SMB over port 445.
#[derive(Debug)]
pub struct TokioTcpTransport {
    stream: TcpStream,
    mode: TcpTransportMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcpTransportMode {
    DirectTcp,
    NetbiosSession,
}

impl TokioTcpTransport {
    /// Connects to an SMB endpoint.
    pub async fn connect<A>(addr: A) -> std::io::Result<Self>
    where
        A: ToSocketAddrs,
    {
        let stream = TcpStream::connect(addr).await?;
        Ok(Self {
            stream,
            mode: TcpTransportMode::DirectTcp,
        })
    }

    /// Connects to an SMB endpoint over NetBIOS session service.
    pub async fn connect_netbios(target: &TransportTarget) -> std::io::Result<Self> {
        if target.protocol() != TransportProtocol::Netbios {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "NetBIOS transport requires a NetBIOS transport target",
            ));
        }

        let mut stream = TcpStream::connect((target.connect_host(), target.port())).await?;
        let request = SessionMessage::session_request(
            default_netbios_called_name(target.server()),
            NETBIOS_CALLING_NAME,
        )
        .and_then(|message| message.encode())
        .map_err(|error| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, error.to_string())
        })?;
        stream.write_all(&request).await?;

        loop {
            let (message_type, payload) = read_netbios_packet(&mut stream).await?;
            match message_type {
                POSITIVE_SESSION_RESPONSE => {
                    if !payload.is_empty() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "NetBIOS positive session response carried an unexpected payload",
                        ));
                    }
                    break;
                }
                NEGATIVE_SESSION_RESPONSE => {
                    let reason = payload.first().copied().unwrap_or_default();
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        format!("NetBIOS session request was rejected with error 0x{reason:02x}"),
                    ));
                }
                SESSION_KEEP_ALIVE => continue,
                other => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "unexpected NetBIOS session response type 0x{other:02x} during connect"
                        ),
                    ));
                }
            }
        }

        Ok(Self {
            stream,
            mode: TcpTransportMode::NetbiosSession,
        })
    }
}

#[async_trait]
impl Transport for TokioTcpTransport {
    async fn send(&mut self, frame: &[u8]) -> std::io::Result<()> {
        self.stream.write_all(frame).await
    }

    async fn recv(&mut self) -> std::io::Result<Vec<u8>> {
        match self.mode {
            TcpTransportMode::DirectTcp => {
                let mut header = [0_u8; 4];
                self.stream.read_exact(&mut header).await?;
                let payload_len = (usize::from(header[1]) << 16)
                    | (usize::from(header[2]) << 8)
                    | usize::from(header[3]);
                let mut payload = vec![0; payload_len];
                self.stream.read_exact(&mut payload).await?;

                let mut frame = Vec::with_capacity(header.len() + payload_len);
                frame.extend_from_slice(&header);
                frame.extend_from_slice(&payload);
                Ok(frame)
            }
            TcpTransportMode::NetbiosSession => loop {
                let (message_type, payload) = read_netbios_packet(&mut self.stream).await?;
                match message_type {
                    SESSION_KEEP_ALIVE => continue,
                    SESSION_MESSAGE => {
                        let mut frame = Vec::with_capacity(4 + payload.len());
                        frame.push(message_type);
                        frame.push(((payload.len() >> 16) & 0xff) as u8);
                        frame.push(((payload.len() >> 8) & 0xff) as u8);
                        frame.push((payload.len() & 0xff) as u8);
                        frame.extend_from_slice(&payload);
                        return Ok(frame);
                    }
                    other => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!(
                                "unexpected NetBIOS session packet type 0x{other:02x} after session setup"
                            ),
                        ));
                    }
                }
            },
        }
    }
}

async fn read_netbios_packet(stream: &mut TcpStream) -> std::io::Result<(u8, Vec<u8>)> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).await?;
    let payload_len =
        (usize::from(header[1]) << 16) | (usize::from(header[2]) << 8) | usize::from(header[3]);
    let mut payload = vec![0; payload_len];
    stream.read_exact(&mut payload).await?;
    Ok((header[0], payload))
}

fn default_netbios_called_name(server: &str) -> &str {
    if server.parse::<IpAddr>().is_ok() {
        return NETBIOS_WILDCARD_SERVER_NAME;
    }
    let label = server.split('.').next().unwrap_or(server);
    if label.is_empty() || label.len() > 15 || !label.is_ascii() {
        NETBIOS_WILDCARD_SERVER_NAME
    } else {
        label
    }
}

/// `quinn` QUIC transport for SMB over QUIC.
///
/// SMB over QUIC still carries the same 1-byte zero + 3-byte length message
/// framing used by Direct TCP; only the underlying transport changes from TCP
/// to QUIC.
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
fn quic_read_exact_error_to_io(error: quinn::ReadExactError) -> std::io::Error {
    match error {
        quinn::ReadExactError::FinishedEarly(bytes_read) => std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!("SMB over QUIC stream finished early after {bytes_read} bytes"),
        ),
        quinn::ReadExactError::ReadError(error) => quic_read_error_to_io(error),
    }
}

#[cfg(feature = "quic")]
#[async_trait]
impl Transport for QuicTransport {
    async fn send(&mut self, frame: &[u8]) -> std::io::Result<()> {
        self.send.write_all(frame).await?;
        self.send.flush().await?;
        Ok(())
    }

    async fn recv(&mut self) -> std::io::Result<Vec<u8>> {
        let mut header = [0_u8; 4];
        self.recv
            .read_exact(&mut header)
            .await
            .map_err(quic_read_exact_error_to_io)?;
        let payload_len =
            (usize::from(header[1]) << 16) | (usize::from(header[2]) << 8) | usize::from(header[3]);
        let mut payload = vec![0; payload_len];
        self.recv
            .read_exact(&mut payload)
            .await
            .map_err(quic_read_exact_error_to_io)?;

        let mut frame = Vec::with_capacity(header.len() + payload_len);
        frame.extend_from_slice(&header);
        frame.extend_from_slice(&payload);
        Ok(frame)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    use smolder_proto::smb::netbios::{
        encode_name, SessionMessage, POSITIVE_SESSION_RESPONSE, SESSION_KEEP_ALIVE,
        SESSION_MESSAGE, SESSION_REQUEST,
    };

    use super::{
        default_netbios_called_name, read_netbios_packet, SmbTransport, TokioTcpTransport,
        TransportProtocol, TransportTarget, NETBIOS_CALLING_NAME,
    };

    #[cfg(feature = "quic")]
    use super::QuicTransport;

    #[test]
    fn netbios_target_defaults_connect_name_to_server() {
        let target = TransportTarget::netbios("files.lab.example");

        assert_eq!(target.server(), "files.lab.example");
        assert_eq!(target.connect_host(), "files.lab.example");
        assert_eq!(target.port(), 139);
        assert_eq!(target.protocol(), TransportProtocol::Netbios);
    }

    #[test]
    fn netbios_called_name_uses_first_label_for_hostnames() {
        assert_eq!(default_netbios_called_name("files.lab.example"), "files");
        assert_eq!(default_netbios_called_name("FILES"), "FILES");
    }

    #[test]
    fn netbios_called_name_falls_back_for_ip_addresses() {
        assert_eq!(default_netbios_called_name("127.0.0.1"), "*SMBSERVER");
        assert_eq!(default_netbios_called_name("::1"), "*SMBSERVER");
    }

    #[tokio::test]
    async fn netbios_transport_handshakes_and_ignores_keepalive() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("listener should bind");
        let port = listener
            .local_addr()
            .expect("listener should expose a local address")
            .port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("server should accept");
            let (message_type, payload) = read_netbios_packet(&mut socket)
                .await
                .expect("session request should decode");
            assert_eq!(message_type, SESSION_REQUEST);
            assert_eq!(payload.len(), 68);
            assert_eq!(
                &payload[..34],
                &encode_name("files", 0x20).expect("called name should encode")
            );
            assert_eq!(
                &payload[34..],
                &encode_name(NETBIOS_CALLING_NAME, 0x00).expect("calling name should encode")
            );

            socket
                .write_all(&[POSITIVE_SESSION_RESPONSE, 0x00, 0x00, 0x00])
                .await
                .expect("positive session response should write");
            socket
                .write_all(&[SESSION_KEEP_ALIVE, 0x00, 0x00, 0x00])
                .await
                .expect("keepalive should write");
            socket
                .write_all(
                    &SessionMessage::encode_payload(b"\xfeSMB")
                        .expect("session message should encode"),
                )
                .await
                .expect("session payload should write");

            let (message_type, payload) = read_netbios_packet(&mut socket)
                .await
                .expect("client frame should decode");
            assert_eq!(message_type, SESSION_MESSAGE);
            assert_eq!(payload, b"PING");
        });

        let target = TransportTarget::netbios("files.lab.example")
            .with_connect_host("127.0.0.1")
            .with_port(port);
        let mut transport = TokioTcpTransport::connect_netbios(&target)
            .await
            .expect("NetBIOS transport should connect");

        let message = transport
            .recv_message()
            .await
            .expect("NetBIOS transport should read the SMB payload");
        assert_eq!(message, b"\xfeSMB");
        transport
            .send_message(b"PING")
            .await
            .expect("NetBIOS transport should send framed SMB payloads");

        server.await.expect("server task should finish cleanly");
    }

    #[tokio::test]
    async fn direct_tcp_transport_rejects_non_session_messages() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("listener should bind");
        let addr = listener
            .local_addr()
            .expect("listener should expose a local address");

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("server should accept");
            socket
                .write_all(&[SESSION_KEEP_ALIVE, 0x00, 0x00, 0x00])
                .await
                .expect("keepalive frame should write");
        });

        let mut transport = TokioTcpTransport::connect(addr)
            .await
            .expect("client should connect");
        let error = transport
            .recv_message()
            .await
            .expect_err("non-session frame should fail");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);

        server.await.expect("server task should finish cleanly");
    }

    #[cfg(feature = "quic")]
    #[test]
    fn quic_client_config_sets_smb_alpn() {
        let client_crypto =
            QuicTransport::rustls_client_config().expect("quic client crypto should build");
        assert_eq!(client_crypto.alpn_protocols, vec![b"smb".to_vec()]);
    }

    #[cfg(feature = "quic")]
    #[test]
    fn transport_target_defaults_connect_and_tls_names_to_server() {
        let target = TransportTarget::quic("files.lab.example");

        assert_eq!(target.server(), "files.lab.example");
        assert_eq!(target.connect_host(), "files.lab.example");
        assert_eq!(target.tls_server_name(), "files.lab.example");
        assert_eq!(target.protocol(), TransportProtocol::Quic);
    }

    #[cfg(feature = "quic")]
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
