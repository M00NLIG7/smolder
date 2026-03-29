//! High-level embedded client facade built on top of the typestate SMB client.
//!
//! This module is the intended additive entry point for users who want a
//! friendlier `connect -> authenticate -> tree connect` flow without dropping
//! directly into raw typestate orchestration.

use rand::random;

use smolder_proto::smb::smb2::{
    Dialect, EchoResponse, GlobalCapabilities, SessionId, SigningMode, TreeConnectRequest, TreeId,
};

use crate::auth::NtlmCredentials;
#[cfg(feature = "kerberos-api")]
use crate::auth::{KerberosCredentials, KerberosTarget};
use crate::client::{Authenticated, Connection, TreeConnected};
use crate::error::CoreError;
use crate::pipe::{connect_session, SmbSessionConfig};
use crate::transport::TokioTcpTransport;

const DEFAULT_PORT: u16 = 445;

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
    server: String,
    port: u16,
    auth: Option<BuilderAuth>,
    signing_mode: SigningMode,
    capabilities: GlobalCapabilities,
    dialects: Vec<Dialect>,
    client_guid: [u8; 16],
}

impl ClientBuilder {
    /// Creates a new client builder for the target server.
    #[must_use]
    pub fn new(server: impl Into<String>) -> Self {
        Self {
            server: server.into(),
            port: DEFAULT_PORT,
            auth: None,
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
            BuilderAuth::Ntlm(credentials) => SmbSessionConfig::new(self.server, credentials),
            #[cfg(feature = "kerberos-api")]
            BuilderAuth::Kerberos {
                credentials,
                target,
            } => SmbSessionConfig::kerberos(self.server, credentials, target),
        }
        .with_port(self.port)
        .with_signing_mode(self.signing_mode)
        .with_capabilities(self.capabilities)
        .with_dialects(self.dialects)
        .with_client_guid(self.client_guid);

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
}

/// Authenticated SMB session returned by the high-level client.
#[derive(Debug)]
pub struct Session {
    server: String,
    connection: Connection<TokioTcpTransport, Authenticated>,
}

impl Session {
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
    pub fn connection(&self) -> &Connection<TokioTcpTransport, Authenticated> {
        &self.connection
    }

    /// Returns a mutable reference to the wrapped authenticated connection.
    #[must_use]
    pub fn connection_mut(&mut self) -> &mut Connection<TokioTcpTransport, Authenticated> {
        &mut self.connection
    }

    /// Consumes the session wrapper and returns the underlying authenticated connection.
    #[must_use]
    pub fn into_connection(self) -> Connection<TokioTcpTransport, Authenticated> {
        self.connection
    }

    /// Performs an `ECHO` request against the active SMB session.
    pub async fn echo(&mut self) -> Result<EchoResponse, CoreError> {
        self.connection.echo().await
    }

    /// Tree-connects to the requested share.
    pub async fn connect_share(self, share: &str) -> Result<Share, CoreError> {
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
    pub async fn connect_ipc(self) -> Result<Share, CoreError> {
        self.connect_share("IPC$").await
    }

    /// Logs off the authenticated SMB session.
    pub async fn logoff(self) -> Result<(), CoreError> {
        let _ = self.connection.logoff().await?;
        Ok(())
    }
}

/// Tree-connected SMB share returned by the high-level client/session facade.
#[derive(Debug)]
pub struct Share {
    server: String,
    name: String,
    connection: Connection<TokioTcpTransport, TreeConnected>,
}

impl Share {
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
    pub fn connection(&self) -> &Connection<TokioTcpTransport, TreeConnected> {
        &self.connection
    }

    /// Returns a mutable reference to the wrapped tree-connected connection.
    #[must_use]
    pub fn connection_mut(&mut self) -> &mut Connection<TokioTcpTransport, TreeConnected> {
        &mut self.connection
    }

    /// Consumes the share wrapper and returns the underlying tree-connected connection.
    #[must_use]
    pub fn into_connection(self) -> Connection<TokioTcpTransport, TreeConnected> {
        self.connection
    }

    /// Disconnects the tree and returns to an authenticated session wrapper.
    pub async fn disconnect(self) -> Result<Session, CoreError> {
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

#[cfg(test)]
mod tests {
    use smolder_proto::smb::smb2::{Dialect, GlobalCapabilities, SigningMode};

    use crate::auth::NtlmCredentials;
    #[cfg(feature = "kerberos-api")]
    use crate::auth::{KerberosCredentials, KerberosTarget};

    use super::{normalize_share_name, Client, ClientBuilder};

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
}
