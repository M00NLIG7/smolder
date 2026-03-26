//! High-level reconnect helpers built on top of the SMB file facade.

use crate::fs::{Share, SmbClient, SmbClientBuilder};
use smolder_core::prelude::CoreError;
use smolder_proto::smb::smb2::{Dialect, GlobalCapabilities, SigningMode};

/// Rebuilds a fresh SMB session/tree for a specific share after transport loss.
///
/// This lives in `smolder-tools` because it is orchestration over the core
/// SMB primitives, not a protocol primitive itself.
#[derive(Debug, Clone)]
pub struct ShareReconnectPlan {
    builder: SmbClientBuilder,
    share: String,
}

impl ShareReconnectPlan {
    /// Creates a reconnect plan from an already-configured SMB client builder.
    #[must_use]
    pub fn from_builder(builder: SmbClientBuilder, share: impl Into<String>) -> Self {
        Self {
            builder,
            share: share.into(),
        }
    }

    /// Creates a reconnect plan from server, share, and credentials.
    #[must_use]
    pub fn new(
        server: impl Into<String>,
        share: impl Into<String>,
        credentials: smolder_core::prelude::NtlmCredentials,
    ) -> Self {
        Self::from_builder(
            SmbClient::builder()
                .server(server.into())
                .credentials(credentials),
            share,
        )
    }

    /// Overrides the target SMB server host name or IP address.
    #[must_use]
    pub fn server(mut self, server: impl Into<String>) -> Self {
        self.builder = self.builder.server(server.into());
        self
    }

    /// Overrides the target share name.
    #[must_use]
    pub fn share(mut self, share: impl Into<String>) -> Self {
        self.share = share.into();
        self
    }

    /// Overrides the TCP port used for the SMB connection.
    #[must_use]
    pub fn port(mut self, port: u16) -> Self {
        self.builder = self.builder.port(port);
        self
    }

    /// Overrides the SMB credentials used during reconnect.
    #[must_use]
    pub fn credentials(mut self, credentials: smolder_core::prelude::NtlmCredentials) -> Self {
        self.builder = self.builder.credentials(credentials);
        self
    }

    /// Overrides the negotiated SMB dialect list used during reconnect.
    #[must_use]
    pub fn dialects(mut self, dialects: Vec<Dialect>) -> Self {
        self.builder = self.builder.dialects(dialects);
        self
    }

    /// Overrides the SMB signing mode used during reconnect.
    #[must_use]
    pub fn signing_mode(mut self, signing_mode: SigningMode) -> Self {
        self.builder = self.builder.signing_mode(signing_mode);
        self
    }

    /// Overrides the SMB global capabilities used during reconnect.
    #[must_use]
    pub fn capabilities(mut self, capabilities: GlobalCapabilities) -> Self {
        self.builder = self.builder.capabilities(capabilities);
        self
    }

    /// Overrides the SMB client GUID used during reconnect.
    #[must_use]
    pub fn client_guid(mut self, client_guid: [u8; 16]) -> Self {
        self.builder = self.builder.client_guid(client_guid);
        self
    }

    /// Overrides the high-level transfer chunk size used by the reconnected share.
    #[must_use]
    pub fn transfer_chunk_size(mut self, transfer_chunk_size: u32) -> Self {
        self.builder = self.builder.transfer_chunk_size(transfer_chunk_size);
        self
    }

    /// Returns the share name that will be reconnected.
    #[must_use]
    pub fn share_name(&self) -> &str {
        &self.share
    }

    /// Rebuilds the transport, authenticates a fresh SMB session, and tree-connects the share.
    pub async fn connect(&self) -> Result<Share, CoreError> {
        let client = self.builder.clone().connect().await?;
        client.share(self.share.clone()).await
    }
}
