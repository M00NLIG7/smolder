//! Kerberos authentication for SMB `SESSION_SETUP`.
//!
//! The concrete Kerberos backend lives in sibling modules, but the public API
//! is structured around backend-agnostic credentials and authenticators so
//! additional Kerberos backends can be added without changing the main SMB
//! authentication surface.

use std::fmt;
use std::marker::PhantomData;
#[cfg(all(unix, feature = "kerberos-gssapi"))]
use std::path::{Path, PathBuf};

use smolder_proto::smb::smb2::NegotiateResponse;

#[cfg(all(unix, feature = "kerberos-gssapi"))]
use super::kerberos_gssapi::GssapiKerberosBackend;
#[cfg(feature = "kerberos-sspi")]
use super::kerberos_sspi::SspiNegotiateKerberosBackend;
use super::kerberos_spn::KerberosTarget;
use super::spnego::{
    encode_neg_token_init, encode_neg_token_resp, extract_mech_token, parse_neg_token_resp,
};
use super::{AuthError, AuthProvider, SpnegoMechanism};

/// Backend implementation used to satisfy a Kerberos SMB authentication request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KerberosBackendKind {
    /// Unix GSSAPI-backed Kerberos backend using the local ticket cache.
    #[cfg(all(unix, feature = "kerberos-gssapi"))]
    Gssapi,
    /// `sspi`-based Kerberos backend.
    #[cfg(feature = "kerberos-sspi")]
    Sspi,
}

/// Credential source represented by [`KerberosCredentials`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KerberosCredentialSourceKind {
    /// Username/password-backed Kerberos credentials.
    Password,
    /// Ticket-cache-backed Kerberos credentials.
    #[cfg(all(unix, feature = "kerberos-gssapi"))]
    TicketCache,
    /// Client-keytab-backed Kerberos credentials.
    #[cfg(all(unix, feature = "kerberos-gssapi"))]
    Keytab,
}

/// Kerberos credentials and backend selection for SMB authentication.
#[derive(Clone, PartialEq, Eq)]
pub struct KerberosCredentials {
    username: String,
    password: String,
    domain: String,
    workstation: String,
    kdc_url: Option<String>,
    #[cfg(all(unix, feature = "kerberos-gssapi"))]
    keytab_name: Option<String>,
    backend: KerberosBackendKind,
    source_kind: KerberosCredentialSourceKind,
}

impl fmt::Debug for KerberosCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("KerberosCredentials");
        debug
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("domain", &self.domain)
            .field("workstation", &self.workstation)
            .field("kdc_url", &self.kdc_url);
        #[cfg(all(unix, feature = "kerberos-gssapi"))]
        debug.field("keytab_name", &self.keytab_name);
        debug
            .field("backend", &self.backend)
            .field("source_kind", &self.source_kind)
            .finish()
    }
}

impl KerberosCredentials {
    /// Creates password-backed Kerberos credentials for an SMB account.
    #[cfg(feature = "kerberos-sspi")]
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self::from_password(username, password)
    }

    /// Creates password-backed Kerberos credentials for an SMB account.
    #[cfg(feature = "kerberos-sspi")]
    pub fn from_password(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
            domain: String::new(),
            workstation: "smolder".to_owned(),
            kdc_url: None,
            #[cfg(all(unix, feature = "kerberos-gssapi"))]
            keytab_name: None,
            backend: default_backend_kind(),
            source_kind: KerberosCredentialSourceKind::Password,
        }
    }

    /// Creates Kerberos credentials that use the default Unix ticket cache.
    #[cfg(all(unix, feature = "kerberos-gssapi"))]
    pub fn from_default_ticket_cache() -> Self {
        Self {
            username: String::new(),
            password: String::new(),
            domain: String::new(),
            workstation: "smolder".to_owned(),
            kdc_url: None,
            keytab_name: None,
            backend: KerberosBackendKind::Gssapi,
            source_kind: KerberosCredentialSourceKind::TicketCache,
        }
    }

    /// Creates Kerberos credentials that use a specific principal from the Unix ticket cache.
    #[cfg(all(unix, feature = "kerberos-gssapi"))]
    pub fn from_ticket_cache(username: impl Into<String>) -> Self {
        Self::from_default_ticket_cache().with_username(username)
    }

    /// Creates Kerberos credentials that acquire initiator credentials from a client keytab.
    #[cfg(all(unix, feature = "kerberos-gssapi"))]
    pub fn from_keytab(username: impl Into<String>, keytab_name: impl Into<String>) -> Self {
        Self::from_default_keytab(keytab_name).with_username(username)
    }

    /// Creates Kerberos credentials that acquire initiator credentials from the default principal
    /// in a client keytab.
    #[cfg(all(unix, feature = "kerberos-gssapi"))]
    pub fn from_default_keytab(keytab_name: impl Into<String>) -> Self {
        Self {
            username: String::new(),
            password: String::new(),
            domain: String::new(),
            workstation: "smolder".to_owned(),
            kdc_url: None,
            keytab_name: Some(normalize_keytab_name(keytab_name.into())),
            backend: KerberosBackendKind::Gssapi,
            source_kind: KerberosCredentialSourceKind::Keytab,
        }
    }

    #[cfg(all(unix, feature = "kerberos-gssapi"))]
    fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = username.into();
        self
    }

    /// Sets the Kerberos domain used to build the client principal.
    #[must_use]
    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = domain.into();
        self
    }

    /// Sets the workstation name sent to the Kerberos backend.
    #[must_use]
    pub fn with_workstation(mut self, workstation: impl Into<String>) -> Self {
        self.workstation = workstation.into();
        self
    }

    /// Overrides the KDC URL used for the Kerberos exchange.
    ///
    /// The value may be a bare `host:port`, `tcp://host:port`, `udp://host:port`,
    /// or an HTTP(S) KDC proxy URL understood by `sspi`.
    #[must_use]
    pub fn with_kdc_url(mut self, kdc_url: impl Into<String>) -> Self {
        self.kdc_url = Some(kdc_url.into());
        self
    }

    /// Returns the backend implementation selected for this credential set.
    #[must_use]
    pub fn backend_kind(&self) -> KerberosBackendKind {
        self.backend
    }

    /// Returns the credential source carried by this credential set.
    #[must_use]
    pub fn credential_source_kind(&self) -> KerberosCredentialSourceKind {
        self.source_kind
    }

    #[cfg(all(unix, feature = "kerberos-gssapi"))]
    pub(super) fn keytab_name(&self) -> Option<&str> {
        self.keytab_name.as_deref()
    }

    #[cfg(all(unix, feature = "kerberos-gssapi"))]
    pub(super) fn initiator_principal(&self) -> Result<Option<String>, AuthError> {
        let username = self.username.trim();
        let domain = self.domain.trim();
        if username.is_empty() {
            return Ok(None);
        }

        if !domain.is_empty() && (username.contains('@') || username.contains('\\')) {
            return Err(AuthError::InvalidState(
                "kerberos username/domain combination must be a bare account name, UPN, or down-level logon name",
            ));
        }

        if username.contains('@') || username.contains('\\') || domain.is_empty() {
            Ok(Some(self.username.clone()))
        } else {
            Ok(Some(format!("{}@{}", self.username, self.domain)))
        }
    }

    #[cfg(feature = "kerberos-sspi")]
    fn username(&self) -> Result<sspi::Username, AuthError> {
        let domain = (!self.domain.is_empty()).then_some(self.domain.as_str());
        sspi::Username::new(&self.username, domain).map_err(|_| {
            AuthError::InvalidState(
                "kerberos username/domain combination must be a bare account name, UPN, or down-level logon name",
            )
        })
    }

    #[cfg(feature = "kerberos-sspi")]
    pub(super) fn auth_identity(&self) -> Result<sspi::AuthIdentity, AuthError> {
        Ok(sspi::AuthIdentity {
            username: self.username()?,
            password: self.password.clone().into(),
        })
    }

    #[cfg(any(feature = "kerberos-sspi", test))]
    pub(super) fn client_computer_name(&self) -> &str {
        if self.workstation.is_empty() {
            "smolder"
        } else {
            self.workstation.as_str()
        }
    }

    #[cfg(any(feature = "kerberos-sspi", test))]
    pub(super) fn kdc_url(&self) -> Option<&str> {
        self.kdc_url.as_deref()
    }
}

#[cfg(all(unix, feature = "kerberos-gssapi"))]
fn normalize_keytab_name(keytab_name: String) -> String {
    if keytab_name.contains(':') {
        keytab_name
    } else {
        let path = Path::new(&keytab_name);
        let canonical = if path.is_absolute() {
            PathBuf::from(path)
        } else {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(path)
        };
        format!("FILE:{}", canonical.to_string_lossy())
    }
}

#[cfg(feature = "kerberos-sspi")]
fn default_backend_kind() -> KerberosBackendKind {
    KerberosBackendKind::Sspi
}

enum KerberosAuthenticatorInner {
    #[cfg(all(unix, feature = "kerberos-gssapi"))]
    Gssapi(KerberosAuthEngine<GssapiKerberosBackend>),
    #[cfg(feature = "kerberos-sspi")]
    Sspi(KerberosAuthEngine<SspiNegotiateKerberosBackend>),
}

/// Kerberos `AuthProvider` selected from the configured backend and credential source.
pub struct KerberosAuthenticator {
    inner: KerberosAuthenticatorInner,
}

impl KerberosAuthenticator {
    /// Creates a Kerberos authenticator using the provided credentials and SMB target.
    pub fn new(credentials: KerberosCredentials, target: KerberosTarget) -> Self {
        let inner = match credentials.backend_kind() {
            #[cfg(all(unix, feature = "kerberos-gssapi"))]
            KerberosBackendKind::Gssapi => {
                KerberosAuthenticatorInner::Gssapi(KerberosAuthEngine::new(credentials, target))
            }
            #[cfg(feature = "kerberos-sspi")]
            KerberosBackendKind::Sspi => {
                KerberosAuthenticatorInner::Sspi(KerberosAuthEngine::new(credentials, target))
            }
        };
        Self { inner }
    }

    /// Returns the SMB Kerberos target for this exchange.
    pub fn target(&self) -> &KerberosTarget {
        match &self.inner {
            #[cfg(all(unix, feature = "kerberos-gssapi"))]
            KerberosAuthenticatorInner::Gssapi(inner) => &inner.target,
            #[cfg(feature = "kerberos-sspi")]
            KerberosAuthenticatorInner::Sspi(inner) => &inner.target,
        }
    }

    /// Returns the credentials used for this exchange.
    pub fn credentials(&self) -> &KerberosCredentials {
        match &self.inner {
            #[cfg(all(unix, feature = "kerberos-gssapi"))]
            KerberosAuthenticatorInner::Gssapi(inner) => &inner.credentials,
            #[cfg(feature = "kerberos-sspi")]
            KerberosAuthenticatorInner::Sspi(inner) => &inner.credentials,
        }
    }

    /// Returns the backend implementation selected for this exchange.
    #[must_use]
    pub fn backend_kind(&self) -> KerberosBackendKind {
        self.credentials().backend_kind()
    }
}

impl AuthProvider for KerberosAuthenticator {
    fn initial_token(&mut self, negotiate: &NegotiateResponse) -> Result<Vec<u8>, AuthError> {
        match &mut self.inner {
            #[cfg(all(unix, feature = "kerberos-gssapi"))]
            KerberosAuthenticatorInner::Gssapi(inner) => inner.initial_token(negotiate),
            #[cfg(feature = "kerberos-sspi")]
            KerberosAuthenticatorInner::Sspi(inner) => inner.initial_token(negotiate),
        }
    }

    fn next_token(&mut self, incoming: &[u8]) -> Result<Vec<u8>, AuthError> {
        match &mut self.inner {
            #[cfg(all(unix, feature = "kerberos-gssapi"))]
            KerberosAuthenticatorInner::Gssapi(inner) => inner.next_token(incoming),
            #[cfg(feature = "kerberos-sspi")]
            KerberosAuthenticatorInner::Sspi(inner) => inner.next_token(incoming),
        }
    }

    fn finish(&mut self, incoming: &[u8]) -> Result<(), AuthError> {
        match &mut self.inner {
            #[cfg(all(unix, feature = "kerberos-gssapi"))]
            KerberosAuthenticatorInner::Gssapi(inner) => inner.finish(incoming),
            #[cfg(feature = "kerberos-sspi")]
            KerberosAuthenticatorInner::Sspi(inner) => inner.finish(incoming),
        }
    }

    fn session_key(&self) -> Option<&[u8]> {
        match &self.inner {
            #[cfg(all(unix, feature = "kerberos-gssapi"))]
            KerberosAuthenticatorInner::Gssapi(inner) => inner.session_key(),
            #[cfg(feature = "kerberos-sspi")]
            KerberosAuthenticatorInner::Sspi(inner) => inner.session_key(),
        }
    }
}

enum KerberosState<P, C> {
    Initial,
    Pending(P),
    Established(C),
    Complete,
}

pub(super) enum KerberosStep<P, C> {
    Continue { pending: P, token: Vec<u8> },
    Finished { context: C, token: Option<Vec<u8>> },
}

pub(super) trait KerberosBackend {
    const SPNEGO_WRAPPED: bool;

    type Pending;
    type Context;

    fn initiate(
        credentials: &KerberosCredentials,
        target: &KerberosTarget,
    ) -> Result<KerberosStep<Self::Pending, Self::Context>, AuthError>;

    fn step(
        pending: Self::Pending,
        incoming: &[u8],
        target: &KerberosTarget,
    ) -> Result<KerberosStep<Self::Pending, Self::Context>, AuthError>;

    fn interim_session_key(_pending: &Self::Pending) -> Result<Option<Vec<u8>>, AuthError> {
        Ok(None)
    }

    fn session_key(context: &Self::Context) -> Result<Vec<u8>, AuthError>;
}

struct KerberosAuthEngine<B: KerberosBackend> {
    credentials: KerberosCredentials,
    target: KerberosTarget,
    state: KerberosState<B::Pending, B::Context>,
    session_key: Option<Vec<u8>>,
    _backend: PhantomData<B>,
}

impl<B: KerberosBackend> KerberosAuthEngine<B> {
    fn new(credentials: KerberosCredentials, target: KerberosTarget) -> Self {
        Self {
            credentials,
            target,
            state: KerberosState::Initial,
            session_key: None,
            _backend: PhantomData,
        }
    }
}

impl<B: KerberosBackend> AuthProvider for KerberosAuthEngine<B> {
    fn initial_token(&mut self, _negotiate: &NegotiateResponse) -> Result<Vec<u8>, AuthError> {
        if !matches!(self.state, KerberosState::Initial) {
            return Err(AuthError::InvalidState(
                "initial token requested after kerberos authentication started",
            ));
        }

        match B::initiate(&self.credentials, &self.target)? {
            KerberosStep::Continue { pending, token } => {
                self.session_key = B::interim_session_key(&pending)?;
                self.state = KerberosState::Pending(pending);
                if B::SPNEGO_WRAPPED {
                    Ok(token)
                } else {
                    Ok(encode_neg_token_init(
                        &[SpnegoMechanism::KerberosV5],
                        Some(&token),
                    ))
                }
            }
            KerberosStep::Finished { context, token } => {
                let token = token.ok_or(AuthError::InvalidState(
                    "kerberos backend finished without an initial token",
                ))?;
                self.session_key = Some(B::session_key(&context)?);
                self.state = KerberosState::Established(context);
                if B::SPNEGO_WRAPPED {
                    Ok(token)
                } else {
                    Ok(encode_neg_token_init(
                        &[SpnegoMechanism::KerberosV5],
                        Some(&token),
                    ))
                }
            }
        }
    }

    fn next_token(&mut self, incoming: &[u8]) -> Result<Vec<u8>, AuthError> {
        let pending = match std::mem::replace(&mut self.state, KerberosState::Complete) {
            KerberosState::Pending(pending) => pending,
            KerberosState::Initial => {
                self.state = KerberosState::Initial;
                return Err(AuthError::InvalidState(
                    "kerberos challenge received before initial token was sent",
                ));
            }
            KerberosState::Established(context) => {
                self.state = KerberosState::Established(context);
                return Err(AuthError::InvalidState(
                    "kerberos context already established",
                ));
            }
            KerberosState::Complete => {
                return Err(AuthError::InvalidState(
                    "kerberos authentication already finished",
                ));
            }
        };

        let server_token = if B::SPNEGO_WRAPPED {
            incoming.to_vec()
        } else {
            match extract_mech_token(incoming) {
                Ok(token) => token,
                Err(AuthError::InvalidToken("SPNEGO response token missing"))
                | Err(AuthError::InvalidToken("SPNEGO mech token missing")) => Vec::new(),
                Err(error) => return Err(error),
            }
        };
        match B::step(pending, &server_token, &self.target)? {
            KerberosStep::Continue { pending, token } => {
                self.session_key = B::interim_session_key(&pending)?;
                self.state = KerberosState::Pending(pending);
                if B::SPNEGO_WRAPPED {
                    Ok(token)
                } else {
                    Ok(encode_neg_token_resp(None, Some(&token), None))
                }
            }
            KerberosStep::Finished { context, token } => {
                self.session_key = Some(B::session_key(&context)?);
                self.state = KerberosState::Established(context);
                if B::SPNEGO_WRAPPED {
                    Ok(token.unwrap_or_default())
                } else {
                    Ok(token
                        .map(|token| encode_neg_token_resp(None, Some(&token), None))
                        .unwrap_or_default())
                }
            }
        }
    }

    fn finish(&mut self, incoming: &[u8]) -> Result<(), AuthError> {
        match std::mem::replace(&mut self.state, KerberosState::Complete) {
            KerberosState::Initial => {
                self.state = KerberosState::Initial;
                Err(AuthError::InvalidState(
                    "kerberos authentication was finished before it started",
                ))
            }
            KerberosState::Pending(pending) => {
                if incoming.is_empty() {
                    self.state = KerberosState::Pending(pending);
                    return Err(AuthError::InvalidState(
                        "kerberos session setup completed without a final server token",
                    ));
                }

                let server_token = if B::SPNEGO_WRAPPED {
                    incoming.to_vec()
                } else {
                    extract_mech_token(incoming)?
                };
                match B::step(pending, &server_token, &self.target)? {
                    KerberosStep::Finished { context, token: None } => {
                        self.session_key = Some(B::session_key(&context)?);
                        Ok(())
                    }
                    KerberosStep::Finished { token: Some(_), .. } => Err(AuthError::InvalidState(
                        "kerberos finish produced an unexpected client continuation token",
                    )),
                    KerberosStep::Continue { .. } => Err(AuthError::InvalidState(
                        "kerberos finish requires another round trip",
                    )),
                }
            }
            KerberosState::Established(context) => {
                if incoming.is_empty() {
                    self.state = KerberosState::Established(context);
                    return Ok(());
                }

                if !B::SPNEGO_WRAPPED {
                    let parsed = parse_neg_token_resp(incoming)?;
                    if parsed.response_token.is_some() {
                        self.state = KerberosState::Established(context);
                        return Err(AuthError::InvalidToken(
                            "unexpected kerberos response token after context establishment",
                        ));
                    }
                }

                self.state = KerberosState::Established(context);
                Ok(())
            }
            KerberosState::Complete => Ok(()),
        }
    }

    fn session_key(&self) -> Option<&[u8]> {
        self.session_key.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use smolder_proto::smb::smb2::{Dialect, GlobalCapabilities, NegotiateResponse, SigningMode};

    use super::super::spnego::{extract_mech_token, parse_neg_token_init};
    use super::*;

    struct MockBackend;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum MockPending {
        AwaitingChallenge,
        AwaitingFinish,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct MockContext;

    impl KerberosBackend for MockBackend {
        const SPNEGO_WRAPPED: bool = false;

        type Pending = MockPending;
        type Context = MockContext;

        fn initiate(
            credentials: &KerberosCredentials,
            target: &KerberosTarget,
        ) -> Result<KerberosStep<Self::Pending, Self::Context>, AuthError> {
            assert_eq!(credentials.username, "alice");
            assert_eq!(credentials.domain, "EXAMPLE.COM");
            assert_eq!(credentials.client_computer_name(), "WORKSTATION1");
            assert_eq!(credentials.kdc_url(), Some("tcp://dc01.example.com:88"));
            #[cfg(feature = "kerberos-sspi")]
            assert_eq!(
                credentials.username().expect("username should parse").inner(),
                "EXAMPLE.COM\\alice"
            );
            assert_eq!(
                target.service_principal_name().expect("SPN should derive"),
                "cifs/fileserver.example.com@EXAMPLE.COM"
            );
            Ok(KerberosStep::Continue {
                pending: MockPending::AwaitingChallenge,
                token: b"ap-req".to_vec(),
            })
        }

        fn step(
            pending: Self::Pending,
            incoming: &[u8],
            _target: &KerberosTarget,
        ) -> Result<KerberosStep<Self::Pending, Self::Context>, AuthError> {
            match pending {
                MockPending::AwaitingChallenge => {
                    assert_eq!(incoming, b"krb-error");
                    Ok(KerberosStep::Continue {
                        pending: MockPending::AwaitingFinish,
                        token: b"ap-retry".to_vec(),
                    })
                }
                MockPending::AwaitingFinish => {
                    assert_eq!(incoming, b"ap-rep");
                    Ok(KerberosStep::Finished {
                        context: MockContext,
                        token: None,
                    })
                }
            }
        }

        fn session_key(_context: &Self::Context) -> Result<Vec<u8>, AuthError> {
            Ok(b"0123456789abcdef".to_vec())
        }
    }

    fn negotiate_response() -> NegotiateResponse {
        NegotiateResponse {
            security_mode: SigningMode::ENABLED,
            dialect_revision: Dialect::Smb311,
            negotiate_contexts: Vec::new(),
            server_guid: [0; 16],
            capabilities: GlobalCapabilities::empty(),
            max_transact_size: 0,
            max_read_size: 0,
            max_write_size: 0,
            system_time: 0,
            server_start_time: 0,
            security_buffer: Vec::new(),
        }
    }

    #[cfg(feature = "kerberos-sspi")]
    fn test_credentials() -> KerberosCredentials {
        KerberosCredentials::new("alice", "password")
            .with_domain("EXAMPLE.COM")
            .with_workstation("WORKSTATION1")
            .with_kdc_url("tcp://dc01.example.com:88")
    }

    #[cfg(all(not(feature = "kerberos-sspi"), unix, feature = "kerberos-gssapi"))]
    fn test_credentials() -> KerberosCredentials {
        KerberosCredentials::from_ticket_cache("alice")
            .with_domain("EXAMPLE.COM")
            .with_workstation("WORKSTATION1")
            .with_kdc_url("tcp://dc01.example.com:88")
    }

    #[cfg(feature = "kerberos-sspi")]
    #[test]
    fn password_credentials_default_to_sspi_backend() {
        let credentials = test_credentials();

        assert_eq!(credentials.backend_kind(), KerberosBackendKind::Sspi);
        assert_eq!(
            credentials.credential_source_kind(),
            KerberosCredentialSourceKind::Password
        );
    }

    #[cfg(all(unix, feature = "kerberos-gssapi"))]
    #[test]
    fn ticket_cache_credentials_select_gssapi_backend() {
        let credentials = KerberosCredentials::from_ticket_cache("alice").with_domain("EXAMPLE.COM");

        assert_eq!(credentials.backend_kind(), KerberosBackendKind::Gssapi);
        assert_eq!(
            credentials.credential_source_kind(),
            KerberosCredentialSourceKind::TicketCache
        );
        assert_eq!(
            credentials
                .initiator_principal()
                .expect("principal should derive"),
            Some("alice@EXAMPLE.COM".to_owned())
        );
    }

    #[cfg(all(unix, feature = "kerberos-gssapi"))]
    #[test]
    fn keytab_credentials_select_gssapi_backend() {
        let credentials =
            KerberosCredentials::from_keytab("alice", "/tmp/alice.keytab").with_domain("EXAMPLE.COM");

        assert_eq!(credentials.backend_kind(), KerberosBackendKind::Gssapi);
        assert_eq!(
            credentials.credential_source_kind(),
            KerberosCredentialSourceKind::Keytab
        );
        assert_eq!(
            credentials.keytab_name(),
            Some("FILE:/tmp/alice.keytab")
        );
    }

    #[cfg(all(unix, feature = "kerberos-gssapi"))]
    #[test]
    fn default_ticket_cache_credentials_use_default_principal() {
        let credentials = KerberosCredentials::from_default_ticket_cache();

        assert_eq!(
            credentials
                .initiator_principal()
                .expect("default cache should allow an unspecified principal"),
            None
        );
    }

    #[cfg(all(unix, feature = "kerberos-gssapi"))]
    #[test]
    fn default_keytab_credentials_use_default_principal() {
        let credentials = KerberosCredentials::from_default_keytab("./alice.keytab");

        assert_eq!(
            credentials
                .initiator_principal()
                .expect("default keytab should allow an unspecified principal"),
            None
        );
        assert!(
            credentials
                .keytab_name()
                .expect("keytab should be recorded")
                .starts_with("FILE:")
        );
    }

    #[test]
    fn initial_token_advertises_kerberos_mechanism() {
        let target =
            KerberosTarget::for_smb_host("fileserver.example.com").with_realm("EXAMPLE.COM");
        let mut auth = KerberosAuthEngine::<MockBackend>::new(test_credentials(), target);

        let token = auth
            .initial_token(&negotiate_response())
            .expect("initial token should build");

        let init = parse_neg_token_init(&token).expect("SPNEGO token should parse");
        assert_eq!(init.mech_types, vec![SpnegoMechanism::KerberosV5]);
        assert_eq!(
            extract_mech_token(&token).expect("token should unwrap"),
            b"ap-req"
        );
    }

    #[test]
    fn next_token_wraps_backend_continuation() {
        let target =
            KerberosTarget::for_smb_host("fileserver.example.com").with_realm("EXAMPLE.COM");
        let mut auth = KerberosAuthEngine::<MockBackend>::new(test_credentials(), target);

        auth.initial_token(&negotiate_response())
            .expect("initial token should build");

        let response = auth
            .next_token(&encode_neg_token_resp(None, Some(b"krb-error"), None))
            .expect("continuation token should build");

        assert_eq!(
            extract_mech_token(&response).expect("token should unwrap"),
            b"ap-retry"
        );
    }

    #[test]
    fn finish_consumes_final_kerberos_response_token() {
        let target =
            KerberosTarget::for_smb_host("fileserver.example.com").with_realm("EXAMPLE.COM");
        let mut auth = KerberosAuthEngine::<MockBackend>::new(test_credentials(), target);

        auth.initial_token(&negotiate_response())
            .expect("initial token should build");
        auth.next_token(&encode_neg_token_resp(None, Some(b"krb-error"), None))
            .expect("continuation token should build");

        auth.finish(&encode_neg_token_resp(None, Some(b"ap-rep"), None))
            .expect("finish should consume the final token");
        assert_eq!(auth.session_key(), Some(&b"0123456789abcdef"[..]));
    }

    #[cfg(feature = "kerberos-sspi")]
    #[test]
    fn rejects_mixed_username_formats() {
        let error = KerberosCredentials::new("alice@example.com", "password")
            .with_domain("EXAMPLE")
            .username()
            .expect_err("UPN plus domain should fail");

        assert!(matches!(error, AuthError::InvalidState(_)));
    }

    #[test]
    fn authenticator_reports_selected_backend() {
        let target =
            KerberosTarget::for_smb_host("fileserver.example.com").with_realm("EXAMPLE.COM");
        let credentials = test_credentials();
        let expected = credentials.backend_kind();
        let auth = KerberosAuthenticator::new(credentials, target);

        assert_eq!(auth.backend_kind(), expected);
    }
}
