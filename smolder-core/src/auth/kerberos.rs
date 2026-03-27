//! Kerberos authentication for SMB `SESSION_SETUP`.
//!
//! The current implementation is backed by the `sspi` crate, but the public
//! API is structured around backend-agnostic credentials and authenticators so
//! additional Kerberos backends can be added without changing the main SMB
//! authentication surface.

use std::fmt;
use std::marker::PhantomData;

use smolder_proto::smb::smb2::NegotiateResponse;
#[cfg(feature = "kerberos-sspi")]
use sspi::{KerberosConfig, Negotiate, NegotiateConfig, Sspi, SspiImpl};

use super::kerberos_spn::KerberosTarget;
use super::spnego::{
    encode_neg_token_init, encode_neg_token_resp, extract_mech_token, parse_neg_token_resp,
};
use super::{AuthError, AuthProvider, SpnegoMechanism};

/// Backend implementation used to satisfy a Kerberos SMB authentication request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KerberosBackendKind {
    /// `sspi`-based Kerberos backend.
    #[cfg(feature = "kerberos-sspi")]
    Sspi,
}

/// Credential source represented by [`KerberosCredentials`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KerberosCredentialSourceKind {
    /// Username/password-backed Kerberos credentials.
    Password,
}

/// Kerberos credentials and backend selection for SMB authentication.
#[derive(Clone, PartialEq, Eq)]
pub struct KerberosCredentials {
    username: String,
    password: String,
    domain: String,
    workstation: String,
    kdc_url: Option<String>,
    backend: KerberosBackendKind,
}

impl fmt::Debug for KerberosCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KerberosCredentials")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("domain", &self.domain)
            .field("workstation", &self.workstation)
            .field("kdc_url", &self.kdc_url)
            .field("backend", &self.backend)
            .field("source_kind", &self.credential_source_kind())
            .finish()
    }
}

impl KerberosCredentials {
    /// Creates password-backed Kerberos credentials for an SMB account.
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self::from_password(username, password)
    }

    /// Creates password-backed Kerberos credentials for an SMB account.
    pub fn from_password(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
            domain: String::new(),
            workstation: "smolder".to_owned(),
            kdc_url: None,
            backend: default_backend_kind(),
        }
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
        KerberosCredentialSourceKind::Password
    }

    fn username(&self) -> Result<sspi::Username, AuthError> {
        let domain = (!self.domain.is_empty()).then_some(self.domain.as_str());
        sspi::Username::new(&self.username, domain).map_err(|_| {
            AuthError::InvalidState(
                "kerberos username/domain combination must be a bare account name, UPN, or down-level logon name",
            )
        })
    }

    fn auth_identity(&self) -> Result<sspi::AuthIdentity, AuthError> {
        Ok(sspi::AuthIdentity {
            username: self.username()?,
            password: self.password.clone().into(),
        })
    }

    fn client_computer_name(&self) -> &str {
        if self.workstation.is_empty() {
            "smolder"
        } else {
            self.workstation.as_str()
        }
    }

    fn kdc_url(&self) -> Option<&str> {
        self.kdc_url.as_deref()
    }
}

fn default_backend_kind() -> KerberosBackendKind {
    #[cfg(feature = "kerberos-sspi")]
    {
        KerberosBackendKind::Sspi
    }
}

enum KerberosAuthenticatorInner {
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
            #[cfg(feature = "kerberos-sspi")]
            KerberosAuthenticatorInner::Sspi(inner) => &inner.target,
        }
    }

    /// Returns the credentials used for this exchange.
    pub fn credentials(&self) -> &KerberosCredentials {
        match &self.inner {
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
            #[cfg(feature = "kerberos-sspi")]
            KerberosAuthenticatorInner::Sspi(inner) => inner.initial_token(negotiate),
        }
    }

    fn next_token(&mut self, incoming: &[u8]) -> Result<Vec<u8>, AuthError> {
        match &mut self.inner {
            #[cfg(feature = "kerberos-sspi")]
            KerberosAuthenticatorInner::Sspi(inner) => inner.next_token(incoming),
        }
    }

    fn finish(&mut self, incoming: &[u8]) -> Result<(), AuthError> {
        match &mut self.inner {
            #[cfg(feature = "kerberos-sspi")]
            KerberosAuthenticatorInner::Sspi(inner) => inner.finish(incoming),
        }
    }

    fn session_key(&self) -> Option<&[u8]> {
        match &self.inner {
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

enum KerberosStep<P, C> {
    Continue { pending: P, token: Vec<u8> },
    Finished { context: C, token: Option<Vec<u8>> },
}

trait KerberosBackend {
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

#[cfg(feature = "kerberos-sspi")]
struct SspiNegotiateKerberosBackend;

#[cfg(feature = "kerberos-sspi")]
struct SspiKerberosContext {
    negotiate: Negotiate,
    credentials_handle: <Negotiate as SspiImpl>::CredentialsHandle,
}

#[cfg(feature = "kerberos-sspi")]
impl SspiKerberosContext {
    fn new(credentials: &KerberosCredentials) -> Result<Self, AuthError> {
        let kerberos_config = if let Some(kdc_url) = credentials.kdc_url() {
            KerberosConfig::new(kdc_url, credentials.client_computer_name().to_owned())
        } else {
            KerberosConfig {
                kdc_url: None,
                client_computer_name: credentials.client_computer_name().to_owned(),
            }
        };
        let mut negotiate = Negotiate::new_client(NegotiateConfig::new(
            Box::new(kerberos_config),
            Some("kerberos,!ntlm,!pku2u".to_owned()),
            credentials.client_computer_name().to_owned(),
        ))
            .map_err(|error| AuthError::Backend(error.to_string()))?;
        let auth_data = sspi::Credentials::from(credentials.auth_identity()?);
        let credentials_handle = negotiate
            .acquire_credentials_handle()
            .with_credential_use(sspi::CredentialUse::Outbound)
            .with_auth_data(&auth_data)
            .execute(&mut negotiate)
            .map_err(|error| AuthError::Backend(error.to_string()))?
            .credentials_handle;

        Ok(Self {
            negotiate,
            credentials_handle,
        })
    }

    fn target_name(target: &KerberosTarget) -> Result<String, AuthError> {
        if let Some(principal) = target.explicit_principal() {
            if principal.trim().is_empty() {
                return Err(AuthError::InvalidState(
                    "kerberos principal override must not be empty",
                ));
            }
            return Ok(principal.to_owned());
        }

        if target.service().trim().is_empty() {
            return Err(AuthError::InvalidState(
                "kerberos service component must not be empty",
            ));
        }
        if target.host().trim().is_empty() {
            return Err(AuthError::InvalidState(
                "kerberos target host must not be empty",
            ));
        }

        Ok(format!("{}/{}", target.service(), target.host()))
    }

    fn step(
        &mut self,
        target: &KerberosTarget,
        incoming: Option<&[u8]>,
    ) -> Result<(sspi::SecurityStatus, Vec<u8>), AuthError> {
        let target_name = Self::target_name(target)?;
        let mut output = [sspi::SecurityBuffer::new(Vec::new(), sspi::BufferType::Token)];
        let mut input = [sspi::SecurityBuffer::new(
            incoming.unwrap_or_default().to_vec(),
            sspi::BufferType::Token,
        )];

        let mut builder = self
            .negotiate
            .initialize_security_context()
            .with_credentials_handle(&mut self.credentials_handle)
            .with_context_requirements(client_request_flags())
            .with_target_data_representation(sspi::DataRepresentation::Native)
            .with_target_name(&target_name)
            .with_input(&mut input)
            .with_output(&mut output);

        let result = self
            .negotiate
            .initialize_security_context_impl(&mut builder)
            .map_err(|error| AuthError::Backend(error.to_string()))?
            .resolve_with_default_network_client()
            .map_err(|error| AuthError::Backend(error.to_string()))?;
        let token = output[0].buffer.clone();

        Ok((result.status, token))
    }
}

#[cfg(feature = "kerberos-sspi")]
impl KerberosBackend for SspiNegotiateKerberosBackend {
    const SPNEGO_WRAPPED: bool = true;

    type Pending = SspiKerberosContext;
    type Context = SspiKerberosContext;

    fn initiate(
        credentials: &KerberosCredentials,
        target: &KerberosTarget,
    ) -> Result<KerberosStep<Self::Pending, Self::Context>, AuthError> {
        let mut context = SspiKerberosContext::new(credentials)?;
        let (status, token) = context.step(target, None)?;
        match status {
            sspi::SecurityStatus::ContinueNeeded => Ok(KerberosStep::Continue {
                pending: context,
                token,
            }),
            sspi::SecurityStatus::Ok => Ok(KerberosStep::Finished {
                context,
                token: Some(token),
            }),
            status => Err(AuthError::Backend(format!(
                "kerberos negotiate backend returned unexpected initial status {status:?}",
            ))),
        }
    }

    fn step(
        mut pending: Self::Pending,
        incoming: &[u8],
        target: &KerberosTarget,
    ) -> Result<KerberosStep<Self::Pending, Self::Context>, AuthError> {
        let (status, token) = pending.step(target, Some(incoming))?;
        match status {
            sspi::SecurityStatus::ContinueNeeded => {
                Ok(KerberosStep::Continue { pending, token })
            }
            sspi::SecurityStatus::Ok => Ok(KerberosStep::Finished {
                context: pending,
                token: (!token.is_empty()).then_some(token),
            }),
            status => Err(AuthError::Backend(format!(
                "kerberos backend returned unexpected continuation status {status:?}",
            ))),
        }
    }

    fn session_key(context: &Self::Context) -> Result<Vec<u8>, AuthError> {
        let keys = context
            .negotiate
            .query_context_session_key()
            .map_err(|error| AuthError::Backend(error.to_string()))?;
        Ok(keys.session_key.as_ref().to_vec())
    }

}

#[cfg(feature = "kerberos-sspi")]
fn client_request_flags() -> sspi::ClientRequestFlags {
    sspi::ClientRequestFlags::MUTUAL_AUTH
        | sspi::ClientRequestFlags::INTEGRITY
        | sspi::ClientRequestFlags::FRAGMENT_TO_FIT
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

    fn test_credentials() -> KerberosCredentials {
        KerberosCredentials::new("alice", "password")
            .with_domain("EXAMPLE.COM")
            .with_workstation("WORKSTATION1")
            .with_kdc_url("tcp://dc01.example.com:88")
    }

    #[test]
    fn password_credentials_default_to_sspi_backend() {
        let credentials = test_credentials();

        assert_eq!(credentials.backend_kind(), KerberosBackendKind::Sspi);
        assert_eq!(
            credentials.credential_source_kind(),
            KerberosCredentialSourceKind::Password
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
        let auth = KerberosAuthenticator::new(test_credentials(), target);

        assert_eq!(auth.backend_kind(), KerberosBackendKind::Sspi);
    }
}
