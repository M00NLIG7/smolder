//! Kerberos authentication for SMB `SESSION_SETUP`.

use std::marker::PhantomData;

use smolder_proto::smb::smb2::NegotiateResponse;

use super::kerberos_spn::KerberosTarget;
use super::spnego::{
    encode_neg_token_init, encode_neg_token_resp, extract_mech_token, parse_neg_token_resp,
};
use super::{AuthError, AuthProvider, SpnegoMechanism};

/// Selects an existing Kerberos client credential from the local ticket cache.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KerberosCredentials {
    principal: Option<String>,
}

impl KerberosCredentials {
    /// Uses the default client principal from the active Kerberos ticket cache.
    pub fn from_ticket_cache() -> Self {
        Self::default()
    }

    /// Uses a specific client principal from the active Kerberos ticket cache.
    #[must_use]
    pub fn with_principal(mut self, principal: impl Into<String>) -> Self {
        self.principal = Some(principal.into());
        self
    }

    fn principal(&self) -> Option<&str> {
        self.principal.as_deref()
    }
}

/// Kerberos `AuthProvider` backed by the local Kerberos ticket cache.
///
/// This milestone only drives the SMB `SESSION_SETUP` token exchange. Exported
/// session-key handling for SMB signing and encryption follows in a later
/// milestone, so `session_key()` currently returns `None`.
pub struct KerberosAuthenticator {
    inner: KerberosAuthEngine<CrossKrb5Backend>,
}

impl KerberosAuthenticator {
    /// Creates a Kerberos authenticator using the provided ticket-cache inputs.
    pub fn new(credentials: KerberosCredentials, target: KerberosTarget) -> Self {
        Self {
            inner: KerberosAuthEngine::new(credentials, target),
        }
    }

    /// Creates a Kerberos authenticator using the default ticket cache.
    pub fn from_ticket_cache(target: KerberosTarget) -> Self {
        Self::new(KerberosCredentials::from_ticket_cache(), target)
    }

    /// Returns the SMB Kerberos target for this exchange.
    pub fn target(&self) -> &KerberosTarget {
        &self.inner.target
    }

    /// Returns the cache-selection inputs for this exchange.
    pub fn credentials(&self) -> &KerberosCredentials {
        &self.inner.credentials
    }
}

impl AuthProvider for KerberosAuthenticator {
    fn initial_token(&mut self, negotiate: &NegotiateResponse) -> Result<Vec<u8>, AuthError> {
        self.inner.initial_token(negotiate)
    }

    fn next_token(&mut self, incoming: &[u8]) -> Result<Vec<u8>, AuthError> {
        self.inner.next_token(incoming)
    }

    fn finish(&mut self, incoming: &[u8]) -> Result<(), AuthError> {
        self.inner.finish(incoming)
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
    type Pending;
    type Context;

    fn initiate(
        credentials: &KerberosCredentials,
        target: &KerberosTarget,
    ) -> Result<(Self::Pending, Vec<u8>), AuthError>;

    fn step(
        pending: Self::Pending,
        incoming: &[u8],
    ) -> Result<KerberosStep<Self::Pending, Self::Context>, AuthError>;
}

struct KerberosAuthEngine<B: KerberosBackend> {
    credentials: KerberosCredentials,
    target: KerberosTarget,
    state: KerberosState<B::Pending, B::Context>,
    _backend: PhantomData<B>,
}

impl<B: KerberosBackend> KerberosAuthEngine<B> {
    fn new(credentials: KerberosCredentials, target: KerberosTarget) -> Self {
        Self {
            credentials,
            target,
            state: KerberosState::Initial,
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

        let (pending, token) = B::initiate(&self.credentials, &self.target)?;
        self.state = KerberosState::Pending(pending);
        Ok(encode_neg_token_init(
            &[SpnegoMechanism::KerberosV5],
            Some(&token),
        ))
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

        let server_token = extract_mech_token(incoming)?;
        match B::step(pending, &server_token)? {
            KerberosStep::Continue { pending, token } => {
                self.state = KerberosState::Pending(pending);
                Ok(encode_neg_token_resp(None, Some(&token), None))
            }
            KerberosStep::Finished { context, token } => {
                self.state = KerberosState::Established(context);
                Ok(token
                    .map(|token| encode_neg_token_resp(None, Some(&token), None))
                    .unwrap_or_default())
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

                let server_token = extract_mech_token(incoming)?;
                match B::step(pending, &server_token)? {
                    KerberosStep::Finished { token: None, .. } => Ok(()),
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
                    return Ok(());
                }

                let parsed = parse_neg_token_resp(incoming)?;
                if parsed.response_token.is_some() {
                    self.state = KerberosState::Established(context);
                    return Err(AuthError::InvalidToken(
                        "unexpected kerberos response token after context establishment",
                    ));
                }
                Ok(())
            }
            KerberosState::Complete => Ok(()),
        }
    }
}

struct CrossKrb5Backend;

impl KerberosBackend for CrossKrb5Backend {
    type Pending = cross_krb5::PendingClientCtx;
    type Context = cross_krb5::ClientCtx;

    fn initiate(
        credentials: &KerberosCredentials,
        target: &KerberosTarget,
    ) -> Result<(Self::Pending, Vec<u8>), AuthError> {
        let spn = target.service_principal_name()?;
        let (pending, token) = cross_krb5::ClientCtx::new(
            cross_krb5::InitiateFlags::empty(),
            credentials.principal(),
            &spn,
            None,
        )
        .map_err(|error| AuthError::Backend(error.to_string()))?;
        Ok((pending, token.as_ref().to_vec()))
    }

    fn step(
        pending: Self::Pending,
        incoming: &[u8],
    ) -> Result<KerberosStep<Self::Pending, Self::Context>, AuthError> {
        match pending
            .step(incoming)
            .map_err(|error| AuthError::Backend(error.to_string()))?
        {
            cross_krb5::Step::Continue((pending, token)) => Ok(KerberosStep::Continue {
                pending,
                token: token.as_ref().to_vec(),
            }),
            cross_krb5::Step::Finished((context, token)) => Ok(KerberosStep::Finished {
                context,
                token: token.map(|token| token.as_ref().to_vec()),
            }),
        }
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
        type Pending = MockPending;
        type Context = MockContext;

        fn initiate(
            credentials: &KerberosCredentials,
            target: &KerberosTarget,
        ) -> Result<(Self::Pending, Vec<u8>), AuthError> {
            assert_eq!(credentials.principal(), Some("alice@EXAMPLE.COM"));
            assert_eq!(
                target.service_principal_name().expect("SPN should derive"),
                "cifs/fileserver.example.com@EXAMPLE.COM"
            );
            Ok((MockPending::AwaitingChallenge, b"ap-req".to_vec()))
        }

        fn step(
            pending: Self::Pending,
            incoming: &[u8],
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

    #[test]
    fn initial_token_advertises_kerberos_mechanism() {
        let credentials =
            KerberosCredentials::from_ticket_cache().with_principal("alice@EXAMPLE.COM");
        let target =
            KerberosTarget::for_smb_host("fileserver.example.com").with_realm("EXAMPLE.COM");
        let mut auth = KerberosAuthEngine::<MockBackend>::new(credentials, target);

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
        let credentials =
            KerberosCredentials::from_ticket_cache().with_principal("alice@EXAMPLE.COM");
        let target =
            KerberosTarget::for_smb_host("fileserver.example.com").with_realm("EXAMPLE.COM");
        let mut auth = KerberosAuthEngine::<MockBackend>::new(credentials, target);

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
        let credentials =
            KerberosCredentials::from_ticket_cache().with_principal("alice@EXAMPLE.COM");
        let target =
            KerberosTarget::for_smb_host("fileserver.example.com").with_realm("EXAMPLE.COM");
        let mut auth = KerberosAuthEngine::<MockBackend>::new(credentials, target);

        auth.initial_token(&negotiate_response())
            .expect("initial token should build");
        auth.next_token(&encode_neg_token_resp(None, Some(b"krb-error"), None))
            .expect("continuation token should build");

        auth.finish(&encode_neg_token_resp(None, Some(b"ap-rep"), None))
            .expect("finish should consume the final token");
    }
}
