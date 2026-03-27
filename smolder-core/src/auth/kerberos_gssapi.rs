use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use kenobi_unix::client::{
    ClientBuilder, ClientContext, PendingClientContext, StepOut,
};
use kenobi_unix::cred::{Credentials, Outbound};
use kenobi_unix::mech::Mechanism;
use kenobi_unix::typestate::{MaybeDelegation, MaybeEncryption, MaybeSigning};

use super::kerberos::{KerberosBackend, KerberosCredentials, KerberosStep};
use super::kerberos_spn::KerberosTarget;
use super::AuthError;

type GssapiClientContext =
    ClientContext<Outbound, MaybeSigning, MaybeEncryption, MaybeDelegation>;

pub(super) struct GssapiKerberosBackend;

pub(super) struct GssapiPendingKerberosContext {
    pending: PendingClientContext<Outbound>,
    cache: Option<GssapiCredentialCache>,
}

pub(super) struct GssapiEstablishedKerberosContext {
    context: GssapiClientContext,
    _cache: Option<GssapiCredentialCache>,
}

struct GssapiCredentialCache {
    path: PathBuf,
}

impl GssapiCredentialCache {
    fn new() -> Self {
        let path = env::temp_dir().join(format!(
            "smolder-krb5cc-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        Self { path }
    }

    fn cache_name(&self) -> String {
        format!("FILE:{}", self.path.to_string_lossy())
    }
}

impl Drop for GssapiCredentialCache {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

impl KerberosBackend for GssapiKerberosBackend {
    const SPNEGO_WRAPPED: bool = false;

    type Pending = GssapiPendingKerberosContext;
    type Context = GssapiEstablishedKerberosContext;

    fn initiate(
        credentials: &KerberosCredentials,
        target: &KerberosTarget,
    ) -> Result<KerberosStep<Self::Pending, Self::Context>, AuthError> {
        let credential_principal = credentials.initiator_principal()?;
        let (cred, cache) = acquire_credentials(credentials, credential_principal.as_deref())?;
        let target_principal = target.service_principal_name()?;
        let step = ClientBuilder::new(cred, Some(&target_principal))
            .map_err(|error| AuthError::Backend(error.to_string()))?
            .request_mutual_auth()
            .request_signing()
            .initialize()
            .map_err(|error| AuthError::Backend(error.to_string()))?;

        match step {
            StepOut::Pending(pending) => {
                let token = pending.next_token().to_vec();
                Ok(KerberosStep::Continue {
                    pending: GssapiPendingKerberosContext { pending, cache },
                    token,
                })
            }
            StepOut::Finished(context) => Ok(KerberosStep::Finished {
                token: context.last_token().map(|token| token.to_vec()),
                context: GssapiEstablishedKerberosContext {
                    context,
                    _cache: cache,
                },
            }),
        }
    }

    fn step(
        pending: Self::Pending,
        incoming: &[u8],
        _target: &KerberosTarget,
    ) -> Result<KerberosStep<Self::Pending, Self::Context>, AuthError> {
        let GssapiPendingKerberosContext { pending, cache } = pending;
        let step = pending
            .step(incoming)
            .map_err(|error| AuthError::Backend(error.to_string()))?;
        match step {
            StepOut::Pending(pending) => Ok(KerberosStep::Continue {
                token: pending.next_token().to_vec(),
                pending: GssapiPendingKerberosContext { pending, cache },
            }),
            StepOut::Finished(context) => Ok(KerberosStep::Finished {
                token: context.last_token().map(|token| token.to_vec()),
                context: GssapiEstablishedKerberosContext {
                    context,
                    _cache: cache,
                },
            }),
        }
    }

    fn session_key(context: &Self::Context) -> Result<Vec<u8>, AuthError> {
        let session_key = context
            .context
            .session_key()
            .map_err(|error: kenobi_unix::Error| AuthError::Backend(error.to_string()))?;
        Ok(session_key.as_slice().to_vec())
    }
}

fn acquire_credentials(
    credentials: &KerberosCredentials,
    principal: Option<&str>,
) -> Result<(Arc<Credentials<Outbound>>, Option<GssapiCredentialCache>), AuthError> {
    match credentials.credential_source_kind() {
        super::kerberos::KerberosCredentialSourceKind::TicketCache => {
            let cred = Credentials::outbound(principal, None, Mechanism::KerberosV5)
                .map_err(|error| AuthError::Backend(error.to_string()))?;
            Ok((Arc::new(cred), None))
        }
        super::kerberos::KerberosCredentialSourceKind::Keytab => {
            let keytab_name = credentials.keytab_name().ok_or(AuthError::InvalidState(
                "kerberos keytab source requires a keytab name",
            ))?;
            let cache = GssapiCredentialCache::new();
            let cache_name = cache.cache_name();
            let cred = Credentials::outbound_from_client_keytab(
                principal,
                None,
                keytab_name,
                Some(&cache_name),
                Mechanism::KerberosV5,
            )
            .map_err(|error| AuthError::Backend(error.to_string()))?;
            Ok((Arc::new(cred), Some(cache)))
        }
        super::kerberos::KerberosCredentialSourceKind::Password => Err(AuthError::InvalidState(
            "password-backed Kerberos credentials require the kerberos-sspi backend",
        )),
    }
}
