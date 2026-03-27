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

pub(super) struct GssapiTicketCacheKerberosBackend;

pub(super) struct GssapiPendingKerberosContext {
    pending: PendingClientContext<Outbound>,
}

impl KerberosBackend for GssapiTicketCacheKerberosBackend {
    const SPNEGO_WRAPPED: bool = false;

    type Pending = GssapiPendingKerberosContext;
    type Context = GssapiClientContext;

    fn initiate(
        credentials: &KerberosCredentials,
        target: &KerberosTarget,
    ) -> Result<KerberosStep<Self::Pending, Self::Context>, AuthError> {
        let credential_principal = credentials.initiator_principal()?;
        let cred = Arc::new(
            Credentials::outbound(credential_principal.as_deref(), None, Mechanism::KerberosV5)
                .map_err(|error| AuthError::Backend(error.to_string()))?,
        );
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
                    pending: GssapiPendingKerberosContext { pending },
                    token,
                })
            }
            StepOut::Finished(context) => Ok(KerberosStep::Finished {
                token: context.last_token().map(|token| token.to_vec()),
                context,
            }),
        }
    }

    fn step(
        pending: Self::Pending,
        incoming: &[u8],
        _target: &KerberosTarget,
    ) -> Result<KerberosStep<Self::Pending, Self::Context>, AuthError> {
        let step = pending
            .pending
            .step(incoming)
            .map_err(|error| AuthError::Backend(error.to_string()))?;
        match step {
            StepOut::Pending(pending) => Ok(KerberosStep::Continue {
                token: pending.next_token().to_vec(),
                pending: GssapiPendingKerberosContext { pending },
            }),
            StepOut::Finished(context) => Ok(KerberosStep::Finished {
                token: context.last_token().map(|token| token.to_vec()),
                context,
            }),
        }
    }

    fn session_key(context: &Self::Context) -> Result<Vec<u8>, AuthError> {
        let session_key = context
            .session_key()
            .map_err(|error: kenobi_unix::Error| AuthError::Backend(error.to_string()))?;
        Ok(session_key.as_slice().to_vec())
    }
}
