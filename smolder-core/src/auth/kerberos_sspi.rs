use sspi::{KerberosConfig, Negotiate, NegotiateConfig, Sspi, SspiImpl};

use super::kerberos::{KerberosBackend, KerberosCredentials, KerberosStep};
use super::kerberos_spn::KerberosTarget;
use super::AuthError;

pub(super) struct SspiNegotiateKerberosBackend;

pub(super) struct SspiKerberosContext {
    negotiate: Negotiate,
    credentials_handle: <Negotiate as SspiImpl>::CredentialsHandle,
}

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

fn client_request_flags() -> sspi::ClientRequestFlags {
    sspi::ClientRequestFlags::MUTUAL_AUTH
        | sspi::ClientRequestFlags::INTEGRITY
        | sspi::ClientRequestFlags::FRAGMENT_TO_FIT
}
