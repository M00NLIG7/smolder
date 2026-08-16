use std::{rc::Rc, time::Duration};

use super::super::types::{usage::OutboundUsable, CapabilityFlags};

use crate::auth::kenobi_unix::{
    client::{step, StepOut},
    cred::Credentials,
    name::NameHandle,
    Error,
};

pub struct ClientBuilder<CU> {
    cred: Rc<Credentials<CU>>,
    target_principal: Option<NameHandle>,
    flags: CapabilityFlags,
    requested_duration: Option<Duration>,
    channel_bindings: Option<Box<[u8]>>,
}
impl<CU: OutboundUsable> ClientBuilder<CU> {
    pub fn new(
        cred: Rc<Credentials<CU>>,
        target_principal: Option<&str>,
    ) -> Result<ClientBuilder<CU>, Error> {
        let mut name_type = crate::auth::kenobi_unix::nt_user_name();
        let target_principal = target_principal
            .map(|t| unsafe { NameHandle::import(t, &mut name_type) })
            .transpose()?;
        Ok(ClientBuilder {
            cred,
            target_principal,
            flags: CapabilityFlags::default(),
            requested_duration: None,
            channel_bindings: None,
        })
    }
}
impl<CU> ClientBuilder<CU> {
    pub fn with_flag(mut self, flags: CapabilityFlags) -> Self {
        self.flags.add_flag(flags);
        self
    }
    pub fn request_mutual_auth(self) -> Self {
        self.with_flag(CapabilityFlags::MUTUAL_AUTH)
    }
    pub fn request_signing(self) -> Self {
        self.with_flag(CapabilityFlags::INTEGRITY)
    }
}
impl<CU: OutboundUsable> ClientBuilder<CU> {
    pub fn initialize(self) -> Result<StepOut<CU>, Error> {
        step(
            None,
            self.cred,
            self.flags,
            self.target_principal,
            None,
            self.requested_duration,
            self.channel_bindings,
        )
    }
}
