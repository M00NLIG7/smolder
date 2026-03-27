use std::sync::Arc;

use kenobi_unix::{
    client::{ClientContext, StepOut},
    cred::Credentials,
    mech::Mechanism,
};

#[test]
fn main() {
    let client_name = std::env::var("KERBEROS_TEST_USER_PRINCIPAL").ok();
    let service_principal = std::env::var("KERBEROS_TEST_SERVICE_PRINCIPAL").ok();
    let cred = match Credentials::outbound(client_name.as_deref(), None, Mechanism::KerberosV5) {
        Ok(cred) => cred,
        Err(err) => {
            eprintln!("Error: {err}");
            panic!()
        }
    };
    let mut _ctx = match ClientContext::new(Arc::new(cred), service_principal.as_deref()) {
        Ok(StepOut::Finished(_)) => return,
        Ok(StepOut::Pending(pending)) => pending,
        Err(err) => {
            eprintln!("Error initiating: {err}");
            panic!()
        }
    };
    todo!();
}
