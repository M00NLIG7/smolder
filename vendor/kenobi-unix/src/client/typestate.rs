pub(crate) mod sign {
    use kenobi_core::typestate::{MaybeSigning, NoSigning};
    use libgssapi_sys::GSS_C_INTEG_FLAG;

    pub trait Sealed {
        const REQUESTED_FLAGS: u32 = 0;
    }
    impl Sealed for NoSigning {}
    impl Sealed for MaybeSigning {
        const REQUESTED_FLAGS: u32 = GSS_C_INTEG_FLAG;
    }
}

pub trait SignPolicy: sign::Sealed {}
impl<S: sign::Sealed> SignPolicy for S {}

pub(crate) mod encrypt {
    use kenobi_core::typestate::{MaybeEncryption, NoEncryption};
    use libgssapi_sys::GSS_C_CONF_FLAG;

    pub trait Sealed {
        const REQUESTED_FLAGS: u32 = 0;
    }
    impl Sealed for NoEncryption {}
    impl Sealed for MaybeEncryption {
        const REQUESTED_FLAGS: u32 = GSS_C_CONF_FLAG;
    }
}
pub trait EncryptionPolicy: encrypt::Sealed {}
impl<E: encrypt::Sealed> EncryptionPolicy for E {}

pub(crate) mod delegation {
    use kenobi_core::typestate::{MaybeDelegation, NoDelegation};
    use libgssapi_sys::GSS_C_DELEG_FLAG;

    pub trait Sealed {
        const REQUESTED_FLAGS: u32 = 0;
    }
    impl Sealed for NoDelegation {}
    impl Sealed for MaybeDelegation {
        const REQUESTED_FLAGS: u32 = GSS_C_DELEG_FLAG;
    }
}

pub trait DelegationPolicy: delegation::Sealed {}
impl<D: delegation::Sealed> DelegationPolicy for D {}
