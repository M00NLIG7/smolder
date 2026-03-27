//! SMB Kerberos service-principal construction.

use super::AuthError;

/// Identifies the Kerberos service principal used for SMB session setup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KerberosTarget {
    service: String,
    host: String,
    realm: Option<String>,
    principal: Option<String>,
}

impl KerberosTarget {
    /// Builds an SMB target for the given host using the default `cifs` service.
    pub fn for_smb_host(host: impl Into<String>) -> Self {
        Self {
            service: "cifs".to_owned(),
            host: host.into(),
            realm: None,
            principal: None,
        }
    }

    /// Overrides the service portion of the SPN.
    #[must_use]
    pub fn with_service(mut self, service: impl Into<String>) -> Self {
        self.service = service.into();
        self
    }

    /// Appends a Kerberos realm to the derived service principal name.
    #[must_use]
    pub fn with_realm(mut self, realm: impl Into<String>) -> Self {
        self.realm = Some(realm.into());
        self
    }

    /// Uses an explicit service principal name instead of deriving one.
    #[must_use]
    pub fn with_principal(mut self, principal: impl Into<String>) -> Self {
        self.principal = Some(principal.into());
        self
    }

    /// Returns the SMB host portion used for SPN derivation.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Returns the Kerberos service component used for SPN derivation.
    pub fn service(&self) -> &str {
        &self.service
    }

    /// Returns the optional Kerberos realm appended to the SPN.
    pub fn realm(&self) -> Option<&str> {
        self.realm.as_deref()
    }

    /// Returns the explicit SPN override, if configured.
    pub fn explicit_principal(&self) -> Option<&str> {
        self.principal.as_deref()
    }

    /// Builds the service principal name used for Kerberos authentication.
    pub fn service_principal_name(&self) -> Result<String, AuthError> {
        if let Some(principal) = self.principal.as_deref() {
            if principal.trim().is_empty() {
                return Err(AuthError::InvalidState(
                    "kerberos principal override must not be empty",
                ));
            }
            return Ok(principal.to_owned());
        }

        if self.service.trim().is_empty() {
            return Err(AuthError::InvalidState(
                "kerberos service component must not be empty",
            ));
        }
        if self.host.trim().is_empty() {
            return Err(AuthError::InvalidState(
                "kerberos target host must not be empty",
            ));
        }

        let mut spn = format!("{}/{}", self.service, self.host);
        if let Some(realm) = self.realm.as_deref() {
            if realm.trim().is_empty() {
                return Err(AuthError::InvalidState("kerberos realm must not be empty"));
            }
            spn.push('@');
            spn.push_str(realm);
        }

        Ok(spn)
    }
}

#[cfg(test)]
mod tests {
    use super::KerberosTarget;

    #[test]
    fn derives_default_smb_spn() {
        let target = KerberosTarget::for_smb_host("fileserver.example.com");

        assert_eq!(
            target.service_principal_name().expect("SPN should derive"),
            "cifs/fileserver.example.com"
        );
    }

    #[test]
    fn appends_realm_when_present() {
        let target =
            KerberosTarget::for_smb_host("fileserver.example.com").with_realm("EXAMPLE.COM");

        assert_eq!(
            target.service_principal_name().expect("SPN should derive"),
            "cifs/fileserver.example.com@EXAMPLE.COM"
        );
    }

    #[test]
    fn explicit_principal_overrides_derived_spn() {
        let target = KerberosTarget::for_smb_host("ignored.example.com")
            .with_principal("cifs/dfs.example.com@EXAMPLE.COM");

        assert_eq!(
            target.service_principal_name().expect("SPN should derive"),
            "cifs/dfs.example.com@EXAMPLE.COM"
        );
    }
}
