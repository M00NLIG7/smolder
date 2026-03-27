# Kerberos

Kerberos is a `smolder-smb-core` authentication feature, not a tools-only add
on.

The stable public surface is:

- [`KerberosCredentials`](/Users/cmagana/Projects/smolder/smolder-core/src/auth/kerberos.rs)
- [`KerberosAuthenticator`](/Users/cmagana/Projects/smolder/smolder-core/src/auth/kerberos.rs)
- [`KerberosTarget`](/Users/cmagana/Projects/smolder/smolder-core/src/auth/kerberos_spn.rs)

Feature flags:

- `kerberos`: stable public Kerberos API
- `kerberos-sspi`: current password-backed backend
- `kerberos-gssapi`: Unix ticket-cache and keytab backend

## Minimal Kerberos Tree Connect

```rust
use smolder_core::prelude::{
    Connection, KerberosAuthenticator, KerberosCredentials, KerberosTarget, TokioTcpTransport,
};
use smolder_proto::smb::smb2::{
    Dialect, GlobalCapabilities, NegotiateRequest, SigningMode, TreeConnectRequest,
};

# async fn demo() -> Result<(), Box<dyn std::error::Error>> {
let transport = TokioTcpTransport::connect(("files1.lab.example", 445)).await?;
let connection = Connection::new(transport);
let negotiate = NegotiateRequest {
    security_mode: SigningMode::ENABLED,
    capabilities: GlobalCapabilities::LARGE_MTU | GlobalCapabilities::ENCRYPTION,
    client_guid: *b"smolder-krb-doc1",
    dialects: vec![Dialect::Smb210, Dialect::Smb302, Dialect::Smb311],
    negotiate_contexts: Vec::new(),
};
let connection = connection.negotiate(&negotiate).await?;

let credentials = KerberosCredentials::new("smolder@LAB.EXAMPLE", "Passw0rd!");
let target = KerberosTarget::for_smb_host("files1.lab.example");
let mut auth = KerberosAuthenticator::new(credentials, target);
let connection = connection.authenticate(&mut auth).await?;
let connection = connection
    .tree_connect(&TreeConnectRequest::from_unc(r"\\files1.lab.example\IPC$"))
    .await?;

println!("kerberos session={} tree={}", connection.session_id().0, connection.tree_id().0);
# Ok(())
# }
```

For the compile-checked example, see
[kerberos_tree_connect.rs](/Users/cmagana/Projects/smolder/smolder-core/examples/kerberos_tree_connect.rs).

## Practical Rules

- Use real hostnames, not raw IPs, when building SMB Kerberos targets.
- Prefer direct `cifs/<host>` SPN derivation unless you know you need an override.
- Keep `kerberos-gssapi` opt-in; it is the Unix/native-linking exception, not
  the default documented build.

## Fixture And Validation Docs

- [samba-ad-kerberos.md](/Users/cmagana/Projects/smolder/docs/testing/samba-ad-kerberos.md)
- [windows-kerberos.md](/Users/cmagana/Projects/smolder/docs/testing/windows-kerberos.md)
- [plans/kerberos-auth-roadmap.md](/Users/cmagana/Projects/smolder/plans/kerberos-auth-roadmap.md)
