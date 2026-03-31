# Kerberos

Kerberos is a `smolder-smb-core` authentication feature, not a tools-only add
on.

The stable public surface is:

- [`KerberosCredentials`](https://github.com/M00NLIG7/smolder/blob/main/smolder-core/src/auth/kerberos.rs)
- [`KerberosAuthenticator`](https://github.com/M00NLIG7/smolder/blob/main/smolder-core/src/auth/kerberos.rs)
- [`KerberosTarget`](https://github.com/M00NLIG7/smolder/blob/main/smolder-core/src/auth/kerberos_spn.rs)

Feature flags:

- `kerberos`: stable public Kerberos API
- `kerberos-sspi`: current password-backed backend
- `kerberos-gssapi`: Unix ticket-cache and keytab backend

## Minimal Kerberos Tree Connect

```rust
use smolder_core::prelude::{Client, KerberosCredentials, KerberosTarget};

# async fn demo() -> Result<(), Box<dyn std::error::Error>> {
let credentials = KerberosCredentials::new("smolder@LAB.EXAMPLE", "Passw0rd!");
let target = KerberosTarget::for_smb_host("files1.lab.example");
let client = Client::builder("files1.lab.example")
    .with_kerberos_credentials(credentials, target)
    .build()?;
let share = client.connect_share("IPC$").await?;

println!("kerberos session={} tree={}", share.session_id().0, share.tree_id().0);
# Ok(())
# }
```

For the compile-checked examples, see:

- [kerberos_tree_connect.rs](https://github.com/M00NLIG7/smolder/blob/main/smolder-core/examples/kerberos_tree_connect.rs)
- [kerberos_share_list.rs](https://github.com/M00NLIG7/smolder/blob/main/smolder-tools/examples/kerberos_share_list.rs)

## Practical Rules

- Use real hostnames, not raw IPs, when building SMB Kerberos targets.
- Prefer direct `cifs/<host>` SPN derivation unless you know you need an override.
- Keep `kerberos-gssapi` opt-in; it is the Unix/native-linking exception, not
  the default documented build.

## Fixture And Validation Docs

- [samba-ad-kerberos.md](https://github.com/M00NLIG7/smolder/blob/main/docs/testing/samba-ad-kerberos.md)
- [windows-kerberos.md](https://github.com/M00NLIG7/smolder/blob/main/docs/testing/windows-kerberos.md)
- [support-policy.md](https://github.com/M00NLIG7/smolder/blob/main/docs/reference/support-policy.md)
