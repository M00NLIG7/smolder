//! SMB cryptographic key-derivation helpers.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use smolder_proto::smb::smb2::{CipherId, Dialect};

use crate::error::CoreError;

/// Session encryption keys derived from the authenticated SMB session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionKeys {
    /// The negotiated SMB cipher.
    pub cipher: CipherId,
    /// The client-to-server encryption key.
    pub encrypting_key: Vec<u8>,
    /// The server-to-client decryption key.
    pub decrypting_key: Vec<u8>,
}

/// Derives the SMB 3.x session encryption and decryption keys.
pub fn derive_encryption_keys(
    dialect: Dialect,
    cipher: CipherId,
    session_key: &[u8],
    full_session_key: Option<&[u8]>,
    preauth_hash: Option<&[u8]>,
) -> Result<EncryptionKeys, CoreError> {
    let key_len = cipher_key_len(cipher);
    let (base_key, encryption_label, decryption_label, encryption_context, decryption_context) =
        match dialect {
            Dialect::Smb202 | Dialect::Smb210 => {
                return Err(CoreError::Unsupported(
                    "SMB encryption is only available for SMB 3.x dialects",
                ));
            }
            Dialect::Smb300 | Dialect::Smb302 => {
                if cipher != CipherId::Aes128Ccm {
                    return Err(CoreError::Unsupported(
                        "SMB 3.0 and 3.0.2 only support AES-128-CCM encryption",
                    ));
                }
                (
                    session_key,
                    b"SMB2AESCCM\0".as_slice(),
                    b"SMB2AESCCM\0".as_slice(),
                    b"ServerIn \0".as_slice(),
                    b"ServerOut\0".as_slice(),
                )
            }
            Dialect::Smb311 => {
                let preauth_hash = preauth_hash.ok_or(CoreError::InvalidResponse(
                    "SMB 3.1.1 encryption requires preauth integrity state",
                ))?;
                let base_key = match cipher {
                    CipherId::Aes128Ccm | CipherId::Aes128Gcm => session_key,
                    CipherId::Aes256Ccm | CipherId::Aes256Gcm => {
                        full_session_key.ok_or(CoreError::Unsupported(
                            "SMB 3.1.1 AES-256 encryption requires a full session key",
                        ))?
                    }
                };
                (
                    base_key,
                    b"SMBC2SCipherKey\0".as_slice(),
                    b"SMBS2CCipherKey\0".as_slice(),
                    preauth_hash,
                    preauth_hash,
                )
            }
        };

    Ok(EncryptionKeys {
        cipher,
        encrypting_key: derive_key(base_key, encryption_label, encryption_context, key_len)?,
        decrypting_key: derive_key(base_key, decryption_label, decryption_context, key_len)?,
    })
}

fn cipher_key_len(cipher: CipherId) -> usize {
    match cipher {
        CipherId::Aes128Ccm | CipherId::Aes128Gcm => 16,
        CipherId::Aes256Ccm | CipherId::Aes256Gcm => 32,
    }
}

fn derive_key(
    key: &[u8],
    label: &[u8],
    context: &[u8],
    output_bytes: usize,
) -> Result<Vec<u8>, CoreError> {
    if output_bytes == 0 {
        return Err(CoreError::InvalidInput(
            "derived SMB key length must be nonzero",
        ));
    }

    let output_bits = output_bytes
        .checked_mul(8)
        .ok_or(CoreError::InvalidInput("derived SMB key length was too large"))?;
    let blocks = output_bytes.div_ceil(32);
    let mut derived = Vec::with_capacity(blocks * 32);

    for counter in 1..=u32::try_from(blocks)
        .map_err(|_| CoreError::InvalidInput("requested SMB key derivation output was too large"))?
    {
        let mut mac = Hmac::<Sha256>::new_from_slice(key)
            .map_err(|_| CoreError::InvalidInput("invalid SMB key derivation key"))?;
        mac.update(&counter.to_be_bytes());
        mac.update(label);
        mac.update(&[0]);
        mac.update(context);
        mac.update(&(output_bits as u32).to_be_bytes());
        derived.extend_from_slice(&mac.finalize().into_bytes());
    }

    derived.truncate(output_bytes);
    Ok(derived)
}

#[cfg(test)]
mod tests {
    use smolder_proto::smb::smb2::{CipherId, Dialect};

    use super::derive_encryption_keys;

    #[test]
    fn derives_smb300_aes128_ccm_keys() {
        let session_key = (0u8..16).collect::<Vec<_>>();

        let keys = derive_encryption_keys(
            Dialect::Smb300,
            CipherId::Aes128Ccm,
            &session_key,
            None,
            None,
        )
        .expect("SMB 3.0 encryption keys should derive");

        assert_eq!(
            hex(&keys.encrypting_key),
            "8e21f3cae16d07d84c03d74467f57878"
        );
        assert_eq!(
            hex(&keys.decrypting_key),
            "95d8b55c852cd25349994b3842fa4105"
        );
    }

    #[test]
    fn derives_smb311_aes128_gcm_keys() {
        let session_key = (0u8..16).collect::<Vec<_>>();
        let preauth_hash = (0u8..64).collect::<Vec<_>>();

        let keys = derive_encryption_keys(
            Dialect::Smb311,
            CipherId::Aes128Gcm,
            &session_key,
            None,
            Some(&preauth_hash),
        )
        .expect("SMB 3.1.1 AES-128 keys should derive");

        assert_eq!(
            hex(&keys.encrypting_key),
            "f1b6250ca4d9f8877e41071f59228ce4"
        );
        assert_eq!(
            hex(&keys.decrypting_key),
            "99676aedfbfd18e61ca5bb60d502e8f2"
        );
    }

    #[test]
    fn derives_smb311_aes256_gcm_keys_from_full_session_key() {
        let session_key = (0u8..16).collect::<Vec<_>>();
        let full_session_key = (0u8..32).collect::<Vec<_>>();
        let preauth_hash = (0u8..64).collect::<Vec<_>>();

        let keys = derive_encryption_keys(
            Dialect::Smb311,
            CipherId::Aes256Gcm,
            &session_key,
            Some(&full_session_key),
            Some(&preauth_hash),
        )
        .expect("SMB 3.1.1 AES-256 keys should derive");

        assert_eq!(
            hex(&keys.encrypting_key),
            "e568de865ae188f20138931c5423898fc0d5e94fa094b72d474fc56cf5703db6"
        );
        assert_eq!(
            hex(&keys.decrypting_key),
            "53f8b2fb513a90f5231f5ac12ba0a24b9eed8f6e80596136560f1b0003e8d2ae"
        );
    }

    #[test]
    fn rejects_smb311_aes256_without_full_session_key() {
        let session_key = (0u8..16).collect::<Vec<_>>();
        let preauth_hash = (0u8..64).collect::<Vec<_>>();

        let error = derive_encryption_keys(
            Dialect::Smb311,
            CipherId::Aes256Ccm,
            &session_key,
            None,
            Some(&preauth_hash),
        )
        .expect_err("AES-256 should require a full session key");

        assert_eq!(
            error.to_string(),
            "unsupported: SMB 3.1.1 AES-256 encryption requires a full session key"
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
