//! SMB cryptographic key-derivation helpers.

use aes::{Aes128, Aes256};
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce as GcmNonce};
use ccm::consts::{U11, U16};
use ccm::aead::generic_array::GenericArray;
use ccm::Ccm;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use smolder_proto::smb::transform::{TransformHeader, TransformValue};
use smolder_proto::smb::smb2::{CipherId, Dialect};
use rand::random;

use crate::error::CoreError;

type Aes128Ccm = Ccm<Aes128, U16, U11>;
type Aes256Ccm = Ccm<Aes256, U16, U11>;

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

/// Runtime SMB 3.x sealing state for one authenticated session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionState {
    /// The negotiated dialect.
    pub dialect: Dialect,
    /// The negotiated SMB cipher.
    pub cipher: CipherId,
    /// The client-to-server encryption key.
    pub encrypting_key: Vec<u8>,
    /// The server-to-client decryption key.
    pub decrypting_key: Vec<u8>,
}

impl EncryptionState {
    /// Creates a runtime encryption state from derived session keys.
    #[must_use]
    pub fn new(dialect: Dialect, keys: EncryptionKeys) -> Self {
        Self {
            dialect,
            cipher: keys.cipher,
            encrypting_key: keys.encrypting_key,
            decrypting_key: keys.decrypting_key,
        }
    }

    /// Encrypts an SMB2 message into an SMB3 transform header and ciphertext.
    pub fn encrypt_message(
        &self,
        session_id: u64,
        message: &[u8],
    ) -> Result<TransformHeader, CoreError> {
        let nonce_len = nonce_len(self.cipher);
        let mut nonce = [0u8; 16];
        fill_nonce_prefix(&mut nonce, nonce_len);
        self.encrypt_message_with_nonce(session_id, message, nonce)
    }

    /// Decrypts an SMB3 transform header into the original SMB2 message.
    pub fn decrypt_message(&self, message: &TransformHeader) -> Result<Vec<u8>, CoreError> {
        let expected = expected_transform_value(self.dialect, self.cipher);
        if message.flags_or_algorithm != expected {
            return Err(CoreError::InvalidResponse(
                "SMB transform header used an unexpected flags or cipher value",
            ));
        }
        let aad = transform_aad(message);
        let mut plaintext = message.encrypted_message.clone();
        match self.cipher {
            CipherId::Aes128Ccm => decrypt_aes128_ccm(
                &self.decrypting_key,
                &message.nonce[..11],
                &aad,
                &mut plaintext,
                &message.signature,
            )?,
            CipherId::Aes256Ccm => decrypt_aes256_ccm(
                &self.decrypting_key,
                &message.nonce[..11],
                &aad,
                &mut plaintext,
                &message.signature,
            )?,
            CipherId::Aes128Gcm => decrypt_aes128_gcm(
                &self.decrypting_key,
                &message.nonce[..12],
                &aad,
                &mut plaintext,
                &message.signature,
            )?,
            CipherId::Aes256Gcm => decrypt_aes256_gcm(
                &self.decrypting_key,
                &message.nonce[..12],
                &aad,
                &mut plaintext,
                &message.signature,
            )?,
        }
        if plaintext.len() != message.original_message_size as usize {
            return Err(CoreError::InvalidResponse(
                "SMB transform header original size did not match the decrypted message",
            ));
        }
        Ok(plaintext)
    }

    fn encrypt_message_with_nonce(
        &self,
        session_id: u64,
        message: &[u8],
        nonce: [u8; 16],
    ) -> Result<TransformHeader, CoreError> {
        let mut transform = TransformHeader {
            signature: [0; 16],
            nonce,
            original_message_size: u32::try_from(message.len())
                .map_err(|_| CoreError::InvalidInput("SMB message too large to encrypt"))?,
            flags_or_algorithm: expected_transform_value(self.dialect, self.cipher),
            session_id,
            encrypted_message: message.to_vec(),
        };
        let aad = transform_aad(&transform);
        let signature = match self.cipher {
            CipherId::Aes128Ccm => encrypt_aes128_ccm(
                &self.encrypting_key,
                &transform.nonce[..11],
                &aad,
                &mut transform.encrypted_message,
            )?,
            CipherId::Aes256Ccm => encrypt_aes256_ccm(
                &self.encrypting_key,
                &transform.nonce[..11],
                &aad,
                &mut transform.encrypted_message,
            )?,
            CipherId::Aes128Gcm => encrypt_aes128_gcm(
                &self.encrypting_key,
                &transform.nonce[..12],
                &aad,
                &mut transform.encrypted_message,
            )?,
            CipherId::Aes256Gcm => encrypt_aes256_gcm(
                &self.encrypting_key,
                &transform.nonce[..12],
                &aad,
                &mut transform.encrypted_message,
            )?,
        };
        transform.signature = signature;
        Ok(transform)
    }
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

fn expected_transform_value(dialect: Dialect, cipher: CipherId) -> TransformValue {
    match dialect {
        Dialect::Smb202 | Dialect::Smb210 => TransformValue(0),
        Dialect::Smb300 | Dialect::Smb302 => TransformValue(cipher as u16),
        Dialect::Smb311 => TransformValue::ENCRYPTED,
    }
}

fn nonce_len(cipher: CipherId) -> usize {
    match cipher {
        CipherId::Aes128Ccm | CipherId::Aes256Ccm => 11,
        CipherId::Aes128Gcm | CipherId::Aes256Gcm => 12,
    }
}

fn fill_nonce_prefix(nonce: &mut [u8; 16], prefix_len: usize) {
    let prefix: [u8; 16] = random();
    nonce[..prefix_len].copy_from_slice(&prefix[..prefix_len]);
}

fn transform_aad(transform: &TransformHeader) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32);
    aad.extend_from_slice(&transform.nonce);
    aad.extend_from_slice(&transform.original_message_size.to_le_bytes());
    aad.extend_from_slice(&0u16.to_le_bytes());
    aad.extend_from_slice(&transform.flags_or_algorithm.0.to_le_bytes());
    aad.extend_from_slice(&transform.session_id.to_le_bytes());
    aad
}

fn encrypt_aes128_ccm(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    payload: &mut Vec<u8>,
) -> Result<[u8; 16], CoreError> {
    let cipher = Aes128Ccm::new_from_slice(key)
        .map_err(|_| CoreError::InvalidInput("invalid SMB CCM encryption key"))?;
    let tag = cipher
        .encrypt_in_place_detached(GenericArray::from_slice(nonce), aad, payload)
        .map_err(|_| CoreError::InvalidInput("SMB CCM encryption failed"))?;
    let mut signature = [0; 16];
    signature.copy_from_slice(&tag);
    Ok(signature)
}

fn encrypt_aes256_ccm(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    payload: &mut Vec<u8>,
) -> Result<[u8; 16], CoreError> {
    let cipher = Aes256Ccm::new_from_slice(key)
        .map_err(|_| CoreError::InvalidInput("invalid SMB CCM encryption key"))?;
    let tag = cipher
        .encrypt_in_place_detached(GenericArray::from_slice(nonce), aad, payload)
        .map_err(|_| CoreError::InvalidInput("SMB CCM encryption failed"))?;
    let mut signature = [0; 16];
    signature.copy_from_slice(&tag);
    Ok(signature)
}

fn decrypt_aes128_ccm(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    payload: &mut Vec<u8>,
    signature: &[u8; 16],
) -> Result<(), CoreError> {
    let cipher = Aes128Ccm::new_from_slice(key)
        .map_err(|_| CoreError::InvalidInput("invalid SMB CCM decryption key"))?;
    cipher
        .decrypt_in_place_detached(
            GenericArray::from_slice(nonce),
            aad,
            payload,
            GenericArray::from_slice(signature),
        )
        .map_err(|_| CoreError::InvalidResponse("SMB CCM signature verification failed"))
}

fn decrypt_aes256_ccm(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    payload: &mut Vec<u8>,
    signature: &[u8; 16],
) -> Result<(), CoreError> {
    let cipher = Aes256Ccm::new_from_slice(key)
        .map_err(|_| CoreError::InvalidInput("invalid SMB CCM decryption key"))?;
    cipher
        .decrypt_in_place_detached(
            GenericArray::from_slice(nonce),
            aad,
            payload,
            GenericArray::from_slice(signature),
        )
        .map_err(|_| CoreError::InvalidResponse("SMB CCM signature verification failed"))
}

fn encrypt_aes128_gcm(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    payload: &mut Vec<u8>,
) -> Result<[u8; 16], CoreError> {
    encrypt_gcm::<Aes128Gcm>(key, nonce, aad, payload)
}

fn encrypt_aes256_gcm(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    payload: &mut Vec<u8>,
) -> Result<[u8; 16], CoreError> {
    encrypt_gcm::<Aes256Gcm>(key, nonce, aad, payload)
}

fn decrypt_aes128_gcm(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    payload: &mut Vec<u8>,
    signature: &[u8; 16],
) -> Result<(), CoreError> {
    decrypt_gcm::<Aes128Gcm>(key, nonce, aad, payload, signature)
}

fn decrypt_aes256_gcm(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    payload: &mut Vec<u8>,
    signature: &[u8; 16],
) -> Result<(), CoreError> {
    decrypt_gcm::<Aes256Gcm>(key, nonce, aad, payload, signature)
}

fn encrypt_gcm<Cipher>(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    payload: &mut Vec<u8>,
) -> Result<[u8; 16], CoreError>
where
    Cipher: AeadInPlace + KeyInit,
{
    let cipher = Cipher::new_from_slice(key)
        .map_err(|_| CoreError::InvalidInput("invalid SMB GCM encryption key"))?;
    let tag = cipher
        .encrypt_in_place_detached(GcmNonce::from_slice(nonce), aad, payload)
        .map_err(|_| CoreError::InvalidInput("SMB GCM encryption failed"))?;
    let mut signature = [0; 16];
    signature.copy_from_slice(&tag);
    Ok(signature)
}

fn decrypt_gcm<Cipher>(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    payload: &mut Vec<u8>,
    signature: &[u8; 16],
) -> Result<(), CoreError>
where
    Cipher: AeadInPlace + KeyInit,
{
    let cipher = Cipher::new_from_slice(key)
        .map_err(|_| CoreError::InvalidInput("invalid SMB GCM decryption key"))?;
    cipher
        .decrypt_in_place_detached(
            GcmNonce::from_slice(nonce),
            aad,
            payload,
            GenericArray::from_slice(signature),
        )
        .map_err(|_| CoreError::InvalidResponse("SMB GCM signature verification failed"))
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
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
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
    use smolder_proto::smb::transform::TransformValue;

    use super::{derive_encryption_keys, EncryptionState};

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

    #[test]
    fn seals_and_unseals_smb311_gcm_messages() {
        let client_state = EncryptionState::new(
            Dialect::Smb311,
            derive_encryption_keys(
                Dialect::Smb311,
                CipherId::Aes128Gcm,
                &(0u8..16).collect::<Vec<_>>(),
                None,
                Some(&(0u8..64).collect::<Vec<_>>()),
            )
            .expect("keys should derive"),
        );
        let server_state = EncryptionState {
            dialect: client_state.dialect,
            cipher: client_state.cipher,
            encrypting_key: client_state.decrypting_key.clone(),
            decrypting_key: client_state.encrypting_key.clone(),
        };
        let message = vec![0xfe, b'S', b'M', b'B', 1, 2, 3, 4];

        let transform = client_state
            .encrypt_message_with_nonce(55, &message, [0x11; 16])
            .expect("message should encrypt");
        let plaintext = server_state
            .decrypt_message(&transform)
            .expect("message should decrypt");

        assert_eq!(transform.flags_or_algorithm, TransformValue::ENCRYPTED);
        assert_eq!(transform.original_message_size, message.len() as u32);
        assert_eq!(plaintext, message);
    }

    #[test]
    fn seals_and_unseals_smb300_ccm_messages() {
        let client_state = EncryptionState::new(
            Dialect::Smb300,
            derive_encryption_keys(
                Dialect::Smb300,
                CipherId::Aes128Ccm,
                &(0u8..16).collect::<Vec<_>>(),
                None,
                None,
            )
            .expect("keys should derive"),
        );
        let server_state = EncryptionState {
            dialect: client_state.dialect,
            cipher: client_state.cipher,
            encrypting_key: client_state.decrypting_key.clone(),
            decrypting_key: client_state.encrypting_key.clone(),
        };
        let message = vec![0xfe, b'S', b'M', b'B', 9, 8, 7, 6];

        let transform = client_state
            .encrypt_message_with_nonce(99, &message, [0x22; 16])
            .expect("message should encrypt");
        let plaintext = server_state
            .decrypt_message(&transform)
            .expect("message should decrypt");

        assert_eq!(transform.flags_or_algorithm, TransformValue(CipherId::Aes128Ccm as u16));
        assert_eq!(transform.original_message_size, message.len() as u32);
        assert_eq!(plaintext, message);
    }

    #[test]
    fn rejects_transform_with_unexpected_flag_value() {
        let state = EncryptionState::new(
            Dialect::Smb311,
            derive_encryption_keys(
                Dialect::Smb311,
                CipherId::Aes128Gcm,
                &(0u8..16).collect::<Vec<_>>(),
                None,
                Some(&(0u8..64).collect::<Vec<_>>()),
            )
            .expect("keys should derive"),
        );
        let message = vec![0xfe, b'S', b'M', b'B', 1, 2, 3, 4];
        let mut transform = state
            .encrypt_message_with_nonce(55, &message, [0x33; 16])
            .expect("message should encrypt");
        transform.flags_or_algorithm = TransformValue(0x0002);

        let error = state
            .decrypt_message(&transform)
            .expect_err("unexpected transform value should fail");

        assert_eq!(
            error.to_string(),
            "invalid response: SMB transform header used an unexpected flags or cipher value"
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
