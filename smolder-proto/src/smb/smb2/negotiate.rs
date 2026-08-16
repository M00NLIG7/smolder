//! SMB2 negotiate request and response bodies.

use std::convert::TryFrom;

use bitflags::bitflags;
use bytes::{BufMut, BytesMut};

use super::{
    check_fixed_structure_size, copy_bytes, get_array, get_u16, get_u32, get_u64, put_padding,
    slice_from_offset, HEADER_LEN,
};
use crate::smb::compression::{CompressionAlgorithm, CompressionCapabilityFlags};
use crate::smb::ProtocolError;

bitflags! {
    /// SMB2 negotiate security mode.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct SigningMode: u16 {
        /// Server/client supports signing.
        const ENABLED = 0x0001;
        /// Server/client requires signing.
        const REQUIRED = 0x0002;
    }
}

bitflags! {
    /// SMB2 transport-capability flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct TransportCapabilityFlags: u32 {
        /// `SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY`
        const ACCEPT_TRANSPORT_LEVEL_SECURITY = 0x0000_0001;
    }
}

bitflags! {
    /// SMB2 negotiate capabilities.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct GlobalCapabilities: u32 {
        /// Distributed file system support.
        const DFS = 0x0000_0001;
        /// Leasing support.
        const LEASING = 0x0000_0002;
        /// Multi-credit support.
        const LARGE_MTU = 0x0000_0004;
        /// Multi-channel support.
        const MULTI_CHANNEL = 0x0000_0008;
        /// Persistent handles support.
        const PERSISTENT_HANDLES = 0x0000_0010;
        /// Directory leasing support.
        const DIRECTORY_LEASING = 0x0000_0020;
        /// Encryption support.
        const ENCRYPTION = 0x0000_0040;
    }
}

/// Supported SMB dialect revisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum Dialect {
    /// SMB 2.0.2
    Smb202 = 0x0202,
    /// SMB 2.1
    Smb210 = 0x0210,
    /// SMB 3.0
    Smb300 = 0x0300,
    /// SMB 3.0.2
    Smb302 = 0x0302,
    /// SMB 3.1.1
    Smb311 = 0x0311,
}

impl TryFrom<u16> for Dialect {
    type Error = ProtocolError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0202 => Ok(Self::Smb202),
            0x0210 => Ok(Self::Smb210),
            0x0300 => Ok(Self::Smb300),
            0x0302 => Ok(Self::Smb302),
            0x0311 => Ok(Self::Smb311),
            _ => Err(ProtocolError::InvalidField {
                field: "dialect",
                reason: "unknown dialect revision",
            }),
        }
    }
}

/// A raw SMB2 negotiate context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiateContext {
    /// Context type identifier.
    pub context_type: u16,
    /// Raw context payload.
    pub data: Vec<u8>,
}

/// SMB3.1.1 negotiate context identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum NegotiateContextType {
    /// `SMB2_PREAUTH_INTEGRITY_CAPABILITIES`
    PreauthIntegrityCapabilities = 0x0001,
    /// `SMB2_ENCRYPTION_CAPABILITIES`
    EncryptionCapabilities = 0x0002,
    /// `SMB2_COMPRESSION_CAPABILITIES`
    CompressionCapabilities = 0x0003,
    /// `SMB2_NETNAME_NEGOTIATE_CONTEXT_ID`
    Netname = 0x0005,
    /// `SMB2_TRANSPORT_CAPABILITIES`
    TransportCapabilities = 0x0006,
    /// `SMB2_RDMA_TRANSFORM_CAPABILITIES`
    RdmaTransformCapabilities = 0x0007,
    /// `SMB2_SIGNING_CAPABILITIES`
    SigningCapabilities = 0x0008,
}

impl TryFrom<u16> for NegotiateContextType {
    type Error = ProtocolError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0001 => Ok(Self::PreauthIntegrityCapabilities),
            0x0002 => Ok(Self::EncryptionCapabilities),
            0x0003 => Ok(Self::CompressionCapabilities),
            0x0005 => Ok(Self::Netname),
            0x0006 => Ok(Self::TransportCapabilities),
            0x0007 => Ok(Self::RdmaTransformCapabilities),
            0x0008 => Ok(Self::SigningCapabilities),
            _ => Err(ProtocolError::InvalidField {
                field: "context_type",
                reason: "unknown negotiate context type",
            }),
        }
    }
}

/// Preauthentication integrity hash algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum PreauthIntegrityHashId {
    /// `SHA-512`
    Sha512 = 0x0001,
}

impl TryFrom<u16> for PreauthIntegrityHashId {
    type Error = ProtocolError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0001 => Ok(Self::Sha512),
            _ => Err(ProtocolError::InvalidField {
                field: "preauth_hash_algorithm",
                reason: "unknown preauth integrity hash algorithm",
            }),
        }
    }
}

/// SMB 3.x encryption ciphers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum CipherId {
    /// `SMB2_ENCRYPTION_AES128_CCM`
    Aes128Ccm = 0x0001,
    /// `SMB2_ENCRYPTION_AES128_GCM`
    Aes128Gcm = 0x0002,
    /// `SMB2_ENCRYPTION_AES256_CCM`
    Aes256Ccm = 0x0003,
    /// `SMB2_ENCRYPTION_AES256_GCM`
    Aes256Gcm = 0x0004,
}

impl TryFrom<u16> for CipherId {
    type Error = ProtocolError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0001 => Ok(Self::Aes128Ccm),
            0x0002 => Ok(Self::Aes128Gcm),
            0x0003 => Ok(Self::Aes256Ccm),
            0x0004 => Ok(Self::Aes256Gcm),
            _ => Err(ProtocolError::InvalidField {
                field: "cipher_id",
                reason: "unknown encryption cipher",
            }),
        }
    }
}

/// `SMB2_ENCRYPTION_CAPABILITIES`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionCapabilities {
    /// Supported encryption ciphers.
    pub ciphers: Vec<CipherId>,
}

/// `SMB2_COMPRESSION_CAPABILITIES`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressionCapabilities {
    /// Supported compression algorithms in preference order.
    pub compression_algorithms: Vec<CompressionAlgorithm>,
    /// Compression capability flags.
    pub flags: CompressionCapabilityFlags,
}

/// `SMB2_TRANSPORT_CAPABILITIES`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportCapabilities {
    /// Transport capability flags.
    pub flags: TransportCapabilityFlags,
}

impl CompressionCapabilities {
    /// Serializes the context payload.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(8 + self.compression_algorithms.len() * 2);
        out.put_u16_le(self.compression_algorithms.len() as u16);
        out.put_u16_le(0);
        out.put_u32_le(self.flags.bits());
        for algorithm in &self.compression_algorithms {
            out.put_u16_le(*algorithm as u16);
        }
        out.to_vec()
    }

    /// Parses the context payload.
    pub fn decode(data: &[u8]) -> Result<Self, ProtocolError> {
        let mut input = data;
        let algorithm_count = usize::from(get_u16(&mut input, "compression_algorithm_count")?);
        if get_u16(&mut input, "padding")? != 0 {
            return Err(ProtocolError::InvalidField {
                field: "padding",
                reason: "must be zero",
            });
        }
        let flags = CompressionCapabilityFlags::from_bits(get_u32(&mut input, "flags")?).ok_or(
            ProtocolError::InvalidField {
                field: "flags",
                reason: "unknown compression capability flags set",
            },
        )?;
        if algorithm_count == 0 {
            return Err(ProtocolError::InvalidField {
                field: "compression_algorithm_count",
                reason: "at least one compression algorithm is required",
            });
        }

        let algorithm_bytes =
            algorithm_count
                .checked_mul(2)
                .ok_or(ProtocolError::SizeLimitExceeded {
                    field: "compression_algorithms",
                })?;
        if input.len() < algorithm_bytes {
            return Err(ProtocolError::UnexpectedEof {
                field: "compression_algorithm",
            });
        }
        let mut compression_algorithms = Vec::new();
        compression_algorithms
            .try_reserve_exact(algorithm_count)
            .map_err(|_| ProtocolError::SizeLimitExceeded {
                field: "compression_algorithms",
            })?;
        for _ in 0..algorithm_count {
            let algorithm =
                CompressionAlgorithm::try_from(get_u16(&mut input, "compression_algorithm")?)?;
            if compression_algorithms.contains(&algorithm) {
                return Err(ProtocolError::InvalidField {
                    field: "compression_algorithm",
                    reason: "duplicate compression algorithm",
                });
            }
            compression_algorithms.push(algorithm);
        }
        if !input.is_empty() {
            return Err(ProtocolError::InvalidField {
                field: "compression_capabilities",
                reason: "trailing bytes after compression algorithms",
            });
        }

        Ok(Self {
            compression_algorithms,
            flags,
        })
    }
}

impl TransportCapabilities {
    /// Serializes the context payload.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(4);
        out.put_u32_le(self.flags.bits());
        out.to_vec()
    }

    /// Parses the context payload.
    pub fn decode(data: &[u8]) -> Result<Self, ProtocolError> {
        let mut input = data;
        let flags = TransportCapabilityFlags::from_bits(get_u32(&mut input, "flags")?).ok_or(
            ProtocolError::InvalidField {
                field: "flags",
                reason: "unknown transport capability flags set",
            },
        )?;
        if !input.is_empty() {
            return Err(ProtocolError::InvalidField {
                field: "transport_capabilities",
                reason: "trailing bytes after transport capability flags",
            });
        }
        Ok(Self { flags })
    }
}

impl EncryptionCapabilities {
    /// Serializes the context payload.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(2 + self.ciphers.len() * 2);
        out.put_u16_le(self.ciphers.len() as u16);
        for cipher in &self.ciphers {
            out.put_u16_le(*cipher as u16);
        }
        out.to_vec()
    }

    /// Parses the context payload.
    pub fn decode(data: &[u8]) -> Result<Self, ProtocolError> {
        let mut input = data;
        let cipher_count = usize::from(get_u16(&mut input, "cipher_count")?);
        if cipher_count == 0 {
            return Err(ProtocolError::InvalidField {
                field: "cipher_count",
                reason: "at least one encryption cipher is required",
            });
        }

        let cipher_bytes = cipher_count
            .checked_mul(2)
            .ok_or(ProtocolError::SizeLimitExceeded { field: "ciphers" })?;
        if input.len() < cipher_bytes {
            return Err(ProtocolError::UnexpectedEof { field: "cipher_id" });
        }
        let mut ciphers = Vec::new();
        ciphers
            .try_reserve_exact(cipher_count)
            .map_err(|_| ProtocolError::SizeLimitExceeded { field: "ciphers" })?;
        for _ in 0..cipher_count {
            let cipher = CipherId::try_from(get_u16(&mut input, "cipher_id")?)?;
            if ciphers.contains(&cipher) {
                return Err(ProtocolError::InvalidField {
                    field: "cipher_id",
                    reason: "duplicate encryption cipher",
                });
            }
            ciphers.push(cipher);
        }
        if !input.is_empty() {
            return Err(ProtocolError::InvalidField {
                field: "encryption_capabilities",
                reason: "trailing bytes after encryption ciphers",
            });
        }

        Ok(Self { ciphers })
    }
}

/// `SMB2_PREAUTH_INTEGRITY_CAPABILITIES`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreauthIntegrityCapabilities {
    /// Supported preauthentication hash algorithms.
    pub hash_algorithms: Vec<PreauthIntegrityHashId>,
    /// Client or server salt.
    pub salt: Vec<u8>,
}

impl PreauthIntegrityCapabilities {
    /// Serializes the context payload.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(4 + self.hash_algorithms.len() * 2 + self.salt.len());
        out.put_u16_le(self.hash_algorithms.len() as u16);
        out.put_u16_le(self.salt.len() as u16);
        for algorithm in &self.hash_algorithms {
            out.put_u16_le(*algorithm as u16);
        }
        out.extend_from_slice(&self.salt);
        out.to_vec()
    }

    /// Parses the context payload.
    pub fn decode(data: &[u8]) -> Result<Self, ProtocolError> {
        let mut input = data;
        let hash_algorithm_count = usize::from(get_u16(&mut input, "hash_algorithm_count")?);
        let salt_length = usize::from(get_u16(&mut input, "salt_length")?);
        if hash_algorithm_count == 0 {
            return Err(ProtocolError::InvalidField {
                field: "hash_algorithm_count",
                reason: "at least one preauth hash algorithm is required",
            });
        }

        let algorithm_bytes =
            hash_algorithm_count
                .checked_mul(2)
                .ok_or(ProtocolError::SizeLimitExceeded {
                    field: "hash_algorithms",
                })?;
        let required =
            algorithm_bytes
                .checked_add(salt_length)
                .ok_or(ProtocolError::SizeLimitExceeded {
                    field: "preauth_integrity_capabilities",
                })?;
        if input.len() < required {
            return Err(ProtocolError::UnexpectedEof {
                field: "preauth_integrity_capabilities",
            });
        }
        let mut hash_algorithms = Vec::new();
        hash_algorithms
            .try_reserve_exact(hash_algorithm_count)
            .map_err(|_| ProtocolError::SizeLimitExceeded {
                field: "hash_algorithms",
            })?;
        for _ in 0..hash_algorithm_count {
            let algorithm =
                PreauthIntegrityHashId::try_from(get_u16(&mut input, "hash_algorithm")?)?;
            if hash_algorithms.contains(&algorithm) {
                return Err(ProtocolError::InvalidField {
                    field: "hash_algorithm",
                    reason: "duplicate preauth hash algorithm",
                });
            }
            hash_algorithms.push(algorithm);
        }
        let mut salt = Vec::new();
        salt.try_reserve_exact(salt_length)
            .map_err(|_| ProtocolError::SizeLimitExceeded { field: "salt" })?;
        salt.extend_from_slice(&input[..salt_length]);
        input = &input[salt_length..];
        if !input.is_empty() {
            return Err(ProtocolError::InvalidField {
                field: "preauth_integrity_capabilities",
                reason: "trailing bytes after preauth salt",
            });
        }

        Ok(Self {
            hash_algorithms,
            salt,
        })
    }
}

impl NegotiateContext {
    /// Returns the typed negotiate context identifier when it is known.
    #[must_use]
    pub fn context_type(&self) -> Option<NegotiateContextType> {
        NegotiateContextType::try_from(self.context_type).ok()
    }

    /// Builds a preauthentication integrity negotiate context.
    #[must_use]
    pub fn preauth_integrity(capabilities: PreauthIntegrityCapabilities) -> Self {
        Self {
            context_type: NegotiateContextType::PreauthIntegrityCapabilities as u16,
            data: capabilities.encode(),
        }
    }

    /// Decodes a preauthentication integrity negotiate context.
    pub fn as_preauth_integrity(
        &self,
    ) -> Result<Option<PreauthIntegrityCapabilities>, ProtocolError> {
        if self.context_type() != Some(NegotiateContextType::PreauthIntegrityCapabilities) {
            return Ok(None);
        }
        PreauthIntegrityCapabilities::decode(&self.data).map(Some)
    }

    /// Builds an encryption-capabilities negotiate context.
    #[must_use]
    pub fn encryption_capabilities(capabilities: EncryptionCapabilities) -> Self {
        Self {
            context_type: NegotiateContextType::EncryptionCapabilities as u16,
            data: capabilities.encode(),
        }
    }

    /// Decodes an encryption-capabilities negotiate context.
    pub fn as_encryption_capabilities(
        &self,
    ) -> Result<Option<EncryptionCapabilities>, ProtocolError> {
        if self.context_type() != Some(NegotiateContextType::EncryptionCapabilities) {
            return Ok(None);
        }
        EncryptionCapabilities::decode(&self.data).map(Some)
    }

    /// Builds a compression-capabilities negotiate context.
    #[must_use]
    pub fn compression_capabilities(capabilities: CompressionCapabilities) -> Self {
        Self {
            context_type: NegotiateContextType::CompressionCapabilities as u16,
            data: capabilities.encode(),
        }
    }

    /// Decodes a compression-capabilities negotiate context.
    pub fn as_compression_capabilities(
        &self,
    ) -> Result<Option<CompressionCapabilities>, ProtocolError> {
        if self.context_type() != Some(NegotiateContextType::CompressionCapabilities) {
            return Ok(None);
        }
        CompressionCapabilities::decode(&self.data).map(Some)
    }

    /// Builds a transport-capabilities negotiate context.
    #[must_use]
    pub fn transport_capabilities(capabilities: TransportCapabilities) -> Self {
        Self {
            context_type: NegotiateContextType::TransportCapabilities as u16,
            data: capabilities.encode(),
        }
    }

    /// Decodes a transport-capabilities negotiate context.
    pub fn as_transport_capabilities(
        &self,
    ) -> Result<Option<TransportCapabilities>, ProtocolError> {
        if self.context_type() != Some(NegotiateContextType::TransportCapabilities) {
            return Ok(None);
        }
        TransportCapabilities::decode(&self.data).map(Some)
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.context_type.to_le_bytes());
        out.extend_from_slice(&(self.data.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&self.data);
        put_padding(out, 8);
    }
}

/// SMB2 negotiate request body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiateRequest {
    /// Client signing preferences.
    pub security_mode: SigningMode,
    /// Global client capabilities.
    pub capabilities: GlobalCapabilities,
    /// Client GUID.
    pub client_guid: [u8; 16],
    /// Requested dialects.
    pub dialects: Vec<Dialect>,
    /// Optional negotiate contexts.
    pub negotiate_contexts: Vec<NegotiateContext>,
}

impl NegotiateRequest {
    /// Serializes the request body.
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        if self.dialects.is_empty() {
            return Err(ProtocolError::InvalidField {
                field: "dialects",
                reason: "at least one dialect is required",
            });
        }
        for (index, dialect) in self.dialects.iter().enumerate() {
            if self.dialects[..index].contains(dialect) {
                return Err(ProtocolError::InvalidField {
                    field: "dialects",
                    reason: "duplicate dialect revision",
                });
            }
        }
        for (index, context) in self.negotiate_contexts.iter().enumerate() {
            if context.data.len() > usize::from(u16::MAX) {
                return Err(ProtocolError::SizeLimitExceeded {
                    field: "negotiate_context_data",
                });
            }
            if self.negotiate_contexts[..index]
                .iter()
                .any(|prior| prior.context_type == context.context_type)
            {
                return Err(ProtocolError::InvalidField {
                    field: "negotiate_contexts",
                    reason: "duplicate negotiate context type",
                });
            }
        }

        let dialect_count = u16::try_from(self.dialects.len())
            .map_err(|_| ProtocolError::SizeLimitExceeded { field: "dialects" })?;
        let context_count = u16::try_from(self.negotiate_contexts.len()).map_err(|_| {
            ProtocolError::SizeLimitExceeded {
                field: "negotiate_contexts",
            }
        })?;

        let mut out = BytesMut::with_capacity(64);
        out.put_u16_le(36);
        out.put_u16_le(dialect_count);
        out.put_u16_le(self.security_mode.bits());
        out.put_u16_le(0);
        out.put_u32_le(self.capabilities.bits());
        out.extend_from_slice(&self.client_guid);

        let include_contexts = !self.negotiate_contexts.is_empty();
        let context_offset = if include_contexts {
            let fixed_and_dialects = 36 + usize::from(dialect_count) * 2;
            let aligned = (fixed_and_dialects + 7) & !7;
            (HEADER_LEN + aligned) as u32
        } else {
            0
        };
        out.put_u32_le(context_offset);
        out.put_u16_le(context_count);
        out.put_u16_le(0);

        for dialect in &self.dialects {
            out.put_u16_le(*dialect as u16);
        }

        if include_contexts {
            let mut variable = out.to_vec();
            put_padding(&mut variable, 8);
            for context in &self.negotiate_contexts {
                context.encode_into(&mut variable);
            }
            return Ok(variable);
        }

        Ok(out.to_vec())
    }

    /// Parses the request body.
    pub fn decode(body: &[u8]) -> Result<Self, ProtocolError> {
        let mut input = body;
        check_fixed_structure_size(get_u16(&mut input, "structure_size")?, 36, "structure_size")?;
        let dialect_count = usize::from(get_u16(&mut input, "dialect_count")?);
        let security_mode = SigningMode::from_bits(get_u16(&mut input, "security_mode")?).ok_or(
            ProtocolError::InvalidField {
                field: "security_mode",
                reason: "unknown signing bits set",
            },
        )?;
        if get_u16(&mut input, "reserved")? != 0 {
            return Err(ProtocolError::InvalidField {
                field: "reserved",
                reason: "must be zero",
            });
        }
        let capabilities = GlobalCapabilities::from_bits(get_u32(&mut input, "capabilities")?)
            .ok_or(ProtocolError::InvalidField {
                field: "capabilities",
                reason: "unknown capability bits set",
            })?;
        let client_guid = get_array::<16>(&mut input, "client_guid")?;
        let context_offset = get_u32(&mut input, "context_offset")?;
        let context_count = usize::from(get_u16(&mut input, "context_count")?);
        if get_u16(&mut input, "reserved2")? != 0 {
            return Err(ProtocolError::InvalidField {
                field: "reserved2",
                reason: "must be zero",
            });
        }

        if dialect_count == 0 {
            return Err(ProtocolError::InvalidField {
                field: "dialect_count",
                reason: "at least one dialect is required",
            });
        }
        let dialect_bytes = dialect_count
            .checked_mul(2)
            .ok_or(ProtocolError::SizeLimitExceeded { field: "dialects" })?;
        if input.len() < dialect_bytes {
            return Err(ProtocolError::UnexpectedEof { field: "dialect" });
        }
        let mut dialects = Vec::new();
        dialects
            .try_reserve_exact(dialect_count)
            .map_err(|_| ProtocolError::SizeLimitExceeded { field: "dialects" })?;
        for _ in 0..dialect_count {
            let dialect = Dialect::try_from(get_u16(&mut input, "dialect")?)?;
            if dialects.contains(&dialect) {
                return Err(ProtocolError::InvalidField {
                    field: "dialect",
                    reason: "duplicate dialect revision",
                });
            }
            dialects.push(dialect);
        }

        let negotiate_contexts = match (context_count, context_offset) {
            (0, 0) => Vec::new(),
            (0, _) => {
                return Err(ProtocolError::InvalidField {
                    field: "context_offset",
                    reason: "context offset must be zero when context count is zero",
                });
            }
            (_, 0) => {
                return Err(ProtocolError::InvalidField {
                    field: "context_offset",
                    reason: "context offset must be nonzero when contexts are present",
                });
            }
            (_, _) => {
                if !dialects.contains(&Dialect::Smb311) {
                    return Err(ProtocolError::InvalidField {
                        field: "context_count",
                        reason: "negotiate contexts require the SMB 3.1.1 dialect",
                    });
                }
                let variable_end = 36usize
                    .checked_add(dialect_bytes)
                    .ok_or(ProtocolError::SizeLimitExceeded { field: "dialects" })?;
                decode_contexts(body, context_offset, context_count, align_8(variable_end))?
            }
        };

        Ok(Self {
            security_mode,
            capabilities,
            client_guid,
            dialects,
            negotiate_contexts,
        })
    }
}

/// SMB2 negotiate response body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiateResponse {
    /// Server signing requirements.
    pub security_mode: SigningMode,
    /// Negotiated dialect.
    pub dialect_revision: Dialect,
    /// Optional negotiate contexts.
    pub negotiate_contexts: Vec<NegotiateContext>,
    /// Server GUID.
    pub server_guid: [u8; 16],
    /// Server capabilities.
    pub capabilities: GlobalCapabilities,
    /// Maximum transact size.
    pub max_transact_size: u32,
    /// Maximum read size.
    pub max_read_size: u32,
    /// Maximum write size.
    pub max_write_size: u32,
    /// Current server time in FILETIME.
    pub system_time: u64,
    /// Server start time in FILETIME.
    pub server_start_time: u64,
    /// Security buffer payload.
    pub security_buffer: Vec<u8>,
}

impl NegotiateResponse {
    /// Serializes the response body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(96);
        out.put_u16_le(65);
        out.put_u16_le(self.security_mode.bits());
        out.put_u16_le(self.dialect_revision as u16);
        out.put_u16_le(self.negotiate_contexts.len() as u16);
        out.extend_from_slice(&self.server_guid);
        out.put_u32_le(self.capabilities.bits());
        out.put_u32_le(self.max_transact_size);
        out.put_u32_le(self.max_read_size);
        out.put_u32_le(self.max_write_size);
        out.put_u64_le(self.system_time);
        out.put_u64_le(self.server_start_time);
        let security_offset = (HEADER_LEN + 64) as u16;
        out.put_u16_le(security_offset);
        out.put_u16_le(self.security_buffer.len() as u16);

        let context_offset = if self.negotiate_contexts.is_empty() {
            0
        } else {
            let base = HEADER_LEN + 64 + self.security_buffer.len();
            (base + ((8 - (base % 8)) % 8)) as u32
        };
        out.put_u32_le(context_offset);
        out.extend_from_slice(&self.security_buffer);

        let mut variable = out.to_vec();
        if !self.negotiate_contexts.is_empty() {
            put_padding(&mut variable, 8);
            for context in &self.negotiate_contexts {
                context.encode_into(&mut variable);
            }
        }
        variable
    }

    /// Parses the response body.
    pub fn decode(body: &[u8]) -> Result<Self, ProtocolError> {
        let mut input = body;
        check_fixed_structure_size(get_u16(&mut input, "structure_size")?, 65, "structure_size")?;
        let security_mode = SigningMode::from_bits(get_u16(&mut input, "security_mode")?).ok_or(
            ProtocolError::InvalidField {
                field: "security_mode",
                reason: "unknown signing bits set",
            },
        )?;
        let dialect_revision = Dialect::try_from(get_u16(&mut input, "dialect_revision")?)?;
        let context_count = usize::from(get_u16(&mut input, "context_count")?);
        let server_guid = get_array::<16>(&mut input, "server_guid")?;
        let capabilities = GlobalCapabilities::from_bits(get_u32(&mut input, "capabilities")?)
            .ok_or(ProtocolError::InvalidField {
                field: "capabilities",
                reason: "unknown capability bits set",
            })?;
        let max_transact_size = get_u32(&mut input, "max_transact_size")?;
        let max_read_size = get_u32(&mut input, "max_read_size")?;
        let max_write_size = get_u32(&mut input, "max_write_size")?;
        let system_time = get_u64(&mut input, "system_time")?;
        let server_start_time = get_u64(&mut input, "server_start_time")?;
        let security_buffer_offset = get_u16(&mut input, "security_buffer_offset")?;
        let security_buffer_len = usize::from(get_u16(&mut input, "security_buffer_len")?);
        let context_offset = get_u32(&mut input, "context_offset")?;

        let security_buffer = copy_bytes(
            slice_from_offset(
                body,
                security_buffer_offset,
                security_buffer_len,
                "security_buffer",
            )?,
            "security_buffer",
        )?;
        let security_start = usize::from(security_buffer_offset)
            .checked_sub(HEADER_LEN)
            .ok_or(ProtocolError::InvalidField {
                field: "security_buffer_offset",
                reason: "offset points before SMB2 body",
            })?;
        if security_buffer_len != 0 && security_start < 64 {
            return Err(ProtocolError::InvalidField {
                field: "security_buffer_offset",
                reason: "security buffer overlaps the fixed negotiate response",
            });
        }
        let security_end = security_start.checked_add(security_buffer_len).ok_or(
            ProtocolError::SizeLimitExceeded {
                field: "security_buffer",
            },
        )?;
        let minimum_context_offset = align_8(64usize.max(security_end));
        let negotiate_contexts = match (context_count, context_offset) {
            (0, 0) => Vec::new(),
            (0, _) => {
                return Err(ProtocolError::InvalidField {
                    field: "context_offset",
                    reason: "context offset must be zero when context count is zero",
                });
            }
            (_, 0) => {
                return Err(ProtocolError::InvalidField {
                    field: "context_offset",
                    reason: "context offset must be nonzero when contexts are present",
                });
            }
            (_, _) => {
                if dialect_revision != Dialect::Smb311 {
                    return Err(ProtocolError::InvalidField {
                        field: "context_count",
                        reason: "negotiate contexts require the SMB 3.1.1 dialect",
                    });
                }
                decode_contexts(body, context_offset, context_count, minimum_context_offset)?
            }
        };

        Ok(Self {
            security_mode,
            dialect_revision,
            negotiate_contexts,
            server_guid,
            capabilities,
            max_transact_size,
            max_read_size,
            max_write_size,
            system_time,
            server_start_time,
            security_buffer,
        })
    }
}

fn align_8(value: usize) -> usize {
    value.saturating_add(7) & !7
}

fn decode_contexts(
    body: &[u8],
    offset_from_header: u32,
    count: usize,
    minimum_body_offset: usize,
) -> Result<Vec<NegotiateContext>, ProtocolError> {
    let offset =
        usize::try_from(offset_from_header).map_err(|_| ProtocolError::SizeLimitExceeded {
            field: "context_offset",
        })?;
    if offset < HEADER_LEN {
        return Err(ProtocolError::InvalidField {
            field: "context_offset",
            reason: "offset points before SMB2 body",
        });
    }
    if offset % 8 != 0 {
        return Err(ProtocolError::InvalidField {
            field: "context_offset",
            reason: "negotiate contexts must start on an 8-byte boundary",
        });
    }

    let mut index = offset
        .checked_sub(HEADER_LEN)
        .ok_or(ProtocolError::InvalidField {
            field: "context_offset",
            reason: "offset points before SMB2 body",
        })?;
    if index < minimum_body_offset {
        return Err(ProtocolError::InvalidField {
            field: "context_offset",
            reason: "negotiate contexts overlap fixed or variable response data",
        });
    }
    if index > body.len() || count > body.len().saturating_sub(index) / 8 {
        return Err(ProtocolError::UnexpectedEof {
            field: "negotiate_context",
        });
    }

    let mut contexts = Vec::new();
    contexts
        .try_reserve_exact(count)
        .map_err(|_| ProtocolError::SizeLimitExceeded {
            field: "negotiate_contexts",
        })?;

    for context_index in 0..count {
        if body.len().saturating_sub(index) < 8 {
            return Err(ProtocolError::UnexpectedEof {
                field: "negotiate_context",
            });
        }

        let mut input = &body[index..];
        let context_type = get_u16(&mut input, "context_type")?;
        if contexts
            .iter()
            .any(|context: &NegotiateContext| context.context_type == context_type)
        {
            return Err(ProtocolError::InvalidField {
                field: "context_type",
                reason: "duplicate negotiate context type",
            });
        }
        let data_len = usize::from(get_u16(&mut input, "context_data_len")?);
        let reserved = get_u32(&mut input, "context_reserved")?;
        if reserved != 0 {
            return Err(ProtocolError::InvalidField {
                field: "context_reserved",
                reason: "reserved negotiate context field must be zero",
            });
        }
        let data_start = index
            .checked_add(8)
            .ok_or(ProtocolError::SizeLimitExceeded {
                field: "context_data",
            })?;
        let data_end =
            data_start
                .checked_add(data_len)
                .ok_or(ProtocolError::SizeLimitExceeded {
                    field: "context_data",
                })?;
        if data_end > body.len() {
            return Err(ProtocolError::UnexpectedEof {
                field: "context_data",
            });
        }

        contexts.push(NegotiateContext {
            context_type,
            data: copy_bytes(&body[data_start..data_end], "context_data")?,
        });

        if context_index + 1 < count {
            index = data_end
                .checked_add(7)
                .ok_or(ProtocolError::SizeLimitExceeded {
                    field: "negotiate_context",
                })?
                & !7;
        }
    }

    Ok(contexts)
}

#[cfg(test)]
mod tests {
    use crate::smb::compression::{CompressionAlgorithm, CompressionCapabilityFlags};

    use super::{
        CipherId, CompressionCapabilities, Dialect, EncryptionCapabilities, GlobalCapabilities,
        NegotiateContext, NegotiateRequest, NegotiateResponse, PreauthIntegrityCapabilities,
        PreauthIntegrityHashId, SigningMode, TransportCapabilities, TransportCapabilityFlags,
    };

    #[test]
    fn preauth_integrity_context_roundtrips() {
        let capabilities = PreauthIntegrityCapabilities {
            hash_algorithms: vec![PreauthIntegrityHashId::Sha512],
            salt: vec![0xaa, 0xbb, 0xcc, 0xdd],
        };
        let context = NegotiateContext::preauth_integrity(capabilities.clone());

        let decoded = context
            .as_preauth_integrity()
            .expect("context should decode")
            .expect("context should be preauth");
        assert_eq!(decoded, capabilities);
    }

    #[test]
    fn encryption_capabilities_context_roundtrips() {
        let capabilities = EncryptionCapabilities {
            ciphers: vec![CipherId::Aes128Ccm, CipherId::Aes128Gcm],
        };
        let context = NegotiateContext::encryption_capabilities(capabilities.clone());

        let decoded = context
            .as_encryption_capabilities()
            .expect("context should decode")
            .expect("context should be encryption");
        assert_eq!(decoded, capabilities);
    }

    #[test]
    fn encryption_capabilities_decode_accepts_single_cipher_response_shape() {
        let decoded = EncryptionCapabilities::decode(&[0x01, 0x00, 0x02, 0x00])
            .expect("single-cipher encryption capabilities should decode");
        assert_eq!(
            decoded,
            EncryptionCapabilities {
                ciphers: vec![CipherId::Aes128Gcm],
            }
        );
    }

    #[test]
    fn compression_capabilities_context_roundtrips() {
        let capabilities = CompressionCapabilities {
            compression_algorithms: vec![CompressionAlgorithm::Lz77, CompressionAlgorithm::Lznt1],
            flags: CompressionCapabilityFlags::empty(),
        };
        let context = NegotiateContext::compression_capabilities(capabilities.clone());

        let decoded = context
            .as_compression_capabilities()
            .expect("context should decode")
            .expect("context should be compression");
        assert_eq!(decoded, capabilities);
    }

    #[test]
    fn compression_capabilities_decode_accepts_single_algorithm_response_shape() {
        let decoded = CompressionCapabilities::decode(&[
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        ])
        .expect("single-algorithm compression capabilities should decode");
        assert_eq!(
            decoded,
            CompressionCapabilities {
                compression_algorithms: vec![CompressionAlgorithm::Lznt1],
                flags: CompressionCapabilityFlags::empty(),
            }
        );
    }

    #[test]
    fn transport_capabilities_context_roundtrips() {
        let capabilities = TransportCapabilities {
            flags: TransportCapabilityFlags::ACCEPT_TRANSPORT_LEVEL_SECURITY,
        };
        let context = NegotiateContext::transport_capabilities(capabilities.clone());

        let decoded = context
            .as_transport_capabilities()
            .expect("context should decode")
            .expect("context should be transport capabilities");
        assert_eq!(decoded, capabilities);
    }

    #[test]
    fn negotiate_request_roundtrips() {
        let request = NegotiateRequest {
            security_mode: SigningMode::ENABLED | SigningMode::REQUIRED,
            capabilities: GlobalCapabilities::DFS | GlobalCapabilities::LARGE_MTU,
            client_guid: *b"0123456789abcdef",
            dialects: vec![Dialect::Smb210, Dialect::Smb302, Dialect::Smb311],
            negotiate_contexts: vec![NegotiateContext::preauth_integrity(
                PreauthIntegrityCapabilities {
                    hash_algorithms: vec![PreauthIntegrityHashId::Sha512],
                    salt: vec![0x01, 0x02, 0x03, 0x04],
                },
            )],
        };

        let encoded = request.encode().expect("request should encode");
        let decoded = NegotiateRequest::decode(&encoded).expect("request should decode");

        assert_eq!(decoded, request);
    }

    #[test]
    fn negotiate_request_rejects_wrapped_misaligned_and_overlapping_context_offsets() {
        for (declared_offset, reason) in [
            (65_640_u32, "wrapped"),
            (105_u32, "misaligned"),
            (96_u32, "overlapping"),
        ] {
            let mut encoded = sample_negotiate_request()
                .encode()
                .expect("sample request should encode");
            encoded[28..32].copy_from_slice(&declared_offset.to_le_bytes());
            assert!(
                NegotiateRequest::decode(&encoded).is_err(),
                "{reason} request context offset must fail"
            );
        }
    }

    #[test]
    fn negotiate_response_roundtrips() {
        let response = NegotiateResponse {
            security_mode: SigningMode::ENABLED,
            dialect_revision: Dialect::Smb311,
            negotiate_contexts: vec![NegotiateContext::preauth_integrity(
                PreauthIntegrityCapabilities {
                    hash_algorithms: vec![PreauthIntegrityHashId::Sha512],
                    salt: vec![0xaa, 0xbb, 0xcc, 0xdd],
                },
            )],
            server_guid: *b"fedcba9876543210",
            capabilities: GlobalCapabilities::DFS | GlobalCapabilities::ENCRYPTION,
            max_transact_size: 65_536,
            max_read_size: 131_072,
            max_write_size: 131_072,
            system_time: 1234,
            server_start_time: 5678,
            security_buffer: vec![0x60, 0x82, 0x01, 0x23],
        };

        let encoded = response.encode();
        let decoded = NegotiateResponse::decode(&encoded).expect("response should decode");

        assert_eq!(decoded, response);
    }

    #[test]
    fn negotiate_response_rejects_wrapped_u32_context_offset() {
        let response = sample_negotiate_response();
        let mut encoded = response.encode();
        encoded[60..64].copy_from_slice(&65_664_u32.to_le_bytes());

        let error = NegotiateResponse::decode(&encoded).expect_err("wrapped offset must fail");
        assert!(matches!(
            error,
            crate::smb::ProtocolError::UnexpectedEof {
                field: "negotiate_context"
            }
        ));
    }

    #[test]
    fn negotiate_response_rejects_misaligned_context_offset() {
        let response = sample_negotiate_response();
        let mut encoded = response.encode();
        let offset = u32::from_le_bytes(encoded[60..64].try_into().unwrap());
        encoded[60..64].copy_from_slice(&(offset + 1).to_le_bytes());

        let error = NegotiateResponse::decode(&encoded).expect_err("misaligned offset must fail");
        assert!(matches!(
            error,
            crate::smb::ProtocolError::InvalidField {
                field: "context_offset",
                ..
            }
        ));
    }

    #[test]
    fn negotiate_response_rejects_context_overlapping_security_buffer() {
        let response = sample_negotiate_response();
        let mut encoded = response.encode();
        encoded[60..64].copy_from_slice(&128_u32.to_le_bytes());

        let error = NegotiateResponse::decode(&encoded).expect_err("overlap must fail");
        assert!(matches!(
            error,
            crate::smb::ProtocolError::InvalidField {
                field: "context_offset",
                ..
            }
        ));
    }

    #[test]
    fn negotiate_response_rejects_fixed_buffer_overlap_and_nonzero_context_reserved() {
        let mut overlapping = sample_negotiate_response().encode();
        overlapping[56..58].copy_from_slice(&64_u16.to_le_bytes());
        assert!(matches!(
            NegotiateResponse::decode(&overlapping),
            Err(crate::smb::ProtocolError::InvalidField {
                field: "security_buffer_offset",
                ..
            })
        ));

        let mut reserved = sample_negotiate_response().encode();
        let context_offset =
            usize::try_from(u32::from_le_bytes(reserved[60..64].try_into().unwrap()))
                .expect("test offset should fit")
                - super::HEADER_LEN;
        reserved[context_offset + 4..context_offset + 8].copy_from_slice(&1_u32.to_le_bytes());
        assert!(matches!(
            NegotiateResponse::decode(&reserved),
            Err(crate::smb::ProtocolError::InvalidField {
                field: "context_reserved",
                ..
            })
        ));
    }

    fn sample_negotiate_request() -> NegotiateRequest {
        NegotiateRequest {
            security_mode: SigningMode::ENABLED,
            capabilities: GlobalCapabilities::ENCRYPTION,
            client_guid: *b"0123456789abcdef",
            dialects: vec![Dialect::Smb311],
            negotiate_contexts: vec![NegotiateContext::preauth_integrity(
                PreauthIntegrityCapabilities {
                    hash_algorithms: vec![PreauthIntegrityHashId::Sha512],
                    salt: vec![1, 2, 3, 4],
                },
            )],
        }
    }

    fn sample_negotiate_response() -> NegotiateResponse {
        NegotiateResponse {
            security_mode: SigningMode::ENABLED,
            dialect_revision: Dialect::Smb311,
            negotiate_contexts: vec![NegotiateContext::preauth_integrity(
                PreauthIntegrityCapabilities {
                    hash_algorithms: vec![PreauthIntegrityHashId::Sha512],
                    salt: vec![0xaa, 0xbb, 0xcc, 0xdd],
                },
            )],
            server_guid: *b"fedcba9876543210",
            capabilities: GlobalCapabilities::DFS | GlobalCapabilities::ENCRYPTION,
            max_transact_size: 65_536,
            max_read_size: 131_072,
            max_write_size: 131_072,
            system_time: 1234,
            server_start_time: 5678,
            security_buffer: vec![0x60, 0x82, 0x01, 0x23],
        }
    }
}
