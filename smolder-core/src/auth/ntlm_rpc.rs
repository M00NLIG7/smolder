//! NTLM packet-integrity helpers for connection-oriented DCE/RPC.

use hmac::{Hmac, Mac};
use md5::Md5;

use smolder_proto::rpc::{AuthLevel, AuthType, AuthVerifier};

use crate::error::CoreError;

const NTLM_SIGNATURE_LEN: usize = 16;
const NTLM_SIGNATURE_VERSION: u32 = 1;
const RPC_COMMON_HEADER_LEN: usize = 16;
const SEC_TRAILER_LEN: usize = 8;
const CLIENT_SIGN_MAGIC: &[u8] = b"session key to client-to-server signing key magic constant\0";
const SERVER_SIGN_MAGIC: &[u8] = b"session key to server-to-client signing key magic constant\0";
const CLIENT_SEAL_MAGIC: &[u8] = b"session key to client-to-server sealing key magic constant\0";
const SERVER_SEAL_MAGIC: &[u8] = b"session key to server-to-client sealing key magic constant\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    Client,
    Server,
}

/// NTLM session-security capabilities that affect RPC packet-integrity keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtlmSessionSecurity {
    /// Whether NTLM extended session security was negotiated.
    pub extended_session_security: bool,
    /// Whether NTLM key exchange was negotiated.
    pub key_exchange: bool,
    /// Whether 128-bit session security was negotiated.
    pub negotiate_128: bool,
    /// Whether 56-bit session security was negotiated.
    pub negotiate_56: bool,
}

impl NtlmSessionSecurity {
    /// Builds an NTLM session-security profile from the negotiated NTLM flags.
    #[must_use]
    pub const fn new(
        extended_session_security: bool,
        key_exchange: bool,
        negotiate_128: bool,
        negotiate_56: bool,
    ) -> Self {
        Self {
            extended_session_security,
            key_exchange,
            negotiate_128,
            negotiate_56,
        }
    }
}

/// Stateful NTLM packet-integrity context for connection-oriented DCE/RPC.
///
/// This helper derives the NTLM signing and sealing keys from an exported NTLM
/// session key and emits/verifies the 16-byte verifier used by RPC
/// `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY` packets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtlmRpcPacketIntegrity {
    auth_context_id: u32,
    supports_header_signing: bool,
    security: NtlmSessionSecurity,
    sequence: u32,
    client_signing_key: [u8; 16],
    server_signing_key: [u8; 16],
    client_sealing: Option<Rc4State>,
    server_sealing: Option<Rc4State>,
}

impl NtlmRpcPacketIntegrity {
    /// Creates a packet-integrity context that signs the full RPC header and body.
    pub fn new(
        session_key: &[u8],
        security: NtlmSessionSecurity,
        auth_context_id: u32,
    ) -> Result<Self, CoreError> {
        Self::with_header_signing(session_key, security, auth_context_id, true)
    }

    /// Creates a packet-integrity context with an explicit header-signing mode.
    pub fn with_header_signing(
        session_key: &[u8],
        security: NtlmSessionSecurity,
        auth_context_id: u32,
        supports_header_signing: bool,
    ) -> Result<Self, CoreError> {
        let session_key: [u8; 16] = session_key.try_into().map_err(|_| {
            CoreError::InvalidInput("NTLM RPC packet integrity requires a 16-byte session key")
        })?;
        if !security.extended_session_security {
            return Err(CoreError::Unsupported(
                "NTLM RPC packet integrity requires extended session security",
            ));
        }

        let client_signing_key = derive_signing_key(session_key, Direction::Client);
        let server_signing_key = derive_signing_key(session_key, Direction::Server);
        let client_sealing = security.key_exchange.then(|| {
            Rc4State::new(&derive_sealing_key(
                session_key,
                security,
                Direction::Client,
            ))
        });
        let server_sealing = security.key_exchange.then(|| {
            Rc4State::new(&derive_sealing_key(
                session_key,
                security,
                Direction::Server,
            ))
        });

        Ok(Self {
            auth_context_id,
            supports_header_signing,
            security,
            sequence: 0,
            client_signing_key,
            server_signing_key,
            client_sealing,
            server_sealing,
        })
    }

    /// Returns a zeroed NTLM verifier placeholder suitable for packet encoding.
    #[must_use]
    pub fn placeholder_auth_verifier(&self) -> AuthVerifier {
        AuthVerifier::new(
            AuthType::WinNt,
            AuthLevel::PacketIntegrity,
            self.auth_context_id,
            vec![0; NTLM_SIGNATURE_LEN],
        )
    }

    /// Signs an outbound RPC request packet that already contains a verifier placeholder.
    pub fn sign_request_verifier(
        &mut self,
        packet_with_placeholder: &[u8],
    ) -> Result<AuthVerifier, CoreError> {
        let auth_value = self.signature_for(Direction::Client, packet_with_placeholder)?;
        self.sequence = self.sequence.wrapping_add(1);
        Ok(AuthVerifier::new(
            AuthType::WinNt,
            AuthLevel::PacketIntegrity,
            self.auth_context_id,
            auth_value,
        ))
    }

    /// Verifies an inbound RPC response packet against its NTLM auth verifier.
    pub fn verify_response(
        &mut self,
        packet_with_auth: &[u8],
        verifier: &AuthVerifier,
    ) -> Result<(), CoreError> {
        self.validate_verifier(verifier)?;
        let expected = self.signature_for(Direction::Server, packet_with_auth)?;
        if verifier.auth_value != expected {
            return Err(CoreError::InvalidResponse(
                "rpc response auth verifier did not match the derived NTLM packet-integrity signature",
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn sign_response_verifier(
        &mut self,
        packet_with_placeholder: &[u8],
    ) -> Result<AuthVerifier, CoreError> {
        let auth_value = self.signature_for(Direction::Server, packet_with_placeholder)?;
        Ok(AuthVerifier::new(
            AuthType::WinNt,
            AuthLevel::PacketIntegrity,
            self.auth_context_id,
            auth_value,
        ))
    }

    fn validate_verifier(&self, verifier: &AuthVerifier) -> Result<(), CoreError> {
        if verifier.auth_type != AuthType::WinNt {
            return Err(CoreError::InvalidResponse(
                "rpc response used an unexpected authentication type",
            ));
        }
        if verifier.auth_level != AuthLevel::PacketIntegrity {
            return Err(CoreError::InvalidResponse(
                "rpc response used an unexpected authentication level",
            ));
        }
        if verifier.auth_context_id != self.auth_context_id {
            return Err(CoreError::InvalidResponse(
                "rpc response auth context id did not match the active NTLM context",
            ));
        }
        if verifier.auth_value.len() != NTLM_SIGNATURE_LEN {
            return Err(CoreError::InvalidResponse(
                "rpc response NTLM verifier was not 16 bytes",
            ));
        }
        Ok(())
    }

    fn signature_for(
        &mut self,
        direction: Direction,
        packet_with_auth: &[u8],
    ) -> Result<Vec<u8>, CoreError> {
        let message = self.signed_payload(packet_with_auth)?;
        let sequence = self.sequence;

        let (signing_key, sealing_state) = match direction {
            Direction::Client => (&self.client_signing_key, self.client_sealing.as_mut()),
            Direction::Server => (&self.server_signing_key, self.server_sealing.as_mut()),
        };

        let mut checksum = hmac_md5(signing_key, &[&sequence.to_le_bytes(), message]);
        let mut checksum8 = checksum[..8].to_vec();
        if self.security.key_exchange {
            let sealing_state = sealing_state.ok_or(CoreError::InvalidInput(
                "NTLM RPC sealing state missing despite negotiated key exchange",
            ))?;
            checksum8 = sealing_state.apply(&checksum8);
        }
        checksum[..8].copy_from_slice(&checksum8);

        let mut signature = [0u8; NTLM_SIGNATURE_LEN];
        signature[..4].copy_from_slice(&NTLM_SIGNATURE_VERSION.to_le_bytes());
        signature[4..12].copy_from_slice(&checksum[..8]);
        signature[12..].copy_from_slice(&sequence.to_le_bytes());
        Ok(signature.to_vec())
    }

    fn signed_payload<'a>(&self, packet_with_auth: &'a [u8]) -> Result<&'a [u8], CoreError> {
        if packet_with_auth.len() < NTLM_SIGNATURE_LEN {
            return Err(CoreError::InvalidInput(
                "rpc packet was shorter than an NTLM auth verifier",
            ));
        }

        let packet_without_auth = &packet_with_auth[..packet_with_auth.len() - NTLM_SIGNATURE_LEN];
        if self.supports_header_signing {
            return Ok(packet_without_auth);
        }

        if packet_without_auth.len() < RPC_COMMON_HEADER_LEN + SEC_TRAILER_LEN {
            return Err(CoreError::InvalidInput(
                "rpc packet was shorter than the RPC header and security trailer",
            ));
        }

        Ok(
            &packet_without_auth
                [RPC_COMMON_HEADER_LEN..packet_without_auth.len() - SEC_TRAILER_LEN],
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Rc4State {
    state: [u8; 256],
    i: usize,
    j: usize,
}

impl Rc4State {
    fn new(key: &[u8]) -> Self {
        let mut state = [0u8; 256];
        for (index, value) in state.iter_mut().enumerate() {
            *value = index as u8;
        }

        let mut j = 0usize;
        for i in 0..state.len() {
            j = (j + usize::from(state[i]) + usize::from(key[i % key.len()])) & 0xff;
            state.swap(i, j);
        }

        Self { state, i: 0, j: 0 }
    }

    fn apply(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len());
        for byte in data {
            self.i = (self.i + 1) & 0xff;
            self.j = (self.j + usize::from(self.state[self.i])) & 0xff;
            self.state.swap(self.i, self.j);
            let key_byte = self.state
                [(usize::from(self.state[self.i]) + usize::from(self.state[self.j])) & 0xff];
            out.push(*byte ^ key_byte);
        }
        out
    }
}

fn derive_signing_key(session_key: [u8; 16], direction: Direction) -> [u8; 16] {
    let magic = match direction {
        Direction::Client => CLIENT_SIGN_MAGIC,
        Direction::Server => SERVER_SIGN_MAGIC,
    };
    md5_concat(&[&session_key, magic])
}

fn derive_sealing_key(
    session_key: [u8; 16],
    security: NtlmSessionSecurity,
    direction: Direction,
) -> [u8; 16] {
    let base_key = if security.negotiate_128 {
        session_key.as_slice()
    } else if security.negotiate_56 {
        &session_key[..7]
    } else {
        &session_key[..5]
    };
    let magic = match direction {
        Direction::Client => CLIENT_SEAL_MAGIC,
        Direction::Server => SERVER_SEAL_MAGIC,
    };
    md5_concat(&[base_key, magic])
}

fn hmac_md5(key: &[u8], payloads: &[&[u8]]) -> [u8; 16] {
    let mut mac = Hmac::<Md5>::new_from_slice(key).expect("HMAC-MD5 accepts any key length");
    for payload in payloads {
        mac.update(payload);
    }
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest);
    out
}

fn md5_concat(payloads: &[&[u8]]) -> [u8; 16] {
    use md5::Digest as _;

    let mut md5 = Md5::new();
    for payload in payloads {
        md5.update(payload);
    }
    let digest = md5.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::{NtlmRpcPacketIntegrity, NtlmSessionSecurity};

    #[test]
    fn placeholder_verifier_uses_ntlm_packet_integrity_profile() {
        let context = NtlmRpcPacketIntegrity::new(
            &[0x55; 16],
            NtlmSessionSecurity::new(true, true, true, false),
            7,
        )
        .expect("packet integrity context");

        let verifier = context.placeholder_auth_verifier();
        assert_eq!(verifier.auth_context_id, 7);
        assert_eq!(verifier.auth_value, vec![0; 16]);
    }

    #[test]
    fn request_signatures_match_impacket_ntlm_vectors() {
        let mut context = NtlmRpcPacketIntegrity::new(
            &(0u8..16).collect::<Vec<_>>(),
            NtlmSessionSecurity::new(true, true, true, false),
            1,
        )
        .expect("packet integrity context");

        let first_packet = packet_with_placeholder(
            "05000003100000002800000001000000deadbeefcafebabe1122334455667788",
        );
        let second_packet =
            packet_with_placeholder("05000000080000001000000002000000aabbccddeeff0011");

        let first = context
            .sign_request_verifier(&first_packet)
            .expect("first request signature");
        let second = context
            .sign_request_verifier(&second_packet)
            .expect("second request signature");

        assert_eq!(first.auth_value, hex("01000000fca82b3c83a7766700000000"),);
        assert_eq!(second.auth_value, hex("010000009ceba7e2c5c29a5201000000"),);
    }

    #[test]
    fn response_verification_rejects_modified_signature() {
        let mut signer = NtlmRpcPacketIntegrity::new(
            &[0x22; 16],
            NtlmSessionSecurity::new(true, true, true, false),
            3,
        )
        .expect("packet integrity context");
        let request_packet =
            packet_with_placeholder("05000000100000001800000004000000aaaaaaaaaaaaaaaa");
        signer
            .sign_request_verifier(&request_packet)
            .expect("request signature should advance sequence");

        let response_packet =
            packet_with_placeholder("05000002080000001000000004000000bbbbbbbbbbbbbbbb");
        let mut verifier = signer
            .sign_response_verifier(&response_packet)
            .expect("response signature");
        verifier.auth_value[0] ^= 0xff;

        let error = signer
            .verify_response(
                &packet_with_auth(&response_packet, &verifier.auth_value),
                &verifier,
            )
            .expect_err("modified signature should fail");
        assert_eq!(
            error.to_string(),
            "invalid response: rpc response auth verifier did not match the derived NTLM packet-integrity signature"
        );
    }

    fn packet_with_placeholder(message_hex: &str) -> Vec<u8> {
        let mut packet = hex(message_hex);
        packet.extend_from_slice(&[0; 16]);
        packet
    }

    fn packet_with_auth(packet_with_placeholder: &[u8], auth_value: &[u8]) -> Vec<u8> {
        let mut packet = packet_with_placeholder.to_vec();
        let start = packet.len() - auth_value.len();
        packet[start..].copy_from_slice(auth_value);
        packet
    }

    fn hex(input: &str) -> Vec<u8> {
        let bytes = input.as_bytes();
        assert_eq!(bytes.len() % 2, 0, "hex input must have an even length");
        bytes
            .chunks(2)
            .map(|chunk| {
                let high = (chunk[0] as char)
                    .to_digit(16)
                    .expect("high nibble should be valid hex");
                let low = (chunk[1] as char)
                    .to_digit(16)
                    .expect("low nibble should be valid hex");
                ((high << 4) | low) as u8
            })
            .collect()
    }
}
