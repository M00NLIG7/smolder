//! NTLMv2 message generation for SMB session setup.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitflags::bitflags;
use hmac::{Hmac, Mac};
use md4::{Digest as _, Md4};
use md5::Md5;
use rand::random;

use smolder_proto::smb::smb2::utf16le;
use smolder_proto::smb::smb2::NegotiateResponse;

use super::spnego::{
    encode_neg_token_init_ntlm, encode_neg_token_resp, encode_neg_token_resp_ntlm,
    extract_mech_token, ntlm_mech_types, parse_neg_token_resp, NEG_STATE_ACCEPT_COMPLETE,
    NEG_STATE_REJECT,
};
use super::{AuthError, AuthProvider};

const NTLMSSP_SIGNATURE: &[u8; 8] = b"NTLMSSP\0";
const NTLM_MESSAGE_NEGOTIATE: u32 = 1;
const NTLM_MESSAGE_CHALLENGE: u32 = 2;
const NTLM_MESSAGE_AUTHENTICATE: u32 = 3;
const WINDOWS_TICK: u64 = 10_000_000;
const SEC_TO_UNIX_EPOCH: u64 = 11_644_473_600;
const MIC_PRESENT_FLAG: u32 = 0x0000_0002;
const NTLM_VERSION: [u8; 8] = [6, 1, 0, 0, 0, 0, 0, 0x0f];

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    struct NegotiateFlags: u32 {
        const UNICODE = 0x0000_0001;
        const REQUEST_TARGET = 0x0000_0004;
        const SIGN = 0x0000_0010;
        const NTLM = 0x0000_0200;
        const ALWAYS_SIGN = 0x0000_8000;
        const TARGET_TYPE_DOMAIN = 0x0001_0000;
        const TARGET_TYPE_SERVER = 0x0002_0000;
        const EXTENDED_SESSIONSECURITY = 0x0008_0000;
        const TARGET_INFO = 0x0080_0000;
        const VERSION = 0x0200_0000;
        const _128 = 0x2000_0000;
        const KEY_EXCH = 0x4000_0000;
        const _56 = 0x8000_0000;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct AvId(u16);

impl AvId {
    const EOL: Self = Self(0x0000);
    #[cfg(test)]
    const NB_COMPUTER_NAME: Self = Self(0x0001);
    #[cfg(test)]
    const NB_DOMAIN_NAME: Self = Self(0x0002);
    #[cfg(test)]
    const DNS_COMPUTER_NAME: Self = Self(0x0003);
    #[cfg(test)]
    const DNS_DOMAIN_NAME: Self = Self(0x0004);
    const FLAGS: Self = Self(0x0006);
    const TIMESTAMP: Self = Self(0x0007);
    #[cfg(test)]
    const SINGLE_HOST: Self = Self(0x0008);
    #[cfg(test)]
    const TARGET_NAME: Self = Self(0x0009);
    #[cfg(test)]
    const CHANNEL_BINDINGS: Self = Self(0x000a);
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AvPair {
    av_id: AvId,
    value: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SecurityBuffer {
    len: u16,
    offset: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ChallengeMessage {
    flags: NegotiateFlags,
    server_challenge: [u8; 8],
    target_info: Vec<AvPair>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NegotiateMessage {
    flags: NegotiateFlags,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthenticateMessage {
    lm_challenge_response: Vec<u8>,
    nt_challenge_response: Vec<u8>,
    domain_name: Vec<u8>,
    user_name: Vec<u8>,
    workstation: Vec<u8>,
    encrypted_random_session_key: Vec<u8>,
    flags: NegotiateFlags,
    version: [u8; 8],
    mic: [u8; 16],
}

#[derive(Debug, Clone)]
enum NtlmState {
    Initial,
    WaitingForChallenge { negotiate_message: Vec<u8> },
    WaitingForCompletion { flags: NegotiateFlags },
    Complete,
}

/// Username, password, and optional domain/workstation information for NTLM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtlmCredentials {
    username: String,
    password: String,
    domain: String,
    workstation: String,
}

impl NtlmCredentials {
    /// Creates credentials for an SMB account.
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
            domain: String::new(),
            workstation: String::new(),
        }
    }

    /// Sets the NTLM domain component.
    #[must_use]
    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = domain.into();
        self
    }

    /// Sets the workstation string placed in the authenticate message.
    #[must_use]
    pub fn with_workstation(mut self, workstation: impl Into<String>) -> Self {
        self.workstation = workstation.into();
        self
    }
}

/// NTLMv2 authentication provider for SMB `SESSION_SETUP`.
#[derive(Debug, Clone)]
pub struct NtlmAuthenticator {
    credentials: NtlmCredentials,
    client_challenge: [u8; 8],
    timestamp: u64,
    state: NtlmState,
    session_key: Option<[u8; 16]>,
}

impl NtlmAuthenticator {
    /// Creates an NTLMv2 authenticator with a random client challenge.
    pub fn new(credentials: NtlmCredentials) -> Self {
        Self {
            credentials,
            client_challenge: random(),
            timestamp: current_windows_timestamp(),
            state: NtlmState::Initial,
            session_key: None,
        }
    }

    /// Overrides the client challenge, which is useful for deterministic tests.
    #[must_use]
    pub fn with_client_challenge(mut self, client_challenge: [u8; 8]) -> Self {
        self.client_challenge = client_challenge;
        self
    }

    /// Overrides the NTLM timestamp, which is useful for deterministic tests.
    #[must_use]
    pub fn with_timestamp(mut self, timestamp: u64) -> Self {
        self.timestamp = timestamp;
        self
    }

    fn negotiate_flags(&self) -> NegotiateFlags {
        NegotiateFlags::UNICODE
            | NegotiateFlags::REQUEST_TARGET
            | NegotiateFlags::SIGN
            | NegotiateFlags::NTLM
            | NegotiateFlags::ALWAYS_SIGN
            | NegotiateFlags::EXTENDED_SESSIONSECURITY
            | NegotiateFlags::VERSION
            | NegotiateFlags::_128
            | NegotiateFlags::KEY_EXCH
    }
}

impl AuthProvider for NtlmAuthenticator {
    fn initial_token(&mut self, _negotiate: &NegotiateResponse) -> Result<Vec<u8>, AuthError> {
        if !matches!(self.state, NtlmState::Initial) {
            return Err(AuthError::InvalidState(
                "initial token requested after authentication started",
            ));
        }

        let negotiate = NegotiateMessage {
            flags: self.negotiate_flags(),
        };
        let negotiate_message = negotiate.encode();
        self.state = NtlmState::WaitingForChallenge {
            negotiate_message: negotiate_message.clone(),
        };
        Ok(encode_neg_token_init_ntlm(&negotiate_message))
    }

    fn next_token(&mut self, incoming: &[u8]) -> Result<Vec<u8>, AuthError> {
        let negotiate_message = match &self.state {
            NtlmState::WaitingForChallenge { negotiate_message } => negotiate_message.clone(),
            NtlmState::Initial => {
                return Err(AuthError::InvalidState(
                    "challenge received before initial token was sent",
                ))
            }
            NtlmState::WaitingForCompletion { flags } => {
                let parsed = parse_neg_token_resp(incoming)?;
                if matches!(parsed.neg_state, Some(NEG_STATE_REJECT)) {
                    return Err(AuthError::InvalidToken("authentication was rejected"));
                }

                let session_key = self.session_key.ok_or(AuthError::InvalidState(
                    "session key missing during completion",
                ))?;
                let mech_list_mic = mech_list_mic(session_key, *flags);
                self.state = NtlmState::Complete;
                return Ok(encode_neg_token_resp(
                    Some(NEG_STATE_ACCEPT_COMPLETE),
                    None,
                    Some(&mech_list_mic),
                ));
            }
            NtlmState::Complete => {
                return Err(AuthError::InvalidState("authentication already finished"))
            }
        };

        let challenge_message = extract_mech_token(incoming)?;
        let challenge = ChallengeMessage::decode(&challenge_message)?;
        let (authenticate, session_key) = build_authenticate_message(
            &self.credentials,
            &challenge,
            &negotiate_message,
            &challenge_message,
            self.client_challenge,
            self.timestamp,
        )?;
        let token = encode_neg_token_resp_ntlm(&authenticate.encode());

        self.session_key = Some(session_key);
        self.state = NtlmState::WaitingForCompletion {
            flags: authenticate.flags,
        };
        Ok(token)
    }

    fn finish(&mut self, incoming: &[u8]) -> Result<(), AuthError> {
        if matches!(self.state, NtlmState::Complete) {
            return Ok(());
        }

        if incoming.is_empty() {
            self.state = NtlmState::Complete;
            return Ok(());
        }

        let parsed = parse_neg_token_resp(incoming)?;
        if matches!(parsed.neg_state, Some(NEG_STATE_REJECT)) {
            return Err(AuthError::InvalidToken("authentication was rejected"));
        }

        self.state = NtlmState::Complete;
        Ok(())
    }

    fn session_key(&self) -> Option<&[u8]> {
        self.session_key.as_ref().map(|value| value.as_slice())
    }
}

impl NegotiateMessage {
    fn encode(&self) -> Vec<u8> {
        let payload_offset = 40u32;
        let mut out = Vec::with_capacity(40);
        out.extend_from_slice(NTLMSSP_SIGNATURE);
        out.extend_from_slice(&NTLM_MESSAGE_NEGOTIATE.to_le_bytes());
        out.extend_from_slice(&self.flags.bits().to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&payload_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&payload_offset.to_le_bytes());
        out.extend_from_slice(&version_bytes(self.flags));
        out
    }

    #[cfg(test)]
    fn decode(message: &[u8]) -> Result<Self, AuthError> {
        if message.len() < 40 {
            return Err(AuthError::InvalidToken("negotiate message too short"));
        }
        if &message[..8] != NTLMSSP_SIGNATURE {
            return Err(AuthError::InvalidToken("missing NTLMSSP signature"));
        }
        if read_u32(message, 8)? != NTLM_MESSAGE_NEGOTIATE {
            return Err(AuthError::InvalidToken("unexpected NTLM message type"));
        }

        Ok(Self {
            flags: NegotiateFlags::from_bits(read_u32(message, 12)?)
                .ok_or(AuthError::InvalidToken("unsupported NTLM negotiate flags"))?,
        })
    }
}

impl ChallengeMessage {
    fn decode(message: &[u8]) -> Result<Self, AuthError> {
        if message.len() < 48 {
            return Err(AuthError::InvalidToken("challenge message too short"));
        }
        if &message[..8] != NTLMSSP_SIGNATURE {
            return Err(AuthError::InvalidToken("missing NTLMSSP signature"));
        }
        if read_u32(message, 8)? != NTLM_MESSAGE_CHALLENGE {
            return Err(AuthError::InvalidToken("unexpected NTLM message type"));
        }

        let flags = NegotiateFlags::from_bits(read_u32(message, 20)?)
            .ok_or(AuthError::InvalidToken("unsupported NTLM negotiate flags"))?;
        let server_challenge = read_array::<8>(message, 24)?;
        let target_info = read_security_buffer(message, 40)?
            .map(parse_target_info)
            .transpose()?
            .unwrap_or_default();

        Ok(Self {
            flags,
            server_challenge,
            target_info,
        })
    }

    #[cfg(test)]
    fn encode_for_test(&self) -> Vec<u8> {
        let target_info = encode_target_info(&self.target_info);
        let target_info_len = u16::try_from(target_info.len()).expect("target info too large");
        let target_info_offset = 48u32;

        let mut out = Vec::with_capacity(48 + target_info.len());
        out.extend_from_slice(NTLMSSP_SIGNATURE);
        out.extend_from_slice(&NTLM_MESSAGE_CHALLENGE.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&self.flags.bits().to_le_bytes());
        out.extend_from_slice(&self.server_challenge);
        out.extend_from_slice(&0u64.to_le_bytes());
        out.extend_from_slice(&target_info_len.to_le_bytes());
        out.extend_from_slice(&target_info_len.to_le_bytes());
        out.extend_from_slice(&target_info_offset.to_le_bytes());
        out.extend_from_slice(&target_info);
        out
    }
}

impl AuthenticateMessage {
    fn encode(&self) -> Vec<u8> {
        let buffers = [
            &self.lm_challenge_response,
            &self.nt_challenge_response,
            &self.domain_name,
            &self.user_name,
            &self.workstation,
            &self.encrypted_random_session_key,
        ];
        let security_buffers = calculate_security_buffers(88, &buffers);

        let mut out = Vec::new();
        out.extend_from_slice(NTLMSSP_SIGNATURE);
        out.extend_from_slice(&NTLM_MESSAGE_AUTHENTICATE.to_le_bytes());
        for buffer in &security_buffers {
            out.extend_from_slice(&buffer.len.to_le_bytes());
            out.extend_from_slice(&buffer.len.to_le_bytes());
            out.extend_from_slice(&buffer.offset.to_le_bytes());
        }
        out.extend_from_slice(&self.flags.bits().to_le_bytes());
        out.extend_from_slice(&self.version);
        out.extend_from_slice(&self.mic);
        for buffer in buffers {
            out.extend_from_slice(buffer);
        }
        out
    }

    #[cfg(test)]
    fn decode(message: &[u8]) -> Result<Self, AuthError> {
        if message.len() < 88 {
            return Err(AuthError::InvalidToken("authenticate message too short"));
        }
        if &message[..8] != NTLMSSP_SIGNATURE {
            return Err(AuthError::InvalidToken("missing NTLMSSP signature"));
        }
        if read_u32(message, 8)? != NTLM_MESSAGE_AUTHENTICATE {
            return Err(AuthError::InvalidToken("unexpected NTLM message type"));
        }

        let lm = read_security_buffer(message, 12)?.unwrap_or(&[]);
        let nt = read_security_buffer(message, 20)?.unwrap_or(&[]);
        let domain = read_security_buffer(message, 28)?.unwrap_or(&[]);
        let user = read_security_buffer(message, 36)?.unwrap_or(&[]);
        let workstation = read_security_buffer(message, 44)?.unwrap_or(&[]);
        let encrypted_random_session_key = read_security_buffer(message, 52)?.unwrap_or(&[]);
        let flags = NegotiateFlags::from_bits(read_u32(message, 60)?)
            .ok_or(AuthError::InvalidToken("unsupported NTLM negotiate flags"))?;
        let version = read_array::<8>(message, 64)?;
        let mic = read_array::<16>(message, 72)?;

        Ok(Self {
            lm_challenge_response: lm.to_vec(),
            nt_challenge_response: nt.to_vec(),
            domain_name: domain.to_vec(),
            user_name: user.to_vec(),
            workstation: workstation.to_vec(),
            encrypted_random_session_key: encrypted_random_session_key.to_vec(),
            flags,
            version,
            mic,
        })
    }
}

fn build_authenticate_message(
    credentials: &NtlmCredentials,
    challenge: &ChallengeMessage,
    negotiate_message: &[u8],
    challenge_message: &[u8],
    client_challenge: [u8; 8],
    fallback_timestamp: u64,
) -> Result<(AuthenticateMessage, [u8; 16]), AuthError> {
    let negotiated_flags = challenge.flags & default_authenticate_flags();
    let timestamp = target_info_timestamp(&challenge.target_info).unwrap_or(fallback_timestamp);
    let use_mic = target_info_timestamp(&challenge.target_info).is_some();
    let target_info = if use_mic {
        with_mic_present_flag(&challenge.target_info)
    } else {
        challenge.target_info.clone()
    };

    let response_key_nt = ntowfv2(credentials);
    let nt_response = ntlmv2_response(
        &response_key_nt,
        challenge.server_challenge,
        client_challenge,
        timestamp,
        &target_info,
    );
    let key_exchange_key = hmac_md5(&response_key_nt, &nt_response[..16]);
    let (encrypted_random_session_key, session_key) =
        encrypt_random_session_key(negotiated_flags, key_exchange_key);
    let lm_challenge_response = if use_mic {
        vec![0; 24]
    } else {
        lmv2_response(
            &response_key_nt,
            challenge.server_challenge,
            client_challenge,
        )
    };

    let mut authenticate = AuthenticateMessage {
        lm_challenge_response,
        nt_challenge_response: nt_response,
        domain_name: utf16le(&credentials.domain),
        user_name: utf16le(&credentials.username),
        workstation: utf16le(&credentials.workstation),
        encrypted_random_session_key,
        flags: negotiated_flags,
        version: version_bytes(negotiated_flags),
        mic: [0; 16],
    };

    if use_mic {
        let encoded = authenticate.encode();
        authenticate.mic = hmac_md5_concat(
            &session_key,
            &[negotiate_message, challenge_message, encoded.as_slice()],
        );
    }

    Ok((authenticate, session_key))
}

fn default_authenticate_flags() -> NegotiateFlags {
    NegotiateFlags::UNICODE
        | NegotiateFlags::SIGN
        | NegotiateFlags::ALWAYS_SIGN
        | NegotiateFlags::NTLM
        | NegotiateFlags::EXTENDED_SESSIONSECURITY
        | NegotiateFlags::VERSION
        | NegotiateFlags::_128
        | NegotiateFlags::KEY_EXCH
}

fn version_bytes(flags: NegotiateFlags) -> [u8; 8] {
    if flags.contains(NegotiateFlags::VERSION) {
        NTLM_VERSION
    } else {
        [0; 8]
    }
}

fn encrypt_random_session_key(
    flags: NegotiateFlags,
    key_exchange_key: [u8; 16],
) -> (Vec<u8>, [u8; 16]) {
    if flags.contains(NegotiateFlags::KEY_EXCH) {
        let exported_session_key: [u8; 16] = random();
        (
            rc4k(&key_exchange_key, &exported_session_key),
            exported_session_key,
        )
    } else {
        (Vec::new(), key_exchange_key)
    }
}

fn mech_list_mic(exported_session_key: [u8; 16], flags: NegotiateFlags) -> [u8; 16] {
    ntlm_message_signature(exported_session_key, flags, &ntlm_mech_types())
}

fn ntlm_message_signature(
    exported_session_key: [u8; 16],
    flags: NegotiateFlags,
    message: &[u8],
) -> [u8; 16] {
    let sign_key = sign_key(exported_session_key, flags);
    let mut checksum = hmac_md5_concat(&sign_key, &[&0u32.to_le_bytes(), message]);
    let mut checksum8 = checksum[..8].to_vec();
    if flags.contains(NegotiateFlags::KEY_EXCH) {
        checksum8 = rc4k(&seal_key(exported_session_key, flags), &checksum8);
    }

    checksum[..8].copy_from_slice(&checksum8);

    let mut signature = [0u8; 16];
    signature[..4].copy_from_slice(&1u32.to_le_bytes());
    signature[4..12].copy_from_slice(&checksum[..8]);
    signature[12..].copy_from_slice(&0u32.to_le_bytes());
    signature
}

fn sign_key(exported_session_key: [u8; 16], flags: NegotiateFlags) -> [u8; 16] {
    if !flags.contains(NegotiateFlags::EXTENDED_SESSIONSECURITY) {
        return [0; 16];
    }

    md5_concat(&[
        &exported_session_key,
        b"session key to client-to-server signing key magic constant\0",
    ])
}

fn seal_key(exported_session_key: [u8; 16], flags: NegotiateFlags) -> [u8; 16] {
    let base_key = if flags.contains(NegotiateFlags::_128) {
        exported_session_key.as_slice()
    } else if flags.contains(NegotiateFlags::_56) {
        &exported_session_key[..7]
    } else {
        &exported_session_key[..5]
    };

    md5_concat(&[
        base_key,
        b"session key to client-to-server sealing key magic constant\0",
    ])
}

fn ntowfv2(credentials: &NtlmCredentials) -> [u8; 16] {
    let nt_hash = nt_hash(&credentials.password);
    let identity = utf16le(&(credentials.username.to_uppercase() + &credentials.domain));
    hmac_md5(&nt_hash, &identity)
}

fn nt_hash(password: &str) -> [u8; 16] {
    let mut md4 = Md4::new();
    md4.update(utf16le(password));
    let digest = md4.finalize();

    let mut out = [0; 16];
    out.copy_from_slice(&digest);
    out
}

fn ntlmv2_response(
    response_key_nt: &[u8; 16],
    server_challenge: [u8; 8],
    client_challenge: [u8; 8],
    timestamp: u64,
    target_info: &[AvPair],
) -> Vec<u8> {
    let mut blob = Vec::new();
    blob.extend_from_slice(&0x0101_0000u32.to_le_bytes());
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&timestamp.to_le_bytes());
    blob.extend_from_slice(&client_challenge);
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&encode_target_info(target_info));

    let mut proof_input = Vec::with_capacity(8 + blob.len());
    proof_input.extend_from_slice(&server_challenge);
    proof_input.extend_from_slice(&blob);
    let nt_proof = hmac_md5(response_key_nt, &proof_input);

    let mut response = Vec::with_capacity(16 + blob.len());
    response.extend_from_slice(&nt_proof);
    response.extend_from_slice(&blob);
    response
}

fn lmv2_response(
    response_key_lm: &[u8; 16],
    server_challenge: [u8; 8],
    client_challenge: [u8; 8],
) -> Vec<u8> {
    let mut input = Vec::with_capacity(16);
    input.extend_from_slice(&server_challenge);
    input.extend_from_slice(&client_challenge);

    let mut response = Vec::with_capacity(24);
    response.extend_from_slice(&hmac_md5(response_key_lm, &input));
    response.extend_from_slice(&client_challenge);
    response
}

fn encode_target_info(target_info: &[AvPair]) -> Vec<u8> {
    let mut out = Vec::new();
    for pair in target_info {
        out.extend_from_slice(&pair.av_id.0.to_le_bytes());
        out.extend_from_slice(&(pair.value.len() as u16).to_le_bytes());
        out.extend_from_slice(&pair.value);
    }
    out.extend_from_slice(&AvId::EOL.0.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

fn parse_target_info(bytes: &[u8]) -> Result<Vec<AvPair>, AuthError> {
    let mut offset = 0;
    let mut pairs = Vec::new();

    while offset + 4 <= bytes.len() {
        let av_id = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        let len = usize::from(u16::from_le_bytes([bytes[offset + 2], bytes[offset + 3]]));
        offset += 4;
        if av_id == AvId::EOL.0 {
            return Ok(pairs);
        }
        if offset + len > bytes.len() {
            return Err(AuthError::InvalidToken("truncated target info"));
        }
        let value = bytes[offset..offset + len].to_vec();
        offset += len;

        pairs.push(AvPair {
            av_id: AvId(av_id),
            value,
        });
    }

    Err(AuthError::InvalidToken("target info missing terminator"))
}

fn with_mic_present_flag(target_info: &[AvPair]) -> Vec<AvPair> {
    let mut output = target_info.to_vec();
    if let Some(pair) = output.iter_mut().find(|pair| pair.av_id == AvId::FLAGS) {
        let mut flags = if pair.value.len() >= 4 {
            u32::from_le_bytes([pair.value[0], pair.value[1], pair.value[2], pair.value[3]])
        } else {
            0
        };
        flags |= MIC_PRESENT_FLAG;
        pair.value = flags.to_le_bytes().to_vec();
        return output;
    }

    output.push(AvPair {
        av_id: AvId::FLAGS,
        value: MIC_PRESENT_FLAG.to_le_bytes().to_vec(),
    });
    output
}

fn target_info_timestamp(target_info: &[AvPair]) -> Option<u64> {
    target_info
        .iter()
        .find(|pair| pair.av_id == AvId::TIMESTAMP && pair.value.len() == 8)
        .map(|pair| {
            u64::from_le_bytes([
                pair.value[0],
                pair.value[1],
                pair.value[2],
                pair.value[3],
                pair.value[4],
                pair.value[5],
                pair.value[6],
                pair.value[7],
            ])
        })
}

fn calculate_security_buffers(base_offset: u32, buffers: &[&Vec<u8>; 6]) -> [SecurityBuffer; 6] {
    let mut offset = base_offset;
    std::array::from_fn(|index| {
        let current = SecurityBuffer {
            len: u16::try_from(buffers[index].len()).expect("buffer length overflow"),
            offset,
        };
        offset += u32::try_from(buffers[index].len()).expect("buffer length overflow");
        current
    })
}

fn read_security_buffer(message: &[u8], offset: usize) -> Result<Option<&[u8]>, AuthError> {
    let len = usize::from(read_u16(message, offset)?);
    let data_offset = usize::try_from(read_u32(message, offset + 4)?)
        .map_err(|_| AuthError::InvalidToken("invalid security buffer offset"))?;
    if len == 0 {
        return Ok(None);
    }
    if data_offset + len > message.len() {
        return Err(AuthError::InvalidToken(
            "security buffer points past message",
        ));
    }
    Ok(Some(&message[data_offset..data_offset + len]))
}

fn read_u16(message: &[u8], offset: usize) -> Result<u16, AuthError> {
    let bytes = message
        .get(offset..offset + 2)
        .ok_or(AuthError::InvalidToken("unexpected end of message"))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(message: &[u8], offset: usize) -> Result<u32, AuthError> {
    let bytes = message
        .get(offset..offset + 4)
        .ok_or(AuthError::InvalidToken("unexpected end of message"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_array<const N: usize>(message: &[u8], offset: usize) -> Result<[u8; N], AuthError> {
    let bytes = message
        .get(offset..offset + N)
        .ok_or(AuthError::InvalidToken("unexpected end of message"))?;
    let mut out = [0; N];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn hmac_md5(key: &[u8], payload: &[u8]) -> [u8; 16] {
    let mut mac = Hmac::<Md5>::new_from_slice(key).expect("HMAC accepts arbitrary key length");
    mac.update(payload);
    let digest = mac.finalize().into_bytes();

    let mut out = [0; 16];
    out.copy_from_slice(&digest);
    out
}

fn hmac_md5_concat(key: &[u8], payloads: &[&[u8]]) -> [u8; 16] {
    let mut mac = Hmac::<Md5>::new_from_slice(key).expect("HMAC accepts arbitrary key length");
    for payload in payloads {
        mac.update(payload);
    }
    let digest = mac.finalize().into_bytes();

    let mut out = [0; 16];
    out.copy_from_slice(&digest);
    out
}

fn md5_concat(payloads: &[&[u8]]) -> [u8; 16] {
    let mut md5 = Md5::new();
    for payload in payloads {
        md5.update(payload);
    }

    let digest = md5.finalize();
    let mut out = [0; 16];
    out.copy_from_slice(&digest);
    out
}

fn rc4k(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut state = [0u8; 256];
    for (index, value) in state.iter_mut().enumerate() {
        *value = index as u8;
    }

    let mut j = 0usize;
    for i in 0..state.len() {
        j = (j + usize::from(state[i]) + usize::from(key[i % key.len()])) & 0xff;
        state.swap(i, j);
    }

    let mut i = 0usize;
    j = 0;
    let mut out = Vec::with_capacity(data.len());
    for byte in data {
        i = (i + 1) & 0xff;
        j = (j + usize::from(state[i])) & 0xff;
        state.swap(i, j);
        let k = state[(usize::from(state[i]) + usize::from(state[j])) & 0xff];
        out.push(*byte ^ k);
    }
    out
}

fn current_windows_timestamp() -> u64 {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0));
    (duration.as_secs() + SEC_TO_UNIX_EPOCH) * WINDOWS_TICK
        + u64::from(duration.subsec_nanos()) / 100
}

#[cfg(test)]
mod tests {
    use smolder_proto::smb::smb2::{Dialect, GlobalCapabilities, NegotiateResponse, SigningMode};

    use super::super::spnego::{
        encode_neg_token_resp_ntlm, extract_mech_token, parse_neg_token_resp,
        NEG_STATE_ACCEPT_COMPLETE,
    };
    use super::{
        current_windows_timestamp, nt_hash, target_info_timestamp, AuthProvider,
        AuthenticateMessage, AvId, AvPair, ChallengeMessage, NegotiateFlags, NegotiateMessage,
        NtlmAuthenticator, NtlmCredentials, NTLM_VERSION,
    };

    #[test]
    fn nt_hash_matches_known_password_vector() {
        assert_eq!(
            nt_hash("password"),
            [
                0x88, 0x46, 0xf7, 0xea, 0xee, 0x8f, 0xb1, 0x17, 0xad, 0x06, 0xbd, 0xd8, 0x30, 0xb7,
                0x58, 0x6c,
            ]
        );
    }

    #[test]
    fn challenge_message_roundtrips_target_info() {
        let challenge = ChallengeMessage {
            flags: NegotiateFlags::UNICODE | NegotiateFlags::TARGET_INFO,
            server_challenge: [1, 2, 3, 4, 5, 6, 7, 8],
            target_info: vec![
                AvPair {
                    av_id: AvId::NB_COMPUTER_NAME,
                    value: vec![b'S', 0, b'R', 0, b'V', 0],
                },
                AvPair {
                    av_id: AvId::DNS_COMPUTER_NAME,
                    value: vec![b's', 0, b'r', 0, b'v', 0],
                },
                AvPair {
                    av_id: AvId::DNS_DOMAIN_NAME,
                    value: vec![
                        b'e', 0, b'x', 0, b'a', 0, b'm', 0, b'p', 0, b'l', 0, b'e', 0,
                    ],
                },
                AvPair {
                    av_id: AvId::SINGLE_HOST,
                    value: vec![0x11; 8],
                },
                AvPair {
                    av_id: AvId::TARGET_NAME,
                    value: vec![b'c', 0, b'i', 0, b'f', 0, b's', 0],
                },
                AvPair {
                    av_id: AvId::CHANNEL_BINDINGS,
                    value: vec![0x22; 16],
                },
                AvPair {
                    av_id: AvId::TIMESTAMP,
                    value: 1_337u64.to_le_bytes().to_vec(),
                },
            ],
        };

        let encoded = challenge.encode_for_test();
        let decoded = ChallengeMessage::decode(&encoded).expect("challenge should decode");

        assert_eq!(decoded.server_challenge, challenge.server_challenge);
        assert_eq!(decoded.target_info, challenge.target_info);
    }

    #[test]
    fn authenticator_initial_token_matches_samba_flag_profile() {
        let negotiate = NegotiateResponse {
            security_mode: SigningMode::ENABLED,
            dialect_revision: Dialect::Smb302,
            negotiate_contexts: Vec::new(),
            server_guid: [0; 16],
            capabilities: GlobalCapabilities::empty(),
            max_transact_size: 0,
            max_read_size: 0,
            max_write_size: 0,
            system_time: 0,
            server_start_time: 0,
            security_buffer: Vec::new(),
        };
        let mut auth = NtlmAuthenticator::new(NtlmCredentials::new("alice", "password"));

        let initial = auth
            .initial_token(&negotiate)
            .expect("initial token should build");
        let negotiate = extract_mech_token(&initial).expect("should extract NTLM token");
        let negotiate = NegotiateMessage::decode(&negotiate).expect("type1 should decode");

        assert_eq!(
            negotiate.flags,
            NegotiateFlags::UNICODE
                | NegotiateFlags::REQUEST_TARGET
                | NegotiateFlags::SIGN
                | NegotiateFlags::NTLM
                | NegotiateFlags::ALWAYS_SIGN
                | NegotiateFlags::EXTENDED_SESSIONSECURITY
                | NegotiateFlags::VERSION
                | NegotiateFlags::_128
                | NegotiateFlags::KEY_EXCH
        );
    }

    #[test]
    fn authenticator_builds_type3_message_with_mic_when_timestamp_present() {
        let credentials = NtlmCredentials::new("alice", "password")
            .with_domain("DOMAIN")
            .with_workstation("WORKSTATION");
        let mut auth = NtlmAuthenticator::new(credentials)
            .with_client_challenge([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11])
            .with_timestamp(5_000);
        let negotiate = NegotiateResponse {
            security_mode: SigningMode::ENABLED,
            dialect_revision: Dialect::Smb302,
            negotiate_contexts: Vec::new(),
            server_guid: [0; 16],
            capabilities: GlobalCapabilities::empty(),
            max_transact_size: 0,
            max_read_size: 0,
            max_write_size: 0,
            system_time: 0,
            server_start_time: 0,
            security_buffer: Vec::new(),
        };
        let initial = auth
            .initial_token(&negotiate)
            .expect("initial token should build");
        assert!(initial.starts_with(&[0x60]));

        let challenge = ChallengeMessage {
            flags: NegotiateFlags::UNICODE
                | NegotiateFlags::NTLM
                | NegotiateFlags::SIGN
                | NegotiateFlags::ALWAYS_SIGN
                | NegotiateFlags::EXTENDED_SESSIONSECURITY
                | NegotiateFlags::TARGET_INFO
                | NegotiateFlags::VERSION
                | NegotiateFlags::_128
                | NegotiateFlags::KEY_EXCH,
            server_challenge: [8, 7, 6, 5, 4, 3, 2, 1],
            target_info: vec![
                AvPair {
                    av_id: AvId::NB_COMPUTER_NAME,
                    value: vec![b'S', 0, b'E', 0, b'R', 0, b'V', 0, b'E', 0, b'R', 0],
                },
                AvPair {
                    av_id: AvId::NB_DOMAIN_NAME,
                    value: vec![b'D', 0, b'O', 0, b'M', 0, b'A', 0, b'I', 0, b'N', 0],
                },
                AvPair {
                    av_id: AvId::TIMESTAMP,
                    value: 9_999u64.to_le_bytes().to_vec(),
                },
            ],
        };
        let response = auth
            .next_token(&encode_neg_token_resp_ntlm(&challenge.encode_for_test()))
            .expect("challenge response should build");
        let authenticate = extract_mech_token(&response).expect("should extract NTLM token");
        let authenticate = AuthenticateMessage::decode(&authenticate).expect("type3 should decode");

        assert_eq!(
            authenticate.domain_name,
            smolder_proto::smb::smb2::utf16le("DOMAIN")
        );
        assert_eq!(
            authenticate.user_name,
            smolder_proto::smb::smb2::utf16le("alice")
        );
        assert_eq!(
            authenticate.workstation,
            smolder_proto::smb::smb2::utf16le("WORKSTATION")
        );
        assert_eq!(authenticate.lm_challenge_response, vec![0; 24]);
        assert!(!authenticate.nt_challenge_response.is_empty());
        assert_eq!(authenticate.encrypted_random_session_key.len(), 16);
        assert_eq!(authenticate.version, NTLM_VERSION);
        assert_ne!(authenticate.mic, [0; 16]);
        assert!(auth.session_key().is_some());
    }

    #[test]
    fn authenticator_allows_final_empty_spnego_leg() {
        let credentials = NtlmCredentials::new("alice", "password");
        let mut auth = NtlmAuthenticator::new(credentials)
            .with_client_challenge([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11])
            .with_timestamp(5_000);
        let negotiate = NegotiateResponse {
            security_mode: SigningMode::ENABLED,
            dialect_revision: Dialect::Smb302,
            negotiate_contexts: Vec::new(),
            server_guid: [0; 16],
            capabilities: GlobalCapabilities::empty(),
            max_transact_size: 0,
            max_read_size: 0,
            max_write_size: 0,
            system_time: 0,
            server_start_time: 0,
            security_buffer: Vec::new(),
        };
        auth.initial_token(&negotiate)
            .expect("initial token should build");

        let challenge = ChallengeMessage {
            flags: NegotiateFlags::UNICODE
                | NegotiateFlags::NTLM
                | NegotiateFlags::SIGN
                | NegotiateFlags::ALWAYS_SIGN
                | NegotiateFlags::EXTENDED_SESSIONSECURITY
                | NegotiateFlags::TARGET_INFO
                | NegotiateFlags::VERSION
                | NegotiateFlags::_128
                | NegotiateFlags::KEY_EXCH,
            server_challenge: [8, 7, 6, 5, 4, 3, 2, 1],
            target_info: vec![AvPair {
                av_id: AvId::TIMESTAMP,
                value: 9_999u64.to_le_bytes().to_vec(),
            }],
        };
        auth.next_token(&encode_neg_token_resp_ntlm(&challenge.encode_for_test()))
            .expect("challenge response should build");

        let final_spnego = vec![0xa1, 0x07, 0x30, 0x05, 0xa0, 0x03, 0x0a, 0x01, 0x00];
        let final_token = auth
            .next_token(&final_spnego)
            .expect("final leg should be acknowledged");

        let parsed = parse_neg_token_resp(&final_token).expect("completion token should parse");
        assert_eq!(parsed.neg_state, Some(NEG_STATE_ACCEPT_COMPLETE));
        assert_eq!(parsed.response_token, None);
        assert_eq!(parsed.mech_list_mic.as_ref().map(Vec::len), Some(16));
    }

    #[test]
    fn timestamp_helper_uses_windows_epoch() {
        assert!(current_windows_timestamp() > 100_000_000);
    }

    #[test]
    fn target_info_timestamp_extracts_value() {
        let target_info = vec![AvPair {
            av_id: AvId::TIMESTAMP,
            value: 42u64.to_le_bytes().to_vec(),
        }];

        assert_eq!(target_info_timestamp(&target_info), Some(42));
    }
}
