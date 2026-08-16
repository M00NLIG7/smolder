//! NTLMv2 message generation for SMB session setup.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitflags::bitflags;
use hmac::{Hmac, Mac};
use md4::{Digest as _, Md4};
use md5::Md5;
use rand::random;
use zeroize::{Zeroize, Zeroizing};

use smolder_proto::smb::smb2::utf16le;
use smolder_proto::smb::smb2::NegotiateResponse;

use super::spnego::{
    encode_mech_type_list, encode_neg_token_init, encode_neg_token_resp,
    encode_neg_token_resp_ntlm, parse_neg_token_resp, NEG_STATE_ACCEPT_COMPLETE, NEG_STATE_REJECT,
};
use super::{AuthError, AuthProvider, SpnegoMechanism};

const NTLMSSP_SIGNATURE: &[u8; 8] = b"NTLMSSP\0";
const NTLM_MESSAGE_NEGOTIATE: u32 = 1;
const NTLM_MESSAGE_CHALLENGE: u32 = 2;
const NTLM_MESSAGE_AUTHENTICATE: u32 = 3;
const WINDOWS_TICK: u64 = 10_000_000;
const SEC_TO_UNIX_EPOCH: u64 = 11_644_473_600;
const MSV_AV_FLAGS_MIC_PRESENT: u32 = 0x0000_0002;
const MAX_NTLM_TARGET_INFO_SIZE: usize = 60 * 1024;
bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    struct NegotiateFlags: u32 {
        const UNICODE = 0x0000_0001;
        const REQUEST_TARGET = 0x0000_0004;
        const SIGN = 0x0000_0010;
        const SEAL = 0x0000_0020;
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
    const DNS_COMPUTER_NAME: Self = Self(0x0003);
    const FLAGS: Self = Self(0x0006);
    #[cfg(test)]
    const DNS_DOMAIN_NAME: Self = Self(0x0004);
    const TIMESTAMP: Self = Self(0x0007);
    #[cfg(test)]
    const SINGLE_HOST: Self = Self(0x0008);
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

#[derive(Clone, PartialEq, Eq)]
struct AuthenticateMessage {
    lm_challenge_response: Vec<u8>,
    nt_challenge_response: Vec<u8>,
    domain_name: Vec<u8>,
    user_name: Vec<u8>,
    workstation: Vec<u8>,
    encrypted_random_session_key: Vec<u8>,
    flags: NegotiateFlags,
    version: Option<[u8; 8]>,
    mic: Option<[u8; 16]>,
}

#[derive(Clone)]
enum NtlmState {
    Initial,
    WaitingForChallenge { negotiate_message: Vec<u8> },
    WaitingForCompletion { flags: NegotiateFlags },
    WaitingForFinalSuccess,
    Complete,
}

/// Username, password, and optional domain/workstation information for NTLM.
#[derive(Clone, PartialEq, Eq)]
pub struct NtlmCredentials {
    username: String,
    password: String,
    domain: String,
    workstation: String,
}

impl fmt::Debug for NtlmCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NtlmCredentials")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("domain", &self.domain)
            .field("workstation", &self.workstation)
            .finish()
    }
}

impl Drop for NtlmCredentials {
    fn drop(&mut self) {
        self.password.zeroize();
    }
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
#[derive(Clone)]
pub struct NtlmAuthenticator {
    credentials: NtlmCredentials,
    client_challenge: [u8; 8],
    timestamp: u64,
    state: NtlmState,
    session_key: Option<[u8; 16]>,
    exported_session_key_override: Option<[u8; 16]>,
}

impl fmt::Debug for NtlmAuthenticator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NtlmAuthenticator")
            .field("credentials", &self.credentials)
            .field("state", &ntlm_state_name(&self.state))
            .field(
                "session_key",
                &self.session_key.as_ref().map(|_| "<redacted>"),
            )
            .finish_non_exhaustive()
    }
}

impl Drop for NtlmAuthenticator {
    fn drop(&mut self) {
        self.session_key.zeroize();
        self.exported_session_key_override.zeroize();
    }
}

fn ntlm_state_name(state: &NtlmState) -> &'static str {
    match state {
        NtlmState::Initial => "initial",
        NtlmState::WaitingForChallenge { .. } => "waiting-for-challenge",
        NtlmState::WaitingForCompletion { .. } => "waiting-for-completion",
        NtlmState::WaitingForFinalSuccess => "waiting-for-final-success",
        NtlmState::Complete => "complete",
    }
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
            exported_session_key_override: None,
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

    /// Overrides the exported session key used when NTLM key exchange is negotiated.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_exported_session_key(mut self, exported_session_key: [u8; 16]) -> Self {
        self.exported_session_key_override = Some(exported_session_key);
        self
    }

    fn negotiate_flags(&self) -> NegotiateFlags {
        NegotiateFlags::UNICODE
            | NegotiateFlags::REQUEST_TARGET
            | NegotiateFlags::SIGN
            | NegotiateFlags::SEAL
            | NegotiateFlags::NTLM
            | NegotiateFlags::ALWAYS_SIGN
            | NegotiateFlags::EXTENDED_SESSIONSECURITY
            | NegotiateFlags::TARGET_INFO
            | NegotiateFlags::_128
            | NegotiateFlags::KEY_EXCH
            | NegotiateFlags::_56
    }

    fn spnego_mechanisms(&self) -> [SpnegoMechanism; 1] {
        [SpnegoMechanism::Ntlm]
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
        #[cfg(feature = "dangerous-ntlm-diagnostics")]
        if ntlm_debug_enabled() {
            eprintln!(
                "ntlm type1 flags=0x{:08x} len={} token={}",
                negotiate.flags.bits(),
                negotiate_message.len(),
                hex_bytes(&negotiate_message)
            );
        }
        self.state = NtlmState::WaitingForChallenge {
            negotiate_message: negotiate_message.clone(),
        };
        Ok(encode_neg_token_init(
            &self.spnego_mechanisms(),
            Some(&negotiate_message),
        ))
    }

    fn next_token(&mut self, incoming: &[u8]) -> Result<Vec<u8>, AuthError> {
        let negotiate_message = match &self.state {
            NtlmState::WaitingForChallenge { negotiate_message } => negotiate_message.clone(),
            NtlmState::Initial => {
                return Err(AuthError::InvalidState(
                    "challenge received before initial token was sent",
                ));
            }
            NtlmState::WaitingForCompletion { flags } => {
                let parsed = parse_neg_token_resp(incoming)?;
                validate_ntlm_spnego_response(&parsed)?;
                if matches!(parsed.neg_state, Some(NEG_STATE_REJECT)) {
                    return Err(AuthError::InvalidToken("authentication was rejected"));
                }

                let session_key = self.session_key.ok_or(AuthError::InvalidState(
                    "session key missing during completion",
                ))?;
                let mech_list_mic = mech_list_mic(session_key, *flags);
                self.state = NtlmState::WaitingForFinalSuccess;
                return Ok(encode_neg_token_resp(
                    Some(NEG_STATE_ACCEPT_COMPLETE),
                    None,
                    Some(&mech_list_mic),
                ));
            }
            NtlmState::WaitingForFinalSuccess => {
                return Err(AuthError::InvalidState(
                    "server requested another NTLM token after mechanism completion",
                ));
            }
            NtlmState::Complete => {
                return Err(AuthError::InvalidState("authentication already finished"));
            }
        };

        let negotiate_flags = NegotiateMessage::decode(&negotiate_message)?.flags;
        let parsed = parse_neg_token_resp(incoming)?;
        validate_ntlm_spnego_response(&parsed)?;
        if matches!(parsed.neg_state, Some(NEG_STATE_REJECT)) {
            return Err(AuthError::InvalidToken("authentication was rejected"));
        }
        let challenge_message = parsed
            .response_token
            .ok_or(AuthError::InvalidToken("SPNEGO response token missing"))?;
        let challenge = ChallengeMessage::decode(&challenge_message)?;
        #[cfg(feature = "dangerous-ntlm-diagnostics")]
        if ntlm_debug_enabled() {
            eprintln!(
                "ntlm type2 flags=0x{:08x} challenge={} len={} av_pairs={} token={}",
                challenge.flags.bits(),
                hex_bytes(&challenge.server_challenge),
                challenge_message.len(),
                av_pairs_debug(&challenge.target_info),
                hex_bytes(&challenge_message)
            );
        }
        let (authenticate, session_key) = build_authenticate_message(
            &self.credentials,
            AuthenticateMessageInput {
                challenge: &challenge,
                negotiate_flags,
                negotiate_message: &negotiate_message,
                challenge_message: &challenge_message,
                client_challenge: self.client_challenge,
                fallback_timestamp: self.timestamp,
                exported_session_key_override: self.exported_session_key_override,
            },
        )?;
        let authenticate_message = authenticate.encode()?;
        #[cfg(feature = "dangerous-ntlm-diagnostics")]
        if ntlm_debug_enabled() {
            eprintln!(
                "ntlm type3 flags=0x{:08x} len={} lm_len={} nt_len={} domain_len={} workstation_len={} token={}",
                authenticate.flags.bits(),
                authenticate_message.len(),
                authenticate.lm_challenge_response.len(),
                authenticate.nt_challenge_response.len(),
                authenticate.domain_name.len(),
                authenticate.workstation.len(),
                hex_bytes(&authenticate_message)
            );
        }
        let token = encode_neg_token_resp_ntlm(&authenticate_message);

        self.session_key = Some(session_key);
        self.state = NtlmState::WaitingForCompletion {
            flags: authenticate.flags,
        };
        Ok(token)
    }

    fn finish(&mut self, incoming: &[u8]) -> Result<(), AuthError> {
        if !matches!(
            self.state,
            NtlmState::WaitingForCompletion { .. } | NtlmState::WaitingForFinalSuccess
        ) {
            return Err(AuthError::InvalidState(
                "NTLM final token received outside the completion state",
            ));
        }

        if incoming.is_empty() {
            self.state = NtlmState::Complete;
            return Ok(());
        }

        let parsed = parse_neg_token_resp(incoming)?;
        validate_ntlm_spnego_response(&parsed)?;
        if parsed.neg_state != Some(NEG_STATE_ACCEPT_COMPLETE) {
            return Err(AuthError::InvalidToken(
                "final NTLM SPNEGO token did not accept authentication",
            ));
        }
        if parsed.response_token.is_some() {
            return Err(AuthError::InvalidToken(
                "final NTLM SPNEGO token carried an unexpected mechanism token",
            ));
        }

        self.state = NtlmState::Complete;
        Ok(())
    }

    fn session_key(&self) -> Option<&[u8]> {
        self.session_key.as_ref().map(|value| value.as_slice())
    }
}

fn validate_ntlm_spnego_response(response: &super::spnego::NegTokenResp) -> Result<(), AuthError> {
    if response
        .supported_mech
        .is_some_and(|mechanism| mechanism != SpnegoMechanism::Ntlm)
    {
        return Err(AuthError::InvalidToken(
            "SPNEGO selected a mechanism other than NTLM",
        ));
    }
    Ok(())
}

impl NegotiateMessage {
    fn encode(&self) -> Vec<u8> {
        let include_version = self.flags.contains(NegotiateFlags::VERSION);
        let payload_offset = if include_version { 40u32 } else { 32u32 };
        let mut out = Vec::with_capacity(payload_offset as usize);
        out.extend_from_slice(NTLMSSP_SIGNATURE);
        out.extend_from_slice(&NTLM_MESSAGE_NEGOTIATE.to_le_bytes());
        out.extend_from_slice(&self.flags.bits().to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        if include_version {
            out.extend_from_slice(&default_version_bytes());
        }
        out
    }

    fn decode(message: &[u8]) -> Result<Self, AuthError> {
        if message.len() < 32 {
            return Err(AuthError::InvalidToken("negotiate message too short"));
        }
        if &message[..8] != NTLMSSP_SIGNATURE {
            return Err(AuthError::InvalidToken("missing NTLMSSP signature"));
        }
        if read_u32(message, 8)? != NTLM_MESSAGE_NEGOTIATE {
            return Err(AuthError::InvalidToken("unexpected NTLM message type"));
        }

        let flags = NegotiateFlags::from_bits(read_u32(message, 12)?)
            .ok_or(AuthError::InvalidToken("unsupported NTLM negotiate flags"))?;
        if flags.contains(NegotiateFlags::VERSION) && message.len() < 40 {
            return Err(AuthError::InvalidToken(
                "negotiate message missing version payload",
            ));
        }

        Ok(Self { flags })
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
        let target_info = encode_target_info(&self.target_info)
            .expect("test challenge target info should encode");
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
    fn encode(&self) -> Result<Vec<u8>, AuthError> {
        let mut offset = 64u32;
        let version = self.version.as_ref();
        if version.is_some() {
            offset = offset.checked_add(8).ok_or(AuthError::InvalidToken(
                "authenticate message length overflowed",
            ))?;
        }
        let mic = self.mic.as_ref();
        if mic.is_some() {
            offset = offset.checked_add(16).ok_or(AuthError::InvalidToken(
                "authenticate message length overflowed",
            ))?;
        }
        let domain_buffer = next_security_buffer(&mut offset, &self.domain_name)?;
        let user_buffer = next_security_buffer(&mut offset, &self.user_name)?;
        let workstation_buffer = next_security_buffer(&mut offset, &self.workstation)?;
        let lm_buffer = next_security_buffer(&mut offset, &self.lm_challenge_response)?;
        let nt_buffer = next_security_buffer(&mut offset, &self.nt_challenge_response)?;
        let session_key_buffer =
            next_security_buffer(&mut offset, &self.encrypted_random_session_key)?;

        let mut out = Vec::new();
        out.try_reserve_exact(offset as usize)
            .map_err(|_| AuthError::InvalidToken("authenticate message allocation failed"))?;
        out.extend_from_slice(NTLMSSP_SIGNATURE);
        out.extend_from_slice(&NTLM_MESSAGE_AUTHENTICATE.to_le_bytes());
        for buffer in [
            &lm_buffer,
            &nt_buffer,
            &domain_buffer,
            &user_buffer,
            &workstation_buffer,
            &session_key_buffer,
        ] {
            out.extend_from_slice(&buffer.len.to_le_bytes());
            out.extend_from_slice(&buffer.len.to_le_bytes());
            out.extend_from_slice(&buffer.offset.to_le_bytes());
        }
        out.extend_from_slice(&self.flags.bits().to_le_bytes());
        if let Some(version) = version {
            out.extend_from_slice(version);
        }
        if let Some(mic) = mic {
            out.extend_from_slice(mic);
        }
        for buffer in [
            &self.domain_name,
            &self.user_name,
            &self.workstation,
            &self.lm_challenge_response,
            &self.nt_challenge_response,
            &self.encrypted_random_session_key,
        ] {
            out.extend_from_slice(buffer);
        }
        Ok(out)
    }

    #[cfg(test)]
    fn decode(message: &[u8]) -> Result<Self, AuthError> {
        if message.len() < 64 {
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
        let payload_offset = [
            lm,
            nt,
            domain,
            user,
            workstation,
            encrypted_random_session_key,
        ]
        .iter()
        .filter(|buffer| !buffer.is_empty())
        .map(|buffer| buffer.as_ptr() as usize - message.as_ptr() as usize)
        .min()
        .unwrap_or(message.len());
        let version = if flags.contains(NegotiateFlags::VERSION) && payload_offset >= 72 {
            Some(read_array::<8>(message, 64)?)
        } else {
            None
        };
        let mic_offset = if version.is_some() { 72 } else { 64 };
        let mic = if payload_offset >= mic_offset + 16 {
            Some(read_array::<16>(message, mic_offset)?)
        } else {
            None
        };

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

struct AuthenticateMessageInput<'a> {
    challenge: &'a ChallengeMessage,
    negotiate_flags: NegotiateFlags,
    negotiate_message: &'a [u8],
    challenge_message: &'a [u8],
    client_challenge: [u8; 8],
    fallback_timestamp: u64,
    exported_session_key_override: Option<[u8; 16]>,
}

fn build_authenticate_message(
    credentials: &NtlmCredentials,
    input: AuthenticateMessageInput<'_>,
) -> Result<(AuthenticateMessage, [u8; 16]), AuthError> {
    let AuthenticateMessageInput {
        challenge,
        negotiate_flags,
        negotiate_message,
        challenge_message,
        client_challenge,
        fallback_timestamp,
        exported_session_key_override,
    } = input;
    let negotiated_flags = authenticate_flags(negotiate_flags, challenge.flags);
    let target_info = ntlmv2_target_info(&challenge.target_info, fallback_timestamp)?;
    let timestamp = target_info_timestamp(&target_info).unwrap_or(fallback_timestamp);

    let response_key_nt = Zeroizing::new(ntowfv2(credentials));
    let nt_response = ntlmv2_response(
        &response_key_nt,
        challenge.server_challenge,
        client_challenge,
        timestamp,
        &target_info,
    )?;
    let key_exchange_key = Zeroizing::new(hmac_md5(response_key_nt.as_slice(), &nt_response[..16]));
    let (encrypted_random_session_key, session_key) = encrypt_random_session_key(
        negotiated_flags,
        *key_exchange_key,
        exported_session_key_override,
    );
    let lm_challenge_response = lmv2_response(
        &response_key_nt,
        challenge.server_challenge,
        client_challenge,
    )?;

    let include_mic = target_info_requires_mic(&challenge.target_info)?;
    let mut authenticate = AuthenticateMessage {
        lm_challenge_response,
        nt_challenge_response: nt_response,
        domain_name: utf16le(&credentials.domain),
        user_name: utf16le(&credentials.username),
        workstation: utf16le(&credentials.workstation),
        encrypted_random_session_key,
        flags: negotiated_flags,
        version: None,
        mic: include_mic.then_some([0; 16]),
    };
    if include_mic {
        let zero_mic_type3 = authenticate.encode()?;
        authenticate.mic = Some(hmac_md5_concat(
            &session_key,
            &[negotiate_message, challenge_message, &zero_mic_type3],
        ));
    }

    Ok((authenticate, session_key))
}

fn authenticate_flags(
    client_flags: NegotiateFlags,
    challenge_flags: NegotiateFlags,
) -> NegotiateFlags {
    let mut flags = client_flags;
    for capability in [
        NegotiateFlags::EXTENDED_SESSIONSECURITY,
        NegotiateFlags::_128,
        NegotiateFlags::KEY_EXCH,
        NegotiateFlags::SEAL,
        NegotiateFlags::SIGN,
        NegotiateFlags::ALWAYS_SIGN,
    ] {
        if !challenge_flags.contains(capability) {
            flags.remove(capability);
        }
    }
    flags.remove(NegotiateFlags::VERSION);
    flags
}

fn default_version_bytes() -> [u8; 8] {
    [6, 1, 0, 0, 0, 0, 0, 0x0f]
}

fn encrypt_random_session_key(
    flags: NegotiateFlags,
    key_exchange_key: [u8; 16],
    exported_session_key_override: Option<[u8; 16]>,
) -> (Vec<u8>, [u8; 16]) {
    if flags.contains(NegotiateFlags::KEY_EXCH) {
        let exported_session_key = exported_session_key_override.unwrap_or_else(random);
        (
            rc4k(&key_exchange_key, &exported_session_key),
            exported_session_key,
        )
    } else {
        (Vec::new(), key_exchange_key)
    }
}

fn mech_list_mic(exported_session_key: [u8; 16], flags: NegotiateFlags) -> [u8; 16] {
    ntlm_message_signature(
        exported_session_key,
        flags,
        &encode_mech_type_list(&[SpnegoMechanism::Ntlm]),
    )
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
    let nt_hash = Zeroizing::new(nt_hash(&credentials.password));
    let identity = utf16le(&(credentials.username.to_uppercase() + &credentials.domain));
    hmac_md5(nt_hash.as_slice(), &identity)
}

fn nt_hash(password: &str) -> [u8; 16] {
    let mut md4 = Md4::new();
    let encoded_password = Zeroizing::new(utf16le(password));
    md4.update(encoded_password.as_slice());
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
) -> Result<Vec<u8>, AuthError> {
    let encoded_target_info = encode_target_info(target_info)?;
    let blob_capacity = 28usize
        .checked_add(encoded_target_info.len())
        .ok_or(AuthError::InvalidToken("NTLMv2 response length overflowed"))?;
    let mut blob = Vec::new();
    blob.try_reserve_exact(blob_capacity)
        .map_err(|_| AuthError::InvalidToken("NTLMv2 response allocation failed"))?;
    blob.extend_from_slice(&0x0000_0101u32.to_le_bytes());
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&timestamp.to_le_bytes());
    blob.extend_from_slice(&client_challenge);
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&encoded_target_info);

    let proof_capacity = 8usize
        .checked_add(blob.len())
        .ok_or(AuthError::InvalidToken("NTLMv2 proof length overflowed"))?;
    let mut proof_input = Vec::new();
    proof_input
        .try_reserve_exact(proof_capacity)
        .map_err(|_| AuthError::InvalidToken("NTLMv2 proof allocation failed"))?;
    proof_input.extend_from_slice(&server_challenge);
    proof_input.extend_from_slice(&blob);
    let nt_proof = hmac_md5(response_key_nt, &proof_input);

    let response_capacity = 16usize
        .checked_add(blob.len())
        .ok_or(AuthError::InvalidToken("NTLMv2 response length overflowed"))?;
    let mut response = Vec::new();
    response
        .try_reserve_exact(response_capacity)
        .map_err(|_| AuthError::InvalidToken("NTLMv2 response allocation failed"))?;
    response.extend_from_slice(&nt_proof);
    response.extend_from_slice(&blob);
    Ok(response)
}

fn lmv2_response(
    response_key_lm: &[u8; 16],
    server_challenge: [u8; 8],
    client_challenge: [u8; 8],
) -> Result<Vec<u8>, AuthError> {
    let mut input = Vec::new();
    input
        .try_reserve_exact(16)
        .map_err(|_| AuthError::InvalidToken("LMv2 proof allocation failed"))?;
    input.extend_from_slice(&server_challenge);
    input.extend_from_slice(&client_challenge);

    let mut response = Vec::new();
    response
        .try_reserve_exact(24)
        .map_err(|_| AuthError::InvalidToken("LMv2 response allocation failed"))?;
    response.extend_from_slice(&hmac_md5(response_key_lm, &input));
    response.extend_from_slice(&client_challenge);
    Ok(response)
}

fn encode_target_info(target_info: &[AvPair]) -> Result<Vec<u8>, AuthError> {
    let mut encoded_len = 4usize;
    for pair in target_info {
        if pair.value.len() > usize::from(u16::MAX) {
            return Err(AuthError::InvalidToken(
                "NTLM target-info AV pair was too large",
            ));
        }
        encoded_len = encoded_len
            .checked_add(4)
            .and_then(|length| length.checked_add(pair.value.len()))
            .ok_or(AuthError::InvalidToken(
                "NTLM target-info length overflowed",
            ))?;
    }
    if encoded_len > MAX_NTLM_TARGET_INFO_SIZE {
        return Err(AuthError::InvalidToken(
            "NTLM target info exceeded the configured maximum",
        ));
    }

    let mut out = Vec::new();
    out.try_reserve_exact(encoded_len)
        .map_err(|_| AuthError::InvalidToken("NTLM target-info allocation failed"))?;
    for pair in target_info {
        out.extend_from_slice(&pair.av_id.0.to_le_bytes());
        out.extend_from_slice(&(pair.value.len() as u16).to_le_bytes());
        out.extend_from_slice(&pair.value);
    }
    out.extend_from_slice(&AvId::EOL.0.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    Ok(out)
}

fn ntlmv2_target_info(
    target_info: &[AvPair],
    fallback_timestamp: u64,
) -> Result<Vec<AvPair>, AuthError> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(target_info.len().saturating_add(2))
        .map_err(|_| AuthError::InvalidToken("NTLM target-info allocation failed"))?;
    for pair in target_info {
        output.push(AvPair {
            av_id: pair.av_id,
            value: copy_ntlm_bytes(&pair.value)?,
        });
    }
    if target_info_timestamp(&output).is_none() {
        upsert_av_pair(
            &mut output,
            AvId::TIMESTAMP,
            fallback_timestamp.to_le_bytes().to_vec(),
        )?;
    }
    if let Some(dns_host) = output
        .iter()
        .find(|pair| pair.av_id == AvId::DNS_COMPUTER_NAME)
        .map(|pair| copy_ntlm_bytes(&pair.value))
        .transpose()?
    {
        let mut target_name = utf16le("cifs/");
        target_name
            .try_reserve(dns_host.len())
            .map_err(|_| AuthError::InvalidToken("NTLM target-name allocation failed"))?;
        target_name.extend_from_slice(&dns_host);
        upsert_av_pair(&mut output, AvId::TARGET_NAME, target_name)?;
    }
    Ok(output)
}

fn parse_target_info(bytes: &[u8]) -> Result<Vec<AvPair>, AuthError> {
    if bytes.len() > MAX_NTLM_TARGET_INFO_SIZE {
        return Err(AuthError::InvalidToken(
            "NTLM target info exceeded the configured maximum",
        ));
    }
    let mut offset = 0;
    let mut pairs = Vec::new();

    while bytes.len().saturating_sub(offset) >= 4 {
        let av_id = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        let len = usize::from(u16::from_le_bytes([bytes[offset + 2], bytes[offset + 3]]));
        offset += 4;
        if av_id == AvId::EOL.0 {
            if len != 0 || offset != bytes.len() {
                return Err(AuthError::InvalidToken(
                    "target info terminator was malformed or not final",
                ));
            }
            return Ok(pairs);
        }
        if pairs.iter().any(|pair: &AvPair| pair.av_id.0 == av_id) {
            return Err(AuthError::InvalidToken(
                "target info contained a duplicate AV identifier",
            ));
        }
        let end = offset
            .checked_add(len)
            .ok_or(AuthError::InvalidToken("target info length overflowed"))?;
        if end > bytes.len() {
            return Err(AuthError::InvalidToken("truncated target info"));
        }
        let mut value = Vec::new();
        value
            .try_reserve_exact(len)
            .map_err(|_| AuthError::InvalidToken("target info allocation failed"))?;
        value.extend_from_slice(&bytes[offset..end]);
        offset = end;

        pairs
            .try_reserve(1)
            .map_err(|_| AuthError::InvalidToken("target info allocation failed"))?;
        pairs.push(AvPair {
            av_id: AvId(av_id),
            value,
        });
    }

    Err(AuthError::InvalidToken("target info missing terminator"))
}

fn upsert_av_pair(
    target_info: &mut Vec<AvPair>,
    av_id: AvId,
    value: Vec<u8>,
) -> Result<(), AuthError> {
    if let Some(pair) = target_info.iter_mut().find(|pair| pair.av_id == av_id) {
        pair.value = value;
        return Ok(());
    }
    target_info
        .try_reserve(1)
        .map_err(|_| AuthError::InvalidToken("NTLM target-info allocation failed"))?;
    target_info.push(AvPair { av_id, value });
    Ok(())
}

fn copy_ntlm_bytes(bytes: &[u8]) -> Result<Vec<u8>, AuthError> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(bytes.len())
        .map_err(|_| AuthError::InvalidToken("NTLM token allocation failed"))?;
    output.extend_from_slice(bytes);
    Ok(output)
}

fn target_info_requires_mic(target_info: &[AvPair]) -> Result<bool, AuthError> {
    let Some(flags) = target_info.iter().find(|pair| pair.av_id == AvId::FLAGS) else {
        return Ok(false);
    };
    let bytes: [u8; 4] = flags
        .value
        .as_slice()
        .try_into()
        .map_err(|_| AuthError::InvalidToken("MsvAvFlags must contain one u32"))?;
    Ok(u32::from_le_bytes(bytes) & MSV_AV_FLAGS_MIC_PRESENT != 0)
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

fn next_security_buffer(offset: &mut u32, buffer: &[u8]) -> Result<SecurityBuffer, AuthError> {
    let len = u16::try_from(buffer.len())
        .map_err(|_| AuthError::InvalidToken("NTLM security buffer exceeded u16"))?;
    let current = SecurityBuffer {
        len,
        offset: *offset,
    };
    *offset = offset
        .checked_add(u32::from(len))
        .ok_or(AuthError::InvalidToken(
            "NTLM security buffer offset overflowed",
        ))?;
    Ok(current)
}

fn read_security_buffer(message: &[u8], offset: usize) -> Result<Option<&[u8]>, AuthError> {
    let len = usize::from(read_u16(message, offset)?);
    let data_offset = usize::try_from(read_u32(message, offset + 4)?)
        .map_err(|_| AuthError::InvalidToken("invalid security buffer offset"))?;
    if len == 0 {
        return Ok(None);
    }
    let end = data_offset
        .checked_add(len)
        .ok_or(AuthError::InvalidToken("security buffer offset overflowed"))?;
    if end > message.len() {
        return Err(AuthError::InvalidToken(
            "security buffer points past message",
        ));
    }
    Ok(Some(&message[data_offset..end]))
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

#[cfg(feature = "dangerous-ntlm-diagnostics")]
fn ntlm_debug_enabled() -> bool {
    std::env::var("SMOLDER_NTLM_DEBUG").as_deref() == Ok("UNSAFE_RAW_TOKENS")
}

#[cfg(feature = "dangerous-ntlm-diagnostics")]
fn av_pairs_debug(target_info: &[AvPair]) -> String {
    target_info
        .iter()
        .map(|pair| format!("0x{:04x}:{}", pair.av_id.0, pair.value.len()))
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(any(test, feature = "dangerous-ntlm-diagnostics"))]
fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(nibble_to_hex(byte >> 4));
        out.push(nibble_to_hex(byte & 0x0f));
    }
    out
}

#[cfg(any(test, feature = "dangerous-ntlm-diagnostics"))]
fn nibble_to_hex(value: u8) -> char {
    match value {
        0..=9 => char::from(b'0' + value),
        10..=15 => char::from(b'a' + (value - 10)),
        _ => unreachable!("hex nibble must be in range"),
    }
}

#[cfg(test)]
mod tests {
    use smolder_proto::smb::smb2::{Dialect, GlobalCapabilities, NegotiateResponse, SigningMode};

    use super::super::spnego::{
        encode_neg_token_resp, encode_neg_token_resp_ntlm, extract_mech_token,
        parse_neg_token_init, parse_neg_token_resp, NEG_STATE_ACCEPT_COMPLETE, NEG_STATE_REJECT,
    };
    use super::{
        build_authenticate_message, current_windows_timestamp, hex_bytes, nt_hash,
        parse_target_info, target_info_timestamp, AuthProvider, AuthenticateMessage,
        AuthenticateMessageInput, AvId, AvPair, ChallengeMessage, NegotiateFlags, NegotiateMessage,
        NtlmAuthenticator, NtlmCredentials, MSV_AV_FLAGS_MIC_PRESENT,
    };
    use crate::auth::{AuthError, SpnegoMechanism};

    #[test]
    fn credential_and_authenticator_debug_redact_passwords_and_keys() {
        const SECRET: &str = "AUDIT-SUPER-SECRET";
        let credentials = NtlmCredentials::new("alice", SECRET)
            .with_domain("EXAMPLE")
            .with_workstation("CLIENT1");
        let credential_debug = format!("{credentials:?}");
        assert!(!credential_debug.contains(SECRET));
        assert!(credential_debug.contains("<redacted>"));

        let authenticator_debug = format!("{:?}", NtlmAuthenticator::new(credentials));
        assert!(!authenticator_debug.contains(SECRET));
        assert!(authenticator_debug.contains("<redacted>"));
    }

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
    fn authenticator_initial_token_matches_impacket_smb3_flag_profile() {
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
        let init = parse_neg_token_init(&initial).expect("SPNEGO token should parse");
        assert_eq!(init.mech_types, vec![SpnegoMechanism::Ntlm]);
        let negotiate = extract_mech_token(&initial).expect("should extract NTLM token");
        assert_eq!(
            hex_bytes(&negotiate),
            "4e544c4d5353500001000000358288e000000000000000000000000000000000"
        );
        let negotiate = NegotiateMessage::decode(&negotiate).expect("type1 should decode");

        assert_eq!(
            negotiate.flags,
            NegotiateFlags::UNICODE
                | NegotiateFlags::REQUEST_TARGET
                | NegotiateFlags::SIGN
                | NegotiateFlags::SEAL
                | NegotiateFlags::NTLM
                | NegotiateFlags::ALWAYS_SIGN
                | NegotiateFlags::EXTENDED_SESSIONSECURITY
                | NegotiateFlags::TARGET_INFO
                | NegotiateFlags::_128
                | NegotiateFlags::KEY_EXCH
                | NegotiateFlags::_56
        );
        assert_eq!(negotiate_message_len(&negotiate), 32);
    }

    #[test]
    fn authenticator_builds_impacket_compatible_type3_message() {
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
                | NegotiateFlags::REQUEST_TARGET
                | NegotiateFlags::NTLM
                | NegotiateFlags::SIGN
                | NegotiateFlags::SEAL
                | NegotiateFlags::ALWAYS_SIGN
                | NegotiateFlags::EXTENDED_SESSIONSECURITY
                | NegotiateFlags::TARGET_INFO
                | NegotiateFlags::VERSION
                | NegotiateFlags::_128
                | NegotiateFlags::KEY_EXCH
                | NegotiateFlags::_56,
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
                    av_id: AvId::DNS_COMPUTER_NAME,
                    value: smolder_proto::smb::smb2::utf16le("server.example"),
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
        assert_eq!(authenticate.flags, auth.negotiate_flags());
        assert_eq!(authenticate.lm_challenge_response.len(), 24);
        assert_ne!(authenticate.lm_challenge_response, vec![0; 24]);
        assert!(!authenticate.nt_challenge_response.is_empty());
        assert_eq!(
            &authenticate.nt_challenge_response[16..24],
            &[0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(authenticate.encrypted_random_session_key.len(), 16);
        assert_eq!(authenticate.version, None);
        assert_eq!(authenticate.mic, None);
        let ntlmv2_target_info =
            parse_target_info(&authenticate.nt_challenge_response[44..]).expect("target info");
        assert_eq!(target_info_timestamp(&ntlmv2_target_info), Some(9_999));
        assert_eq!(
            ntlmv2_target_info
                .iter()
                .find(|pair| pair.av_id == AvId::TARGET_NAME)
                .map(|pair| pair.value.clone()),
            Some(smolder_proto::smb::smb2::utf16le("cifs/server.example"))
        );
        assert!(auth.session_key().is_some());
    }

    #[test]
    fn target_info_rejects_duplicate_mic_flags_and_trailing_terminator_data() {
        let duplicate_flags = [
            AvId::FLAGS.0.to_le_bytes().as_slice(),
            4_u16.to_le_bytes().as_slice(),
            MSV_AV_FLAGS_MIC_PRESENT.to_le_bytes().as_slice(),
            AvId::FLAGS.0.to_le_bytes().as_slice(),
            4_u16.to_le_bytes().as_slice(),
            0_u32.to_le_bytes().as_slice(),
            AvId::EOL.0.to_le_bytes().as_slice(),
            0_u16.to_le_bytes().as_slice(),
        ]
        .concat();
        assert!(parse_target_info(&duplicate_flags).is_err());

        let trailing = [
            AvId::EOL.0.to_le_bytes().as_slice(),
            0_u16.to_le_bytes().as_slice(),
            &[0_u8; 4],
        ]
        .concat();
        assert!(parse_target_info(&trailing).is_err());
    }

    #[test]
    fn authenticate_mic_binds_exact_type1_type2_and_zero_mic_type3() {
        let credentials = NtlmCredentials::new("alice", "password").with_domain("DOMAIN");
        let negotiate = NegotiateMessage {
            flags: NegotiateFlags::UNICODE
                | NegotiateFlags::REQUEST_TARGET
                | NegotiateFlags::SIGN
                | NegotiateFlags::SEAL
                | NegotiateFlags::NTLM
                | NegotiateFlags::ALWAYS_SIGN
                | NegotiateFlags::EXTENDED_SESSIONSECURITY
                | NegotiateFlags::TARGET_INFO
                | NegotiateFlags::_128
                | NegotiateFlags::KEY_EXCH
                | NegotiateFlags::_56,
        };
        let negotiate_bytes = negotiate.encode();
        let challenge = ChallengeMessage {
            flags: negotiate.flags,
            server_challenge: *b"SRVCHALL",
            target_info: vec![
                AvPair {
                    av_id: AvId::FLAGS,
                    value: MSV_AV_FLAGS_MIC_PRESENT.to_le_bytes().to_vec(),
                },
                AvPair {
                    av_id: AvId::TIMESTAMP,
                    value: 123_456u64.to_le_bytes().to_vec(),
                },
            ],
        };
        let challenge_bytes = challenge.encode_for_test();
        let (authenticate, session_key) = build_authenticate_message(
            &credentials,
            AuthenticateMessageInput {
                challenge: &challenge,
                negotiate_flags: negotiate.flags,
                negotiate_message: &negotiate_bytes,
                challenge_message: &challenge_bytes,
                client_challenge: *b"CLICHALL",
                fallback_timestamp: 123_456,
                exported_session_key_override: Some([0x55; 16]),
            },
        )
        .expect("MIC-bearing authenticate message should build");

        assert_eq!(session_key, [0x55; 16]);
        assert_eq!(
            hex_bytes(&authenticate.mic.expect("MIC should be present")),
            "cdf8689a90083d11b6225b003b8fa26f"
        );
        let encoded = authenticate.encode().expect("type3 message should encode");
        let decoded = AuthenticateMessage::decode(&encoded).expect("type3 should decode");
        assert_eq!(decoded.mic, authenticate.mic);
    }

    #[test]
    fn authenticator_matches_impacket_on_windows_key_exchange_challenge() {
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
        let mut auth = NtlmAuthenticator::new(NtlmCredentials::new("testuser", "testpass"))
            .with_client_challenge(*b"A1B2C3D4")
            .with_timestamp(0)
            .with_exported_session_key(*b"E5F6G7H8J9K0L1M2");

        let initial = auth
            .initial_token(&negotiate)
            .expect("initial token should build");
        let type1 = extract_mech_token(&initial).expect("should extract NTLM token");
        assert_eq!(
            hex_bytes(&type1),
            "4e544c4d5353500001000000358288e000000000000000000000000000000000"
        );

        let challenge = hex_decode(
            "4e544c4d53535000020000001e001e003800000035828ae2764ed429d9c4d848\
             000000000000000098009800560000000a00f4650000000f4400450053004b00\
             54004f0050002d00500054004e004a0055005300350002001e00440045005300\
             4b0054004f0050002d00500054004e004a0055005300350001001e0044004500\
             53004b0054004f0050002d00500054004e004a0055005300350004001e004400\
             450053004b0054004f0050002d00500054004e004a0055005300350003001e00\
             4400450053004b0054004f0050002d00500054004e004a005500530035000700\
             0800a2cd625d3abddc0100000000",
        );

        let response = auth
            .next_token(&encode_neg_token_resp_ntlm(&challenge))
            .expect("challenge response should build");
        let type3 = extract_mech_token(&response).expect("should extract NTLM token");

        assert_eq!(
            hex_bytes(&type3),
            "4e544c4d53535000030000001800180050000000f000f0006800000000000000\
             40000000100010004000000000000000500000001000100058010000358288e0\
             74006500730074007500730065007200f82632d3054326f5c701c2f8f7ed7ae0\
             4131423243334434a32f6188d4745a74f0396860fd18c5a60101000000000000\
             a2cd625d3abddc0141314232433344340000000002001e004400450053004b00\
             54004f0050002d00500054004e004a0055005300350001001e00440045005300\
             4b0054004f0050002d00500054004e004a0055005300350004001e0044004500\
             53004b0054004f0050002d00500054004e004a0055005300350003001e004400\
             450053004b0054004f0050002d00500054004e004a0055005300350007000800\
             a2cd625d3abddc010900280063006900660073002f004400450053004b005400\
             4f0050002d00500054004e004a00550053003500000000008ebc1e1cc3a2c134\
             2f6d1c5dcefea0be"
                .replace(char::is_whitespace, "")
        );
        assert_eq!(auth.session_key(), Some(&b"E5F6G7H8J9K0L1M2"[..]));
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
        let mut rejecting_auth = auth.clone();
        let final_token = auth
            .next_token(&final_spnego)
            .expect("final leg should be acknowledged");

        let parsed = parse_neg_token_resp(&final_token).expect("completion token should parse");
        assert_eq!(parsed.neg_state, Some(NEG_STATE_ACCEPT_COMPLETE));
        assert_eq!(parsed.response_token, None);
        assert_eq!(parsed.mech_list_mic.as_ref().map(Vec::len), Some(16));
        auth.finish(&[])
            .expect("empty final SMB success token should complete NTLM");

        rejecting_auth
            .next_token(&final_spnego)
            .expect("comparison flow should reach final success state");
        let rejection = encode_neg_token_resp(Some(NEG_STATE_REJECT), None, None);
        let error = rejecting_auth
            .finish(&rejection)
            .expect_err("a final SPNEGO reject token must fail authentication");
        assert!(matches!(error, AuthError::InvalidToken(_)));
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

    fn negotiate_message_len(negotiate: &NegotiateMessage) -> usize {
        negotiate.encode().len()
    }

    fn hex_decode(input: &str) -> Vec<u8> {
        let hex = input
            .chars()
            .filter(|ch| !ch.is_ascii_whitespace())
            .collect::<String>();
        assert_eq!(hex.len() % 2, 0, "hex input must have an even length");

        hex.as_bytes()
            .chunks_exact(2)
            .map(|chunk| (hex_nibble(chunk[0]) << 4) | hex_nibble(chunk[1]))
            .collect()
    }

    fn hex_nibble(value: u8) -> u8 {
        match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => 10 + (value - b'a'),
            b'A'..=b'F' => 10 + (value - b'A'),
            _ => panic!("invalid hex nibble: {value:#x}"),
        }
    }
}
