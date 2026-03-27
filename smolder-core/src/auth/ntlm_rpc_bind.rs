//! NTLM secure-bind helpers for connection-oriented DCE/RPC.

use smolder_proto::rpc::{AuthLevel, AuthType, AuthVerifier, BindAckPdu, PacketFlags, RpcAuth3Pdu};
use smolder_proto::smb::smb2::{Dialect, GlobalCapabilities, NegotiateResponse, SigningMode};

use crate::error::CoreError;

use super::spnego::{encode_neg_token_resp_ntlm, extract_mech_token, parse_neg_token_resp};
use super::{
    AuthProvider, NtlmAuthenticator, NtlmCredentials, NtlmRpcPacketIntegrity, NtlmSessionSecurity,
};

const NTLMSSP_SIGNATURE: &[u8; 8] = b"NTLMSSP\0";
const NTLM_MESSAGE_AUTHENTICATE: u32 = 3;
const NTLM_NEGOTIATE_SIGN: u32 = 0x0000_0010;
const NTLM_NEGOTIATE_SEAL: u32 = 0x0000_0020;
const NTLM_NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;
const NTLM_NEGOTIATE_128: u32 = 0x2000_0000;
const NTLM_NEGOTIATE_KEY_EXCH: u32 = 0x4000_0000;
const NTLM_NEGOTIATE_56: u32 = 0x8000_0000;
const NTLM_RPC_AUTH_CONTEXT_OFFSET: u32 = 79_231;

#[derive(Debug)]
pub(crate) struct NtlmRpcBindHandshake {
    ntlm: NtlmAuthenticator,
    auth_level: AuthLevel,
    auth_context_id: u32,
}

#[derive(Debug)]
pub(crate) struct NtlmRpcBindComplete {
    pub(crate) auth3: RpcAuth3Pdu,
    pub(crate) packet_integrity: Option<NtlmRpcPacketIntegrity>,
}

impl NtlmRpcBindHandshake {
    pub(crate) fn new(
        credentials: NtlmCredentials,
        auth_level: AuthLevel,
        context_id: u16,
    ) -> Result<Self, CoreError> {
        match auth_level {
            AuthLevel::Connect | AuthLevel::PacketIntegrity => {}
            AuthLevel::PacketPrivacy => {
                return Err(CoreError::Unsupported(
                    "NTLM RPC packet privacy is not implemented yet",
                ));
            }
            _ => {
                return Err(CoreError::InvalidInput(
                    "NTLM RPC secure bind requires auth level Connect or PacketIntegrity",
                ));
            }
        }

        Ok(Self {
            ntlm: NtlmAuthenticator::new(credentials),
            auth_level,
            auth_context_id: u32::from(context_id) + NTLM_RPC_AUTH_CONTEXT_OFFSET,
        })
    }

    pub(crate) fn bind_flags(&self) -> PacketFlags {
        PacketFlags::FIRST_FRAGMENT | PacketFlags::LAST_FRAGMENT
    }

    pub(crate) fn initial_auth_verifier(&mut self) -> Result<AuthVerifier, CoreError> {
        let initial_token = self.ntlm.initial_token(&dummy_negotiate_response())?;
        let ntlm_type1 = extract_mech_token(&initial_token)?;
        Ok(AuthVerifier::new(
            AuthType::WinNt,
            self.auth_level,
            self.auth_context_id,
            ntlm_type1,
        ))
    }

    pub(crate) fn complete(
        &mut self,
        bind_ack: &BindAckPdu,
    ) -> Result<NtlmRpcBindComplete, CoreError> {
        let challenge = bind_ack
            .auth_verifier
            .as_ref()
            .ok_or(CoreError::InvalidResponse(
                "expected NTLM auth verifier in rpc bind ack",
            ))?;
        if challenge.auth_type != AuthType::WinNt {
            return Err(CoreError::InvalidResponse(
                "rpc bind ack used an unexpected authentication type",
            ));
        }
        if challenge.auth_level != self.auth_level {
            return Err(CoreError::InvalidResponse(
                "rpc bind ack used an unexpected authentication level",
            ));
        }
        if challenge.auth_context_id != self.auth_context_id {
            return Err(CoreError::InvalidResponse(
                "rpc bind ack auth context id did not match the NTLM bind context",
            ));
        }

        let spnego_challenge = encode_neg_token_resp_ntlm(&challenge.auth_value);
        let response_token = self.ntlm.next_token(&spnego_challenge)?;
        let response_token = parse_neg_token_resp(&response_token)?
            .response_token
            .ok_or(CoreError::InvalidResponse(
                "NTLM secure bind did not produce a type3 response token",
            ))?;
        self.ntlm.finish(&[])?;

        let packet_integrity = if self.auth_level == AuthLevel::PacketIntegrity {
            let session_key = self.ntlm.session_key().ok_or(CoreError::InvalidResponse(
                "NTLM secure bind did not establish a session key",
            ))?;
            let security = session_security_from_authenticate(&response_token)?;
            Some(NtlmRpcPacketIntegrity::with_header_signing(
                session_key,
                security,
                self.auth_context_id,
                bind_ack.flags.contains(PacketFlags::SUPPORT_HEADER_SIGN),
            )?)
        } else {
            None
        };

        Ok(NtlmRpcBindComplete {
            auth3: RpcAuth3Pdu {
                call_id: bind_ack.call_id,
                flags: PacketFlags::FIRST_FRAGMENT | PacketFlags::LAST_FRAGMENT,
                pad: *b"    ",
                auth_verifier: AuthVerifier::new(
                    AuthType::WinNt,
                    self.auth_level,
                    self.auth_context_id,
                    response_token,
                ),
            },
            packet_integrity,
        })
    }
}

fn session_security_from_authenticate(token: &[u8]) -> Result<NtlmSessionSecurity, CoreError> {
    if token.len() < 64 || &token[..8] != NTLMSSP_SIGNATURE {
        return Err(CoreError::InvalidResponse(
            "NTLM authenticate token was malformed",
        ));
    }

    let message_type = read_u32(token, 8)?;
    if message_type != NTLM_MESSAGE_AUTHENTICATE {
        return Err(CoreError::InvalidResponse(
            "expected NTLM authenticate token during rpc auth3",
        ));
    }

    let flags = read_u32(token, 60)?;
    let security = NtlmSessionSecurity::new(
        flags & NTLM_NEGOTIATE_EXTENDED_SESSIONSECURITY != 0,
        flags & NTLM_NEGOTIATE_KEY_EXCH != 0,
        flags & NTLM_NEGOTIATE_128 != 0,
        flags & NTLM_NEGOTIATE_56 != 0,
    );
    if !security.extended_session_security
        || flags & NTLM_NEGOTIATE_SIGN == 0
        || flags & NTLM_NEGOTIATE_SEAL == 0
    {
        return Err(CoreError::Unsupported(
            "NTLM RPC secure bind requires sign, seal, and extended session security",
        ));
    }
    Ok(security)
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, CoreError> {
    let end = offset.checked_add(4).ok_or(CoreError::InvalidResponse(
        "integer overflow while parsing NTLM token",
    ))?;
    let slice = bytes.get(offset..end).ok_or(CoreError::InvalidResponse(
        "short NTLM token while reading u32",
    ))?;
    Ok(u32::from_le_bytes(
        slice.try_into().expect("slice length is fixed"),
    ))
}

fn dummy_negotiate_response() -> NegotiateResponse {
    NegotiateResponse {
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
    }
}

#[cfg(test)]
mod tests {
    use smolder_proto::rpc::{
        AuthLevel, AuthType, AuthVerifier, BindAckPdu, BindAckResult, Packet, PacketFlags,
        SyntaxId, Uuid,
    };
    use smolder_proto::smb::smb2::utf16le;

    use super::{session_security_from_authenticate, NtlmRpcBindHandshake};
    use crate::auth::NtlmCredentials;

    const SVCCTL_SYNTAX: SyntaxId = SyntaxId::new(
        Uuid::new(
            0x367a_bb81,
            0x9844,
            0x35f1,
            [0xad, 0x32, 0x98, 0xf0, 0x38, 0x00, 0x10, 0x03],
        ),
        2,
        0,
    );

    #[test]
    fn initial_auth_verifier_contains_raw_ntlm_type1() {
        let mut handshake = NtlmRpcBindHandshake::new(
            NtlmCredentials::new("alice", "password"),
            AuthLevel::Connect,
            0,
        )
        .expect("handshake");

        let verifier = handshake
            .initial_auth_verifier()
            .expect("type1 verifier should build");

        assert_eq!(verifier.auth_type, AuthType::WinNt);
        assert_eq!(verifier.auth_level, AuthLevel::Connect);
        assert_eq!(&verifier.auth_value[..8], b"NTLMSSP\0");
        assert_eq!(
            u32::from_le_bytes(verifier.auth_value[8..12].try_into().unwrap()),
            1
        );
    }

    #[test]
    fn connect_auth3_matches_impacket_bytes_without_key_exchange() {
        let mut handshake = NtlmRpcBindHandshake::new(
            NtlmCredentials::new("testuser", "testpass"),
            AuthLevel::Connect,
            0,
        )
        .expect("handshake");
        handshake.ntlm = handshake
            .ntlm
            .with_client_challenge(*b"A1B2C3D4")
            .with_timestamp(9_999);

        let type1 = handshake
            .initial_auth_verifier()
            .expect("type1 verifier should build");
        assert_eq!(
            hex_bytes(&type1.auth_value),
            "4e544c4d5353500001000000358288e000000000000000000000000000000000"
        );

        let bind_ack = BindAckPdu {
            call_id: 1,
            flags: PacketFlags::FIRST_FRAGMENT | PacketFlags::LAST_FRAGMENT,
            max_xmit_frag: 4280,
            max_recv_frag: 4280,
            assoc_group_id: 0,
            secondary_address: b"\\PIPE\\svcctl\0".to_vec(),
            result: BindAckResult {
                result: 0,
                reason: 0,
                transfer_syntax: SVCCTL_SYNTAX,
            },
            auth_verifier: Some(AuthVerifier::new(
                AuthType::WinNt,
                AuthLevel::Connect,
                type1.auth_context_id,
                encode_connect_challenge_message_without_key_exchange(),
            )),
        };

        let completed = handshake.complete(&bind_ack).expect("auth3 should build");
        assert_eq!(
            hex_bytes(&completed.auth3.auth_verifier.auth_value),
            "4e544c4d53535000030000001800180050000000a600a60068000000000000004000000010001000400000000000000050000000000000000e010000358288a0740065007300740075007300650072008be9cfe55b19d0e218e9cecb3dd7759b4131423243334434bba2050e465f11f4d9d3f19eb3230b2001010000000000000f2700000000000041314232433344340000000001000c0053004500520056004500520002000c0044004f004d00410049004e0003001c007300650072007600650072002e006500780061006d0070006c006500070008000f270000000000000900260063006900660073002f007300650072007600650072002e006500780061006d0070006c00650000000000"
        );
        assert_eq!(
            hex_bytes(&Packet::RpcAuth3(completed.auth3).encode()),
            "05001003100000002a010e0101000000202020200a0200007f3501004e544c4d53535000030000001800180050000000a600a60068000000000000004000000010001000400000000000000050000000000000000e010000358288a0740065007300740075007300650072008be9cfe55b19d0e218e9cecb3dd7759b4131423243334434bba2050e465f11f4d9d3f19eb3230b2001010000000000000f2700000000000041314232433344340000000001000c0053004500520056004500520002000c0044004f004d00410049004e0003001c007300650072007600650072002e006500780061006d0070006c006500070008000f270000000000000900260063006900660073002f007300650072007600650072002e006500780061006d0070006c00650000000000"
        );
    }

    #[test]
    fn complete_builds_auth3_and_packet_integrity_state() {
        let mut handshake = NtlmRpcBindHandshake::new(
            NtlmCredentials::new("alice", "password")
                .with_domain("DOMAIN")
                .with_workstation("WORKSTATION"),
            AuthLevel::PacketIntegrity,
            0,
        )
        .expect("handshake");
        let type1 = handshake
            .initial_auth_verifier()
            .expect("type1 verifier should build");

        let bind_ack = BindAckPdu {
            call_id: 1,
            flags: PacketFlags::FIRST_FRAGMENT
                | PacketFlags::LAST_FRAGMENT
                | PacketFlags::SUPPORT_HEADER_SIGN,
            max_xmit_frag: 4280,
            max_recv_frag: 4280,
            assoc_group_id: 0,
            secondary_address: b"\\PIPE\\svcctl\0".to_vec(),
            result: BindAckResult {
                result: 0,
                reason: 0,
                transfer_syntax: SVCCTL_SYNTAX,
            },
            auth_verifier: Some(AuthVerifier::new(
                AuthType::WinNt,
                AuthLevel::PacketIntegrity,
                type1.auth_context_id,
                encode_challenge_message(),
            )),
        };

        let completed = handshake.complete(&bind_ack).expect("auth3 should build");

        assert_eq!(completed.auth3.call_id, bind_ack.call_id);
        assert_eq!(completed.auth3.auth_verifier.auth_type, AuthType::WinNt);
        assert_eq!(
            completed.auth3.auth_verifier.auth_level,
            AuthLevel::PacketIntegrity
        );
        assert_eq!(&completed.auth3.auth_verifier.auth_value[..8], b"NTLMSSP\0");
        assert_eq!(
            u32::from_le_bytes(
                completed.auth3.auth_verifier.auth_value[8..12]
                    .try_into()
                    .unwrap()
            ),
            3
        );
        assert!(completed.packet_integrity.is_some());
    }

    #[test]
    fn session_security_parser_rejects_missing_signing_flags() {
        let mut token = Vec::new();
        token.extend_from_slice(b"NTLMSSP\0");
        token.extend_from_slice(&3u32.to_le_bytes());
        token.resize(64, 0);
        token[60..64].copy_from_slice(&0x0008_0000u32.to_le_bytes());

        let error = session_security_from_authenticate(&token).expect_err("flags should reject");
        assert_eq!(
            error.to_string(),
            "unsupported: NTLM RPC secure bind requires sign, seal, and extended session security"
        );
    }

    fn encode_challenge_message() -> Vec<u8> {
        let target_info = encode_target_info(&[
            (0x0001, utf16le("SERVER")),
            (0x0002, utf16le("DOMAIN")),
            (0x0003, utf16le("server.example")),
            (0x0007, 9_999u64.to_le_bytes().to_vec()),
        ]);
        let target_info_len = target_info.len() as u16;
        let target_info_offset = 48u32;
        let flags: u32 = 0x0000_0001
            | 0x0000_0004
            | 0x0000_0200
            | 0x0000_0010
            | 0x0000_0020
            | 0x0000_8000
            | 0x0008_0000
            | 0x0080_0000
            | 0x0200_0000
            | 0x2000_0000
            | 0x4000_0000
            | 0x8000_0000;

        let mut out = Vec::with_capacity(48 + target_info.len());
        out.extend_from_slice(b"NTLMSSP\0");
        out.extend_from_slice(&2u32.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&48u32.to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&[8, 7, 6, 5, 4, 3, 2, 1]);
        out.extend_from_slice(&0u64.to_le_bytes());
        out.extend_from_slice(&target_info_len.to_le_bytes());
        out.extend_from_slice(&target_info_len.to_le_bytes());
        out.extend_from_slice(&target_info_offset.to_le_bytes());
        out.extend_from_slice(&target_info);
        out
    }

    fn encode_connect_challenge_message_without_key_exchange() -> Vec<u8> {
        let target_info = encode_target_info(&[
            (0x0001, utf16le("SERVER")),
            (0x0002, utf16le("DOMAIN")),
            (0x0003, utf16le("server.example")),
            (0x0007, 9_999u64.to_le_bytes().to_vec()),
        ]);
        let flags = 0xa28a_8235u32;
        let target_info_len = target_info.len() as u16;
        let target_info_offset = 48u32;

        let mut out = Vec::with_capacity(48 + target_info.len());
        out.extend_from_slice(b"NTLMSSP\0");
        out.extend_from_slice(&2u32.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&48u32.to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&[8, 7, 6, 5, 4, 3, 2, 1]);
        out.extend_from_slice(&0u64.to_le_bytes());
        out.extend_from_slice(&target_info_len.to_le_bytes());
        out.extend_from_slice(&target_info_len.to_le_bytes());
        out.extend_from_slice(&target_info_offset.to_le_bytes());
        out.extend_from_slice(&target_info);
        out
    }

    fn hex_bytes(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(nibble_to_hex(byte >> 4));
            out.push(nibble_to_hex(byte & 0x0f));
        }
        out
    }

    fn nibble_to_hex(value: u8) -> char {
        match value {
            0..=9 => char::from(b'0' + value),
            10..=15 => char::from(b'a' + (value - 10)),
            _ => unreachable!("hex nibble must be in range"),
        }
    }

    fn encode_target_info(pairs: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (av_id, value) in pairs {
            out.extend_from_slice(&av_id.to_le_bytes());
            out.extend_from_slice(&(value.len() as u16).to_le_bytes());
            out.extend_from_slice(value);
        }
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }
}
