use proptest::prelude::*;
use smolder_proto::rpc::{
    AuthLevel, AuthType, AuthVerifier, BindPdu, Packet, PacketFlags, RequestPdu, ResponsePdu,
    SyntaxId, Uuid,
};
use smolder_proto::smb::netbios::SessionMessage;
use smolder_proto::smb::smb2::{
    ChangeNotifyRequest, Command, CreateRequest, Header, HeaderFlags, IoctlRequest, LockRequest,
    MessageId, NegotiateRequest, ReadRequest, SessionId, SessionSetupRequest, TreeConnectRequest,
    TreeId, WriteRequest, utf16le, utf16le_string,
};
use smolder_proto::smb::transform::{TransformHeader, TransformValue};
use smolder_proto::smb::ProtocolError;

const PROPTEST_CASES: u32 = 64;

fn header_flags_from_bits(bits: u8) -> HeaderFlags {
    let mut flags = HeaderFlags::empty();
    if bits & 0x01 != 0 {
        flags |= HeaderFlags::SERVER_TO_REDIR;
    }
    if bits & 0x02 != 0 {
        flags |= HeaderFlags::ASYNC_COMMAND;
    }
    if bits & 0x04 != 0 {
        flags |= HeaderFlags::RELATED_OPERATIONS;
    }
    if bits & 0x08 != 0 {
        flags |= HeaderFlags::SIGNED;
    }
    if bits & 0x10 != 0 {
        flags |= HeaderFlags::REPLAY_OPERATION;
    }
    flags
}

fn rpc_flags_from_bits(bits: u8) -> PacketFlags {
    let mut flags = PacketFlags::empty();
    if bits & 0x01 != 0 {
        flags |= PacketFlags::FIRST_FRAGMENT;
    }
    if bits & 0x02 != 0 {
        flags |= PacketFlags::LAST_FRAGMENT;
    }
    if bits & 0x04 != 0 {
        flags |= PacketFlags::SUPPORT_HEADER_SIGN;
    }
    if bits & 0x08 != 0 {
        flags |= PacketFlags::CONCURRENT_MULTIPLEX;
    }
    if bits & 0x10 != 0 {
        flags |= PacketFlags::DID_NOT_EXECUTE;
    }
    flags
}

fn command_strategy() -> impl Strategy<Value = Command> {
    prop_oneof![
        Just(Command::Negotiate),
        Just(Command::SessionSetup),
        Just(Command::Logoff),
        Just(Command::TreeConnect),
        Just(Command::TreeDisconnect),
        Just(Command::Create),
        Just(Command::Close),
        Just(Command::Flush),
        Just(Command::Read),
        Just(Command::Write),
        Just(Command::Lock),
        Just(Command::Ioctl),
        Just(Command::Cancel),
        Just(Command::Echo),
        Just(Command::QueryDirectory),
        Just(Command::ChangeNotify),
        Just(Command::QueryInfo),
        Just(Command::SetInfo),
    ]
}

fn auth_type_strategy() -> impl Strategy<Value = AuthType> {
    prop_oneof![
        Just(AuthType::None),
        Just(AuthType::GssNegotiate),
        Just(AuthType::WinNt),
        Just(AuthType::GssSchannel),
        Just(AuthType::GssKerberos),
        Just(AuthType::Netlogon),
        Just(AuthType::Default),
    ]
}

fn auth_level_strategy() -> impl Strategy<Value = AuthLevel> {
    prop_oneof![
        Just(AuthLevel::Default),
        Just(AuthLevel::None),
        Just(AuthLevel::Connect),
        Just(AuthLevel::Call),
        Just(AuthLevel::Packet),
        Just(AuthLevel::PacketIntegrity),
        Just(AuthLevel::PacketPrivacy),
    ]
}

fn uuid_strategy() -> impl Strategy<Value = Uuid> {
    (
        any::<u32>(),
        any::<u16>(),
        any::<u16>(),
        prop::array::uniform8(any::<u8>()),
    )
        .prop_map(|(data1, data2, data3, data4)| Uuid::new(data1, data2, data3, data4))
}

fn syntax_id_strategy() -> impl Strategy<Value = SyntaxId> {
    (uuid_strategy(), any::<u16>(), any::<u16>())
        .prop_map(|(uuid, version, version_minor)| SyntaxId::new(uuid, version, version_minor))
}

fn auth_verifier_strategy() -> impl Strategy<Value = AuthVerifier> {
    (
        auth_type_strategy(),
        auth_level_strategy(),
        any::<u8>(),
        any::<u32>(),
        prop::collection::vec(any::<u8>(), 1..128),
    )
        .prop_map(
            |(auth_type, auth_level, auth_reserved, auth_context_id, auth_value)| AuthVerifier {
                auth_type,
                auth_level,
                auth_reserved,
                auth_context_id,
                auth_value,
            },
        )
}

fn optional_auth_verifier_strategy() -> impl Strategy<Value = Option<AuthVerifier>> {
    prop_oneof![Just(None), auth_verifier_strategy().prop_map(Some)]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(PROPTEST_CASES))]

    #[test]
    fn utf16le_roundtrips_random_strings(chars in prop::collection::vec(any::<char>(), 0..64)) {
        let input = chars.into_iter().collect::<String>();
        let encoded = utf16le(&input);
        let decoded = utf16le_string(&encoded).expect("valid UTF-16LE roundtrip should decode");
        prop_assert_eq!(decoded, input);
    }

    #[test]
    fn session_message_roundtrips_random_payloads(
        message_type in any::<u8>(),
        payload in prop::collection::vec(any::<u8>(), 0..2048),
    ) {
        let message = SessionMessage { message_type, payload };
        let encoded = message.encode().expect("session message should encode");
        let decoded = SessionMessage::decode(&encoded).expect("session message should decode");
        prop_assert_eq!(decoded, message);
    }

    #[test]
    fn smb2_header_roundtrips_random_valid_headers(
        command in command_strategy(),
        message_id in any::<u64>(),
        credit_charge in any::<u16>(),
        status in any::<u32>(),
        credit_request_response in any::<u16>(),
        raw_flags in any::<u8>(),
        next_command in any::<u32>(),
        async_id in any::<u64>(),
        tree_id in any::<u32>(),
        session_id in any::<u64>(),
        signature in prop::array::uniform16(any::<u8>()),
    ) {
        let flags = header_flags_from_bits(raw_flags);
        let is_async = flags.contains(HeaderFlags::ASYNC_COMMAND);
        let header = Header {
            credit_charge: smolder_proto::smb::smb2::CreditCharge(credit_charge),
            status,
            command,
            credit_request_response,
            flags,
            next_command,
            message_id: MessageId(message_id),
            async_id: is_async.then_some(smolder_proto::smb::smb2::AsyncId(async_id)),
            tree_id: if is_async { TreeId(0) } else { TreeId(tree_id) },
            session_id: SessionId(session_id),
            signature,
        };

        let encoded = header.encode();
        let decoded = Header::decode(&encoded).expect("valid SMB2 header should decode");
        prop_assert_eq!(decoded, header);
    }

    #[test]
    fn transform_header_roundtrips_random_packets(
        signature in prop::array::uniform16(any::<u8>()),
        nonce in prop::array::uniform16(any::<u8>()),
        original_message_size in any::<u32>(),
        flags_or_algorithm in any::<u16>(),
        session_id in any::<u64>(),
        encrypted_message in prop::collection::vec(any::<u8>(), 0..2048),
    ) {
        let packet = TransformHeader {
            signature,
            nonce,
            original_message_size,
            flags_or_algorithm: TransformValue(flags_or_algorithm),
            session_id,
            encrypted_message,
        };

        let encoded = packet.encode();
        let decoded = TransformHeader::decode(&encoded).expect("transform header should decode");
        prop_assert_eq!(decoded, packet);
    }

    #[test]
    fn bind_pdu_roundtrips_random_valid_packets(
        call_id in any::<u32>(),
        raw_flags in any::<u8>(),
        max_xmit_frag in any::<u16>(),
        max_recv_frag in any::<u16>(),
        assoc_group_id in any::<u32>(),
        context_id in any::<u16>(),
        abstract_syntax in syntax_id_strategy(),
        transfer_syntax in syntax_id_strategy(),
        auth_verifier in optional_auth_verifier_strategy(),
    ) {
        let packet = BindPdu {
            call_id,
            flags: rpc_flags_from_bits(raw_flags),
            max_xmit_frag,
            max_recv_frag,
            assoc_group_id,
            context_id,
            abstract_syntax,
            transfer_syntax,
            auth_verifier,
        };

        let encoded = packet.encode();
        let decoded = BindPdu::decode(&encoded).expect("bind PDU should decode");
        prop_assert_eq!(decoded, packet.clone());
        prop_assert_eq!(Packet::decode(&encoded).expect("packet dispatch should decode"), Packet::Bind(packet));
    }

    #[test]
    fn request_pdu_roundtrips_random_valid_packets(
        call_id in any::<u32>(),
        raw_flags in any::<u8>(),
        alloc_hint in any::<u32>(),
        context_id in any::<u16>(),
        opnum in any::<u16>(),
        object_uuid in prop_oneof![Just(None), uuid_strategy().prop_map(Some)],
        stub_data in prop::collection::vec(any::<u8>(), 0..256),
        auth_verifier in optional_auth_verifier_strategy(),
    ) {
        let packet = RequestPdu {
            call_id,
            flags: rpc_flags_from_bits(raw_flags),
            alloc_hint,
            context_id,
            opnum,
            object_uuid,
            stub_data,
            auth_verifier,
        };

        let encoded = packet.encode();
        let decoded = RequestPdu::decode(&encoded).expect("request PDU should decode");
        let mut expected = packet.clone();
        if expected.object_uuid.is_some() {
            expected.flags |= PacketFlags::OBJECT_UUID;
        }
        prop_assert_eq!(decoded, expected.clone());
        prop_assert_eq!(Packet::decode(&encoded).expect("packet dispatch should decode"), Packet::Request(expected));
    }

    #[test]
    fn response_pdu_roundtrips_random_valid_packets(
        call_id in any::<u32>(),
        raw_flags in any::<u8>(),
        alloc_hint in any::<u32>(),
        context_id in any::<u16>(),
        cancel_count in any::<u8>(),
        stub_data in prop::collection::vec(any::<u8>(), 0..256),
        auth_verifier in optional_auth_verifier_strategy(),
    ) {
        let packet = ResponsePdu {
            call_id,
            flags: rpc_flags_from_bits(raw_flags),
            alloc_hint,
            context_id,
            cancel_count,
            stub_data,
            auth_verifier,
        };

        let encoded = packet.encode();
        let decoded = ResponsePdu::decode(&encoded).expect("response PDU should decode");
        prop_assert_eq!(decoded, packet.clone());
        prop_assert_eq!(Packet::decode(&encoded).expect("packet dispatch should decode"), Packet::Response(packet));
    }

    #[test]
    fn malformed_bytes_do_not_panic_across_public_decoders(
        bytes in prop::collection::vec(any::<u8>(), 0..1024),
    ) {
        let _ = SessionMessage::decode(&bytes);
        let _ = Header::decode(&bytes);
        let _ = TransformHeader::decode(&bytes);
        let _ = Packet::decode(&bytes);
        let _ = NegotiateRequest::decode(&bytes);
        let _ = SessionSetupRequest::decode(&bytes);
        let _ = TreeConnectRequest::decode(&bytes);
        let _ = CreateRequest::decode(&bytes);
        let _ = ReadRequest::decode(&bytes);
        let _ = WriteRequest::decode(&bytes);
        let _ = IoctlRequest::decode(&bytes);
        let _ = ChangeNotifyRequest::decode(&bytes);
        let _ = LockRequest::decode(&bytes);
    }
}

#[test]
fn utf16le_rejects_odd_length_buffers() {
    let error = utf16le_string(&[0x41]).expect_err("odd-length UTF-16LE should fail");
    assert!(matches!(error, ProtocolError::InvalidField { field: "utf16le_string", .. }));
}
