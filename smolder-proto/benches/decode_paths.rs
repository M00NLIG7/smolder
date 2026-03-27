use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use smolder_proto::rpc::{
    AuthLevel, AuthType, AuthVerifier, BindPdu, Packet, PacketFlags, RequestPdu, SyntaxId, Uuid,
};
use smolder_proto::smb::netbios::SessionMessage;
use smolder_proto::smb::smb2::{
    CipherId, Dialect, EncryptionCapabilities, GlobalCapabilities, NegotiateContext,
    NegotiateContextType, NegotiateRequest, PreauthIntegrityCapabilities,
    PreauthIntegrityHashId, SessionSetupRequest, SessionSetupSecurityMode, SigningMode, Command,
    Header, HeaderFlags, MessageId, SessionId, TreeId,
};
use smolder_proto::smb::transform::{TransformHeader, TransformValue};

fn bench_decode_paths(c: &mut Criterion) {
    let header_bytes = build_header_bytes();
    let negotiate_request_bytes = build_negotiate_request_bytes();
    let session_setup_bytes = build_session_setup_request_bytes();
    let netbios_frame_bytes = build_netbios_frame_bytes();
    let transform_bytes = build_transform_bytes();
    let rpc_bind_bytes = build_rpc_bind_bytes();
    let rpc_request_bytes = build_rpc_request_bytes();

    let mut group = c.benchmark_group("proto/decode_paths");

    group.throughput(Throughput::Bytes(header_bytes.len() as u64));
    group.bench_function(BenchmarkId::new("smb2_header", header_bytes.len()), |b| {
        b.iter(|| Header::decode(black_box(&header_bytes)).expect("header should decode"));
    });

    group.throughput(Throughput::Bytes(negotiate_request_bytes.len() as u64));
    group.bench_function(
        BenchmarkId::new("negotiate_request", negotiate_request_bytes.len()),
        |b| {
            b.iter(|| {
                NegotiateRequest::decode(black_box(&negotiate_request_bytes))
                    .expect("negotiate request should decode")
            });
        },
    );

    group.throughput(Throughput::Bytes(session_setup_bytes.len() as u64));
    group.bench_function(
        BenchmarkId::new("session_setup_request", session_setup_bytes.len()),
        |b| {
            b.iter(|| {
                SessionSetupRequest::decode(black_box(&session_setup_bytes))
                    .expect("session setup request should decode")
            });
        },
    );

    group.throughput(Throughput::Bytes(netbios_frame_bytes.len() as u64));
    group.bench_function(
        BenchmarkId::new("netbios_session_frame", netbios_frame_bytes.len()),
        |b| {
            b.iter(|| {
                SessionMessage::decode(black_box(&netbios_frame_bytes))
                    .expect("netbios frame should decode")
            });
        },
    );

    group.throughput(Throughput::Bytes(transform_bytes.len() as u64));
    group.bench_function(
        BenchmarkId::new("transform_header", transform_bytes.len()),
        |b| {
            b.iter(|| {
                TransformHeader::decode(black_box(&transform_bytes))
                    .expect("transform header should decode")
            });
        },
    );

    group.throughput(Throughput::Bytes(rpc_bind_bytes.len() as u64));
    group.bench_function(BenchmarkId::new("rpc_bind_packet", rpc_bind_bytes.len()), |b| {
        b.iter(|| Packet::decode(black_box(&rpc_bind_bytes)).expect("rpc bind should decode"));
    });

    group.throughput(Throughput::Bytes(rpc_request_bytes.len() as u64));
    group.bench_function(
        BenchmarkId::new("rpc_request_packet", rpc_request_bytes.len()),
        |b| {
            b.iter(|| {
                Packet::decode(black_box(&rpc_request_bytes)).expect("rpc request should decode")
            });
        },
    );

    group.finish();
}

fn build_header_bytes() -> Vec<u8> {
    let mut header = Header::new(Command::Write, MessageId(7));
    header.flags = HeaderFlags::SIGNED | HeaderFlags::RELATED_OPERATIONS;
    header.credit_request_response = 32;
    header.next_command = 128;
    header.tree_id = TreeId(9);
    header.session_id = SessionId(0x0102_0304_0506_0708);
    header.signature = [0xaa; 16];
    header.encode()
}

fn build_negotiate_request_bytes() -> Vec<u8> {
    let request = NegotiateRequest {
        security_mode: SigningMode::ENABLED | SigningMode::REQUIRED,
        capabilities: GlobalCapabilities::DFS
            | GlobalCapabilities::LARGE_MTU
            | GlobalCapabilities::ENCRYPTION,
        client_guid: *b"proto-benchguid!",
        dialects: vec![Dialect::Smb210, Dialect::Smb302, Dialect::Smb311],
        negotiate_contexts: vec![
            NegotiateContext {
                context_type: NegotiateContextType::PreauthIntegrityCapabilities as u16,
                data: PreauthIntegrityCapabilities {
                    hash_algorithms: vec![PreauthIntegrityHashId::Sha512],
                    salt: vec![0x44; 32],
                }
                .encode(),
            },
            NegotiateContext {
                context_type: NegotiateContextType::EncryptionCapabilities as u16,
                data: EncryptionCapabilities {
                    ciphers: vec![CipherId::Aes128Gcm, CipherId::Aes256Gcm],
                }
                .encode(),
            },
        ],
    };

    request
        .encode()
        .expect("negotiate request benchmark input should encode")
}

fn build_session_setup_request_bytes() -> Vec<u8> {
    SessionSetupRequest {
        flags: 0,
        security_mode: SessionSetupSecurityMode::SIGNING_ENABLED,
        capabilities: 0,
        channel: 0,
        security_buffer: vec![0x60; 2048],
        previous_session_id: 0,
    }
    .encode()
}

fn build_netbios_frame_bytes() -> Vec<u8> {
    SessionMessage::encode_payload(&vec![0x5a; 4 * 1024])
        .expect("netbios benchmark input should encode")
}

fn build_transform_bytes() -> Vec<u8> {
    TransformHeader {
        signature: [0x11; 16],
        nonce: [0x22; 16],
        original_message_size: 4096,
        flags_or_algorithm: TransformValue::ENCRYPTED,
        session_id: 0x0102_0304_0506_0708,
        encrypted_message: vec![0xaa; 4 * 1024],
    }
    .encode()
}

fn build_rpc_bind_bytes() -> Vec<u8> {
    BindPdu {
        call_id: 1,
        flags: PacketFlags::FIRST_FRAGMENT | PacketFlags::LAST_FRAGMENT,
        max_xmit_frag: 4280,
        max_recv_frag: 4280,
        assoc_group_id: 0,
        context_id: 0,
        abstract_syntax: SyntaxId::new(
            Uuid::new(
                0x367a_eb81,
                0x9844,
                0x35f1,
                [0xad, 0x32, 0x98, 0xf0, 0x38, 0x00, 0x10, 0x03],
            ),
            2,
            0,
        ),
        transfer_syntax: SyntaxId::NDR32,
        auth_verifier: Some(AuthVerifier::new(
            AuthType::WinNt,
            AuthLevel::PacketIntegrity,
            0,
            vec![0x7f; 48],
        )),
    }
    .encode()
}

fn build_rpc_request_bytes() -> Vec<u8> {
    RequestPdu {
        call_id: 2,
        flags: PacketFlags::FIRST_FRAGMENT | PacketFlags::LAST_FRAGMENT,
        alloc_hint: 2048,
        context_id: 0,
        opnum: 15,
        object_uuid: Some(Uuid::new(
            0x0011_2233,
            0x4455,
            0x6677,
            [0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        )),
        stub_data: vec![0x5c; 2048],
        auth_verifier: Some(AuthVerifier::new(
            AuthType::WinNt,
            AuthLevel::PacketIntegrity,
            0,
            vec![0x80; 32],
        )),
    }
    .encode()
}

criterion_group!(decode_paths, bench_decode_paths);
criterion_main!(decode_paths);
