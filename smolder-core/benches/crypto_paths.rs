use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use smolder_core::crypto::{derive_encryption_keys, EncryptionState};
use smolder_proto::smb::smb2::{CipherId, Dialect};

const SESSION_KEY_128: [u8; 16] = [0x11; 16];
const SESSION_KEY_256_PREFIX: [u8; 16] = [0x22; 16];
const SESSION_KEY_256: [u8; 32] = [0x22; 32];
const PREAUTH_HASH: [u8; 64] = [0x33; 64];
const SESSION_ID: u64 = 0x0102_0304_0506_0708;

#[derive(Clone, Copy)]
struct CryptoProfile {
    name: &'static str,
    dialect: Dialect,
    cipher: CipherId,
    session_key: &'static [u8],
    full_session_key: Option<&'static [u8]>,
    preauth_hash: Option<&'static [u8]>,
}

const PROFILES: [CryptoProfile; 3] = [
    CryptoProfile {
        name: "smb302_aes128ccm",
        dialect: Dialect::Smb302,
        cipher: CipherId::Aes128Ccm,
        session_key: &SESSION_KEY_128,
        full_session_key: None,
        preauth_hash: None,
    },
    CryptoProfile {
        name: "smb311_aes128gcm",
        dialect: Dialect::Smb311,
        cipher: CipherId::Aes128Gcm,
        session_key: &SESSION_KEY_128,
        full_session_key: None,
        preauth_hash: Some(&PREAUTH_HASH),
    },
    CryptoProfile {
        name: "smb311_aes256gcm",
        dialect: Dialect::Smb311,
        cipher: CipherId::Aes256Gcm,
        session_key: &SESSION_KEY_256_PREFIX,
        full_session_key: Some(&SESSION_KEY_256),
        preauth_hash: Some(&PREAUTH_HASH),
    },
];

fn bench_key_derivation(c: &mut Criterion) {
    let mut group = c.benchmark_group("core/derive_encryption_keys");
    for profile in PROFILES {
        group.bench_function(profile.name, |b| {
            b.iter(|| {
                derive_encryption_keys(
                    black_box(profile.dialect),
                    black_box(profile.cipher),
                    black_box(profile.session_key),
                    black_box(profile.full_session_key),
                    black_box(profile.preauth_hash),
                )
                .expect("benchmark profile should derive encryption keys")
            });
        });
    }
    group.finish();
}

fn bench_message_sealing(c: &mut Criterion) {
    let mut group = c.benchmark_group("core/message_sealing");
    for size in [4 * 1024usize, 64 * 1024usize] {
        let message = vec![0x5a; size];
        group.throughput(Throughput::Bytes(size as u64));

        for profile in PROFILES {
            let keys = derive_encryption_keys(
                profile.dialect,
                profile.cipher,
                profile.session_key,
                profile.full_session_key,
                profile.preauth_hash,
            )
            .expect("benchmark profile should derive encryption keys");
            let state = EncryptionState::new(profile.dialect, keys);
            let transform = state
                .encrypt_message(SESSION_ID, &message)
                .expect("benchmark profile should encrypt a message");

            group.bench_with_input(
                BenchmarkId::new(format!("{}/encrypt", profile.name), size),
                &message,
                |b, message| {
                    b.iter(|| {
                        state
                            .encrypt_message(black_box(SESSION_ID), black_box(message))
                            .expect("benchmark profile should encrypt a message")
                    });
                },
            );

            group.bench_with_input(
                BenchmarkId::new(format!("{}/decrypt", profile.name), size),
                &transform,
                |b, transform| {
                    b.iter(|| {
                        state
                            .decrypt_message(black_box(transform))
                            .expect("benchmark profile should decrypt a message")
                    });
                },
            );
        }
    }
    group.finish();
}

criterion_group!(crypto_paths, bench_key_derivation, bench_message_sealing);
criterion_main!(crypto_paths);
