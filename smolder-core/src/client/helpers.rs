use std::sync::Arc;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use smolder_proto::smb::compression::{
    COMPRESSION_TRANSFORM_PROTOCOL_ID, CompressionCapabilityFlags, CompressionTransformHeader,
};
use smolder_proto::smb::smb2::{
    AsyncId, CipherId, CompressionCapabilities, CreateContext, CreateRequest, CreateResponse,
    Dialect, DurableHandleFlags, DurableHandleReconnect, DurableHandleReconnectV2,
    DurableHandleRequest, DurableHandleRequestV2, GlobalCapabilities, Header, HeaderFlags,
    NegotiateRequest, NegotiateResponse, PreauthIntegrityCapabilities, SessionFlags,
    SessionSetupSecurityMode, ShareFlags, SigningMode, TransportCapabilityFlags,
};
use smolder_proto::smb::status::NtStatus;
use smolder_proto::smb::transform::{TRANSFORM_PROTOCOL_ID, TransformHeader};

use crate::compression::CompressionState;
use crate::crypto::{derive_encryption_keys, EncryptionState};
use crate::error::CoreError;

use super::state::{
    DurableHandle, DurableOpenOptions, PreauthIntegrityState, RequestContext, SigningAlgorithm,
    SigningState,
};

pub(super) fn align_to_8(len: usize) -> usize {
    (len + 7) & !7
}

pub(super) fn split_compound_packets(payload: &[u8]) -> Result<Vec<&[u8]>, CoreError> {
    if payload.len() < Header::LEN {
        return Err(CoreError::InvalidResponse(
            "response shorter than SMB2 header",
        ));
    }

    let mut packets = Vec::new();
    let mut offset = 0usize;
    loop {
        let header_end = offset
            .checked_add(Header::LEN)
            .ok_or(CoreError::InvalidResponse(
                "compound response offset overflowed",
            ))?;
        if header_end > payload.len() {
            return Err(CoreError::InvalidResponse(
                "compound response packet was truncated",
            ));
        }
        let header = Header::decode(&payload[offset..header_end])?;
        let next = header.next_command as usize;
        let end = if next == 0 {
            payload.len()
        } else {
            if next < Header::LEN || next % 8 != 0 {
                return Err(CoreError::InvalidResponse(
                    "compound response next-command offset was invalid",
                ));
            }
            offset.checked_add(next).ok_or(CoreError::InvalidResponse(
                "compound response offset overflowed",
            ))?
        };
        if end > payload.len() || end <= offset {
            return Err(CoreError::InvalidResponse(
                "compound response next-command offset was invalid",
            ));
        }
        packets.push(&payload[offset..end]);
        if next == 0 {
            break;
        }
        offset = end;
    }

    Ok(packets)
}

pub(super) fn encode_transport_payload(
    payload: &[u8],
    context: &RequestContext,
) -> Result<Vec<u8>, CoreError> {
    let session_payload = if context.compress_outbound {
        context
            .compression
            .as_deref()
            .map(|compression| compression.compress_message(payload))
            .transpose()?
            .flatten()
            .unwrap_or_else(|| payload.to_vec())
    } else {
        payload.to_vec()
    };
    let session_payload = if context.should_encrypt() {
        let encryption = context
            .encryption
            .as_deref()
            .ok_or(CoreError::InvalidInput(
                "session requires encryption but no encryption key is available",
            ))?;
        encryption
            .encrypt_message(context.session_id.0, &session_payload)?
            .encode()
    } else {
        session_payload
    };
    Ok(session_payload)
}

pub(super) fn decode_transport_payload(
    payload: &[u8],
    context: &RequestContext,
) -> Result<(Vec<u8>, bool), CoreError> {
    if payload.starts_with(&TRANSFORM_PROTOCOL_ID) {
        let encryption = context
            .encryption
            .as_deref()
            .ok_or(CoreError::InvalidResponse(
                "received encrypted SMB response but no encryption state is available",
            ))?;
        let transform = TransformHeader::decode(payload)?;
        if transform.session_id != context.session_id.0 {
            return Err(CoreError::InvalidResponse(
                "encrypted SMB response session id did not match the active session",
            ));
        }
        let decrypted = encryption.decrypt_message(&transform)?;
        if decrypted.starts_with(&COMPRESSION_TRANSFORM_PROTOCOL_ID) {
            let compression = context
                .compression
                .as_deref()
                .ok_or(CoreError::InvalidResponse(
                    "received compressed SMB response but no compression state is available",
                ))?;
            let transform = CompressionTransformHeader::decode(&decrypted)?;
            return Ok((compression.decompress_message(&transform)?, true));
        }
        return Ok((decrypted, true));
    }
    if payload.starts_with(&COMPRESSION_TRANSFORM_PROTOCOL_ID) {
        if context.should_encrypt() {
            return Err(CoreError::InvalidResponse(
                "session required encryption but the SMB response was only compressed",
            ));
        }
        let compression = context
            .compression
            .as_deref()
            .ok_or(CoreError::InvalidResponse(
                "received compressed SMB response but no compression state is available",
            ))?;
        let transform = CompressionTransformHeader::decode(payload)?;
        return Ok((compression.decompress_message(&transform)?, false));
    }
    if context.should_encrypt() {
        return Err(CoreError::InvalidResponse(
            "session required encryption but the SMB response was not encrypted",
        ));
    }
    Ok((payload.to_vec(), false))
}

pub(super) fn durable_create_request(
    dialect: Dialect,
    request: &CreateRequest,
    options: &DurableOpenOptions,
) -> Result<CreateRequest, CoreError> {
    let mut request = request.clone();
    request.create_contexts = strip_durable_create_contexts(&request.create_contexts)?;
    request.create_contexts.push(match dialect {
        Dialect::Smb202 | Dialect::Smb210 => {
            CreateContext::durable_handle_request(DurableHandleRequest)
        }
        Dialect::Smb300 | Dialect::Smb302 | Dialect::Smb311 => {
            let create_guid = options.create_guid.ok_or(CoreError::InvalidInput(
                "durable SMB 3.x opens require a create GUID",
            ))?;
            CreateContext::durable_handle_request_v2(DurableHandleRequestV2 {
                timeout: options.timeout,
                flags: options.flags,
                create_guid,
            })
        }
    });
    Ok(request)
}

pub(super) fn durable_reconnect_request(
    dialect: Dialect,
    handle: &DurableHandle,
) -> Result<CreateRequest, CoreError> {
    let mut request = handle.create_request.clone();
    request.create_contexts = strip_durable_create_contexts(&request.create_contexts)?;
    request.create_contexts.push(match dialect {
        Dialect::Smb202 | Dialect::Smb210 => {
            CreateContext::durable_handle_reconnect(DurableHandleReconnect {
                file_id: handle.file_id(),
            })
        }
        Dialect::Smb300 | Dialect::Smb302 | Dialect::Smb311 => {
            let create_guid = handle.create_guid.ok_or(CoreError::InvalidInput(
                "durable SMB 3.x reconnect is missing its create GUID",
            ))?;
            CreateContext::durable_handle_reconnect_v2(DurableHandleReconnectV2 {
                file_id: handle.file_id(),
                create_guid,
                flags: handle.flags,
            })
        }
    });
    Ok(request)
}

pub(super) fn build_durable_handle(
    dialect: Dialect,
    request: &CreateRequest,
    response: CreateResponse,
    options: &DurableOpenOptions,
) -> Result<DurableHandle, CoreError> {
    let (timeout, flags, create_guid) = match dialect {
        Dialect::Smb202 | Dialect::Smb210 => {
            let granted = response
                .create_contexts
                .iter()
                .find_map(|context| context.durable_handle_response_data().transpose())
                .transpose()?
                .ok_or(CoreError::InvalidResponse(
                    "durable open response did not include the granted durable context",
                ))?;
            let _ = granted;
            (0, DurableHandleFlags::empty(), None)
        }
        Dialect::Smb300 | Dialect::Smb302 | Dialect::Smb311 => {
            let granted = response
                .create_contexts
                .iter()
                .find_map(|context| context.durable_handle_response_v2_data().transpose())
                .transpose()?;
            let create_guid = options.create_guid.ok_or(CoreError::InvalidInput(
                "durable SMB 3.x opens require a create GUID",
            ))?;
            let (timeout, flags) = granted
                .map(|granted| (granted.timeout, granted.flags))
                .unwrap_or((options.timeout, options.flags));
            (timeout, flags, Some(create_guid))
        }
    };

    Ok(DurableHandle {
        create_request: request.clone(),
        response,
        timeout,
        flags,
        create_guid,
        resilient_timeout: None,
    })
}

pub(super) fn strip_durable_create_contexts(
    contexts: &[CreateContext],
) -> Result<Vec<CreateContext>, CoreError> {
    let mut filtered = Vec::with_capacity(contexts.len());
    for context in contexts {
        if context.durable_handle_request_data()?.is_some()
            || context.durable_handle_reconnect_data()?.is_some()
            || context.durable_handle_request_v2_data()?.is_some()
            || context.durable_handle_reconnect_v2_data()?.is_some()
        {
            continue;
        }
        filtered.push(context.clone());
    }
    Ok(filtered)
}

pub(super) fn validate_pending_response(header: &Header) -> Result<AsyncId, CoreError> {
    if !header.flags.contains(HeaderFlags::ASYNC_COMMAND) {
        return Err(CoreError::InvalidResponse(
            "pending response must use the async SMB2 header",
        ));
    }
    let async_id = header.async_id.ok_or(CoreError::InvalidResponse(
        "pending response was missing an async id",
    ))?;
    if async_id.0 == 0 {
        return Err(CoreError::InvalidResponse(
            "pending response async id must be nonzero",
        ));
    }
    Ok(async_id)
}

pub(super) fn validate_async_final_response(
    header: &Header,
    async_id: AsyncId,
) -> Result<(), CoreError> {
    if !header.flags.contains(HeaderFlags::ASYNC_COMMAND) {
        return Err(CoreError::InvalidResponse(
            "final async response must use the async SMB2 header",
        ));
    }
    if header.async_id != Some(async_id) {
        return Err(CoreError::InvalidResponse(
            "final async response async id did not match the interim response",
        ));
    }
    Ok(())
}

pub(super) fn verify_response_signature(
    header: &Header,
    response_packet: &[u8],
    context: &RequestContext,
) -> Result<(), CoreError> {
    if header.flags.contains(HeaderFlags::SIGNED) {
        let signing = context
            .signing
            .as_deref()
            .ok_or(CoreError::InvalidResponse(
                "received a signed SMB response but no signing key is available",
            ))?;
        return signing.verify_packet(response_packet);
    }

    if context.signing_required {
        return Err(CoreError::InvalidResponse(
            "session requires signed SMB responses",
        ));
    }

    Ok(())
}

pub(super) fn negotiate_preauth_integrity_state(
    request: &NegotiateRequest,
    response: &NegotiateResponse,
    request_packet: &[u8],
    response_packet: &[u8],
) -> Result<Option<PreauthIntegrityState>, CoreError> {
    if response.dialect_revision != Dialect::Smb311 {
        return Ok(None);
    }

    let requested = single_preauth_context(&request.negotiate_contexts, true)?.ok_or(
        CoreError::InvalidInput(
            "SMB 3.1.1 negotiate requests must include a preauth integrity context",
        ),
    )?;
    let received = single_preauth_context(&response.negotiate_contexts, false)?.ok_or(
        CoreError::InvalidResponse(
            "SMB 3.1.1 negotiate responses must include exactly one preauth integrity context",
        ),
    )?;
    if received.hash_algorithms.len() != 1 {
        return Err(CoreError::InvalidResponse(
            "SMB 3.1.1 preauth negotiate response must select exactly one hash algorithm",
        ));
    }
    let algorithm = received.hash_algorithms[0];
    if !requested.hash_algorithms.contains(&algorithm) {
        return Err(CoreError::InvalidResponse(
            "server selected a preauth hash algorithm that was not offered by the client",
        ));
    }

    let mut preauth = PreauthIntegrityState::new(algorithm);
    preauth.update(request_packet)?;
    preauth.update(response_packet)?;
    Ok(Some(preauth))
}

pub(super) fn negotiate_compression_state(
    request: &NegotiateRequest,
    response: &NegotiateResponse,
) -> Result<Option<Arc<CompressionState>>, CoreError> {
    if response.dialect_revision != Dialect::Smb311 {
        return Ok(None);
    }

    let Some(requested) = single_compression_context(&request.negotiate_contexts, true)? else {
        return Ok(None);
    };
    let Some(received) = single_compression_context(&response.negotiate_contexts, false)? else {
        return Ok(None);
    };
    if received.compression_algorithms.len() != 1 {
        return Err(CoreError::InvalidResponse(
            "SMB 3.1.1 negotiate response must select exactly one compression algorithm",
        ));
    }
    let algorithm = received.compression_algorithms[0];
    if !requested.compression_algorithms.contains(&algorithm) {
        return Err(CoreError::InvalidResponse(
            "server selected a compression algorithm that was not offered by the client",
        ));
    }
    if !requested.flags.contains(received.flags) {
        return Err(CoreError::InvalidResponse(
            "server selected unsupported SMB compression flags",
        ));
    }
    if received.flags.contains(CompressionCapabilityFlags::CHAINED) {
        return Err(CoreError::Unsupported(
            "SMB chained compression negotiation is not supported yet",
        ));
    }

    Ok(Some(Arc::new(CompressionState::new(
        algorithm,
        received.flags.contains(CompressionCapabilityFlags::CHAINED),
    ))))
}

fn single_preauth_context(
    contexts: &[smolder_proto::smb::smb2::NegotiateContext],
    request: bool,
) -> Result<Option<PreauthIntegrityCapabilities>, CoreError> {
    let mut found = None;
    for context in contexts {
        let Some(preauth) = context.as_preauth_integrity()? else {
            continue;
        };
        if found.is_some() {
            return Err(if request {
                CoreError::InvalidInput(
                    "SMB 3.1.1 negotiate request contained multiple preauth integrity contexts",
                )
            } else {
                CoreError::InvalidResponse(
                    "SMB 3.1.1 negotiate response contained multiple preauth integrity contexts",
                )
            });
        }
        found = Some(preauth);
    }
    Ok(found)
}

fn single_compression_context(
    contexts: &[smolder_proto::smb::smb2::NegotiateContext],
    request: bool,
) -> Result<Option<CompressionCapabilities>, CoreError> {
    let mut found = None;
    for context in contexts {
        let Some(compression) = context.as_compression_capabilities()? else {
            continue;
        };
        if found.is_some() {
            return Err(if request {
                CoreError::InvalidInput(
                    "SMB 3.1.1 negotiate request contained multiple compression contexts",
                )
            } else {
                CoreError::InvalidResponse(
                    "SMB 3.1.1 negotiate response contained multiple compression contexts",
                )
            });
        }
        found = Some(compression);
    }
    Ok(found)
}

pub(super) fn update_session_setup_preauth(
    preauth_integrity: &mut Option<PreauthIntegrityState>,
    request_packet: &[u8],
    response_packet: &[u8],
    success: bool,
) -> Result<(), CoreError> {
    let Some(preauth_integrity) = preauth_integrity.as_mut() else {
        return Ok(());
    };

    preauth_integrity.update(request_packet)?;
    if !success {
        preauth_integrity.update(response_packet)?;
    }

    Ok(())
}

pub(super) fn verify_final_session_setup_response(
    dialect: Dialect,
    header: &Header,
    response_packet: &[u8],
    signing_required: bool,
    signing: Option<&SigningState>,
) -> Result<(), CoreError> {
    if header.status != NtStatus::SUCCESS.to_u32() || dialect != Dialect::Smb311 {
        return Ok(());
    }

    if !header.flags.contains(HeaderFlags::SIGNED) {
        if signing_required {
            return Err(CoreError::InvalidResponse(
                "SMB 3.1.1 final session setup response must be signed",
            ));
        }
        return Ok(());
    }

    let Some(signing) = signing else {
        return Ok(());
    };

    signing.verify_packet(response_packet)
}

pub(super) fn derive_signing_state(
    dialect: Dialect,
    session_key: Option<&[u8]>,
    preauth_integrity: Option<&PreauthIntegrityState>,
) -> Result<Option<Arc<SigningState>>, CoreError> {
    let Some(session_key) = session_key else {
        return Ok(None);
    };

    let signing = match dialect {
        Dialect::Smb202 | Dialect::Smb210 => SigningState {
            algorithm: SigningAlgorithm::HmacSha256,
            key: session_key.to_vec(),
        },
        Dialect::Smb300 | Dialect::Smb302 => SigningState {
            algorithm: SigningAlgorithm::Aes128Cmac,
            key: derive_key(
                session_key,
                b"SMB2AESCMAC\0",
                b"SmbSign\0",
                Header::SIGNATURE_RANGE.len() * 8,
            )?,
        },
        Dialect::Smb311 => {
            let preauth_integrity = preauth_integrity.ok_or(CoreError::InvalidResponse(
                "SMB 3.1.1 session is missing preauth integrity state",
            ))?;
            SigningState {
                algorithm: SigningAlgorithm::Aes128Cmac,
                key: derive_key(
                    session_key,
                    b"SMBSigningKey\0",
                    &preauth_integrity.hash_value,
                    Header::SIGNATURE_RANGE.len() * 8,
                )?,
            }
        }
    };

    Ok(Some(Arc::new(signing)))
}

pub(super) fn derive_smb_session_key(session_key: Option<&[u8]>) -> Option<Vec<u8>> {
    let session_key = session_key?;
    let mut smb_session_key = session_key[..session_key.len().min(16)].to_vec();
    if smb_session_key.len() < 16 {
        smb_session_key.resize(16, 0);
    }
    Some(smb_session_key)
}

pub(super) fn derive_encryption_state(
    negotiated: &NegotiateResponse,
    session_key: Option<&[u8]>,
    preauth_integrity: Option<&PreauthIntegrityState>,
) -> Result<Option<Arc<EncryptionState>>, CoreError> {
    if transport_level_security_accepted(negotiated)? {
        return Ok(None);
    }
    let Some(session_key) = session_key else {
        return Ok(None);
    };
    let Some(cipher) = negotiated_cipher(negotiated)? else {
        return Ok(None);
    };
    let key_material = match cipher {
        CipherId::Aes256Ccm | CipherId::Aes256Gcm => session_key.to_vec(),
        _ => derive_smb_session_key(Some(session_key))
            .ok_or(CoreError::InvalidInput("missing SMB session key"))?,
    };

    let keys = derive_encryption_keys(
        negotiated.dialect_revision,
        cipher,
        &key_material,
        None,
        preauth_integrity.map(|state| state.hash_value.as_slice()),
    )?;
    Ok(Some(Arc::new(EncryptionState::new(
        negotiated.dialect_revision,
        keys,
    ))))
}

pub(super) fn transport_level_security_accepted(
    negotiated: &NegotiateResponse,
) -> Result<bool, CoreError> {
    if negotiated.dialect_revision != Dialect::Smb311 {
        return Ok(false);
    }

    let mut accepted = false;
    for context in &negotiated.negotiate_contexts {
        let Some(capabilities) = context.as_transport_capabilities()? else {
            continue;
        };
        if accepted {
            return Err(CoreError::InvalidResponse(
                "SMB 3.1.1 negotiate response contained multiple transport-capabilities contexts",
            ));
        }
        accepted = capabilities
            .flags
            .contains(TransportCapabilityFlags::ACCEPT_TRANSPORT_LEVEL_SECURITY);
    }
    Ok(accepted)
}

pub(super) fn negotiated_cipher(
    negotiated: &NegotiateResponse,
) -> Result<Option<CipherId>, CoreError> {
    match negotiated.dialect_revision {
        Dialect::Smb202 | Dialect::Smb210 => Ok(None),
        Dialect::Smb300 | Dialect::Smb302 => {
            if negotiated
                .capabilities
                .contains(GlobalCapabilities::ENCRYPTION)
            {
                Ok(Some(CipherId::Aes128Ccm))
            } else {
                Ok(None)
            }
        }
        Dialect::Smb311 => {
            let mut selected = None;
            for context in &negotiated.negotiate_contexts {
                let Some(capabilities) = context.as_encryption_capabilities()? else {
                    continue;
                };
                if capabilities.ciphers.len() != 1 {
                    return Err(CoreError::InvalidResponse(
                        "SMB 3.1.1 negotiate response must select exactly one encryption cipher",
                    ));
                }
                if selected.replace(capabilities.ciphers[0]).is_some() {
                    return Err(CoreError::InvalidResponse(
                        "SMB 3.1.1 negotiate response contained multiple encryption contexts",
                    ));
                }
            }

            if negotiated
                .capabilities
                .contains(GlobalCapabilities::ENCRYPTION)
                && selected.is_none()
            {
                return Err(CoreError::InvalidResponse(
                    "SMB 3.1.1 negotiate response did not select an encryption cipher",
                ));
            }

            Ok(selected)
        }
    }
}

pub(super) fn session_signing_required(
    client_signing_mode: SigningMode,
    server_signing_mode: SigningMode,
    session_flags: SessionFlags,
) -> bool {
    if session_flags
        .intersects(SessionFlags::IS_GUEST | SessionFlags::IS_NULL | SessionFlags::ENCRYPT_DATA)
    {
        return false;
    }

    client_signing_mode.contains(SigningMode::REQUIRED)
        || server_signing_mode.contains(SigningMode::REQUIRED)
}

pub(super) fn session_encryption_required(
    negotiated: &NegotiateResponse,
    session_flags: SessionFlags,
) -> Result<bool, CoreError> {
    if transport_level_security_accepted(negotiated)? {
        return Ok(false);
    }
    Ok(session_flags.contains(SessionFlags::ENCRYPT_DATA))
}

pub(super) fn tree_encryption_required(
    negotiated: &NegotiateResponse,
    session_flags: SessionFlags,
    share_flags: ShareFlags,
) -> Result<bool, CoreError> {
    Ok(session_encryption_required(negotiated, session_flags)?
        || share_flags.contains(ShareFlags::ENCRYPT_DATA))
}

fn derive_key(
    key: &[u8],
    label: &[u8],
    context: &[u8],
    output_bits: usize,
) -> Result<Vec<u8>, CoreError> {
    if output_bits == 0 {
        return Err(CoreError::InvalidInput(
            "derived SMB key length must be nonzero",
        ));
    }

    let output_bytes = output_bits / 8;
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

pub(super) fn session_setup_security_mode(
    signing_mode: SigningMode,
) -> SessionSetupSecurityMode {
    let mut security_mode = SessionSetupSecurityMode::empty();
    if signing_mode.contains(SigningMode::ENABLED) {
        security_mode |= SessionSetupSecurityMode::SIGNING_ENABLED;
    }
    if signing_mode.contains(SigningMode::REQUIRED) {
        security_mode |= SessionSetupSecurityMode::SIGNING_REQUIRED;
    }
    security_mode
}
