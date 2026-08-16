//! Reusable DCE/RPC transport primitives built on top of named pipes.

use smolder_proto::rpc::{
    AuthLevel, AuthVerifier, BindAckPdu, BindPdu, Packet, PacketFlags, RequestPdu, ResponsePdu,
    SyntaxId, Uuid,
};

use crate::auth::{NtlmCredentials, NtlmRpcBindHandshake, NtlmRpcPacketIntegrity};
use crate::client::{Connection, TreeConnected};
use crate::error::CoreError;
use crate::pipe::NamedPipe;
use crate::transport::TokioTcpTransport;

const RPC_DEFAULT_FRAGMENT_SIZE: u16 = 4_280;

/// Reusable DCE/RPC client over a named pipe transport.
#[derive(Debug)]
pub struct PipeRpcClient<T = TokioTcpTransport> {
    pipe: NamedPipe<T>,
    next_call_id: u32,
    bound_contexts: Vec<(u16, SyntaxId)>,
    max_outbound_fragment: Option<u16>,
    max_inbound_fragment: Option<u16>,
    ntlm_packet_integrity: Option<NtlmRpcPacketIntegrity>,
    poisoned: bool,
}

impl<T> PipeRpcClient<T> {
    /// Wraps an opened named pipe.
    #[must_use]
    pub fn new(pipe: NamedPipe<T>) -> Self {
        Self {
            pipe,
            next_call_id: 1,
            bound_contexts: Vec::new(),
            max_outbound_fragment: None,
            max_inbound_fragment: None,
            ntlm_packet_integrity: None,
            poisoned: false,
        }
    }

    /// Returns the underlying named pipe.
    #[must_use]
    pub fn pipe(&self) -> &NamedPipe<T> {
        &self.pipe
    }

    /// Returns whether cancellation, I/O failure, or protocol mis-correlation made this RPC stream
    /// unsafe to reuse.
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Consumes the RPC client and returns the underlying named pipe.
    ///
    /// If RPC correlation was poisoned, the returned pipe's physical SMB connection is also
    /// invalidated and must be discarded rather than reused.
    #[must_use]
    pub fn into_pipe(mut self) -> NamedPipe<T> {
        if self.poisoned {
            self.pipe.invalidate_connection();
        }
        self.pipe
    }

    /// Enables automatic NTLM RPC packet-integrity signing and verification.
    #[must_use]
    pub fn with_ntlm_packet_integrity(
        mut self,
        ntlm_packet_integrity: NtlmRpcPacketIntegrity,
    ) -> Self {
        self.ntlm_packet_integrity = Some(ntlm_packet_integrity);
        self
    }

    /// Replaces the active NTLM RPC packet-integrity context.
    pub fn set_ntlm_packet_integrity(&mut self, ntlm_packet_integrity: NtlmRpcPacketIntegrity) {
        self.ntlm_packet_integrity = Some(ntlm_packet_integrity);
    }

    fn next_call_id(&mut self) -> Result<u32, CoreError> {
        let current = self.next_call_id;
        self.next_call_id = self
            .next_call_id
            .checked_add(1)
            .ok_or(CoreError::InvalidInput("DCE/RPC call id space exhausted"))?;
        Ok(current)
    }

    fn ensure_usable(&self) -> Result<(), CoreError> {
        if self.poisoned {
            Err(CoreError::ConnectionPoisoned)
        } else {
            Ok(())
        }
    }

    fn remember_bound_context(&mut self, context_id: u16, syntax: SyntaxId) {
        if let Some((_, existing)) = self
            .bound_contexts
            .iter_mut()
            .find(|(bound_id, _)| *bound_id == context_id)
        {
            *existing = syntax;
        } else {
            self.bound_contexts.push((context_id, syntax));
        }
    }

    #[cfg(test)]
    pub(crate) fn assume_bound_context_for_test(&mut self, context_id: u16, syntax: SyntaxId) {
        self.remember_bound_context(context_id, syntax);
    }
}

impl<T> PipeRpcClient<T>
where
    T: crate::transport::SmbTransport + Send,
{
    /// Closes the named-pipe handle and returns the tree-connected SMB connection.
    pub async fn close(self) -> Result<Connection<T, TreeConnected>, CoreError> {
        self.pipe.close().await
    }

    pub(crate) async fn close_after_error(self, error: CoreError) -> CoreError {
        if !self.poisoned {
            let _ = self.pipe.close().await;
        }
        // A poisoned RPC stream is dropped here, closing the physical transport rather than
        // issuing another SMB request on potentially mis-correlated framing.
        error
    }

    /// Sends a bind PDU and returns the raw bind acknowledgement.
    pub async fn bind(
        &mut self,
        context_id: u16,
        abstract_syntax: SyntaxId,
    ) -> Result<BindAckPdu, CoreError> {
        self.bind_with_flags_and_auth(
            context_id,
            abstract_syntax,
            PacketFlags::FIRST_FRAGMENT | PacketFlags::LAST_FRAGMENT,
            None,
        )
        .await
    }

    /// Sends a bind PDU with an optional authentication verifier.
    pub async fn bind_with_auth(
        &mut self,
        context_id: u16,
        abstract_syntax: SyntaxId,
        auth_verifier: Option<AuthVerifier>,
    ) -> Result<BindAckPdu, CoreError> {
        self.bind_with_flags_and_auth(
            context_id,
            abstract_syntax,
            PacketFlags::FIRST_FRAGMENT | PacketFlags::LAST_FRAGMENT,
            auth_verifier,
        )
        .await
    }

    /// Sends a bind PDU with explicit packet flags and an optional authentication verifier.
    pub async fn bind_with_flags_and_auth(
        &mut self,
        context_id: u16,
        abstract_syntax: SyntaxId,
        flags: PacketFlags,
        auth_verifier: Option<AuthVerifier>,
    ) -> Result<BindAckPdu, CoreError> {
        self.ensure_usable()?;
        let call_id = self.next_call_id()?;
        let bind = Packet::Bind(BindPdu {
            call_id,
            flags,
            max_xmit_frag: RPC_DEFAULT_FRAGMENT_SIZE,
            max_recv_frag: RPC_DEFAULT_FRAGMENT_SIZE,
            assoc_group_id: 0,
            context_id,
            abstract_syntax,
            transfer_syntax: SyntaxId::NDR32,
            auth_verifier,
        });
        self.poisoned = true;
        let response = self.pipe.call(bind.encode()).await?;
        let packet = Packet::decode(&response)?;
        let Packet::BindAck(bind_ack) = packet else {
            return Err(CoreError::InvalidResponse("expected rpc bind ack"));
        };
        if bind_ack.call_id != call_id {
            return Err(CoreError::InvalidResponse(
                "rpc bind ack call id did not match the bind request",
            ));
        }
        if !bind_ack
            .flags
            .contains(PacketFlags::FIRST_FRAGMENT | PacketFlags::LAST_FRAGMENT)
        {
            return Err(CoreError::InvalidResponse(
                "rpc bind ack was not a complete first/last fragment",
            ));
        }
        if bind_ack.result.result == 0 && bind_ack.result.transfer_syntax != SyntaxId::NDR32 {
            return Err(CoreError::InvalidResponse(
                "rpc bind ack selected a transfer syntax that was not offered",
            ));
        }
        if bind_ack.result.result == 0
            && (bind_ack.result.reason != 0
                || bind_ack.max_xmit_frag < 16
                || bind_ack.max_recv_frag < 16)
        {
            return Err(CoreError::InvalidResponse(
                "rpc bind ack returned invalid accepted-context parameters",
            ));
        }
        if bind_ack.result.result == 0 {
            self.remember_bound_context(context_id, abstract_syntax);
            let outbound = bind_ack.max_recv_frag.min(RPC_DEFAULT_FRAGMENT_SIZE);
            let inbound = bind_ack.max_xmit_frag.min(RPC_DEFAULT_FRAGMENT_SIZE);
            self.max_outbound_fragment = Some(
                self.max_outbound_fragment
                    .map_or(outbound, |current| current.min(outbound)),
            );
            self.max_inbound_fragment = Some(
                self.max_inbound_fragment
                    .map_or(inbound, |current| current.min(inbound)),
            );
        }
        self.poisoned = false;
        Ok(bind_ack)
    }

    /// Sends a bind PDU and requires an acceptance result.
    pub async fn bind_context(
        &mut self,
        context_id: u16,
        abstract_syntax: SyntaxId,
    ) -> Result<BindAckPdu, CoreError> {
        let bind_ack = self.bind(context_id, abstract_syntax).await?;
        if bind_ack.result.result == 0 {
            return Ok(bind_ack);
        }
        Err(CoreError::RemoteOperation {
            operation: "rpc_bind",
            code: u32::from(bind_ack.result.reason),
        })
    }

    /// Performs a secure NTLM bind and sends the follow-up `rpc_auth_3` leg.
    pub async fn bind_ntlm(
        &mut self,
        context_id: u16,
        abstract_syntax: SyntaxId,
        credentials: NtlmCredentials,
        auth_level: AuthLevel,
    ) -> Result<BindAckPdu, CoreError> {
        self.ntlm_packet_integrity = None;

        let mut handshake = NtlmRpcBindHandshake::new(credentials, auth_level, context_id)?;
        let bind_ack = self
            .bind_with_flags_and_auth(
                context_id,
                abstract_syntax,
                handshake.bind_flags(),
                Some(handshake.initial_auth_verifier()?),
            )
            .await?;
        if bind_ack.result.result != 0 {
            return Err(CoreError::RemoteOperation {
                operation: "rpc_bind",
                code: u32::from(bind_ack.result.reason),
            });
        }

        // The accepted bind has advanced server-side authentication state. Any local token
        // validation failure or cancellation before AUTH3 completes makes this stream unusable.
        self.poisoned = true;
        let completed = handshake.complete(&bind_ack)?;
        let auth3 = Packet::RpcAuth3(completed.auth3).encode();
        let maximum_outbound = self.max_outbound_fragment.unwrap_or(u16::MAX);
        if auth3.len() > usize::from(maximum_outbound) {
            return Err(CoreError::ResourceLimit {
                resource: "negotiated DCE/RPC outbound fragment",
                requested: auth3.len() as u64,
                maximum: u64::from(maximum_outbound),
            });
        }
        self.pipe.write_all(&auth3).await?;
        self.ntlm_packet_integrity = completed.packet_integrity;
        self.poisoned = false;
        Ok(bind_ack)
    }

    /// Sends a request PDU and returns the decoded response stub bytes.
    pub async fn call(
        &mut self,
        context_id: u16,
        opnum: u16,
        stub_data: Vec<u8>,
    ) -> Result<Vec<u8>, CoreError> {
        let response = self
            .call_with_auth(context_id, opnum, stub_data, None)
            .await?;
        Ok(response.stub_data)
    }

    /// Sends a request PDU and returns the decoded response PDU.
    pub async fn call_with_auth(
        &mut self,
        context_id: u16,
        opnum: u16,
        stub_data: Vec<u8>,
        auth_verifier: Option<AuthVerifier>,
    ) -> Result<ResponsePdu, CoreError> {
        self.call_with_object_pdu(context_id, opnum, None, stub_data, auth_verifier)
            .await
    }

    /// Sends a request PDU with an optional object UUID.
    pub async fn call_with_object(
        &mut self,
        context_id: u16,
        opnum: u16,
        object_uuid: Option<Uuid>,
        stub_data: Vec<u8>,
    ) -> Result<Vec<u8>, CoreError> {
        let response = self
            .call_with_object_pdu(context_id, opnum, object_uuid, stub_data, None)
            .await?;
        Ok(response.stub_data)
    }

    /// Sends a request PDU with an optional object UUID and authentication verifier.
    pub async fn call_with_object_pdu(
        &mut self,
        context_id: u16,
        opnum: u16,
        object_uuid: Option<Uuid>,
        stub_data: Vec<u8>,
        auth_verifier: Option<AuthVerifier>,
    ) -> Result<ResponsePdu, CoreError> {
        self.ensure_usable()?;
        if self.ntlm_packet_integrity.is_some() && auth_verifier.is_some() {
            return Err(CoreError::InvalidInput(
                "rpc auth verifier cannot be supplied when NTLM packet integrity is enabled",
            ));
        }

        if !self
            .bound_contexts
            .iter()
            .any(|(bound_id, _)| *bound_id == context_id)
        {
            return Err(CoreError::InvalidInput(
                "DCE/RPC request used a presentation context that was not bound",
            ));
        }
        let limits = self.pipe.resource_limits();
        if stub_data.len() > limits.max_rpc_stub_size {
            return Err(CoreError::ResourceLimit {
                resource: "DCE/RPC request stub",
                requested: stub_data.len() as u64,
                maximum: limits.max_rpc_stub_size as u64,
            });
        }
        let alloc_hint = u32::try_from(stub_data.len())
            .map_err(|_| CoreError::InvalidInput("DCE/RPC request stub exceeded u32"))?;
        let call_id = self.next_call_id()?;
        let request = RequestPdu {
            call_id,
            flags: PacketFlags::FIRST_FRAGMENT | PacketFlags::LAST_FRAGMENT,
            alloc_hint,
            context_id,
            opnum,
            object_uuid,
            stub_data,
            auth_verifier: auth_verifier.or_else(|| {
                self.ntlm_packet_integrity
                    .as_ref()
                    .map(NtlmRpcPacketIntegrity::placeholder_auth_verifier)
            }),
        };
        let maximum_outbound = self.max_outbound_fragment.unwrap_or(u16::MAX);
        let request_packet =
            if let Some(ntlm_packet_integrity) = self.ntlm_packet_integrity.as_mut() {
                let placeholder_packet = request.encode();
                if placeholder_packet.len() > usize::from(maximum_outbound) {
                    return Err(CoreError::ResourceLimit {
                        resource: "negotiated DCE/RPC outbound fragment",
                        requested: placeholder_packet.len() as u64,
                        maximum: u64::from(maximum_outbound),
                    });
                }
                let signed_verifier =
                    ntlm_packet_integrity.sign_request_verifier(&placeholder_packet)?;
                RequestPdu {
                    auth_verifier: Some(signed_verifier),
                    ..request
                }
                .encode()
            } else {
                request.encode()
            };
        if request_packet.len() > usize::from(maximum_outbound) {
            return Err(CoreError::ResourceLimit {
                resource: "negotiated DCE/RPC outbound fragment",
                requested: request_packet.len() as u64,
                maximum: u64::from(maximum_outbound),
            });
        }

        self.poisoned = true;
        let first_fragment = self.pipe.call(request_packet).await?;
        self.receive_call_response(call_id, context_id, first_fragment)
            .await
    }

    async fn receive_call_response(
        &mut self,
        expected_call_id: u32,
        expected_context_id: u16,
        first_fragment: Vec<u8>,
    ) -> Result<ResponsePdu, CoreError> {
        let limits = self.pipe.resource_limits();
        let mut raw_fragment = first_fragment;
        let mut aggregate = Vec::new();
        let mut first = true;
        let mut fragment_count = 0usize;
        let mut initial_alloc_hint = 0u32;

        loop {
            let maximum_inbound = self.max_inbound_fragment.unwrap_or(u16::MAX);
            if raw_fragment.len() > usize::from(maximum_inbound) {
                return Err(CoreError::ResourceLimit {
                    resource: "negotiated DCE/RPC inbound fragment",
                    requested: raw_fragment.len() as u64,
                    maximum: u64::from(maximum_inbound),
                });
            }
            fragment_count = fragment_count
                .checked_add(1)
                .ok_or(CoreError::InvalidResponse("rpc fragment count overflowed"))?;
            if fragment_count > limits.max_rpc_pages {
                return Err(CoreError::ResourceLimit {
                    resource: "DCE/RPC response fragments",
                    requested: fragment_count as u64,
                    maximum: limits.max_rpc_pages as u64,
                });
            }

            let packet = Packet::decode(&raw_fragment)?;
            match packet {
                Packet::Response(response) => {
                    if response.call_id != expected_call_id {
                        return Err(CoreError::InvalidResponse(
                            "rpc response call id did not match the request",
                        ));
                    }
                    if response.context_id != expected_context_id {
                        return Err(CoreError::InvalidResponse(
                            "rpc response context id did not match the request",
                        ));
                    }
                    if response.cancel_count != 0 {
                        return Err(CoreError::InvalidResponse(
                            "rpc response reported an unexpected cancellation count",
                        ));
                    }
                    if first {
                        if !response.flags.contains(PacketFlags::FIRST_FRAGMENT) {
                            return Err(CoreError::InvalidResponse(
                                "rpc response did not start with a FIRST fragment",
                            ));
                        }
                        initial_alloc_hint = response.alloc_hint;
                    } else if response.flags.contains(PacketFlags::FIRST_FRAGMENT) {
                        return Err(CoreError::InvalidResponse(
                            "rpc response repeated the FIRST fragment flag",
                        ));
                    }
                    if usize::try_from(response.alloc_hint).unwrap_or(usize::MAX)
                        > limits.max_rpc_stub_size
                    {
                        return Err(CoreError::ResourceLimit {
                            resource: "DCE/RPC allocation hint",
                            requested: u64::from(response.alloc_hint),
                            maximum: limits.max_rpc_stub_size as u64,
                        });
                    }

                    if let Some(ntlm_packet_integrity) = self.ntlm_packet_integrity.as_mut() {
                        let verifier =
                            response
                                .auth_verifier
                                .as_ref()
                                .ok_or(CoreError::InvalidResponse(
                                    "expected rpc packet-integrity auth verifier on the response",
                                ))?;
                        ntlm_packet_integrity.verify_response(&raw_fragment, verifier)?;
                    }

                    let new_len = aggregate
                        .len()
                        .checked_add(response.stub_data.len())
                        .ok_or(CoreError::ResourceLimit {
                            resource: "DCE/RPC response stub",
                            requested: u64::MAX,
                            maximum: limits.max_rpc_stub_size as u64,
                        })?;
                    if new_len > limits.max_rpc_stub_size {
                        return Err(CoreError::ResourceLimit {
                            resource: "DCE/RPC response stub",
                            requested: new_len as u64,
                            maximum: limits.max_rpc_stub_size as u64,
                        });
                    }
                    aggregate
                        .try_reserve(response.stub_data.len())
                        .map_err(|_| CoreError::AllocationFailed("DCE/RPC response stub"))?;
                    aggregate.extend_from_slice(&response.stub_data);

                    if response.flags.contains(PacketFlags::LAST_FRAGMENT) {
                        if initial_alloc_hint != 0
                            && aggregate.len()
                                > usize::try_from(initial_alloc_hint).unwrap_or(usize::MAX)
                        {
                            return Err(CoreError::InvalidResponse(
                                "rpc response exceeded its initial allocation hint",
                            ));
                        }
                        self.poisoned = false;
                        return Ok(ResponsePdu {
                            call_id: response.call_id,
                            flags: PacketFlags::FIRST_FRAGMENT | PacketFlags::LAST_FRAGMENT,
                            alloc_hint: initial_alloc_hint,
                            context_id: response.context_id,
                            cancel_count: response.cancel_count,
                            stub_data: aggregate,
                            auth_verifier: response.auth_verifier,
                        });
                    }
                }
                Packet::Fault(fault) => {
                    if fault.call_id != expected_call_id {
                        return Err(CoreError::InvalidResponse(
                            "rpc fault call id did not match the request",
                        ));
                    }
                    if fault.context_id != expected_context_id {
                        return Err(CoreError::InvalidResponse(
                            "rpc fault context id did not match the request",
                        ));
                    }
                    if !first
                        || !fault
                            .flags
                            .contains(PacketFlags::FIRST_FRAGMENT | PacketFlags::LAST_FRAGMENT)
                    {
                        return Err(CoreError::InvalidResponse(
                            "rpc fault was not one complete terminal fragment",
                        ));
                    }
                    if let Some(ntlm_packet_integrity) = self.ntlm_packet_integrity.as_mut() {
                        let verifier =
                            fault
                                .auth_verifier
                                .as_ref()
                                .ok_or(CoreError::InvalidResponse(
                                    "expected rpc packet-integrity auth verifier on the response",
                                ))?;
                        ntlm_packet_integrity.verify_response(&raw_fragment, verifier)?;
                    }
                    self.poisoned = false;
                    return Err(CoreError::RemoteOperation {
                        operation: "rpc_fault",
                        code: fault.status,
                    });
                }
                _ => return Err(CoreError::InvalidResponse("unexpected rpc packet type")),
            }

            first = false;
            raw_fragment = self.pipe.read_pdu().await?;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use smolder_proto::rpc::{
        AuthLevel, AuthType, AuthVerifier, BindAckPdu, BindAckResult, FaultPdu, Packet,
        PacketFlags, RequestPdu, ResponsePdu, SyntaxId, Uuid,
    };
    use smolder_proto::smb::netbios::SessionMessage;
    use smolder_proto::smb::smb2::{
        utf16le, Command, CreateResponse, Dialect, FileAttributes, FileId, GlobalCapabilities,
        Header, MessageId, NegotiateRequest, NegotiateResponse, OplockLevel, ReadResponse,
        ReadResponseFlags, SessionFlags, SessionSetupRequest, SessionSetupResponse,
        SessionSetupSecurityMode, ShareFlags, ShareType, SigningMode, TreeCapabilities,
        TreeConnectRequest, TreeConnectResponse, TreeId, WriteRequest, WriteResponse,
    };
    use smolder_proto::smb::status::NtStatus;

    use crate::auth::{
        AuthError, AuthProvider, NtlmCredentials, NtlmRpcPacketIntegrity, NtlmSessionSecurity,
    };
    use crate::client::{Connection, TreeConnected};
    use crate::error::CoreError;
    use crate::pipe::{NamedPipe, PipeAccess};
    use crate::transport::Transport;

    use super::PipeRpcClient;

    const TEST_SYNTAX: SyntaxId = SyntaxId::new(
        Uuid::new(
            0x367a_bb81,
            0x9844,
            0x35f1,
            [0xad, 0x32, 0x98, 0xf0, 0x38, 0x00, 0x10, 0x03],
        ),
        2,
        0,
    );

    #[derive(Debug)]
    struct ScriptedTransport {
        reads: VecDeque<Vec<u8>>,
        writes: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl ScriptedTransport {
        fn new(reads: Vec<Vec<u8>>, writes: Arc<Mutex<Vec<Vec<u8>>>>) -> Self {
            Self {
                reads: reads.into(),
                writes,
            }
        }
    }

    struct PassthroughAuthProvider(Vec<u8>);

    impl AuthProvider for PassthroughAuthProvider {
        fn initial_token(&mut self, _negotiate: &NegotiateResponse) -> Result<Vec<u8>, AuthError> {
            Ok(self.0.clone())
        }

        fn next_token(&mut self, _incoming: &[u8]) -> Result<Vec<u8>, AuthError> {
            Err(AuthError::InvalidState(
                "passthrough test provider does not support challenge tokens",
            ))
        }
    }

    #[async_trait]
    impl Transport for ScriptedTransport {
        async fn send(&mut self, frame: &[u8]) -> std::io::Result<()> {
            self.writes
                .lock()
                .expect("writes lock")
                .push(frame.to_vec());
            Ok(())
        }

        async fn recv(&mut self) -> std::io::Result<Vec<u8>> {
            let frame = self.reads.pop_front().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "no scripted response")
            })?;
            let session = SessionMessage::decode(&frame).map_err(std::io::Error::other)?;
            let header = Header::decode(&session.payload).map_err(std::io::Error::other)?;
            if header.command != Command::Write {
                return Ok(frame);
            }
            let written = self
                .writes
                .lock()
                .expect("writes lock")
                .iter()
                .rev()
                .find_map(|request_frame| {
                    let request = SessionMessage::decode(request_frame).ok()?;
                    let request_header = Header::decode(&request.payload).ok()?;
                    (request_header.command == Command::Write)
                        .then(|| WriteRequest::decode(&request.payload[Header::LEN..]).ok())
                        .flatten()
                })
                .ok_or_else(|| std::io::Error::other("scripted write response had no request"))?
                .data
                .len();
            Ok(response_frame(
                Command::Write,
                header.status,
                header.message_id.0,
                header.session_id.0,
                header.tree_id.0,
                WriteResponse {
                    count: u32::try_from(written).map_err(std::io::Error::other)?,
                }
                .encode(),
            ))
        }
    }

    #[tokio::test]
    async fn binds_and_returns_bind_ack() {
        let pipe = open_pipe(vec![bind_ack_response_frame()]).await;
        let mut rpc = PipeRpcClient::new(pipe);

        let bind_ack = rpc
            .bind_context(0, TEST_SYNTAX)
            .await
            .expect("bind should succeed");

        assert_eq!(bind_ack.result.result, 0);
        assert_eq!(bind_ack.result.transfer_syntax, SyntaxId::NDR32);
    }

    #[tokio::test]
    async fn into_pipe_returns_underlying_named_pipe() {
        let pipe = open_pipe(vec![]).await;
        let file_id = pipe.file_id();

        let rpc = PipeRpcClient::new(pipe);
        let pipe = rpc.into_pipe();

        assert_eq!(pipe.file_id(), file_id);
    }

    #[tokio::test]
    async fn call_rejects_an_unbound_presentation_context() {
        let pipe = open_pipe(Vec::new()).await;
        let mut rpc = PipeRpcClient::new(pipe);

        let error = rpc
            .call(0, 15, Vec::new())
            .await
            .expect_err("an RPC call before bind must be rejected");
        assert!(matches!(
            error,
            CoreError::InvalidInput(
                "DCE/RPC request used a presentation context that was not bound"
            )
        ));
        assert!(!rpc.is_poisoned());
    }

    #[tokio::test]
    async fn bind_preserves_auth_verifier_on_bind_ack() {
        let verifier = AuthVerifier::new(
            AuthType::WinNt,
            AuthLevel::PacketIntegrity,
            0,
            vec![0x55; 16],
        );
        let pipe = open_pipe(vec![rpc_response_frame(Packet::BindAck(BindAckPdu {
            call_id: 1,
            flags: PacketFlags::FIRST_FRAGMENT | PacketFlags::LAST_FRAGMENT,
            max_xmit_frag: 4280,
            max_recv_frag: 4280,
            assoc_group_id: 0,
            secondary_address: b"\\PIPE\\svcctl\0".to_vec(),
            result: BindAckResult {
                result: 0,
                reason: 0,
                transfer_syntax: SyntaxId::NDR32,
            },
            auth_verifier: Some(verifier.clone()),
        }))])
        .await;
        let mut rpc = PipeRpcClient::new(pipe);

        let bind_ack = rpc
            .bind_with_auth(0, TEST_SYNTAX, Some(verifier.clone()))
            .await
            .expect("bind with auth should succeed");

        assert_eq!(bind_ack.auth_verifier, Some(verifier));
    }

    #[tokio::test]
    async fn bind_uses_standard_rpc_fragment_size() {
        let verifier =
            AuthVerifier::new(AuthType::WinNt, AuthLevel::Connect, 79_231, vec![0x11; 8]);
        let (pipe, writes) =
            open_pipe_with_writes(vec![rpc_response_frame(Packet::BindAck(BindAckPdu {
                call_id: 1,
                flags: PacketFlags::FIRST_FRAGMENT | PacketFlags::LAST_FRAGMENT,
                max_xmit_frag: 4280,
                max_recv_frag: 4280,
                assoc_group_id: 0,
                secondary_address: b"\\PIPE\\svcctl\0".to_vec(),
                result: BindAckResult {
                    result: 0,
                    reason: 0,
                    transfer_syntax: SyntaxId::NDR32,
                },
                auth_verifier: None,
            }))])
            .await;
        let mut rpc = PipeRpcClient::new(pipe);

        rpc.bind_with_auth(0, TEST_SYNTAX, Some(verifier))
            .await
            .expect("bind with auth should succeed");

        let writes = writes.lock().expect("writes lock");
        let bind_packet = decode_nth_rpc_write(&writes, 0).expect("bind write should decode");
        let Packet::Bind(bind) = bind_packet else {
            panic!("expected bind write");
        };
        assert_eq!(bind.max_xmit_frag, 4280);
        assert_eq!(bind.max_recv_frag, 4280);
    }

    #[tokio::test]
    async fn call_returns_stub_data_on_response() {
        let pipe = open_pipe(vec![rpc_response_frame(Packet::Response(ResponsePdu {
            call_id: 1,
            flags: PacketFlags::FIRST_FRAGMENT | PacketFlags::LAST_FRAGMENT,
            alloc_hint: 4,
            context_id: 0,
            cancel_count: 0,
            stub_data: vec![1, 2, 3, 4],
            auth_verifier: None,
        }))])
        .await;
        let mut rpc = bound_rpc(pipe);

        let stub = rpc
            .call(0, 15, vec![0xaa, 0xbb])
            .await
            .expect("rpc call should succeed");

        assert_eq!(stub, vec![1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn rejects_response_with_wrong_call_id_and_poisons_rpc_stream() {
        let pipe = open_pipe(vec![rpc_response_frame(Packet::Response(ResponsePdu {
            call_id: 99,
            flags: PacketFlags::FIRST_FRAGMENT | PacketFlags::LAST_FRAGMENT,
            alloc_hint: 1,
            context_id: 0,
            cancel_count: 0,
            stub_data: vec![0xaa],
            auth_verifier: None,
        }))])
        .await;
        let mut rpc = bound_rpc(pipe);

        let error = rpc
            .call(0, 15, Vec::new())
            .await
            .expect_err("wrong-call response must be rejected");
        assert!(matches!(
            error,
            CoreError::InvalidResponse("rpc response call id did not match the request")
        ));
        assert!(matches!(
            rpc.call(0, 15, Vec::new()).await,
            Err(CoreError::ConnectionPoisoned)
        ));

        let mut pipe = rpc.into_pipe();
        assert!(matches!(
            pipe.write_all(b"must-not-be-sent").await,
            Err(CoreError::ConnectionPoisoned)
        ));
    }

    #[tokio::test]
    async fn reassembles_first_and_last_rpc_response_fragments() {
        let pipe = open_pipe(vec![
            rpc_response_frame_with_message_id(
                Packet::Response(ResponsePdu {
                    call_id: 1,
                    flags: PacketFlags::FIRST_FRAGMENT,
                    alloc_hint: 4,
                    context_id: 0,
                    cancel_count: 0,
                    stub_data: vec![1, 2],
                    auth_verifier: None,
                }),
                6,
            ),
            rpc_response_frame_with_message_id(
                Packet::Response(ResponsePdu {
                    call_id: 1,
                    flags: PacketFlags::LAST_FRAGMENT,
                    alloc_hint: 2,
                    context_id: 0,
                    cancel_count: 0,
                    stub_data: vec![3, 4],
                    auth_verifier: None,
                }),
                7,
            ),
        ])
        .await;
        let mut rpc = bound_rpc(pipe);

        let stub = rpc
            .call(0, 15, Vec::new())
            .await
            .expect("fragmented response should reassemble");

        assert_eq!(stub, vec![1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn preserves_coalesced_trailing_rpc_pdus_for_the_next_call() {
        let first = Packet::Response(ResponsePdu {
            call_id: 1,
            flags: PacketFlags::FIRST_FRAGMENT | PacketFlags::LAST_FRAGMENT,
            alloc_hint: 2,
            context_id: 0,
            cancel_count: 0,
            stub_data: vec![1, 2],
            auth_verifier: None,
        })
        .encode();
        let second = Packet::Response(ResponsePdu {
            call_id: 2,
            flags: PacketFlags::FIRST_FRAGMENT | PacketFlags::LAST_FRAGMENT,
            alloc_hint: 2,
            context_id: 0,
            cancel_count: 0,
            stub_data: vec![3, 4],
            auth_verifier: None,
        })
        .encode();
        let mut coalesced = first;
        coalesced.extend_from_slice(&second);
        let pipe = open_pipe(vec![
            rpc_bytes_response_frame(coalesced, 6),
            response_frame(
                Command::Write,
                NtStatus::SUCCESS.to_u32(),
                7,
                11,
                7,
                WriteResponse { count: 24 }.encode(),
            ),
            response_frame(
                Command::Flush,
                NtStatus::SUCCESS.to_u32(),
                8,
                11,
                7,
                smolder_proto::smb::smb2::FlushResponse.encode(),
            ),
        ])
        .await;
        let mut rpc = bound_rpc(pipe);

        assert_eq!(
            rpc.call(0, 15, Vec::new()).await.expect("first call"),
            vec![1, 2]
        );
        assert_eq!(
            rpc.call(0, 16, Vec::new()).await.expect("second call"),
            vec![3, 4]
        );
    }

    #[tokio::test]
    async fn call_with_auth_returns_response_pdu() {
        let verifier = AuthVerifier::new(
            AuthType::WinNt,
            AuthLevel::PacketIntegrity,
            1,
            vec![0x77; 16],
        );
        let pipe = open_pipe(vec![rpc_response_frame(Packet::Response(ResponsePdu {
            call_id: 1,
            flags: PacketFlags::FIRST_FRAGMENT | PacketFlags::LAST_FRAGMENT,
            alloc_hint: 4,
            context_id: 0,
            cancel_count: 0,
            stub_data: vec![9, 8, 7, 6],
            auth_verifier: Some(verifier.clone()),
        }))])
        .await;
        let mut rpc = bound_rpc(pipe);

        let response = rpc
            .call_with_auth(0, 15, vec![0xaa, 0xbb], Some(verifier.clone()))
            .await
            .expect("authenticated rpc call should succeed");

        assert_eq!(response.stub_data, vec![9, 8, 7, 6]);
        assert_eq!(response.auth_verifier, Some(verifier));
    }

    #[tokio::test]
    async fn call_maps_fault_to_remote_operation() {
        let pipe = open_pipe(vec![rpc_response_frame(Packet::Fault(FaultPdu {
            call_id: 1,
            flags: PacketFlags::FIRST_FRAGMENT | PacketFlags::LAST_FRAGMENT,
            alloc_hint: 0,
            context_id: 0,
            status: 0x1c01_0003,
            stub_data: Vec::new(),
            auth_verifier: None,
        }))])
        .await;
        let mut rpc = bound_rpc(pipe);

        let error = rpc
            .call(0, 15, vec![0xaa, 0xbb])
            .await
            .expect_err("rpc fault should fail");

        match error {
            CoreError::RemoteOperation { operation, code } => {
                assert_eq!(operation, "rpc_fault");
                assert_eq!(code, 0x1c01_0003);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn call_verifies_ntlm_packet_integrity_response() {
        let request_placeholder = Packet::Request(RequestPdu {
            call_id: 1,
            flags: PacketFlags::FIRST_FRAGMENT | PacketFlags::LAST_FRAGMENT,
            alloc_hint: 2,
            context_id: 0,
            opnum: 15,
            object_uuid: None,
            stub_data: vec![0xaa, 0xbb],
            auth_verifier: Some(ntlm_packet_integrity().placeholder_auth_verifier()),
        })
        .encode();
        let response_placeholder = Packet::Response(ResponsePdu {
            call_id: 1,
            flags: PacketFlags::FIRST_FRAGMENT | PacketFlags::LAST_FRAGMENT,
            alloc_hint: 4,
            context_id: 0,
            cancel_count: 0,
            stub_data: vec![1, 2, 3, 4],
            auth_verifier: Some(ntlm_packet_integrity().placeholder_auth_verifier()),
        })
        .encode();

        let mut responder_integrity = ntlm_packet_integrity();
        let _ = responder_integrity
            .sign_request_verifier(&request_placeholder)
            .expect("request signature should advance sequence");
        let response_verifier = responder_integrity
            .sign_response_verifier(&response_placeholder)
            .expect("response signature should succeed");

        let pipe = open_pipe(vec![rpc_response_frame(Packet::Response(ResponsePdu {
            call_id: 1,
            flags: PacketFlags::FIRST_FRAGMENT | PacketFlags::LAST_FRAGMENT,
            alloc_hint: 4,
            context_id: 0,
            cancel_count: 0,
            stub_data: vec![1, 2, 3, 4],
            auth_verifier: Some(response_verifier),
        }))])
        .await;
        let mut rpc = bound_rpc(pipe).with_ntlm_packet_integrity(ntlm_packet_integrity());

        let stub = rpc
            .call(0, 15, vec![0xaa, 0xbb])
            .await
            .expect("rpc call should verify packet integrity");

        assert_eq!(stub, vec![1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn call_requires_response_verifier_when_ntlm_packet_integrity_is_enabled() {
        let pipe = open_pipe(vec![rpc_response_frame(Packet::Response(ResponsePdu {
            call_id: 1,
            flags: PacketFlags::FIRST_FRAGMENT | PacketFlags::LAST_FRAGMENT,
            alloc_hint: 4,
            context_id: 0,
            cancel_count: 0,
            stub_data: vec![1, 2, 3, 4],
            auth_verifier: None,
        }))])
        .await;
        let mut rpc = bound_rpc(pipe).with_ntlm_packet_integrity(ntlm_packet_integrity());

        let error = rpc
            .call(0, 15, vec![0xaa, 0xbb])
            .await
            .expect_err("missing verifier should fail");

        assert_eq!(
            error.to_string(),
            "invalid response: expected rpc packet-integrity auth verifier on the response"
        );
    }

    #[tokio::test]
    async fn bind_ntlm_sends_auth3_and_enables_packet_integrity() {
        let bind_type2 = ntlm_type2_challenge();
        let (pipe, writes) = open_pipe_with_writes(vec![
            rpc_response_frame(Packet::BindAck(BindAckPdu {
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
                    transfer_syntax: SyntaxId::NDR32,
                },
                auth_verifier: Some(AuthVerifier::new(
                    AuthType::WinNt,
                    AuthLevel::PacketIntegrity,
                    79_231,
                    bind_type2,
                )),
            })),
            response_frame(
                Command::Write,
                NtStatus::SUCCESS.to_u32(),
                7,
                11,
                7,
                WriteResponse { count: 144 }.encode(),
            ),
            response_frame(
                Command::Flush,
                NtStatus::SUCCESS.to_u32(),
                8,
                11,
                7,
                smolder_proto::smb::smb2::FlushResponse.encode(),
            ),
        ])
        .await;
        let mut rpc = PipeRpcClient::new(pipe);

        rpc.bind_ntlm(
            0,
            TEST_SYNTAX,
            NtlmCredentials::new("alice", "password")
                .with_domain("DOMAIN")
                .with_workstation("WORKSTATION"),
            AuthLevel::PacketIntegrity,
        )
        .await
        .expect("secure bind should succeed");
        assert!(rpc.ntlm_packet_integrity.is_some());

        let writes = writes.lock().expect("writes lock");
        let auth3_packet = decode_last_rpc_write(&writes).expect("auth3 write should decode");
        match auth3_packet {
            Packet::RpcAuth3(auth3) => {
                assert_eq!(auth3.call_id, 1);
                assert_eq!(auth3.auth_verifier.auth_type, AuthType::WinNt);
                assert_eq!(auth3.auth_verifier.auth_level, AuthLevel::PacketIntegrity);
                assert_eq!(auth3.auth_verifier.auth_context_id, 79_231);
                assert_eq!(&auth3.auth_verifier.auth_value[..8], b"NTLMSSP\0");
            }
            other => panic!("expected rpc_auth_3 write, got {other:?}"),
        }
    }

    fn ntlm_packet_integrity() -> NtlmRpcPacketIntegrity {
        ntlm_packet_integrity_with_context(1)
    }

    fn ntlm_packet_integrity_with_context(auth_context_id: u32) -> NtlmRpcPacketIntegrity {
        NtlmRpcPacketIntegrity::new(
            &[0x44; 16],
            NtlmSessionSecurity::new(true, true, true, false),
            auth_context_id,
        )
        .expect("packet integrity context")
    }

    async fn open_pipe(reads: Vec<Vec<u8>>) -> NamedPipe<ScriptedTransport> {
        let (connection, _) = build_tree_connection(reads).await;
        NamedPipe::open(connection, "svcctl", PipeAccess::ReadWrite)
            .await
            .expect("pipe open should succeed")
    }

    fn bound_rpc(pipe: NamedPipe<ScriptedTransport>) -> PipeRpcClient<ScriptedTransport> {
        let mut rpc = PipeRpcClient::new(pipe);
        rpc.remember_bound_context(0, TEST_SYNTAX);
        rpc
    }

    async fn open_pipe_with_writes(
        reads: Vec<Vec<u8>>,
    ) -> (NamedPipe<ScriptedTransport>, Arc<Mutex<Vec<Vec<u8>>>>) {
        let (connection, writes) = build_tree_connection(reads).await;
        let pipe = NamedPipe::open(connection, "svcctl", PipeAccess::ReadWrite)
            .await
            .expect("pipe open should succeed");
        (pipe, writes)
    }

    fn bind_ack_response_frame() -> Vec<u8> {
        rpc_response_frame(Packet::BindAck(BindAckPdu {
            call_id: 1,
            flags: PacketFlags::FIRST_FRAGMENT | PacketFlags::LAST_FRAGMENT,
            max_xmit_frag: 4280,
            max_recv_frag: 4280,
            assoc_group_id: 0,
            secondary_address: b"\\PIPE\\svcctl\0".to_vec(),
            result: BindAckResult {
                result: 0,
                reason: 0,
                transfer_syntax: SyntaxId::NDR32,
            },
            auth_verifier: None,
        }))
    }

    fn rpc_response_frame(packet: Packet) -> Vec<u8> {
        rpc_response_frame_with_message_id(packet, 6)
    }

    fn rpc_response_frame_with_message_id(packet: Packet, message_id: u64) -> Vec<u8> {
        rpc_bytes_response_frame(packet.encode(), message_id)
    }

    fn rpc_bytes_response_frame(packet: Vec<u8>, message_id: u64) -> Vec<u8> {
        let mut header = Header::new(Command::Read, MessageId(message_id));
        header.flags |= smolder_proto::smb::smb2::HeaderFlags::SERVER_TO_REDIR;
        header.status = NtStatus::SUCCESS.to_u32();
        header.session_id = smolder_proto::smb::smb2::SessionId(11);
        header.tree_id = TreeId(7);

        let mut smb_packet = header.encode();
        smb_packet.extend_from_slice(
            &ReadResponse {
                data_remaining: 0,
                flags: ReadResponseFlags::empty(),
                data: packet,
            }
            .encode(),
        );
        SessionMessage::new(smb_packet)
            .encode()
            .expect("frame should encode")
    }

    async fn build_tree_connection(
        reads: Vec<Vec<u8>>,
    ) -> (
        Connection<ScriptedTransport, TreeConnected>,
        Arc<Mutex<Vec<Vec<u8>>>>,
    ) {
        let negotiate_response = NegotiateResponse {
            security_mode: SigningMode::ENABLED,
            dialect_revision: Dialect::Smb302,
            negotiate_contexts: Vec::new(),
            server_guid: *b"server-guid-0001",
            capabilities: GlobalCapabilities::LARGE_MTU,
            max_transact_size: 65_536,
            max_read_size: 65_536,
            max_write_size: 65_536,
            system_time: 1,
            server_start_time: 1,
            security_buffer: Vec::new(),
        };
        let session_response = SessionSetupResponse {
            session_flags: SessionFlags::empty(),
            security_buffer: Vec::new(),
        };
        let tree_response = TreeConnectResponse {
            share_type: ShareType::Pipe,
            share_flags: ShareFlags::empty(),
            capabilities: TreeCapabilities::empty(),
            maximal_access: 0x0012_019f,
        };
        let create_response = CreateResponse {
            oplock_level: OplockLevel::None,
            file_attributes: FileAttributes::NORMAL,
            allocation_size: 0,
            end_of_file: 0,
            file_id: FileId {
                persistent: 1,
                volatile: 2,
            },
            create_contexts: Vec::new(),
        };

        let mut scripted_reads = vec![
            response_frame(
                Command::Negotiate,
                NtStatus::SUCCESS.to_u32(),
                0,
                0,
                0,
                negotiate_response.encode(),
            ),
            response_frame(
                Command::SessionSetup,
                NtStatus::SUCCESS.to_u32(),
                1,
                11,
                0,
                session_response.encode(),
            ),
            response_frame(
                Command::TreeConnect,
                NtStatus::SUCCESS.to_u32(),
                2,
                11,
                7,
                tree_response.encode(),
            ),
            response_frame(
                Command::Create,
                NtStatus::SUCCESS.to_u32(),
                3,
                11,
                7,
                create_response.encode(),
            ),
            response_frame(
                Command::Write,
                NtStatus::SUCCESS.to_u32(),
                4,
                11,
                7,
                WriteResponse { count: 72 }.encode(),
            ),
            response_frame(
                Command::Flush,
                NtStatus::SUCCESS.to_u32(),
                5,
                11,
                7,
                smolder_proto::smb::smb2::FlushResponse.encode(),
            ),
        ];
        scripted_reads.extend(reads);

        let writes = Arc::new(Mutex::new(Vec::new()));
        let transport = ScriptedTransport::new(scripted_reads, Arc::clone(&writes));
        let connection = Connection::new(transport);
        let negotiate_request = NegotiateRequest {
            security_mode: SigningMode::ENABLED,
            capabilities: GlobalCapabilities::LARGE_MTU,
            client_guid: *b"client-guid-0001",
            dialects: vec![Dialect::Smb210, Dialect::Smb302],
            negotiate_contexts: Vec::new(),
        };
        let session_request = SessionSetupRequest {
            flags: 0,
            security_mode: SessionSetupSecurityMode::SIGNING_ENABLED,
            capabilities: 0,
            channel: 0,
            security_buffer: vec![0x60, 0x48],
            previous_session_id: 0,
        };
        let connection = connection
            .negotiate(&negotiate_request)
            .await
            .expect("negotiate should succeed");
        let connection = connection
            .authenticate(&mut PassthroughAuthProvider(
                session_request.security_buffer.clone(),
            ))
            .await
            .expect("session setup should succeed");
        let connection = connection
            .tree_connect(&TreeConnectRequest::from_unc(r"\\server\IPC$"))
            .await
            .expect("tree connect should succeed");
        (connection, writes)
    }

    fn decode_last_rpc_write(
        writes: &[Vec<u8>],
    ) -> Result<Packet, smolder_proto::smb::ProtocolError> {
        decode_nth_rpc_write(writes, 0)
    }

    fn decode_nth_rpc_write(
        writes: &[Vec<u8>],
        reverse_index: usize,
    ) -> Result<Packet, smolder_proto::smb::ProtocolError> {
        let mut rpc_writes = writes
            .iter()
            .rev()
            .filter_map(|frame| {
                let session = SessionMessage::decode(frame).ok()?;
                let header = Header::decode(&session.payload).ok()?;
                if header.command != Command::Write {
                    return None;
                }
                let write_request = WriteRequest::decode(&session.payload[Header::LEN..]).ok()?;
                Packet::decode(&write_request.data).ok()
            })
            .collect::<Vec<_>>();
        if reverse_index >= rpc_writes.len() {
            panic!(
                "requested rpc write index {reverse_index} but only {} writes were captured",
                rpc_writes.len()
            );
        }
        Ok(rpc_writes.remove(reverse_index))
    }

    fn ntlm_type2_challenge() -> Vec<u8> {
        let target_info = encode_target_info(&[
            (0x0001, utf16le("SERVER")),
            (0x0002, utf16le("DOMAIN")),
            (0x0003, utf16le("server.example")),
            (0x0007, 9_999u64.to_le_bytes().to_vec()),
        ]);
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

    fn response_frame(
        command: Command,
        status: u32,
        message_id: u64,
        session_id: u64,
        tree_id: u32,
        body: Vec<u8>,
    ) -> Vec<u8> {
        let mut header = Header::new(command, MessageId(message_id));
        header.flags |= smolder_proto::smb::smb2::HeaderFlags::SERVER_TO_REDIR;
        header.status = status;
        header.session_id = smolder_proto::smb::smb2::SessionId(session_id);
        header.tree_id = TreeId(tree_id);

        let mut packet = header.encode();
        packet.extend_from_slice(&body);
        SessionMessage::new(packet)
            .encode()
            .expect("response should frame")
    }
}
