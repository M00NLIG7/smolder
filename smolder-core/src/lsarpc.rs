//! Typed `lsarpc` DCE/RPC helpers built on top of named pipes.

use smolder_proto::rpc::{SyntaxId, Uuid};

use crate::error::CoreError;
use crate::rpc::PipeRpcClient;
use crate::transport::TokioTcpTransport;

const LSARPC_SYNTAX: SyntaxId = SyntaxId::new(
    Uuid::new(
        0x1234_5778,
        0x1234,
        0xabcd,
        [0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab],
    ),
    0,
    0,
);
const LSARPC_CONTEXT_ID: u16 = 0;
const LSAR_CLOSE_OPNUM: u16 = 0;
const LSAR_QUERY_INFORMATION_POLICY_OPNUM: u16 = 7;
const LSAR_OPEN_POLICY2_OPNUM: u16 = 44;
const LSAR_QUERY_INFORMATION_POLICY2_OPNUM: u16 = 46;
const POLICY_PRIMARY_DOMAIN_INFORMATION_CLASS: u32 = 3;
const POLICY_ACCOUNT_DOMAIN_INFORMATION_CLASS: u32 = 5;
const POLICY_VIEW_LOCAL_INFORMATION: u32 = 0x0000_0001;
const RPC_S_OP_RANGE_ERROR: u32 = 0x1c01_0002;

/// Default policy access mask used by the typed LSARPC client.
pub const DEFAULT_POLICY_ACCESS: u32 = POLICY_VIEW_LOCAL_INFORMATION;

/// Minimal LSA SID representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsaSid {
    /// SID revision.
    pub revision: u8,
    /// SID identifier authority bytes.
    pub identifier_authority: [u8; 6],
    /// SID subauthorities.
    pub sub_authorities: Vec<u32>,
}

/// Decoded `POLICY_PRIMARY_DOMAIN_INFO` or `POLICY_ACCOUNT_DOMAIN_INFO`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsaDomainInfo {
    /// NetBIOS-style domain or workgroup name.
    pub name: String,
    /// Optional domain SID.
    pub sid: Option<LsaSid>,
}

/// Typed `lsarpc` client over an already-open RPC transport.
#[derive(Debug)]
pub struct LsarpcClient<T = TokioTcpTransport> {
    rpc: PipeRpcClient<T>,
    context_id: u16,
    policy_handle: [u8; 20],
    desired_access: u32,
}

impl<T> LsarpcClient<T> {
    /// The `lsarpc` abstract syntax identifier.
    pub const SYNTAX: SyntaxId = LSARPC_SYNTAX;

    /// The default `lsarpc` presentation context identifier.
    pub const CONTEXT_ID: u16 = LSARPC_CONTEXT_ID;

    /// Returns the underlying RPC transport.
    #[must_use]
    pub fn rpc(&self) -> &PipeRpcClient<T> {
        &self.rpc
    }

    /// Returns the access mask requested when opening the policy handle.
    #[must_use]
    pub fn desired_access(&self) -> u32 {
        self.desired_access
    }

    /// Consumes the client and returns the underlying RPC transport.
    #[must_use]
    pub fn into_rpc(self) -> PipeRpcClient<T> {
        self.rpc
    }
}

impl<T> LsarpcClient<T>
where
    T: crate::transport::SmbTransport + Send,
{
    /// Performs the default `lsarpc` bind and `LsarOpenPolicy2`.
    pub async fn bind(mut rpc: PipeRpcClient<T>) -> Result<Self, CoreError> {
        rpc.bind_context(Self::CONTEXT_ID, Self::SYNTAX).await?;
        let desired_access = DEFAULT_POLICY_ACCESS;
        let response = rpc
            .call(
                Self::CONTEXT_ID,
                LSAR_OPEN_POLICY2_OPNUM,
                encode_open_policy2_request(desired_access),
            )
            .await?;
        let policy_handle = parse_open_policy2_response(&response)?;
        Ok(Self {
            rpc,
            context_id: Self::CONTEXT_ID,
            policy_handle,
            desired_access,
        })
    }

    /// Queries `PolicyPrimaryDomainInformation`.
    pub async fn primary_domain_info(&mut self) -> Result<LsaDomainInfo, CoreError> {
        let response = self
            .query_policy_information(POLICY_PRIMARY_DOMAIN_INFORMATION_CLASS)
            .await?;
        parse_primary_domain_info_response(&response)
    }

    /// Queries `PolicyAccountDomainInformation`.
    pub async fn account_domain_info(&mut self) -> Result<LsaDomainInfo, CoreError> {
        let response = self
            .query_policy_information(POLICY_ACCOUNT_DOMAIN_INFORMATION_CLASS)
            .await?;
        parse_account_domain_info_response(&response)
    }

    /// Closes the policy handle and returns the underlying RPC transport.
    pub async fn close(mut self) -> Result<PipeRpcClient<T>, CoreError> {
        let response = self
            .rpc
            .call(
                self.context_id,
                LSAR_CLOSE_OPNUM,
                encode_close_handle_request(self.policy_handle),
            )
            .await?;
        parse_close_handle_response(&response)?;
        Ok(self.rpc)
    }

    async fn query_policy_information(&mut self, info_class: u32) -> Result<Vec<u8>, CoreError> {
        let request = encode_query_policy_request(self.policy_handle, info_class);
        match self
            .rpc
            .call(
                self.context_id,
                LSAR_QUERY_INFORMATION_POLICY2_OPNUM,
                request.clone(),
            )
            .await
        {
            Ok(response) => Ok(response),
            Err(error) if should_retry_legacy_policy_query(&error) => {
                self.rpc
                    .call(
                        self.context_id,
                        LSAR_QUERY_INFORMATION_POLICY_OPNUM,
                        request,
                    )
                    .await
            }
            Err(error) => Err(error),
        }
    }
}

fn should_retry_legacy_policy_query(error: &CoreError) -> bool {
    matches!(
        error,
        CoreError::RemoteOperation {
            operation: "rpc_fault",
            code: RPC_S_OP_RANGE_ERROR,
        }
    )
}

fn encode_open_policy2_request(desired_access: u32) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32);
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&24_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&desired_access.to_le_bytes());
    bytes
}

fn parse_open_policy2_response(response: &[u8]) -> Result<[u8; 20], CoreError> {
    if response.len() < 24 {
        return Err(CoreError::InvalidResponse(
            "LsarOpenPolicy2 response was too short",
        ));
    }
    let mut policy_handle = [0_u8; 20];
    policy_handle.copy_from_slice(&response[0..20]);
    let status = u32::from_le_bytes(response[20..24].try_into().expect("status slice"));
    if status != 0 {
        return Err(CoreError::RemoteOperation {
            operation: "LsarOpenPolicy2",
            code: status,
        });
    }
    Ok(policy_handle)
}

fn encode_query_policy_request(policy_handle: [u8; 20], info_class: u32) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(24);
    bytes.extend_from_slice(&policy_handle);
    bytes.extend_from_slice(&info_class.to_le_bytes());
    bytes
}

fn parse_primary_domain_info_response(response: &[u8]) -> Result<LsaDomainInfo, CoreError> {
    let mut reader = NdrReader::new(response);
    let referent = reader.read_u32("PolicyInformation")?;
    if referent == 0 {
        return Err(CoreError::InvalidResponse(
            "LsarQueryInformationPolicy2 did not return primary domain data",
        ));
    }
    reader.consume_optional_union_discriminant(
        POLICY_PRIMARY_DOMAIN_INFORMATION_CLASS,
        "PrimaryDomainInfoClass",
    )?;

    let name_header = reader.read_unicode_string_header("PrimaryDomainName")?;
    let sid_referent = reader.read_u32("PrimaryDomainSidReferent")?;
    let name = reader.read_deferred_unicode_string(name_header, "PrimaryDomainName")?;
    let sid = if sid_referent == 0 {
        None
    } else {
        Some(reader.read_sid("PrimaryDomainSid")?)
    };
    let status = reader.read_u32("LsarQueryInformationPolicy2Status")?;
    if status != 0 {
        return Err(CoreError::RemoteOperation {
            operation: "LsarQueryInformationPolicy2(PrimaryDomainInformation)",
            code: status,
        });
    }

    Ok(LsaDomainInfo { name, sid })
}

fn parse_account_domain_info_response(response: &[u8]) -> Result<LsaDomainInfo, CoreError> {
    let mut reader = NdrReader::new(response);
    let referent = reader.read_u32("PolicyInformation")?;
    if referent == 0 {
        return Err(CoreError::InvalidResponse(
            "LsarQueryInformationPolicy2 did not return account domain data",
        ));
    }
    reader.consume_optional_union_discriminant(
        POLICY_ACCOUNT_DOMAIN_INFORMATION_CLASS,
        "AccountDomainInfoClass",
    )?;

    let name_header = reader.read_unicode_string_header("AccountDomainName")?;
    let sid_referent = reader.read_u32("AccountDomainSidReferent")?;
    let name = reader.read_deferred_unicode_string(name_header, "AccountDomainName")?;
    let sid = if sid_referent == 0 {
        None
    } else {
        Some(reader.read_sid("AccountDomainSid")?)
    };
    let status = reader.read_u32("LsarQueryInformationPolicy2Status")?;
    if status != 0 {
        return Err(CoreError::RemoteOperation {
            operation: "LsarQueryInformationPolicy2(AccountDomainInformation)",
            code: status,
        });
    }

    Ok(LsaDomainInfo { name, sid })
}

fn encode_close_handle_request(handle: [u8; 20]) -> Vec<u8> {
    handle.to_vec()
}

fn parse_close_handle_response(response: &[u8]) -> Result<(), CoreError> {
    if response.len() < 24 {
        return Err(CoreError::InvalidResponse(
            "LsarClose response was too short",
        ));
    }
    let status = u32::from_le_bytes(response[20..24].try_into().expect("status slice"));
    if status != 0 {
        return Err(CoreError::RemoteOperation {
            operation: "LsarClose",
            code: status,
        });
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct UnicodeStringHeader {
    length: usize,
    maximum_length: usize,
    referent: u32,
}

struct NdrReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> NdrReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn align(&mut self, alignment: usize, field: &'static str) -> Result<(), CoreError> {
        let padding = (alignment - (self.offset % alignment)) % alignment;
        if self.remaining() < padding {
            return Err(CoreError::InvalidResponse(field));
        }
        self.offset += padding;
        Ok(())
    }

    fn consume_optional_union_discriminant(
        &mut self,
        expected: u32,
        field: &'static str,
    ) -> Result<(), CoreError> {
        if self.remaining() < 4 {
            return Ok(());
        }
        if self.peek_u32(field)? == expected {
            let _ = self.read_u32(field)?;
        }
        Ok(())
    }

    fn peek_u32(&self, field: &'static str) -> Result<u32, CoreError> {
        let padding = (4 - (self.offset % 4)) % 4;
        if self.remaining() < padding + 4 {
            return Err(CoreError::InvalidResponse(field));
        }
        let offset = self.offset + padding;
        Ok(u32::from_le_bytes(
            self.bytes[offset..offset + 4]
                .try_into()
                .expect("u32 slice should decode"),
        ))
    }

    fn read_u32(&mut self, field: &'static str) -> Result<u32, CoreError> {
        self.align(4, field)?;
        if self.remaining() < 4 {
            return Err(CoreError::InvalidResponse(field));
        }
        let value = u32::from_le_bytes(
            self.bytes[self.offset..self.offset + 4]
                .try_into()
                .expect("u32 slice should decode"),
        );
        self.offset += 4;
        Ok(value)
    }

    fn read_u16(&mut self, field: &'static str) -> Result<u16, CoreError> {
        if self.remaining() < 2 {
            return Err(CoreError::InvalidResponse(field));
        }
        let value = u16::from_le_bytes(
            self.bytes[self.offset..self.offset + 2]
                .try_into()
                .expect("u16 slice should decode"),
        );
        self.offset += 2;
        Ok(value)
    }

    fn read_unicode_string_header(
        &mut self,
        field: &'static str,
    ) -> Result<UnicodeStringHeader, CoreError> {
        let length = self.read_u16(field)? as usize;
        let maximum_length = self.read_u16(field)? as usize;
        let referent = self.read_u32(field)?;
        Ok(UnicodeStringHeader {
            length,
            maximum_length,
            referent,
        })
    }

    fn read_deferred_unicode_string(
        &mut self,
        header: UnicodeStringHeader,
        field: &'static str,
    ) -> Result<String, CoreError> {
        if header.referent == 0 {
            return Ok(String::new());
        }
        self.align(4, field)?;
        let max_count = self.read_u32(field)? as usize;
        if max_count * 2 < header.length || header.maximum_length < header.length {
            return Err(CoreError::InvalidResponse(field));
        }
        let expected_units = header.length / 2;
        let mut units_to_read = max_count;
        if self.remaining() >= 8 {
            let offset = u32::from_le_bytes(
                self.bytes[self.offset..self.offset + 4]
                    .try_into()
                    .expect("offset slice should decode"),
            ) as usize;
            let actual_count = u32::from_le_bytes(
                self.bytes[self.offset + 4..self.offset + 8]
                    .try_into()
                    .expect("actual count slice should decode"),
            ) as usize;
            if offset <= max_count && actual_count <= max_count && actual_count >= expected_units {
                self.offset += 8;
                units_to_read = actual_count;
            }
        }

        let mut code_units = Vec::with_capacity(units_to_read);
        for _ in 0..units_to_read {
            code_units.push(self.read_u16(field)?);
        }
        self.align(4, field)?;
        String::from_utf16(&code_units[..expected_units])
            .map_err(|_| CoreError::InvalidResponse("failed to decode lsarpc UTF-16 string"))
    }

    fn read_sid(&mut self, field: &'static str) -> Result<LsaSid, CoreError> {
        self.align(4, field)?;
        if self.remaining() >= 12 {
            let possible_sub_authority_count = u32::from_le_bytes(
                self.bytes[self.offset..self.offset + 4]
                    .try_into()
                    .expect("sub-authority count slice should decode"),
            ) as usize;
            let revision = self.bytes[self.offset + 4];
            let actual_sub_authority_count = self.bytes[self.offset + 5] as usize;
            if revision == 1 && possible_sub_authority_count == actual_sub_authority_count {
                self.offset += 4;
            }
        }
        if self.remaining() < 8 {
            return Err(CoreError::InvalidResponse(field));
        }
        let revision = self.bytes[self.offset];
        let sub_authority_count = self.bytes[self.offset + 1] as usize;
        let mut identifier_authority = [0_u8; 6];
        identifier_authority.copy_from_slice(&self.bytes[self.offset + 2..self.offset + 8]);
        self.offset += 8;

        let mut sub_authorities = Vec::with_capacity(sub_authority_count);
        for _ in 0..sub_authority_count {
            sub_authorities.push(self.read_u32(field)?);
        }

        Ok(LsaSid {
            revision,
            identifier_authority,
            sub_authorities,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        encode_close_handle_request, encode_open_policy2_request, encode_query_policy_request,
        parse_account_domain_info_response, parse_close_handle_response,
        parse_open_policy2_response, parse_primary_domain_info_response,
        should_retry_legacy_policy_query, LsaDomainInfo, LsaSid, DEFAULT_POLICY_ACCESS,
        POLICY_ACCOUNT_DOMAIN_INFORMATION_CLASS, POLICY_PRIMARY_DOMAIN_INFORMATION_CLASS,
        RPC_S_OP_RANGE_ERROR,
    };
    use crate::error::CoreError;

    struct ResponseWriter {
        head: Vec<u8>,
        deferred: Vec<u8>,
        next_referent: u32,
    }

    impl ResponseWriter {
        fn new() -> Self {
            Self {
                head: Vec::new(),
                deferred: Vec::new(),
                next_referent: 1,
            }
        }

        fn write_u32(&mut self, value: u32) {
            self.align_head(4);
            self.head.extend_from_slice(&value.to_le_bytes());
        }

        fn write_u16(&mut self, value: u16) {
            self.head.extend_from_slice(&value.to_le_bytes());
        }

        fn write_unicode_string_header(&mut self, value: &str) {
            let encoded = value.encode_utf16().collect::<Vec<_>>();
            let byte_len = (encoded.len() * 2) as u16;
            self.write_u16(byte_len);
            self.write_u16(byte_len);
            let referent = self.take_referent();
            self.write_u32(referent);

            self.align_deferred(4);
            self.deferred
                .extend_from_slice(&(encoded.len() as u32).to_le_bytes());
            for code_unit in encoded {
                self.deferred.extend_from_slice(&code_unit.to_le_bytes());
            }
            self.align_deferred(4);
        }

        fn write_varying_unicode_string_header(&mut self, value: &str) {
            let encoded = value.encode_utf16().collect::<Vec<_>>();
            let byte_len = (encoded.len() * 2) as u16;
            self.write_u16(byte_len);
            self.write_u16(byte_len);
            let referent = self.take_referent();
            self.write_u32(referent);

            self.align_deferred(4);
            self.deferred
                .extend_from_slice(&(encoded.len() as u32).to_le_bytes());
            self.deferred.extend_from_slice(&0_u32.to_le_bytes());
            self.deferred
                .extend_from_slice(&(encoded.len() as u32).to_le_bytes());
            for code_unit in encoded {
                self.deferred.extend_from_slice(&code_unit.to_le_bytes());
            }
            self.align_deferred(4);
        }

        fn write_null_unicode_string_header(&mut self) {
            self.write_u16(0);
            self.write_u16(0);
            self.write_u32(0);
        }

        fn write_sid_pointer(&mut self, sid: Option<&LsaSid>) {
            match sid {
                Some(sid) => {
                    let referent = self.take_referent();
                    self.write_u32(referent);
                    self.align_deferred(4);
                    self.deferred.push(sid.revision);
                    self.deferred.push(sid.sub_authorities.len() as u8);
                    self.deferred.extend_from_slice(&sid.identifier_authority);
                    for sub_authority in &sid.sub_authorities {
                        self.deferred
                            .extend_from_slice(&sub_authority.to_le_bytes());
                    }
                }
                None => self.write_u32(0),
            }
        }

        fn write_sid_pointer_with_conformant_count(&mut self, sid: Option<&LsaSid>) {
            match sid {
                Some(sid) => {
                    let referent = self.take_referent();
                    self.write_u32(referent);
                    self.align_deferred(4);
                    self.deferred
                        .extend_from_slice(&(sid.sub_authorities.len() as u32).to_le_bytes());
                    self.deferred.push(sid.revision);
                    self.deferred.push(sid.sub_authorities.len() as u8);
                    self.deferred.extend_from_slice(&sid.identifier_authority);
                    for sub_authority in &sid.sub_authorities {
                        self.deferred
                            .extend_from_slice(&sub_authority.to_le_bytes());
                    }
                }
                None => self.write_u32(0),
            }
        }

        fn finish_with_status(mut self, status: u32) -> Vec<u8> {
            self.head.extend_from_slice(&self.deferred);
            self.align_head(4);
            self.head.extend_from_slice(&status.to_le_bytes());
            self.head
        }

        fn take_referent(&mut self) -> u32 {
            let value = self.next_referent;
            self.next_referent += 1;
            value
        }

        fn align_head(&mut self, alignment: usize) {
            let padding = (alignment - (self.head.len() % alignment)) % alignment;
            self.head.resize(self.head.len() + padding, 0);
        }

        fn align_deferred(&mut self, alignment: usize) {
            let padding = (alignment - (self.deferred.len() % alignment)) % alignment;
            self.deferred.resize(self.deferred.len() + padding, 0);
        }
    }

    #[test]
    fn open_policy2_request_uses_null_system_name_and_default_object_attributes() {
        assert_eq!(
            encode_open_policy2_request(DEFAULT_POLICY_ACCESS),
            [
                0_u32.to_le_bytes(),
                24_u32.to_le_bytes(),
                0_u32.to_le_bytes(),
                0_u32.to_le_bytes(),
                0_u32.to_le_bytes(),
                0_u32.to_le_bytes(),
                0_u32.to_le_bytes(),
                DEFAULT_POLICY_ACCESS.to_le_bytes(),
            ]
            .concat()
        );
    }

    #[test]
    fn parse_open_policy2_response_decodes_handle() {
        let mut response = vec![0_u8; 24];
        response[0..20].copy_from_slice(&[
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        ]);
        response[20..24].copy_from_slice(&0_u32.to_le_bytes());

        let handle = parse_open_policy2_response(&response).expect("handle should decode");
        assert_eq!(
            handle,
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]
        );
    }

    #[test]
    fn query_policy_request_encodes_handle_and_info_class() {
        let request = encode_query_policy_request([0x55; 20], 12);
        assert_eq!(request.len(), 24);
        assert_eq!(&request[0..20], &[0x55; 20]);
        assert_eq!(&request[20..24], &12_u32.to_le_bytes());
    }

    #[test]
    fn parse_primary_domain_info_response_decodes_name_and_sid() {
        let sid = LsaSid {
            revision: 1,
            identifier_authority: [0, 0, 0, 0, 0, 5],
            sub_authorities: vec![21, 42, 84],
        };
        let mut writer = ResponseWriter::new();
        writer.write_u32(1);
        writer.write_unicode_string_header("LAB");
        writer.write_sid_pointer(Some(&sid));

        assert_eq!(
            parse_primary_domain_info_response(&writer.finish_with_status(0))
                .expect("response should decode"),
            LsaDomainInfo {
                name: "LAB".to_owned(),
                sid: Some(sid),
            }
        );
    }

    #[test]
    fn parse_account_domain_info_response_decodes_name_and_sid() {
        let sid = LsaSid {
            revision: 1,
            identifier_authority: [0, 0, 0, 0, 0, 5],
            sub_authorities: vec![21, 42, 84],
        };
        let mut writer = ResponseWriter::new();
        writer.write_u32(1);
        writer.write_unicode_string_header("LAB");
        writer.write_sid_pointer(Some(&sid));

        assert_eq!(
            parse_account_domain_info_response(&writer.finish_with_status(0))
                .expect("response should decode"),
            LsaDomainInfo {
                name: "LAB".to_owned(),
                sid: Some(sid),
            }
        );
    }

    #[test]
    fn parse_primary_domain_info_response_decodes_varying_string_layout() {
        let sid = LsaSid {
            revision: 1,
            identifier_authority: [0, 0, 0, 0, 0, 5],
            sub_authorities: vec![21, 42, 84],
        };
        let mut writer = ResponseWriter::new();
        writer.write_u32(1);
        writer.write_varying_unicode_string_header("WORKGROUP");
        writer.write_sid_pointer(Some(&sid));

        assert_eq!(
            parse_primary_domain_info_response(&writer.finish_with_status(0))
                .expect("response should decode"),
            LsaDomainInfo {
                name: "WORKGROUP".to_owned(),
                sid: Some(sid),
            }
        );
    }

    #[test]
    fn parse_primary_domain_info_response_decodes_union_discriminant_layout() {
        let sid = LsaSid {
            revision: 1,
            identifier_authority: [0, 0, 0, 0, 0, 5],
            sub_authorities: vec![21, 42, 84],
        };
        let mut writer = ResponseWriter::new();
        writer.write_u32(1);
        writer.write_u32(POLICY_PRIMARY_DOMAIN_INFORMATION_CLASS);
        writer.write_varying_unicode_string_header("WORKGROUP");
        writer.write_sid_pointer(Some(&sid));

        assert_eq!(
            parse_primary_domain_info_response(&writer.finish_with_status(0))
                .expect("response should decode"),
            LsaDomainInfo {
                name: "WORKGROUP".to_owned(),
                sid: Some(sid),
            }
        );
    }

    #[test]
    fn parse_account_domain_info_response_decodes_union_and_sid_count_layout() {
        let sid = LsaSid {
            revision: 1,
            identifier_authority: [0, 0, 0, 0, 0, 5],
            sub_authorities: vec![21, 42, 84, 0],
        };
        let mut writer = ResponseWriter::new();
        writer.write_u32(1);
        writer.write_u32(POLICY_ACCOUNT_DOMAIN_INFORMATION_CLASS);
        writer.write_varying_unicode_string_header("B104FD764986");
        writer.write_sid_pointer_with_conformant_count(Some(&sid));

        assert_eq!(
            parse_account_domain_info_response(&writer.finish_with_status(0))
                .expect("response should decode"),
            LsaDomainInfo {
                name: "B104FD764986".to_owned(),
                sid: Some(sid),
            }
        );
    }

    #[test]
    fn parse_close_handle_response_checks_status() {
        let response = [[0_u8; 20].as_slice(), 0_u32.to_le_bytes().as_slice()].concat();
        parse_close_handle_response(&response).expect("close should succeed");
    }

    #[test]
    fn parse_primary_domain_info_response_rejects_null_pointer() {
        let response = [0_u32.to_le_bytes(), 0_u32.to_le_bytes()].concat();
        let error = parse_primary_domain_info_response(&response)
            .expect_err("null policy information should fail");
        assert!(matches!(error, CoreError::InvalidResponse(_)));
    }

    #[test]
    fn parse_account_domain_info_response_rejects_remote_error() {
        let mut writer = ResponseWriter::new();
        writer.write_u32(1);
        writer.write_null_unicode_string_header();
        writer.write_sid_pointer(None);
        let error = parse_account_domain_info_response(&writer.finish_with_status(5))
            .expect_err("non-zero status should fail");
        assert!(matches!(error, CoreError::RemoteOperation { .. }));
    }

    #[test]
    fn close_handle_request_uses_handle_bytes_directly() {
        let request = encode_close_handle_request([0xaa; 20]);
        assert_eq!(request, vec![0xaa; 20]);
    }

    #[test]
    fn op_range_rpc_fault_retries_with_legacy_policy_query() {
        assert!(should_retry_legacy_policy_query(
            &CoreError::RemoteOperation {
                operation: "rpc_fault",
                code: RPC_S_OP_RANGE_ERROR,
            }
        ));
        assert!(!should_retry_legacy_policy_query(
            &CoreError::RemoteOperation {
                operation: "rpc_fault",
                code: 5,
            }
        ));
    }
}
