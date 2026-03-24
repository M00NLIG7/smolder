//! Minimal SPNEGO token encoding and decoding for NTLM over SMB.

use super::AuthError;

const SPNEGO_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
const NTLM_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];
pub(crate) const NEG_STATE_ACCEPT_COMPLETE: u8 = 0;
pub(crate) const NEG_STATE_REJECT: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NegTokenResp {
    pub(crate) neg_state: Option<u8>,
    pub(crate) response_token: Option<Vec<u8>>,
    pub(crate) mech_list_mic: Option<Vec<u8>>,
}

pub(crate) fn encode_neg_token_init_ntlm(mech_token: &[u8]) -> Vec<u8> {
    let mech_types = ntlm_mech_types();
    let neg_token_init = encode_sequence(
        &[
            encode_explicit(0, &mech_types),
            encode_explicit(2, &encode_tlv(0x04, mech_token)),
        ]
        .concat(),
    );

    encode_tlv(
        0x60,
        &[
            encode_tlv(0x06, SPNEGO_OID),
            encode_explicit(0, &neg_token_init),
        ]
        .concat(),
    )
}

pub(crate) fn ntlm_mech_types() -> Vec<u8> {
    encode_sequence(&encode_tlv(0x06, NTLM_OID))
}

pub(crate) fn encode_neg_token_resp_ntlm(response_token: &[u8]) -> Vec<u8> {
    encode_neg_token_resp(None, Some(response_token), None)
}

pub(crate) fn encode_neg_token_resp(
    neg_state: Option<u8>,
    response_token: Option<&[u8]>,
    mech_list_mic: Option<&[u8]>,
) -> Vec<u8> {
    let mut fields = Vec::new();
    if let Some(neg_state) = neg_state {
        fields.extend_from_slice(&encode_explicit(0, &encode_tlv(0x0a, &[neg_state])));
    }
    if let Some(response_token) = response_token {
        fields.extend_from_slice(&encode_explicit(2, &encode_tlv(0x04, response_token)));
    }
    if let Some(mech_list_mic) = mech_list_mic {
        fields.extend_from_slice(&encode_explicit(3, &encode_tlv(0x04, mech_list_mic)));
    }

    let neg_token_resp = encode_sequence(&fields);
    encode_explicit(1, &neg_token_resp)
}

pub(crate) fn extract_mech_token(token: &[u8]) -> Result<Vec<u8>, AuthError> {
    let token = if token.first() == Some(&0x60) {
        let (tag, content, rest) = read_tlv(token)?;
        if tag != 0x60 || !rest.is_empty() {
            return Err(AuthError::InvalidToken(
                "invalid SPNEGO initial context token",
            ));
        }

        let (oid_tag, oid, inner) = read_tlv(content)?;
        if oid_tag != 0x06 || oid != SPNEGO_OID {
            return Err(AuthError::InvalidToken("unexpected SPNEGO mechanism oid"));
        }
        inner
    } else {
        token
    };

    let (choice_tag, choice_content, rest) = read_tlv(token)?;
    if !rest.is_empty() {
        return Err(AuthError::InvalidToken("trailing SPNEGO data"));
    }
    if choice_tag != 0xa0 && choice_tag != 0xa1 {
        return Err(AuthError::InvalidToken("unexpected SPNEGO choice tag"));
    }

    let (seq_tag, seq_content, seq_rest) = read_tlv(choice_content)?;
    if seq_tag != 0x30 || !seq_rest.is_empty() {
        return Err(AuthError::InvalidToken("invalid SPNEGO sequence"));
    }

    let mut fields = seq_content;
    while !fields.is_empty() {
        let (tag, content, rest) = read_tlv(fields)?;
        if tag == 0xa2 {
            let (octet_tag, octets, octet_rest) = read_tlv(content)?;
            if octet_tag != 0x04 || !octet_rest.is_empty() {
                return Err(AuthError::InvalidToken("invalid SPNEGO mech token field"));
            }
            return Ok(octets.to_vec());
        }
        fields = rest;
    }

    Err(AuthError::InvalidToken("SPNEGO response token missing"))
}

pub(crate) fn parse_neg_token_resp(token: &[u8]) -> Result<NegTokenResp, AuthError> {
    let (choice_tag, choice_content, rest) = read_tlv(token)?;
    if choice_tag != 0xa1 || !rest.is_empty() {
        return Err(AuthError::InvalidToken("expected negTokenResp"));
    }

    let (seq_tag, seq_content, seq_rest) = read_tlv(choice_content)?;
    if seq_tag != 0x30 || !seq_rest.is_empty() {
        return Err(AuthError::InvalidToken("invalid negTokenResp sequence"));
    }

    let mut neg_state = None;
    let mut response_token = None;
    let mut mech_list_mic = None;
    let mut fields = seq_content;
    while !fields.is_empty() {
        let (tag, content, rest) = read_tlv(fields)?;
        match tag {
            0xa0 => {
                let (enum_tag, value, enum_rest) = read_tlv(content)?;
                if enum_tag != 0x0a || !enum_rest.is_empty() || value.len() != 1 {
                    return Err(AuthError::InvalidToken("invalid negState field"));
                }
                neg_state = Some(value[0]);
            }
            0xa2 => {
                let (octet_tag, value, octet_rest) = read_tlv(content)?;
                if octet_tag != 0x04 || !octet_rest.is_empty() {
                    return Err(AuthError::InvalidToken("invalid responseToken field"));
                }
                response_token = Some(value.to_vec());
            }
            0xa3 => {
                let (octet_tag, value, octet_rest) = read_tlv(content)?;
                if octet_tag != 0x04 || !octet_rest.is_empty() {
                    return Err(AuthError::InvalidToken("invalid mechListMIC field"));
                }
                mech_list_mic = Some(value.to_vec());
            }
            _ => {}
        }
        fields = rest;
    }

    Ok(NegTokenResp {
        neg_state,
        response_token,
        mech_list_mic,
    })
}

fn encode_sequence(content: &[u8]) -> Vec<u8> {
    encode_tlv(0x30, content)
}

fn encode_explicit(tag_number: u8, content: &[u8]) -> Vec<u8> {
    encode_tlv(0xa0 | tag_number, content)
}

fn encode_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + content.len());
    out.push(tag);
    encode_length(content.len(), &mut out);
    out.extend_from_slice(content);
    out
}

fn encode_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
        return;
    }

    let mut bytes = Vec::new();
    let mut value = len;
    while value > 0 {
        bytes.push((value & 0xff) as u8);
        value >>= 8;
    }
    bytes.reverse();

    out.push(0x80 | (bytes.len() as u8));
    out.extend_from_slice(&bytes);
}

fn read_tlv(input: &[u8]) -> Result<(u8, &[u8], &[u8]), AuthError> {
    let Some((&tag, rest)) = input.split_first() else {
        return Err(AuthError::InvalidToken("missing tag"));
    };
    let (len, rest) = read_length(rest)?;
    if rest.len() < len {
        return Err(AuthError::InvalidToken("truncated ASN.1 content"));
    }

    Ok((tag, &rest[..len], &rest[len..]))
}

fn read_length(input: &[u8]) -> Result<(usize, &[u8]), AuthError> {
    let Some((&first, rest)) = input.split_first() else {
        return Err(AuthError::InvalidToken("missing length"));
    };

    if first & 0x80 == 0 {
        return Ok((usize::from(first), rest));
    }

    let byte_count = usize::from(first & 0x7f);
    if byte_count == 0 || rest.len() < byte_count {
        return Err(AuthError::InvalidToken("invalid length encoding"));
    }

    let mut value = 0usize;
    for byte in &rest[..byte_count] {
        value = (value << 8) | usize::from(*byte);
    }
    Ok((value, &rest[byte_count..]))
}

#[cfg(test)]
mod tests {
    use super::{
        encode_neg_token_init_ntlm, encode_neg_token_resp, encode_neg_token_resp_ntlm,
        extract_mech_token, parse_neg_token_resp, NEG_STATE_ACCEPT_COMPLETE,
    };

    #[test]
    fn initial_token_roundtrips_mech_token() {
        let token = encode_neg_token_init_ntlm(b"NTLMSSP\0demo");
        let extracted = extract_mech_token(&token).expect("token should parse");

        assert_eq!(extracted, b"NTLMSSP\0demo");
    }

    #[test]
    fn response_parser_extracts_state_and_mech_token() {
        let token = vec![
            0xa1, 0x12, 0x30, 0x10, 0xa0, 0x03, 0x0a, 0x01, 0x01, 0xa2, 0x09, 0x04, 0x07, b'N',
            b'T', b'L', b'M', b'S', b'S', b'P',
        ];

        let parsed = parse_neg_token_resp(&token).expect("token should parse");
        assert_eq!(parsed.neg_state, Some(1));
        assert_eq!(parsed.response_token, Some(b"NTLMSSP".to_vec()));
    }

    #[test]
    fn follow_up_token_roundtrips_mech_token() {
        let token = encode_neg_token_resp_ntlm(b"NTLMSSP\0auth");
        let extracted = extract_mech_token(&token).expect("token should parse");

        assert_eq!(extracted, b"NTLMSSP\0auth");
    }

    #[test]
    fn response_parser_extracts_mech_list_mic() {
        let token = encode_neg_token_resp(Some(NEG_STATE_ACCEPT_COMPLETE), None, Some(b"mic"));

        let parsed = parse_neg_token_resp(&token).expect("token should parse");
        assert_eq!(parsed.neg_state, Some(NEG_STATE_ACCEPT_COMPLETE));
        assert_eq!(parsed.response_token, None);
        assert_eq!(parsed.mech_list_mic, Some(b"mic".to_vec()));
    }
}
