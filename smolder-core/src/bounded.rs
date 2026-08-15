use crate::error::CoreError;

pub(crate) fn copy_bytes(bytes: &[u8], resource: &'static str) -> Result<Vec<u8>, CoreError> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(bytes.len())
        .map_err(|_| CoreError::AllocationFailed(resource))?;
    output.extend_from_slice(bytes);
    Ok(output)
}

pub(crate) fn utf16_string(
    code_units: &[u16],
    resource: &'static str,
    invalid: &'static str,
) -> Result<String, CoreError> {
    let maximum_utf8_len = code_units
        .len()
        .checked_mul(3)
        .ok_or(CoreError::ResourceLimit {
            resource,
            requested: u64::MAX,
            maximum: u64::MAX,
        })?;
    let mut decoded = String::new();
    decoded
        .try_reserve_exact(maximum_utf8_len)
        .map_err(|_| CoreError::AllocationFailed(resource))?;
    for character in char::decode_utf16(code_units.iter().copied()) {
        decoded.push(character.map_err(|_| CoreError::InvalidResponse(invalid))?);
    }
    Ok(decoded)
}
