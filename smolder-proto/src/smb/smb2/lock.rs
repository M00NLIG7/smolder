//! SMB2 lock request and response bodies.

use bitflags::bitflags;
use bytes::{BufMut, BytesMut};

use super::create::FileId;
use super::{check_fixed_structure_size, get_u16, get_u32, get_u64};
use crate::smb::ProtocolError;

bitflags! {
    /// SMB2 lock element flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct LockFlags: u32 {
        /// Shared byte-range lock.
        const SHARED_LOCK = 0x0000_0001;
        /// Exclusive byte-range lock.
        const EXCLUSIVE_LOCK = 0x0000_0002;
        /// Unlock a previously locked range.
        const UNLOCK = 0x0000_0004;
        /// Fail immediately on conflict.
        const FAIL_IMMEDIATELY = 0x0000_0010;
    }
}

/// Single byte-range lock or unlock entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LockElement {
    /// Starting byte offset of the range.
    pub offset: u64,
    /// Length of the range in bytes.
    pub length: u64,
    /// Lock operation flags.
    pub flags: LockFlags,
}

impl LockElement {
    const LEN: usize = 24;

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.put_u64_le(self.offset);
        out.put_u64_le(self.length);
        out.put_u32_le(self.flags.bits());
        out.put_u32_le(0);
    }

    fn decode(input: &mut &[u8]) -> Result<Self, ProtocolError> {
        let offset = get_u64(input, "offset")?;
        let length = get_u64(input, "length")?;
        let flags =
            LockFlags::from_bits(get_u32(input, "flags")?).ok_or(ProtocolError::InvalidField {
                field: "flags",
                reason: "unknown lock flags set",
            })?;
        if !valid_lock_flags(flags) {
            return Err(ProtocolError::InvalidField {
                field: "flags",
                reason: "invalid lock flag combination",
            });
        }
        let _reserved = get_u32(input, "reserved")?;
        Ok(Self {
            offset,
            length,
            flags,
        })
    }
}

/// SMB2 lock request body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockRequest {
    /// Number identifying the lock sequence within the indexed slot.
    pub lock_sequence_number: u8,
    /// Lock sequence slot index for replay-aware dialects.
    pub lock_sequence_index: u32,
    /// File handle on which to perform locking.
    pub file_id: FileId,
    /// Lock or unlock ranges.
    pub locks: Vec<LockElement>,
}

impl LockRequest {
    /// Creates a lock request for an open file handle.
    #[must_use]
    pub fn for_file(file_id: FileId, locks: Vec<LockElement>) -> Self {
        Self {
            lock_sequence_number: 0,
            lock_sequence_index: 0,
            file_id,
            locks,
        }
    }

    /// Serializes the request body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(24 + (self.locks.len() * LockElement::LEN));
        out.put_u16_le(48);
        out.put_u16_le(self.locks.len() as u16);
        out.put_u32_le(pack_lock_sequence(
            self.lock_sequence_number,
            self.lock_sequence_index,
        ));
        out.put_u64_le(self.file_id.persistent);
        out.put_u64_le(self.file_id.volatile);
        for lock in &self.locks {
            lock.encode_into(&mut out);
        }
        out.to_vec()
    }

    /// Parses the request body.
    pub fn decode(body: &[u8]) -> Result<Self, ProtocolError> {
        let mut input = body;
        check_fixed_structure_size(get_u16(&mut input, "structure_size")?, 48, "structure_size")?;
        let lock_count = usize::from(get_u16(&mut input, "lock_count")?);
        if lock_count == 0 {
            return Err(ProtocolError::InvalidField {
                field: "lock_count",
                reason: "lock count must be at least one",
            });
        }
        let sequence = get_u32(&mut input, "lock_sequence")?;
        let lock_sequence_number = (sequence & 0x0f) as u8;
        let lock_sequence_index = sequence >> 4;
        let file_id = FileId {
            persistent: get_u64(&mut input, "file_id_persistent")?,
            volatile: get_u64(&mut input, "file_id_volatile")?,
        };
        let mut locks = Vec::with_capacity(lock_count);
        for _ in 0..lock_count {
            locks.push(LockElement::decode(&mut input)?);
        }
        Ok(Self {
            lock_sequence_number,
            lock_sequence_index,
            file_id,
            locks,
        })
    }
}

/// SMB2 lock response body.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LockResponse;

impl LockResponse {
    /// Serializes the response body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(4);
        out.put_u16_le(4);
        out.put_u16_le(0);
        out.to_vec()
    }

    /// Parses the response body.
    pub fn decode(body: &[u8]) -> Result<Self, ProtocolError> {
        let mut input = body;
        check_fixed_structure_size(get_u16(&mut input, "structure_size")?, 4, "structure_size")?;
        let _reserved = get_u16(&mut input, "reserved")?;
        Ok(Self)
    }
}

fn pack_lock_sequence(lock_sequence_number: u8, lock_sequence_index: u32) -> u32 {
    ((lock_sequence_index & 0x0fff_ffff) << 4) | u32::from(lock_sequence_number & 0x0f)
}

fn valid_lock_flags(flags: LockFlags) -> bool {
    flags == LockFlags::SHARED_LOCK
        || flags == LockFlags::EXCLUSIVE_LOCK
        || flags == LockFlags::UNLOCK
        || flags == (LockFlags::SHARED_LOCK | LockFlags::FAIL_IMMEDIATELY)
        || flags == (LockFlags::EXCLUSIVE_LOCK | LockFlags::FAIL_IMMEDIATELY)
}

#[cfg(test)]
mod tests {
    use super::{LockElement, LockFlags, LockRequest, LockResponse};
    use crate::smb::smb2::FileId;
    use crate::smb::ProtocolError;

    #[test]
    fn lock_request_roundtrips() {
        let request = LockRequest {
            lock_sequence_number: 3,
            lock_sequence_index: 7,
            file_id: FileId {
                persistent: 0x1122_3344_5566_7788,
                volatile: 0x8877_6655_4433_2211,
            },
            locks: vec![
                LockElement {
                    offset: 4096,
                    length: 1024,
                    flags: LockFlags::EXCLUSIVE_LOCK | LockFlags::FAIL_IMMEDIATELY,
                },
                LockElement {
                    offset: 8192,
                    length: 2048,
                    flags: LockFlags::UNLOCK,
                },
            ],
        };

        let encoded = request.encode();
        let decoded = LockRequest::decode(&encoded).expect("lock request should decode");
        assert_eq!(decoded, request);
    }

    #[test]
    fn lock_request_rejects_invalid_lock_flags() {
        let mut encoded = LockRequest {
            lock_sequence_number: 0,
            lock_sequence_index: 0,
            file_id: FileId {
                persistent: 1,
                volatile: 2,
            },
            locks: vec![LockElement {
                offset: 0,
                length: 1,
                flags: LockFlags::SHARED_LOCK,
            }],
        }
        .encode();

        encoded[40..44].copy_from_slice(
            &(LockFlags::SHARED_LOCK | LockFlags::EXCLUSIVE_LOCK)
                .bits()
                .to_le_bytes(),
        );

        let error = LockRequest::decode(&encoded).expect_err("invalid flags should fail");
        assert!(matches!(
            error,
            ProtocolError::InvalidField {
                field: "flags",
                reason: "invalid lock flag combination",
            }
        ));
    }

    #[test]
    fn lock_response_roundtrips() {
        let response = LockResponse;
        let encoded = response.encode();
        let decoded = LockResponse::decode(&encoded).expect("lock response should decode");
        assert_eq!(decoded, response);
    }
}
