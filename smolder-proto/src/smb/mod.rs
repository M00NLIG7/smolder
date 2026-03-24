//! SMB protocol primitives.

mod error;
pub mod netbios;
pub mod smb2;

pub use error::ProtocolError;
