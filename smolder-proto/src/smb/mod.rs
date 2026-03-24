//! SMB protocol primitives.

mod error;
pub mod netbios;
pub mod smb2;
pub mod status;

pub use error::ProtocolError;
