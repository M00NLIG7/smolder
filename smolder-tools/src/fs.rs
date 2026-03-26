//! High-level SMB file APIs built on top of the core typestate client.

// Keep the high-level facade compiled from `smolder-tools` while the original
// source file is transitioned out of the dirty `smolder-core` worktree.
#[path = "../../smolder-core/src/fs.rs"]
mod implementation;

pub use implementation::*;
