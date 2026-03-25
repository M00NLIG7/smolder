//! Smolder tools crate
//!
//! Copyright (c) 2025 M00NLIG7

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod remote_exec;
pub mod prelude {
    //! Common types and traits

    pub use crate::remote_exec::{
        ExecMode, ExecRequest, ExecResult, InteractiveReader, InteractiveSession, InteractiveStdin,
        InteractiveWaiter, RemoteExecBuilder, RemoteExecClient,
    };
}
