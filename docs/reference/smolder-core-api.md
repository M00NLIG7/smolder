# smolder-core Public API Notes

This document captures the intended public surface of `smolder-smb-core` as of
the current `0.1.x` line.

The goal is not "everything public in the crate is equally ergonomic." The goal
is to make the recommended integration path explicit so downstream users build
on the right abstractions.

## Intended Entry Points

For most users, the supported starting surface is:

- `smolder_core::prelude`
- `smolder_core::client::Connection`
- `smolder_core::pipe::{SmbSessionConfig, NamedPipe, PipeAccess, connect_tree}`
- `smolder_core::rpc::PipeRpcClient`
- `smolder_core::auth::{NtlmCredentials, NtlmAuthenticator}`
- `smolder_core::auth::{KerberosCredentials, KerberosAuthenticator, KerberosTarget}`
  when the `kerberos` feature is enabled
- `smolder_core::dfs::{UncPath, DfsReferral, resolve_unc_path}`
- `smolder_core::error::CoreError`
- `smolder_core::transport::{Transport, TokioTcpTransport}`

These are the APIs new examples, docs, and downstream integrations should
prefer.

## Public But Expert-Oriented

Some public types are intentionally lower-level:

- typestate session-state structs in `client`
- SMB signing/encryption helpers in `crypto`
- NTLM RPC integrity helpers in `auth`
- DFS referral conversion helpers that operate on decoded protocol responses

These remain public because they are useful for advanced integrations and test
fixtures, but they are not the recommended first stop for new consumers.

Two especially internal session-state helpers are now hidden from generated
rustdoc:

- `client::PreauthIntegrityState`
- `client::SigningState`

They remain public for compatibility, but they are internal connection-state
machinery rather than primary API concepts.

## Compatibility Direction

The current direction for `0.1.x` is:

- prefer additive changes over signature churn
- keep `prelude` curated rather than exhaustive
- avoid moving tool-specific orchestration back into `smolder-core`
- only narrow the public surface when the existing shape is clearly wrong

The next follow-on work after this audit should focus on examples and docs for
the intended entry points rather than adding more raw public types.
