# smolder-core Public API Notes

This document captures the intended public surface of `smolder-smb-core` as of
the current `0.2.x` line.

The broader release/support contract for the workspace lives in
[support-policy.md](/Users/cmagana/Projects/smolder/docs/reference/support-policy.md).

The goal is not "everything public in the crate is equally ergonomic." The goal
is to make the recommended integration path explicit so downstream users build
on the right abstractions.

## Intended Entry Points

For most users, the supported starting surface is:

- `smolder_core::prelude`
- `smolder_core::facade::{Client, ClientBuilder}`
- `smolder_core::facade::{Session, Share, File, OpenOptions, FileMetadata, DirectoryEntry}`
- `smolder_core::client::Connection`
- `smolder_core::pipe::{SmbSessionConfig, NamedPipe, PipeAccess, connect_tree}`
- `smolder_core::rpc::PipeRpcClient`
- `smolder_core::auth::{NtlmCredentials, NtlmAuthenticator}`
- `smolder_core::auth::{KerberosCredentials, KerberosAuthenticator, KerberosTarget}`
  when the `kerberos` feature is enabled
- `smolder_core::auth::{KerberosBackendKind, KerberosCredentialSourceKind}`
  when you need to inspect which backend/capability path the current Kerberos
  integration is using
- `smolder_core::dfs::{UncPath, DfsReferral, resolve_unc_path}`
- `smolder_core::error::CoreError`
- `smolder_core::transport::{Transport, TokioTcpTransport}`

These are the APIs new examples, docs, and downstream integrations should
prefer.

For the `0.2.x` line, the preferred split is:

- use `facade::Client` when you want an embedded SMB client that gets you to an
  authenticated session or tree connection quickly
- use `facade::Share` and `facade::File` when you want routine file reads,
  writes, stats, deletes, directory listing, directory creation, renames, and
  durable/resilient opens without driving raw `CREATE` / `READ` / `WRITE` /
  `QUERY_INFO` / `QUERY_DIRECTORY` / `SET_INFO` calls yourself
- use `client::Connection` directly when you need full typestate control or are
  implementing new high-level flows inside Smolder itself

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

The current direction for `0.2.x` is:

- prefer additive changes over signature churn
- keep `prelude` curated rather than exhaustive
- avoid moving tool-specific orchestration back into `smolder-core`
- only narrow the public surface when the existing shape is clearly wrong

For Kerberos specifically:

- `kerberos` is the umbrella feature consumers should enable
- `kerberos-sspi` remains the default password-backed backend
- `kerberos-gssapi` adds Unix ticket-cache and keytab backends without
  changing the top-level `KerberosCredentials` / `KerberosAuthenticator` API
- `kerberos-gssapi` is independent of `kerberos-sspi`, so Unix GSS/Kerberos
  libraries are only pulled in when that backend is requested explicitly
- backend-specific capability expansion should happen behind the stable
  `KerberosCredentials` / `KerberosAuthenticator` surface rather than by
  replacing those top-level types

The next follow-on work after this audit should focus on examples and docs for
the intended entry points rather than adding more raw public types.
