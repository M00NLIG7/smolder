# smolder-proto

`smolder-proto` provides the typed SMB2/3 and DCE/RPC wire layer for Smolder.

It focuses on packet structures, framing, codec logic, and validation primitives
that higher layers can build on without mixing transport or workflow concerns.

Use this crate when you need:

- typed SMB2/3 request and response bodies
- typed DCE/RPC PDUs and auth trailers
- NetBIOS session framing and SMB3 transform codecs
- a safe wire-model layer beneath your own transport/session logic

Most users should start one layer higher with `smolder-smb-core` unless they
are building protocol tooling, analysis, or a custom SMB/RPC client stack.

Start here:

- crate docs: [smolder-proto/src/lib.rs](/Users/cmagana/Projects/smolder/smolder-proto/src/lib.rs)
- support policy:
  <https://github.com/M00NLIG7/smolder/blob/main/docs/reference/support-policy.md>
- fuzz/property/bench coverage:
  <https://github.com/M00NLIG7/smolder/blob/main/docs/testing/fuzzing.md>
  and
  <https://github.com/M00NLIG7/smolder/blob/main/docs/testing/benchmarks.md>

Repository: <https://github.com/M00NLIG7/smolder>
