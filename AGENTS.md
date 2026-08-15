# Project agent memory

This file is the project's committed home for project-intrinsic agent knowledge: build, test, release, architecture, and sharp-edge notes that should travel with the code.

- The deterministic release matrix is authoritative in `.github/workflows/verify.yml` and
  `docs/testing/release.md`; keep `Cargo.lock` current and use locked builds.
- Security defaults, Pandora's strict construction path, resource limits, and operation deadlines
  live in `smolder-core/src/policy.rs`. Keep connection/authentication state generation-scoped.
- Live SMB fixture tests are intentionally ignored in ordinary runs. Use the explicit scripts and
  matrix in `docs/testing/interop.md`; an ignored test is not a live pass.
- `scripts/test-package-consumer.sh` verifies normalized crate archives without inheriting
  workspace path patches and must run from a clean tracked tree.

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.
