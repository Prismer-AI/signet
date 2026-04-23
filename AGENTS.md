# Repository Guidelines

## Project Structure & Module Organization
`crates/signet-core/` is the source of truth for signing, verification, delegation, and policy logic. `signet-cli/` builds the `signet` binary. `bindings/signet-ts/` produces the WASM layer consumed by `packages/signet-core/`, while `bindings/signet-py/` exposes the Rust core through PyO3 and keeps Python tests in `bindings/signet-py/tests/`. TypeScript packages live in `packages/` (`signet-core`, `signet-mcp`, `signet-mcp-server`, `signet-mcp-tools`, `signet-vercel-ai`). Use `examples/` for runnable demos and `plugins/` for Codex and Claude integrations.

## Build, Test, and Development Commands
Use the same commands CI runs:

- `cargo test --workspace` runs Rust crate and CLI tests.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` checks Rust lint violations.
- `cargo fmt --all -- --check` verifies Rust formatting.
- `wasm-pack build bindings/signet-ts --target nodejs --out-dir ../../packages/signet-core/wasm` rebuilds the WASM binding.
- `cd packages/signet-core && npm test` runs the TypeScript core build and Node test suite. Repeat in other `packages/*` directories as needed.
- `cd bindings/signet-py && maturin develop && pytest tests/ -v` rebuilds and tests the Python binding.
- `npm run version:check` validates that all managed package versions match the repo version.

## Coding Style & Naming Conventions
Follow existing formatting instead of introducing a new style layer. Rust uses `rustfmt` defaults, `clippy` must stay clean, and application crates must remain free of `unsafe` code. TypeScript is strict (`NodeNext`, `strict: true`) and uses ESM. Match existing naming: Rust modules are `snake_case`, TypeScript source files are lower-case with hyphens only when already established, and tests end with `.test.ts` or `test_*.py`. Preserve receipt field names such as `params_hash` and `trace_id`; do not rename signed payload fields to camelCase.

## Testing Guidelines
Add or update tests with every behavioral change. Keep Rust unit tests close to the module, TypeScript tests under each package’s `tests/`, and Python coverage under `bindings/signet-py/tests/`. When changing WASM or cross-language behavior, run both `node examples/wasm-roundtrip/test.mjs` and the affected package tests.

## Commit & Pull Request Guidelines
Use Conventional Commits as seen in history: `feat(cli): ...`, `fix(mcp-tools): ...`, `docs: ...`, `ci: ...`. Scope the prefix to the touched area when possible. PRs should explain the problem, summarize the fix, list verification commands, and include logs or screenshots for demos, dashboard changes, or example flows. If versions move, include the `npm run version:check` or `npm run version:sync` results in the review notes.
