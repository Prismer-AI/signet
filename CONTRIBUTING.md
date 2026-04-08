# Contributing to Signet

Thanks for your interest in contributing! Signet is an open-source project and we welcome contributions of all kinds.

## Getting Started

### Prerequisites

- Rust (1.70+ nightly)
- wasm-pack (`cargo install wasm-pack`)
- Node.js (18+)

### Build

```bash
# Rust core + CLI
cargo build -p signet-cli

# WASM binding
wasm-pack build bindings/signet-ts --target nodejs --out-dir ../../packages/signet-core/wasm

# TypeScript packages
cd packages/signet-core && npx tsc && cp -r wasm dist/wasm
cd ../signet-mcp && npm install && npx tsc
```

### Test

```bash
# Rust (64 tests)
cargo test --workspace

# WASM roundtrip (8 tests)
wasm-pack build bindings/signet-ts --target nodejs --out-dir pkg
node examples/wasm-roundtrip/test.mjs

# TypeScript (11 tests)
cd packages/signet-core && npm test
cd packages/signet-mcp && npm test
```

### Lint

```bash
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
```

## Project Structure

```
signet/
├── crates/
│   └── signet-core/        # Core crypto library (source of truth)
├── signet-cli/             # CLI binary
├── bindings/
│   └── signet-ts/          # wasm-bindgen WASM binding
├── packages/
│   ├── signet-core/        # @signet-auth/core — TypeScript WASM wrapper
│   └── signet-mcp/         # @signet-auth/mcp — MCP SigningTransport
└── examples/
    ├── wasm-roundtrip/     # WASM smoke test
    └── mcp-agent/          # End-to-end MCP agent example
```

## Development Workflow

1. Fork the repo and create a feature branch
2. Make your changes with tests
3. Run the full test suite
4. Commit with conventional commits (`feat:`, `fix:`, `test:`, `docs:`)
5. Open a PR against `main`

## Versioning And Releases

`VERSION` at the repo root is the single source of truth for Signet release versions. Rust crates, Python metadata, TypeScript packages, MCP server metadata, plugin manifests, and the checked-in `package-lock.json` workspace entries are synced from that file.

Use these commands before cutting a release:

```bash
# Check that every managed file matches VERSION
npm run version:check

# Re-write all managed manifests from VERSION
npm run version:sync

# Bump VERSION and sync every managed manifest
npm run version:set -- 0.4.6
```

Release flow:

1. Run `npm run version:set -- <next-version>`
2. Review the manifest changes and commit them
3. Push the commit
4. Create the matching git tag: `git tag v<next-version>`
5. Push the tag so the release workflow can publish artifacts

CI now checks version consistency on every PR, and the release workflow refuses to publish unless the pushed tag exactly matches `VERSION`.

## Commit Messages

We use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat(core):` new feature in signet-core
- `feat(cli):` new feature in signet-cli
- `feat(wasm):` WASM binding changes
- `feat(mcp):` @signet-auth/mcp changes
- `feat(ts):` TypeScript package changes
- `fix:` bug fix
- `test:` test changes
- `docs:` documentation
- `ci:` CI/CD changes

## Architecture

- `signet-core` is the source of truth for all crypto logic
- TypeScript packages wrap WASM, never re-implement crypto
- Filesystem code is gated with `#[cfg(not(target_arch = "wasm32"))]`
- All public functions must have tests
- No `unsafe` code

## License

By contributing, you agree that your contributions will be licensed under the Apache-2.0 OR MIT dual license.
