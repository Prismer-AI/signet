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
```

## Development Workflow

1. Fork the repo and create a feature branch
2. Make your changes with tests
3. Run the full test suite
4. Commit with conventional commits (`feat:`, `fix:`, `test:`, `docs:`)
5. Open a PR against `main`

## Commit Messages

We use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat(core):` new feature in signet-core
- `feat(cli):` new feature in signet-cli
- `feat(wasm):` WASM binding changes
- `feat(mcp):` @signet/mcp changes
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
