# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-04-02

### Added
- **signet-auth (Python)**: LangChain `SignetCallbackHandler` + `AsyncSignetCallbackHandler`
- **signet-auth (Python)**: CrewAI `install_hooks()` / `uninstall_hooks()` integration
- **signet-auth (Python)**: Full tool lifecycle signing (start + end + error)
- **signet-cli**: Published to crates.io (`cargo install signet-cli`)

### Fixed
- CrewAI hooks: thread safety via `threading.Lock`
- CrewAI hooks: no longer mutates `tool_input` (was injecting `_signet_receipt_id`)
- CrewAI hooks: guard against double `install_hooks()` registration
- LangChain handler: narrow exception catch to `SignetError` (was bare `Exception`)
- Fixed stale test counts in README, SECURITY.md (Python 66 → 85, total → 172)
- TODOS.md: Python Binding marked as completed

## [0.1.0] - 2026-03-29

### Added
- **signet-core**: Ed25519 identity generation with Argon2id + XChaCha20-Poly1305 encrypted storage
- **signet-core**: Action signing with RFC 8785 (JCS) canonical JSON
- **signet-core**: Offline signature verification
- **signet-core**: Append-only JSONL audit log with SHA-256 hash chain
- **signet-cli**: `signet identity generate/list/export` commands
- **signet-cli**: `signet sign` with `--hash-only`, `--output`, `@file` params, `--no-log`
- **signet-cli**: `signet verify` for receipt verification + `--chain` for hash chain integrity
- **signet-cli**: `signet audit` with `--since`, `--tool`, `--signer`, `--verify`, `--export`
- **@signet-auth/core**: TypeScript wrapper for WASM crypto functions
- **@signet-auth/mcp**: SigningTransport middleware for MCP tool call signing
- WASM binding (wasm-bindgen) for Node.js
- End-to-end MCP agent example (agent + echo server)

[0.1.0]: https://github.com/Prismer-AI/signet/releases/tag/v0.1.0
