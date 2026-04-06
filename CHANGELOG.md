# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-04-06

### Added

#### Bilateral Receipt (v3)
- **signet-core**: `BilateralReceipt` type — embeds v1 agent receipt + server response signature
- **signet-core**: `sign_bilateral()` — server co-signs agent receipt with response binding
- **signet-core**: `verify_bilateral()` — validates server sig + embedded agent sig
- **signet-core**: `verify_any()` now rejects v3 receipts (must use `verify_bilateral()`)
- **signet-core**: Audit layer v3 support — field extraction, signature verification, mixed v1/v2/v3 logs
- **@signet-auth/core**: `signBilateral()`, `verifyBilateral()`, `contentHash()` TypeScript functions
- **@signet-auth/mcp-server**: `signResponse()` — handler-level server co-signing
- **@signet-auth/mcp**: SigningTransport extracts v3 from response, `onBilateral` callback, `trustedServerKeys` option
- **WASM**: `wasm_sign_bilateral()`, `wasm_verify_bilateral()`, `wasm_content_hash()`

#### Claude Code Plugin
- **plugins/claude-code**: PostToolUse hook signs every tool call via embedded WASM (zero npm dependencies)
- **plugins/claude-code**: Hash-chained JSONL audit log at `~/.signet/audit/`
- **plugins/claude-code**: Auto key generation on first run with atomic file operations
- **signet-cli**: `signet claude install` / `signet claude uninstall` commands

#### Ecosystem Integrations
- **@signet-auth/mcp-tools**: Standalone MCP server exposing signing/verification as tools
- **signet-auth (Python)**: AutoGen 0.4 integration with `SignedTool` wrapper
- **signet-auth (Python)**: `verify_request()` for server-side MCP verification
- Docker support with verifier server example

#### Action Fields
- **signet-core**: `Action` struct gains optional `session`, `call_id`, `response_hash` fields (backward-compatible, omitted when `None`)
- **plugins/claude-code**: Captures `session_id`, `tool_use_id`, `tool_response` from stdin; stores response in audit meta

### Changed
- **WASM**: `wasm_generate_keypair()` now outputs 32-byte seed (was 64-byte keypair) — compatible with CLI `.key` files
- **WASM**: Key parsing accepts both 32-byte seed and 64-byte keypair via `parse_signing_key()`
- **WASM**: New `wasm_pubkey_from_seed()` replaces dummy-sign hack for public key derivation
- **plugins/claude-code**: `.pub` file uses bare base64 pubkey (no `ed25519:` prefix) + `created_at` field
- **plugins/claude-code**: `params_hash` now computed via `contentHash()` (was empty string)
- **@signet-auth/mcp-server**: `trustedKeys` empty array now means "trust any valid signer" (was: reject all)

### Fixed
- Anti-staple params verification in `verifyRequest()` — correctly compares params hash
- XNonce guard in sign functions — prevents nonce reuse
- `trusted_keys` semantics aligned across TS and Python
- `ed25519:` prefix normalization in `verify()` and `verifyAny()`
- MCP message forwarding after bilateral check — always forwards regardless of verification result
- Plugin: genesis hash mismatch, key permission check, corrupt line recovery
- Plugin: atomic key write prevents partial file on crash

### Breaking Changes
- **signet-core**: `verify_any()` now returns error on v3 receipts — use `verify_bilateral()` instead
- **signet-auth (Python)**: `generate_keypair()` reverted to 32-byte seed (was 64-byte in v0.2). Both formats still accepted by `sign()`.

## [0.3.0] - 2026-04-03

### Added
- **@signet-auth/mcp-server**: New package — server-side verification for MCP tool calls
- **@signet-auth/mcp-server**: `verifyRequest()` — validates signature, trusted keys, freshness, target, anti-staple (tool + params match)
- **@signet-auth/mcp**: `onDispatch` callback — fires at send time with v1 dispatch receipt
- **@signet-auth/mcp**: Restores inline `_meta._signet` injection for server verification (alongside v0.2 compound receipts)

### Changed
- **@signet-auth/mcp**: SigningTransport now produces both: v1 dispatch receipt (injected at send) + v2 compound receipt (after response)
- Example echo-server now demonstrates `verifyRequest()` in log-only mode

## [0.2.0] - 2026-04-02

### Added
- **signet-core**: Compound receipts (v2) — bind request + response in a single signed record
- **signet-core**: `sign_compound()` — signs tool call dispatch + response hash atomically
- **signet-core**: `verify_compound()` — verifies v2 compound receipts
- **signet-core**: `verify_any()` — auto-detects v1/v2 and dispatches to correct verifier
- **signet-core**: `Response` and `CompoundReceipt` types
- **@signet-auth/core**: `signCompound()` and `verifyAny()` TypeScript functions
- **@signet-auth/mcp**: SigningTransport now captures responses and produces compound receipts
- **signet-auth (Python)**: `sign_compound()`, `verify_any()`, `CompoundReceipt`, `Response` types
- **signet-cli**: `signet verify` handles both v1 and v2 receipts

### Changed
- **signet-core**: `audit::append()` now accepts `&serde_json::Value` instead of `&Receipt` (supports v1+v2)
- **signet-core**: `compute_params_hash()` extracted as shared function (DRY fix)
- **signet-core**: null params normalized to `{}` before hashing (cross-language consistency)

### Breaking Changes
- **@signet-auth/mcp**: `onSign` callback removed from `SigningTransportOptions` — use `onReceipt` instead
- **@signet-auth/mcp**: SigningTransport no longer injects `_meta._signet` into outbound messages at dispatch time — compound receipt is produced only after response arrives
- **@signet-auth/mcp**: Added `responseTimeout` option (default 30s) — no receipt for timed-out calls
- **signet-core (Rust)**: `audit::append()` signature changed: `&Receipt` → `&serde_json::Value`
- **signet-core (Rust)**: `verify_any()` requires receipt to have a `v` field (no silent v1 fallback)
- **signet-auth (Python)**: `generate_keypair()` returns 64-byte keypair (was 32-byte seed). Both formats accepted by `sign()`/`sign_compound()` for backward compatibility.
- **signet-auth (Python)**: `AuditRecord.receipt` returns `dict` instead of typed `Receipt` object

### Migration Guide

**TypeScript (@signet-auth/mcp):**
```typescript
// Before (v0.1)
const transport = new SigningTransport(inner, key, "agent", "owner", {
  onSign: (receipt) => console.log(receipt),  // fires at dispatch
});

// After (v0.2)
const transport = new SigningTransport(inner, key, "agent", "owner", {
  onReceipt: (compound) => console.log(compound),  // fires after response
  responseTimeout: 30000,
});
```

**Python (signet-auth):**
```python
# Key format change — both work:
kp = generate_keypair()  # now returns 64-byte keypair (88 chars base64)
sign(kp.secret_key, ...)  # accepts both 32-byte and 64-byte keys

# Audit record change:
record = audit_query(...)
record.receipt["id"]  # was: record.receipt.id
```

**Rust (signet-core):**
```rust
// Audit append change:
let receipt_json = serde_json::to_value(&receipt)?;
audit::append(&dir, &receipt_json)?;  // was: audit::append(&dir, &receipt)
```

### Fixed
- Timer memory leak in SigningTransport `close()` — now clears all pending timeouts
- Empty catch block in SigningTransport swallowing WASM errors — now forwards to `onerror`
- `extract_timestamp` ignoring receipt version — now reads `ts_request` for v2
- `query()` `--since` filter silently including records with missing timestamps — now skips them
- `result ?? error` conflating `result: null` with error response — now checks `'result' in msg`

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

[0.4.0]: https://github.com/Prismer-AI/signet/releases/tag/v0.4.0
[0.3.0]: https://github.com/Prismer-AI/signet/releases/tag/v0.3.0
[0.2.0]: https://github.com/Prismer-AI/signet/releases/tag/v0.2.0
[0.1.1]: https://github.com/Prismer-AI/signet/releases/tag/v0.1.1
[0.1.0]: https://github.com/Prismer-AI/signet/releases/tag/v0.1.0
