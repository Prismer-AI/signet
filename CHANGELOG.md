# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.10.0] - 2026-05-11

> **Note:** This release consolidates changes accumulated since v0.9.0 that were not
> individually documented in the v0.9.1, v0.9.2, and v0.9.3 maintenance releases.
> Sub-sections below cover the full delta from v0.9.0 through v0.10.0, with the
> Pilot Readiness suite (outcome binding, durable nonce store, server-key
> persistence, forensic bundle/restore) being the v0.10.0-specific work.

### Added

#### Pilot Readiness — v0.10.0 headline (2026-04-28)

- **signet-cli**: `signet proxy --server-key <name>` — persistent server signing identity for stable bilateral pubkey across restarts. Trust bundles can now anchor a stable server identity. Refuses identical agent/server keys.
- **signet-core**: `FileNonceChecker` — JSON file-backed nonce store, survives process restarts. Single-host pilot grade. Native-only (gated off WASM).
- **signet-cli**: `signet verify --nonce-store <path>` — durable v3 bilateral replay protection across `signet verify` invocations.
- **signet-cli**: `signet audit --bundle <dir>` — portable signed evidence bundle (records.jsonl + manifest.json + hash-summary.txt + optional trust-bundle.json) for off-host audit handoff.
- **signet-cli**: `signet audit --restore <dir>` — re-verify a previously produced evidence bundle on any machine, no signet keystore required.
- **signet-cli**: `signet audit --include-trust-bundle <path>` — embed a trust bundle snapshot in the evidence package.
- **signet-cli**: `signet audit --verify` and `signet audit --restore` apply forensic verification (replay-tolerant nonce semantics).
- **signet-core**: `Outcome` + `OutcomeStatus` (`verified`/`rejected`/`executed`/`failed`) attached to v2/v3 `Response`. Inside the signature scope; tampering is detectable.
- **signet-core**: `sign_bilateral_with_outcome()` — produce a v3 receipt that records both intent and final result.
- **signet-core**: Atomic `check_and_record` + `BilateralVerifyOptions::forensic()` — replay-tolerant verification mode for audit/forensic flows.
- **signet-core**: `audit::extract_policy_decision()` and `audit::compute_record_hash()` exposed for forensic restoration.
- **signet-auth (Python)**: `sign_bilateral_with_outcome()` binding accepting `outcome={"status": ..., "reason"?, "error"?}` dict.
- **@signet-auth/core**: `signBilateralWithOutcome()` + `SignetOutcome` type + `SignetResponse.outcome?` field + `FileNonceCache` adapter.
- **docs/guides/team-deployment.md**: end-to-end pilot deployment runbook.
- **packages/signet-openclaw-plugin** v0.1.0/0.1.1: OpenClaw gateway plugin — `before_tool_call`/`after_tool_call` hooks, hash-chained audit, Ed25519 + policy + XChaCha20-Poly1305 encryption, daily contract-drift CI against `openclaw/openclaw` main, fail-closed by default.

#### Receipt Expiration (Issue #3, included in v0.9.1)

- **signet-core**: `exp: Option<String>` field on `Receipt`, inside the signature scope
- **signet-core**: `sign_with_expiration()` — sign with an RFC 3339 expiration time
- **signet-core**: `verify()` rejects expired receipts by default
- **signet-core**: `verify_allow_expired()` — audit/forensic override, skips expiration check
- **signet-auth (Python)**: `sign_with_expiration()`, `verify_allow_expired()` bindings
- **@signet-auth/core**: `signWithExpiration()`, `verifyAllowExpired()` TypeScript functions

#### Bilateral Verify Options (Issues #1, #4, included in v0.9.1)

- **signet-core**: `expected_session` and `expected_call_id` on `BilateralVerifyOptions` — cross-check agent receipt fields against expected values (Issue #4)
- **signet-core**: `NonceChecker` trait + `InMemoryNonceChecker` — replay protection for bilateral server nonces (Issue #1)
- **signet-auth (Python)**: `verify_bilateral_with_options()` with session/call_id/nonce params
- **@signet-auth/core**: `verifyBilateralWithOptions()` TypeScript function

#### CLI hardening (included in v0.9.1)

- **signet-cli**: `signet explore` command for interactive receipt browsing
- **signet-cli**: `--ttl` flag on delegation token creation for short-lived authority
- **signet-cli**: Quickstart CLI (`signet quickstart`) for one-command first-run experience
- **signet-auth (Python)**: `@signet_sign` decorator API — wrap any function with audit signing
- **signet-auth (Python)**: `ComplianceBackend` Protocol adapter (LangChain RFC #35691)

#### Trust Bundle + Encrypted Audit (included in v0.9.2)

- **signet-core**: Trust bundle format + verify enhancements — distribute and pin trusted signer keys
- **signet-core**: Encrypted audit envelope (XChaCha20-Poly1305) — logs are both verifiable and confidential
- **signet-cli**: `signet trust` subcommand + `signet audit --trust-bundle <path>` + `signet audit --decrypt-params`
- **signet-cli**: Hardened proxy execution + trusted-key audit flows
- **signet-auth (Python)**: Trust bundle support and audit decryption in `signet_auth`
- **@signet-auth/mcp-server**: Trust bundle option for `VerifyOptions`
- **@signet-auth/node** (v0.10.0 wrapper): bounded timeout + `passphraseFromEnv` option, CLI compat probe, env-var/temp-file fallback for argv length limits, session forwarding

#### Documentation (mostly v0.9.1)

- **SECURITY.md**: Signed vs unsigned field tables for v1/v3/v4 receipts, extensions attack scenario warning (Issue #2)
- **COMPLIANCE.md**: Compliance mapping for SOC 2, ISO 27001, EU AI Act, DORA, NIST AI RMF
- **README.md**: Independent verification layer positioning, hero reframed around independent proof ownership
- **docs/RFC-0002-composite-receipt.md**: Composite receipt for cross-layer verification
- **CONTRIBUTING.md**: Repository contributor guide
- **Codespaces**: `.devcontainer/` + `demo.sh` for one-click browser experience

#### Ecosystem

- **signet-action**: GitHub Action for CI audit chain verification
- **dify-plugin-signet**: Dify plugin (local-first, no API key)
- **examples/langchain-compliance**: Signed audit receipts for LangChain compliance flows
- 5 example repos: LangChain, CrewAI, MCP, OpenAI Agents, Pydantic AI

### Changed

- **`verify_any()` now auto-dispatches v3 bilateral receipts** to `verify_bilateral()` instead of returning an error. Previous behavior required calling `verify_bilateral()` explicitly.
- **`BilateralVerifyOptions::default()` now enables in-memory nonce replay protection by default** (10k entries, 1 hour TTL). Previous default had `nonce_checker: None`. Use `BilateralVerifyOptions::insecure_no_replay_check()` for audit/forensic replay where nonce reuse is expected. **This is a behavioral break for code that calls `verify_bilateral()` repeatedly on the same receipt.**
- **Python `SigningAgent.sign_authorized()` now accepts `chain=` (typed `list[dict] | str`)** as the preferred parameter. `chain_json=` is kept for backward compatibility.
- **TypeScript `BilateralReceipt.extensions`** is now typed as `UnsignedExtensions` (alias for `Record<string, unknown>`) with prominent JSDoc warning that the field is outside the signature scope. Previously typed as `unknown` with no warning.
- `sign_inner()` extracted — `sign()`, `sign_with_expiration()`, `sign_with_policy()` are now thin wrappers (net -46 lines)
- `verify_receipt_signature()` extracted — `verify()` and `verify_allow_expired()` share signature logic
- CLI exit codes unified: 1 = verification/policy fail, 2 = approval needed, 3 = general error
- `cmd_policy.rs` uses `bail!()` instead of `process::exit()` — flows through main.rs error handler
- **CI**: release pipeline gates `@signet-auth/node` publish on `smoke-cargo` (cargo install + sign/verify roundtrip) so the npm wrapper is never published before the matching `signet` CLI is installable from crates.io.

### Fixed

- **signet-cli**: hardened proxy execution and added trusted-key audit flows
- **signet-core**: tightened trust verification and audit integrity surfaces
- **@signet-auth/mcp-tools**: restored canonical `Prismer-AI` casing in `mcpName`
- **packages/signet-openclaw-plugin**: receipts bound to OpenClaw `session`/`runId`/`toolCallId`; preserves `target` verbatim; readiness un-latches on every sign failure; system-failure detection widened to cover `EACCES` + non-JSON CLI output

### Tests

- 537 total tests (269 Rust core + 40 CLI + 195 Python + 33 TypeScript)

## [0.9.0] - 2026-04-13

### Added

#### Signed Trace Correlation
- **signet-core**: `trace_id` and `parent_receipt_id` optional fields on `Action` — link receipts across multi-step agent workflows
- **signet-core**: Both fields are included in the signed payload (tampering invalidates signature)
- **signet-core**: `sign()`, `sign_bilateral()`, `sign_authorized()` all propagate trace fields from `Action`
- **signet-core**: `audit::append()` serializes trace fields when present (omitted when `None` — backward compatible)
- **@signet-auth/core**: `trace_id?: string` and `parent_receipt_id?: string` on `ActionInput` TypeScript interface
- **signet-auth (Python)**: `trace_id` and `parent_receipt_id` kwargs on `sign()`, `sign_hash_only()`, `SigningAgent.sign()`
- **signet-auth (Python)**: `receipt.trace_id` and `receipt.parent_receipt_id` accessors on `PyReceipt`

### Tests
- Rust: 6 trace-specific tests (sign with trace_id, parent_receipt_id, combined, tampering detection, audit roundtrip)
- Python: 9 trace tests — roundtrip, signature scope, absent-when-None, multi-step workflow chain
- TypeScript: 5 trace tests — trace_id/parent_receipt_id in receipt, tampering invalidation, workflow chain
- 495 total tests passing (213 Rust core + 40 CLI + 214 Python + 28 TypeScript)

## [0.8.0] - 2026-04-13

### Added

#### MCP Proxy — Transparent Signing
- **signet-cli**: `signet proxy --target <cmd> --key <name>` — run as stdio MCP proxy, sign every `tools/call` transparently without modifying agent or server code
- **signet-cli**: Bilateral co-signing: proxy signs agent request (v1 receipt logged immediately), then co-signs server response (v3 bilateral receipt) — server-side evidence even when the server has no Signet integration
- **signet-cli**: `--policy <path>` — evaluate policy before signing; `deny` rules halt the call and log a violation; `require_approval` rules block with an error message
- **signet-cli**: `--no-log` — disable audit log (useful for testing)
- **signet-cli**: `--env-filter` — strip sensitive env vars (`SECRET`, `PASSWORD`, `PRIVATE_KEY`, `CREDENTIAL`) from child process; `SIGNET_PASSPHRASE` always filtered
- **signet-cli**: Stale pending request eviction (30-minute TTL) — v1 receipt already logged, memory cleaned automatically
- Non-`tools/call` messages (initialize, ping, etc.) pass through unmodified

### Fixed
- `Action` struct initializers in `cmd_proxy.rs` updated to include `trace_id` and `parent_receipt_id` fields (added in v0.9.0)

### Tests
- 9 CLI integration tests: tools/call signing, passthrough for non-tool messages, audit log written, `--no-log` skips audit, policy allow/deny, multiple sequential calls, bilateral co-signing roundtrip, bilateral with multiple concurrent calls

## [0.7.0] - 2026-04-11

### Added

#### Policy Engine
- **signet-core**: `Policy`, `Rule`, `RuleAction`, `MatchSpec`, `PolicyAttestation`, `PolicyEvalResult` types
- **signet-core**: `evaluate_policy()` — max-severity evaluation (deny > require_approval > allow)
- **signet-core**: `sign_with_policy()` — evaluate policy before signing, embed `PolicyAttestation` in receipt
- **signet-core**: `parse_policy_yaml()`, `parse_policy_json()`, `validate_policy()`, `load_policy()`, `compute_policy_hash()`
- **signet-core**: `RateLimitState` — in-memory sliding window rate limiting per rule
- **signet-core**: `audit::append_violation()` — log denied/require_approval actions to audit trail
- **signet-core**: 3 new error variants: `PolicyViolation`, `PolicyParseError`, `RequiresApproval`
- **signet-core**: `Display` impl for `RuleAction`
- **signet-cli**: `signet policy validate <path>` — validate policy file syntax and rules
- **signet-cli**: `signet policy check <path> --tool --params --agent --target` — dry-run policy evaluation
- **signet-cli**: `signet sign --policy <path>` — enforce policy before signing
- **WASM**: `wasm_parse_policy_yaml()`, `wasm_evaluate_policy()`, `wasm_sign_with_policy()`, `wasm_compute_policy_hash()`
- **@signet-auth/core**: `parsePolicyYaml()`, `evaluatePolicy()`, `signWithPolicy()`, `computePolicyHash()` with `Policy`, `PolicyReceipt`, `SignWithPolicyResult`, `PolicyEvalResult`, `PolicyAttestation` interfaces
- **signet-auth (Python)**: `parse_policy_yaml()`, `parse_policy_json()`, `evaluate_policy()`, `sign_with_policy()`, `compute_policy_hash()` bindings
- **signet-auth (Python)**: `PolicyViolationError`, `PolicyParseError`, `RequiresApprovalError` exception types

### Changed
- `Receipt` struct now has optional `policy: Option<PolicyAttestation>` field (backward compatible)
- `verify()` includes policy field in signable when present (receipts without policy unaffected)
- New dependency: `serde_yaml = "0.9"` (non-WASM only)

### Tests
- 102 policy-specific tests across Rust (73), Python (18), TypeScript (11)
- 421 total tests passing (194 Rust core + 31 CLI + 173 Python + 23 TypeScript)

## [0.6.0] - 2026-04-11

### Added

#### Delegation Chain (v4 Receipts)
- **signet-core**: `DelegationToken`, `Scope`, `Authorization` types for cryptographic delegation
- **signet-core**: `sign_delegation()` — create scoped authority tokens from delegator to delegate
- **signet-core**: `verify_delegation()` — verify token signature + expiry with optional `at` parameter
- **signet-core**: `verify_chain()` — verify entire delegation chain (pubkey continuity, scope narrowing, depth limits, trusted roots)
- **signet-core**: `sign_authorized()` — sign tool call with delegation proof (produces v4 receipt)
- **signet-core**: `verify_authorized()` — full verification: signature + chain + scope + root trust
- **signet-core**: `verify_v4_signature_only()` — signature-only check for audit-level verification
- **signet-core**: `verify_any()` now accepts v4 receipts (signature-only, delegates to `verify_authorized()` for full check)
- **signet-core**: Audit `extract_timestamp()` updated for v4 (uses `ts`, not `ts_response`)
- **signet-core**: 4 new error variants: `ScopeViolation`, `ChainError`, `DelegationExpired`, `Unauthorized`
- **signet-core**: Shared crypto helpers: `generate_nonce()`, `current_timestamp()`, `derive_id()`, `format_pubkey()`, `format_sig()`, `is_wildcard()`
- **signet-cli**: `signet delegate create|verify|sign|verify-auth` subcommands
- **WASM**: `wasm_sign_delegation()`, `wasm_verify_delegation()`, `wasm_sign_authorized()`, `wasm_verify_authorized()`
- **@signet-auth/core**: `signDelegation()`, `verifyDelegation()`, `signAuthorized()`, `verifyAuthorized()` with full TypeScript types
- **signet-auth (Python)**: `sign_delegation()`, `verify_delegation()`, `sign_authorized()`, `verify_authorized()` bindings
- **signet-auth (Python)**: `SigningAgent.delegate()`, `SigningAgent.sign_authorized()`, `SigningAgent.verify_delegation()`, `SigningAgent.verify_authorized()` high-level API

#### Dashboard
- Editorial/newspaper redesign (Playfair Display + Source Serif 4 + IBM Plex Mono)
- v4 delegation chain visualization in timeline detail (delegator -> delegate path, scope, root pubkey, expiry)
- "By Authorization" stats chart (delegated vs direct signing)
- Fixed `receiptTime()` for v4 receipts

#### Demo Assets
- `demo-delegation.mjs` — 8-step delegation chain demo script
- `demo-delegation-full.mp4` — CLI + Dashboard combined video
- `demo-delegation.svg` — animated SVG for README

### Tests
- **Python**: 17 delegation tests — sign_delegation/verify_delegation roundtrip, scope narrowing/widening, sign_authorized/verify_authorized v4 receipts, error handling
- **CLI**: 7 delegation tests — delegate create/verify/sign/verify-auth end-to-end, output file, wrong root key rejection
- All 369 tests passing (188 Rust core + 26 CLI + 155 Python)

### Fixed
- **@signet-auth/core**: Cast `clockSkewSecs` to `BigInt` for WASM `u64` parameter in `verifyAuthorized()`

### Changed
- `Receipt` struct now has optional `authorization` field (backward compatible — v1/v2/v3 unaffected)
- `sign.rs` refactored to use shared helpers (reduced ~30 lines of duplication)
- Mixed wildcard scopes (e.g. `["*", "Bash"]`) now rejected at sign time
- `sign_authorized()` validates signing key matches final delegate in chain
- CI npm smoke test reduced to core-only install (reduces self-inflated download counts)

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

[0.10.0]: https://github.com/Prismer-AI/signet/releases/tag/v0.10.0
[0.9.0]: https://github.com/Prismer-AI/signet/releases/tag/v0.9.0
[0.8.0]: https://github.com/Prismer-AI/signet/releases/tag/v0.8.0
[0.7.0]: https://github.com/Prismer-AI/signet/releases/tag/v0.7.0
[0.6.0]: https://github.com/Prismer-AI/signet/releases/tag/v0.6.0
[0.5.0]: https://github.com/Prismer-AI/signet/releases/tag/v0.5.0
[0.4.0]: https://github.com/Prismer-AI/signet/releases/tag/v0.4.0
[0.3.0]: https://github.com/Prismer-AI/signet/releases/tag/v0.3.0
[0.2.0]: https://github.com/Prismer-AI/signet/releases/tag/v0.2.0
[0.1.1]: https://github.com/Prismer-AI/signet/releases/tag/v0.1.1
[0.1.0]: https://github.com/Prismer-AI/signet/releases/tag/v0.1.0
