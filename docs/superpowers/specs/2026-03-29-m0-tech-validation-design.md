# M0: Tech Validation — Design Spec

**Date:** 2026-03-29
**Status:** Draft
**Scope:** Validate Ed25519 sign/verify roundtrip in Rust + WASM (Node.js)

## Goal

Derisk the critical technical assumption: Rust crypto compiled to WASM via wasm-bindgen
produces correct, deterministic Ed25519 signatures that can be verified in both Rust and
Node.js environments.

## Non-Goals

- Key encryption/storage (M1)
- Audit log / hash chain (M2)
- MCP transport integration (M3)
- CLI tool (M1)
- Browser/Workers/Deno/Bun targets (v2+)

## Exit Criteria

1. `cargo test` passes: Rust-native sign → verify roundtrip
2. `wasm-pack build --target nodejs` compiles successfully
3. Node.js script calls WASM module: generate keypair → sign → verify → pass
4. Node.js script: tampered receipt → verify → reject
5. Canonical JSON (JCS) produces identical output in Rust and WASM

## Architecture

```
┌──────────────────────────────────┐
│         signet-core              │  crates/signet-core/
│  (Rust library, requires std)    │
│                                  │
│  identity.rs   — generate Ed25519 keypair
│  sign.rs       — sign Action → Receipt
│  verify.rs     — verify Receipt + pubkey
│  receipt.rs    — Action, Receipt, Signer types
│  canonical.rs  — RFC 8785 (JCS) canonicalization
│  lib.rs        — public API
└──────────────┬───────────────────┘
               │ dependency
               v
┌──────────────────────────────────┐
│         signet-wasm              │  bindings/signet-ts/
│  (wasm-bindgen wrapper)          │
│                                  │
│  lib.rs  — #[wasm_bindgen] functions:
│             wasm_generate_keypair()
│             wasm_sign(secret_key, action_json)
│             wasm_verify(receipt_json, public_key)
└──────────────┬───────────────────┘
               │ wasm-pack build --target nodejs
               v
┌──────────────────────────────────┐
│    Node.js validation script     │  examples/wasm-roundtrip/
│                                  │
│  test.mjs — import WASM pkg,
│             run sign/verify roundtrip,
│             test tamper rejection
└──────────────────────────────────┘
```

## Data Structures

### Action

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub tool: String,           // e.g. "github_create_issue"
    pub params: serde_json::Value,  // raw params (plaintext by default)
    pub params_hash: String,    // "sha256:<hex>" — always computed
    pub target: String,         // e.g. "mcp://github.local"
    pub transport: String,      // "stdio" | "http" | "sse"
}
```

Design note: `params` stores the original parameters in plaintext for human-readable
audit. `params_hash` is always computed as `sha256(JCS(params))` for compact verification.
Callers can opt into hash-only mode by omitting `params` and providing only `params_hash`.

**`params_hash` ownership rule:** `sign()` always recomputes `params_hash` from `params`
using `sha256(JCS(params))`, ignoring any caller-supplied value. If `params` is null/empty
and `params_hash` is provided, `sign()` uses the caller-supplied hash as-is (hash-only mode).

### Signer

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signer {
    pub pubkey: String,         // "ed25519:<base64>"
    pub name: String,           // human-readable agent name
    pub owner: String,          // who controls this agent (opaque string in M0)
}
```

Note: `owner` is included for future M1 authorization checks. M0 treats it as opaque
string data with no validation beyond non-empty check.

### Receipt

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub v: u8,                  // protocol version, always 1
    pub id: String,             // "rec_<hex>" — see ID Derivation below
    pub action: Action,
    pub signer: Signer,
    pub ts: String,             // ISO 8601 UTC timestamp
    pub nonce: String,          // "rnd_<hex>" — 16 random bytes
    pub sig: String,            // "ed25519:<base64>"
}
```

### ID Derivation

Receipt ID is deterministically derived from the signature:

```
id = "rec_" + hex_encode(sha256(base64_decode(sig_without_prefix))[0..16])
```

Where `sig_without_prefix` strips the `"ed25519:"` prefix to get raw base64,
then decodes to 64 bytes, hashes with SHA-256, and takes the first 16 bytes
(32 hex chars). This makes `id` globally unique and recomputable from `sig`.

### Signature Scope

The signature covers the JCS canonicalization of the **entire receipt body** minus the
`sig` and `id` fields (since `id` is derived from `sig`):

```rust
let signable = json!({
    "v": receipt.v,
    "action": receipt.action,
    "signer": receipt.signer,
    "ts": receipt.ts,
    "nonce": receipt.nonce,
});
let canonical = jcs_canonicalize(&signable)?;
let sig = signing_key.sign(canonical.as_bytes());
```

This ensures all meaningful fields (including `signer.name` and `signer.owner`) are
tamper-evident. Modifying any field invalidates the signature.

## Canonical JSON — RFC 8785 (JCS)

Using the `json-canonicalization` crate which implements RFC 8785:
- Deterministic key ordering (lexicographic by Unicode code point)
- Deterministic number serialization (no trailing zeros, no scientific notation)
- No whitespace
- UTF-8 encoding

This is critical for cross-platform signature verification. The same Action must produce
the same canonical bytes in Rust, WASM, and any future SDK.

## Dependencies

### signet-core (Rust)

| Crate | Version | Purpose |
|-------|---------|---------|
| `ed25519-dalek` | 2.x | Ed25519 sign/verify |
| `rand` | 0.8 | Nonce generation, keypair generation |
| `serde` + `serde_json` | 1.x | Serialization |
| `sha2` | 0.10 | SHA-256 for params_hash and receipt ID |
| `json-canonicalization` | 1.x | RFC 8785 JCS |
| `chrono` | 0.4 | UTC timestamps |
| `base64` | 0.22 | Encoding keys and signatures |

### signet-wasm (bindings/signet-ts/)

| Crate | Version | Purpose |
|-------|---------|---------|
| `wasm-bindgen` | 0.2 | Rust ↔ JS bridge |
| `getrandom` | 0.2 (with `js` feature) | WASM entropy source |
| `serde-wasm-bindgen` | 0.6 | JsValue conversion |
| `signet-core` | path dep | Core logic |

### Known WASM Risk: `getrandom`

`ed25519-dalek` and `rand` depend on `getrandom` for entropy. In WASM, `getrandom`
requires the `js` feature flag to use `crypto.getRandomValues()`. Without it,
compilation succeeds but panics at runtime.

**Mitigation:** Enable `getrandom/js` in both crates. In the workspace root `Cargo.toml`,
use a target-specific dependency to force the feature transitively:

```toml
# signet-wasm/Cargo.toml
[dependencies]
getrandom = { version = "0.2", features = ["js"] }

# OR in workspace root Cargo.toml:
[target.'cfg(target_arch = "wasm32")'.dependencies]
getrandom = { version = "0.2", features = ["js"] }
```

Note: `ed25519-dalek 2.x` uses `OsRng` directly (via `rand_core`), which routes
through `getrandom`. The `rand 0.8` dependency is needed for nonce generation only.
Both paths require `getrandom/js` in WASM.

## WASM Binding API

```rust
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn wasm_generate_keypair() -> Result<JsValue, JsError> {
    // Returns { secret_key: string, public_key: string }
    // Keys are bare base64 (no "ed25519:" prefix):
    //   secret_key: base64(64 bytes), public_key: base64(32 bytes)
    // The "ed25519:" prefix is only added when serializing into Receipt fields.
}

#[wasm_bindgen]
pub fn wasm_sign(
    secret_key_b64: &str,
    action_json: &str,
    signer_name: &str,
    signer_owner: &str,
) -> Result<String, JsError> {
    // Returns receipt JSON string
}

#[wasm_bindgen]
pub fn wasm_verify(
    receipt_json: &str,
    public_key_b64: &str,
) -> Result<bool, JsError> {
    // Returns true if signature valid, false otherwise
}
```

## Node.js Validation Script

`examples/wasm-roundtrip/test.mjs`:

```javascript
import assert from 'node:assert';
import { wasm_generate_keypair, wasm_sign, wasm_verify } from '../../bindings/signet-ts/pkg/signet_wasm.js';

// Test 1: Generate keypair
const { secret_key, public_key } = wasm_generate_keypair();
assert(secret_key && public_key);

// Test 2: Sign an action
const action = JSON.stringify({
    tool: "github_create_issue",
    params: { title: "fix bug", body: "details" },
    params_hash: "", // computed by sign()
    target: "mcp://github.local",
    transport: "stdio"
});
const receipt_json = wasm_sign(secret_key, action, "test-agent", "willamhou");
const receipt = JSON.parse(receipt_json);
assert(receipt.sig.startsWith("ed25519:"));
assert(receipt.id.startsWith("rec_"));

// Test 3: Verify valid receipt
assert(wasm_verify(receipt_json, public_key) === true);

// Test 4: Tampered receipt should fail
const tampered = { ...receipt, action: { ...receipt.action, tool: "evil_tool" } };
assert(wasm_verify(JSON.stringify(tampered), public_key) === false);

// Test 5: Wrong key should fail
const { public_key: other_key } = wasm_generate_keypair();
assert(wasm_verify(receipt_json, other_key) === false);

// Test 6: Tampered signer name should fail (signer is in signature scope)
const tampered_signer = { ...receipt, signer: { ...receipt.signer, name: "impostor" } };
assert(wasm_verify(JSON.stringify(tampered_signer), public_key) === false);

console.log("All tests passed.");
```

## File Layout

```
signet/
├── Cargo.toml                      # workspace root
├── crates/
│   └── signet-core/
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs              # pub mod + public API
│           ├── identity.rs         # generate_keypair()
│           ├── sign.rs             # sign(key, action, signer) -> Receipt
│           ├── verify.rs           # verify(receipt, pubkey) -> Result
│           ├── receipt.rs          # Action, Signer, Receipt structs
│           ├── canonical.rs        # JCS wrapper
│           └── error.rs            # SignetError enum (see below)
├── bindings/
│   └── signet-ts/
│       ├── Cargo.toml              # wasm-bindgen, depends on signet-core
│       └── src/
│           └── lib.rs              # #[wasm_bindgen] exports
└── examples/
    └── wasm-roundtrip/
        ├── test.mjs                # Node.js validation script
        └── README.md               # How to run the validation
```

## Error Types

`error.rs` defines `SignetError` using `thiserror`:

```rust
#[derive(Debug, thiserror::Error)]
pub enum SignetError {
    #[error("invalid key: {0}")]
    InvalidKey(String),

    #[error("signature verification failed")]
    SignatureMismatch,

    #[error("failed to canonicalize JSON: {0}")]
    CanonicalizeError(String),

    #[error("invalid receipt: {0}")]
    InvalidReceipt(String),

    #[error("serialization error: {0}")]
    SerializeError(#[from] serde_json::Error),
}
```

| Variant | Returned by |
|---------|-------------|
| `InvalidKey` | `sign()`, `verify()` — malformed key bytes |
| `SignatureMismatch` | `verify()` — signature does not match |
| `CanonicalizeError` | `sign()`, `verify()` — JCS serialization fails |
| `InvalidReceipt` | `verify()` — missing or malformed fields |
| `SerializeError` | `sign()` — serde serialization fails |

## Rust Test Plan

### Unit Tests (in signet-core)

| Test | What it validates |
|------|-------------------|
| `test_generate_keypair` | Keypair generation produces valid Ed25519 keys |
| `test_sign_verify_roundtrip` | Sign → verify with same key succeeds |
| `test_verify_wrong_key` | Verify with different key fails |
| `test_verify_tampered_action` | Modify action field → verify fails |
| `test_verify_tampered_signer` | Modify signer.name → verify fails |
| `test_verify_tampered_timestamp` | Modify ts → verify fails |
| `test_verify_tampered_nonce` | Modify nonce → verify fails |
| `test_canonical_determinism` | Same input → same canonical JSON bytes |
| `test_canonical_key_order` | Keys sorted lexicographically |
| `test_receipt_id_from_sig` | `id == SHA-256(sig)[..16]` |
| `test_params_hash_computed` | `params_hash == sha256(JCS(params))` |
| `test_nonce_uniqueness` | Two signs produce different nonces |

### Property Test (optional, with proptest)

| Test | What it validates |
|------|-------------------|
| `prop_sign_verify` | For any random Action, sign → verify succeeds |
| `prop_tamper_detect` | For any random mutation, verify fails |

## Success Definition

M0 is complete when:
1. All Rust unit tests pass (`cargo test`)
2. WASM compiles without warnings (`wasm-pack build --target nodejs`)
3. Node.js script runs all 6 assertions successfully
4. No `unsafe` code in signet-core
5. `getrandom` entropy works in WASM (no runtime panics)

If WASM compilation fails or `getrandom` has unresolvable issues, the fallback is
pure TypeScript crypto (using `@noble/ed25519`) for the TS binding, with Rust core
remaining for CLI. This would change the M3 architecture but not block the project.

**Fallback impact on exit criteria:** If the fallback is taken, Exit Criterion 1
(Rust-native roundtrip) still stands. Criteria 3-5 are replaced by TS-native
equivalents. The original WASM risk remains unresolved and must be tracked as a
debt item for M3.
