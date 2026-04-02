# Architecture

## Overview

Signet follows a **single-source core** architecture: all cryptographic logic lives in one Rust crate (`signet-core`), compiled to native (CLI), WASM (Node.js/TypeScript), and Python (PyO3). This eliminates cross-language divergence — there is exactly one implementation of sign, verify, and audit.

```text
                        ┌─────────────────────────┐
                        │      signet-core         │
                        │       (Rust)             │
                        │                         │
                        │  Ed25519 · Argon2id     │
                        │  XChaCha20 · JCS · SHA2 │
                        └────┬────────┬────────┬──┘
                             │        │        │
              ┌──────────────┤        │        ├──────────────┐
              │              │        │        │              │
              ▼              ▼        │        ▼              ▼
        ┌──────────┐  ┌──────────┐   │  ┌──────────┐  ┌─────────────┐
        │ signet-  │  │ signet-  │   │  │ signet-  │  │ @signet-    │
        │ cli      │  │ ts       │   │  │ py       │  │ auth/core   │
        │ (native) │  │ (WASM)   │   │  │ (PyO3)   │  │ (TS)        │
        └──────────┘  └────┬─────┘   │  └──────────┘  └──────┬──────┘
                           │         │                        │
                           ▼         │                        ▼
                     ┌──────────┐    │               ┌─────────────┐
                     │ @signet- │    │               │ @signet-    │
                     │ auth/    │    │               │ auth/mcp    │
                     │ core     │    │               │ (TS)        │
                     └──────────┘    │               └─────────────┘
                                     │
                              Your Agent
```

## Components

### signet-core (Rust)

The source of truth. All other packages wrap this crate.

| Module       | Responsibility                                          |
| ------------ | ------------------------------------------------------- |
| `identity`   | Ed25519 keypair generation, filesystem save/load        |
| `keystore`   | Argon2id KDF + XChaCha20-Poly1305 encrypted key storage |
| `receipt`    | `Action`, `Signer`, `Receipt` data structures           |
| `sign`       | Create signed receipts (canonicalize → sign → generate ID) |
| `verify`     | Verify receipt signature against public key              |
| `audit`      | Append-only JSONL log with SHA-256 hash chain           |
| `canonical`  | RFC 8785 (JCS) JSON canonicalization                    |
| `error`      | `SignetError` enum                                      |

**Platform gating**: Filesystem operations (`identity`, `keystore`, `audit`) are gated behind `#[cfg(not(target_arch = "wasm32"))]`. WASM builds only expose pure crypto functions.

### signet-cli (Rust, native)

Command-line tool built on `clap`. Subcommands:

- `identity generate|list|export` — Manage Ed25519 identities
- `sign` — Sign an action, append to audit log
- `verify` — Verify a receipt or the full hash chain
- `audit` — Query and filter the audit log

### bindings/signet-ts (Rust → WASM)

`wasm-bindgen` FFI layer. Exports three functions:

- `wasm_generate_keypair()` → `{secret_key, public_key}` (base64)
- `wasm_sign(secret_key_b64, action_json, signer_name, signer_owner)` → receipt JSON
- `wasm_verify(receipt_json, public_key_b64)` → bool

Compiled with `wasm-pack --target nodejs` to CommonJS for Node.js.

### bindings/signet-py (Rust → Python)

`PyO3` + `maturin` binding. Exposes two API levels:

- **High-level**: `SigningAgent.create()`, `.sign()`, `.verify()`, `.audit_query()`
- **Low-level**: `generate_keypair()`, `sign()`, `verify()`, `Action`

Thread-safe via `py.allow_threads()`. ABI3-stable for Python 3.10+.

### @signet-auth/core (TypeScript)

Thin TypeScript wrapper over the WASM module. Provides typed interfaces (`SignetKeypair`, `SignetAction`, `SignetReceipt`) and re-exports `generateKeypair()`, `sign()`, `verify()`.

### @signet-auth/mcp (TypeScript)

MCP middleware. `SigningTransport` wraps any MCP `Transport` and intercepts `tools/call` requests:

1. Detect `tools/call` method
2. Extract tool name and arguments
3. Create `SignetAction` and sign it
4. Inject receipt into `params._meta._signet`
5. Forward modified message to inner transport

MCP servers don't need changes — they ignore unknown `_meta` fields.

## Data Flow

### Signing

```text
Agent calls tool
    │
    ▼
SigningTransport.send()
    │
    ├─ Build Action {tool, params, params_hash, target, transport}
    ├─ Build Signer {pubkey, name, owner}
    ├─ Generate nonce (16 random bytes)
    ├─ Timestamp (RFC 3339 with millis)
    ├─ Canonicalize receipt body (RFC 8785 JCS)
    ├─ Sign canonical bytes with Ed25519
    ├─ Receipt ID = first 16 bytes of SHA-256(signature)
    ├─ Inject receipt into params._meta._signet
    │
    ▼
Forward to MCP server (unchanged)
```

### Audit Log

```text
~/.signet/audit/
├── 2026-03-29.jsonl     ← one AuditRecord per line
├── 2026-03-30.jsonl
└── 2026-03-31.jsonl

AuditRecord {
  receipt:     Receipt,      // full signed receipt
  prev_hash:   String,       // previous record's hash (or genesis)
  record_hash: String        // SHA-256 of canonical({prev_hash, receipt})
}
```

- **Genesis**: First record uses `sha256:0000...0000` as `prev_hash`
- **Cross-day continuity**: New day files read the last record hash from the previous day's file
- **Verification**: `signet verify --chain` walks the full chain chronologically, recomputing each hash

## Design Decisions

### Why client-side SDK, not a proxy/gateway?

|                      | SDK (Signet)                        | Proxy (Aegis, etc.)                         |
| -------------------- | ----------------------------------- | ------------------------------------------- |
| **Deploy**           | `pip install` / `npm install`       | Docker container + process orchestration    |
| **stdio support**    | Native — wraps transport in-process | Requires process interposition              |
| **Failure modes**    | Same process, no extra IPC          | Extra process = extra failure point         |
| **Can block actions** | No (attestation only)              | Yes (policy enforcement)                    |

Signet is a security camera, not a security guard. The two approaches complement each other.

### Why one Rust core?

Reimplementing Ed25519 + JCS + Argon2id in TypeScript and Python separately would create divergence risk. One Rust implementation compiled to all targets means:

- Zero chance of signing incompatibility across languages
- Single place to audit crypto code
- Single set of crypto tests (68 Rust tests cover the core logic)

### Why RFC 8785 (JCS)?

JSON key ordering is undefined. Without canonicalization, `{"a":1,"b":2}` and `{"b":2,"a":1}` produce different signatures. JCS provides deterministic JSON serialization so signatures are reproducible across any language and platform.
