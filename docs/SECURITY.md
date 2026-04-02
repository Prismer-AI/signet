# Security Model

## Cryptographic Primitives

| Function         | Algorithm           | Crate                  | Parameters                              |
| ---------------- | ------------------- | ---------------------- | --------------------------------------- |
| Signing          | Ed25519             | `ed25519-dalek` 2.x    | 128-bit security, 64-byte signatures    |
| Key derivation   | Argon2id            | `argon2` 0.5           | t=3, m=64MB, p=1 (OWASP minimum)       |
| Key encryption   | XChaCha20-Poly1305  | `chacha20poly1305` 0.10 | 24-byte nonce, AEAD with AAD           |
| Hashing          | SHA-256             | `sha2` 0.10            | Params hash, receipt ID, hash chain     |
| Canonicalization | RFC 8785 (JCS)      | `json-canon` 0.1       | Deterministic JSON serialization        |

## Key Storage

Keys are stored at `~/.signet/keys/` (override with `SIGNET_HOME`).

```text
~/.signet/keys/
├── my-agent.key       # Encrypted private key (Argon2id + XChaCha20-Poly1305)
└── my-agent.pub       # Public key (plaintext JSON)
```

- File permissions: `0600` (owner read/write only)
- Encrypted key file format:

```json
{
  "v": 1,
  "algorithm": "ed25519",
  "name": "my-agent",
  "kdf": "argon2id",
  "kdf_params": { "t": 3, "m": 65536, "p": 1 },
  "salt": "hex...",
  "cipher": "xchacha20-poly1305",
  "nonce": "hex...",
  "ciphertext": "hex..."
}
```

- **AAD (Additional Authenticated Data)**: Canonical JSON of header metadata (`v`, `algorithm`, `name`, `kdf`, `kdf_params`). Tampering with any header field causes decryption to fail.
- **Unencrypted mode**: `--unencrypted` flag stores raw key bytes for CI/automation. Use `SIGNET_PASSPHRASE` env var for automated encrypted key access.

## Signature Scheme

### What gets signed

The full receipt body (minus the `sig` and `id` fields) is canonicalized via JCS:

```text
canonical({v, action, signer, ts, nonce}) → bytes → Ed25519.sign(bytes)
```

The `id` field is derived *after* signing (`rec_` + first 16 hex chars of SHA-256(signature)), so it is not part of the signed payload. Modifying any signed field — tool name, params, timestamp, signer identity, nonce — invalidates the signature.

### Receipt ID generation

```text
receipt.id = "rec_" + hex(SHA-256(signature))[0..16]
```

This provides a short, collision-resistant identifier derived from the signature itself.

## Audit Log Integrity

### Hash Chain

Each audit record contains a hash linking it to the previous record:

```text
record_hash = SHA-256(canonical({prev_hash, receipt}))
```

- **Genesis**: First record uses `sha256:0000...0000`
- **Cross-day**: New daily files link back to the last record of the previous day
- **Verification**: `signet verify --chain` recomputes every hash and checks continuity

### Tamper detection

| Attack             | Detection                                                                      |
| ------------------ | ------------------------------------------------------------------------------ |
| Modify a receipt   | Signature verification fails (`signet audit --verify`)                         |
| Delete a record    | Hash chain breaks at the gap (`signet verify --chain`)                         |
| Reorder records    | Hash chain breaks (prev_hash mismatch)                                         |
| Modify and re-sign | Requires the private key; public key verification catches if different key used |
| Truncate log tail  | Detectable if expected record count is known                                   |

### Limitations

- Audit log is local. An attacker with filesystem access can delete the entire log.
- No remote attestation server (planned for v2).
- Hash chain proves ordering and integrity, not completeness — a compromised agent could skip logging (`--no-log`).

## Threat Model

### What Signet proves

- Agent key X signed intent to call tool Y with params Z at time T
- The audit log has not been tampered with (hash chain intact)
- Receipts were created by the holder of the signing key

### What Signet does NOT prove

| Gap                                        | Mitigation (planned)                    |
| ------------------------------------------ | --------------------------------------- |
| MCP server received/executed the action    | v2: Server-side counter-signatures      |
| `signer.owner` actually controls the key   | v2: Identity registry / attestation     |
| Agent was authorized to perform the action | Out of scope — use policy engines       |
| Params were not modified in transit        | Out of scope — use TLS for transport    |

### Trust boundaries

```text
┌─────────────────────────────────┐
│  Trusted (Signet's scope)       │
│                                 │
│  Key generation                 │
│  Signing (client-side)          │
│  Audit log append               │
│  Offline verification           │
└─────────────────────────────────┘

┌─────────────────────────────────┐
│  Untrusted (outside scope)      │
│                                 │
│  MCP server execution           │
│  Network transport              │
│  Agent authorization            │
│  Identity binding               │
└─────────────────────────────────┘
```

## Code Safety

- **Zero `unsafe` blocks** in `signet-core`
- **No `unwrap()` in production code** — all errors propagated via `?` and `SignetError`
- **145 tests** across Rust (68), Python (66), TypeScript (11)
- CI runs `cargo clippy -- -D warnings` and `cargo fmt --check` on every PR

## Reporting Vulnerabilities

If you discover a security vulnerability, please email <security@prismer.ai> instead of opening a public issue. We will respond within 48 hours.
