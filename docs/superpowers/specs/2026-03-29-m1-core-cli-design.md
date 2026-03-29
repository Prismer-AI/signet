# M1: Core + CLI — Design Spec

**Date:** 2026-03-29
**Status:** Draft
**Depends on:** M0 (complete — signet-core sign/verify/canonical/identity, signet-wasm binding)

## Goal

Extend signet-core with encrypted key management and build a CLI tool (`signet`) that
exposes identity generation, signing, and verification as shell commands.

## Non-Goals

- Audit log / hash chain (M2)
- MCP transport integration (M3)
- Browser/Workers targets (v2+)
- Delegation tokens (v2+)
- Key rotation / revocation (v2+)

## Exit Criteria

1. `signet identity generate --name x` creates encrypted `.key` + `.pub` files in `~/.signet/keys/`
2. `signet identity generate --name x --unencrypted` creates unencrypted `.key` file
3. `signet identity list` shows all keys with name, owner, created_at
4. `signet identity export --name x` outputs public key JSON to stdout
5. `signet sign --key x --tool y --params '{}' --target z` outputs receipt JSON to stdout
6. `signet sign --output file.json` writes receipt to file
7. `signet verify receipt.json --pubkey x` exits 0 on valid, 1 on invalid
8. Passphrase via TTY prompt (default) or `SIGNET_PASSPHRASE` env var (CI)
9. `cargo test` passes — every public function has at least one test, every error path tested
10. All 17 M0 tests continue passing

## Architecture

```
┌─────────────────────────────────────────┐
│              signet-cli                  │  signet-cli/src/
│  (binary crate, thin shell over core)   │
│                                         │
│  main.rs         — clap App + dispatch  │
│  cmd_identity.rs — generate/list/export │
│  cmd_sign.rs     — sign subcommand      │
│  cmd_verify.rs   — verify subcommand    │
└───────────────────┬─────────────────────┘
                    │ depends on
                    v
┌─────────────────────────────────────────┐
│              signet-core                 │  crates/signet-core/src/
│  (library crate, all business logic)    │
│                                         │
│  identity.rs  — generate + save/load    │  #[cfg(not(wasm32))]
│                  list + export           │
│  keystore.rs  — encrypt/decrypt helpers │  #[cfg(not(wasm32))]
│  sign.rs      — sign() (from M0)        │
│  verify.rs    — verify() (from M0)      │
│  receipt.rs   — types (from M0)         │
│  canonical.rs — JCS (from M0)           │
│  error.rs     — errors (extended)       │
└─────────────────────────────────────────┘
```

### New Module: keystore.rs

Separates crypto (encrypt/decrypt) from IO (file read/write). `identity.rs` handles
the public API and file operations; `keystore.rs` handles the raw key encryption.

```
identity.rs (public API, #[cfg(not(target_arch = "wasm32"))]):
  generate_and_save(dir, name, owner, passphrase) → Result<KeyInfo>
  // owner defaults to empty string "" when --owner is omitted
  load_key_info(dir, name) → Result<KeyInfo>       // reads .pub, returns name/owner/pubkey
  load_signing_key(dir, name, passphrase) → Result<SigningKey>
  load_verifying_key(dir, name) → Result<VerifyingKey>
  list_keys(dir) → Result<Vec<KeyInfo>>
  export_public_key(dir, name) → Result<PubKeyFile>
  default_signet_dir() → PathBuf                    // ~/.signet/ via dirs crate
  validate_key_name(name) → Result<()>              // [a-zA-Z0-9_-] only

keystore.rs (internal, #[cfg(not(target_arch = "wasm32"))]):
  encrypt_key(signing_key, passphrase, aad) → EncryptedKeyFile
  decrypt_key(encrypted, passphrase) → Result<SigningKey>
  encode_unencrypted(signing_key) → UnencryptedKeyFile
  decode_unencrypted(file) → Result<SigningKey>

Note: generate_and_save() ALWAYS writes both .key and .pub, regardless of
--unencrypted flag. Write order: .pub first (can be rebuilt), then .key.
On .key write failure, delete .pub to avoid orphaned metadata.

Note: CLI signing reads .pub via load_key_info() to get name/owner for the
Signer struct, then load_signing_key() to get the signing key.
```

## Key File Formats

### .key file (encrypted, default)

```json
{
  "v": 1,
  "algorithm": "ed25519",
  "name": "deploy-bot",
  "kdf": "argon2id",
  "kdf_params": {
    "salt": "<base64, 16 bytes>",
    "t": 3,
    "m": 65536,
    "p": 1
  },
  "cipher": "xchacha20poly1305",
  "nonce": "<base64, 24 bytes>",
  "encrypted_key": "<base64, 32 + 16 bytes (key + auth tag)>"
}
```

KDF parameters: Argon2id with `t=3` (iterations), `m=64MB` (memory), `p=1` (parallelism).
This is OWASP's recommended minimum. Decrypt time ~0.5-1s on desktop hardware.

**Test mode:** Tests use reduced KDF params (`t=1, m=64 (64KB), p=1`) to avoid
0.5-1s per key operation. Controlled via `keystore::encrypt_key()` accepting a
`KdfParams` struct. Tests pass `KdfParams::test_default()`, production uses
`KdfParams::default()`. These test params are insecure and must never be used
in production.

### .key file (unencrypted, --unencrypted flag)

```json
{
  "v": 1,
  "algorithm": "ed25519",
  "name": "deploy-bot",
  "kdf": "none",
  "key": "<base64, 32 bytes>"
}
```

### .pub file

```json
{
  "v": 1,
  "algorithm": "ed25519",
  "pubkey": "ed25519:<base64>",
  "name": "deploy-bot",
  "owner": "willamhou",
  "created_at": "2026-03-29T14:32:00.000Z"
}
```

### Key Storage (.key bytes)

Both encrypted and unencrypted `.key` files store the 32-byte Ed25519 seed (not the
64-byte keypair). `SigningKey::from_bytes(&seed)` reconstructs the full keypair.
This is consistent with the standard Ed25519 key format.

The WASM binding uses 64-byte keypair bytes (`to_keypair_bytes()`) for its JS API,
but that is a WASM-layer concern. The core keystore always works with 32-byte seeds.

### File Safety

- **Name validation:** Key names must match `[a-zA-Z0-9_-]+`. Reject anything else
  with `SignetError::InvalidName`.
- **No overwrite:** If `{name}.key` already exists, return `SignetError::KeyExists`.
  User must delete manually to regenerate.
- **Atomic write:** Write to `{name}.key.tmp`, then rename to `{name}.key`. This
  prevents half-written files on crash.
- **File permissions:** Set mode `0600` on `.key.tmp` BEFORE renaming (safer).
  Unix-only for M1. Windows is not a supported platform for M1.
- **Write order:** Write `.pub` first, then `.key`. On `.key` failure, delete `.pub`.

### AEAD with AAD

When encrypting with XChaCha20-Poly1305, the plaintext header fields are included
as Associated Authenticated Data (AAD). This prevents tampering with metadata
(name, algorithm, kdf_params) without detection.

```rust
let aad = serde_json::json!({
    "v": 1,
    "algorithm": "ed25519",
    "name": name,
    "kdf": "argon2id",
    "kdf_params": kdf_params,
    "cipher": "xchacha20poly1305",
});
let aad_bytes = canonical::canonicalize(&aad)?;
// encrypt with aad_bytes as associated data
```

WARNING: AAD uses the same JCS canonicalization as receipt signing. Changing
`canonical.rs` is a breaking change for existing encrypted keys — old keys
become undecryptable. This must be documented as a compatibility constraint.

### SIGNET_HOME Override

The default key directory is `~/.signet/keys/` (via `dirs::home_dir()`).
Override with `SIGNET_HOME` env var: `$SIGNET_HOME/keys/`.

This is required for test isolation. All CLI integration tests set `SIGNET_HOME`
to a tempdir.

### File Layout

```
~/.signet/                   # or $SIGNET_HOME
└── keys/
    ├── deploy-bot.key       # encrypted (or unencrypted) private key
    └── deploy-bot.pub       # public key + metadata (always written)
```

### Detection Logic

`load_signing_key()` reads the `.key` file, checks the `kdf` field:
- `"none"` → decode `key` field directly (no passphrase needed)
- `"argon2id"` → derive encryption key from passphrase → decrypt `encrypted_key`
- anything else → return `SignetError::InvalidKey("unsupported kdf: {kdf}")`

## CLI Design

### Subcommands

```
signet identity generate --name <name> [--owner <owner>] [--unencrypted]
signet identity list
signet identity export --name <name>

signet sign --key <name> --tool <tool> --params <json|@file> --target <uri>
            [--hash-only] [--output <file>]

signet verify <receipt> --pubkey <name-or-file>
```

### --hash-only Flag

When `--hash-only` is set, CLI does NOT send raw params to `sign()`. Instead:
1. Compute `sha256(JCS(params))` locally
2. Call `sign()` with `params: Value::Null, params_hash: "sha256:..."` (hash-only mode)
3. Receipt contains hash but not original params

### Passphrase Acquisition

```rust
fn get_passphrase(prompt: &str) -> Result<String> {
    if let Ok(p) = std::env::var("SIGNET_PASSPHRASE") {
        if p.is_empty() {
            bail!("SIGNET_PASSPHRASE is set but empty");
        }
        return Ok(p);
    }
    if !std::io::stdin().is_terminal() {  // std::io::IsTerminal, stable since Rust 1.70
        bail!("no TTY and SIGNET_PASSPHRASE not set — cannot read passphrase");
    }
    let p = rpassword::prompt_password(prompt)
        .map_err(|e| anyhow!("failed to read passphrase: {e}"))?;
    if p.is_empty() {
        bail!("passphrase cannot be empty");
    }
    Ok(p)
}
```

Rules:
- Minimum length: 1 character (no empty passphrases)
- `signet identity generate` prompts twice (enter + confirm, must match)
- `signet sign` prompts once
- `signet verify` never prompts (public key only)
- `--unencrypted` keys never prompt
- Non-TTY without `SIGNET_PASSPHRASE` → clear error (not a hang)

### --params @file syntax

`--params` accepts either inline JSON or `@path` to read JSON from file:
```
signet sign --key bot --tool create_issue --params '{"title":"bug"}' --target mcp://gh
signet sign --key bot --tool create_issue --params @params.json --target mcp://gh
```

### --pubkey detection

`--pubkey` argument is interpreted as:
- File path if it contains `/` or ends with `.pub` → read directly, fail with
  file-not-found if absent (no fallback to keystore lookup)
- Key name otherwise → resolves to `$SIGNET_HOME/keys/{name}.pub`

### Output Behavior

- `signet sign` → receipt JSON to stdout (one line, compact)
- `signet sign --output file.json` → receipt JSON to file, prints path to stderr
- `signet verify` → exit 0 + "Valid: ..." to stdout, or exit 1 + "Invalid: ..." to stderr
- `signet identity list` → table format to stdout
- `signet identity export` → pub key JSON to stdout

### Error Output

All errors go to stderr. Exit codes managed explicitly via `std::process::exit()`:
- 0: success
- 1: verification failed (expected failure, not a bug)
- 2: usage/parse error (clap handles this by default, matches)
- 3: runtime error (file not found, decryption failed, etc.)

Implementation: `main()` returns `Result<(), anyhow::Error>`. A custom error handler
maps verification failure → exit 1, clap errors → exit 2, all others → exit 3.

## New Dependencies

### signet-core additions

| Crate | Version | Purpose |
|-------|---------|---------|
| `argon2` | 0.5 | Argon2id KDF |
| `chacha20poly1305` | 0.10 | XChaCha20-Poly1305 AEAD |
| `tempfile` | 3 | dev-dep: temp dirs for tests |

### signet-cli (new crate)

| Crate | Version | Purpose |
|-------|---------|---------|
| `signet-core` | path | Core library |
| `clap` | 4 | CLI argument parsing (derive) |
| `rpassword` | 7 | TTY password input |
| `dirs` | 5 | `~/.signet/` path resolution |
| `anyhow` | 1 | CLI error handling |
| `serde_json` | 1 | JSON output |
| ~~atty~~ | — | Not needed: use `std::io::IsTerminal` (stable since Rust 1.70) |
| `assert_cmd` | 2 | dev-dep: CLI integration tests |
| `predicates` | 3 | dev-dep: assertion helpers |

## Error Types Extension

Add to `SignetError`:

```rust
#[error("key not found: {0}")]
KeyNotFound(String),

#[error("key already exists: {0}")]
KeyExists(String),

#[error("invalid key name: {0} (must match [a-zA-Z0-9_-]+)")]
InvalidName(String),

#[error("decryption failed: wrong passphrase or corrupted key")]
DecryptionError,

#[error("corrupted key file: {0}")]
CorruptedFile(String),

#[error("IO error: {0}")]
IoError(#[from] std::io::Error),

#[error("unsupported key format: {0}")]
UnsupportedFormat(String),

// IoError, KeyNotFound, KeyExists, InvalidName, CorruptedFile are gated with
// #[cfg(not(target_arch = "wasm32"))] since they relate to filesystem operations.
// WASM consumers only see: InvalidKey, SignatureMismatch, CanonicalizeError,
// InvalidReceipt, SerializeError.
```

## File Map (new/modified)

| File | Action | Responsibility |
|------|--------|----------------|
| `crates/signet-core/src/keystore.rs` | Create | Key encryption/decryption helpers |
| `crates/signet-core/src/identity.rs` | Modify | Add save/load/list/export functions |
| `crates/signet-core/src/error.rs` | Modify | Add KeyNotFound, DecryptionError, IoError |
| `crates/signet-core/src/lib.rs` | Modify | Add `pub mod keystore`, update re-exports |
| `signet-cli/Cargo.toml` | Create | CLI crate with clap, rpassword, dirs |
| `signet-cli/src/main.rs` | Create | Clap App definition + dispatch |
| `signet-cli/src/cmd_identity.rs` | Create | identity generate/list/export |
| `signet-cli/src/cmd_sign.rs` | Create | sign subcommand |
| `signet-cli/src/cmd_verify.rs` | Create | verify subcommand |
| `Cargo.toml` | Modify | Add signet-cli to workspace members |

## Test Plan

### signet-core: identity + keystore tests (9 new)

| Test | What it validates |
|------|-------------------|
| `test_encrypt_save_load_roundtrip` | Generate → encrypt → save → load → decrypt → key matches |
| `test_load_wrong_passphrase` | Wrong passphrase → `DecryptionError` |
| `test_load_nonexistent_key` | Missing key → `KeyNotFound` |
| `test_unencrypted_save_load_roundtrip` | `--unencrypted` mode full roundtrip |
| `test_list_keys` | Generate 3 keys → list returns 3 entries |
| `test_list_keys_empty_dir` | Empty dir → returns empty vec |
| `test_export_public_key` | Export returns complete PubKeyFile with all fields |
| `test_key_file_name_mismatch` | `.key` name field != filename → error |
| `test_pub_file_format` | `.pub` file is valid JSON with required fields |
| `test_corrupted_ciphertext` | Tampered encrypted_key → `DecryptionError` |
| `test_auto_create_keys_dir` | Dir doesn't exist → auto-created |
| `test_corrupted_json_key_file` | Invalid JSON in .key → `CorruptedFile` |
| `test_key_name_validation` | Invalid chars in name → `InvalidName` |

All file tests use `tempfile::tempdir()`.

### signet-cli: integration tests (12 new)

| Test | What it validates |
|------|-------------------|
| `test_identity_generate` | Command succeeds, files created |
| `test_identity_generate_unencrypted` | `--unencrypted` mode, files readable |
| `test_identity_list` | Lists generated keys |
| `test_identity_list_empty` | Empty → "No keys found" |
| `test_identity_export` | Outputs valid JSON with pubkey |
| `test_sign_stdout` | Receipt JSON on stdout |
| `test_sign_output_file` | `--output` writes file |
| `test_verify_valid` | Exit 0, "Valid" output |
| `test_verify_invalid` | Tampered receipt → exit 1 |
| `test_verify_pubkey_file` | `--pubkey ./path.pub` works |
| `test_sign_verify_e2e` | generate → sign → verify full chain |
| `test_passphrase_env_var` | `SIGNET_PASSPHRASE` env var works |
| `test_params_at_file` | `--params @file.json` reads from file |
| `test_params_at_nonexistent` | `--params @missing.json` → clear error |

CLI tests use `assert_cmd` + `SIGNET_PASSPHRASE` env var + `tempdir` for `--home`.

### Coverage Target

Every public function must have at least one test. Every error path must have a test
that triggers it. No specific percentage target — coverage is verified by the test
plan completeness, not by a measurement tool.

```
Module              M0    M1 New    Total
──────────────────────────────────────────
canonical.rs        4     0         4
identity.rs         2     13        15
keystore.rs         0     (in identity tests)
sign.rs             5     0         5
verify.rs           6     0         6
CLI integration     0     14        14
──────────────────────────────────────────
Total               17    27        44
```

## Success Definition

M1 is complete when:
1. All 10 exit criteria pass
2. `cargo test --workspace` passes (17 M0 + 27 M1 = 44 tests)
3. No `unsafe` code
4. `cargo clippy --workspace` has no warnings
5. CLI binary builds: `cargo build -p signet-cli`
6. `wasm-pack build bindings/signet-ts --target nodejs` still works (WASM not broken)
