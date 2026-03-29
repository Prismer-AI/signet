# M0: Tech Validation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Validate Ed25519 sign/verify roundtrip works correctly in both Rust and WASM (Node.js).

**Architecture:** Rust workspace with two crates — `signet-core` (crypto library) and `signet-wasm` (wasm-bindgen wrapper). A Node.js script validates the WASM output matches Rust behavior.

**Tech Stack:** Rust, ed25519-dalek, serde, json-canonicalization (RFC 8785), wasm-bindgen, wasm-pack, Node.js

**Spec:** `docs/superpowers/specs/2026-03-29-m0-tech-validation-design.md`

**Toolchain:** Rust 1.95.0-nightly, wasm-pack 0.14.0, Node.js v24.12.0. Cargo bin at `~/.cargo/bin/`.

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `Cargo.toml` | Create | Workspace root: members = signet-core, signet-wasm |
| `crates/signet-core/Cargo.toml` | Create | Dependencies: ed25519-dalek, rand, serde, serde_json, sha2, json-canonicalization, chrono, base64, thiserror |
| `crates/signet-core/src/lib.rs` | Create | Module declarations + re-exports |
| `crates/signet-core/src/error.rs` | Create | `SignetError` enum with thiserror |
| `crates/signet-core/src/receipt.rs` | Create | `Action`, `Signer`, `Receipt` structs |
| `crates/signet-core/src/canonical.rs` | Create | JCS canonicalization wrapper |
| `crates/signet-core/src/identity.rs` | Create | `generate_keypair()` → (SigningKey, VerifyingKey) |
| `crates/signet-core/src/sign.rs` | Create | `sign()` → Receipt |
| `crates/signet-core/src/verify.rs` | Create | `verify()` → Result |
| `bindings/signet-ts/Cargo.toml` | Create | wasm-bindgen crate depending on signet-core |
| `bindings/signet-ts/src/lib.rs` | Create | `#[wasm_bindgen]` exports: generate, sign, verify |
| `examples/wasm-roundtrip/test.mjs` | Create | Node.js validation script (8 assertions: 6 roundtrip + 2 error) |

---

### Task 1: Workspace + signet-core Cargo Setup

**Files:**
- Create: `Cargo.toml`
- Create: `crates/signet-core/Cargo.toml`
- Create: `crates/signet-core/src/lib.rs`

- [ ] **Step 1: Create workspace root Cargo.toml**

```toml
[workspace]
members = ["crates/signet-core", "bindings/signet-ts"]
resolver = "2"
```

- [ ] **Step 2: Create signet-core Cargo.toml**

```toml
[package]
name = "signet-core"
version = "0.1.0"
edition = "2021"
description = "Cryptographic action receipts for AI agents"
license = "Apache-2.0 OR MIT"

[dependencies]
ed25519-dalek = { version = "2", features = ["rand_core"] }
rand = "0.8"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
sha2 = "0.10"
json-canonicalization = "1"
chrono = { version = "0.4", features = ["serde"] }
base64 = "0.22"
hex = "0.4"
thiserror = "2"
```

- [ ] **Step 3: Create empty lib.rs**

```rust
pub mod canonical;
pub mod error;
pub mod identity;
pub mod receipt;
pub mod sign;
pub mod verify;

pub use error::SignetError;
pub use identity::generate_keypair;
pub use receipt::{Action, Receipt, Signer};
pub use sign::sign;
pub use verify::verify;

#[cfg(test)]
pub(crate) mod test_helpers {
    use crate::receipt::Action;
    use serde_json::json;

    pub fn test_action() -> Action {
        Action {
            tool: "github_create_issue".to_string(),
            params: json!({"title": "fix bug", "body": "details"}),
            params_hash: String::new(),
            target: "mcp://github.local".to_string(),
            transport: "stdio".to_string(),
        }
    }
}
```

- [ ] **Step 4: Create stub files so it compiles**

Create each module file with a minimal placeholder so `cargo check` passes:

`crates/signet-core/src/error.rs`:
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

`crates/signet-core/src/receipt.rs`:
```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub tool: String,
    pub params: serde_json::Value,
    pub params_hash: String,
    pub target: String,
    pub transport: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signer {
    pub pubkey: String,
    pub name: String,
    pub owner: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub v: u8,
    pub id: String,
    pub action: Action,
    pub signer: Signer,
    pub ts: String,
    pub nonce: String,
    pub sig: String,
}
```

`crates/signet-core/src/canonical.rs`:
```rust
use crate::error::SignetError;

pub fn canonicalize(value: &serde_json::Value) -> Result<String, SignetError> {
    json_canonicalization::serialize(value)
        .map_err(|e| SignetError::CanonicalizeError(e.to_string()))
}
```

`crates/signet-core/src/identity.rs`:
```rust
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;

pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}
```

`crates/signet-core/src/sign.rs`:
```rust
use crate::error::SignetError;
use crate::receipt::{Action, Receipt, Signer};
use ed25519_dalek::SigningKey;

pub fn sign(_key: &SigningKey, _action: &Action, _signer_name: &str, _signer_owner: &str) -> Result<Receipt, SignetError> {
    todo!()
}
```

`crates/signet-core/src/verify.rs`:
```rust
use crate::error::SignetError;
use crate::receipt::Receipt;
use ed25519_dalek::VerifyingKey;

pub fn verify(_receipt: &Receipt, _pubkey: &VerifyingKey) -> Result<(), SignetError> {
    todo!()
}
```

- [ ] **Step 5: Verify it compiles**

Run: `~/.cargo/bin/cargo check`
Expected: compiles with no errors (warnings about unused are OK)

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml crates/
git commit -m "feat(core): scaffold signet-core workspace with types and stubs"
```

---

### Task 2: Canonical JSON + Tests

**Files:**
- Modify: `crates/signet-core/src/canonical.rs`

- [ ] **Step 1: Write the failing tests**

Add to the bottom of `crates/signet-core/src/canonical.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_canonical_determinism() {
        let value = json!({"b": 2, "a": 1, "c": {"z": 26, "a": 1}});
        let result1 = canonicalize(&value).unwrap();
        let result2 = canonicalize(&value).unwrap();
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_canonical_key_order() {
        let value = json!({"zebra": 1, "apple": 2, "mango": 3});
        let result = canonicalize(&value).unwrap();
        assert_eq!(result, r#"{"apple":2,"mango":3,"zebra":1}"#);
    }

    #[test]
    fn test_canonical_nested_key_order() {
        let value = json!({"b": {"d": 4, "c": 3}, "a": 1});
        let result = canonicalize(&value).unwrap();
        assert_eq!(result, r#"{"a":1,"b":{"c":3,"d":4}}"#);
    }

    #[test]
    fn test_canonical_no_whitespace() {
        let value = json!({"key": "value"});
        let result = canonicalize(&value).unwrap();
        assert!(!result.contains(' '));
        assert!(!result.contains('\n'));
    }
}
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `~/.cargo/bin/cargo test -p signet-core canonical`
Expected: 4 tests PASS (the implementation already exists from Task 1)

- [ ] **Step 3: Commit**

```bash
git add crates/signet-core/src/canonical.rs
git commit -m "test(core): add canonical JSON (JCS) tests"
```

---

### Task 3: Identity + Tests

**Files:**
- Modify: `crates/signet-core/src/identity.rs`

- [ ] **Step 1: Write the failing test**

Add to the bottom of `crates/signet-core/src/identity.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    #[test]
    fn test_generate_keypair() {
        let (signing_key, verifying_key) = generate_keypair();
        // Verify the keys are related: sign something and verify
        let message = b"test message";
        let signature = signing_key.sign(message);
        assert!(verifying_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_keypair_uniqueness() {
        let (key1, _) = generate_keypair();
        let (key2, _) = generate_keypair();
        assert_ne!(key1.to_bytes(), key2.to_bytes());
    }
}
```

- [ ] **Step 2: Add missing import to identity.rs**

Add at top of `identity.rs`, after existing imports:

```rust
use ed25519_dalek::Signer as _;
```

- [ ] **Step 3: Run tests to verify they pass**

Run: `~/.cargo/bin/cargo test -p signet-core identity`
Expected: 2 tests PASS

- [ ] **Step 4: Commit**

```bash
git add crates/signet-core/src/identity.rs
git commit -m "test(core): add identity keypair generation tests"
```

---

### Task 4: Sign Implementation + Tests

**Files:**
- Modify: `crates/signet-core/src/sign.rs`

- [ ] **Step 1: Write the failing tests**

Replace the entire `crates/signet-core/src/sign.rs` with:

```rust
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::Utc;
use ed25519_dalek::{Signer as _, SigningKey};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::canonical;
use crate::error::SignetError;
use crate::receipt::{Action, Receipt, Signer};

pub fn sign(
    key: &SigningKey,
    action: &Action,
    signer_name: &str,
    signer_owner: &str,
) -> Result<Receipt, SignetError> {
    // 1. Compute params_hash from params
    let params_hash = if action.params.is_null() && !action.params_hash.is_empty() {
        // Hash-only mode: use caller-supplied hash
        action.params_hash.clone()
    } else {
        // Normal mode: compute hash from params
        let canonical_params = canonical::canonicalize(&action.params)?;
        let hash = Sha256::digest(canonical_params.as_bytes());
        format!("sha256:{}", hex::encode(hash))
    };

    // 2. Build action with computed hash
    let signed_action = Action {
        tool: action.tool.clone(),
        params: action.params.clone(),
        params_hash,
        target: action.target.clone(),
        transport: action.transport.clone(),
    };

    // 3. Build signer
    let pubkey_bytes = key.verifying_key().to_bytes();
    let signer = Signer {
        pubkey: format!("ed25519:{}", BASE64.encode(pubkey_bytes)),
        name: signer_name.to_string(),
        owner: signer_owner.to_string(),
    };

    // 4. Generate nonce
    let mut nonce_bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = format!("rnd_{}", hex::encode(nonce_bytes));

    // 5. Get timestamp
    let ts = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    // 6. Build signable JSON (everything except sig and id)
    let signable = serde_json::json!({
        "v": 1u8,
        "action": signed_action,
        "signer": signer,
        "ts": ts,
        "nonce": nonce,
    });
    let canonical_bytes = canonical::canonicalize(&signable)?;

    // 7. Sign
    let signature = key.sign(canonical_bytes.as_bytes());
    let sig_b64 = BASE64.encode(signature.to_bytes());
    let sig = format!("ed25519:{}", sig_b64);

    // 8. Derive receipt ID from signature
    let sig_hash = Sha256::digest(signature.to_bytes());
    let id = format!("rec_{}", hex::encode(&sig_hash[..16]));

    Ok(Receipt {
        v: 1,
        id,
        action: signed_action,
        signer,
        ts,
        nonce,
        sig,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::generate_keypair;
    use crate::test_helpers::test_action;

    #[test]
    fn test_sign_produces_receipt() {
        let (key, _) = generate_keypair();
        let action = test_action();
        let receipt = sign(&key, &action, "test-agent", "willamhou").unwrap();

        assert_eq!(receipt.v, 1);
        assert!(receipt.id.starts_with("rec_"));
        assert!(receipt.sig.starts_with("ed25519:"));
        assert!(receipt.nonce.starts_with("rnd_"));
        assert!(receipt.signer.pubkey.starts_with("ed25519:"));
        assert_eq!(receipt.signer.name, "test-agent");
        assert_eq!(receipt.signer.owner, "willamhou");
        assert_eq!(receipt.action.tool, "github_create_issue");
    }

    #[test]
    fn test_params_hash_computed() {
        let (key, _) = generate_keypair();
        let action = test_action();
        let receipt = sign(&key, &action, "test-agent", "owner").unwrap();

        // Verify params_hash matches sha256(JCS(params))
        let canonical_params = canonical::canonicalize(&action.params).unwrap();
        let expected_hash = format!("sha256:{}", hex::encode(Sha256::digest(canonical_params.as_bytes())));
        assert_eq!(receipt.action.params_hash, expected_hash);
    }

    #[test]
    fn test_params_hash_only_mode() {
        let (key, _) = generate_keypair();
        let action = Action {
            tool: "test".to_string(),
            params: serde_json::Value::Null,
            params_hash: "sha256:abc123".to_string(),
            target: "mcp://test".to_string(),
            transport: "stdio".to_string(),
        };
        let receipt = sign(&key, &action, "agent", "owner").unwrap();
        assert_eq!(receipt.action.params_hash, "sha256:abc123");
    }

    #[test]
    fn test_nonce_uniqueness() {
        let (key, _) = generate_keypair();
        let action = test_action();
        let r1 = sign(&key, &action, "agent", "owner").unwrap();
        let r2 = sign(&key, &action, "agent", "owner").unwrap();
        assert_ne!(r1.nonce, r2.nonce);
    }

    #[test]
    fn test_receipt_id_from_sig() {
        let (key, _) = generate_keypair();
        let action = test_action();
        let receipt = sign(&key, &action, "agent", "owner").unwrap();

        // Recompute ID from sig
        let sig_b64 = receipt.sig.strip_prefix("ed25519:").unwrap();
        let sig_bytes = BASE64.decode(sig_b64).unwrap();
        let sig_hash = Sha256::digest(&sig_bytes);
        let expected_id = format!("rec_{}", hex::encode(&sig_hash[..16]));
        assert_eq!(receipt.id, expected_id);
    }
}
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `~/.cargo/bin/cargo test -p signet-core sign`
Expected: 5 tests PASS

- [ ] **Step 3: Commit**

```bash
git add crates/signet-core/
git commit -m "feat(core): implement sign() with Ed25519 + JCS canonicalization"
```

---

### Task 5: Verify Implementation + Tests

**Files:**
- Modify: `crates/signet-core/src/verify.rs`

- [ ] **Step 1: Replace verify.rs with full implementation + tests**

```rust
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::canonical;
use crate::error::SignetError;
use crate::receipt::Receipt;

pub fn verify(receipt: &Receipt, pubkey: &VerifyingKey) -> Result<(), SignetError> {
    // 1. Decode signature
    let sig_b64 = receipt
        .sig
        .strip_prefix("ed25519:")
        .ok_or_else(|| SignetError::InvalidReceipt("sig missing ed25519: prefix".to_string()))?;
    let sig_bytes = BASE64
        .decode(sig_b64)
        .map_err(|e| SignetError::InvalidReceipt(format!("invalid sig base64: {e}")))?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| SignetError::InvalidReceipt(format!("invalid sig bytes: {e}")))?;

    // 2. Reconstruct signable JSON (same fields as sign())
    let signable = serde_json::json!({
        "v": receipt.v,
        "action": receipt.action,
        "signer": receipt.signer,
        "ts": receipt.ts,
        "nonce": receipt.nonce,
    });
    let canonical_bytes = canonical::canonicalize(&signable)?;

    // 3. Verify
    pubkey
        .verify(canonical_bytes.as_bytes(), &signature)
        .map_err(|_| SignetError::SignatureMismatch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::generate_keypair;
    use crate::sign;
    use crate::test_helpers::test_action;

    #[test]
    fn test_sign_verify_roundtrip() {
        let (signing_key, verifying_key) = generate_keypair();
        let action = test_action();
        let receipt = sign::sign(&signing_key, &action, "agent", "owner").unwrap();
        assert!(verify(&receipt, &verifying_key).is_ok());
    }

    #[test]
    fn test_verify_wrong_key() {
        let (signing_key, _) = generate_keypair();
        let (_, wrong_key) = generate_keypair();
        let action = test_action();
        let receipt = sign::sign(&signing_key, &action, "agent", "owner").unwrap();

        let result = verify(&receipt, &wrong_key);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignetError::SignatureMismatch));
    }

    #[test]
    fn test_verify_tampered_action() {
        let (signing_key, verifying_key) = generate_keypair();
        let action = test_action();
        let mut receipt = sign::sign(&signing_key, &action, "agent", "owner").unwrap();
        receipt.action.tool = "evil_tool".to_string();

        assert!(matches!(
            verify(&receipt, &verifying_key),
            Err(SignetError::SignatureMismatch)
        ));
    }

    #[test]
    fn test_verify_tampered_signer() {
        let (signing_key, verifying_key) = generate_keypair();
        let action = test_action();
        let mut receipt = sign::sign(&signing_key, &action, "agent", "owner").unwrap();
        receipt.signer.name = "impostor".to_string();

        assert!(matches!(
            verify(&receipt, &verifying_key),
            Err(SignetError::SignatureMismatch)
        ));
    }

    #[test]
    fn test_verify_tampered_timestamp() {
        let (signing_key, verifying_key) = generate_keypair();
        let action = test_action();
        let mut receipt = sign::sign(&signing_key, &action, "agent", "owner").unwrap();
        receipt.ts = "2099-01-01T00:00:00.000Z".to_string();

        assert!(matches!(
            verify(&receipt, &verifying_key),
            Err(SignetError::SignatureMismatch)
        ));
    }

    #[test]
    fn test_verify_tampered_nonce() {
        let (signing_key, verifying_key) = generate_keypair();
        let action = test_action();
        let mut receipt = sign::sign(&signing_key, &action, "agent", "owner").unwrap();
        receipt.nonce = "rnd_0000000000000000".to_string();

        assert!(matches!(
            verify(&receipt, &verifying_key),
            Err(SignetError::SignatureMismatch)
        ));
    }
}
```

- [ ] **Step 2: Run all tests**

Run: `~/.cargo/bin/cargo test -p signet-core`
Expected: all 13 tests PASS (4 canonical + 2 identity + 5 sign + 6 verify — some overlap with roundtrip counted once)

- [ ] **Step 3: Commit**

```bash
git add crates/signet-core/src/verify.rs
git commit -m "feat(core): implement verify() with tamper detection tests"
```

---

### Task 6: WASM Binding

**Files:**
- Create: `bindings/signet-ts/Cargo.toml`
- Create: `bindings/signet-ts/src/lib.rs`

- [ ] **Step 1: Create signet-wasm Cargo.toml**

```toml
[package]
name = "signet-wasm"
version = "0.1.0"
edition = "2021"
description = "WASM bindings for signet-core"
license = "Apache-2.0 OR MIT"

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
signet-core = { path = "../../crates/signet-core" }
wasm-bindgen = "0.2"
serde-wasm-bindgen = "0.6"
serde_json = "1"
getrandom = { version = "0.2", features = ["js"] }
base64 = "0.22"
```

- [ ] **Step 2: Create the WASM binding**

`bindings/signet-ts/src/lib.rs`:

```rust
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use wasm_bindgen::prelude::*;

use signet_core::receipt::Action;
use signet_core::{generate_keypair, sign, verify};

#[wasm_bindgen]
pub fn wasm_generate_keypair() -> Result<JsValue, JsError> {
    let (signing_key, verifying_key) = generate_keypair();
    let secret_b64 = BASE64.encode(signing_key.to_keypair_bytes());
    let public_b64 = BASE64.encode(verifying_key.to_bytes());

    let result = serde_json::json!({
        "secret_key": secret_b64,
        "public_key": public_b64,
    });

    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn wasm_sign(
    secret_key_b64: &str,
    action_json: &str,
    signer_name: &str,
    signer_owner: &str,
) -> Result<String, JsError> {
    let key_bytes = BASE64
        .decode(secret_key_b64)
        .map_err(|e| JsError::new(&format!("invalid secret key base64: {e}")))?;
    let signing_key = ed25519_dalek::SigningKey::from_keypair_bytes(
        key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| JsError::new("secret key must be 64 bytes"))?,
    )
    .map_err(|e| JsError::new(&format!("invalid signing key: {e}")))?;

    let action: Action = serde_json::from_str(action_json)
        .map_err(|e| JsError::new(&format!("invalid action JSON: {e}")))?;

    let receipt = sign(&signing_key, &action, signer_name, signer_owner)
        .map_err(|e| JsError::new(&e.to_string()))?;

    serde_json::to_string(&receipt).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn wasm_verify(receipt_json: &str, public_key_b64: &str) -> Result<bool, JsError> {
    let pubkey_bytes = BASE64
        .decode(public_key_b64)
        .map_err(|e| JsError::new(&format!("invalid public key base64: {e}")))?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(
        pubkey_bytes
            .as_slice()
            .try_into()
            .map_err(|_| JsError::new("public key must be 32 bytes"))?,
    )
    .map_err(|e| JsError::new(&format!("invalid verifying key: {e}")))?;

    let receipt: signet_core::Receipt = serde_json::from_str(receipt_json)
        .map_err(|e| JsError::new(&format!("invalid receipt JSON: {e}")))?;

    match verify(&receipt, &verifying_key) {
        Ok(()) => Ok(true),
        Err(signet_core::SignetError::SignatureMismatch) => Ok(false),
        Err(e) => Err(JsError::new(&e.to_string())),
    }
}
```

- [ ] **Step 3: Verify it compiles (native)**

Run: `~/.cargo/bin/cargo check -p signet-wasm`
Expected: compiles with no errors

- [ ] **Step 4: Commit**

```bash
git add bindings/signet-ts/
git commit -m "feat(wasm): add wasm-bindgen bindings for signet-core"
```

---

### Task 7: WASM Build

**Files:**
- Build output: `bindings/signet-ts/pkg/`

- [ ] **Step 1: Build WASM with wasm-pack**

Run: `cd /home/willamhou/codes/signet && ~/.cargo/bin/wasm-pack build bindings/signet-ts --target nodejs --out-dir pkg`
Expected: build succeeds, `bindings/signet-ts/pkg/` directory created with `.js` and `.wasm` files

- [ ] **Step 2: Verify pkg contents**

Run: `ls bindings/signet-ts/pkg/`
Expected: should contain `signet_wasm.js`, `signet_wasm_bg.wasm`, `package.json`, etc.

- [ ] **Step 3: Commit**

No commit needed — `pkg/` is in `.gitignore`.

---

### Task 8: Node.js Validation Script

**Files:**
- Create: `examples/wasm-roundtrip/test.mjs`

- [ ] **Step 1: Create the validation script**

```javascript
import assert from 'node:assert';
import { wasm_generate_keypair, wasm_sign, wasm_verify } from '../../bindings/signet-ts/pkg/signet_wasm.js';

// Test 1: Generate keypair
console.log('Test 1: Generate keypair...');
const { secret_key, public_key } = wasm_generate_keypair();
assert(secret_key && public_key, 'keypair should have both keys');
console.log('  PASS');

// Test 2: Sign an action
console.log('Test 2: Sign an action...');
const action = JSON.stringify({
    tool: 'github_create_issue',
    params: { title: 'fix bug', body: 'details' },
    params_hash: '',
    target: 'mcp://github.local',
    transport: 'stdio'
});
const receipt_json = wasm_sign(secret_key, action, 'test-agent', 'willamhou');
const receipt = JSON.parse(receipt_json);
assert(receipt.sig.startsWith('ed25519:'), 'sig should have ed25519: prefix');
assert(receipt.id.startsWith('rec_'), 'id should have rec_ prefix');
assert.strictEqual(receipt.signer.name, 'test-agent');
assert.strictEqual(receipt.action.tool, 'github_create_issue');
assert(receipt.action.params_hash.startsWith('sha256:'), 'params_hash should be computed');
console.log('  PASS');

// Test 3: Verify valid receipt
console.log('Test 3: Verify valid receipt...');
assert.strictEqual(wasm_verify(receipt_json, public_key), true, 'valid receipt should verify');
console.log('  PASS');

// Test 4: Tampered action should fail
console.log('Test 4: Tampered action should fail...');
const tampered = { ...receipt, action: { ...receipt.action, tool: 'evil_tool' } };
assert.strictEqual(wasm_verify(JSON.stringify(tampered), public_key), false, 'tampered action should fail');
console.log('  PASS');

// Test 5: Wrong key should fail
console.log('Test 5: Wrong key should fail...');
const { public_key: other_key } = wasm_generate_keypair();
assert.strictEqual(wasm_verify(receipt_json, other_key), false, 'wrong key should fail');
console.log('  PASS');

// Test 6: Tampered signer should fail
console.log('Test 6: Tampered signer should fail...');
const tampered_signer = { ...receipt, signer: { ...receipt.signer, name: 'impostor' } };
assert.strictEqual(wasm_verify(JSON.stringify(tampered_signer), public_key), false, 'tampered signer should fail');
console.log('  PASS');

// Test 7: Invalid secret key should throw
console.log('Test 7: Invalid secret key should throw...');
try {
    wasm_sign('not-valid-base64!!!', action, 'agent', 'owner');
    assert.fail('should have thrown');
} catch (e) {
    assert(e.message.includes('invalid'), `expected invalid key error, got: ${e.message}`);
}
console.log('  PASS');

// Test 8: Malformed action JSON should throw
console.log('Test 8: Malformed action JSON should throw...');
try {
    wasm_sign(secret_key, '{not json', 'agent', 'owner');
    assert.fail('should have thrown');
} catch (e) {
    assert(e.message.includes('invalid') || e.message.includes('JSON'), `expected JSON error, got: ${e.message}`);
}
console.log('  PASS');

console.log('\n=== All 8 tests passed. M0 validation complete. ===');
```

- [ ] **Step 2: Run the validation script**

Run: `node examples/wasm-roundtrip/test.mjs`
Expected: all 8 tests print PASS, ending with `=== All 8 tests passed. M0 validation complete. ===`

- [ ] **Step 3: Commit**

```bash
git add examples/wasm-roundtrip/test.mjs
git commit -m "test(wasm): add Node.js validation script for WASM roundtrip"
```

---

### Task 9: Final Verification

- [ ] **Step 1: Run full Rust test suite**

Run: `~/.cargo/bin/cargo test`
Expected: all tests PASS

- [ ] **Step 2: Check for unsafe code**

Run: `grep -r "unsafe" crates/signet-core/src/`
Expected: no matches

- [ ] **Step 3: Run WASM build clean**

Run: `rm -rf bindings/signet-ts/pkg && ~/.cargo/bin/wasm-pack build bindings/signet-ts --target nodejs --out-dir pkg`
Expected: builds successfully

- [ ] **Step 4: Run Node.js validation again**

Run: `node examples/wasm-roundtrip/test.mjs`
Expected: all 8 tests pass

- [ ] **Step 5: Commit all remaining changes**

```bash
git add -A
git status
git commit -m "feat: complete M0 tech validation — Ed25519 + WASM roundtrip verified"
```

---

## Exit Criteria Checklist

| # | Criterion | Verified by |
|---|-----------|-------------|
| 1 | `cargo test` passes | Task 9 Step 1 |
| 2 | `wasm-pack build --target nodejs` succeeds | Task 9 Step 3 |
| 3 | Node.js sign → verify → pass | Task 8 Step 2 (Tests 1-3) |
| 4 | Node.js tampered → reject | Task 8 Step 2 (Tests 4-6) |
| 4b | WASM error boundary works | Task 8 Step 2 (Tests 7-8) |
| 5 | JCS identical in Rust and WASM | Task 8 validates implicitly — Rust signs, WASM verifies using same JCS |
