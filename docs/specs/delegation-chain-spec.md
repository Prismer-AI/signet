# Technical Spec: Delegation Chains (Signet v0.6)

Date: 2026-04-09
Status: Implemented (v3 — all phases completed 2026-04-09)
Based on: RFC-0001

---

## 0. Open Question Decisions

**Q1: Embed chain in every receipt, or reference by ID?**
Decision: **Always embed.** Elided mode (where a receipt carries only `chain_hash` as an external reference, with the full chain stored elsewhere) is deferred to a future version. Rationale: elided mode requires a resolver/cache API that adds complexity without a concrete use case yet. Offline verifiability requires the full chain. Note: `Authorization.chain_hash` still exists but serves a different purpose — it binds the receipt signature to the chain content without including the full chain in the signable payload (see section 7). Re-evaluate elided mode when chain sizes exceed 5KB in practice.

**Q2: Wildcard semantics — "everything now" or "everything including future"?**
Decision: **Everything including future tools.** `["*"]` means any tool/target at invocation time, including tools added after token issuance. If restricting, enumerate explicitly.

**Q3: Scope intersection vs rejection on invalid narrowing?**
Decision: **Reject with typed error.** `sign_delegation()` returns `ScopeViolation("tool 'Write' not in parent scope")`. No silent intersection.

**Q4: Should delegation tokens include a `correlation_id`?**
Decision: **Yes, optional and unsigned.** Not included in signed payload. Zero cost when unused.

---

## 1. Data Structures

### 1.1 New Types (`crates/signet-core/src/delegation.rs`)

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DelegationIdentity {
    pub pubkey: String,  // "ed25519:<base64>" — validated on sign/verify
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Scope {
    pub tools: Vec<String>,         // tool names, or ["*"]
    pub targets: Vec<String>,       // target URIs, or ["*"]
    pub max_depth: u32,             // 0 = cannot re-delegate
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,    // RFC 3339 with UTC suffix (Z)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<serde_json::Value>,  // reserved for future use, forward-compat
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationToken {
    pub v: u8,                      // always 1
    pub id: String,                 // "del_" + 32 lowercase hex chars (first 16 bytes of SHA-256 of sig)
    pub delegator: DelegationIdentity,
    pub delegate: DelegationIdentity,
    pub scope: Scope,
    pub issued_at: String,          // RFC 3339 with UTC suffix (Z)
    pub nonce: String,              // "rnd_<hex>"
    pub sig: String,                // "ed25519:<base64>"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,  // unsigned annotation
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Authorization {
    pub chain: Vec<DelegationToken>,   // ordered root→leaf, must not be empty
    pub chain_hash: String,            // "sha256:<hex>" of JCS-canonicalized chain array
    pub root_pubkey: String,           // must match chain[0].delegator.pubkey
}
```

**v4 is NOT a separate type.** Following the RFC, v4 is the existing `Receipt` with an optional `authorization` field:

```rust
// In receipt.rs — add to existing Receipt struct:
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub v: u8,                         // 1 for basic, 4 for authorized
    pub id: String,
    pub action: Action,
    pub signer: Signer,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization: Option<Authorization>,  // NEW — present when v=4
    pub ts: String,
    pub nonce: String,
    pub sig: String,
}
```

This approach:
- Matches the RFC exactly ("optional `authorization` field")
- Avoids a separate `AuthorizedReceipt` type that breaks Python/TS deserialization
- Keeps `verify_any()` able to deserialize v4 receipts
- Keeps audit.rs working (v4 uses `ts`, same as v1)

### 1.2 Signer.owner in v4 Context

The `signer.owner` field remains in the struct for backward compatibility but is **semantically superseded** by the delegation chain in v4 receipts:

- `sign_authorized()` sets `signer.owner` to the root identity name from `chain[0].delegator.name` automatically
- `verify_authorized()` does NOT trust `signer.owner` — it verifies the chain instead
- Documentation: "In v4 receipts, `signer.owner` is informational. The delegation chain is the authoritative proof of authorization."

### 1.3 New Error Variants

Add to `SignetError` in `error.rs`:

```rust
#[error("delegation scope violation: {0}")]
ScopeViolation(String),

#[error("delegation chain invalid: {0}")]
ChainError(String),

#[error("delegation token expired at {0}")]
DelegationExpired(String),

#[error("action not authorized: {0}")]
Unauthorized(String),
```

**Binding impact:** Python bindings (`bindings/signet-py/src/errors.rs`) exhaustively match `SignetError`. Adding variants requires updating the match. This must be done in Phase 1, not deferred to Phase 4.

---

## 2. API Surface

### 2.1 `sign_delegation()`

```rust
pub fn sign_delegation(
    delegator_key: &SigningKey,
    delegator_name: &str,
    delegate_pubkey: &VerifyingKey,
    delegate_name: &str,
    scope: &Scope,
    parent_scope: Option<&Scope>,
) -> Result<DelegationToken, SignetError>
```

1. Validate `delegator_key` and `delegate_pubkey` produce valid `"ed25519:<base64>"` strings
2. If `parent_scope` is `Some(ps)`, call `validate_scope_narrowing(scope, ps)?`
3. Build identities, generate nonce (`rnd_<32-hex-chars>`), get timestamp (RFC 3339 UTC)
4. Build signable payload (see section 7), JCS-canonicalize, sign with `delegator_key`
5. Derive `id` as `"del_" + hex::encode(&sha256(sig)[..16])` (32 hex chars)

### 2.2 `verify_delegation()`

```rust
pub fn verify_delegation(
    token: &DelegationToken,
    at: Option<DateTime<Utc>>,  // defaults to Utc::now() if None
) -> Result<(), SignetError>
```

1. Validate `delegator.pubkey` has `"ed25519:"` prefix, decode to `VerifyingKey`
2. Reconstruct signable JSON (section 7), JCS-canonicalize, verify signature
3. If `scope.expires` is `Some(t)`, parse as RFC 3339, check `t + clock_skew >= at`. Return `DelegationExpired` if past.

The `at` parameter enables:
- Passing a consistent timestamp through the entire chain (fixes TOCTOU)
- Replaying/auditing old receipts at their original timestamp

### 2.3 `verify_chain()`

```rust
pub fn verify_chain(
    chain: &[DelegationToken],
    trusted_roots: &[VerifyingKey],
    at: Option<DateTime<Utc>>,  // defaults to Utc::now() if None
) -> Result<Scope, SignetError>
```

Algorithm:

1. If `chain.is_empty()`, return `ChainError("empty delegation chain")`
2. If `chain.len() > 16`, return `ChainError("chain exceeds maximum depth of 16")`
3. Resolve `verification_time = at.unwrap_or_else(Utc::now)`
4. Check `chain[0].delegator.pubkey` is in `trusted_roots`
5. For each token at index `i` (0-indexed):
   a. `verify_delegation(&chain[i], Some(verification_time))?`
   b. If `i > 0`: pubkey continuity — `chain[i].delegator.pubkey == chain[i-1].delegate.pubkey`
   c. If `i > 0`: `validate_scope_narrowing(&chain[i].scope, &chain[i-1].scope)?`
   d. Depth check: `(chain.len() - 1 - i) <= chain[i].scope.max_depth as usize`
6. Return `chain.last().unwrap().scope.clone()`

**max_depth worked example:**

```
chain[0]: root→A   max_depth=2   remaining below = 3-1-0 = 2  ✓ (2 <= 2)
chain[1]: A→B      max_depth=1   remaining below = 3-1-1 = 1  ✓ (1 <= 1)
chain[2]: B→C      max_depth=0   remaining below = 3-1-2 = 0  ✓ (0 <= 0)

Meaning: max_depth=N means "this delegate may create at most N more levels below."
```

**Failing example:**

```
chain[0]: root→A   max_depth=1   remaining below = 3-1-0 = 2  ✗ (2 > 1)
→ ChainError("depth limit exceeded at index 0: max_depth=1 but 2 levels remain")
```

### 2.4 `verify_authorized()`

```rust
pub struct AuthorizedVerifyOptions {
    pub trusted_roots: Vec<VerifyingKey>,
    pub clock_skew_secs: u64,  // default: 60, applied to delegation expiry checks
    pub max_chain_depth: usize, // default: 16
}

pub fn verify_authorized(
    receipt: &Receipt,
    options: &AuthorizedVerifyOptions,
) -> Result<Scope, SignetError>
```

1. Check `receipt.v == 4` and `receipt.authorization.is_some()`, return error otherwise
2. Verify receipt signature (signable payload uses `chain_hash`, NOT full chain — see section 7)
3. Verify `authorization.chain_hash == sha256(JCS(authorization.chain))`
4. `let at = parse_rfc3339(receipt.ts)? + Duration::seconds(options.clock_skew_secs)`
5. `verify_chain(&authorization.chain, &options.trusted_roots, Some(at))?` → effective scope
6. Check `signer.pubkey == chain.last().delegate.pubkey`
7. Check `root_pubkey == chain[0].delegator.pubkey`
8. Check `action.tool` in effective scope tools (or scope is `["*"]`)
9. Check `action.target` in effective scope targets (or scope is `["*"]`)
10. Return effective scope

Note: `clock_skew_secs` flows through to `verify_chain()` → `verify_delegation()` via the `at` parameter. It is not dead API. The skew is applied one-directionally: `at = receipt.ts + clock_skew_secs`. This provides a grace period — delegations that expired up to `clock_skew_secs` before the receipt timestamp are still accepted. Delegations that are clearly valid at receipt time are unaffected.

### 2.5 `sign_authorized()`

```rust
pub fn sign_authorized(
    key: &SigningKey,
    action: &Action,
    signer_name: &str,
    chain: Vec<DelegationToken>,
) -> Result<Receipt, SignetError>
```

1. Reject empty chain
2. Compute `params_hash` (reuse `compute_params_hash` from sign.rs)
3. Set `signer.owner = chain[0].delegator.name.clone()` (auto-derived, not caller-supplied)
4. Compute `chain_hash = sha256(JCS(chain))`
5. Build `Authorization { chain, chain_hash, root_pubkey: chain[0].delegator.pubkey }`
6. Build signable payload with `v: 4`, include `chain_hash` (NOT full chain) in signed bytes
7. JCS-canonicalize, sign, derive ID
8. Return `Receipt { v: 4, authorization: Some(authorization), ... }`

Existing `sign()` is NOT modified. This is additive.

**Rust implementation note:** `chain[0].delegator.pubkey` and `chain[0].delegator.name` must be extracted before `chain` is moved into `Authorization`. Compute `root_pubkey` and `signer_owner` first, then move `chain`.

### 2.6 `verify_any()` Update

Add `v: 4` branch that performs **signature-only verification** (no chain check). Because v4 signs a different payload shape (includes `chain_hash` and `root_pubkey`), it CANNOT reuse the existing `verify()` function. A dedicated `verify_v4_signature_only()` is needed:

```rust
4 => {
    let receipt: Receipt = serde_json::from_value(raw)?;
    verify_v4_signature_only(&receipt, pubkey)?;
    Ok(())
}
```

`verify_v4_signature_only()` reconstructs the v4 signable payload `{v, action, signer, authorization: {chain_hash, root_pubkey}, ts, nonce}` and verifies the signature. It does NOT verify the chain — that requires `verify_authorized()`.

**Why not reuse `verify()`:** The existing `verify()` builds its signable from `{v, action, signer, ts, nonce}`. v4 receipts were signed with `{v, action, signer, authorization: {chain_hash, root_pubkey}, ts, nonce}`. Using `verify()` would always fail because the payload doesn't match what was signed.

This matches the RFC ("verify_any() will accept v4 but only verify signature") and keeps the audit verifier working (`audit.rs:450` calls `verify_any()` on stored receipts).

### 2.7 `audit.rs` Changes

`extract_timestamp()` currently routes `v >= 3` to `ts_response`. v4 uses `ts` (like v1), but v2 uses `ts_request` (not `ts`). Fix with explicit routing per version:

```rust
match v {
    1 | 4 => receipt["ts"].as_str(),
    2 => receipt["ts_request"].as_str(),
    3 => receipt["ts_response"].as_str(),
    _ => None,
}
```

This is a **required change** in Phase 2, not "unchanged."

---

## 3. Scope Narrowing Algorithm

`validate_scope_narrowing(child: &Scope, parent: &Scope) -> Result<(), SignetError>`

**Tools:**
- Parent `["*"]` → any child valid
- Child `["*"]` with non-wildcard parent → `ScopeViolation("child cannot have wildcard tools when parent has explicit tools")`
- Otherwise: every child tool must exist in parent tools

**Targets:** Same rules as tools.

**max_depth:**
- `child.max_depth < parent.max_depth` (strictly less than)
- Parent `max_depth == 0` → `ScopeViolation("parent max_depth is 0, cannot delegate")`

**Expiry:**
- Parent has expiry, child has none → `ScopeViolation("child must have expiry when parent does")`
- Parent has expiry, child has expiry → parse both as RFC 3339 `DateTime<Utc>`, check `child <= parent`
- Parent has no expiry → any child expiry valid

**Budget:** Ignored in v1. `validate_scope_narrowing` does not check `budget`. Forward-compat only.

---

## 4. File Changes

### New Files

| File | Contents |
|------|----------|
| `crates/signet-core/src/delegation.rs` | Types: `DelegationToken`, `DelegationIdentity`, `Scope`, `Authorization`, `validate_scope_narrowing()` |
| `crates/signet-core/src/sign_delegation.rs` | `sign_delegation()`, `sign_authorized()` |
| `crates/signet-core/src/verify_delegation.rs` | `verify_delegation()`, `verify_chain()`, `verify_authorized()`, `AuthorizedVerifyOptions` |

### Modified Files

| File | Change |
|------|--------|
| `lib.rs` | Add modules + re-exports |
| `error.rs` | Add 4 error variants |
| `receipt.rs` | Add `authorization: Option<Authorization>` to `Receipt` |
| `verify.rs` | Add v4 branch to `verify_any()` + `verify_v4_signature_only()` helper |
| `sign.rs` | Extract `compute_params_hash` and `validate_params_hash` to `pub(crate)` |
| `audit.rs` | Fix `extract_timestamp()` to route v4 to `ts` not `ts_response` |
| `bindings/signet-py/src/errors.rs` | Add match arms for 4 new error variants |

### Unchanged

`canonical.rs`, `identity.rs`

---

## 5. Edge Cases

| Case | Behavior |
|------|----------|
| Empty chain | `ChainError("empty delegation chain")` |
| Self-delegation (delegator == delegate) | Allowed — legitimate for capability attenuation |
| Expired token mid-chain | `DelegationExpired` at that index, using unified `at` timestamp |
| Scope with unknown tools | Valid — string-based, no registry check |
| max_depth=0 re-delegating | `ScopeViolation` at sign time, `ChainError` at verify time |
| root_pubkey mismatch | `ChainError` |
| Chain > 16 levels | `ChainError("chain exceeds maximum depth of 16")` |
| Duplicate tokens | Caught by pubkey continuity or depth check |
| v4 receipt in verify_any() | Signature-only verification (no chain check) |
| v4 receipt in audit.rs | Uses `ts` field (same as v1/v2), not `ts_response` |
| Old receipt verified after delegation expires | Pass `at` = receipt's `ts` for historical verification |

---

## 6. Implementation Phases

| Phase | Scope | Tests |
|-------|-------|-------|
| 1 | Types in `delegation.rs` + `sign_delegation()` + `verify_delegation()` + scope narrowing + error variants + **Python error match update** | Unit: roundtrip, scope validation, expiry, depth, pubkey format |
| 2 | `Receipt.authorization` field + `verify_chain()` + `sign_authorized()` + `verify_authorized()` + `verify_any()` v4 + `audit.rs` timestamp fix | Integration: 3-level chain → v4 receipt → verification → audit roundtrip |
| 3 | CLI: `signet delegate`, `signet verify --authorized` | E2E: full delegate → sign → verify flow |
| 4 | TypeScript + Python bindings for delegation API | Cross-language roundtrip tests |

---

## 7. Signable Payloads

### DelegationToken (excludes `sig`, `id`, `correlation_id`, `budget`)

```json
{
  "v": 1,
  "delegator": { "pubkey": "ed25519:...", "name": "alice" },
  "delegate": { "pubkey": "ed25519:...", "name": "deploy-bot" },
  "scope": { "tools": ["Bash", "Read"], "targets": ["mcp://github"], "max_depth": 1, "expires": "2026-04-10T00:00:00Z" },
  "issued_at": "2026-04-09T12:00:00Z",
  "nonce": "rnd_abcdef0123456789abcdef0123456789"
}
```

### v4 Receipt (excludes `sig`, `id`; uses `chain_hash` NOT full chain)

```json
{
  "v": 4,
  "action": { "tool": "Bash", "params_hash": "sha256:...", "target": "mcp://github", "transport": "stdio" },
  "signer": { "pubkey": "ed25519:...", "name": "deploy-bot", "owner": "alice" },
  "authorization": { "chain_hash": "sha256:...", "root_pubkey": "ed25519:..." },
  "ts": "2026-04-09T12:00:01Z",
  "nonce": "rnd_..."
}
```

Note: The full `chain` array is in the receipt JSON but excluded from the signable payload. Only `chain_hash` and `root_pubkey` are signed. This keeps receipt signature verification O(1) regardless of chain length, while the full chain is still available for `verify_chain()`.

---

## 8. Security Considerations

- Signed scope is immutable — delegate cannot widen without forging delegator's signature
- Monotonic narrowing prevents privilege escalation
- Nonce ensures token uniqueness
- `correlation_id` is unsigned — no security impact
- No revocation in v1 — mitigated by short-lived `expires`
- Chain length cap (16, configurable via `AuthorizedVerifyOptions`) prevents verification DoS
- **Wildcard warning:** Tokens with `["*"]` tools/targets automatically cover future tools. Use short expiry times for wildcard delegations. Systems adding new high-privilege tools should evaluate whether existing wildcard delegations should cover them.
- `signer.owner` is informational in v4 — the chain is the authoritative proof. Do not use `signer.owner` for access control decisions on v4 receipts.
- `budget` field is reserved but not enforced — do not rely on it for spend control until a future spec defines enforcement semantics.
- Receipt signature binds `chain_hash`, not the full chain. An attacker who can find a SHA-256 collision could substitute a different chain with the same hash. This is considered infeasible with current cryptography.

---

## 9. Resolved Review Findings

Issues addressed in this revision (v2):

| # | Issue | Source | Resolution |
|---|-------|--------|------------|
| 1 | audit.rs extract_timestamp breaks v4 | Codex | Added explicit v4→ts routing in section 2.7 and file changes |
| 2 | Elided chain mode unsafe | Codex | Removed elided mode from v1 spec (Q1 decision revised) |
| 3 | max_depth formula imprecise | Claude | Added explicit formula + worked example in section 2.3 |
| 4 | budget field forward-compat | Claude | Added `budget: Option<Value>` to Scope |
| 5 | Expiry TOCTOU / offline audit | Both | Added `at: Option<DateTime>` param to verify_delegation/verify_chain |
| 6 | Signer.owner contradicts RFC | Both | Auto-derived from chain root, documented as informational in v4 |
| 7 | verify_any() v4 breaks audit | Codex | Changed to signature-only verification (matches RFC) |
| 8 | Error variants break Python | Codex | Added to Phase 1 scope explicitly |
| 9 | Separate AuthorizedReceipt type | Codex | Changed to optional field on existing Receipt (matches RFC) |
| 10 | Sign full chain O(n) overhead | Claude | Sign chain_hash instead, chain still embedded for offline verify |
| 11 | compute_params_hash + validate | Claude | Both marked pub(crate) in file changes |
| 12 | Wildcard security risk | Claude | Added warning in security section |
| 13 | pubkey format validation | Claude | Added to sign/verify steps |
| 14 | expires string comparison | Claude | Mandated RFC 3339, parse to DateTime for comparison |
| 15 | Token ID length unclear | Claude | Specified "32 lowercase hex chars" |
| 16 | clock_skew_secs dead API | Codex | Flows through at param, documented in verify_authorized |

### v3 Fixes (second review pass)

| # | Issue | Source | Resolution |
|---|-------|--------|------------|
| 17 | verify_any() v4 signable payload mismatch | Claude v2 review | Added `verify_v4_signature_only()` with v4-specific payload in section 2.6 |
| 18 | clock_skew_secs one-directional — needs docs | Claude v2 review | Added explicit grace period explanation in section 2.4 |
| 19 | sign_authorized() Rust move semantics | Claude v2 review | Added implementation note in section 2.5 |
| 20 | v2 timestamp routing regression | Claude v2 review | Fixed to `1\|4 => ts, 2 => ts_request, 3 => ts_response` in section 2.7 |
| 21 | Q1 chain_hash wording ambiguity | Claude v2 review | Clarified: elided-mode removed, but chain_hash for signature binding remains |
