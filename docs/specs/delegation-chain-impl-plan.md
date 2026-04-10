# Implementation Plan: Delegation Chain (Phase 1 + Phase 2)

Date: 2026-04-09 (v2 — revised after Claude + Codex plan review)
Status: **COMPLETED** — All 4 phases implemented 2026-04-09
Based on: delegation-chain-spec.md (v3)

---

## Phase 1: Types + sign_delegation + verify_delegation + scope narrowing

### Step Order (strictly sequential)

| Step | File | Action |
|------|------|--------|
| 1.1 | `error.rs` | Add 4 error variants: ScopeViolation, ChainError, DelegationExpired, Unauthorized |
| 1.2 | `bindings/signet-py/src/errors.rs` + `__init__.py` + `_signet.pyi` | Add exception types + match arms + Python exports (must compile after 1.1) |
| 1.3 | `delegation.rs` (NEW) + `lib.rs` | Types + `validate_scope_narrowing()` + shared signable helpers. **Register module in lib.rs immediately** so tests can compile. |
| 1.4 | `delegation.rs` tests | TDD: write 15 scope narrowing tests (RED), then implement (GREEN) |
| 1.5 | `sign_delegation.rs` (NEW) + `lib.rs` | `sign_delegation()` using shared helper from delegation.rs. **Register module in lib.rs immediately.** |
| 1.6 | `verify_delegation.rs` (NEW) + `lib.rs` | `verify_delegation(token, at)` using shared helper from delegation.rs. **Register module in lib.rs immediately.** |
| 1.7 | tests | TDD: 12 sign/verify roundtrip tests (RED then GREEN) |
| 1.8 | `sign.rs` | Make `compute_params_hash` + `validate_params_hash` pub(crate) (prep for Phase 2) |

Note: lib.rs module registration happens incrementally with each new file (1.3, 1.5, 1.6), NOT deferred to the end. Each step must compile and pass `cargo check` before proceeding.

### Key Design: Shared Signable Helpers

Both helpers live in `delegation.rs` (the types module). This is the single source of truth for signable payload construction — sign and verify both call these.

```rust
// In delegation.rs — used by both sign and verify to avoid payload divergence
pub(crate) fn build_delegation_signable(
    delegator: &DelegationIdentity,
    delegate: &DelegationIdentity,
    scope: &Scope,       // excludes budget from output
    issued_at: &str,
    nonce: &str,
) -> serde_json::Value

pub(crate) fn build_v4_receipt_signable(
    action: &Action,
    signer: &Signer,
    chain_hash: &str,
    root_pubkey: &str,
    ts: &str,
    nonce: &str,
) -> serde_json::Value
```

### Phase 1 Tests (TDD)

**Scope narrowing (15 tests):**
- valid subset, wildcard parent, child wildcard with explicit parent (fail)
- tool not in parent (fail), target not in parent (fail)
- max_depth valid/equal/zero parent
- expiry valid/child later/parent has child missing/parent none
- both wildcard

**Sign/verify delegation (12 tests):**
- roundtrip, field validation, scope violation rejection
- wrong key, tampered scope/delegate
- expired, not expired, custom `at` for historical verify
- nonce uniqueness, ID derivation

---

## Phase 2: Receipt v4 + verify_chain + sign_authorized + verify_authorized + audit

### Step Order (strictly sequential)

| Step | File | Action |
|------|------|--------|
| 2.1 | `receipt.rs` + `sign.rs` | Add `authorization: Option<Authorization>` to Receipt. Only `sign.rs:99` needs `authorization: None` added (serde default handles deserialization). |
| 2.2 | `audit.rs` | Fix `extract_timestamp()`: `1\|4 => ts, 2 => ts_request, 3 => ts_response`. **Moved up — must happen before any v4 audit tests.** |
| 2.3 | `verify_delegation.rs` | `verify_chain(chain, trusted_roots, at)` — configurable depth cap via `max_chain_depth` param (default 16), depth formula, pubkey continuity |
| 2.4 | `sign_delegation.rs` | `sign_authorized(key, action, signer_name, chain)` — signs chain_hash not full chain. **Note: extract root_pubkey and signer_owner from chain BEFORE moving chain into Authorization.** |
| 2.5 | `verify_delegation.rs` | `verify_authorized(receipt, options)` + `AuthorizedVerifyOptions { trusted_roots, clock_skew_secs, max_chain_depth }`. `max_chain_depth` is passed to `verify_chain()`. |
| 2.6 | `verify.rs` | `verify_v4_signature_only()` (uses `build_v4_receipt_signable` from delegation.rs) + v4 branch in `verify_any()` |
| 2.7 | `lib.rs` | Add Phase 2 re-exports: `sign_authorized`, `verify_authorized`, `verify_chain` (as `verify_delegation_chain` to avoid collision with `audit::verify_chain`), `AuthorizedVerifyOptions` |

### Receipt struct change (Step 2.1)

Adding `authorization: Option<Authorization>` to Receipt with `#[serde(default, skip_serializing_if = "Option::is_none")]`.

**Only one struct literal to update:** `sign.rs:99` — add `authorization: None`. No other Rust code constructs `Receipt { ... }` directly. Python bindings use serde deserialization, which handles `Option` default correctly — no changes needed.

Run `cargo test` immediately after this step to verify no regressions.

### Phase 2 Tests (TDD)

**verify_chain (10 tests):**
- empty chain, single token, three-level (worked example from spec)
- depth exceeded, pubkey continuity broken, untrusted root
- expired mid-chain, scope violation mid-chain
- exceeds 16 (and configurable max_chain_depth), custom `at`

**sign_authorized + verify_authorized (12 tests):**
- roundtrip, v4 field checks, owner auto-derived
- wrong root, tool not in scope, target not in scope, wildcard scope
- tampered chain_hash, tampered chain, tampered root_pubkey, empty chain

**verify_any v4 (4 tests):**
- v4 signature-only pass, wrong key fail
- **v4 with tampered chain_hash** (signature mismatch because chain_hash is in signable)
- **v4 with tampered root_pubkey** (same)

**audit (5 tests):**
- extract_timestamp v4, **extract_timestamp v2** (regression check), audit append v4, verify_signatures v4, mixed v1-v4

**backward compat (1 test):**
- Deserialize v1 receipt JSON into new Receipt struct → `authorization` is `None`

---

## Risk Mitigations

| Risk | Mitigation |
|------|------------|
| Sign/verify payload mismatch | Shared helpers in `delegation.rs`, used by sign, verify, and verify_any |
| Receipt struct literal breakage | Only `sign.rs:99` — grep `Receipt {` to confirm |
| budget in signable | Explicitly excluded from `build_delegation_signable`, test with budget=Some |
| audit::verify_chain name collision | Re-export as `verify_delegation_chain` at crate root |
| chrono parsing edge cases | Test RFC 3339 variants: Z suffix, milliseconds, +00:00 |
| lib.rs module registration timing | Register each new module immediately, not at end |
| Python export completeness | Update `errors.rs` + `__init__.py` + `_signet.pyi` together |
| max_chain_depth dead field | Pass from AuthorizedVerifyOptions to verify_chain, test configurable limit |
| audit verify_signatures v4 path | v4 flows through verify_any → verify_v4_signature_only. Signer pubkey extraction works (same location as v1). Explicit test in audit test suite. |

---

## Success Criteria

- [ ] `cargo test` passes (all existing tests + new delegation tests)
- [ ] sign_delegation → verify_delegation roundtrip
- [ ] validate_scope_narrowing rejects all invalid narrowings
- [ ] sign_authorized → verify_authorized roundtrip (1, 2, 3-level chains)
- [ ] verify_any() accepts v4 (signature-only)
- [ ] verify_any() rejects v4 with tampered chain_hash/root_pubkey
- [ ] audit.rs correctly timestamps v1, v2, v3, v4
- [ ] verify_authorized rejects: wrong root, out-of-scope, expired, tampered
- [ ] Python bindings compile (`cargo build -p signet-py`)
- [ ] cargo clippy clean, cargo fmt --check clean
- [ ] v1 receipt JSON deserializes to Receipt with authorization=None

---

## Files Summary

**New:** `delegation.rs`, `sign_delegation.rs`, `verify_delegation.rs`

**Modified:** `error.rs`, `receipt.rs`, `sign.rs`, `verify.rs`, `audit.rs`, `lib.rs`, `bindings/signet-py/src/errors.rs`, `bindings/signet-py/python/signet_auth/__init__.py`, `bindings/signet-py/python/signet_auth/_signet.pyi`

---

## Review Findings Resolved (v2)

| # | Issue | Source | Resolution |
|---|-------|--------|------------|
| 1 | audit fix step (2.6) too late | Claude | Moved to step 2.2 (immediately after Receipt change) |
| 2 | Receipt breakage scope overstated | Claude | Clarified: only sign.rs:99 |
| 3 | lib.rs module registration too late | Codex | Register incrementally with each new file (1.3, 1.5, 1.6) |
| 4 | Python __init__.py + _signet.pyi missing | Codex | Added to step 1.2 and files summary |
| 5 | Shared helper location contradictory | Codex | Clarified: both in delegation.rs |
| 6 | Missing v4 chain_hash/root_pubkey tamper tests | Codex | Added 2 tests to verify_any section, 1 to verify_authorized |
| 7 | Missing v2 timestamp routing regression test | Codex | Added explicit v2 test to audit section |
| 8 | max_chain_depth configurable but no impl step | Codex | Added to verify_chain (2.3) and AuthorizedVerifyOptions (2.5) |
| 9 | audit::verify_signatures v4 path undocumented | Claude | Added to risk mitigations with explanation |
| 10 | verify_chain name collision re-export strategy | Claude | Re-export as verify_delegation_chain |
