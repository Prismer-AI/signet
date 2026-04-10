# RFC-0001: Delegation Chain for Agent Authorization

- **Status:** Implemented (v0.6, 2026-04-09)
- **Author:** Signet Contributors
- **Created:** 2026-04-06
- **Target version:** v0.6+

## Summary

Extend Signet's signing model with cryptographically verifiable **delegation chains**, enabling an owner to grant scoped authority to an agent, and agents to delegate subsets of their authority to sub-agents. Each tool call receipt carries proof of the full authorization path.

## Problem

Today, Signet's `Signer.owner` field is **self-declared**:

```rust
pub struct Signer {
    pub pubkey: String,   // ed25519:<base64>
    pub name: String,     // "deploy-bot"
    pub owner: String,    // self-declared, not verified
}
```

This means:
1. Any agent can claim any owner — there is no cryptographic binding between an identity and a key.
2. Signet receipts prove **"key K signed action A"**, but not **"owner O authorized key K to perform action A"**.
3. Without authorization proof, attestation is audit noise — you know *what* happened, but not *whether it was allowed*.

This gap was identified in SECURITY.md and TODOS.md as a known limitation.

## Proposal

### Delegation Token

A **DelegationToken** is a signed statement from a delegator granting scoped authority to a delegate.

```
DelegationToken {
    v: 1,
    id: "<sha256 of sig>",
    delegator: {
        pubkey: "ed25519:<base64>",
        name: "alice",
    },
    delegate: {
        pubkey: "ed25519:<base64>",
        name: "deploy-bot",
    },
    scope: {
        tools: ["Bash", "Read", "Write"],   // allowed tools, or ["*"] for all
        targets: ["mcp://github.local"],     // allowed targets, or ["*"]
        max_depth: 1,                        // can this delegate re-delegate? 0 = no
        expires: "2026-04-07T00:00:00Z",     // optional TTL
        budget: null,                        // future: token/cost budget
    },
    issued_at: "2026-04-06T12:00:00Z",
    nonce: "<random>",
    sig: "ed25519:<base64>",                 // delegator signs this token
}
```

Key properties:
- **Scoped:** The delegator specifies which tools, targets, and depth are allowed.
- **Time-bound:** Optional expiration via `expires`.
- **Chain-aware:** `max_depth` controls whether the delegate can further delegate (and how deep).
- **Verifiable:** The token is signed by the delegator's Ed25519 key.

### Delegation Chain

A chain is an ordered list of DelegationTokens proving authorization from a root identity down to the signing agent:

```
Root Owner (human/org key)
    │
    └─ DelegationToken: owner → agent-A (scope: tools=["*"], targets=["*"], max_depth=2)
            │
            └─ DelegationToken: agent-A → agent-B (scope: tools=["Bash","Read"], max_depth=0)
                    │
                    └─ Receipt: agent-B signs tool call (tool="Bash")
```

Each token in the chain must satisfy:
1. The `delegate.pubkey` of token N must equal the `delegator.pubkey` of token N+1.
2. The scope of token N+1 must be a **subset** of token N's scope (monotonically narrowing).
3. The chain depth must not exceed the `max_depth` of any ancestor token.
4. No token in the chain is expired.

### Receipt Extension

Receipts gain an optional `authorization` field:

```
Receipt {
    v: 4,                           // new version
    action: { tool, params, ... },
    signer: { pubkey, name, owner },
    authorization: {                // NEW — optional, omit for v1/v2/v3 compat
        chain: [DelegationToken, ...],
        root_pubkey: "ed25519:<base64>",
    },
    ts: "...",
    nonce: "...",
    sig: "ed25519:<base64>",
}
```

### Verification

`verify_authorized(receipt, trusted_roots)` performs:

1. Standard signature verification (existing `verify()`).
2. Walk the `authorization.chain` from root to signer:
   a. Verify each DelegationToken signature.
   b. Check pubkey continuity (delegate of N = delegator of N+1).
   c. Check scope narrows monotonically.
   d. Check depth limits.
   e. Check expiration.
3. Verify the receipt's `signer.pubkey` matches the final delegate.
4. Verify the receipt's `action.tool` and `action.target` are within the final scope.
5. Verify the `root_pubkey` is in the caller's `trusted_roots` set.

If any step fails, return a typed error indicating which check failed.

### Scope Model

```
Scope {
    tools: [String],        // tool names, or ["*"] for wildcard
    targets: [String],      // target URIs, or ["*"] for wildcard
    max_depth: u32,         // 0 = cannot re-delegate
    expires: Option<String>, // ISO 8601 timestamp
    budget: Option<Budget>,  // future extension
}
```

**Scope narrowing rule:** A child scope S' is valid under parent scope S if and only if:
- `S'.tools ⊆ S.tools` (or S.tools is `["*"]`)
- `S'.targets ⊆ S.targets` (or S.targets is `["*"]`)
- `S'.max_depth < S.max_depth`
- `S'.expires <= S.expires` (if parent has expiration)

### Root Identity

The root of a delegation chain is a key that represents a human, organization, or governance entity. This RFC does **not** specify how root identity is established — it could be:

- A self-generated key pair (current Signet model)
- An organization key published in DNS TXT / `.well-known`
- A key registered with a future identity registry (e.g., QNTM Agent Identity WG)
- An existing PKI certificate mapped to Ed25519

The root identity problem is orthogonal to the delegation chain mechanism. This RFC provides the chain; identity registries provide the root.

## Backward Compatibility

- v1/v2/v3 receipts remain valid — the `authorization` field is optional.
- `verify()`, `verify_compound()`, `verify_bilateral()` continue to work unchanged.
- `verify_authorized()` is a new function — callers opt in.
- `verify_any()` will accept v4 but only verify signature, not authorization (use `verify_authorized()` for full check).

## What This RFC Does NOT Cover

- **Identity registry:** How root keys map to real-world identities. Deferred to a separate RFC.
- **Revocation:** How to revoke a delegation token before expiry. Requires online checking or CRL — deferred.
- **Budget enforcement:** Tracking spend against a delegation budget. Deferred.
- **Multi-signature:** Requiring N-of-M delegators to agree. Deferred.
- **Cross-organization delegation:** Agent A (org X) delegates to Agent B (org Y). Requires identity federation — deferred.

## Relationship to Existing Standards

| Standard | Relationship |
|----------|-------------|
| X.509 certificate chains | Inspiration for chain structure, but simpler (no CA hierarchy, no ASN.1) |
| SPIFFE/SPIRE | Similar identity-to-workload binding, but for cloud services not agents |
| OAuth 2.0 scopes | Scope model is similar, but delegation tokens are signed + offline-verifiable |
| APS PolicyReceipt | DelegationToken can map to APS ActionIntent; adapter possible |
| SEP-1763 Policy gate | Delegation chain fills the "policy gate" layer in the SEP-1763 stack |
| ZCAP-LD (W3C) | Object capability model for linked data — closest prior art for delegated authorization |

## Open Questions

1. **Should the chain be embedded in every receipt, or referenced by ID?** Embedding is simpler but adds size. Reference requires a lookup service.
2. **Wildcard semantics:** Should `["*"]` mean "everything that exists now" or "everything including future tools"?
3. **Scope intersection vs narrowing:** If agent A has `tools: ["Bash", "Read"]` and delegates `tools: ["Bash", "Write"]`, is `Write` silently dropped or is the token invalid?
4. **Correlation with monitoring:** Should the delegation chain include a `correlation_id` field to link receipts to external monitoring events (e.g., Aegis EDR)?

## Implementation Phases

1. **Phase 0 (now):** This RFC. Collect feedback.
2. **Phase 1:** `DelegationToken` type + `sign_delegation()` + `verify_delegation()` in signet-core.
3. **Phase 2:** `verify_authorized()` for v4 receipts with embedded chains.
4. **Phase 3:** CLI `signet delegate --to <name> --scope <json>` command.
5. **Phase 4:** TypeScript + Python bindings.
6. **Phase 5:** Integration with identity registries (separate RFC).

## References

- [SECURITY.md](../SECURITY.md) — Current threat model and known gaps
- [ZCAP-LD](https://w3c-ccg.github.io/zcap-spec/) — W3C object capability delegation
- [SPIFFE](https://spiffe.io/) — Secure Production Identity Framework
- [SEP-1763](https://github.com/anthropics/sep) — AI agent enforcement stack
