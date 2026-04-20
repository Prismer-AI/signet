# RFC-0002: Composite Receipt for Cross-Layer Verification

- **Status:** Draft (discussion open, no implementation committed)
- **Author:** Signet Contributors
- **Created:** 2026-04-20
- **Target version:** TBD
- **Related:** MCP SEP-1763 discussion on multi-layer proof composition (Signet + APS + ArkForge)

## Summary

Define a minimal cross-layer binding so an MCP action with receipts from multiple governance layers (request integrity, authority and policy, execution anchoring) can be independently verified by a third party, with a single anchored digest proving all layers refer to the same action.

The design starts from one shared **origin binding** copied verbatim across layers, plus a **composite envelope** that commits per-layer receipt digests and carries its own signature. No changes to how individual layers sign today beyond adding one field to downstream layers' signable bodies.

## Problem

MCP deployments increasingly involve multiple receipt-producing layers:

- **Request integrity** — an agent signs a tool call (Signet v1 unilateral, v2 compound, v3 bilateral).
- **Authority and policy** — a gateway evaluates delegation + policy and produces its own signed decision receipt (e.g., APS).
- **Execution anchoring** — an execution layer commits its result and optionally anchors to an external log (e.g., ArkForge / Rekor).

Today there is no standardized way for a verifier with receipts from multiple layers to answer the question @aeoess framed on SEP-1763:

> Given receipts from Signet (request integrity) + APS (authority + policy) + ArkForge (execution anchoring), can a verifier check all three independently AND confirm they refer to the same action?

Without cross-layer binding, each layer proves its own internal consistency but cannot prove co-reference to the same underlying MCP action. That defeats multi-party proof composition.

## Non-goals

- Changing how any individual layer signs today.
- Defining a shared schema for layer-level receipts.
- Picking a specific anchoring backend (Rekor, blockchain, or local append-only log).
- Defining a layer-kind registry in core; profiles enumerate required kinds.

## Proposal

### Origin binding (`origin_ref`)

Every **downstream** layer receipt MUST include a signed `origin_ref`:

```json
"origin_ref": {
  "origin_receipt_id": "rec_<16hex>",
  "origin_receipt_digest": "sha256:<hex>"
}
```

- `origin_receipt_id` — ID of the originating layer's receipt (typically the Signet request receipt). Downstream layers copy this rather than minting their own.
- `origin_receipt_digest` — `SHA-256(RFC 8785 JCS(origin layer's signable body))`. Computed from the origin receipt by any party with access to it. Downstream layers copy the value verbatim into their own signable body.

The origin layer itself does NOT embed `origin_ref` in its signable body. That avoids a self-referential digest. A verifier that has the origin receipt recomputes `origin_receipt_digest` from the origin's signable body directly, then checks equality against every downstream layer's copied value.

The cryptographic binding is the digest, not the ID. `origin_receipt_id` is a convenience handle for cross-referencing and MAY collide across independent deployments; `origin_receipt_digest` is what actually binds downstream layers to the same action.

### Composite envelope

The last layer that anchors the proof emits a composite envelope:

```json
{
  "v": 1,
  "origin_ref": { "origin_receipt_id": "...", "origin_receipt_digest": "sha256:..." },
  "layers": [
    { "kind": "signet",   "receipt_digest": "sha256:..." },
    { "kind": "aps",      "receipt_digest": "sha256:..." },
    { "kind": "arkforge", "receipt_digest": "sha256:..." }
  ],
  "ts_anchor": "<RFC 3339>",
  "sig": "ed25519:..."
}
```

- `receipt_digest` for each entry is `SHA-256(RFC 8785 JCS(layer receipt's signable body))`. "Signable body" means the exact bytes that layer actually signed, not the full serialized receipt object (e.g., fields marked unsigned, such as Signet v3 `extensions`, are excluded).
- Composite `sig` covers `{v, origin_ref, layers, ts_anchor}` canonicalized with RFC 8785 JCS. Nothing outside that scope is evidence.
- `composite_digest = SHA-256(JCS({v, origin_ref, layers, ts_anchor}))` is the digest committed to the external anchor, if any. Anchoring exactly one digest per composite keeps cost bounded and verification reproducible.
- `layers` order reflects production order (request → policy → execution). Verifiers do not need to follow this order.

### Verifier rules

Verification outcomes are one of `rejected | partial | full`. The label `valid` MUST mean `full` only. Implementations MUST expose partial as a distinct machine-visible status, not collapse it into a boolean success.

1. **Full verification** requires the verifier to obtain the origin receipt and every layer receipt referenced in `layers[]`, recompute `origin_receipt_digest` from the origin signable body, and recompute each layer's `receipt_digest` from its signable body.
2. **Partial verification** accepts the composite and a subset of layer receipts. It proves that each provided layer signed the same `origin_ref` value, but does NOT prove that `origin_receipt_digest` corresponds to a real origin receipt. A composite verified partially MUST be reported as `partial`, never as `full` or `valid`.
3. Every downstream layer's receipt MUST carry `origin_ref` equal to the composite's `origin_ref`. Mismatch = reject.
4. Every layer's `receipt_digest` in the composite MUST equal `SHA-256(JCS(layer signable body))` when checked against the provided layer receipt. Mismatch = reject.
5. Duplicate `kind` values in `layers` MUST be rejected (prevents smuggling an alternate policy/execution claim).
6. Unknown `kind` values MUST be rejected unless explicitly allowed by profile (prevents ghost layers).
7. Which `kind` values are REQUIRED is profile-defined, not core. The core spec defines the binding invariant and the verification algorithm; profiles say "an MCP tool call with policy gating MUST include `signet` + `aps`," etc.
8. The composite's `sig` MUST verify against a key the verifier trusts. Anchor layer choice is profile-defined.

### What this does NOT require

- No shared schema for individual layer receipts. Signet keeps v1/v2/v3/v4; APS keeps policy/scope fields; ArkForge keeps its execution attestation.
- No layer registry in core. Profiles enumerate kinds.
- No change to each layer's signing algorithm, canonicalization rule, or key material. Downstream layers add one field (`origin_ref`) to their signable body; the origin layer is unchanged.

## Concrete mapping to Signet

- **Signet as origin** (MCP request path) — mints `origin_receipt_id = receipt.id`, `origin_receipt_digest = SHA-256(JCS(signable_body))`. Signet's signable body is defined for v1, v2, v3, and v4 today (all JCS-canonicalized before Ed25519 signing), but is reconstructed inline in signing/verification code rather than exposed as a public versioned helper. This RFC's implementation work includes exposing those per-version helpers so cross-implementation tests can share vectors.
  - v1 signable: `{v, action, signer, ts, nonce}` plus optional `policy`/`exp`
  - v2 signable: `{v, action, response, signer, ts_request, ts_response, nonce}`
  - v3 signable: `{v, agent_receipt, response, server, ts_response, nonce}`
  - v4 signable: includes `authorization.{chain_hash, root_pubkey}` only (delegation-specific, different shape from v1–v3)
- **Signet as downstream layer** — if Signet is used behind another origin (e.g., a policy gateway is the origin), Signet's receipt gains a signed `origin_ref` field. This is a schema addition to `Receipt`/`CompoundReceipt`/`BilateralReceipt`, to be done behind a version bump or as an optional signed field inside existing versions.

## Open questions

1. `origin_receipt_id` uniqueness scope. Collisions are possible across independent deployments; `origin_receipt_digest` is the cryptographic binding, so the ID only needs to be unique within a deployment context. Should the RFC require a scope qualifier?
2. Whether a composite needs its own `composite_id` distinct from `origin_receipt_id`, for cases where a single action produces multiple composites (retries, audit re-anchoring).
3. Anchor-layer indirection. The composite envelope may need an `anchor_method` field so verifiers know how to reproduce the anchoring check (Rekor log ID, blockchain tx hash, local file path, etc.).
4. Whether `origin_ref` should support chaining (a composite references another composite) or stay flat.

## Reference canonicalization

Signet uses RFC 8785 JCS via `json-canon` for signable-body canonicalization across v1/v2/v3/v4, so `origin_receipt_digest` and `receipt_digest` have a testable reference implementation today (see [`crates/signet-core/src/canonical.rs`](https://github.com/Prismer-AI/signet/blob/main/crates/signet-core/src/canonical.rs)).

Cross-implementation test vectors (origin receipt + expected `origin_receipt_digest`, and composite envelope + expected `composite_digest`) will be published alongside any implementation of this RFC so APS / ArkForge / other governance-layer implementations can be conformance-tested against the same inputs.

## Context

This RFC grew out of discussion on MCP SEP-1763 between @aeoess (APS gateway), @desiorac (multi-layer proof composition), and Signet. The draft version of this proposal was moved into the Signet repository to keep the technical conversation open and reviewable in a single location. External feedback is welcome via issues on this repository.
