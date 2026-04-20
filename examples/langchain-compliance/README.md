# LangChain Compliance Example

End-to-end example showing how to produce tamper-evident audit receipts for
every LangChain tool call using Signet's `SignetCallbackHandler`.

Relevant to:

- [LangChain RFC #35691 — ComplianceCallbackHandler](https://github.com/langchain-ai/langchain/issues/35691)
- EU AI Act Article 12 (automatic event logging, August 2026)
- AIUC-1, ISO 42001, Colorado AI Act audit evidence requirements

## What This Demonstrates

1. A LangChain agent with two tools (`search`, `calculator`, both stubbed for offline demo)
2. `SignetCallbackHandler` passed via `config={"callbacks": [...]}` on each `invoke()`
3. Every `on_tool_start` / `on_tool_end` / `on_tool_error` lifecycle event produces an Ed25519-signed receipt appended to a hash-chained audit log at `~/.signet/audit/`
4. Offline verification of the audit chain using the `signet_auth` Python API
5. An optional `policy.yaml` showing the pre-sign policy schema. `agent.py` does **not** wire policy into the callback handler today — the Python `sign_with_policy()` binding exists, but the LangChain callback currently calls `SigningAgent.sign()` directly. Combining policy enforcement with the callback handler is a separate, planned integration.

## Run It

```bash
# Prerequisites
pip install signet-auth[langchain] langchain langchain-openai

# Generate an agent identity (one-time)
signet identity generate --name demo-bot --unencrypted

# Run the example (you'll need an OpenAI API key)
export OPENAI_API_KEY="sk-..."
python agent.py

# Verify the audit chain offline (no vendor service)
python verify.py
# or use the CLI:
signet audit --verify
```

## Files

- `agent.py` — LangChain agent with `SignetCallbackHandler` passed at `invoke()` time
- `verify.py` — Offline verification using `signet_auth` helpers (chain integrity + signature check + recent actions)
- `policy.yaml` — Policy schema example (schema-valid; not currently wired into `agent.py`)

## What a Receipt Looks Like

Each tool call produces **three** receipts through the handler lifecycle:

1. `on_tool_start` — receipt with `action.tool = "<your_tool>"`, params include tool args + LangChain `run_id`
2. `on_tool_end` — receipt with `action.tool = "_tool_end"`, params include `output_hash` + matching `run_id`
3. `on_tool_error` — (only on failure) receipt with `action.tool = "_tool_error"`, params include error + matching `run_id`

Example start receipt:

```json
{
  "v": 1,
  "id": "rec_a1b2c3d4e5f6a7b8",
  "action": {
    "tool": "calculator",
    "params": { "args": { "expression": "2+2" }, "run_id": "7f3a..." },
    "params_hash": "sha256:...",
    "target": "langchain://demo",
    "transport": "stdio"
  },
  "signer": {
    "name": "demo-bot",
    "pubkey": "ed25519:...",
    "owner": ""
  },
  "ts": "2026-04-21T09:00:00.000Z",
  "nonce": "rnd_...",
  "sig": "ed25519:..."
}
```

The `run_id` lets you correlate the start and end receipts for a single tool invocation.

## Verification

`verify.py` uses the `signet_auth` Python API (`audit_verify_chain`, `audit_verify_signatures`, `audit_query`) to check the local audit log. This requires the `signet-auth` package — it is not a standalone Ed25519 verifier.

Receipts themselves are verifiable with standard crypto (Ed25519 + RFC 8785 JCS canonicalization + SHA-256) by any language that has those primitives. A minimal standalone verifier in a few lines of Python is on the roadmap and will be added alongside this example.

## Relationship to RFC #35691

`SignetCallbackHandler` uses `BaseCallbackHandler`, the same lifecycle that the RFC targets. If the RFC lands with a shared `ComplianceCallbackHandler` Protocol, the handler will implement the Protocol directly — existing code will not need changes.

Mapping between the RFC Protocol surface and what Signet produces today:

| RFC field | Signet field | Notes |
|-----------|--------------|-------|
| `event_ref` | LangChain `run_id` (stored in `action.params.run_id`) | Handler puts `run_id` into the signed params, which binds it to the signature |
| `signature` | `sig` | Format: `ed25519:<base64>` |
| `chain_ref` | audit log `prev_hash` | Stored in the audit record wrapper, not in the receipt itself |
| `backend_id` | signer `name` or `pubkey` | `"signet"` + version could be surfaced as optional metadata |
| `signer_pubkey` | `signer.pubkey` | Already in every receipt |
| `policy_attestation` | `receipt.policy` (v0.7+) | Produced by `sign_with_policy()`. Not yet wired through `SignetCallbackHandler`; planned |
