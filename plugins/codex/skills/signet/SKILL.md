---
name: signet
description: Cryptographic signing for every tool call with Ed25519 audit trail
---

# /signet — Cryptographic Tool Call Signing

Signet is active. Every tool call is signed with Ed25519 and logged
to a hash-chained audit trail at ~/.signet/audit/.

Agent identity: `codex-agent` (auto-generated on first use)

## Audit Commands

View recent signed tool calls (requires signet CLI):

    signet audit --since 1h

Verify hash chain integrity:

    signet audit --verify

View raw audit log without CLI:

    cat ~/.signet/audit/$(date +%Y-%m-%d).jsonl | jq '.receipt.action.tool'

Export audit report:

    signet audit --export report.json --since 24h
