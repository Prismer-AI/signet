# Signet Claude Code Plugin

Cryptographic signing for every tool call in Claude Code. Ed25519 receipts + hash-chained audit log.

## Install

```
claude plugin add signet
```

Or clone and register manually:
```bash
git clone https://github.com/Prismer-AI/signet.git
cd signet/plugins/claude-code
claude plugin add .
```

## What It Does

Every tool call Claude Code makes is automatically:
1. **Signed** with an Ed25519 key (auto-generated on first use)
2. **Logged** to a hash-chained audit trail at `~/.signet/audit/`

No configuration needed. Signing starts immediately after installation.

## Audit

View raw logs:
```bash
cat ~/.signet/audit/$(date +%Y-%m-%d).jsonl | jq '.receipt.action.tool'
```

With [signet CLI](https://github.com/Prismer-AI/signet) (optional):
```bash
signet audit --since 1h
signet audit --verify   # verify hash chain integrity
```

## Key Management

- Keys stored at `~/.signet/keys/claude-agent.key` (unencrypted, 0600 permissions)
- Auto-generated on first tool call
- Shared with signet CLI if installed

## How It Works

A PostToolUse hook runs after every tool call, reading the tool name and
input from stdin. The hook signs the action with the agent's Ed25519 key
using an embedded WASM module (no Rust or native dependencies needed),
then appends the signed receipt to the daily audit log.

## License

Apache-2.0 OR MIT
