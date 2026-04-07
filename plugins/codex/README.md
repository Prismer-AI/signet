# Signet Codex Plugin

Cryptographic signing for every Bash tool call in OpenAI Codex CLI. Ed25519 receipts + hash-chained audit log.

## Install

### Option A: Plugin (auto-signs Bash tool calls)

```bash
git clone https://github.com/Prismer-AI/signet.git
cp -r signet/plugins/codex ~/.codex/plugins/signet
```

Then add the hook to `~/.codex/hooks.json`:

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{
          "type": "command",
          "command": "node \"$HOME/.codex/plugins/signet/bin/sign.cjs\"",
          "timeout": 5
        }]
      }
    ]
  }
}
```

> **Note:** Codex CLI currently only supports `Bash` matcher for hooks. Other tool calls (file edits, etc.) are not hooked yet.

### Option B: MCP Server (manual signing/verification tools)

```bash
codex mcp add signet -- npx @signet-auth/mcp-tools
```

This exposes `signet_sign`, `signet_verify`, and `signet_audit` as tools Codex can call on demand.

## What It Does

Every Bash tool call Codex makes is automatically:

1. **Signed** with an Ed25519 key (auto-generated on first use)
2. **Logged** to a hash-chained audit trail at `~/.signet/audit/`

No configuration beyond the hook setup above. Signing starts immediately.

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

- Keys stored at `~/.signet/keys/codex-agent.key` (unencrypted, 0600 permissions)
- Auto-generated on first tool call
- Shared with signet CLI if installed

## How It Works

A PostToolUse hook runs after every Bash tool call, reading the tool name and
input from stdin. The hook signs the action with the agent's Ed25519 key
using an embedded WASM module (no Rust or native dependencies needed),
then appends the signed receipt to the daily audit log.

## Limitations

- Codex CLI hooks currently only support the `Bash` matcher — file edit and other tool calls are not signed yet
- When Codex adds `*` (wildcard) matcher support, update `hooks.json` to sign all tool calls

## License

Apache-2.0 OR MIT
