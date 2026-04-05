# Claude Code Plugin Design

## Goal

Ship a Claude Code plugin that signs every tool call with Ed25519 and appends to a hash-chained audit log. Zero npm dependencies, zero Rust requirement. Distributed via Git, installed with `claude plugin add`.

## Architecture

The plugin embeds a pre-built WASM binary (475KB) from `@signet-auth/core` and uses Node.js CommonJS scripts to sign tool calls in a PostToolUse hook. Keys and audit logs live in `~/.signet/`, shared with the CLI tool.

**Tech Stack:** Node.js (CommonJS), wasm-pack WASM binary (Ed25519 + SHA-256 + JCS), Claude Code plugin system.

---

## Directory Structure

```
plugins/claude-code/
├── .claude-plugin/
│   └── plugin.json              # Plugin manifest
├── skills/
│   └── signet/
│       └── SKILL.md             # /signet skill definition
├── hooks/
│   └── hooks.json               # PostToolUse hook config
├── bin/
│   └── sign.cjs                 # Hook entry: stdin → sign → audit append
├── lib/
│   ├── signet.cjs               # WASM wrapper: sign, generateKeypair, contentHash
│   └── audit.cjs                # JSONL append + hash chain
├── wasm/
│   ├── signet_wasm_bg.wasm      # Pre-built WASM binary (~475KB)
│   └── signet_wasm.js           # wasm-pack CJS glue (unmodified copy)
├── scripts/
│   └── build-plugin.sh          # Copy WASM artifacts + verify
├── .gitattributes               # Mark .wasm as binary
├── package.json                 # type: commonjs, zero dependencies
└── README.md
```

## Plugin Manifest

**`.claude-plugin/plugin.json`:**
```json
{
  "name": "signet",
  "description": "Cryptographic signing for every AI agent tool call — Ed25519 receipts + hash-chained audit log",
  "version": "0.4.0",
  "author": { "name": "Prismer AI" },
  "homepage": "https://github.com/Prismer-AI/signet",
  "repository": "https://github.com/Prismer-AI/signet",
  "license": "Apache-2.0 OR MIT",
  "keywords": ["security", "signing", "audit", "ed25519", "mcp"]
}
```

**`package.json`:**
```json
{
  "name": "signet-claude-plugin",
  "version": "0.4.0",
  "type": "commonjs",
  "private": true
}
```

## Hooks

**`hooks/hooks.json`:**
```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "*",
        "hooks": [{
          "type": "command",
          "command": "node \"${CLAUDE_PLUGIN_ROOT}/bin/sign.cjs\"",
          "timeout": 5
        }]
      }
    ]
  }
}
```

The `*` matcher fires on every tool call. PostToolUse is post-execution, so no recursion risk. Failed/errored tool calls are also signed (desirable for audit completeness).

## Data Flow

```
Claude Code tool call completes
    │
    ▼
PostToolUse hook fires
    │ stdin: { tool_name, tool_input, tool_response }
    ▼
bin/sign.cjs
    ├─ 1. Read stdin JSON, extract tool_name + tool_input
    ├─ 2. Load key from ~/.signet/keys/claude-agent.key (unencrypted)
    │     └─ First run: auto generateKeypair() + write file + chmod 0600
    ├─ 3. WASM sign(secretKey, action, "claude-agent", "")
    ├─ 4. lib/audit.cjs appends receipt to ~/.signet/audit/YYYY-MM-DD.jsonl
    │     └─ Read last line → prev_hash → compute record_hash → appendFileSync
    └─ 5. exit 0 (stderr warning on failure, never blocks)
```

## File Responsibilities

### `bin/sign.cjs` (~60 lines)

Hook entry point. Reads stdin JSON, orchestrates signing and audit.

```
1. Read stdin (fd 0) as JSON
2. Extract tool_name and tool_input from parsed object
3. Call lib/signet.cjs to load or generate key
4. Call lib/signet.cjs sign() with action = { tool, params, target: "claude-code://local" }
5. Call lib/audit.cjs append() with the receipt
6. Exit 0
```

On any error: write warning to stderr, exit 0. Never throw, never block.

### `lib/signet.cjs` (~40 lines)

Thin WASM wrapper. Handles WASM initialization and key management.

Exports:
- `sign(secretKeyB64, action, signerName)` — returns receipt JSON string
- `generateKeypair()` — returns `{ publicKey, secretKey }` (base64 strings)
- `contentHash(value)` — returns `sha256:...` string
- `loadOrCreateKey(keyPath)` — reads key file or generates + saves new one

Key file format (`~/.signet/keys/claude-agent.key`):
```json
{
  "name": "claude-agent",
  "public_key": "ed25519:...",
  "secret_key": "...",
  "encrypted": false,
  "created_at": "2026-04-05T..."
}
```

If the key file exists but `"encrypted": true`, log a stderr warning:
```
signet: encrypted key detected. Run 'signet identity generate --name claude-agent --unencrypted' or delete the key to auto-generate.
```

Key file permissions: `0600` (set via `fs.chmodSync` on creation, Unix only).

### `lib/audit.cjs` (~50 lines)

JSONL append with hash chain. Compatible with CLI's `signet audit` and `signet verify --chain`.

Exports:
- `append(signetDir, receipt)` — appends one record to today's JSONL file

Record format (one line):
```json
{"receipt": {...}, "record_hash": "sha256:...", "prev_hash": "sha256:..."}
```

Algorithm:
1. Determine file path: `~/.signet/audit/YYYY-MM-DD.jsonl`
2. Create `~/.signet/audit/` if missing (`mkdirSync({ recursive: true })`)
3. Read last line of file (or use `"sha256:genesis"` if empty/missing)
4. Extract `record_hash` from last line as `prev_hash`
5. Compute `record_hash = sha256(JCS({ prev_hash, receipt }))`
   where JCS is RFC 8785 canonical JSON. This matches the Rust CLI's
   `audit::compute_record_hash` implementation exactly. Use the WASM
   `contentHash()` function with `{ prev_hash, receipt }` as input.
6. `fs.appendFileSync(path, JSON.stringify(record) + '\n')` — O_APPEND for atomic writes

The `contentHash()` call uses the WASM JCS canonical JSON implementation, ensuring hash compatibility with the Rust CLI.

## Skill Definition

**`skills/signet/SKILL.md`:**

```markdown
---
name: signet
description: Cryptographic signing for every tool call with Ed25519 audit trail
---

# /signet — Cryptographic Tool Call Signing

Signet is active. Every tool call is signed with Ed25519 and logged
to a hash-chained audit trail at ~/.signet/audit/.

Agent identity: `claude-agent` (auto-generated on first use)

## Audit Commands

View recent signed tool calls (requires signet CLI):
  signet audit --since 1h

Verify hash chain integrity:
  signet audit --verify

View raw audit log without CLI:
  cat ~/.signet/audit/$(date +%Y-%m-%d).jsonl | jq '.receipt.action.tool'

Export audit report:
  signet audit --export report.json --since 24h
```

## Build Process

**`scripts/build-plugin.sh`:**

```bash
#!/bin/bash
set -e
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PLUGIN_DIR="$REPO_ROOT/plugins/claude-code"
WASM_SRC="$REPO_ROOT/packages/signet-core/wasm"

if [ ! -f "$WASM_SRC/signet_wasm_bg.wasm" ]; then
  echo "WASM not built. Run: wasm-pack build bindings/signet-ts --target nodejs --out-dir ../../packages/signet-core/wasm"
  exit 1
fi

cp "$WASM_SRC/signet_wasm_bg.wasm" "$PLUGIN_DIR/wasm/"
cp "$WASM_SRC/signet_wasm.js" "$PLUGIN_DIR/wasm/"

# Verify WASM loads
node -e "const s = require('$PLUGIN_DIR/lib/signet.cjs'); const kp = s.generateKeypair(); console.log('WASM OK, pubkey:', kp.publicKey)"

echo "Plugin build complete"
```

**`.gitattributes`:**
```
wasm/signet_wasm_bg.wasm binary
```

## Distribution

The plugin lives in the monorepo at `plugins/claude-code/`. For marketplace registration:

```json
{
  "source": "git-subdir",
  "url": "Prismer-AI/signet",
  "path": "plugins/claude-code"
}
```

Users install with:
```
claude plugin add signet
```

Or manually clone and register.

## Error Handling

| Scenario | Behavior |
|----------|----------|
| WASM load failure | stderr warning, exit 0 |
| Key file missing | Auto-generate unencrypted key, continue |
| Key file encrypted | stderr warning with instructions, exit 0 |
| Audit directory missing | Auto mkdirSync, continue |
| Audit write failure | stderr warning, exit 0 |
| stdin not JSON | stderr warning, exit 0 |
| Signing failure | stderr warning, exit 0 |

**Principle:** Never block a tool call. Signing is audit, not a gate.

## Performance

Each PostToolUse invocation spawns a new Node.js process:
- Node.js startup: ~40-80ms
- WASM compilation: ~20-50ms
- WASM instantiation: ~5-10ms
- Signing: ~1ms
- Audit append: ~1-5ms

**Total: ~70-140ms per tool call.** Acceptable for a security feature. The 5-second timeout provides ample headroom. Optimization (WASM V8 cache, long-running daemon) deferred to a future version if user feedback warrants it.

## Compatibility

- **With CLI:** Shares `~/.signet/` directory. `signet audit` reads the same JSONL files. `signet verify --chain` validates the same hash chain.
- **Without CLI:** Fully functional. Key auto-generated, audit log viewable with `jq`.
- **With `signet claude install`:** Both can coexist. The plugin hook and the skill hook are separate. If both are active, tool calls get signed twice (harmless, deduplicated by receipt ID).
- **Node.js requirement:** Claude Code requires Node.js 18+, which is always present.

## What This Does NOT Include

- Key encryption (plugin uses unencrypted keys for automated signing)
- MCP transport signing (that is `@signet-auth/mcp`, a separate concern)
- Bilateral co-signing (server-side, not applicable to Claude Code hooks)
- Delegation chains (v0.5 feature)
