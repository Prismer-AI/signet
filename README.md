# Signet

Cryptographic action receipts for AI agents -- sign, audit, verify.

Signet gives every AI agent an Ed25519 identity and signs every tool call. Know exactly what your agent did, when, and prove it.

## Why

AI agents execute high-value actions with zero accountability. Signet fixes this:

- **Sign** every tool call with the agent's cryptographic key
- **Audit** what happened with an append-only, hash-chained local log
- **Verify** any action receipt offline, no network needed

## Quick Start

### CLI

```bash
# Generate an agent identity
signet identity generate --name my-agent

# Sign an action
signet sign --key my-agent --tool "github_create_issue" \
  --params '{"title":"fix bug"}' --target mcp://github.local

# Verify a receipt
signet verify receipt.json --pubkey my-agent

# Audit recent actions
signet audit --since 24h

# Verify log integrity
signet verify --chain
```

### MCP Integration (TypeScript)

```typescript
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { generateKeypair } from "@signet/core";
import { SigningTransport } from "@signet/mcp";

// Generate an agent identity
const { secretKey } = generateKeypair();

// Wrap any MCP transport -- all tool calls are now signed
const inner = new StdioClientTransport({ command: "my-mcp-server" });
const transport = new SigningTransport(inner, secretKey, "my-agent");

const client = new Client({ name: "my-agent", version: "1.0" }, {});
await client.connect(transport);

// Every callTool() is now cryptographically signed
const result = await client.callTool({
  name: "echo",
  arguments: { message: "Hello!" },
});
```

Every `tools/call` request gets a signed receipt injected into `params._meta._signet`.
MCP servers don't need to change -- they ignore unknown fields.

## How It Works

```
Your Agent
    |
    v
SigningTransport (wraps any MCP transport)
    |
    +---> Signs each tool call (Ed25519)
    +---> Appends Action Receipt to local audit log (hash-chained)
    +---> Forwards request to MCP server (unchanged)
```

Agent-side only. MCP servers don't need to change.

## Action Receipt

Every tool call produces a signed receipt:

```json
{
  "v": 1,
  "id": "rec_e7039e7e7714e84f...",
  "action": {
    "tool": "github_create_issue",
    "params": {"title": "fix bug"},
    "params_hash": "sha256:b878192252cb...",
    "target": "mcp://github.local",
    "transport": "stdio"
  },
  "signer": {
    "pubkey": "ed25519:0CRkURt/tc6r...",
    "name": "demo-bot",
    "owner": "willamhou"
  },
  "ts": "2026-03-29T23:24:03.309Z",
  "nonce": "rnd_dcd4e135799393...",
  "sig": "ed25519:6KUohbnSmehP..."
}
```

The signature covers the entire receipt body (action + signer + timestamp + nonce) using [RFC 8785 (JCS)](https://datatracker.ietf.org/doc/html/rfc8785) canonical JSON. Modifying any field invalidates the signature.

## CLI Commands

| Command | Description |
|---------|-------------|
| `signet identity generate --name <n>` | Generate Ed25519 identity (encrypted by default) |
| `signet identity generate --unencrypted` | Generate without encryption (for CI) |
| `signet identity list` | List all identities |
| `signet identity export --name <n>` | Export public key as JSON |
| `signet sign --key <n> --tool <t> --params <json> --target <uri>` | Sign an action |
| `signet sign --hash-only` | Store only params hash (not raw params) |
| `signet sign --output <file>` | Write receipt to file instead of stdout |
| `signet sign --no-log` | Skip audit log append |
| `signet verify <receipt.json> --pubkey <name>` | Verify a receipt signature |
| `signet verify --chain` | Verify audit log hash chain integrity |
| `signet audit` | List recent actions |
| `signet audit --since <duration>` | Filter by time (e.g. 24h, 7d) |
| `signet audit --tool <substring>` | Filter by tool name |
| `signet audit --verify` | Verify all receipt signatures |
| `signet audit --export <file>` | Export records as JSON |

Passphrase via interactive prompt or `SIGNET_PASSPHRASE` env var for CI.

## Project Structure

```
signet/
├── crates/signet-core/       Rust core: identity, sign, verify, audit, keystore
├── signet-cli/               CLI tool (signet binary)
├── bindings/signet-ts/       WASM binding (wasm-bindgen)
├── packages/
│   ├── signet-core/          @signet/core — TypeScript wrapper
│   └── signet-mcp/           @signet/mcp — MCP SigningTransport middleware
├── examples/
│   ├── wasm-roundtrip/       WASM validation tests
│   └── mcp-agent/            MCP agent + echo server example
├── docs/                     Design docs, specs, plans
├── LICENSE-APACHE
└── LICENSE-MIT
```

## Building from Source

### Prerequisites

- Rust (1.70+)
- wasm-pack
- Node.js (18+)

### Build

```bash
# Rust core + CLI
cargo build --release -p signet-cli

# WASM binding
wasm-pack build bindings/signet-ts --target nodejs --out-dir ../../packages/signet-core/wasm

# TypeScript packages
cd packages/signet-core && npm run build
cd packages/signet-mcp && npm run build
```

### Test

```bash
# Rust tests (64 tests)
cargo test --workspace

# WASM roundtrip (8 tests)
node examples/wasm-roundtrip/test.mjs

# TypeScript tests (11 tests)
cd packages/signet-core && npm test
cd packages/signet-mcp && npm test
```

## Security

- **Ed25519** signatures (128-bit security level, `ed25519-dalek`)
- **Argon2id** key derivation (OWASP recommended minimum)
- **XChaCha20-Poly1305** key encryption with authenticated associated data (AAD)
- **SHA-256 hash chain** for tamper-evident audit log
- **RFC 8785 (JCS)** canonical JSON for deterministic signatures

Keys stored at `~/.signet/keys/` with `0600` permissions. Override with `SIGNET_HOME` env var.

### What Signet proves

- Agent key X signed intent to call tool Y with params Z at time T

### What Signet does NOT prove (yet)

- That the MCP server received or executed the action (v2: server receipts)
- That signer.owner actually controls the key (v2: identity registry)

Signet is an attestation tool (proving what happened), not a prevention tool (blocking bad actions). It complements policy enforcement tools like firewalls and gateways.

## License

Apache-2.0 + MIT dual license.
