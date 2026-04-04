<h1 align="center">Signet</h1>

<p align="center">
  <strong>Cryptographic Action Receipts for AI Agents</strong><br/>
  <sub>Sign every tool call. Audit what happened. Verify offline. 3 lines of code.</sub>
</p>

<p align="center">
  <a href="https://github.com/Prismer-AI/signet/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/Prismer-AI/signet/ci.yml?branch=main&style=flat-square&labelColor=black&label=CI" alt="CI"></a>
  <a href="https://github.com/Prismer-AI/signet/releases/latest"><img src="https://img.shields.io/github/v/release/Prismer-AI/signet?style=flat-square&labelColor=black&color=green&label=release" alt="Release"></a>
  <a href="https://github.com/Prismer-AI/signet/blob/main/LICENSE-APACHE"><img src="https://img.shields.io/badge/license-Apache--2.0%20%2F%20MIT-blue?labelColor=black&style=flat-square" alt="License"></a>
  <a href="https://github.com/Prismer-AI/signet/stargazers"><img src="https://img.shields.io/github/stars/Prismer-AI/signet?style=flat-square&labelColor=black&color=yellow" alt="Stars"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/SDKs-333?style=flat-square" alt="SDKs">
  <a href="https://crates.io/crates/signet-core"><img src="https://img.shields.io/crates/v/signet-core?style=flat-square&labelColor=black&color=dea584&logo=rust&logoColor=white&label=signet--core" alt="crates.io"></a>
  <a href="https://www.npmjs.com/package/@signet-auth/mcp"><img src="https://img.shields.io/npm/v/@signet-auth/mcp?style=flat-square&labelColor=black&color=cb3837&logo=npm&logoColor=white&label=mcp" alt="npm"></a>
  <a href="https://pypi.org/project/signet-auth/"><img src="https://img.shields.io/pypi/v/signet-auth?style=flat-square&labelColor=black&color=3775A9&logo=python&logoColor=white&label=signet--auth" alt="PyPI"></a>
</p>

<p align="center">
  <a href="./README.md"><img alt="English" src="https://img.shields.io/badge/English-d9d9d9"></a>
  <a href="./README.zh.md"><img alt="简体中文" src="https://img.shields.io/badge/简体中文-d9d9d9"></a>
</p>

Signet gives every AI agent an Ed25519 identity and signs every tool call. Know exactly what your agent did, when, and prove it.

<p align="center">
  <img src="demo-cli.svg" alt="Signet CLI demo" width="820">
</p>

## Why

AI agents execute high-value actions with zero accountability. Signet fixes this:

- **Sign** every tool call with the agent's cryptographic key
- **Audit** what happened with an append-only, hash-chained local log
- **Verify** any action receipt offline, no network needed

## Install

```bash
# CLI
cargo install signet-cli

# Python
pip install signet-auth

# TypeScript (MCP middleware)
npm install @signet-auth/core @signet-auth/mcp

# TypeScript (MCP server verification)
npm install @signet-auth/mcp-server
```

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

<p align="center">
  <img src="demo-mcp.svg" alt="Signet MCP bilateral flow demo" width="820">
</p>

```typescript
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { generateKeypair } from "@signet-auth/core";
import { SigningTransport } from "@signet-auth/mcp";

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
MCP servers can optionally verify these signatures:

```typescript
import { verifyRequest } from "@signet-auth/mcp-server";

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const verified = verifyRequest(request, {
    trustedKeys: ["ed25519:..."],
    maxAge: 300,
  });
  if (!verified.ok) return { content: [{ type: "text", text: verified.error }], isError: true };
  console.log(`Verified: ${verified.signerName}`);
  // process tool call...
});
```

<p align="center">
  <img src="demo-mcp.svg" alt="Signet MCP end-to-end demo" width="820">
</p>

### Reference MCP Server

This repo also includes a minimal MCP reference server that demonstrates server-side verification with `@signet-auth/mcp-server`.

```bash
cd examples/mcp-agent
npm ci
npm run verifier-server
```

Available tools:

- `inspect_current_request` — verifies the current MCP tool call if it includes `params._meta._signet`
- `verify_receipt` — verifies a raw Signet receipt against a public key
- `verify_request_payload` — verifies a synthetic MCP `tools/call` payload offline

Environment variables:

- `SIGNET_TRUSTED_KEYS` — comma-separated `ed25519:<base64>` public keys
- `SIGNET_REQUIRE_SIGNATURE` — `true` or `false` (default `false`)
- `SIGNET_MAX_AGE` — max receipt age in seconds (default `300`)
- `SIGNET_EXPECTED_TARGET` — optional expected `receipt.action.target`

### Python (LangChain / CrewAI / AutoGen)

```bash
pip install signet-auth
```

```python
from signet_auth import SigningAgent

# Create an agent identity (saved to ~/.signet/keys/)
agent = SigningAgent.create("my-agent", owner="willamhou")

# Sign any tool call -- receipt is auto-appended to audit log
receipt = agent.sign("github_create_issue", params={"title": "fix bug"})

# Verify
assert agent.verify(receipt)

# Query audit log
for record in agent.audit_query(since="24h"):
    print(f"{record.receipt.ts} {record.receipt.action.tool}")
```

#### LangChain Integration

```python
from signet_auth import SigningAgent
from signet_auth.langchain import SignetCallbackHandler

agent = SigningAgent("my-agent")
handler = SignetCallbackHandler(agent)

# Every tool call is now signed + audited
chain.invoke(input, config={"callbacks": [handler]})

# Async chains supported too
from signet_auth.langchain import AsyncSignetCallbackHandler
```

#### CrewAI Integration

```python
from signet_auth import SigningAgent
from signet_auth.crewai import install_hooks

agent = SigningAgent("my-agent")
install_hooks(agent)

# All CrewAI tool calls are now globally signed
crew.kickoff()
```

#### Low-Level API

```python
from signet_auth import generate_keypair, sign, verify, Action

kp = generate_keypair()
action = Action("github_create_issue", params={"title": "fix bug"})
receipt = sign(kp.secret_key, action, "my-agent", "willamhou")
assert verify(receipt, kp.public_key)
```

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

## Documentation

| Doc | Description |
|-----|-------------|
| [Architecture](docs/ARCHITECTURE.md) | System design, component overview, data flow |
| [Security](docs/SECURITY.md) | Crypto primitives, threat model, key storage |
| [MCP Integration Guide](docs/guides/mcp-integration.md) | Step-by-step MCP setup with SigningTransport |
| [CI/CD Integration](docs/guides/ci-integration.md) | GitHub Actions example, key management for CI |
| [Audit Log Guide](docs/guides/audit-log.md) | Querying, filtering, hash chain verification |
| [Contributing](CONTRIBUTING.md) | Build instructions, development workflow |
| [Changelog](CHANGELOG.md) | Version history |

## Project Structure

```
signet/
├── crates/signet-core/       Rust core: identity, sign, verify, audit, keystore
├── signet-cli/               CLI tool (signet binary)
├── bindings/
│   ├── signet-ts/            WASM binding (wasm-bindgen)
│   └── signet-py/            Python binding (PyO3 + maturin)
├── packages/
│   ├── signet-core/          @signet-auth/core — TypeScript wrapper
│   ├── signet-mcp/           @signet-auth/mcp — MCP SigningTransport middleware
│   └── signet-mcp-server/    @signet-auth/mcp-server — Server verification
├── examples/
│   ├── wasm-roundtrip/       WASM validation tests
│   └── mcp-agent/            MCP agent, echo server, and verifier server example
├── docs/                     Design docs, specs, plans
├── LICENSE-APACHE
└── LICENSE-MIT
```

## Building from Source

### Prerequisites

- Rust (1.70+)
- wasm-pack
- Node.js (18+)
- Python (3.10+) + maturin (for Python binding)

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

```bash
# Python binding
cd bindings/signet-py
pip install maturin
maturin develop
```

### Test

```bash
# Rust tests (80 tests)
cargo test --workspace

# Python tests (73 tests)
cd bindings/signet-py && pytest tests/ -v

# WASM roundtrip (8 tests)
node examples/wasm-roundtrip/test.mjs

# TypeScript tests (26 tests)
cd packages/signet-core && npm test
cd packages/signet-mcp && npm test
cd packages/signet-mcp-server && npm test

# Reference verifier server smoke test
cd examples/mcp-agent && npm run smoke
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

- That the MCP server executed the action (server can verify the request via `@signet-auth/mcp-server`, but execution proof requires server co-signing — v0.4)
- That signer.owner actually controls the key (v2: identity registry)

Signet is an attestation tool (proving what happened), not a prevention tool (blocking bad actions). It complements policy enforcement tools like firewalls and gateways.

## License

Apache-2.0 + MIT dual license.
