# Signet Protocol — Design Document

**Date:** 2026-03-29
**Status:** Approved
**Author:** willamhou

## Overview

Signet is an open-source SDK that gives AI agents cryptographic identity and action-level signing. Every tool call gets signed — who did it, who authorized it, when, verifiable and tamper-proof.

**One-liner:** Cryptographic action receipts for AI agents — sign, audit, verify.

## Problem

AI agents are executing high-value actions (API calls, database writes, contract operations) with zero accountability:

- 78% of breached agents had overly broad permissions (Digital Applied 2025)
- 97% of organizations with AI breaches lacked proper access controls (IBM 2025)
- Agent-involved breaches grew 340% YoY (2024-2025)
- MCP auth is broken: 53% of servers use static API keys, 79% pass tokens via env vars
- stdio transport (the dominant MCP deployment model) has zero auth story

Real incidents: Amazon Kiro deleted a production environment (13h outage), Replit agent deleted a live database, Supabase MCP leaked secret tokens via prompt injection, $47K agent infinite loop.

No existing solution provides **action-level signing** — a cryptographic proof that a specific agent performed a specific action at a specific time, authorized by a specific owner.

## Target User (MVP)

Developers building MCP-based agent applications who need to answer: "What did my agent do, and can I prove it?"

Not targeting: enterprise CISOs, compliance teams, legal departments (v2+).

## Architecture

```
Developer's Agent
       |
       v
  SigningTransport (wraps any MCP transport)
       |
       ├──> Signs each tool call with agent's Ed25519 key
       ├──> Appends Action Receipt to local audit log
       └──> Forwards request to MCP server (unchanged)
              |
              v
         MCP Server (unmodified — doesn't need Signet)
```

Key principle: **agent-side only integration**. MVP does not require MCP servers to change. Signing is opt-in at the client side. Value is delivered through local audit.

## Core Modules

### 1. Identity

Each agent gets an Ed25519 keypair.

- **Generation:** `signet identity generate --name deploy-bot`
- **Storage:** Private key encrypted with XChaCha20-Poly1305, passphrase derived via Argon2id
- **Metadata:** name, owner, created_at, capabilities[]
- **Export:** `signet identity export --public` outputs the public key for sharing

File layout:
```
~/.signet/
├── keys/
│   ├── deploy-bot.key    # encrypted private key
│   └── deploy-bot.pub    # public key + metadata (JSON)
└── config.toml
```

### 2. Sign

Signs an action and produces an **Action Receipt**.

```rust
let receipt = signet::sign(&agent_key, &Action {
    tool_name: "github_create_issue",
    params_hash: sha256(&canonical_json(params)),
    target: "mcp://github.local",
    transport: "stdio",
})?;
```

Signature covers: canonical JSON of `action` + `ts` + `nonce`.

### 3. Verify

Offline verification — no network needed.

```rust
signet::verify(&receipt, &known_public_key)?;
```

```bash
signet verify receipt.json --pubkey deploy-bot.pub
# ✅ Valid: "deploy-bot" signed "github_create_issue" at 2026-03-29T14:32:00Z
```

### 4. Audit Log

Append-only JSONL log of all Action Receipts.

```
~/.signet/audit/
├── 2026-03-29.jsonl
└── 2026-03-30.jsonl
```

- One receipt per line, append-only
- Split by day (no single file bloat)
- No database dependency
- Optional encrypted param storage: `signet sign --store-params`

CLI:
```bash
signet audit --since 24h                    # list recent actions
signet audit --tool "github_*" --since 7d   # filter by tool
signet audit --verify                       # verify all signatures
signet audit --export report.json --since 30d  # export for review
```

### 5. MCP Middleware (TypeScript)

Zero-config integration via transport wrapper:

```typescript
import { SigningTransport } from "@signet/mcp";

const transport = new SigningTransport(innerTransport, agentKey);
// All tool calls are now automatically signed + logged
```

- **HTTP transport:** signature in `X-Signet-Signature` header
- **stdio transport:** signature in `_signet` JSON-RPC extension field
- MCP server receives the request as normal (ignores unknown fields/headers)

## Action Receipt Format

```json
{
  "v": 1,
  "id": "rec_a8f3e...",
  "action": {
    "tool": "github_create_issue",
    "params_hash": "sha256:e3b0c44...",
    "target": "mcp://github.local",
    "transport": "stdio"
  },
  "signer": {
    "pubkey": "ed25519:3b6a27b...",
    "name": "deploy-bot",
    "owner": "willamhou"
  },
  "ts": "2026-03-29T14:32:00.123Z",
  "nonce": "rnd_7f2a...",
  "sig": "ed25519:4a9c1b..."
}
```

Design decisions:

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Params | Hash only, not raw | Params may contain secrets; original can be rehashed for verification |
| Serialization | JSON (MVP) | Developer-readable; CBOR as optional v2 compact format |
| Signature scope | canonical(action + ts + nonce) | Deterministic serialization prevents field-order ambiguity |
| Receipt ID | SHA-256(sig) truncated 16 bytes | Globally unique, recomputable from signature |
| Target field | MCP server URI | Audit trail shows which server received the action |
| Replay protection | nonce + timestamp | Unique nonce per action, timestamp for time-window validation |

## Tech Stack

### Rust Core (`signet-core`)

| Function | Crate | Rationale |
|----------|-------|-----------|
| Ed25519 | `ed25519-dalek` | Industry standard, audited |
| Key encryption | `chacha20poly1305` | XChaCha20-Poly1305, modern AEAD |
| KDF | `argon2` | Passphrase-to-key derivation |
| Serialization | `serde` + `serde_json` | Standard |
| CLI | `clap` | Standard |
| Time | `chrono` | Timestamps |
| Random | `rand` | Nonce generation |
| Hashing | `sha2` | SHA-256 for params_hash and receipt ID |

### TypeScript Binding (`signet-ts`)

Built from `signet-core` via `wasm-bindgen` + `wasm-pack`. Targets:

- Node.js
- Bun
- Deno
- Cloudflare Workers
- Browser

### MCP Middleware (`@signet/mcp`)

Pure TypeScript. Wraps any MCP transport. Depends on `signet-ts` for crypto.

## Project Structure

```
signet/
├── crates/
│   └── signet-core/          # Rust core library
│       ├── identity.rs       # Ed25519 keypair generate/load/store
│       ├── sign.rs           # Action signing
│       ├── verify.rs         # Signature verification
│       ├── receipt.rs        # Action Receipt types + serialization
│       ├── audit.rs          # JSONL audit log read/write
│       └── canonical.rs      # Canonical JSON serialization
├── signet-cli/               # CLI tool
│   └── main.rs               # identity/sign/verify/audit subcommands
├── bindings/
│   └── signet-ts/            # TypeScript binding (wasm-bindgen)
│       └── src/
├── packages/
│   └── signet-mcp/           # @signet/mcp — TS MCP middleware
│       ├── signing-transport.ts
│       └── index.ts
├── examples/
│   ├── rust-basic/           # Rust sign/verify example
│   └── mcp-agent/            # MCP agent + Signet integration example
├── LICENSE-APACHE
├── LICENSE-MIT
└── README.md
```

## Milestones

### M0: Tech Validation (2-3 days)

Derisk the two key assumptions:
1. Ed25519 sign → verify roundtrip in Rust + WASM
2. MCP stdio transport wrapping: inject `_signet` field without breaking MCP server

**Exit criteria:** Working prototype that signs an MCP tool call via wrapped stdio transport, and a stock MCP server processes the request normally (ignores the extra field).

### M1: Core (2 weeks)

- `signet-core`: identity + sign + verify + receipt + canonical JSON
- `signet-cli`: `identity generate/list/export`, `sign`, `verify`
- Unit tests 80%+ coverage
- README + quickstart doc

### M2: Audit (1 week)

- `signet-core`: audit log (JSONL append/query)
- `signet-cli`: `audit --since/--tool/--verify/--export`
- Integration tests

### M3: MCP + WASM (2 weeks)

- `signet-ts`: wasm-bindgen binding (identity/sign/verify)
- `@signet/mcp`: SigningTransport middleware
- MCP agent example project
- npm publish
- End-to-end example: agent + Signet + MCP server

**Total: ~5.5 weeks to usable MVP.**

## What MVP Does NOT Include (v2+)

| Feature | Why deferred |
|---------|-------------|
| Delegation tokens (A authorizes B) | Needs identity registry for chain verification |
| Budget-scoped tokens | Needs delegation foundation |
| Hosted identity registry | MVP proves "signing is useful" first |
| Server-side verification middleware | Chicken-and-egg: needs adoption first |
| Agent-to-agent signing (contracts) | Needs registry + delegation |
| Hash chain in audit log | Enterprise tamper-evidence need, not developer MVP need |
| Multi-signature (M-of-N) | Complex, needs threshold crypto |
| CBOR serialization | JSON is fine for MVP, CBOR for compact wire format later |
| Python binding | TypeScript covers MCP ecosystem majority |
| Compliance dashboard | Enterprise feature |
| Legal attribution layer | Needs legal framework partnership |
| Cross-framework (A2A, ANP) | MCP first, expand after |

## Open Source Strategy

- **License:** Apache-2.0 + MIT dual license (maximum compatibility)
- **GitHub org:** `signet-auth`
- **Public development** from day 1
- Conventional commits, CHANGELOG
- Issue templates for bug reports and feature requests

## Competitive Positioning

| | Signet | Signet-AI | Aembit | Cloudflare MCP | Red Hat Gateway |
|--|--------|-----------|--------|----------------|-----------------|
| What | Action signing SDK | Memory layer | Enterprise NHI gateway | Platform-bound auth | Envoy + OPA |
| Agent identity | Ed25519 keypairs | None | Workload identity | OAuth server | JWT + mTLS |
| Action signing | Per-tool-call receipts | None | None | None | None |
| Audit log | Local JSONL | None | Cloud dashboard | Logs | ELK |
| MCP support | Client middleware | MCP server (memory) | Gateway proxy | Workers only | Envoy proxy |
| stdio support | Yes (_signet field) | N/A | No | No | No |
| Developer effort | Add 3 lines of code | Install daemon | Deploy gateway | Use Workers | Deploy Envoy |
| Open source | Yes (Apache-2.0 + MIT) | Yes (custom) | No | No | Partial |
| Target | Developers | Developers | Enterprise | Cloudflare users | Enterprise |

**Unique differentiator:** Signet is the only solution that provides **action-level cryptographic signing** as an **open-source developer SDK** with **stdio transport support**.

## Market Context

- AI security funding: $6.34B in 2025 (3x YoY)
- NIST AI Agent Standards Initiative (Feb 2026) recommends agent identity registries
- OpenAI hiring "Agent Security Engineer" roles
- 88% of MCP servers require credentials but only 8.5% use OAuth
- No existing tool signs individual agent actions

## Success Metrics (6 months post-launch)

- 500+ GitHub stars
- 50+ weekly npm downloads of @signet/mcp
- 3+ third-party integrations (agent frameworks adopting Signet)
- 1+ conference talk or blog post from an external developer
- Action Receipt format adopted or referenced by at least 1 MCP-adjacent project
