# Signet Protocol — Design Document

**Date:** 2026-03-29
**Status:** Approved
**Author:** willamhou

## Overview

Signet is an open-source SDK that gives AI agents cryptographic identity and action-level signing. Every tool call gets signed — which agent key signed it, what was requested, when — producing a verifiable, tamper-evident local audit trail.

**One-liner:** Cryptographic action receipts for AI agents — sign, audit, verify.

## Problem

AI agents are executing high-value actions (API calls, database writes, contract operations) with zero accountability:

- 78% of breached agents had overly broad permissions (Digital Applied 2025)
- 97% of organizations with AI breaches lacked proper access controls (IBM 2025)
- Agent-involved breaches grew 340% YoY (2024-2025)
- MCP auth is broken: 53% of servers use static API keys, 79% pass tokens via env vars
- stdio transport (the dominant MCP deployment model) has zero auth story

Real incidents: Amazon Kiro deleted a production environment (13h outage), Replit agent deleted a live database, Supabase MCP leaked secret tokens via prompt injection, $47K agent infinite loop.

No existing SDK provides **action-level signing as a client-side library** — a cryptographic attestation that a specific agent key signed a specific tool-call intent at a specific time. This is signed intent, not proof of execution: the receipt proves the agent requested an action, not that the server executed it. Server-side execution receipts are a v2+ goal.

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

**What Signet proves vs. what it doesn't:**
- Proves: agent key X signed intent to call tool Y with params Z at time T
- Does NOT prove (MVP): that the MCP server received or executed the action
- Does NOT prove (MVP): that signer.owner actually controls the key (requires identity registry, v2+)

## Core Modules

### 1. Identity

Each agent gets an Ed25519 keypair.

- **Generation:** `signet identity generate --name deploy-bot`
- **Storage:** Private key encrypted with XChaCha20-Poly1305, passphrase derived via Argon2id
- **Passphrase:** Interactive TTY prompt by default; `SIGNET_PASSPHRASE` env var for CI/automation
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
    tool: "github_create_issue",
    params: json!({"title": "fix bug"}),   // plaintext by default
    params_hash: String::new(),             // auto-computed: sha256(JCS(params))
    target: "mcp://github.local",
    transport: "stdio",
}, &signer)?;
```

Signature covers: canonical JSON (RFC 8785 JCS) of the entire receipt body minus `sig` and `id` fields — specifically `v` + `action` + `signer` + `ts` + `nonce`. This ensures all meaningful fields (including `signer.name` and `signer.owner`) are tamper-evident.

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
- Params stored in plaintext by default (human-readable audit)
- `signet sign --hash-only` omits raw params, stores only hash
- Optional encrypted param storage: `signet sign --encrypt-params` (v2+)

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
    "params": {"title": "fix bug"},
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
| Params | Plaintext by default, hash-only opt-in | Human-readable audit requires original params; `--hash-only` for sensitive data |
| Serialization | JSON (MVP) | Developer-readable; CBOR as optional v2 compact format |
| Canonicalization | RFC 8785 (JCS) | Standard deterministic JSON; `json-canonicalization` crate |
| Signature scope | canonical(v + action + signer + ts + nonce) | All meaningful fields are tamper-evident; `sig` and `id` excluded (derived) |
| Receipt ID | SHA-256(sig) truncated 16 bytes | Globally unique, recomputable from signature |
| Target field | MCP server URI | Audit trail shows which server received the action |
| Uniqueness guarantee | nonce + timestamp | Unique nonce per action, timestamp for ordering; true replay protection requires server-side nonce tracking (v2+) |

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
| Canonicalization | `json-canonicalization` | RFC 8785 (JCS) deterministic JSON |

### TypeScript Binding (`signet-ts`)

Built from `signet-core` via `wasm-bindgen` + `wasm-pack`.

MVP target: **Node.js only** (`wasm-pack build --target nodejs`).

Browser, Bun, Deno, and Cloudflare Workers require different key-storage and
audit-log models (no `~/.signet`, no local filesystem). These are v2+ targets
that need separate storage abstractions.

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
│       ├── canonical.rs      # RFC 8785 (JCS) canonical JSON
│       └── error.rs          # SignetError enum (thiserror)
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

Derisk the critical technical assumption:
1. Ed25519 sign → verify roundtrip in Rust + WASM (Node.js)

**Exit criteria:** `cargo test` passes (Rust roundtrip), `wasm-pack build --target nodejs` succeeds, Node.js script verifies sign/verify/tamper-detect via WASM.

See `docs/superpowers/specs/2026-03-29-m0-tech-validation-design.md` for full M0 spec.

### M1: Core (2 weeks)

- `signet-core`: identity + sign + verify + receipt + canonical JSON
- `signet-cli`: `identity generate/list/export`, `sign`, `verify`
- Unit tests 80%+ coverage
- README + quickstart doc

### M2: Audit + Chain (1 week)

- `signet-core`: audit log (JSONL append/query)
- `signet-core`: SHA-256 hash chain (each record includes hash of previous record)
- `signet-cli`: `audit --since/--tool/--verify/--export`
- `signet-cli`: `verify --chain` (validate chain integrity, detect tampering)
- Integration tests

Note: hash chain provides tamper-evidence for the local log (detects accidental
or non-privileged modification). It does NOT prevent a compromised machine from
regenerating a consistent fake history — off-host anchoring is a v2+ feature.

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
| Off-host chain anchoring | Local hash chain is MVP; remote anchoring for durable tamper-evidence is v2+ |
| Multi-signature (M-of-N) | Complex, needs threshold crypto |
| CBOR serialization | JSON is fine for MVP, CBOR for compact wire format later |
| Python binding (PyO3) | TypeScript covers MCP ecosystem majority; Python follows for LangChain/CrewAI |
| Browser/Workers/Deno/Bun targets | Require different storage model; Node.js only for MVP |
| Compliance dashboard | Enterprise feature |
| Legal attribution layer | Needs legal framework partnership |
| Cross-framework (A2A, ANP) | MCP first, expand after |

## Open Source Strategy

- **License:** Apache-2.0 + MIT dual license (maximum compatibility)
- **GitHub:** `Prismer-AI/signet`
- **Public development** from day 1
- Conventional commits, CHANGELOG
- Issue templates for bug reports and feature requests
