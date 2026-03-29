# Show HN: Signet – Cryptographic action receipts for AI agents

**TL;DR:** Signet signs every AI agent tool call with Ed25519. Know what your agent did, when, and prove it. 3 lines of code to add to your MCP client. Open source (Apache-2.0 + MIT).

GitHub: https://github.com/Prismer-AI/signet

---

## The Problem

AI agents are executing real actions — creating GitHub issues, sending Slack messages, making API calls — with zero accountability. When something goes wrong, you can't answer a basic question: *what exactly did my agent do?*

MCP (Model Context Protocol) is becoming the standard for agent-tool communication. But MCP has no signing, no audit trail, and no way to prove which agent did what. 53% of MCP servers use static API keys. 79% pass tokens via environment variables. stdio transport (the most common deployment) has zero authentication.

We've already seen the consequences: agents deleting production environments, leaking tokens via prompt injection, running up $47K bills in infinite loops.

## What Signet Does

Signet gives every AI agent an Ed25519 identity and signs every tool call. It's a client-side SDK — not a proxy, not a gateway, not a daemon. You add it to your code, and every tool call gets a cryptographic receipt.

```typescript
import { generateKeypair } from "@signet/core";
import { SigningTransport } from "@signet/mcp";

const { secretKey } = generateKeypair();
const transport = new SigningTransport(innerTransport, secretKey, "my-agent");
// That's it. Every tool call is now signed.
```

Each receipt contains: which tool was called, with what parameters, by which agent key, at what time, with a cryptographic signature covering all of it. Tamper with any field and the signature breaks.

## What a Receipt Looks Like

```json
{
  "v": 1,
  "id": "rec_e7039e7e7714e84f...",
  "action": {
    "tool": "github_create_issue",
    "params": {"title": "fix bug"},
    "params_hash": "sha256:b878192252cb..."
  },
  "signer": {
    "pubkey": "ed25519:0CRkURt/tc6r...",
    "name": "deploy-bot"
  },
  "ts": "2026-03-29T23:24:03.309Z",
  "sig": "ed25519:6KUohbnSmehP..."
}
```

## CLI

Signet also ships a CLI for managing identities and auditing:

```bash
# Generate an agent identity (encrypted with Argon2id + XChaCha20-Poly1305)
signet identity generate --name deploy-bot

# After your agent runs, check what it did
signet audit --since 24h

# Verify every signature in the log
signet audit --verify

# Verify the hash chain hasn't been tampered with
signet verify --chain
```

The audit log is append-only JSONL, split by day, with a SHA-256 hash chain. Each record links to the previous one. Delete or modify a record and the chain breaks.

## Architecture

```
Your Agent → SigningTransport → MCP Server (unchanged)
                    |
                    +→ Signs tool call (Ed25519)
                    +→ Appends to hash-chained audit log
                    +→ Injects receipt into _meta._signet
```

Agent-side only. MCP servers don't need to change. The receipt is injected into MCP's `params._meta` extension field, which servers ignore by default.

## What Signet Is Not

Signet is an *attestation* tool, not a *prevention* tool. It proves what happened — it doesn't block bad actions. That's what policy firewalls (like Aegis) are for.

Think of it like this: Aegis is the bouncer at the door. Signet is the security camera. You probably want both.

Signet also doesn't prove the server *executed* the action — only that the agent *requested* it. Server-side receipts are planned for v2.

## Tech Stack

- **Rust core** with `ed25519-dalek`, compiled to WASM for Node.js
- **TypeScript packages**: `@signet/core` (crypto wrapper) and `@signet/mcp` (transport middleware)
- **RFC 8785 (JCS)** for deterministic JSON canonicalization
- **83 tests** (64 Rust + 8 WASM + 11 TypeScript), zero unsafe code

## Why Open Source

Agent security should be infrastructure, not a product differentiator. We want the receipt format to become a standard, and that only happens if everyone can use it.

Apache-2.0 + MIT dual license. Use it in anything.

## Try It

```bash
git clone https://github.com/Prismer-AI/signet.git
cd signet
cargo build --release -p signet-cli
./target/release/signet identity generate --name test --unencrypted
./target/release/signet sign --key test --tool hello --params '{}' --target mcp://test
./target/release/signet audit
./target/release/signet verify --chain
```

Or for MCP integration: `npm install @signet/core @signet/mcp` (coming soon to npm).

---

GitHub: https://github.com/Prismer-AI/signet
License: Apache-2.0 + MIT
