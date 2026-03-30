# Hacker News — Show HN Post

发帖时间：周二或周三，美西上午 9-11 点
与 Twitter thread 同步

---

## 标题

Show HN: Signet – Cryptographic action receipts for AI agents

## URL

https://github.com/Prismer-AI/signet

## 首条评论（发帖后立即自己回复）

Hi HN, I built Signet because I kept seeing AI agents do things nobody could trace. Amazon Kiro deleted a production environment. Replit agent dropped a live database. Supabase MCP leaked tokens via prompt injection. In every case: zero audit trail.

MCP (Model Context Protocol) is becoming the standard for agent-tool communication, but it has no signing, no audit log, and no way to prove which agent did what. 53% of MCP servers use static API keys. stdio transport has zero auth.

Signet gives every agent an Ed25519 identity and signs every tool call. It's a client-side SDK, not a proxy or gateway. You wrap your MCP transport with SigningTransport and every tools/call request gets a cryptographic receipt.

The receipt contains: tool name, params hash, signer pubkey, timestamp, nonce, and an Ed25519 signature covering all fields via RFC 8785 (JCS) canonical JSON. Tamper with any field and the signature breaks.

Quick start:

    npm install @signet-auth/core @signet-auth/mcp

Or for the CLI:

    cargo install signet-cli
    signet identity generate --name my-agent
    signet sign --key my-agent --tool test --params '{}' --target mcp://test
    signet audit --since 24h
    signet verify --chain

Tech stack: Rust core (ed25519-dalek) compiled to WASM for Node.js. Keys encrypted with Argon2id + XChaCha20-Poly1305. Audit log is append-only JSONL with SHA-256 hash chain. 83 tests, zero unsafe code.

What Signet does NOT do (yet): it proves the agent requested an action, not that the server executed it. Server-side receipts are v2. It's attestation (security camera), not prevention (bouncer). Tools like Aegis handle the prevention side.

Apache-2.0 + MIT dual license. Happy to answer questions about the design decisions, crypto choices, or where this is going.
