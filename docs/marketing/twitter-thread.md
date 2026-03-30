# Signet Launch Twitter Thread

发帖时间：周二或周三，美西上午 9-11 点（北京时间凌晨 1-3 点）
配合 HN Show HN 同步发

---

## Tweet 1 (Hook)

Your AI agent just mass-deleted a production database.

Can you prove exactly what it did? When? Who authorized it?

We built Signet — open-source cryptographic receipts for every AI agent tool call.

Ed25519 signatures. Hash-chained audit log. 3 lines of code.

🔗 github.com/Prismer-AI/signet

---

## Tweet 2 (Problem)

The numbers are wild:

- 78% of breached agents had overly broad permissions
- 53% of MCP servers use static API keys
- Agent-involved breaches grew 340% YoY

And stdio transport (the most common MCP deployment) has zero auth.

When your agent breaks something, you literally can't prove what happened.

---

## Tweet 3 (Solution — code)

Signet fixes this in 3 lines:

```typescript
import { generateKeypair } from "@signet-auth/core";
import { SigningTransport } from "@signet-auth/mcp";

const { secretKey } = generateKeypair();
const transport = new SigningTransport(inner, secretKey, "my-agent");
```

Every `tools/call` is now signed with Ed25519. MCP servers don't need to change.

---

## Tweet 4 (What you get)

Every tool call produces a signed receipt:

- Which tool was called
- With what params (+ SHA-256 hash)
- Which agent key signed it
- Exact timestamp
- Ed25519 signature covering all fields

Tamper with any field — signature breaks.

[attach: receipt JSON screenshot]

---

## Tweet 5 (CLI)

CLI for managing agent identities and auditing:

```
signet identity generate --name deploy-bot
signet sign --key deploy-bot --tool create_issue --params '{"title":"bug"}'
signet audit --since 24h
signet verify --chain
```

Keys encrypted with Argon2id + XChaCha20-Poly1305. Audit log is hash-chained.

[attach: terminal screenshot]

---

## Tweet 6 (Differentiator)

Signet is NOT a proxy, NOT a gateway, NOT a daemon.

It's an SDK. No infrastructure to deploy. No Docker. No extra process.

Other tools (Aegis, estoppl) are the bouncer at the door.
Signet is the security camera. You probably want both.

---

## Tweet 7 (Tech)

Under the hood:

- Rust core (ed25519-dalek) → WASM → TypeScript
- RFC 8785 (JCS) canonical JSON for deterministic signatures
- 83 tests (64 Rust + 8 WASM + 11 TypeScript)
- Zero unsafe code
- Apache-2.0 + MIT dual license

---

## Tweet 8 (CTA)

Try it:

```
npm install @signet-auth/core @signet-auth/mcp
```

or

```
cargo install signet-cli
```

GitHub: github.com/Prismer-AI/signet

Star if this matters to you. Issues/PRs welcome.

We think every agent action should be signed by default. This is step one.

---

## 备选 Hook（A/B 测试用）

**Hook A (incident-led):**
"Amazon Kiro deleted a production environment. 13 hours of downtime. Replit agent dropped a live database. Nobody could prove exactly what happened."

**Hook B (question-led):**
"If your AI agent did something catastrophic right now, could you produce a cryptographic proof of exactly what it did, when, and who authorized it?"

**Hook C (stat-led):**
"97% of organizations with AI breaches lacked proper access controls. We built the missing piece."

---

## 配图建议

1. Tweet 3: 代码截图（VS Code 深色主题，import + SigningTransport 3 行）
2. Tweet 4: receipt JSON 截图（terminal，syntax highlighted）
3. Tweet 5: terminal 录屏 gif（identity generate → sign → audit → verify --chain 全流程，15 秒）
4. Tweet 1: 可以不配图，纯文字 hook 更有力
