# Signet: 给 AI Agent 的每一次操作签个名

**一句话：** Signet 用 Ed25519 签名 AI Agent 的每一次工具调用。你的 Agent 做了什么，什么时候做的，密码学可证明。3 行代码接入 MCP。开源，Apache-2.0 + MIT。

GitHub: https://github.com/Prismer-AI/signet

---

## 问题

AI Agent 正在执行真实的操作 — 创建 GitHub Issue、发送 Slack 消息、调用 API — 但没有任何问责机制。出了问题，你回答不了一个基本问题：**我的 Agent 到底做了什么？**

MCP（Model Context Protocol）正在成为 Agent 和工具通信的标准协议。但 MCP 没有签名机制，没有审计日志，没有办法证明哪个 Agent 做了什么。53% 的 MCP Server 使用静态 API Key，79% 通过环境变量传递 Token。stdio 传输模式（最常见的部署方式）完全没有认证。

后果已经出现了：Agent 删除生产环境（13 小时宕机）、通过 prompt injection 泄露密钥、在死循环中烧掉 47000 美元账单。

## Signet 做了什么

Signet 给每个 AI Agent 一个 Ed25519 身份，对每次工具调用进行签名。它是一个客户端 SDK — 不是代理、不是网关、不是守护进程。你把它加到代码里，每次工具调用就会产生一个密码学收据。

```typescript
import { generateKeypair } from "@signet/core";
import { SigningTransport } from "@signet/mcp";

const { secretKey } = generateKeypair();
const transport = new SigningTransport(innerTransport, secretKey, "my-agent");
// 就这样。每次工具调用都会被签名。
```

每个收据包含：调用了哪个工具、参数是什么、哪个 Agent 密钥签的、什么时间，以及覆盖所有字段的密码学签名。篡改任何字段，签名就会失效。

## 收据长什么样

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

## 命令行工具

Signet 还提供了一个 CLI，用于管理身份和审计：

```bash
# 生成 Agent 身份（Argon2id + XChaCha20-Poly1305 加密存储）
signet identity generate --name deploy-bot

# Agent 运行之后，查看它做了什么
signet audit --since 24h

# 验证日志中每个收据的签名
signet audit --verify

# 验证哈希链的完整性（是否被篡改）
signet verify --chain
```

审计日志是 append-only 的 JSONL 文件，按天分割，带 SHA-256 哈希链。每条记录链接到前一条。删除或修改任何记录，链就会断裂。

## 架构

```
你的 Agent → SigningTransport → MCP Server（不需要改动）
                    |
                    +→ 签名工具调用（Ed25519）
                    +→ 写入哈希链审计日志
                    +→ 注入收据到 _meta._signet
```

纯客户端。MCP Server 不需要任何改动。收据注入到 MCP 的 `params._meta` 扩展字段，Server 默认会忽略未知字段。

## Signet 不是什么

Signet 是一个**证明**工具，不是一个**阻止**工具。它证明发生了什么 — 不能阻止坏的操作发生。阻止是策略防火墙（比如 Aegis）的工作。

打个比方：Aegis 是门口的保安，Signet 是安防摄像头。你可能两个都需要。

Signet 也不能证明 Server *执行*了操作 — 只能证明 Agent *请求*了操作。Server 端收据是 v2 的计划。

## 技术栈

- **Rust 核心**，使用 `ed25519-dalek`，编译为 WASM 供 Node.js 使用
- **TypeScript 包**：`@signet/core`（加密 wrapper）和 `@signet/mcp`（传输中间件）
- **RFC 8785 (JCS)** 确定性 JSON 规范化
- **83 个测试**（64 Rust + 8 WASM + 11 TypeScript），零 unsafe 代码

## 为什么开源

Agent 安全应该是基础设施，不是产品差异化。我们希望收据格式成为标准，而这只有在所有人都能用的时候才会发生。

Apache-2.0 + MIT 双协议。随便用。

## 试试看

```bash
git clone https://github.com/Prismer-AI/signet.git
cd signet
cargo build --release -p signet-cli
./target/release/signet identity generate --name test --unencrypted
./target/release/signet sign --key test --tool hello --params '{}' --target mcp://test
./target/release/signet audit
./target/release/signet verify --chain
```

MCP 集成：`npm install @signet/core @signet/mcp`（即将发布到 npm）。

---

GitHub: https://github.com/Prismer-AI/signet
协议: Apache-2.0 + MIT
