# Signet

[![English](https://img.shields.io/badge/English-lightgrey?style=flat-square)](README.md)
[![简体中文](https://img.shields.io/badge/简体中文-lightgrey?style=flat-square)](README.zh.md)

[![CI](https://github.com/Prismer-AI/signet/actions/workflows/ci.yml/badge.svg)](https://github.com/Prismer-AI/signet/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/signet-core.svg)](https://crates.io/crates/signet-core)
[![npm](https://img.shields.io/npm/v/@signet-auth/mcp.svg)](https://www.npmjs.com/package/@signet-auth/mcp)
[![PyPI](https://img.shields.io/pypi/v/signet-auth.svg)](https://pypi.org/project/signet-auth/)
[![License](https://img.shields.io/badge/license-Apache--2.0%20%2F%20MIT-blue.svg)](LICENSE-APACHE)

AI Agent 的密码学操作收据 — 签名、审计、验证。

Signet 给每个 AI Agent 分配 Ed25519 身份，对每次工具调用进行签名。精确掌握你的 Agent 做了什么、什么时候做的，并且可以证明。

<p align="center">
  <img src="demo.gif" alt="Signet CLI 演示" width="800">
</p>

如果 Signet 对你有帮助，点个 ⭐ 让更多人发现它 — 感谢！

## 为什么需要

AI Agent 执行高价值操作，却零问责。Signet 解决这个问题：

- **签名** — 用 Agent 的密码学密钥签名每次工具调用
- **审计** — 仅追加、哈希链接的本地日志
- **验证** — 离线验证任意操作收据，无需网络

## 快速开始

### CLI

```bash
# 生成 Agent 身份
signet identity generate --name my-agent

# 签名操作
signet sign --key my-agent --tool "github_create_issue" \
  --params '{"title":"fix bug"}' --target mcp://github.local

# 验证收据
signet verify receipt.json --pubkey my-agent

# 审计最近操作
signet audit --since 24h

# 验证日志完整性
signet verify --chain
```

### MCP 集成（TypeScript）

```typescript
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { generateKeypair } from "@signet-auth/core";
import { SigningTransport } from "@signet-auth/mcp";

// 生成 Agent 身份
const { secretKey } = generateKeypair();

// 包装任意 MCP transport — 所有工具调用自动签名
const inner = new StdioClientTransport({ command: "my-mcp-server" });
const transport = new SigningTransport(inner, secretKey, "my-agent");

const client = new Client({ name: "my-agent", version: "1.0" }, {});
await client.connect(transport);

// 每次 callTool() 都会被密码学签名
const result = await client.callTool({
  name: "echo",
  arguments: { message: "Hello!" },
});
```

每次 `tools/call` 请求会在 `params._meta._signet` 中注入签名收据。
MCP Server 无需修改 — 未知字段会被忽略。

### Python（LangChain / CrewAI / AutoGen）

```bash
pip install signet-auth
```

```python
from signet_auth import SigningAgent

# 创建 Agent 身份（密钥保存到 ~/.signet/keys/）
agent = SigningAgent.create("my-agent", owner="willamhou")

# 签名任意工具调用 — 收据自动写入审计日志
receipt = agent.sign("github_create_issue", params={"title": "fix bug"})

# 验证
assert agent.verify(receipt)

# 查询审计日志
for record in agent.audit_query(since="24h"):
    print(f"{record.receipt.ts} {record.receipt.action.tool}")
```

或使用底层 API 进行框架集成：

```python
from signet_auth import generate_keypair, sign, verify, Action

kp = generate_keypair()
action = Action("github_create_issue", params={"title": "fix bug"})
receipt = sign(kp.secret_key, action, "my-agent", "willamhou")
assert verify(receipt, kp.public_key)
```

## 工作原理

```
你的 Agent
    |
    v
SigningTransport（包装任意 MCP transport）
    |
    +---> 签名每次工具调用（Ed25519）
    +---> 将操作收据追加到本地审计日志（哈希链接）
    +---> 将请求原样转发给 MCP Server
```

仅在 Agent 端。MCP Server 无需任何修改。

## 操作收据

每次工具调用都会产生一个签名收据：

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

签名覆盖整个收据体（action + signer + timestamp + nonce），使用 [RFC 8785 (JCS)](https://datatracker.ietf.org/doc/html/rfc8785) 规范化 JSON。篡改任何字段，签名即失效。

## CLI 命令

| 命令 | 说明 |
|------|------|
| `signet identity generate --name <n>` | 生成 Ed25519 身份（默认加密） |
| `signet identity generate --unencrypted` | 不加密生成（用于 CI） |
| `signet identity list` | 列出所有身份 |
| `signet identity export --name <n>` | 导出公钥为 JSON |
| `signet sign --key <n> --tool <t> --params <json> --target <uri>` | 签名操作 |
| `signet sign --hash-only` | 仅存储参数哈希（不存原始参数） |
| `signet sign --output <file>` | 将收据写入文件 |
| `signet sign --no-log` | 跳过审计日志追加 |
| `signet verify <receipt.json> --pubkey <name>` | 验证收据签名 |
| `signet verify --chain` | 验证审计日志哈希链完整性 |
| `signet audit` | 列出最近操作 |
| `signet audit --since <duration>` | 按时间过滤（如 24h, 7d） |
| `signet audit --tool <substring>` | 按工具名过滤 |
| `signet audit --verify` | 验证所有收据签名 |
| `signet audit --export <file>` | 导出记录为 JSON |

密码短语通过交互提示输入，或通过 `SIGNET_PASSPHRASE` 环境变量设置（用于 CI）。

## 文档

| 文档 | 说明 |
|------|------|
| [架构设计](docs/ARCHITECTURE.md) | 系统设计、组件概览、数据流 |
| [安全模型](docs/SECURITY.md) | 密码学原语、威胁模型、密钥存储 |
| [MCP 集成指南](docs/guides/mcp-integration.md) | SigningTransport 完整接入教程 |
| [CI/CD 集成](docs/guides/ci-integration.md) | GitHub Actions 示例、CI 密钥管理 |
| [审计日志指南](docs/guides/audit-log.md) | 查询、过滤、哈希链验证 |
| [贡献指南](CONTRIBUTING.md) | 构建说明、开发流程 |
| [更新日志](CHANGELOG.md) | 版本历史 |

## 项目结构

```
signet/
├── crates/signet-core/       Rust 核心：身份、签名、验证、审计、密钥存储
├── signet-cli/               CLI 工具（signet 二进制）
├── bindings/
│   ├── signet-ts/            WASM 绑定（wasm-bindgen）
│   └── signet-py/            Python 绑定（PyO3 + maturin）
├── packages/
│   ├── signet-core/          @signet-auth/core — TypeScript 封装
│   └── signet-mcp/           @signet-auth/mcp — MCP SigningTransport 中间件
├── examples/
│   ├── wasm-roundtrip/       WASM 验证测试
│   └── mcp-agent/            MCP agent + echo server 示例
├── docs/                     设计文档、规格、计划
├── LICENSE-APACHE
└── LICENSE-MIT
```

## 从源码构建

### 前置条件

- Rust (1.70+)
- wasm-pack
- Node.js (18+)
- Python (3.10+) + maturin（Python 绑定需要）

### 构建

```bash
# Rust 核心 + CLI
cargo build --release -p signet-cli

# WASM 绑定
wasm-pack build bindings/signet-ts --target nodejs --out-dir ../../packages/signet-core/wasm

# TypeScript 包
cd packages/signet-core && npm run build
cd packages/signet-mcp && npm run build
```

```bash
# Python 绑定
cd bindings/signet-py
pip install maturin
maturin develop
```

### 测试

```bash
# Rust 测试（68 个）
cargo test --workspace

# Python 测试（66 个）
cd bindings/signet-py && pytest tests/ -v

# WASM 往返测试（8 个）
node examples/wasm-roundtrip/test.mjs

# TypeScript 测试（11 个）
cd packages/signet-core && npm test
cd packages/signet-mcp && npm test
```

## 安全性

- **Ed25519** 签名（128 位安全级别，`ed25519-dalek`）
- **Argon2id** 密钥派生（OWASP 推荐最低参数）
- **XChaCha20-Poly1305** 密钥加密存储，带关联数据认证（AAD）
- **SHA-256 哈希链** 防篡改审计日志
- **RFC 8785 (JCS)** 规范化 JSON，确保确定性签名

密钥存储在 `~/.signet/keys/`，权限 `0600`。可通过 `SIGNET_HOME` 环境变量覆盖。

### Signet 能证明的

- Agent 密钥 X 在时间 T 签署了使用参数 Z 调用工具 Y 的意图

### Signet 目前不能证明的

- MCP Server 是否接收或执行了操作（v2：服务端收据）
- signer.owner 是否真正控制该密钥（v2：身份注册中心）

Signet 是证明工具（证明发生了什么），不是防护工具（阻止坏操作）。它与策略引擎、防火墙等工具互补。

## 许可证

Apache-2.0 + MIT 双协议。
