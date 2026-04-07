# @signet-auth/mcp

MCP middleware for Signet — signs every tool call in an MCP server with Ed25519 and creates verifiable audit receipts.

[![npm](https://img.shields.io/npm/v/@signet-auth/mcp?style=flat-square)](https://www.npmjs.com/package/@signet-auth/mcp)
[![GitHub Stars](https://img.shields.io/github/stars/Prismer-AI/signet?style=flat-square&color=yellow)](https://github.com/Prismer-AI/signet)

## Install

```bash
npm install @signet-auth/mcp
```

## Usage

```typescript
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { createSignetMiddleware } from "@signet-auth/mcp";

const server = new Server({ name: "my-server", version: "1.0.0" });

const { secretKey } = generateKeypair();
createSignetMiddleware(server, secretKey, "my-agent");
```

Every tool call is signed and receipt written to `~/.signet/audit/`.

## Links

- [Full documentation & all SDKs](https://github.com/Prismer-AI/signet)

If Signet is useful to you, [star us on GitHub](https://github.com/Prismer-AI/signet) — it helps others discover the project.
