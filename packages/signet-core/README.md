# @signet-auth/core

Core Signet primitives for TypeScript. WASM-backed Ed25519 receipts, content hashes, compound receipts, and bilateral receipts.

[![npm](https://img.shields.io/npm/v/@signet-auth/core?style=flat-square)](https://www.npmjs.com/package/@signet-auth/core)
[![GitHub Stars](https://img.shields.io/github/stars/Prismer-AI/signet?style=flat-square&color=yellow)](https://github.com/Prismer-AI/signet)

Best for:

- Building a custom Signet integration or framework adapter
- Managing keys, signing actions, and verifying receipts directly
- Lower-level control over Signet data structures in TypeScript

Use another package if:

- You want MCP client-side transport signing: [`@signet-auth/mcp`](https://www.npmjs.com/package/@signet-auth/mcp)
- You want MCP execution-boundary verification: [`@signet-auth/mcp-server`](https://www.npmjs.com/package/@signet-auth/mcp-server)
- You want Vercel AI SDK callbacks: [`@signet-auth/vercel-ai`](https://www.npmjs.com/package/@signet-auth/vercel-ai)

## Install

```bash
npm install @signet-auth/core
```

## Usage

```typescript
import { contentHash, generateKeypair, sign, verify } from "@signet-auth/core";

const { secretKey, publicKey } = generateKeypair();
const params = { query: "signet" };

const receipt = sign(secretKey, {
  tool: "web_search",
  params,
  params_hash: contentHash(params),
  target: "mcp://search",
  transport: "stdio",
}, "my-agent", "team");

console.log(verify(receipt, publicKey)); // true
```

## Related packages

- [`@signet-auth/mcp`](https://www.npmjs.com/package/@signet-auth/mcp) — client-side signing transport for MCP
- [`@signet-auth/mcp-server`](https://www.npmjs.com/package/@signet-auth/mcp-server) — server-side execution-boundary verification for MCP
- [`@signet-auth/vercel-ai`](https://www.npmjs.com/package/@signet-auth/vercel-ai) — callbacks for Vercel AI SDK tool calls
- [`@signet-auth/mcp-tools`](https://www.npmjs.com/package/@signet-auth/mcp-tools) — standalone MCP server exposing Signet tools
- [Python (`signet-auth`)](https://pypi.org/project/signet-auth/)
- [Rust (`signet-core`)](https://crates.io/crates/signet-core)
- [Full documentation & all SDKs](https://github.com/Prismer-AI/signet)

If Signet is useful to you, [star us on GitHub](https://github.com/Prismer-AI/signet) — it helps others discover the project.
