# @signet-auth/core

Cryptographic action receipts for AI agents. Sign every tool call with Ed25519, verify offline, audit what happened.

[![npm](https://img.shields.io/npm/v/@signet-auth/core?style=flat-square)](https://www.npmjs.com/package/@signet-auth/core)
[![GitHub Stars](https://img.shields.io/github/stars/Prismer-AI/signet?style=flat-square&color=yellow)](https://github.com/Prismer-AI/signet)

## Install

```bash
npm install @signet-auth/core
```

## Usage

```typescript
import { generateKeypair, sign, verify } from "@signet-auth/core";

const { secretKey, publicKey } = generateKeypair();

const receipt = sign(secretKey, {
  tool: "web_search",
  params: { query: "signet" },
  params_hash: "",
  target: "mcp://my-server",
  transport: "stdio",
}, "my-agent", "owner");

console.log(verify(receipt, publicKey)); // true
```

## Links

- [Full documentation & all SDKs](https://github.com/Prismer-AI/signet)
- [Python (`signet-auth`)](https://pypi.org/project/signet-auth/)
- [Rust (`signet-core`)](https://crates.io/crates/signet-core)

If Signet is useful to you, [star us on GitHub](https://github.com/Prismer-AI/signet) — it helps others discover the project.
