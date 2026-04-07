# @signet-auth/mcp-server

Server-side receipt verification for Signet. Verify signed action receipts from AI agents before trusting them.

[![npm](https://img.shields.io/npm/v/@signet-auth/mcp-server?style=flat-square)](https://www.npmjs.com/package/@signet-auth/mcp-server)
[![GitHub Stars](https://img.shields.io/github/stars/Prismer-AI/signet?style=flat-square&color=yellow)](https://github.com/Prismer-AI/signet)

## Install

```bash
npm install @signet-auth/mcp-server
```

## Usage

```typescript
import { verifyReceipt } from "@signet-auth/mcp-server";

// Verify a receipt before processing the tool call
const result = verifyReceipt(receipt, agentPublicKey);
if (!result.valid) {
  throw new Error("Receipt verification failed");
}
```

## Links

- [Full documentation & all SDKs](https://github.com/Prismer-AI/signet)

If Signet is useful to you, [star us on GitHub](https://github.com/Prismer-AI/signet) — it helps others discover the project.
