# @signet-auth/vercel-ai

Vercel AI SDK callbacks for Signet. Add a small callback bundle, sign every tool call, and keep receipts in memory without adding MCP-specific code.

[![npm](https://img.shields.io/npm/v/@signet-auth/vercel-ai?style=flat-square)](https://www.npmjs.com/package/@signet-auth/vercel-ai)
[![GitHub Stars](https://img.shields.io/github/stars/Prismer-AI/signet?style=flat-square&color=yellow)](https://github.com/Prismer-AI/signet)

Best for:

- Apps using `generateText()` and tool calling in the Vercel AI SDK
- Collecting signed receipts from tool calls with minimal integration work
- Keeping Vercel AI-specific logic out of your lower-level signing code

Use another package if:

- You need MCP transport signing: [`@signet-auth/mcp`](https://www.npmjs.com/package/@signet-auth/mcp)
- You need MCP execution-boundary verification: [`@signet-auth/mcp-server`](https://www.npmjs.com/package/@signet-auth/mcp-server)
- You want lower-level primitives only: [`@signet-auth/core`](https://www.npmjs.com/package/@signet-auth/core)

## Install

```bash
npm install ai @signet-auth/vercel-ai @signet-auth/core
```

## Usage

```typescript
import { generateText } from "ai";
import { openai } from "@ai-sdk/openai";
import { createSignetCallbacks } from "@signet-auth/vercel-ai";
import { generateKeypair } from "@signet-auth/core";

const { secretKey } = generateKeypair();
const callbacks = createSignetCallbacks(secretKey, "my-agent");

const result = await generateText({
  model: openai("gpt-4o"),
  tools: { myTool },
  ...callbacks,
  prompt: "Use the tool to ...",
});

console.log(callbacks.receipts); // signed receipts for every tool call
```

## Related packages

- [`@signet-auth/core`](https://www.npmjs.com/package/@signet-auth/core) — lower-level signing and verification primitives
- [`@signet-auth/mcp`](https://www.npmjs.com/package/@signet-auth/mcp) — client-side signing transport for MCP
- [`@signet-auth/mcp-server`](https://www.npmjs.com/package/@signet-auth/mcp-server) — server-side execution-boundary verification for MCP
- [Full documentation & all SDKs](https://github.com/Prismer-AI/signet)

If Signet is useful to you, [star us on GitHub](https://github.com/Prismer-AI/signet) — it helps others discover the project.
