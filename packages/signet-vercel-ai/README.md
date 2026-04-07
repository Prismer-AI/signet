# @signet-auth/vercel-ai

Signet signing callbacks for Vercel AI SDK. Signs every tool call with Ed25519 — 3 lines of code, no infrastructure.

[![npm](https://img.shields.io/npm/v/@signet-auth/vercel-ai?style=flat-square)](https://www.npmjs.com/package/@signet-auth/vercel-ai)
[![GitHub Stars](https://img.shields.io/github/stars/Prismer-AI/signet?style=flat-square&color=yellow)](https://github.com/Prismer-AI/signet)

## Install

```bash
npm install @signet-auth/vercel-ai @signet-auth/core
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

## Links

- [Full documentation & all SDKs](https://github.com/Prismer-AI/signet)

If Signet is useful to you, [star us on GitHub](https://github.com/Prismer-AI/signet) — it helps others discover the project.
