# @signet-auth/mcp

Client-side signing transport for MCP. Wrap an existing transport, inject `_meta._signet` into every `tools/call`, and collect receipts without changing server code.

[![npm](https://img.shields.io/npm/v/@signet-auth/mcp?style=flat-square)](https://www.npmjs.com/package/@signet-auth/mcp)
[![GitHub Stars](https://img.shields.io/github/stars/Prismer-AI/signet?style=flat-square&color=yellow)](https://github.com/Prismer-AI/signet)

Best for:

- MCP clients and agent runtimes you control
- Signing outbound `tools/call` requests without modifying the target server
- Collecting dispatch, compound, and bilateral receipts on the client side

Use another package if:

- You need verification before execution on the server: [`@signet-auth/mcp-server`](https://www.npmjs.com/package/@signet-auth/mcp-server)
- You want Signet as a standalone MCP server: [`@signet-auth/mcp-tools`](https://www.npmjs.com/package/@signet-auth/mcp-tools)

## Install

```bash
npm install @modelcontextprotocol/sdk @signet-auth/mcp @signet-auth/core
```

## Usage

```typescript
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { generateKeypair } from "@signet-auth/core";
import { SigningTransport } from "@signet-auth/mcp";

const { secretKey } = generateKeypair();
const inner = new StdioClientTransport({ command: "my-mcp-server" });
const transport = new SigningTransport(inner, secretKey, "my-agent", "team", {
  target: "mcp://my-mcp-server",
  trustedServerKeys: ["ed25519:..."],
  onDispatch: (receipt) => console.log("signed request", receipt.id),
  onBilateral: (receipt) => console.log("trusted bilateral", receipt.id),
});

const client = new Client({ name: "my-agent", version: "1.0.0" }, {});
await client.connect(transport);

await client.callTool({
  name: "echo",
  arguments: { message: "hello" },
});
```

Every outbound `tools/call` request gets a receipt injected into `params._meta._signet`.

Notes:

- `trustedServerKeys` is recommended whenever you expect bilateral receipts; without it, bilateral receipts are treated as integrity-only and do not trigger `onBilateral` by default.
- `allowUntrustedBilateral: true` is an explicit compatibility opt-in if you still want `onBilateral` for integrity-only receipts.

## Related packages

- [`@signet-auth/core`](https://www.npmjs.com/package/@signet-auth/core) — lower-level signing and verification primitives
- [`@signet-auth/mcp-server`](https://www.npmjs.com/package/@signet-auth/mcp-server) — verify requests before execution on the server
- [`@signet-auth/mcp-tools`](https://www.npmjs.com/package/@signet-auth/mcp-tools) — standalone MCP server exposing Signet tools
- [Full documentation & all SDKs](https://github.com/Prismer-AI/signet)

If Signet is useful to you, [star us on GitHub](https://github.com/Prismer-AI/signet) — it helps others discover the project.
