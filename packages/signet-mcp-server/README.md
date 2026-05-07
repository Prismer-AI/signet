# @signet-auth/mcp-server

Execution-boundary verification for MCP servers. Reject unsigned, tampered, stale, replayed, or mis-targeted requests before tool execution, and optionally co-sign responses.

[![npm](https://img.shields.io/npm/v/@signet-auth/mcp-server?style=flat-square)](https://www.npmjs.com/package/@signet-auth/mcp-server)
[![GitHub Stars](https://img.shields.io/github/stars/Prismer-AI/signet?style=flat-square&color=yellow)](https://github.com/Prismer-AI/signet)

Best for:

- MCP server owners who want verification before execution
- Enforcing freshness, target binding, and tool/params matching
- Adding replay protection and response co-signing at the server boundary

Use another package if:

- You control the MCP client transport and need outbound signing: [`@signet-auth/mcp`](https://www.npmjs.com/package/@signet-auth/mcp)
- You want Signet as a standalone MCP server instead of an in-process library: [`@signet-auth/mcp-tools`](https://www.npmjs.com/package/@signet-auth/mcp-tools)

## Install

```bash
npm install @modelcontextprotocol/sdk @signet-auth/mcp-server
```

## Usage

```typescript
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { FileNonceCache, verifyRequest } from "@signet-auth/mcp-server";

const nonceCache = new FileNonceCache(".signet/nonces.json");

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const verified = verifyRequest(request, {
    trustedKeys: ["ed25519:..."],
    expectedTarget: "mcp://my-server",
    maxAge: 300,
    nonceCache,
  });

  if (!verified.ok) {
    return {
      content: [{ type: "text", text: verified.error ?? "verification failed" }],
      isError: true,
    };
  }
  if (!verified.trusted) {
    return {
      content: [{ type: "text", text: "untrusted signer" }],
      isError: true,
    };
  }

  // process tool call...
});
```

Useful exports:

- `verifyRequest()` checks signature validity, freshness, target binding, and tool/params matching, and tells you whether the signer is trusted
- `FileNonceCache` adds replay protection that survives ordinary restarts in a single-host pilot deployment
- `NonceCache` is still available for tests and demos
- `signResponse()` lets the server co-sign a response after a successful trusted `verifyRequest()`, by default records an `executed` or `failed` outcome, and also accepts an explicit `outcome` override for cases like `rejected` or `requires_approval`

## Related packages

- [`@signet-auth/mcp`](https://www.npmjs.com/package/@signet-auth/mcp) — sign outbound MCP requests on the client side
- [`@signet-auth/core`](https://www.npmjs.com/package/@signet-auth/core) — lower-level cryptographic primitives
- [`@signet-auth/mcp-tools`](https://www.npmjs.com/package/@signet-auth/mcp-tools) — standalone MCP server exposing Signet tools
- [Full documentation & all SDKs](https://github.com/Prismer-AI/signet)

If Signet is useful to you, [star us on GitHub](https://github.com/Prismer-AI/signet) — it helps others discover the project.
