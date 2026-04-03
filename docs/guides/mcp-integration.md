# MCP Integration Guide

This guide walks through integrating Signet with any MCP (Model Context Protocol) client. After setup, every `tools/call` your agent makes will carry a cryptographic receipt.

## Prerequisites

```bash
npm install @signet-auth/core @signet-auth/mcp
```

## Basic Setup

### 1. Generate a keypair

```typescript
import { generateKeypair } from "@signet-auth/core";

const { secretKey, publicKey } = generateKeypair();
// secretKey: base64-encoded Ed25519 secret key
// publicKey: base64-encoded Ed25519 public key
```

Or use the CLI to generate a persistent identity:

```bash
signet identity generate --name my-agent --owner "your-name"
```

### 2. Wrap your MCP transport

```typescript
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { SigningTransport } from "@signet-auth/mcp";

const inner = new StdioClientTransport({ command: "my-mcp-server" });
const transport = new SigningTransport(inner, secretKey, "my-agent", "your-org");

const client = new Client({ name: "my-agent", version: "1.0" }, {});
await client.connect(transport);
```

That's it. Every `client.callTool()` is now signed.

### 3. Verify a receipt

```typescript
import { verify } from "@signet-auth/core";

const result = await client.callTool({
  name: "echo",
  arguments: { message: "Hello!" },
});

// The receipt was injected into the request
// On the server side, extract from params._meta._signet
// Verify with the agent's public key:
const isValid = verify(receipt, publicKey);
```

## SigningTransport Options

```typescript
const transport = new SigningTransport(inner, secretKey, "my-agent", "owner-name", {
  target: "mcp://github.local",    // MCP target URI (default: "unknown")
  transport: "stdio",              // Transport type (default: "stdio")
  onDispatch: (receipt) => {       // Callback after each dispatch receipt
    console.log(`Signed: ${receipt.action.tool} at ${receipt.ts}`);
  },
});
```

## How Receipt Injection Works

When `SigningTransport` intercepts a `tools/call` request:

1. Extracts `tool` name and `arguments` from the message
2. Creates a `SignetAction` with tool, params, target, transport
3. Signs the action with Ed25519
4. Injects the receipt into `message.params._meta._signet`
5. Stores the request so a compound receipt can be created after the response
6. Forwards the modified message to the inner transport

MCP servers ignore unknown `_meta` fields, so no server-side changes are needed.

## Working with Different Transports

`SigningTransport` wraps any MCP `Transport` implementation:

```typescript
// stdio
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
const inner = new StdioClientTransport({ command: "server" });

// SSE
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
const inner = new SSEClientTransport(new URL("http://localhost:3000/sse"));

// Wrap any of them
const transport = new SigningTransport(inner, secretKey, "my-agent");
```

## Server-Side Receipt Extraction

If you want to verify receipts on the server side:

```typescript
// In your MCP server tool handler
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const signetReceipt = request.params._meta?._signet;

  if (signetReceipt) {
    console.log(`Tool call signed by: ${signetReceipt.signer.name}`);
    console.log(`Signature: ${signetReceipt.sig}`);
    // Verify with the agent's known public key
  }

  // Handle the tool call as normal
  return { content: [{ type: "text", text: "done" }] };
});
```

## Full Example

See [examples/mcp-agent/](../../examples/mcp-agent/) for a complete working example with:

- a signed MCP client (`agent.ts`)
- a demo echo server (`echo-server.ts`)
- a reference verifier MCP server (`verifier-server.mjs`)
