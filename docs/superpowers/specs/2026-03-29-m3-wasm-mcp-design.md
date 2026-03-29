# M3: WASM + MCP Middleware — Design Spec

**Date:** 2026-03-29
**Status:** Draft
**Depends on:** M0 (WASM roundtrip), M1 (core+CLI), M2 (audit+chain)

## Goal

Build the TypeScript npm packages that make Signet usable by MCP developers:
a TypeScript wrapper for the WASM core (`@signet/core`) and an MCP transport
middleware (`@signet/mcp`) that auto-signs every tool call.

## Non-Goals

- npm publish (prepare package.json, but don't actually publish)
- Browser/Workers/Deno/Bun support (Node.js only)
- Audit log integration in SigningTransport (CLI handles audit)
- Server-side verification middleware (v2+)
- Python binding (v2+)

## Exit Criteria

1. `@signet/core` exports typed `generateKeypair()`, `sign()`, `verify()` functions
2. `@signet/mcp` exports `SigningTransport` class that implements MCP `Transport`
3. SigningTransport intercepts `tools/call` → signs → injects `_meta._signet` with receipt (params nulled, hash preserved)
4. SigningTransport passes through all non-tool-call messages unmodified
5. Example MCP agent + echo server runs end-to-end
6. Unit tests for both packages pass
7. WASM binary loads correctly in Node.js
8. All existing Rust tests (64) still pass

## Architecture

```
Developer's Agent Code
        |
        v
┌─────────────────────────────────────────┐
│  @signet/mcp — SigningTransport          │
│  implements MCP Transport interface      │
│                                          │
│  send(message):                          │
│    if tools/call:                        │
│      action = extract from message       │
│      receipt = signet.sign(key, action)  │
│      inject _meta._signet = receipt      │
│    inner.send(message)                   │
└────────────────┬────────────────────────┘
                 │ depends on
                 v
┌─────────────────────────────────────────┐
│  @signet/core — TypeScript wrapper       │
│                                          │
│  generateKeypair() → SignetKeypair       │
│  sign(key, action, name, owner) → Receipt│
│  verify(receipt, pubkey) → boolean       │
└────────────────┬────────────────────────┘
                 │ loads
                 v
┌─────────────────────────────────────────┐
│  signet_wasm.js + signet_wasm_bg.wasm    │
│  (built by wasm-pack from signet-core)   │
└─────────────────────────────────────────┘
```

## Package 1: @signet/core

### API

```typescript
export interface SignetKeypair {
  secretKey: string;   // base64 (64 bytes — keypair)
  publicKey: string;   // base64 (32 bytes — verifying key)
}

export interface SignetAction {
  tool: string;
  params: unknown;
  params_hash: string;   // auto-computed by sign(); pass "" and Rust fills it in
  target: string;
  transport: string;
}

// Errors: all functions throw standard Error with message from Rust.
// No custom error class in M3 — the WASM layer converts Rust errors to JsError
// which becomes a standard JS Error. Check e.message for details.

export interface SignetSigner {
  pubkey: string;     // "ed25519:<base64>"
  name: string;
  owner: string;
}

export interface SignetReceipt {
  v: number;
  id: string;
  action: SignetAction;
  signer: SignetSigner;
  ts: string;
  nonce: string;
  sig: string;
}

export function generateKeypair(): SignetKeypair;

export function sign(
  secretKey: string,
  action: SignetAction,
  signerName: string,
  signerOwner: string,
): SignetReceipt;

export function verify(receipt: SignetReceipt, publicKey: string): boolean;
```

### Implementation

Thin wrapper over WASM functions. Each function:
1. Calls the underlying `wasm_*` function
2. Handles the Map vs object quirk from `serde-wasm-bindgen` (if applicable)
3. Parses JSON response into typed objects
4. Throws typed errors on failure

NOTE: `wasm_generate_keypair` should be changed to return `Result<String, JsError>`
(JSON string, same as `wasm_sign`) instead of `Result<JsValue, JsError>`. This
eliminates the `serde-wasm-bindgen` Map-vs-object ambiguity. The Rust binding change:
```rust
// bindings/signet-ts/src/lib.rs — change wasm_generate_keypair to:
pub fn wasm_generate_keypair() -> Result<String, JsError> {
    let (signing_key, verifying_key) = generate_keypair();
    let result = serde_json::json!({
        "secret_key": BASE64.encode(signing_key.to_keypair_bytes()),
        "public_key": BASE64.encode(verifying_key.to_bytes()),
    });
    serde_json::to_string(&result).map_err(|e| JsError::new(&e.to_string()))
}
```

This means `examples/wasm-roundtrip/test.mjs` must also be updated to `JSON.parse()`.

TypeScript wrapper:
```typescript
import { wasm_generate_keypair, wasm_sign, wasm_verify } from './wasm/signet_wasm.js';

export function generateKeypair(): SignetKeypair {
  const json = wasm_generate_keypair();
  const result = JSON.parse(json);
  return {
    secretKey: result.secret_key,
    publicKey: result.public_key,
  };
}

export function sign(
  secretKey: string,
  action: SignetAction,
  signerName: string,
  signerOwner: string,
): SignetReceipt {
  const actionJson = JSON.stringify(action);
  const receiptJson = wasm_sign(secretKey, actionJson, signerName, signerOwner);
  return JSON.parse(receiptJson);
}

export function verify(receipt: SignetReceipt, publicKey: string): boolean {
  return wasm_verify(JSON.stringify(receipt), publicKey);
}
```

### Package Structure

```
packages/signet-core/
├── package.json
├── tsconfig.json
├── src/
│   └── index.ts         # typed wrapper
├── wasm/                # copied from wasm-pack output at build time
│   ├── signet_wasm.js
│   ├── signet_wasm_bg.wasm
│   └── signet_wasm.d.ts
└── tests/
    └── core.test.ts     # unit tests
```

`package.json`:
```json
{
  "name": "@signet/core",
  "version": "0.1.0",
  "description": "Cryptographic action receipts for AI agents",
  "type": "module",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "files": ["dist/", "wasm/"],
  "scripts": {
    "build": "tsc",
    "test": "tsc && node --test dist/tests/core.test.js"
  },
  "license": "Apache-2.0 OR MIT"
}
```

TypeScript compiled with `tsc`, output to `dist/`. Tests run on compiled JS:
`node --test dist/tests/core.test.js` (compile first with `tsc`).

WASM target is `nodejs` (synchronous loading, no async `init()` required).
Do NOT use `--target web` or `--target bundler` — they require async init.

tsconfig.json for both packages:
```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "outDir": "dist",
    "rootDir": ".",
    "declaration": true,
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true
  },
  "include": ["src/**/*", "tests/**/*"]
}
```

## Package 2: @signet/mcp

### SigningTransport

```typescript
import type { Transport, TransportSendOptions } from "@modelcontextprotocol/sdk/shared/transport.js";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { sign, type SignetReceipt, type SignetAction } from "@signet/core";

export interface SigningTransportOptions {
  target?: string;              // default "unknown"
  transport?: string;           // default "stdio"
  onSign?: (receipt: SignetReceipt) => void;  // callback after signing
}

export class SigningTransport implements Transport {
  private inner: Transport;
  private secretKey: string;
  private signerName: string;
  private signerOwner: string;
  private options: SigningTransportOptions;

  constructor(
    inner: Transport,
    secretKey: string,
    signerName: string,
    signerOwner?: string,
    options?: SigningTransportOptions,
  ) {
    this.inner = inner;
    this.secretKey = secretKey;
    this.signerName = signerName;
    this.signerOwner = signerOwner ?? "";
    this.options = options ?? {};

    // Forward callbacks using lazy closures.
    // MCP SDK's Protocol.connect() sets our callbacks AFTER construction,
    // so these closures must read this.onclose/etc lazily at call time.
    this.inner.onclose = () => this.onclose?.();
    this.inner.onerror = (e) => this.onerror?.(e);
    this.inner.onmessage = (msg, extra) => this.onmessage?.(msg, extra);
  }

  // Transport interface
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: (message: JSONRPCMessage, extra?: any) => void;

  get sessionId() { return this.inner.sessionId; }
  setProtocolVersion = (v: string) => this.inner.setProtocolVersion?.(v);

  start(): Promise<void> { return this.inner.start(); }
  close(): Promise<void> { return this.inner.close(); }

  async send(message: JSONRPCMessage, options?: TransportSendOptions): Promise<void> {
    if (this.isToolCall(message)) {
      const receipt = this.signToolCall(message);
      this.injectSignet(message, receipt);
      this.options.onSign?.(receipt);
    }
    return this.inner.send(message, options);
  }

  private isToolCall(message: JSONRPCMessage): boolean {
    return 'method' in message && message.method === 'tools/call';
  }

  private signToolCall(message: any): SignetReceipt {
    const params = message.params ?? {};
    const action: SignetAction = {
      tool: params.name ?? "unknown",
      params: params.arguments ?? {},  // sign with real params for correct hash
      params_hash: "",                 // computed by sign()
      target: this.options.target ?? "unknown",
      transport: this.options.transport ?? "stdio",
    };
    return sign(this.secretKey, action, this.signerName, this.signerOwner);
  }

  private injectSignet(message: any, receipt: SignetReceipt): void {
    // Deep-clone message.params to avoid mutating the original object
    // (MCP SDK may reuse it for logging/retries)
    message.params = JSON.parse(JSON.stringify(message.params ?? {}));
    if (!message.params._meta) message.params._meta = {};
    // Inject receipt with params nulled (avoid duplication — params are
    // already in message.params.arguments)
    message.params._meta._signet = {
      ...receipt,
      action: { ...receipt.action, params: null },
    };
  }
}
```

### Key Design Decisions

**`params._meta._signet` injection point:**
MCP spec marks `_meta` as a loose schema (Zod passthrough). Extra fields are
preserved through the pipeline. This is the officially sanctioned extension point.

**params = null in injected receipt:**
The tool call's actual params are already in `message.params.arguments`. Duplicating
them in `_signet` would bloat the message. The `params_hash` in the receipt allows
verification without the raw params.

**`onSign` callback:**
Optional hook for logging, metrics, or audit. SigningTransport itself does NOT
write to filesystem (no audit log). This keeps it pure and browser-compatible
in the future.

**Callback forwarding:**
MCP SDK's `Protocol.connect()` takes ownership of transport callbacks. The wrapper
must forward `onclose`/`onerror`/`onmessage` from inner to outer. This is done in
the constructor.

### Package Structure

```
packages/signet-mcp/
├── package.json
├── tsconfig.json
├── src/
│   ├── index.ts              # re-exports
│   └── signing-transport.ts  # SigningTransport class
└── tests/
    └── mcp.test.ts           # unit tests with InMemoryTransport
```

`package.json`:
```json
{
  "name": "@signet/mcp",
  "version": "0.1.0",
  "description": "MCP middleware for Signet cryptographic action receipts",
  "type": "module",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "files": ["dist/"],
  "scripts": {
    "build": "tsc",
    "test": "tsc && node --test dist/tests/mcp.test.js"
  },
  "peerDependencies": {
    "@modelcontextprotocol/sdk": ">=1.10.0"
  },
  "dependencies": {
    "@signet/core": "workspace:*"
  },
  "license": "Apache-2.0 OR MIT"
}
```

## Package 3: Example MCP Agent

```
examples/mcp-agent/
├── package.json
├── agent.ts         # MCP client with SigningTransport
└── echo-server.ts   # Minimal MCP server that echoes tool call params
```

### echo-server.ts

Minimal MCP server with one tool "echo" that returns its params:

```typescript
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new Server({ name: "echo", version: "1.0" }, {
  capabilities: { tools: {} }
});

server.setRequestHandler("tools/list", async () => ({
  tools: [{
    name: "echo",
    description: "Echoes back the input",
    inputSchema: { type: "object", properties: { message: { type: "string" } } }
  }]
}));

server.setRequestHandler("tools/call", async (request) => ({
  content: [{ type: "text", text: JSON.stringify(request.params.arguments) }]
}));

const transport = new StdioServerTransport();
await server.connect(transport);
```

### agent.ts

MCP client that connects to echo-server via SigningTransport:

```typescript
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { generateKeypair } from "@signet/core";
import { SigningTransport } from "@signet/mcp";

// Generate agent identity
const { secretKey, publicKey } = generateKeypair();
console.log("Agent public key:", publicKey);

// Create transport with signing
const inner = new StdioClientTransport({ command: "npx", args: ["tsx", "echo-server.ts"] });
const transport = new SigningTransport(inner, secretKey, "demo-agent", "demo-owner", {
  target: "mcp://echo-server",
  onSign: (receipt) => console.log("Signed:", receipt.id, receipt.action.tool),
});

// Connect
const client = new Client({ name: "demo-agent", version: "1.0" }, {
  capabilities: {}
});
await client.connect(transport);

// Call tool
const result = await client.callTool({ name: "echo", arguments: { message: "Hello Signet!" } });
console.log("Response:", result.content);

// Verify our own receipt
// (In real usage, a third party would verify with publicKey)

await client.close();
```

## Workspace Configuration

Root `package.json` (new):
```json
{
  "private": true,
  "workspaces": ["packages/*", "examples/*"]
}
```

This enables npm/yarn workspace linking so `@signet/mcp` can resolve `@signet/core`
locally during development.

## Build Flow

```bash
# 1. Build WASM → packages/signet-core/wasm/ (run from repo root)
wasm-pack build bindings/signet-ts --target nodejs --out-dir ../../packages/signet-core/wasm

# IMPORTANT: The generated wasm glue (signet_wasm.js) resolves the .wasm file
# relative to its own location. Since wasm/ is in packages/signet-core/wasm/ and
# src/index.ts imports from '../wasm/signet_wasm.js', after tsc compiles to dist/,
# the import becomes 'dist/../wasm/signet_wasm.js' = 'wasm/signet_wasm.js' which
# resolves correctly because wasm/ is adjacent to dist/.
# Tests must run AFTER tsc (on dist/*.js), not on raw .ts files.

# 2. Install npm deps
npm install

# 3. Build TS packages
cd packages/signet-core && npx tsc
cd packages/signet-mcp && npx tsc

# 4. Run tests
cd packages/signet-core && node --test tests/core.test.ts
cd packages/signet-mcp && node --test tests/mcp.test.ts

# 5. Run example
cd examples/mcp-agent && npx tsx agent.ts
```

## Test Plan

### @signet/core tests (6 tests)

| Test | What it validates |
|------|-------------------|
| `test_generate_keypair` | Returns object with secretKey + publicKey strings |
| `test_sign_produces_receipt` | Receipt has all required fields with correct prefixes |
| `test_sign_verify_roundtrip` | sign → verify returns true |
| `test_verify_wrong_key` | verify with different key returns false |
| `test_verify_tampered` | Tampered receipt → verify returns false |
| `test_params_hash_computed` | Receipt.action.params_hash starts with "sha256:" |

### @signet/mcp tests (5 tests)

| Test | What it validates |
|------|-------------------|
| `test_signs_tool_call` | tools/call message gets _meta._signet injected |
| `test_passthrough_non_tool` | Non-tool messages forwarded unchanged |
| `test_receipt_has_correct_tool` | _signet.action.tool matches tool call name |
| `test_receipt_params_null` | _signet.action.params is null (hash-only) |
| `test_on_sign_callback` | onSign callback fires with receipt |

MCP tests use a mock transport (simple object implementing Transport interface)
instead of InMemoryTransport to avoid @modelcontextprotocol/sdk dependency
complexity in tests.

### Coverage

```
Package             Tests
──────────────────────────
@signet/core        6
@signet/mcp         5
──────────────────────────
Total TS            11
Total Rust (M0-M2)  64
──────────────────────────
Grand total         75
```

## File Map (new)

| File | Action | Responsibility |
|------|--------|----------------|
| `package.json` (root) | Create | npm workspace config |
| `packages/signet-core/package.json` | Create | @signet/core metadata |
| `packages/signet-core/tsconfig.json` | Create | TypeScript config |
| `packages/signet-core/src/index.ts` | Create | Typed WASM wrapper |
| `packages/signet-core/tests/core.test.ts` | Create | 6 unit tests |
| `packages/signet-mcp/package.json` | Create | @signet/mcp metadata |
| `packages/signet-mcp/tsconfig.json` | Create | TypeScript config |
| `packages/signet-mcp/src/index.ts` | Create | Re-export SigningTransport |
| `packages/signet-mcp/src/signing-transport.ts` | Create | SigningTransport class |
| `packages/signet-mcp/tests/mcp.test.ts` | Create | 5 unit tests |
| `examples/mcp-agent/package.json` | Create | Example deps |
| `examples/mcp-agent/agent.ts` | Create | Demo MCP client |
| `examples/mcp-agent/echo-server.ts` | Create | Demo MCP server |

## Success Definition

M3 is complete when:
1. All 8 exit criteria pass
2. `node --test packages/signet-core/tests/core.test.ts` — 6 tests pass
3. `node --test packages/signet-mcp/tests/mcp.test.ts` — 5 tests pass
4. `cargo test --workspace` — 64 Rust tests pass
5. Example agent runs end-to-end and prints signed receipt
6. No TypeScript errors (`npx tsc --noEmit` in both packages)

## MVP Complete After M3

When M3 ships, Signet MVP is done:

```
M0: Ed25519 + WASM roundtrip          ✅
M1: Identity management + CLI          ✅
M2: Audit log + hash chain             ✅
M3: TypeScript packages + MCP middleware ← this
```

A developer can:
1. `signet identity generate --name my-agent`
2. Add 3 lines to their MCP client code (SigningTransport wrap)
3. Every tool call is now signed + logged
4. `signet audit` to see what happened
5. `signet verify --chain` to prove integrity
