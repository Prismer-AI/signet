# @signet-auth/mcp-tools

<!-- mcp-name: io.github.prismer-ai/signet-mcp-tools -->

Standalone MCP server exposing Signet cryptographic tools over `stdio`. Use it from any MCP-compatible client without embedding Signet directly into your app.

[![npm](https://img.shields.io/npm/v/@signet-auth/mcp-tools?style=flat-square)](https://www.npmjs.com/package/@signet-auth/mcp-tools)
[![GitHub Stars](https://img.shields.io/github/stars/Prismer-AI/signet?style=flat-square&color=yellow)](https://github.com/Prismer-AI/signet)

Best for:

- Plugging Signet into Claude, Codex, or any MCP-compatible client
- Running signing and verification as an external tool server
- Quick experiments that need Signet over `stdio`

Use another package if:

- You want to embed Signet directly into app code: [`@signet-auth/core`](https://www.npmjs.com/package/@signet-auth/core)
- You want client-side MCP transport signing: [`@signet-auth/mcp`](https://www.npmjs.com/package/@signet-auth/mcp)
- You want server-side execution-boundary verification: [`@signet-auth/mcp-server`](https://www.npmjs.com/package/@signet-auth/mcp-server)

## Tools

- `signet_generate_keypair`: Generate an Ed25519 keypair and return the public key.
- `signet_sign`: Sign a tool action and return a Signet receipt.
- `signet_verify`: Verify a Signet receipt against a public key.
- `signet_content_hash`: Compute the canonical SHA-256 content hash for JSON input.

## Quick start

```bash
npx @signet-auth/mcp-tools
```

Or install globally:

```bash
npm install -g @signet-auth/mcp-tools
signet-mcp-tools
```

To avoid passing secret keys through MCP arguments, prefer setting:

```bash
export SIGNET_SECRET_KEY=...
signet-mcp-tools
```

## Local Development

```bash
npm run build --workspace @signet-auth/mcp-tools
npm run test --workspace @signet-auth/mcp-tools
npm run start --workspace @signet-auth/mcp-tools
```

## MCP Registry / Glama

This package is intended to be published with the MCP name:

```text
io.github.prismer-ai/signet-mcp-tools
```

The registry manifest is in [server.json](./server.json).

## Related packages

- [`@signet-auth/core`](https://www.npmjs.com/package/@signet-auth/core) — lower-level signing and verification primitives
- [`@signet-auth/mcp`](https://www.npmjs.com/package/@signet-auth/mcp) — sign outbound MCP requests on the client side
- [`@signet-auth/mcp-server`](https://www.npmjs.com/package/@signet-auth/mcp-server) — verify requests before execution on the server side
- [Full documentation & all SDKs](https://github.com/Prismer-AI/signet)

If Signet is useful to you, [star us on GitHub](https://github.com/Prismer-AI/signet) — it helps others discover the project.
