# @signet-auth/mcp-tools

<!-- mcp-name: io.github.prismer-ai/signet-mcp-tools -->

Standalone MCP server exposing Signet cryptographic tools over `stdio`.

## Tools

- `signet_generate_keypair`: Generate an Ed25519 keypair and return the public key.
- `signet_sign`: Sign a tool action and return a Signet receipt.
- `signet_verify`: Verify a Signet receipt against a public key.
- `signet_content_hash`: Compute the canonical SHA-256 content hash for JSON input.

## Install

```bash
npm install -g @signet-auth/mcp-tools
```

## Run

```bash
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
