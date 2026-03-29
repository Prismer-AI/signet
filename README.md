# Signet

Cryptographic action receipts for AI agents -- sign, audit, verify.

Signet gives every AI agent an Ed25519 identity and signs every tool call. Know exactly what your agent did, when, and prove it.

## Why

AI agents execute high-value actions with zero accountability. Signet fixes this:

- **Sign** every tool call with the agent's cryptographic key
- **Audit** what happened with append-only local logs
- **Verify** any action receipt offline, no network needed

## Quick Start

```bash
# Generate an agent identity
signet identity generate --name my-agent

# Sign an action
signet sign --tool "github_create_issue" --params '{"title":"fix bug"}'

# Verify a receipt
signet verify receipt.json --pubkey my-agent.pub

# Audit recent actions
signet audit --since 24h
```

### MCP Integration (TypeScript)

```typescript
import { SigningTransport } from "@signet/mcp";

// Wrap any MCP transport -- all tool calls are now signed + logged
const transport = new SigningTransport(innerTransport, agentKey);
```

## Architecture

```
Your Agent
    |
    v
SigningTransport (wraps any MCP transport)
    |
    +---> Signs each tool call (Ed25519)
    +---> Appends Action Receipt to local audit log
    +---> Forwards request to MCP server (unchanged)
```

Agent-side only. MCP servers don't need to change.

## Project Structure

```
crates/signet-core/     Rust core: identity, sign, verify, audit
signet-cli/             CLI tool
bindings/signet-ts/     TypeScript binding (WASM)
packages/signet-mcp/    @signet/mcp middleware
examples/               Usage examples
```

## Status

Early development. See [design document](docs/plans/2026-03-29-signet-design.md) for full details.

## License

Apache-2.0 + MIT dual license.
