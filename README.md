<h1 align="center">Signet</h1>

<p align="center">
  <strong>Your agents run on their infrastructure. The proof belongs to you.</strong><br/>
  <sub>Cryptographic evidence for every agent tool call — signed, hash-chained, offline-verifiable. Independent of any provider.</sub>
</p>

<p align="center">
  <a href="https://github.com/Prismer-AI/signet/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/Prismer-AI/signet/ci.yml?branch=main&style=flat-square&labelColor=black&label=CI" alt="CI"></a>
  <a href="https://github.com/Prismer-AI/signet/releases/latest"><img src="https://img.shields.io/github/v/release/Prismer-AI/signet?style=flat-square&labelColor=black&color=green&label=release" alt="Release"></a>
  <a href="https://github.com/Prismer-AI/signet/blob/main/LICENSE-APACHE"><img src="https://img.shields.io/badge/license-Apache--2.0%20%2F%20MIT-blue?labelColor=black&style=flat-square" alt="License"></a>
  <a href="https://github.com/Prismer-AI/signet/stargazers"><img src="https://img.shields.io/github/stars/Prismer-AI/signet?style=flat-square&labelColor=black&color=yellow" alt="Stars"></a>
  <a href="https://codespaces.new/Prismer-AI/signet?quickstart=1"><img src="https://img.shields.io/badge/Try_it-Open_in_Codespaces-black?style=flat-square&logo=github" alt="Open in Codespaces"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/SDKs-333?style=flat-square" alt="SDKs">
  <a href="https://crates.io/crates/signet-core"><img src="https://img.shields.io/crates/v/signet-core?style=flat-square&labelColor=black&color=dea584&logo=rust&logoColor=white&label=signet--core" alt="crates.io"></a>
  <a href="https://pypi.org/project/signet-auth/"><img src="https://img.shields.io/pypi/v/signet-auth?style=flat-square&labelColor=black&color=3775A9&logo=python&logoColor=white&label=signet--auth" alt="PyPI"></a>
  <a href="https://www.npmjs.com/org/signet-auth"><img src="https://img.shields.io/badge/npm-5%20packages-cb3837?style=flat-square&labelColor=black&logo=npm&logoColor=white" alt="npm packages"></a>
</p>

<p align="center">
  <sub>
    TypeScript packages:
    <a href="https://www.npmjs.com/package/@signet-auth/core"><code>@signet-auth/core</code></a> ·
    <a href="https://www.npmjs.com/package/@signet-auth/mcp"><code>@signet-auth/mcp</code></a> ·
    <a href="https://www.npmjs.com/package/@signet-auth/mcp-server"><code>@signet-auth/mcp-server</code></a> ·
    <a href="https://www.npmjs.com/package/@signet-auth/mcp-tools"><code>@signet-auth/mcp-tools</code></a> ·
    <a href="https://www.npmjs.com/package/@signet-auth/vercel-ai"><code>@signet-auth/vercel-ai</code></a>
  </sub>
</p>

<p align="center">
  <a href="./README.md"><img alt="English" src="https://img.shields.io/badge/English-d9d9d9"></a>
  <a href="./README.zh.md"><img alt="简体中文" src="https://img.shields.io/badge/简体中文-d9d9d9"></a>
</p>

<p align="center">
  <a href="https://www.youtube.com/watch?v=7OiGV_pyZas">
    <img src="https://img.youtube.com/vi/7OiGV_pyZas/maxresdefault.jpg" alt="Watch the Signet walkthrough on YouTube" width="820">
  </a>
</p>

<p align="center">
  <sub><a href="https://www.youtube.com/watch?v=7OiGV_pyZas">▶ Walkthrough: signing, audit log, and verification</a> · <a href="https://www.youtube.com/watch?v=PQnZC594qZc">▶ Demo: execution boundary &amp; MCP integration</a></sub>
</p>

**AI agents can already call Bash, GitHub, cloud APIs, and payment rails. Most teams still cannot prove exactly what the agent sent, who authorized it, or which policy was checked before it ran.**

Signet turns agent actions into portable, cryptographically verifiable evidence — evidence you hold, not evidence a vendor holds on your behalf.

Platforms log what happened. Signet proves it. The difference matters when an auditor asks for independent verification, when an incident happens on infrastructure you don't control, or when "trust the console" isn't a sufficient answer.

Each agent gets an Ed25519 identity. Every tool call can be signed, appended to a hash-chained audit trail, verified offline or before execution, co-signed by the server, bound to a delegation chain, and optionally bound to a policy decision.

If Signet is useful to you, [star this repo](https://github.com/Prismer-AI/signet) to help more teams find it.

The video above shows the full flow. The SVG below shows the CLI signing details, or jump to [See It Reject Bad Requests](#execution-boundary-demo) to watch the server block bad requests before they run.

<p align="center">
  <img src="demo-cli.svg" alt="Signet demo" width="820">
</p>

<p align="center">
  <sub>This first demo shows signing + audit receipts. See also the <a href="./demo-mcp.svg">MCP flow diagram</a>.</sub>
</p>

## What Signet Adds

Signet adds a lightweight trust layer for agent actions:

- **Sign** every tool call with the agent's cryptographic key
- **Verify** requests offline or at the execution boundary before they are trusted
- **Proxy** any MCP server transparently — sign and co-sign without touching agent or server code
- **Co-sign** server responses with bilateral receipts when you control both sides
- **Trace** multi-step workflows by linking receipts with `trace_id` and `parent_receipt_id`
- **Authorize** agents with scoped delegation chains that prove who allowed the action
- **Attest policy** by embedding a signed `PolicyAttestation` when a YAML policy is satisfied
- **Inspect locally** with an append-only audit log and dashboard, no hosted control plane required

## What's New In 0.9

- **MCP proxy**: `signet proxy --target <cmd> --key <name>` — drop Signet in front of any MCP server as a transparent stdio proxy. No changes to the agent or server required. Signs every `tools/call` and co-signs server responses with bilateral receipts.
- **Trace correlation**: `trace_id` and `parent_receipt_id` fields on `Action` link receipts across multi-step workflows into a causal chain. Both fields are part of the signed payload — tampering invalidates the signature.
- **Policy engine**: `signet sign --policy policy.yaml` enforces policy before signing and binds the decision into the receipt. The proxy also respects `--policy`, blocking denied calls before they reach the server.
- **Delegation chains**: `signet delegate ...` produces v4 receipts that prove who authorized the agent and what scope it had.
- **Local dashboard**: `signet dashboard` shows timeline, chain integrity, signature health, and delegated vs direct activity.
- **Broader integrations**: official Claude Code plugin, Codex plugin, MCP middleware, Python SDK, and Vercel AI SDK callbacks.

## Try It In 30 Seconds

```bash
pip install signet-auth
```

```python
from signet_auth import SigningAgent

agent = SigningAgent.create("my-agent", owner="team")
receipt = agent.sign("github_create_issue", params={"title": "fix bug"})

assert agent.verify(receipt)
print(receipt.id)
```

If you're new, start with one of these five paths:

## Choose Your Path

- [**Claude Code**](#claude-code-plugin): Best for the fastest first run in a coding agent. Run `/plugin install signet@claude-plugins-official` in Claude Code. In 5 minutes you'll have signed tool calls and a local audit log at `~/.signet/audit/`.
- [**Codex CLI**](#codex-plugin): Best for signing Bash tool calls in Codex. Copy `plugins/codex/` into `~/.codex/plugins/signet` and add one `PostToolUse` hook. In 5 minutes you'll have signed Bash actions in Codex using the same audit trail.
- [**Python SDK**](#python-sdk): Best if you want receipts inside LangGraph, LlamaIndex, OpenAI Agents, CrewAI, or your own tool runner. Start with `SigningAgent.create(...)` and add framework hooks only where you need them.
- [**MCP clients**](#mcp-client-integration): Best if you control an MCP client or transport. Wrap your transport with `new SigningTransport(inner, secretKey, "my-agent")`. In 5 minutes you'll have signed `tools/call` requests with receipts in `params._meta._signet`.
- [**MCP servers**](#mcp-server-verification): Best if you want verification before execution. Call `verifyRequest(request, {...})` in your tool handler. In 5 minutes you'll have signer, freshness, target-binding, and tool/params checks at the execution boundary.

<a id="execution-boundary-demo"></a>
## See It Reject Bad Requests

Run the shortest execution-boundary demo:

```bash
cd examples/mcp-agent
npm run execution-boundary-demo
```

<p align="center">
  <img src="demo-execution-boundary.svg" alt="Execution-boundary demo showing invalid requests rejected before execution" width="820">
</p>

<p align="center">
  <sub>Prefer motion? Download the <a href="./demo-execution-boundary.mp4">MP4</a> or <a href="./demo-execution-boundary.gif">GIF</a>.</sub>
</p>

See [examples/mcp-agent/demo-execution-boundary.mjs](./examples/mcp-agent/demo-execution-boundary.mjs) for the demo source.

<a id="delegation-chains"></a>
## Delegation Chains: Who Authorized This Agent?

Signet receipts prove **what** happened. Delegation chains prove **who allowed it**.

A root identity (human or org) cryptographically delegates scoped authority to an agent. Permissions can only narrow, never widen. The agent's v4 receipt carries the full proof of authorization.

```text
Owner (alice) → Agent A (tools: [Bash, Read], max_depth: 0)
                    ↓
              v4 Receipt: tool=Bash, authorization.chain proves alice → Agent A
```

```bash
# Create a delegation token
signet delegate create --from alice --to deploy-bot --to-name deploy-bot \
    --tools Bash,Read --targets "mcp://github" --max-depth 0

# Sign with authorization proof (v4 receipt)
signet delegate sign --key deploy-bot --tool Bash \
    --params '{"cmd":"git pull"}' --target "mcp://github" --chain chain.json

# Verify: signature + chain + scope + root trust
signet delegate verify-auth receipt.json --trusted-roots alice
```

Or in Python:

```python
from signet_auth import sign_delegation, sign_authorized, verify_authorized

# Delegation functions accept JSON strings for scope, chain, and receipts
token_json = sign_delegation(root_key_b64, "alice", agent_pubkey_b64, "bot", scope_json)
receipt_json = sign_authorized(agent_key_b64, action_json, "bot", f"[{token_json}]")
scope_json = verify_authorized(receipt_json, [root_pubkey_b64])
```

<p align="center">
  <img src="demo-delegation.svg" alt="Delegation chain demo" width="820">
</p>

## Policy Attestations: Was This Allowed?

Signet can enforce a YAML policy before signing. When an action is allowed, the signed receipt carries a `PolicyAttestation` proving which policy hash, rule, and decision were in force.

```yaml
version: 1
name: production-agents
default_action: deny
rules:
  - id: allow-read
    match:
      tool: Read
    action: allow
  - id: deny-rm-rf
    match:
      tool: Bash
      params:
        command:
          contains: "rm -rf"
    action: deny
    reason: destructive command
```

```bash
signet policy validate policy.yaml
signet policy check policy.yaml --tool Bash --params '{"command":"rm -rf /"}'

signet sign --key deploy-bot --tool Read \
    --params '{"path":"README.md"}' --target "mcp://github" --policy policy.yaml
```

Denied actions fail before a receipt is produced. Allowed actions produce a receipt whose signed payload proves the policy decision.

## When Teams Reach For Signet

- You need a tamper-evident audit trail for coding agents, MCP tools, or CI automation
- You want to prove which agent requested an action and who authorized it after an incident
- You need receipts that can be verified offline without depending on a hosted service
- You want lightweight policy enforcement before signing without adding a proxy to your stack

## What Signet Is And Isn't

- **Signet is** a trust layer for agent actions: signing, audit, verification, delegation, and policy attestation
- **Signet is** designed to fit into existing agent stacks with SDKs, plugins, and MCP middleware
- **Signet can** reject unsigned, stale, replayed, or mis-targeted MCP requests before execution
- **Signet can** deny actions before signing when you provide a policy file
- **Signet is not** a hosted gateway, always-on control plane, or replacement for sandboxing and least-privilege design

## Install

```bash
# CLI
cargo install signet-cli

# Python
pip install signet-auth

# TypeScript (MCP middleware)
npm install @signet-auth/core @signet-auth/mcp

# TypeScript (MCP server verification)
npm install @signet-auth/mcp-server

# TypeScript (Vercel AI SDK middleware)
npm install @signet-auth/vercel-ai

# TypeScript (standalone MCP signing server)
npx @signet-auth/mcp-tools
```

## Quick Start

<a id="claude-code-plugin"></a>
### Claude Code Plugin

Auto-sign every tool call in [Claude Code](https://claude.ai/code) with zero configuration:

```bash
# Option A: From the official Anthropic plugin marketplace
/plugin install signet@claude-plugins-official

# Option B: Add Signet as a marketplace source, then install
/plugin marketplace add Prismer-AI/signet
/plugin install signet@signet
```

Every tool call is signed with Ed25519 and logged to a hash-chained audit trail at `~/.signet/audit/`.

Alternative install methods:

```bash
# From Git
claude plugin add --from https://github.com/Prismer-AI/signet

# Via signet CLI
signet claude install
```

<a id="codex-plugin"></a>
### Codex Plugin

Auto-sign every Bash tool call in [Codex CLI](https://github.com/openai/codex):

```bash
git clone https://github.com/Prismer-AI/signet.git
cp -r signet/plugins/codex ~/.codex/plugins/signet
```

Then add the hook to `~/.codex/hooks.json`:

```json
{
  "hooks": {
    "PostToolUse": [{
      "matcher": "Bash",
      "hooks": [{
        "type": "command",
        "command": "node \"$HOME/.codex/plugins/signet/bin/sign.cjs\"",
        "timeout": 5
      }]
    }]
  }
}
```

Or use the MCP server for on-demand signing tools:

```bash
codex mcp add signet -- npx @signet-auth/mcp-tools
```

### CLI

```bash
# Generate an agent identity
signet identity generate --name my-agent

# Sign an action
signet sign --key my-agent --tool "github_create_issue" \
  --params '{"title":"fix bug"}' --target mcp://github.local

# Verify a receipt
signet verify receipt.json --pubkey my-agent

# Audit recent actions
signet audit --since 24h

# Verify log integrity
signet verify --chain
```

<a id="mcp-client-integration"></a>
### MCP Client Integration (TypeScript)

<p align="center">
  <img src="demo-mcp.svg" alt="Signet MCP bilateral flow demo" width="820">
</p>

```typescript
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { generateKeypair } from "@signet-auth/core";
import { SigningTransport } from "@signet-auth/mcp";

// Generate an agent identity
const { secretKey } = generateKeypair();

// Wrap any MCP transport -- all tool calls are now signed
const inner = new StdioClientTransport({ command: "my-mcp-server" });
const transport = new SigningTransport(inner, secretKey, "my-agent");

const client = new Client({ name: "my-agent", version: "1.0" }, {});
await client.connect(transport);

// Every callTool() is now cryptographically signed
const result = await client.callTool({
  name: "echo",
  arguments: { message: "Hello!" },
});
```

Every `tools/call` request gets a signed receipt injected into `params._meta._signet`.

<a id="mcp-server-verification"></a>
### MCP Server Verification

If you control the MCP server too, verify requests before execution:

```typescript
import { verifyRequest } from "@signet-auth/mcp-server";

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const verified = verifyRequest(request, {
    trustedKeys: ["ed25519:..."],
    maxAge: 300,
  });
  if (!verified.ok) return { content: [{ type: "text", text: verified.error }], isError: true };
  console.log(`Verified: ${verified.signerName}`);
  // process tool call...
});
```

### Vercel AI SDK Integration

```typescript
import { generateText } from "ai";
import { openai } from "@ai-sdk/openai";
import { generateKeypair } from "@signet-auth/core";
import { createSignetCallbacks } from "@signet-auth/vercel-ai";

const { secretKey } = generateKeypair();
const callbacks = createSignetCallbacks(secretKey, "my-agent");

const result = await generateText({
  model: openai("gpt-4o"),
  tools: { myTool },
  ...callbacks,
  prompt: "...",
});

// Every tool call is now signed
console.log(callbacks.receipts);
```

### Reference MCP Server

This repo also includes a minimal MCP reference server that demonstrates server-side verification with `@signet-auth/mcp-server`.

```bash
cd examples/mcp-agent
npm ci
npm run verifier-server
```

Available tools:

- `inspect_current_request` — verifies the current MCP tool call if it includes `params._meta._signet`
- `verify_receipt` — verifies a raw Signet receipt against a public key
- `verify_request_payload` — verifies a synthetic MCP `tools/call` payload offline

Environment variables:

- `SIGNET_TRUSTED_KEYS` — comma-separated `ed25519:<base64>` public keys
- `SIGNET_REQUIRE_SIGNATURE` — `true` or `false` (default `false`)
- `SIGNET_MAX_AGE` — max receipt age in seconds (default `300`)
- `SIGNET_EXPECTED_TARGET` — optional expected `receipt.action.target`

### Standalone MCP Signing Server

`@signet-auth/mcp-tools` exposes Signet signing, verification, and content hashing as MCP tools — plug into any MCP-compatible client:

```bash
npx @signet-auth/mcp-tools
```

Available tools: `signet_generate_keypair`, `signet_sign`, `signet_verify`, `signet_content_hash`.

<a id="python-sdk"></a>
### Python SDK (LangChain / CrewAI / AutoGen + 6 more)

```bash
pip install signet-auth
```

```python
from signet_auth import SigningAgent

# Create an agent identity (saved to ~/.signet/keys/)
agent = SigningAgent.create("my-agent", owner="willamhou")

# Sign any tool call -- receipt is auto-appended to audit log
receipt = agent.sign("github_create_issue", params={"title": "fix bug"})

# Verify
assert agent.verify(receipt)

# Query audit log
for record in agent.audit_query(since="24h"):
    print(f"{record.receipt.ts} {record.receipt.action.tool}")
```

#### LangChain Integration

```python
from signet_auth import SigningAgent
from signet_auth.langchain import SignetCallbackHandler

agent = SigningAgent("my-agent")
handler = SignetCallbackHandler(agent)

# Every tool call is now signed + audited
chain.invoke(input, config={"callbacks": [handler]})

# Async chains supported too
from signet_auth.langchain import AsyncSignetCallbackHandler
```

#### CrewAI Integration

```python
from signet_auth import SigningAgent
from signet_auth.crewai import install_hooks

agent = SigningAgent("my-agent")
install_hooks(agent)

# All CrewAI tool calls are now globally signed
crew.kickoff()
```

#### AutoGen Integration

```python
from signet_auth import SigningAgent
from signet_auth.autogen import signed_tool, sign_tools

agent = SigningAgent("my-agent")

# Wrap a single tool
wrapped = signed_tool(tool, agent)

# Or wrap all tools at once
wrapped_tools = sign_tools([tool1, tool2], agent)
```

#### LangGraph Integration

LangGraph uses LangChain's callback system — the same handler works directly:

```python
from signet_auth import SigningAgent
from signet_auth.langgraph import SignetCallbackHandler

agent = SigningAgent("my-agent")
handler = SignetCallbackHandler(agent)

result = graph.invoke(input, config={"callbacks": [handler]})
```

#### LlamaIndex Integration

```python
from signet_auth import SigningAgent
from signet_auth.llamaindex import install_handler

agent = SigningAgent("my-agent")
handler = install_handler(agent)

# All tool call events are now signed
index = ... # your LlamaIndex setup
response = index.as_query_engine().query("What is Signet?")

# Access receipts
print(handler.receipts)
```

#### Pydantic AI Integration

```python
from signet_auth import SigningAgent
from signet_auth.pydantic_ai_integration import SignetMiddleware

agent = SigningAgent("my-agent")
middleware = SignetMiddleware(agent)

@middleware.wrap
def my_tool(query: str) -> str:
    return f"result: {query}"
```

#### Google ADK Integration

```python
from signet_auth import SigningAgent
from signet_auth.google_adk import SignetPlugin

agent = SigningAgent("my-agent")
plugin = SignetPlugin(agent)

# Pass as callback to ADK agent
```

#### Smolagents Integration

```python
from signet_auth import SigningAgent
from signet_auth.smolagents import signet_step_callback

agent = SigningAgent("my-agent")
callback = signet_step_callback(agent)

bot = CodeAgent(tools=[...], model=model, step_callbacks=[callback])
```

#### OpenAI Agents SDK Integration

```python
from signet_auth import SigningAgent
from signet_auth.openai_agents import SignetAgentHooks

agent = SigningAgent("my-agent")

oai_agent = Agent(
    name="assistant",
    hooks=SignetAgentHooks(agent),
    tools=[...],
)
```

> **Note:** Tool call arguments are not yet available in the hook API ([issue #939](https://github.com/openai/openai-agents-python/issues/939)). Only the tool name is signed.

#### Low-Level API

```python
from signet_auth import generate_keypair, sign, verify, Action

kp = generate_keypair()
action = Action("github_create_issue", params={"title": "fix bug"})
receipt = sign(kp.secret_key, action, "my-agent", "willamhou")
assert verify(receipt, kp.public_key)
```

#### Bilateral Receipt (Server Co-signing)

```python
from signet_auth import generate_keypair, sign, sign_bilateral, verify_bilateral, Action

# Agent signs the tool call
agent_kp = generate_keypair()
action = Action("github_create_issue", params={"title": "fix bug"})
agent_receipt = sign(agent_kp.secret_key, action, "my-agent")

# Server co-signs with the response
server_kp = generate_keypair()
bilateral = sign_bilateral(
    server_kp.secret_key, agent_receipt,
    {"content": [{"type": "text", "text": "issue #42 created"}]},
    "github-server",
)
assert verify_bilateral(bilateral, server_kp.public_key)
assert bilateral.v == 3  # v3 = bilateral receipt
```

## How It Works

```
Your Agent
    |
    v
SigningTransport (wraps any MCP transport)
    |
    +---> Signs each tool call (Ed25519)
    +---> Appends Action Receipt to local audit log (hash-chained)
    +---> Forwards request to MCP server (unchanged)
```

Client-side signing works without changing the server. If you control the server too, add `verifyRequest()` and optional `signResponse()` for execution-boundary verification and bilateral receipts.

## Action Receipt

Every tool call starts with a signed receipt. Higher receipt versions add server co-signing (v3) and authorization chains (v4):

```json
{
  "v": 1,
  "id": "rec_e7039e7e7714e84f...",
  "action": {
    "tool": "github_create_issue",
    "params": {"title": "fix bug"},
    "params_hash": "sha256:b878192252cb...",
    "target": "mcp://github.local",
    "transport": "stdio"
  },
  "signer": {
    "pubkey": "ed25519:0CRkURt/tc6r...",
    "name": "demo-bot",
    "owner": "willamhou"
  },
  "ts": "2026-03-29T23:24:03.309Z",
  "nonce": "rnd_dcd4e135799393...",
  "sig": "ed25519:6KUohbnSmehP..."
}
```

The signature covers the entire receipt body (action + signer + timestamp + nonce) using [RFC 8785 (JCS)](https://datatracker.ietf.org/doc/html/rfc8785) canonical JSON. Modifying any field invalidates the signature.

## CLI Commands

| Command | Description |
|---------|-------------|
| `signet identity generate --name <n>` | Generate Ed25519 identity (encrypted by default) |
| `signet identity generate --unencrypted` | Generate without encryption (for CI) |
| `signet identity list` | List all identities |
| `signet identity export --name <n>` | Export public key as JSON |
| `signet sign --key <n> --tool <t> --params <json> --target <uri>` | Sign an action |
| `signet sign --hash-only` | Store only params hash (not raw params) |
| `signet sign --output <file>` | Write receipt to file instead of stdout |
| `signet sign --no-log` | Skip audit log append |
| `signet sign --policy <path>` | Enforce policy before signing and embed `PolicyAttestation` |
| `signet verify <receipt.json> --pubkey <name>` | Verify a receipt signature |
| `signet verify --chain` | Verify audit log hash chain integrity |
| `signet audit` | List recent actions |
| `signet audit --since <duration>` | Filter by time (e.g. 24h, 7d) |
| `signet audit --tool <substring>` | Filter by tool name |
| `signet audit --verify` | Verify all receipt signatures |
| `signet audit --export <file>` | Export records as JSON |
| `signet delegate create ...` | Create a scoped delegation token for another agent |
| `signet delegate sign ... --chain <file>` | Sign with delegation proof and produce a v4 receipt |
| `signet delegate verify-auth <receipt> --trusted-roots <name>` | Verify authorization chain, scope, and trusted root |
| `signet policy validate <path>` | Validate policy syntax and print its hash |
| `signet policy check <path> --tool <t> --params <json>` | Dry-run whether an action would be allowed |
| `signet proxy --target <cmd> --key <name>` | Run as MCP stdio proxy — sign all tool calls transparently |
| `signet proxy --target <cmd> --key <n> --policy <path>` | Proxy with policy enforcement before signing |
| `signet claude install` | Install Claude Code plugin (PostToolUse signing hook) |
| `signet claude uninstall` | Remove Claude Code plugin |
| `signet dashboard` | Open local audit dashboard in browser |

Passphrase via interactive prompt or `SIGNET_PASSPHRASE` env var for CI.

## Audit Dashboard

Run `signet dashboard` to open a local web UI for your audit log — no account, no network, just your local receipts.

<p align="center">
  <img src="dashboard-timeline.png" alt="Signet audit dashboard — timeline view showing every signed tool call" width="820">
</p>

<p align="center">
  <sub>Timeline view: every tool call logged with signer, tool name, target, and receipt ID. Filter by time, tool, or signer.</sub>
</p>

The **Chain Integrity** tab verifies the SHA-256 hash chain across your entire audit log — any tampering or gap is pinpointed to the exact file and line:

<p align="center">
  <img src="dashboard-chain-integrity.png" alt="Signet chain integrity check — break point detected at line 189" width="820">
</p>

<p align="center">
  <sub>Chain broken at line 189: expected vs actual hash shown. This is what "append-only" actually looks like in practice.</sub>
</p>

## Documentation

| Doc | Description |
|-----|-------------|
| [Architecture](docs/ARCHITECTURE.md) | System design, component overview, data flow |
| [Security](docs/SECURITY.md) | Crypto primitives, threat model, key storage |
| [MCP Integration Guide](docs/guides/mcp-integration.md) | Step-by-step MCP setup with SigningTransport |
| [CI/CD Integration](docs/guides/ci-integration.md) | GitHub Actions example, key management for CI |
| [Audit Log Guide](docs/guides/audit-log.md) | Querying, filtering, hash chain verification |
| [Contributing](CONTRIBUTING.md) | Build instructions, development workflow |
| [Changelog](CHANGELOG.md) | Version history |

## Project Structure

```
signet/
├── crates/signet-core/       Rust core: identity, sign, verify, audit, keystore
├── signet-cli/               CLI tool (signet binary)
├── bindings/
│   ├── signet-ts/            WASM binding (wasm-bindgen)
│   └── signet-py/            Python binding (PyO3 + maturin)
├── plugins/
│   ├── claude-code/          Claude Code plugin (WASM signing + audit)
│   └── codex/                Codex CLI plugin (WASM signing + audit)
├── packages/
│   ├── signet-core/          @signet-auth/core — TypeScript wrapper
│   ├── signet-mcp/           @signet-auth/mcp — MCP SigningTransport middleware
│   ├── signet-mcp-server/    @signet-auth/mcp-server — Server verification
│   ├── signet-mcp-tools/     @signet-auth/mcp-tools — Standalone MCP signing server
│   └── signet-vercel-ai/     @signet-auth/vercel-ai — Vercel AI SDK middleware
├── examples/
│   ├── wasm-roundtrip/       WASM validation tests
│   └── mcp-agent/            MCP agent, echo server, and verifier server example
├── docs/                     Design docs, specs, plans
├── LICENSE-APACHE
└── LICENSE-MIT
```

## Building from Source

### Prerequisites

- Rust (1.70+)
- wasm-pack
- Node.js (18+)
- Python (3.10+) + maturin (for Python binding)

### Build

```bash
# Rust core + CLI
cargo build --release -p signet-cli

# WASM binding
wasm-pack build bindings/signet-ts --target nodejs --out-dir ../../packages/signet-core/wasm

# TypeScript packages
cd packages/signet-core && npm run build
cd packages/signet-mcp && npm run build
cd packages/signet-mcp-tools && npm run build
```

```bash
# Python binding
cd bindings/signet-py
pip install maturin
maturin develop
```

### Test

```bash
# Rust tests
cargo test --workspace

# Python tests
cd bindings/signet-py && pytest tests/ -v

# WASM roundtrip
node examples/wasm-roundtrip/test.mjs

# TypeScript tests
cd packages/signet-core && npm test
cd packages/signet-mcp && npm test
cd packages/signet-mcp-server && npm test
cd packages/signet-mcp-tools && npm test

# Plugin tests
cd plugins/claude-code && npm test
cd plugins/codex && npm test

# Vercel AI SDK tests
cd packages/signet-vercel-ai && npm test

# Reference verifier server smoke test
cd examples/mcp-agent && npm run smoke
```

## Security

- **Ed25519** signatures (128-bit security level, `ed25519-dalek`)
- **Argon2id** key derivation (OWASP recommended minimum)
- **XChaCha20-Poly1305** key encryption with authenticated associated data (AAD)
- **SHA-256 hash chain** for tamper-evident audit log
- **RFC 8785 (JCS)** canonical JSON for deterministic signatures

Keys stored at `~/.signet/keys/` with `0600` permissions. Override with `SIGNET_HOME` env var.

### What Signet proves

- Agent key X signed intent to call tool Y with params Z at time T

### What Signet does NOT prove (yet)

- That the MCP server executed the action (use bilateral receipts with `signResponse()` for server co-signing — shipped in v0.4)
- That signer.owner actually controls the key (planned: identity registry)

Signet is first an evidence layer: it proves what happened. It can also enforce checks at the signing boundary and execution boundary, but it does not replace sandboxing, least-privilege design, or human approval where those are required.

## Related Projects

- **[Prismer Cloud](https://github.com/Prismer-AI/PrismerCloud)** — Full agent harness with evolution engine, memory layer, community, and built-in Ed25519/DID identity. Use Prismer Cloud for the complete agent platform; use Signet when you only need the standalone attestation layer.
- **[Prismer.AI](https://github.com/Prismer-AI/Prismer)** — The open-source AI research platform

## Star History

If Signet is useful to you, please star this repo — it helps more teams find it.

[![Star History Chart](https://api.star-history.com/svg?repos=Prismer-AI/signet&type=Date)](https://star-history.com/#Prismer-AI/signet&Date)

## License

Apache-2.0 + MIT dual license.
