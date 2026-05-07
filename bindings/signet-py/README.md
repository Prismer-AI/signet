# signet-auth

Cryptographic action receipts for AI agents. Sign every tool call with Ed25519 — works with LangChain, LangGraph, LlamaIndex, Google ADK, Pydantic AI, Smolagents, Semantic Kernel, OpenAI Agents, AutoGen, CrewAI, and more.

[![PyPI](https://img.shields.io/pypi/v/signet-auth?style=flat-square)](https://pypi.org/project/signet-auth/)
[![GitHub Stars](https://img.shields.io/github/stars/Prismer-AI/signet?style=flat-square&color=yellow)](https://github.com/Prismer-AI/signet)

## Install

```bash
pip install signet-auth
```

## Quick Start

```python
from signet_auth import SigningAgent

agent = SigningAgent.create("my-bot", owner="alice")
receipt = agent.sign("web_search", params={"query": "signet"}, target="mcp://local")
print(receipt.id)
```

## Decorator Entry Point

For plain Python tools, the easiest way to adopt Signet is the decorator layer:

```python
from signet_auth import SigningAgent, signet_tool

agent = SigningAgent.create("tool-bot", owner="alice")

@signet_tool(
    agent=agent,
    target="mcp://github.prod",
    audit_encrypt_params=True,
)
def create_issue(title: str, repo: str) -> str:
    return f"{repo}:{title}"
```

`@signet_tool` also supports:

- async tool functions
- custom `tool_name`
- explicit `transport`
- `on_sign_error="warn" | "raise"`

## MCP Server Verification

If you enforce Signet at the execution boundary, use `verify_request()` with a durable nonce backend:

```python
from signet_auth import FileNonceChecker, VerifyOptions, verify_request

nonce_checker = FileNonceChecker(".signet/nonces.json")
opts = VerifyOptions(
    trusted_keys=["ed25519:..."],
    expected_target="mcp://github.prod",
    nonce_checker=nonce_checker,
)

result = verify_request(request_params, opts)
if not result.ok:
    raise ValueError(result.error or "verification failed")
if not result.trusted:
    raise ValueError("untrusted signer")
```

`ServerVerifyResult` tells you both whether a receipt was present (`has_receipt`) and whether the signer was anchored to trust (`trusted`). `FileNonceChecker` is the default single-host pilot shape; `InMemoryNonceChecker` is still useful for tests and demos.

## Framework Integrations

| Framework | Import |
|-----------|--------|
| LangChain / LangGraph | `from signet_auth.langchain import SignetCallbackHandler` |
| LlamaIndex | `from signet_auth.llamaindex import SignetEventHandler` |
| Google ADK | `from signet_auth.google_adk import SignetPlugin` |
| OpenAI Agents SDK | `from signet_auth.openai_agents import SignetAgentHooks` |
| Pydantic AI | `from signet_auth.pydantic_ai import SignetMiddleware` |
| Semantic Kernel | `from signet_auth.semantic_kernel import SignetFunctionFilter` |
| Smolagents | `from signet_auth.smolagents import SignetStepCallback` |
| AutoGen | `from signet_auth.autogen import SignetAutogenHook` |
| CrewAI | `from signet_auth.crewai import SignetCrewCallback` |

Install with framework extras:

```bash
pip install signet-auth[langchain]     # LangChain / LangGraph
pip install signet-auth[llamaindex]    # LlamaIndex
pip install signet-auth[google-adk]    # Google ADK
pip install signet-auth[pydantic-ai]   # Pydantic AI
pip install signet-auth[semantic-kernel] # Semantic Kernel
pip install signet-auth[all]           # All frameworks
```

## Links

- [Full documentation & source](https://github.com/Prismer-AI/signet)
- [npm (@signet-auth/core)](https://www.npmjs.com/package/@signet-auth/core)
- [Rust (signet-core)](https://crates.io/crates/signet-core)

If Signet is useful to you, [star us on GitHub](https://github.com/Prismer-AI/signet) — it helps others discover the project.
