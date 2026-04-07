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

## Links

- [Full documentation & source](https://github.com/Prismer-AI/signet)
- [npm (@signet-auth/core)](https://www.npmjs.com/package/@signet-auth/core)
- [Rust (signet-core)](https://crates.io/crates/signet-core)

If Signet is useful to you, [star us on GitHub](https://github.com/Prismer-AI/signet) — it helps others discover the project.
