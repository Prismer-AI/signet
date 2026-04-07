"""LangGraph integration for Signet.

LangGraph uses the same callback system as LangChain. Use SignetCallbackHandler
directly with your LangGraph graph:

    from signet_auth import SigningAgent
    from signet_auth.langgraph import SignetCallbackHandler

    agent = SigningAgent("my-bot")
    handler = SignetCallbackHandler(agent)
    result = graph.invoke(input, config={"callbacks": [handler]})
"""

from __future__ import annotations

# LangGraph uses LangChain's callback system
try:
    from signet_auth.langchain import (
        AsyncSignetCallbackHandler,
        SignetCallbackHandler,
    )
except ImportError as e:
    raise ImportError(
        "langchain-core is required for Signet LangGraph integration. "
        "Install it with: pip install langchain-core"
    ) from e

__all__ = ["SignetCallbackHandler", "AsyncSignetCallbackHandler"]
