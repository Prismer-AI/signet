"""Pydantic AI middleware for Signet.

Signs every tool execution with the agent's Ed25519 key.

Pydantic AI does not expose a formal capability/plugin interface, so this
module provides a wrapper that intercepts tool calls via the model settings
or by wrapping the agent's tool functions directly.

Usage:
    from signet_auth import SigningAgent
    from signet_auth.pydantic_ai import SignetMiddleware

    agent = SigningAgent("my-bot")
    middleware = SignetMiddleware(agent)

    # Wrap individual tool functions
    @middleware.wrap
    def my_tool(query: str) -> str:
        return f"result for {query}"

    # Or use the receipts after a run
    print(middleware.receipts)
"""

from __future__ import annotations

import functools
import logging
from typing import Any, Callable, TypeVar

from signet_auth._signet import Receipt, SignetError
from signet_auth.agent import SigningAgent

logger = logging.getLogger("signet_auth.pydantic_ai")

F = TypeVar("F", bound=Callable[..., Any])


class SignetMiddleware:
    """Pydantic AI middleware that signs tool calls with Signet.

    Wraps tool functions to sign each invocation before execution.
    Compatible with any pydantic-ai version since it operates at the
    function level, not the framework level.
    """

    def __init__(
        self, agent: SigningAgent, *, audit: bool = True, target: str = ""
    ) -> None:
        self.agent = agent
        self.audit = audit
        self.target = target
        self.receipts: list[Receipt] = []

    def wrap(self, fn: F) -> F:
        """Decorator that signs the tool call before executing the function."""
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            tool_name = fn.__name__
            try:
                receipt = self.agent.sign(
                    tool_name,
                    params=kwargs if kwargs else (args[0] if args else {}),
                    target=self.target or "pydantic-ai://local",
                    audit=self.audit,
                )
                self.receipts.append(receipt)
                logger.debug("Signed tool call: %s (receipt: %s)", tool_name, receipt.id)
            except (SignetError, RuntimeError):
                logger.warning("Failed to sign tool call: %s", tool_name, exc_info=True)
            return fn(*args, **kwargs)
        return wrapper  # type: ignore[return-value]

    def wrap_async(self, fn: F) -> F:
        """Decorator that signs the tool call before executing an async function."""
        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            tool_name = fn.__name__
            try:
                receipt = self.agent.sign(
                    tool_name,
                    params=kwargs if kwargs else (args[0] if args else {}),
                    target=self.target or "pydantic-ai://local",
                    audit=self.audit,
                )
                self.receipts.append(receipt)
                logger.debug("Signed tool call: %s (receipt: %s)", tool_name, receipt.id)
            except (SignetError, RuntimeError):
                logger.warning("Failed to sign tool call: %s", tool_name, exc_info=True)
            return await fn(*args, **kwargs)
        return wrapper  # type: ignore[return-value]
