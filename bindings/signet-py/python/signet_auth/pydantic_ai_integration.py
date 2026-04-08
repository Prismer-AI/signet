"""Pydantic AI middleware for Signet.

Signs every tool execution with the agent's Ed25519 key.

Pydantic AI does not expose a formal capability/plugin interface, so this
module provides a wrapper that intercepts tool calls via the model settings
or by wrapping the agent's tool functions directly.

Usage:
    from signet_auth import SigningAgent
    from signet_auth.pydantic_ai_integration import SignetMiddleware

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
import inspect
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

    Note: This class is not thread-safe. Use a separate instance per thread
    if concurrent access to ``receipts`` is needed.
    """

    def __init__(
        self, agent: SigningAgent, *, audit: bool = True, target: str = ""
    ) -> None:
        self.agent = agent
        self.audit = audit
        self.target = target
        self.receipts: list[Receipt] = []

    def _sign_call(self, fn: Callable[..., Any], args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
        """Sign a tool call, capturing all arguments via inspect."""
        tool_name = fn.__name__
        try:
            sig = inspect.signature(fn)
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            params = dict(bound.arguments)
        except (TypeError, ValueError):
            params = kwargs.copy()
            if args:
                params["__positional"] = list(args)
        try:
            receipt = self.agent.sign(
                tool_name,
                params=params,
                target=self.target or "pydantic-ai://local",
                audit=self.audit,
            )
            self.receipts.append(receipt)
            logger.debug("Signed tool call: %s (receipt: %s)", tool_name, receipt.id)
        except (SignetError, RuntimeError):
            logger.warning("Failed to sign tool call: %s", tool_name, exc_info=True)

    def wrap(self, fn: F) -> F:
        """Decorator that signs the tool call before executing the function."""

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            self._sign_call(fn, args, kwargs)
            return fn(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    def wrap_async(self, fn: F) -> F:
        """Decorator that signs the tool call before executing an async function."""

        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            self._sign_call(fn, args, kwargs)
            return await fn(*args, **kwargs)

        return wrapper  # type: ignore[return-value]
