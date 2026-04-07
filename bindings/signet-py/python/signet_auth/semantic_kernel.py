"""Semantic Kernel filter for Signet.

Signs every function/tool invocation with the agent's Ed25519 key.

Usage:
    from signet_auth import SigningAgent
    from signet_auth.semantic_kernel import SignetFunctionFilter

    agent = SigningAgent("my-bot")
    filter = SignetFunctionFilter(agent)

    kernel.add_filter("function_invocation", filter)
"""

from __future__ import annotations

import logging
from typing import Any

from signet_auth._signet import Receipt, SignetError
from signet_auth.agent import SigningAgent

logger = logging.getLogger("signet_auth.semantic_kernel")

try:
    from semantic_kernel.filters import FilterTypes  # noqa: F401
    from semantic_kernel.filters.functions.function_invocation_context import (
        FunctionInvocationContext,
    )
except ImportError as e:
    raise ImportError(
        "semantic-kernel is required for Signet Semantic Kernel integration. "
        "Install it with: pip install signet-auth[semantic-kernel]"
    ) from e


class SignetFunctionFilter:
    """Semantic Kernel function invocation filter that signs calls with Signet.

    Register with:
        kernel.add_filter(FilterTypes.FUNCTION_INVOCATION, filter)
    """

    def __init__(
        self, agent: SigningAgent, *, audit: bool = True, target: str = ""
    ) -> None:
        self.agent = agent
        self.audit = audit
        self.target = target
        self.receipts: list[Receipt] = []

    async def __call__(self, context: FunctionInvocationContext, next: Any) -> None:
        """Filter handler: sign before invocation, then call next."""
        function_name = (
            context.function.name if hasattr(context, "function") else "unknown"
        )
        plugin_name = (
            context.function.plugin_name
            if hasattr(context.function, "plugin_name")
            else ""
        )
        full_name = f"{plugin_name}.{function_name}" if plugin_name else function_name

        arguments = {}
        if hasattr(context, "arguments") and context.arguments:
            arguments = dict(context.arguments)

        try:
            receipt = self.agent.sign(
                full_name,
                params=arguments,
                target=self.target or "semantic-kernel://local",
                audit=self.audit,
            )
            self.receipts.append(receipt)
            logger.debug(
                "Signed function call: %s (receipt: %s)", full_name, receipt.id
            )
        except Exception:
            logger.warning("Failed to sign function call: %s", full_name, exc_info=True)
        finally:
            # Always continue the filter pipeline
            await next(context)
