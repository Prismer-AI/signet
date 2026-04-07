"""Pydantic AI capability for Signet.

Signs every tool execution with the agent's Ed25519 key.

Usage:
    from signet_auth import SigningAgent
    from signet_auth.pydantic_ai_integration import SignetCapability

    agent = SigningAgent("my-bot")
    capability = SignetCapability(agent)

    pydantic_agent = Agent(model, capabilities=[capability])
"""

from __future__ import annotations

import logging
from typing import Any

from signet_auth._signet import Receipt, SignetError
from signet_auth.agent import SigningAgent

logger = logging.getLogger("signet_auth.pydantic_ai")

try:
    from pydantic_ai import AbstractCapability
except ImportError as e:
    raise ImportError(
        "pydantic-ai is required for Signet Pydantic AI integration. "
        "Install it with: pip install signet-auth[pydantic-ai]"
    ) from e


class SignetCapability(AbstractCapability):
    """Pydantic AI capability that signs tool executions with Signet."""

    def __init__(
        self, agent: SigningAgent, *, audit: bool = True, target: str = ""
    ) -> None:
        self.agent = agent
        self.audit = audit
        self.target = target
        self.receipts: list[Receipt] = []

    async def before_tool_execute(
        self, tool_def: Any, arguments: dict[str, Any]
    ) -> None:
        tool_name = getattr(tool_def, "name", str(tool_def))
        try:
            receipt = self.agent.sign(
                tool_name,
                params=arguments,
                target=self.target or "pydantic-ai://local",
                audit=self.audit,
            )
            self.receipts.append(receipt)
            logger.debug("Signed tool call: %s (receipt: %s)", tool_name, receipt.id)
        except (SignetError, RuntimeError):
            logger.warning("Failed to sign tool call: %s", tool_name, exc_info=True)

    async def after_tool_execute(
        self, tool_def: Any, arguments: dict[str, Any], result: Any
    ) -> None:
        pass  # Tool end tracking can be added if needed
