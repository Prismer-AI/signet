"""Smolagents step callback for Signet.

Signs tool calls from ActionStep objects.

Usage:
    from signet_auth import SigningAgent
    from signet_auth.smolagents import signet_step_callback

    agent = SigningAgent("my-bot")
    callback = signet_step_callback(agent)

    bot = CodeAgent(tools=[...], model=model, step_callbacks=[callback])
"""

from __future__ import annotations

import logging
from typing import Any

from signet_auth._signet import Receipt, SignetError
from signet_auth.agent import SigningAgent

logger = logging.getLogger("signet_auth.smolagents")

try:
    from smolagents.memory import ActionStep
except ImportError as e:
    raise ImportError(
        "smolagents is required for Signet smolagents integration. "
        "Install it with: pip install signet-auth[smolagents]"
    ) from e


class SignetStepCallback:
    """Callable step callback that signs tool calls from ActionStep."""

    def __init__(
        self, agent: SigningAgent, *, audit: bool = True, target: str = ""
    ) -> None:
        self.agent = agent
        self.audit = audit
        self.target = target
        self.receipts: list[Receipt] = []

    def __call__(self, step: Any) -> None:
        if not isinstance(step, ActionStep):
            return

        tool_calls = getattr(step, "tool_calls", None)
        if not tool_calls:
            return

        for tool_call in tool_calls:
            tool_name = tool_call.get("tool_name", tool_call.get("name", "unknown"))
            arguments = tool_call.get("arguments", {})
            try:
                receipt = self.agent.sign(
                    tool_name,
                    params=arguments,
                    target=self.target or "smolagents://local",
                    audit=self.audit,
                )
                self.receipts.append(receipt)
                logger.debug(
                    "Signed tool call: %s (receipt: %s)", tool_name, receipt.id
                )
            except (SignetError, RuntimeError):
                logger.warning("Failed to sign tool call: %s", tool_name, exc_info=True)


def signet_step_callback(
    agent: SigningAgent, *, audit: bool = True, target: str = ""
) -> SignetStepCallback:
    """Create a Signet step callback for smolagents.

    Args:
        agent: A SigningAgent with a loaded key.
        audit: If True (default), append receipts to audit log.
        target: Optional target URI for receipts.

    Returns:
        A callable to pass to step_callbacks=[...].
    """
    return SignetStepCallback(agent, audit=audit, target=target)
