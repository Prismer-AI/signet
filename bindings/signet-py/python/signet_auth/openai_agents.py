"""OpenAI Agents SDK hooks for Signet.

Signs tool call lifecycle events. Note: the OpenAI Agents SDK does not
currently expose tool call arguments in hooks (see GitHub issue #939).
Only the tool name is available for signing.

Usage:
    from signet_auth import SigningAgent
    from signet_auth.openai_agents import SignetAgentHooks

    agent = SigningAgent("my-bot")

    oai_agent = Agent(
        name="assistant",
        hooks=SignetAgentHooks(agent),
        tools=[...],
    )
"""
from __future__ import annotations

import logging
from typing import Any

from signet_auth._signet import Receipt, SignetError
from signet_auth.agent import SigningAgent

logger = logging.getLogger("signet_auth.openai_agents")

try:
    from agents import AgentHooks
except ImportError:
    try:
        from openai_agents import AgentHooks
    except ImportError as e:
        raise ImportError(
            "openai-agents is required for Signet OpenAI Agents integration. "
            "Install it with: pip install signet-auth[openai-agents]"
        ) from e


class SignetAgentHooks(AgentHooks):
    """OpenAI Agents SDK hooks that sign tool call events with Signet.

    Limitation: Tool call arguments are NOT available in the hook API
    (see https://github.com/openai/openai-agents-python/issues/939).
    Only the tool name is signed. This will be updated when the API
    adds argument access.
    """

    def __init__(self, agent: SigningAgent, *, audit: bool = True, target: str = "") -> None:
        super().__init__()
        self.agent = agent
        self.audit = audit
        self.target = target
        self.receipts: list[Receipt] = []

    async def on_tool_start(self, context: Any, agent: Any, tool: Any) -> None:
        tool_name = getattr(tool, "name", str(tool))
        try:
            receipt = self.agent.sign(
                tool_name,
                params={"_note": "arguments not available in hook API (issue #939)"},
                target=self.target or "openai-agents://local",
                audit=self.audit,
            )
            self.receipts.append(receipt)
            logger.debug("Signed tool start: %s (receipt: %s)", tool_name, receipt.id)
        except (SignetError, RuntimeError):
            logger.warning("Failed to sign tool start: %s", tool_name, exc_info=True)

    async def on_tool_end(self, context: Any, agent: Any, tool: Any) -> None:
        tool_name = getattr(tool, "name", str(tool))
        try:
            receipt = self.agent.sign(
                "_tool_end",
                params={"tool": tool_name, "_note": "result not available in hook API"},
                target=self.target or "openai-agents://local",
                audit=self.audit,
            )
            self.receipts.append(receipt)
            logger.debug("Signed tool end: %s (receipt: %s)", tool_name, receipt.id)
        except (SignetError, RuntimeError):
            logger.warning("Failed to sign tool end: %s", tool_name, exc_info=True)
