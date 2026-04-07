"""Google ADK plugin for Signet.

Signs every tool call with the agent's Ed25519 key.

Usage:
    from signet_auth import SigningAgent
    from signet_auth.google_adk import SignetPlugin

    agent = SigningAgent("my-bot")
    plugin = SignetPlugin(agent)

    runner = Runner(plugins=[plugin])
"""

from __future__ import annotations

import json
import logging
from typing import Any

from signet_auth._signet import Receipt, SignetError
from signet_auth.agent import SigningAgent

logger = logging.getLogger("signet_auth.google_adk")


class SignetPlugin:
    """Google ADK plugin that signs tool calls with Signet.

    Works in observe mode (returns None) — does not modify tool behavior.
    """

    def __init__(
        self, agent: SigningAgent, *, audit: bool = True, target: str = ""
    ) -> None:
        self.agent = agent
        self.audit = audit
        self.target = target
        self.receipts: list[Receipt] = []

    def before_tool_callback(self, tool_call: Any) -> None:
        tool_name = getattr(tool_call, "name", str(tool_call))
        args = getattr(tool_call, "args", {})
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except (json.JSONDecodeError, TypeError):
                args = {"raw": args}
        try:
            receipt = self.agent.sign(
                tool_name,
                params=args,
                target=self.target or "google-adk://local",
                audit=self.audit,
            )
            self.receipts.append(receipt)
            logger.debug("Signed tool call: %s (receipt: %s)", tool_name, receipt.id)
        except (SignetError, RuntimeError):
            logger.warning("Failed to sign tool call: %s", tool_name, exc_info=True)
        return None  # Observe mode

    def after_tool_callback(self, tool_result: Any) -> None:
        return None  # Observe mode
