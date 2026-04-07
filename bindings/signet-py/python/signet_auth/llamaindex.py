"""LlamaIndex event handler for Signet.

Usage:
    from signet_auth import SigningAgent
    from signet_auth.llamaindex import SignetEventHandler, install_handler

    agent = SigningAgent("my-bot")
    install_handler(agent)

    # All LlamaIndex tool calls are now signed.
"""

from __future__ import annotations

import logging
from typing import Any

from signet_auth._signet import Receipt, SignetError
from signet_auth.agent import SigningAgent

logger = logging.getLogger("signet_auth.llamaindex")

try:
    from llama_index.core.instrumentation import get_dispatcher
    from llama_index.core.instrumentation.event_handlers import BaseEventHandler
    from llama_index.core.instrumentation.events import BaseEvent
except ImportError as e:
    raise ImportError(
        "llama-index-core is required for Signet LlamaIndex integration. "
        "Install it with: pip install signet-auth[llamaindex]"
    ) from e


class SignetEventHandler(BaseEventHandler):
    """LlamaIndex event handler that signs tool call events."""

    def __init__(
        self, agent: SigningAgent, *, audit: bool = True, target: str = ""
    ) -> None:
        super().__init__()
        self.agent = agent
        self.audit = audit
        self.target = target
        self.receipts: list[Receipt] = []

    @classmethod
    def class_name(cls) -> str:
        return "SignetEventHandler"

    def handle(self, event: BaseEvent, **kwargs: Any) -> None:
        # Import here to avoid issues if the event class doesn't exist in older versions
        try:
            from llama_index.core.instrumentation.events.agent import AgentToolCallEvent
        except ImportError:
            return

        if not isinstance(event, AgentToolCallEvent):
            return

        try:
            params = event.arguments if hasattr(event, "arguments") else {}
            tool_name = (
                event.tool.name
                if hasattr(event, "tool")
                else getattr(event, "tool_name", "unknown")
            )
            receipt = self.agent.sign(
                tool_name,
                params=params,
                target=self.target or "llamaindex://local",
                audit=self.audit,
            )
            self.receipts.append(receipt)
            logger.debug("Signed tool call: %s (receipt: %s)", tool_name, receipt.id)
        except (SignetError, RuntimeError):
            logger.warning("Failed to sign tool call", exc_info=True)


def install_handler(
    agent: SigningAgent, *, audit: bool = True, target: str = ""
) -> SignetEventHandler:
    """Install a Signet event handler into LlamaIndex's dispatcher.

    Args:
        agent: A SigningAgent with a loaded key.
        audit: If True (default), append receipts to audit log.
        target: Optional target URI for receipts.

    Returns:
        The installed SignetEventHandler (access .receipts for collected receipts).
    """
    handler = SignetEventHandler(agent, audit=audit, target=target)
    dispatcher = get_dispatcher()
    dispatcher.add_event_handler(handler)
    logger.info("Signet event handler installed for agent '%s'", agent.name)
    return handler
