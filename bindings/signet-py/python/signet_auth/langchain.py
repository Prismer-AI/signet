"""LangChain callback handler for Signet.

Signs every tool call with the agent's Ed25519 key and appends
to the hash-chained audit log.

Usage:
    from signet_auth import SigningAgent
    from signet_auth.langchain import SignetCallbackHandler

    agent = SigningAgent("my-bot")
    handler = SignetCallbackHandler(agent)

    chain.invoke(input, config={"callbacks": [handler]})
"""

from __future__ import annotations

import json
import logging
from typing import Any

from signet_auth._signet import Receipt, SignetError
from signet_auth.agent import SigningAgent

logger = logging.getLogger("signet_auth.langchain")

try:
    from langchain_core.callbacks import BaseCallbackHandler
except ImportError as e:
    raise ImportError(
        "langchain-core is required for SignetCallbackHandler. "
        "Install it with: pip install signet-auth[langchain]"
    ) from e


class SignetCallbackHandler(BaseCallbackHandler):
    """LangChain callback handler that signs every tool invocation.

    Each tool call produces an Ed25519-signed receipt that is appended
    to the local hash-chained audit log.

    Attributes:
        agent: The SigningAgent instance used for signing.
        receipts: List of receipts produced during this handler's lifetime.
    """

    def __init__(
        self,
        agent: SigningAgent,
        *,
        audit: bool = True,
        target: str = "",
    ) -> None:
        """Initialize the handler.

        Args:
            agent: A SigningAgent with a loaded key.
            audit: If True (default), append receipts to audit log.
            target: Optional target URI for receipts (e.g. "langchain://my-chain").
        """
        super().__init__()
        self.agent = agent
        self.audit = audit
        self.target = target
        self.receipts: list[Receipt] = []

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: Any | None = None,
        **kwargs: Any,
    ) -> None:
        """Called when a tool starts. Signs the tool invocation."""
        tool_name = serialized.get("name", "unknown")

        # Parse input — could be JSON string or plain string
        try:
            params = json.loads(input_str) if isinstance(input_str, str) else input_str
        except (json.JSONDecodeError, TypeError):
            params = {"raw_input": input_str}

        try:
            receipt = self.agent.sign(
                tool_name,
                params=params,
                target=self.target,
                audit=self.audit,
            )
            self.receipts.append(receipt)
            logger.debug("Signed tool call: %s (receipt: %s, run_id: %s)", tool_name, receipt.id, run_id)
        except SignetError:
            logger.warning("Failed to sign tool call: %s", tool_name, exc_info=True)
