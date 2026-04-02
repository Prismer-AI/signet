"""LangChain callback handler for Signet.

Signs every tool call with the agent's Ed25519 key and appends
to the hash-chained audit log. Tracks the full lifecycle:
on_tool_start → on_tool_end / on_tool_error.

Usage:
    from signet_auth import SigningAgent
    from signet_auth.langchain import SignetCallbackHandler

    agent = SigningAgent("my-bot")
    handler = SignetCallbackHandler(agent)

    chain.invoke(input, config={"callbacks": [handler]})

For async chains:
    from signet_auth.langchain import AsyncSignetCallbackHandler

    handler = AsyncSignetCallbackHandler(agent)
    await chain.ainvoke(input, config={"callbacks": [handler]})
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any
from uuid import UUID

from signet_auth._signet import Receipt, SignetError
from signet_auth.agent import SigningAgent

logger = logging.getLogger("signet_auth.langchain")

try:
    from langchain_core.callbacks import AsyncCallbackHandler, BaseCallbackHandler
except ImportError as e:
    raise ImportError(
        "langchain-core is required for SignetCallbackHandler. "
        "Install it with: pip install signet-auth[langchain]"
    ) from e


def _hash_output(output: Any) -> str:
    """SHA-256 hash of tool output. Avoids storing potentially large output in audit log."""
    raw = output if isinstance(output, str) else json.dumps(output, default=str)
    return f"sha256:{hashlib.sha256(raw.encode()).hexdigest()}"


def _sign_tool_start(
    agent: SigningAgent,
    serialized: dict[str, Any],
    input_str: str,
    run_id: UUID | None,
    inputs: dict[str, Any] | None,
    target: str,
    audit: bool,
) -> Receipt:
    tool_name = serialized.get("name", "unknown")

    # Prefer structured inputs over raw input_str
    if inputs is not None:
        params = inputs
    else:
        try:
            params = json.loads(input_str) if isinstance(input_str, str) else input_str
        except (json.JSONDecodeError, TypeError):
            params = {"raw_input": input_str}

    receipt = agent.sign(
        tool_name,
        params={"args": params, "run_id": str(run_id)} if run_id else params,
        target=target,
        audit=audit,
    )
    logger.debug("Signed tool start: %s (receipt: %s, run_id: %s)", tool_name, receipt.id, run_id)
    return receipt


def _sign_tool_end(
    agent: SigningAgent,
    output: Any,
    run_id: UUID | None,
    target: str,
    audit: bool,
) -> Receipt:
    receipt = agent.sign(
        "_tool_end",
        params={"output_hash": _hash_output(output), "run_id": str(run_id)},
        target=target,
        audit=audit,
    )
    logger.debug("Signed tool end (run_id: %s)", run_id)
    return receipt


def _sign_tool_error(
    agent: SigningAgent,
    error: BaseException,
    run_id: UUID | None,
    target: str,
    audit: bool,
) -> Receipt:
    receipt = agent.sign(
        "_tool_error",
        params={"error": str(error), "error_type": type(error).__name__, "run_id": str(run_id)},
        target=target,
        audit=audit,
    )
    logger.debug("Signed tool error (run_id: %s)", run_id)
    return receipt


class SignetCallbackHandler(BaseCallbackHandler):
    """LangChain callback handler that signs every tool invocation.

    Each tool call produces an Ed25519-signed receipt that is appended
    to the local hash-chained audit log. The full lifecycle is tracked:
    start → end/error, linked by LangChain's run_id.

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
        run_id: UUID | None = None,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        inputs: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        try:
            receipt = _sign_tool_start(self.agent, serialized, input_str, run_id, inputs, self.target, self.audit)
            self.receipts.append(receipt)
        except SignetError:
            logger.warning("Failed to sign tool start: %s", serialized.get("name"), exc_info=True)

    def on_tool_end(
        self,
        output: Any,
        *,
        run_id: UUID | None = None,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        try:
            receipt = _sign_tool_end(self.agent, output, run_id, self.target, self.audit)
            self.receipts.append(receipt)
        except SignetError:
            logger.warning("Failed to sign tool end (run_id: %s)", run_id, exc_info=True)

    def on_tool_error(
        self,
        error: BaseException,
        *,
        run_id: UUID | None = None,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        try:
            receipt = _sign_tool_error(self.agent, error, run_id, self.target, self.audit)
            self.receipts.append(receipt)
        except SignetError:
            logger.warning("Failed to sign tool error (run_id: %s)", run_id, exc_info=True)


class AsyncSignetCallbackHandler(AsyncCallbackHandler):
    """Async version of SignetCallbackHandler for async LangChain chains.

    Same behavior as SignetCallbackHandler but compatible with ainvoke/astream.
    Note: signing itself is synchronous (Ed25519 sign is ~50μs), but this handler
    satisfies the AsyncCallbackHandler interface.
    """

    def __init__(
        self,
        agent: SigningAgent,
        *,
        audit: bool = True,
        target: str = "",
    ) -> None:
        super().__init__()
        self.agent = agent
        self.audit = audit
        self.target = target
        self.receipts: list[Receipt] = []

    async def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID | None = None,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        inputs: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        try:
            receipt = _sign_tool_start(self.agent, serialized, input_str, run_id, inputs, self.target, self.audit)
            self.receipts.append(receipt)
        except SignetError:
            logger.warning("Failed to sign tool start: %s", serialized.get("name"), exc_info=True)

    async def on_tool_end(
        self,
        output: Any,
        *,
        run_id: UUID | None = None,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        **kwargs: Any,
    ) -> None:
        try:
            receipt = _sign_tool_end(self.agent, output, run_id, self.target, self.audit)
            self.receipts.append(receipt)
        except SignetError:
            logger.warning("Failed to sign tool end (run_id: %s)", run_id, exc_info=True)

    async def on_tool_error(
        self,
        error: BaseException,
        *,
        run_id: UUID | None = None,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        **kwargs: Any,
    ) -> None:
        try:
            receipt = _sign_tool_error(self.agent, error, run_id, self.target, self.audit)
            self.receipts.append(receipt)
        except SignetError:
            logger.warning("Failed to sign tool error (run_id: %s)", run_id, exc_info=True)
