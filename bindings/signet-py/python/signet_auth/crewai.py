"""CrewAI tool call hooks for Signet.

Signs every tool call with the agent's Ed25519 key and appends
to the hash-chained audit log. Tracks the full lifecycle:
before_tool_call → after_tool_call.

Usage:
    from signet_auth import SigningAgent
    from signet_auth.crewai import install_hooks, uninstall_hooks

    agent = SigningAgent("my-bot")
    install_hooks(agent)

    # All CrewAI tool calls are now signed.
    crew.kickoff()

    # When done:
    uninstall_hooks()
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

from signet_auth._signet import Receipt, SignetError
from signet_auth.agent import SigningAgent

logger = logging.getLogger("signet_auth.crewai")

try:
    from crewai.hooks import tool_hooks
    from crewai.hooks.tool_hooks import ToolCallHookContext
except ImportError as e:
    raise ImportError(
        "crewai is required for Signet CrewAI hooks. "
        "Install it with: pip install signet-auth[crewai]"
    ) from e


def _hash_output(output: Any) -> str:
    """SHA-256 hash of tool output."""
    raw = output if isinstance(output, str) else json.dumps(output, default=str)
    return f"sha256:{hashlib.sha256(raw.encode()).hexdigest()}"


# Module-level state for installed hooks
_installed_agent: SigningAgent | None = None
_installed_target: str = ""
_installed_audit: bool = True
_receipts: list[Receipt] = []


def _before_hook(context: ToolCallHookContext) -> bool | None:
    """Sign tool call before execution."""
    if _installed_agent is None:
        return None

    try:
        receipt = _installed_agent.sign(
            context.tool_name,
            params=context.tool_input,
            target=_installed_target,
            audit=_installed_audit,
        )
        _receipts.append(receipt)

        # Stash receipt ID in tool_input for after_hook correlation
        context.tool_input["_signet_receipt_id"] = receipt.id

        logger.debug("Signed tool start: %s (receipt: %s)", context.tool_name, receipt.id)
    except SignetError:
        logger.warning("Failed to sign tool start: %s", context.tool_name, exc_info=True)

    return None  # allow execution


def _after_hook(context: ToolCallHookContext) -> str | None:
    """Sign tool result after execution."""
    if _installed_agent is None:
        return None

    receipt_id = context.tool_input.get("_signet_receipt_id", "")

    try:
        receipt = _installed_agent.sign(
            "_tool_end",
            params={
                "tool": context.tool_name,
                "output_hash": _hash_output(context.tool_result),
                "start_receipt_id": receipt_id,
            },
            target=_installed_target,
            audit=_installed_audit,
        )
        _receipts.append(receipt)
        logger.debug("Signed tool end: %s (receipt: %s)", context.tool_name, receipt.id)
    except SignetError:
        logger.warning("Failed to sign tool end: %s", context.tool_name, exc_info=True)

    return None  # keep original result


def install_hooks(
    agent: SigningAgent,
    *,
    audit: bool = True,
    target: str = "",
) -> None:
    """Install Signet signing hooks into CrewAI.

    After calling this, every tool call in any CrewAI crew will be
    signed with the given agent's key.

    Args:
        agent: A SigningAgent with a loaded key.
        audit: If True (default), append receipts to audit log.
        target: Optional target URI for receipts.
    """
    global _installed_agent, _installed_target, _installed_audit
    _installed_agent = agent
    _installed_target = target
    _installed_audit = audit
    _receipts.clear()

    tool_hooks.register_before_tool_call_hook(_before_hook)
    tool_hooks.register_after_tool_call_hook(_after_hook)

    logger.info("Signet hooks installed for agent '%s'", agent.name)


def uninstall_hooks() -> None:
    """Remove Signet hooks from CrewAI."""
    global _installed_agent
    _installed_agent = None

    tool_hooks.unregister_before_tool_call_hook(_before_hook)
    tool_hooks.unregister_after_tool_call_hook(_after_hook)

    logger.info("Signet hooks uninstalled")


def get_receipts() -> list[Receipt]:
    """Return all receipts collected since hooks were installed."""
    return list(_receipts)
