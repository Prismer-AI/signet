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

Design notes:
- Uses module-level global state because CrewAI hooks are global (register/unregister).
- Thread safety via threading.Lock on all mutable state.
- Correlation between before/after hooks uses id(context) as key instead of
  mutating tool_input (avoids breaking tools with strict input validation).
- CrewAI does not provide a run_id equivalent, unlike LangChain.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
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


# Module-level state (protected by _lock)
_lock = threading.Lock()
_installed_agent: SigningAgent | None = None
_installed_target: str = ""
_installed_audit: bool = True
_receipts: list[Receipt] = []
_pending_receipt_ids: dict[int, str] = {}  # id(context) → receipt_id for correlation


def _before_hook(context: ToolCallHookContext) -> bool | None:
    """Sign tool call before execution. Returns None to allow execution."""
    with _lock:
        agent = _installed_agent
        target = _installed_target
        audit = _installed_audit

    if agent is None:
        return None  # hooks uninstalled, allow execution

    try:
        receipt = agent.sign(
            context.tool_name,
            params=context.tool_input,
            target=target,
            audit=audit,
        )
        with _lock:
            _receipts.append(receipt)
            _pending_receipt_ids[id(context)] = receipt.id

        logger.debug("Signed tool start: %s (receipt: %s)", context.tool_name, receipt.id)
    except SignetError:
        logger.warning("Failed to sign tool start: %s", context.tool_name, exc_info=True)

    return None  # allow execution


def _after_hook(context: ToolCallHookContext) -> str | None:
    """Sign tool result after execution. Returns None to keep original result."""
    with _lock:
        agent = _installed_agent
        target = _installed_target
        audit = _installed_audit
        start_receipt_id = _pending_receipt_ids.pop(id(context), "")

    if agent is None:
        return None

    try:
        receipt = agent.sign(
            "_tool_end",
            params={
                "tool": context.tool_name,
                "output_hash": _hash_output(context.tool_result),
                "start_receipt_id": start_receipt_id,
            },
            target=target,
            audit=audit,
        )
        with _lock:
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

    Safe to call multiple times — previous hooks are unregistered first.

    Args:
        agent: A SigningAgent with a loaded key.
        audit: If True (default), append receipts to audit log.
        target: Optional target URI for receipts.
    """
    global _installed_agent, _installed_target, _installed_audit

    # Guard against double registration
    with _lock:
        if _installed_agent is not None:
            # Unregister previous hooks before re-registering
            tool_hooks.unregister_before_tool_call_hook(_before_hook)
            tool_hooks.unregister_after_tool_call_hook(_after_hook)
            _do_uninstall()

        _installed_agent = agent
        _installed_target = target
        _installed_audit = audit
        _receipts.clear()
        _pending_receipt_ids.clear()

    tool_hooks.register_before_tool_call_hook(_before_hook)
    tool_hooks.register_after_tool_call_hook(_after_hook)

    logger.info("Signet hooks installed for agent '%s'", agent.name)


def _do_uninstall() -> None:
    """Internal uninstall (caller must hold _lock)."""
    global _installed_agent, _installed_target, _installed_audit
    _installed_agent = None
    _installed_target = ""
    _installed_audit = True
    _pending_receipt_ids.clear()


def uninstall_hooks() -> None:
    """Remove Signet hooks from CrewAI.

    Receipts collected before uninstall are preserved and accessible
    via get_receipts().
    """
    with _lock:
        _do_uninstall()

    tool_hooks.unregister_before_tool_call_hook(_before_hook)
    tool_hooks.unregister_after_tool_call_hook(_after_hook)

    logger.info("Signet hooks uninstalled")


def get_receipts() -> list[Receipt]:
    """Return all receipts collected since hooks were installed.

    Receipts persist after uninstall_hooks() so you can retrieve them
    after a crew run completes.
    """
    with _lock:
        return list(_receipts)
