"""AutoGen tool wrapper for Signet.

Signs every tool call with the agent's Ed25519 key and appends
to the hash-chained audit log. Wraps FunctionTool to intercept
calls transparently.

Note: AutoGen is not imported here. This module uses structural duck-typing
against FunctionTool's interface (name, description, run_json, return_value_as_string).
Install AutoGen separately: pip install autogen-agentchat

Usage:
    from signet_auth import SigningAgent
    from signet_auth.autogen import signed_tool, sign_tools

    agent = SigningAgent.create("my-bot")

    # Wrap a single tool
    tool = FunctionTool(my_func, description="...")
    wrapped = signed_tool(tool, agent)

    # Or wrap all tools at once
    wrapped_tools = sign_tools([tool1, tool2], agent)
"""

from __future__ import annotations

import logging
from typing import Any, Sequence

from signet_auth._signet import Receipt, SignetError
from signet_auth.agent import SigningAgent

logger = logging.getLogger("signet_auth.autogen")


class SignedFunctionTool:
    """Wraps an AutoGen FunctionTool to add Signet signing."""

    def __init__(self, tool: Any, agent: SigningAgent) -> None:
        """
        Args:
            tool: An AutoGen FunctionTool (or any object with name, description,
                  and run_json method).
            agent: A SigningAgent instance.
        """
        self._tool = tool
        self._agent = agent
        self.receipts: list[Receipt] = []
        # Forward tool attributes
        self.name = tool.name
        self.description = tool.description
        if hasattr(tool, "schema"):
            self.schema = tool.schema
        if hasattr(tool, "args_type"):
            self.args_type = tool.args_type

    async def run_json(
        self, args: dict[str, Any], cancellation_token: Any = None
    ) -> Any:
        """Run the tool with Signet signing before execution."""
        receipt = self._agent.sign(
            self.name,
            params=args,
            target="autogen://local",
        )
        self.receipts.append(receipt)

        # Always forward cancellation_token
        result = await self._tool.run_json(args, cancellation_token)
        return result

    def return_value_as_string(self, value: Any) -> str:
        """Forward to original tool."""
        if hasattr(self._tool, "return_value_as_string"):
            return self._tool.return_value_as_string(value)
        return str(value)

    def __getattr__(self, name: str) -> Any:
        """Forward unknown attributes to the wrapped tool."""
        tool = self.__dict__.get("_tool")
        if tool is None:
            raise AttributeError(name)
        return getattr(tool, name)


def signed_tool(tool: Any, agent: SigningAgent) -> SignedFunctionTool:
    """Wrap a single AutoGen FunctionTool with Signet signing.

    Args:
        tool: AutoGen FunctionTool.
        agent: SigningAgent instance.

    Returns:
        SignedFunctionTool that signs every call before execution.
    """
    return SignedFunctionTool(tool, agent)


def sign_tools(tools: Sequence[Any], agent: SigningAgent) -> list[SignedFunctionTool]:
    """Wrap multiple AutoGen tools with Signet signing.

    Args:
        tools: List of AutoGen FunctionTools.
        agent: SigningAgent instance.

    Returns:
        List of SignedFunctionTools.
    """
    return [SignedFunctionTool(t, agent) for t in tools]
