"""Tests for OpenAI Agents SDK integration (mock-based)."""
import sys
import types
import tempfile
import pytest

# Mock agents module
def _setup_mocks():
    agents_mod = types.ModuleType("agents")

    class AgentHooks:
        def __init__(self):
            pass

    agents_mod.AgentHooks = AgentHooks
    sys.modules["agents"] = agents_mod
    return AgentHooks

_AgentHooks = _setup_mocks()

import signet_auth
from signet_auth.openai_agents import SignetAgentHooks


@pytest.fixture
def agent():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield signet_auth.SigningAgent.create("test-oai", owner="tester", signet_dir=tmpdir)


@pytest.mark.asyncio
async def test_hooks_sign_tool_start(agent):
    hooks = SignetAgentHooks(agent)

    class FakeTool:
        name = "web_search"

    await hooks.on_tool_start(None, None, FakeTool())
    assert len(hooks.receipts) == 1
    assert hooks.receipts[0].action.tool == "web_search"


@pytest.mark.asyncio
async def test_hooks_sign_tool_end(agent):
    hooks = SignetAgentHooks(agent)

    class FakeTool:
        name = "calculator"

    await hooks.on_tool_start(None, None, FakeTool())
    await hooks.on_tool_end(None, None, FakeTool())
    assert len(hooks.receipts) == 2
    assert hooks.receipts[1].action.tool == "_tool_end"


@pytest.mark.asyncio
async def test_hooks_sign_multiple_tools(agent):
    hooks = SignetAgentHooks(agent)
    for name in ["search", "write", "read"]:
        tool = type("T", (), {"name": name})()
        await hooks.on_tool_start(None, None, tool)
    assert len(hooks.receipts) == 3


def test_hooks_is_agent_hooks(agent):
    hooks = SignetAgentHooks(agent)
    assert isinstance(hooks, _AgentHooks)
