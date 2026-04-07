"""Tests for Pydantic AI integration (mock-based)."""

import sys
import types
import tempfile
import pytest


# Mock pydantic_ai
def _setup_mocks():
    pydantic_ai = types.ModuleType("pydantic_ai")

    class AbstractCapability:
        pass

    pydantic_ai.AbstractCapability = AbstractCapability
    sys.modules["pydantic_ai"] = pydantic_ai
    return AbstractCapability


_AbstractCapability = _setup_mocks()

import signet_auth  # noqa: E402
from signet_auth.pydantic_ai_integration import SignetCapability  # noqa: E402


@pytest.fixture
def agent():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield signet_auth.SigningAgent.create(
            "test-pydantic", owner="tester", signet_dir=tmpdir
        )


@pytest.mark.asyncio
async def test_capability_signs_tool_call(agent):
    cap = SignetCapability(agent)

    class FakeTool:
        name = "calculator"

    await cap.before_tool_execute(FakeTool(), {"expression": "2+2"})
    assert len(cap.receipts) == 1
    assert cap.receipts[0].action.tool == "calculator"


@pytest.mark.asyncio
async def test_capability_signs_multiple_calls(agent):
    cap = SignetCapability(agent)

    for name in ["search", "write", "read"]:
        tool = type("T", (), {"name": name})()
        await cap.before_tool_execute(tool, {"q": name})

    assert len(cap.receipts) == 3
    assert [r.action.tool for r in cap.receipts] == ["search", "write", "read"]


def test_capability_is_abstract_capability(agent):
    cap = SignetCapability(agent)
    assert isinstance(cap, _AbstractCapability)
