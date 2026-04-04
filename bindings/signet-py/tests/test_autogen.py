"""Tests for AutoGen integration."""

import asyncio
import tempfile

import signet_auth
from signet_auth.autogen import SignedFunctionTool, sign_tools, signed_tool


class MockTool:
    """Mock AutoGen FunctionTool for testing."""

    def __init__(
        self, name: str = "mock_tool", description: str = "A mock tool"
    ) -> None:
        self.name = name
        self.description = description

    async def run_json(self, args: dict, cancellation_token: object = None) -> dict:
        return {"result": f"executed {self.name} with {args}"}

    def return_value_as_string(self, value: object) -> str:
        return str(value)


def test_signed_tool_wraps_correctly() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        agent = signet_auth.SigningAgent.create("autogen-bot", signet_dir=tmpdir)
        tool = MockTool("search", "Search the web")
        wrapped = signed_tool(tool, agent)

        assert isinstance(wrapped, SignedFunctionTool)
        assert wrapped.name == "search"
        assert wrapped.description == "Search the web"


def test_signed_tool_signs_on_call() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        agent = signet_auth.SigningAgent.create("autogen-bot", signet_dir=tmpdir)
        tool = MockTool("search")
        wrapped = signed_tool(tool, agent)

        result = asyncio.get_event_loop().run_until_complete(
            wrapped.run_json({"query": "signet crypto"})
        )

        assert "executed" in str(result)

        # Check audit log has the receipt
        records = agent.audit_query()
        assert len(records) >= 1
        assert records[-1].receipt["action"]["tool"] == "search"


def test_signed_tool_forwards_result() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        agent = signet_auth.SigningAgent.create("autogen-bot", signet_dir=tmpdir)
        tool = MockTool("echo")
        wrapped = signed_tool(tool, agent)

        result = asyncio.get_event_loop().run_until_complete(
            wrapped.run_json({"message": "hello"})
        )

        assert result == {"result": "executed echo with {'message': 'hello'}"}


def test_sign_tools_wraps_multiple() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        agent = signet_auth.SigningAgent.create("autogen-bot", signet_dir=tmpdir)
        tools = [MockTool("tool_a"), MockTool("tool_b"), MockTool("tool_c")]
        wrapped = sign_tools(tools, agent)

        assert len(wrapped) == 3
        assert all(isinstance(t, SignedFunctionTool) for t in wrapped)
        assert [t.name for t in wrapped] == ["tool_a", "tool_b", "tool_c"]


def test_signed_tool_audit_chain() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        agent = signet_auth.SigningAgent.create("autogen-bot", signet_dir=tmpdir)
        tools = [MockTool("step_1"), MockTool("step_2")]
        wrapped = sign_tools(tools, agent)

        loop = asyncio.get_event_loop()
        loop.run_until_complete(wrapped[0].run_json({"data": "a"}))
        loop.run_until_complete(wrapped[1].run_json({"data": "b"}))

        chain = agent.audit_verify_chain()
        assert chain.valid
        assert chain.total_records == 2
