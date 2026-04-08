"""Tests for Pydantic AI integration (middleware-based)."""

import tempfile

import pytest

import signet_auth
from signet_auth.pydantic_ai_integration import SignetMiddleware


@pytest.fixture
def agent():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield signet_auth.SigningAgent.create(
            "test-pydantic", owner="tester", signet_dir=tmpdir
        )


def test_middleware_wraps_sync_function(agent):
    mw = SignetMiddleware(agent)

    @mw.wrap
    def calculator(expression: str = "") -> str:
        return f"result: {expression}"

    result = calculator(expression="2+2")
    assert result == "result: 2+2"
    assert len(mw.receipts) == 1
    assert mw.receipts[0].action.tool == "calculator"


@pytest.mark.asyncio
async def test_middleware_wraps_async_function(agent):
    mw = SignetMiddleware(agent)

    @mw.wrap_async
    async def search(query: str = "") -> str:
        return f"found: {query}"

    result = await search(query="signet")
    assert result == "found: signet"
    assert len(mw.receipts) == 1
    assert mw.receipts[0].action.tool == "search"


def test_middleware_multiple_calls(agent):
    mw = SignetMiddleware(agent)

    @mw.wrap
    def tool_a(x: int = 0) -> int:
        return x + 1

    @mw.wrap
    def tool_b(y: str = "") -> str:
        return y.upper()

    tool_a(x=1)
    tool_b(y="hello")
    tool_a(x=2)

    assert len(mw.receipts) == 3
    assert [r.action.tool for r in mw.receipts] == ["tool_a", "tool_b", "tool_a"]


def test_middleware_preserves_function_name(agent):
    mw = SignetMiddleware(agent)

    @mw.wrap
    def my_special_tool() -> str:
        return "ok"

    assert my_special_tool.__name__ == "my_special_tool"


def test_middleware_positional_args(agent):
    mw = SignetMiddleware(agent)

    @mw.wrap
    def calculator(expression: str) -> str:
        return f"result: {expression}"

    result = calculator("2+2")
    assert result == "result: 2+2"
    assert len(mw.receipts) == 1
    assert mw.receipts[0].action.tool == "calculator"


def test_middleware_mixed_args(agent):
    mw = SignetMiddleware(agent)

    @mw.wrap
    def search(query: str, limit: int = 10) -> str:
        return f"{query}:{limit}"

    result = search("signet", limit=5)
    assert result == "signet:5"
    assert len(mw.receipts) == 1


def test_middleware_no_args(agent):
    mw = SignetMiddleware(agent)

    @mw.wrap
    def ping() -> str:
        return "pong"

    result = ping()
    assert result == "pong"
    assert len(mw.receipts) == 1


def test_middleware_signing_failure_still_executes(agent):
    mw = SignetMiddleware(agent)
    agent.close()  # signing will fail

    @mw.wrap
    def my_tool() -> str:
        return "executed"

    result = my_tool()
    assert result == "executed"
    assert len(mw.receipts) == 0  # no receipt due to closed agent
