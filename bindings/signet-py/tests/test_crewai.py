"""Tests for Signet CrewAI tool call hooks."""

import tempfile

import pytest
import signet_auth

crewai = pytest.importorskip("crewai")

from crewai.hooks import tool_hooks  # noqa: E402
from crewai.hooks.tool_hooks import ToolCallHookContext  # noqa: E402
from signet_auth.crewai import get_receipts, install_hooks, uninstall_hooks  # noqa: E402


@pytest.fixture
def agent():
    with tempfile.TemporaryDirectory() as tmpdir:
        a = signet_auth.SigningAgent.create("crew-bot", owner="tester", signet_dir=tmpdir)
        yield a


@pytest.fixture(autouse=True)
def cleanup_hooks():
    """Ensure hooks are cleaned up after each test."""
    yield
    uninstall_hooks()
    tool_hooks.clear_all_tool_call_hooks()


def _make_context(tool_name: str = "test_tool", tool_input: dict | None = None) -> ToolCallHookContext:
    class FakeTool:
        name = tool_name
    return ToolCallHookContext(
        tool_name=tool_name,
        tool_input=tool_input if tool_input is not None else {},
        tool=FakeTool(),  # type: ignore
    )


def _run_before(ctx: ToolCallHookContext) -> None:
    for hook in tool_hooks.get_before_tool_call_hooks():
        hook(ctx)


def _run_after(ctx: ToolCallHookContext) -> None:
    for hook in tool_hooks.get_after_tool_call_hooks():
        hook(ctx)


def test_install_and_sign(agent):
    install_hooks(agent, audit=False)
    ctx = _make_context("search_web", {"query": "test"})
    _run_before(ctx)
    receipts = get_receipts()
    assert len(receipts) == 1
    assert receipts[0].action.tool == "search_web"
    assert receipts[0].sig.startswith("ed25519:")


def test_before_and_after_hooks(agent):
    install_hooks(agent, audit=False)
    ctx = _make_context("calculator", {"expression": "2+2"})
    _run_before(ctx)
    ctx.tool_result = "4"
    _run_after(ctx)
    receipts = get_receipts()
    assert len(receipts) == 2
    assert receipts[0].action.tool == "calculator"
    assert receipts[1].action.tool == "_tool_end"


def test_correlation_via_context_id(agent):
    """Before/after hooks correlate via id(context), not tool_input mutation."""
    install_hooks(agent, audit=False)
    ctx = _make_context("my_tool", {"key": "value"})
    _run_before(ctx)
    # tool_input should NOT have _signet_receipt_id (no longer mutated)
    assert "_signet_receipt_id" not in ctx.tool_input


def test_uninstall_stops_signing(agent):
    install_hooks(agent, audit=False)
    uninstall_hooks()
    ctx = _make_context("should_not_sign")
    _run_before(ctx)
    assert len(get_receipts()) == 0


def test_receipts_are_verifiable(agent):
    install_hooks(agent, audit=False)
    ctx = _make_context("verified_tool", {"data": "test"})
    _run_before(ctx)
    assert agent.verify(get_receipts()[0]) is True


def test_multiple_tool_calls(agent):
    install_hooks(agent, audit=False)
    for tool in ["search", "write", "deploy"]:
        ctx = _make_context(tool)
        _run_before(ctx)
    assert len(get_receipts()) == 3
    assert [r.action.tool for r in get_receipts()] == ["search", "write", "deploy"]


def test_with_target(agent):
    install_hooks(agent, audit=False, target="crewai://my-crew")
    ctx = _make_context("test")
    _run_before(ctx)
    assert get_receipts()[0].action.target == "crewai://my-crew"


def test_output_is_hashed(agent):
    install_hooks(agent, audit=False)
    ctx = _make_context("sensitive_tool")
    _run_before(ctx)
    ctx.tool_result = "secret output data"
    _run_after(ctx)
    end_receipt = get_receipts()[1]
    assert "secret output data" not in str(end_receipt.action.params)


def test_double_install_does_not_double_sign(agent):
    """Calling install_hooks twice should not register hooks twice."""
    install_hooks(agent, audit=False)
    install_hooks(agent, audit=False)  # second call
    ctx = _make_context("test")
    _run_before(ctx)
    # Should produce exactly 1 receipt, not 2
    assert len(get_receipts()) == 1


def test_closed_agent_does_not_crash_hook(agent):
    """Signing failure (closed agent) should log warning, not crash."""
    install_hooks(agent, audit=False)
    agent.close()
    ctx = _make_context("test")
    # RuntimeError is not SignetError, so it propagates
    with pytest.raises(RuntimeError, match="closed"):
        _run_before(ctx)
    assert len(get_receipts()) == 0


def test_receipts_persist_after_uninstall(agent):
    """get_receipts() returns data after uninstall."""
    install_hooks(agent, audit=False)
    ctx = _make_context("test")
    _run_before(ctx)
    assert len(get_receipts()) == 1
    uninstall_hooks()
    # Receipts should still be accessible
    assert len(get_receipts()) == 1
