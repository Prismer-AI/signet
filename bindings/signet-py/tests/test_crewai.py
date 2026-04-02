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
    """Create a minimal ToolCallHookContext for testing."""
    # We need a mock tool object — use a simple object with required attrs
    class FakeTool:
        name = tool_name
    return ToolCallHookContext(
        tool_name=tool_name,
        tool_input=tool_input or {},
        tool=FakeTool(),  # type: ignore
    )


def test_install_and_sign(agent):
    install_hooks(agent, audit=False)
    # Simulate before hook
    ctx = _make_context("search_web", {"query": "test"})
    hooks = tool_hooks.get_before_tool_call_hooks()
    assert len(hooks) >= 1
    for hook in hooks:
        hook(ctx)
    receipts = get_receipts()
    assert len(receipts) == 1
    assert receipts[0].action.tool == "search_web"
    assert receipts[0].sig.startswith("ed25519:")


def test_before_and_after_hooks(agent):
    install_hooks(agent, audit=False)
    ctx = _make_context("calculator", {"expression": "2+2"})

    # Before hook
    for hook in tool_hooks.get_before_tool_call_hooks():
        hook(ctx)

    # Simulate tool execution
    ctx.tool_result = "4"

    # After hook
    for hook in tool_hooks.get_after_tool_call_hooks():
        hook(ctx)

    receipts = get_receipts()
    assert len(receipts) == 2
    assert receipts[0].action.tool == "calculator"
    assert receipts[1].action.tool == "_tool_end"


def test_receipt_id_correlation(agent):
    install_hooks(agent, audit=False)
    ctx = _make_context("my_tool", {"key": "value"})

    for hook in tool_hooks.get_before_tool_call_hooks():
        hook(ctx)

    # Before hook should stash receipt ID in tool_input
    assert "_signet_receipt_id" in ctx.tool_input
    stashed_id = ctx.tool_input["_signet_receipt_id"]
    assert stashed_id.startswith("rec_")


def test_uninstall_stops_signing(agent):
    install_hooks(agent, audit=False)
    uninstall_hooks()

    ctx = _make_context("should_not_sign")
    for hook in tool_hooks.get_before_tool_call_hooks():
        hook(ctx)

    assert len(get_receipts()) == 0


def test_receipts_are_verifiable(agent):
    install_hooks(agent, audit=False)
    ctx = _make_context("verified_tool", {"data": "test"})
    for hook in tool_hooks.get_before_tool_call_hooks():
        hook(ctx)

    receipt = get_receipts()[0]
    assert agent.verify(receipt) is True


def test_multiple_tool_calls(agent):
    install_hooks(agent, audit=False)
    for tool in ["search", "write", "deploy"]:
        ctx = _make_context(tool)
        for hook in tool_hooks.get_before_tool_call_hooks():
            hook(ctx)

    assert len(get_receipts()) == 3
    assert [r.action.tool for r in get_receipts()] == ["search", "write", "deploy"]


def test_with_target(agent):
    install_hooks(agent, audit=False, target="crewai://my-crew")
    ctx = _make_context("test")
    for hook in tool_hooks.get_before_tool_call_hooks():
        hook(ctx)

    assert get_receipts()[0].action.target == "crewai://my-crew"


def test_output_is_hashed(agent):
    install_hooks(agent, audit=False)
    ctx = _make_context("sensitive_tool")

    for hook in tool_hooks.get_before_tool_call_hooks():
        hook(ctx)

    ctx.tool_result = "secret output data"
    for hook in tool_hooks.get_after_tool_call_hooks():
        hook(ctx)

    end_receipt = get_receipts()[1]
    assert "secret output data" not in str(end_receipt.action.params)
