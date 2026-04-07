"""Tests for Google ADK integration (mock-based)."""

import tempfile
import pytest
import signet_auth
from signet_auth.google_adk import SignetPlugin


@pytest.fixture
def agent():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield signet_auth.SigningAgent.create(
            "test-adk", owner="tester", signet_dir=tmpdir
        )


def test_plugin_signs_tool_call(agent):
    plugin = SignetPlugin(agent)

    class FakeToolCall:
        name = "web_search"
        args = {"query": "signet"}

    result = plugin.before_tool_callback(FakeToolCall())
    assert result is None  # observe mode
    assert len(plugin.receipts) == 1
    assert plugin.receipts[0].action.tool == "web_search"


def test_plugin_signs_multiple_calls(agent):
    plugin = SignetPlugin(agent)
    for name in ["search", "calculate"]:
        tc = type("TC", (), {"name": name, "args": {"x": 1}})()
        plugin.before_tool_callback(tc)
    assert len(plugin.receipts) == 2


def test_after_callback_returns_none(agent):
    plugin = SignetPlugin(agent)
    assert plugin.after_tool_callback("some result") is None


def test_plugin_handles_string_args(agent):
    plugin = SignetPlugin(agent)
    tc = type("TC", (), {"name": "echo", "args": '{"msg": "hi"}'})()
    plugin.before_tool_callback(tc)
    assert len(plugin.receipts) == 1
