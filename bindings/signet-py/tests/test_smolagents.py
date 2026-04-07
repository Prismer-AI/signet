"""Tests for smolagents integration (mock-based)."""

import sys
import tempfile
import types

import pytest


# Create mock smolagents modules
def _setup_mocks():
    smolagents_mod = types.ModuleType("smolagents")
    memory_mod = types.ModuleType("smolagents.memory")

    class ActionStep:
        def __init__(self, tool_calls=None):
            self.tool_calls = tool_calls

    memory_mod.ActionStep = ActionStep
    smolagents_mod.memory = memory_mod

    sys.modules["smolagents"] = smolagents_mod
    sys.modules["smolagents.memory"] = memory_mod

    return ActionStep


_ActionStep = _setup_mocks()

import signet_auth  # noqa: E402
from signet_auth.smolagents import SignetStepCallback, signet_step_callback  # noqa: E402


@pytest.fixture
def agent():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield signet_auth.SigningAgent.create(
            "test-smol", owner="tester", signet_dir=tmpdir
        )


def test_callback_signs_tool_call(agent):
    cb = signet_step_callback(agent)
    step = _ActionStep(
        tool_calls=[{"tool_name": "web_search", "arguments": {"query": "test"}}]
    )
    cb(step)
    assert len(cb.receipts) == 1
    assert cb.receipts[0].action.tool == "web_search"


def test_callback_signs_multiple_tools(agent):
    cb = signet_step_callback(agent)
    step = _ActionStep(
        tool_calls=[
            {"tool_name": "search", "arguments": {"q": "a"}},
            {"tool_name": "read", "arguments": {"path": "/tmp"}},
        ]
    )
    cb(step)
    assert len(cb.receipts) == 2


def test_callback_ignores_non_action_step(agent):
    cb = signet_step_callback(agent)
    cb("not a step")
    assert len(cb.receipts) == 0


def test_callback_ignores_step_without_tool_calls(agent):
    cb = signet_step_callback(agent)
    step = _ActionStep(tool_calls=None)
    cb(step)
    assert len(cb.receipts) == 0


def test_callback_returns_signet_step_callback(agent):
    cb = signet_step_callback(agent)
    assert isinstance(cb, SignetStepCallback)
