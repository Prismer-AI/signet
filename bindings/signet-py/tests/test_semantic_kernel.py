"""Tests for Semantic Kernel integration (mock-based)."""

import sys
import types
import tempfile
import pytest


# Mock semantic_kernel
def _setup_mocks():
    sk = types.ModuleType("semantic_kernel")
    filters = types.ModuleType("semantic_kernel.filters")
    functions = types.ModuleType("semantic_kernel.filters.functions")
    fic = types.ModuleType(
        "semantic_kernel.filters.functions.function_invocation_context"
    )

    class FilterTypes:
        FUNCTION_INVOCATION = "function_invocation"

    class FunctionInvocationContext:
        pass

    filters.FilterTypes = FilterTypes
    fic.FunctionInvocationContext = FunctionInvocationContext

    sys.modules["semantic_kernel"] = sk
    sys.modules["semantic_kernel.filters"] = filters
    sys.modules["semantic_kernel.filters.functions"] = functions
    sys.modules["semantic_kernel.filters.functions.function_invocation_context"] = fic

    return FunctionInvocationContext


_FunctionInvocationContext = _setup_mocks()

import signet_auth  # noqa: E402
from signet_auth.semantic_kernel import SignetFunctionFilter  # noqa: E402


@pytest.fixture
def agent():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield signet_auth.SigningAgent.create(
            "test-sk", owner="tester", signet_dir=tmpdir
        )


@pytest.mark.asyncio
async def test_filter_signs_function_call(agent):
    filt = SignetFunctionFilter(agent)

    class FakeFunction:
        name = "summarize"
        plugin_name = "TextPlugin"

    ctx = _FunctionInvocationContext()
    ctx.function = FakeFunction()
    ctx.arguments = {"text": "hello world"}

    called = []

    async def fake_next(c):
        called.append(True)

    await filt(ctx, fake_next)
    assert len(filt.receipts) == 1
    assert filt.receipts[0].action.tool == "TextPlugin.summarize"
    assert len(called) == 1  # next was called


@pytest.mark.asyncio
async def test_filter_handles_no_plugin_name(agent):
    filt = SignetFunctionFilter(agent)

    class FakeFunction:
        name = "my_tool"
        plugin_name = ""

    ctx = _FunctionInvocationContext()
    ctx.function = FakeFunction()
    ctx.arguments = {}

    async def fake_next(c):
        pass

    await filt(ctx, fake_next)
    assert filt.receipts[0].action.tool == "my_tool"


@pytest.mark.asyncio
async def test_filter_calls_next_even_on_sign_failure(agent):
    """Filter should always call next(), even if signing fails."""
    filt = SignetFunctionFilter(agent)
    filt.agent = None  # break signing

    class FakeFunction:
        name = "broken"
        plugin_name = ""

    ctx = _FunctionInvocationContext()
    ctx.function = FakeFunction()
    ctx.arguments = {}

    called = []

    async def fake_next(c):
        called.append(True)

    # Should not raise, should still call next
    await filt(ctx, fake_next)
    assert len(called) == 1
