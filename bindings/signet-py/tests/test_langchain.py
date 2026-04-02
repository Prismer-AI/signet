"""Tests for SignetCallbackHandler and AsyncSignetCallbackHandler."""

import json
import tempfile
from uuid import uuid4

import pytest
import signet_auth

pytest.importorskip("langchain_core")

from signet_auth.langchain import AsyncSignetCallbackHandler, SignetCallbackHandler  # noqa: E402


@pytest.fixture
def agent():
    with tempfile.TemporaryDirectory() as tmpdir:
        a = signet_auth.SigningAgent.create("test-agent", owner="tester", signet_dir=tmpdir)
        yield a


# --- Sync handler tests ---


def test_handler_signs_tool_call(agent):
    handler = SignetCallbackHandler(agent)
    handler.on_tool_start(
        serialized={"name": "search_web"},
        input_str=json.dumps({"query": "signet crypto"}),
    )
    assert len(handler.receipts) == 1
    assert handler.receipts[0].action.tool == "search_web"
    assert handler.receipts[0].signer.name == "test-agent"
    assert handler.receipts[0].sig.startswith("ed25519:")


def test_handler_signs_multiple_tools(agent):
    handler = SignetCallbackHandler(agent)
    for tool in ["search", "calculate", "write_file"]:
        handler.on_tool_start(serialized={"name": tool}, input_str="{}")
    assert len(handler.receipts) == 3
    assert [r.action.tool for r in handler.receipts] == ["search", "calculate", "write_file"]


def test_handler_handles_plain_string_input(agent):
    handler = SignetCallbackHandler(agent)
    handler.on_tool_start(
        serialized={"name": "echo"},
        input_str="just a plain string, not json",
    )
    assert len(handler.receipts) == 1


def test_handler_handles_missing_tool_name(agent):
    handler = SignetCallbackHandler(agent)
    handler.on_tool_start(serialized={}, input_str="{}")
    assert len(handler.receipts) == 1
    assert handler.receipts[0].action.tool == "unknown"


def test_handler_receipts_are_verifiable(agent):
    handler = SignetCallbackHandler(agent)
    handler.on_tool_start(
        serialized={"name": "test_tool"},
        input_str=json.dumps({"key": "value"}),
    )
    assert agent.verify(handler.receipts[0]) is True


def test_handler_with_audit_false(agent):
    handler = SignetCallbackHandler(agent, audit=False)
    handler.on_tool_start(serialized={"name": "test"}, input_str="{}")
    assert len(handler.receipts) == 1
    assert len(agent.audit_query()) == 0


def test_handler_with_target(agent):
    handler = SignetCallbackHandler(agent, target="langchain://my-chain")
    handler.on_tool_start(serialized={"name": "test"}, input_str="{}")
    assert handler.receipts[0].action.target == "langchain://my-chain"


def test_handler_with_closed_agent(agent):
    handler = SignetCallbackHandler(agent)
    agent.close()
    with pytest.raises(RuntimeError, match="closed"):
        handler.on_tool_start(serialized={"name": "test"}, input_str="{}")
    assert len(handler.receipts) == 0


def test_handler_on_tool_end(agent):
    handler = SignetCallbackHandler(agent)
    handler.on_tool_start(serialized={"name": "search"}, input_str=json.dumps({"query": "test"}))
    handler.on_tool_end(output="search result: found 3 items")
    assert len(handler.receipts) == 2
    assert handler.receipts[0].action.tool == "search"
    assert handler.receipts[1].action.tool == "_tool_end"


def test_handler_on_tool_error(agent):
    handler = SignetCallbackHandler(agent)
    handler.on_tool_start(serialized={"name": "failing_tool"}, input_str="{}")
    handler.on_tool_error(error=ValueError("something broke"))
    assert len(handler.receipts) == 2
    assert handler.receipts[1].action.tool == "_tool_error"


def test_handler_end_output_is_hashed(agent):
    handler = SignetCallbackHandler(agent, audit=False)
    handler.on_tool_end(output="sensitive output data")
    assert len(handler.receipts) == 1
    assert "sensitive output data" not in str(handler.receipts[0].action.params)


# --- run_id correlation ---


def test_handler_run_id_links_start_end(agent):
    handler = SignetCallbackHandler(agent, audit=False)
    rid = uuid4()
    handler.on_tool_start(serialized={"name": "tool_a"}, input_str="{}", run_id=rid)
    handler.on_tool_end(output="ok", run_id=rid)
    assert len(handler.receipts) == 2
    # Both receipts should reference the same run_id in their params
    start_params = handler.receipts[0].action.params
    end_params = handler.receipts[1].action.params
    assert str(rid) in json.dumps(start_params, default=str)
    assert str(rid) in json.dumps(end_params, default=str)


def test_handler_run_id_links_start_error(agent):
    handler = SignetCallbackHandler(agent, audit=False)
    rid = uuid4()
    handler.on_tool_start(serialized={"name": "tool_b"}, input_str="{}", run_id=rid)
    handler.on_tool_error(error=RuntimeError("boom"), run_id=rid)
    assert len(handler.receipts) == 2
    error_params = handler.receipts[1].action.params
    assert str(rid) in json.dumps(error_params, default=str)


# --- inputs param (newer LangChain) ---


def test_handler_prefers_inputs_over_input_str(agent):
    handler = SignetCallbackHandler(agent, audit=False)
    handler.on_tool_start(
        serialized={"name": "structured_tool"},
        input_str="this should be ignored",
        inputs={"structured": True, "key": "value"},
    )
    assert len(handler.receipts) == 1
    params = handler.receipts[0].action.params
    params_str = json.dumps(params, default=str)
    assert "structured" in params_str
    assert "this should be ignored" not in params_str


# --- dict/object output (not just string) ---


def test_handler_end_with_dict_output(agent):
    handler = SignetCallbackHandler(agent, audit=False)
    handler.on_tool_end(output={"result": [1, 2, 3], "status": "ok"})
    assert len(handler.receipts) == 1


def test_handler_end_with_non_serializable_output(agent):
    handler = SignetCallbackHandler(agent, audit=False)
    handler.on_tool_end(output=object())  # not JSON serializable normally
    assert len(handler.receipts) == 1  # _hash_output uses default=str fallback


# --- Async handler tests ---


@pytest.mark.asyncio
async def test_async_handler_signs_tool_call(agent):
    handler = AsyncSignetCallbackHandler(agent, audit=False)
    await handler.on_tool_start(serialized={"name": "async_tool"}, input_str="{}")
    assert len(handler.receipts) == 1
    assert handler.receipts[0].action.tool == "async_tool"


@pytest.mark.asyncio
async def test_async_handler_full_lifecycle(agent):
    handler = AsyncSignetCallbackHandler(agent, audit=False)
    rid = uuid4()
    await handler.on_tool_start(serialized={"name": "async_search"}, input_str="{}", run_id=rid)
    await handler.on_tool_end(output="found it", run_id=rid)
    assert len(handler.receipts) == 2
    assert handler.receipts[0].action.tool == "async_search"
    assert handler.receipts[1].action.tool == "_tool_end"


@pytest.mark.asyncio
async def test_async_handler_error(agent):
    handler = AsyncSignetCallbackHandler(agent, audit=False)
    await handler.on_tool_start(serialized={"name": "bad_tool"}, input_str="{}")
    await handler.on_tool_error(error=ValueError("async failure"))
    assert len(handler.receipts) == 2
    assert handler.receipts[1].action.tool == "_tool_error"
