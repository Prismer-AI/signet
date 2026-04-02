"""Tests for SignetCallbackHandler (LangChain integration)."""

import json
import tempfile

import pytest
import signet_auth


# Skip all tests if langchain-core is not installed
pytest.importorskip("langchain_core")

from signet_auth.langchain import SignetCallbackHandler  # noqa: E402


@pytest.fixture
def agent():
    """Create a temporary SigningAgent for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        a = signet_auth.SigningAgent.create(
            "test-agent", owner="tester", signet_dir=tmpdir
        )
        yield a


def test_handler_signs_tool_call(agent):
    handler = SignetCallbackHandler(agent)
    handler.on_tool_start(
        serialized={"name": "search_web"},
        input_str=json.dumps({"query": "signet crypto"}),
    )
    assert len(handler.receipts) == 1
    receipt = handler.receipts[0]
    assert receipt.action.tool == "search_web"
    assert receipt.signer.name == "test-agent"
    assert receipt.sig.startswith("ed25519:")


def test_handler_signs_multiple_tools(agent):
    handler = SignetCallbackHandler(agent)
    for tool in ["search", "calculate", "write_file"]:
        handler.on_tool_start(
            serialized={"name": tool},
            input_str="{}",
        )
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
    handler.on_tool_start(
        serialized={},  # no "name" key
        input_str="{}",
    )
    assert len(handler.receipts) == 1
    assert handler.receipts[0].action.tool == "unknown"


def test_handler_receipts_are_verifiable(agent):
    handler = SignetCallbackHandler(agent)
    handler.on_tool_start(
        serialized={"name": "test_tool"},
        input_str=json.dumps({"key": "value"}),
    )
    receipt = handler.receipts[0]
    assert agent.verify(receipt) is True


def test_handler_with_audit_false(agent):
    handler = SignetCallbackHandler(agent, audit=False)
    handler.on_tool_start(
        serialized={"name": "test"},
        input_str="{}",
    )
    assert len(handler.receipts) == 1
    # No audit records should exist
    records = agent.audit_query()
    assert len(records) == 0


def test_handler_with_target(agent):
    handler = SignetCallbackHandler(agent, target="langchain://my-chain")
    handler.on_tool_start(
        serialized={"name": "test"},
        input_str="{}",
    )
    assert len(handler.receipts) == 1
    assert handler.receipts[0].action.target == "langchain://my-chain"


def test_handler_with_closed_agent(agent):
    handler = SignetCallbackHandler(agent)
    agent.close()
    # Signing fails (RuntimeError), but handler should not propagate it
    # RuntimeError is not a SignetError, so it WILL propagate
    import pytest

    with pytest.raises(RuntimeError, match="closed"):
        handler.on_tool_start(
            serialized={"name": "test"},
            input_str="{}",
        )
    assert len(handler.receipts) == 0


def test_handler_on_tool_end(agent):
    handler = SignetCallbackHandler(agent)
    handler.on_tool_start(
        serialized={"name": "search"},
        input_str=json.dumps({"query": "test"}),
    )
    handler.on_tool_end(output="search result: found 3 items")
    assert len(handler.receipts) == 2
    assert handler.receipts[0].action.tool == "search"
    assert handler.receipts[1].action.tool == "_tool_end"


def test_handler_on_tool_error(agent):
    handler = SignetCallbackHandler(agent)
    handler.on_tool_start(
        serialized={"name": "failing_tool"},
        input_str="{}",
    )
    handler.on_tool_error(error=ValueError("something broke"))
    assert len(handler.receipts) == 2
    assert handler.receipts[1].action.tool == "_tool_error"


def test_handler_end_output_is_hashed(agent):
    handler = SignetCallbackHandler(agent, audit=False)
    handler.on_tool_end(output="sensitive output data")
    assert len(handler.receipts) == 1
    # Output should be hashed, not stored raw
    receipt_json = handler.receipts[0].action.params
    # params contains output_hash, not the raw output
    assert "sensitive output data" not in str(receipt_json)
