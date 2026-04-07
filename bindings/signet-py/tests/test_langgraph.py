"""Tests for LangGraph integration (re-export of LangChain callbacks)."""

import pytest

pytest.importorskip("langchain_core")


def test_langgraph_reexports():
    from signet_auth.langgraph import SignetCallbackHandler, AsyncSignetCallbackHandler
    from signet_auth.langchain import (
        SignetCallbackHandler as LCHandler,
        AsyncSignetCallbackHandler as LCAsyncHandler,
    )

    assert SignetCallbackHandler is LCHandler
    assert AsyncSignetCallbackHandler is LCAsyncHandler


def test_langgraph_handler_works(tmp_path):
    """Verify the re-exported handler actually signs."""
    import signet_auth
    from signet_auth.langgraph import SignetCallbackHandler

    agent = signet_auth.SigningAgent.create(
        "test-lg", owner="tester", signet_dir=str(tmp_path)
    )
    handler = SignetCallbackHandler(agent)
    handler.on_tool_start(serialized={"name": "search"}, input_str='{"q": "test"}')
    assert len(handler.receipts) == 1
    assert handler.receipts[0].action.tool == "search"
