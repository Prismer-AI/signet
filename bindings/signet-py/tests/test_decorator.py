"""Tests for @signet_sign decorator API."""

import pytest
import signet_auth
from signet_auth.decorator import signet_sign, sign, init, _default_agent


def _get_or_create(name):
    """Get existing agent or create new one."""
    try:
        return signet_auth.SigningAgent(name)
    except signet_auth.KeyNotFoundError:
        return signet_auth.SigningAgent.create(name, owner="test")


def test_signet_sign_with_agent():
    agent = _get_or_create("dec-test-1")

    @signet_sign(agent)
    def my_tool(x: int, y: str) -> str:
        return f"{x}-{y}"

    result = my_tool(42, "hello")
    assert result == "42-hello"
    # Verify a receipt was written to audit
    records = agent.audit_query(since="1h")
    tool_names = [r.receipt.get("action", {}).get("tool") for r in records]
    assert "my_tool" in tool_names


def test_signet_sign_preserves_function_name():
    agent = _get_or_create("dec-test-2")

    @signet_sign(agent)
    def original_name():
        pass

    assert original_name.__name__ == "original_name"


def test_signet_sign_custom_tool_name():
    agent = _get_or_create("dec-test-3")

    @signet_sign(agent, tool_name="custom_tool")
    def my_func():
        return "ok"

    result = my_func()
    assert result == "ok"


def test_signet_sign_with_kwargs():
    agent = _get_or_create("dec-test-4")

    @signet_sign(agent)
    def search(query: str, limit: int = 10) -> dict:
        return {"query": query, "limit": limit}

    result = search("AI news", limit=5)
    assert result == {"query": "AI news", "limit": 5}


def test_sign_with_global_init():
    init("dec-test-global")

    @sign
    def global_tool(msg: str) -> str:
        return msg.upper()

    result = global_tool("hello")
    assert result == "HELLO"


def test_sign_without_init_raises():
    # Reset global agent
    import signet_auth.decorator as dec
    old = dec._default_agent
    dec._default_agent = None

    @sign
    def will_fail():
        pass

    with pytest.raises(RuntimeError, match="No SigningAgent"):
        will_fail()

    # Restore
    dec._default_agent = old


def test_signet_sign_no_args_decorator():
    """@signet_sign without parentheses uses global agent."""
    init("dec-test-bare")

    @signet_sign
    def bare_func(a: int) -> int:
        return a * 2

    assert bare_func(5) == 10
    assert bare_func.__name__ == "bare_func"


def test_decorator_handles_non_serializable_args():
    agent = _get_or_create("dec-test-serial")

    class Custom:
        pass

    @signet_sign(agent)
    def func_with_custom(obj: Custom) -> str:
        return "ok"

    # Should not raise — non-serializable args are repr()'d
    result = func_with_custom(Custom())
    assert result == "ok"
