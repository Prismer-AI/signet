"""Tests for @signet_sign decorator API."""

import asyncio

import pytest
import signet_auth
from signet_auth.decorator import (
    signet_sign,
    signet_tool,
    sign,
    init,
    _default_agent,
)


@pytest.fixture(autouse=True)
def _isolated_signet_home(tmp_path, monkeypatch):
    monkeypatch.setenv("SIGNET_HOME", str(tmp_path))


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


def test_signet_tool_target_transport_and_custom_name():
    agent = _get_or_create("dec-test-tool-v2")

    @signet_tool(
        agent,
        tool_name="refund_customer",
        target="payments://refund.prod",
        transport="https",
    )
    def refund(order_id: str, amount: int) -> str:
        return f"{order_id}:{amount}"

    result = refund("ord_123", 50)
    assert result == "ord_123:50"
    records = agent.audit_query(since="1h")
    matching = [
        r for r in records if r.receipt.get("action", {}).get("tool") == "refund_customer"
    ]
    assert matching, "expected a signed audit record for refund_customer"
    action = matching[-1].receipt["action"]
    assert action["target"] == "payments://refund.prod"
    assert action["transport"] == "https"


def test_signet_tool_audit_encrypt_params(tmp_path):
    agent = signet_auth.SigningAgent.create(
        "dec-test-encrypted",
        owner="test",
        signet_dir=str(tmp_path),
    )

    @signet_tool(agent=agent, audit_encrypt_params=True)
    def fetch_secret(secret: str) -> str:
        return secret.upper()

    result = fetch_secret("token-123")
    assert result == "TOKEN-123"

    raw = agent.audit_query(since="1h")
    assert raw, "expected encrypted audit record"
    action = raw[-1].receipt["action"]
    assert action.get("params") is None
    assert action.get("params_encrypted") is not None

    decrypted = agent.audit_query(since="1h", decrypt_params=True)
    assert decrypted[-1].receipt["action"]["params"]["secret"] == "token-123"


def test_signet_tool_warn_mode_returns_function_result_after_sign_failure(tmp_path):
    agent = signet_auth.SigningAgent.create(
        "dec-test-warn",
        owner="test",
        signet_dir=str(tmp_path),
    )
    agent.close()

    @signet_tool(agent=agent, on_sign_error="warn")
    def fragile_tool() -> str:
        return "ok"

    assert fragile_tool() == "ok"


def test_signet_tool_invalid_config_raises_at_decoration_time(tmp_path):
    agent = signet_auth.SigningAgent.create(
        "dec-test-invalid-config",
        owner="test",
        signet_dir=str(tmp_path),
    )

    with pytest.raises(ValueError, match="audit_encrypt_params requires audit=True"):

        @signet_tool(agent=agent, audit=False, audit_encrypt_params=True)
        def fragile_tool() -> str:
            return "ok"


def test_signet_tool_raise_mode_propagates_sign_failure(tmp_path):
    agent = signet_auth.SigningAgent.create(
        "dec-test-raise",
        owner="test",
        signet_dir=str(tmp_path),
    )
    agent.close()

    @signet_tool(agent=agent, on_sign_error="raise")
    def fragile_tool() -> str:
        return "ok"

    with pytest.raises(RuntimeError, match="SigningAgent has been closed"):
        fragile_tool()


def test_signet_tool_supports_async_functions(tmp_path):
    agent = signet_auth.SigningAgent.create(
        "dec-test-async",
        owner="test",
        signet_dir=str(tmp_path),
    )

    @signet_tool(agent=agent, target="mcp://async")
    async def async_tool(query: str) -> str:
        await asyncio.sleep(0)
        return query.upper()

    result = asyncio.run(async_tool("hello"))
    assert result == "HELLO"

    records = agent.audit_query(since="1h")
    tools = [r.receipt.get("action", {}).get("tool") for r in records]
    assert "async_tool" in tools


def test_top_level_sign_export_is_core_function():
    assert signet_auth.sign.__module__ == "signet_auth._signet"
    assert signet_auth.signet_tool.__module__ == "signet_auth.decorator"
