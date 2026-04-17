"""Decorator API for Signet — sign function calls with @signet_sign.

Usage:
    from signet_auth import SigningAgent
    from signet_auth.decorator import signet_sign

    agent = SigningAgent.create("my-agent")

    @signet_sign(agent)
    def call_api(url: str, payload: dict) -> dict:
        return requests.post(url, json=payload).json()

    result = call_api("https://api.example.com", {"key": "value"})
    # The call is signed automatically. Receipt in agent.receipts[-1].

    # Or with a default global agent:
    from signet_auth.decorator import init, sign

    init("my-agent")  # creates/loads agent globally

    @sign
    def fetch_data(query: str) -> list:
        return db.query(query)
"""

from __future__ import annotations

import functools
import inspect
import json
import logging
from typing import Any, Callable, Optional, TypeVar, overload

from signet_auth.agent import SigningAgent

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])

# Global default agent for @sign decorator (set via init())
_default_agent: Optional[SigningAgent] = None


def init(key_name: str = "signet-agent", owner: str = "") -> SigningAgent:
    """Initialize a global SigningAgent for the @sign decorator.

    Args:
        key_name: Identity name. Auto-created if it doesn't exist.
        owner: Optional owner label.

    Returns:
        The SigningAgent instance.
    """
    global _default_agent
    try:
        _default_agent = SigningAgent(key_name)
    except Exception:
        _default_agent = SigningAgent.create(key_name, owner=owner)
    return _default_agent


def _get_agent(agent: Optional[SigningAgent]) -> SigningAgent:
    if agent is not None:
        return agent
    if _default_agent is not None:
        return _default_agent
    raise RuntimeError(
        "No SigningAgent provided. Either pass an agent to @signet_sign(agent) "
        "or call signet_auth.decorator.init('my-agent') first."
    )


def _serialize_args(func: Callable, args: tuple, kwargs: dict) -> dict:
    """Convert function arguments to a JSON-serializable dict."""
    sig = inspect.signature(func)
    bound = sig.bind(*args, **kwargs)
    bound.apply_defaults()
    params = {}
    for k, v in bound.arguments.items():
        try:
            json.dumps(v)
            params[k] = v
        except (TypeError, ValueError):
            params[k] = repr(v)
    return params


@overload
def signet_sign(func: F) -> F: ...

@overload
def signet_sign(
    agent: Optional[SigningAgent] = None,
    *,
    tool_name: Optional[str] = None,
    audit: bool = True,
) -> Callable[[F], F]: ...

def signet_sign(
    func_or_agent=None,
    *,
    tool_name: Optional[str] = None,
    audit: bool = True,
):
    """Decorator that signs every call to the wrapped function.

    Can be used in three ways:

        @signet_sign              # uses global agent, function name as tool
        def my_func(): ...

        @signet_sign(agent)       # uses specific agent
        def my_func(): ...

        @signet_sign(agent, tool_name="custom_name")
        def my_func(): ...
    """
    # Case 1: @signet_sign (no args, func_or_agent is the function)
    if callable(func_or_agent) and not isinstance(func_or_agent, SigningAgent):
        func = func_or_agent
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            ag = _get_agent(None)
            params = _serialize_args(func, args, kwargs)
            try:
                ag.sign(func.__name__, params=params, audit=audit)
            except Exception:
                logger.warning("signet: failed to sign %s", func.__name__, exc_info=True)
            return func(*args, **kwargs)
        return wrapper

    # Case 2: @signet_sign(agent) or @signet_sign(agent, tool_name="x")
    agent = func_or_agent if isinstance(func_or_agent, SigningAgent) else None

    def decorator(func: F) -> F:
        name = tool_name or func.__name__

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            ag = _get_agent(agent)
            params = _serialize_args(func, args, kwargs)
            try:
                ag.sign(name, params=params, audit=audit)
            except Exception:
                logger.warning("signet: failed to sign %s", name, exc_info=True)
            return func(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorator


# Convenience alias: @sign uses the global agent
sign = signet_sign
