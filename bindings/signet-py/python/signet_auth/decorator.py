"""Decorator API for Signet — protect tool functions with lightweight decorators.

Usage:
    from signet_auth import SigningAgent
    from signet_auth.decorator import signet_tool

    agent = SigningAgent.create("my-agent")

    @signet_tool(agent=agent, target="https://api.example.com")
    def call_api(url: str, payload: dict) -> dict:
        return requests.post(url, json=payload).json()

    result = call_api("https://api.example.com", {"key": "value"})
    # The call is signed automatically and appended to audit.

    # Or with a default global agent:
    from signet_auth.decorator import init, signet_tool

    init("my-agent")  # creates/loads agent globally

    @signet_tool
    def fetch_data(query: str) -> list:
        return db.query(query)
"""

from __future__ import annotations

import functools
import inspect
import json
import logging
from typing import Any, Callable, Literal, Optional, TypeVar, overload

from signet_auth.agent import SigningAgent

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])
ParamsSerializer = Callable[[Callable[..., Any], tuple[Any, ...], dict[str, Any]], Any]
SignErrorMode = Literal["warn", "raise"]

# Global default agent for decorator-based tool signing (set via init())
_default_agent: Optional[SigningAgent] = None


def init(
    key_name: str = "signet-agent",
    owner: str = "",
    *,
    signet_dir: str | None = None,
    passphrase: str | None = None,
) -> SigningAgent:
    """Initialize a global SigningAgent for decorator-based tool signing.

    Args:
        key_name: Identity name. Auto-created if it doesn't exist.
        owner: Optional owner label.
        signet_dir: Optional Signet home override.
        passphrase: Optional passphrase for loading or creating the key.

    Returns:
        The SigningAgent instance.
    """
    global _default_agent
    try:
        _default_agent = SigningAgent(
            key_name,
            signet_dir=signet_dir,
            passphrase=passphrase,
        )
    except Exception:
        _default_agent = SigningAgent.create(
            key_name,
            owner=owner,
            signet_dir=signet_dir,
            passphrase=passphrase,
        )
    return _default_agent


def _get_agent(agent: Optional[SigningAgent]) -> SigningAgent:
    if agent is not None:
        return agent
    if _default_agent is not None:
        return _default_agent
    raise RuntimeError(
        "No SigningAgent provided. Either pass an agent to @signet_tool(agent) "
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


def _sign_call(
    agent: SigningAgent,
    *,
    name: str,
    params: Any,
    target: str,
    transport: str,
    audit: bool,
    audit_encrypt_params: bool,
    on_sign_error: SignErrorMode,
) -> None:
    try:
        agent.sign(
            name,
            params=params,
            target=target,
            transport=transport,
            audit=audit,
            audit_encrypt_params=audit_encrypt_params,
        )
    except Exception:
        if on_sign_error == "raise":
            raise
        logger.warning("signet: failed to sign %s", name, exc_info=True)


def _validate_decorator_config(
    *,
    audit: bool,
    audit_encrypt_params: bool,
    on_sign_error: str,
) -> None:
    if audit_encrypt_params and not audit:
        raise ValueError("audit_encrypt_params requires audit=True")
    if on_sign_error not in ("warn", "raise"):
        raise ValueError("on_sign_error must be 'warn' or 'raise'")


def _wrap_function(
    func: F,
    *,
    agent: Optional[SigningAgent],
    tool_name: Optional[str],
    target: str,
    transport: str,
    audit: bool,
    audit_encrypt_params: bool,
    on_sign_error: SignErrorMode,
    params_serializer: Optional[ParamsSerializer],
) -> F:
    name = tool_name or func.__name__
    serializer = params_serializer or _serialize_args

    if inspect.iscoroutinefunction(func):

        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            ag = _get_agent(agent)
            params = serializer(func, args, kwargs)
            _sign_call(
                ag,
                name=name,
                params=params,
                target=target,
                transport=transport,
                audit=audit,
                audit_encrypt_params=audit_encrypt_params,
                on_sign_error=on_sign_error,
            )
            return await func(*args, **kwargs)

        return async_wrapper  # type: ignore[return-value]

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        ag = _get_agent(agent)
        params = serializer(func, args, kwargs)
        _sign_call(
            ag,
            name=name,
            params=params,
            target=target,
            transport=transport,
            audit=audit,
            audit_encrypt_params=audit_encrypt_params,
            on_sign_error=on_sign_error,
        )
        return func(*args, **kwargs)

    return wrapper  # type: ignore[return-value]


@overload
def signet_tool(func: F) -> F: ...

@overload
def signet_tool(
    func_or_agent: Optional[SigningAgent] = None,
    *,
    agent: Optional[SigningAgent] = None,
    tool_name: Optional[str] = None,
    target: str = "",
    transport: str = "stdio",
    audit: bool = True,
    audit_encrypt_params: bool = False,
    on_sign_error: SignErrorMode = "warn",
    params_serializer: Optional[ParamsSerializer] = None,
) -> Callable[[F], F]: ...


def signet_tool(
    func_or_agent=None,
    *,
    agent: Optional[SigningAgent] = None,
    tool_name: Optional[str] = None,
    target: str = "",
    transport: str = "stdio",
    audit: bool = True,
    audit_encrypt_params: bool = False,
    on_sign_error: SignErrorMode = "warn",
    params_serializer: Optional[ParamsSerializer] = None,
):
    """Decorator that signs every call to the wrapped tool function.

    Can be used in three ways:

        @signet_tool              # uses global agent, function name as tool
        def my_func(): ...

        @signet_tool(agent)       # uses specific agent
        def my_func(): ...

        @signet_tool(
            agent=agent,
            tool_name="custom_name",
            target="mcp://github.prod",
            audit_encrypt_params=True,
        )
        def my_func(): ...
    """
    _validate_decorator_config(
        audit=audit,
        audit_encrypt_params=audit_encrypt_params,
        on_sign_error=on_sign_error,
    )

    # Case 1: @signet_sign (no args, func_or_agent is the function)
    if callable(func_or_agent) and not isinstance(func_or_agent, SigningAgent):
        func = func_or_agent
        return _wrap_function(
            func,
            agent=None,
            tool_name=tool_name,
            target=target,
            transport=transport,
            audit=audit,
            audit_encrypt_params=audit_encrypt_params,
            on_sign_error=on_sign_error,
            params_serializer=params_serializer,
        )

    if (
        func_or_agent is not None
        and isinstance(func_or_agent, SigningAgent)
        and agent is not None
        and func_or_agent is not agent
    ):
        raise TypeError("signet_tool() takes a positional agent or agent=..., not both")

    # Case 2: @signet_tool(agent) / @signet_tool(agent=agent)
    resolved_agent = (
        func_or_agent if isinstance(func_or_agent, SigningAgent) else agent
    )

    def decorator(func: F) -> F:
        return _wrap_function(
            func,
            agent=resolved_agent,
            tool_name=tool_name,
            target=target,
            transport=transport,
            audit=audit,
            audit_encrypt_params=audit_encrypt_params,
            on_sign_error=on_sign_error,
            params_serializer=params_serializer,
        )

    return decorator


# Backward-compatible name
signet_sign = signet_tool

# Convenience aliases
sign = signet_sign
protect_tool = signet_tool
