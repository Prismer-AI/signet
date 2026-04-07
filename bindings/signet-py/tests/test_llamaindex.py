"""Tests for LlamaIndex integration (mock-based, no llama_index dependency)."""

import sys
import tempfile
import types

import pytest


# Create mock llama_index modules so we can test without installing llama_index
def _setup_mocks():
    """Set up mock llama_index modules."""
    core = types.ModuleType("llama_index.core")
    instrumentation = types.ModuleType("llama_index.core.instrumentation")
    event_handlers = types.ModuleType("llama_index.core.instrumentation.event_handlers")
    events = types.ModuleType("llama_index.core.instrumentation.events")
    agent_events = types.ModuleType("llama_index.core.instrumentation.events.agent")

    class BaseEvent:
        pass

    class BaseEventHandler:
        def __init__(self):
            pass

        @classmethod
        def class_name(cls):
            return cls.__name__

    class AgentToolCallEvent(BaseEvent):
        def __init__(self, tool_name, arguments):
            self.tool_name = tool_name
            self.arguments = arguments

    _handlers = []

    class MockDispatcher:
        def add_event_handler(self, handler):
            _handlers.append(handler)

    def get_dispatcher(*args, **kwargs):
        return MockDispatcher()

    event_handlers.BaseEventHandler = BaseEventHandler
    events.BaseEvent = BaseEvent
    agent_events.AgentToolCallEvent = AgentToolCallEvent
    instrumentation.get_dispatcher = get_dispatcher
    instrumentation.event_handlers = event_handlers
    instrumentation.events = events

    # Register in sys.modules
    for name, mod in [
        ("llama_index", types.ModuleType("llama_index")),
        ("llama_index.core", core),
        ("llama_index.core.instrumentation", instrumentation),
        ("llama_index.core.instrumentation.event_handlers", event_handlers),
        ("llama_index.core.instrumentation.events", events),
        ("llama_index.core.instrumentation.events.agent", agent_events),
    ]:
        sys.modules[name] = mod

    return AgentToolCallEvent, BaseEvent


_AgentToolCallEvent, _BaseEvent = _setup_mocks()


import signet_auth  # noqa: E402
from signet_auth.llamaindex import SignetEventHandler, install_handler  # noqa: E402


@pytest.fixture
def agent():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield signet_auth.SigningAgent.create(
            "test-llama", owner="tester", signet_dir=tmpdir
        )


def test_handler_signs_tool_call_event(agent):
    handler = SignetEventHandler(agent)
    event = _AgentToolCallEvent(tool_name="search", arguments={"query": "test"})
    handler.handle(event)
    assert len(handler.receipts) == 1
    assert handler.receipts[0].action.tool == "search"


def test_handler_ignores_non_tool_events(agent):
    handler = SignetEventHandler(agent)
    event = _BaseEvent()
    handler.handle(event)
    assert len(handler.receipts) == 0


def test_install_handler_returns_handler(agent):
    handler = install_handler(agent)
    assert isinstance(handler, SignetEventHandler)


def test_handler_class_name():
    assert SignetEventHandler.class_name() == "SignetEventHandler"
