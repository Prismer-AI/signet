#!/usr/bin/env python3
"""Signet Python demo: LangChain integration.

Signs every tool call via LangChain callback handler.

Usage:
    pip install signet-auth langchain-core
    python demo_langchain.py
"""

import tempfile
from signet_auth import SigningAgent
from signet_auth.langchain import SignetCallbackHandler


def main():
    print("=== Signet LangChain Integration Demo ===\n")

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create agent
        agent = SigningAgent.create("langchain-bot", owner="willamhou", signet_dir=tmpdir)
        handler = SignetCallbackHandler(agent)
        print(f"1. Agent: {agent.name} | Key: {agent.public_key[:30]}...")

        # Simulate LangChain tool callbacks
        # (In real usage, these fire automatically via chain.invoke())
        tools = [
            {
                "name": "search_web",
                "id": "call_001",
                "serialized": {"name": "search_web"},
                "input_str": '{"query": "signet crypto"}',
            },
            {
                "name": "create_document",
                "id": "call_002",
                "serialized": {"name": "create_document"},
                "input_str": '{"title": "Report", "body": "findings..."}',
            },
        ]

        for tool in tools:
            # Simulate on_tool_start (LangChain fires this)
            handler.on_tool_start(
                serialized=tool["serialized"],
                input_str=tool["input_str"],
                run_id=tool["id"],
            )
            print(f"2. Tool started: {tool['name']}")

            # Simulate on_tool_end (LangChain fires this after execution)
            handler.on_tool_end(
                output=f"Result for {tool['name']}",
                run_id=tool["id"],
            )
            print(f"   Tool ended: {tool['name']} → receipt logged")

        print()

        # Check audit log
        records = agent.audit_query()
        print(f"3. Audit log: {len(records)} receipts")
        for r in records:
            receipt = r.receipt
            print(f"   {receipt['action']['tool']} | {receipt['ts']}")

        # Verify chain
        chain = agent.audit_verify_chain()
        print(f"\n4. Chain: {'INTACT' if chain.valid else 'BROKEN'} ({chain.total_records} records)")

        print("\n=== LangChain callbacks → Signet receipts → hash-chained audit. ===")


if __name__ == "__main__":
    main()
