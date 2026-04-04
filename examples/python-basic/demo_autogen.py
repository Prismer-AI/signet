#!/usr/bin/env python3
"""Signet AutoGen integration demo.

Usage:
    pip install signet-auth
    python demo_autogen.py
"""

import asyncio
import tempfile

from signet_auth import SigningAgent
from signet_auth.autogen import sign_tools


class MockSearchTool:
    name = "web_search"
    description = "Search the web"

    async def run_json(self, args: dict, ct: object = None) -> dict:
        return {"results": [f"Result for: {args.get('query', '')}"]}

    def return_value_as_string(self, v: object) -> str:
        return str(v)


class MockWriteTool:
    name = "write_document"
    description = "Write a document"

    async def run_json(self, args: dict, ct: object = None) -> dict:
        return {"status": "created", "title": args.get("title", "")}

    def return_value_as_string(self, v: object) -> str:
        return str(v)


async def main() -> None:
    print("=== Signet AutoGen Integration Demo ===\n")

    with tempfile.TemporaryDirectory() as tmpdir:
        agent = SigningAgent.create("autogen-bot", owner="willamhou", signet_dir=tmpdir)
        print(f"1. Agent: {agent.name} | Key: {agent.public_key[:30]}...")

        # Wrap tools
        tools = sign_tools([MockSearchTool(), MockWriteTool()], agent)
        print(f"2. Wrapped {len(tools)} tools: {[t.name for t in tools]}")

        # Execute tools — signing happens automatically
        r1 = await tools[0].run_json({"query": "signet crypto signing"})
        print(f"3. {tools[0].name}: {r1}")

        r2 = await tools[1].run_json(
            {"title": "Security Report", "body": "findings..."}
        )
        print(f"4. {tools[1].name}: {r2}")

        # Check audit
        records = agent.audit_query()
        print(f"\n5. Audit: {len(records)} receipts")
        for r in records:
            print(f"   {r.receipt['action']['tool']} | {r.receipt['ts']}")

        chain = agent.audit_verify_chain()
        print(f"\n6. Chain: {'INTACT' if chain.valid else 'BROKEN'}")

    print("\n=== AutoGen tools wrapped — every call signed + audited. ===")


if __name__ == "__main__":
    asyncio.run(main())
