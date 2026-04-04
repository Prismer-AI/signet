#!/usr/bin/env python3
"""Signet Python demo: identity, signing, audit, chain verification.

Usage:
    pip install signet-auth
    python demo_signing.py
"""

import tempfile
from signet_auth import SigningAgent

def main():
    with tempfile.TemporaryDirectory() as tmpdir:
        print("=== Signet Python Demo ===\n")

        # 1. Create agent identity
        agent = SigningAgent.create("demo-bot", owner="willamhou", signet_dir=tmpdir)
        print(f"1. Created agent: {agent.name} (owner: {agent.owner})")
        print(f"   Public key: {agent.public_key}\n")

        # 2. Sign tool calls
        tools = [
            ("github_create_issue", {"title": "fix auth bug", "priority": "high"}),
            ("slack_send_message", {"channel": "#alerts", "text": "deploy started"}),
            ("db_query", {"sql": "SELECT count(*) FROM users"}),
        ]

        for tool, params in tools:
            receipt = agent.sign(tool, params=params, target="mcp://test")
            print(f"2. Signed: {receipt.id[:20]}... | tool: {receipt.action.tool}")

        print()

        # 3. Query audit log
        records = agent.audit_query()
        print(f"3. Audit log: {len(records)} records")
        for r in records:
            receipt = r.receipt
            print(f"   {receipt['ts']} | {receipt['action']['tool']}")

        print()

        # 4. Verify chain integrity
        chain = agent.audit_verify_chain()
        print(f"4. Chain integrity: {'INTACT' if chain.valid else 'BROKEN'} ({chain.total_records} records)")

        # 5. Verify all signatures
        sigs = agent.audit_verify_signatures()
        print(f"5. Signature verification: {sigs.valid}/{sigs.total} valid")

        print("\n=== Done. Every tool call signed + audited + chain-verified. ===")


if __name__ == "__main__":
    main()
