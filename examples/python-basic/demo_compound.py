#!/usr/bin/env python3
"""Signet Python demo: v2 compound receipts (request + response binding).

Usage:
    pip install signet-auth
    python demo_compound.py
"""

import json
import signet_auth


def main():
    print("=== Signet Compound Receipt Demo ===\n")

    # Generate keypair
    kp = signet_auth.generate_keypair()
    print(f"1. Agent public key: {kp.public_key[:30]}...")

    # Sign a compound receipt (request + response bound together)
    action = signet_auth.Action(
        "github_create_issue",
        params={"title": "fix bug", "body": "details"},
        target="mcp://github.local",
    )
    response_content = {"content": [{"type": "text", "text": "issue #42 created"}]}

    compound = signet_auth.sign_compound(
        kp.secret_key,
        action,
        response_content,
        "demo-agent",
        "willamhou",
    )

    print(f"2. Compound receipt: {compound.id}")
    print(f"   Version: v{compound.v}")
    print(f"   Tool: {compound.action.tool}")
    print(f"   Response hash: {compound.response.content_hash[:30]}...")
    print(f"   Request time: {compound.ts_request}")
    print(f"   Response time: {compound.ts_response}")

    # Verify
    receipt_json = compound.to_json()
    verified = signet_auth.verify_any(receipt_json, kp.public_key)
    print(f"\n3. Verify: {'PASS' if verified else 'FAIL'}")

    # Tamper and verify again
    tampered = json.loads(receipt_json)
    tampered["action"]["tool"] = "evil_tool"
    tampered_verified = signet_auth.verify_any(json.dumps(tampered), kp.public_key)
    print(f"4. Tampered verify: {'PASS' if tampered_verified else 'FAIL (expected)'}")

    print("\n=== Compound receipt binds request + response atomically. ===")


if __name__ == "__main__":
    main()
