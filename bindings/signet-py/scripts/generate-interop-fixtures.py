#!/usr/bin/env python3
"""Generate cross-language interop fixtures: Python signs, TypeScript verifies.

Output: packages/signet-core/tests/fixtures/python-signed.json

Run from repo root with the local Python binding installed:
    python bindings/signet-py/scripts/generate-interop-fixtures.py

These fixtures are checked in and consumed by
packages/signet-core/tests/interop.test.ts to verify that receipts signed
in Python verify correctly when parsed in TypeScript.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import signet_auth as sa
from signet_auth import Action, SigningAgent

REPO_ROOT = Path(__file__).resolve().parents[3]
OUT = REPO_ROOT / "packages" / "signet-core" / "tests" / "fixtures"
OUT.mkdir(parents=True, exist_ok=True)


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        # v1 unilateral
        a1 = SigningAgent.create("py-signer-v1", owner="interop", signet_dir=tmp)
        r1 = a1.sign("interop_v1", params={"k": "v"}, target="mcp://test", audit=False)
        v1 = json.loads(r1.to_json())

        # v2 compound
        a2 = SigningAgent.create("py-signer-v2", owner="interop", signet_dir=tmp)
        action2 = Action(tool="interop_v2", params={"k": "v"}, target="mcp://test", transport="stdio")
        ts = "2026-04-21T12:00:00.000Z"
        r2 = sa.sign_compound(
            a2._secret_key, action2, {"result": "ok"},
            a2.name, "interop", ts, ts,
        )
        v2 = json.loads(r2.to_json() if hasattr(r2, "to_json") else r2)

        # v3 bilateral
        agent = SigningAgent.create("py-agent-v3", owner="owner", signet_dir=tmp)
        server = SigningAgent.create("py-server-v3", owner="provider", signet_dir=tmp)
        agent_receipt = agent.sign("interop_v3", params={"q": "hi"}, target="mcp://test", audit=False)
        bilateral = server.sign_bilateral(agent_receipt, response_content={"result": "data"})
        v3 = json.loads(bilateral.to_json())

        # v4 delegation
        owner = SigningAgent.create("py-owner-v4", owner="root", signet_dir=tmp)
        delegate = SigningAgent.create("py-delegate-v4", owner="bot", signet_dir=tmp)
        scope_json = json.dumps({"tools": ["*"], "targets": ["*"], "max_depth": 0})
        token_json = sa.sign_delegation(
            owner._secret_key, owner.name, delegate.public_key, delegate.name, scope_json,
        )
        chain = [json.loads(token_json)]
        v4_json = delegate.sign_authorized("interop_v4", target="mcp://test", chain=chain)
        v4 = json.loads(v4_json)

        fixtures = {
            "v1": {"receipt": v1, "public_key": a1.public_key},
            "v2": {"receipt": v2, "public_key": a2.public_key},
            "v3": {
                "receipt": v3,
                "agent_public_key": agent.public_key,
                "server_public_key": server.public_key,
            },
            "v4": {
                "receipt": v4,
                "delegate_public_key": delegate.public_key,
                "owner_public_key": owner.public_key,
            },
        }

    out_file = OUT / "python-signed.json"
    out_file.write_text(json.dumps(fixtures, indent=2))
    print(f"Wrote {out_file}")
    for v in ["v1", "v2", "v3", "v4"]:
        sig = fixtures[v]["receipt"].get("sig", "")
        print(f"  {v} sig: {sig[:60]}...")


if __name__ == "__main__":
    main()
