#!/usr/bin/env python3
"""Signet Python demo: server-side verification (v0.3 + bilateral v0.4 concepts).

Usage:
    pip install signet-auth
    python demo_server_verify.py
"""

import json
import signet_auth


def main():
    print("=== Signet Server Verification Demo ===\n")

    # Agent signs a request
    agent_kp = signet_auth.generate_keypair()
    action = signet_auth.Action(
        "create_issue",
        params={"title": "bug report"},
        target="mcp://github",
    )
    receipt = signet_auth.sign(agent_kp.secret_key, action, "deploy-bot", "willamhou")
    receipt_dict = json.loads(receipt.to_json())

    print(f"1. Agent signed: {receipt.id[:20]}... | tool: {receipt.action.tool}")

    # Simulate MCP request with _meta._signet
    request_params = {
        "name": "create_issue",
        "arguments": {"title": "bug report"},
        "_meta": {"_signet": receipt_dict},
    }

    # Server verifies — with trusted key
    agent_pubkey = receipt_dict["signer"]["pubkey"]
    opts = signet_auth.VerifyOptions(trusted_keys=[agent_pubkey])
    result = signet_auth.verify_request(request_params, opts)
    print(f"2. Server verify (trusted): ok={result.ok}, signer={result.signer_name}")

    # Server verifies — unknown key
    opts_unknown = signet_auth.VerifyOptions(trusted_keys=["ed25519:UNKNOWN"])
    result_unknown = signet_auth.verify_request(request_params, opts_unknown)
    print(f"3. Server verify (untrusted): ok={result_unknown.ok}, error={result_unknown.error}")

    # Server verifies — tampered tool name (anti-staple)
    tampered_params = {**request_params, "name": "delete_everything"}
    result_tampered = signet_auth.verify_request(tampered_params, opts)
    print(f"4. Anti-staple (tool mismatch): ok={result_tampered.ok}, error={result_tampered.error}")

    # Server verifies — tampered arguments (anti-staple)
    tampered_args = {**request_params, "arguments": {"title": "HACKED"}}
    result_args = signet_auth.verify_request(tampered_args, opts)
    print(f"5. Anti-staple (params mismatch): ok={result_args.ok}, error={result_args.error}")

    # Unsigned request
    unsigned = {"name": "echo", "arguments": {}}
    result_unsigned = signet_auth.verify_request(unsigned, signet_auth.VerifyOptions(require_signature=True))
    print(f"6. Unsigned request: ok={result_unsigned.ok}, error={result_unsigned.error}")

    print("\n=== Server verification: signature + trust + anti-staple + freshness. ===")


if __name__ == "__main__":
    main()
