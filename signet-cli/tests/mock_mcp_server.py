#!/usr/bin/env python3
"""Minimal mock MCP server for proxy integration tests.
Reads JSON-RPC from stdin, writes responses to stdout."""
import json
import sys

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        msg = json.loads(line)
    except json.JSONDecodeError:
        continue

    msg_id = msg.get("id", 0)
    method = msg.get("method", "")

    if method == "initialize":
        resp = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mock", "version": "1.0"},
            },
        }
    elif method == "tools/call":
        params = msg.get("params", {})
        has_signet = "yes" if params.get("_meta", {}).get("_signet") else "no"
        tool_name = params.get("name", "unknown")
        # Echo back the receipt ID if signed
        signet_data = params.get("_meta", {}).get("_signet", {})
        receipt_id = signet_data.get("id", "none")
        resp = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps({
                            "tool": tool_name,
                            "signed": has_signet,
                            "receipt_id": receipt_id,
                        }),
                    }
                ]
            },
        }
    else:
        resp = {"jsonrpc": "2.0", "id": msg_id, "result": {}}

    print(json.dumps(resp), flush=True)
