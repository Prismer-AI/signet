"""Server-side verification for MCP tool call requests."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from signet_auth._signet import Receipt, verify

CLOCK_SKEW_TOLERANCE_SECONDS = 30


@dataclass
class VerifyOptions:
    """Options for verify_request()."""

    trusted_keys: list[str] = field(default_factory=list)
    """List of trusted 'ed25519:<base64>' pubkeys.
    If empty and require_signature=True, ALL signed requests are rejected."""

    require_signature: bool = True
    """Reject unsigned requests. Default: True."""

    max_age: int = 300
    """Max age of receipt in seconds. Default: 300 (5 min)."""

    expected_target: str | None = None
    """If set, receipt.action.target must match this value."""


@dataclass
class VerifyResult:
    """Result of verify_request()."""

    ok: bool
    signer_name: str | None = None
    signer_pubkey: str | None = None
    error: str | None = None


def verify_request(
    params: dict[str, Any],
    options: VerifyOptions | None = None,
) -> VerifyResult:
    """Verify a Signet signature in an MCP tool call request.

    Args:
        params: The request params dict (should contain _meta._signet).
        options: Verification options (trusted keys, freshness, etc.).

    Returns:
        VerifyResult with ok=True if verified, ok=False with error if not.
    """
    opts = options or VerifyOptions()

    # 1. Extract _meta._signet
    meta = params.get("_meta")
    signet = meta.get("_signet") if isinstance(meta, dict) else None

    # 2. Check presence
    if signet is None:
        if opts.require_signature:
            return VerifyResult(ok=False, error="unsigned request")
        return VerifyResult(ok=True)

    # 3. Validate receipt shape
    if not isinstance(signet, dict):
        return VerifyResult(ok=False, error="malformed receipt")
    for key in ("v", "sig", "action", "signer", "ts"):
        if key not in signet:
            return VerifyResult(ok=False, error="malformed receipt")

    # 4. Verify signature
    try:
        receipt = Receipt.from_json(json.dumps(signet))
    except Exception:
        return VerifyResult(ok=False, error="malformed receipt")

    prefixed_pubkey = receipt.signer.pubkey
    bare_pubkey = (
        prefixed_pubkey[len("ed25519:") :]
        if prefixed_pubkey.startswith("ed25519:")
        else prefixed_pubkey
    )

    try:
        valid = verify(receipt, bare_pubkey)
    except Exception:
        return VerifyResult(ok=False, error="invalid signature")

    if not valid:
        return VerifyResult(ok=False, error="invalid signature")

    # 5. Check trusted keys
    if prefixed_pubkey not in opts.trusted_keys:
        return VerifyResult(ok=False, error=f"untrusted signer: {prefixed_pubkey}")

    # 6. Check freshness
    try:
        receipt_time = datetime.fromisoformat(receipt.ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return VerifyResult(ok=False, error="invalid receipt timestamp")

    now = datetime.now(timezone.utc)
    age = (now - receipt_time).total_seconds()

    if age > opts.max_age:
        return VerifyResult(ok=False, error="receipt too old")
    if age < -CLOCK_SKEW_TOLERANCE_SECONDS:
        return VerifyResult(ok=False, error="receipt from future")

    # 7. Check target
    if opts.expected_target and receipt.action.target != opts.expected_target:
        return VerifyResult(
            ok=False,
            error=f"target mismatch: expected {opts.expected_target}, got {receipt.action.target}",
        )

    # 8. Anti-staple: tool name
    request_tool = params.get("name")
    if request_tool is not None and receipt.action.tool != request_tool:
        return VerifyResult(
            ok=False,
            error=f'tool mismatch: receipt signed for "{receipt.action.tool}", request is for "{request_tool}"',
        )

    # 9. Anti-staple: params
    request_args = params.get("arguments")
    receipt_params = receipt.action.params
    if request_args is not None or receipt_params is not None:
        signed = json.dumps(receipt_params, sort_keys=True) if receipt_params is not None else "null"
        actual = json.dumps(request_args, sort_keys=True) if request_args is not None else "null"
        if signed != actual:
            return VerifyResult(ok=False, error="params mismatch: signed params differ from request arguments")

    # All checks pass
    return VerifyResult(
        ok=True,
        signer_name=receipt.signer.name,
        signer_pubkey=prefixed_pubkey,
    )
