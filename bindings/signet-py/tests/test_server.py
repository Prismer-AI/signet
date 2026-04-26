"""Tests for server-side verify_request()."""

import json

import signet_auth


def _signed_request(tool="echo", args=None):
    """Create a mock MCP request with a valid Signet signature."""
    if args is None:
        args = {"message": "hello"}
    kp = signet_auth.generate_keypair()
    action = signet_auth.Action(tool, params=args, target="mcp://test")
    receipt = signet_auth.sign(kp.secret_key, action, "test-agent", "owner")
    receipt_dict = json.loads(receipt.to_json())
    return {
        "name": tool,
        "arguments": args,
        "_meta": {"_signet": receipt_dict},
    }, receipt_dict["signer"]["pubkey"], kp


def test_verify_valid_signature():
    params, pubkey, _ = _signed_request()
    opts = signet_auth.VerifyOptions(trusted_keys=[pubkey])
    result = signet_auth.verify_request(params, opts)
    assert result.ok is True
    assert result.signer_name == "test-agent"
    assert result.signer_pubkey == pubkey


def test_verify_untrusted_key():
    params, _, _ = _signed_request()
    opts = signet_auth.VerifyOptions(trusted_keys=["ed25519:AAAA"])
    result = signet_auth.verify_request(params, opts)
    assert result.ok is False
    assert "untrusted" in result.error


def test_verify_trust_bundle_active_agent():
    params, pubkey, _ = _signed_request()
    opts = signet_auth.VerifyOptions(
        trust_bundle={
            "version": 1,
            "bundle_id": "tb_prod",
            "org": "signet",
            "env": "prod",
            "generated_at": "2026-04-25T10:30:00Z",
            "agents": [
                {
                    "id": "agent-1",
                    "name": "test-agent",
                    "owner": "platform",
                    "pubkey": pubkey,
                    "status": "active",
                    "created_at": "2026-04-25T10:00:00Z",
                }
            ],
        }
    )
    result = signet_auth.verify_request(params, opts)
    assert result.ok is True


def test_verify_trust_bundle_disabled_agent_rejected():
    params, pubkey, _ = _signed_request()
    opts = signet_auth.VerifyOptions(
        trust_bundle={
            "version": 1,
            "bundle_id": "tb_prod",
            "org": "signet",
            "env": "prod",
            "generated_at": "2026-04-25T10:30:00Z",
            "agents": [
                {
                    "id": "agent-1",
                    "name": "test-agent",
                    "owner": "platform",
                    "pubkey": pubkey,
                    "status": "disabled",
                    "created_at": "2026-04-25T10:00:00Z",
                    "disabled_at": "2026-04-25T10:05:00Z",
                }
            ],
        }
    )
    result = signet_auth.verify_request(params, opts)
    assert result.ok is False
    assert "untrusted" in result.error


def test_verify_invalid_signature():
    params, pubkey, _ = _signed_request()
    params["_meta"]["_signet"]["sig"] = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    opts = signet_auth.VerifyOptions(trusted_keys=[pubkey])
    result = signet_auth.verify_request(params, opts)
    assert result.ok is False
    assert "invalid signature" in result.error


def test_verify_unsigned_required():
    params = {"name": "echo", "arguments": {}}
    opts = signet_auth.VerifyOptions(require_signature=True)
    result = signet_auth.verify_request(params, opts)
    assert result.ok is False
    assert result.error == "unsigned request"


def test_verify_unsigned_optional():
    params = {"name": "echo", "arguments": {}}
    opts = signet_auth.VerifyOptions(require_signature=False)
    result = signet_auth.verify_request(params, opts)
    assert result.ok is True


def test_verify_returns_signer_info():
    params, pubkey, _ = _signed_request()
    opts = signet_auth.VerifyOptions(trusted_keys=[pubkey])
    result = signet_auth.verify_request(params, opts)
    assert result.ok is True
    assert result.signer_name == "test-agent"
    assert result.signer_pubkey == pubkey


def test_verify_expired_receipt():
    params, pubkey, _ = _signed_request()
    opts = signet_auth.VerifyOptions(trusted_keys=[pubkey], max_age=0)
    # ts is "now" but maxAge=0 means any age is too old
    import time
    time.sleep(0.1)
    result = signet_auth.verify_request(params, opts)
    assert result.ok is False
    assert "too old" in result.error


def test_verify_target_mismatch():
    params, pubkey, _ = _signed_request()
    opts = signet_auth.VerifyOptions(trusted_keys=[pubkey], expected_target="mcp://other-server")
    result = signet_auth.verify_request(params, opts)
    assert result.ok is False
    assert "target mismatch" in result.error


def test_verify_malformed_signet():
    params = {"name": "echo", "_meta": {"_signet": {"garbage": True}}}
    opts = signet_auth.VerifyOptions()
    result = signet_auth.verify_request(params, opts)
    assert result.ok is False
    assert "malformed" in result.error


def test_verify_tool_mismatch():
    params, pubkey, _ = _signed_request(tool="echo")
    params["name"] = "delete_everything"  # swap tool name
    opts = signet_auth.VerifyOptions(trusted_keys=[pubkey])
    result = signet_auth.verify_request(params, opts)
    assert result.ok is False
    assert "tool mismatch" in result.error


def test_verify_params_mismatch():
    params, pubkey, _ = _signed_request(tool="echo", args={"safe": True})
    params["arguments"] = {"dangerous": True}  # swap args
    opts = signet_auth.VerifyOptions(trusted_keys=[pubkey])
    result = signet_auth.verify_request(params, opts)
    assert result.ok is False
    assert "params mismatch" in result.error


def test_verify_no_meta():
    params = {"name": "echo", "arguments": {}}
    opts = signet_auth.VerifyOptions(require_signature=True)
    result = signet_auth.verify_request(params, opts)
    assert result.ok is False
    assert result.error == "unsigned request"


# --- Regression tests ---


def test_verify_timezone_less_timestamp_returns_false_not_raises():
    """Fix #5: timezone-less timestamp must return ok=False, not raise TypeError."""
    params, pubkey, _ = _signed_request()
    # Overwrite the timestamp with one that has no timezone info (no Z, no +00:00)
    params["_meta"]["_signet"]["ts"] = "2026-04-05T12:00:00.000"
    opts = signet_auth.VerifyOptions(trusted_keys=[pubkey])
    # Must not raise; must return a VerifyResult with ok=False
    result = signet_auth.verify_request(params, opts)
    assert result.ok is False
    assert result.error is not None


def test_verify_empty_trusted_keys_accepts_any_valid_signer():
    """Fix #8 (positive): empty trusted_keys list trusts any valid signature."""
    params, _, _ = _signed_request()
    opts = signet_auth.VerifyOptions(trusted_keys=[])
    result = signet_auth.verify_request(params, opts)
    assert result.ok is True


def test_verify_nonempty_trusted_keys_rejects_unknown_signer():
    """Fix #8 (inverse): non-matching trusted_keys rejects the signer."""
    params, _, _ = _signed_request()
    opts = signet_auth.VerifyOptions(trusted_keys=["ed25519:DIFFERENTKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="])
    result = signet_auth.verify_request(params, opts)
    assert result.ok is False
    assert "untrusted" in result.error
