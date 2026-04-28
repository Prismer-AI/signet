import pytest
import signet_auth


RESPONSE_CONTENT = {"content": [{"type": "text", "text": "issue #42 created"}]}


def _make_agent_receipt():
    """Create a v1 agent receipt for bilateral signing."""
    kp = signet_auth.generate_keypair()
    action = signet_auth.Action("github_create_issue", params={"title": "fix bug"})
    receipt = signet_auth.sign(kp.secret_key, action, "agent", "owner")
    return kp, receipt


def test_sign_bilateral_roundtrip():
    _, agent_receipt = _make_agent_receipt()
    server_kp = signet_auth.generate_keypair()

    bilateral = signet_auth.sign_bilateral(
        server_kp.secret_key, agent_receipt, RESPONSE_CONTENT, "my-server",
    )
    assert signet_auth.verify_bilateral(bilateral, server_kp.public_key) is True


def test_bilateral_receipt_fields():
    _, agent_receipt = _make_agent_receipt()
    server_kp = signet_auth.generate_keypair()

    bilateral = signet_auth.sign_bilateral(
        server_kp.secret_key, agent_receipt, RESPONSE_CONTENT, "my-server",
        ts_response="2026-04-06T10:00:00.000Z",
    )
    assert bilateral.v == 3
    assert bilateral.id.startswith("rec_")
    assert bilateral.sig.startswith("ed25519:")
    assert bilateral.nonce.startswith("rnd_")
    assert bilateral.ts_response == "2026-04-06T10:00:00.000Z"
    assert bilateral.server.name == "my-server"
    assert bilateral.server.pubkey.startswith("ed25519:")
    assert bilateral.response.content_hash.startswith("sha256:")
    # Embedded agent receipt preserved
    assert bilateral.agent_receipt.v == 1
    assert bilateral.agent_receipt.action.tool == "github_create_issue"
    assert bilateral.agent_receipt.signer.name == "agent"


def test_bilateral_wrong_server_key():
    _, agent_receipt = _make_agent_receipt()
    server_kp = signet_auth.generate_keypair()
    other_kp = signet_auth.generate_keypair()

    bilateral = signet_auth.sign_bilateral(
        server_kp.secret_key, agent_receipt, RESPONSE_CONTENT, "my-server",
    )
    # Verify with wrong key
    assert signet_auth.verify_bilateral(bilateral, other_kp.public_key) is False


def test_bilateral_tampered_sig():
    _, agent_receipt = _make_agent_receipt()
    server_kp = signet_auth.generate_keypair()

    bilateral = signet_auth.sign_bilateral(
        server_kp.secret_key, agent_receipt, RESPONSE_CONTENT, "my-server",
    )
    # Tamper via JSON roundtrip
    json_str = bilateral.to_json()
    tampered = json_str.replace('"my-server"', '"evil-server"')
    restored = signet_auth.BilateralReceipt.from_json(tampered)
    assert signet_auth.verify_bilateral(restored, server_kp.public_key) is False


def test_bilateral_json_roundtrip():
    _, agent_receipt = _make_agent_receipt()
    server_kp = signet_auth.generate_keypair()

    bilateral = signet_auth.sign_bilateral(
        server_kp.secret_key, agent_receipt, RESPONSE_CONTENT, "my-server",
    )
    json_str = bilateral.to_json()
    restored = signet_auth.BilateralReceipt.from_json(json_str)
    assert signet_auth.verify_bilateral(restored, server_kp.public_key) is True
    assert restored.v == 3
    assert restored.server.name == "my-server"


def test_bilateral_invalid_server_key():
    _, agent_receipt = _make_agent_receipt()
    with pytest.raises(signet_auth.InvalidKeyError):
        signet_auth.sign_bilateral("not-valid-base64!", agent_receipt, RESPONSE_CONTENT, "srv")


def test_bilateral_verify_invalid_pubkey():
    _, agent_receipt = _make_agent_receipt()
    server_kp = signet_auth.generate_keypair()
    bilateral = signet_auth.sign_bilateral(
        server_kp.secret_key, agent_receipt, RESPONSE_CONTENT, "srv",
    )
    with pytest.raises(signet_auth.InvalidKeyError):
        signet_auth.verify_bilateral(bilateral, "garbage")


def test_bilateral_from_json_invalid():
    with pytest.raises(signet_auth.SerializeError):
        signet_auth.BilateralReceipt.from_json("{invalid json")


def test_bilateral_empty_response():
    _, agent_receipt = _make_agent_receipt()
    server_kp = signet_auth.generate_keypair()
    bilateral = signet_auth.sign_bilateral(
        server_kp.secret_key, agent_receipt, {}, "srv",
    )
    assert signet_auth.verify_bilateral(bilateral, server_kp.public_key) is True


def test_bilateral_embedded_agent_receipt_verifiable():
    agent_kp, agent_receipt = _make_agent_receipt()
    server_kp = signet_auth.generate_keypair()
    bilateral = signet_auth.sign_bilateral(
        server_kp.secret_key, agent_receipt, RESPONSE_CONTENT, "srv",
    )
    assert signet_auth.verify(bilateral.agent_receipt, agent_kp.public_key) is True


def test_bilateral_auto_timestamp():
    _, agent_receipt = _make_agent_receipt()
    server_kp = signet_auth.generate_keypair()

    bilateral = signet_auth.sign_bilateral(
        server_kp.secret_key, agent_receipt, RESPONSE_CONTENT, "my-server",
    )
    # ts_response should be auto-generated (non-empty, RFC3339-ish)
    assert len(bilateral.ts_response) > 10
    assert "T" in bilateral.ts_response


# ─── Outcome model (sign_bilateral_with_outcome) ──────────────────────────────


def test_bilateral_default_has_no_outcome():
    """Existing sign_bilateral path stays outcome-free for backward compat."""
    _, agent_receipt = _make_agent_receipt()
    server_kp = signet_auth.generate_keypair()
    bilateral = signet_auth.sign_bilateral(
        server_kp.secret_key, agent_receipt, RESPONSE_CONTENT, "srv",
    )
    assert bilateral.response.outcome is None


def test_bilateral_with_outcome_executed():
    _, agent_receipt = _make_agent_receipt()
    server_kp = signet_auth.generate_keypair()
    bilateral = signet_auth.sign_bilateral_with_outcome(
        server_kp.secret_key, agent_receipt, RESPONSE_CONTENT, "srv",
        outcome={"status": "executed"},
    )
    outcome = bilateral.response.outcome
    assert outcome is not None
    assert outcome["status"] == "executed"
    assert outcome.get("reason") is None
    assert outcome.get("error") is None
    # Verifies cleanly.
    assert signet_auth.verify_bilateral(bilateral, server_kp.public_key) is True


def test_bilateral_with_outcome_rejected_with_reason():
    _, agent_receipt = _make_agent_receipt()
    server_kp = signet_auth.generate_keypair()
    bilateral = signet_auth.sign_bilateral_with_outcome(
        server_kp.secret_key, agent_receipt, RESPONSE_CONTENT, "srv",
        outcome={"status": "rejected", "reason": "policy: deny destructive Bash"},
    )
    outcome = bilateral.response.outcome
    assert outcome["status"] == "rejected"
    assert outcome["reason"].startswith("policy")


def test_bilateral_with_outcome_failed_with_error():
    _, agent_receipt = _make_agent_receipt()
    server_kp = signet_auth.generate_keypair()
    bilateral = signet_auth.sign_bilateral_with_outcome(
        server_kp.secret_key, agent_receipt, RESPONSE_CONTENT, "srv",
        outcome={"status": "failed", "error": "connection refused"},
    )
    outcome = bilateral.response.outcome
    assert outcome["status"] == "failed"
    assert outcome["error"] == "connection refused"


def test_bilateral_outcome_invalid_status_rejected():
    _, agent_receipt = _make_agent_receipt()
    server_kp = signet_auth.generate_keypair()
    with pytest.raises(ValueError, match="invalid outcome"):
        signet_auth.sign_bilateral_with_outcome(
            server_kp.secret_key, agent_receipt, RESPONSE_CONTENT, "srv",
            outcome={"status": "frobnicated"},
        )
