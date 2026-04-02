import json
import pytest
import signet_auth


RESPONSE_CONTENT = {"content": [{"type": "text", "text": "issue #42 created"}]}
TS_REQUEST = "2026-04-02T10:00:00.000Z"
TS_RESPONSE = "2026-04-02T10:00:00.150Z"


def test_sign_compound_roundtrip():
    kp = signet_auth.generate_keypair()
    action = signet_auth.Action("github_create_issue", params={"title": "fix bug"})
    receipt = signet_auth.sign_compound(
        kp.secret_key, action, RESPONSE_CONTENT, "agent", "owner",
        ts_request=TS_REQUEST, ts_response=TS_RESPONSE,
    )
    assert isinstance(receipt, signet_auth.CompoundReceipt)
    json_str = receipt.to_json()
    assert signet_auth.verify_any(json_str, kp.public_key) is True


def test_compound_tampered():
    kp = signet_auth.generate_keypair()
    action = signet_auth.Action("github_create_issue", params={"title": "fix bug"})
    receipt = signet_auth.sign_compound(
        kp.secret_key, action, RESPONSE_CONTENT, "agent", "owner",
        ts_request=TS_REQUEST, ts_response=TS_RESPONSE,
    )
    json_str = receipt.to_json()
    # Tamper with the signer name
    tampered = json_str.replace('"agent"', '"evil"')
    assert signet_auth.verify_any(tampered, kp.public_key) is False


def test_compound_receipt_fields():
    kp = signet_auth.generate_keypair()
    action = signet_auth.Action("github_create_issue", params={"title": "fix bug"})
    receipt = signet_auth.sign_compound(
        kp.secret_key, action, RESPONSE_CONTENT, "agent", "owner",
        ts_request=TS_REQUEST, ts_response=TS_RESPONSE,
    )
    assert receipt.v == 2
    assert receipt.id.startswith("rec_")
    assert receipt.sig.startswith("ed25519:")
    assert receipt.nonce.startswith("rnd_")
    assert receipt.action.tool == "github_create_issue"
    assert receipt.signer.name == "agent"
    assert receipt.signer.owner == "owner"
    assert receipt.ts_request == TS_REQUEST
    assert receipt.ts_response == TS_RESPONSE
    assert receipt.response.content_hash.startswith("sha256:")


def test_compound_from_json_roundtrip():
    kp = signet_auth.generate_keypair()
    action = signet_auth.Action("test_tool")
    receipt = signet_auth.sign_compound(
        kp.secret_key, action, RESPONSE_CONTENT, "agent", "owner",
    )
    json_str = receipt.to_json()
    restored = signet_auth.CompoundReceipt.from_json(json_str)
    assert restored.id == receipt.id
    assert restored.v == 2
    assert restored.response.content_hash == receipt.response.content_hash
    assert restored.sig == receipt.sig


def test_verify_any_accepts_v1():
    kp = signet_auth.generate_keypair()
    action = signet_auth.Action("test_tool", params={"k": "v"})
    receipt = signet_auth.sign(kp.secret_key, action, "agent", "owner")
    json_str = receipt.to_json()
    assert signet_auth.verify_any(json_str, kp.public_key) is True


def test_verify_any_wrong_key():
    kp1 = signet_auth.generate_keypair()
    kp2 = signet_auth.generate_keypair()
    action = signet_auth.Action("test_tool")
    receipt = signet_auth.sign_compound(
        kp1.secret_key, action, RESPONSE_CONTENT, "agent", "owner",
    )
    json_str = receipt.to_json()
    assert signet_auth.verify_any(json_str, kp2.public_key) is False


def test_sign_compound_auto_timestamps():
    kp = signet_auth.generate_keypair()
    action = signet_auth.Action("test_tool")
    # No timestamps provided — should still work
    receipt = signet_auth.sign_compound(
        kp.secret_key, action, RESPONSE_CONTENT, "agent", "owner",
    )
    assert receipt.v == 2
    assert receipt.ts_request != ""
    assert receipt.ts_response != ""
