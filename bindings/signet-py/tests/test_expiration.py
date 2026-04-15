"""Tests for receipt expiration (exp field)."""

import json
from datetime import datetime, timedelta, timezone

import pytest
import signet_auth


def _future(hours=1):
    return (datetime.now(timezone.utc) + timedelta(hours=hours)).strftime(
        "%Y-%m-%dT%H:%M:%S.000Z"
    )


def _past(hours=1):
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime(
        "%Y-%m-%dT%H:%M:%S.000Z"
    )


def test_sign_with_expiration_roundtrip():
    kp = signet_auth.generate_keypair()
    action = signet_auth.Action("Read", params={})
    exp = _future()
    receipt = signet_auth.sign_with_expiration(
        kp.secret_key, action, "agent", "owner", exp,
    )
    assert signet_auth.verify(receipt, kp.public_key) is True
    data = json.loads(receipt.to_json())
    assert data["exp"] == exp


def test_sign_without_expiration_no_exp_field():
    kp = signet_auth.generate_keypair()
    action = signet_auth.Action("Read", params={})
    receipt = signet_auth.sign(kp.secret_key, action, "agent", "owner")
    data = json.loads(receipt.to_json())
    assert "exp" not in data
    assert signet_auth.verify(receipt, kp.public_key) is True


def test_expired_receipt_rejected():
    kp = signet_auth.generate_keypair()
    action = signet_auth.Action("Read", params={})
    exp = _past()
    receipt = signet_auth.sign_with_expiration(
        kp.secret_key, action, "agent", "owner", exp,
    )
    # verify() raises InvalidReceiptError for expired receipts
    with pytest.raises(signet_auth.InvalidReceiptError, match="expired"):
        signet_auth.verify(receipt, kp.public_key)


def test_expired_receipt_allow_expired():
    kp = signet_auth.generate_keypair()
    action = signet_auth.Action("Read", params={})
    exp = _past()
    receipt = signet_auth.sign_with_expiration(
        kp.secret_key, action, "agent", "owner", exp,
    )
    # verify_allow_expired should accept
    assert signet_auth.verify_allow_expired(receipt, kp.public_key) is True


def test_tampered_expiration_fails():
    kp = signet_auth.generate_keypair()
    action = signet_auth.Action("Read", params={})
    exp = _future(1)
    receipt = signet_auth.sign_with_expiration(
        kp.secret_key, action, "agent", "owner", exp,
    )
    # Tamper: extend expiration
    data = json.loads(receipt.to_json())
    data["exp"] = _future(8760)  # 1 year
    tampered = signet_auth.Receipt.from_json(json.dumps(data))
    assert signet_auth.verify(tampered, kp.public_key) is False


def test_verify_allow_expired_rejects_tampered():
    kp = signet_auth.generate_keypair()
    action = signet_auth.Action("Read", params={})
    exp = _past()
    receipt = signet_auth.sign_with_expiration(
        kp.secret_key, action, "agent", "owner", exp,
    )
    data = json.loads(receipt.to_json())
    data["action"]["tool"] = "evil"
    tampered = signet_auth.Receipt.from_json(json.dumps(data))
    # allow_expired still rejects tampered signatures
    assert signet_auth.verify_allow_expired(tampered, kp.public_key) is False
