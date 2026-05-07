import json
from pathlib import Path

import pytest
import signet_auth


NO_TIME_WINDOW = 100 * 365 * 24 * 3600
FIXTURES_PATH = (
    Path(__file__).resolve().parents[3]
    / "packages"
    / "signet-core"
    / "tests"
    / "fixtures"
    / "ts-signed.json"
)


with FIXTURES_PATH.open("r", encoding="utf-8") as fh:
    FIXTURES = json.load(fh)


def test_typescript_signed_v1_verifies_in_python():
    fixture = FIXTURES["v1"]
    receipt = signet_auth.Receipt.from_json(json.dumps(fixture["receipt"]))
    assert signet_auth.verify(receipt, fixture["public_key"]) is True


def test_typescript_signed_v1_wrong_key_fails_in_python():
    receipt = signet_auth.Receipt.from_json(json.dumps(FIXTURES["v1"]["receipt"]))
    assert signet_auth.verify(receipt, FIXTURES["v2"]["public_key"]) is False


def test_typescript_signed_v2_verifies_via_verify_any_in_python():
    fixture = FIXTURES["v2"]
    assert signet_auth.verify_any(json.dumps(fixture["receipt"]), fixture["public_key"]) is True


def test_typescript_signed_v3_verifies_with_server_key_in_python():
    fixture = FIXTURES["v3"]
    receipt = signet_auth.BilateralReceipt.from_json(json.dumps(fixture["receipt"]))
    assert signet_auth.verify_bilateral_with_options(
        receipt,
        fixture["server_public_key"],
        max_time_window_secs=NO_TIME_WINDOW,
    ) is True


def test_typescript_signed_v3_trusted_agent_path_verifies_in_python():
    fixture = FIXTURES["v3"]
    receipt = signet_auth.BilateralReceipt.from_json(json.dumps(fixture["receipt"]))
    assert signet_auth.verify_bilateral_with_options(
        receipt,
        fixture["server_public_key"],
        max_time_window_secs=NO_TIME_WINDOW,
        trusted_agent_public_key=fixture["agent_public_key"],
    ) is True
    assert signet_auth.verify_bilateral_detailed(
        receipt,
        fixture["server_public_key"],
        max_time_window_secs=NO_TIME_WINDOW,
        trusted_agent_public_key=fixture["agent_public_key"],
    ) == "agent_trusted"


def test_typescript_signed_v3_wrong_server_key_fails_in_python():
    fixture = FIXTURES["v3"]
    receipt = signet_auth.BilateralReceipt.from_json(json.dumps(fixture["receipt"]))
    assert signet_auth.verify_bilateral_with_options(
        receipt,
        fixture["agent_public_key"],
        max_time_window_secs=NO_TIME_WINDOW,
    ) is False


def test_typescript_signed_v3_verify_any_dispatches_in_python():
    fixture = FIXTURES["v3"]
    receipt_json = json.dumps(fixture["receipt"])
    try:
        assert signet_auth.verify_any(receipt_json, fixture["server_public_key"]) is True
    except signet_auth.InvalidReceiptError as err:
        message = str(err)
        assert "time gap" in message or "window" in message


def test_typescript_signed_v4_verifies_against_trusted_root_in_python():
    fixture = FIXTURES["v4"]
    scope_json = signet_auth.verify_authorized(
        json.dumps(fixture["receipt"]),
        [fixture["owner_public_key"]],
    )
    scope = json.loads(scope_json)
    assert isinstance(scope["tools"], list)
    assert isinstance(scope["targets"], list)


def test_typescript_signed_v4_wrong_root_fails_in_python():
    fixture = FIXTURES["v4"]
    with pytest.raises(signet_auth.ChainError):
        signet_auth.verify_authorized(
            json.dumps(fixture["receipt"]),
            [FIXTURES["v1"]["public_key"]],
        )
