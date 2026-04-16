"""Tests for bilateral verify options (session/call_id cross-check, nonce replay)."""

import signet_auth


def _make_bilateral(session=None, call_id=None):
    agent_kp = signet_auth.generate_keypair()
    server_kp = signet_auth.generate_keypair()
    action = signet_auth.Action(
        "test_tool", params={"key": "value"},
        session=session, call_id=call_id,
    )
    agent_receipt = signet_auth.sign(agent_kp.secret_key, action, "agent", "owner")
    content = {"text": "ok"}
    bilateral = signet_auth.sign_bilateral(
        server_kp.secret_key, agent_receipt, content, "server",
    )
    return bilateral, server_kp


# ─── session cross-check ─────────────────────────────────────────────────────


def test_session_match():
    bilateral, server_kp = _make_bilateral(session="sess_123")
    assert signet_auth.verify_bilateral_with_options(
        bilateral, server_kp.public_key, expected_session="sess_123",
    ) is True


def test_session_mismatch():
    bilateral, server_kp = _make_bilateral(session="sess_123")
    assert signet_auth.verify_bilateral_with_options(
        bilateral, server_kp.public_key, expected_session="sess_wrong",
    ) is False


def test_session_unset_skips():
    bilateral, server_kp = _make_bilateral(session="sess_123")
    # No expected_session = skip check
    assert signet_auth.verify_bilateral_with_options(
        bilateral, server_kp.public_key,
    ) is True


# ─── call_id cross-check ─────────────────────────────────────────────────────


def test_call_id_match():
    bilateral, server_kp = _make_bilateral(call_id="call_abc")
    assert signet_auth.verify_bilateral_with_options(
        bilateral, server_kp.public_key, expected_call_id="call_abc",
    ) is True


def test_call_id_mismatch():
    bilateral, server_kp = _make_bilateral(call_id="call_abc")
    assert signet_auth.verify_bilateral_with_options(
        bilateral, server_kp.public_key, expected_call_id="call_xyz",
    ) is False


# ─── combined ────────────────────────────────────────────────────────────────


def test_both_session_and_call_id_match():
    bilateral, server_kp = _make_bilateral(session="s1", call_id="c1")
    assert signet_auth.verify_bilateral_with_options(
        bilateral, server_kp.public_key,
        expected_session="s1", expected_call_id="c1",
    ) is True


def test_session_match_call_id_mismatch():
    bilateral, server_kp = _make_bilateral(session="s1", call_id="c1")
    assert signet_auth.verify_bilateral_with_options(
        bilateral, server_kp.public_key,
        expected_session="s1", expected_call_id="c_wrong",
    ) is False
