"""Tests for signed trace correlation (trace_id + parent_receipt_id)."""

import json
import signet_auth


def test_action_with_trace_id():
    action = signet_auth.Action("Bash", params={"cmd": "ls"}, trace_id="tr_abc123")
    assert action.trace_id == "tr_abc123"
    assert action.parent_receipt_id is None


def test_action_with_parent_receipt_id():
    action = signet_auth.Action("Bash", params={}, parent_receipt_id="rec_parent")
    assert action.parent_receipt_id == "rec_parent"


def test_action_with_both_trace_fields():
    action = signet_auth.Action(
        "Bash", params={}, trace_id="tr_workflow", parent_receipt_id="rec_step1",
    )
    assert action.trace_id == "tr_workflow"
    assert action.parent_receipt_id == "rec_step1"


def test_action_without_trace_fields():
    action = signet_auth.Action("Read", params={})
    assert action.trace_id is None
    assert action.parent_receipt_id is None


def test_sign_with_trace_id_roundtrip():
    kp = signet_auth.generate_keypair()
    action = signet_auth.Action("Bash", params={"cmd": "ls"}, trace_id="tr_test")
    receipt = signet_auth.sign(kp.secret_key, action, "agent", "owner")
    assert signet_auth.verify(receipt, kp.public_key) is True
    # trace_id should be in the signed JSON
    receipt_data = json.loads(receipt.to_json())
    assert receipt_data["action"]["trace_id"] == "tr_test"


def test_sign_with_parent_receipt_id_roundtrip():
    kp = signet_auth.generate_keypair()
    action = signet_auth.Action("Write", params={}, parent_receipt_id="rec_prev")
    receipt = signet_auth.sign(kp.secret_key, action, "agent", "owner")
    assert signet_auth.verify(receipt, kp.public_key) is True
    receipt_data = json.loads(receipt.to_json())
    assert receipt_data["action"]["parent_receipt_id"] == "rec_prev"


def test_trace_fields_in_signature_scope():
    """Tampering with trace_id should invalidate the signature."""
    kp = signet_auth.generate_keypair()
    action = signet_auth.Action("Bash", params={}, trace_id="tr_legit")
    receipt = signet_auth.sign(kp.secret_key, action, "agent", "owner")
    # Tamper with trace_id
    receipt_json = receipt.to_json()
    tampered = receipt_json.replace('"tr_legit"', '"tr_forged"')
    restored = signet_auth.Receipt.from_json(tampered)
    assert signet_auth.verify(restored, kp.public_key) is False


def test_trace_fields_absent_in_json_when_none():
    """trace_id and parent_receipt_id should not appear in JSON when None."""
    kp = signet_auth.generate_keypair()
    action = signet_auth.Action("Read", params={})
    receipt = signet_auth.sign(kp.secret_key, action, "agent", "owner")
    receipt_data = json.loads(receipt.to_json())
    assert "trace_id" not in receipt_data["action"]
    assert "parent_receipt_id" not in receipt_data["action"]


def test_workflow_start_then_child_calls():
    """Simulate a workflow: start receipt, then child calls referencing trace_id."""
    kp = signet_auth.generate_keypair()

    # Workflow start
    start_action = signet_auth.Action(
        "_workflow_start", params={"skill": "create-flask-app"}, trace_id="tr_wf001",
    )
    start_receipt = signet_auth.sign(kp.secret_key, start_action, "agent", "owner")
    start_data = json.loads(start_receipt.to_json())
    start_id = start_data["id"]

    # Child call 1
    child1_action = signet_auth.Action(
        "Bash", params={"cmd": "pip install flask"},
        trace_id="tr_wf001", parent_receipt_id=start_id,
    )
    child1_receipt = signet_auth.sign(kp.secret_key, child1_action, "agent", "owner")
    child1_data = json.loads(child1_receipt.to_json())

    # Child call 2
    child2_action = signet_auth.Action(
        "Write", params={"path": "app.py"},
        trace_id="tr_wf001", parent_receipt_id=child1_data["id"],
    )
    child2_receipt = signet_auth.sign(kp.secret_key, child2_action, "agent", "owner")

    # All verifiable
    assert signet_auth.verify(start_receipt, kp.public_key) is True
    assert signet_auth.verify(child1_receipt, kp.public_key) is True
    assert signet_auth.verify(child2_receipt, kp.public_key) is True

    # Chain: start -> child1 -> child2
    child2_data = json.loads(child2_receipt.to_json())
    assert child1_data["action"]["trace_id"] == "tr_wf001"
    assert child1_data["action"]["parent_receipt_id"] == start_id
    assert child2_data["action"]["trace_id"] == "tr_wf001"
    assert child2_data["action"]["parent_receipt_id"] == child1_data["id"]
