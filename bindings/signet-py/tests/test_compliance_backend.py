"""Tests for ComplianceBackend Protocol adapter."""

from signet_auth.compliance_backend import (
    SignetComplianceBackend,
    ToolEvent,
    ComplianceReceipt,
)


def test_create_backend():
    backend = SignetComplianceBackend.create("cb-test-1")
    assert backend.BACKEND_ID == "signet-v0.9"


def test_notarize_returns_receipt():
    backend = SignetComplianceBackend.create("cb-test-2")
    event = ToolEvent(tool_name="web_search", params={"query": "AI"}, run_id="run-1")
    receipt = backend.notarize(event)

    assert isinstance(receipt, ComplianceReceipt)
    assert receipt.backend_id == "signet-v0.9"
    assert receipt.signature.startswith("ed25519:")
    assert receipt.signer_pubkey.startswith("ed25519:")
    assert receipt.params_hash.startswith("sha256:")
    assert "web_search" in receipt.event_ref


def test_verify_roundtrip():
    backend = SignetComplianceBackend.create("cb-test-3")
    event = ToolEvent(tool_name="file_read", params={"path": "/tmp"})
    receipt = backend.notarize(event)
    assert backend.verify(receipt) is True


def test_verify_tampered_fails():
    backend = SignetComplianceBackend.create("cb-test-4")
    event = ToolEvent(tool_name="api_call", params={"url": "example.com"})
    receipt = backend.notarize(event)
    # Tamper
    receipt.raw_receipt["action"]["tool"] = "evil"
    assert backend.verify(receipt) is False


def test_chain_ref_links_receipts():
    backend = SignetComplianceBackend.create("cb-test-5")
    r1 = backend.notarize(ToolEvent(tool_name="step_1"))
    r2 = backend.notarize(ToolEvent(tool_name="step_2"))
    r3 = backend.notarize(ToolEvent(tool_name="step_3"))

    assert r1.chain_ref == ""  # first receipt has no parent
    assert r2.chain_ref != ""  # links to r1
    assert r3.chain_ref != ""  # links to r2
    assert r2.chain_ref != r3.chain_ref  # different parents


def test_no_raw_receipt_verify_fails():
    receipt = ComplianceReceipt(
        event_ref="test", signature="fake", chain_ref="",
        backend_id="signet-v0.9", signer_pubkey="", params_hash="",
    )
    backend = SignetComplianceBackend.create("cb-test-6")
    assert backend.verify(receipt) is False
