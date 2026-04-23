import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest
import signet_auth


def _sign_receipt():
    kp = signet_auth.generate_keypair()
    action = signet_auth.Action("test_tool", params={"k": "v"})
    return signet_auth.sign(kp.secret_key, action, "test-agent", "owner")


def _sign_bilateral():
    agent_kp = signet_auth.generate_keypair()
    server_kp = signet_auth.generate_keypair()
    action = signet_auth.Action("test_tool", params={"k": "v"})
    agent_receipt = signet_auth.sign(agent_kp.secret_key, action, "test-agent", "owner")
    return signet_auth.sign_bilateral(
        server_kp.secret_key,
        agent_receipt,
        {"ok": True},
        "test-server",
    )


def test_audit_append(tmp_path):
    receipt = _sign_receipt()
    record = signet_auth.audit_append(str(tmp_path), receipt)
    assert isinstance(record, signet_auth.AuditRecord)
    assert record.record_hash.startswith("sha256:")
    assert record.receipt["id"] == receipt.id


def test_audit_append_chain(tmp_path):
    r1 = _sign_receipt()
    rec1 = signet_auth.audit_append(str(tmp_path), r1)
    r2 = _sign_receipt()
    rec2 = signet_auth.audit_append(str(tmp_path), r2)
    assert rec2.prev_hash == rec1.record_hash


def test_audit_query_no_filter(tmp_path):
    for _ in range(3):
        signet_auth.audit_append(str(tmp_path), _sign_receipt())
    records = signet_auth.audit_query(str(tmp_path))
    assert len(records) == 3


def test_audit_query_tool_filter(tmp_path):
    signet_auth.audit_append(str(tmp_path), _sign_receipt())
    records = signet_auth.audit_query(str(tmp_path), tool="test")
    assert len(records) == 1
    records_miss = signet_auth.audit_query(str(tmp_path), tool="nonexistent")
    assert len(records_miss) == 0


def test_audit_query_limit(tmp_path):
    for _ in range(5):
        signet_auth.audit_append(str(tmp_path), _sign_receipt())
    records = signet_auth.audit_query(str(tmp_path), limit=2)
    assert len(records) == 2


def test_audit_query_since_string(tmp_path):
    signet_auth.audit_append(str(tmp_path), _sign_receipt())
    records = signet_auth.audit_query(str(tmp_path), since="1h")
    assert len(records) == 1


def test_audit_query_since_datetime(tmp_path):
    signet_auth.audit_append(str(tmp_path), _sign_receipt())
    one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
    records = signet_auth.audit_query(str(tmp_path), since=one_hour_ago)
    assert len(records) == 1


def test_audit_query_since_naive_datetime_rejected(tmp_path):
    signet_auth.audit_append(str(tmp_path), _sign_receipt())
    with pytest.raises(ValueError, match="timezone-aware"):
        signet_auth.audit_query(str(tmp_path), since=datetime.now())


def test_audit_verify_chain(tmp_path):
    for _ in range(3):
        signet_auth.audit_append(str(tmp_path), _sign_receipt())
    status = signet_auth.audit_verify_chain(str(tmp_path))
    assert isinstance(status, signet_auth.ChainStatus)
    assert status.valid is True
    assert status.total_records == 3
    assert status.break_point is None


def test_audit_verify_signatures(tmp_path):
    for _ in range(3):
        signet_auth.audit_append(str(tmp_path), _sign_receipt())
    result = signet_auth.audit_verify_signatures(str(tmp_path))
    assert isinstance(result, signet_auth.VerifyResult)
    assert result.total == 3
    assert result.valid == 3
    assert result.warnings == []
    assert result.failures == []


def test_audit_verify_signatures_v3_warns_on_integrity_only(tmp_path):
    bilateral = _sign_bilateral()
    audit_dir = Path(tmp_path) / "audit"
    audit_dir.mkdir()
    audit_file = audit_dir / f"{bilateral.ts_response[:10]}.jsonl"
    audit_file.write_text(
        json.dumps(
            {
                "receipt": json.loads(bilateral.to_json()),
                "prev_hash": "sha256:0",
                "record_hash": "sha256:1",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    result = signet_auth.audit_verify_signatures(str(tmp_path))
    assert result.total == 1
    assert result.valid == 1
    assert len(result.warnings) == 1
    assert "integrity only" in result.warnings[0].reason
    assert result.failures == []


def test_audit_verify_signatures_v3_with_trusted_keys(tmp_path):
    bilateral = _sign_bilateral()
    audit_dir = Path(tmp_path) / "audit"
    audit_dir.mkdir()
    audit_file = audit_dir / f"{bilateral.ts_response[:10]}.jsonl"
    audit_file.write_text(
        json.dumps(
            {
                "receipt": json.loads(bilateral.to_json()),
                "prev_hash": "sha256:0",
                "record_hash": "sha256:1",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    result = signet_auth.audit_verify_signatures(
        str(tmp_path),
        trusted_agent_keys=[bilateral.agent_receipt.signer.pubkey],
        trusted_server_keys=[bilateral.server.pubkey],
    )
    assert result.total == 1
    assert result.valid == 1
    assert result.warnings == []
    assert result.failures == []
